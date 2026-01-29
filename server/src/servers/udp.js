// ============================================================================
// NFSU2 Server - UDP Relay Server
// Handles P2P packet forwarding between players
//
// NFSU2 uses a simple relay protocol for NAT traversal:
// 1. Clients connect to relay server and register with small "ping" packets
// 2. When game starts, clients send packets with 6-byte header:
//    [2 bytes port BE][4 bytes IP] + payload
// 3. Server forwards packets between players, replacing header with source info
//
// For localhost testing (same machine), both clients will be 127.0.0.1
// and relay just bounces packets back.
// ============================================================================

import dgram from 'dgram';
import { createLogger } from '../utils/logger.js';
import config from '../config.js';

const log = createLogger('UDP');

class UDPServer {
    constructor() {
        this.server = null;
        this.clients = new Map(); // address:port -> clientInfo
        this.gameClients = new Map(); // gameId -> Set of clientKeys
        this.clientToGame = new Map(); // clientKey -> gameId
        this.packetBuffer = new Map(); // clientKey -> Array of packets to send when other clients connect
        this.expectedClients = new Map(); // gameId -> Set of expected clientKeys
        this.sentFakeP2P = new Set(); // gameId -> already sent fake P2P packets
        this.fakeP2PIntervals = new Map(); // gameId -> interval ID for periodic fake P2P packets
    }

    start(port = config.ports.relay) {
        this.server = dgram.createSocket('udp4');

        this.server.on('message', (msg, rinfo) => this._onMessage(msg, rinfo));
        this.server.on('error', (err) => this._onError(err));
        this.server.on('listening', () => {
            const addr = this.server.address();
            log.info(`UDP relay server listening on ${addr.address}:${addr.port}`);
        });

        this.server.bind(port, '0.0.0.0');

        // Cleanup stale clients periodically
        setInterval(() => this._cleanup(), 60000);

        return this;
    }

    stop() {
        if (this.server) {
            this.server.close();
            log.info('UDP relay server stopped');
        }
    }

    _onMessage(msg, rinfo) {
        const clientKey = `${rinfo.address}:${rinfo.port}`;
        
        // Update/register client
        this._updateClient(clientKey, rinfo);

        // Log raw packet for debugging
        const hexStr = msg.toString('hex').substring(0, 40);
        log.debug(`[UDP] ${clientKey} <- ${msg.length} bytes: ${hexStr}`);

        // NFSU2 relay packet format from hooks.h:
        // [2 bytes dest port (network order)][4 bytes dest IP][payload...]
        // 
        // But client also sends small "probe" packets that are NOT relay format:
        // - 2 byte packets: likely NAT keepalive or probe
        // - Packets where first 4 bytes == 5: game packets (bypass relay)
        
        // Handle probe/keepalive packets (less than 6 bytes)
        if (msg.length < 6) {
            // This could be:
            // 1. NAT keepalive (2 bytes: 0x01 0x00)
            // 2. Connection probe
            // 
            // For 2-byte packet 0x0100: this is NOT a relay header, it's a probe
            // The game sends these to test connectivity before sending actual data
            
            if (msg.length === 2 && msg[0] === 0x01 && msg[1] === 0x00) {
                log.info(`[UDP] NAT probe from ${clientKey} (0x0100) - echoing back`);
            } else {
                log.info(`[UDP] Probe packet from ${clientKey} (${msg.length} bytes): ${hexStr}`);
            }
            
            // Echo back to confirm connectivity
            this._sendPingResponse(rinfo, msg);
            return;
        }

        // OLD: Check for game packets that bypass relay (first dword == 5)
        // NEW: With full relay mode, type=5 packets also come WITH relay header
        // So we no longer check for raw type=5 here - they go through relay path below
        // 
        // However, keep this for backwards compatibility with old clients:
        const firstDword = msg.readUInt32LE(0);
        if (firstDword === 5 && msg.length <= 8) {
            // This is a RAW type=5 packet (old client without relay header)
            // Wrap it in relay header and broadcast
            log.debug(`[UDP] Legacy type=5 packet from ${clientKey}, wrapping and broadcasting`);
            const wrappedPacket = this._buildRelayPacket(rinfo.address, rinfo.port, msg);
            this._broadcastWrapped(clientKey, wrappedPacket);
            return;
        }

        // Parse relay header: [port 2B network order][IP 4B]
        // Note: Port is stored in NETWORK byte order (big endian) by the game
        const destPort = msg.readUInt16BE(0);  // Network order = BE
        const destIP = `${msg[2]}.${msg[3]}.${msg[4]}.${msg[5]}`;
        const payload = msg.slice(6);
        
        // Determine payload type for logging and routing
        const payloadType = payload.length >= 4 ? payload.readUInt32LE(0) : 0;
        const payloadHex = payload.slice(0, Math.min(32, payload.length)).toString('hex');
        
        log.debug(`[UDP] RELAY from ${clientKey}: dest=${destIP}:${destPort}, payload=${payload.length}b, type=${payloadType} (0x${payloadType.toString(16)})`);
        
        // Log full payload for debugging race start issues
        if (payload.length > 0) {
            log.debug(`[UDP] Payload hex: ${payloadHex}${payload.length > 32 ? '...' : ''}`);
        }

        // Check if payload is a type=5 "broadcast" packet
        // In full relay mode, even type=5 packets come with relay header
        // The payload starts with 05 00 00 00 if it's a broadcast packet
        if (payloadType === 5) {
            // This is a game broadcast packet - send to all other players
            log.info(`[UDP] Broadcast packet (type=5) from ${clientKey}: dest=${destIP}:${destPort}, payload=${payloadHex}...`);
            log.info(`[UDP] Broadcasting type=5 to ${this.clients.size - 1} other client(s)`);
            this._relayToOtherClient(clientKey, rinfo, destPort, payload);
            
            const srcClient = this.clients.get(clientKey);
            if (srcClient) srcClient.packetsSent++;
            return;
        }

        // Type=1 в твоих логах — это 8-байтовый heartbeat/NAT keepalive.
        // Многие клиенты ожидают "ack" от relay (echo) прежде чем слать следующие стадии (P2P/sync).
        // Поэтому делаем echo обратно отправителю + релейим (если есть кому).
        const isHeartbeatType1 = payloadType === 1 && payload.length === 8;
        if (isHeartbeatType1) {
            log.info(`[UDP] Heartbeat(type=1) from ${clientKey} -> echo ack + relay (${this.clients.size - 1} other(s))`);
            this._sendPingResponse(rinfo, msg); // echo original packet (with relay header)
            this._relayToOtherClient(clientKey, rinfo, destPort, payload);

            const srcClient = this.clients.get(clientKey);
            if (srcClient) srcClient.packetsSent++;
            return;
        }
        
        // Handle other packet types that might be important for race synchronization
        // Type 11 (0x0B) - seen in IDA analysis, might be sync packets
        // Type 0x676E6B73 ("sknG") - magic value for packet validation (P2P connection setup)
        // This magic value appears at offset ~28 bytes in the packet, not at the start
        // Packet format: [1 byte: 0x45][...][28 bytes offset: 0x676E6B73][timestamp][data...]
        const magicValue = 0x676E6B73; // "sknG" in little endian
        const magicBytes = Buffer.from([0x73, 0x6B, 0x6E, 0x67]); // "sknG" as bytes
        
        // Search for magic value anywhere in payload (not just offset 28)
        let magicOffset = -1;
        if (payload.length >= 4) {
            // Check at offset 28 first (expected location)
            if (payload.length >= 32) {
                if (payload.readUInt32LE(28) === magicValue || payload.readUInt32BE(28) === magicValue) {
                    magicOffset = 28;
                }
            }
            // Also search anywhere in payload
            if (magicOffset === -1) {
                const idx = payload.indexOf(magicBytes);
                if (idx >= 0) magicOffset = idx;
            }
        }
        const hasMagicValue = magicOffset >= 0;
        
        // Check if packet starts with 0x45 (P2P connection packet)
        const isP2PConnectionPacket = payload.length > 0 && payload[0] === 0x45;
        
        // Log ALL packets that might be P2P connection packets for debugging
        if (isP2PConnectionPacket || hasMagicValue || payload.length > 30) {
            log.info(`[UDP] Potential P2P packet from ${clientKey}: type=${payloadType}, startsWith0x45=${isP2PConnectionPacket}, hasMagic=${hasMagicValue}@${magicOffset}, len=${payload.length}, hex=${payloadHex}${payload.length > 32 ? '...' : ''}`);
        }
        
        if (payloadType === 11 || payloadType === magicValue || hasMagicValue || isP2PConnectionPacket) {
            log.info(`[UDP] Special packet from ${clientKey}: type=${payloadType}, hasMagic=${hasMagicValue}@${magicOffset}, isP2P=${isP2PConnectionPacket}, len=${payload.length}, full hex: ${payload.toString('hex')}`);
            this._relayToOtherClient(clientKey, rinfo, destPort, payload);
            
            const srcClient = this.clients.get(clientKey);
            if (srcClient) srcClient.packetsSent++;
            return;
        }
        
        // Log unknown packet types for debugging
        if (payloadType !== 0 && payloadType !== 1 && payloadType !== 5) {
            log.info(`[UDP] Unknown packet type=${payloadType} (0x${payloadType.toString(16)}) from ${clientKey}, payload=${payloadHex.substring(0, 32)}...`);
        }
        
        // Check for P2P handshake packets (start with 0x45, contain magic 0x676E6B73)
        const isP2PPacket = payload.length >= 36 && payload[0] === 0x45;
        if (isP2PPacket) {
            const hasMagic = payload.length >= 32 && payload.readUInt32LE(28) === 0x676E6B73;
            log.info(`[UDP] *** REAL P2P PACKET from ${clientKey}: ${payload.length} bytes, magic=${hasMagic ? 'YES' : 'NO'}, hex: ${payloadHex.substring(0, 72)}`);
        }
        
        // Log large packets - they might contain race synchronization data
        if (payload.length > 50 && !isP2PPacket) {
            log.info(`[UDP] Large packet from ${clientKey}: ${payload.length} bytes, type=${payloadType}, first 64 bytes: ${payloadHex.substring(0, 128)}`);
        }
        
        // IMPORTANT: All non-probe packets should be relayed to ensure race synchronization works
        // Don't drop any packets - they might be critical for race start
        // Only skip if it's a probe packet (handled below)

        // Check for keepalive/probe packets
        // These have invalid destination (0.0.0.0) or special port values
        // Packet 0100000000000000 = port 256, IP 0.0.0.0, payload 0000 - this is a probe/heartbeat
        const isProbePacket = destIP === '0.0.0.0' || 
                              (destPort === 256 && payload.length <= 4) ||
                              (destPort === 1 && payload.length <= 4);
        
        if (isProbePacket) {
            // Count other clients for this game
            const otherCount = this.clients.size - 1;
            
            if (otherCount === 0) {
                // Solo player - just echo back to confirm relay is alive
                // Build response with relay server's info so game knows relay works
                const response = this._buildRelayPacket(rinfo.address, rinfo.port, payload);
                log.debug(`[UDP] Heartbeat from ${clientKey} (solo) - sending relay ack`);
                this.server.send(response, rinfo.port, rinfo.address);
            } else {
                // Multiple players - relay the heartbeat to others
                log.info(`[UDP] Heartbeat from ${clientKey} - relaying to ${otherCount} other(s)`);
                this._relayToOtherClient(clientKey, rinfo, destPort, payload);
            }
            return;
        }

        // Validate destination for real relay packets
        if (destPort === 0) {
            log.warn(`[UDP] Invalid relay dest ${destIP}:${destPort} from ${clientKey}, broadcasting to all`);
            this._relayToOtherClient(clientKey, rinfo, destPort, payload);
            return;
        }

        const destKey = `${destIP}:${destPort}`;

        // For relay mode: ALWAYS relay to other clients
        // The destination IP in the header is the "intended" peer, but since we're
        // doing full relay, we forward to all other registered clients instead
        // 
        // IMPORTANT: For race synchronization, we need to relay ALL packets between players
        // Some packets might be critical for race start even if they're not type=5
        // 
        // Check if dest is relay server IP (meaning client wants broadcast)
        // or if dest is localhost/same-IP (LAN mode)
        const isRelayDest = destIP === rinfo.address || 
                           destIP === '127.0.0.1' ||
                           this._isRelayServerIP(destIP);
        
        // Always relay to all other clients in relay mode
        // This ensures all synchronization packets reach all players
        if (isRelayDest || this.clients.size <= 3 || true) {  // Force broadcast mode for now
            // Relay to all other clients
            // Log important packets for debugging race start issues
            if (payload.length > 8 || payloadType !== 0 && payloadType !== 1 && payloadType !== 5) {
                log.info(`[UDP] Relay mode: ${clientKey} -> all other clients (dest was ${destIP}:${destPort}, type=${payloadType}, len=${payload.length})`);
            } else {
                log.debug(`[UDP] Relay mode: ${clientKey} -> all other clients (dest was ${destIP}:${destPort}, type=${payloadType})`);
            }
            this._relayToOtherClient(clientKey, rinfo, destPort, payload);
        } else {
            // Try to relay to specific destination (if it's a known client)
            const forwardPacket = this._buildRelayPacket(rinfo.address, rinfo.port, payload);
            
            // Check if destination is a registered client
            if (this.clients.has(destKey)) {
                const destClient = this.clients.get(destKey);
                this.server.send(forwardPacket, destClient.port, destClient.address, (err) => {
                    if (err) {
                        log.warn(`[UDP] Failed to relay to ${destKey}: ${err.message}`);
                        // Fallback to broadcast if direct relay fails
                        this._relayToOtherClient(clientKey, rinfo, destPort, payload);
                    } else {
                        log.debug(`[UDP] Relayed ${forwardPacket.length} bytes to ${destKey} (type=${payloadType})`);
                    }
                });
            } else {
                // Unknown dest - broadcast to all
                log.debug(`[UDP] Unknown dest ${destKey}, broadcasting to all (type=${payloadType})`);
                this._relayToOtherClient(clientKey, rinfo, destPort, payload);
            }
        }

        const srcClient = this.clients.get(clientKey);
        if (srcClient) srcClient.packetsSent++;
    }

    _sendPingResponse(rinfo, originalMsg) {
        // Echo back the ping packet
        // This confirms to client that relay server is reachable
        try {
            this.server.send(originalMsg, rinfo.port, rinfo.address, (err) => {
                if (err) {
                    log.debug(`[UDP] Ping response failed: ${err.message}`);
                } else {
                    log.debug(`[UDP] Ping response sent to ${rinfo.address}:${rinfo.port}`);
                }
            });
        } catch (e) {
            log.error(`[UDP] Ping response error: ${e.message}`);
        }
    }

    _relayToOtherClient(srcKey, srcRinfo, destPort, payload) {
        // For localhost/same-IP testing: find other clients and relay to them
        // This allows game instances on same machine/NAT to communicate
        
        // Get game ID for source client to filter by same game
        const srcGameId = this.clientToGame.get(srcKey);
        
        // Find all other clients from the same game (exclude source)
        const otherClients = [];
        for (const [key, client] of this.clients.entries()) {
            if (key !== srcKey) {
                const clientGameId = this.clientToGame.get(key);
                // Only include clients from the same game, or if gameId is not set, include all
                if (!srcGameId || !clientGameId || clientGameId === srcGameId) {
                    otherClients.push({ key, ...client });
                }
            }
        }

        // Build packet with source info in relay header
        // Format: [2 bytes src port][4 bytes src IP][payload]
        const forwardPacket = this._buildRelayPacket(srcRinfo.address, srcRinfo.port, payload);
        
        // Determine payload type for logging
        const payloadType = payload.length >= 4 ? payload.readUInt32LE(0) : 0;
        const payloadHex = payload.slice(0, Math.min(16, payload.length)).toString('hex');

        if (otherClients.length === 0) {
            // No other clients connected yet - buffer the packet
            // Check if we're expecting more clients for this game
            const gameId = this.clientToGame.get(srcKey);
            const expectedClients = gameId ? this.expectedClients.get(gameId) : null;
            
            // Count connected clients from the same game
            const connectedSameGame = gameId ? 
                Array.from(this.clients.keys()).filter(k => this.clientToGame.get(k) === gameId).length :
                this.clients.size;
            
            if (expectedClients && expectedClients.size > connectedSameGame) {
                // We're expecting more clients - buffer this packet
                if (!this.packetBuffer.has(srcKey)) {
                    this.packetBuffer.set(srcKey, []);
                }
                this.packetBuffer.get(srcKey).push({
                    data: forwardPacket,
                    timestamp: Date.now(),
                    type: payloadType
                });
                
                log.info(`[UDP] Buffering packet from ${srcKey} (type=${payloadType}, len=${payload.length}) - waiting for other clients (${connectedSameGame}/${expectedClients.size} connected for game ${gameId})`);
                
                // Limit buffer size to prevent memory issues
                const buffer = this.packetBuffer.get(srcKey);
                if (buffer.length > 100) {
                    buffer.shift(); // Remove oldest packet
                    log.warn(`[UDP] Packet buffer for ${srcKey} exceeded 100 packets, dropping oldest`);
                }
            } else {
                if (!gameId) {
                    log.warn(`[UDP] No other clients to relay to from ${srcKey} - client not associated with any game!`);
                } else {
                    log.warn(`[UDP] No other clients to relay to from ${srcKey} (game=${gameId}, connected=${connectedSameGame}, expected=${expectedClients?.size || 'unknown'})`);
                }
            }
            return;
        }

        log.info(`[UDP] Relaying from ${srcKey} to ${otherClients.length} other client(s) [type=${payloadType}, payload=${payloadHex}...]`);

        // Send to all other clients
        for (const client of otherClients) {
            // Log BEFORE sending to ensure we see the attempt
            log.debug(`[UDP] Sending ${forwardPacket.length} bytes to ${client.address}:${client.port} ...`);
            
            this.server.send(forwardPacket, client.port, client.address, (err) => {
                if (err) {
                    log.error(`[UDP] SEND FAILED to ${client.key}: ${err.message} (code=${err.code})`);
                } else {
                    log.info(`[UDP] SENT OK ${forwardPacket.length} bytes: ${srcKey} -> ${client.key} [type=${payloadType}]`);
                    const c = this.clients.get(client.key);
                    if (c) c.packetsRecv++;
                }
            });
        }

        const srcClient = this.clients.get(srcKey);
        if (srcClient) srcClient.packetsSent++;
    }

    _relayByDestPort(srcKey, srcRinfo, destPort, payload) {
        // Try to find a client by destination port
        // Used when dest IP is invalid but port is specified
        
        for (const [key, client] of this.clients.entries()) {
            if (key !== srcKey && client.port === destPort) {
                const forwardPacket = this._buildRelayPacket(srcRinfo.address, srcRinfo.port, payload);
                this.server.send(forwardPacket, client.port, client.address, (err) => {
                    if (!err) {
                        log.info(`[UDP] Relayed by port ${destPort}: ${srcKey} -> ${key}`);
                    }
                });
                return true;
            }
        }
        return false;
    }

    _broadcastToOthers(srcKey, originalMsg) {
        // Broadcast raw packet to all other clients (no header modification)
        // Used for game packets that bypass relay header
        for (const [key, client] of this.clients.entries()) {
            if (key !== srcKey) {
                this.server.send(originalMsg, client.port, client.address, (err) => {
                    if (!err) {
                        log.debug(`[UDP] Broadcast (raw) to ${client.address}:${client.port}`);
                        client.packetsRecv++;
                    }
                });
            }
        }
    }

    _broadcastWrapped(srcKey, wrappedPacket) {
        // Broadcast packet WITH relay header to all other clients
        // Used when we need to add source info to outgoing packets
        for (const [key, client] of this.clients.entries()) {
            if (key !== srcKey) {
                this.server.send(wrappedPacket, client.port, client.address, (err) => {
                    if (!err) {
                        log.debug(`[UDP] Broadcast (wrapped) to ${client.address}:${client.port}`);
                        client.packetsRecv++;
                    }
                });
            }
        }
    }

    _broadcastToGame(srcKey, srcRinfo, originalMsg) {
        // Broadcast packet to all other clients WITH relay header
        // Used when destination is invalid (0.0.0.0:0)
        const forwardPacket = this._buildRelayPacket(srcRinfo.address, srcRinfo.port, originalMsg);

        for (const [key, client] of this.clients.entries()) {
            if (key !== srcKey) {
                this.server.send(forwardPacket, client.port, client.address, (err) => {
                    if (!err) {
                        log.debug(`[UDP] Broadcast (relay) to ${client.address}:${client.port}`);
                        client.packetsRecv++;
                    }
                });
            }
        }
    }

    _buildRelayPacket(ip, port, payload) {
        // Build packet with 6-byte header: [port in network order][IP]
        // 
        // The client stores port in NETWORK byte order (sin_port is already BE)
        // and reads it back the same way. So we need to write BE too.
        // 
        // rinfo.port is in HOST order (a regular JS number), so we use writeUInt16BE
        // to convert it to network order.
        const header = Buffer.alloc(6);
        header.writeUInt16BE(port, 0);
        
        const ipParts = ip.split('.').map(Number);
        header[2] = ipParts[0] || 127;
        header[3] = ipParts[1] || 0;
        header[4] = ipParts[2] || 0;
        header[5] = ipParts[3] || 1;
        
        return Buffer.concat([header, payload]);
    }

    _isRelayServerIP(ip) {
        // Check if IP is our relay server's public IP
        // This is used to detect when client wants to "broadcast" via relay
        const relayIP = config.server?.publicIP || '185.23.18.117';
        return ip === relayIP;
    }

    _updateClient(key, rinfo) {
        const isNew = !this.clients.has(key);
        
        // Try to associate client with game by IP address
        // Clients may connect with different ports than registered, so match by IP only
        if (isNew) {
            // Check if this IP belongs to any registered game
            const clientIP = rinfo.address;
            let associatedGameId = null;
            
            // Check if this IP belongs to any registered game
            if (this.expectedClients.size > 0) {
                log.debug(`[UDP] Checking ${this.expectedClients.size} registered games for IP ${clientIP}`);
                for (const [gameId, expectedSet] of this.expectedClients.entries()) {
                    log.debug(`[UDP] Game ${gameId} has ${expectedSet.size} expected clients`);
                    for (const expectedAddr of expectedSet) {
                        const [expectedIP] = expectedAddr.split(':');
                        log.debug(`[UDP] Comparing ${clientIP} with ${expectedIP} from ${expectedAddr}`);
                        if (expectedIP === clientIP) {
                            associatedGameId = gameId;
                            this.clientToGame.set(key, gameId);
                            log.info(`[UDP] ✓ Associated client ${key} with game ${gameId} by IP ${clientIP}`);
                            break;
                        }
                    }
                    if (associatedGameId) break;
                }
            } else {
                log.debug(`[UDP] No games registered yet, client ${key} will be associated when game registers`);
            }
            
            log.info(`[UDP] New relay client: ${key} (total clients: ${this.clients.size + 1}, game=${associatedGameId || 'none'})`);
        }

        const oldClient = this.clients.get(key);
        this.clients.set(key, {
            address: rinfo.address,
            port: rinfo.port,
            lastSeen: Date.now(),
            packetsSent: oldClient?.packetsSent || 0,
            packetsRecv: oldClient?.packetsRecv || 0,
        });
        
        // Log client list for debugging race start issues
        if (isNew) {
            const clientList = Array.from(this.clients.keys()).join(', ');
            log.info(`[UDP] Active clients (${this.clients.size}): ${clientList}`);
            
            // Send multiple test packets to new client to verify connectivity
            // These should appear in client logs as [IAT-RECVFROM] if received
            const sendTestPackets = () => {
                // Test 1: Echo back the original packet (should trigger NAT mapping response)
                log.info(`[UDP] Sending echo test packet to ${key}...`);
                
                // Test 2: Send a simple 8-byte packet with type=0x99 (unusual type for easy identification)
                const testPayload = Buffer.from([0x99, 0x99, 0x99, 0x99, 0x00, 0x00, 0x00, 0x00]);
                const testPacket = this._buildRelayPacket(rinfo.address, rinfo.port, testPayload);
                
                log.info(`[UDP] Test packet hex: ${testPacket.toString('hex')}`);
                log.info(`[UDP] Sending to ${rinfo.address}:${rinfo.port} from server port ${this.server.address().port}`);
                
                this.server.send(testPacket, rinfo.port, rinfo.address, (err) => {
                    if (err) {
                        log.error(`[UDP] Test packet to ${key} FAILED: ${err.message} (code=${err.code})`);
                    } else {
                        log.info(`[UDP] Test packet SENT to ${key} (${testPacket.length} bytes)`);
                    }
                });
                
                // Test 3: Send multiple times with delay to ensure NAT mapping is established
                setTimeout(() => {
                    this.server.send(testPacket, rinfo.port, rinfo.address, (err) => {
                        if (!err) log.info(`[UDP] Test packet #2 SENT to ${key}`);
                    });
                }, 100);
                
                setTimeout(() => {
                    this.server.send(testPacket, rinfo.port, rinfo.address, (err) => {
                        if (!err) log.info(`[UDP] Test packet #3 SENT to ${key}`);
                    });
                }, 200);
            };
            
            // Send test packets immediately
            sendTestPackets();
            
            // Check if all expected clients are connected
            const gameId = this.clientToGame.get(key);
            if (gameId) {
                const expectedClients = this.expectedClients.get(gameId);
                if (expectedClients) {
                    const connectedCount = Array.from(this.clients.keys()).filter(k => 
                        this.clientToGame.get(k) === gameId
                    ).length;
                    
                    log.info(`[UDP] Game ${gameId}: ${connectedCount}/${expectedClients.size} clients connected`);
                    
                    if (connectedCount >= expectedClients.size) {
                        log.info(`[UDP] All expected clients connected for game ${gameId}!`);
                        // All clients connected - flush any remaining buffered packets
                        this._flushBufferedPackets(key);
                        // NOTE: Fake P2P handshakes DISABLED - may interfere with real handshake
                        // this._sendFakeP2PHandshakes(gameId);
                    } else if (this.clients.size >= 2) {
                        // At least 2 clients connected - flush buffered packets
                        this._flushBufferedPackets(key);
                    }
                }
            } else {
                log.warn(`[UDP] Client ${key} not associated with any game - packets may not be relayed correctly`);
            }
        }
    }
    
    _flushBufferedPackets(newClientKey) {
        // Send all buffered packets from other clients to the new client
        const newClient = this.clients.get(newClientKey);
        if (!newClient) return;
        
        const gameId = this.clientToGame.get(newClientKey);
        const expectedClients = gameId ? this.expectedClients.get(gameId) : null;
        const connectedClients = gameId ? 
            Array.from(this.clients.keys()).filter(k => this.clientToGame.get(k) === gameId) : 
            Array.from(this.clients.keys());
        
        let flushedCount = 0;
        for (const [srcKey, packets] of this.packetBuffer.entries()) {
            if (srcKey !== newClientKey && packets.length > 0) {
                // Only flush if packets are from the same game
                const srcGameId = this.clientToGame.get(srcKey);
                if (srcGameId === gameId) {
                    log.info(`[UDP] Flushing ${packets.length} buffered packets from ${srcKey} to new client ${newClientKey}`);
                    
                    for (const packet of packets) {
                        this.server.send(packet.data, newClient.port, newClient.address, (err) => {
                            if (err) {
                                log.warn(`[UDP] Failed to flush buffered packet: ${err.message}`);
                            } else {
                                flushedCount++;
                            }
                        });
                    }
                    
                    // Only clear buffer if all expected clients are connected
                    // Otherwise keep it for other clients that might connect later
                    if (expectedClients && connectedClients.length >= expectedClients.size) {
                        log.info(`[UDP] All clients connected, clearing buffer for ${srcKey}`);
                        this.packetBuffer.delete(srcKey);
                    }
                }
            }
        }
        
        if (flushedCount > 0) {
            log.info(`[UDP] Flushed ${flushedCount} buffered packets to ${newClientKey}`);
        }
    }

    // Register a game session - called from TCP server when game starts
    registerGame(gameId, clientAddresses) {
        // Clear old packet buffers when new game starts
        this.packetBuffer.clear();
        
        // Extract IP addresses from client addresses (format: "ip:port")
        const expectedIPs = new Set();
        for (const addr of clientAddresses) {
            const [ip] = addr.split(':');
            expectedIPs.add(ip);
        }
        
        // clientAddresses: array of "ip:port" strings
        const clientSet = new Set(clientAddresses);
        this.gameClients.set(gameId, clientSet);
        this.expectedClients.set(gameId, new Set(clientAddresses));
        
        // Associate already connected clients with this game by IP address
        // Clients may connect with different ports than registered
        let associatedCount = 0;
        for (const [clientKey, client] of this.clients.entries()) {
            if (expectedIPs.has(client.address)) {
                this.clientToGame.set(clientKey, gameId);
                associatedCount++;
                log.info(`[UDP] Associated existing client ${clientKey} with game ${gameId} by IP ${client.address}`);
            }
        }
        
        // Also store mapping by registered addresses (for reference)
        for (const addr of clientAddresses) {
            // Store mapping by IP only (without port) for flexible matching
            const [ip] = addr.split(':');
            // Store full address mapping too
            this.clientToGame.set(addr, gameId);
        }
        
        log.info(`[UDP] Registered game ${gameId} with ${clientAddresses.length} clients: ${clientAddresses.join(', ')}`);
        if (associatedCount > 0) {
            log.info(`[UDP] Associated ${associatedCount} already connected clients with game ${gameId}`);
            
            // Check if all expected clients are already connected
            const expectedClients = this.expectedClients.get(gameId);
            if (expectedClients) {
                const connectedCount = Array.from(this.clients.keys()).filter(k => 
                    this.clientToGame.get(k) === gameId
                ).length;
                
                log.info(`[UDP] Game ${gameId}: ${connectedCount}/${expectedClients.size} clients connected`);
                
                if (connectedCount >= expectedClients.size) {
                    log.info(`[UDP] All expected clients already connected for game ${gameId}!`);
                    // NOTE: Fake P2P handshakes DISABLED - may interfere with real handshake
                    // this._sendFakeP2PHandshakes(gameId);
                }
            }
        }
    }

    // Unregister a game session
    unregisterGame(gameId) {
        const clients = this.gameClients.get(gameId);
        if (clients) {
            for (const addr of clients) {
                this.clientToGame.delete(addr);
            }
            this.gameClients.delete(gameId);
            this.sentFakeP2P.delete(gameId); // Clear fake P2P flag
            
            // Clear periodic fake P2P packet interval
            const intervalId = this.fakeP2PIntervals.get(gameId);
            if (intervalId) {
                clearInterval(intervalId);
                this.fakeP2PIntervals.delete(gameId);
                log.info(`[UDP] Stopped periodic fake P2P packet sending for game ${gameId}`);
            }
            
            log.info(`[UDP] Unregistered game ${gameId}`);
        }
    }

    _cleanup() {
        const now = Date.now();
        let removed = 0;
        const packetTimeout = 10000; // 10 seconds - packets older than this are dropped

        // Clean up stale clients
        for (const [key, client] of this.clients) {
            if (now - client.lastSeen > (config.timeouts?.client || 300000)) {
                this.clients.delete(key);
                this.clientToGame.delete(key);
                this.packetBuffer.delete(key);
                removed++;
            }
        }

        // Clean up old buffered packets
        for (const [key, packets] of this.packetBuffer.entries()) {
            const filtered = packets.filter(p => now - p.timestamp < packetTimeout);
            if (filtered.length !== packets.length) {
                log.debug(`[UDP] Cleaned up ${packets.length - filtered.length} old buffered packets from ${key}`);
                if (filtered.length === 0) {
                    this.packetBuffer.delete(key);
                } else {
                    this.packetBuffer.set(key, filtered);
                }
            }
        }

        if (removed > 0) {
            log.debug(`[UDP] Cleaned up ${removed} stale relay clients`);
        }
    }

    _onError(err) {
        log.error('[UDP] Server error:', err.message);
    }

    getClientCount() {
        return this.clients.size;
    }

    /**
     * Generate fake P2P handshake packet to trick game into thinking P2P connection is established
     * Format based on sub_756710:
     * - v20[0] = 0x45 (69)
     * - v20[2]: LOBYTE = v6 (from a2+56), BYTE1 = 1
     * - v20[4] = IP address (4 bytes: HIBYTE, BYTE2, BYTE1, LOBYTE of a1)
     * - v20[5]: LOBYTE = 8, BYTE2/HIBYTE = checksum
     * - v20[6]: LOWORD = a5, BYTE2/HIBYTE = other data
     * - v20[7] = 0x676E6B73 (1733513331, magic "sknG")
     * - v20[8] = GetTickCount()
     * - v20[9]... = data (a3)
     * Size: (((a4 + 3) & 0x7FFC) + 36) bytes
     */
    _createFakeP2PPacket(fromIP, toIP) {
        // Convert IPs to bytes
        const fromIPBytes = fromIP.split('.').map(Number);
        
        // Create packet buffer (36 bytes minimum, no data)
        const packet = Buffer.alloc(36);
        packet.fill(0);
        
        // v20[0] = 0x45 (69) - first byte
        packet[0] = 0x45;
        
        // v20[2]: LOBYTE = v6 (unknown, use 0), BYTE1 = 1
        // v20[2] is at offset 8 (2 * 4 bytes), but we need to set individual bytes
        // BYTE1(v20[2]) = 1 means byte at offset 8+1 = 9
        // LOBYTE(v20[2]) = v6 means byte at offset 8+0 = 8
        packet[8] = 0x00; // LOBYTE(v20[2]) = v6 (use 0)
        packet[9] = 0x01; // BYTE1(v20[2]) = 1
        
        // v20[4] = IP address (4 bytes, little endian)
        // v20[4] is at offset 16 (4 * 4 bytes)
        // IP bytes: LOBYTE = fromIPBytes[3], BYTE1 = fromIPBytes[2], BYTE2 = fromIPBytes[1], HIBYTE = fromIPBytes[0]
        packet[16] = fromIPBytes[3]; // LOBYTE(v20[4])
        packet[17] = fromIPBytes[2]; // BYTE1(v20[4])
        packet[18] = fromIPBytes[1]; // BYTE2(v20[4])
        packet[19] = fromIPBytes[0]; // HIBYTE(v20[4])
        
        // v20[5]: LOBYTE = 8
        // v20[5] is at offset 20 (5 * 4 bytes)
        packet[20] = 0x08; // LOBYTE(v20[5]) = 8
        
        // v20[6]: LOWORD = a5 (use 0), BYTE2/HIBYTE = other data
        // v20[6] is at offset 24 (6 * 4 bytes)
        packet[24] = 0x00; // LOWORD LOBYTE
        packet[25] = 0x00; // LOWORD BYTE1
        
        // v20[7] = 0x676E6B73 (magic "sknG")
        // v20[7] is at offset 28 (7 * 4 bytes)
        packet.writeUInt32LE(0x676E6B73, 28);
        
        // v20[8] = GetTickCount() (timestamp)
        // v20[8] is at offset 32 (8 * 4 bytes)
        // GetTickCount() returns milliseconds since system boot, but we'll use current time modulo 2^32
        // Use >>> 0 to convert to unsigned 32-bit integer
        const timestamp = Date.now() >>> 0;
        packet.writeUInt32LE(timestamp, 32);
        
        // Calculate checksum (from sub_756710: checksum of v20[5] onwards, excluding checksum bytes)
        // Formula: v9 = (((a4 + 3) & 0x7FFC) + 16), checksum from v20[5] for v9 bytes
        // But exclude BYTE2 and HIBYTE of v20[5] (bytes 22-23) from checksum calculation
        const dataSize = 0; // No data (a4 = 0)
        const v9 = (((dataSize + 3) & 0x7FFC) + 16); // = 16 bytes
        const checksumStart = 20; // v20[5] offset
        
        // Calculate checksum: sum 16-bit words from v20[5], skipping checksum bytes (22-23)
        // Use >>> 0 to ensure unsigned arithmetic
        let checksum = 0;
        // Sum from offset 20 (LOBYTE v20[5]) to 21 (BYTE1 v20[5]), skip 22-23 (checksum), then 24-35
        checksum = (checksum + ((packet[20] << 8) | packet[21])) >>> 0; // LOBYTE and BYTE1 of v20[5]
        // Skip bytes 22-23 (checksum bytes - will be filled later)
        for (let i = 24; i < checksumStart + v9 && i + 1 < packet.length; i += 2) {
            checksum = (checksum + ((packet[i] << 8) | packet[i + 1])) >>> 0;
        }
        // Handle odd byte if any
        if (checksumStart + v9 - 1 < packet.length && (checksumStart + v9 - 1) % 2 === 0) {
            checksum = (checksum + (packet[checksumStart + v9 - 1] << 8)) >>> 0;
        }
        
        // Final checksum: ~(checksum + HIWORD(checksum) + (checksum >> 16))
        const hiword = (checksum >>> 16) & 0xFFFF;
        const sumWithHiword = (checksum + hiword) >>> 0;
        const finalChecksum = (~(sumWithHiword + (sumWithHiword >>> 16))) & 0xFFFF;
        
        // Store checksum in BYTE2 and HIBYTE of v20[5] (bytes 22-23)
        packet[22] = (finalChecksum >> 8) & 0xFF; // BYTE2(v20[5])
        packet[23] = finalChecksum & 0xFF; // HIBYTE(v20[5])
        
        return packet; // Return 36 bytes
    }

    /**
     * Send fake P2P handshake packets between all clients in a game
     * This tricks the game into thinking P2P connection is established
     * Sends packets periodically every 30 seconds (like the game does)
     */
    _sendFakeP2PHandshakes(gameId) {
        log.info(`[UDP] _sendFakeP2PHandshakes called for game ${gameId}`);
        
        // Check if we already set up periodic sending for this game
        if (this.sentFakeP2P.has(gameId)) {
            log.info(`[UDP] Fake P2P packets already set up for game ${gameId}, skipping`);
            return; // Already set up
        }
        
        const gameClients = Array.from(this.clients.keys()).filter(k => 
            this.clientToGame.get(k) === gameId
        );
        
        log.info(`[UDP] Game ${gameId} has ${gameClients.length} clients: ${gameClients.join(', ')}`);
        
        if (gameClients.length < 2) {
            log.warn(`[UDP] Not enough clients for game ${gameId} (need 2, have ${gameClients.length}), skipping fake P2P`);
            return; // Need at least 2 clients
        }
        
        // Mark as set up
        this.sentFakeP2P.add(gameId);
        
        // Get opponent IP addresses from +ses response (expectedClients)
        // These are the IPs that were sent in +ses ADDR field, not relay IPs
        const expectedClientsSet = this.expectedClients.get(gameId);
        if (!expectedClientsSet || expectedClientsSet.size < 2) {
            log.warn(`[UDP] Cannot send fake P2P packets: expectedClients not found or < 2 for game ${gameId}`);
            return;
        }
        
        // Map clientKey -> opponent IP from +ses
        // expectedClientsSet contains IPs that were sent in +ses ADDR field
        const clientToOpponentIP = new Map();
        const expectedIPs = Array.from(expectedClientsSet).map(addr => addr.split(':')[0]);
        
        log.info(`[UDP] Creating IP mapping for game ${gameId}: expectedIPs=${expectedIPs.join(', ')}, gameClients=${gameClients.join(', ')}`);
        
        for (const fromKey of gameClients) {
            const fromClient = this.clients.get(fromKey);
            if (!fromClient) continue;
            
            // Find opponent IP: the IP from expectedClients that is NOT fromClient's IP
            // This is the IP that was sent to fromClient in +ses ADDR field as opponent
            const opponentIP = expectedIPs.find(ip => ip !== fromClient.address);
            if (opponentIP) {
                clientToOpponentIP.set(fromKey, opponentIP);
                log.info(`[UDP] Mapped client ${fromKey} (relay IP ${fromClient.address}) -> opponent IP ${opponentIP} from +ses`);
            } else {
                log.warn(`[UDP] Could not find opponent IP for client ${fromKey} (relay IP ${fromClient.address}) in expectedIPs: ${expectedIPs.join(', ')}`);
            }
        }
        
        if (clientToOpponentIP.size < 2) {
            log.warn(`[UDP] Not enough IP mappings (${clientToOpponentIP.size}/2), cannot send fake P2P packets`);
            return;
        }
        
        // Function to send fake P2P packets for this game
        const sendPackets = () => {
            const currentClients = Array.from(this.clients.keys()).filter(k => 
                this.clientToGame.get(k) === gameId
            );
            
            if (currentClients.length < 2) {
                // Not enough clients, stop sending
                const intervalId = this.fakeP2PIntervals.get(gameId);
                if (intervalId) {
                    clearInterval(intervalId);
                    this.fakeP2PIntervals.delete(gameId);
                }
                return;
            }
            
            log.info(`[UDP] Sending periodic fake P2P handshake packets for game ${gameId} (${currentClients.length} clients)`);
            
            // Send fake P2P packet from each client to every other client
            for (let i = 0; i < currentClients.length; i++) {
                const fromKey = currentClients[i];
                const fromClient = this.clients.get(fromKey);
                if (!fromClient) continue;
                
                // Get opponent IP from +ses (not relay IP)
                const fromOpponentIP = clientToOpponentIP.get(fromKey);
                if (!fromOpponentIP) {
                    log.warn(`[UDP] No opponent IP found for client ${fromKey}, skipping`);
                    continue;
                }
                
                for (let j = 0; j < currentClients.length; j++) {
                    if (i === j) continue; // Don't send to self
                    
                    const toKey = currentClients[j];
                    const toClient = this.clients.get(toKey);
                    if (!toClient) continue;
                    
                    // Get opponent IP for recipient (the IP that recipient expects in P2P packets)
                    // When sending from A to B, the packet should contain opponent IP of B
                    // (which is A's IP from +ses response sent to B)
                    const recipientOpponentIP = clientToOpponentIP.get(toKey);
                    if (!recipientOpponentIP) {
                        log.warn(`[UDP] No opponent IP found for recipient ${toKey}, skipping`);
                        continue;
                    }
                    
                    // Create fake P2P packet: from opponent IP of recipient (recipientOpponentIP)
                    // This is the IP that recipient expects to receive P2P packets from
                    // Example: if B received +ses with ADDR=193.32.248.173, then recipientOpponentIP=193.32.248.173
                    // So we send packet with fromIP=193.32.248.173 (the opponent from B's perspective)
                    // toIP parameter is not used in _createFakeP2PPacket, but we pass it for logging
                    const fakePacket = this._createFakeP2PPacket(recipientOpponentIP, toClient.address);
                    
                    // Build relay packet with fromClient's info as source
                    const relayPacket = this._buildRelayPacket(fromClient.address, fromClient.port, fakePacket);
                    
                    // Send to toClient
                    this.server.send(relayPacket, toClient.port, toClient.address, (err) => {
                        if (err) {
                            log.warn(`[UDP] Failed to send periodic fake P2P packet from ${fromKey} to ${toKey}: ${err.message}`);
                        } else {
                            const fakeHex = fakePacket.toString('hex').substring(0, 72);
                            log.info(`[UDP] ✓ Sent periodic fake P2P packet: ${fromKey} -> ${toKey}, opponent IP ${recipientOpponentIP}, hex: ${fakeHex}`);
                        }
                    });
                }
            }
        };
        
        // Wait a bit for clients to process +ses response before sending first fake P2P packets
        setTimeout(() => {
            // Send initial packets (3 rounds with 200ms delay)
            for (let round = 0; round < 3; round++) {
                setTimeout(() => {
                    const currentClients = Array.from(this.clients.keys()).filter(k => 
                        this.clientToGame.get(k) === gameId
                    );
                    
                    if (currentClients.length < 2) return;
                    
                    for (let i = 0; i < currentClients.length; i++) {
                        const fromKey = currentClients[i];
                        const fromClient = this.clients.get(fromKey);
                        if (!fromClient) continue;
                        
                        for (let j = 0; j < currentClients.length; j++) {
                            if (i === j) continue;
                            
                            const toKey = currentClients[j];
                            const toClient = this.clients.get(toKey);
                            if (!toClient) continue;
                            
                            // Get opponent IP for recipient (the IP that recipient expects in P2P packets)
                            const recipientOpponentIP = clientToOpponentIP.get(toKey);
                            if (!recipientOpponentIP) {
                                log.warn(`[UDP] No opponent IP found for recipient ${toKey} in initial send, skipping`);
                                continue;
                            }
                            
                            // Create fake P2P packet with opponent IP from +ses (not relay IP)
                            const fakePacket = this._createFakeP2PPacket(recipientOpponentIP, toClient.address);
                            const relayPacket = this._buildRelayPacket(fromClient.address, fromClient.port, fakePacket);
                            
                            this.server.send(relayPacket, toClient.port, toClient.address, (err) => {
                                if (err) {
                                    log.warn(`[UDP] Failed to send initial fake P2P packet (round ${round + 1}) from ${fromKey} to ${toKey}: ${err.message}`);
                                } else {
                                    const hexDump = fakePacket.toString('hex').substring(0, 72);
                                    log.info(`[UDP] ✓ Sent initial fake P2P handshake (round ${round + 1}): ${fromKey} -> ${toKey}, using opponent IP ${recipientOpponentIP} from +ses, hex: ${hexDump}`);
                                }
                            });
                        }
                    }
                }, round * 200);
            }
            
            // Set up periodic sending every 30 seconds (like the game does)
            const intervalId = setInterval(sendPackets, 30000);
            this.fakeP2PIntervals.set(gameId, intervalId);
            log.info(`[UDP] Set up periodic fake P2P packet sending for game ${gameId} (every 30 seconds)`);
        }, 500); // 500ms delay to let clients process +ses
    }

    getStats() {
        let totalSent = 0;
        let totalRecv = 0;

        for (const client of this.clients.values()) {
            totalSent += client.packetsSent;
            totalRecv += client.packetsRecv;
        }

        return {
            clients: this.clients.size,
            packetsSent: totalSent,
            packetsRecv: totalRecv,
        };
    }
}

export default UDPServer;
