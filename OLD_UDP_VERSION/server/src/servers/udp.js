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
        
        log.debug(`[UDP] RELAY from ${clientKey}: dest=${destIP}:${destPort}, payload=${payload.length}b`);

        // Check if payload is a type=5 "broadcast" packet
        // In full relay mode, even type=5 packets come with relay header
        // The payload starts with 05 00 00 00 if it's a broadcast packet
        const payloadType = payload.length >= 4 ? payload.readUInt32LE(0) : 0;
        if (payloadType === 5) {
            // This is a game broadcast packet - send to all other players
            const payloadHex = payload.slice(0, Math.min(16, payload.length)).toString('hex');
            log.info(`[UDP] Broadcast packet (type=5) from ${clientKey}: dest=${destIP}:${destPort}, payload=${payloadHex}...`);
            log.info(`[UDP] Broadcasting type=5 to ${this.clients.size - 1} other client(s)`);
            this._relayToOtherClient(clientKey, rinfo, destPort, payload);
            
            const srcClient = this.clients.get(clientKey);
            if (srcClient) srcClient.packetsSent++;
            return;
        }

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
        // Check if dest is relay server IP (meaning client wants broadcast)
        // or if dest is localhost/same-IP (LAN mode)
        const isRelayDest = destIP === rinfo.address || 
                           destIP === '127.0.0.1' ||
                           this._isRelayServerIP(destIP);
        
        if (isRelayDest || this.clients.size <= 3) {
            // Relay to all other clients
            log.info(`[UDP] Relay mode: ${clientKey} -> all other clients (dest was ${destIP}:${destPort})`);
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
                    } else {
                        log.info(`[UDP] Relayed ${forwardPacket.length} bytes to ${destKey}`);
                    }
                });
            } else {
                // Unknown dest - broadcast to all
                log.warn(`[UDP] Unknown dest ${destKey}, broadcasting to all`);
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
        
        // Find all other clients (exclude source)
        const otherClients = [];
        for (const [key, client] of this.clients.entries()) {
            if (key !== srcKey) {
                otherClients.push({ key, ...client });
            }
        }

        if (otherClients.length === 0) {
            log.warn(`[UDP] No other clients to relay to from ${srcKey}`);
            return;
        }

        // Build packet with source info in relay header
        // Format: [2 bytes src port][4 bytes src IP][payload]
        const forwardPacket = this._buildRelayPacket(srcRinfo.address, srcRinfo.port, payload);

        log.info(`[UDP] Relaying from ${srcKey} to ${otherClients.length} other client(s)`);

        // Send to all other clients
        for (const client of otherClients) {
            this.server.send(forwardPacket, client.port, client.address, (err) => {
                if (err) {
                    log.warn(`[UDP] Relay to ${client.key} failed: ${err.message}`);
                } else {
                    log.info(`[UDP] Relayed ${forwardPacket.length} bytes: ${srcKey} -> ${client.key}`);
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
        
        if (isNew) {
            log.info(`[UDP] New relay client: ${key}`);
        }

        this.clients.set(key, {
            address: rinfo.address,
            port: rinfo.port,
            lastSeen: Date.now(),
            packetsSent: this.clients.get(key)?.packetsSent || 0,
            packetsRecv: this.clients.get(key)?.packetsRecv || 0,
        });
    }

    // Register a game session - called from TCP server when game starts
    registerGame(gameId, clientAddresses) {
        // Clear old clients when new game starts - prevents stale connections
        log.info(`[UDP] Clearing ${this.clients.size} old clients before new game`);
        this.clients.clear();
        
        // clientAddresses: array of "ip:port" strings
        const clientSet = new Set(clientAddresses);
        this.gameClients.set(gameId, clientSet);
        
        for (const addr of clientAddresses) {
            this.clientToGame.set(addr, gameId);
        }
        
        log.info(`[UDP] Registered game ${gameId} with ${clientAddresses.length} clients`);
    }

    // Unregister a game session
    unregisterGame(gameId) {
        const clients = this.gameClients.get(gameId);
        if (clients) {
            for (const addr of clients) {
                this.clientToGame.delete(addr);
            }
            this.gameClients.delete(gameId);
            log.info(`[UDP] Unregistered game ${gameId}`);
        }
    }

    _cleanup() {
        const now = Date.now();
        let removed = 0;

        for (const [key, client] of this.clients) {
            if (now - client.lastSeen > (config.timeouts?.client || 300000)) {
                this.clients.delete(key);
                this.clientToGame.delete(key);
                removed++;
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
