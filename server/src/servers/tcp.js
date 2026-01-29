// ============================================================================
// NFSU2 Server - TCP Game Server
// Based on captured traffic from NFSOR server (ug2.nfsor.net)
// 
// Protocol flow (from capture):
// 1. Client connects to port 20921 - SSL handshake
// 2. After SSL, client connects to port 20923 - EA protocol
// 3. EA Protocol: [4-byte CMD][4-byte STATUS][4-byte LEN][PAYLOAD]
// 
// Commands observed:
// - AUTH: Authentication (PROD, VERS, PRES, USER, LKEY)
// - EPGT: Endpoint Get (LRSC, ID) -> (ENAB, ID, ADDR)
// - RGET: Roster Get (LRSC, LIST, PRES, PEND, ID) -> (SIZE, ID)
// - ROST: Roster response
// - PSET: Presence Set (SHOW, STAT, PROD)
// - DISC: Disconnect
// ============================================================================

import net from 'net';
import tls from 'tls';
import fs from 'fs';
import path from 'path';
import { createLogger } from '../utils/logger.js';
import config from '../config.js';
import database from '../database/index.js';

const log = createLogger('TCP');

class TCPServer {
    constructor(udpServer = null) {
        this.sslServer = null;
        this.gameServer = null;
        this.clients = new Map();
        this.games = new Map();       // Active games: gameId -> game object
        this.nextClientId = 1;
        this.nextGameId = 800;        // Start game IDs from 800 (like NFSOR)
        this.udpServer = udpServer;   // Reference to UDP relay for game registration
        
        // Try to load SSL certs (optional)
        this.sslOptions = null;
        try {
            const certPath = path.join(process.cwd(), 'certs');
            if (fs.existsSync(path.join(certPath, 'server.key'))) {
                this.sslOptions = {
                    key: fs.readFileSync(path.join(certPath, 'server.key')),
                    cert: fs.readFileSync(path.join(certPath, 'server.crt')),
                    // Allow self-signed
                    rejectUnauthorized: false,
                };
                log.info('SSL certificates loaded');
            }
        } catch (e) {
            log.warn('No SSL certs found, SSL port will be disabled');
        }
    }

    start() {
        // Port layout (matching NFSOR ug2.nfsor.net):
        // 20920 - Base port
        // 20921 - SSL/TLS handshake for authentication  
        // 20922 - Ping/keepalive
        // 20923 - Main EA text protocol (AUTH, PSET, EPGT, RGET, DISC)
        
        const ports = config.ports;
        
        // Start main EA protocol server on port 20923 (EA Messenger)
        this.gameServer = net.createServer((socket) => {
            const localPort = socket.localPort;
            log.info(`>>> NEW CONNECTION on port ${localPort} (EA Messenger) from ${socket.remoteAddress}:${socket.remotePort}`);
            this._onGameConnection(socket);
        });
        this.gameServer.on('error', (err) => log.error(`Game server error (${ports.game}):`, err.message));
        this.gameServer.listen(ports.game, '0.0.0.0', () => {
            log.info(`EA Protocol server (EA Messenger) listening on port ${ports.game}`);
        });

        // Start SSL server on port 20921
        if (this.sslOptions) {
            this.sslServer = tls.createServer(this.sslOptions, (socket) => this._onSSLConnection(socket));
            this.sslServer.on('error', (err) => log.error(`SSL server error (${ports.ssl}):`, err.message));
            this.sslServer.listen(ports.ssl, '0.0.0.0', () => {
                log.info(`SSL Auth server listening on port ${ports.ssl}`);
            });
        } else {
            // Create plain TCP that handles custom EA SSL handshake
            // From capture: client sends 0x801C0100... server responds with certificate
            const sslHandshakeServer = net.createServer((socket) => this._onSSLHandshake(socket));
            sslHandshakeServer.on('error', (err) => log.error(`SSL handshake server error (${ports.ssl}):`, err.message));
            sslHandshakeServer.listen(ports.ssl, '0.0.0.0', () => {
                log.info(`SSL Handshake server listening on port ${ports.ssl} (custom EA protocol)`);
            });
        }

        // Ping/keepalive server on port 20922
        const pingServer = net.createServer((socket) => this._onPingConnection(socket));
        pingServer.on('error', (err) => {
            if (err.code !== 'EADDRINUSE') log.error(`Ping server error (${ports.ping}):`, err.message);
        });
        pingServer.listen(ports.ping, '0.0.0.0', () => {
            log.info(`Ping server listening on port ${ports.ping}`);
        });

        // Also listen on base port 20920
        const baseServer = net.createServer((socket) => this._onGameConnection(socket));
        baseServer.on('error', (err) => {
            if (err.code !== 'EADDRINUSE') log.error(`Base server error (${ports.base}):`, err.message);
        });
        baseServer.listen(ports.base, '0.0.0.0', () => {
            log.info(`Base server listening on port ${ports.base}`);
        });

        // UDP-over-TCP tunnel server on port 20924
        // This is more reliable than raw UDP for NAT traversal
        const udpTunnelPort = ports.udpTunnel || 20924;  // Fallback to 20924
        this.udpTunnelClients = new Map(); // clientKey -> { socket, gameId, address }
        this.udpTunnelServer = net.createServer((socket) => this._onUdpTunnelConnection(socket));
        this.udpTunnelServer.on('error', (err) => {
            if (err.code !== 'EADDRINUSE') log.error(`UDP tunnel server error (${udpTunnelPort}):`, err.message);
        });
        this.udpTunnelServer.listen(udpTunnelPort, '0.0.0.0', () => {
            log.info(`UDP-over-TCP tunnel server listening on port ${udpTunnelPort}`);
        });

        return this;
    }

    stop() {
        this.sslServer?.close();
        this.gameServer?.close();
        log.info('TCP servers stopped');
    }

    _onSSLConnection(socket) {
        const clientId = this.nextClientId++;
        const addr = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        log.info(`[${clientId}] SSL connection from ${addr}`);
        
        // SSL is just for authentication, then game switches to port+3
        socket.on('data', (data) => {
            log.info(`[${clientId}] SSL data: ${data.length} bytes`);
        });
        socket.on('close', () => {
            log.info(`[${clientId}] SSL connection closed`);
        });
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') {
                log.error(`[${clientId}] SSL error: ${err.message}`);
            }
        });
    }

    _onSSLHandshake(socket) {
        // Handle EA's custom SSL-like handshake without real TLS
        // From capture: client sends 0x801C0100... 
        // Server responds with certificate data (0x833E0400 + X.509 cert)
        //
        // HOWEVER: When client has SSL disabled by patches, it will send
        // @tic/@dir directly (starts with 0x40 '@') instead of SSL hello!
        // In that case, we treat this as a regular game connection.
        
        const clientId = this.nextClientId++;
        const addr = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        log.info(`[${clientId}] SSL Handshake connection from ${addr}`);
        
        let state = 'WAIT_HELLO';  // WAIT_HELLO -> WAIT_KEY_EXCHANGE -> ESTABLISHED
        let client = null;  // Will be created if we switch to game mode
        
        socket.on('data', (data) => {
            const hexStr = data.toString('hex').substring(0, 64);
            
            // Check if this looks like @tic/@dir (SSL was patched/disabled)
            // '@' = 0x40, '@tic' = 40 74 69 63, '@dir' = 40 64 69 72
            if (state === 'WAIT_HELLO' && data[0] === 0x40) {
                log.info(`[${clientId}] Detected @tic/@dir instead of SSL - client has SSL disabled!`);
                log.info(`[${clientId}] Switching to regular game connection mode`);
                
                // Create a game client and process this data
                client = {
                    id: clientId,
                    socket: socket,
                    address: addr,
                    buffer: Buffer.alloc(0),
                    authenticated: false,
                    sessionId: null,
                };
                this.clients.set(clientId, client);
                
                // Process this data as game data
                state = 'GAME_MODE';
                client.buffer = Buffer.concat([client.buffer, data]);
                this._onData(client, data);
                return;
            }
            
            // If we're in game mode, process as game data
            if (state === 'GAME_MODE' && client) {
                client.buffer = Buffer.concat([client.buffer, data]);
                this._onData(client, data);
                return;
            }
            
            log.info(`[${clientId}] SSL Handshake <<< ${data.length} bytes (state=${state}): ${hexStr}...`);
            
            // Check for initial handshake (0x801C0100...)
            if (state === 'WAIT_HELLO' && data.length >= 4 && data[0] === 0x80 && data[1] === 0x1C) {
                log.info(`[${clientId}] Received EA SSL ClientHello`);
                this._sendSSLCertificate(socket, clientId);
                state = 'WAIT_KEY_EXCHANGE';
            }
            // Handle key exchange (0x808A...)
            else if (state === 'WAIT_KEY_EXCHANGE' && data.length >= 4 && data[0] === 0x80 && data[1] === 0x8A) {
                log.info(`[${clientId}] Received EA SSL key exchange (${data.length} bytes)`);
                this._sendSSLKeyResponse(socket, clientId);
                state = 'ESTABLISHED';
            }
            // Handle subsequent encrypted messages
            else if (state === 'ESTABLISHED') {
                log.info(`[${clientId}] SSL encrypted data: ${data.length} bytes`);
                // Forward to game protocol handler or respond appropriately
            }
            else {
                log.warn(`[${clientId}] Unexpected SSL data in state ${state}: ${hexStr}...`);
            }
        });
        
        socket.on('close', () => {
            log.info(`[${clientId}] SSL Handshake connection closed`);
            if (client) {
                this.clients.delete(clientId);
            }
        });
        
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') {
                log.error(`[${clientId}] SSL Handshake error: ${err.message}`);
            }
        });
    }

    _sendSSLCertificate(socket, clientId) {
        // EA's custom SSL certificate response
        // From captured NFSOR traffic: 4-byte header + 828-byte X.509 certificate
        // Header: 0x833E0400 where 0x033E = 830 (cert length + 2)
        // Certificate: OTG3 Certificate Authority (Electronic Arts)
        
        try {
            // Load certificate from file (captured from real NFSOR server)
            const certPath = path.join(process.cwd(), 'certs', 'ea_ssl_certificate.bin');
            let certificate;
            
            if (fs.existsSync(certPath)) {
                certificate = fs.readFileSync(certPath);
                log.info(`[${clientId}] Loaded SSL certificate from file (${certificate.length} bytes)`);
            } else {
                log.error(`[${clientId}] SSL certificate file not found: ${certPath}`);
                log.error(`[${clientId}] Please capture certificate using CAPTURE_CERT_MODE=1`);
                socket.destroy();
                return;
            }
            
            // Header: 0x83 0x3E 0x04 0x00 
            // 0x833E in little-endian = certificate length + 2 (830 = 828 + 2)
            const header = Buffer.from([0x83, 0x3E, 0x04, 0x00]);
            
            // Send header first, then certificate
            socket.write(header);
            socket.write(certificate);
            log.info(`[${clientId}] >>> Sent SSL certificate response (${header.length + certificate.length} bytes)`);
        } catch (err) {
            log.error(`[${clientId}] Failed to send SSL cert: ${err.message}`);
        }
    }

    _sendSSLKeyResponse(socket, clientId) {
        // Response to key exchange from captured traffic
        // After client sends 140 bytes (0x808A...), server responds with:
        // 4 bytes header + 15 bytes data = 19 bytes total
        // Then more encrypted exchanges follow
        
        // First response: 80 11 + 2 random bytes, then 15 bytes
        // From capture: 80 11 E1 64 | 4F 1C 11 18 A9 67 29 E3 23 05 B8 C8 62 04 49
        const response1 = Buffer.from([
            0x80, 0x11, 0xE1, 0x64,  // Header
            0x4F, 0x1C, 0x11, 0x18, 0xA9, 0x67, 0x29, 0xE3, 
            0x23, 0x05, 0xB8, 0xC8, 0x62, 0x04, 0x49
        ]);
        
        try {
            socket.write(response1);
            log.info(`[${clientId}] >>> Sent SSL key response 1 (${response1.length} bytes)`);
        } catch (err) {
            log.error(`[${clientId}] Failed to send SSL key response: ${err.message}`);
        }
    }

    _onPingConnection(socket) {
        // Port 20922 - Main FESL protocol port!
        // After @tic/@dir on port 20921, client connects here for:
        // ?tic (verify encryption), addr, skey, news, sele, auth, pers, etc.
        const clientId = this.nextClientId++;
        const addr = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        
        const client = {
            id: clientId,
            socket: socket,
            address: addr,
            port: socket.remotePort || 0,
            buffer: Buffer.alloc(0),
            user: null,
            persona: null,
            session: null,
            authenticated: false,
            presence: 'CHAT',
            requestId: 0,
            pingInterval: null,  // Will be set after auth
            lastPingTime: Date.now(),
        };
        
        this.clients.set(clientId, client);
        log.info(`[${clientId}] FESL connection from ${addr} (port 20922)`);
        
        socket.setKeepAlive(true, 30000);
        socket.setNoDelay(true);
        
        // Start ping interval immediately (NFSOR sends ping even before auth)
        // Ping every 16 seconds like real NFSOR
        this._startPingInterval(client);
        
        socket.on('data', (data) => {
            client.buffer = Buffer.concat([client.buffer, data]);
            const hexStr = data.toString('hex').substring(0, 80);
            const asciiStr = data.toString('latin1').replace(/[^\x20-\x7E]/g, '.').substring(0, 40);
            log.info(`[${clientId}] <<< ${data.length} bytes: ${hexStr}`);
            log.debug(`[${clientId}] ASCII: ${asciiStr}`);
            
            // Update last activity time
            client.lastPingTime = Date.now();
            
            // Process accumulated buffer
            this._processFeslBuffer(client);
        });
        
        socket.on('close', () => {
            log.info(`[${clientId}] FESL connection closed`);
            this._stopPingInterval(client);
            this._onClose(client);
        });
        
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') {
                log.error(`[${clientId}] FESL error: ${err.message}`);
            }
        });
        
        socket.setTimeout(300000);
    }
    
    _startPingInterval(client) {
        // Send ~png every 16 seconds like real NFSOR
        // This keeps the connection alive and syncs time
        if (client.pingInterval) {
            clearInterval(client.pingInterval);
        }
        
        // Send first ping after short delay (let client initialize)
        setTimeout(() => {
            if (client.socket && !client.socket.destroyed) {
                this._sendServerPing(client);
            }
        }, 1000);  // First ping after 1 second
        
        client.pingInterval = setInterval(() => {
            if (client.socket && !client.socket.destroyed) {
                this._sendServerPing(client);
            } else {
                this._stopPingInterval(client);
            }
        }, 16000);  // Every 5 seconds
        
        log.info(`[${client.id}] Started ping interval (first in 1s, then every 5s)`);
    }
    
    _stopPingInterval(client) {
        if (client.pingInterval) {
            clearInterval(client.pingInterval);
            client.pingInterval = null;
            log.info(`[${client.id}] Stopped ping interval`);
        }
    }
    
    _sendServerPing(client) {
        // Send ~png to client
        // Format: ~png + status(0) + length + "REF=YYYY-MM-DD\n"
        const today = new Date().toISOString().split('T')[0];  // YYYY-MM-DD
        
        this._sendFeslResponse(client, '~png', {
            'REF': today,
        });
        
        log.info(`[${client.id}] >>> Server ~png ping sent (REF=${today})`);
    }
    
    _processFeslBuffer(client) {
        // Process fesl protocol buffer
        // Commands: ?tic, addr, skey, news, sele, auth, pers, user, onln, gsea, etc.
        
        while (client.buffer.length >= 12) {
            const cmdStr = client.buffer.slice(0, 4).toString('latin1');
            
            // Check for ?tic (encryption verification)
            if (cmdStr === '?tic') {
                const packetLen = client.buffer.readUInt32BE(8);
                if (client.buffer.length < packetLen) break;
                
                log.info(`[${client.id}] ?tic received (${packetLen} bytes) - encryption verified`);
                
                // Send 0xFFFFFFFF/-1 ready signal
                const readyPacket = Buffer.alloc(12);
                readyPacket.writeUInt32BE(0xFFFFFFFF, 0);  // cmd = 0xFFFFFFFF
                readyPacket.writeInt32BE(-1, 4);  // status = -1
                readyPacket.writeUInt32BE(12, 8);  // length = 12
                
                client.socket.write(readyPacket);
                log.info(`[${client.id}] >>> Ready signal (0xFFFFFFFF/-1)`);
                
                client.buffer = client.buffer.slice(packetLen);
                client.encryptionVerified = true;
                continue;
            }
            
            // Check if this is a known fesl command
            if (this._isFeslCommand(client.buffer)) {
                this._processFeslProtocol(client);
                return;  // _processFeslProtocol handles the buffer
            }
            
            // Unknown command - skip 1 byte
            log.warn(`[${client.id}] Unknown FESL data: ${cmdStr} (0x${client.buffer.slice(0, 4).toString('hex')})`);
            client.buffer = client.buffer.slice(1);
        }
    }

    _onGameConnection(socket) {
        const clientId = this.nextClientId++;
        
        const client = {
            id: clientId,
            socket: socket,
            address: socket.remoteAddress?.replace('::ffff:', '') || 'unknown',
            port: socket.remotePort || 0,
            buffer: Buffer.alloc(0),
            user: null,
            persona: null,
            session: null,
            authenticated: false,
            presence: 'CHAT',
            requestId: 0,
        };

        this.clients.set(clientId, client);
        log.info(`[${clientId}] Game connection from ${client.address}:${client.port}`);

        socket.setKeepAlive(true, 30000);
        socket.setNoDelay(true);

        socket.on('data', (data) => this._onData(client, data));
        socket.on('close', () => this._onClose(client));
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') {
                log.error(`[${clientId}] Error: ${err.message}`);
            }
        });
        socket.on('timeout', () => {
            log.warn(`[${clientId}] Timeout`);
            socket.end();
        });

        socket.setTimeout(300000); // 5 min timeout
    }

    _onData(client, data) {
        // Append to buffer
        client.buffer = Buffer.concat([client.buffer, data]);
        
        // Log raw data
        const hexStr = data.toString('hex').substring(0, 64);
        log.info(`[${client.id}] <<< ${data.length} bytes: ${hexStr}...`);
        
        // Check for @tic/@dir text protocol (starts with '@')
        if (client.buffer[0] === 0x40) { // '@' = 0x40
            this._processTextProtocol(client);
        } 
        // Check for lowercase fesl protocol (addr, skey, news, etc)
        else if (this._isFeslCommand(client.buffer)) {
            this._processFeslProtocol(client);
        }
        else {
            // Binary EA protocol
            this._processBuffer(client);
        }
    }
    
    _isFeslCommand(buffer) {
        // fesl commands: addr, skey, news, auth, acct, etc (lowercase or special, 4 chars)
        if (buffer.length < 4) return false;
        const cmd = buffer.slice(0, 4).toString('latin1');
        const feslCommands = [
            'addr', 'skey', 'news', 'auth', 'acct', 'pers', 'sele', 'user', 'onln',
            'cper',  // create persona
            'dper',  // delete persona
            'sper',  // select persona (login with persona)
            'llvl',  // lobby level
            'gsea',  // game search
            'gget',  // get game info
            'glea',  // leave game
            'gjoi',  // join game
            'gset',  // set game flags (ready status)
            'gsta',  // game start (host starts the race)
            'gcre',  // create game
            'gdel',  // delete/destroy game (host command)
            'usld',  // user load (stats)
            'gpsc',  // get persona count?
            'rank',  // ranking
            'lost',  // password recovery
            'snap',  // snapshot?
            'auxi',  // auxiliary data (car customization)
            '~png',  // ping/keepalive
            '+sst',  // stats update (push)
        ];
        return feslCommands.includes(cmd);
    }
    
    _processFeslProtocol(client) {
        // fesl protocol: cmd(4) + status(4 BE) + length(4 BE) + data
        // Length includes the 12-byte header!
        
        while (client.buffer.length >= 12) {
            const cmd = client.buffer.slice(0, 4).toString('latin1');
            const status = client.buffer.readUInt32BE(4);
            const packetLen = client.buffer.readUInt32BE(8);
            
            if (packetLen < 12 || packetLen > 65536) {
                log.warn(`[${client.id}] fesl ${cmd}: invalid length ${packetLen}, skipping byte`);
                client.buffer = client.buffer.slice(1);
                continue;
            }
            
            if (client.buffer.length < packetLen) {
                log.debug(`[${client.id}] fesl ${cmd}: waiting for more data (have ${client.buffer.length}, need ${packetLen})`);
                break;
            }
            
            log.info(`[${client.id}] fesl '${cmd}' received (${packetLen} bytes, status=${status})`);
            
            // Extract data after header
            const dataStr = client.buffer.slice(12, packetLen).toString('latin1');
            
            // Parse KEY=VALUE pairs
            const fields = {};
            const lines = dataStr.split('\n');
            for (const line of lines) {
                const eqIdx = line.indexOf('=');
                if (eqIdx > 0) {
                    const key = line.substring(0, eqIdx).replace(/\x00/g, '').trim();
                    const value = line.substring(eqIdx + 1).replace(/\x00/g, '').trim();
                    if (key) fields[key] = value;
                }
            }
            
            log.info(`[${client.id}] fesl '${cmd}' fields:`, fields);
            
            // Handle specific commands
            switch (cmd) {
                case 'addr':
                    // Client reporting its address (local/LAN IP)
                    client.reportedAddr = fields.ADDR;
                    client.reportedPort = fields.PORT;
                    client.localAddr = fields.ADDR;  // Store as local address for +who
                    log.info(`[${client.id}] ADDR: Local=${fields.ADDR}:${fields.PORT}`);
                    this._sendFeslResponse(client, 'addr', {});
                    break;
                    
                case 'skey':
                    // Session key from client
                    client.sessionKey = fields.SKEY;
                    this._sendFeslResponse(client, 'skey', {});
                    break;
                    
                case 'news':
                    // News request - NAME=7 means config/settings request
                    // From captured real NFSOR traffic, this returns HUGE config with tier points!
                    const newsId = (fields.NAME || '0').replace(/\x00/g, '').trim();
                    log.info(`[${client.id}] News request ID: '${newsId}'`);
                    
                    // Send full news/config response like real NFSOR server
                    // NOTE: Status must be 'news7' (0x6E657737) for ID=7!
                    this._sendFeslResponseWithStatus(client, 'news', 0x6E657737, {
                        'TOSURL': 'http://127.0.0.1/nfsu2/tos',
                        'CIRCUIT_TIER_POINTS': '0,1999,4999,9999,19999,39999,59999,79999,99999,119999',
                        'DRAG_TIER_POINTS': '0,1999,4999,9999,19999,39999,59999,79999,99999,119999',
                        'URL_TIER_POINTS': '0,1999,4999,9999,19999,39999,59999,79999,99999,119999',
                        'BUDDY_SERVER': '127.0.0.1',
                        'BUDDY_PORT': '20923',
                        'STREET_CROSS_TIER_POINTS': '0,1999,4999,9999,19999,39999,59999,79999,99999,119999',
                        'NEWSURL': 'http://127.0.0.1/nfsu2/news',
                        'SPRINT_TIER_POINTS': '0,1999,4999,9999,19999,39999,59999,79999,99999,119999',
                        'DRIFT_TIER_POINTS': '0,1999,4999,9999,19999,39999,59999,79999,99999,119999',
                    });
                    break;
                    
                case 'sele':
                    // Select - game mode selection, stats request
                    // CLIENT: MYGAME=1, STATS=5000, ASYNC=1, MESGS=1
                    // SERVER from NFSOR: ROOMS=1, SLOTS=32, USERSET=1, MORE=1, MYGAME=1, RANKS=1, GAMES=2, ASYNC=1, STATS=500, MESGS=1, USERS=5
                    client.gameMode = fields.MYGAME;
                    client.wantsMessenger = fields.MESGS === '1';
                    
                    log.info(`[${client.id}] SELE: MYGAME=${fields.MYGAME}, STATS=${fields.STATS}, MESGS=${fields.MESGS}`);
                    
                    // Send sele response EXACTLY like NFSOR!
                    this._sendFeslResponse(client, 'sele', {
                        'ROOMS': '1',      // Number of rooms/lobbies
                        'SLOTS': '32',     // Max slots per game
                        'USERSET': '1',    // User settings enabled
                        'MORE': '1',       // More data available
                        'MYGAME': fields.MYGAME || '1',  // Echo back MYGAME
                        'RANKS': '1',      // Rankings enabled
                        'GAMES': '2',      // Number of active games (can be dynamic)
                        'ASYNC': fields.ASYNC || '1',   // Async mode
                        'STATS': '500',    // Stats limit
                        'MESGS': fields.MESGS || '1',   // Messenger enabled
                        'USERS': String(this.clients.size),  // Online users count
                    });
                    break;
                    
                case 'auth':
                    // Authentication/login (after acct created)
                    this._handleFeslAuth(client, fields);
                    break;
                    
                case 'lost':
                    // Password recovery request
                    // CLIENT: NAME=<username> or MAIL=<email>, FROM=US, LANG=EN
                    // SERVER: empty response (status 0 = request received)
                    // Real server would send email with recovery link
                    const lostName = fields.NAME;
                    const lostMail = fields.MAIL;
                    log.info(`[${client.id}] LOST: Password recovery request - NAME=${lostName || 'N/A'}, MAIL=${lostMail || 'N/A'}`);
                    
                    // Just acknowledge the request (we don't actually send emails)
                    this._sendFeslResponse(client, 'lost', {});
                    break;
                    
                case 'acct':
                    // Account creation/registration request
                    // Fields: REGN, CLST, NETV, FROM, LANG, MID, PROD, VERS, SLUS, SKU, 
                    //         NAME, PASS, MAIL, BORN, GEND, SPAM, TOS, MASK
                    this._handleAcct(client, fields);
                    break;
                    
                case 'pers':
                    // Persona selection/login - this is the final step before EA Messenger!
                    // After pers, client will disconnect and reconnect to port 20923
                    const persona = fields.PERS || fields.NAME || 'Player';
                    client.persona = persona;
                    
                    // Generate 32-char hex LKEY (must match what client sends to EA Messenger)
                    const lkeyHex = [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
                    client.lkey = lkeyHex;
                    
                    // Store session for EA Messenger auth
                    if (client.user) {
                        database.updateSession(client.session?.odId, {
                            lkey: lkeyHex,
                            persona: persona,
                        });
                    }
                    
                    log.info(`[${client.id}] PERS: Persona '${persona}' selected, LKEY=${lkeyHex.substring(0,8)}...`);
                    log.info(`[${client.id}] PERS: Client should now connect to BUDDY_SERVER:BUDDY_PORT for EA Messenger`);
                    
                    // Send pers response - match REAL NFSOR protocol exactly!
                    // From captured traffic, pers response contains:
                    // LKEY, PERS, LAST, PLAST, NAME (NO ADDR/PORT - client uses BUDDY_* from conf!)
                    this._sendFeslResponse(client, 'pers', {
                        'LKEY': lkeyHex,  // 32-char hex key for EA Messenger auth
                        'PERS': persona,
                        'LAST': '2006.12.8 15:51:58',  // Last login time
                        'PLAST': '2006.12.8 16:51:40', // Last persona use time
                        'NAME': client.user?.name || persona,  // Account name
                    });
                    
                    // Send stats update after persona selection (like NFSOR does)
                    setTimeout(() => {
                        this._sendStatsUpdate(client);
                    }, 100);
                    break;
                    
                case 'onln':
                    // Check if persona is online
                    // CLIENT: PERS=<persona_name>
                    // SERVER: I=0 (not online) or I=<id> (online)
                    this._handleOnlineCheck(client, fields);
                    break;
                    
                case 'gsta':
                    // Game start - host signals to start the race
                    // CLIENT: NAME=069.usersssss
                    // SERVER: empty response, then +ses to all players
                    log.info(`[${client.id}] >>> GSTA received! fields: ${JSON.stringify(fields)}`);
                    this._handleGameStart(client, fields);
                    break;
                    
                case 'user':
                    // User info request (NOT auth!)
                    // CLIENT: PERS=test
                    // SERVER: LMSTAT=, STAT=0,0,0,0,..., LGAME=
                    this._handleUserInfo(client, fields);
                    break;
                    
                case 'llvl':
                    // Lobby level
                    this._sendFeslResponse(client, 'llvl', {
                        'LLVL': '1',
                    });
                    break;
                    
                case 'gsea':
                    // Game search
                    // CLIENT: START=0, COUNT=20, CUSTFLAGS=67109107, CUSTMASK=67109363, SYSFLAGS=0, SYSMASK=786432
                    // SERVER: COUNT=N + multiple +gam pushes for each game
                    this._handleGameSearch(client, fields);
                    break;
                    
                case 'gget':
                    // Get game info by name
                    this._handleGameGet(client, fields);
                    break;
                    
                case 'gjoi':
                    // Join game
                    // CLIENT: NAME=292.vpotoke
                    // SERVER: Full game info + player info via +who and +mgm
                    this._handleGameJoin(client, fields);
                    break;
                    
                case 'gset':
                    // Set game flags (player ready status, etc.)
                    // CLIENT: NAME=292.vpotoke, USERFLAGS=0 (or 134217728 for ready)
                    this._handleGameSet(client, fields);
                    break;
                    
                case 'glea':
                    // Leave game
                    this._handleGameLeave(client, fields);
                    break;
                    
                case 'gdel':
                    // Delete/destroy game (host command)
                    // CLIENT: NAME=079.debil123
                    // SERVER: empty response, then +who with G=0
                    this._handleGameDelete(client, fields);
                    break;
                    
                case 'gcre':
                    // Create game
                    this._handleGameCreate(client, fields);
                    break;
                    
                case 'auxi':
                    // Auxiliary data (car customization data)
                    // CLIENT: TEXT=<base64 encoded car data>
                    this._handleAuxi(client, fields);
                    break;
                    
                case 'usld':
                    // User load (stats)
                    this._sendFeslResponse(client, 'usld', {});
                    break;
                    
                case 'gpsc':
                    // Get persona?
                    this._sendFeslResponse(client, 'gpsc', {
                        'COUNT': '0',
                    });
                    break;
                    
                case 'cper':
                    // Create persona - PERS=<persona_name>
                    this._handleCreatePersona(client, fields);
                    break;
                    
                case 'dper':
                    // Delete persona
                    this._sendFeslResponse(client, 'dper', {});
                    break;
                    
                case 'sper':
                    // Select persona (login with persona)
                    this._handleSelectPersona(client, fields);
                    break;
                    
                case 'rank':
                    // Ranking request
                    this._sendFeslResponse(client, 'rank', {
                        'RANK': '1',
                        'SCORE': '0',
                    });
                    break;
                    
                case 'snap':
                    // Leaderboard/ranking snapshot
                    // CLIENT: INDEX=1, CHAN=12, RANGE=1, FIND=$ (or START=0 for range query)
                    // SERVER: snap response + multiple +snp pushes
                    this._handleSnapRequest(client, fields);
                    break;
                    
                case '~png':
                    // Ping/keepalive
                    // CLIENT: REF=2026-01-25, TIME=187
                    // SERVER: REF=2026-01-25 (echo back)
                    const pingRef = fields.REF || new Date().toISOString().split('T')[0];
                    this._sendFeslResponse(client, '~png', { 'REF': pingRef });
                    break;
                    
                case '+sst':
                    // Stats update (server pushes this, but client might echo)
                    // Ignore or log
                    log.debug(`[${client.id}] +sst received (stats update)`);
                    break;
                    
                default:
                    log.warn(`[${client.id}] Unhandled fesl command: ${cmd}`);
                    this._sendFeslResponse(client, cmd, {});
            }
            
            // Remove processed packet
            client.buffer = client.buffer.slice(packetLen);
        }
    }
    
    _sendFeslResponse(client, cmd, fields) {
        this._sendFeslResponseWithStatus(client, cmd, 0, fields);
    }
    
    _sendFeslResponseWithStatus(client, cmd, status, fields) {
        // Build response in EA text protocol format:
        // [4 bytes cmd][4 bytes status][4 bytes total_length][payload]
        // Total length includes the 12-byte header
        let data = '';
        for (const [key, value] of Object.entries(fields)) {
            data += `${key}=${value}\n`;
        }
        
        const body = Buffer.from(data, 'latin1');
        const totalLen = 12 + body.length;  // header(12) + payload
        
        const packet = Buffer.alloc(totalLen);
        // Command (4 bytes)
        packet.write(cmd.substring(0, 4).padEnd(4, '\0'), 0, 'latin1');
        // Status (4 bytes) - use Int32 to support negative values like -1
        packet.writeInt32BE(status, 4);
        // Length (4 bytes) - total packet length including header
        packet.writeUInt32BE(totalLen, 8);
        // Payload
        body.copy(packet, 12);
        
        try {
            client.socket.write(packet);
            log.info(`[${client.id}] >>> fesl '${cmd}' response (${packet.length} bytes)`);
            log.debug(`[${client.id}] fesl '${cmd}' body: ${data.replace(/\n/g, ', ').slice(0, 100)}`);
        } catch (err) {
            log.error(`[${client.id}] Failed to send fesl response: ${err.message}`);
        }
    }
    
    _handleAcct(client, fields) {
        // Account creation/registration request
        // Fields: NAME, PASS, MAIL, BORN, GEND, TOS, etc.
        const name = fields.NAME || '';
        const pass = fields.PASS || '';
        const mail = fields.MAIL || '';
        const tos = parseInt(fields.TOS) || 0;
        const prod = fields.PROD || 'nfs-pc-2005';
        
        log.info(`[${client.id}] ACCT: Creating account for name=${name} mail=${mail} tos=${tos}`);
        
        // Store TOS acceptance and user info in client
        client.tosAccepted = (tos >= 1);
        client.userName = name;
        client.userPass = pass;
        client.userMail = mail;
        client.product = prod;
        
        if (!client.tosAccepted) {
            log.warn(`[${client.id}] ACCT: TOS not accepted in acct request`);
        }
        
        // Try to get or create user in database
        let dbUser = database.getUser(name);
        if (!dbUser) {
            const result = database.createUser(name, pass, mail);
            if (result.success) {
                dbUser = result.user;
                log.info(`[${client.id}] ACCT: New user registered: ${name}`);
                // Don't auto-create persona - player will create via 'cper' command
            } else {
                log.warn(`[${client.id}] ACCT: Failed to create user: ${result.error}`);
            }
        }
        
        client.user = dbUser || { name: name, id: Date.now(), personas: [] };
        
        // Generate session/persona key
        const lkey = '$' + Math.random().toString(16).slice(2, 14);
        client.lkey = lkey;
        
        // Get personas list - for NEW accounts this should be EMPTY!
        // From capture: PERSONAS= (empty) when account is new
        // After creating persona via 'cper', it becomes PERSONAS=usersssss,
        const personas = dbUser?.personas || [];
        
        // If account was just created (no personas yet), return empty
        // Otherwise return comma-separated list ending with comma
        let personasList = '';
        if (personas.length > 0) {
            personasList = personas.join(',') + ',';
        }
        
        // Calculate age from BORN field (YYYYMMDD)
        let age = 20;  // default
        const born = fields.BORN || '19800101';
        if (born && born.length >= 4) {
            const birthYear = parseInt(born.substring(0, 4));
            const currentYear = new Date().getFullYear();
            age = currentYear - birthYear;
        }
        
        // Send success response - based on original NFSOR protocol
        // From capture: PERSONAS=\nNAME=test123123\nAGE=20
        this._sendFeslResponse(client, 'acct', {
            'PERSONAS': personasList,  // Empty for new account, "name," for existing
            'NAME': name,
            'AGE': String(age),
        });
    }
    
    _handleFeslAuth(client, fields) {
        // Authentication/login request (called after acct)
        // Fields: REGN, CLST, NETV, FROM, LANG, MID, PROD, VERS, SLUS, SKU, NAME, PASS, PSES, MASK
        const name = fields.NAME || client.userName || '';
        const pass = fields.PASS || '';
        const pses = fields.PSES || '';  // Previous session token
        const prod = fields.PROD || client.product || 'nfs-pc-2005';
        
        log.info(`[${client.id}] AUTH: prod=${prod} name=${name} pses=${pses ? 'yes' : 'no'} tosAccepted=${client.tosAccepted || false}`);
        
        // Validate name
        if (!name || name.length < 3) {
            log.warn(`[${client.id}] AUTH: Invalid username '${name}'`);
            this._sendFeslResponseWithStatus(client, 'auth', 0x70617373, {});  // "pass"
            return;
        }
        
        // Check if user exists in database
        let dbUser = database.getUser(name);
        
        log.info(`[${client.id}] AUTH: User '${name}' exists in DB: ${dbUser ? 'YES' : 'NO'}`);
        
        if (dbUser) {
            // User exists - validate password format
            const result = database.validateUser(name, pass);
            if (!result.success) {
                // IMPORTANT: Invalid password returns STATUS=0x70617373 ("pass" in ASCII)
                // This is what real NFSOR does!
                log.warn(`[${client.id}] AUTH: Validation failed for ${name}: ${result.error}`);
                this._sendFeslResponseWithStatus(client, 'auth', 0x70617373, {});  // "pass"
                return;
            }
            dbUser = result.user;
            log.info(`[${client.id}] AUTH: User ${name} logged in successfully`);
        } else {
            // User doesn't exist
            // If TOS was accepted in prior 'acct' call (same TCP connection), create account
            // If not, this is a login attempt for non-existent user -> return error
            if (client.tosAccepted) {
                // TOS was accepted in 'acct' step, create user
                log.info(`[${client.id}] AUTH: Creating new user '${name}' (TOS accepted)`);
                const result = database.createUser(name, pass, client.userMail || '');
                if (result.success) {
                    dbUser = result.user;
                    log.info(`[${client.id}] AUTH: New user created: ${name}`);
                } else {
                    log.warn(`[${client.id}] AUTH: Failed to create user: ${result.error}`);
                    this._sendFeslResponseWithStatus(client, 'auth', 0x70617373, {});
                    return;
                }
            } else {
                // No TOS acceptance -> user trying to login with non-existent account
                // Return "pass" error like NFSOR does
                log.warn(`[${client.id}] AUTH: User '${name}' NOT FOUND and no TOS accepted - rejecting`);
                this._sendFeslResponseWithStatus(client, 'auth', 0x70617373, {});  // "pass"
                return;
            }
        }
        
        // Create session
        const session = database.createSession(dbUser.id, {
            addr: client.address,
            port: client.port,
            name: name,
        });
        
        client.user = dbUser;
        client.session = session;
        client.authenticated = true;
        client.persona = name;  // Default persona is same as username
        
        // Generate session key
        const lkey = client.lkey || ('$' + Math.random().toString(16).slice(2, 14));
        const addr = client.address || '127.0.0.1';
        
        // Get personas list
        const personas = dbUser.personas || [];
        const personasList = personas.length > 0 ? personas.join(',') + ',' : '';
        
        // Send success response - match real NFSOR format!
        this._sendFeslResponse(client, 'auth', {
            'MAIL': dbUser.mail || 'user@example.com',
            'LAST': '2005.12.8 15:51:38',  // Last login time
            'BORN': dbUser.born || '19800101',
            'PERSONAS': personasList,  // Comma-separated list ending with comma
            'TOS': '3',  // TOS version accepted
            'NAME': name,
            'SPAM': 'N',
            'ADDR': addr,
        });
        
        log.info(`[${client.id}] AUTH: Success! User ${name} authenticated`);
        
        // Send +who push with user stats (like real NFSOR)
        // Use real user data from database
        const userStats = dbUser.stats || {};
        const userOpid = dbUser.id || (client.id + 2485);
        
        setTimeout(() => {
            this._sendFeslResponse(client, '+who', {
                'A': addr,                              // External IP address
                'C': '20043',                           // Connection type?
                'G': '0',                               // Game ID (0 = not in game)
                'I': String(userOpid),                  // User ID (OPID) - unique per user
                'CL': String(userStats.circuitLaps || 0),    // Circuit laps
                'LV': String(userStats.level || 1),          // Level
                'M': dbUser.name,                       // Username (account name)
                'N': 'null',                            // Persona (null = not selected yet)
                'HW': String(userStats.wins || 0),           // Highway wins?
                'P': String(userStats.rep || 0),             // Rep points
                'WI': String(userStats.wins || 0),           // Total wins
                'R': String(userStats.races || 0),           // Total races
                'S': config.server?.name || 'NFSU2',    // Server name
                'AT': String(userStats.driftScore || 0),     // Drift score?
                'MA': String(userStats.maxRep || 0),         // Max rep achieved
                'LA': client.localAddr || addr,         // Local address (LAN IP)
                'MD': String(userStats.dragWins || 0),       // Drag wins?
                'X': 'null',                            // Aux data (car info?)
                'WT': String(userStats.sprintWins || 0),     // Sprint wins?
                'RP': String(userStats.rep || 0),            // Rep points
                'US': String(this.clients.size),        // Online users count
            });
        }, 50);
    }
    
    _sendStatsUpdate(client) {
        // Send +sst stats update
        // From NFSOR: GCM=0, UIG=0, GCR=1, UIL=8, UIR=0, GIP=0
        this._sendFeslResponse(client, '+sst', {
            'GCM': '0',  // Games completed?
            'UIG': '0',  // Users in game?
            'GCR': String(this.games.size),  // Games created/rooms
            'UIL': String(this.clients.size),  // Users in lobby
            'UIR': '0',  // Users in race?
            'GIP': '0',  // Games in progress?
        });
    }
    
    _broadcastStatsUpdate() {
        // Send +sst stats update to all connected clients
        for (const client of this.clients.values()) {
            if (client.authenticated) {
                this._sendStatsUpdate(client);
            }
        }
    }
    
    _handleUserInfo(client, fields) {
        // User info request - return player statistics
        // CLIENT: PERS=test
        // SERVER from NFSOR: LMSTAT=, STAT=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,, LGAME=
        const persona = fields.PERS || client.persona || 'Player';
        
        log.info(`[${client.id}] USER: Getting info for persona '${persona}'`);
        
        // Build 38-element stats array (all zeros for now)
        const stats = new Array(38).fill('0').join(',') + ',';
        
        this._sendFeslResponse(client, 'user', {
            'LMSTAT': '',     // Last match stat
            'STAT': stats,    // 38 comma-separated values
            'LGAME': '',      // Last game
        });
    }
    
    _handleCreatePersona(client, fields) {
        // Create persona - PERS=<persona_name>
        const personaName = fields.PERS || fields.NAME || '';
        
        log.info(`[${client.id}] CPER: Creating persona '${personaName}'`);
        
        if (!personaName || personaName.length < 3) {
            log.warn(`[${client.id}] CPER: Invalid persona name`);
            this._sendFeslResponse(client, 'cper', {
                'ERR': 'misg',
                'MSG': 'Persona name too short'
            });
            return;
        }
        
        // Store persona on client
        client.persona = personaName;
        
        // Add persona to user in database if we have one
        if (client.user && client.user.id) {
            // Try to add persona to database
            const result = database.addPersona(client.user.id, personaName);
            if (!result.success) {
                log.warn(`[${client.id}] CPER: ${result.error}`);
                // Continue anyway - persona might already exist
            }
        }
        
        // Send success response
        // Based on captured traffic, response should include PERS and NAME
        this._sendFeslResponse(client, 'cper', {
            'PERS': personaName,
            'NAME': personaName,
        });
        
        log.info(`[${client.id}] CPER: Persona '${personaName}' created successfully`);
    }
    
    _handleSelectPersona(client, fields) {
        // Select/login with persona - PERS=<persona_name>
        const personaName = fields.PERS || fields.NAME || client.persona || '';
        
        log.info(`[${client.id}] SPER: Selecting persona '${personaName}'`);
        
        client.persona = personaName;
        
        // Generate LKEY for this persona session
        const lkey = '$' + Math.random().toString(16).slice(2, 14);
        client.personaLkey = lkey;
        
        // Send success response
        this._sendFeslResponse(client, 'sper', {
            'PERS': personaName,
            'LKEY': lkey,
        });
        
        log.info(`[${client.id}] SPER: Persona '${personaName}' selected`);
    }
    
    _processTextProtocol(client) {
        // EA fesl/@tic/@dir/?tic protocol
        // @tic: ticket/encryption negotiation (client -> server)
        // @dir: directory service request
        // ?tic: encryption verification (client -> server, after @dir response)
        // Both can arrive in same TCP stream!
        
        while (client.buffer.length >= 12) {
            const dataStr = client.buffer.toString('latin1');
            
            // Handle ?tic (encryption verification) - client sends 52 bytes back
            if (dataStr.startsWith('?tic')) {
                const packetLen = client.buffer.readUInt32BE(8);
                if (client.buffer.length < packetLen) {
                    log.debug(`[${client.id}] ?tic: waiting for more data (have ${client.buffer.length}, need ${packetLen})`);
                    break;
                }
                
                log.info(`[${client.id}] ?tic (verify) received (${packetLen} bytes) - encryption handshake complete`);
                
                // Extract verification data (after 12-byte header)
                const verifyData = client.buffer.slice(12, packetLen);
                log.debug(`[${client.id}] ?tic verify data hex: ${verifyData.toString('hex').substring(0, 64)}...`);
                
                // Client has verified encryption, mark as ready
                client.encryptionVerified = true;
                
                // NFSOR responds with 0xFFFFFFFF/-1 status (connection ready)
                // This signals that encryption is established
                const readyPacket = Buffer.alloc(12);
                readyPacket.write('\xFF\xFF\xFF\xFF', 0, 'latin1');  // cmd = 0xFFFFFFFF
                readyPacket.writeInt32BE(-1, 4);  // status = -1
                readyPacket.writeUInt32BE(12, 8);  // length = 12 (header only)
                
                try {
                    client.socket.write(readyPacket);
                    log.info(`[${client.id}] >>> Connection ready signal (0xFFFFFFFF/-1)`);
                } catch (err) {
                    log.error(`[${client.id}] Failed to send ready signal: ${err.message}`);
                }
                
                // Remove processed packet
                client.buffer = client.buffer.slice(packetLen);
                continue;
            }
            
            if (dataStr.startsWith('@tic')) {
                // Get packet length from byte 11
                const packetLen = client.buffer[11];
                if (client.buffer.length < packetLen) {
                    log.debug(`[${client.id}] @tic: waiting for more data (have ${client.buffer.length}, need ${packetLen})`);
                    break;
                }
                
                log.info(`[${client.id}] @tic (ticket) message received (${packetLen} bytes)`);
                
                // Extract algorithm (after @tic + 8 bytes header)
                const algoStart = 12;
                const algoEnd = dataStr.indexOf('\0', algoStart);
                const algorithm = dataStr.substring(algoStart, algoEnd > 0 ? algoEnd : undefined);
                log.info(`[${client.id}] Encryption algorithm: ${algorithm}`);
                
                client.algorithm = algorithm;
                
                // Send @tic response
                this._sendTicResponse(client);
                
                // Remove processed packet from buffer
                client.buffer = client.buffer.slice(packetLen);
            }
            else if (dataStr.startsWith('@dir')) {
                // Get packet length from byte 11
                const packetLen = client.buffer[11];
                if (client.buffer.length < packetLen) {
                    log.debug(`[${client.id}] @dir: waiting for more data (have ${client.buffer.length}, need ${packetLen})`);
                    break;
                }
                
                log.info(`[${client.id}] @dir (directory) message received (${packetLen} bytes)`);
                
                // Extract fields (after header)
                const dataOffset = 12;
                const fieldsStr = dataStr.substring(dataOffset, packetLen);
                
                // Parse KEY=VALUE pairs
                const fields = {};
                const lines = fieldsStr.split('\n');
                for (const line of lines) {
                    const eqIdx = line.indexOf('=');
                    if (eqIdx > 0) {
                        let key = line.substring(0, eqIdx).replace(/[^\x20-\x7E]/g, '').trim();
                        const value = line.substring(eqIdx + 1).trim().replace(/"/g, '');
                        if (key) fields[key] = value;
                    }
                }
                
                log.info(`[${client.id}] @dir fields:`, fields);
                
                client.product = fields.PROD || 'unknown';
                client.version = fields.VERS || 'unknown';
                client.region = fields.REGN || 'NA';
                client.language = fields.LANG || 'EN';
                client.machineId = fields.MID || '';
                
                // Send @dir response
                this._sendDirResponse(client);
                
                // Remove processed packet from buffer
                client.buffer = client.buffer.slice(packetLen);
            }
            else {
                log.warn(`[${client.id}] Unknown @ protocol: ${dataStr.substring(0, 20)}`);
                break;
            }
        }
    }
    
    _sendTicResponse(client) {
        // @tic response: send encryption key data
        // From NFSOR capture: server responds with 43 bytes of key data
        // Format: cmd(4) + status(4 BE) + length(4 BE) + key_data
        //
        // The key data is used for RC4+MD5 encryption negotiation
        // Total packet = 12 (header) + 43 (data) = 55 bytes
        
        // Generate 43-byte key data (like NFSOR)
        const keyData = Buffer.alloc(43);
        for (let i = 0; i < 43; i++) {
            keyData[i] = Math.floor(Math.random() * 256);
        }
        
        // Store for later use
        client.ticKey = keyData;
        
        // EA text protocol format
        const totalLen = 12 + keyData.length;  // header(12) + key(43) = 55 bytes
        
        const packet = Buffer.alloc(totalLen);
        packet.write('@tic', 0, 'latin1');
        packet.writeUInt32BE(0, 4);  // status = 0
        packet.writeUInt32BE(totalLen, 8);  // total length
        keyData.copy(packet, 12);
        
        try {
            client.socket.write(packet);
            log.info(`[${client.id}] >>> @tic response (${packet.length} bytes): encryption key sent`);
            log.debug(`[${client.id}] @tic key hex: ${keyData.toString('hex')}`);
        } catch (err) {
            log.error(`[${client.id}] Failed to send @tic response: ${err.message}`);
        }
    }
    
    _sendDirResponse(client) {
        // Build @dir response
        // Format: @dir(4) + status(4) + length(4) + data
        // From NFSOR capture: PORT=20922, SESS=1651138085, ADDR=45.131.64.63, MASK=ed5faa76adec3f22520b6c90ec35acd4
        
        // Generate session ID (numeric, like NFSOR uses)
        const sessionId = Math.floor(Date.now() / 1000);
        client.sessionId = sessionId;
        
        // Generate MASK (32-char hex MD5-like hash)
        const maskHash = [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
        client.mask = maskHash;
        
        // Use public server IP (from config or client's destination)
        const serverAddr = config.server?.publicIP || '127.0.0.1';
        
        // Response fields - EXACTLY like real NFSOR!
        // Note: PORT is ping port (20922), not base port
        const response = [
            'PORT=20922',                    // Ping port!
            `SESS=${sessionId}`,             // Numeric session ID
            `ADDR=${serverAddr}`,            // Server IP (for client reference)
            `MASK=${maskHash}`,              // 32-char hex mask
            ''
        ].join('\n');
        
        const body = Buffer.from(response, 'latin1');
        
        // EA text protocol: cmd(4) + status(4 BE) + length(4 BE) + body
        const totalLen = 12 + body.length;
        
        const packet = Buffer.alloc(totalLen);
        packet.write('@dir', 0, 'latin1');
        packet.writeUInt32BE(0, 4);  // status = 0
        packet.writeUInt32BE(totalLen, 8);  // total length
        body.copy(packet, 12);
        
        try {
            client.socket.write(packet);
            log.info(`[${client.id}] >>> @dir response (${packet.length} bytes)`);
            log.info(`[${client.id}] @dir body: PORT=20922, SESS=${sessionId}, ADDR=${serverAddr}, MASK=${maskHash.substring(0,8)}...`);
        } catch (err) {
            log.error(`[${client.id}] Failed to send @dir response: ${err.message}`);
        }
    }

    _processBuffer(client) {
        // EA Protocol: [4-byte CMD ASCII][4-byte STATUS][4-byte LEN][PAYLOAD + \0]
        // Length includes the 12-byte header
        while (client.buffer.length >= 12) {
            // Read command as 4 ASCII chars (not int)
            const cmdBytes = client.buffer.slice(0, 4);
            const cmd = cmdBytes.toString('ascii');
            const status = client.buffer.readInt32BE(4);
            const length = client.buffer.readUInt32BE(8);
            
            // Validate - check if this looks like a valid EA command
            const isValidCmd = /^[A-Z]{4}$/.test(cmd);
            
            if (!isValidCmd) {
                // Could be encrypted data or wrong offset
                log.warn(`[${client.id}] Non-command packet: ${cmdBytes.toString('hex')} (not ASCII cmd)`);
                // Skip one byte and try again
                client.buffer = client.buffer.slice(1);
                continue;
            }
            
            // Validate length
            if (length < 12 || length > 65536) {
                log.warn(`[${client.id}] Invalid packet length: ${length} for cmd ${cmd}, skipping`);
                client.buffer = client.buffer.slice(1);
                continue;
            }
            
            // Wait for complete packet
            if (client.buffer.length < length) {
                log.debug(`[${client.id}] Waiting for more data: have ${client.buffer.length}, need ${length}`);
                break;
            }
            
            // Extract payload (after 12-byte header, minus null terminator)
            const payload = client.buffer.slice(12, length);
            const payloadStr = payload.toString('utf8').replace(/\0+$/, ''); // Remove null terminators
            
            log.info(`[${client.id}] <<< CMD: ${cmd} status=${status} len=${length}`);
            if (payloadStr.length > 0) {
                log.info(`[${client.id}]     payload: ${payloadStr.replace(/\n/g, ' | ')}`);
            }
            
            // Handle command
            this._handleCommand(client, cmd, status, payloadStr);
            
            // Remove processed packet
            client.buffer = client.buffer.slice(length);
        }
    }

    _handleCommand(client, cmd, status, payload) {
        const params = this._parsePayload(payload);
        
        switch (cmd) {
            case 'AUTH':
                this._handleAuth(client, params);
                break;
            case 'EPGT':
                this._handleEPGT(client, params);
                break;
            case 'RGET':
                this._handleRGET(client, params);
                break;
            case 'PSET':
                this._handlePSET(client, params);
                break;
            case 'DISC':
                this._handleDisc(client, params);
                break;
            case 'PING':
                this._handlePing(client, params);
                break;
            case 'PADD':
                // Add to buddy/presence list
                this._handlePADD(client, params);
                break;
            case 'PGET':
                // Get presence/status of user
                this._handlePGET(client, params);
                break;
            default:
                log.warn(`[${client.id}] Unknown command: ${cmd}`);
                // Echo back with OK status
                this._sendPacket(client, cmd, 0, '');
        }
    }

    // ============================================================================
    // Command Handlers (based on captured traffic)
    // ============================================================================

    _handleAuth(client, params) {
        // EA Messenger AUTH has two formats:
        // Format 1 (EA Messenger on port 20923): PROD=NFS-CONSOLE-2005\nVERS=0.1\nPRES=20920\nUSER=/PC/...\nLKEY=...
        // Format 2 (fesl login): NAME=username\nPASS=password\nTOS=1\n...
        // 
        // Response for EA Messenger: TITL=EA MESSENGER (simple!)
        
        const prod = params.PROD || '';
        const user = params.USER || '';
        const lkey = params.LKEY || '';
        const pres = params.PRES || '';  // Presence port
        
        // Check if this is EA Messenger AUTH (has PROD and USER and LKEY, no NAME/PASS)
        if (prod && user && lkey && !params.NAME) {
            log.info(`[${client.id}] EA MESSENGER AUTH: prod=${prod} user=${user} lkey=${lkey.substring(0,8)}...`);
            
            // This is EA Messenger connection on port 20923!
            // Client already authenticated via fesl (pers), just validate LKEY
            client.authenticated = true;
            client.product = prod;
            client.messengerUser = user;
            client.lkey = lkey;
            
            // Simple response - just TITL=EA MESSENGER
            // This is all the original NFSOR server responds with!
            const response = 'TITL=EA MESSENGER\n';
            this._sendPacket(client, 'AUTH', 0, response);
            
            log.info(`[${client.id}] EA MESSENGER: Client authenticated, ready for EPGT/RGET/PSET`);
            return;
        }
        
        // Check if this is NAME/PASS/TOS format (account creation/login via fesl)
        const name = params.NAME || '';
        const pass = params.PASS || '';
        const tos = parseInt(params.TOS) || 0;
        
        log.info(`[${client.id}] AUTH: prod=${prod || 'N/A'} user=${user || 'N/A'} name=${name || 'N/A'}`);
        
        // If NAME/PASS/TOS provided, handle account creation/login
        if (name && pass) {
            // Check TOS agreement
            if (tos < 1) {
                log.warn(`[${client.id}] AUTH failed: TOS not accepted`);
                const errorResponse = 'ERR=tosa\nMSG=Must accept Terms of Service\n';
                this._sendPacket(client, 'AUTH', -1, errorResponse);
                return;
            }
            
            // Validate name
            if (name.length < 3 || name.length > 16) {
                log.warn(`[${client.id}] AUTH failed: Invalid username length`);
                const errorResponse = 'ERR=misg\nMSG=Invalid username\n';
                this._sendPacket(client, 'AUTH', -1, errorResponse);
                return;
            }
            
            // Try to login or register
            let dbUser = database.getUser(name);
            
            if (!dbUser) {
                // Auto-register new user
                const result = database.createUser(name, pass);
                if (!result.success) {
                    log.warn(`[${client.id}] AUTH failed: ${result.error}`);
                    const errorResponse = `ERR=dupl\nMSG=${result.error}\n`;
                    this._sendPacket(client, 'AUTH', -1, errorResponse);
                    return;
                }
                dbUser = result.user;
                log.info(`[${client.id}] New user registered: ${name}`);
            } else {
                // Validate password
                const result = database.validateUser(name, pass);
                if (!result.success) {
                    log.warn(`[${client.id}] AUTH failed: Invalid password`);
                    const errorResponse = 'ERR=pass\nMSG=Invalid password\n';
                    this._sendPacket(client, 'AUTH', -1, errorResponse);
                    return;
                }
                dbUser = result.user;
            }
            
            // Create session
            const session = database.createSession(dbUser.id, {
                addr: client.address,
                port: client.port,
                name: name,
            });
            
            client.user = dbUser;
            client.session = session;
            client.authenticated = true;
            
            // Send success response with session info
            const response = [
                'TITL=EA MESSENGER',
                `SESS=${session.odId}`,
                `LKEY=${lkey || this._generateLKey()}`,
                `NAME=${dbUser.name}`,
                `ADDR=${client.address}`,
                `PERSONAS=${dbUser.personas.length}`,
            ].join('\n') + '\n';
            
            this._sendPacket(client, 'AUTH', 0, response);
            return;
        }
        
        // Legacy format: PROD/VERS/USER/LKEY without NAME/PASS
        // Extract username from USER format: /PC/username or /PC/NFS-CONSOLE-2005
        let username = user || 'Unknown';
        if (user.startsWith('/PC/')) {
            username = user.substring(4);
        } else if (user.includes('/')) {
            username = user.split('/').pop();
        }
        
        // Try to get or create user based on username
        let dbUser = database.getUser(username);
        if (!dbUser) {
            // Auto-create user with default password (empty or username)
            const result = database.createUser(username, username, '');
            if (result.success) {
                dbUser = result.user;
                log.info(`[${client.id}] Auto-created user from USER field: ${username}`);
            }
        }
        
        // Create session
        const session = database.createSession(dbUser?.id || Date.now(), {
            addr: client.address,
            port: client.port,
            name: username,
        });
        
        client.user = dbUser || { name: username, id: Date.now() };
        client.session = session;
        client.authenticated = true;
        
        // Response observed from NFSOR: TITL=EA MESSENGER
        const response = 'TITL=EA MESSENGER\n';
        this._sendPacket(client, 'AUTH', 0, response);
    }
    
    _generateLKey() {
        // Generate session key (32 hex chars)
        return [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
    }

    _handleEPGT(client, params) {
        // Request: LRSC=PC\nID=4
        // Response: ENAB=t\nID=4\nADDR=127.0.0.1
        
        const lrsc = params.LRSC || 'PC';
        const id = params.ID || '0';
        
        log.info(`[${client.id}] EPGT: lrsc=${lrsc} id=${id}`);
        
        const response = [
            'ENAB=t',
            `ID=${id}`,
            `ADDR=${client.address}`,
        ].join('\n') + '\n';
        
        this._sendPacket(client, 'EPGT', 0, response);
    }

    _handleRGET(client, params) {
        // Request: LRSC=PC\nLIST=B\nPRES=Y\nPEND=Y\nID=1
        // Response: SIZE=0\nID=1 (as RGET or ROST)
        
        const list = params.LIST || 'B';
        const id = params.ID || '0';
        
        log.info(`[${client.id}] RGET: list=${list} id=${id}`);
        
        // For now, return empty roster
        const response = [
            'SIZE=0',
            `ID=${id}`,
        ].join('\n') + '\n';
        
        // NFSOR returns RGET for first request, ROST for second
        const responseCmd = list === 'I' ? 'ROST' : 'RGET';
        this._sendPacket(client, responseCmd, 0, response);
    }

    _handlePSET(client, params) {
        // Request: SHOW=CHAT\nSTAT=EX%3d0%0aP%3dnfs5%0a\nPROD="..."
        // Response: (empty, just status 0)
        
        const show = params.SHOW || 'CHAT';
        const stat = params.STAT || '';
        
        log.info(`[${client.id}] PSET: show=${show}`);
        
        client.presence = show;
        
        // NFSOR responds with empty PSET
        this._sendPacket(client, 'PSET', 0, '');
    }

    _handleDisc(client, params) {
        log.info(`[${client.id}] DISC: client disconnecting`);
        
        // Acknowledge and close
        this._sendPacket(client, 'DISC', 0, '');
        
        setTimeout(() => {
            client.socket?.end();
        }, 100);
    }

    _handlePing(client, params) {
        log.debug(`[${client.id}] PING`);
        this._sendPacket(client, 'PING', 0, '');
    }

    _handlePADD(client, params) {
        // Add user to buddy/presence list (for in-game presence tracking)
        // Request: LRSC=PC\nUSER=<persona>
        // Response: LRSC=PC\nUSER=<persona> (echo back)
        const lrsc = params.LRSC || 'PC';
        const user = params.USER || '';
        
        log.info(`[${client.id}] PADD: Adding ${user} to presence list`);
        
        // Store in client's buddy tracking (for presence updates)
        if (!client.buddyList) {
            client.buddyList = [];
        }
        if (!client.buddyList.includes(user)) {
            client.buddyList.push(user);
        }
        
        // Echo back
        const response = `LRSC=${lrsc}\nUSER=${user}\n`;
        this._sendPacket(client, 'PADD', 0, response);
    }
    
    _handlePGET(client, params) {
        // Get presence/status of user
        // This is triggered when looking up a player (e.g., someone joins your game)
        // Response from NFSOR:
        // EXTR=NFS-CONSOLE-2005
        // STAT=EX%3d0%0aP%3dnfs5%0a
        // PROD=is playing Underground 2
        // TITL=Need for Speed Underground 2 [PC]
        // SHOW=AWAY
        // USER=<persona>
        // ATTR=D
        const user = params.USER || '';
        
        log.info(`[${client.id}] PGET: Getting presence for ${user}`);
        
        // Find the user's client
        let targetClient = null;
        for (const c of this.clients.values()) {
            if (c.persona === user && c.authenticated) {
                targetClient = c;
                break;
            }
        }
        
        // Build presence response
        const show = targetClient?.presence || 'AWAY';  // CHAT, AWAY, PASS, etc.
        
        const response = [
            'EXTR=NFS-CONSOLE-2005',
            'STAT=EX%3d0%0aP%3dnfs5%0a',
            'PROD=is playing Underground 2',
            'TITL=Need for Speed Underground 2 [PC]',
            `SHOW=${show}`,
            `USER=${user}`,
            'ATTR=D',  // D = default? 
        ].join('\n') + '\n';
        
        this._sendPacket(client, 'PGET', 0, response);
    }

    // ============================================================================
    // Protocol Helpers
    // ============================================================================

    _intToCmd(val) {
        return String.fromCharCode(
            (val >> 24) & 0xFF,
            (val >> 16) & 0xFF,
            (val >> 8) & 0xFF,
            val & 0xFF
        );
    }

    _cmdToInt(cmd) {
        if (typeof cmd !== 'string' || cmd.length < 4) return 0;
        return (cmd.charCodeAt(0) << 24) |
               (cmd.charCodeAt(1) << 16) |
               (cmd.charCodeAt(2) << 8) |
               cmd.charCodeAt(3);
    }

    _parsePayload(payload) {
        const result = {};
        if (!payload) return result;
        
        // Format: KEY=VALUE\nKEY2=VALUE2\n\0
        const lines = payload.split('\n');
        for (const line of lines) {
            const eqIdx = line.indexOf('=');
            if (eqIdx > 0) {
                const key = line.substring(0, eqIdx).trim();
                let value = line.substring(eqIdx + 1).trim();
                // Remove quotes
                if (value.startsWith('"') && value.endsWith('"')) {
                    value = value.slice(1, -1);
                }
                result[key] = value;
            }
        }
        return result;
    }

    _sendPacket(client, cmd, status, payload) {
        // EA Protocol: [4-byte CMD ASCII][4-byte STATUS BE][4-byte LENGTH BE][PAYLOAD + \0]
        const payloadStr = payload + '\0';  // Null terminate
        const payloadBuf = Buffer.from(payloadStr, 'utf8');
        const totalLength = 12 + payloadBuf.length;
        
        const packet = Buffer.alloc(totalLength);
        
        // Write command as 4 ASCII characters
        packet.write(cmd.padEnd(4, '\0').substring(0, 4), 0, 4, 'ascii');
        // Write status as big-endian int32
        packet.writeInt32BE(status, 4);
        // Write total length as big-endian uint32
        packet.writeUInt32BE(totalLength, 8);
        // Copy payload
        payloadBuf.copy(packet, 12);
        
        try {
            if (client.socket && !client.socket.destroyed) {
                client.socket.write(packet);
                log.info(`[${client.id}] >>> CMD: ${cmd} status=${status} len=${totalLength}`);
                if (payload.length > 0) {
                    log.info(`[${client.id}]     payload: ${payload.replace(/\n/g, ' | ')}`);
                }
            }
        } catch (err) {
            log.error(`[${client.id}] Send error: ${err.message}`);
        }
    }

    // ============================================================================
    // Game Management Functions
    // ============================================================================

    _handleGameSearch(client, fields) {
        // Game search - return list of active games
        // CLIENT: START=0, COUNT=20, CUSTFLAGS=67109107, CUSTMASK=67109363, SYSFLAGS=0, SYSMASK=786432
        //
        // Filtering logic:
        // - CUSTFLAGS/CUSTMASK: game type filter (circuit, sprint, drag, etc.)
        // - SYSFLAGS/SYSMASK: system flags filter (password protected, etc.)
        //
        // A game matches if: (game.flags & mask) == (search.flags & mask)
        //
        // SYSFLAGS values:
        // 0 = no password
        // 65536 (0x10000) = password protected
        // 786432 (0xC0000) = other system flags
        
        const start = parseInt(fields.START) || 0;
        const count = parseInt(fields.COUNT) || 20;
        const custFlags = parseInt(fields.CUSTFLAGS) || 0;
        const custMask = parseInt(fields.CUSTMASK) || 0;
        const sysFlags = parseInt(fields.SYSFLAGS) || 0;
        const sysMask = parseInt(fields.SYSMASK) || 0;
        
        log.info(`[${client.id}] GSEA: start=${start}, count=${count}, custFlags=${custFlags}, custMask=${custMask}, sysFlags=${sysFlags}, sysMask=${sysMask}`);
        
        // Filter games - DISABLED, show all games
        const allGames = Array.from(this.games.values());
        const matchingGames = allGames;  // No filtering
        
        // Apply pagination
        const paginatedGames = matchingGames.slice(start, start + count);
        
        log.info(`[${client.id}] GSEA: Found ${matchingGames.length} games, returning ${paginatedGames.length}`);
        
        // Send gsea response with count
        this._sendFeslResponse(client, 'gsea', {
            'COUNT': String(paginatedGames.length),
        });
        
        // Send +gam push for each game
        for (const game of paginatedGames) {
            this._sendGameInfo(client, game, '+gam');
        }
    }
    
    _handleGameGet(client, fields) {
        const gameName = fields.NAME || '';
        const game = this._findGameByName(gameName);
        
        if (game) {
            this._sendGameInfo(client, game, 'gget');
        } else {
            this._sendFeslResponse(client, 'gget', { 'COUNT': '0' });
        }
    }
    
    _handleGameJoin(client, fields) {
        // Join game
        // CLIENT without password: NAME=292.vpotoke
        // CLIENT with password: NAME=127.debil123, PASS=123123
        const gameName = fields.NAME || '';
        const providedPassword = fields.PASS || '';
        const game = this._findGameByName(gameName);
        
        log.info(`[${client.id}] GJOI: Joining game '${gameName}'${providedPassword ? ' (with password)' : ''}`);
        
        if (!game) {
            log.warn(`[${client.id}] GJOI: Game '${gameName}' not found`);
            this._sendFeslResponseWithStatus(client, 'gjoi', -1, { 'ERR': 'notfound' });
            return;
        }
        
        // Check if game requires password
        // SYSFLAGS=65536 indicates password protected game
        if (game.password && game.password.length > 0) {
            if (!providedPassword) {
                log.warn(`[${client.id}] GJOI: Game '${gameName}' requires password, none provided`);
                // Return error status - client should prompt for password
                // Status 0x70617373 = "pass" in ASCII (same as auth failure)
                this._sendFeslResponseWithStatus(client, 'gjoi', 0x70617373, { 'ERR': 'pass' });
                return;
            }
            if (providedPassword !== game.password) {
                log.warn(`[${client.id}] GJOI: Game '${gameName}' wrong password`);
                this._sendFeslResponseWithStatus(client, 'gjoi', 0x70617373, { 'ERR': 'pass' });
                return;
            }
            log.info(`[${client.id}] GJOI: Password verified for game '${gameName}'`);
        }
        
        // Check if game is full
        if (game.players.length >= game.maxSize) {
            log.warn(`[${client.id}] GJOI: Game '${gameName}' is full`);
            this._sendFeslResponseWithStatus(client, 'gjoi', -1, { 'ERR': 'full' });
            return;
        }
        
        // Add player to game
        const playerIndex = game.players.length;
        const playerInfo = {
            id: client.id,
            opid: client.id + 2485,  // Generate OPID like NFSOR
            name: client.persona || 'Player',
            addr: client.address,  // External IP (what server sees)
            laddr: client.reportedAddr || client.address,  // Local IP from addr command
            udpPort: parseInt(client.reportedPort) || 0,  // UDP port for P2P/relay
            flags: 0,  // 0 = not ready, 134217728 = ready
            part: 0,
            partSize: 4,
        };
        game.players.push(playerInfo);
        client.currentGame = game;
        client.gamePlayerIndex = playerIndex;
        
        log.info(`[${client.id}] GJOI: Player ${playerInfo.name} joined as player #${playerIndex}`);
        log.info(`[${client.id}] GJOI: addr=${playerInfo.addr}, laddr=${playerInfo.laddr}, udpPort=${playerInfo.udpPort}`);
        
        // Send gjoi response with full game info to joining player
        this._sendGameInfo(client, game, 'gjoi');
        
        // Send +who for ALL players in game to the new joiner
        // This way the new player sees everyone already in the room
        for (const existingPlayer of game.players) {
            this._sendPlayerWho(client, existingPlayer, game);
        }
        
        // Send +who of new player to ALL OTHER players in game
        // This way existing players see the new player
        for (const existingPlayer of game.players) {
            if (existingPlayer.id !== client.id) {
                const existingClient = this.clients.get(existingPlayer.id);
                if (existingClient) {
                    this._sendPlayerWho(existingClient, playerInfo, game);
                }
            }
        }
        
        // Send +mgm (game update) to ALL players in game (including new joiner)
        // This notifies everyone about the new player count and info
        setTimeout(() => {
            this._broadcastToGame(game, '+mgm');
        }, 100);
        
        // Broadcast stats update
        setTimeout(() => {
            this._broadcastStatsUpdate();
        }, 200);
    }
    
    _handleGameSet(client, fields) {
        // Player sets their flags (ready status)
        // CLIENT: NAME=069.usersssss, USERFLAGS=134217728 (ready)
        // SERVER: Full game info via gset response, then +mgm to everyone
        const gameName = fields.NAME || '';
        const userFlags = parseInt(fields.USERFLAGS) || 0;
        const game = client.currentGame;
        
        log.info(`[${client.id}] GSET: game='${gameName}', flags=${userFlags} (${userFlags === 134217728 ? 'READY' : 'NOT READY'})`);
        
        if (!game) {
            log.warn(`[${client.id}] GSET: Not in a game`);
            this._sendFeslResponse(client, 'gset', {});
            return;
        }
        
        // Find this player in game and update their flags
        let playerFound = false;
        for (let i = 0; i < game.players.length; i++) {
            if (game.players[i].id === client.id) {
                game.players[i].flags = userFlags;
                client.gamePlayerIndex = i;
                playerFound = true;
                log.info(`[${client.id}] GSET: Updated player ${i} flags to ${userFlags}`);
                break;
            }
        }
        
        if (!playerFound) {
            log.warn(`[${client.id}] GSET: Player not found in game`);
        }
        
        // Send gset response with updated game info to the requester
        this._sendGameInfo(client, game, 'gset');
        
        // Broadcast +mgm to ALL players in game with updated info
        setTimeout(() => {
            this._broadcastToGame(game, '+mgm');
        }, 50);
        
        // Check if all players ready (but don't auto-start - wait for gsta)
        this._checkGameStart(game);
    }
    
    _handleGameLeave(client, fields) {
        const game = client.currentGame;
        
        log.info(`[${client.id}] GLEA: Leaving game`);
        
        if (game) {
            // Remove player from game
            game.players = game.players.filter(p => p.id !== client.id);
            
            if (game.players.length === 0) {
                // Delete empty game
                this.games.delete(game.id);
                log.info(`[${client.id}] Game ${game.name} deleted (empty)`);
            } else {
                // Broadcast update
                this._broadcastToGame(game, '+mgm');
            }
        }
        
        client.currentGame = null;
        this._sendFeslResponse(client, 'glea', {});
    }
    
    _handleGameDelete(client, fields) {
        // Delete/destroy game - host command
        // CLIENT: NAME=079.debil123
        // SERVER: empty response, then +who with G=0
        const gameName = fields.NAME || '';
        const game = this._findGameByName(gameName) || client.currentGame;
        
        log.info(`[${client.id}] GDEL: Deleting game '${gameName}'`);
        
        if (game) {
            // Verify this is the host
            if (game.hostId !== client.id) {
                log.warn(`[${client.id}] GDEL: Not the host of game '${gameName}'`);
                // Still allow delete for now (maybe they are leaving)
            }
            
            // Notify all other players in game that game is deleted
            // They should receive +who with G=0 (not in game)
            for (const player of game.players) {
                const playerClient = this.clients.get(player.id);
                if (playerClient && playerClient.id !== client.id) {
                    playerClient.currentGame = null;
                    // Send +who to update their game status to G=0
                    this._sendPlayerWhoUpdate(playerClient, 0);
                }
            }
            
            // Delete the game
            this.games.delete(game.id);
            log.info(`[${client.id}] Game ${game.name} (ID: ${game.id}) deleted`);
        }
        
        // Clear current game for host
        client.currentGame = null;
        
        // Send empty gdel response
        this._sendFeslResponse(client, 'gdel', {});
        
        // Send +who to host with G=0 (no longer in game)
        this._sendPlayerWhoUpdate(client, 0);
        
        // Broadcast stats update
        setTimeout(() => {
            this._broadcastStatsUpdate();
        }, 100);
    }
    
    _sendPlayerWhoUpdate(client, gameId) {
        // Send +who with updated game ID
        const persona = client.persona || 'Player';
        const userName = client.user?.name || persona;
        const userOpid = client.user?.id || (client.id + 2485);
        const auxiData = client.auxiData || 'null';
        const udpPort = client.reportedPort || '3658';
        
        this._sendFeslResponse(client, '+who', {
            'A': client.address,
            'C': udpPort,
            'G': String(gameId),  // 0 = not in game
            'I': String(userOpid),
            'CL': '423',
            'LV': '354',
            'M': userName,
            'N': persona,
            'HW': '5765',
            'P': '100',
            'WI': '10323',
            'R': '11432',
            'S': config.server?.name || 'NFSU2',
            'AT': '1423',
            'MA': '7876',
            'LA': client.reportedAddr || client.address,
            'MD': '4654',
            'X': auxiData,
            'WT': '8987',
            'RP': '676',
            'US': String(this.clients.size),
        });
    }
    
    _handleGameCreate(client, fields) {
        // Create a new game
        // CLIENT sends: NAME=069.usersssss, MAXSIZE=4, MINSIZE=2, CUSTFLAGS=67109107, SYSFLAGS=0, PARAMS=TRACK%3d4014%0aDIR%3d0%0aLAPS%3d3
        // WITH PASSWORD: NAME=127.debil123, MAXSIZE=4, MINSIZE=2, CUSTFLAGS=67109107, SYSFLAGS=0, PASS=123123, PARAMS=TRACK%3d4014%0aDIR%3d0%0aLAPS%3d3
        const gameId = this.nextGameId++;
        
        // Parse the NAME field - client may send pre-formatted name like "069.usersssss"
        // or we generate it from gameId + persona
        let gameName = fields.NAME;
        if (!gameName) {
            gameName = `${String(gameId).padStart(3, '0')}.${client.persona || 'Player'}`;
        }
        
        // Check for password - if PASS is provided, game is password protected
        // SYSFLAGS=65536 means password protected in the response
        const password = fields.PASS || '';
        const hasPassword = password.length > 0;
        // Client sends SYSFLAGS=0, but server returns SYSFLAGS=65536 for password-protected games
        const sysFlags = hasPassword ? 65536 : (parseInt(fields.SYSFLAGS) || 0);
        
        const game = {
            id: gameId,
            name: gameName,
            host: client.persona || 'Player',
            hostId: client.id,
            custFlags: parseInt(fields.CUSTFLAGS) || 67109107,  // From capture
            sysFlags: sysFlags,  // 65536 = password protected
            minSize: parseInt(fields.MINSIZE) || 2,
            maxSize: parseInt(fields.MAXSIZE) || 4,
            numPart: 1,  // Always 1 in NFSU2
            params: fields.PARAMS || 'TRACK%3d4014%0aDIR%3d0%0aLAPS%3d3',
            password: password,  // Store password for join validation
            room: 0,
            evid: 0,
            evgid: 0,
            players: [],
            createdAt: Date.now(),  // Track when game was created for cleanup
        };
        
        // Add host as first player
        // Use real external address + local address
        const hostInfo = {
            id: client.id,
            opid: client.id + 2485,  // Generate OPID like NFSOR
            name: client.persona || 'Player',
            addr: client.address,  // External IP (what server sees)
            laddr: client.reportedAddr || client.address,  // Local IP (what client reports)
            udpPort: parseInt(client.reportedPort) || 0,  // UDP port for P2P/relay
            flags: 0,  // 0 = not ready, 134217728 = ready
            part: 0,
            partSize: 4,
        };
        game.players.push(hostInfo);
        
        this.games.set(gameId, game);
        client.currentGame = game;
        client.gamePlayerIndex = 0;
        
        log.info(`[${client.id}] GCRE: Created game '${gameName}' (ID: ${gameId})`);
        log.info(`[${client.id}] GCRE: custFlags=${game.custFlags}, params=${game.params}`);
        
        // Send gcre response with full game info
        this._sendGameInfo(client, game, 'gcre');
        
        // Send +who with player stats (client needs X= for car data)
        this._sendPlayerWho(client, hostInfo, game);
        
        // Send +mgm game management update (like NFSOR does after gcre)
        setTimeout(() => {
            this._sendGameInfo(client, game, '+mgm');
        }, 100);
        
        // Broadcast stats update to everyone
        setTimeout(() => {
            this._broadcastStatsUpdate();
        }, 200);
    }
    
    _handleAuxi(client, fields) {
        // Store car customization data
        const text = fields.TEXT || '';
        client.auxiData = text;
        
        log.info(`[${client.id}] AUXI: Received car data (${text.length} chars)`);
        
        // Echo back empty response
        this._sendFeslResponse(client, 'auxi', {});
    }
    
    _findGameByName(name) {
        for (const game of this.games.values()) {
            if (game.name === name) {
                return game;
            }
        }
        return null;
    }
    
    _sendGameInfo(client, game, cmd) {
        // Build game info response (matches NFSOR format)
        const info = {
            'HOST': game.host,
            'NAME': game.name,
            'IDENT': String(game.id),
            'CUSTFLAGS': String(game.custFlags),
            'SYSFLAGS': String(game.sysFlags),
            'MINSIZE': String(game.minSize),
            'MAXSIZE': String(game.maxSize),
            'NUMPART': String(game.numPart),
            'COUNT': String(game.players.length),
            'PARAMS': game.params,
            'ROOM': String(game.room),
            'EVID': String(game.evid),
            'EVGID': String(game.evgid),
        };
        
        // Get relay server IP for ADDR fields
        // In relay mode, all players connect through relay server
        // ADDR = relay server IP (where to send UDP)
        // LADDR = real local IP (for LAN detection, informational only)
        const relayServerIP = config.server?.publicIP || '127.0.0.1';
        
        // Add player info (OPID0, OPPO0, ADDR0, LADDR0, etc for each player)
        for (let i = 0; i < game.players.length; i++) {
            const p = game.players[i];
            info[`OPID${i}`] = String(p.opid);
            info[`OPPO${i}`] = p.name;
            // Use relay server IP - matches original NFSOR behavior
            info[`ADDR${i}`] = relayServerIP;
            info[`LADDR${i}`] = p.laddr;
            info[`MADDR${i}`] = '';  // Media address (empty)
            info[`OPFLAG${i}`] = String(p.flags);
            info[`OPPART${i}`] = String(p.part);
            info[`PARTSIZE${i}`] = '4';
        }
        
        this._sendFeslResponse(client, cmd, info);
    }
    
    _sendPlayerWho(client, playerInfo, game) {
        // Send +who with player statistics
        // This contains player info including car customization data in X=
        // From captured NFSOR traffic:
        // A=195.3.223.202 (external IP)
        // C=20043 (port?)
        // G=833 (game ID, or 0 if not in game)
        // I=2594 (OPID - unique player ID)
        // ...stats...
        // X=C%3d281DCV74j/4AAA... (car customization data, URL encoded)
        
        // Get the client object for this player to get their auxiData
        const playerClient = this.clients.get(playerInfo.id);
        const auxiData = playerClient?.auxiData || 'null';
        const userName = playerClient?.user?.name || playerInfo.name;
        // UDP port from 'addr' command - used for P2P relay
        const udpPort = playerClient?.reportedPort || '3658';
        
        this._sendFeslResponse(client, '+who', {
            'A': playerInfo.addr,       // External IP address
            'C': udpPort,               // UDP port for P2P (from addr command)
            'G': String(game.id),       // Current game ID
            'I': String(playerInfo.opid), // Unique player ID (OPID)
            'CL': '423',                // Career Level?
            'LV': '354',                // Level?
            'M': userName,              // Account name
            'N': playerInfo.name,       // Persona name
            'HW': '5765',               // Hardware ID?
            'P': '100',                 // Points?
            'WI': '10323',              // Wins?
            'R': '11432',               // Races?
            'S': 'online',              // Status/Server
            'AT': '1423',               // ?
            'MA': '7876',               // ?
            'LA': playerInfo.laddr || playerInfo.addr,  // Local address
            'MD': '4654',               // ?
            'X': auxiData,              // Car customization data (important!)
            'WT': '8987',               // ?
            'RP': '676',                // Rep points?
            'US': '2',                  // User status?
        });
    }
    
    _broadcastToGame(game, cmd) {
        // Send game update to all players
        for (const player of game.players) {
            const clientObj = this.clients.get(player.id);
            if (clientObj) {
                this._sendGameInfo(clientObj, game, cmd);
            }
        }
    }
    
    _checkGameStart(game) {
        // Check if all players are ready (flag 134217728)
        const allReady = game.players.length >= game.minSize && 
                         game.players.every(p => p.flags === 134217728);
        
        if (allReady) {
            log.info(`Game ${game.name}: All players ready, waiting for host 'gsta' command...`);
            game.allReady = true;
            // Don't auto-start! Wait for host to send 'gsta' command
        }
    }
    
    _handleOnlineCheck(client, fields) {
        // Check if persona is online
        // CLIENT: PERS=<persona_name>
        // SERVER: I=0 (not online) or I=<id> (online)
        const persona = fields.PERS || '';
        
        log.info(`[${client.id}] ONLN: Checking if '${persona}' is online`);
        
        // Search for online client with this persona
        let onlineId = 0;
        for (const [id, c] of this.clients.entries()) {
            if (c.persona === persona && c.authenticated) {
                onlineId = c.id + 2485;  // OPID format
                break;
            }
        }
        
        this._sendFeslResponse(client, 'onln', {
            'I': String(onlineId),
        });
    }
    
    _handleGameStart(client, fields) {
        // Game start - host signals to start the race
        // CLIENT: NAME=069.usersssss
        // SERVER: empty response, then +mgm, then +ses to all players
        const gameName = fields.NAME || '';
        const game = client.currentGame;
        
        log.info(`[${client.id}] GSTA: Host starting game '${gameName}'`);
        
        // Send empty gsta response first
        this._sendFeslResponse(client, 'gsta', {});
        
        if (!game) {
            log.warn(`[${client.id}] GSTA: Not in a game`);
            return;
        }
        
        // Verify this is the host
        if (game.hostId !== client.id) {
            log.warn(`[${client.id}] GSTA: Not the host`);
            return;
        }
        
        // Send +mgm update to all players
        this._broadcastToGame(game, '+mgm');
        
        // Now start the game - send +ses to all players
        log.info(`Game ${game.name}: Starting game via gsta!`);
        
        // Generate random seed for game sync
        const seed = Math.floor(Math.random() * 10000000);
        
        // Calculate session hash the same way the game does (sub_7528A0)
        // The game hashes the string starting from '#' character
        // Hash algorithm: for each char c: hash = ((hash * 32) ^ (hash >>> 27)) ^ c
        const calcSessionHash = (seedValue) => {
            const str = `#${seedValue}`;
            let hash = 0;
            for (let i = 0; i < str.length; i++) {
                const v5 = ((hash * 32) ^ (hash >>> 27)) >>> 0;
                hash = (v5 ^ str.charCodeAt(i)) >>> 0;
            }
            return hash;
        };
        
        const sessionHash = calcSessionHash(seed);
        log.info(`Game ${game.name}: SEED=${seed}, sessionHash=${sessionHash} (0x${sessionHash.toString(16)})`);
        
        // Build +ses (session start) packet
        const sesInfo = {
            'HOST': game.host,
            'NAME': game.name,
            'IDENT': String(game.id),
            'SEED': String(seed),
            'SELF': '',  // Will be set per-player
            'CUSTFLAGS': String(game.custFlags),
            'SYSFLAGS': String(game.sysFlags),
            'MINSIZE': String(game.minSize),
            'MAXSIZE': String(game.maxSize),
            'NUMPART': String(game.numPart),
            'COUNT': String(game.players.length),
            'PARAMS': game.params,
            'ROOM': String(game.room),
            'EVID': String(game.evid),
            'EVGID': String(game.evgid),
        };
        
        // In +ses, ADDRx contains the IP where each player should send UDP packets
        // 
        // STRATEGY: Use REAL IP addresses of other players in ADDR
        // The game needs to see different IPs to trigger P2P handshake logic
        // Hook will intercept ALL packets to port 3658 and redirect to relay server
        //
        // Format: IP:PORT#SEED where:
        // - IP = real external IP of the other player (triggers P2P logic)
        // - PORT = 3658 (relay port - hook intercepts and redirects)
        // - SEED = game seed for sync
        //
        // LADDRx = local IP (for LAN detection)
        // MADDRx = mapped/external IP (same as real IP for reference)
        
        const relayPort = config.ports.relay;  // UDP relay port (53 = DNS to bypass NAT)
        
        // IMPORTANT: Game expects separate ADDR (IP only) and PORT fields
        // ADDR format should be IP only (not IP:PORT#SEED)
        // PORT is a separate field
        // The game uses ADDR0 and PORT for P2P connection setup
        
        for (let i = 0; i < game.players.length; i++) {
            const p = game.players[i];
            const clientObj = this.clients.get(p.id);
            
            sesInfo[`OPID${i}`] = String(p.opid);
            sesInfo[`OPPO${i}`] = p.name;
            // ADDR should contain ONLY IP (game parses IP:PORT#SEED but only extracts IP)
            // Use REAL IP of the other player - game needs to see different IPs
            // Hook intercepts all packets to port 3658 and redirects to relay server
            sesInfo[`ADDR${i}`] = p.addr;  // IP only, no port
            sesInfo[`LADDR${i}`] = p.laddr || p.addr;
            sesInfo[`MADDR${i}`] = p.addr;
            sesInfo[`OPFLAG${i}`] = String(p.flags);
            sesInfo[`OPPART${i}`] = String(p.part);
            sesInfo[`PARTSIZE${i}`] = '4';
            
            log.info(`+ses player ${i}: ${p.name} ADDR=${p.addr} (IP only) LADDR=${p.laddr} MADDR=${p.addr}`);
        }
        
        // Add PORT field - game expects this separate from ADDR
        // Use relay port (3658) - hook will intercept and redirect
        sesInfo['PORT'] = String(relayPort);
        log.info(`+ses PORT=${relayPort} (relay port)`);
        
        // Register game in UDP relay server (so it knows which clients belong together)
        if (this.udpServer) {
            // Build list of expected UDP endpoints (IP:reportedPort for each player)
            const udpEndpoints = game.players.map(p => {
                const clientObj = this.clients.get(p.id);
                const udpPort = clientObj?.reportedPort || 0;
                return `${p.addr}:${udpPort}`;
            }).filter(addr => !addr.includes(':0'));
            
            if (udpEndpoints.length > 0) {
                // Pass sessionHash to UDP server - this is the ACTUAL session ID used in UDP packets
                // The game calculates hash from #SEED string, so we must use the same hash!
                this.udpServer.registerGame(game.id, udpEndpoints, sessionHash);
                log.info(`Game ${game.id}: Registered ${udpEndpoints.length} UDP endpoints with sessionHash=${sessionHash}`);
            }
        }
        
        // Log full +ses content for debugging
        log.info(`+ses content: COUNT=${game.players.length}`);
        for (let i = 0; i < game.players.length; i++) {
            log.info(`  OPPO${i}=${sesInfo[`OPPO${i}`]} ADDR${i}=${sesInfo[`ADDR${i}`]} OPID${i}=${sesInfo[`OPID${i}`]}`);
        }
        
        // Send +ses to each player with their name in SELF
        // IMPORTANT: Game expects single ADDR field (not ADDR0/ADDR1) with IP of the peer
        // Each player gets ADDR = IP of first opponent (not self)
        for (const player of game.players) {
            const clientObj = this.clients.get(player.id);
            if (clientObj) {
                // Create player-specific sesInfo
                const playerSesInfo = { ...sesInfo };
                playerSesInfo['SELF'] = player.name;
                
                // Find first opponent (not self)
                const opponent = game.players.find(p => p.id !== player.id);
                if (opponent) {
                    // Set ADDR to opponent's IP only (PORT is in separate PORT field)
                    // Game's sub_742140 extracts IP and stops at any non-digit/dot character
                    // Game uses sub_7414A0 to find "ADDR" field (without index)
                    // Keep ADDR0, ADDR1, etc. for compatibility, but also set single ADDR field
                    playerSesInfo['ADDR'] = opponent.addr; // Just IP, no :PORT#SEED
                    log.info(`[${clientObj.id}] >>> +ses sent to ${player.name}: ADDR=${opponent.addr} (IP only, opponent ${opponent.name}), PORT=${relayPort}, SEED=${seed}`);
                } else {
                    // Fallback: use first player's IP if no opponent found
                    playerSesInfo['ADDR'] = game.players[0]?.addr || '';
                    log.warn(`[${clientObj.id}] >>> +ses sent to ${player.name}: No opponent found, using first player IP`);
                }
                
                // Log full +ses content for debugging
                const sesKeys = Object.keys(playerSesInfo).filter(k => k.startsWith('ADDR') || k === 'PORT' || k === 'SEED' || k === 'SELF');
                log.info(`[${clientObj.id}] >>> +ses full content for ${player.name}: ${sesKeys.map(k => `${k}=${playerSesInfo[k]}`).join(', ')}`);
                
                this._sendFeslResponse(clientObj, '+ses', playerSesInfo);
                log.info(`[${clientObj.id}] >>> +ses sent to ${player.name} (SELF=${player.name})`);
            }
        }
    }

    _handleSnapRequest(client, fields) {
        // Leaderboard/ranking snapshot request
        // Two modes:
        // 1. FIND=$ - find current player's ranking (INDEX=1, CHAN=12, RANGE=1, FIND=$)
        // 2. START=N, RANGE=M - get range of players (INDEX=1, CHAN=6, START=0, RANGE=100)
        //
        // CHAN values (channels/categories):
        // 6 = Overall ranking
        // 12 = Circuit ranking?
        // etc.
        //
        // Response: snap + multiple +snp entries
        // snap: START=<position>, CHAN=<channel>, RANGE=<count>
        // +snp: P=<points>, R=<rank>, S=<stats>, N=<name>, O=<online?>
        
        const index = parseInt(fields.INDEX) || 1;
        const chan = parseInt(fields.CHAN) || 6;
        const range = parseInt(fields.RANGE) || 1;
        const find = fields.FIND || '';
        const start = parseInt(fields.START) || 0;
        
        log.info(`[${client.id}] SNAP: chan=${chan}, range=${range}, find=${find}, start=${start}`);
        
        // Get leaderboard data from database
        const leaderboard = database.getLeaderboard ? database.getLeaderboard(chan, start, range) : [];
        
        // If FIND=$ - look for current player's position
        let playerStart = start;
        if (find === '$' && client.persona) {
            // Find player's rank
            const allPlayers = database.getLeaderboard ? database.getLeaderboard(chan, 0, 100000) : [];
            const playerIdx = allPlayers.findIndex(p => p.name === client.persona);
            playerStart = playerIdx >= 0 ? playerIdx + 1 : 45707;  // Default position if not found
        }
        
        // Send snap response
        this._sendFeslResponse(client, 'snap', {
            'START': String(playerStart),
            'CHAN': String(chan),
            'RANGE': String(leaderboard.length || range),
        });
        
        // Send +snp entries for each player in range
        // If we have no database leaderboard, send at least the current player
        if (leaderboard.length === 0 && client.persona) {
            // Send current player's entry
            this._sendFeslResponse(client, '+snp', {
                'P': '0',         // Points
                'R': String(playerStart),  // Rank
                'S': '10,0,0',    // Stats (format: wins,losses,?)
                'N': client.persona,
                'O': '1',         // Online
            });
        } else {
            // Send each player from leaderboard
            for (let i = 0; i < leaderboard.length; i++) {
                const entry = leaderboard[i];
                this._sendFeslResponse(client, '+snp', {
                    'P': String(entry.points || 0),
                    'R': String(start + i + 1),
                    'S': entry.stats || '0,0,0',
                    'N': entry.name,
                    'O': entry.online ? '1' : '0',
                });
            }
        }
    }

    // ========================================================================
    // UDP-over-TCP Tunnel Handler
    // Protocol: [4 bytes total_len LE][2 bytes dest_port BE][4 bytes dest_IP][payload]
    // Server wraps responses: [4 bytes total_len LE][2 bytes src_port BE][4 bytes src_IP][payload]
    // ========================================================================
    _onUdpTunnelConnection(socket) {
        const addr = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        const clientKey = `${addr}:${socket.remotePort}`;
        
        log.info(`[UDP-TUNNEL] New connection from ${clientKey}`);
        
        // Reset host tracking if this is first/only client
        if (this.udpTunnelClients.size === 0) {
            this.udpTunnelHostKey = null;
            log.debug(`[UDP-TUNNEL] Reset host tracking (first client connecting)`);
        }
        
        const tunnelClient = {
            socket: socket,
            address: addr,
            port: socket.remotePort,
            buffer: Buffer.alloc(0),
            gameId: null,
            playerName: null,
            lastActivity: Date.now(),
        };
        
        this.udpTunnelClients.set(clientKey, tunnelClient);
        log.info(`[UDP-TUNNEL] Active clients: ${this.udpTunnelClients.size}`);
        
        // Try to associate with game by IP
        // IMPORTANT: Only associate with ACTIVE games (not old finished ones)
        for (const [gameId, game] of this.games.entries()) {
            // Skip games that are too old (more than 5 minutes since creation)
            const gameAge = Date.now() - (game.createdAt || 0);
            if (gameAge > 5 * 60 * 1000) {
                continue;
            }
            
            for (const player of game.players) {
                if (player.addr === tunnelClient.address) {
                    tunnelClient.gameId = gameId;
                    tunnelClient.playerName = player.name;
                    log.info(`[UDP-TUNNEL] Pre-associated ${clientKey} with game ${gameId} (player: ${player.name})`);
                    break;
                }
            }
            if (tunnelClient.gameId) break;
        }
        
        // NOTE: Removed fallback to "other tunnel clients" - it caused wrong associations
        // Association will happen properly when first packet is received (by destination IP)
        
        if (!tunnelClient.gameId) {
            log.warn(`[UDP-TUNNEL] Could not associate ${clientKey} with any game - will relay to all tunnel clients`);
        }
        
        // DON'T flush buffered packets immediately on connect!
        // The game needs to initialize its connection state before receiving BROADCAST.
        // Instead, we'll flush when the client sends its first packet.
        // This ensures the game has created its connection structure.
        tunnelClient.pendingFlush = true;  // Mark that we need to flush buffer to this client
        
        if (this.udpTunnelBuffer && this.udpTunnelBuffer.size > 0) {
            log.info(`[UDP-TUNNEL] ${this.udpTunnelBuffer.size} buffer(s) pending - will flush after client sends first packet`);
        }
        
        socket.on('data', (data) => {
            tunnelClient.lastActivity = Date.now();
            tunnelClient.buffer = Buffer.concat([tunnelClient.buffer, data]);
            
            // Process complete packets
            while (tunnelClient.buffer.length >= 4) {
                // Read packet length (4 bytes LE)
                const packetLen = tunnelClient.buffer.readUInt32LE(0);
                
                // Sanity check
                if (packetLen < 6 || packetLen > 65535) {
                    log.warn(`[UDP-TUNNEL] Invalid packet length ${packetLen} from ${clientKey}, resetting buffer`);
                    tunnelClient.buffer = Buffer.alloc(0);
                    break;
                }
                
                // Wait for complete packet (4 bytes header + packetLen)
                if (tunnelClient.buffer.length < 4 + packetLen) {
                    break;
                }
                
                // Extract packet
                const packet = tunnelClient.buffer.slice(4, 4 + packetLen);
                tunnelClient.buffer = tunnelClient.buffer.slice(4 + packetLen);
                
                this._handleUdpTunnelPacket(tunnelClient, clientKey, packet);
            }
        });
        
        socket.on('close', () => {
            log.info(`[UDP-TUNNEL] Connection closed: ${clientKey}`);
            this.udpTunnelClients.delete(clientKey);
            
            // If host disconnected, reset host tracking for next session
            if (this.udpTunnelHostKey === clientKey) {
                log.info(`[UDP-TUNNEL] Host ${clientKey} disconnected, resetting host tracking`);
                this.udpTunnelHostKey = null;
                this.broadcastSentTime = null;
                this.syncStartTime = null;
            }
        });
        
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') {
                log.error(`[UDP-TUNNEL] Error from ${clientKey}: ${err.message}`);
            }
            this.udpTunnelClients.delete(clientKey);
        });
    }
    
    _handleUdpTunnelPacket(tunnelClient, clientKey, packet) {
        // Packet format: [2 bytes dest_port BE][4 bytes dest_IP][payload]
        if (packet.length < 6) {
            log.warn(`[UDP-TUNNEL] Packet too small (${packet.length} bytes) from ${clientKey}`);
            return;
        }
        
        const destPort = packet.readUInt16BE(0);
        const destIP = `${packet[2]}.${packet[3]}.${packet[4]}.${packet[5]}`;
        const payload = packet.slice(6);
        
        // Determine payload type
        const payloadType = payload.length >= 4 ? payload.readUInt32LE(0) : 0;
        const payloadHex = payload.slice(0, Math.min(16, payload.length)).toString('hex');
        
        // Type names for logging
        const typeNames = {
            1: 'HELLO', 2: 'HELLO_ACK', 3: 'READY', 4: 'ACK', 5: 'BROADCAST',
            101: 'SYNC_BASE', 102: 'CAR_DATA_1', 103: 'CAR_DATA_2', 104: 'CAR_DATA_3', 105: 'CAR_DATA_4'
        };
        const typeName = typeNames[payloadType] || `TYPE_${payloadType}`;
        
        // Track who is likely the host (first to send BROADCAST type 5)
        if (payloadType === 5 && !this.udpTunnelHostKey) {
            this.udpTunnelHostKey = clientKey;
            this.broadcastSentTime = Date.now();
            this.syncStartTime = Date.now(); // For timing analysis
            log.info(`[UDP-TUNNEL] Detected HOST: ${clientKey} (first to send BROADCAST)`);
            log.info(`[UDP-TUNNEL] >>> P2P sync started - timing from now`);
        }
        
        // Log timing for all important events relative to sync start
        if (this.syncStartTime) {
            const elapsed = Date.now() - this.syncStartTime;
            if (payloadType === 101 && payload.length >= 40) {
                log.info(`[UDP-TUNNEL] [T+${elapsed}ms] ${clientKey} sent FULL SYNC_BASE - car loaded!`);
            } else if (payloadType === 101) {
                log.info(`[UDP-TUNNEL] [T+${elapsed}ms] ${clientKey} sent SHORT SYNC_BASE (${payload.length}b) - car NOT loaded`);
            } else if (payloadType >= 102 && payloadType <= 105) {
                log.info(`[UDP-TUNNEL] [T+${elapsed}ms] ${clientKey} sent CAR_DATA type ${payloadType}`);
            } else if (payloadType === 3) {
                const hasCar = tunnelClient.syncState?.sentCarData;
                log.info(`[UDP-TUNNEL] [T+${elapsed}ms] ${clientKey} sent READY (has CAR_DATA: ${hasCar})`);
            }
        }
        
        // Flag for delayed relay (set later after responsePacket is built)
        let skipImmediateRelay = false;
        
        // ALWAYS log packets (for debugging relay issues)
        log.info(`[UDP-TUNNEL] Packet from ${clientKey}: dest=${destIP}:${destPort}, type=${payloadType} (${typeName}), len=${payload.length}`);
        log.info(`[UDP-TUNNEL] Active clients: ${Array.from(this.udpTunnelClients.keys()).join(', ')}`);
        if (payloadType === 8 || payloadType === 12) {
            log.info(`[UDP-TUNNEL] Payload hex: ${payloadHex}`);
        }
        
        // Track sync state per client
        if (!tunnelClient.syncState) {
            tunnelClient.syncState = {
                sentCarData: false,
                receivedCarData: false,
                sentReady: false,
                receivedReady: false,
                sentFullSyncBase: false,
                carDataTypes: new Set(), // which CAR_DATA types (102-105) this client sent
                carDataPackets: new Map() // type -> packet buffer for retransmit
            };
        }
        
        // Track what this client sends
        if (payloadType >= 102 && payloadType <= 105) {
            tunnelClient.syncState.sentCarData = true;
            tunnelClient.syncState.carDataTypes.add(payloadType);
            log.info(`[UDP-TUNNEL] ${clientKey} sent CAR_DATA (type ${payloadType}, ${payload.length} bytes) - types sent: ${Array.from(tunnelClient.syncState.carDataTypes).join(',')}`);
            
            // If this client was waiting to send READY (joiner case), reset the retry counter
            // so next READY attempt will go through
            if (tunnelClient.readyRetryCount > 0) {
                log.info(`[UDP-TUNNEL] ${clientKey} finally sent CAR_DATA! Resetting READY retry counter.`);
                tunnelClient.readyRetryCount = 0;
                tunnelClient.firstReadyTime = null;
            }
        }
        if (payloadType === 3) {
            tunnelClient.syncState.sentReady = true;
            if (!tunnelClient.syncState.sentCarData) {
                log.warn(`[UDP-TUNNEL] WARNING: ${clientKey} sent READY but never sent CAR_DATA!`);
            }
        }
        if (payloadType === 101) {
            if (payload.length >= 40) {
                tunnelClient.syncState.sentFullSyncBase = true;
            }
            // Logging is already done in the timing section above
        }
        
        // Try to associate client with game by IP (source IP or destination IP)
        if (!tunnelClient.gameId) {
            for (const [gameId, game] of this.games.entries()) {
                // Skip old games
                const gameAge = Date.now() - (game.createdAt || 0);
                if (gameAge > 5 * 60 * 1000) continue;
                
                for (const player of game.players) {
                    // Match by source IP (this client's IP)
                    if (player.addr === tunnelClient.address) {
                        tunnelClient.gameId = gameId;
                        tunnelClient.playerName = player.name;
                        log.info(`[UDP-TUNNEL] Associated ${clientKey} with game ${gameId} (player: ${player.name}, by source IP)`);
                        break;
                    }
                    // Also match by destination IP (packet target) - this helps when client IP doesn't match
                    if (player.addr === destIP) {
                        tunnelClient.gameId = gameId;
                        log.info(`[UDP-TUNNEL] Associated ${clientKey} with game ${gameId} (by destination IP ${destIP})`);
                        break;
                    }
                }
                if (tunnelClient.gameId) break;
            }
        }
        
        // Build response packet with source info (for relay and buffering)
        // [4 bytes total_len LE][2 bytes src_port BE][4 bytes src_IP][payload]
        const srcIP = tunnelClient.address.split('.').map(Number);
        const responsePacket = Buffer.alloc(4 + 2 + 4 + payload.length);
        
        // Write total length (excluding the 4-byte length field itself)
        responsePacket.writeUInt32LE(2 + 4 + payload.length, 0);
        
        // Write source port (use 3658 as standard P2P port)
        responsePacket.writeUInt16BE(3658, 4);
        
        // Write source IP
        responsePacket[6] = srcIP[0] || 0;
        responsePacket[7] = srcIP[1] || 0;
        responsePacket[8] = srcIP[2] || 0;
        responsePacket[9] = srcIP[3] || 0;
        
        // Copy payload
        payload.copy(responsePacket, 10);
        
        // EXPERIMENTAL: Delay first BROADCAST to give joiner time to load car
        // In original P2P, NAT traversal caused natural delay (~1-3 seconds), giving car time to load.
        // In relay mode, packets arrive instantly. We need to simulate this delay.
        //
        // CRITICAL: The joiner's car must be FULLY LOADED before receiving BROADCAST,
        // otherwise it won't have CAR_DATA to send and the race won't start.
        //
        // UPDATED: Client now suppresses SHORT SYNC_BASE for 6 seconds.
        // Server still delays BROADCAST to help ensure joiner's car loads before receiving it.
        // Increased delay to give joiner more time to:
        // 1. Receive simulated HELLO from host
        // 2. Generate and send their CAR_DATA
        // 3. Have their car fully loaded
        const BROADCAST_DELAY_MS = 5000; // 5 seconds (increased from 3s)
        
        if (payloadType === 5 && this.udpTunnelHostKey === clientKey) {
            if (!tunnelClient.broadcastCount) {
                tunnelClient.broadcastCount = 0;
            }
            tunnelClient.broadcastCount++;
            
            if (tunnelClient.broadcastCount === 1) {
                log.info(`[UDP-TUNNEL] Delaying first BROADCAST by ${BROADCAST_DELAY_MS}ms to allow joiner car to load`);
                skipImmediateRelay = true;
                
                const delayedPacket = Buffer.from(responsePacket);
                const savedClientKey = clientKey;
                
                // Record when we started waiting - for timeout tracking
                this.broadcastDelayStart = Date.now();
                
                setTimeout(() => {
                    for (const [otherKey, otherClient] of this.udpTunnelClients.entries()) {
                        if (otherKey !== savedClientKey) {
                            try {
                                otherClient.socket.write(delayedPacket);
                                log.info(`[UDP-TUNNEL] Sent delayed BROADCAST from ${savedClientKey} to ${otherKey} (after ${BROADCAST_DELAY_MS}ms)`);
                            } catch (err) {
                                log.warn(`[UDP-TUNNEL] Failed to send delayed BROADCAST: ${err.message}`);
                            }
                        }
                    }
                }, BROADCAST_DELAY_MS);
            }
        }
        
        // Save CAR_DATA packets for potential retransmission
        if (payloadType >= 102 && payloadType <= 105) {
            if (!this.carDataCache) {
                this.carDataCache = new Map(); // clientKey -> Map(type -> responsePacket)
            }
            if (!this.carDataCache.has(clientKey)) {
                this.carDataCache.set(clientKey, new Map());
            }
            this.carDataCache.get(clientKey).set(payloadType, Buffer.from(responsePacket));
            log.info(`[UDP-TUNNEL] Cached CAR_DATA type ${payloadType} from ${clientKey} for retransmission`);
        }
        
        // Flush buffered packets to this client AFTER it sends its first packet
        // This ensures the game has initialized its connection state
        if (tunnelClient.pendingFlush && this.udpTunnelBuffer && this.udpTunnelBuffer.size > 0) {
            tunnelClient.pendingFlush = false;
            log.info(`[UDP-TUNNEL] Client ${clientKey} sent first packet - flushing buffered packets`);
            
            for (const [bufferId, buffer] of this.udpTunnelBuffer.entries()) {
                let sentCount = 0;
                
                for (const item of buffer) {
                    // Send packets NOT from this client
                    // ALSO skip BROADCAST (type 5) - it has its own delayed delivery mechanism
                    if (item.srcAddress !== tunnelClient.address && item.type !== 5) {
                        try {
                            tunnelClient.socket.write(item.packet);
                            sentCount++;
                            log.info(`[UDP-TUNNEL] Flushed buffered type=${item.type} from ${item.srcAddress} to ${clientKey}`);
                        } catch (err) {
                            log.warn(`[UDP-TUNNEL] Failed to flush: ${err.message}`);
                        }
                    } else if (item.type === 5) {
                        log.debug(`[UDP-TUNNEL] Skipping buffered BROADCAST - will be sent via delayed delivery`);
                    }
                }
                
                if (sentCount > 0) {
                    log.info(`[UDP-TUNNEL] Flushed ${sentCount} buffered packets to ${clientKey} (from buffer '${bufferId}')`);
                }
            }
            
            // Clear all buffers after flushing
            this.udpTunnelBuffer.clear();
        }
        
        // CRITICAL: If non-host client sends READY without CAR_DATA, we must wait.
        //
        // Problem: Joiner's car isn't loaded when P2P sync starts.
        // In original P2P this worked because NAT traversal took time (~1-3 seconds),
        // giving the joiner's car time to load. In relay mode, packets arrive instantly.
        //
        // SOLUTION: If joiner hasn't sent CAR_DATA when they send READY:
        // 1. Do NOT relay their READY to host
        // 2. Re-send host's CAR_DATA to joiner (to trigger game's sync logic)
        // 3. Wait for joiner to send their CAR_DATA
        // 4. After timeout (5 seconds), relay READY anyway as last resort
        //
        const JOINER_CAR_DATA_TIMEOUT_MS = 10000; // Wait up to 10 seconds for joiner's car
        const JOINER_CAR_DATA_RETRY_INTERVAL_MS = 500; // Re-send host CAR_DATA every 500ms
        
        let shouldRelayReady = true;
        let joinerNeedsCarData = false;
        
        if (payloadType === 3 && tunnelClient.syncState && !tunnelClient.syncState.sentCarData) {
            joinerNeedsCarData = true;
            
            // Check if this is joiner (not host)
            const isJoiner = this.udpTunnelHostKey && this.udpTunnelHostKey !== clientKey;
            
            if (isJoiner) {
                // Increment retry counter
                if (!tunnelClient.readyRetryCount) {
                    tunnelClient.readyRetryCount = 0;
                    tunnelClient.firstReadyTime = Date.now();
                    tunnelClient.lastCarDataResend = 0;
                }
                tunnelClient.readyRetryCount++;
                
                const elapsed = Date.now() - tunnelClient.firstReadyTime;
                const timeSinceLastResend = Date.now() - (tunnelClient.lastCarDataResend || 0);
                
                // Give joiner up to 5 seconds to load car data
                if (elapsed < JOINER_CAR_DATA_TIMEOUT_MS) {
                    log.warn(`[UDP-TUNNEL] JOINER ${clientKey} sent READY without CAR_DATA (attempt ${tunnelClient.readyRetryCount}, ${elapsed}ms elapsed) - WAITING`);
                    shouldRelayReady = false;
                    
                    // Re-send host's CAR_DATA to joiner periodically
                    // This helps trigger the game's sync state machine
                    if (timeSinceLastResend >= JOINER_CAR_DATA_RETRY_INTERVAL_MS) {
                        tunnelClient.lastCarDataResend = Date.now();
                        
                        if (this.carDataCache) {
                            let resendCount = 0;
                            for (const [cachedClientKey, cachedData] of this.carDataCache.entries()) {
                                if (cachedClientKey !== clientKey) {
                                    for (const [type, packet] of cachedData.entries()) {
                                        try {
                                            tunnelClient.socket.write(packet);
                                            resendCount++;
                                        } catch (err) {}
                                    }
                                }
                            }
                            if (resendCount > 0) {
                                log.info(`[UDP-TUNNEL] Re-sent ${resendCount} CAR_DATA packets to joiner ${clientKey} (helping car load)`);
                            }
                        }
                        
                        // Also re-send BROADCAST to joiner - might help trigger car loading
                        if (tunnelClient.readyRetryCount % 2 === 0) { // Every 2nd attempt
                            // Create BROADCAST packet (type 5)
                            const broadcastPayload = Buffer.alloc(8);
                            broadcastPayload.writeUInt32LE(5, 0); // type = 5 (BROADCAST)
                            broadcastPayload.writeUInt32LE(0, 4); // padding
                            
                            // Build full packet with source info from host
                            const hostClient = this.udpTunnelClients.get(this.udpTunnelHostKey);
                            if (hostClient) {
                                const srcIP = hostClient.address.split('.').map(Number);
                                const resendPacket = Buffer.alloc(4 + 2 + 4 + 8);
                                resendPacket.writeUInt32LE(2 + 4 + 8, 0); // length
                                resendPacket.writeUInt16BE(3658, 4); // port
                                resendPacket[6] = srcIP[0] || 0;
                                resendPacket[7] = srcIP[1] || 0;
                                resendPacket[8] = srcIP[2] || 0;
                                resendPacket[9] = srcIP[3] || 0;
                                broadcastPayload.copy(resendPacket, 10);
                                
                                try {
                                    tunnelClient.socket.write(resendPacket);
                                    log.info(`[UDP-TUNNEL] Re-sent BROADCAST to joiner ${clientKey} (attempt ${tunnelClient.readyRetryCount})`);
                                } catch (err) {}
                            }
                        }
                    }
                } else {
                    // Timeout - relay READY anyway and hope for the best
                    log.warn(`[UDP-TUNNEL] JOINER ${clientKey} TIMEOUT waiting for CAR_DATA after ${elapsed}ms - RELAYING READY ANYWAY`);
                    log.warn(`[UDP-TUNNEL] >>> This may cause race start failure - joiner's car may not be properly synced`);
                    shouldRelayReady = true;
                }
            } else {
                // Host without CAR_DATA - just relay (host should always have car loaded)
                log.warn(`[UDP-TUNNEL] HOST ${clientKey} sent READY without CAR_DATA - RELAY ANYWAY`);
                shouldRelayReady = true;
            }
        }
        
        // Relay packet to other tunnel clients in the same game
        let relayCount = 0;
        
        // Skip relay for READY if we decided not to relay it, or for delayed BROADCAST
        if (skipImmediateRelay) {
            log.debug(`[UDP-TUNNEL] Skipping immediate relay of type ${payloadType} (will be delayed)`);
        } else if (payloadType === 3 && !shouldRelayReady) {
            log.debug(`[UDP-TUNNEL] Not relaying READY from ${clientKey} (waiting for CAR_DATA)`);
        } else {
            for (const [otherKey, otherClient] of this.udpTunnelClients.entries()) {
                if (otherKey === clientKey) continue;
                
                // Only relay to clients in the same game (or if no game association, relay to all)
                if (tunnelClient.gameId && otherClient.gameId && tunnelClient.gameId !== otherClient.gameId) {
                    continue;
                }
                
                try {
                    otherClient.socket.write(responsePacket);
                    relayCount++;
                    log.info(`[UDP-TUNNEL] >>> Relayed type ${payloadType} (${payload.length} bytes) from ${clientKey} to ${otherKey}`);
                    
                    // Track what this client received
                    if (payloadType >= 102 && payloadType <= 105) {
                        if (!otherClient.syncState) {
                            otherClient.syncState = { 
                                sentCarData: false, receivedCarData: false, 
                                sentReady: false, receivedReady: false,
                                sentFullSyncBase: false, carDataTypes: new Set()
                            };
                        }
                        otherClient.syncState.receivedCarData = true;
                    }
                    if (payloadType === 3) {
                        if (otherClient.syncState) {
                            otherClient.syncState.receivedReady = true;
                        }
                    }
                } catch (err) {
                    log.warn(`[UDP-TUNNEL] Failed to relay to ${otherKey}: ${err.message}`);
                }
            }
            
            // Log relay result
            log.info(`[UDP-TUNNEL] Relayed type ${payloadType} from ${clientKey} to ${relayCount} client(s), total clients: ${this.udpTunnelClients.size}`);
        }
        
        // CRITICAL FIX: When joiner sends HELLO, mark them for receiving simulated HELLO from host
        // 
        // In original P2P, BOTH players send HELLO to each other:
        //   Host  -> Joiner: HELLO (type 1)
        //   Joiner -> Host:  HELLO (type 1)
        // 
        // The game generates CAR_DATA in response to receiving HELLO (in sub_58C420).
        // When all CAR_DATA parts from peer are received, it triggers OUR car data generation.
        //
        // In relay mode, only joiner sends HELLO (host sends BROADCAST first).
        // Without receiving HELLO + CAR_DATA, joiner never triggers CAR_DATA generation!
        //
        // FIX: Mark joiner when they send HELLO, then when host sends ALL their CAR_DATA,
        // we send simulated HELLO + CAR_DATA to joiner
        //
        if (payloadType === 1 && payload.length === 8) {
            log.debug(`[UDP-TUNNEL] Type 1 HELLO from ${clientKey} - relaying to peers`);
            
            // Check if this is joiner (not host)
            const isJoiner = this.udpTunnelHostKey && this.udpTunnelHostKey !== clientKey;
            
            if (isJoiner) {
                // Mark joiner as needing simulated HELLO + CAR_DATA from host
                tunnelClient.needsSimulatedHello = true;
                log.info(`[UDP-TUNNEL] Joiner ${clientKey} sent HELLO - marked for simulated HELLO+CAR_DATA from host`);
            }
        }
        
        // When HOST sends CAR_DATA type 105 (last one), send simulated HELLO + CAR_DATA to all waiting joiners
        // Type 105 is the last CAR_DATA packet, so all parts are now available
        if (payloadType === 105 && this.udpTunnelHostKey === clientKey) {
            log.info(`[UDP-TUNNEL] HOST sent CAR_DATA type 105 (last) - checking for joiners needing sync trigger`);
            
            // Small delay to let this packet be cached first
            setTimeout(() => {
                for (const [joinerKey, joinerClient] of this.udpTunnelClients.entries()) {
                    if (joinerKey === clientKey) continue; // Skip host
                    
                    if (joinerClient.needsSimulatedHello && !joinerClient.receivedSimulatedHello) {
                        joinerClient.receivedSimulatedHello = true;
                        joinerClient.needsSimulatedHello = false;
                        
                        log.info(`[UDP-TUNNEL] CRITICAL: Sending simulated HELLO + CAR_DATA to joiner ${joinerKey}`);
                        
                        try {
                            // Build HELLO packet (type 1, 8 bytes) with host's IP as source
                            const helloPayload = Buffer.alloc(8);
                            helloPayload.writeUInt32LE(1, 0); // type = 1 (HELLO)
                            helloPayload.writeUInt32LE(0, 4); // padding
                            
                            const hostIP = tunnelClient.address.split('.').map(Number);
                            const helloFromHost = Buffer.alloc(4 + 2 + 4 + 8);
                            helloFromHost.writeUInt32LE(2 + 4 + 8, 0); // length
                            helloFromHost.writeUInt16BE(3658, 4); // port
                            helloFromHost[6] = hostIP[0] || 0;
                            helloFromHost[7] = hostIP[1] || 0;
                            helloFromHost[8] = hostIP[2] || 0;
                            helloFromHost[9] = hostIP[3] || 0;
                            helloPayload.copy(helloFromHost, 10);
                            
                            // 1. Send HELLO from host to joiner
                            joinerClient.socket.write(helloFromHost);
                            log.info(`[UDP-TUNNEL] Sent simulated HELLO from ${tunnelClient.address}:3658 to joiner`);
                            
                            // 2. Send all cached CAR_DATA from host to joiner
                            if (this.carDataCache && this.carDataCache.has(clientKey)) {
                                const hostCarData = this.carDataCache.get(clientKey);
                                let sentCount = 0;
                                
                                // Send in order: 102, 103, 104, 105
                                for (let type = 102; type <= 105; type++) {
                                    if (hostCarData.has(type)) {
                                        joinerClient.socket.write(hostCarData.get(type));
                                        sentCount++;
                                    }
                                }
                                
                                log.info(`[UDP-TUNNEL] Sent ${sentCount} CAR_DATA packets from host to joiner (post-simulated-HELLO)`);
                                log.info(`[UDP-TUNNEL] >>> Joiner should now generate their own CAR_DATA!`);
                            }
                        } catch (err) {
                            log.warn(`[UDP-TUNNEL] Failed to send simulated HELLO+CAR_DATA to joiner: ${err.message}`);
                        }
                    }
                }
            }, 50); // Small delay to ensure CAR_DATA 105 is cached
        }
        
        if (relayCount > 0) {
            log.info(`[UDP-TUNNEL] Relayed packet from ${clientKey} to ${relayCount} other client(s)`);
        } else {
            // No clients to relay to - buffer important packets
            // This happens when one player connects before the other
            // NOTE: Game may be deleted from this.games when FESL closes, so use default of 2
            const expectedClients = 2;
            
            if (this.udpTunnelClients.size < expectedClients) {
                // Initialize buffer if needed
                if (!this.udpTunnelBuffer) {
                    this.udpTunnelBuffer = new Map(); // gameId -> Array of {packet, srcAddress}
                }
                
                const gameId = tunnelClient.gameId || 'default';
                if (!this.udpTunnelBuffer.has(gameId)) {
                    this.udpTunnelBuffer.set(gameId, []);
                }
                
                const buffer = this.udpTunnelBuffer.get(gameId);
                // Buffer important packets (type 1-4, 101-105) and limit buffer size
                // NOTE: DO NOT buffer type 5 (BROADCAST) - it has its own delayed delivery via setTimeout
                // Buffering BROADCAST here would cause it to be flushed immediately when joiner connects,
                // defeating the purpose of the 2-second delay
                const isImportant = (payloadType >= 1 && payloadType <= 4) || (payloadType >= 101 && payloadType <= 110);
                if (isImportant && buffer.length < 100) {
                    buffer.push({ 
                        packet: Buffer.from(responsePacket), 
                        srcAddress: tunnelClient.address,
                        type: payloadType 
                    });
                    log.info(`[UDP-TUNNEL] BUFFERED type=${payloadType} from ${clientKey} (clients=${this.udpTunnelClients.size}/${expectedClients}, buffer=${buffer.length})`);
                } else if (payloadType === 5) {
                    log.debug(`[UDP-TUNNEL] NOT buffering BROADCAST (type 5) - using delayed delivery instead`);
                }
            }
        }
    }

    _onClose(client) {
        log.info(`[${client.id}] Connection closed`);
        
        // Stop ping interval if active
        this._stopPingInterval(client);
        
        // Leave any game
        if (client.currentGame) {
            const game = client.currentGame;
            game.players = game.players.filter(p => p.id !== client.id);
            if (game.players.length === 0) {
                this.games.delete(game.id);
            } else {
                this._broadcastToGame(game, '+mgm');
            }
        }
        
        this.clients.delete(client.id);
    }

    getClientCount() {
        return this.clients.size;
    }

    getClients() {
        return Array.from(this.clients.values());
    }

    broadcast(cmd, status, payload) {
        for (const client of this.clients.values()) {
            this._sendPacket(client, cmd, status, payload);
        }
    }
}

export default TCPServer;
