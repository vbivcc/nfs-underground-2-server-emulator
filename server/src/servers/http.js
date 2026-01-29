// ============================================================================
// NFSU2 Server - HTTP Server
// Handles redirector, news, status endpoints
// 
// IMPORTANT: Uses raw TCP to handle malformed HTTP requests from patched game!
// The game with SSL disabled sends "GET  HTTP/1.0" (empty path) which
// standard HTTP parsers reject as 400 Bad Request.
// ============================================================================

import net from 'net';
import { createLogger } from '../utils/logger.js';
import config from '../config.js';
import database from '../database/index.js';

const log = createLogger('HTTP');

class HTTPServer {
    constructor(tcpServer, udpServer) {
        this.server = null;
        this.tcpServer = tcpServer;
        this.udpServer = udpServer;
    }

    start(port = config.ports.http) {
        // Use raw TCP server to handle malformed HTTP requests
        this.server = net.createServer((socket) => this._onConnection(socket));

        this.server.on('error', (err) => {
            if (err.code === 'EACCES') {
                log.warn(`Cannot bind to port ${port} (need admin/root). Trying ${port + 8000}...`);
                this.server.listen(port + 8000, '0.0.0.0');
            } else if (err.code === 'EADDRINUSE') {
                log.warn(`Port ${port} in use. Trying ${port + 8000}...`);
                this.server.listen(port + 8000, '0.0.0.0');
            } else {
                log.error('HTTP server error:', err.message);
            }
        });

        this.server.listen(port, '0.0.0.0', () => {
            log.info(`HTTP server listening on port ${port}`);
        });

        return this;
    }

    stop() {
        if (this.server) {
            this.server.close();
            log.info('HTTP server stopped');
        }
    }
    
    _onConnection(socket) {
        const clientIP = socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        let buffer = '';
        
        socket.on('data', (data) => {
            buffer += data.toString();
            
            // Check if we have a complete HTTP request (ends with \r\n\r\n)
            if (buffer.includes('\r\n\r\n')) {
                this._handleRawRequest(socket, buffer, clientIP);
                buffer = '';
            }
        });
        
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') {
                log.error(`HTTP socket error: ${err.message}`);
            }
        });
    }
    
    _handleRawRequest(socket, rawRequest, clientIP) {
        // Parse HTTP request manually to handle malformed requests
        const lines = rawRequest.split('\r\n');
        const requestLine = lines[0] || '';
        
        // Parse: "GET /path HTTP/1.0" or "GET  HTTP/1.0" (empty path!)
        const parts = requestLine.split(' ');
        const method = parts[0] || 'GET';
        let url = parts[1] || '';
        
        // Handle empty/whitespace URL (patched game sends this)
        if (!url || url.trim() === '' || url === 'HTTP/1.0' || url === 'HTTP/1.1') {
            log.info(`HTTP ${method} (empty URL) from ${clientIP} - treating as TOS`);
            url = '/nfsu2/tos';  // Default to TOS
        } else {
            log.info(`HTTP ${method} "${url}" from ${clientIP}`);
        }
        
        // Create fake req/res objects for compatibility with existing handlers
        const req = {
            method,
            url,
            socket,
            headers: this._parseHeaders(lines.slice(1)),
        };
        
        const res = {
            socket,
            _headers: {},
            _statusCode: 200,
            _statusMessage: 'OK',
            setHeader: function(name, value) { this._headers[name] = value; },
            writeHead: function(code, headers) {
                this._statusCode = code;
                if (headers) Object.assign(this._headers, headers);
            },
            end: function(body) {
                let response = `HTTP/1.0 ${this._statusCode} ${this._statusMessage}\r\n`;
                for (const [key, value] of Object.entries(this._headers)) {
                    response += `${key}: ${value}\r\n`;
                }
                response += '\r\n';
                if (body) response += body;
                
                try {
                    socket.write(response);
                    socket.end();
                } catch (e) {
                    // Socket may already be closed
                }
            }
        };
        
        this._onRequest(req, res);
    }
    
    _parseHeaders(lines) {
        const headers = {};
        for (const line of lines) {
            if (!line || line.trim() === '') break;
            const colonIdx = line.indexOf(':');
            if (colonIdx > 0) {
                const name = line.substring(0, colonIdx).trim().toLowerCase();
                const value = line.substring(colonIdx + 1).trim();
                headers[name] = value;
            }
        }
        return headers;
    }

    _onRequest(req, res) {
        const url = req.url || '/';
        const clientIP = req.socket.remoteAddress?.replace('::ffff:', '') || 'unknown';
        log.info(`HTTP ${req.method} "${url}" from ${clientIP}`);

        // CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

        try {
            // IMPORTANT: Game with patched SSL sends empty URL path!
            // "GET  HTTP/1.0" instead of "GET /nfsu2/tos HTTP/1.0"
            // Treat empty/whitespace URL as TOS request
            const trimmedUrl = url.trim();
            
            if (trimmedUrl === '' || trimmedUrl === ' ') {
                log.info(`Empty URL detected - treating as TOS request`);
                this._handleTOS(req, res);
                return;
            }
            
            // Route requests
            if (url === '/' || url === '/index.html') {
                this._handleIndex(req, res);
            } else if (url === '/status' || url === '/api/status') {
                this._handleStatus(req, res);
            } else if (url.startsWith('/ms/') || url.startsWith('/sv/')) {
                // EA master/slave server redirector
                this._handleRedirector(req, res);
            } else if (url === '/news' || url === '/api/news') {
                this._handleNews(req, res);
            } else if (url === '/nfsu2/tos' || url === '/nfsu2/tos/') {
                // NFSU2 Terms of Service - exact path from conf TOSURL
                log.info(`NFSU2 TOS request: ${url}`);
                this._handleTOS(req, res);
            } else if (url === '/nfsu2/news' || url === '/nfsu2/news/') {
                // NFSU2 News - exact path from conf NEWSURL  
                log.info(`NFSU2 News request: ${url}`);
                this._handleTOSNews(req, res);
            } else if (url.includes('tos') || url.includes('TOS') || 
                       url.includes('terms') || url.includes('eula')) {
                // Terms of Service - various URLs the game might use
                log.info(`TOS request: ${url}`);
                this._handleTOS(req, res);
            } else if (url.includes('news') || url.includes('NEWS')) {
                this._handleTOSNews(req, res);
            } else {
                // For any unknown URL, try TOS response (game might use weird URLs)
                log.warn(`Unknown URL, trying TOS: ${url}`);
                this._handleTOS(req, res);
            }
        } catch (err) {
            log.error('HTTP request error:', err);
            res.writeHead(500, { 'Content-Type': 'text/plain' });
            res.end('Internal Server Error');
        }
    }
    
    _handleTOSNews(req, res) {
        // Some games request news in a specific format
        const news = `%{ CMD=news TITLE="Server News" BTN1="OK" BTN1-GOTO="$quit" %} 
Welcome to NFSU2 Custom Server!

${config.server.motd}

Server Version: ${config.server.version}
`;
        
        res.writeHead(200, { 
            'Content-Type': 'application/octet-stream',
            'Content-Length': Buffer.byteLength(news),
            'Connection': 'close',
        });
        res.end(news);
    }

    _handleIndex(req, res) {
        const tcpClients = this.tcpServer?.getClientCount() || 0;
        const udpStats = this.udpServer?.getStats() || { clients: 0 };

        const html = `<!DOCTYPE html>
<html>
<head>
    <title>NFSU2 Server</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, sans-serif; 
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #eee; 
            margin: 0; 
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { 
            color: #00d4ff; 
            text-shadow: 0 0 10px #00d4ff;
            font-size: 2.5em;
        }
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            backdrop-filter: blur(10px);
        }
        .stat { 
            display: inline-block; 
            margin: 10px 20px;
            text-align: center;
        }
        .stat-value { 
            font-size: 2em; 
            color: #00d4ff;
            font-weight: bold;
        }
        .stat-label { color: #888; }
        a { color: #00d4ff; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🏎️ NFSU2 Online Server</h1>
        
        <div class="card">
            <h2>Server Status</h2>
            <div class="stat">
                <div class="stat-value">${tcpClients}</div>
                <div class="stat-label">Players Online</div>
            </div>
            <div class="stat">
                <div class="stat-value">${udpStats.clients}</div>
                <div class="stat-label">P2P Connections</div>
            </div>
            <div class="stat">
                <div class="stat-value">${database.users.size}</div>
                <div class="stat-label">Registered Users</div>
            </div>
        </div>

        <div class="card">
            <h2>Server Info</h2>
            <p><strong>Name:</strong> ${config.server.name}</p>
            <p><strong>Version:</strong> ${config.server.version}</p>
            <p><strong>Ports:</strong> TCP ${config.ports.game}, UDP ${config.ports.relay}</p>
            <p><strong>MOTD:</strong> ${config.server.motd}</p>
        </div>

        <div class="card">
            <h2>API Endpoints</h2>
            <ul>
                <li><a href="/status">/status</a> - JSON server status</li>
                <li><a href="/news">/news</a> - Server news</li>
            </ul>
        </div>
    </div>
</body>
</html>`;

        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(html);
    }

    _handleStatus(req, res) {
        const status = {
            server: {
                name: config.server.name,
                version: config.server.version,
                uptime: process.uptime(),
            },
            players: {
                online: this.tcpServer?.getClientCount() || 0,
                max: config.server.maxPlayers,
            },
            relay: this.udpServer?.getStats() || {},
            database: {
                users: database.users.size,
                sessions: database.sessions.size,
            },
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(status, null, 2));
    }

    _handleRedirector(req, res) {
        // EA redirector response
        // The game expects specific format
        const clientIP = req.socket.remoteAddress?.replace('::ffff:', '') || '127.0.0.1';
        
        const response = `ADDR=${clientIP}
PORT=${config.ports.game}
SESS=0
MASK=0`;

        log.debug(`Redirector response to ${clientIP}`);
        
        res.writeHead(200, { 
            'Content-Type': 'text/plain',
            'Connection': 'close',
        });
        res.end(response);
    }

    _handleNews(req, res) {
        const news = {
            motd: config.server.motd,
            news: [
                {
                    date: new Date().toISOString().split('T')[0],
                    title: 'Server Online!',
                    content: 'Welcome to NFSU2 Custom Server!',
                },
            ],
        };

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(news, null, 2));
    }

    _handleTOS(req, res) {
        // Terms of Service - format from captured NFSOR traffic
        // Format: %{ CMD=news TITLE="..." BTN1="Agree" BTN1-GOTO="$quit" BTN2="Disagree" BTN2-GOTO="$exit=-1" %} 
        // Followed by TOS text
        
        const tos = `%{ CMD=news TITLE="Terms of Service" BTN1="Agree" BTN1-GOTO="$quit" BTN2="Disagree" BTN2-GOTO="$exit=-1" %} 
NFSU2 Custom Server - Terms of Service

Welcome to NFSU2 Custom Server!

By clicking "Agree", you accept the following terms:

1. This is a community-run server for educational and preservation purposes.
2. Be respectful to other players.
3. No cheating or exploiting bugs.
4. Have fun racing!

Server: ${config.server.name}
Version: ${config.server.version}

MOTD: ${config.server.motd}
`;

        log.info(`TOS requested from ${req.socket.remoteAddress}`);
        
        res.writeHead(200, { 
            'Content-Type': 'application/octet-stream',
            'Content-Length': Buffer.byteLength(tos),
            'Connection': 'close',
        });
        res.end(tos);
    }

    _handle404(req, res) {
        log.warn(`404 Not Found: ${req.method} ${req.url}`);
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
}

export default HTTPServer;
