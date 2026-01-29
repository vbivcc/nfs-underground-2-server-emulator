// ============================================================================
// NFSU2 Server - Main Entry Point
// ============================================================================

import { createLogger } from './utils/logger.js';
import config from './config.js';
import TCPServer from './servers/tcp.js';
import UDPServer from './servers/udp.js';
import HTTPServer from './servers/http.js';
import database from './database/index.js';

const log = createLogger('Main');

// ASCII Art Banner
const banner = `
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ███╗   ██╗███████╗███████╗██╗   ██╗██████╗                ║
║     ████╗  ██║██╔════╝██╔════╝██║   ██║╚════██╗               ║
║     ██╔██╗ ██║█████╗  ███████╗██║   ██║ █████╔╝               ║
║     ██║╚██╗██║██╔══╝  ╚════██║██║   ██║██╔═══╝                ║
║     ██║ ╚████║██║     ███████║╚██████╔╝███████╗               ║
║     ╚═╝  ╚═══╝╚═╝     ╚══════╝ ╚════���╝ ╚══════╝               ║
║                                                               ║
║              Online Server Emulator v${config.server.version.padEnd(24)}║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
`;

async function main() {
    console.log(banner);
    
    log.info('Starting NFSU2 Server...');
    log.info(`Server name: ${config.server.name}`);

    // Start servers
    const udpServer = new UDPServer().start(config.ports.relay);
    const tcpServer = new TCPServer(udpServer).start();  // Pass UDP server for game registration
    const httpServer = new HTTPServer(tcpServer, udpServer).start(config.ports.http);

    log.info('All servers started!');
    log.info(`Ports:`);
    log.info(`  Base:     ${config.ports.base}`);
    log.info(`  SSL:      ${config.ports.ssl}`);
    log.info(`  Ping:     ${config.ports.ping}`);
    log.info(`  Game:     ${config.ports.game} (EA Protocol)`);
    log.info(`  HTTP:     ${config.ports.http} (TOS/News)`);
    log.info(`  Relay:    ${config.ports.relay} (UDP P2P)`);

    // Session cleanup interval
    setInterval(() => {
        database.cleanupSessions();
    }, 60000);

    // Status log interval
    setInterval(() => {
        const tcpClients = tcpServer.getClientCount();
        const udpStats = udpServer.getStats();
        log.info(`Status: ${tcpClients} players, ${udpStats.clients} P2P connections`);
    }, 300000); // Every 5 min

    // Graceful shutdown
    process.on('SIGINT', () => shutdown(tcpServer, udpServer, httpServer));
    process.on('SIGTERM', () => shutdown(tcpServer, udpServer, httpServer));

    log.info('Server ready! Press Ctrl+C to stop.');
}

function shutdown(tcp, udp, http) {
    log.info('Shutting down...');
    
    tcp?.stop();
    udp?.stop();
    http?.stop();
    
    log.info('Goodbye!');
    process.exit(0);
}

// Run
main().catch(err => {
    log.error('Fatal error:', err);
    process.exit(1);
});
