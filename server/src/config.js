// ============================================================================
// NFSU2 Server - Configuration
// Ports based on captured traffic from ug2.nfsor.net
// ============================================================================

export default {
    // Server ports (matching NFSOR ug2.nfsor.net)
    ports: {
        base: 20920,        // Base TCP port (game uses this as reference)
        ssl: 20921,         // SSL/TLS handshake for authentication
        ping: 20922,        // Ping/keepalive (ICMP-like)
        game: 20923,        // Main EA protocol (AUTH, PSET, EPGT, RGET, DISC)
        udpTunnel: 20924,   // UDP-over-TCP tunnel (for NAT bypass)
        http: 80,           // HTTP for TOS (Terms of Service), news
        relay: 53,          // UDP relay - using DNS port to bypass NAT/firewall (fallback)
    },

    // Server info
    server: {
        name: 'NFSU2 Custom Server',
        version: '1.0.0',
        maxPlayers: 100,
        motd: 'Welcome to NFSU2 Custom Server!',
        // Public IP for relay - clients will use this to send UDP packets
        // This IP is sent to clients in +ses so they know where to send UDP
        // For remote server: use your server's public IP
        // For localhost testing with 2 PCs: use server's LAN IP (e.g. 192.168.x.x)
        // NOTE: Set PUBLIC_IP environment variable or change default here!
        publicIP: process.env.PUBLIC_IP || '135.181.20.250',
    },

    // Timeouts (ms)
    timeouts: {
        client: 300000,     // 5 min client timeout
        ping: 30000,        // 30 sec ping interval
        session: 3600000,   // 1 hour session timeout
    },

    // Database (simple JSON for now)
    database: {
        path: './data',
        usersFile: 'users.json',
        statsFile: 'stats.json',
    },

    // Logging
    logging: {
        level: 'debug',     // debug, info, warn, error
        colors: true,
    },
};
