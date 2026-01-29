// ============================================================================
// NFSU2 Server - EA Binary Protocol
// Format: 12-byte header + payload
// Header: [4 bytes cmd][4 bytes status][4 bytes length]
// All values are big-endian
// ============================================================================

import { createLogger } from './logger.js';

const log = createLogger('Protocol');

/**
 * Command codes (4 bytes, stored as string like "AUTH", "PING", etc.)
 */
export const Commands = {
    AUTH: 'AUTH',   // Authentication
    PING: 'PING',   // Ping/keepalive
    PONG: 'GNOP',   // Pong response
    PERS: 'PERS',   // Persona
    SELE: 'SELE',   // Select
    NEWS: 'SWEN',   // News
    ADDR: 'RDDA',   // Address
    PORT: 'TROP',   // Port
    MESG: 'GSEM',   // Message
    MOVE: 'EVOM',   // Move
    ROOM: 'MOOR',   // Room
    USER: 'RESU',   // User
    RGET: 'TEGR',   // Room get
    ROST: 'TSOR',   // Roster
    PGET: 'TEGP',   // Persona get
    LLVL: 'LVLL',   // Lobby level
    SKEY: 'YEKS',   // Session key
    ACCT: 'TCCA',   // Account
    ONLN: 'NLNO',   // Online
    DPTS: 'STPD',   // ?
    DERR: 'RRED',   // Error
    VCER: 'RECV',   // ?
};

/**
 * Status/Error codes
 */
export const Status = {
    OK: 0,
    ERROR: -1,
    DUPLICATE: 0x6C707564,  // 'dupl'
    INVALID: 0x6C766E69,    // 'invl'
    TIMEOUT: 0x74756F74,    // 'tout'
};

/**
 * Convert 4-char command string to big-endian int
 * "AUTH" -> 0x41555448 (A=0x41, U=0x55, T=0x54, H=0x48)
 */
export function cmdToInt(cmd) {
    if (typeof cmd !== 'string' || cmd.length < 4) {
        return 0;
    }
    // Big-endian: first char is MSB
    return (cmd.charCodeAt(0) << 24) |
           (cmd.charCodeAt(1) << 16) |
           (cmd.charCodeAt(2) << 8) |
           cmd.charCodeAt(3);
}

/**
 * Convert big-endian int to 4-char command string
 * 0x41555448 -> "AUTH"
 */
export function intToCmd(val) {
    return String.fromCharCode(
        (val >> 24) & 0xFF,
        (val >> 16) & 0xFF,
        (val >> 8) & 0xFF,
        val & 0xFF
    );
}

/**
 * Build EA protocol packet
 * @param {string} cmd - 4-char command (e.g., "AUTH")
 * @param {number} status - Status code (0 = OK)
 * @param {string} payload - Payload string (key=value pairs)
 * @returns {Buffer}
 */
export function buildPacket(cmd, status, payload = '') {
    const payloadBuf = Buffer.from(payload, 'utf8');
    const packet = Buffer.alloc(12 + payloadBuf.length);
    
    // Command (4 bytes, big-endian)
    const cmdInt = cmdToInt(cmd);
    packet.writeUInt32BE(cmdInt, 0);
    
    // Status (4 bytes, big-endian)
    packet.writeInt32BE(status, 4);
    
    // Length (4 bytes, big-endian) - includes header
    packet.writeUInt32BE(12 + payloadBuf.length, 8);
    
    // Payload
    payloadBuf.copy(packet, 12);
    
    log.debug(`Build packet: cmd=${cmd} status=${status} len=${packet.length} payload="${payload.substring(0, 50)}"`);
    
    return packet;
}

/**
 * Parse EA protocol packet
 * @param {Buffer} data - Raw packet data
 * @returns {Object|null} Parsed packet or null if incomplete
 */
export function parsePacket(data) {
    if (!data || data.length < 12) {
        return null; // Need at least header
    }
    
    // Read header
    const cmdInt = data.readUInt32BE(0);
    const status = data.readInt32BE(4);
    const length = data.readUInt32BE(8);
    
    if (data.length < length) {
        return null; // Incomplete packet
    }
    
    const cmd = intToCmd(cmdInt);
    const payload = data.slice(12, length).toString('utf8');
    
    log.debug(`Parse packet: cmd=${cmd} status=${status} len=${length} payload="${payload.substring(0, 50)}"`);
    
    return {
        cmd,
        cmdInt,
        status,
        length,
        payload,
        raw: data.slice(0, length),
        remaining: data.length > length ? data.slice(length) : null,
    };
}

/**
 * Parse key=value payload string
 * @param {string} payload 
 * @returns {Object}
 */
export function parsePayload(payload) {
    const result = {};
    if (!payload) return result;
    
    // Format: key=value\nkey2=value2 or key=value\tkey2=value2
    const pairs = payload.split(/[\n\t\r]+/);
    
    for (const pair of pairs) {
        const eqIdx = pair.indexOf('=');
        if (eqIdx > 0) {
            const key = pair.substring(0, eqIdx).trim();
            let value = pair.substring(eqIdx + 1).trim();
            
            // Remove quotes if present
            if (value.startsWith('"') && value.endsWith('"')) {
                value = value.slice(1, -1);
            }
            
            result[key] = value;
        }
    }
    
    return result;
}

/**
 * Build key=value payload string
 * @param {Object} data 
 * @returns {string}
 */
export function buildPayload(data) {
    const pairs = [];
    
    for (const [key, value] of Object.entries(data)) {
        if (value === undefined || value === null) continue;
        
        let str = String(value);
        // Quote if contains special chars
        if (str.includes(' ') || str.includes('\t') || str.includes('\n')) {
            str = `"${str}"`;
        }
        pairs.push(`${key}=${str}`);
    }
    
    return pairs.join('\n');
}

export default {
    Commands,
    Status,
    cmdToInt,
    intToCmd,
    buildPacket,
    parsePacket,
    parsePayload,
    buildPayload,
};
