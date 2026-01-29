// ============================================================================
// NFSU2 Server - Protocol Parser/Builder
// EA FN Protocol format: KEY=VALUE pairs separated by tabs/spaces
// ============================================================================

import { createLogger } from './logger.js';

const log = createLogger('Protocol');

/**
 * Parse EA protocol message (KEY=VALUE format)
 * @param {string|Buffer} data - Raw message data
 * @returns {Object} Parsed key-value pairs
 */
export function parseMessage(data) {
    const str = Buffer.isBuffer(data) ? data.toString('utf8') : data;
    const result = {};
    
    // Split by whitespace or tab
    const pairs = str.split(/[\t\s]+/);
    
    for (const pair of pairs) {
        const eqIndex = pair.indexOf('=');
        if (eqIndex > 0) {
            const key = pair.substring(0, eqIndex).trim();
            let value = pair.substring(eqIndex + 1).trim();
            
            // Remove quotes if present
            if (value.startsWith('"') && value.endsWith('"')) {
                value = value.slice(1, -1);
            }
            
            // URL decode special chars (%XX)
            try {
                value = decodeURIComponent(value.replace(/%([0-9A-Fa-f]{2})/g, '%$1'));
            } catch (e) {
                // Keep original if decode fails
            }
            
            result[key] = value;
        }
    }
    
    return result;
}

/**
 * Build EA protocol message from object
 * @param {Object} data - Key-value pairs to encode
 * @returns {string} Encoded message
 */
export function buildMessage(data) {
    const pairs = [];
    
    for (const [key, value] of Object.entries(data)) {
        if (value === undefined || value === null) continue;
        
        let encoded = String(value);
        
        // Encode special characters
        encoded = encoded.replace(/[%=":\x00-\x1f\x7f]/g, (c) => {
            return '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
        });
        
        // Quote if contains spaces
        if (encoded.includes(' ')) {
            encoded = `"${encoded}"`;
        }
        
        pairs.push(`${key}=${encoded}`);
    }
    
    return pairs.join('\t');
}

/**
 * Parse relay packet header (6 bytes: 2 port + 4 IP)
 * @param {Buffer} buffer 
 * @returns {Object|null}
 */
export function parseRelayHeader(buffer) {
    if (!buffer || buffer.length < 6) return null;
    
    return {
        port: buffer.readUInt16BE(0),
        ip: `${buffer[2]}.${buffer[3]}.${buffer[4]}.${buffer[5]}`,
        payload: buffer.slice(6),
    };
}

/**
 * Build relay packet header
 * @param {string} ip - Destination IP
 * @param {number} port - Destination port
 * @param {Buffer} payload - Data to send
 * @returns {Buffer}
 */
export function buildRelayHeader(ip, port, payload) {
    const header = Buffer.alloc(6);
    header.writeUInt16BE(port, 0);
    
    const ipParts = ip.split('.').map(Number);
    header[2] = ipParts[0] || 0;
    header[3] = ipParts[1] || 0;
    header[4] = ipParts[2] || 0;
    header[5] = ipParts[3] || 0;
    
    return Buffer.concat([header, payload]);
}

/**
 * Convert IP string to integer
 */
export function ipToInt(ip) {
    const parts = ip.split('.').map(Number);
    return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

/**
 * Convert integer to IP string
 */
export function intToIp(num) {
    return [
        (num >>> 24) & 255,
        (num >>> 16) & 255,
        (num >>> 8) & 255,
        num & 255,
    ].join('.');
}

export default {
    parseMessage,
    buildMessage,
    parseRelayHeader,
    buildRelayHeader,
    ipToInt,
    intToIp,
};
