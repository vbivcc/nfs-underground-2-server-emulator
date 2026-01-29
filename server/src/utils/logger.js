// ============================================================================
// NFSU2 Server - Logger
// ============================================================================

import config from '../config.js';

const colors = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    gray: '\x1b[90m',
};

const levels = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
};

class Logger {
    constructor(module) {
        this.module = module;
        this.level = levels[config.logging.level] || 0;
    }

    _format(level, msg, ...args) {
        const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19);
        const prefix = `[${timestamp}] [${this.module}]`;
        
        if (config.logging.colors) {
            const levelColors = {
                debug: colors.gray,
                info: colors.green,
                warn: colors.yellow,
                error: colors.red,
            };
            return `${colors.cyan}${prefix}${colors.reset} ${levelColors[level]}[${level.toUpperCase()}]${colors.reset} ${msg}`;
        }
        return `${prefix} [${level.toUpperCase()}] ${msg}`;
    }

    debug(msg, ...args) {
        if (this.level <= levels.debug) {
            console.log(this._format('debug', msg), ...args);
        }
    }

    info(msg, ...args) {
        if (this.level <= levels.info) {
            console.log(this._format('info', msg), ...args);
        }
    }

    warn(msg, ...args) {
        if (this.level <= levels.warn) {
            console.warn(this._format('warn', msg), ...args);
        }
    }

    error(msg, ...args) {
        if (this.level <= levels.error) {
            console.error(this._format('error', msg), ...args);
        }
    }

    hex(label, buffer) {
        if (this.level <= levels.debug) {
            const hex = Buffer.isBuffer(buffer) 
                ? buffer.toString('hex').match(/.{1,2}/g)?.join(' ') || ''
                : buffer;
            this.debug(`${label}: ${hex}`);
        }
    }
}

export function createLogger(module) {
    return new Logger(module);
}

export default Logger;
