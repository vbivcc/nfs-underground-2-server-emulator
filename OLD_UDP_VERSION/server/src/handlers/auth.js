// ============================================================================
// NFSU2 Server - Authentication Handler
// Handles: AUTH, PERS, SKEY commands
// ============================================================================

import { createLogger } from '../utils/logger.js';
import { parseMessage, buildMessage } from '../utils/protocol.js';
import database from '../database/index.js';

const log = createLogger('Auth');

/**
 * Handle AUTH command - Login/Register
 * Client sends: AUTH TOS=1 NAME=username PASS=password ...
 * Server responds with session info or error
 */
export function handleAuth(client, data) {
    const msg = parseMessage(data);
    log.debug('AUTH request:', msg);

    const name = msg.NAME || '';
    const pass = msg.PASS || '';
    const tos = parseInt(msg.TOS) || 0;

    // Check TOS agreement
    if (tos < 1) {
        return sendAuthError(client, 'tosa', 'Must accept Terms of Service');
    }

    // Validate name
    if (!name || name.length < 3 || name.length > 16) {
        return sendAuthError(client, 'misg', 'Invalid username');
    }

    // Try to login or register
    let user = database.getUser(name);
    
    if (!user) {
        // Auto-register new user
        const result = database.createUser(name, pass);
        if (!result.success) {
            return sendAuthError(client, 'dupl', result.error);
        }
        user = result.user;
        log.info(`New user registered: ${name}`);
    } else {
        // Validate password
        const result = database.validateUser(name, pass);
        if (!result.success) {
            return sendAuthError(client, 'pass', result.error);
        }
        user = result.user;
    }

    // Create session
    const session = database.createSession(user.id, {
        addr: client.address,
        port: client.port,
        name: name,
    });

    client.session = session;
    client.user = user;

    // Send success response
    const response = buildMessage({
        SESS: session.odId,
        LKEY: generateLKey(),
        NAME: user.name,
        ADDR: client.address,
        // Additional user info
        PERSONAS: user.personas.length,
    });

    log.info(`User logged in: ${name} (session: ${session.id})`);
    client.send(`@ack\t${response}`);
}

/**
 * Handle PERS command - Select persona
 * Client sends: PERS PERS=personaname
 */
export function handlePers(client, data) {
    const msg = parseMessage(data);
    log.debug('PERS request:', msg);

    if (!client.session) {
        return sendError(client, 'PERS', 'naut', 'Not authenticated');
    }

    const persona = msg.PERS || msg.NAME || client.user?.name;
    
    if (!persona) {
        return sendError(client, 'PERS', 'misg', 'Persona name required');
    }

    // Update session with selected persona
    client.session.persona = persona;
    database.updateSession(client.session.id, { persona });

    // Get user stats
    const user = client.user;
    const stats = user?.stats || {};

    const response = buildMessage({
        PERS: persona,
        LKEY: generateLKey(),
        // Stats
        'EX-userinfo': `STAT=${stats.rep || 0}`,
    });

    log.info(`Persona selected: ${persona}`);
    client.send(`@ack\t${response}`);
}

/**
 * Handle SKEY command - Session key validation
 */
export function handleSkey(client, data) {
    const msg = parseMessage(data);
    log.debug('SKEY request:', msg);

    if (!client.session) {
        return sendError(client, 'SKEY', 'naut', 'Not authenticated');
    }

    const response = buildMessage({
        SKEY: generateLKey(),
    });

    client.send(`@ack\t${response}`);
}

/**
 * Handle ACCT command - Account info
 */
export function handleAcct(client, data) {
    const msg = parseMessage(data);
    log.debug('ACCT request:', msg);

    // For registration or account lookup
    const name = msg.NAME || '';
    
    // Check if user exists
    const exists = database.getUser(name) !== null;

    const response = buildMessage({
        NAME: name,
        PERSONAS: exists ? 1 : 0,
    });

    client.send(`@ack\t${response}`);
}

// ======================== Helpers ========================

function sendAuthError(client, code, message) {
    log.warn(`Auth error: ${code} - ${message}`);
    client.send(`@err\tAUTH\tERR=${code}\tMSG=${message}`);
}

function sendError(client, cmd, code, message) {
    log.warn(`Error ${cmd}: ${code} - ${message}`);
    client.send(`@err\t${cmd}\tERR=${code}\tMSG=${message}`);
}

function generateLKey() {
    // Generate session key (32 hex chars)
    return [...Array(32)].map(() => Math.floor(Math.random() * 16).toString(16)).join('');
}

export default {
    handleAuth,
    handlePers,
    handleSkey,
    handleAcct,
};
