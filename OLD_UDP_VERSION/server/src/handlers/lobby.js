// ============================================================================
// NFSU2 Server - Lobby Handler
// Handles: ROOM, MOVE, MESG, USER, LLVL commands
// ============================================================================

import { createLogger } from '../utils/logger.js';
import { parseMessage, buildMessage } from '../utils/protocol.js';
import database from '../database/index.js';
import rooms from '../game/rooms.js';
import config from '../config.js';

const log = createLogger('Lobby');

// Connected clients in lobby
const lobbyClients = new Map();

/**
 * Handle LLVL command - Lobby level/list
 * Returns lobby information and room list
 */
export function handleLlvl(client, data) {
    const msg = parseMessage(data);
    log.debug('LLVL request:', msg);

    if (!client.session) {
        return sendError(client, 'LLVL', 'naut', 'Not authenticated');
    }

    // Add to lobby
    lobbyClients.set(client.session.id, client);

    // Get room list
    const roomList = rooms.list();
    
    const response = buildMessage({
        TYPE: 'LOBBY',
        COUNT: roomList.length,
        LIMIT: config.server.maxPlayers,
        MOTD: config.server.motd,
    });

    client.send(`@ack\t${response}`);
    
    // Send room list
    for (const room of roomList) {
        sendRoomInfo(client, room);
    }
}

/**
 * Handle ROOM command - Room operations
 * Operations: CREATE, JOIN, LEAVE, INFO
 */
export function handleRoom(client, data) {
    const msg = parseMessage(data);
    log.debug('ROOM request:', msg);

    if (!client.session) {
        return sendError(client, 'ROOM', 'naut', 'Not authenticated');
    }

    const op = (msg.OP || msg.CMD || 'INFO').toUpperCase();

    switch (op) {
        case 'CREATE':
        case 'CREA':
            return handleRoomCreate(client, msg);
        
        case 'JOIN':
        case 'GJOI':
            return handleRoomJoin(client, msg);
        
        case 'LEAVE':
        case 'GLEA':
            return handleRoomLeave(client, msg);
        
        case 'INFO':
        case 'LIST':
            return handleRoomList(client, msg);
        
        default:
            log.warn(`Unknown ROOM operation: ${op}`);
            sendError(client, 'ROOM', 'unkn', `Unknown operation: ${op}`);
    }
}

function handleRoomCreate(client, msg) {
    const name = msg.NAME || `${client.session.persona}'s Room`;
    const pass = msg.PASS || msg.SECRET || '';
    const maxPlayers = parseInt(msg.LIMIT) || 8;

    const room = rooms.create(name, client.session.id, {
        password: pass,
        maxPlayers: Math.min(maxPlayers, 8),
    });

    client.session.room = room.id;
    database.updateSession(client.session.id, { room: room.id });

    const response = buildMessage({
        IDENT: room.id,
        NAME: room.name,
        HOST: client.session.persona,
        COUNT: 1,
        LIMIT: room.maxPlayers,
        FLAGS: room.flags,
    });

    log.info(`Room created: ${room.name} by ${client.session.persona}`);
    client.send(`@ack\t${response}`);

    // Notify lobby
    broadcastToLobby(`+rom\t${buildMessage({
        IDENT: room.id,
        NAME: room.name,
        HOST: client.session.persona,
        COUNT: 1,
        LIMIT: room.maxPlayers,
    })}`);
}

function handleRoomJoin(client, msg) {
    const roomId = parseInt(msg.IDENT) || parseInt(msg.ROOM) || 0;
    const pass = msg.PASS || msg.SECRET || '';

    if (!roomId) {
        return sendError(client, 'ROOM', 'misg', 'Room ID required');
    }

    const result = rooms.join(roomId, client.session.id, pass);
    
    if (!result.success) {
        return sendError(client, 'ROOM', 'fail', result.error);
    }

    const room = result.room;
    client.session.room = room.id;
    database.updateSession(client.session.id, { room: room.id });

    const response = buildMessage({
        IDENT: room.id,
        NAME: room.name,
        COUNT: room.players.size,
        LIMIT: room.maxPlayers,
    });

    log.info(`${client.session.persona} joined room: ${room.name}`);
    client.send(`@ack\t${response}`);

    // Notify room players
    broadcastToRoom(room.id, `+usr\t${buildMessage({
        IDENT: client.session.odId,
        NAME: client.session.persona,
        ROOM: room.id,
    })}`, client.session.id);

    // Send existing players to new client
    for (const player of room.players.values()) {
        if (player.sessionId !== client.session.id) {
            const playerSession = database.getSessionByUserId(player.sessionId);
            if (playerSession) {
                client.send(`+usr\t${buildMessage({
                    IDENT: playerSession.odId,
                    NAME: playerSession.persona,
                    ROOM: room.id,
                })}`);
            }
        }
    }
}

function handleRoomLeave(client, msg) {
    const roomId = client.session?.room;
    
    if (!roomId) {
        return sendError(client, 'ROOM', 'notinroom', 'Not in a room');
    }

    rooms.leave(roomId, client.session.id);
    
    client.session.room = null;
    database.updateSession(client.session.id, { room: null });

    log.info(`${client.session.persona} left room ${roomId}`);
    client.send(`@ack\tROOM`);

    // Notify room
    broadcastToRoom(roomId, `-usr\t${buildMessage({
        IDENT: client.session.odId,
    })}`);
}

function handleRoomList(client, msg) {
    const roomList = rooms.list();
    
    for (const room of roomList) {
        sendRoomInfo(client, room);
    }

    client.send(`@ack\tROOM\tCOUNT=${roomList.length}`);
}

/**
 * Handle MESG command - Chat messages
 */
export function handleMesg(client, data) {
    const msg = parseMessage(data);
    log.debug('MESG request:', msg);

    if (!client.session) {
        return sendError(client, 'MESG', 'naut', 'Not authenticated');
    }

    const text = msg.TEXT || msg.MSG || '';
    const roomId = client.session.room;

    if (!text) return;

    const message = buildMessage({
        NAME: client.session.persona,
        TEXT: text,
        ROOM: roomId || 0,
    });

    if (roomId) {
        // Room chat
        broadcastToRoom(roomId, `+msg\t${message}`);
    } else {
        // Lobby chat
        broadcastToLobby(`+msg\t${message}`);
    }
}

/**
 * Handle USER command - User info request
 */
export function handleUser(client, data) {
    const msg = parseMessage(data);
    log.debug('USER request:', msg);

    const targetId = parseInt(msg.IDENT) || 0;
    const targetSession = database.getSessionByUserId(targetId);

    if (!targetSession) {
        return sendError(client, 'USER', 'notfound', 'User not found');
    }

    const response = buildMessage({
        IDENT: targetSession.odId,
        NAME: targetSession.persona,
        ROOM: targetSession.room || 0,
        ADDR: targetSession.addr,
    });

    client.send(`@ack\t${response}`);
}

/**
 * Handle MOVE command - Move to room/lobby
 */
export function handleMove(client, data) {
    const msg = parseMessage(data);
    log.debug('MOVE request:', msg);

    // Similar to room operations
    const dest = msg.DEST || msg.TO || 'LOBBY';
    
    if (dest === 'LOBBY' || dest === '0') {
        // Leave current room
        if (client.session?.room) {
            handleRoomLeave(client, {});
        }
        client.send(`@ack\tMOVE`);
    }
}

// ======================== Helpers ========================

function sendError(client, cmd, code, message) {
    client.send(`@err\t${cmd}\tERR=${code}\tMSG=${message}`);
}

function sendRoomInfo(client, room) {
    client.send(`+rom\t${buildMessage({
        IDENT: room.id,
        NAME: room.name,
        HOST: room.host,
        COUNT: room.players,
        LIMIT: room.maxPlayers,
        FLAGS: room.hasPassword ? 1 : 0,
    })}`);
}

function broadcastToLobby(message, excludeSessionId = null) {
    for (const [sessionId, client] of lobbyClients) {
        if (sessionId !== excludeSessionId) {
            try {
                client.send(message);
            } catch (e) {
                lobbyClients.delete(sessionId);
            }
        }
    }
}

function broadcastToRoom(roomId, message, excludeSessionId = null) {
    const room = rooms.get(roomId);
    if (!room) return;

    for (const player of room.players.values()) {
        if (player.sessionId !== excludeSessionId) {
            const client = lobbyClients.get(player.sessionId);
            if (client) {
                try {
                    client.send(message);
                } catch (e) {
                    // Client disconnected
                }
            }
        }
    }
}

export function removeFromLobby(sessionId) {
    lobbyClients.delete(sessionId);
}

export default {
    handleLlvl,
    handleRoom,
    handleMesg,
    handleUser,
    handleMove,
    removeFromLobby,
};
