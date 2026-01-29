// ============================================================================
// NFSU2 Server - Game Handler
// Handles: GAME, GSET, GCRE, GJOI, GLEA, CHAL commands
// ============================================================================

import { createLogger } from '../utils/logger.js';
import { parseMessage, buildMessage } from '../utils/protocol.js';
import database from '../database/index.js';
import rooms from '../game/rooms.js';
import games from '../game/games.js';

const log = createLogger('Game');

/**
 * Handle GAME command - Game operations
 */
export function handleGame(client, data) {
    const msg = parseMessage(data);
    log.debug('GAME request:', msg);

    if (!client.session) {
        return sendError(client, 'GAME', 'naut', 'Not authenticated');
    }

    const op = (msg.OP || msg.CMD || 'INFO').toUpperCase();

    switch (op) {
        case 'CREATE':
        case 'GCRE':
            return handleGameCreate(client, msg);
        
        case 'JOIN':
            return handleGameJoin(client, msg);
        
        case 'LEAVE':
            return handleGameLeave(client, msg);
        
        case 'START':
            return handleGameStart(client, msg);
        
        case 'FINISH':
        case 'END':
            return handleGameFinish(client, msg);
        
        default:
            return handleGameInfo(client, msg);
    }
}

function handleGameCreate(client, msg) {
    const roomId = client.session?.room;
    
    if (!roomId) {
        return sendError(client, 'GAME', 'noroom', 'Must be in a room');
    }

    const room = rooms.get(roomId);
    if (!room) {
        return sendError(client, 'GAME', 'noroom', 'Room not found');
    }

    // Check if client is host
    const player = room.players.get(client.session.id);
    if (!player?.isHost) {
        return sendError(client, 'GAME', 'nothost', 'Only host can create game');
    }

    // Create game with settings
    const game = games.create(roomId, client.session.id, {
        track: parseInt(msg.TRACK) || 0,
        laps: parseInt(msg.LAPS) || 3,
        mode: msg.MODE || 'circuit',
        traffic: msg.TRAFFIC !== '0',
        catchup: msg.CATCHUP !== '0',
    });

    // Add all room players to game
    for (const [sessionId, _] of room.players) {
        games.addPlayer(game.id, sessionId);
    }

    client.session.game = game.id;
    room.state = 'starting';

    const response = buildMessage({
        IDENT: game.id,
        ROOM: roomId,
        HOST: client.session.persona,
        TRACK: game.settings.track,
        LAPS: game.settings.laps,
        MODE: game.settings.mode,
    });

    log.info(`Game created: ${game.id} in room ${room.name}`);
    
    // Notify all players
    broadcastToRoom(roomId, `+gam\t${response}`);
}

function handleGameJoin(client, msg) {
    const gameId = parseInt(msg.IDENT) || client.session?.game;
    
    if (!gameId) {
        return sendError(client, 'GAME', 'misg', 'Game ID required');
    }

    const game = games.get(gameId);
    if (!game) {
        return sendError(client, 'GAME', 'notfound', 'Game not found');
    }

    games.addPlayer(gameId, client.session.id, {
        car: msg.CAR || 0,
    });

    client.session.game = gameId;

    const response = buildMessage({
        IDENT: gameId,
        COUNT: game.players.size,
    });

    client.send(`@ack\t${response}`);
}

function handleGameLeave(client, msg) {
    const gameId = client.session?.game;
    
    if (!gameId) {
        return sendError(client, 'GAME', 'notingame', 'Not in a game');
    }

    games.removePlayer(gameId, client.session.id);
    client.session.game = null;

    log.info(`${client.session.persona} left game ${gameId}`);
    client.send(`@ack\tGAME`);
}

function handleGameStart(client, msg) {
    const gameId = client.session?.game;
    
    if (!gameId) {
        return sendError(client, 'GAME', 'notingame', 'Not in a game');
    }

    const game = games.get(gameId);
    if (!game) {
        return sendError(client, 'GAME', 'notfound', 'Game not found');
    }

    // Check if host
    if (game.host !== client.session.id) {
        return sendError(client, 'GAME', 'nothost', 'Only host can start');
    }

    games.start(gameId);

    // Notify all players
    broadcastToRoom(game.roomId, `+gam\t${buildMessage({
        IDENT: gameId,
        STATE: 'starting',
    })}`);
}

function handleGameFinish(client, msg) {
    const gameId = client.session?.game;
    
    if (!gameId) return;

    const time = parseInt(msg.TIME) || 0;
    games.playerFinished(gameId, client.session.id, time);

    log.info(`${client.session.persona} finished game ${gameId} in ${time}ms`);
}

function handleGameInfo(client, msg) {
    const gameId = parseInt(msg.IDENT) || client.session?.game;
    
    if (!gameId) {
        return sendError(client, 'GAME', 'misg', 'Game ID required');
    }

    const game = games.get(gameId);
    if (!game) {
        return sendError(client, 'GAME', 'notfound', 'Game not found');
    }

    const response = buildMessage({
        IDENT: game.id,
        ROOM: game.roomId,
        STATE: game.state,
        COUNT: game.players.size,
        TRACK: game.settings.track,
        LAPS: game.settings.laps,
    });

    client.send(`@ack\t${response}`);
}

/**
 * Handle GSET command - Game settings
 */
export function handleGset(client, data) {
    const msg = parseMessage(data);
    log.debug('GSET request:', msg);

    const roomId = client.session?.room;
    if (!roomId) {
        return sendError(client, 'GSET', 'noroom', 'Not in a room');
    }

    // Broadcast settings to room
    broadcastToRoom(roomId, `+gst\t${data}`);
    client.send(`@ack\tGSET`);
}

/**
 * Handle CHAL command - Challenge/Quick match
 */
export function handleChal(client, data) {
    const msg = parseMessage(data);
    log.debug('CHAL request:', msg);

    // TODO: Implement matchmaking
    client.send(`@ack\tCHAL`);
}

// ======================== Helpers ========================

function sendError(client, cmd, code, message) {
    client.send(`@err\t${cmd}\tERR=${code}\tMSG=${message}`);
}

function broadcastToRoom(roomId, message) {
    const room = rooms.get(roomId);
    if (!room) return;

    for (const player of room.players.values()) {
        const session = database.getSessionByUserId(player.sessionId);
        if (session?.client) {
            try {
                session.client.send(message);
            } catch (e) {
                // Client disconnected
            }
        }
    }
}

export default {
    handleGame,
    handleGset,
    handleChal,
};
