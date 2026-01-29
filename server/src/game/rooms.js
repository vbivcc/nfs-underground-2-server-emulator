// ============================================================================
// NFSU2 Server - Room Management
// ============================================================================

import { createLogger } from '../utils/logger.js';
import { EventEmitter } from 'events';

const log = createLogger('Rooms');

class RoomManager extends EventEmitter {
    constructor() {
        super();
        this.rooms = new Map();
        this.nextRoomId = 1;
    }

    create(name, host, options = {}) {
        const roomId = this.nextRoomId++;
        
        const room = {
            id: roomId,
            name: name || `Room ${roomId}`,
            host: host, // Session ID of host
            password: options.password || '',
            maxPlayers: options.maxPlayers || 8,
            flags: options.flags || 0,
            created: Date.now(),
            players: new Map(), // sessionId -> playerInfo
            state: 'lobby', // lobby, starting, ingame
            gameSettings: options.gameSettings || {},
        };

        // Add host to room
        room.players.set(host, {
            sessionId: host,
            isHost: true,
            ready: false,
            joinedAt: Date.now(),
        });

        this.rooms.set(roomId, room);
        log.info(`Room created: ${room.name} (ID: ${roomId}) by ${host}`);
        
        this.emit('roomCreated', room);
        return room;
    }

    get(roomId) {
        return this.rooms.get(roomId) || null;
    }

    getByName(name) {
        for (const room of this.rooms.values()) {
            if (room.name.toLowerCase() === name.toLowerCase()) {
                return room;
            }
        }
        return null;
    }

    list() {
        return Array.from(this.rooms.values()).map(room => ({
            id: room.id,
            name: room.name,
            host: room.host,
            players: room.players.size,
            maxPlayers: room.maxPlayers,
            hasPassword: !!room.password,
            state: room.state,
        }));
    }

    join(roomId, sessionId, password = '') {
        const room = this.rooms.get(roomId);
        if (!room) {
            return { success: false, error: 'Room not found' };
        }

        if (room.password && room.password !== password) {
            return { success: false, error: 'Invalid password' };
        }

        if (room.players.size >= room.maxPlayers) {
            return { success: false, error: 'Room is full' };
        }

        if (room.state !== 'lobby') {
            return { success: false, error: 'Game already in progress' };
        }

        room.players.set(sessionId, {
            sessionId: sessionId,
            isHost: false,
            ready: false,
            joinedAt: Date.now(),
        });

        log.info(`Player ${sessionId} joined room ${room.name}`);
        this.emit('playerJoined', room, sessionId);
        
        return { success: true, room };
    }

    leave(roomId, sessionId) {
        const room = this.rooms.get(roomId);
        if (!room) return false;

        const wasHost = room.players.get(sessionId)?.isHost;
        room.players.delete(sessionId);

        log.info(`Player ${sessionId} left room ${room.name}`);
        this.emit('playerLeft', room, sessionId);

        // If room is empty, delete it
        if (room.players.size === 0) {
            this.rooms.delete(roomId);
            log.info(`Room ${room.name} deleted (empty)`);
            this.emit('roomDeleted', room);
            return true;
        }

        // If host left, assign new host
        if (wasHost) {
            const newHost = room.players.keys().next().value;
            if (newHost) {
                room.players.get(newHost).isHost = true;
                room.host = newHost;
                log.info(`New host for ${room.name}: ${newHost}`);
                this.emit('hostChanged', room, newHost);
            }
        }

        return true;
    }

    setReady(roomId, sessionId, ready) {
        const room = this.rooms.get(roomId);
        if (!room) return false;

        const player = room.players.get(sessionId);
        if (!player) return false;

        player.ready = ready;
        this.emit('playerReady', room, sessionId, ready);
        
        return true;
    }

    getPlayersInRoom(roomId) {
        const room = this.rooms.get(roomId);
        if (!room) return [];
        return Array.from(room.players.values());
    }

    findRoomByPlayer(sessionId) {
        for (const room of this.rooms.values()) {
            if (room.players.has(sessionId)) {
                return room;
            }
        }
        return null;
    }

    delete(roomId) {
        const room = this.rooms.get(roomId);
        if (!room) return false;

        this.rooms.delete(roomId);
        log.info(`Room deleted: ${room.name}`);
        this.emit('roomDeleted', room);
        return true;
    }
}

// Singleton
const roomManager = new RoomManager();
export default roomManager;
