// ============================================================================
// NFSU2 Server - Game Session Management
// ============================================================================

import { createLogger } from '../utils/logger.js';
import { EventEmitter } from 'events';

const log = createLogger('Games');

class GameManager extends EventEmitter {
    constructor() {
        super();
        this.games = new Map();
        this.nextGameId = 1;
    }

    create(roomId, host, settings = {}) {
        const gameId = this.nextGameId++;
        
        const game = {
            id: gameId,
            roomId: roomId,
            host: host,
            created: Date.now(),
            started: null,
            ended: null,
            state: 'waiting', // waiting, countdown, racing, finished
            players: new Map(), // sessionId -> playerState
            settings: {
                track: settings.track || 0,
                laps: settings.laps || 3,
                mode: settings.mode || 'circuit', // circuit, sprint, drift, drag
                traffic: settings.traffic || true,
                catchup: settings.catchup || true,
                ...settings,
            },
            results: [],
        };

        this.games.set(gameId, game);
        log.info(`Game created: ID ${gameId} for room ${roomId}`);
        
        this.emit('gameCreated', game);
        return game;
    }

    get(gameId) {
        return this.games.get(gameId) || null;
    }

    getByRoom(roomId) {
        for (const game of this.games.values()) {
            if (game.roomId === roomId && game.state !== 'finished') {
                return game;
            }
        }
        return null;
    }

    addPlayer(gameId, sessionId, carData = {}) {
        const game = this.games.get(gameId);
        if (!game) return false;

        game.players.set(sessionId, {
            sessionId: sessionId,
            car: carData,
            position: 0,
            lap: 0,
            finished: false,
            finishTime: null,
            dnf: false,
        });

        log.debug(`Player ${sessionId} added to game ${gameId}`);
        this.emit('playerAdded', game, sessionId);
        return true;
    }

    removePlayer(gameId, sessionId) {
        const game = this.games.get(gameId);
        if (!game) return false;

        game.players.delete(sessionId);
        log.debug(`Player ${sessionId} removed from game ${gameId}`);
        
        // If no players left and game not finished, end it
        if (game.players.size === 0 && game.state !== 'finished') {
            this.end(gameId);
        }

        return true;
    }

    start(gameId) {
        const game = this.games.get(gameId);
        if (!game || game.state !== 'waiting') return false;

        game.state = 'countdown';
        game.started = Date.now();
        
        log.info(`Game ${gameId} starting countdown`);
        this.emit('gameStarting', game);

        // After countdown, change to racing
        setTimeout(() => {
            if (game.state === 'countdown') {
                game.state = 'racing';
                log.info(`Game ${gameId} racing started`);
                this.emit('gameStarted', game);
            }
        }, 5000); // 5 sec countdown

        return true;
    }

    playerFinished(gameId, sessionId, time) {
        const game = this.games.get(gameId);
        if (!game) return false;

        const player = game.players.get(sessionId);
        if (!player || player.finished) return false;

        player.finished = true;
        player.finishTime = time;
        player.position = game.results.length + 1;

        game.results.push({
            sessionId: sessionId,
            position: player.position,
            time: time,
        });

        log.info(`Player ${sessionId} finished game ${gameId} in position ${player.position}`);
        this.emit('playerFinished', game, sessionId, player.position);

        // Check if all players finished
        const allFinished = Array.from(game.players.values()).every(p => p.finished || p.dnf);
        if (allFinished) {
            this.end(gameId);
        }

        return true;
    }

    updatePlayerPosition(gameId, sessionId, lap, position) {
        const game = this.games.get(gameId);
        if (!game) return false;

        const player = game.players.get(sessionId);
        if (!player) return false;

        player.lap = lap;
        player.position = position;
        
        return true;
    }

    end(gameId) {
        const game = this.games.get(gameId);
        if (!game) return false;

        game.state = 'finished';
        game.ended = Date.now();

        log.info(`Game ${gameId} ended`);
        this.emit('gameEnded', game);

        // Cleanup after some time
        setTimeout(() => {
            this.games.delete(gameId);
            log.debug(`Game ${gameId} removed from memory`);
        }, 60000); // Keep for 1 min for stats

        return true;
    }

    getActiveGames() {
        return Array.from(this.games.values()).filter(g => g.state !== 'finished');
    }
}

// Singleton
const gameManager = new GameManager();
export default gameManager;
