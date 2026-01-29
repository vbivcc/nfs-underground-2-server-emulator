// ============================================================================
// NFSU2 Server - Simple JSON Database
// ============================================================================

import fs from 'fs';
import path from 'path';
import { createLogger } from '../utils/logger.js';
import config from '../config.js';

const log = createLogger('Database');

class Database {
    constructor() {
        this.dataPath = config.database.path;
        this.users = new Map();
        this.stats = new Map();
        this.sessions = new Map();
        
        this._ensureDir();
        this._load();
    }

    _ensureDir() {
        if (!fs.existsSync(this.dataPath)) {
            fs.mkdirSync(this.dataPath, { recursive: true });
            log.info(`Created data directory: ${this.dataPath}`);
        }
    }

    _load() {
        try {
            const usersPath = path.join(this.dataPath, config.database.usersFile);
            if (fs.existsSync(usersPath)) {
                const data = JSON.parse(fs.readFileSync(usersPath, 'utf8'));
                for (const [key, value] of Object.entries(data)) {
                    this.users.set(key, value);
                }
                log.info(`Loaded ${this.users.size} users`);
            }
        } catch (err) {
            log.error('Failed to load users:', err.message);
        }

        try {
            const statsPath = path.join(this.dataPath, config.database.statsFile);
            if (fs.existsSync(statsPath)) {
                const data = JSON.parse(fs.readFileSync(statsPath, 'utf8'));
                for (const [key, value] of Object.entries(data)) {
                    this.stats.set(key, value);
                }
                log.info(`Loaded ${this.stats.size} stats records`);
            }
        } catch (err) {
            log.error('Failed to load stats:', err.message);
        }
    }

    _saveUsers() {
        try {
            const usersPath = path.join(this.dataPath, config.database.usersFile);
            const data = Object.fromEntries(this.users);
            fs.writeFileSync(usersPath, JSON.stringify(data, null, 2));
        } catch (err) {
            log.error('Failed to save users:', err.message);
        }
    }

    _saveStats() {
        try {
            const statsPath = path.join(this.dataPath, config.database.statsFile);
            const data = Object.fromEntries(this.stats);
            fs.writeFileSync(statsPath, JSON.stringify(data, null, 2));
        } catch (err) {
            log.error('Failed to save stats:', err.message);
        }
    }

    // ======================== Users ========================

    createUser(name, password, email = '') {
        const nameLower = name.toLowerCase();
        
        if (this.users.has(nameLower)) {
            return { success: false, error: 'User already exists' };
        }

        const user = {
            id: Date.now(),
            name: name,
            nameLower: nameLower,
            password: password, // TODO: hash in production
            mail: email,  // Store as 'mail' to match protocol
            email: email, // Keep both for compatibility
            born: '19800101',  // Default birth date
            created: new Date().toISOString(),
            lastLogin: null,
            personas: [], // Empty - player creates personas via 'cper' command
            stats: {
                // Basic stats
                wins: 0,
                losses: 0,
                races: 0,
                rep: 0,
                maxRep: 0,
                level: 1,
                // Race type specific
                circuitLaps: 0,
                circuitWins: 0,
                sprintWins: 0,
                dragWins: 0,
                driftScore: 0,
                streetXWins: 0,
                urlWins: 0,
            },
        };

        this.users.set(nameLower, user);
        this._saveUsers();
        
        log.info(`Created user: ${name}`);
        return { success: true, user };
    }

    getUser(name) {
        return this.users.get(name.toLowerCase()) || null;
    }

    validateUser(name, password) {
        const user = this.getUser(name);
        if (!user) return { success: false, error: 'User not found' };
        
        // NFSU2 password behavior (from traffic analysis):
        // - The game sends hashed passwords in format: $<hex_hash>  
        // - The hash includes session data (MASK), so it changes every login
        // - IMPORTANTLY: Same password = same hash regardless of username!
        //   (NAME=zalupa PASS=$ec92382e81f4 and NAME=debil123 PASS=$ec92382e81f4)
        // - Real NFSOR only checks if account EXISTS, not the actual password!
        //
        // This means EA's "security" was: if you know an account name exists,
        // you can login as them. The password hash just proves you're using
        // a real game client, not that you know the password.
        //
        // For our server, we mimic this behavior (account existence = login OK)
        // but we also validate the hash format to filter out fake clients.
        
        log.debug(`User ${name} login - stored: ${user.password?.substring(0,12)}..., received: ${password?.substring(0,12)}...`);
        
        // Validate password format - must start with $ (hashed from game client)
        if (!password || !password.startsWith('$')) {
            log.warn(`User ${name}: Invalid password format (missing $ prefix) - rejecting`);
            return { success: false, error: 'Invalid password format' };
        }
        
        // Validate password is reasonable length (at least $XXXX = 5 chars)
        if (password.length < 5) {
            log.warn(`User ${name}: Password hash too short - rejecting`);
            return { success: false, error: 'Invalid password' };
        }
        
        // Account exists + valid hash format = login success
        // This matches real NFSOR behavior
        user.lastLogin = new Date().toISOString();
        this._saveUsers();
        
        return { success: true, user };
    }

    updateUserStats(name, stats) {
        const user = this.getUser(name);
        if (!user) return false;
        
        Object.assign(user.stats, stats);
        this._saveUsers();
        return true;
    }

    addPersona(userId, personaName) {
        // Find user by ID
        for (const user of this.users.values()) {
            if (user.id === userId) {
                // Check if persona already exists
                if (user.personas.includes(personaName)) {
                    return { success: false, error: 'Persona already exists' };
                }
                
                // Add persona
                user.personas.push(personaName);
                this._saveUsers();
                
                log.info(`Added persona '${personaName}' to user ${user.name}`);
                return { success: true };
            }
        }
        return { success: false, error: 'User not found' };
    }

    getPersonas(userId) {
        for (const user of this.users.values()) {
            if (user.id === userId) {
                return user.personas || [];
            }
        }
        return [];
    }

    deletePersona(userId, personaName) {
        for (const user of this.users.values()) {
            if (user.id === userId) {
                const idx = user.personas.indexOf(personaName);
                if (idx > -1) {
                    user.personas.splice(idx, 1);
                    this._saveUsers();
                    log.info(`Deleted persona '${personaName}' from user ${user.name}`);
                    return { success: true };
                }
                return { success: false, error: 'Persona not found' };
            }
        }
        return { success: false, error: 'User not found' };
    }

    // ======================== Sessions ========================

    createSession(userId, clientInfo = {}) {
        const sessionId = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
        const numericId = Math.floor(Math.random() * 0xFFFFFFFF); // Session numeric ID
        
        const session = {
            id: sessionId,
            odId: numericId,
            userId: userId,
            created: Date.now(),
            lastActivity: Date.now(),
            clientInfo: clientInfo,
            persona: null,
            room: null,
            game: null,
            addr: clientInfo.addr || '0.0.0.0',
            port: clientInfo.port || 0,
        };

        this.sessions.set(sessionId, session);
        return session;
    }

    getSession(sessionId) {
        return this.sessions.get(sessionId) || null;
    }

    getSessionByUserId(odId) {
        for (const session of this.sessions.values()) {
            if (session.odId === odId) return session;
        }
        return null;
    }

    updateSession(sessionId, data) {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        
        Object.assign(session, data);
        session.lastActivity = Date.now();
        return true;
    }

    deleteSession(sessionId) {
        return this.sessions.delete(sessionId);
    }

    cleanupSessions() {
        const now = Date.now();
        let removed = 0;
        
        for (const [id, session] of this.sessions) {
            if (now - session.lastActivity > config.timeouts.session) {
                this.sessions.delete(id);
                removed++;
            }
        }
        
        if (removed > 0) {
            log.info(`Cleaned up ${removed} expired sessions`);
        }
    }

    // ======================== Leaderboards ========================

    getLeaderboard(channel, start = 0, count = 100) {
        // Get sorted leaderboard data
        // Channel values:
        // 6 = Overall ranking (total wins/rep)
        // 12 = Circuit ranking
        // Other channels can be added as needed
        
        const players = [];
        
        for (const user of this.users.values()) {
            const stats = user.stats || {};
            let points = 0;
            let statStr = '0,0,0';
            
            switch (channel) {
                case 6:  // Overall
                    points = stats.rep || 0;
                    statStr = `${stats.wins || 0},${stats.losses || 0},${stats.races || 0}`;
                    break;
                case 12: // Circuit
                    points = stats.circuitWins || 0;
                    statStr = `${stats.circuitWins || 0},${stats.circuitLaps || 0},0`;
                    break;
                default:
                    points = stats.rep || 0;
                    statStr = `${stats.wins || 0},0,0`;
            }
            
            // Add each persona to leaderboard
            for (const persona of (user.personas || [])) {
                players.push({
                    name: persona,
                    points: points,
                    stats: statStr,
                    online: this._isPersonaOnline(persona),
                });
            }
        }
        
        // Sort by points descending
        players.sort((a, b) => b.points - a.points);
        
        // Return requested range
        return players.slice(start, start + count);
    }

    _isPersonaOnline(personaName) {
        // Check if any active session has this persona
        for (const session of this.sessions.values()) {
            if (session.persona === personaName) {
                return true;
            }
        }
        return false;
    }

    getPlayerRank(personaName, channel = 6) {
        const leaderboard = this.getLeaderboard(channel, 0, 100000);
        const idx = leaderboard.findIndex(p => p.name === personaName);
        return idx >= 0 ? idx + 1 : -1;
    }
}

// Singleton
const database = new Database();
export default database;
