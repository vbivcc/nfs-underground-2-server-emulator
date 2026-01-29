#pragma once

// ============================================================================
// NFSOR Custom - Configuration
// ============================================================================

// =============================================================================
// MODE SELECTION - Choose ONE mode:
// =============================================================================
// Mode 1: LOCAL SERVER - Connect to local emulator (SSL/encryption disabled)
// Mode 2: CAPTURE MODE - Connect to REAL NFSOR server, capture decrypted traffic
// Mode 3: UDP CAPTURE  - Capture UDP traffic without modifying it (for analysis)
// =============================================================================

#define MODE_LOCAL_SERVER   1   // Local server mode (default)
#define MODE_CAPTURE_REAL   2   // Capture from real server mode
#define MODE_UDP_CAPTURE    3   // UDP capture only mode (no relay modification)

// *** SELECT MODE HERE ***
// #define CURRENT_MODE        MODE_LOCAL_SERVER
// #define CURRENT_MODE        MODE_CAPTURE_REAL
#define CURRENT_MODE        MODE_LOCAL_SERVER

// =============================================================================
// Server settings based on mode
// =============================================================================
#if CURRENT_MODE == MODE_CAPTURE_REAL
    // Connect to REAL NFSOR server - DO NOT disable SSL/encryption!
    #define SERVER_HOSTNAME     "*45.131.64.63"  // Real NFSOR server
    #define DISABLE_SSL         0                 // 0 = Keep SSL enabled for real server!
    #define DISABLE_ENCRYPTION  0                 // 0 = Keep encryption enabled!
    #define HOOK_DECRYPTED_DATA 1                 // Hook to capture decrypted data
    #define UDP_CAPTURE_ONLY    0                 // Modify UDP for relay
#elif CURRENT_MODE == MODE_UDP_CAPTURE
    // UDP CAPTURE MODE - Connect to REAL server, capture ALL UDP without modifying
    #define SERVER_HOSTNAME     "*45.131.64.63"  // Real NFSOR server
    #define DISABLE_SSL         0                 // Keep SSL for real server
    #define DISABLE_ENCRYPTION  0                 // Keep encryption
    #define HOOK_DECRYPTED_DATA 1                 // Capture decrypted data
    #define UDP_CAPTURE_ONLY    1                 // *** CAPTURE UDP WITHOUT MODIFYING ***
#else
    // Connect to LOCAL server - disable SSL/encryption for easy debugging
    #define SERVER_HOSTNAME     "*135.181.20.250"      // Local server
    #define DISABLE_SSL         1                 // Disable SSL for local server
    #define DISABLE_ENCRYPTION  1                 // Disable encryption
    #define HOOK_DECRYPTED_DATA 1                 // Enable hooks to see game protocol
    #define UDP_CAPTURE_ONLY    0                 // 0 = RELAY MODE (add header), 1 = capture only
#endif

#define SERVER_PORT         20921            // Game server port (EA uses 0x51B8 = 20920)
#define RELAY_PORT          53               // UDP relay port - using DNS port to bypass NAT/firewall

// Debug settings
#define ENABLE_CONSOLE      1                // Enable debug console
#define ENABLE_LOGGING      1                // Enable file logging
#define ENABLE_TRAFFIC_LOG  1                // Enable traffic capture to file

// Game settings
#define ENABLE_WINDOWED_MODE 1               // Enable windowed mode (1 = windowed, 0 = fullscreen)

// Traffic capture file
#define TRAFFIC_LOG_FILE    "nfsor_traffic.log"
#define DECRYPTED_LOG_FILE  "nfsor_decrypted.log"  // For decrypted data capture

// Timeouts
#define UNPACK_TIMEOUT_MS   12000            // Wait for game to unpack (12 sec)
#define UNPACK_CHECK_INTERVAL 100            // Check interval in ms

// Legacy compatibility
#define CAPTURE_CERT_MODE   (CURRENT_MODE == MODE_CAPTURE_REAL ? 1 : 0)
