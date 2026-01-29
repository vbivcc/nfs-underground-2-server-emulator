#pragma once

// ============================================================================
// NFSOR Custom - Configuration
// ============================================================================

// =============================================================================
// MODE SELECTION - Choose ONE mode:
// =============================================================================
// Mode 1: LOCAL SERVER - Connect to local emulator (SSL/encryption disabled)
// Mode 2: CAPTURE MODE - Connect to REAL NFSOR server, capture decrypted traffic
// =============================================================================

#define MODE_LOCAL_SERVER   1   // Local server mode (default)
#define MODE_CAPTURE_REAL   2   // Capture from real server mode

// *** SELECT MODE HERE ***
 #define CURRENT_MODE        MODE_LOCAL_SERVER
// #define CURRENT_MODE        MODE_CAPTURE_REAL

// =============================================================================
// Server settings based on mode
// =============================================================================
#if CURRENT_MODE == MODE_CAPTURE_REAL
    // Connect to REAL NFSOR server - DO NOT disable SSL/encryption!
    #define SERVER_HOSTNAME     "*ug2.nfsor.net"  // Real NFSOR server
    #define DISABLE_SSL         0                 // 0 = Keep SSL enabled for real server!
    #define DISABLE_ENCRYPTION  0                 // 0 = Keep encryption enabled!
    #define HOOK_DECRYPTED_DATA 1                 // Hook to capture decrypted data
#else
    // Connect to LOCAL server - disable SSL/encryption for easy debugging
    #define SERVER_HOSTNAME     "*185.23.18.117"      // Local server
    #define DISABLE_SSL         1                 // Disable SSL for local server
    #define DISABLE_ENCRYPTION  1                 // Disable encryption
    #define HOOK_DECRYPTED_DATA 1                 // Enable hooks to see game protocol
#endif

#define SERVER_PORT         20921            // Game server port (EA uses 0x51B8 = 20920)
#define RELAY_PORT          3658             // UDP relay port for P2P (0x0E4A)

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
