#pragma once

// ============================================================================
// NFSOR Custom - Pattern signatures for NFS Underground 2
// ============================================================================

// Pattern format: bytes with ? as wildcard
// These patterns are used to find functions/addresses in the game executable

namespace Patterns {

    // EA Server URL - patches the server URL pointer
    // Original: pushes EA server URL onto stack
    constexpr const char* EA_SERVER_URL = 
        "68 ? ? ? ? 50 E8 ? ? ? ? 8B F8 83 C4 ? 85 FF 7D";

    // Multiple instances patch - allows running multiple game copies
    constexpr const char* MULTI_INSTANCE = 
        "6A ? E8 ? ? ? ? 8B 44 24 ? 8B 4C 24 ? 50";

    // SSL patch - disables SSL certificate verification
    constexpr const char* SSL_PATCH = 
        "7D ? C7 86 ? ? ? ? ? ? ? ? EB ? 03 7C 24";

    // Encryption patch - disables packet encryption
    constexpr const char* ENCRYPTION_PATCH = 
        "F7 DA 1B D2 83 E2 ? 83 C2 ? 89 96";

    // Year limit patch - extends year check (post-2024 fix)
    constexpr const char* YEAR_LIMIT = 
        "B8 ? ? ? ? C3 90 90 90 90 90 90 90 90 90 90 56 57 8B 7C 24 ? 81 FF";

    // SendSocket in client handshake
    constexpr const char* SEND_SOCKET_CLIENT = 
        "E8 ? ? ? ? 83 C4 ? 83 F8 ? 75 ? E8 ? ? ? ? 8B 55 ? 8B 4D ? 83 C2 ? 89 85 ? ? ? ? 8B 44 24";

    // SendSocket in host handshake  
    constexpr const char* SEND_SOCKET_HOST = 
        "E8 ? ? ? ? 83 C4 ? 83 F8 ? 75 ? E8 ? ? ? ? 8B 55 ? 8B 4D ? 83 C2 ? 89 85 ? ? ? ? 8B 84 24";

    // Reset room info call
    constexpr const char* RESET_ROOM_INFO = 
        "E8 ? ? ? ? 83 C4 ? 6A ? B9 ? ? ? ? C6 86";

    // Create socket function
    constexpr const char* CREATE_SOCKET = 
        "E8 ? ? ? ? 83 C4 ? 3B C7 75 ? 5F";

    // RecvFrom function
    constexpr const char* RECVFROM_FUNC = 
        "E8 ? ? ? ? 8B F8 85 FF 7E ? E8";

    // SendTo function
    constexpr const char* SENDTO_FUNC = 
        "E8 ? ? ? ? 5E 85 C0 5F 5D";

    // Server bind function
    constexpr const char* SRV_BIND = 
        "E8 ? ? ? ? 83 C4 ? 85 C0 7D ? 53";

    // SendSocket function
    constexpr const char* SEND_SOCKET = 
        "83 EC ? A1 ? ? ? ? 53 55 8B 6C 24 ? 89 44 24 ? 83 7D ? ? 57";

    // sub_58FD50 - network related
    constexpr const char* SUB_58FD50 = 
        "55 8B EC 83 E4 ? 81 EC ? ? ? ? 53 56 57 33 DB";

    // sub_58F740 - network related
    constexpr const char* SUB_58F740 = 
        "8A 0D ? ? ? ? B8 ? ? ? ? 84 C8 75 ? 8B 15 ? ? ? ? 0B D0 B8 ? ? ? ? A3";

    // CreateSocket internal
    constexpr const char* CREATE_SOCKET_INTERNAL = 
        "51 8B 44 24 ? 8B 4C 24 ? 53";

    // Windowed mode - fullscreen flag check
    // This pattern finds where the game checks fullscreen mode
    constexpr const char* WINDOWED_MODE = 
        "74 ? 6A 00 6A 00 6A 00 68 00 00 00 80";  // JE xx, push 0, push 0, push 0, push WS_POPUP
    
    // Alternative: Direct3D CreateDevice fullscreen flag
    constexpr const char* D3D_FULLSCREEN = 
        "C7 44 24 ? 01 00 00 00";  // MOV [esp+xx], 1 (Windowed = TRUE would be this)

}
