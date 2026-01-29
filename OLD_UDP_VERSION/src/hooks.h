#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <ctime>
#include "config.h"
#include "logger.h"

#pragma comment(lib, "ws2_32.lib")

// ============================================================================
// Network Hooks - Exact replica of original NFSOR mod
// Based on full IDA analysis
// ============================================================================

namespace Hooks {

    // ========================================================================
    // Global variables (exact match to original)
    // ========================================================================
    
    // dword_10020734 - Server IP (from inet_addr)
    inline uint32_t g_serverIP = 0;
    
    // dword_1002073C - Game socket handle (captured in Bind hook)
    inline SOCKET g_gameSocket = INVALID_SOCKET;
    
    // dword_10020738 - Original CreateSocket function (from pattern scan)
    inline uintptr_t g_origCreateSocket = 0;
    
    // dword_10020740 - Saved value from sub_58F740 (used in SendSocket wrapper)
    inline uint32_t g_savedValue = 0;
    
    // dword_10020744 - Original SendSocket function (from pattern scan)
    inline uintptr_t g_origSendSocketFunc = 0;
    
    // dword_10020748 - Original sub_58FD50 function (from pattern scan)  
    inline uintptr_t g_origFunc58FD50 = 0;
    
    // dword_1002074C - Original sub_58F740 function (from pattern scan)
    inline uintptr_t g_origFunc58F740 = 0;
    
    // dword_10020758 - Return address (from CreateSocket hook)
    inline uintptr_t g_createSocketRetAddr = 0;
    
    // Original Bind function address (hardcoded 0x74A380 in original,
    // but we need to get it from pattern scan result)
    inline uintptr_t g_origBindFunc = 0;
    
    // For debugging - original sub_745160 function
    inline uintptr_t g_orig745160 = 0;
    
    // Flag to track if hooks are active
    inline bool g_hooksActive = false;
    
    // Original WinSock function pointers for IAT hooks
    typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
    typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
    typedef int (WSAAPI *send_t)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WSAAPI *recv_t)(SOCKET s, char* buf, int len, int flags);
    
    inline connect_t g_origConnect = nullptr;
    inline gethostbyname_t g_origGethostbyname = nullptr;
    inline send_t g_origSend = nullptr;
    inline recv_t g_origRecv = nullptr;
    
    // Traffic log file
    inline FILE* g_trafficLog = nullptr;
    inline CRITICAL_SECTION g_trafficLogCS;
    inline bool g_trafficLogInitialized = false;
    
    // Track game sockets for traffic logging
    inline SOCKET g_tcpGameSocket = INVALID_SOCKET;
    
    // ========================================================================
    // Traffic logging functions
    // ========================================================================
    inline void InitTrafficLog() {
        if (g_trafficLogInitialized) return;
        
        InitializeCriticalSection(&g_trafficLogCS);
        g_trafficLog = fopen(TRAFFIC_LOG_FILE, "w");
        if (g_trafficLog) {
            fprintf(g_trafficLog, "=== NFSOR Traffic Capture ===\n");
            fprintf(g_trafficLog, "Server: %s:%d\n", SERVER_HOSTNAME, SERVER_PORT);
            fprintf(g_trafficLog, "Started: %s\n\n", __TIMESTAMP__);
            fflush(g_trafficLog);
            LOG("Traffic logging to: %s", TRAFFIC_LOG_FILE);
        } else {
            LOG("WARNING: Could not open traffic log file!");
        }
        g_trafficLogInitialized = true;
    }
    
    inline void LogTrafficRaw(const char* direction, const char* data, int len) {
        if (!g_trafficLog) return;
        
        EnterCriticalSection(&g_trafficLogCS);
        
        // Get timestamp
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        fprintf(g_trafficLog, "[%02d:%02d:%02d.%03d] %s (%d bytes)\n", 
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                direction, len);
        
        // HEX dump - full, 32 bytes per line
        fprintf(g_trafficLog, "HEX: ");
        for (int i = 0; i < len; i++) {
            fprintf(g_trafficLog, "%02X ", (unsigned char)data[i]);
            if ((i + 1) % 32 == 0 && i + 1 < len) fprintf(g_trafficLog, "\n     ");
        }
        fprintf(g_trafficLog, "\n");
        
        // ASCII (printable) - full
        fprintf(g_trafficLog, "ASCII: ");
        for (int i = 0; i < len; i++) {
            char c = data[i];
            if (c >= 32 && c < 127) 
                fputc(c, g_trafficLog);
            else if (c == '\n')
                fprintf(g_trafficLog, "\\n");
            else if (c == '\r')
                fprintf(g_trafficLog, "\\r");
            else
                fputc('.', g_trafficLog);
        }
        fprintf(g_trafficLog, "\n");
        
        // Try to parse EA protocol header if >= 12 bytes
        if (len >= 12) {
            uint32_t cmd = ((unsigned char)data[0] << 24) | ((unsigned char)data[1] << 16) | 
                           ((unsigned char)data[2] << 8) | (unsigned char)data[3];
            int32_t status = ((unsigned char)data[4] << 24) | ((unsigned char)data[5] << 16) | 
                             ((unsigned char)data[6] << 8) | (unsigned char)data[7];
            uint32_t pktLen = ((unsigned char)data[8] << 24) | ((unsigned char)data[9] << 16) | 
                              ((unsigned char)data[10] << 8) | (unsigned char)data[11];
            
            char cmdStr[5] = {0};
            cmdStr[0] = (cmd >> 24) & 0xFF;
            cmdStr[1] = (cmd >> 16) & 0xFF;
            cmdStr[2] = (cmd >> 8) & 0xFF;
            cmdStr[3] = cmd & 0xFF;
            
            fprintf(g_trafficLog, "EA PKT: cmd='%s' (0x%08X) status=%d len=%u\n", 
                    cmdStr, cmd, status, pktLen);
            
            // Log payload - full
            if (len > 12) {
                fprintf(g_trafficLog, "PAYLOAD: %.*s\n", len - 12, data + 12);
            }
        }
        
        fprintf(g_trafficLog, "---\n\n");
        fflush(g_trafficLog);
        
        LeaveCriticalSection(&g_trafficLogCS);
    }
    
    inline void CloseTrafficLog() {
        if (g_trafficLog) {
            fprintf(g_trafficLog, "\n=== END OF CAPTURE ===\n");
            fclose(g_trafficLog);
            g_trafficLog = nullptr;
        }
        if (g_trafficLogInitialized) {
            DeleteCriticalSection(&g_trafficLogCS);
            g_trafficLogInitialized = false;
        }
    }

    // ========================================================================
    // Buffers (exact match to original)
    // ========================================================================
    
    // ::buf (at 0x10020768) - first 6 bytes of relay packet
    // ::to (relay destination sockaddr)
    // unk_1002076E - payload start (after 6 byte header)
    inline char g_relayBuffer[4096 + 6];
    inline sockaddr_in g_relayDest;
    
    // unk_10021FE0 - SendSocket wrapper buffer
    inline char g_sendSocketBuffer[4096];
    
    // unk_10021774 - Last peer IP string (for debug)
    inline char g_lastPeerIP[64];

    // ========================================================================
    // Relay port constant (from config.h or default)
    // ========================================================================
    #ifndef RELAY_PORT
    #define RELAY_PORT 0x0E4A  // 3658
    #endif

    // ========================================================================
    // Diagnostic hook for connect() - logs all connection attempts
    // ========================================================================
    inline int WSAAPI Hook_Connect(SOCKET s, const struct sockaddr* name, int namelen) {
        if (name && name->sa_family == AF_INET) {
            const sockaddr_in* addr = reinterpret_cast<const sockaddr_in*>(name);
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
            uint16_t port = ntohs(addr->sin_port);
            LOG(">>> CONNECT: %s:%d (socket=%d)", ipStr, port, (int)s);
            
            // Track game socket for traffic logging
            if (port == SERVER_PORT || port == SERVER_PORT + 1) {
                g_tcpGameSocket = s;
                LOG(">>> Tracking socket %d for traffic logging", (int)s);
                
                // Log to traffic file
                if (g_trafficLog) {
                    EnterCriticalSection(&g_trafficLogCS);
                    fprintf(g_trafficLog, "=== CONNECT to %s:%d (socket %d) ===\n\n", ipStr, port, (int)s);
                    fflush(g_trafficLog);
                    LeaveCriticalSection(&g_trafficLogCS);
                }
            }
        } else {
            LOG(">>> CONNECT: non-IPv4 (family=%d, socket=%d)", name ? name->sa_family : -1, (int)s);
        }
        
        // Call original
        if (g_origConnect) {
            int result = g_origConnect(s, name, namelen);
            LOG(">>> CONNECT result: %d (error=%d)", result, result < 0 ? WSAGetLastError() : 0);
            return result;
        }
        return SOCKET_ERROR;
    }
    
    // ========================================================================
    // Hook for send() - capture outgoing traffic
    // ========================================================================
    inline int WSAAPI Hook_Send(SOCKET s, const char* buf, int len, int flags) {
        // Log traffic from game socket
        if (s == g_tcpGameSocket && len > 0) {
            LOG(">>> SEND: %d bytes on socket %d", len, (int)s);
            LogTrafficRaw(">>> CLIENT SEND", buf, len);
        }
        
        // Call original
        if (g_origSend) {
            return g_origSend(s, buf, len, flags);
        }
        return SOCKET_ERROR;
    }
    
    // ========================================================================
    // Hook for recv() - capture incoming traffic
    // ========================================================================
    inline int WSAAPI Hook_Recv(SOCKET s, char* buf, int len, int flags) {
        // Call original first
        int result = SOCKET_ERROR;
        if (g_origRecv) {
            result = g_origRecv(s, buf, len, flags);
        }
        
        // Log traffic from game socket
        if (s == g_tcpGameSocket && result > 0) {
            LOG("<<< RECV: %d bytes on socket %d", result, (int)s);
            LogTrafficRaw("<<< SERVER RECV", buf, result);
        }
        
        return result;
    }
    
    // ========================================================================
    // Diagnostic hook for gethostbyname() - logs DNS lookups
    // ========================================================================
    inline struct hostent* WSAAPI Hook_Gethostbyname(const char* name) {
        LOG(">>> GETHOSTBYNAME: %s", name ? name : "(null)");
        
        if (g_origGethostbyname) {
            struct hostent* result = g_origGethostbyname(name);
            if (result && result->h_addr_list && result->h_addr_list[0]) {
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, result->h_addr_list[0], ipStr, sizeof(ipStr));
                LOG(">>> GETHOSTBYNAME result: %s -> %s", name, ipStr);
            } else {
                LOG(">>> GETHOSTBYNAME failed for: %s", name);
            }
            return result;
        }
        return nullptr;
    }
    
    // ========================================================================
    // IAT Hook installer
    // ========================================================================
    inline bool HookIAT(const char* moduleName, const char* funcName, void* hookFunc, void** origFunc) {
        HMODULE hModule = GetModuleHandleA(nullptr); // Main exe
        if (!hModule) return false;
        
        // Get DOS header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        
        // Get import directory
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        // Find the module
        while (importDesc->Name) {
            const char* name = (const char*)((BYTE*)hModule + importDesc->Name);
            if (_stricmp(name, moduleName) == 0) {
                // Found module, now find function
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                
                while (origThunk->u1.AddressOfData) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);
                        if (strcmp((const char*)importByName->Name, funcName) == 0) {
                            // Found! Save original and replace
                            DWORD oldProtect;
                            if (VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect)) {
                                *origFunc = (void*)thunk->u1.Function;
                                thunk->u1.Function = (ULONG_PTR)hookFunc;
                                VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                                LOG("IAT hook installed: %s!%s", moduleName, funcName);
                                return true;
                            }
                        }
                    }
                    origThunk++;
                    thunk++;
                }
            }
            importDesc++;
        }
        LOG("IAT hook FAILED: %s!%s not found", moduleName, funcName);
        return false;
    }
    
    // ========================================================================
    // Debug hook for sub_74AA10 - Async DNS creation
    // DISABLED - may cause crash due to threading issues
    // ========================================================================
    inline uintptr_t g_orig74AA10 = 0;
    
    /*
    inline void* __cdecl Hook_74AA10(char* hostname, int timeout) {
        LOG(">>> sub_74AA10 (async DNS) CALLED!");
        LOG("    hostname=%s, timeout=%d", hostname ? hostname : "(null)", timeout);
        
        typedef void*(__cdecl* Func74AA10_t)(char*, int);
        void* result = reinterpret_cast<Func74AA10_t>(g_orig74AA10)(hostname, timeout);
        
        LOG("    Result = 0x%08X", (uintptr_t)result);
        
        if (result) {
            int* ptr = reinterpret_cast<int*>(result);
            LOG("    DNS state: ptr[0]=%d, ptr[1]=0x%08X (IP)", ptr[0], ptr[1]);
        }
        
        return result;
    }
    */
    
    // ========================================================================
    // Debug hook for sub_754490 - Socket processing / DNS resolve trigger
    // ========================================================================
    inline uintptr_t g_orig754490 = 0;
    inline int g_754490CallCount = 0;
    
    inline int __cdecl Hook_754490(int addrlen) {
        g_754490CallCount++;
        
        if (g_754490CallCount <= 20 || g_754490CallCount % 100 == 0) {
            int* ptr = reinterpret_cast<int*>(addrlen);
            int state = ptr[23];  // offset 92
            LOG(">>> sub_754490 (socket proc) call #%d, state=%d", g_754490CallCount, state);
            
            // Log sockaddr info
            if (ptr) {
                unsigned short sin_family = *reinterpret_cast<unsigned short*>(addrlen + 4);
                unsigned short sin_port = ntohs(*reinterpret_cast<unsigned short*>(addrlen + 6));
                unsigned int sin_addr = ntohl(*reinterpret_cast<unsigned int*>(addrlen + 8));
                char* hostname = reinterpret_cast<char*>(addrlen + 28);
                LOG("    family=%d, port=%d, addr=0x%08X, hostname=%s", 
                    sin_family, sin_port, sin_addr, hostname[0] ? hostname : "(empty)");
            }
        }
        
        // Call original
        typedef int(__cdecl* Func754490_t)(int);
        int result = reinterpret_cast<Func754490_t>(g_orig754490)(addrlen);
        
        if (g_754490CallCount <= 20 || g_754490CallCount % 100 == 0) {
            int* ptr = reinterpret_cast<int*>(addrlen);
            LOG("    After: state=%d, socket=%d", ptr[23], ptr[0]);
        }
        
        return result;
    }
    
    // ========================================================================
    // Inline Hook (Detour) infrastructure
    // ========================================================================
    
    // Trampoline storage for original function bytes
    // All three functions start with:
    //   sub esp, 14h      (3 bytes: 83 EC 14)
    //   mov eax, [addr]   (5 bytes: A1 xx xx xx xx)
    // Total = 8 bytes, so we need 8-byte trampoline
    struct Trampoline {
        uint8_t code[32];       // Trampoline code: original bytes + JMP back
        uintptr_t originalAddr;
        size_t stolenBytes;
        bool active;
    };
    
    inline Trampoline g_tramp74A3F0 = {};  // Connect wrapper
    inline Trampoline g_tramp74A5C0 = {};  // Send wrapper  
    inline Trampoline g_tramp74A6D0 = {};  // Recv wrapper
    inline Trampoline g_tramp759750 = {};  // HTTP connect
    
    // ========================================================================
    // Debug hook for sub_759750 - HTTP client connect with DNS
    // This is THE function that creates HTTP connections (TOS, news, etc)
    // 
    // Parameters:
    //   a1 = HTTP client structure
    //   a2 = SSL flag (1 = use SSL port 443, 0 = use HTTP port 80)
    //   a3 = hostname string
    //   a4 = IP address (if already resolved)
    //   a5 = port (0 = default based on SSL flag)
    // ========================================================================
    inline uintptr_t g_orig759750 = 0;
    
    // Redirect hostname buffer for HTTP
    inline char g_httpHostname[64] = "127.0.0.1";
    
    inline int __cdecl Hook_759750(int a1, int a2, char* a3, int a4, int a5) {
        LOG(">>> sub_759750 (HTTP connect) CALLED!");
        LOG("    a1=0x%08X, ssl=%d, hostname=\"%s\", ip=0x%08X, port=%d",
            a1, a2, a3 ? a3 : "(null)", a4, a5);
        
        // REDIRECT: Replace hostname with our server!
        char* newHostname = a3;
        
        #if CAPTURE_CERT_MODE == 0
        // Only redirect when NOT in capture mode
        if (a3 && a3[0] != '\0') {
            // Use our local server
            newHostname = g_httpHostname;
            LOG("    REDIRECTED hostname: \"%s\" -> \"%s\"", a3, newHostname);
        }
        #else
        LOG("    CAPTURE MODE: Using original hostname");
        #endif
        
        // Call original via trampoline
        typedef int(__cdecl* Func759750_t)(int, int, char*, int, int);
        Func759750_t origFunc = reinterpret_cast<Func759750_t>(&g_tramp759750.code[0]);
        int result = origFunc(a1, a2, newHostname, a4, a5);
        
        LOG("    Result = %d", result);
        return result;
    }
    
    // Install hook on sub_759750
    constexpr uintptr_t HTTP_CONNECT_FUNC = 0x759750;
    
    // Install inline hook with proper instruction-boundary handling
    // stolenBytes = number of bytes to copy (must be >= 5, and end on instruction boundary)
    inline bool InstallInlineHook(uintptr_t targetAddr, void* hookFunc, Trampoline* tramp, size_t stolenBytes = 8) {
        if (!targetAddr || !hookFunc || !tramp || stolenBytes < 5 || stolenBytes > 16) return false;
        
        tramp->originalAddr = targetAddr;
        tramp->stolenBytes = stolenBytes;
        
        // Make trampoline memory executable
        DWORD oldProtect;
        VirtualProtect(tramp->code, sizeof(tramp->code), PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // Copy original bytes to trampoline
        memcpy(tramp->code, (void*)targetAddr, stolenBytes);
        
        // Add JMP rel32 back to original function + stolenBytes
        tramp->code[stolenBytes] = 0xE9;  // JMP rel32
        uintptr_t jmpFrom = reinterpret_cast<uintptr_t>(&tramp->code[stolenBytes]) + 5;
        uintptr_t jmpTo = targetAddr + stolenBytes;
        *reinterpret_cast<int32_t*>(&tramp->code[stolenBytes + 1]) = static_cast<int32_t>(jmpTo - jmpFrom);
        
        // Now patch the target function with JMP to our hook
        if (!VirtualProtect((void*)targetAddr, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG("  Failed VirtualProtect for 0x%08X", targetAddr);
            return false;
        }
        
        // Write JMP to hook
        *reinterpret_cast<uint8_t*>(targetAddr) = 0xE9;  // JMP rel32
        *reinterpret_cast<int32_t*>(targetAddr + 1) = 
            static_cast<int32_t>(reinterpret_cast<uintptr_t>(hookFunc) - targetAddr - 5);
        
        // NOP remaining bytes if stolenBytes > 5
        for (size_t i = 5; i < stolenBytes; i++) {
            *reinterpret_cast<uint8_t*>(targetAddr + i) = 0x90;  // NOP
        }
        
        VirtualProtect((void*)targetAddr, stolenBytes, oldProtect, &oldProtect);
        FlushInstructionCache(GetCurrentProcess(), (void*)targetAddr, stolenBytes);
        
        tramp->active = true;
        return true;
    }
    
    // Game function addresses (from IDA)
    constexpr uintptr_t GAME_CONNECT_WRAPPER = 0x74A3F0;  // sub_74A3F0
    constexpr uintptr_t GAME_SEND_WRAPPER = 0x74A5C0;     // sub_74A5C0
    constexpr uintptr_t GAME_RECV_WRAPPER = 0x74A6D0;     // sub_74A6D0
    
    // ========================================================================
    // Hook for game's connect wrapper (sub_74A3F0)
    // int __cdecl sub_74A3F0(int socketStruct, int sockaddrPtr, int namelen)
    // ========================================================================
    inline int __cdecl Hook_GameConnect(int a1, int a2, int namelen) {
        LOG(">>> GAME CONNECT (sub_74A3F0)");
        LOG("    socketStruct=0x%08X, sockaddr=0x%08X, namelen=%d", a1, a2, namelen);
        
        // Get socket handle from structure (offset +24)
        SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
        LOG("    Socket handle: %d", (int)sock);
        
        // Try to decode sockaddr (it's built by sub_74A030)
        if (a2 && namelen >= 8) {
            sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(a2);
            if (addr->sin_family == AF_INET) {
                char originalIP[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, originalIP, sizeof(originalIP));
                uint16_t port = ntohs(addr->sin_port);
                LOG("    Original target: %s:%d", originalIP, port);
                
                // ============================================================
                // REDIRECT TO LOCAL SERVER!
                // Replace the IP with our configured server IP
                // CAPTURE_CERT_MODE is defined in config.h
                // ============================================================
                #if CAPTURE_CERT_MODE == 0
                if (g_serverIP != 0) {
                    addr->sin_addr.s_addr = g_serverIP;
                    
                    char newIP[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr->sin_addr, newIP, sizeof(newIP));
                    LOG("    REDIRECTED to: %s:%d", newIP, port);
                }
                #else
                LOG("    CAPTURE MODE: NOT redirecting, using real server");
                #endif
                
                // Track this socket for traffic logging
                g_tcpGameSocket = sock;
                
                // Log to traffic file
                if (g_trafficLog) {
                    EnterCriticalSection(&g_trafficLogCS);
                    fprintf(g_trafficLog, "=== GAME CONNECT (redirected %s -> %s:%d, socket %d) ===\n\n", 
                            originalIP, g_serverIP != 0 ? "localhost" : originalIP, port, (int)sock);
                    fflush(g_trafficLog);
                    LeaveCriticalSection(&g_trafficLogCS);
                }
            }
        }
        
        // Call original via trampoline
        typedef int(__cdecl* OrigFunc_t)(int, int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp74A3F0.code[0]);
        int result = origFunc(a1, a2, namelen);
        
        LOG("    Connect result: %d", result);
        if (result < 0) {
            LOG("    WSAError: %d", WSAGetLastError());
        }
        
        return result;
    }
    
    // ========================================================================
    // Hook for game's send wrapper (sub_74A5C0)
    // int __cdecl sub_74A5C0(int socketStruct, char* buf, int len, int a4, int flags, int tolen)
    // ========================================================================
    inline int __cdecl Hook_GameSend(int a1, const char* buf, int len, int a4, int flags, int tolen) {
        // Get socket from structure
        SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
        
        // Log only if it's our tracked socket or any traffic
        if (len > 0) {
            LOG(">>> GAME SEND: %d bytes (socket %d, flags=%d)", len, (int)sock, flags);
            LogTrafficRaw(">>> CLIENT SEND", buf, len);
        }
        
        // Call original via trampoline
        typedef int(__cdecl* OrigFunc_t)(int, const char*, int, int, int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp74A5C0.code[0]);
        int result = origFunc(a1, buf, len, a4, flags, tolen);
        
        if (len > 0 && result != len) {
            LOG("    Send result: %d (expected %d)", result, len);
        }
        
        return result;
    }
    
    // ========================================================================
    // Hook for game's recv wrapper (sub_74A6D0)
    // int __cdecl sub_74A6D0(int socketStruct, char* buf, int len, char a4, sockaddr* from, int* fromlen)
    // ========================================================================
    inline int __cdecl Hook_GameRecv(int a1, char* buf, int len, char a4, sockaddr* from, int* fromlen) {
        // Call original first
        typedef int(__cdecl* OrigFunc_t)(int, char*, int, char, sockaddr*, int*);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp74A6D0.code[0]);
        int result = origFunc(a1, buf, len, a4, from, fromlen);
        
        // Get socket from structure
        SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
        
        // Log received data
        if (result > 0) {
            LOG("<<< GAME RECV: %d bytes (socket %d)", result, (int)sock);
            LogTrafficRaw("<<< SERVER RECV", buf, result);
            
            // Save SSL certificate to file if this looks like cert data (828 bytes, starts with 01 00 02 03)
            if (result == 828 && buf[0] == 0x01 && buf[1] == 0x00 && buf[2] == 0x02 && buf[3] == 0x03) {
                FILE* certFile = fopen("ea_ssl_certificate.bin", "wb");
                if (certFile) {
                    fwrite(buf, 1, result, certFile);
                    fclose(certFile);
                    LOG(">>> SAVED SSL CERTIFICATE to ea_ssl_certificate.bin (%d bytes)", result);
                }
            }
        }
        
        return result;
    }
    
    // ========================================================================
    // sub_10002130 - Initialize relay (DNS resolution)
    // ========================================================================
    inline bool InitRelay() {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            LOG("WSAStartup failed");
            return false;
        }

        // Initialize traffic logging
        #ifdef ENABLE_TRAFFIC_LOG
        InitTrafficLog();
        #endif

        addrinfo hints = {};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        
        // Strip '*' prefix if present (it's only for game's SSL flag)
        const char* hostname = SERVER_HOSTNAME;
        if (hostname[0] == '*') {
            hostname++;
        }
        
        addrinfo* result = nullptr;
        int ret = getaddrinfo(hostname, nullptr, &hints, &result);
        if (ret != 0 || !result) {
            LOG("getaddrinfo error for %s (error %d)", hostname, ret);
            return false;
        }

        // dword_10020734 = inet_addr(cp)
        g_serverIP = reinterpret_cast<sockaddr_in*>(result->ai_addr)->sin_addr.s_addr;
        freeaddrinfo(result);

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_serverIP, ipStr, sizeof(ipStr));
        LOG("Server resolved: %s -> %s", hostname, ipStr);
        
        // Install INLINE hooks on GAME network functions
        // NOTE: For CAPTURE_REAL mode, we skip TCP hooks to not interfere with SSL
        #if CAPTURE_CERT_MODE == 0
        LOG("Installing inline hooks on game network functions (LOCAL mode)...");
        
        // Hook sub_74A3F0 (connect wrapper) - for IP redirection
        if (InstallInlineHook(GAME_CONNECT_WRAPPER, (void*)Hook_GameConnect, &g_tramp74A3F0)) {
            LOG("  sub_74A3F0 (connect): HOOKED");
        } else {
            LOG("  sub_74A3F0 (connect): FAILED");
        }
        
        // Hook sub_74A5C0 (send wrapper) - for traffic logging
        if (InstallInlineHook(GAME_SEND_WRAPPER, (void*)Hook_GameSend, &g_tramp74A5C0)) {
            LOG("  sub_74A5C0 (send): HOOKED");
        } else {
            LOG("  sub_74A5C0 (send): FAILED");
        }
        
        // Hook sub_74A6D0 (recv wrapper) - for traffic logging
        if (InstallInlineHook(GAME_RECV_WRAPPER, (void*)Hook_GameRecv, &g_tramp74A6D0)) {
            LOG("  sub_74A6D0 (recv): HOOKED");
        } else {
            LOG("  sub_74A6D0 (recv): FAILED");
        }
        
        // Hook sub_759750 (HTTP connect) - for TOS/news URL override
        if (InstallInlineHook(HTTP_CONNECT_FUNC, (void*)Hook_759750, &g_tramp759750, 6)) {
            LOG("  sub_759750 (HTTP): HOOKED");
        } else {
            LOG("  sub_759750 (HTTP): FAILED");
        }
        #else
        LOG("CAPTURE MODE: Skipping TCP hooks to preserve SSL handshake");
        #endif
        
        // Test DNS resolution
        LOG("Testing DNS resolution...");
        struct hostent* he = gethostbyname(hostname);
        if (he && he->h_addr_list && he->h_addr_list[0]) {
            char testIpStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, he->h_addr_list[0], testIpStr, sizeof(testIpStr));
            LOG("  %s resolves to: %s", hostname, testIpStr);
        } else {
            LOG("  FAILED to resolve %s! Error=%d", hostname, WSAGetLastError());
        }

        return true;
    }

    // ========================================================================
    // Debug hook for sub_745160 - logs connection attempts
    // sub_745160(int a1, char *Source, int a3, int a4, int a5, int a6)
    // Source is the server hostname (e.g., "*localhost")
    // a3 is the port
    // ========================================================================
    inline int __cdecl Hook_745160(int a1, char* Source, int a3, int a4, int a5, int a6) {
        LOG(">>> sub_745160 CALLED!");
        LOG("    Server: %s", Source ? Source : "(null)");
        LOG("    Port: %d", a3);
        LOG("    a1=0x%08X, a4=0x%08X, a5=0x%08X, a6=%d", a1, a4, a5, a6);
        
        // Call original
        typedef int(__cdecl* Func745160_t)(int, char*, int, int, int, int);
        int result = reinterpret_cast<Func745160_t>(g_orig745160)(a1, Source, a3, a4, a5, a6);
        
        LOG("    Result: %d", result);
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_74A3F0 - actual TCP connect wrapper
    // sub_74A3F0(int a1, int a2, int namelen)
    // a1 is socket structure, a2 points to sockaddr, namelen is 16
    // ========================================================================
    inline uintptr_t g_orig74A3F0 = 0;
    
    inline int __cdecl Hook_74A3F0(int a1, int a2, int namelen) {
        LOG(">>> sub_74A3F0 (TCP connect) CALLED!");
        LOG("    a1=0x%08X, a2=0x%08X, namelen=%d", a1, a2, namelen);
        
        // Try to decode sockaddr
        if (a2 && namelen >= 8) {
            sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(a2);
            if (addr->sin_family == AF_INET) {
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
                LOG("    Connecting to: %s:%d", ipStr, ntohs(addr->sin_port));
            }
        }
        
        // Get socket from structure (offset 24)
        if (a1) {
            SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
            LOG("    Socket handle: %d", (int)sock);
        }
        
        // Call original
        typedef int(__cdecl* Func74A3F0_t)(int, int, int);
        int result = reinterpret_cast<Func74A3F0_t>(g_orig74A3F0)(a1, a2, namelen);
        
        LOG("    Connect result: %d", result);
        if (result < 0) {
            LOG("    WSAError: %d", WSAGetLastError());
        }
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_747670 - HTTP handler (network tick)
    // This is called every frame to process network
    // ========================================================================
    inline uintptr_t g_orig747670 = 0;
    inline int g_747670CallCount = 0;
    
    inline int __cdecl Hook_747670(int* a1) {
        g_747670CallCount++;
        
        // Log only first few calls and then every 100th
        if (g_747670CallCount <= 5 || g_747670CallCount % 100 == 0) {
            LOG(">>> sub_747670 (HTTP tick) call #%d, state=%d", g_747670CallCount, a1 ? a1[69] : -1);
        }
        
        // Call original
        typedef int(__cdecl* Func747670_t)(int*);
        int result = reinterpret_cast<Func747670_t>(g_orig747670)(a1);
        
        // Log state changes
        static int lastState = -1;
        if (a1 && a1[69] != lastState) {
            LOG("    State changed: %d -> %d", lastState, a1[69]);
            lastState = a1[69];
        }
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_586760 - Main EA network tick
    // This is the main network processing function that calls sub_745540
    // ========================================================================
    inline uintptr_t g_orig586760 = 0;
    inline int g_586760CallCount = 0;
    
    // __fastcall for __thiscall emulation
    inline int __fastcall Hook_586760(void* thisPtr, void* /*edx*/) {
        g_586760CallCount++;
        
        // Log first calls and then every 100th
        if (g_586760CallCount <= 10 || g_586760CallCount % 500 == 0) {
            LOG(">>> sub_586760 (EA network tick) call #%d, this=0x%08X", g_586760CallCount, (uintptr_t)thisPtr);
            
            // Log network manager state
            if (thisPtr) {
                int* ptr = reinterpret_cast<int*>(thisPtr);
                // ptr[17] is the network connection object
                if (ptr[17]) {
                    int* netConn = reinterpret_cast<int*>(ptr[17]);
                    // netConn[2] is state (offset 8)
                    LOG("    NetConn at 0x%08X, state=0x%08X (%d)", ptr[17], netConn[2], netConn[2]);
                } else {
                    LOG("    NetConn = NULL (not initialized!)");
                }
            }
        }
        
        // Call original
        typedef int(__fastcall* Func586760_t)(void*, void*);
        int result = reinterpret_cast<Func586760_t>(g_orig586760)(thisPtr, nullptr);
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_745540 - Main network protocol handler
    // This processes the network state machine
    // ========================================================================
    inline uintptr_t g_orig745540 = 0;
    inline int g_745540CallCount = 0;
    
    inline unsigned int __cdecl Hook_745540(int* a1) {
        g_745540CallCount++;
        
        // Log first calls and periodically
        if (g_745540CallCount <= 10 || g_745540CallCount % 500 == 0) {
            LOG(">>> sub_745540 (protocol tick) call #%d", g_745540CallCount);
            
            if (a1) {
                // a1[0] = some pointer
                // a1[2] = state (offset 8)
                LOG("    a1[0]=0x%08X, a1[2]=0x%08X", a1[0], a1[2]);
                
                // Check hostname at offset 6472 (a1 + 1618)
                char* hostname = reinterpret_cast<char*>(a1) + 6472;
                if (hostname[0]) {
                    LOG("    Hostname: %s", hostname);
                }
            }
        }
        
        // Call original
        typedef unsigned int(__cdecl* Func745540_t)(int*);
        unsigned int result = reinterpret_cast<Func745540_t>(g_orig745540)(a1);
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_60AEE0 - Online state machine tick
    // This controls when sub_586760 gets called based on state
    // ========================================================================
    inline uintptr_t g_orig60AEE0 = 0;
    inline int g_60AEE0CallCount = 0;
    
    // __fastcall for __thiscall emulation (this has 1 additional param: char a2)
    inline char __fastcall Hook_60AEE0(void* thisPtr, void* /*edx*/, char a2) {
        g_60AEE0CallCount++;
        
        // Log first calls and periodically
        if (g_60AEE0CallCount <= 20 || g_60AEE0CallCount % 500 == 0) {
            int* ptr = reinterpret_cast<int*>(thisPtr);
            int state = ptr ? *ptr : -1;
            LOG(">>> sub_60AEE0 (online tick) call #%d, this=0x%08X, state=%d, a2=%d", 
                g_60AEE0CallCount, (uintptr_t)thisPtr, state, (int)a2);
        }
        
        // Call original
        typedef char(__fastcall* Func60AEE0_t)(void*, void*, char);
        char result = reinterpret_cast<Func60AEE0_t>(g_orig60AEE0)(thisPtr, nullptr, a2);
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_588D40 - Network init (creates connection object)
    // Note: __thiscall on MSVC x86 passes 'this' in ECX
    // We use __fastcall which also uses ECX for first param
    // ========================================================================
    inline uintptr_t g_orig588D40 = 0;
    
    // __fastcall: first param in ECX (=this), second in EDX (=dummy)
    inline int __fastcall Hook_588D40(void* thisPtr, void* /*edx_unused*/) {
        LOG(">>> sub_588D40 (network init) CALLED! this=0x%08X", (uintptr_t)thisPtr);
        
        int* ptr = reinterpret_cast<int*>(thisPtr);
        LOG("    this[17] BEFORE = 0x%08X", ptr[17]);
        
        // Call original - it's __thiscall (use __fastcall with dummy EDX)
        typedef int(__fastcall* Func588D40_t)(void*, void*);
        int result = reinterpret_cast<Func588D40_t>(g_orig588D40)(thisPtr, nullptr);
        
        LOG("    Result = %d", result);
        LOG("    this[17] AFTER = 0x%08X", ptr[17]);
        
        if (ptr[17]) {
            int* netConn = reinterpret_cast<int*>(ptr[17]);
            LOG("    Connection object at 0x%08X", ptr[17]);
            LOG("    netConn[2] (state) = 0x%08X", netConn[2]);
        }
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_588630 - Start connection to server
    // __thiscall with 3 stack params: thisPtr in ECX, (a2, a3, a4) on stack
    // ========================================================================
    inline uintptr_t g_orig588630 = 0;
    
    // For __thiscall with stack params, use __fastcall with edx dummy, then stack params
    inline int __fastcall Hook_588630(void* thisPtr, void* /*edx*/, char a2, int a3, int a4) {
        LOG(">>> sub_588630 (start connection) CALLED!");
        LOG("    this=0x%08X, a2=%d (test=%d, prod=%d), a3=0x%08X, a4=0x%08X", 
            (uintptr_t)thisPtr, (int)a2, a2 ? 1 : 0, a2 ? 0 : 1, a3, a4);
        
        // a2: 1=test server (127.0.0.1:9900), 0=prod server (*pcnfs05:20920)
        if (a2) {
            LOG("    Using TEST server (127.0.0.1:9900 -> patched to localhost:%d)", SERVER_PORT);
        } else {
            LOG("    Using PROD server (*pcnfs05.ea.com:20920 -> patched to *localhost:%d)", SERVER_PORT);
        }
        
        // Call original
        typedef int(__fastcall* Func588630_t)(void*, void*, char, int, int);
        int result = reinterpret_cast<Func588630_t>(g_orig588630)(thisPtr, nullptr, a2, a3, a4);
        
        LOG("    Result = %d (0x%X)", result, result);
        
        return result;
    }
    
    // ========================================================================
    // sub_10002E90 - CreateSocket hook
    // Saves return address and calls original
    // ========================================================================
    inline int __cdecl Hook_CreateSocket() {
        // Original:
        // dword_10020758 = retaddr;
        // return dword_10020738();
        
        // Get return address from stack (caller's address)
        void* retAddr = _ReturnAddress();
        g_createSocketRetAddr = reinterpret_cast<uintptr_t>(retAddr);
        
        // Call original CreateSocket
        typedef int(__cdecl* CreateSocketFunc_t)();
        return reinterpret_cast<CreateSocketFunc_t>(g_origCreateSocket)();
    }

    // ========================================================================
    // sub_10002EB0 - RecvFrom hook  
    // Extracts real peer address from relay header
    // ========================================================================
    inline int __stdcall Hook_RecvFrom(
        SOCKET s,
        char* buf,
        int len,
        int flags,
        sockaddr* from,
        int* fromlen)
    {
        // Call original recvfrom
        int result = recvfrom(s, buf, len, flags, from, fromlen);
        
        // Original: if ( s == dword_1002073C && result >= 6 )
        if (s != g_gameSocket || result < 6) {
            if (result > 0 && s == g_gameSocket) {
                LOG("[UDP] RecvFrom: got %d bytes (< 6, no relay header)", result);
            }
            return result;
        }

        sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
        
        // Log relay server source
        char relayFromIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &srcAddr->sin_addr, relayFromIP, sizeof(relayFromIP));
        LOG("[UDP] RecvFrom RELAY: from=%s:%d, total=%d bytes", 
            relayFromIP, ntohs(srcAddr->sin_port), result);

        // Original: v8 = inet_ntoa(...); copy to unk_10021774
        char* relayIP = inet_ntoa(srcAddr->sin_addr);
        char* dst = g_lastPeerIP;
        do {
            *dst = *relayIP;
            dst++;
            relayIP++;
        } while (*(relayIP - 1));

        // Original: htons(*(_WORD *)from->sa_data); (just for debug, ignored result)
        htons(srcAddr->sin_port);

        // v11 = v7 - 6;
        size_t dataLen = result - 6;
        
        // *(_WORD *)from->sa_data = *(_WORD *)buf;  (port)
        srcAddr->sin_port = *reinterpret_cast<uint16_t*>(buf);
        
        // v12 = *(struct in_addr *)(buf + 2);
        // *(struct in_addr *)&from->sa_data[2] = v12;
        srcAddr->sin_addr.s_addr = *reinterpret_cast<uint32_t*>(buf + 2);

        // Log extracted peer info from relay header
        char peerIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &srcAddr->sin_addr, peerIP, sizeof(peerIP));
        LOG("[UDP] RecvFrom RELAY: extracted peer=%s:%d, payload=%zu bytes", 
            peerIP, ntohs(srcAddr->sin_port), dataLen);

        // memmove(buf, buf + 6, v11);
        memmove(buf, buf + 6, dataLen);

        return static_cast<int>(dataLen);
    }

    // ========================================================================
    // sub_10002F50 - SendTo hook
    // Adds relay header and sends to relay server
    // ========================================================================
    inline int __stdcall Hook_SendTo(
        SOCKET s, 
        char* buf, 
        int len, 
        int flags, 
        sockaddr* to, 
        int tolen)
    {
        // Check destination - if it's relay server port 3658, this IS the game socket
        // This is a fallback if Hook_Bind didn't capture the socket
        sockaddr_in* destAddr = reinterpret_cast<sockaddr_in*>(to);
        uint16_t destPort = destAddr ? ntohs(destAddr->sin_port) : 0;
        
        // Auto-detect game socket: if sending to relay port and socket not yet captured
        if (destPort == RELAY_PORT && g_gameSocket == INVALID_SOCKET) {
            g_gameSocket = s;
            LOG("[UDP] Auto-captured game socket: %d (sending to relay port)", (int)s);
        }
        
        // Also capture if socket matches but wasn't set
        if (destPort == RELAY_PORT && s != g_gameSocket) {
            LOG("[UDP] Updating game socket: %d -> %d (relay port match)", (int)g_gameSocket, (int)s);
            g_gameSocket = s;
        }
        
        // Original NFSOR check: if ( s != dword_1002073C || *(_DWORD *)buf == 5 )
        //             return sendto(s, buf, len, flags, to, tolen);
        // 
        // MODIFIED: In full relay mode, we ALWAYS wrap packets in relay header
        // even type=5 "broadcast" packets. The server will handle distribution.
        // 
        // Check if this is traffic to relay port - if so, wrap it
        if (s != g_gameSocket && destPort != RELAY_PORT) {
            // Non-game socket AND not going to relay port - send directly
            if (to) {
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &destAddr->sin_addr, ipStr, sizeof(ipStr));
                LOG("[UDP] SendTo (non-game socket): socket=%d, dest=%s:%d, len=%d", 
                    (int)s, ipStr, destPort, len);
            }
            return sendto(s, buf, len, flags, to, tolen);
        }
        
        // Game socket OR sending to relay port - wrap in relay header
        uint32_t packetType = (len >= 4) ? *reinterpret_cast<uint32_t*>(buf) : 0;
        if (packetType == 5) {
            LOG("[UDP] SendTo: type=5 broadcast packet, wrapping in relay header");
        }

        // destAddr already declared above, reuse it
        // Log the original destination
        char origIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &destAddr->sin_addr, origIP, sizeof(origIP));
        LOG("[UDP] SendTo RELAY: origDest=%s:%d, len=%d", origIP, ntohs(destAddr->sin_port), len);

        // memmove(&unk_1002076E, buf, len);
        memmove(g_relayBuffer + 6, buf, len);
        
        // dword_1002076A = *(_DWORD *)&to->sa_data[2];  (dest IP, stored but not used)
        // *(_WORD *)::buf = *(_WORD *)to->sa_data;      (dest port)
        *reinterpret_cast<uint16_t*>(g_relayBuffer) = destAddr->sin_port;
        *reinterpret_cast<uint32_t*>(g_relayBuffer + 2) = destAddr->sin_addr.s_addr;

        // *(_DWORD *)&::to.sa_data[2] = dword_10020734;
        // *(_WORD *)::to.sa_data = htons(0xE4Au);
        // ::to.sa_family = 2;
        g_relayDest.sin_family = AF_INET;
        g_relayDest.sin_port = htons(RELAY_PORT);
        g_relayDest.sin_addr.s_addr = g_serverIP;

        // Log relay destination
        char relayIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &g_relayDest.sin_addr, relayIP, sizeof(relayIP));
        LOG("[UDP] SendTo RELAY: -> relay=%s:%d (total %d bytes)", relayIP, RELAY_PORT, len + 6);

        // result = sendto(s, ::buf, len + 6, flags, &::to, 16);
        int result = sendto(s, g_relayBuffer, len + 6, flags, 
                           reinterpret_cast<sockaddr*>(&g_relayDest), 16);

        if (result < 0) {
            LOG("[UDP] SendTo RELAY FAILED: error=%d", WSAGetLastError());
        }

        // if ( result > 0 ) result -= 6;
        if (result > 0) {
            result -= 6;
        }

        return result;
    }

    // ========================================================================
    // sub_10003000 - Bind hook
    // Captures game socket handle
    // ========================================================================
    inline int __cdecl Hook_Bind(int a1, int a2, int a3) {
        // Original: sub_10001B60("Bind hook!\n");
        LOG("Bind hook!");
        
        // result = MEMORY[0x74A380](a1, a2, a3);
        typedef int(__cdecl* BindFunc_t)(int, int, int);
        int result = reinterpret_cast<BindFunc_t>(g_origBindFunc)(a1, a2, a3);
        
        // dword_1002073C = *(_DWORD *)(a1 + 24);
        g_gameSocket = *reinterpret_cast<SOCKET*>(a1 + 24);
        LOG("Game socket: %d", static_cast<int>(g_gameSocket));
        
        return result;
    }

    // ========================================================================
    // sub_10002E40 - SendSocket wrapper
    // Modifies packet before sending
    // ========================================================================
    inline int __cdecl Hook_SendSocketWrapper(int a1, void* src, size_t size) {
        // memmove(&unk_10021FE0, Src, Size);
        memmove(g_sendSocketBuffer, src, size);
        
        // dword_10021FE4 = dword_10020740;
        // (offset 4 in buffer = saved value)
        *reinterpret_cast<uint32_t*>(g_sendSocketBuffer + 4) = g_savedValue;
        
        // return dword_10020744(a1, &unk_10021FE0);
        typedef int(__cdecl* SendFunc_t)(int, void*);
        return reinterpret_cast<SendFunc_t>(g_origSendSocketFunc)(a1, g_sendSocketBuffer);
    }

    // ========================================================================
    // sub_10002E70 - PreSendSocket hook
    // Saves socket info before send
    // ========================================================================
    inline int __cdecl Hook_PreSendSocket() {
        // v0 = dword_1002074C();
        typedef int(__cdecl* Func58F740_t)();
        int v0 = reinterpret_cast<Func58F740_t>(g_origFunc58F740)();
        
        // if ( v0 ) v0 = *(_DWORD *)(v0 + 28);
        if (v0) {
            v0 = *reinterpret_cast<int*>(v0 + 28);
        }
        
        // dword_10020740 = v0;
        g_savedValue = v0;
        
        // return dword_10020748();
        typedef int(__cdecl* Func58FD50_t)();
        return reinterpret_cast<Func58FD50_t>(g_origFunc58FD50)();
    }

    // ========================================================================
    // Windowed Mode Hook - CreateWindowExA + Direct3D
    // ========================================================================
    
    // Original function pointer
    inline decltype(&CreateWindowExA) g_origCreateWindowExA = nullptr;
    
    // Saved window handle for D3D
    inline HWND g_gameWindow = nullptr;
    inline int g_windowWidth = 800;
    inline int g_windowHeight = 600;
    
    // Hook function - forces windowed mode
    inline HWND WINAPI Hook_CreateWindowExA(
        DWORD dwExStyle,
        LPCSTR lpClassName,
        LPCSTR lpWindowName,
        DWORD dwStyle,
        int X, int Y,
        int nWidth, int nHeight,
        HWND hWndParent,
        HMENU hMenu,
        HINSTANCE hInstance,
        LPVOID lpParam)
    {
        // Check if this is the main game window (fullscreen style)
        if (dwStyle & WS_POPUP) {
            LOG("[WINDOWED] Intercepted fullscreen window creation!");
            LOG("[WINDOWED] Original style: 0x%08X, size: %dx%d", dwStyle, nWidth, nHeight);
            
            // Save original size for D3D
            g_windowWidth = nWidth;
            g_windowHeight = nHeight;
            
            // Change from WS_POPUP (fullscreen) to windowed style
            dwStyle &= ~WS_POPUP;
            dwStyle |= WS_OVERLAPPEDWINDOW;  // Title bar, borders, resize
            
            // Adjust window size for borders
            RECT rect = { 0, 0, nWidth, nHeight };
            AdjustWindowRect(&rect, dwStyle, FALSE);
            nWidth = rect.right - rect.left;
            nHeight = rect.bottom - rect.top;
            
            // Center on screen
            int screenW = GetSystemMetrics(SM_CXSCREEN);
            int screenH = GetSystemMetrics(SM_CYSCREEN);
            X = (screenW - nWidth) / 2;
            Y = (screenH - nHeight) / 2;
            
            LOG("[WINDOWED] New style: 0x%08X, size: %dx%d, pos: %d,%d", dwStyle, nWidth, nHeight, X, Y);
        }
        
        HWND hwnd = g_origCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle,
                                      X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
        
        // Save main window handle
        if (hwnd && (dwStyle & WS_OVERLAPPEDWINDOW)) {
            g_gameWindow = hwnd;
            LOG("[WINDOWED] Saved game window handle: 0x%p", hwnd);
        }
        
        return hwnd;
    }
    
    // ========================================================================
    // Direct3D9 CreateDevice Hook
    // ========================================================================
    
    // D3D9 types (minimal)
    typedef struct _D3DPRESENT_PARAMETERS {
        UINT BackBufferWidth;
        UINT BackBufferHeight;
        UINT BackBufferFormat;      // D3DFORMAT
        UINT BackBufferCount;
        UINT MultiSampleType;       // D3DMULTISAMPLE_TYPE
        DWORD MultiSampleQuality;
        UINT SwapEffect;            // D3DSWAPEFFECT
        HWND hDeviceWindow;
        BOOL Windowed;              // THIS IS WHAT WE NEED!
        BOOL EnableAutoDepthStencil;
        UINT AutoDepthStencilFormat;
        DWORD Flags;
        UINT FullScreen_RefreshRateInHz;
        UINT PresentationInterval;
    } D3DPRESENT_PARAMETERS;
    
    // IDirect3D9::CreateDevice function pointer type
    typedef HRESULT (WINAPI *CreateDevice_t)(
        void* pThis,                    // IDirect3D9*
        UINT Adapter,
        UINT DeviceType,                // D3DDEVTYPE
        HWND hFocusWindow,
        DWORD BehaviorFlags,
        D3DPRESENT_PARAMETERS* pPresentationParameters,
        void** ppReturnedDeviceInterface // IDirect3DDevice9**
    );
    
    inline CreateDevice_t g_origCreateDevice = nullptr;
    inline void** g_d3d9VTable = nullptr;
    
    inline HRESULT WINAPI Hook_CreateDevice(
        void* pThis,
        UINT Adapter,
        UINT DeviceType,
        HWND hFocusWindow,
        DWORD BehaviorFlags,
        D3DPRESENT_PARAMETERS* pPresentationParameters,
        void** ppReturnedDeviceInterface)
    {
        if (pPresentationParameters) {
            LOG("[WINDOWED] D3D CreateDevice intercepted!");
            LOG("[WINDOWED] Original: Windowed=%d, %dx%d", 
                pPresentationParameters->Windowed,
                pPresentationParameters->BackBufferWidth,
                pPresentationParameters->BackBufferHeight);
            
            // Force windowed mode!
            pPresentationParameters->Windowed = TRUE;
            pPresentationParameters->FullScreen_RefreshRateInHz = 0;  // Must be 0 for windowed
            
            LOG("[WINDOWED] Modified: Windowed=%d", pPresentationParameters->Windowed);
        }
        
        return g_origCreateDevice(pThis, Adapter, DeviceType, hFocusWindow, 
                                   BehaviorFlags, pPresentationParameters, ppReturnedDeviceInterface);
    }
    
    // Hook D3D9 CreateDevice via vtable
    inline bool HookD3D9CreateDevice() {
        // Load d3d9.dll
        HMODULE hD3D9 = GetModuleHandleA("d3d9.dll");
        if (!hD3D9) {
            hD3D9 = LoadLibraryA("d3d9.dll");
        }
        if (!hD3D9) {
            LOG("[WINDOWED] d3d9.dll not loaded");
            return false;
        }
        
        // Get Direct3DCreate9
        typedef void* (WINAPI *Direct3DCreate9_t)(UINT SDKVersion);
        Direct3DCreate9_t pDirect3DCreate9 = (Direct3DCreate9_t)GetProcAddress(hD3D9, "Direct3DCreate9");
        if (!pDirect3DCreate9) {
            LOG("[WINDOWED] Direct3DCreate9 not found");
            return false;
        }
        
        // Create temporary D3D9 object to get vtable
        void* pD3D9 = pDirect3DCreate9(32);  // D3D_SDK_VERSION
        if (!pD3D9) {
            LOG("[WINDOWED] Failed to create D3D9 object");
            return false;
        }
        
        // Get vtable
        g_d3d9VTable = *(void***)pD3D9;
        LOG("[WINDOWED] D3D9 vtable at 0x%p", g_d3d9VTable);
        
        // CreateDevice is at index 16 in IDirect3D9 vtable
        void* pCreateDevice = g_d3d9VTable[16];
        LOG("[WINDOWED] Original CreateDevice at 0x%p", pCreateDevice);
        
        // Save original
        g_origCreateDevice = (CreateDevice_t)pCreateDevice;
        
        // Hook vtable
        DWORD oldProtect;
        VirtualProtect(&g_d3d9VTable[16], sizeof(void*), PAGE_READWRITE, &oldProtect);
        g_d3d9VTable[16] = (void*)Hook_CreateDevice;
        VirtualProtect(&g_d3d9VTable[16], sizeof(void*), oldProtect, &oldProtect);
        
        // Release temp object (call Release at vtable index 2)
        typedef ULONG (WINAPI *Release_t)(void*);
        ((Release_t)g_d3d9VTable[2])(pD3D9);
        
        LOG("[WINDOWED] D3D9 CreateDevice hooked!");
        return true;
    }
    
    // Install the hook using IAT patching
    inline bool InstallWindowedModeHook() {
        #if ENABLE_WINDOWED_MODE == 0
        LOG("[WINDOWED] Disabled in config");
        return true;
        #endif
        
        LOG("[WINDOWED] Installing CreateWindowExA hook...");
        
        HMODULE hModule = GetModuleHandle(NULL);
        if (!hModule) {
            LOG("[WINDOWED] Failed to get module handle");
            return false;
        }
        
        // Get DOS header
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            LOG("[WINDOWED] Invalid DOS signature");
            return false;
        }
        
        // Get NT headers
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            LOG("[WINDOWED] Invalid NT signature");
            return false;
        }
        
        // Get import directory
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        // Find USER32.dll
        while (importDesc->Name) {
            char* dllName = (char*)((BYTE*)hModule + importDesc->Name);
            
            if (_stricmp(dllName, "USER32.dll") == 0) {
                LOG("[WINDOWED] Found USER32.dll imports");
                
                // Get thunk data
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                
                while (origThunk->u1.AddressOfData) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);
                        
                        if (strcmp(importByName->Name, "CreateWindowExA") == 0) {
                            LOG("[WINDOWED] Found CreateWindowExA at 0x%p", &thunk->u1.Function);
                            
                            // Save original
                            g_origCreateWindowExA = (decltype(g_origCreateWindowExA))thunk->u1.Function;
                            
                            // Patch IAT
                            DWORD oldProtect;
                            VirtualProtect(&thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
                            thunk->u1.Function = (ULONG_PTR)Hook_CreateWindowExA;
                            VirtualProtect(&thunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
                            
                            LOG("[WINDOWED] CreateWindowExA hook installed!");
                            
                            // Also hook D3D9 CreateDevice
                            HookD3D9CreateDevice();
                            
                            return true;
                        }
                    }
                    origThunk++;
                    thunk++;
                }
            }
            importDesc++;
        }
        
        LOG("[WINDOWED] CreateWindowExA not found in imports");
        return false;
    }

    // ========================================================================
    // Decrypted Data Capture Hook (for CAPTURE_REAL mode)
    // Hooks sub_754B10 which receives decrypted packets
    // ========================================================================
    
    #if HOOK_DECRYPTED_DATA
    
    // Log file for decrypted data
    inline FILE* g_decryptedLog = nullptr;
    inline CRITICAL_SECTION g_decryptedLogCS;
    inline bool g_decryptedLogInitialized = false;
    
    // Original function pointer
    typedef int (__cdecl *sub_754B10_t)(int socket, int* pCmd, int* pStatus, char** pData);
    inline sub_754B10_t g_orig_sub_754B10 = nullptr;
    inline uintptr_t g_sub_754B10_addr = 0;
    
    inline void InitDecryptedLog() {
        if (g_decryptedLogInitialized) return;
        
        InitializeCriticalSection(&g_decryptedLogCS);
        g_decryptedLog = fopen(DECRYPTED_LOG_FILE, "w");
        if (g_decryptedLog) {
            fprintf(g_decryptedLog, "=== NFSOR Decrypted Traffic Capture ===\n");
            fprintf(g_decryptedLog, "Server: %s\n", SERVER_HOSTNAME);
            fprintf(g_decryptedLog, "Started: %s\n\n", __TIMESTAMP__);
            fflush(g_decryptedLog);
            LOG("Decrypted traffic logging to: %s", DECRYPTED_LOG_FILE);
        }
        g_decryptedLogInitialized = true;
    }
    
    inline void LogDecryptedPacket(int cmd, int status, const char* data, int dataLen) {
        if (!g_decryptedLog) return;
        
        EnterCriticalSection(&g_decryptedLogCS);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        // Convert command to string
        char cmdStr[5] = {0};
        cmdStr[0] = (cmd >> 24) & 0xFF;
        cmdStr[1] = (cmd >> 16) & 0xFF;
        cmdStr[2] = (cmd >> 8) & 0xFF;
        cmdStr[3] = cmd & 0xFF;
        
        fprintf(g_decryptedLog, "\n[%02d:%02d:%02d.%03d] DECRYPTED PACKET\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        fprintf(g_decryptedLog, "CMD: '%s' (0x%08X)\n", cmdStr, cmd);
        fprintf(g_decryptedLog, "STATUS: %d (0x%08X)\n", status, status);
        
        if (data && dataLen > 0) {
            fprintf(g_decryptedLog, "DATA (%d bytes):\n", dataLen);
            
            // Print as key=value pairs (EA format)
            fprintf(g_decryptedLog, "---\n");
            for (int i = 0; i < dataLen && data[i]; i++) {
                char c = data[i];
                if (c == '\n') {
                    fputc('\n', g_decryptedLog);
                } else if (c >= 32 && c < 127) {
                    fputc(c, g_decryptedLog);
                } else {
                    fprintf(g_decryptedLog, "\\x%02X", (unsigned char)c);
                }
            }
            fprintf(g_decryptedLog, "\n---\n");
            
            // Also hex dump
            fprintf(g_decryptedLog, "HEX: ");
            for (int i = 0; i < dataLen && i < 512; i++) {
                fprintf(g_decryptedLog, "%02X ", (unsigned char)data[i]);
                if ((i + 1) % 32 == 0) fprintf(g_decryptedLog, "\n     ");
            }
            if (dataLen > 512) fprintf(g_decryptedLog, "... (truncated)");
            fprintf(g_decryptedLog, "\n");
        }
        
        fflush(g_decryptedLog);
        LeaveCriticalSection(&g_decryptedLogCS);
    }
    
    // Trampoline storage
    inline uint8_t g_754B10_trampoline[32] = {0};
    
    // Hook function
    inline int __cdecl Hook_sub_754B10(int socket, int* pCmd, int* pStatus, char** pData) {
        // Call original
        int result = g_orig_sub_754B10(socket, pCmd, pStatus, pData);
        
        // If successful and we got data, log it
        if (result >= 0 && pCmd && pStatus && pData && *pData) {
            int cmd = *pCmd;
            int status = *pStatus;
            const char* data = *pData;
            
            // Calculate data length (null-terminated or fixed size)
            int dataLen = 0;
            if (data) {
                // EA packets are null-terminated strings
                dataLen = strlen(data);
                if (dataLen == 0) dataLen = result;  // Fallback to return value
            }
            
            LogDecryptedPacket(cmd, status, data, dataLen);
        }
        
        return result;
    }
    
    inline bool InstallDecryptedHook() {
        // Address of sub_754B10 (hardcoded from IDA)
        g_sub_754B10_addr = 0x754B10;
        
        LOG("[DECRYPT] Installing hook at sub_754B10 (0x%08X)", g_sub_754B10_addr);
        
        // Initialize log
        InitDecryptedLog();
        
        // Create trampoline
        // First, copy original bytes (need at least 5 for JMP)
        DWORD oldProtect;
        if (!VirtualProtect((void*)g_sub_754B10_addr, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG("[DECRYPT] VirtualProtect failed!");
            return false;
        }
        
        // Copy first 10 bytes to trampoline (includes full prologue)
        // 53                push ebx
        // 8B 5C 24 14       mov ebx, [esp+14h]
        // 55                push ebp
        // 8B 6C 24 14       mov ebp, [esp+14h]
        memcpy(g_754B10_trampoline, (void*)g_sub_754B10_addr, 10);
        
        // Add JMP back to original+10
        g_754B10_trampoline[10] = 0xE9;  // JMP rel32
        uintptr_t trampolineEnd = (uintptr_t)&g_754B10_trampoline[11];
        uintptr_t jumpTarget = g_sub_754B10_addr + 10;
        *(int32_t*)&g_754B10_trampoline[11] = (int32_t)(jumpTarget - trampolineEnd - 4);
        
        // Make trampoline executable
        DWORD trampolineProtect;
        VirtualProtect(g_754B10_trampoline, sizeof(g_754B10_trampoline), PAGE_EXECUTE_READWRITE, &trampolineProtect);
        
        // Set original pointer to trampoline
        g_orig_sub_754B10 = reinterpret_cast<sub_754B10_t>(reinterpret_cast<void*>(g_754B10_trampoline));
        
        // Write JMP to hook at original location
        uint8_t hookJmp[10];
        hookJmp[0] = 0xE9;  // JMP rel32
        int32_t relAddr = (int32_t)((uintptr_t)Hook_sub_754B10 - g_sub_754B10_addr - 5);
        memcpy(&hookJmp[1], &relAddr, 4);
        // Pad with NOPs
        for (int i = 5; i < 10; i++) hookJmp[i] = 0x90;
        
        memcpy((void*)g_sub_754B10_addr, hookJmp, 10);
        
        VirtualProtect((void*)g_sub_754B10_addr, 16, oldProtect, &oldProtect);
        
        LOG("[DECRYPT] Hook installed! Trampoline at 0x%p", g_754B10_trampoline);
        return true;
    }
    
    inline void CloseDecryptedLog() {
        if (g_decryptedLog) {
            fprintf(g_decryptedLog, "\n=== Session ended ===\n");
            fclose(g_decryptedLog);
            g_decryptedLog = nullptr;
        }
        if (g_decryptedLogInitialized) {
            DeleteCriticalSection(&g_decryptedLogCS);
            g_decryptedLogInitialized = false;
        }
    }
    
    // ========================================================================
    // Outgoing packet hook - sub_7549F0 (sends packets to server)
    // From IDA: int __cdecl sub_7549F0(int addrlen, int a2, int a3, const char *a4, int a5)
    // addrlen = socket struct, a2 = cmd, a3 = status, a4 = data, a5 = dataLen
    // ========================================================================
    
    typedef int (__cdecl *sub_7549F0_t)(int socketStruct, int cmd, int status, const char* data, int dataLen);
    inline sub_7549F0_t g_orig_sub_7549F0 = nullptr;
    inline uintptr_t g_sub_7549F0_addr = 0;
    inline uint8_t g_7549F0_trampoline[32] = {0};
    
    inline void LogOutgoingPacket(int cmd, int status, const char* data, int dataLen) {
        if (!g_decryptedLog) return;
        
        EnterCriticalSection(&g_decryptedLogCS);
        
        SYSTEMTIME st;
        GetLocalTime(&st);
        
        // Convert command to string (stored as big-endian in function)
        char cmdStr[5] = {0};
        cmdStr[0] = (cmd >> 24) & 0xFF;
        cmdStr[1] = (cmd >> 16) & 0xFF;
        cmdStr[2] = (cmd >> 8) & 0xFF;
        cmdStr[3] = cmd & 0xFF;
        
        fprintf(g_decryptedLog, "\n[%02d:%02d:%02d.%03d] >>> SEND (CLIENT->SERVER)\n",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        fprintf(g_decryptedLog, "CMD: '%s' (0x%08X)\n", cmdStr, cmd);
        fprintf(g_decryptedLog, "STATUS: %d (0x%08X)\n", status, status);
        
        if (data && dataLen != 0) {
            int actualLen = dataLen;
            if (dataLen < 0) actualLen = (int)strlen(data);
            
            fprintf(g_decryptedLog, "DATA (%d bytes):\n", actualLen);
            fprintf(g_decryptedLog, "---\n");
            for (int i = 0; i < actualLen && i < 1024; i++) {
                char c = data[i];
                if (c == '\n') {
                    fputc('\n', g_decryptedLog);
                } else if (c >= 32 && c < 127) {
                    fputc(c, g_decryptedLog);
                } else if (c == 0) {
                    break;
                } else {
                    fprintf(g_decryptedLog, "\\x%02X", (unsigned char)c);
                }
            }
            fprintf(g_decryptedLog, "\n---\n");
        }
        
        fflush(g_decryptedLog);
        LeaveCriticalSection(&g_decryptedLogCS);
    }
    
    // Use naked function to preserve all registers and stack
    inline int __cdecl Hook_sub_7549F0(int socketStruct, int cmd, int status, const char* data, int dataLen) {
        // Log before sending
        LogOutgoingPacket(cmd, status, data, dataLen);
        
        // Call original
        return g_orig_sub_7549F0(socketStruct, cmd, status, data, dataLen);
    }
    
    inline bool InstallOutgoingHook() {
        g_sub_7549F0_addr = 0x7549F0;
        
        LOG("[OUTGOING] Installing hook at sub_7549F0 (0x%08X)", g_sub_7549F0_addr);
        
        DWORD oldProtect;
        if (!VirtualProtect((void*)g_sub_7549F0_addr, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            LOG("[OUTGOING] VirtualProtect failed!");
            return false;
        }
        
        // sub_7549F0 prologue (from IDA disasm):
        // 0x7549f0: 53             push ebx           (1 byte)
        // 0x7549f1: 56             push esi           (1 byte)
        // 0x7549f2: 57             push edi           (1 byte)
        // 0x7549f3: 8B 7C 24 0C    mov edi, [esp+0Ch] (4 bytes)
        // 0x7549f7: 57             push edi           (1 byte)
        // Total = 8 bytes, clean boundary
        const int HOOK_SIZE = 8;
        memcpy(g_7549F0_trampoline, (void*)g_sub_7549F0_addr, HOOK_SIZE);
        
        g_7549F0_trampoline[HOOK_SIZE] = 0xE9;  // JMP rel32
        uintptr_t trampolineJmpAddr = (uintptr_t)&g_7549F0_trampoline[HOOK_SIZE + 1];
        uintptr_t jumpTarget = g_sub_7549F0_addr + HOOK_SIZE;
        *(int32_t*)&g_7549F0_trampoline[HOOK_SIZE + 1] = (int32_t)(jumpTarget - trampolineJmpAddr - 4);
        
        DWORD trampolineProtect;
        VirtualProtect(g_7549F0_trampoline, sizeof(g_7549F0_trampoline), PAGE_EXECUTE_READWRITE, &trampolineProtect);
        
        g_orig_sub_7549F0 = reinterpret_cast<sub_7549F0_t>(reinterpret_cast<void*>(g_7549F0_trampoline));
        
        // Write JMP at original location (5 bytes JMP + 3 NOPs)
        uint8_t hookJmp[8];
        hookJmp[0] = 0xE9;  // JMP rel32
        int32_t relAddr = (int32_t)((uintptr_t)Hook_sub_7549F0 - g_sub_7549F0_addr - 5);
        memcpy(&hookJmp[1], &relAddr, 4);
        hookJmp[5] = 0x90;  // NOP
        hookJmp[6] = 0x90;  // NOP
        hookJmp[7] = 0x90;  // NOP
        
        memcpy((void*)g_sub_7549F0_addr, hookJmp, HOOK_SIZE);
        
        VirtualProtect((void*)g_sub_7549F0_addr, 16, oldProtect, &oldProtect);
        
        LOG("[OUTGOING] Hook installed! Trampoline at 0x%p", g_7549F0_trampoline);
        return true;
    }
    
    #endif // HOOK_DECRYPTED_DATA
}
