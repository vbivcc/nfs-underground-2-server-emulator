#pragma once

#include <Windows.h>
#include <cstdint>
#include <cstring>
#include "pattern_scanner.h"
#include "memory.h"
#include "patterns.h"
#include "logger.h"
#include "config.h"
#include "hooks.h"

// ============================================================================
// Game Patches - EXACT replica of original NFSOR mod
// Based on full IDA analysis of StartAddress and sub_10002250
// ============================================================================

namespace Patches {

    // ========================================================================
    // Pattern scan results - stores FOUND ADDRESSES (like their vector[0])
    // In original: dword_1001F*** points to vector.data(), *dword_1001F*** = found addr
    // Here: g_results.*** = found addr directly
    // ========================================================================
    struct PatternResults {
        uintptr_t eaServerUrl;          // Pattern: "68 ? ? ? ? 50 E8..."
        uintptr_t multiInstance;        // Pattern: "6A ? E8 ? ? ? ?..."
        uintptr_t sslPatch;             // Pattern: "7D ? C7 86..."
        uintptr_t disableEncryption;    // Pattern: "F7 DA 1B D2..."
        uintptr_t yearLimit;            // Pattern: "B8 ? ? ? ? C3 90 90..."
        uintptr_t createSocketCall;     // Pattern: "E8 ? ? ? ? 83 C4 ? 3B C7..."
        uintptr_t recvFromCall;         // Pattern: "E8 ? ? ? ? 8B F8 85 FF..."
        uintptr_t sendToCall;           // Pattern: "E8 ? ? ? ? 5E 85 C0..."
        uintptr_t srvBindCall;          // Pattern: "E8 ? ? ? ? 83 C4 ? 85 C0 7D..."
        uintptr_t sendSocketFunc;       // Pattern: "83 EC ? A1..."
        uintptr_t func58FD50;           // Pattern: "55 8B EC 83 E4..."
        uintptr_t func58F740;           // Pattern: "8A 0D ? ? ? ?..."
        uintptr_t createSocketFunc;     // Pattern: "51 8B 44 24..."
        
        // These are found by sub_10002250 but result pointers stored differently
        // We need separate scanning for client/host handshake
        uintptr_t sendSocketClient;     // E8...8B 44 24
        uintptr_t sendSocketHost;       // E8...8B 84 24
        uintptr_t preSendSocket;        // For sub_10002E70
        
        // Windowed mode
        uintptr_t windowedMode;         // Fullscreen flag location
    };

    inline PatternResults g_results = {};
    
    // Server URL buffer: "*hostname\0" (byte_10021FA4 in original)
    // Defined in dllmain.cpp to ensure single global instance
    extern char g_serverUrl[64];

    // ========================================================================
    // Wait for game to unpack (original: 120 loops * 100ms = 12 sec)
    // ========================================================================
    inline bool WaitForUnpack(PatternScanner& scanner) {
        LOG("Waiting for game to unpack...");
        
        for (int i = 0; i < 120; i++) {
            scanner.SetPattern(Patterns::EA_SERVER_URL);
            if (scanner.Scan(1) && scanner.GetResultCount() >= 1) {
                LOG("Game unpacked (attempt %d)", i + 1);
                return true;
            }
            Sleep(100);
        }
        
        LOG("ERROR: Game did not unpack in time!");
        return false;
    }

    // ========================================================================
    // Find all patterns (sub_10002250)
    // ========================================================================
    inline bool FindAllPatterns(PatternScanner& scanner) {
        LOG("Scanning patterns...");

        #define SCAN(name, pattern) \
            g_results.name = scanner.FindPattern(pattern); \
            LOG("  " #name ": 0x%08X %s", g_results.name, g_results.name ? "OK" : "FAIL");

        SCAN(eaServerUrl, Patterns::EA_SERVER_URL);
        SCAN(multiInstance, Patterns::MULTI_INSTANCE);
        SCAN(sslPatch, Patterns::SSL_PATCH);
        SCAN(disableEncryption, Patterns::ENCRYPTION_PATCH);
        SCAN(yearLimit, Patterns::YEAR_LIMIT);
        SCAN(createSocketCall, Patterns::CREATE_SOCKET);
        SCAN(recvFromCall, Patterns::RECVFROM_FUNC);
        SCAN(sendToCall, Patterns::SENDTO_FUNC);
        SCAN(srvBindCall, Patterns::SRV_BIND);
        SCAN(sendSocketFunc, Patterns::SEND_SOCKET);
        SCAN(func58FD50, Patterns::SUB_58FD50);
        SCAN(func58F740, Patterns::SUB_58F740);
        SCAN(createSocketFunc, Patterns::CREATE_SOCKET_INTERNAL);
        SCAN(sendSocketClient, Patterns::SEND_SOCKET_CLIENT);
        SCAN(sendSocketHost, Patterns::SEND_SOCKET_HOST);
        SCAN(windowedMode, Patterns::WINDOWED_MODE);

        #undef SCAN

        if (!g_results.eaServerUrl) {
            LOG("CRITICAL: EA Server URL pattern not found!");
            return false;
        }

        return true;
    }

    // ========================================================================
    // Helper: Patch bytes with VirtualProtect
    // ========================================================================
    inline bool PatchBytes(uintptr_t addr, const void* data, size_t size) {
        DWORD oldProtect;
        if (!VirtualProtect(reinterpret_cast<void*>(addr), size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        memcpy(reinterpret_cast<void*>(addr), data, size);
        DWORD temp;
        VirtualProtect(reinterpret_cast<void*>(addr), size, oldProtect, &temp);
        return true;
    }

    // ========================================================================
    // Apply patches - EXACTLY as original NFSOR StartAddress does
    // ========================================================================
    inline bool ApplyPatches() {
        LOG("Applying patches (NFSOR compatible)...");
        
        // ================================================================
        // 1. Multi-instance patch: 7 NOPs at found address
        // Original: v5 = *(_DWORD **)dword_1001F938; *v5 = 0x90909090; etc
        // Our g_results.multiInstance IS the found address directly
        // ================================================================
        if (g_results.multiInstance) {
            uintptr_t addr = g_results.multiInstance;
            LOG("  [1] Multi-instance at 0x%08X: writing 7 NOPs", addr);
            
            // Write: 90 90 90 90 90 90 90 (7 NOPs)
            uint8_t nops[7] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (!PatchBytes(addr, nops, 7)) {
                LOG("      FAILED!");
            }
        }

        // ================================================================
        // 2. SSL Patch - EXACTLY like original NFSOR mod!
        // 
        // Original mod (from StartAddress):
        //   v6 = *(_BYTE **)dword_1001FAA0;  // Address from pattern "7D ? C7 86..."
        //   *v6 = 126;                        // 0x7E
        //
        // This changes JGE (7D) to JLE (7E) - inverting the SSL condition
        // Pattern finds: "7D ? C7 86 ? ? ? ? ? ? ? ? EB ? 03 7C 24"
        // 
        // NOTE: Original NFSOR ALWAYS applies this patch! It's required for
        // connecting to NFSOR servers. Without it, SSL handshake fails!
        // ================================================================
        if (g_results.sslPatch) {
            uintptr_t addr = g_results.sslPatch;
            uint8_t oldVal = *reinterpret_cast<uint8_t*>(addr);
            LOG("  [2a] SSL patch at 0x%08X:", addr);
            LOG("       Old value: 0x%02X (%s)", oldVal, oldVal == 0x7D ? "JGE" : "???");
            
            // Change 7D (JGE) to 7E (JLE) - EXACTLY like original NFSOR
            uint8_t newVal = 0x7E;
            if (PatchBytes(addr, &newVal, 1)) {
                LOG("       New value: 0x7E (JLE) - SSL condition INVERTED (like original NFSOR)");
            } else {
                LOG("       FAILED!");
            }
        }
        
        // ================================================================
        // 2b. Disable Encryption - prevents RC4 encryption of packets
        //
        // Pattern: "F7 DA 1B D2 83 E2 ? 83 C2 ? 89 96"
        // Assembly:
        //   F7 DA       = NEG EDX
        //   1B D2       = SBB EDX, EDX
        //   83 E2 xx    = AND EDX, xx
        //   83 C2 xx    = ADD EDX, xx
        //   89 96 xxxx  = MOV [ESI+xxxx], EDX
        //
        // This calculates encryption type. We patch to always set EDX=0:
        //   F7 DA 1B D2 -> 31 D2 90 90 (XOR EDX,EDX; NOP; NOP)
        // ================================================================
        #if DISABLE_ENCRYPTION
        if (g_results.disableEncryption) {
            uintptr_t addr = g_results.disableEncryption;
            LOG("  [2b] Disable encryption at 0x%08X:", addr);
            
            // Read old bytes
            uint8_t oldBytes[4];
            memcpy(oldBytes, reinterpret_cast<void*>(addr), 4);
            LOG("       Old: %02X %02X %02X %02X (NEG EDX; SBB EDX,EDX)", 
                oldBytes[0], oldBytes[1], oldBytes[2], oldBytes[3]);
            
            // Patch: XOR EDX,EDX; NOP; NOP (always sets EDX=0)
            uint8_t newBytes[4] = {0x31, 0xD2, 0x90, 0x90};
            if (PatchBytes(addr, newBytes, 4)) {
                LOG("       New: 31 D2 90 90 (XOR EDX,EDX; NOP; NOP) - ENCRYPTION DISABLED");
            } else {
                LOG("       FAILED!");
            }
        }
        #else
        LOG("  [2b] Encryption patch: SKIPPED (will hook decrypted data instead)");
        #endif

        // ================================================================
        // 3. Build server URL string
        // If hostname starts with '*', SSL is enabled
        // If hostname has no '*', SSL is disabled (plain connection)
        // ================================================================
        {
            const char* hostname = SERVER_HOSTNAME;
            
            // Copy hostname as-is (with or without '*' prefix)
            size_t hostnameLen = strlen(hostname);
            memcpy(g_serverUrl, hostname, hostnameLen);
            g_serverUrl[hostnameLen] = '\0';  // Null terminate
            
            LOG("  [3] Server URL buffer at 0x%08X:", reinterpret_cast<uintptr_t>(g_serverUrl));
            LOG("      Content: \"%s\" (len=%zu)", g_serverUrl, strlen(g_serverUrl));
            LOG("      SSL: %s", (g_serverUrl[0] == '*') ? "ENABLED" : "DISABLED");
            LOG("      Bytes: %02X %02X %02X %02X %02X...", 
                (unsigned char)g_serverUrl[0], (unsigned char)g_serverUrl[1],
                (unsigned char)g_serverUrl[2], (unsigned char)g_serverUrl[3],
                (unsigned char)g_serverUrl[4]);
        }

        // ================================================================
        // 4. Patch URL pointer in PUSH instruction (EXACTLY like NFSOR)
        // Pattern "68 XX XX XX XX" - PUSH imm32
        // We patch the 4 bytes AFTER opcode 0x68 (at addr+1) to point to our buffer
        // ================================================================
        if (g_results.eaServerUrl) {
            uintptr_t pushAddr = g_results.eaServerUrl;
            uintptr_t operandAddr = pushAddr + 1;  // Skip 0x68 opcode
            
            uintptr_t oldPtr = *reinterpret_cast<uintptr_t*>(operandAddr);
            LOG("  [4] URL patch at PUSH 0x%08X:", pushAddr);
            LOG("      Old ptr: 0x%08X -> \"%s\"", oldPtr, reinterpret_cast<char*>(oldPtr));
            LOG("      Our buffer at: 0x%08X -> \"%s\"", reinterpret_cast<uintptr_t>(g_serverUrl), g_serverUrl);
            
            uintptr_t newPtr = reinterpret_cast<uintptr_t>(g_serverUrl);
            if (PatchBytes(operandAddr, &newPtr, 4)) {
                // Verify
                uintptr_t verifyPtr = *reinterpret_cast<uintptr_t*>(operandAddr);
                LOG("      New ptr: 0x%08X -> \"%s\"", verifyPtr, reinterpret_cast<char*>(verifyPtr));
            } else {
                LOG("      FAILED!");
            }
        }

        // ================================================================
        // 5. Year limit patch: write 2050 at found address + 1
        // Original: v13 = *(_DWORD *)dword_1001FB78 + 1; *v13 = 2050;
        // Pattern "B8 XX XX XX XX" - MOV EAX, imm32
        // We patch the 4 bytes AFTER opcode 0xB8 (at addr+1)
        // ================================================================
        if (g_results.yearLimit) {
            uintptr_t movAddr = g_results.yearLimit;
            uintptr_t operandAddr = movAddr + 1;  // Skip 0xB8 opcode
            
            uint32_t oldYear = *reinterpret_cast<uint32_t*>(operandAddr);
            LOG("  [5] Year limit at 0x%08X+1:", movAddr);
            LOG("      Old: %u", oldYear);
            
            uint32_t newYear = 2050;
            if (PatchBytes(operandAddr, &newYear, 4)) {
                LOG("      New: %u", newYear);
            } else {
                LOG("      FAILED!");
            }
        }

        // ================================================================
        // 6. Windowed mode - handled via IAT hook in DllMain
        // (CreateWindowExA hook is installed before window creation)
        // ================================================================
        #if ENABLE_WINDOWED_MODE
        LOG("  [6] Windowed mode: enabled via CreateWindowExA hook");
        #else
        LOG("  [6] Windowed mode: DISABLED in config");
        #endif

        LOG("Patches applied!");
        return true;
    }

    // ========================================================================
    // Install CALL hooks for relay (UDP traffic redirection)
    // Original installs hooks at: CreateSocket, RecvFrom, SendTo, Bind, etc
    // ========================================================================
    inline bool InstallHooks() {
        LOG("Installing hooks...");
        
        // Save original function addresses for hooks to call
        Hooks::g_origCreateSocket = g_results.createSocketFunc;
        Hooks::g_origSendSocketFunc = g_results.sendSocketFunc;
        Hooks::g_origFunc58FD50 = g_results.func58FD50;
        Hooks::g_origFunc58F740 = g_results.func58F740;
        Hooks::g_origBindFunc = 0x74A380;  // Hardcoded in original
        
        LOG("  Function addresses:");
        LOG("    CreateSocket: 0x%08X", Hooks::g_origCreateSocket);
        LOG("    SendSocket:   0x%08X", Hooks::g_origSendSocketFunc);
        LOG("    sub_58FD50:   0x%08X", Hooks::g_origFunc58FD50);
        LOG("    sub_58F740:   0x%08X", Hooks::g_origFunc58F740);
        LOG("    Bind:         0x%08X", Hooks::g_origBindFunc);

        // Helper to install E8 CALL hook
        auto InstallCallHook = [](uintptr_t addr, void* hook, const char* name) {
            if (!addr) {
                LOG("    %s: SKIPPED (not found)", name);
                return;
            }
            
            DWORD oldProtect;
            if (!VirtualProtect(reinterpret_cast<void*>(addr), 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                LOG("    %s: FAILED (VirtualProtect)", name);
                return;
            }
            
            // Write E8 xx xx xx xx (CALL rel32)
            *reinterpret_cast<uint8_t*>(addr) = 0xE8;
            *reinterpret_cast<int32_t*>(addr + 1) = 
                static_cast<int32_t>(reinterpret_cast<uintptr_t>(hook) - addr - 5);
            
            DWORD temp;
            VirtualProtect(reinterpret_cast<void*>(addr), 5, oldProtect, &temp);
            LOG("    %s: hooked at 0x%08X", name, addr);
        };

        // Install relay hooks for P2P UDP traffic redirection through relay server
        LOG("  Installing relay hooks for UDP...");
        
        InstallCallHook(g_results.createSocketCall, Hooks::Hook_CreateSocket, "CreateSocket");
        InstallCallHook(g_results.recvFromCall, Hooks::Hook_RecvFrom, "RecvFrom");
        InstallCallHook(g_results.sendToCall, Hooks::Hook_SendTo, "SendTo");
        InstallCallHook(g_results.srvBindCall, Hooks::Hook_Bind, "Bind");
        // Optional: socket wrappers (not needed for basic relay)
        // InstallCallHook(g_results.sendSocketClient, Hooks::Hook_SendSocketWrapper, "SendSocketClient");
        // InstallCallHook(g_results.sendSocketHost, Hooks::Hook_SendSocketWrapper, "SendSocketHost");

        LOG("Relay hooks installed");
        return true;
    }

    // ========================================================================
    // Main initialization
    // ========================================================================
    inline bool ApplyAll() {
        if (!ApplyPatches()) {
            LOG("Failed to apply patches");
            return false;
        }
        
        if (!InstallHooks()) {
            LOG("Failed to install hooks");
            return false;
        }
        
        return true;
    }
}
