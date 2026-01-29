// ============================================================================
// NFSOR Custom - NFS Underground 2 Online Mod
// Custom server support - ASI Plugin
// Based on full IDA analysis of original NFSOR.asi
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <Windows.h>
#include "config.h"
#include "logger.h"
#include "pattern_scanner.h"
#include "memory.h"
#include "patches.h"
#include "hooks.h"

// Global scanner instance
PatternScanner g_scanner;

// Global URL buffer - MUST stay in memory for game to use
// (defined here to ensure single instance, declared extern in patches.h)
char Patches::g_serverUrl[64] = {};

// ============================================================================
// Main initialization thread
// Replicates StartAddress from original NFSOR.asi
// ============================================================================
DWORD WINAPI InitThread(LPVOID) {
    Logger::Init();
    LOG("===========================================");
    LOG("NFSOR Custom v1.0 (ASI)");
    LOG("Server: %s:%d", SERVER_HOSTNAME, SERVER_PORT);
    LOG("===========================================");

    // Initialize pattern scanner with game module
    if (!g_scanner.Initialize()) {
        LOG("ERROR: Failed to initialize scanner");
        return 1;
    }

    // Wait for game to unpack (original: 120 * 100ms = 12 sec)
    if (!Patches::WaitForUnpack(g_scanner)) {
        MessageBoxA(nullptr, 
            "Game not unpacked in tolerable time.\n"
            "Are you using correct ASI?",
            "NFSOR Custom - Error", MB_ICONERROR);
        return 1;
    }

    // Find all patterns
    if (!Patches::FindAllPatterns(g_scanner)) {
        MessageBoxA(nullptr,
            "Failed to find required patterns.\n"
            "Game version may not be supported.",
            "NFSOR Custom - Error", MB_ICONERROR);
        return 1;
    }

    // Apply patches FIRST (like original NFSOR)
    if (!Patches::ApplyAll()) {
        LOG("WARNING: Some patches/hooks failed");
    }

    // THEN initialize relay (DNS resolution) - like original
    if (!Hooks::InitRelay()) {
        LOG("WARNING: Failed to initialize relay");
    }

    // Install decrypted data capture hook (for CAPTURE_REAL mode)
    #if HOOK_DECRYPTED_DATA
    if (!Hooks::InstallDecryptedHook()) {
        LOG("WARNING: Failed to install decrypted data hook (incoming)");
    } else {
        LOG("Incoming packet capture ENABLED");
    }
    if (!Hooks::InstallOutgoingHook()) {
        LOG("WARNING: Failed to install outgoing hook");
    } else {
        LOG("Outgoing packet capture ENABLED");
    }
    LOG("Traffic capture logging to: %s", DECRYPTED_LOG_FILE);
    #endif

    LOG("===========================================");
    LOG("Initialization complete!");
    LOG("===========================================");

    return 0;
}

// ============================================================================
// DLL Entry Point
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID reserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            
            // Install windowed mode hook IMMEDIATELY before game creates window!
            // This must happen before InitThread because window is created early
            #if ENABLE_WINDOWED_MODE
            Hooks::InstallWindowedModeHook();
            #endif
            
            CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
            break;

        case DLL_PROCESS_DETACH:
            Hooks::CloseTrafficLog();
            #if HOOK_DECRYPTED_DATA
            Hooks::CloseDecryptedLog();
            #endif
            Logger::Shutdown();
            WSACleanup();
            break;
    }
    return TRUE;
}

// ============================================================================
// ASI Loader export
// ============================================================================
extern "C" __declspec(dllexport) void InitializeASI() {
    // Some ASI loaders call this
}
