#pragma once

#include <Windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstdint>
#include "config.h"

// ============================================================================
// Debug Logger
// ============================================================================

namespace Logger {
    
    inline FILE* g_logFile = nullptr;
    inline bool g_consoleEnabled = false;

    inline void Init() {
#if ENABLE_CONSOLE
        AllocConsole();
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        SetConsoleTitleA("NFSOR Custom Debug");
        g_consoleEnabled = true;
#endif

#if ENABLE_LOGGING
        fopen_s(&g_logFile, "nfsor_custom.log", "w");
#endif
    }

    inline void Shutdown() {
        if (g_logFile) {
            fclose(g_logFile);
            g_logFile = nullptr;
        }
        if (g_consoleEnabled) {
            FreeConsole();
        }
    }

    inline void Log(const char* format, ...) {
        char buffer[1024];
        va_list args;
        va_start(args, format);
        vsnprintf(buffer, sizeof(buffer), format, args);
        va_end(args);

        if (g_consoleEnabled) {
            printf("%s\n", buffer);
        }

        if (g_logFile) {
            fprintf(g_logFile, "%s\n", buffer);
            fflush(g_logFile);
        }

        // Also output to debugger
        OutputDebugStringA(buffer);
        OutputDebugStringA("\n");
    }

    inline void LogHex(const char* name, const void* data, size_t size) {
        Log("=== %s (%zu bytes) ===", name, size);
        
        const uint8_t* dataBytes = static_cast<const uint8_t*>(data);
        char line[128];
        char* p = line;
        
        for (size_t i = 0; i < size; i++) {
            if (i > 0 && i % 16 == 0) {
                Log("%s", line);
                p = line;
            }
            p += sprintf_s(p, sizeof(line) - (p - line), "%02X ", dataBytes[i]);
        }
        
        if (p != line) {
            Log("%s", line);
        }
    }
}

#define LOG(fmt, ...) Logger::Log(fmt, ##__VA_ARGS__)
#define LOG_HEX(name, data, size) Logger::LogHex(name, data, size)
