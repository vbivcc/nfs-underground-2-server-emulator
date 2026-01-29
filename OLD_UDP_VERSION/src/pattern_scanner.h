#pragma once

#include <Windows.h>
#include <vector>
#include <string>

// ============================================================================
// Pattern Scanner - Boyer-Moore style pattern matching
// ============================================================================

class PatternScanner {
public:
    struct PatternByte {
        uint8_t value;
        bool isWildcard;
    };

private:
    std::vector<PatternByte> m_pattern;
    std::vector<uintptr_t> m_results;
    uintptr_t m_moduleBase;
    uintptr_t m_moduleEnd;
    bool m_scanned;

public:
    PatternScanner() : m_moduleBase(0), m_moduleEnd(0), m_scanned(false) {}

    // Initialize with module base address
    bool Initialize(HMODULE hModule = nullptr) {
        if (!hModule) {
            hModule = GetModuleHandleW(nullptr);
        }
        
        m_moduleBase = reinterpret_cast<uintptr_t>(hModule);
        
        // Get module size from PE header
        auto dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(m_moduleBase);
        auto ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(m_moduleBase + dosHeader->e_lfanew);
        
        m_moduleEnd = m_moduleBase + ntHeaders->OptionalHeader.SizeOfImage;
        
        // Find code section end for more accurate scanning
        auto section = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
            if (section->Characteristics & IMAGE_SCN_CNT_CODE) {
                uintptr_t sectionEnd = m_moduleBase + section->VirtualAddress + section->Misc.VirtualSize;
                if (sectionEnd > m_moduleEnd) {
                    m_moduleEnd = sectionEnd;
                }
            }
        }
        
        return true;
    }

    // Parse pattern string like "68 ? ? ? ? 50 E8"
    bool SetPattern(const char* pattern) {
        m_pattern.clear();
        m_results.clear();
        m_scanned = false;

        const char* p = pattern;
        while (*p) {
            // Skip whitespace
            while (*p == ' ' || *p == '\t') p++;
            if (!*p) break;

            PatternByte pb;
            if (*p == '?') {
                pb.isWildcard = true;
                pb.value = 0;
                p++;
                if (*p == '?') p++; // Handle "??" format
            } else {
                pb.isWildcard = false;
                // Parse hex byte
                char hex[3] = { p[0], p[1], 0 };
                pb.value = static_cast<uint8_t>(strtol(hex, nullptr, 16));
                p += 2;
            }
            m_pattern.push_back(pb);
        }

        return !m_pattern.empty();
    }

    // Scan memory for pattern
    bool Scan(int maxResults = -1) {
        if (m_pattern.empty() || !m_moduleBase) return false;

        m_results.clear();
        m_scanned = true;

        size_t patternSize = m_pattern.size();
        
        for (uintptr_t addr = m_moduleBase; addr < m_moduleEnd - patternSize; addr++) {
            bool found = true;
            
            for (size_t i = 0; i < patternSize; i++) {
                if (!m_pattern[i].isWildcard) {
                    uint8_t byte = *reinterpret_cast<uint8_t*>(addr + i);
                    if (byte != m_pattern[i].value) {
                        found = false;
                        break;
                    }
                }
            }

            if (found) {
                m_results.push_back(addr);
                if (maxResults > 0 && m_results.size() >= static_cast<size_t>(maxResults)) {
                    break;
                }
            }
        }

        return !m_results.empty();
    }

    // Get first result
    uintptr_t GetResult(size_t index = 0) const {
        if (index < m_results.size()) {
            return m_results[index];
        }
        return 0;
    }

    // Get number of results
    size_t GetResultCount() const {
        return m_results.size();
    }

    // Combined: set pattern, scan, return first result
    uintptr_t FindPattern(const char* pattern) {
        if (!SetPattern(pattern)) return 0;
        if (!Scan(1)) return 0;
        return GetResult(0);
    }

    // Get call target from E8 instruction
    static uintptr_t GetCallTarget(uintptr_t callAddr) {
        if (*reinterpret_cast<uint8_t*>(callAddr) != 0xE8) return 0;
        int32_t offset = *reinterpret_cast<int32_t*>(callAddr + 1);
        return callAddr + 5 + offset;
    }

    // Read pointer at pattern offset
    static uintptr_t ReadPointer(uintptr_t addr, int offset = 0) {
        return *reinterpret_cast<uintptr_t*>(addr + offset);
    }
};
