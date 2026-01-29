#pragma once

#include <Windows.h>
#include <cstdint>

// ============================================================================
// Memory utilities - patching and hooking
// ============================================================================

namespace Memory {

    // RAII class for memory protection
    class ScopedProtect {
        void* m_addr;
        size_t m_size;
        DWORD m_oldProtect;
        bool m_success;
    public:
        ScopedProtect(void* addr, size_t size, DWORD newProtect = PAGE_EXECUTE_READWRITE)
            : m_addr(addr), m_size(size), m_oldProtect(0), m_success(false)
        {
            m_success = VirtualProtect(addr, size, newProtect, &m_oldProtect) != 0;
        }
        
        ~ScopedProtect() {
            if (m_success) {
                DWORD temp;
                VirtualProtect(m_addr, m_size, m_oldProtect, &temp);
            }
        }
        
        bool Success() const { return m_success; }
    };

    // Write bytes to memory
    inline bool WriteBytes(uintptr_t addr, const void* data, size_t size) {
        ScopedProtect protect(reinterpret_cast<void*>(addr), size);
        if (!protect.Success()) return false;
        memcpy(reinterpret_cast<void*>(addr), data, size);
        return true;
    }

    // Write single value
    template<typename T>
    inline bool Write(uintptr_t addr, T value) {
        return WriteBytes(addr, &value, sizeof(T));
    }

    // Read value
    template<typename T>
    inline T Read(uintptr_t addr) {
        return *reinterpret_cast<T*>(addr);
    }

    // NOP bytes
    inline bool Nop(uintptr_t addr, size_t size) {
        ScopedProtect protect(reinterpret_cast<void*>(addr), size);
        if (!protect.Success()) return false;
        memset(reinterpret_cast<void*>(addr), 0x90, size);
        return true;
    }

    // Write relative call (E8)
    inline bool WriteCall(uintptr_t addr, uintptr_t target) {
        ScopedProtect protect(reinterpret_cast<void*>(addr), 5);
        if (!protect.Success()) return false;
        
        *reinterpret_cast<uint8_t*>(addr) = 0xE8;
        *reinterpret_cast<int32_t*>(addr + 1) = static_cast<int32_t>(target - addr - 5);
        return true;
    }

    // Write relative jump (E9)
    inline bool WriteJump(uintptr_t addr, uintptr_t target) {
        ScopedProtect protect(reinterpret_cast<void*>(addr), 5);
        if (!protect.Success()) return false;
        
        *reinterpret_cast<uint8_t*>(addr) = 0xE9;
        *reinterpret_cast<int32_t*>(addr + 1) = static_cast<int32_t>(target - addr - 5);
        return true;
    }

    // Install inline hook (saves original bytes)
    struct Hook {
        uintptr_t address;
        uint8_t originalBytes[16];
        size_t size;
        uintptr_t target;
        
        Hook() : address(0), size(0), target(0) {
            memset(originalBytes, 0, sizeof(originalBytes));
        }
    };

    inline bool InstallHook(Hook& hook, uintptr_t addr, uintptr_t target, size_t size = 5) {
        if (size < 5 || size > 16) return false;
        
        hook.address = addr;
        hook.size = size;
        hook.target = target;
        
        // Save original bytes
        memcpy(hook.originalBytes, reinterpret_cast<void*>(addr), size);
        
        // Write jump
        ScopedProtect protect(reinterpret_cast<void*>(addr), size);
        if (!protect.Success()) return false;
        
        *reinterpret_cast<uint8_t*>(addr) = 0xE9;
        *reinterpret_cast<int32_t*>(addr + 1) = static_cast<int32_t>(target - addr - 5);
        
        // NOP remaining bytes
        for (size_t i = 5; i < size; i++) {
            *reinterpret_cast<uint8_t*>(addr + i) = 0x90;
        }
        
        return true;
    }

    inline bool RemoveHook(Hook& hook) {
        if (!hook.address || !hook.size) return false;
        return WriteBytes(hook.address, hook.originalBytes, hook.size);
    }

    // Get call target from E8 xx xx xx xx
    inline uintptr_t GetCallTarget(uintptr_t addr) {
        if (Read<uint8_t>(addr) != 0xE8) return 0;
        int32_t offset = Read<int32_t>(addr + 1);
        return addr + 5 + offset;
    }
}
