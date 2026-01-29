cmake_minimum_required(VERSION 3.15)
project(NFSOR_Custom)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    src/dllmain.cpp
)

set(HEADERS
    src/config.h
    src/logger.h
    src/memory.h
    src/pattern_scanner.h
    src/patterns.h
    src/patches.h
    src/hooks.h
)

# Create DLL (ASI is just a renamed DLL)
add_library(${PROJECT_NAME} SHARED ${SOURCES} ${HEADERS})

# Output as .asi file
set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "NFSOR_Custom"
    SUFFIX ".asi"
    PREFIX ""
)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE
    ws2_32
)

# Windows definitions
target_compile_definitions(${PROJECT_NAME} PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _CRT_SECURE_NO_WARNINGS
    _WINSOCK_DEPRECATED_NO_WARNINGS
)

# MSVC specific settings
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W3          # Warning level 3
        /GS-         # Disable security checks (for hooks)
        /Gy          # Enable function-level linking
    )
    
    target_link_options(${PROJECT_NAME} PRIVATE
        /SAFESEH:NO  # Disable safe exception handlers (for hooks)
    )
endif()
