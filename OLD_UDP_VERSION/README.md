# NFSOR Custom

Custom online mod for Need for Speed Underground 2 with configurable server support.

## Features

- Custom server hostname configuration
- UDP relay support for NAT traversal
- SSL bypass
- Encryption disable
- Multi-instance support
- Year limit patch
- Debug console and logging

## Building

### Requirements

- Visual Studio 2022 (or 2019)
- CMake 3.15+
- Windows SDK

### Build Steps

1. Open **Developer Command Prompt for VS 2022** (x86)
2. Navigate to project folder
3. Run `build.bat`

Or manually:

```batch
mkdir build
cd build
cmake -G "Visual Studio 17 2022" -A Win32 ..
cmake --build . --config Release
```

## Installation

1. Copy `dinput8.dll` to your NFS Underground 2 game folder
2. Edit `src/config.h` to set your server address before building
3. Start the game

## Configuration

Edit `src/config.h`:

```cpp
#define SERVER_HOSTNAME     "your.server.com"
#define SERVER_PORT         3658
#define ENABLE_CONSOLE      1    // Debug console
#define ENABLE_LOGGING      1    // File logging
```

## Server Protocol

The mod uses a simple relay protocol:

### Outgoing Packet Format
```
[2 bytes] Destination port (network order)
[4 bytes] Destination IP (network order)
[N bytes] Original game data
```

### Incoming Packet Format
```
[2 bytes] Source port (network order)
[4 bytes] Source IP (network order)  
[N bytes] Original game data
```

## Server Implementation Example

See `../NFSOR_ANALYSIS.md` for Python server example.

## Patterns

The mod uses signature scanning to find game functions. Patterns are defined in `src/patterns.h`.

If the game version is not supported, patterns may need to be updated.

## License

For educational purposes only.
