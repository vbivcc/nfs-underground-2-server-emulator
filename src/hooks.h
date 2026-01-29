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
    
    // Global tracking for P2P sync state (shared between sendto and recvfrom hooks)
    inline DWORD g_firstBroadcastRecvTime = 0; // When joiner received first BROADCAST
    inline bool g_weAreHost = false; // True if we sent BROADCAST (type 5)
    inline bool g_sentCarData = false; // True if we sent any CAR_DATA (102-105)
    inline bool g_sentCarDataTypes[4] = {false, false, false, false}; // Track each type 102-105
    inline bool g_hostPeerRegistered = false; // True if host registered joiner peer (reset on new session)
    
    // Global variables to track host address from received packets (for sending CAR_DATA)
    inline uint32_t g_lastRecvIP = 0;
    inline uint16_t g_lastRecvPort = 0;
    
    // Original WinSock function pointers for IAT hooks
    typedef int (WSAAPI *connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
    typedef struct hostent* (WSAAPI *gethostbyname_t)(const char* name);
    typedef int (WSAAPI *send_t)(SOCKET s, const char* buf, int len, int flags);
    typedef int (WSAAPI *recv_t)(SOCKET s, char* buf, int len, int flags);
    typedef int (WSAAPI *recvfrom_t)(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen);
    typedef int (WSAAPI *sendto_t)(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen);
    
    inline connect_t g_origConnect = nullptr;
    inline gethostbyname_t g_origGethostbyname = nullptr;
    inline send_t g_origSend = nullptr;
    inline recv_t g_origRecv = nullptr;
    inline recvfrom_t g_origRecvfrom = nullptr;
    inline sendto_t g_origSendto = nullptr;
    
    // Traffic log file
    inline FILE* g_trafficLog = nullptr;
    inline CRITICAL_SECTION g_trafficLogCS;
    inline bool g_trafficLogInitialized = false;
    
    // Track game sockets for traffic logging
    inline SOCKET g_tcpGameSocket = INVALID_SOCKET;
    
    // ========================================================================
    // UDP-over-TCP Tunnel variables
    // ========================================================================
    #define UDP_TUNNEL_PORT 20924   // Server port for UDP tunnel
    
    inline SOCKET g_udpTunnelSocket = INVALID_SOCKET;
    inline HANDLE g_udpTunnelThread = NULL;
    inline volatile bool g_udpTunnelRunning = false;
    inline CRITICAL_SECTION g_udpTunnelCS;
    inline bool g_udpTunnelCSInitialized = false;
    
    // Received UDP packets queue (from TCP tunnel)
    struct UdpTunnelPacket {
        uint16_t srcPort;
        uint32_t srcIP;
        char payload[4096];
        int payloadLen;
    };
    
    #define UDP_TUNNEL_QUEUE_SIZE 64
    inline UdpTunnelPacket g_udpTunnelQueue[UDP_TUNNEL_QUEUE_SIZE];
    inline int g_udpTunnelQueueHead = 0;
    inline int g_udpTunnelQueueTail = 0;
    inline int g_udpTunnelQueueCount = 0;
    
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
    // UDP-over-TCP Tunnel functions
    // ========================================================================
    
    // Initialize UDP tunnel
    inline void InitUdpTunnel() {
        if (!g_udpTunnelCSInitialized) {
            InitializeCriticalSection(&g_udpTunnelCS);
            g_udpTunnelCSInitialized = true;
        }
    }
    
    // Connect to UDP tunnel server
    inline bool ConnectUdpTunnel() {
        if (g_udpTunnelSocket != INVALID_SOCKET) {
            return true; // Already connected
        }
        
        if (g_serverIP == 0) {
            LOG("[UDP-TUNNEL] Server IP not resolved yet");
            return false;
        }
        
        InitUdpTunnel();
        
        // Create TCP socket
        g_udpTunnelSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_udpTunnelSocket == INVALID_SOCKET) {
            LOG("[UDP-TUNNEL] Failed to create socket: %d", WSAGetLastError());
            return false;
        }
        
        // Set non-blocking for connect timeout
        u_long nonBlocking = 1;
        ioctlsocket(g_udpTunnelSocket, FIONBIO, &nonBlocking);
        
        // Connect to server
        sockaddr_in serverAddr = {};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = g_serverIP;
        serverAddr.sin_port = htons(UDP_TUNNEL_PORT);
        
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &serverAddr.sin_addr, ipStr, sizeof(ipStr));
        LOG("[UDP-TUNNEL] Connecting to %s:%d (g_serverIP=0x%08X)...", ipStr, UDP_TUNNEL_PORT, g_serverIP);
        
        int result = connect(g_udpTunnelSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr));
        if (result == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                LOG("[UDP-TUNNEL] Connect failed: %d", err);
                closesocket(g_udpTunnelSocket);
                g_udpTunnelSocket = INVALID_SOCKET;
                return false;
            }
            
            // Wait for connection with timeout (5 seconds)
            fd_set writeSet;
            FD_ZERO(&writeSet);
            FD_SET(g_udpTunnelSocket, &writeSet);
            
            timeval timeout = { 5, 0 };
            result = select(0, NULL, &writeSet, NULL, &timeout);
            
            if (result <= 0) {
                LOG("[UDP-TUNNEL] Connect timeout or error");
                closesocket(g_udpTunnelSocket);
                g_udpTunnelSocket = INVALID_SOCKET;
                return false;
            }
            
            // Check if connected
            int optVal = 0;
            int optLen = sizeof(optVal);
            getsockopt(g_udpTunnelSocket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&optVal), &optLen);
            if (optVal != 0) {
                LOG("[UDP-TUNNEL] Connect failed: %d", optVal);
                closesocket(g_udpTunnelSocket);
                g_udpTunnelSocket = INVALID_SOCKET;
                return false;
            }
        }
        
        // Set back to non-blocking for async recv
        nonBlocking = 1;
        ioctlsocket(g_udpTunnelSocket, FIONBIO, &nonBlocking);
        
        LOG("[UDP-TUNNEL] Connected successfully to %s:%d!", ipStr, UDP_TUNNEL_PORT);
        LOG("[UDP-TUNNEL] Local socket: %d, g_serverIP=0x%08X", (int)g_udpTunnelSocket, g_serverIP);
        return true;
    }
    
    // Send UDP packet through TCP tunnel
    // Format: [4 bytes total_len LE][2 bytes dest_port BE][4 bytes dest_IP][payload]
    inline int SendUdpViaTunnel(uint16_t destPort, uint32_t destIP, const char* payload, int payloadLen) {
        static int s_sendCallCount = 0;
        s_sendCallCount++;
        
        if (g_udpTunnelSocket == INVALID_SOCKET) {
            LOG("[UDP-TUNNEL-SEND] Socket INVALID, reconnecting...");
            if (!ConnectUdpTunnel()) {
                LOG("[UDP-TUNNEL-SEND] Reconnect FAILED!");
                return -1;
            }
        }
        
        // Log first send with server info
        if (s_sendCallCount == 1) {
            char serverIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_serverIP, serverIPStr, sizeof(serverIPStr));
            LOG("[UDP-TUNNEL-FIRST-SEND] Connected to relay server %s:%d, socket=%d",
                serverIPStr, UDP_TUNNEL_PORT, (int)g_udpTunnelSocket);
        }
        
        // Periodic status log
        if (s_sendCallCount % 10 == 1) {
            LOG("[UDP-TUNNEL-STATUS] sendCall=%d, socket=%d, weAreHost=%d, peerRegistered=%d, lastRecvIP=0x%08X",
                s_sendCallCount, (int)g_udpTunnelSocket, g_weAreHost ? 1 : 0, 
                g_hostPeerRegistered ? 1 : 0, g_lastRecvIP);
        }
        
        // Build packet: [len][port][ip][payload]
        char packet[4096 + 10];
        int packetLen = 2 + 4 + payloadLen;  // port + ip + payload
        
        if (packetLen > sizeof(packet) - 4) {
            LOG("[UDP-TUNNEL] Packet too large: %d", payloadLen);
            return -1;
        }
        
        // Write length (LE)
        *reinterpret_cast<uint32_t*>(packet) = packetLen;
        
        // Write dest port (BE)
        packet[4] = (destPort >> 8) & 0xFF;
        packet[5] = destPort & 0xFF;
        
        // Write dest IP (network byte order already)
        memcpy(packet + 6, &destIP, 4);
        
        // Write payload
        memcpy(packet + 10, payload, payloadLen);
        
        // Send
        int totalLen = 4 + packetLen;
        int sent = send(g_udpTunnelSocket, packet, totalLen, 0);
        
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK) {
                LOG("[UDP-TUNNEL] Send failed: %d", err);
                closesocket(g_udpTunnelSocket);
                g_udpTunnelSocket = INVALID_SOCKET;
                return -1;
            }
            return 0; // Would block
        }
        
        char destIPStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &destIP, destIPStr, sizeof(destIPStr));
        LOG("[UDP-TUNNEL] Sent %d bytes (dest=%s:%d)", payloadLen, destIPStr, destPort);
        
        return payloadLen;
    }
    
    // Receive UDP packet from TCP tunnel (non-blocking)
    // Returns true if packet received
    inline bool RecvUdpFromTunnel(uint16_t* srcPort, uint32_t* srcIP, char* payload, int* payloadLen, int maxLen) {
        // Safety check - critical section must be initialized
        if (!g_udpTunnelCSInitialized) {
            return false;
        }
        
        // First check queue
        EnterCriticalSection(&g_udpTunnelCS);
        
        if (g_udpTunnelQueueCount > 0) {
            UdpTunnelPacket& pkt = g_udpTunnelQueue[g_udpTunnelQueueTail];
            
            *srcPort = pkt.srcPort;
            *srcIP = pkt.srcIP;
            int copyLen = (pkt.payloadLen < maxLen) ? pkt.payloadLen : maxLen;
            memcpy(payload, pkt.payload, copyLen);
            *payloadLen = copyLen;
            
            g_udpTunnelQueueTail = (g_udpTunnelQueueTail + 1) % UDP_TUNNEL_QUEUE_SIZE;
            g_udpTunnelQueueCount--;
            
            LeaveCriticalSection(&g_udpTunnelCS);
            return true;
        }
        
        LeaveCriticalSection(&g_udpTunnelCS);
        
        // No queued packets, try to receive from socket
        if (g_udpTunnelSocket == INVALID_SOCKET) {
            return false;
        }
        
        // Receive header first (4 bytes length)
        static char s_recvBuffer[8192];
        static int s_recvBufferLen = 0;
        static DWORD s_lastRecvLog = 0;
        static int s_recvAttempts = 0;
        
        s_recvAttempts++;
        
        // Non-blocking receive
        int received = recv(g_udpTunnelSocket, s_recvBuffer + s_recvBufferLen, 
                           sizeof(s_recvBuffer) - s_recvBufferLen, 0);
        
        // Periodic status log
        DWORD now = GetTickCount();
        if (now - s_lastRecvLog >= 3000) {
            s_lastRecvLog = now;
            
            // Check socket state
            int sockErr = 0;
            int sockErrLen = sizeof(sockErr);
            getsockopt(g_udpTunnelSocket, SOL_SOCKET, SO_ERROR, (char*)&sockErr, &sockErrLen);
            
            LOG("[UDP-TUNNEL-DEBUG] recv status: socket=%d, bufLen=%d, attempts=%d, lastRecv=%d, sockErr=%d, weHost=%d",
                (int)g_udpTunnelSocket, s_recvBufferLen, s_recvAttempts, received, sockErr, g_weAreHost ? 1 : 0);
        }
        
        if (received > 0) {
            s_recvBufferLen += received;
            LOG("[UDP-TUNNEL-DEBUG] Received %d raw bytes from TCP, buffer now %d bytes", 
                received, s_recvBufferLen);
        } else if (received == 0) {
            // Connection closed by server - try to reconnect
            LOG("[UDP-TUNNEL] Connection closed by server, will reconnect on next send");
            closesocket(g_udpTunnelSocket);
            g_udpTunnelSocket = INVALID_SOCKET;
            // Don't return false - let the game continue, we'll reconnect on next send
        } else {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != 0) {
                LOG("[UDP-TUNNEL] Recv error: %d, will reconnect on next send", err);
                closesocket(g_udpTunnelSocket);
                g_udpTunnelSocket = INVALID_SOCKET;
            }
            // WSAEWOULDBLOCK (10035) or 0 is normal for non-blocking socket - no data available
        }
        
        // Process complete packets
        while (s_recvBufferLen >= 4) {
            uint32_t packetLen = *reinterpret_cast<uint32_t*>(s_recvBuffer);
            
            // Sanity check
            if (packetLen < 6 || packetLen > 65535) {
                LOG("[UDP-TUNNEL] Invalid packet length %u, resetting buffer", packetLen);
                s_recvBufferLen = 0;
                break;
            }
            
            // Wait for complete packet
            if (s_recvBufferLen < (int)(4 + packetLen)) {
                break;
            }
            
            // Parse packet
            uint16_t pktSrcPort = (static_cast<uint8_t>(s_recvBuffer[4]) << 8) | static_cast<uint8_t>(s_recvBuffer[5]);
            uint32_t pktSrcIP;
            memcpy(&pktSrcIP, s_recvBuffer + 6, 4);
            int pktPayloadLen = packetLen - 6;
            
            // Add to queue
            EnterCriticalSection(&g_udpTunnelCS);
            
            if (g_udpTunnelQueueCount < UDP_TUNNEL_QUEUE_SIZE) {
                UdpTunnelPacket& pkt = g_udpTunnelQueue[g_udpTunnelQueueHead];
                pkt.srcPort = pktSrcPort;
                pkt.srcIP = pktSrcIP;
                pkt.payloadLen = (pktPayloadLen < (int)sizeof(pkt.payload)) ? pktPayloadLen : sizeof(pkt.payload);
                memcpy(pkt.payload, s_recvBuffer + 10, pkt.payloadLen);
                
                g_udpTunnelQueueHead = (g_udpTunnelQueueHead + 1) % UDP_TUNNEL_QUEUE_SIZE;
                g_udpTunnelQueueCount++;
                
                char srcIPStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &pktSrcIP, srcIPStr, sizeof(srcIPStr));
                LOG("[UDP-TUNNEL] Received %d bytes (src=%s:%d), queue=%d", 
                    pktPayloadLen, srcIPStr, pktSrcPort, g_udpTunnelQueueCount);
            } else {
                LOG("[UDP-TUNNEL] Queue full, dropping packet");
            }
            
            LeaveCriticalSection(&g_udpTunnelCS);
            
            // Shift buffer
            memmove(s_recvBuffer, s_recvBuffer + 4 + packetLen, s_recvBufferLen - 4 - packetLen);
            s_recvBufferLen -= (4 + packetLen);
        }
        
        // Try to return one packet from queue
        EnterCriticalSection(&g_udpTunnelCS);
        
        if (g_udpTunnelQueueCount > 0) {
            UdpTunnelPacket& pkt = g_udpTunnelQueue[g_udpTunnelQueueTail];
            
            *srcPort = pkt.srcPort;
            *srcIP = pkt.srcIP;
            int copyLen = (pkt.payloadLen < maxLen) ? pkt.payloadLen : maxLen;
            memcpy(payload, pkt.payload, copyLen);
            *payloadLen = copyLen;
            
            g_udpTunnelQueueTail = (g_udpTunnelQueueTail + 1) % UDP_TUNNEL_QUEUE_SIZE;
            g_udpTunnelQueueCount--;
            
            LeaveCriticalSection(&g_udpTunnelCS);
            return true;
        }
        
        LeaveCriticalSection(&g_udpTunnelCS);
        return false;
    }
    
    // Close UDP tunnel
    inline void CloseUdpTunnel() {
        g_udpTunnelRunning = false;
        
        if (g_udpTunnelThread) {
            WaitForSingleObject(g_udpTunnelThread, 1000);
            CloseHandle(g_udpTunnelThread);
            g_udpTunnelThread = NULL;
        }
        
        if (g_udpTunnelSocket != INVALID_SOCKET) {
            closesocket(g_udpTunnelSocket);
            g_udpTunnelSocket = INVALID_SOCKET;
        }
        
        if (g_udpTunnelCSInitialized) {
            DeleteCriticalSection(&g_udpTunnelCS);
            g_udpTunnelCSInitialized = false;
        }
        
        LOG("[UDP-TUNNEL] Closed");
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
    // IAT hook for recvfrom() - DIAGNOSTIC ONLY
    // This hook is for debugging - it logs recvfrom calls but does NOT
    // modify data. The actual relay header processing is done in Hook_GameRecv.
    // ========================================================================
    inline int g_recvfromCallCount = 0;
    inline int g_recvfromSuccessCount = 0;
    
    inline int WSAAPI Hook_Recvfrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromlen) {
        // Call original first
        int result = SOCKET_ERROR;
        if (g_origRecvfrom) {
            result = g_origRecvfrom(s, buf, len, flags, from, fromlen);
        }
        
        g_recvfromCallCount++;
        
        // Log ALL successful UDP receives - this is critical for debugging!
        if (from && result > 0) {
            g_recvfromSuccessCount++;
            sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
            char srcIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &srcAddr->sin_addr, srcIP, sizeof(srcIP));
            
            // Log first bytes as hex
            char hexBuf[64] = {0};
            int hexLen = 0;
            int dumpLen = (result < 16) ? result : 16;
            for (int i = 0; i < dumpLen && hexLen < 60; i++) {
                hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
            }
            
            // ALWAYS LOG successful UDP receives!
            LOG("[IAT-RECVFROM] *** SUCCESS #%d ***: socket=%d, from=%s:%d, len=%d, hex=%s",
                g_recvfromSuccessCount, (int)s, srcIP, ntohs(srcAddr->sin_port), result, hexBuf);
        }
        // Log periodically even if no data
        else if (g_recvfromCallCount <= 10 || g_recvfromCallCount % 1000 == 0) {
            int err = (result < 0) ? WSAGetLastError() : 0;
            LOG("[IAT-RECVFROM] #%d: socket=%d, result=%d, err=%d, from=%p, g_gameSocket=%d",
                g_recvfromCallCount, (int)s, result, err, from, (int)g_gameSocket);
        }
        
        return result;
    }
    
    // ========================================================================
    // IAT hook for sendto() - diagnose UDP send
    // ========================================================================
    inline int g_sendtoCallCount = 0;
    
    inline int WSAAPI Hook_Sendto(SOCKET s, const char* buf, int len, int flags, const struct sockaddr* to, int tolen) {
        g_sendtoCallCount++;
        
        // Log destination
        if (to) {
            const sockaddr_in* destAddr = reinterpret_cast<const sockaddr_in*>(to);
            char destIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &destAddr->sin_addr, destIP, sizeof(destIP));
            
            // Log first 10 calls
            if (g_sendtoCallCount <= 10 || g_sendtoCallCount % 100 == 0) {
                LOG("[IAT-SENDTO] #%d: socket=%d, to=%s:%d, len=%d",
                    g_sendtoCallCount, (int)s, destIP, ntohs(destAddr->sin_port), len);
            }
        }
        
        // Call original
        if (g_origSendto) {
            return g_origSendto(s, buf, len, flags, to, tolen);
        }
        return SOCKET_ERROR;
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
    inline Trampoline g_tramp74A380 = {};  // Bind wrapper
    inline Trampoline g_tramp58C420 = {};  // HELLO handler (sub_58C420)
    inline Trampoline g_tramp58F020 = {};  // Packet dispatcher (sub_58F020)
    inline Trampoline g_tramp585E80 = {};  // CAR_DATA accumulator (sub_585E80)
    inline Trampoline g_tramp587DB0 = {};  // CAR_DATA generator (sub_587DB0)
    inline Trampoline g_tramp588350 = {};  // Send to all peers except one (sub_588350)
    inline Trampoline g_tramp586120 = {};  // Send to specific peer (sub_586120)
    inline Trampoline g_tramp5883A0 = {};  // Send to ALL peers (sub_5883A0)
    inline Trampoline g_tramp58C690 = {};  // Type 12 state sync handler (sub_58C690)
    inline Trampoline g_tramp58C620 = {};  // Peer disconnect/timeout handler (sub_58C620)
    inline Trampoline g_tramp58F690 = {};  // Network tick - CRITICAL for tunnel packet pumping
    
    // ========================================================================
    // Manual peer registration for relay mode
    // In relay mode, the game doesn't create UDP connections to peers naturally.
    // We need to manually register the host as a peer so CAR_DATA can be sent.
    // ========================================================================
    
    // ========================================================================
    // CRITICAL GAME STRUCTURES for peer registration:
    //
    // 1. Connection array at dword_8691D0 (5 slots, 20 bytes each):
    //    [0] = state (0=empty, 1=init, 2=ready, 3=active, 4=closing)
    //    [1] = peer index (-1 = empty)
    //    [2] = unknown
    //    [3] = connection struct pointer (REQUIRED for sub_585810!)
    //    [4] = timeout?
    //    End address: 0x869234
    //
    // 2. Peer array at dword_8693C8 (5 slots, 32 bytes each):
    //    [0] = peer struct pointer (from sub_586010)
    //    [1] = peer index (-1 = empty)
    //    [4] = state (>=3 means ready for sending in sub_588350)
    //    End address: 0x869468
    //
    // sub_588350 iterates peer array and calls sub_586120 for each valid peer.
    // sub_586120 calls sub_585810 which looks up peer index in CONNECTION array!
    // If not found, it crashes trying to dereference NULL+12.
    // ========================================================================
    
    inline bool g_peerRegistered = false;
    inline int g_registeredPeerIndex = -1;
    
    // Create a minimal connection structure for sending data
    // Based on sub_5834E0 which creates real connection structures
    inline int CreateMinimalConnectionStruct() {
        // CRITICAL FIX: Return 0 (NULL) instead of invalid pointer!
        // 
        // Previous code returned *(int*)0x7FBE80 which is 0xFFFFFFFF on joiner
        // This caused crash in sub_585880 -> sub_748650(0xFFFFFFFF)
        //
        // With NULL, the cleanup code in sub_585880 will skip the sub_748650 call:
        //   v4 = v3[3];  // connPtr - will be 0
        //   if ( v4 )    // false, skips crash-causing call
        //       sub_748650(v4);
        //
        return 0;  // NULL is safe - cleanup code checks for it
    }
    
    inline bool RegisterHostAsPeer(int peerIndex = 0) {
        if (g_peerRegistered) {
            return true;  // Already registered
        }
        
        LOG("[PEER-REG] === Starting host registration as peer %d ===", peerIndex);
        
        // ---------------------------------------------------------------
        // Step 1: Register in CONNECTION array (dword_8691D0)
        // This is REQUIRED for sub_585810 to find the peer!
        // ---------------------------------------------------------------
        int* connArray = (int*)0x8691D0;
        const int* connArrayEnd = (int*)0x869234;
        
        // Check if peer already in connection array
        int* connSlot = connArray;
        int connSlotNum = 0;
        bool foundInConn = false;
        while (connSlot < connArrayEnd) {
            if (connSlot[1] == peerIndex) {
                LOG("[PEER-REG] Peer %d already in connection array slot %d (state=%d)", 
                    peerIndex, connSlotNum, connSlot[0]);
                foundInConn = true;
                break;
            }
            connSlot += 5;  // 20 bytes per slot
            connSlotNum++;
        }
        
        if (!foundInConn) {
            // Find empty slot in connection array
            connSlot = connArray;
            connSlotNum = 0;
            while (connSlot < connArrayEnd) {
                if (connSlot[0] == 0 || connSlot[1] == -1) {  // empty or invalid
                    // Create minimal connection struct
                    int connStruct = CreateMinimalConnectionStruct();
                    
                    LOG("[PEER-REG] Adding peer %d to connection array slot %d", peerIndex, connSlotNum);
                    LOG("[PEER-REG] Using connection struct: 0x%08X", connStruct);
                    
                    // Fill connection slot
                    connSlot[0] = 3;           // state = 3 (active)
                    connSlot[1] = peerIndex;   // peer index
                    connSlot[2] = 0;           // unknown
                    connSlot[3] = connStruct;  // connection struct pointer (CRITICAL!)
                    connSlot[4] = 0;           // timeout
                    
                    LOG("[PEER-REG] Connection slot filled: state=%d, idx=%d, struct=0x%08X",
                        connSlot[0], connSlot[1], connSlot[3]);
                    break;
                }
                connSlot += 5;
                connSlotNum++;
            }
            
            if (connSlot >= connArrayEnd) {
                LOG("[PEER-REG] ERROR: No empty connection slots!");
                return false;
            }
        }
        
        // ---------------------------------------------------------------
        // Step 2: Register in PEER array (dword_8693C8)
        // This is used by sub_588350 to iterate over peers for sending
        // ---------------------------------------------------------------
        int* peerArray = (int*)0x8693C8;
        const int* peerArrayEnd = (int*)0x869468;
        
        // Check if already in peer array
        int* peerSlot = peerArray;
        int peerSlotNum = 0;
        while (peerSlot < peerArrayEnd) {
            if (peerSlot[1] == peerIndex) {
                LOG("[PEER-REG] Peer %d already in peer array slot %d", peerIndex, peerSlotNum);
                g_peerRegistered = true;
                g_registeredPeerIndex = peerIndex;
                return true;
            }
            peerSlot += 8;  // 32 bytes per slot
            peerSlotNum++;
        }
        
        // Find empty slot in peer array
        peerSlot = peerArray;
        peerSlotNum = 0;
        while (peerSlot < peerArrayEnd) {
            if (peerSlot[1] == -1) {
                // Generate unique peer struct
                typedef int(__cdecl* GenPeerId_t)();
                GenPeerId_t genPeerId = (GenPeerId_t)0x586010;
                int newPeerStruct = genPeerId();
                
                LOG("[PEER-REG] Adding peer %d to peer array slot %d", peerIndex, peerSlotNum);
                LOG("[PEER-REG] Generated peer struct: 0x%08X", newPeerStruct);
                
                // Fill peer slot
                peerSlot[0] = newPeerStruct;  // peer struct pointer
                peerSlot[1] = peerIndex;      // peer index
                peerSlot[2] = 0;              // unknown
                peerSlot[3] = 0;              // unknown
                peerSlot[4] = 3;              // state >= 3 for sending
                peerSlot[5] = 0;              // unknown
                peerSlot[6] = 0;              // float?
                peerSlot[7] = 0;              // unknown
                
                LOG("[PEER-REG] Peer slot filled: struct=0x%08X, idx=%d, state=%d",
                    peerSlot[0], peerSlot[1], peerSlot[4]);
                break;
            }
            peerSlot += 8;
            peerSlotNum++;
        }
        
        if (peerSlot >= peerArrayEnd) {
            LOG("[PEER-REG] ERROR: No empty peer slots!");
            return false;
        }
        
        g_peerRegistered = true;
        g_registeredPeerIndex = peerIndex;
        
        LOG("[PEER-REG] === Host registration complete! ===");
        return true;
    }
    
    // Dump both arrays for debugging
    inline void DumpPeerArray() {
        LOG("[PEER-DUMP] === Connection array (dword_8691D0) ===");
        int* connArray = (int*)0x8691D0;
        for (int i = 0; i < 5; i++) {
            int* slot = connArray + i * 5;
            LOG("[PEER-DUMP]   Conn slot %d: state=%d, idx=%d, connPtr=0x%08X", 
                i, slot[0], slot[1], slot[3]);
        }
        
        LOG("[PEER-DUMP] === Peer array (dword_8693C8) ===");
        int* peerArray = (int*)0x8693C8;
        for (int i = 0; i < 5; i++) {
            int* slot = peerArray + i * 8;
            LOG("[PEER-DUMP]   Peer slot %d: struct=0x%08X, idx=%d, state=%d", 
                i, slot[0], slot[1], slot[4]);
        }
        
        // Also show important globals
        LOG("[PEER-DUMP] Globals: dword_7FBE80=0x%08X, dword_864FAC=%d",
            *(int*)0x7FBE80, *(int*)0x864FAC);
    }
    
    // ========================================================================
    // Hook for sub_587DB0 - CAR_DATA packet generator
    // This creates CAR_DATA packets from player's car data buffer.
    // Called after receiving peer's CAR_DATA to send ours back.
    //
    // MODIFIED: After packets are generated, send them through UDP tunnel!
    // This bypasses the broken connection array mechanism on joiner.
    // ========================================================================
    inline uint8_t __cdecl Hook_587DB0(uint8_t packetType, int carDataBuffer, int outputList) {
        static int s_carGenCalls = 0;
        s_carGenCalls++;
        LOG("[CAR-GEN] =====================================================");
        LOG("[CAR-GEN] sub_587DB0 CALLED #%d! type=%d, carDataBuf=0x%08X, outList=0x%08X", 
            s_carGenCalls, packetType, carDataBuffer, outputList);
        LOG("[CAR-GEN] weAreHost=%d, peerIP=0x%08X, peerPort=%d, tunnelSocket=%d",
            g_weAreHost ? 1 : 0, g_lastRecvIP, g_lastRecvPort, (int)g_udpTunnelSocket);
        LOG("[CAR-GEN] =====================================================");
        
        // Check if car data buffer has valid data
        int carDataSize = 0;
        if (carDataBuffer) {
            carDataSize = *(int*)(carDataBuffer + 1024);  // offset 0x400 = data size
            LOG("[CAR-GEN] Car data buffer size: %d bytes", carDataSize);
            
            if (carDataSize < 8) {
                LOG("[CAR-GEN] *** WARNING: Car data too small (%d bytes) - car not loaded! ***", carDataSize);
            }
        }
        
        typedef uint8_t(__cdecl* OrigFunc_t)(uint8_t, int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp587DB0.code[0]);
        
        uint8_t result = 0;
        __try {
            result = origFunc(packetType, carDataBuffer, outputList);
            LOG("[CAR-GEN] sub_587DB0 returned %d packets", result);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[CAR-GEN] *** EXCEPTION in sub_587DB0! ***");
            return 0;
        }
        
        // If packets were generated and we have host address, send them through tunnel!
        // outputList is a linked list structure:
        //   outputList[0] = pointer to first node (or self if empty)
        //   outputList[1] = pointer to last node (or self if empty)
        // Each node:
        //   node[0] = next pointer
        //   node[1] = prev pointer
        //   node[2] = 0 ?
        //   node[3...] = packet data starts here
        //     +0 (node[3]) = part number (byte)
        //     +1 (node[3]+1) = total parts (byte) 
        //     +2-3 = data size (word)
        //     +4... = actual data
        // Actually based on sub_587DB0:
        //   v10 = malloc(0x418) = 1048 bytes
        //   v10[259] = next, v10[260] = prev
        //   v10+8 = part number, v10+9 = total parts, v10+10 = size (word)
        //   v10+12 = data
        // So the structure is different - data starts at offset 8 from node pointer
        
        // Check conditions for sending
        LOG("[CAR-GEN] >>> Check send conditions: result=%d, tunnel=%d, hostIP=0x%08X, outList=0x%08X, alreadySent=%d%d%d%d",
            result, (g_udpTunnelSocket != INVALID_SOCKET ? 1 : 0), g_lastRecvIP, outputList,
            g_sentCarDataTypes[0] ? 1 : 0, g_sentCarDataTypes[1] ? 1 : 0, 
            g_sentCarDataTypes[2] ? 1 : 0, g_sentCarDataTypes[3] ? 1 : 0);
        
        // CRITICAL: Don't send CAR_DATA if we already sent all 4 parts!
        // This prevents re-sending when receiving peer's CAR_DATA response.
        bool alreadySentAll = g_sentCarDataTypes[0] && g_sentCarDataTypes[1] && 
                              g_sentCarDataTypes[2] && g_sentCarDataTypes[3];
        
        if (result > 0 && g_udpTunnelSocket != INVALID_SOCKET && g_lastRecvIP != 0 && outputList && !alreadySentAll) {
            LOG("[CAR-GEN] >>> Sending %d generated CAR_DATA packets through tunnel...", result);
            
            // outputList[0] points to first node, outputList[1] points to &outputList[0]
            int* listPtr = (int*)outputList;
            int firstNode = listPtr[0];
            int listEnd = (int)listPtr;  // list ends when we reach back to listPtr
            
            LOG("[CAR-GEN] >>> List: first=0x%08X, end=0x%08X", firstNode, listEnd);
            
            int sentCount = 0;
            int currentNode = firstNode;
            
            while (currentNode != listEnd && currentNode != 0 && sentCount < 10) {
                int* node = (int*)currentNode;
                
                // Get packet info from node
                // Based on sub_587DB0 allocation:
                // node is 0x418 bytes allocated (1048 bytes)
                // node+8 = part# (byte), node+9 = totalParts (byte), node+10 = size (word)
                // node+12 = bitstream encoded data
                uint8_t* nodeBytes = (uint8_t*)node;
                uint8_t partNum = nodeBytes[8];
                uint8_t totalParts = nodeBytes[9];
                uint16_t rawDataSize = *(uint16_t*)(nodeBytes + 10);  // 760 for full chunks
                
                LOG("[CAR-GEN] >>> Node 0x%08X: part=%d/%d, rawSize=%d", 
                    currentNode, partNum, totalParts, rawDataSize);
                
                // Dump first 32 bytes starting from node+8 to see structure
                char structHex[128];
                int structLen = 0;
                for (int i = 0; i < 32 && structLen < 120; i++) {
                    structLen += sprintf(structHex + structLen, "%02X ", nodeBytes[8 + i]);
                }
                LOG("[CAR-GEN] >>> Node+8 data: %s", structHex);
                
                // Build CAR_DATA packet (type 102-105 based on part number)
                // 
                // BITSTREAM STRUCTURE at node+12 (written by sub_587DB0 using sub_581D00):
                //   byte 0: packetType (arg0 to sub_587DB0, always 1 for CAR_DATA exchange)
                //   byte 1: partNum (1-4)
                //   byte 2: totalParts (4)
                //   bytes 3-4: dataSize in BIG ENDIAN (0x02 0xF8 = 760)
                //   bytes 5+: actual encoded car data
                //
                // Real packet format (as seen from host):
                // [type:4 LE][sessionId:4 LE][bitstream data from node+12...]
                // Total: 109 bytes for parts 1-3, 103 bytes for part 4
                //
                if (partNum >= 1 && partNum <= totalParts && totalParts >= 1 && totalParts <= 5) {
                    uint8_t pktType = 101 + partNum;  // 102, 103, 104, 105
                    
                    // Determine bitstream data size
                    // From host packets: parts 1-3 are 109 bytes total, part 4 is 103 bytes
                    // After 8-byte header (type+sessionId): 101 bytes for 1-3, 95 bytes for last part
                    // This is the bitstream content including packetType, partNum, totalParts, dataSize, and data
                    int bitstreamSize = (partNum < totalParts) ? 101 : 95;
                    int totalPacketSize = 8 + bitstreamSize;  // 109 or 103
                    
                    // Build packet
                    uint8_t packetBuf[256];
                    memset(packetBuf, 0, sizeof(packetBuf));
                    
                    // Header: [type:4 LE][sessionId:4 LE]
                    packetBuf[0] = pktType;
                    packetBuf[1] = 0;
                    packetBuf[2] = 0;
                    packetBuf[3] = 0;
                    // Session ID (use same as received - 0x64 = 100)
                    packetBuf[4] = 0x64;
                    packetBuf[5] = 0;
                    packetBuf[6] = 0;
                    packetBuf[7] = 0;
                    
                    // Copy bitstream data directly from node+12
                    // This includes: packetType(1), partNum(1), totalParts(1), dataSize(2), data(...)
                    memcpy(packetBuf + 8, nodeBytes + 12, bitstreamSize);
                    
                    // Dump packet for debugging
                    char hexBuf[256];
                    int hexLen = 0;
                    for (int i = 0; i < 40 && i < totalPacketSize && hexLen < 250; i++) {
                        hexLen += sprintf(hexBuf + hexLen, "%02X ", packetBuf[i]);
                    }
                    LOG("[CAR-GEN] >>> Built packet %d: type=%d, size=%d", partNum, pktType, totalPacketSize);
                    LOG("[CAR-GEN] >>> HEX: %s", hexBuf);
                    
                    // Send through UDP tunnel using existing SendUdpViaTunnel function
                    // This ensures consistent format with other tunnel sends
                    int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, 
                                                reinterpret_cast<char*>(packetBuf), totalPacketSize);
                    if (sent > 0) {
                        char ipStr[20];
                        inet_ntop(AF_INET, &g_lastRecvIP, ipStr, sizeof(ipStr));
                        LOG("[CAR-GEN] >>> SENT CAR_DATA_%d (%d bytes) to %s:%d via tunnel!", 
                            partNum, totalPacketSize, ipStr, g_lastRecvPort);
                        if (partNum >= 1 && partNum <= 4) {
                            g_sentCarDataTypes[partNum - 1] = true;
                        }
                        g_sentCarData = true;
                        sentCount++;
                    } else {
                        LOG("[CAR-GEN] >>> FAILED to send via tunnel! result=%d", sent);
                    }
                } else {
                    LOG("[CAR-GEN] >>> Skipping: partNum=%d, totalParts=%d (invalid)", partNum, totalParts);
                }
                
                // Move to next node
                currentNode = node[0];  // node[0] = next pointer
            }
            
            LOG("[CAR-GEN] >>> Sent %d CAR_DATA packets through tunnel", sentCount);
            
            // CRITICAL: After sending CAR_DATA, we must send READY to complete handshake!
            // In original P2P flow: HELLO -> CAR_DATA exchange -> READY from both sides
            // Joiner's READY was suppressed earlier (waiting for CAR_DATA), now we send it
            if (sentCount >= 4 && g_sentCarDataTypes[0] && g_sentCarDataTypes[1] && 
                g_sentCarDataTypes[2] && g_sentCarDataTypes[3]) {
                LOG("[CAR-GEN] >>> All CAR_DATA sent! Now sending READY to host...");
                
                // Build READY packet: [type:4][padding:4] = [3, 0, 0, 0, 0, 0, 0, 0]
                uint8_t readyPacket[8] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                
                int readySent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, 
                                                  reinterpret_cast<char*>(readyPacket), 8);
                if (readySent > 0) {
                    char ipStr[20];
                    inet_ntop(AF_INET, &g_lastRecvIP, ipStr, sizeof(ipStr));
                    LOG("[CAR-GEN] >>> SENT READY to %s:%d via tunnel!", ipStr, g_lastRecvPort);
                } else {
                    LOG("[CAR-GEN] >>> FAILED to send READY! result=%d", readySent);
                }
            }
        } else if (result > 0) {
            // Packets were generated but couldn't send - log why
            if (alreadySentAll) {
                LOG("[CAR-GEN] >>> SKIPPED: Already sent all 4 CAR_DATA parts (no duplicate send)");
            } else if (g_udpTunnelSocket == INVALID_SOCKET) {
                LOG("[CAR-GEN] >>> Cannot send: UDP tunnel not connected");
            } else if (g_lastRecvIP == 0) {
                LOG("[CAR-GEN] >>> Cannot send: Host IP not known yet (waiting for first packet from host)");
            } else if (!outputList) {
                LOG("[CAR-GEN] >>> Cannot send: outputList is NULL");
            }
        }
        
        return result;
    }
    
    // ========================================================================
    // Hook for sub_5883A0 - Send packet to ALL peers (no exclusion)
    // This is used for type 12 (state sync), type 13 (session state), etc.
    // 
    // CRITICAL: On joiner without registered peer, peer array is empty!
    // The loop does 0 iterations and nothing is sent. We MUST send via tunnel!
    // ========================================================================
    inline int __cdecl Hook_5883A0(char packetType, int data, int flag) {
        static int s_hookCalls = 0;
        s_hookCalls++;
        
        LOG("[SEND-ALL] sub_5883A0 CALLED #%d! pktType=%d, data=0x%08X, flag=%d",
            s_hookCalls, (int)packetType, data, flag);
        
        // Call original function first
        typedef int(__cdecl* OrigFunc_t)(char, int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp5883A0.code[0]);
        
        int result = 0;
        __try {
            result = origFunc(packetType, data, flag);
            LOG("[SEND-ALL] sub_5883A0 returned %d", result);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[SEND-ALL] *** EXCEPTION in sub_5883A0! ***");
            result = -1;
        }
        
        // CRITICAL: Both HOST and JOINER must send through tunnel!
        // Original function tries to use direct UDP which doesn't work through NAT.
        // result == -1 means original function failed to send.
        if (g_udpTunnelSocket != INVALID_SOCKET && g_lastRecvIP != 0) {
            bool shouldTunnel = false;
            int tunnelDataSize = 8;
            
            switch (packetType) {
                case 1:  // HELLO/CAR_DATA  
                case 3:  // READY
                case 8:  // Heartbeat
                case 10: // Sync state  
                case 12: // State sync - CRITICAL for race start!
                case 13: // Session state
                case 14: // Unknown
                case 15: // Unknown
                case 16: // Unknown
                case 17: // Unknown
                    shouldTunnel = true;
                    tunnelDataSize = 8;
                    break;
            }
            
            if (shouldTunnel) {
                char peerIPStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &g_lastRecvIP, peerIPStr, sizeof(peerIPStr));
                LOG("[SEND-ALL] >>> Sending TYPE %d via tunnel to %s:%d (%s mode)", 
                    packetType, peerIPStr, g_lastRecvPort, g_weAreHost ? "HOST" : "joiner");
                
                // Build sync packet
                uint8_t syncPacket[64];
                memset(syncPacket, 0, sizeof(syncPacket));
                
                // Packet format: [type:4][sessionId:4][payload...]
                syncPacket[0] = (uint8_t)packetType;
                syncPacket[1] = 0;
                syncPacket[2] = 0;
                syncPacket[3] = 0;
                // Session ID (use 100 = 0x64)
                syncPacket[4] = 0x64;
                syncPacket[5] = 0;
                syncPacket[6] = 0;
                syncPacket[7] = 0;
                
                // For type 12 (state sync), include our state value
                if (packetType == 12) {
                    // Read actual session state from game memory
                    int ourState = *(int*)0x866A14;
                    if (ourState < 3) ourState = 3;  // Minimum state 3 for ready
                    syncPacket[8] = ourState & 0xFF;
                    syncPacket[9] = (ourState >> 8) & 0xFF;
                    syncPacket[10] = (ourState >> 16) & 0xFF;
                    syncPacket[11] = (ourState >> 24) & 0xFF;
                    tunnelDataSize = 12;
                    LOG("[SEND-ALL] >>> Type 12 state sync: sending state=%d", ourState);
                }
                
                // CRITICAL FIX: For type 13 (session state), also include state!
                // Otherwise joiner receives [type:4][sessionId:4] without actual state value.
                // Use same format as SEND-PEER: [type:4][state:4][padding:4] for consistency.
                if (packetType == 13) {
                    int ourState = *(int*)0x866A14;
                    if (ourState < 3) ourState = 3;
                    // Reformat: [type:4][state:4][padding:4] (not [type:4][sessionId:4])
                    syncPacket[4] = ourState & 0xFF;  // state instead of sessionId
                    syncPacket[5] = (ourState >> 8) & 0xFF;
                    syncPacket[6] = (ourState >> 16) & 0xFF;
                    syncPacket[7] = (ourState >> 24) & 0xFF;
                    syncPacket[8] = 0;  // padding
                    syncPacket[9] = 0;
                    syncPacket[10] = 0;
                    syncPacket[11] = 0;
                    tunnelDataSize = 12;
                    LOG("[SEND-ALL] >>> Type 13 session state: sending state=%d", ourState);
                }
                
                int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, (char*)syncPacket, tunnelDataSize);
                if (sent > 0) {
                    LOG("[SEND-ALL] >>> Sent type %d (%d bytes) via tunnel!", packetType, tunnelDataSize);
                    result = tunnelDataSize;
                } else {
                    LOG("[SEND-ALL] >>> Failed to send type %d via tunnel", packetType);
                }
            }
            
            // CRITICAL FIX: JOINER ONLY must send type 12 state=3 to host periodically!
            // The game doesn't call sub_5883A0 with type 12 on joiner side,
            // but host needs type 12 from joiner to know joiner is ready (state >= 3).
            // Without this, host's sub_58EBC0 won't transition to state 2 and race won't start!
            //
            // Send type 12 every time we send type 8 heartbeat (JOINER ONLY!)
            if (!g_weAreHost) {
                static DWORD s_lastType12Send = 0;
                static int s_type12Counter = 0;
                DWORD now = GetTickCount();
                
                if (packetType == 8 && (now - s_lastType12Send) >= 300) {  // Every 300ms when sending heartbeat
                    s_lastType12Send = now;
                    s_type12Counter++;
                    
                    // Build type 12 state sync packet
                    uint8_t type12Packet[12];
                    memset(type12Packet, 0, sizeof(type12Packet));
                    
                    type12Packet[0] = 12;  // type = 12
                    type12Packet[1] = 0;
                    type12Packet[2] = 0;
                    type12Packet[3] = 0;
                    
                    type12Packet[4] = 0x64;  // session ID = 100
                    type12Packet[5] = 0;
                    type12Packet[6] = 0;
                    type12Packet[7] = 0;
                    
                    // Read our game state from dword_8669F4 to send actual state
                    int ourGameState = *(int*)0x8669F4;
                    // If game state >= 3, we're ready. Send state 3 to be safe.
                    int sendState = (ourGameState >= 3) ? ourGameState : 3;
                    
                    type12Packet[8] = sendState & 0xFF;
                    type12Packet[9] = (sendState >> 8) & 0xFF;
                    type12Packet[10] = (sendState >> 16) & 0xFF;
                    type12Packet[11] = (sendState >> 24) & 0xFF;
                    
                    int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, (char*)type12Packet, 12);
                    if (sent > 0) {
                        LOG("[SEND-ALL] >>> JOINER sent TYPE 12 state=%d to host (#%d)", sendState, s_type12Counter);
                    }
                }
            }
        }
        
        return result;
    }
    
    // ========================================================================
    // Hook for sub_588350 - Send packet to all peers EXCEPT one
    // MODIFIED: If no peers in array, send directly through UDP tunnel!
    // 
    // Original function iterates peer array (0x8693C8) and calls sub_586120
    // for each valid peer. But on joiner, peer array is empty!
    // 
    // We intercept and send CAR_DATA (type 1) through tunnel ourselves.
    // ========================================================================
    inline int __cdecl Hook_588350(int excludePeer, int packetType, int data, int flag) {
        static int s_hookCalls = 0;
        s_hookCalls++;
        
        // Read packet data to understand what we're sending
        // data points to a structure where +0 contains actual packet data
        // Based on sub_58C420: sub_588350(a2, 1, (int)(v9 + 3), 1)
        // v9 is a list node, v9+3 is the data pointer (offset 12)
        
        int dataSize = 0;
        uint8_t* packetData = nullptr;
        uint8_t firstByte = 0;
        
        if (data) {
            // In the linked list structure:
            // [0] = next pointer
            // [1] = prev pointer
            // [2] = 0x418 allocated block containing:
            //   +8 = part number
            //   +9 = total parts
            //   +10-11 = data size (word)
            //   +12... = actual packet data
            // Actually, looking at sub_587DB0:
            // v10[259] = next, v10[260] = prev, v10+8 = part#, v10+9 = total, v10+10 = size
            // The pointer passed to sub_588350 is v9+3 = &v10[3] = data pointer
            // So 'data' points to the actual packet content!
            
            packetData = (uint8_t*)data;
            firstByte = packetData[0];
            
            // For CAR_DATA, the size is in the structure at offset -2 from data
            // Actually let's just use a fixed size based on packet type
            // Standard sizes: 102-104 = 109 bytes, 105 = 103 bytes
            if (firstByte >= 102 && firstByte <= 104) {
                dataSize = 109;
            } else if (firstByte == 105) {
                dataSize = 103;
            } else {
                dataSize = 128;  // default guess
            }
        }
        
        LOG("[SEND-PEERS] sub_588350 CALLED #%d! exclude=%d, pktType=%d, data=0x%08X, flag=%d, firstByte=%d, weAreHost=%d, peerIP=0x%08X, tunnel=%d",
            s_hookCalls, excludePeer, packetType, data, flag, firstByte, 
            g_weAreHost ? 1 : 0, g_lastRecvIP, (g_udpTunnelSocket != INVALID_SOCKET) ? 1 : 0);
        
        // Call original function first
        typedef int(__cdecl* OrigFunc_t)(int, int, int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp588350.code[0]);
        
        int result = 0;
        __try {
            result = origFunc(excludePeer, packetType, data, flag);
            LOG("[SEND-PEERS] sub_588350 returned %d", result);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[SEND-PEERS] *** EXCEPTION in sub_588350! ***");
            result = -1;
        }
        
        // CRITICAL: Send important packets through tunnel even if original failed
        // On joiner without registered peer, sub_5883A0 does nothing (peer array empty)!
        // We MUST send through tunnel:
        // - CAR_DATA (102-105) - packetType=1
        // - Type 12 (state sync) - packetType=12
        // - Type 13 (session state) - packetType=13
        // - Other sync types
        
        // Get actual packet data from bitstream buffer
        // The first byte of data at 'data' pointer is the packet type
        // BUT for sub_5883A0, 'packetType' parameter IS the packet type!
        // The 'data' is the bitstream buffer containing payload
        
        bool shouldTunnel = false;
        uint8_t tunnelPacketType = (uint8_t)packetType;
        int tunnelDataSize = 8;  // default minimal packet size
        
        // CRITICAL: Both HOST and JOINER need tunneling!
        // Direct UDP doesn't work through NAT - must go through relay server.
        if (g_udpTunnelSocket != INVALID_SOCKET && g_lastRecvIP != 0) {
            switch (packetType) {
                case 1:  // HELLO/CAR_DATA
                    if (packetData && firstByte >= 102 && firstByte <= 105) {
                        shouldTunnel = true;
                        tunnelPacketType = firstByte;
                        if (firstByte >= 102 && firstByte <= 104) tunnelDataSize = 109;
                        else if (firstByte == 105) tunnelDataSize = 103;
                    }
                    break;
                case 3:  // READY
                case 8:  // Heartbeat
                case 10: // Sync state  
                case 12: // State sync - CRITICAL for race start!
                case 13: // Session state
                case 14: // Unknown
                case 15: // Unknown
                case 16: // Unknown
                case 17: // Unknown
                    shouldTunnel = true;
                    tunnelDataSize = 8;
                    break;
            }
        }
        
        // NOTE: sub_588350 is called with packetType=1 for CAR_DATA, but the actual
        // CAR_DATA sending happens in Hook_587DB0 which parses the linked list output.
        // Here we just log and DON'T try to parse 'data' as CAR_DATA - it's a bitstream!
        //
        // CAR_DATA packets are already sent by Hook_587DB0, so skip type 1 here.
        // This hook handles other sync packet types (3, 8, 12, 13, etc.)
        if (shouldTunnel && packetType == 1) {
            // Type 1 (HELLO/CAR_DATA) is handled by Hook_587DB0 already
            LOG("[SEND-PEERS] >>> Type 1 skipped (Hook_587DB0 handles CAR_DATA)");
        }
        // Handle other sync packet types (type 12, 13, etc.)
        else if (shouldTunnel && packetType != 1) {
            char peerIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_lastRecvIP, peerIPStr, sizeof(peerIPStr));
            LOG("[SEND-PEERS] >>> Sending TYPE %d sync packet to %s:%d via tunnel (%s)", 
                packetType, peerIPStr, g_lastRecvPort, g_weAreHost ? "HOST->joiner" : "joiner->HOST");
            
            // Build sync packet
            // The 'data' parameter is bitstream buffer containing the packed data
            // We need to extract the actual size from it
            int bitstreamSize = (data != 0) ? *(int*)(data + 1024) : 0;
            
            // For sync packets, build UDP packet with type header
            uint8_t syncPacket[64];
            memset(syncPacket, 0, sizeof(syncPacket));
            
            // Packet format: [type:4][sessionId:4][payload...]
            syncPacket[0] = (uint8_t)packetType;
            syncPacket[1] = 0;
            syncPacket[2] = 0;
            syncPacket[3] = 0;
            // Session ID (use 100 = 0x64)
            syncPacket[4] = 0x64;
            syncPacket[5] = 0;
            syncPacket[6] = 0;
            syncPacket[7] = 0;
            
            // For type 12 (state sync), we need to include our state value
            // The state should be >= 3 for race to start
            if (packetType == 12) {
                // Add state value (32-bit little endian)
                // State 3 = ready, state 4 = loaded, etc.
                int ourState = 3;  // Minimum state for race start
                syncPacket[8] = ourState & 0xFF;
                syncPacket[9] = (ourState >> 8) & 0xFF;
                syncPacket[10] = (ourState >> 16) & 0xFF;
                syncPacket[11] = (ourState >> 24) & 0xFF;
                tunnelDataSize = 12;  // 8 header + 4 state
                LOG("[SEND-PEERS] >>> Type 12 state sync: sending state=%d", ourState);
            }
            
            int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, (char*)syncPacket, tunnelDataSize);
            if (sent > 0) {
                LOG("[SEND-PEERS] >>> Sent type %d (%d bytes) via tunnel!", packetType, tunnelDataSize);
                result = tunnelDataSize;
            } else {
                LOG("[SEND-PEERS] >>> Failed to send type %d via tunnel", packetType);
            }
        }
        
        return result;
    }
    
    // ========================================================================
    // Hook for sub_586120 - Send to specific peer
    // This is called by sub_589FA0 (peer car data exchange) and sub_588350 (broadcast)
    // ========================================================================
    inline int __cdecl Hook_586120(int peerIdx, char packetType, int carDataBuf, int flag) {
        static int s_hookCalls = 0;
        s_hookCalls++;
        
        // Read car data size
        int carDataSize = carDataBuf ? *(int*)(carDataBuf + 1024) : 0;
        
        LOG("[SEND-PEER] sub_586120 CALLED #%d! peerIdx=%d, pktType=%d, carData=0x%08X (size=%d), flag=%d",
            s_hookCalls, peerIdx, (int)packetType, carDataBuf, carDataSize, flag);
        
        // Check if this peer exists in connection array
        int* connArray = (int*)0x8691D0;
        bool foundPeer = false;
        int connSlot = -1;
        for (int i = 0; i < 5; i++) {
            if (connArray[i * 5 + 1] == peerIdx) {
                foundPeer = true;
                connSlot = i;
                int state = connArray[i * 5 + 0];
                int connPtr = connArray[i * 5 + 3];
                LOG("[SEND-PEER] Found peer %d in conn slot %d: state=%d, connPtr=0x%08X",
                    peerIdx, i, state, connPtr);
                break;
            }
        }
        
        if (!foundPeer) {
            LOG("[SEND-PEER] *** Peer %d NOT in connection array! ***", peerIdx);
            
            // CRITICAL FIX: Do NOT call original function - it will crash!
            // Instead, send through UDP tunnel directly.
            
            if (g_udpTunnelSocket != INVALID_SOCKET && g_lastRecvIP != 0 && carDataBuf) {
                LOG("[SEND-PEER] >>> Sending via UDP tunnel instead (avoiding crash)...");
                
                char ipStr[20];
                inet_ntop(AF_INET, &g_lastRecvIP, ipStr, sizeof(ipStr));
                
                // ================================================================
                // CRITICAL: For type 1 (HELLO/CAR_DATA), DON'T send here!
                // 
                // Hook_587DB0 already sends CAR_DATA packets through tunnel when
                // they are generated. sub_589FA0 then calls sub_586120 for each
                // packet, but we've already sent them.
                //
                // Just return success to prevent double-sending.
                // ================================================================
                if (packetType == 1) {
                    LOG("[SEND-PEER] >>> Type 1 already sent by Hook_587DB0, skipping duplicate");
                    return carDataSize > 0 ? carDataSize : 8;  // Return success
                }
                
                // ================================================================
                // CRITICAL FIX: For TYPE 13 (session control), send REAL data!
                // The carDataBuf contains bitstream-encoded data from sub_581D00:
                // - Byte 0: packet type (13)
                // - Bytes 1-4: session state value (2, 5, or 6) in big-endian bitstream
                // 
                // carDataSize is in BITS (from *(carDataBuf + 1024)), so convert to bytes.
                // ================================================================
                
                if (packetType == 13 && carDataBuf) {
                    // Read actual data size in bits, convert to bytes
                    int dataSizeBits = *(int*)(carDataBuf + 1024);
                    int dataSizeBytes = (dataSizeBits + 7) / 8;  // Round up
                    
                    if (dataSizeBytes > 0 && dataSizeBytes <= 64) {
                        uint8_t pktBuffer[128];
                        memset(pktBuffer, 0, sizeof(pktBuffer));
                        
                        // Copy the bitstream data
                        memcpy(pktBuffer, (void*)carDataBuf, dataSizeBytes);
                        
                        // Log what we're sending
                        LOG("[SEND-PEER] >>> TYPE 13 buffer: bits=%d, bytes=%d, data[0-7]=%02X %02X %02X %02X %02X %02X %02X %02X",
                            dataSizeBits, dataSizeBytes,
                            pktBuffer[0], pktBuffer[1], pktBuffer[2], pktBuffer[3],
                            pktBuffer[4], pktBuffer[5], pktBuffer[6], pktBuffer[7]);
                        
                        // Extract session state from bitstream for logging
                        // After sub_581D00(13, 8) and sub_581D00(state, 32):
                        // The session state is written in big-endian bits starting at bit 8
                        // But sub_581D00 writes HIBYTE first, so bytes 1-4 contain state in big-endian
                        int sessionState = (pktBuffer[1] << 24) | (pktBuffer[2] << 16) | 
                                          (pktBuffer[3] << 8) | pktBuffer[4];
                        LOG("[SEND-PEER] >>> TYPE 13 session state = %d (from bitstream)", sessionState);
                        
                        // For network transmission, we need to reformat:
                        // Game expects: type (4 bytes LE), then data
                        // Send as: [type=13 LE][session_state LE]
                        uint8_t networkPkt[12];
                        networkPkt[0] = 13;  // type
                        networkPkt[1] = 0;
                        networkPkt[2] = 0;
                        networkPkt[3] = 0;
                        // Session state in little-endian
                        networkPkt[4] = sessionState & 0xFF;
                        networkPkt[5] = (sessionState >> 8) & 0xFF;
                        networkPkt[6] = (sessionState >> 16) & 0xFF;
                        networkPkt[7] = (sessionState >> 24) & 0xFF;
                        // Padding
                        networkPkt[8] = 0;
                        networkPkt[9] = 0;
                        networkPkt[10] = 0;
                        networkPkt[11] = 0;
                        
                        int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, 
                                                    reinterpret_cast<char*>(networkPkt), 12);
                        if (sent > 0) {
                            LOG("[SEND-PEER] >>> Sent TYPE 13 (state=%d) to %s:%d", 
                                sessionState, ipStr, g_lastRecvPort);
                            return dataSizeBytes;
                        }
                    }
                    
                    LOG("[SEND-PEER] >>> TYPE 13 invalid data size: %d bits", dataSizeBits);
                }
                
                // For other packet types, build simple sync packet
                uint8_t syncPacket[64];
                memset(syncPacket, 0, sizeof(syncPacket));
                
                syncPacket[0] = (uint8_t)packetType;  // type (8, 9, 10, etc)
                syncPacket[1] = 0;
                syncPacket[2] = 0;
                syncPacket[3] = 0;
                // Session ID
                syncPacket[4] = 0x64;  // 100
                syncPacket[5] = 0;
                syncPacket[6] = 0;
                syncPacket[7] = 0;
                
                int packetLen = 8;  // Minimum sync packet size
                
                int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, 
                                            reinterpret_cast<char*>(syncPacket), packetLen);
                if (sent > 0) {
                    LOG("[SEND-PEER] >>> Sent type %d via tunnel to %s:%d (no crash)", 
                        packetType, ipStr, g_lastRecvPort);
                    return packetLen;  // Success - return packet size
                } else {
                    LOG("[SEND-PEER] >>> Failed to send type %d via tunnel", packetType);
                    return 0;
                }
            } else {
                LOG("[SEND-PEER] >>> Cannot send - no tunnel (socket=%d, IP=0x%08X)", 
                    (int)g_udpTunnelSocket, g_lastRecvIP);
                return 0;
            }
        }
        
        // Peer exists in connection array - call original function safely
        typedef int(__cdecl* OrigFunc_t)(int, char, int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp586120.code[0]);
        
        int result = 0;
        __try {
            result = origFunc(peerIdx, packetType, carDataBuf, flag);
            LOG("[SEND-PEER] sub_586120 returned %d", result);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[SEND-PEER] *** EXCEPTION in sub_586120! ***");
            
            // Fallback to tunnel on exception
            if (g_udpTunnelSocket != INVALID_SOCKET && g_lastRecvIP != 0) {
                uint8_t syncPacket[8] = {(uint8_t)packetType, 0, 0, 0, 0x64, 0, 0, 0};
                SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, (char*)syncPacket, 8);
                LOG("[SEND-PEER] >>> Sent via tunnel after exception");
                result = 8;
            }
        }
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_58F020 - Main packet dispatcher
    // This is called for ALL incoming UDP packets.
    // It reads packet type from bitstream and dispatches to handlers.
    // Types >= 18 are IGNORED by the dispatcher!
    // ========================================================================
    inline int __cdecl Hook_58F020(int peerIdx, const void* data, unsigned int size, char flag) {
        static int s_dispatcherCalls = 0;
        s_dispatcherCalls++;
        
        // Read first byte as type (same as dispatcher does)
        int type = (size > 0 && data) ? ((const unsigned char*)data)[0] : -1;
        
        // Only log occasionally to avoid spam
        if (s_dispatcherCalls <= 20 || type <= 14 || s_dispatcherCalls % 100 == 0) {
            const char* typeName = "UNKNOWN";
            switch(type) {
                case 1: typeName = "HELLO"; break;
                case 2: typeName = "HELLO_ACK"; break;
                case 3: typeName = "READY"; break;
                case 5: typeName = "BROADCAST"; break;
                case 7: typeName = "TYPE_7"; break;
                case 8: typeName = "TYPE_8"; break;
                case 9: typeName = "TYPE_9"; break;
                case 12: typeName = "TYPE_12_STATE_SYNC"; break;
                case 13: typeName = "TYPE_13_SESSION"; break;
                case 14: typeName = "TYPE_14"; break;
                case 17: typeName = "TYPE_17_GAME_START"; break;
            }
            
            if (type >= 18) {
                LOG("[DISPATCHER] sub_58F020 #%d: type=%d (0x%02X) IGNORED (>=18)! peer=%d, size=%u",
                    s_dispatcherCalls, type, type, peerIdx, size);
            } else {
                LOG("[DISPATCHER] sub_58F020 #%d: type=%d (%s), peer=%d, size=%u",
                    s_dispatcherCalls, type, typeName, peerIdx, size);
            }
            
            // Extra logging for type 12 (state sync) - show the state value!
            if (type == 12 && size >= 12 && data) {
                const uint8_t* bytes = (const uint8_t*)data;
                int stateValue = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
                LOG("[DISPATCHER] >>> TYPE 12 STATE SYNC: state=%d from peer %d", stateValue, peerIdx);
                
                // Log peer array state for debugging
                int* peerArray = (int*)0x8693C8;
                for (int i = 0; i < 5; i++) {
                    int peerPtr = peerArray[i * 8];
                    int peerIndex = peerArray[i * 8 + 1];
                    int peerState = peerArray[i * 8 + 4];
                    if (peerIndex != -1) {
                        LOG("[DISPATCHER] >>> Peer slot %d: peerIdx=%d, state=%d (will be set to %d)", 
                            i, peerIndex, peerState, stateValue);
                    }
                }
            }
            
            // Log type 17 (game start) which is critical
            if (type == 17 && data) {
                LOG("[DISPATCHER] >>> TYPE 17 GAME START received! Race should begin!");
            }
            
            // Handle TYPE 13 (session state) - NOT handled by original dispatcher!
            // Type 13 is sent by host to control session state machine.
            // Payload: [type:4][sessionId:4][value:4]
            // Values: 2=ready, 3=?, 4=?, 5=countdown, 6=start
            if (type == 13 && size >= 8 && data) {
                const uint8_t* bytes = (const uint8_t*)data;
                // Read session value (at byte 8, but might be missing in short packets)
                int sessionValue = 0;
                if (size >= 12) {
                    sessionValue = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
                }
                
                LOG("[DISPATCHER] >>> TYPE 13 SESSION: value=%d from peer %d", sessionValue, peerIdx);
                LOG("[DISPATCHER] >>> Current dword_866A14=%d, will process type 13...", *(int*)0x866A14);
                
                // Type 13 controls the session state machine
                // We need to call sub_587C50 (type 13 handler from sub_58E900)
                // But sub_587C50 expects bitstream format, not raw bytes
                
                // Instead, let's manually update dword_866A08 and call the handler
                if (sessionValue >= 2 && sessionValue <= 7) {
                    // Set the session value that sub_587C50 would read
                    *(int*)0x866A08 = sessionValue;
                    
                    // Call sub_587C50 (type 13 handler)
                    typedef int(__cdecl* Sub587C50_t)();
                    Sub587C50_t handler = (Sub587C50_t)0x587C50;
                    
                    __try {
                        // Note: sub_587C50 reads from bitstream, so this may not work directly
                        // Let's manually handle the important cases:
                        
                        if (sessionValue == 2) {
                            // Host says "all ready, prepare race"
                            LOG("[DISPATCHER] >>> TYPE 13 value=2: Host signals all ready!");
                            
                            // Check if we can transition to state 4
                            int gameState = *(int*)0x8669F4;
                            if (gameState < 4) {
                                // Check if this is joiner (no broadcast socket)
                                int broadcastSocket = *(int*)0x8667EC;
                                if (broadcastSocket == 0 || broadcastSocket == -1) {
                                    // Joiner - set game state directly
                                    LOG("[DISPATCHER] >>> Joiner mode - setting game state to 4 directly");
                                    *(int*)0x8669F4 = 4;
                                } else {
                                    // Host - use normal function
                                    LOG("[DISPATCHER] >>> Host mode - calling sub_585E10(4)...");
                                    typedef int(__cdecl* Sub585E10_t)(int);
                                    Sub585E10_t setGameState = (Sub585E10_t)0x585E10;
                                    setGameState(4);
                                }
                                LOG("[DISPATCHER] >>> Game state now: %d", *(int*)0x8669F4);
                            }
                        }
                        else if (sessionValue == 6) {
                            // Host says "race starting now"
                            LOG("[DISPATCHER] >>> TYPE 13 value=6: RACE STARTING!");
                            *(int*)0x8669F4 = 7;  // Set game state to 7 (racing)
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER) {
                        LOG("[DISPATCHER] >>> Exception handling type 13!");
                    }
                }
            }
        }
        
        // Call original
        typedef int(__cdecl* OrigFunc_t)(int, const void*, unsigned int, char);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp58F020.code[0]);
        return origFunc(peerIdx, data, size, flag);
    }
    
    // ========================================================================
    // Hook for sub_58C690 - Type 12 (state sync) handler
    // This is CRITICAL for race start! Host uses this to track peer readiness.
    // 
    // PROBLEM DISCOVERED: The original function reads state via bitstream (sub_581D90)
    // which reads the NEXT 32 bits after dispatcher consumed the type byte.
    // But bitstream cursor is at session ID position, so it reads 100 (0x64) as state!
    // 
    // Packet structure (raw bytes):
    //   [0-3] = type (12)
    //   [4-7] = session ID (100 = 0x64)
    //   [8-11] = state (3 or 4)
    // 
    // Bitstream after dispatcher reads type:
    //   Next 32 bits = session ID (100) <-- original reads THIS as state!
    //   Following 32 bits = actual state (3)
    // 
    // FIX: We manually set the peer state from raw packet bytes AND call original.
    // ========================================================================
    inline int __cdecl Hook_58C690(int packetData, int peerIdx) {
        static int s_hookCalls = 0;
        s_hookCalls++;
        
        // Read state from RAW packet bytes (offset 8 = after type and sessionId)
        const uint8_t* bytes = (const uint8_t*)packetData;
        int stateFromPacket = -1;
        
        if (bytes) {
            // Packet format: [type:4][sessionId:4][state:4]
            // State is at byte offset 8
            stateFromPacket = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
        }
        
        // Find peer in peer array
        int* peerArray = (int*)0x8693C8;
        int oldState = -1;
        int peerSlot = -1;
        
        for (int i = 0; i < 5; i++) {
            if (peerArray[i * 8 + 1] == peerIdx) {  // Found peer by index
                oldState = peerArray[i * 8 + 4];
                peerSlot = i;
                break;
            }
        }
        
        LOG("[TYPE12-HANDLER] sub_58C690 #%d: peerIdx=%d, stateFromPacket=%d, oldState=%d, slot=%d", 
            s_hookCalls, peerIdx, stateFromPacket, oldState, peerSlot);
        
        int result = stateFromPacket;  // Default return value
        
        // CRITICAL FIX: If peer not in peer array, DON'T call original function!
        // Original will crash trying to access peer data that doesn't exist.
        // Instead, manually update peer state if we can find/create the slot.
        if (peerSlot < 0) {
            LOG("[TYPE12-HANDLER] >>> Peer %d NOT in peer array - trying to add manually...", peerIdx);
            
            // Try to add peer to first empty slot
            for (int i = 0; i < 5; i++) {
                if (peerArray[i * 8 + 1] == -1) {  // Empty slot
                    peerArray[i * 8 + 0] = peerIdx;  // struct (use peerIdx as placeholder)
                    peerArray[i * 8 + 1] = peerIdx;  // idx
                    peerArray[i * 8 + 4] = stateFromPacket;  // state
                    peerArray[i * 8 + 7] = *(int*)0x8651AC;  // timestamp
                    peerSlot = i;
                    
                    // Also update dword_866A24 (peer count for state machine)
                    int* peerCount866A24 = (int*)0x866A24;
                    (*peerCount866A24)++;
                    
                    LOG("[TYPE12-HANDLER] >>> Created peer entry: slot=%d, idx=%d, state=%d, dword_866A24=%d", 
                        i, peerIdx, stateFromPacket, *peerCount866A24);
                    break;
                }
            }
            
            // Skip original function call - peer data not properly initialized
            LOG("[TYPE12-HANDLER] >>> Skipping original sub_58C690 (would crash)");
        } else {
            // Peer found in array - safe to call original
            // CRITICAL FIX: Manually set the peer state BEFORE calling original!
            // Original function will read session ID (100) as state due to bitstream bug.
            
            // Call original handler (let it do its thing, even if it sets wrong state)
            typedef int(__cdecl* OrigFunc_t)(int, int);
            OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp58C690.code[0]);
            
            __try {
                result = origFunc(packetData, peerIdx);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG("[TYPE12-HANDLER] *** EXCEPTION in sub_58C690! peerIdx=%d ***", peerIdx);
            }
        }
        
        // CRITICAL FIX: Now correct the state that original function set wrongly!
        // Original read session ID (100) as state, we need to set actual state.
        if (peerSlot >= 0 && stateFromPacket >= 0 && stateFromPacket <= 10) {
            int wrongState = peerArray[peerSlot * 8 + 4];
            
            // Only fix if original set a wrong value (like 100)
            if (wrongState > 10 || wrongState != stateFromPacket) {
                peerArray[peerSlot * 8 + 4] = stateFromPacket;
                LOG("[TYPE12-HANDLER] >>> FIXED state: %d -> %d (original set %d incorrectly)", 
                    oldState, stateFromPacket, wrongState);
            }
            
            // Check for race start condition: new state=4, old state was 3
            // This should trigger sub_589F30 to send type 17
            if (stateFromPacket == 4 && oldState == 3) {
                LOG("[TYPE12-HANDLER] >>> RACE START CONDITION! state 3->4");
                
                // Get peer ID for sub_589F30
                int peerID = peerArray[peerSlot * 8];
                
                // CRITICAL: Check if peerID is a virtual peer marker or real player index!
                // Real peers have peerID = small number (0-6) that indexes into player array.
                // Virtual peers use marker 0xDEAD0000 to indicate "no real player struct".
                //
                // For real peers: peerID indexes into dword_89CF50 (player array)
                // For virtual peers: NO player struct exists - skip dangerous operations!
                
                const int VIRTUAL_PEER_MARKER = 0xDEAD0000;
                if (peerID == VIRTUAL_PEER_MARKER || (peerID & 0xFFFF0000) == 0xDEAD0000) {
                    // This is a virtual peer with no real player struct - DON'T call sub_589F30!
                    // sub_589F30 would crash trying to dereference player array[peerID]
                    LOG("[TYPE12-HANDLER] >>> peerID=%d is virtual (no player struct), NOT calling sub_589F30!", peerID);
                    
                    // On JOINER: We don't need to send type 17 to host - host already knows.
                    // Just make sure our game state advances.
                    int* sessionStatePtr = (int*)0x866A14;
                    if (*sessionStatePtr < 4) {
                        *sessionStatePtr = 4;  // Move session to "ready to countdown" state
                        LOG("[TYPE12-HANDLER] >>> Set session state to 4 (joiner side)");
                    }
                } else {
                    // Real peer with valid pointer - safe to call original function
                    // (This is HOST side with actual connected client)
                    typedef int(__cdecl* Sub589F30_t)(int, int);
                    Sub589F30_t sub_589F30 = (Sub589F30_t)0x589F30;
                    
                    __try {
                        int startResult = sub_589F30(peerIdx, peerID);
                        LOG("[TYPE12-HANDLER] >>> sub_589F30 returned %d - TYPE 17 should be sent!", startResult);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER) {
                        LOG("[TYPE12-HANDLER] >>> EXCEPTION in sub_589F30!");
                    }
                }
            }
        }
        
        // Log final state
        int newState = (peerSlot >= 0) ? peerArray[peerSlot * 8 + 4] : -1;
        LOG("[TYPE12-HANDLER] >>> Final state: %d, result=%d", newState, result);
        
        // Log session state
        int sessionState = *(int*)0x866A14;
        int playerCount = *(int*)0x7FBDB8;
        int gameState = *(int*)0x8669F4;
        LOG("[TYPE12-HANDLER] >>> Session: dword_866A14=%d, playerCount=%d, gameState=%d", 
            sessionState, playerCount, gameState);
        
        return result;
    }
    
    // ========================================================================
    // Hook for sub_58C620 - Peer disconnect/timeout handler
    // This function removes a peer from peer array and calls cleanup functions.
    // 
    // PROBLEM: For virtual peers with marker 0xDEAD0000, the cleanup code
    // tries to access player array at invalid index, causing crash.
    // 
    // SOLUTION: Skip cleanup for virtual peers.
    // ========================================================================
    inline int __cdecl Hook_58C620(int peerIdx, char flag) {
        static int s_disconnectCalls = 0;
        s_disconnectCalls++;
        
        LOG("[DISCONNECT] sub_58C620 #%d: peerIdx=%d, flag=%d", s_disconnectCalls, peerIdx, (int)flag);
        
        // Find peer in peer array to check if it's virtual
        int* peerArray = (int*)0x8693C8;
        int peerID = -1;
        int peerSlot = -1;
        
        for (int i = 0; i < 5; i++) {
            if (peerArray[i * 8 + 1] == peerIdx) {
                peerID = peerArray[i * 8];
                peerSlot = i;
                break;
            }
        }
        
        LOG("[DISCONNECT] Found peer: slot=%d, peerID=0x%08X", peerSlot, peerID);
        
        // CRITICAL: Check if player data exists for this peer!
        // Original sub_58C620 calls sub_6099C0(dword_89CF48, peer[0], flag)
        // which accesses dword_89CF48[peer[0] + 2] as player data pointer.
        // If that slot is NULL, it will CRASH!
        //
        // For TCP tunnel peers registered via sub_58C360, the peer struct ID
        // is generated but player data is NOT allocated (done by sub_5FE5E0).
        // We must detect this and avoid calling the original!
        
        bool playerDataValid = false;
        if (peerID >= 0 && peerID < 6) {
            // Check dword_89CF48[peerID + 2] (offset +8, +12, +16, ... bytes)
            int* sessionStruct = (int*)0x89CF48;
            int playerDataPtr = sessionStruct[peerID + 2];  // [2], [3], [4], [5], [6], [7]
            
            LOG("[DISCONNECT] >>> Checking player data: dword_89CF48[%d + 2] = 0x%08X", 
                peerID, playerDataPtr);
            
            // Valid if pointer is in reasonable range (not NULL, not small number)
            if (playerDataPtr > 0x10000) {
                playerDataValid = true;
            }
        }
        
        // Check if this is a virtual peer (marker 0xDEAD0000) OR has invalid player data
        const int VIRTUAL_PEER_MARKER = 0xDEAD0000;
        bool isVirtual = (peerID == VIRTUAL_PEER_MARKER || (peerID & 0xFFFF0000) == 0xDEAD0000);
        bool shouldSkipOriginal = isVirtual || !playerDataValid;
        
        if (shouldSkipOriginal) {
            if (isVirtual) {
                LOG("[DISCONNECT] >>> VIRTUAL PEER detected! Skipping original cleanup to avoid crash.");
            } else {
                LOG("[DISCONNECT] >>> INVALID PLAYER DATA (NULL or invalid)! Skipping original to avoid crash.");
            }
            
            // Just clear the peer array entry manually
            if (peerSlot >= 0) {
                peerArray[peerSlot * 8 + 0] = -1;  // Clear peer struct
                peerArray[peerSlot * 8 + 1] = -1;  // Clear peer index
                peerArray[peerSlot * 8 + 4] = 0;   // Clear state
                LOG("[DISCONNECT] >>> Cleared peer slot %d manually", peerSlot);
            }
            
            // Decrement player count (this is normally done by original function)
            int* playerCount = (int*)0x7FBDB8;
            if (*playerCount > 0) {
                (*playerCount)--;
                LOG("[DISCONNECT] >>> Player count decremented to %d", *playerCount);
            }
            
            // Also reset our tracking variable to allow new peer registration
            g_hostPeerRegistered = false;
            LOG("[DISCONNECT] >>> Reset g_hostPeerRegistered for new connections");
            
            return 0;  // Return without calling dangerous original function
        }
        
        // Real peer with valid player data - call original function
        LOG("[DISCONNECT] >>> Real peer with valid player data, calling original sub_58C620...");
        typedef int(__cdecl* OrigFunc_t)(int, char);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp58C620.code[0]);
        
        int result = 0;
        __try {
            result = origFunc(peerIdx, flag);
            LOG("[DISCONNECT] >>> Original returned %d", result);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[DISCONNECT] *** EXCEPTION in sub_58C620! peerIdx=%d ***", peerIdx);
            
            // If crashed, still clean up peer array
            if (peerSlot >= 0) {
                peerArray[peerSlot * 8 + 0] = -1;
                peerArray[peerSlot * 8 + 1] = -1;
                peerArray[peerSlot * 8 + 4] = 0;
            }
            g_hostPeerRegistered = false;
        }
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_585E80 - CAR_DATA accumulator
    // This function is called from HELLO handler to accumulate CAR_DATA parts.
    // Returns 1 when ALL parts are received, 0 otherwise.
    // 
    // Parameters:
    //   a1 = bitstream data (float is actually passed as int from calling convention)
    //   a2 = linked list to accumulate parts
    // Returns:
    //   1 if all parts received, 0 otherwise
    // ========================================================================
    inline int __cdecl Hook_585E80(float a1, int a2) {
        // Call original first
        typedef int(__cdecl* OrigFunc_t)(float, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp585E80.code[0]);
        int result = origFunc(a1, a2);
        
        static int s_accumCalls = 0;
        s_accumCalls++;
        
        // Log result - this tells us if all CAR_DATA parts are received
        LOG("[CAR-ACCUM] sub_585E80 #%d: a1=0x%08X, a2=0x%08X -> result=%d (%s)",
            s_accumCalls, *(int*)&a1, a2, result, 
            result == 1 ? "ALL PARTS RECEIVED!" : "waiting for more parts");
        
        return result;
    }
    
    // ========================================================================
    // Debug hook for sub_58C420 - HELLO packet handler
    // This function is called when a HELLO (type 1) packet is received.
    // It accumulates CAR_DATA parts and triggers generation of OUR car data.
    // 
    // Parameters:
    //   a1 = bitstream buffer with packet data
    //   a2 = peer index (0-5)
    // ========================================================================
    inline void __cdecl Hook_58C420(int a1, int a2) {
        static int s_helloHandlerCalls = 0;
        s_helloHandlerCalls++;
        
        LOG("[HELLO-HANDLER] sub_58C420 CALLED! call #%d, bitstream=0x%08X, peerIdx=%d, weAreHost=%d",
            s_helloHandlerCalls, a1, a2, g_weAreHost ? 1 : 0);
        
        // Log first bytes of bitstream for debugging
        if (a1) {
            char hexBuf[64];
            int hexLen = 0;
            for (int i = 0; i < 16 && hexLen < 60; i++) {
                hexLen += sprintf(hexBuf + hexLen, "%02X ", ((unsigned char*)a1)[i]);
            }
            LOG("[HELLO-HANDLER] Bitstream data: %s", hexBuf);
        }
        
        // ================================================================
        // CRITICAL FIX FOR JOINER:
        // 
        // When sub_58C420 receives ALL CAR_DATA parts (sub_585E80 returns 1),
        // it calls sub_601EB0 which tries to create player data.
        // On joiner, this CRASHES because the player struct isn't set up.
        //
        // Solution for joiner:
        // 1. Call sub_585E80 ourselves to accumulate parts
        // 2. If NOT all parts received, return (let game continue accumulating)
        // 3. If all parts received, DON'T call original (it would crash)
        // 4. Instead, manually call sub_587DB0 to generate our CAR_DATA response
        // 5. Send CAR_DATA via tunnel (Hook_587DB0 already handles this!)
        //
        // On host, just call original normally.
        // ================================================================
        
        if (!g_weAreHost) {
            // JOINER: Special handling to avoid crash
            
            // First, check/update accumulator for this peer
            // dword_86A600[a2] is the accumulator pointer
            int* accumArray = (int*)0x86A600;
            int* accumPtr = (int*)accumArray[a2];
            
            // If no accumulator yet, allocate one (like original does)
            if (!accumPtr) {
                accumPtr = (int*)malloc(8);
                if (accumPtr) {
                    accumPtr[0] = (int)accumPtr;  // linked list: points to self
                    accumPtr[1] = (int)accumPtr;
                }
                accumArray[a2] = (int)accumPtr;
                LOG("[HELLO-HANDLER] >>> JOINER: Created accumulator for peer %d at 0x%08X", a2, (int)accumPtr);
            }
            
            // Call sub_585E80 to accumulate this part
            typedef int(__cdecl* Sub585E80_t)(int, int);
            Sub585E80_t sub_585E80 = (Sub585E80_t)0x585E80;
            
            int accumResult = 0;
            __try {
                accumResult = sub_585E80(a1, (int)accumPtr);
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG("[HELLO-HANDLER] *** EXCEPTION in sub_585E80! ***");
                return;
            }
            
            LOG("[CAR-ACCUM] sub_585E80 #%d: a1=0x%08X, a2=0x%08X -> result=%d%s", 
                s_helloHandlerCalls, a1, (int)accumPtr, accumResult,
                accumResult == 1 ? " (ALL PARTS RECEIVED!)" : " (waiting for more parts)");
            
            if (accumResult != 1) {
                // Not all parts received yet, just return
                LOG("[HELLO-HANDLER] sub_58C420 RETURNED OK for peer %d (accumulating)", a2);
                return;
            }
            
            // ALL PARTS RECEIVED!
            // Now we need to:
            // 1. Call sub_588010 to assemble data into bitstream
            // 2. Skip sub_601EB0 (would crash)
            // 3. Call sub_587DB0 to generate our CAR_DATA response
            // 4. Clean up accumulator
            
            LOG("[HELLO-HANDLER] >>> JOINER: All CAR_DATA parts received! Generating response...");
            
            // Allocate bitstream buffer (like original v18[257])
            uint8_t bitstreamBuf[1028];  // 1024 + 4 bytes for size
            memset(bitstreamBuf, 0, sizeof(bitstreamBuf));
            
            // Call sub_588010 to assemble accumulated data
            typedef void(__cdecl* Sub588010_t)(int, int);
            Sub588010_t sub_588010 = (Sub588010_t)0x588010;
            
            __try {
                sub_588010((int)bitstreamBuf, (int)accumPtr);
                LOG("[HELLO-HANDLER] >>> sub_588010 completed - data assembled");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG("[HELLO-HANDLER] *** EXCEPTION in sub_588010! ***");
            }
            
            // Free accumulator linked list
            if (accumPtr) {
                int* node = (int*)accumPtr[0];
                while (node != accumPtr) {
                    int* nextNode = (int*)node[0];
                    free(node);
                    node = nextNode;
                }
                free(accumPtr);
                accumArray[a2] = 0;
                LOG("[HELLO-HANDLER] >>> Freed accumulator for peer %d", a2);
            }
            
            // Create output linked list for sub_587DB0 (like original Block)
            int outputList[2];
            outputList[0] = (int)outputList;  // points to self (empty list)
            outputList[1] = (int)outputList;
            
            // Call sub_587DB0 to generate our CAR_DATA packets
            // sub_587DB0(1, bitstreamBuf, &outputList)
            // This will trigger Hook_587DB0 which sends via tunnel!
            typedef void(__cdecl* Sub587DB0_t)(unsigned int, int, int);
            Sub587DB0_t sub_587DB0 = (Sub587DB0_t)0x587DB0;
            
            LOG("[HELLO-HANDLER] >>> Calling sub_587DB0 to generate our CAR_DATA...");
            __try {
                sub_587DB0(1, (int)bitstreamBuf, (int)outputList);
                LOG("[HELLO-HANDLER] >>> sub_587DB0 completed - our CAR_DATA generated!");
            }
            __except(EXCEPTION_EXECUTE_HANDLER) {
                LOG("[HELLO-HANDLER] *** EXCEPTION in sub_587DB0! ***");
            }
            
            // Clean up output list (free any nodes that were created)
            int* outNode = (int*)outputList[0];
            while (outNode != (int*)outputList) {
                int* nextOutNode = (int*)outNode[0];
                free(outNode);
                outNode = nextOutNode;
            }
            
            LOG("[HELLO-HANDLER] >>> JOINER: CAR_DATA exchange complete (no crash!)");
            return;
        }
        
        // HOST: Call original normally
        typedef void(__cdecl* OrigFunc_t)(int, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp58C420.code[0]);
        
        __try {
            origFunc(a1, a2);
            LOG("[HELLO-HANDLER] sub_58C420 RETURNED OK for peer %d", a2);
        }
        __except(EXCEPTION_EXECUTE_HANDLER) {
            LOG("[HELLO-HANDLER] *** EXCEPTION in sub_58C420! peer=%d ***", a2);
        }
    }
    
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
    constexpr uintptr_t GAME_BIND_WRAPPER = 0x74A380;     // sub_74A380
    
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
    // int __cdecl sub_74A5C0(int socketStruct, char* buf, int len, int a4, sockaddr* to, int tolen)
    // 
    // When 'to' != 0, this is UDP sendto and we need to:
    // 1. Redirect to relay server
    // 2. Prepend 6-byte header with original destination
    // 
    // IMPORTANT: We must call sendto() DIRECTLY, not through original function,
    // because original function calls sub_74A030() which modifies the destination!
    // ========================================================================
    inline int __cdecl Hook_GameSend(int a1, const char* buf, int len, int a4, sockaddr* to, int tolen) {
        // *** VERY FIRST LOG - proves hook is called ***
        static bool s_firstSendCall = true;
        if (s_firstSendCall) {
            s_firstSendCall = false;
            LOG("*** Hook_GameSend FIRST CALL! a1=0x%08X, buf=%p, len=%d, to=%p ***", a1, buf, len, to);
        }
        
        // Get socket from structure
        SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
        
#if !UDP_CAPTURE_ONLY
        // === RELAY MODE: Redirect UDP packets through relay server ===
        if (to != nullptr && g_serverIP != 0 && len > 0) {
            sockaddr_in* destAddr = reinterpret_cast<sockaddr_in*>(to);
            
            // Get original destination for logging
            char destIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &destAddr->sin_addr, destIPStr, sizeof(destIPStr));
            uint16_t destPort = ntohs(destAddr->sin_port);
            
            // Detect packet type
            uint8_t firstByte = (len >= 1) ? (uint8_t)buf[0] : 0;
            uint32_t pktType = (len >= 4) ? *reinterpret_cast<const uint32_t*>(buf) : 0;
            uint32_t peerId = (len >= 8) ? *reinterpret_cast<const uint32_t*>(buf + 4) : 0;
            
            // Check if this is a P2P handshake packet (starts with 0x45, NOT a relay packet)
            // P2P handshake: first byte 0x45, contains "sknG" magic at offset 28
            // Relay packets: type 1 or 5, 8 bytes, simple format
            bool isP2PHandshake = (firstByte == 0x45 && len >= 32);
            
            // Also check for "sknG" magic to be sure
            if (isP2PHandshake && len >= 32) {
                uint32_t magic = *reinterpret_cast<const uint32_t*>(buf + 28);
                isP2PHandshake = (magic == 0x676E6B73); // "sknG"
            }
            
            if (isP2PHandshake) {
                // P2P handshake packet - DO NOT send through relay!
                // In relay mode, we don't need direct P2P - just drop these packets
                // The relay server will handle the connection
                LOG("[UDP-P2P] DROPPING P2P handshake packet (0x45/sknG): dest=%s:%d, len=%d - relay mode active",
                    destIPStr, destPort, len);
                return len;  // Pretend we sent it successfully
            }
            
            // Skip packets with invalid destination (port 0 usually means P2P probe)
            if (destPort == 0) {
                LOG("[UDP-SKIP] Skipping packet with dest port 0: dest=%s, len=%d, firstByte=0x%02X",
                    destIPStr, len, firstByte);
                return len;  // Pretend we sent it
            }
            
            // Detailed logging for packet types
            const char* pktTypeName = "UNKNOWN";
            switch(pktType) {
                case 1: pktTypeName = "HELLO/PROBE"; break;
                case 2: pktTypeName = "HELLO_ACK"; break;
                case 3: pktTypeName = "READY"; break;
                case 4: pktTypeName = "ACK"; break;
                case 5: pktTypeName = "BROADCAST"; break;
                case 101: pktTypeName = "SYNC_BASE"; break;
                case 102: pktTypeName = "CAR_DATA_1"; break;
                case 103: pktTypeName = "CAR_DATA_2"; break;
                case 104: pktTypeName = "CAR_DATA_3"; break;
                case 105: pktTypeName = "CAR_DATA_4"; break;
            }
            
            LOG("[UDP-RELAY] SEND: dest=%s:%d, type=%u (%s), len=%d", 
                destIPStr, destPort, pktType, pktTypeName, len);
            
            // Log raw hex for debugging - more for important packets
            char hexBuf[256];
            int hexLen = 0;
            int dumpLen = (pktType >= 101 && pktType <= 105) ? (len < 64 ? len : 64) : (len < 32 ? len : 32);
            for (int i = 0; i < dumpLen && hexLen < 250; i++) {
                hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
            }
            LOG("[UDP-RELAY] HEX: %s", hexBuf);
            
            // Track if we sent FULL SYNC_BASE (car is loaded)
            static bool s_sentFullSyncBase = false;
            static DWORD s_firstHelloAckRecvTime = 0; // When we received first HELLO_ACK
            static int s_shortSyncBaseSuppressCount = 0;
            const DWORD SHORT_SYNC_SUPPRESS_TIMEOUT_MS = 6000; // Suppress short SYNC_BASE for 6 seconds
            
            // Track FULL SYNC_BASE - this indicates car is loaded
            if (pktType == 101 && len >= 40) {
                s_sentFullSyncBase = true;
                LOG("[UDP-RELAY] Sent FULL SYNC_BASE (%d bytes) - CAR IS LOADED!", len);
            }
            
            // CRITICAL FIX: Suppress SHORT SYNC_BASE from joiner until car loads
            // 
            // Problem: Joiner receives HELLO_ACK and immediately sends SHORT SYNC_BASE (8-21 bytes)
            // because car isn't loaded yet. This happens BEFORE BROADCAST arrives!
            // In original P2P, NAT traversal delay (~1-5 sec) allowed car to load.
            // 
            // Solution: Suppress SHORT SYNC_BASE until either:
            // 1. We send FULL SYNC_BASE (car loaded), OR
            // 2. Timeout expires (6 seconds)
            if (pktType == 101 && len < 40 && !g_weAreHost) {
                // We're joiner trying to send SHORT SYNC_BASE
                s_shortSyncBaseSuppressCount++;
                
                // Initialize timer on first attempt
                if (s_shortSyncBaseSuppressCount == 1) {
                    s_firstHelloAckRecvTime = GetTickCount();
                }
                
                DWORD elapsed = GetTickCount() - s_firstHelloAckRecvTime;
                
                // Check if we should suppress
                if (!s_sentFullSyncBase && elapsed < SHORT_SYNC_SUPPRESS_TIMEOUT_MS) {
                    LOG("[UDP-RELAY] >>> SUPPRESSING SHORT SYNC_BASE (%d bytes) - car not loaded!", len);
                    LOG("[UDP-RELAY] >>> Attempt #%d, elapsed %dms, timeout %dms", 
                        s_shortSyncBaseSuppressCount, elapsed, SHORT_SYNC_SUPPRESS_TIMEOUT_MS);
                    LOG("[UDP-RELAY] >>> Waiting for car to load (FULL SYNC_BASE >= 40 bytes)");
                    // Return success without sending - game thinks it sent
                    return len;
                } else if (!s_sentFullSyncBase) {
                    LOG("[UDP-RELAY] TIMEOUT: Sending SHORT SYNC_BASE anyway after %dms (car may fail to sync!)", elapsed);
                } else {
                    LOG("[UDP-RELAY] Sending SHORT SYNC_BASE after FULL was sent (len=%d)", len);
                }
            } else if (pktType == 101 && len < 40) {
                LOG("[UDP-RELAY] WARNING: HOST sending SHORT SYNC_BASE (%d bytes) - allowed", len);
            }
            
            // Track if we sent CAR_DATA (102-105)
            // Using GLOBAL variables so recvfrom hook can also access this state
            static int s_readyWithoutCarDataCount = 0;
            
            if (pktType >= 102 && pktType <= 105) {
                g_sentCarData = true;
                g_sentCarDataTypes[pktType - 102] = true;
                LOG("[UDP-RELAY] Sent CAR_DATA type %u (sent types: 102=%d 103=%d 104=%d 105=%d)", 
                    pktType,
                    g_sentCarDataTypes[0], g_sentCarDataTypes[1], 
                    g_sentCarDataTypes[2], g_sentCarDataTypes[3]);
            }
            
            // Track if we are host (sending BROADCAST)
            if (pktType == 5) {
                g_weAreHost = true;
                LOG("[UDP-RELAY] We are HOST (sending BROADCAST)");
            }
            
            // EXPERIMENTAL: Suppress READY from joiner if CAR_DATA not sent yet
            // This gives the joiner's car time to load
            // WARNING: This may cause game to hang if car never loads - use timeout
            static DWORD s_firstReadySuppressTime = 0;
            static int s_readySuppressCount = 0;
            const DWORD READY_SUPPRESS_TIMEOUT_MS = 8000; // Max 8 seconds suppression
            
            if (pktType == 3 && !g_sentCarData && !g_weAreHost) {
                // We are JOINER trying to send READY without CAR_DATA
                s_readyWithoutCarDataCount++;
                
                if (s_readySuppressCount == 0) {
                    s_firstReadySuppressTime = GetTickCount();
                }
                s_readySuppressCount++;
                
                DWORD suppressElapsed = GetTickCount() - s_firstReadySuppressTime;
                DWORD timeSinceBroadcast = g_firstBroadcastRecvTime ? (GetTickCount() - g_firstBroadcastRecvTime) : 0;
                
                LOG("[UDP-RELAY] JOINER READY without CAR_DATA (attempt #%d, suppress: %dms, since BROADCAST: %dms)", 
                    s_readyWithoutCarDataCount, suppressElapsed, timeSinceBroadcast);
                LOG("[UDP-RELAY] >>> CAR_DATA sent: 102=%d 103=%d 104=%d 105=%d", 
                    g_sentCarDataTypes[0], g_sentCarDataTypes[1], 
                    g_sentCarDataTypes[2], g_sentCarDataTypes[3]);
                
                // Suppress READY for up to READY_SUPPRESS_TIMEOUT_MS
                if (suppressElapsed < READY_SUPPRESS_TIMEOUT_MS) {
                    LOG("[UDP-RELAY] >>> SUPPRESSING READY - waiting for car to load (%dms remaining)", 
                        READY_SUPPRESS_TIMEOUT_MS - suppressElapsed);
                    // Return success without actually sending - game thinks it sent
                    // This gives car time to load and send CAR_DATA first
                    return len;  // Fake success
                } else {
                    LOG("[UDP-RELAY] >>> TIMEOUT - sending READY anyway (car may not be synced!)");
                    // Reset suppression for next attempt
                    s_readySuppressCount = 0;
                    // Fall through to actually send
                }
            } else if (pktType == 3 && !g_sentCarData && g_weAreHost) {
                // Host without CAR_DATA - unusual but let it through
                LOG("[UDP-RELAY] WARNING: HOST sending READY without CAR_DATA (allowed)");
            } else if (pktType == 3 && g_sentCarData) {
                // Normal case - READY with CAR_DATA
                LOG("[UDP-RELAY] Sending READY (CAR_DATA already sent - OK)");
                // Reset suppression counter
                s_readySuppressCount = 0;
            }
            
            // Reset tracking when new game starts (detected by BROADCAST to a new dest)
            // NOTE: Only reset on BROADCAST, NOT on HELLO!
            // HELLO is sent by host AFTER broadcast, so resetting on HELLO would clear g_weAreHost
            // which breaks host logic.
            if (pktType == 5) {
                if (g_sentCarData || s_readyWithoutCarDataCount > 0 || s_sentFullSyncBase) {
                    LOG("[UDP-RELAY] New game detected (BROADCAST) - resetting all sync tracking");
                }
                g_sentCarData = false;
                g_sentCarDataTypes[0] = g_sentCarDataTypes[1] = g_sentCarDataTypes[2] = g_sentCarDataTypes[3] = false;
                s_readyWithoutCarDataCount = 0;
                g_firstBroadcastRecvTime = 0;
                // DO NOT reset g_weAreHost here - it gets set to true right after this (line 2431)
                s_readySuppressCount = 0;
                s_firstReadySuppressTime = 0;
                // Reset SHORT SYNC_BASE suppression
                s_sentFullSyncBase = false;
                s_firstHelloAckRecvTime = 0;
                s_shortSyncBaseSuppressCount = 0;
                // Reset host peer registration for new session
                g_hostPeerRegistered = false;
                LOG("[UDP-RELAY] Reset g_hostPeerRegistered for new session");
            }
            // Reset joiner-specific state on HELLO (but preserve g_weAreHost!)
            if (pktType == 1 && !g_weAreHost) {
                // Only reset joiner state if we are NOT the host
                // This handles joiner reconnecting to a new host
                if (g_sentCarData || s_readyWithoutCarDataCount > 0 || s_sentFullSyncBase) {
                    LOG("[UDP-RELAY] Joiner detected new session (HELLO) - resetting sync tracking");
                }
                g_sentCarData = false;
                g_sentCarDataTypes[0] = g_sentCarDataTypes[1] = g_sentCarDataTypes[2] = g_sentCarDataTypes[3] = false;
                s_readyWithoutCarDataCount = 0;
                g_firstBroadcastRecvTime = 0;
                s_readySuppressCount = 0;
                s_firstReadySuppressTime = 0;
                s_sentFullSyncBase = false;
                s_firstHelloAckRecvTime = 0;
                s_shortSyncBaseSuppressCount = 0;
            }
            
            // ================================================================
            // USE TCP TUNNEL FOR UDP RELAY (more reliable than raw UDP)
            // ================================================================
            int tcpResult = SendUdpViaTunnel(destPort, destAddr->sin_addr.s_addr, buf, len);
            if (tcpResult >= 0) {
                LOG("[UDP-TUNNEL] Sent via TCP tunnel: %d bytes to %s:%d", tcpResult, destIPStr, destPort);
                return len;  // Success
            }
            
            // TCP tunnel failed - fall back to UDP relay
            LOG("[UDP-TUNNEL] TCP tunnel failed, falling back to UDP relay");
            
            // Build relay packet: [2 bytes dest port][4 bytes dest IP][payload]
            // sin_port is already in network byte order, copy directly
            memcpy(g_relayBuffer, &destAddr->sin_port, 2);         // Port (2 bytes, network order)
            memcpy(g_relayBuffer + 2, &destAddr->sin_addr.s_addr, 4);  // IP (4 bytes)
            memcpy(g_relayBuffer + 6, buf, len);  // Payload
            
            // Setup relay server destination
            g_relayDest.sin_family = AF_INET;
            g_relayDest.sin_addr.s_addr = g_serverIP;
            g_relayDest.sin_port = htons(RELAY_PORT);
            
            // DEBUG: Log where we're actually sending
            char relayIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &g_relayDest.sin_addr, relayIPStr, sizeof(relayIPStr));
            LOG("[UDP-DEBUG] SEND to relay %s:%d (g_serverIP=0x%08X), header dest=%s:%d",
                relayIPStr, RELAY_PORT, g_serverIP, destIPStr, destPort);
            
            // IMPORTANT: Use g_gameSocket if captured, otherwise use sock from structure
            // g_gameSocket is the UDP socket that was bound for P2P communication
            SOCKET udpSock = (g_gameSocket != INVALID_SOCKET) ? g_gameSocket : sock;
            
            LOG("[UDP-DEBUG] Using socket %d for sendto (g_gameSocket=%d, struct sock=%d)",
                (int)udpSock, (int)g_gameSocket, (int)sock);
            
            // IMPORTANT: Call sendto() DIRECTLY instead of original function!
            // Original sub_74A5C0 calls sub_74A030() which may modify destination address.
            // We need to bypass that and send directly to relay server.
            int result = sendto(udpSock, g_relayBuffer, len + 6, 0,
                               reinterpret_cast<sockaddr*>(&g_relayDest), sizeof(g_relayDest));
            
            // Handle errors like original function does
            if (result < 0) {
                int err = WSAGetLastError();
                switch (err) {
                    case WSAEWOULDBLOCK:  // 10035
                    case WSAECONNRESET:   // 10054
                        return 0;
                    case WSAENETUNREACH:  // 10051
                    case WSAEHOSTUNREACH: // 10065
                        return -5;
                    case WSAENOTCONN:     // 10057
                        return -2;
                    case WSAECONNREFUSED: // 10061
                        return -6;
                    default:
                        return -7;
                }
            }
            
            // Adjust result to reflect original payload length
            if (result == len + 6) {
                return len;  // Success - return original length
            } else if (result > 0) {
                return result - 6;  // Partial send - return payload bytes sent
            }
            return result;
        }
#endif
        
        // Log only if it's our tracked socket or any traffic (TCP or non-relay)
        if (len > 0) {
            LOG(">>> GAME SEND: %d bytes (socket %d, to=%p)", len, (int)sock, to);
            LogTrafficRaw(">>> CLIENT SEND", buf, len);
        }
        
        // Call original via trampoline
        typedef int(__cdecl* OrigFunc_t)(int, const char*, int, int, sockaddr*, int);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp74A5C0.code[0]);
        int result = origFunc(a1, buf, len, a4, to, tolen);
        
        if (len > 0 && result != len) {
            LOG("    Send result: %d (expected %d)", result, len);
        }
        
        return result;
    }
    
    // ========================================================================
    // Hook for game's recv wrapper (sub_74A6D0)
    // int __cdecl sub_74A6D0(int socketStruct, char* buf, int len, char a4, sockaddr* from, int* fromlen)
    // 
    // CRITICAL: This function is called for both TCP and UDP!
    // For UDP packets from relay server, we must strip the 6-byte relay header
    // and update the 'from' address with the real peer address.
    // ========================================================================
    // Counter for recv hook calls
    inline int g_recvHookCallCount = 0;
    
    inline int __cdecl Hook_GameRecv(int a1, char* buf, int len, char a4, sockaddr* from, int* fromlen) {
        // *** VERY FIRST LOG - proves hook is called ***
        static bool s_firstCall = true;
        static int s_recvCallCount = 0;
        static DWORD s_lastRecvStatusLog = 0;
        
        s_recvCallCount++;
        
        if (s_firstCall) {
            s_firstCall = false;
            LOG("*** Hook_GameRecv FIRST CALL! a1=0x%08X, buf=%p, len=%d, from=%p ***", a1, buf, len, from);
        }
        
        // Periodic status every 3 seconds (reduced from 5)
        DWORD now = GetTickCount();
        if (now - s_lastRecvStatusLog >= 3000) {
            s_lastRecvStatusLog = now;
            LOG("[RECV-STATUS] calls=%d, tunnel=%d, game=%d, CS=%d, host=%d, peerReg=%d, queueCount=%d",
                s_recvCallCount, (int)g_udpTunnelSocket, (int)g_gameSocket, 
                g_udpTunnelCSInitialized ? 1 : 0, g_weAreHost ? 1 : 0, g_hostPeerRegistered ? 1 : 0,
                g_udpTunnelQueueCount);
        }
        
        // Get socket from structure
        SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
        
        // Debug: log recv calls on host to understand why tunnel data isn't received
        static DWORD s_lastRecvDebugLog = 0;
        DWORD nowRecv = GetTickCount();
        if (g_weAreHost && nowRecv - s_lastRecvDebugLog >= 2000) {
            s_lastRecvDebugLog = nowRecv;
            LOG("[HOST-RECV-DEBUG] Hook_GameRecv: sock=%d, g_gameSocket=%d, from=%p, tunnelSocket=%d, CSinit=%d",
                (int)sock, (int)g_gameSocket, from, (int)g_udpTunnelSocket, g_udpTunnelCSInitialized ? 1 : 0);
        }
        
#if !UDP_CAPTURE_ONLY
        // ================================================================
        // CHECK TCP TUNNEL FOR UDP PACKETS FIRST
        // This is more reliable than raw UDP for NAT traversal
        // Only check if:
        // 1. This is a UDP call (from != nullptr)
        // 2. We have captured the game socket AND this is that socket
        // 3. Critical section is initialized
        // ================================================================
        if (from != nullptr && 
            g_gameSocket != INVALID_SOCKET && 
            sock == g_gameSocket &&
            g_udpTunnelCSInitialized) {
            
            uint16_t srcPort = 0;
            uint32_t srcIP = 0;
            int payloadLen = 0;
            
            // Try to receive from TCP tunnel
            if (RecvUdpFromTunnel(&srcPort, &srcIP, buf, &payloadLen, len)) {
                // Got packet from TCP tunnel!
                sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
                memset(srcAddr, 0, sizeof(sockaddr_in));
                srcAddr->sin_family = AF_INET;
                srcAddr->sin_addr.s_addr = srcIP;
                srcAddr->sin_port = htons(srcPort);
                
                if (fromlen) {
                    *fromlen = sizeof(sockaddr_in);
                }
                
                char srcIPStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &srcIP, srcIPStr, sizeof(srcIPStr));
                
                // Determine packet type for logging
                // NOTE: Our tunnel packets use [type:4 LE][sessionId:4 LE][data...]
                // But SYNC packets (types 101-120) from host may use different format:
                //   - [type:1][data...] - bitstream format where first byte is type
                // So we check: if first DWORD > 100, try reading first byte as type
                uint32_t pktType = 0;
                uint8_t firstByte = (payloadLen >= 1) ? (uint8_t)buf[0] : 0;
                uint32_t firstDword = (payloadLen >= 4) ? *reinterpret_cast<uint32_t*>(buf) : 0;
                
                // If firstDword looks like a valid small type (1-20), use it
                // Otherwise, if firstByte looks like SYNC type (101-120), use firstByte
                if (firstDword >= 1 && firstDword <= 120) {
                    pktType = firstDword;
                } else if (firstByte >= 101 && firstByte <= 120) {
                    // SYNC packet in bitstream format - first byte is type
                    pktType = firstByte;
                } else {
                    // Unknown format - use first DWORD but log warning
                    pktType = firstDword;
                }
                
                // Detailed type names
                const char* pktTypeName = "UNKNOWN";
                switch(pktType) {
                    case 1: pktTypeName = "HELLO/PROBE"; break;
                    case 2: pktTypeName = "HELLO_ACK"; break;
                    case 3: pktTypeName = "READY"; break;
                    case 4: pktTypeName = "ACK"; break;
                    case 5: pktTypeName = "BROADCAST"; break;
                    case 8: pktTypeName = "HEARTBEAT"; break;
                    case 12: pktTypeName = "STATE_SYNC"; break;
                    case 13: pktTypeName = "SESSION_STATE"; break;
                    case 101: pktTypeName = "SYNC_BASE"; break;
                    case 102: pktTypeName = "CAR_DATA_1"; break;
                    case 103: pktTypeName = "CAR_DATA_2"; break;
                    case 104: pktTypeName = "CAR_DATA_3"; break;
                    case 105: pktTypeName = "CAR_DATA_4"; break;
                    case 107: case 108: case 109: case 110:
                    case 111: case 112: case 113: case 114:
                    case 115: case 116: case 117: case 118:
                        pktTypeName = "SYNC_DATA"; break;
                }
                
                LOG("[UDP-TUNNEL-RECV] %d bytes from %s:%d, type=%u (%s) -> RETURNED TO GAME", 
                    payloadLen, srcIPStr, srcPort, pktType, pktTypeName);
                
                // Track received car data and BROADCAST timing
                static bool s_receivedCarData[4] = {false, false, false, false};
                static bool s_receivedBroadcast = false;
                static DWORD s_receivedBroadcastTime = 0;
                static int s_broadcastCount = 0;
                
                // Track received HELLO for sync debugging
                static bool s_receivedHelloFromHost = false;
                static DWORD s_firstHelloFromHostTime = 0;
                
                if (pktType == 1 && !g_weAreHost) {
                    // We are joiner and received HELLO - this triggers CAR_DATA generation!
                    if (!s_receivedHelloFromHost) {
                        s_receivedHelloFromHost = true;
                        s_firstHelloFromHostTime = GetTickCount();
                        LOG("[UDP-TUNNEL-RECV] >>> CRITICAL: Received HELLO from host! This should trigger CAR_DATA generation.");
                    }
                    LOG("[UDP-TUNNEL-RECV] >>> HELLO from peer (first at %dms ago) - game's sub_58C420 should process this", 
                        s_firstHelloFromHostTime ? (GetTickCount() - s_firstHelloFromHostTime) : 0);
                }
                
                if (pktType == 5) {
                    s_broadcastCount++;
                    if (!s_receivedBroadcast) {
                        s_receivedBroadcast = true;
                        s_receivedBroadcastTime = GetTickCount();
                        // Set GLOBAL variable so sendto hook knows when we received BROADCAST
                        g_firstBroadcastRecvTime = s_receivedBroadcastTime;
                        
                        // CRITICAL: Save host address for sending CAR_DATA later!
                        g_lastRecvIP = srcIP;
                        g_lastRecvPort = srcPort;
                        
                        char hostIPStr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &srcIP, hostIPStr, sizeof(hostIPStr));
                        LOG("[UDP-TUNNEL-RECV] >>> Saved host address: %s:%d", hostIPStr, srcPort);
                    }
                    LOG("[UDP-TUNNEL-RECV] >>> Received BROADCAST #%d from host (first at %dms ago) - game should start loading car data", 
                        s_broadcastCount, s_receivedBroadcastTime ? (GetTickCount() - s_receivedBroadcastTime) : 0);
                    
                    // DISABLED: Registering fake peer causes CRASH!
                    // 
                    // Problem: RegisterHostAsPeer creates fake peer with peer struct ID (small number like 5)
                    // Later, game calls sub_58C620 (disconnect) -> sub_6099C0(peerStruct, ...)
                    // sub_6099C0 treats peerStruct as pointer: *(peerStruct + offset) -> CRASH!
                    //
                    // Solution: Don't register fake peer. Instead:
                    // 1. CAR_DATA is sent via tunnel in Hook_587DB0 (already works)
                    // 2. Type 8 heartbeat is sent via tunnel in this recv hook (already works)
                    // 3. Packets are returned to game via recvfrom hook (already works)
                    //
                    // if (!g_peerRegistered) {
                    //     LOG("[UDP-TUNNEL-RECV] >>> Attempting to register host as peer for CAR_DATA sending...");
                    //     DumpPeerArray();
                    //     if (RegisterHostAsPeer(0)) {
                    //         LOG("[UDP-TUNNEL-RECV] >>> Host registered successfully!");
                    //         DumpPeerArray();
                    //     } else {
                    //         LOG("[UDP-TUNNEL-RECV] >>> FAILED to register host as peer!");
                    //     }
                    // }
                    LOG("[UDP-TUNNEL-RECV] >>> NOT registering fake peer (causes crash on disconnect)");
                    LOG("[UDP-TUNNEL-RECV] >>> Session state: dword_866A14=%d, player count dword_7FBDB8=%d",
                        *(int*)0x866A14, *(int*)0x7FBDB8);
                    DumpPeerArray();  // Still dump for debugging
                    
                    // CRITICAL FIX: Initialize joiner session state!
                    // On joiner, dword_866A14 stays 0 because sub_58F490 is only called on host.
                    // Without session state >= 1, the state machine doesn't work and
                    // joiner never sends type 12 (state sync) to host.
                    //
                    // We need to initialize session when receiving BROADCAST from host:
                    // 1. Set dword_866A14 = 1 (session active)
                    // 2. Generate our peer ID if not set
                    // 3. Increment player count
                    
                    static bool s_joinerSessionInitialized = false;
                    if (!s_joinerSessionInitialized && !g_weAreHost) {
                        s_joinerSessionInitialized = true;
                        
                        int currentState = *(int*)0x866A14;
                        int currentPeerID = *(int*)0x7FBE80;
                        int currentPlayerCount = *(int*)0x7FBDB8;
                        
                        LOG("[JOINER-INIT] >>> Initializing joiner session...");
                        LOG("[JOINER-INIT] >>> Before: state=%d, peerID=0x%X, players=%d",
                            currentState, currentPeerID, currentPlayerCount);
                        
                        // CRITICAL FIX: Initialize race on joiner side!
                        // When host sends BROADCAST, it means host already did sub_5F9250 (race init)
                        // and is waiting for joiner to be ready. We must:
                        // 1. Call sub_5F9250 to initialize race data
                        // 2. Set session state to match host's expectations
                        // 3. Send TYPE 12 with appropriate state
                        
                        // First, initialize race by calling sub_5F9250(&dword_89CF48)
                        // NOTE: 0x89CF48 is the ADDRESS of the race data structure
                        // sub_5F9250 is __thiscall so 'this' pointer goes in ECX
                        LOG("[JOINER-INIT] >>> Calling sub_5F9250(0x89CF48) to initialize race...");
                        
                        // Cast to __thiscall with this pointer
                        typedef int(__thiscall* Sub5F9250_t)(void* thisPtr);
                        Sub5F9250_t initRace = (Sub5F9250_t)0x5F9250;
                        
                        __try {
                            // Pass the ADDRESS 0x89CF48 as 'this' pointer
                            initRace((void*)0x89CF48);
                            LOG("[JOINER-INIT] >>> sub_5F9250 completed - race initialized!");
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            // Exception likely means race data not ready yet - this is expected
                            // when joining because host's BROADCAST may arrive before track is loaded
                            LOG("[JOINER-INIT] >>> sub_5F9250 threw exception - race data may not be ready yet");
                            LOG("[JOINER-INIT] >>> This is expected, will continue without race init");
                        }
                        
                        // Set game state to 4 (race preparing) - this is what sub_585E10(4) does
                        int gameState = *(int*)0x8669F4;
                        if (gameState < 4) {
                            *(int*)0x8669F4 = 4;
                            LOG("[JOINER-INIT] >>> Set game state dword_8669F4 = 4 (race preparing)");
                        }
                        
                        // Set session state to 6 (ready for countdown)
                        // This is what host expects to see in peer's TYPE 12 packets
                        // Host's sub_58EBC0 case 4: if peer_state == 6 for all peers -> state 5
                        if (currentState < 6) {
                            *(int*)0x866A14 = 6;
                            LOG("[JOINER-INIT] >>> Set session state dword_866A14 = 6 (ready for countdown)");
                        }
                        
                        // Generate peer ID if not set
                        if (currentPeerID == -1 || currentPeerID == 0xFFFFFFFF) {
                            typedef int(__cdecl* GenPeerId_t)();
                            GenPeerId_t genPeerId = (GenPeerId_t)0x586010;
                            int newPeerID = genPeerId();
                            *(int*)0x7FBE80 = newPeerID;
                            LOG("[JOINER-INIT] >>> Generated new peer ID: 0x%X", newPeerID);
                        }
                        
                        // Increment player count (we are joining, so +1)
                        // CRITICAL FIX: Player count for joiner should be 1 (just the host peer)
                        // The sub_58EBC0 state machine checks: (ready peers count) == player count
                        // If player count = 2 but we only have 1 peer in array, condition fails!
                        // 
                        // In original P2P, host adds joiner to peer array, so host has 1 peer.
                        // Joiner adds host to peer array, so joiner also has 1 peer.
                        // Player count for session state machine = number of OTHER players = 1
                        *(int*)0x7FBDB8 = 1;  // Just the host (our only peer)
                        LOG("[JOINER-INIT] >>> Set player count to 1 (host is our only peer)");
                        
                        LOG("[JOINER-INIT] >>> After: state=%d, peerID=0x%X, players=%d",
                            *(int*)0x866A14, *(int*)0x7FBE80, *(int*)0x7FBDB8);
                        
                        // Now trigger state sync by calling sub_5883E0(12)
                        // This sends type 12 with our state to host
                        LOG("[JOINER-INIT] >>> Sending type 12 state sync to host...");
                        
                        // Build and send type 12 packet manually via tunnel
                        // 
                        // Packet format (based on bitstream analysis):
                        // - First 8 bits: packet type (12 = 0x0C)
                        // - Next 32 bits: state value
                        // 
                        // Looking at actual packets in logs (type 8):
                        //   08 00 00 00 64 00 00 00
                        // This appears to be: [type:1][padding:3][sessionId:4]
                        // 
                        // For type 12, game expects:
                        //   0C xx xx xx yy yy yy yy
                        // Where xx = padding(?), yy = state (32 bits)
                        //
                        // Actually simpler: just send like other packets
                        // [type:4 LE][sessionId:4 LE][state:4 LE]
                        
                        uint8_t type12Packet[12];
                        memset(type12Packet, 0, sizeof(type12Packet));
                        
                        // Type (DWORD, little-endian)
                        type12Packet[0] = 12;  // type = 12
                        type12Packet[1] = 0;
                        type12Packet[2] = 0;
                        type12Packet[3] = 0;
                        
                        // Session ID (DWORD, little-endian) = 100
                        type12Packet[4] = 0x64;
                        type12Packet[5] = 0;
                        type12Packet[6] = 0;
                        type12Packet[7] = 0;
                        
                        // State (DWORD, little-endian) = 6 (ready for countdown)
                        // Host's sub_58EBC0 case 4 checks: peer_state == 6
                        // Only when all peers have state 6, host transitions to state 5 (countdown)
                        type12Packet[8] = 6;
                        type12Packet[9] = 0;
                        type12Packet[10] = 0;
                        type12Packet[11] = 0;
                        
                        LOG("[JOINER-INIT] >>> Sending type 12 packet: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
                            type12Packet[0], type12Packet[1], type12Packet[2], type12Packet[3],
                            type12Packet[4], type12Packet[5], type12Packet[6], type12Packet[7],
                            type12Packet[8], type12Packet[9], type12Packet[10], type12Packet[11]);
                        
                        int sent = SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, (char*)type12Packet, 12);
                        if (sent > 0) {
                            LOG("[JOINER-INIT] >>> Sent type 12 state=6 to host via tunnel!");
                        } else {
                            LOG("[JOINER-INIT] >>> FAILED to send type 12!");
                        }
                        
                        // Also send multiple times for reliability
                        for (int retry = 0; retry < 3; retry++) {
                            Sleep(100);
                            SendUdpViaTunnel(g_lastRecvPort, g_lastRecvIP, (char*)type12Packet, 12);
                        }
                        LOG("[JOINER-INIT] >>> Sent type 12 x4 times for reliability");
                    }
                }
                if (pktType >= 102 && pktType <= 105) {
                    s_receivedCarData[pktType - 102] = true;
                    LOG("[UDP-TUNNEL-RECV] >>> Received CAR_DATA_%d from peer (recv: 102=%d 103=%d 104=%d 105=%d)", 
                        pktType - 101,
                        s_receivedCarData[0], s_receivedCarData[1], s_receivedCarData[2], s_receivedCarData[3]);
                    
                    // Parse CAR_DATA structure for debugging
                    // Format: [type:4][sessionId:4][flag1:1][partNum:1][totalParts:1][flag2:1][data...]
                    if (payloadLen >= 12) {
                        uint8_t flag1 = buf[8];
                        uint8_t partNum = buf[9];
                        uint8_t totalParts = buf[10];
                        uint8_t flag2 = buf[11];
                        LOG("[UDP-TUNNEL-RECV] >>> CAR_DATA structure: flag1=%d, part=%d/%d, flag2=%d, dataLen=%d",
                            flag1, partNum, totalParts, flag2, payloadLen - 12);
                    }
                    
                    // CRITICAL: Save host address EARLY (at first CAR_DATA) so we can send our CAR_DATA back!
                    // sub_587DB0 is called right after receiving CAR_DATA, BEFORE BROADCAST arrives.
                    if (g_lastRecvIP == 0) {
                        g_lastRecvIP = srcIP;
                        g_lastRecvPort = srcPort;
                        char hostIPStr[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, &srcIP, hostIPStr, sizeof(hostIPStr));
                        LOG("[UDP-TUNNEL-RECV] >>> EARLY: Saved host address: %s:%d (for CAR_DATA sending)", hostIPStr, srcPort);
                    }
                }
                if (pktType == 3) {
                    DWORD timeSinceBroadcast = s_receivedBroadcastTime ? (GetTickCount() - s_receivedBroadcastTime) : 0;
                    LOG("[UDP-TUNNEL-RECV] >>> Received READY from peer");
                    LOG("[UDP-TUNNEL-RECV] >>> RECV car data status: 102=%d 103=%d 104=%d 105=%d", 
                        s_receivedCarData[0], s_receivedCarData[1], s_receivedCarData[2], s_receivedCarData[3]);
                    LOG("[UDP-TUNNEL-RECV] >>> Time since first BROADCAST: %dms", timeSinceBroadcast);
                    LOG("[UDP-TUNNEL-RECV] >>> Session state: dword_866A14=%d, player count dword_7FBDB8=%d, weAreHost=%d",
                        *(int*)0x866A14, *(int*)0x7FBDB8, g_weAreHost ? 1 : 0);
                }
                
                // Log hex for all packets (more detailed)
                static int s_tunnelRecvCount = 0;
                s_tunnelRecvCount++;
                if (s_tunnelRecvCount <= 50 || (pktType >= 101 && pktType <= 105)) {
                    char hexBuf[128];
                    int hexLen = 0;
                    int dumpLen = (payloadLen < 32) ? payloadLen : 32;
                    for (int i = 0; i < dumpLen && hexLen < 120; i++) {
                        hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
                    }
                    LOG("[UDP-TUNNEL-RECV] HEX: %s", hexBuf);
                }
                
                // SPECIAL LOGGING FOR HOST
                // Host needs to see packets from joiner and process them
                if (g_weAreHost) {
                    // CRITICAL: Save/update joiner's IP address so we can send packets back!
                    // Always update on valid packets from joiner.
                    if (srcIP != 0) {
                        if (g_lastRecvIP != srcIP || g_lastRecvPort != srcPort) {
                            char joinerIPStr[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &srcIP, joinerIPStr, sizeof(joinerIPStr));
                            LOG("[HOST-RECV] >>> %s JOINER ADDRESS: %s:%d (for sending packets)", 
                                g_lastRecvIP == 0 ? "SAVED" : "UPDATED", joinerIPStr, srcPort);
                        }
                        g_lastRecvIP = srcIP;
                        g_lastRecvPort = srcPort;
                    }
                    
                    LOG("[HOST-RECV] HOST received type %d (%s) from joiner, size=%d",
                        pktType, pktTypeName, payloadLen);
                    
                    // Log session state on host
                    static DWORD s_lastHostStateLog = 0;
                    DWORD now = GetTickCount();
                    if (now - s_lastHostStateLog >= 1000 || pktType == 12 || pktType == 3) {
                        s_lastHostStateLog = now;
                        LOG("[HOST-STATE] Session: dword_866A14=%d, players=%d, peerID=0x%X",
                            *(int*)0x866A14, *(int*)0x7FBDB8, *(int*)0x7FBE80);
                        
                        // Dump first peer slot
                        int* peerArray = (int*)0x8693C8;
                        LOG("[HOST-STATE] Peer slot 0: struct=0x%08X, idx=%d, state=%d",
                            peerArray[0], peerArray[1], peerArray[4]);
                    }
                }
                
                // ANALYSIS from testing:
                // - Calling dispatcher directly WORKS (HELLO handler called, CAR_DATA accum returned 1)
                // - But game CRASHED after sub_58C420 completed!
                // - Crash likely in sub_587DB0 (CAR_DATA generation) or sub_588350 (send to peers)
                //
                // Hypothesis: peer index 0 is wrong, or player data structure not initialized
                //
                // Let's try to find the correct peer index from the connection array.
                // Array at dword_8691D0, 5 entries, 20 bytes each:
                //   [0] = state (3 = active/receiving)
                //   [1] = peer index  
                //   [2] = unknown
                //   [3] = connection struct ptr
                //   [4] = unknown
                
                // NOTE: firstByte already defined above for packet type detection
                
                // Handle packet types 1-17 (control) and 102-105 (CAR_DATA via tunnel)
                if ((firstByte >= 1 && firstByte <= 17) || (firstByte >= 102 && firstByte <= 105)) {
                    // Try to find correct peer index by scanning connection array
                    int foundPeerIdx = -1;
                    int* connArray = (int*)0x8691D0;
                    
                    for (int i = 0; i < 5; i++) {
                        int state = connArray[i * 5 + 0];
                        int peerIdx = connArray[i * 5 + 1];
                        int connPtr = connArray[i * 5 + 3];
                        
                        // State 3 = active connection receiving data
                        if (state == 3 && peerIdx >= 0 && peerIdx < 6) {
                            foundPeerIdx = peerIdx;
                            LOG("[UDP-TUNNEL-PEER] Found active peer: entry=%d, state=%d, peerIdx=%d, connPtr=0x%08X",
                                i, state, peerIdx, connPtr);
                            break;
                        }
                    }
                    
                    if (foundPeerIdx >= 0) {
                        // Found valid peer in CONNECTION array
                        // CRITICAL FIX: Check if peer is also in PEER array!
                        // Connection array can be filled by game but peer array may be empty.
                        // Dispatcher will crash if peer array is empty!
                        int* peerArray = (int*)0x8693C8;
                        bool peerInPeerArray = false;
                        for (int i = 0; i < 5; i++) {
                            if (peerArray[i * 8 + 1] == foundPeerIdx) {
                                peerInPeerArray = true;
                                break;
                            }
                        }
                        
                        if (!peerInPeerArray && !g_hostPeerRegistered && g_weAreHost) {
                            // Peer in connection array but NOT in peer array!
                            // Need to call sub_58C360 to register properly.
                            LOG("[HOST-PEER] >>> Peer %d in connection array but NOT in peer array - registering...", foundPeerIdx);
                            
                            // Save joiner IP first
                            if (g_lastRecvIP == 0 && srcIP != 0) {
                                g_lastRecvIP = srcIP;
                                g_lastRecvPort = srcPort;
                            }
                            
                            typedef void(__cdecl* RegisterPeer_t)(int);
                            RegisterPeer_t registerPeer = (RegisterPeer_t)0x58C360;
                            
                            __try {
                                registerPeer(foundPeerIdx);
                                g_hostPeerRegistered = true;
                                LOG("[HOST-PEER] >>> sub_58C360(%d) completed - peer registered!", foundPeerIdx);
                                
                                // Set player count
                                *(int*)0x7FBDB8 = 1;
                                
                                // Ensure session state is at least 1
                                if (*(int*)0x866A14 < 1) {
                                    *(int*)0x866A14 = 1;
                                }
                                
                                // Log peer count
                                int peerCount866A24 = *(int*)0x866A24;
                                LOG("[HOST-PEER] >>> Session: state=%d, players=%d, dword_866A24=%d",
                                    *(int*)0x866A14, *(int*)0x7FBDB8, peerCount866A24);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER) {
                                LOG("[HOST-PEER] *** EXCEPTION in sub_58C360! ***");
                            }
                        }
                        
                        // Now try calling dispatcher
                        typedef int(__cdecl* Dispatcher_t)(int peerIdx, const void* data, unsigned int size, char flag);
                        Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                        
                        LOG("[UDP-TUNNEL-DISPATCH] Calling dispatcher for type %d (%s), size %d, peer %d", 
                            firstByte, pktTypeName, payloadLen, foundPeerIdx);
                        
                        __try {
                            int dispResult = dispatcher(foundPeerIdx, buf, payloadLen, 0);
                            LOG("[UDP-TUNNEL-DISPATCH] Dispatcher returned %d", dispResult);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            LOG("[UDP-TUNNEL-DISPATCH] *** EXCEPTION in dispatcher! ***");
                        }
                        
                        // CRITICAL: For type 8 (heartbeat), send response back to keep connection alive!
                        // This is needed because joiner's sub_586120 won't be called (no real connection)
                        if (firstByte == 8 && !g_weAreHost && g_udpTunnelSocket != INVALID_SOCKET && srcIP != 0) {
                            static DWORD s_lastType8Response = 0;
                            DWORD now = GetTickCount();
                            // Send type 8 response every 100ms max
                            if (now - s_lastType8Response >= 100) {
                                s_lastType8Response = now;
                                uint8_t response[8] = {0x08, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00};
                                int sent = SendUdpViaTunnel(srcPort, srcIP, (char*)response, 8);
                                if (sent > 0) {
                                    LOG("[UDP-TUNNEL-DISPATCH] >>> Sent type 8 heartbeat response to host");
                                }
                            }
                        }
                    } 
                    // ============================================================
                    // CASE 0.5: We are HOST and peer is already registered in PEER array
                    // (but NOT in connection array - tunnel mode)
                    // ============================================================
                    else if (g_weAreHost && g_hostPeerRegistered && 
                             ((firstByte >= 1 && firstByte <= 17) || (firstByte >= 101 && firstByte <= 105))) {
                        // Peer registered in peer array but not in connection array
                        // Types 1-17 are control packets, 101-105 are sync/CAR_DATA
                        // Find peer in PEER array and dispatch
                        int* peerArray = (int*)0x8693C8;
                        int registeredPeerIdx = -1;
                        
                        for (int i = 0; i < 5; i++) {
                            if (peerArray[i * 8 + 1] != -1) {
                                registeredPeerIdx = peerArray[i * 8 + 1];
                                break;
                            }
                        }
                        
                        if (registeredPeerIdx >= 0) {
                            // Update peer timestamp to prevent timeout disconnect
                            for (int i = 0; i < 5; i++) {
                                if (peerArray[i * 8 + 1] == registeredPeerIdx) {
                                    peerArray[i * 8 + 7] = *(int*)0x8651AC;
                                    break;
                                }
                            }
                            
                            // CRITICAL FIX: Only dispatch SAFE packet types!
                            // Type 1 (HELLO) expects full CAR_DATA - only dispatch if packet is large (real CAR_DATA).
                            // Small type 1 packets (8 bytes) are probe/handshake and will hang sub_587DB0!
                            // Type 3 (sub_586060) dereferences peer struct which may be NULL.
                            // Type 8 (heartbeat) and Type 12 (state sync) are SAFE.
                            // Types 101-105 (CAR_DATA parts) should be dispatched for game to process.
                            bool safeToDispatch = (firstByte == 8 || firstByte == 12 || 
                                                   (firstByte >= 101 && firstByte <= 105) ||
                                                   (firstByte == 1 && payloadLen >= 20)); // Type 1 only if large enough
                            
                            if (safeToDispatch) {
                                LOG("[HOST-DISPATCH] Dispatching type %d to joiner peer %d (from peer array)", 
                                    firstByte, registeredPeerIdx);
                                
                                typedef int(__cdecl* Dispatcher_t)(int peerIdx, const void* data, unsigned int size, char flag);
                                Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                                
                                __try {
                                    int dispResult = dispatcher(registeredPeerIdx, buf, payloadLen, 0);
                                    LOG("[HOST-DISPATCH] Dispatcher returned %d", dispResult);
                                }
                                __except(EXCEPTION_EXECUTE_HANDLER) {
                                    LOG("[HOST-DISPATCH] *** EXCEPTION in dispatcher! ***");
                                }
                            } else {
                                LOG("[HOST-DISPATCH] Skipping type %d (unsafe to dispatch)", firstByte);
                            }
                            
                            // For type 12, manually update peer state
                            if (firstByte == 12 && payloadLen >= 12) {
                                const uint8_t* bytes = (const uint8_t*)buf;
                                int stateFromPacket = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
                                LOG("[HOST-TYPE12] Type 12 from joiner: state=%d", stateFromPacket);
                                
                                for (int i = 0; i < 5; i++) {
                                    if (peerArray[i * 8 + 1] == registeredPeerIdx) {
                                        int oldState = peerArray[i * 8 + 4];
                                        peerArray[i * 8 + 4] = stateFromPacket;
                                        LOG("[HOST-TYPE12] Peer slot %d state: %d -> %d", i, oldState, stateFromPacket);
                                        break;
                                    }
                                }
                            }
                        } else {
                            LOG("[HOST-DISPATCH] WARNING: Peer registered but not found in peer array!");
                        }
                    } else {
                        // NO active peer in connection array!
                        
                        // ============================================================
                        // CASE 1: We are HOST and received packet from JOINER
                        // ============================================================
                        // Host needs to register joiner as peer so dispatcher can handle packets.
                        // In normal UDP mode, sub_585990 callback registers peer when connection
                        // is established. In tunnel mode, we need to do this manually.
                        
                        // Use global g_hostPeerRegistered (reset when BROADCAST is sent)
                        if (g_weAreHost && !g_hostPeerRegistered && 
                            ((firstByte >= 1 && firstByte <= 17) || (firstByte >= 101 && firstByte <= 105))) {
                            // CRITICAL: Save joiner's IP BEFORE registering peer!
                            // sub_58C360 -> sub_589FA0 -> sub_586120 will try to send packets
                            // and needs g_lastRecvIP to know where to send them.
                            if (g_lastRecvIP == 0 && srcIP != 0) {
                                g_lastRecvIP = srcIP;
                                g_lastRecvPort = srcPort;
                                char joinerIPStr[INET_ADDRSTRLEN];
                                inet_ntop(AF_INET, &srcIP, joinerIPStr, sizeof(joinerIPStr));
                                LOG("[HOST-PEER] >>> SAVED JOINER ADDRESS EARLY: %s:%d", joinerIPStr, srcPort);
                            }
                            
                            // Check if peer already exists in peer array (game may have registered it)
                            int* peerArray = (int*)0x8693C8;
                            bool peerAlreadyExists = false;
                            for (int i = 0; i < 5; i++) {
                                if (peerArray[i * 8 + 1] != -1) {  // idx != -1
                                    peerAlreadyExists = true;
                                    LOG("[HOST-PEER] Peer already exists in slot %d (idx=%d), skipping registration",
                                        i, peerArray[i * 8 + 1]);
                                    break;
                                }
                            }
                            
                            g_hostPeerRegistered = true;
                            
                            if (peerAlreadyExists) {
                                LOG("[HOST-PEER] >>> Peer already registered by game, not calling sub_58C360");
                                
                                // Clean up any duplicate peer entries (same idx in multiple slots)
                                int seenIdx[5] = {-1, -1, -1, -1, -1};
                                int seenCount = 0;
                                int validPeerCount = 0;
                                for (int i = 0; i < 5; i++) {
                                    int idx = peerArray[i * 8 + 1];
                                    if (idx != -1) {
                                        // Check if we've seen this idx before
                                        bool duplicate = false;
                                        for (int j = 0; j < seenCount; j++) {
                                            if (seenIdx[j] == idx) {
                                                duplicate = true;
                                                break;
                                            }
                                        }
                                        if (duplicate) {
                                            LOG("[HOST-PEER] >>> Clearing DUPLICATE peer in slot %d (idx=%d)", i, idx);
                                            peerArray[i * 8 + 0] = -1;  // struct
                                            peerArray[i * 8 + 1] = -1;  // idx
                                            peerArray[i * 8 + 4] = 0;   // state
                                        } else {
                                            seenIdx[seenCount++] = idx;
                                            validPeerCount++;
                                        }
                                    }
                                }
                                
                                // Sync player count with actual peer count
                                int* playerCount = (int*)0x7FBDB8;
                                if (*playerCount != validPeerCount) {
                                    LOG("[HOST-PEER] >>> Syncing player count: %d -> %d", *playerCount, validPeerCount);
                                    *playerCount = validPeerCount;
                                }
                            } else {
                                LOG("[HOST-PEER] HOST received packet from joiner - registering peer...");
                            
                            // Call sub_58C360 to register peer properly
                            // This function:
                            // 1. Adds peer to peer array (sub_583A70)
                            // 2. Generates peer struct ID (sub_586010)
                            // 3. Sends sync packets (sub_588170, sub_589FA0)
                            typedef void(__cdecl* RegisterPeer_t)(int);
                            RegisterPeer_t registerPeer = (RegisterPeer_t)0x58C360;
                            
                            // Use peer index 0 for the joiner
                            int joinerPeerIdx = 0;
                            
                            LOG("[HOST-PEER] Calling sub_58C360(%d) to register joiner peer...", joinerPeerIdx);
                            
                            // Dump peer array BEFORE registration
                            LOG("[HOST-PEER] === BEFORE registration ===");
                            int* peerArrayBefore = (int*)0x8693C8;
                            for (int i = 0; i < 2; i++) {
                                LOG("[HOST-PEER] Peer slot %d: struct=0x%08X, idx=%d, state=%d, ts=%d",
                                    i, peerArrayBefore[i*8], peerArrayBefore[i*8+1], 
                                    peerArrayBefore[i*8+4], peerArrayBefore[i*8+7]);
                            }
                            
                            __try {
                                registerPeer(joinerPeerIdx);
                                LOG("[HOST-PEER] >>> sub_58C360 returned!");
                                
                                // Dump peer array AFTER registration
                                LOG("[HOST-PEER] === AFTER registration ===");
                                for (int i = 0; i < 2; i++) {
                                    LOG("[HOST-PEER] Peer slot %d: struct=0x%08X, idx=%d, state=%d, ts=%d",
                                        i, peerArrayBefore[i*8], peerArrayBefore[i*8+1], 
                                        peerArrayBefore[i*8+4], peerArrayBefore[i*8+7]);
                                }
                                
                                // Check what sub_586010 generates
                                typedef int(__cdecl* GenPeerId_t)();
                                GenPeerId_t genPeerId = (GenPeerId_t)0x586010;
                                int testId = genPeerId();
                                LOG("[HOST-PEER] >>> Test: sub_586010() returns 0x%08X", testId);
                                
                                LOG("[HOST-PEER] >>> Joiner peer registered successfully!");
                                
                                // Set player count to 1 (only 1 other peer)
                                // sub_58EBC0 checks: ready_peers == player_count
                                // We have 1 peer, so player_count should be 1
                                int* playerCount = (int*)0x7FBDB8;
                                *playerCount = 1;
                                LOG("[HOST-PEER] >>> Player count set to 1 (one joiner peer)");
                                
                                // Ensure session state is 1 (active)
                                int* sessionState = (int*)0x866A14;
                                if (*sessionState < 1) {
                                    *sessionState = 1;
                                    LOG("[HOST-PEER] >>> Session state set to 1 (active)");
                                }
                                // Log dword_866A24 (peer count for state machine)
                                int peerCount866A24 = *(int*)0x866A24;
                                LOG("[HOST-PEER] >>> Session state: %d, player count: %d, dword_866A24: %d", 
                                    *sessionState, *playerCount, peerCount866A24);
                                
                                // Dump peer array to verify
                                DumpPeerArray();
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER) {
                                LOG("[HOST-PEER] *** EXCEPTION registering joiner peer! ***");
                                g_hostPeerRegistered = false;  // Allow retry
                            }
                            }  // end else (peer doesn't exist)
                        }
                        
                        // After registration, try to dispatch again
                        if (g_weAreHost && g_hostPeerRegistered) {
                            // Re-scan peer array for peer
                            int newFoundPeerIdx = -1;
                            int* peerArray = (int*)0x8693C8;
                            int peerSlot = -1;
                            
                            for (int i = 0; i < 5; i++) {
                                if (peerArray[i * 8 + 1] != -1) {
                                    newFoundPeerIdx = peerArray[i * 8 + 1];
                                    peerSlot = i;
                                    LOG("[HOST-PEER] Found peer in peer array: slot=%d, idx=%d, struct=0x%08X, state=%d",
                                        i, newFoundPeerIdx, peerArray[i * 8], peerArray[i * 8 + 4]);
                                    
                                    // WORKAROUND: If peer state is 0, set it to 3 (ready)
                                    // This is needed because host may not receive type 12 from joiner
                                    // due to tunnel issues, but joiner has already sent CAR_DATA
                                    if (peerArray[i * 8 + 4] < 3) {
                                        LOG("[HOST-PEER] >>> WORKAROUND: Setting peer state from %d to 3 (ready)", 
                                            peerArray[i * 8 + 4]);
                                        peerArray[i * 8 + 4] = 3;
                                        
                                        // Log state for session state machine check
                                        int readyPeers = 0;
                                        for (int j = 0; j < 5; j++) {
                                            if (peerArray[j * 8 + 1] != -1 && peerArray[j * 8 + 4] >= 3) {
                                                readyPeers++;
                                            }
                                        }
                                        int playerCount = *(int*)0x7FBDB8;
                                        int sessionState = *(int*)0x866A14;
                                        LOG("[HOST-PEER] >>> State machine check: readyPeers=%d, playerCount=%d, sessionState=%d",
                                            readyPeers, playerCount, sessionState);
                                        LOG("[HOST-PEER] >>> Condition for race start: readyPeers(%d) == playerCount(%d) && playerCount > 0 = %s",
                                            readyPeers, playerCount, (readyPeers == playerCount && playerCount > 0) ? "TRUE" : "FALSE");
                                    }
                                    break;
                                }
                            }
                            
                            if (newFoundPeerIdx >= 0) {
                                // CRITICAL: Update peer timestamp on EVERY packet from joiner!
                                // This prevents timeout disconnect (sub_58EBC0 checks peer[7] timestamp).
                                for (int i = 0; i < 5; i++) {
                                    if (peerArray[i * 8 + 1] == newFoundPeerIdx) {
                                        peerArray[i * 8 + 7] = *(int*)0x8651AC; // Update timestamp
                                        break;
                                    }
                                }
                                
                                // ============================================================
                                // CRITICAL FIX: Do NOT dispatch type 1 (HELLO) automatically!
                                // 
                                // Type 1 (HELLO) calls sub_58C420 which expects FULL CAR_DATA.
                                // sub_58C420 -> sub_585E80 (accumulator) -> sub_587DB0 (parser)
                                // If we dispatch a small packet as type 1, sub_587DB0 will:
                                // - Read garbage data from bitstream
                                // - Potentially loop forever or crash
                                //
                                // Type 1 should only be dispatched if it's a REAL CAR_DATA packet (large).
                                // Small type 1 packets (8 bytes) are probe/handshake.
                                //
                                // SAFE to dispatch: type 8 (heartbeat), type 12 (state sync)
                                // SAFE if large: type 1 (CAR_DATA) - only if >= 20 bytes
                                // UNSAFE: type 3 (NULL deref)
                                // ============================================================
                                
                                bool safeToDispatch = (firstByte == 8 || firstByte == 12 ||
                                                       (firstByte == 1 && payloadLen >= 20));
                                
                                if (safeToDispatch) {
                                    LOG("[HOST-DISPATCH] Dispatching type %d to registered joiner peer %d", 
                                        firstByte, newFoundPeerIdx);
                                    
                                    typedef int(__cdecl* Dispatcher_t)(int peerIdx, const void* data, unsigned int size, char flag);
                                    Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                                    
                                    __try {
                                        int dispResult = dispatcher(newFoundPeerIdx, buf, payloadLen, 0);
                                        LOG("[HOST-DISPATCH] Dispatcher returned %d", dispResult);
                                    }
                                    __except(EXCEPTION_EXECUTE_HANDLER) {
                                        LOG("[HOST-DISPATCH] *** EXCEPTION in dispatcher! ***");
                                    }
                                } else {
                                    LOG("[HOST-DISPATCH] Skipping dispatch of type %d (unsafe/not handled)", firstByte);
                                }
                                
                                // SPECIAL: For type 12 on host, manually update peer state
                                // This ensures session state machine sees joiner as ready
                                if (firstByte == 12 && payloadLen >= 12) {
                                    const uint8_t* bytes = (const uint8_t*)buf;
                                    int stateFromPacket = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
                                    LOG("[HOST-TYPE12] Type 12 from joiner: state=%d", stateFromPacket);
                                    
                                    // Find peer slot and update state (timestamp already updated above)
                                    for (int i = 0; i < 5; i++) {
                                        if (peerArray[i * 8 + 1] == newFoundPeerIdx) {
                                            int oldState = peerArray[i * 8 + 4];
                                            peerArray[i * 8 + 4] = stateFromPacket;
                                            LOG("[HOST-TYPE12] Peer slot %d state updated: %d -> %d", i, oldState, stateFromPacket);
                                            break;
                                        }
                                    }
                                }
                            } else {
                                LOG("[HOST-DISPATCH] No peer found in peer array after registration!");
                            }
                        }
                        
                        // ============================================================
                        // CASE 2: We are JOINER - handle packets directly
                        // ============================================================
                        // Analysis of handlers:
                        // - Type 8 (sub_5860F0) - SAFE, returns without crash if peer not found
                        // - Type 3 (sub_586060) - UNSAFE, dereferences NULL if peer not found!
                        // - Type 12 (sub_58C690) - UNSAFE, dereferences NULL if peer not found!
                        //
                        // Solution: Don't create virtual peer. Handle packets directly.
                        // On joiner, we don't need peer array - we handle type 12/13 directly.
                        
                        // CRITICAL CHANGE: Do NOT create virtual peer in peer array!
                        // 
                        // PROBLEM: Creating virtual peer causes crash because:
                        // 1. sub_58EBC0 (session state machine) checks peer array for ready peers
                        // 2. When all peers are "ready" (state >= 3), it calls sub_5F9250
                        // 3. sub_5F9250 tries to access player struct via peer ID
                        // 4. Virtual peer has marker 0xDEAD0000 as ID, not real player index
                        // 5. CRASH when accessing player array at invalid index!
                        //
                        // SOLUTION: Don't create virtual peer. Handle packets directly.
                        // On joiner, we don't need peer array - we handle type 12/13 directly.
                        
                        static bool s_virtualPeerCreated = false;
                        if (!s_virtualPeerCreated && s_receivedBroadcast && !g_weAreHost) {
                            s_virtualPeerCreated = true;
                            LOG("[VIRTUAL-PEER] Creating minimal peer entry for host...");
                            
                            // Create minimal peer entry for host in peer array
                            // This allows sub_58EBC0 to check peer states correctly
                            // Peer array at 0x8693C8, 5 slots, 32 bytes each:
                            //   +0 = peer struct ptr (we use 0x1 as dummy)
                            //   +4 = peer index (0 for first peer)
                            //   +16 = peer state (3 = ready)
                            //   +28 = timestamp
                            int* peerArray = (int*)0x8693C8;
                            peerArray[0] = 0x1;  // Non-zero dummy ptr (not -1)
                            peerArray[1] = 0;    // peer idx = 0
                            peerArray[4] = 3;    // state = 3 (ready)
                            peerArray[7] = *(int*)0x8651AC;  // timestamp
                            LOG("[VIRTUAL-PEER] Created peer entry: struct=0x%X, idx=%d, state=%d",
                                peerArray[0], peerArray[1], peerArray[4]);
                            
                            // Set player count = 1 (we have one peer = host)
                            *(int*)0x7FBDB8 = 1;
                            LOG("[VIRTUAL-PEER] Set player count = 1");
                            
                            // Keep session state = 1 (set by JOINER-INIT)
                            LOG("[VIRTUAL-PEER] Session state = %d", *(int*)0x866A14);
                            
                            DumpPeerArray();
                        }
                        
                        // CRITICAL: Don't use dispatcher at all on joiner!
                        // We don't have peer array entries, so dispatcher handlers will crash.
                        // Handle ALL packet types directly.
                        
                        // Track last received host state (TYPE 12/13) BEFORE BROADCAST
                        // These packets arrive before s_virtualPeerCreated is set!
                        static int s_pendingHostState = 0;
                        static int s_pendingSessionState = 0;
                        
                        // Handle TYPE 8 (heartbeat) directly - just log it, no action needed
                        if (firstByte == 8) {
                            static int s_type8Count = 0;
                            s_type8Count++;
                            if (s_type8Count <= 5 || s_type8Count % 50 == 0) {
                                LOG("[UDP-TUNNEL-JOINER] >>> TYPE 8 (heartbeat) #%d received from host", s_type8Count);
                            }
                        } 
                        // Handle TYPE 12 (state sync) - process EVEN BEFORE BROADCAST!
                        // Format: [type:4][sessionId:4][state:4]
                        else if (firstByte == 12 && payloadLen >= 12) {
                            const uint8_t* bytes = (const uint8_t*)buf;
                            int stateFromPacket = bytes[8] | (bytes[9] << 8) | (bytes[10] << 16) | (bytes[11] << 24);
                            LOG("[UDP-TUNNEL-JOINER] >>> TYPE 12 (state sync): host_state=%d (virtualPeer=%d)", 
                                stateFromPacket, s_virtualPeerCreated ? 1 : 0);
                            
                            // Save pending state even before BROADCAST
                            if (stateFromPacket >= 0 && stateFromPacket <= 10) {
                                s_pendingHostState = stateFromPacket;
                            }
                            
                            // If virtual peer exists, update peer array too
                            if (s_virtualPeerCreated) {
                                int* peerArray = (int*)0x8693C8;
                                int oldState = peerArray[4];
                                if (stateFromPacket >= 0 && stateFromPacket <= 10) {
                                    peerArray[4] = stateFromPacket;
                                    peerArray[7] = *(int*)0x8651AC;  // Update timestamp
                                    LOG("[UDP-TUNNEL-JOINER] >>> Peer state updated: %d -> %d", oldState, stateFromPacket);
                                }
                                
                                // Check if host transitioned to state 4 (race preparing)
                                if (stateFromPacket == 4 && oldState == 3) {
                                    LOG("[UDP-TUNNEL-JOINER] >>> HOST STATE 3->4: Race preparing!");
                                    int* sessionStatePtr = (int*)0x866A14;
                                    if (*sessionStatePtr < 4) {
                                        *sessionStatePtr = 4;
                                        LOG("[UDP-TUNNEL-JOINER] >>> Session state set to 4");
                                    }
                                }
                            }
                        }
                        // Handle TYPE 13 (session control) - process EVEN BEFORE BROADCAST!
                        // Two formats from host:
                        // 1. From sub_586120 (SEND-PEER): [type:4][state:4][padding:4] - 12 bytes
                        // 2. From sub_5883A0 (SEND-ALL): [type:4][sessionId:4] - 8 bytes (state NOT included!)
                        else if (firstByte == 13 && payloadLen >= 8) {
                            int sessionValue = 0;
                            const uint8_t* bytes = (const uint8_t*)buf;
                            
                            // Check if this has state or just sessionId
                            // If bytes[4-7] == 0x64 (session ID = 100) and len==8, this is SEND-ALL format
                            // If bytes[4-7] is small number (1-10), this is state from SEND-PEER
                            int value4 = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
                            
                            if (value4 == 100 && payloadLen == 8) {
                                // SEND-ALL format: [type:4][sessionId:4] - no state info
                                LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 (SEND-ALL format): sessionId=%d - IGNORED (no state)", value4);
                            }
                            else if (value4 >= 0 && value4 <= 10) {
                                // SEND-PEER format: [type:4][state:4][padding:4]
                                sessionValue = value4;
                                LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 (session): state=%d, payloadLen=%d, bytes=%02X %02X %02X %02X %02X %02X %02X %02X",
                                    sessionValue, payloadLen,
                                    bytes[0], bytes[1], bytes[2], bytes[3],
                                    payloadLen >= 8 ? bytes[4] : 0, payloadLen >= 8 ? bytes[5] : 0,
                                    payloadLen >= 8 ? bytes[6] : 0, payloadLen >= 8 ? bytes[7] : 0);
                                
                                // Save pending state even before BROADCAST
                                s_pendingSessionState = sessionValue;
                                
                                // Handle session state changes
                                if (sessionValue == 2) {
                                    LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 state=2: Host signals ALL READY!");
                                    int* sessionStatePtr = (int*)0x866A14;
                                    if (*sessionStatePtr > 0 && *sessionStatePtr < 2) {
                                        *sessionStatePtr = 2;
                                        LOG("[UDP-TUNNEL-JOINER] >>> dword_866A14 set to 2 (preparing)");
                                    }
                                }
                                else if (sessionValue == 3) {
                                    LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 state=3: Host in READY state!");
                                    int* sessionStatePtr = (int*)0x866A14;
                                    if (*sessionStatePtr > 0 && *sessionStatePtr < 3) {
                                        *sessionStatePtr = 3;
                                        LOG("[UDP-TUNNEL-JOINER] >>> dword_866A14 set to 3 (ready)");
                                    }
                                }
                                else if (sessionValue == 5) {
                                    LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 state=5: COUNTDOWN starting!");
                                    *(int*)0x866A14 = 5;
                                    LOG("[UDP-TUNNEL-JOINER] >>> dword_866A14 set to 5");
                                }
                                else if (sessionValue == 6) {
                                    LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 state=6: RACE STARTING!");
                                    *(int*)0x866A14 = 6;
                                    int gameState = *(int*)0x8669F4;
                                    if (gameState < 7) {
                                        *(int*)0x8669F4 = 7;
                                        LOG("[UDP-TUNNEL-JOINER] >>> Game state set to 7 (RACING!)");
                                    }
                                }
                            }
                            else {
                                // Unknown format - just log it
                                LOG("[UDP-TUNNEL-JOINER] >>> TYPE 13 (unknown format): value4=%d, payloadLen=%d", value4, payloadLen);
                            }
                        }
                        // Handle TYPE 17 (game start) directly
                        else if (firstByte == 17 && s_virtualPeerCreated) {
                            LOG("[UDP-TUNNEL-JOINER] >>> TYPE 17 (game start) received!");
                            // This is the final signal to start race
                            int gameState = *(int*)0x8669F4;
                            if (gameState < 7) {
                                *(int*)0x8669F4 = 7;  // Set game state to racing
                                LOG("[UDP-TUNNEL-JOINER] >>> Game state set to 7 (racing)");
                            }
                        }
                        // CRITICAL: Handle TYPE 5 (BROADCAST) - must dispatch to game!
                        // BROADCAST contains track/session data and triggers sub_5FF000
                        // which initializes race on joiner side.
                        else if (firstByte == 5 && s_virtualPeerCreated) {
                            LOG("[UDP-TUNNEL-JOINER] >>> TYPE 5 (BROADCAST) received (%d bytes)!", payloadLen);
                            
                            // Dispatch BROADCAST through game's dispatcher
                            // This calls sub_5896F0 -> sub_5FF000 which processes track data
                            typedef int(__cdecl* Dispatcher_t)(int, const void*, unsigned int, char);
                            Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                            
                            // Use peer idx 0 - sub_5896F0 uses it to call sub_588350 which
                            // re-broadcasts to other peers. Since we're joiner with no peers,
                            // sub_588350 will just return.
                            __try {
                                int dispResult = dispatcher(0, buf, payloadLen, 0);
                                LOG("[UDP-TUNNEL-JOINER] >>> BROADCAST dispatched, result=%d", dispResult);
                            }
                            __except(EXCEPTION_EXECUTE_HANDLER) {
                                LOG("[UDP-TUNNEL-JOINER] >>> EXCEPTION dispatching BROADCAST!");
                            }
                        }
                        // CRITICAL: Handle CAR_DATA (102-105) for joiner!
                        // Our tunnel uses types 102-105, but game expects type=1.
                        // Extract bitstream (buf+8) and dispatch as type 1 to sub_58C420.
                        // NOTE: CAR_DATA arrives BEFORE BROADCAST, so don't require s_virtualPeerCreated!
                        else if (firstByte >= 102 && firstByte <= 105 && !g_weAreHost) {
                            int partNum = firstByte - 101;
                            
                            // CRITICAL: Don't dispatch if we already sent our CAR_DATA response!
                            // This prevents processing duplicate CAR_DATA from host (causes crash).
                            bool alreadySentOurCarData = g_sentCarDataTypes[0] && g_sentCarDataTypes[1] && 
                                                         g_sentCarDataTypes[2] && g_sentCarDataTypes[3];
                            
                            if (alreadySentOurCarData) {
                                LOG("[UDP-TUNNEL-JOINER] >>> CAR_DATA_%d SKIPPED (already sent our response)", partNum);
                            }
                            else {
                                LOG("[UDP-TUNNEL-JOINER] >>> CAR_DATA_%d received (%d bytes)", partNum, payloadLen);
                                
                                if (payloadLen > 8) {
                                    // Extract bitstream (skip our 8-byte tunnel header)
                                    char dispatchBuf[2048];
                                    int bitstreamLen = payloadLen - 8;
                                    memcpy(dispatchBuf, buf + 8, bitstreamLen);
                                    
                                    LOG("[UDP-TUNNEL-JOINER] >>> Dispatching CAR_DATA_%d as type 1 (%d bytes): %02X %02X %02X %02X",
                                        partNum, bitstreamLen,
                                        (unsigned char)dispatchBuf[0], (unsigned char)dispatchBuf[1],
                                        (unsigned char)dispatchBuf[2], (unsigned char)dispatchBuf[3]);
                                    
                                    typedef int(__cdecl* Dispatcher_t)(int, const void*, unsigned int, char);
                                    Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                                    
                                    __try {
                                        int dispResult = dispatcher(0, dispatchBuf, bitstreamLen, 0);
                                        LOG("[UDP-TUNNEL-JOINER] >>> CAR_DATA_%d dispatched, result=%d", partNum, dispResult);
                                    }
                                    __except(EXCEPTION_EXECUTE_HANDLER) {
                                        LOG("[UDP-TUNNEL-JOINER] >>> EXCEPTION dispatching CAR_DATA_%d!", partNum);
                                    }
                                }
                            }
                        }
                        else if (!s_receivedBroadcast) {
                            LOG("[UDP-TUNNEL-HANDSHAKE] Type %d (%s) - waiting for BROADCAST first", 
                                firstByte, pktTypeName);
                        }
                        else {
                            LOG("[UDP-TUNNEL-JOINER] Type %d (%s) - skipped (not safe to dispatch)", 
                                firstByte, pktTypeName);
                        }
                        
                        // Respond to type 8 heartbeat to keep host happy
                        if (firstByte == 8 && !g_weAreHost && g_udpTunnelSocket != INVALID_SOCKET && srcIP != 0) {
                            static DWORD s_lastType8ResponseNoPeer = 0;
                            static DWORD s_lastType12Send = 0;
                            static DWORD s_lastStateLog = 0;
                            static int s_type12SendCount = 0;
                            DWORD now = GetTickCount();
                            
                            // Send type 8 response
                            if (now - s_lastType8ResponseNoPeer >= 100) {
                                s_lastType8ResponseNoPeer = now;
                                uint8_t response[8] = {0x08, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00};
                                int sent = SendUdpViaTunnel(srcPort, srcIP, (char*)response, 8);
                                if (sent > 0) {
                                    LOG("[UDP-TUNNEL-HANDSHAKE] >>> Sent type 8 response (no peer yet)");
                                }
                            }
                            
                            // CRITICAL: Also send type 12 (state sync) periodically!
                            // This tells host our state so it can proceed with race start.
                            // But ONLY after we received BROADCAST and initialized session!
                            if (now - s_lastType12Send >= 500 && s_type12SendCount < 50 && s_receivedBroadcast) {
                                s_lastType12Send = now;
                                s_type12SendCount++;
                                
                                // Read current session state and send it
                                int ourState = *(int*)0x866A14;
                                // CRITICAL FIX: Always send state 6 for joiner (ready for countdown)
                                // If state is 0 or less than 6, force to 6
                                if (ourState < 6) ourState = 6;
                                
                                // Build type 12 packet: [type:4][sessionId:4][state:4]
                                uint8_t type12[12] = {
                                    0x0C, 0x00, 0x00, 0x00,  // type = 12
                                    0x64, 0x00, 0x00, 0x00,  // session ID = 100
                                    (uint8_t)(ourState & 0xFF), 0x00, 0x00, 0x00  // state
                                };
                                
                                int sent = SendUdpViaTunnel(srcPort, srcIP, (char*)type12, 12);
                                if (sent > 0) {
                                    LOG("[UDP-TUNNEL-HANDSHAKE] >>> Sent type 12 state=%d (#%d)", ourState, s_type12SendCount);
                                }
                            }
                            
                            // Log state every second for debugging
                            if (now - s_lastStateLog >= 1000) {
                                s_lastStateLog = now;
                                LOG("[UDP-TUNNEL-STATE] Session: dword_866A14=%d, players=%d, dword_7FBE80=0x%X, weHost=%d",
                                    *(int*)0x866A14, *(int*)0x7FBDB8, *(int*)0x7FBE80, g_weAreHost ? 1 : 0);
                            }
                        }
                    }
                } else if (firstByte >= 101 && firstByte <= 110) {
                    LOG("[UDP-TUNNEL-SYNC] Type %d sync packet - returning to game", firstByte);
                }
                
                return payloadLen;
            }
        }
#endif
        
        // Call original
        typedef int(__cdecl* OrigFunc_t)(int, char*, int, char, sockaddr*, int*);
        OrigFunc_t origFunc = reinterpret_cast<OrigFunc_t>(&g_tramp74A6D0.code[0]);
        int result = origFunc(a1, buf, len, a4, from, fromlen);
        
        // Log first calls to verify hook is working
        g_recvHookCallCount++;
        if (g_recvHookCallCount <= 10 || g_recvHookCallCount % 500 == 0) {
            LOG("[HOOK-DEBUG] Hook_GameRecv call #%d: socket=%d, from=%p, result=%d, g_gameSocket=%d", 
                g_recvHookCallCount, (int)sock, from, result, (int)g_gameSocket);
        }
        
    // Log ALL UDP receives (from != NULL means UDP mode)
    // result=0 means no data, result=-1 means error, result>0 means data
    // 
    // DIAGNOSTIC: Log EVERY UDP recvfrom call for debugging
    static int s_udpRecvCalls = 0;
    if (from != nullptr) {
        s_udpRecvCalls++;
        
        // Log first 20 UDP recv attempts and then every 100th
        if (s_udpRecvCalls <= 20 || s_udpRecvCalls % 100 == 0) {
            int err = (result < 0) ? WSAGetLastError() : 0;
            LOG("[UDP-RECV-DIAG] call #%d: socket=%d, result=%d, WSAErr=%d, g_gameSocket=%d",
                s_udpRecvCalls, (int)sock, result, err, (int)g_gameSocket);
        }
        
        if (result > 0) {
            sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
            char srcIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &srcAddr->sin_addr, srcIPStr, sizeof(srcIPStr));
            LOG("[UDP-RECV-RAW] from=%s:%d, result=%d, socket=%d", 
                srcIPStr, ntohs(srcAddr->sin_port), result, (int)sock);
        } else if (result < 0) {
            int err = WSAGetLastError();
            // Only log non-WOULDBLOCK errors (10035 = no data available)
            if (err != WSAEWOULDBLOCK) {
                LOG("[UDP-RECV-ERR] socket=%d, result=%d, WSAError=%d", (int)sock, result, err);
            }
        }
        // result == 0 means connection closed (TCP) or no data (UDP non-blocking)
    }
        
        // DEBUG: Log ALL UDP receives with detailed info
        if (from != nullptr && result > 0) {
            sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
            char srcIPStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &srcAddr->sin_addr, srcIPStr, sizeof(srcIPStr));
            uint16_t srcPort = ntohs(srcAddr->sin_port);
            
            // Log first bytes as hex
            char hexBuf[64];
            int hexLen = 0;
            int dumpLen = (result < 16) ? result : 16;
            for (int i = 0; i < dumpLen && hexLen < 60; i++) {
                hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
            }
            
            LOG("[UDP-RECV] from %s:%d, len=%d, sock=%d, hex=%s", 
                srcIPStr, srcPort, result, (int)sock, hexBuf);
            
            // Check if this is from relay server
            bool ipMatch = (srcAddr->sin_addr.s_addr == g_serverIP);
            bool portMatch = (srcPort == RELAY_PORT);
            if (ipMatch || portMatch) {
                char serverIPStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &g_serverIP, serverIPStr, sizeof(serverIPStr));
                LOG("[UDP-RECV] RELAY CHECK: g_serverIP=%s, ipMatch=%d, portMatch=%d", 
                    serverIPStr, ipMatch, portMatch);
            }
        }
        
        // === RELAY HEADER PROCESSING ===
        // For UDP packets from relay server, strip the 6-byte header and extract peer address
        // 
        // Format: [2 bytes port BE][4 bytes IP][payload...]
        // We need to:
        // 1. Check if packet came from relay server
        // 2. Extract real peer address from header
        // 3. Move payload to start of buffer
        // 4. Return payload length (result - 6)
        
#if !UDP_CAPTURE_ONLY
        if (result >= 6 && from != nullptr && g_serverIP != 0) {
            sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
            
            // Check if packet came from relay server (IP and port match)
            bool fromRelayServer = 
                (srcAddr->sin_addr.s_addr == g_serverIP) &&
                (ntohs(srcAddr->sin_port) == RELAY_PORT);
            
        if (fromRelayServer) {
            // Extract peer address from relay header
            // Port is in network byte order (BE) - we need to copy raw bytes, not cast
            // Because pointer cast on x86 would interpret as LE
            uint16_t peerPort;
            memcpy(&peerPort, buf, 2);  // Copy raw bytes (keeps network order)
            uint32_t peerIP;
            memcpy(&peerIP, buf + 2, 4);  // Copy raw bytes
                
                // Calculate payload length
                int payloadLen = result - 6;
                
                // Log for debugging - ALWAYS log relay packets for debugging
                char peerIPStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peerIP, peerIPStr, sizeof(peerIPStr));
                
                // Detect P2P handshake packets (type 1 and 5) for detailed logging
                uint32_t pktType = (payloadLen >= 4) ? *reinterpret_cast<uint32_t*>(buf + 6) : 0;
                uint32_t peerId = (payloadLen >= 8) ? *reinterpret_cast<uint32_t*>(buf + 10) : 0;
                
                LOG("[UDP-RELAY] RECV: relay->client, peer=%s:%d, type=%u, peerId=%u, payloadLen=%d (rawLen=%d)", 
                    peerIPStr, ntohs(peerPort), pktType, peerId, payloadLen, result);
                
                // Log raw hex for debugging
                char hexBuf[128];
                int hexLen = 0;
                int dumpLen = (result < 32) ? result : 32;
                for (int i = 0; i < dumpLen && hexLen < 120; i++) {
                    hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
                }
                LOG("[UDP-RELAY] RAW HEX: %s", hexBuf);
                
                // Update 'from' with real peer address BEFORE stripping header
                srcAddr->sin_port = peerPort;  // Already in network order
                srcAddr->sin_addr.s_addr = peerIP;
                
                // Strip relay header - move payload to start of buffer
                memmove(buf, buf + 6, payloadLen);
                
                // Log payload hex after stripping
                hexLen = 0;
                dumpLen = (payloadLen < 32) ? payloadLen : 32;
                for (int i = 0; i < dumpLen && hexLen < 120; i++) {
                    hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
                }
                LOG("[UDP-RELAY] PAYLOAD HEX: %s (returning %d bytes)", hexBuf, payloadLen);
                
                // Return payload length instead of full packet length!
                return payloadLen;
            }
        }
#endif
        
        // Log received data (for non-relay or if relay processing failed)
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
    // Hook for game's bind wrapper (sub_74A380)
    // int __cdecl sub_74A380(int socketStruct, sockaddr* name, int namelen)
    // Captures UDP game socket for relay
    // ========================================================================
    inline int __cdecl Hook_Bind(int a1, int a2, int a3) {
        LOG("Bind hook! a1=0x%08X", a1);
        
        // Call original via trampoline
        typedef int(__cdecl* BindFunc_t)(int, int, int);
        BindFunc_t origFunc = reinterpret_cast<BindFunc_t>(&g_tramp74A380.code[0]);
        int result = origFunc(a1, a2, a3);
        
        // Capture game socket handle from structure (offset +24 = 0x18)
        SOCKET sock = *reinterpret_cast<SOCKET*>(a1 + 24);
        
        // Log bind address
        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(a2);
        if (addr && a3 >= (int)sizeof(sockaddr_in)) {
            char ipStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ipStr, sizeof(ipStr));
            uint16_t port = ntohs(addr->sin_port);
            LOG("Bind: socket=%d, addr=%s:%d, result=%d", (int)sock, ipStr, port, result);
            
            // Capture UDP socket - game binds to port 3658 for P2P
            // We capture any bind to a fixed port (not 0) as potential game UDP socket
            // Port 3658 = original game P2P port
            // We redirect traffic to RELAY_PORT (53) for NAT bypass
            if (port == 3658 || port == RELAY_PORT || port == 0) {
                SOCKET oldSocket = g_gameSocket;
                g_gameSocket = sock;
                LOG("*** Captured UDP game socket: %d (bound port=%d, relay port=%d) [was: %d]", 
                    (int)g_gameSocket, port, RELAY_PORT, (int)oldSocket);
            }
        } else {
            LOG("Bind: socket=%d, result=%d", (int)sock, result);
            // Capture anyway if we don't have one yet
            if (g_gameSocket == INVALID_SOCKET) {
                g_gameSocket = sock;
                LOG("*** Captured game socket (no addr): %d", (int)g_gameSocket);
            }
        }
        
        return result;
    }
    
    // ========================================================================
    // CRITICAL HOOK: sub_58F690 - Network tick (calls state machine)
    // 
    // This function is called from sub_60AEE0 when network is active.
    // It calls:
    //   - sub_585B20() if dword_8669F4 > 0
    //   - sub_5877D0() if dword_866A14 > 0 (processes connection array - CRITICAL!)
    //   - sub_58EBC0() if dword_866A14 > 0 (session state machine - CRITICAL!)
    //
    // PROBLEM: sub_5877D0() only processes connections in connection array.
    // In tunnel mode, connection array is EMPTY because we don't have real UDP.
    // So sub_5877D0() doesn't read any packets!
    //
    // SOLUTION: Before calling original function, manually read packets from
    // tunnel and dispatch them. This ensures host receives type 12 from joiner.
    // ========================================================================
    inline int g_58F690CallCount = 0;
    
    inline char Hook_58F690() {
        g_58F690CallCount++;
        
        // Periodic logging
        static DWORD s_lastLog = 0;
        DWORD now = GetTickCount();
        if (now - s_lastLog >= 5000) {
            s_lastLog = now;
            LOG("[NETWORK-TICK] sub_58F690 #%d, session=%d, game=%d, weHost=%d, peerReg=%d",
                g_58F690CallCount, *(int*)0x866A14, *(int*)0x8669F4, 
                g_weAreHost ? 1 : 0, g_hostPeerRegistered ? 1 : 0);
        }
        
        // ============================================================
        // CRITICAL: Read tunnel packets BEFORE calling original!
        // Original sub_5877D0 won't read from tunnel because connection
        // array is empty. We need to manually pump tunnel packets.
        // ============================================================
        if (g_weAreHost && g_hostPeerRegistered && g_udpTunnelCSInitialized) {
            static int s_pumpCount = 0;
            int packetsProcessed = 0;
            int* peerArray = (int*)0x8693C8;  // Moved outside loop for use after loop
            
            // Read up to 10 packets per tick to avoid blocking
            for (int i = 0; i < 10; i++) {
                uint16_t srcPort = 0;
                uint32_t srcIP = 0;
                char pktBuf[2048];
                int pktLen = 0;
                
                if (!RecvUdpFromTunnel(&srcPort, &srcIP, pktBuf, &pktLen, sizeof(pktBuf))) {
                    break;  // No more packets
                }
                
                packetsProcessed++;
                
                // Get packet type
                uint32_t pktType = (pktLen >= 4) ? *reinterpret_cast<uint32_t*>(pktBuf) : 0;
                
                char srcIPStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &srcIP, srcIPStr, sizeof(srcIPStr));
                
                LOG("[TUNNEL-PUMP] Packet #%d: type=%u, len=%d, from=%s:%d",
                    packetsProcessed, pktType, pktLen, srcIPStr, srcPort);
                
                // CRITICAL: Save joiner's address so we can send responses!
                if (srcIP != 0) {
                    if (g_lastRecvIP != srcIP || g_lastRecvPort != srcPort) {
                        LOG("[TUNNEL-PUMP] >>> SAVED JOINER ADDRESS: %s:%d (for Hook_587DB0)", srcIPStr, srcPort);
                    }
                    g_lastRecvIP = srcIP;
                    g_lastRecvPort = srcPort;
                }
                
                // Find peer idx for this source IP
                int peerIdx = -1;
                
                for (int j = 0; j < 5; j++) {
                    if (peerArray[j * 8 + 1] != -1) {  // idx != -1
                        peerIdx = peerArray[j * 8 + 1];
                        break;  // Use first valid peer
                    }
                }
                
                if (peerIdx < 0) {
                    LOG("[TUNNEL-PUMP] No peer in peer array, skipping dispatch");
                    continue;
                }
                
                // Update peer timestamp to prevent timeout
                for (int j = 0; j < 5; j++) {
                    if (peerArray[j * 8 + 1] == peerIdx) {
                        peerArray[j * 8 + 7] = *(int*)0x8651AC;
                        break;
                    }
                }
                
                // Special handling for type 12 (state sync) - update peer state directly
                if (pktType == 12 && pktLen >= 12) {
                    int stateFromPacket = pktBuf[8] | (pktBuf[9] << 8) | (pktBuf[10] << 16) | (pktBuf[11] << 24);
                    LOG("[TUNNEL-PUMP] TYPE 12: state=%d from joiner", stateFromPacket);
                    
                    // Update peer state in peer array
                    for (int j = 0; j < 5; j++) {
                        if (peerArray[j * 8 + 1] == peerIdx) {
                            int oldState = peerArray[j * 8 + 4];
                            peerArray[j * 8 + 4] = stateFromPacket;
                            LOG("[TUNNEL-PUMP] Peer %d state: %d -> %d", j, oldState, stateFromPacket);
                            break;
                        }
                    }
                }
                
                // Special handling for type 8 (heartbeat) - just update timestamp (already done above)
                if (pktType == 8) {
                    static int s_type8Count = 0;
                    s_type8Count++;
                    if (s_type8Count <= 5 || s_type8Count % 50 == 0) {
                        LOG("[TUNNEL-PUMP] TYPE 8: heartbeat #%d from joiner", s_type8Count);
                    }
                    // Timestamp already updated above
                    continue;  // No need to dispatch
                }
                
                // Dispatch SAFE packet types through game's dispatcher
                // 
                // CRITICAL: Our tunnel uses types 102-105 for CAR_DATA, but game expects type=1!
                // For CAR_DATA (102-105): extract bitstream (pktBuf+8) and dispatch as type 1
                // For type 1 if large: dispatch directly (real CAR_DATA from network)
                //
                // ALREADY HANDLED above: 8 (heartbeat), 12 (state sync)
                // UNSAFE: 1 if small (handshake), 3 (NULL deref possible)
                
                typedef int(__cdecl* Dispatcher_t)(int, const void*, unsigned int, char);
                Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                
                if (pktType >= 102 && pktType <= 105 && pktLen > 8) {
                    // CRITICAL: Don't dispatch if we already sent our CAR_DATA response!
                    // Host receives CAR_DATA from joiner AFTER host already sent its CAR_DATA.
                    // Processing joiner's CAR_DATA triggers another send (duplicate).
                    bool alreadySentOurCarData = g_sentCarDataTypes[0] && g_sentCarDataTypes[1] && 
                                                 g_sentCarDataTypes[2] && g_sentCarDataTypes[3];
                    
                    if (alreadySentOurCarData) {
                        LOG("[TUNNEL-PUMP] CAR_DATA_%d SKIPPED (already sent our response)", pktType - 101);
                    }
                    else {
                        // CAR_DATA from tunnel: extract bitstream and dispatch
                        char dispatchBuf[2048];
                        int bitstreamLen = pktLen - 8;  // Remove our 8-byte header
                        memcpy(dispatchBuf, pktBuf + 8, bitstreamLen);
                        
                        LOG("[TUNNEL-PUMP] CAR_DATA_%d: dispatching %d bytes as type 1", 
                            pktType - 101, bitstreamLen);
                        
                        __try {
                            int dispResult = dispatcher(peerIdx, dispatchBuf, bitstreamLen, 0);
                            LOG("[TUNNEL-PUMP] CAR_DATA_%d dispatched, result=%d", pktType - 101, dispResult);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            LOG("[TUNNEL-PUMP] *** EXCEPTION dispatching CAR_DATA_%d! ***", pktType - 101);
                        }
                    }
                }
                else if (pktType == 1 && pktLen >= 20) {
                    // Real type 1 packet (large enough to be real CAR_DATA)
                    __try {
                        int dispResult = dispatcher(peerIdx, pktBuf, pktLen, 0);
                        LOG("[TUNNEL-PUMP] Dispatched type 1 to peer %d, result=%d", peerIdx, dispResult);
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER) {
                        LOG("[TUNNEL-PUMP] *** EXCEPTION dispatching type 1! ***");
                    }
                }
                else if (pktType != 8 && pktType != 12) {
                    LOG("[TUNNEL-PUMP] Skipping type %u (not safe to dispatch)", pktType);
                }
            }
            
            if (packetsProcessed > 0) {
                s_pumpCount++;
                LOG("[TUNNEL-PUMP] Processed %d packets in tick #%d (pump #%d)", 
                    packetsProcessed, g_58F690CallCount, s_pumpCount);
                
                // After processing packets, check state machine condition
                int readyPeers = 0;
                for (int j = 0; j < 5; j++) {
                    if (peerArray[j * 8 + 1] != -1 && peerArray[j * 8 + 4] >= 3) {
                        readyPeers++;
                    }
                }
                int playerCount = *(int*)0x7FBDB8;
                int sessionState = *(int*)0x866A14;
                
                // For case 4, count peers with state == 6
                int peers6 = 0;
                for (int j = 0; j < 5; j++) {
                    if (peerArray[j * 8 + 1] != -1 && peerArray[j * 8 + 4] == 6) {
                        peers6++;
                    }
                }
                int peerCount866A24 = *(int*)0x866A24;
                
                LOG("[TUNNEL-PUMP] State check: ready=%d, peers6=%d, players=%d, peerCnt=%d, session=%d",
                    readyPeers, peers6, playerCount, peerCount866A24, sessionState);
                
                if (sessionState == 1 && readyPeers == playerCount && playerCount > 0) {
                    LOG("[TUNNEL-PUMP] >>> CONDITION 1→2 MET! Race init should happen...");
                }
                if (sessionState == 4 && peers6 == peerCount866A24 && peers6 > 0) {
                    LOG("[TUNNEL-PUMP] >>> CONDITION 4→5 MET! Countdown should start...");
                }
            }
        }
        
        // ============================================================
        // JOINER: Pump tunnel packets and dispatch CAR_DATA (102-105)
        // 
        // DISABLED: This was causing packet corruption because both
        // JOINER-PUMP and Hook_GameRecv read from the same queue,
        // leading to packets being read in wrong order or partially.
        //
        // CAR_DATA processing now happens in Hook_GameRecv when
        // packets are returned to the game.
        // ============================================================
        if (false && !g_weAreHost && g_udpTunnelCSInitialized && g_lastRecvIP != 0) {
            static int s_joinerPumpCount = 0;
            int packetsProcessed = 0;
            
            // Read up to 10 packets per tick
            for (int i = 0; i < 10; i++) {
                uint16_t srcPort = 0;
                uint32_t srcIP = 0;
                char pktBuf[2048];
                int pktLen = 0;
                
                if (!RecvUdpFromTunnel(&srcPort, &srcIP, pktBuf, &pktLen, sizeof(pktBuf))) {
                    break;  // No more packets
                }
                
                packetsProcessed++;
                
                uint32_t pktType = (pktLen >= 4) ? *reinterpret_cast<uint32_t*>(pktBuf) : 0;
                
                // CAR_DATA packets (102-105) need to be dispatched so sub_58C420 can process them
                // and trigger our CAR_DATA generation via sub_587DB0
                //
                // CRITICAL: Our tunnel uses types 102-105, but game's dispatcher expects type=1!
                // The real type is in the bitstream at offset 8 (after our 8-byte header).
                // We need to pass the bitstream data (pktBuf+8) with type=1 to dispatcher.
                if (pktType >= 102 && pktType <= 105) {
                    LOG("[JOINER-PUMP] >>> CAR_DATA_%d received (%d bytes), dispatching as type 1...", 
                        pktType - 101, pktLen);
                    
                    // Build type 1 packet for dispatcher
                    // Original format: [type=1 (4 bytes)][bitstream from our pktBuf+8]
                    // We need to prepend type=1 to the bitstream data
                    if (pktLen > 8) {
                        char dispatchBuf[2048];
                        int bitstreamLen = pktLen - 8;  // Remove our 8-byte header
                        
                        // Dispatcher expects raw bitstream with first byte = packet type
                        // Our pktBuf+8 already contains: [packetType=1][partNum][totalParts][dataSize][data...]
                        // So we just pass pktBuf+8 directly!
                        memcpy(dispatchBuf, pktBuf + 8, bitstreamLen);
                        
                        LOG("[JOINER-PUMP] >>> Dispatching %d bytes of bitstream, first bytes: %02X %02X %02X %02X",
                            bitstreamLen, 
                            (unsigned char)dispatchBuf[0], (unsigned char)dispatchBuf[1],
                            (unsigned char)dispatchBuf[2], (unsigned char)dispatchBuf[3]);
                        
                        typedef int(__cdecl* Dispatcher_t)(int, const void*, unsigned int, char);
                        Dispatcher_t dispatcher = (Dispatcher_t)0x58F020;
                        
                        __try {
                            int dispResult = dispatcher(0, dispatchBuf, bitstreamLen, 0);
                            LOG("[JOINER-PUMP] >>> CAR_DATA_%d dispatched, result=%d", pktType - 101, dispResult);
                        }
                        __except(EXCEPTION_EXECUTE_HANDLER) {
                            LOG("[JOINER-PUMP] >>> EXCEPTION dispatching CAR_DATA_%d!", pktType - 101);
                        }
                    } else {
                        LOG("[JOINER-PUMP] >>> CAR_DATA_%d too short (%d bytes), skipping", pktType - 101, pktLen);
                    }
                }
                // Type 13 (session info) - update session state
                else if (pktType == 13 && pktLen >= 8) {
                    int sessionValue = pktBuf[4] | (pktBuf[5] << 8) | (pktBuf[6] << 16) | (pktBuf[7] << 24);
                    LOG("[JOINER-PUMP] >>> TYPE 13 (session): state=%d (current: %d)", 
                        sessionValue, *(int*)0x866A14);
                    
                    if (sessionValue >= 2 && sessionValue <= 6) {
                        int oldState = *(int*)0x866A14;
                        *(int*)0x866A14 = sessionValue;
                        LOG("[JOINER-PUMP] >>> Session state: %d -> %d", oldState, sessionValue);
                        
                        // Special handling for race start states
                        if (sessionValue == 6 && oldState < 6) {
                            LOG("[JOINER-PUMP] >>> RACE STARTING! Setting game state to 7...");
                            int* gameState = (int*)0x8669F4;
                            if (*gameState < 7) {
                                *gameState = 7;
                                LOG("[JOINER-PUMP] >>> Game state set to 7 (RACING)");
                            }
                        }
                    }
                }
                // Type 8 (heartbeat) - just log
                else if (pktType == 8) {
                    static int s_jHeartbeat = 0;
                    s_jHeartbeat++;
                    if (s_jHeartbeat <= 5 || s_jHeartbeat % 50 == 0) {
                        LOG("[JOINER-PUMP] TYPE 8: heartbeat #%d from host", s_jHeartbeat);
                    }
                }
                else {
                    LOG("[JOINER-PUMP] Type %u (%d bytes) - not handled", pktType, pktLen);
                }
            }
            
            if (packetsProcessed > 0) {
                s_joinerPumpCount++;
                if (s_joinerPumpCount <= 20 || s_joinerPumpCount % 50 == 0) {
                    LOG("[JOINER-PUMP] Processed %d packets (pump #%d)", packetsProcessed, s_joinerPumpCount);
                }
            }
        }
        
        // Call original via trampoline
        typedef char(__cdecl* Func58F690_t)();
        Func58F690_t origFunc = reinterpret_cast<Func58F690_t>(&g_tramp58F690.code[0]);
        char result = origFunc();
        
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
        LOG("Server resolved: %s -> %s (g_serverIP=0x%08X)", hostname, ipStr, g_serverIP);
        LOG("RELAY_PORT = %d (0x%04X)", RELAY_PORT, RELAY_PORT);
        
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
        
        // Hook sub_74A380 (bind wrapper) - to capture UDP socket
        if (InstallInlineHook(GAME_BIND_WRAPPER, (void*)Hook_Bind, &g_tramp74A380, 8)) {
            LOG("  sub_74A380 (bind): HOOKED");
        } else {
            LOG("  sub_74A380 (bind): FAILED");
        }
        
        // Hook sub_58F020 (packet dispatcher) - to see which packet types are processed
        const uintptr_t PACKET_DISPATCHER_FUNC = 0x58F020;
        if (InstallInlineHook(PACKET_DISPATCHER_FUNC, (void*)Hook_58F020, &g_tramp58F020, 6)) {
            LOG("  sub_58F020 (dispatcher): HOOKED");
        } else {
            LOG("  sub_58F020 (dispatcher): FAILED");
        }
        
        // Hook sub_585E80 (CAR_DATA accumulator) - to see when all parts are received
        const uintptr_t CAR_ACCUM_FUNC = 0x585E80;
        if (InstallInlineHook(CAR_ACCUM_FUNC, (void*)Hook_585E80, &g_tramp585E80, 6)) {
            LOG("  sub_585E80 (CAR accum): HOOKED");
        } else {
            LOG("  sub_585E80 (CAR accum): FAILED");
        }
        
        // Hook sub_58C420 (HELLO handler) - for CAR_DATA generation debugging
        // This function is called when receiving HELLO packets and triggers car data generation
        const uintptr_t HELLO_HANDLER_FUNC = 0x58C420;
        if (InstallInlineHook(HELLO_HANDLER_FUNC, (void*)Hook_58C420, &g_tramp58C420, 8)) {
            LOG("  sub_58C420 (HELLO handler): HOOKED");
        } else {
            LOG("  sub_58C420 (HELLO handler): FAILED");
        }
        
        // Hook sub_587DB0 (CAR_DATA generator) - to see car data being created
        const uintptr_t CAR_GEN_FUNC = 0x587DB0;
        if (InstallInlineHook(CAR_GEN_FUNC, (void*)Hook_587DB0, &g_tramp587DB0, 6)) {
            LOG("  sub_587DB0 (CAR gen): HOOKED");
        } else {
            LOG("  sub_587DB0 (CAR gen): FAILED");
        }
        
        // Hook sub_5883A0 (send to ALL peers) - CRITICAL for type 12 state sync!
        const uintptr_t SEND_ALL_FUNC = 0x5883A0;
        if (InstallInlineHook(SEND_ALL_FUNC, (void*)Hook_5883A0, &g_tramp5883A0, 5)) {
            LOG("  sub_5883A0 (send ALL): HOOKED");
        } else {
            LOG("  sub_5883A0 (send ALL): FAILED");
        }
        
        // Hook sub_58C690 (type 12 state sync handler) - CRITICAL for race start!
        // This is called when peer sends type 12, it sets peer's state in peer array.
        // Host needs all peers at state >= 3 to start race.
        const uintptr_t TYPE12_HANDLER_FUNC = 0x58C690;
        if (InstallInlineHook(TYPE12_HANDLER_FUNC, (void*)Hook_58C690, &g_tramp58C690, 6)) {
            LOG("  sub_58C690 (type 12 handler): HOOKED");
        } else {
            LOG("  sub_58C690 (type 12 handler): FAILED");
        }
        
        // Hook sub_58C620 (peer disconnect/timeout) - to protect virtual peers from crash
        const uintptr_t PEER_DISCONNECT_FUNC = 0x58C620;
        if (InstallInlineHook(PEER_DISCONNECT_FUNC, (void*)Hook_58C620, &g_tramp58C620, 6)) {
            LOG("  sub_58C620 (peer disconnect): HOOKED");
        } else {
            LOG("  sub_58C620 (peer disconnect): FAILED");
        }
        
        // Hook sub_588350 (send to peers except one) - for broadcast packets
        const uintptr_t SEND_PEERS_FUNC = 0x588350;
        if (InstallInlineHook(SEND_PEERS_FUNC, (void*)Hook_588350, &g_tramp588350, 6)) {
            LOG("  sub_588350 (send peers): HOOKED");
        } else {
            LOG("  sub_588350 (send peers): FAILED");
        }
        
        // Hook sub_586120 (send to specific peer) - to intercept individual sends
        const uintptr_t SEND_PEER_FUNC = 0x586120;
        if (InstallInlineHook(SEND_PEER_FUNC, (void*)Hook_586120, &g_tramp586120, 6)) {
            LOG("  sub_586120 (send peer): HOOKED");
        } else {
            LOG("  sub_586120 (send peer): FAILED");
        }
        
        // Hook sub_58F690 (network tick) - CRITICAL for tunnel packet pumping!
        // This function is called every network tick and calls the session state machine.
        // In tunnel mode, we need to pump packets from tunnel BEFORE the state machine
        // checks, otherwise host never receives type 12 from joiner.
        // 
        // Assembly at 0x58F690:
        //   58F690: A0 xx xx xx xx    mov al, byte_7FBE78  (5 bytes)
        //   58F695: 84 C0             test al, al          (2 bytes)
        // Total: 7 bytes needed for clean cut
        const uintptr_t NETWORK_TICK_FUNC = 0x58F690;
        if (InstallInlineHook(NETWORK_TICK_FUNC, (void*)Hook_58F690, &g_tramp58F690, 7)) {
            LOG("  sub_58F690 (network tick): HOOKED");
        } else {
            LOG("  sub_58F690 (network tick): FAILED");
        }
        #else
        LOG("CAPTURE MODE: Skipping TCP hooks to preserve SSL handshake");
        #endif
        
        // Install IAT hooks for WinSock diagnostics
        LOG("Installing IAT hooks for UDP diagnostics...");
        if (HookIAT("WS2_32.dll", "recvfrom", (void*)Hook_Recvfrom, (void**)&g_origRecvfrom)) {
            LOG("  recvfrom: IAT HOOKED");
        } else {
            LOG("  recvfrom: IAT hook FAILED");
        }
        if (HookIAT("WS2_32.dll", "sendto", (void*)Hook_Sendto, (void**)&g_origSendto)) {
            LOG("  sendto: IAT HOOKED");
        } else {
            LOG("  sendto: IAT hook FAILED");
        }
        
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
    // sub_10002EB0 - RecvFrom hook (EXACT copy of original NFSOR)
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
        
        // Get source address for logging
        sockaddr_in* srcAddr = reinterpret_cast<sockaddr_in*>(from);
        char srcIP[INET_ADDRSTRLEN];
        if (srcAddr) {
            inet_ntop(AF_INET, &srcAddr->sin_addr, srcIP, sizeof(srcIP));
        } else {
            strcpy(srcIP, "?");
        }
        
#if UDP_CAPTURE_ONLY
        // === CAPTURE ONLY MODE - Log everything, don't modify ===
        if (result > 0) {
            // Log raw packet data as hex
            char hexBuf[512];
            int hexLen = 0;
            for (int i = 0; i < result && hexLen < 500; i++) {
                hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
            }
            
            // Decode packet type if possible
            uint32_t pktType = (result >= 4) ? *reinterpret_cast<uint32_t*>(buf) : 0;
            
            LOG("[UDP-CAPTURE] RECV from %s:%d len=%d type=%d", 
                srcIP, srcAddr ? ntohs(srcAddr->sin_port) : 0, result, pktType);
            LOG("[UDP-CAPTURE] DATA: %s", hexBuf);
            
            // Log to traffic file for detailed analysis
            LogTrafficRaw("UDP-RECV", buf, result);
        }
        return result;  // Return unmodified!
#else
        // === RELAY MODE - Process relay header ===
        // Original NFSOR logic EXACTLY:
        // if ( s == dword_1002073C && result >= 6 )
        // Only process relay packets from game socket with at least 6 bytes (relay header)
        if (result < 6 || !srcAddr) {
            return result;
        }

        // IMPORTANT:
        // Some game builds send certain UDP packets (incl. P2P handshake) from a different socket
        // than the one captured by Bind. In relay mode we must still strip the relay header for
        // ANY socket, as long as the packet came from the relay server.
        const bool fromRelayServer =
            (g_serverIP != 0) &&
            (srcAddr->sin_addr.s_addr == g_serverIP) &&
            (ntohs(srcAddr->sin_port) == RELAY_PORT);

        if (!fromRelayServer && s != g_gameSocket) {
            return result;
        }

        // If the first relay packet arrives on a different socket, capture it so SendTo hook can reuse it.
        if (fromRelayServer && g_gameSocket == INVALID_SOCKET) {
            g_gameSocket = s;
            LOG("[UDP] Auto-captured game socket from RecvFrom: %d (from relay %s:%d)",
                (int)s, srcIP, ntohs(srcAddr->sin_port));
        }

        // Original: v8 = inet_ntoa(...); copy to unk_10021774
        // Store relay server IP (for debugging/display)
        char* relayIP = inet_ntoa(srcAddr->sin_addr);
        char* dst = g_lastPeerIP;
        do {
            *dst = *relayIP;
            dst++;
            relayIP++;
        } while (*(relayIP - 1));

        // Original: htons(*(_WORD *)from->sa_data); (debug call, result ignored)
        htons(srcAddr->sin_port);

        // v11 = v7 - 6;
        // Calculate actual data length (minus relay header)
        size_t dataLen = result - 6;
        
        // Extract peer address from relay header:
        // *(_WORD *)from->sa_data = *(_WORD *)buf;  (peer port)
        srcAddr->sin_port = *reinterpret_cast<uint16_t*>(buf);
        
        // v12 = *(struct in_addr *)(buf + 2);
        // *(struct in_addr *)&from->sa_data[2] = v12;  (peer IP)
        srcAddr->sin_addr.s_addr = *reinterpret_cast<uint32_t*>(buf + 2);

        // Log for debugging
        char peerIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &srcAddr->sin_addr, peerIP, sizeof(peerIP));
        LOG("[UDP] RecvFrom: peer=%s:%d, payload=%zu bytes", 
            peerIP, ntohs(srcAddr->sin_port), dataLen);

        // memmove(buf, buf + 6, v11);
        // Strip relay header, move payload to beginning of buffer
        memmove(buf, buf + 6, dataLen);

        // Detect P2P handshake packets (0x45 ... "sknG" magic) reaching the client
        // Based on IDA: sub_756710 builds a packet with:
        // - first byte 0x45
        // - dword 0x676E6B73 ("sknG") at offset 28
        if (dataLen >= 36) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(buf);
            if (p[0] == 0x45) {
                const uint32_t magic = *reinterpret_cast<const uint32_t*>(p + 28);
                if (magic == 0x676E6B73) {
                    char hexBuf[256] = {0};
                    int hexLen = 0;
                    const size_t dumpLen = (dataLen < 36) ? dataLen : 36;
                    for (size_t i = 0; i < dumpLen && hexLen < 240; i++) {
                        hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)p[i]);
                    }
                    LOG("[UDP][P2P] RECV sknG from peer=%s:%d len=%zu data=%s",
                        peerIP, ntohs(srcAddr->sin_port), dataLen, hexBuf);
                }
            }
        }

        return static_cast<int>(dataLen);
#endif
    }

    // ========================================================================
    // sub_10002F50 - SendTo hook (FULL RELAY MODE)
    // ALL game socket packets go through relay server
    // ========================================================================
    inline int __stdcall Hook_SendTo(
        SOCKET s, 
        char* buf, 
        int len, 
        int flags, 
        sockaddr* to, 
        int tolen)
    {
        sockaddr_in* destAddr = reinterpret_cast<sockaddr_in*>(to);
        uint16_t destPort = destAddr ? ntohs(destAddr->sin_port) : 0;
        
        // Get destination IP for logging
        char destIP[INET_ADDRSTRLEN];
        if (destAddr) {
            inet_ntop(AF_INET, &destAddr->sin_addr, destIP, sizeof(destIP));
        } else {
            strcpy(destIP, "?");
        }
        
#if UDP_CAPTURE_ONLY
        // === CAPTURE ONLY MODE - Log everything, send unmodified ===
        // Decode packet type if possible
        uint32_t pktType = (len >= 4) ? *reinterpret_cast<uint32_t*>(buf) : 0;
        
        // Log raw packet data as hex
        char hexBuf[512];
        int hexLen = 0;
        for (int i = 0; i < len && hexLen < 500; i++) {
            hexLen += sprintf(hexBuf + hexLen, "%02X ", (unsigned char)buf[i]);
        }
        
        LOG("[UDP-CAPTURE] SEND to %s:%d len=%d type=%d", 
            destIP, destPort, len, pktType);
        LOG("[UDP-CAPTURE] DATA: %s", hexBuf);
        
        // Log to traffic file for detailed analysis
        LogTrafficRaw("UDP-SEND", buf, len);
        
        // Send unmodified!
        return sendto(s, buf, len, flags, to, tolen);
#else
        // === RELAY MODE - Redirect through relay server ===
        
        // If server IP not set, can't relay - send directly
        if (g_serverIP == 0) {
            return sendto(s, buf, len, flags, to, tolen);
        }
        
        // IMPORTANT: In relay mode, ALL packets to port 3658 (relay port) must go through relay,
        // regardless of destination IP. The game might send to real peer IPs (from +ses ADDR),
        // but we need to intercept and redirect to relay server.
        //
        // Check if this is a game UDP packet (port 3658 OR game socket OR looks like game packet)
        const bool isRelayPort = destPort == RELAY_PORT;
        const bool isGameSocket = (s == g_gameSocket);
        const bool looksLikeGamePacket = (len == 8) && (destAddr != nullptr) && 
                                         (*reinterpret_cast<uint32_t*>(buf) == 1 || 
                                          *reinterpret_cast<uint32_t*>(buf) == 5);
        
        // Treat any socket that talks to relay IP:RELAY_PORT as "game UDP"
        const bool toRelayServer = destAddr && 
                                   (destAddr->sin_addr.s_addr == g_serverIP) && 
                                   (destPort == RELAY_PORT);

        // Auto-capture game socket based on packet characteristics
        // This is critical for HOST who sends packets before Bind hook captures socket
        if (g_gameSocket == INVALID_SOCKET) {
            // Capture if sending to relay port (3658) - regardless of IP!
            if (isRelayPort) {
                g_gameSocket = s;
                LOG("[UDP] Auto-captured game socket from SendTo: %d (dest port 3658, IP=%s)", 
                    (int)s, destIP);
            }
            // Capture if this looks like a game UDP packet (8 bytes, type 1 or 5)
            else if (looksLikeGamePacket) {
                g_gameSocket = s;
                LOG("[UDP] Auto-captured game socket from SendTo: %d (type=%d packet)", (int)s, 
                    *reinterpret_cast<uint32_t*>(buf));
            }
            // Capture any UDP socket sending to server IP (likely game traffic)
            else if (destAddr && destAddr->sin_addr.s_addr == g_serverIP) {
                g_gameSocket = s;
                LOG("[UDP] Auto-captured game socket from SendTo: %d (dest=server)", (int)s);
            }
        }
        
        // CRITICAL: Intercept ALL packets to port 3658 (relay port), even if destination IP
        // is a peer's real IP. The game sends to peer IPs from +ses ADDR, but we must
        // redirect to relay server. Also intercept if it's the game socket.
        if (!isRelayPort && !isGameSocket && !toRelayServer) {
            // Not relay port, not game socket, not relay server -> send directly (non-game traffic)
            LOG("[UDP] SendTo DIRECT (not intercepted): dest=%s:%d, socket=%d, len=%d", 
                destIP, destPort, (int)s, len);
            return sendto(s, buf, len, flags, to, tolen);
        }
        
        // Game socket -> wrap in relay header and send to relay server
        uint32_t packetType = (len >= 4) ? *reinterpret_cast<uint32_t*>(buf) : 0;
        
        LOG("[UDP] SendTo RELAY: dest=%s:%d, len=%d, type=%d, isRelayPort=%d, isGameSocket=%d, toRelayServer=%d", 
            destIP, destPort, len, packetType, isRelayPort, isGameSocket, toRelayServer);

        // Build relay packet: [2 bytes dest port][4 bytes dest IP][payload...]
        // Copy payload after 6-byte relay header
        memmove(g_relayBuffer + 6, buf, len);
        
        // IMPORTANT: Store ORIGINAL destination in relay header (even if it's a peer's real IP)
        // The relay server will use gameId to route to correct clients, but the header
        // preserves the original intent for debugging/logging
        *reinterpret_cast<uint16_t*>(g_relayBuffer) = destAddr->sin_port;  // Network byte order
        *reinterpret_cast<uint32_t*>(g_relayBuffer + 2) = destAddr->sin_addr.s_addr;

        // Always send to relay server (even if game thinks it's sending to peer IP)
        // The relay server will forward to correct clients based on gameId
        g_relayDest.sin_family = AF_INET;
        g_relayDest.sin_port = htons(RELAY_PORT);  // 3658
        g_relayDest.sin_addr.s_addr = g_serverIP;

        int result = sendto(s, g_relayBuffer, len + 6, flags, 
                           reinterpret_cast<sockaddr*>(&g_relayDest), 16);

        if (result < 0) {
            LOG("[UDP] SendTo RELAY FAILED: error=%d", WSAGetLastError());
        } else {
            // Adjust return value to hide relay header from game
            result -= 6;
        }

        return result;
#endif
    }

    // ========================================================================
    // sub_10003000 - Bind hook (EXACT copy of original NFSOR)
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
