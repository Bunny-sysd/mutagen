#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#define SOCKET int
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

// A dummy network server that listens on port 8888
// It has a classic buffer overflow vulnerability when parsing the payload.

void process_client_data(char *data) {
    // VULNERABILITY: Unsafe copy from network input
    char buffer[128];
    printf("[*] Processing %zu bytes of data...\n", strlen(data));
    strcpy(buffer, data); // BOOM!
    printf("[*] Data processed successfully.\n");
}

int main(int argc, char *argv[]) {
    SOCKET listenSocket = INVALID_SOCKET, clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char recvbuf[1024];
    int recvbuflen = 1024;
    int port = 8888;

#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("[-] WSAStartup failed.\n");
        return 1;
    }
#endif

    listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        printf("[-] Socket creation failed.\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(port);

    if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("[-] Bind failed.\n");
        closesocket(listenSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("[-] Listen failed.\n");
        closesocket(listenSocket);
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }

    printf("[+] Listening on 127.0.0.1:%d...\n", port);

    // Accept one connection and then exit, to work nicely with the fuzzer
    clientSocket = accept(listenSocket, NULL, NULL);
    if (clientSocket != INVALID_SOCKET) {
        printf("[+] Client connected.\n");
        memset(recvbuf, 0, recvbuflen);
        int bytesReceived = recv(clientSocket, recvbuf, recvbuflen - 1, 0);
        if (bytesReceived > 0) {
            printf("[+] Received %d bytes from client.\n", bytesReceived);
            process_client_data(recvbuf);
        }
        closesocket(clientSocket);
    }

    closesocket(listenSocket);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
