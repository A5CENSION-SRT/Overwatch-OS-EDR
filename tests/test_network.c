/**
 * Test program: Network Syscalls
 * 
 * This test demonstrates network-related syscalls that
 * the EDR should monitor for suspicious connections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void) {
    printf("=== Network Syscall Test ===\n\n");
    
    /* Test 1: Create a socket */
    printf("[1] Creating TCP socket...\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("    socket");
        return 1;
    }
    printf("    Socket created (fd=%d)\n", sock);
    
    /* Test 2: Attempt connection to localhost:80 (will likely fail, but that's OK) */
    printf("\n[2] Attempting connection to 127.0.0.1:80...\n");
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    
    /* This will likely fail (connection refused), but the syscall is what matters */
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("    Connection failed (expected on most systems)\n");
    } else {
        printf("    Connected!\n");
    }
    
    close(sock);
    
    /* Test 3: Create a UDP socket */
    printf("\n[3] Creating UDP socket...\n");
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        printf("    UDP socket created (fd=%d)\n", sock);
        close(sock);
    }
    
    printf("\n=== Test Complete ===\n");
    printf("(The EDR should have logged all socket/connect syscalls)\n");
    return 0;
}
