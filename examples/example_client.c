/**
 * @file example_client.c
 * @brief example betanet client application
 * 
 * demonstrates how to:
 * - initialize the betanet library
 * - resolve addresses (currently host:port format)
 * - establish secure l2 connections
 * - send data over encrypted channels
 */

#include "betanet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <host:port>\n", argv[0]);
        fprintf(stderr, "example: %s 127.0.0.1:8080\n", argv[0]);
        return 1;
    }

    printf("betanet client example\n");
    printf("=====================\n\n");

    // initialize library
    printf("[1/5] initializing betanet library...\n");
    if (betanet_init(NULL) != 0) {
        fprintf(stderr, "error: failed to initialize betanet\n");
        return 1;
    }
    printf("[ok] library initialized\n\n");

    // resolve address
    const char *address = argv[1];
    printf("[2/5] resolving address: %s\n", address);
    betanet_addr_t addr = betanet_resolve(address);
    if (addr == NULL) {
        fprintf(stderr, "error: failed to resolve address '%s'\n", address);
        fprintf(stderr, "note: use format 'host:port' (e.g., '127.0.0.1:8080')\n");
        betanet_cleanup();
        return 1;
    }
    printf("[ok] address resolved\n\n");

    // create socket
    printf("[3/5] creating socket...\n");
    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        fprintf(stderr, "error: failed to create socket\n");
        betanet_free_addr(addr);
        betanet_cleanup();
        return 1;
    }
    printf("[ok] socket created\n\n");

    // establish secure connection
    printf("[4/5] establishing secure l2 connection...\n");
    printf("note: this performs htx bootstrap + noise xk handshake\n");
    if (betanet_connect(sock, addr) != 0) {
        fprintf(stderr, "error: failed to connect to %s\n", address);
        fprintf(stderr, "note: ensure server is running and reachable\n");
        betanet_close(sock);
        betanet_free_addr(addr);
        betanet_cleanup();
        return 1;
    }
    printf("[ok] secure connection established\n\n");

    // send encrypted message
    printf("[5/5] sending encrypted message...\n");
    const char *message = "hello from betanet client!";
    ssize_t sent = betanet_send(sock, message, strlen(message));
    if (sent < 0) {
        fprintf(stderr, "error: failed to send message\n");
        betanet_close(sock);
        betanet_free_addr(addr);
        betanet_cleanup();
        return 1;
    }
    printf("[ok] sent %zd bytes (encrypted)\n", sent);

    // wait for response without artificial delay - proper protocol prevents deadlock
    printf("waiting for response...\n");
    
    // add small delay to help with timing
    usleep(100000); // 100ms
    
    char buffer[1024];
    uint64_t response_stream_id;
    ssize_t received = betanet_recv(sock, buffer, sizeof(buffer) - 1, &response_stream_id);
    if (received > 0) {
        buffer[received] = '\0';
        printf("[ok] received response: %s (on stream %llu)\n", buffer, (unsigned long long)response_stream_id);
    } else if (received == 0) {
        printf("server closed connection\n");
    } else {
        printf("no response received\n");
    }

    // cleanup
    printf("\ncleaning up...\n");
    betanet_close(sock);
    betanet_free_addr(addr);
    betanet_cleanup();
    printf("[ok] cleanup completed\n\n");

    printf("client example completed successfully!\n");
    return 0;
}
