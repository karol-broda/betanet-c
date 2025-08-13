/**
 * @file example_server.c
 * @brief example betanet server application
 * 
 * demonstrates how to:
 * - initialize the betanet library
 * - bind to a local address
 * - listen for incoming secure connections
 * - handle clients with encrypted communication
 */

#include "betanet.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

static volatile int running = 1;

static void signal_handler(int sig) {
    (void)sig;
    running = 0;
    printf("\nshutdown signal received...\n");
    exit(0);
}

int main(int argc, char **argv) {
    // setup signal handler for clean shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("betanet server example\n");
    printf("=====================\n\n");

    // determine bind address
    const char *bind_addr = (argc > 1) ? argv[1] : "127.0.0.1:8080";
    printf("bind address: %s\n", bind_addr);
    printf("press ctrl+c to stop\n\n");

    // initialize library
    printf("[1/4] initializing betanet library...\n");
    if (betanet_init(NULL) != 0) {
        fprintf(stderr, "error: failed to initialize betanet\n");
        return 1;
    }
    printf("[ok] library initialized\n\n");

    // create socket
    printf("[2/4] creating socket...\n");
    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        fprintf(stderr, "error: failed to create socket\n");
        betanet_cleanup();
        return 1;
    }
    printf("[ok] socket created\n\n");

    // resolve and bind to local address
    printf("[3/4] binding to address...\n");
    betanet_addr_t local_addr = betanet_resolve(bind_addr);
    if (local_addr == NULL) {
        fprintf(stderr, "error: failed to resolve bind address '%s'\n", bind_addr);
        betanet_close(sock);
        betanet_cleanup();
        return 1;
    }

    if (betanet_bind(sock, local_addr) != 0) {
        fprintf(stderr, "error: failed to bind to %s\n", bind_addr);
        fprintf(stderr, "note: address may already be in use\n");
        betanet_free_addr(local_addr);
        betanet_close(sock);
        betanet_cleanup();
        return 1;
    }
    printf("[ok] bound to %s\n\n", bind_addr);

    // start listening
    printf("[4/4] starting to listen for connections...\n");
    if (betanet_listen(sock, 10) != 0) {
        fprintf(stderr, "error: failed to listen\n");
        betanet_free_addr(local_addr);
        betanet_close(sock);
        betanet_cleanup();
        return 1;
    }
    printf("[ok] listening for connections\n\n");

    printf("server ready! waiting for clients...\n\n");

    int client_count = 0;
    while (running) {
        betanet_addr_t client_addr = NULL;
        betanet_socket_t client_sock = betanet_accept(sock, &client_addr);
        
        if (client_sock == NULL) {
            if (running) {
                fprintf(stderr, "warning: failed to accept connection\n");
            }
            continue;
        }

        client_count++;
        printf("[client %d] secure connection established\n", client_count);
        printf("[client %d] performing htx bootstrap + noise xk handshake\n", client_count);

        // add small delay to ensure client message arrives
        usleep(50000); // 50ms

        // receive encrypted message
        char buffer[1024];
        uint64_t request_stream_id;
        ssize_t received = betanet_recv(client_sock, buffer, sizeof(buffer) - 1, &request_stream_id);
        if (received > 0) {
            buffer[received] = '\0';
            printf("[client %d] received encrypted message: %s\n", client_count, buffer);
            
            // send encrypted response on the same stream as the request
            const char *response = "hello from betanet server!";
            ssize_t sent = betanet_send_response(client_sock, response, strlen(response), request_stream_id);
            if (sent > 0) {
                printf("[client %d] sent encrypted response (%zd bytes) on stream %llu\n", client_count, sent, (unsigned long long)request_stream_id);
            } else {
                printf("[client %d] failed to send response\n", client_count);
            }
        } else if (received == 0) {
            printf("[client %d] client closed connection\n", client_count);
        } else {
            printf("[client %d] failed to receive data\n", client_count);
        }

        printf("[client %d] closing connection\n\n", client_count);
        betanet_close(client_sock);
        if (client_addr != NULL) {
            betanet_free_addr(client_addr);
        }
    }

    // cleanup
    printf("\nshutting down server...\n");
    betanet_free_addr(local_addr);
    betanet_close(sock);
    betanet_cleanup();
    printf("[ok] server shutdown completed\n");

    return 0;
}
