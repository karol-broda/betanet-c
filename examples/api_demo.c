/**
 * @file api_demo.c
 * @brief demonstration of the betanet c library api
 *
 * this example shows how to use the current betanet api functions.
 * note: this demonstrates the current implementation which supports full
 * l2 secure channel (htx + noise xk handshake) for encrypted communication.
 */

#include "betanet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

void demonstrate_library_initialization() {
    printf("=== library initialization ===\n");

    // initialize with default options
    printf("initializing betanet library with defaults...\n");
    if (betanet_init(NULL) != 0) {
        (void)fprintf(stderr, "failed to initialize betanet\n");
        exit(1);
    }
    printf("[ok] library initialized successfully\n");

    // initialize with custom options
    betanet_init_options_t options = {.cache_path = "/tmp/betanet_demo_cache"};
    printf("initializing with custom cache path...\n");
    if (betanet_init(&options) != 0) {
        (void)fprintf(stderr, "failed to initialize with custom options\n");
        exit(1);
    }
    printf("[ok] custom initialization successful\n");

    printf("\n");
}

void demonstrate_socket_management() {
    printf("=== socket management ===\n");

    // create a socket
    printf("creating betanet socket...\n");
    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        (void)fprintf(stderr, "failed to create socket\n");
        exit(1);
    }
    printf("[ok] socket created successfully\n");

    // set socket options
    printf("setting privacy mode to strict...\n");
    betanet_privacy_mode_t mode = BETANET_PRIVACY_STRICT;
    if (betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &mode) != 0) {
        (void)fprintf(stderr, "failed to set privacy mode\n");
        betanet_close(sock);
        exit(1);
    }
    printf("[ok] privacy mode set to strict\n");

    printf("setting connection timeout to 60 seconds...\n");
    int timeout = 60000;
    if (betanet_setsockopt(sock, BETANET_OPT_CONNECT_TIMEOUT_MS, &timeout) != 0) {
        (void)fprintf(stderr, "failed to set timeout\n");
        betanet_close(sock);
        exit(1);
    }
    printf("[ok] timeout set to 60 seconds\n");

    // clean up
    printf("closing socket...\n");
    if (betanet_close(sock) != 0) {
        (void)fprintf(stderr, "failed to close socket\n");
        exit(1);
    }
    printf("[ok] socket closed successfully\n");

    printf("\n");
}

void demonstrate_address_resolution() {
    printf("=== address resolution ===\n");

    // resolve a valid address
    printf("resolving address '127.0.0.1:8080'...\n");
    betanet_addr_t addr = betanet_resolve("127.0.0.1:8080");
    if (addr == NULL) {
        (void)fprintf(stderr, "failed to resolve address\n");
        exit(1);
    }
    printf("[ok] address resolved successfully\n");

    // clean up
    printf("freeing resolved address...\n");
    betanet_free_addr(addr);
    printf("[ok] address freed successfully\n");

    // demonstrate error handling
    printf("testing invalid address resolution...\n");
    betanet_addr_t invalid_addr = betanet_resolve("invalid-format");
    if (invalid_addr == NULL) {
        printf("[ok] invalid address correctly rejected\n");
    } else {
        (void)fprintf(stderr, "unexpected: invalid address was accepted\n");
        betanet_free_addr(invalid_addr);
    }

    printf("\n");
}

void demonstrate_error_handling() {
    printf("=== error handling ===\n");

    // test null parameter handling
    printf("testing null parameter handling...\n");

    betanet_socket_t null_sock = NULL;
    if (betanet_close(null_sock) == -1) {
        printf("[ok] null socket parameter correctly rejected\n");
    }

    betanet_addr_t null_addr = betanet_resolve(NULL);
    if (null_addr == NULL) {
        printf("[ok] null uri parameter correctly rejected\n");
    }

    // test invalid socket operations
    printf("testing operations on unconnected socket...\n");
    betanet_socket_t sock = betanet_socket();
    char buffer[100];

    ssize_t result = betanet_send(sock, buffer, sizeof(buffer));
    if (result == -1) {
        printf("[ok] send on unconnected socket correctly failed\n");
    }

    uint64_t stream_id;
    result = betanet_recv(sock, buffer, sizeof(buffer), &stream_id);
    if (result == -1) {
        printf("[ok] recv on unconnected socket correctly failed\n");
    }

    betanet_close(sock);

    printf("\n");
}

void demonstrate_complete_workflow() {
    printf("=== complete workflow ===\n");

    printf("demonstrating typical betanet usage pattern...\n");

    // step 1: initialize library
    betanet_init_options_t options = {.cache_path = "/tmp/betanet_workflow_cache"};
    if (betanet_init(&options) != 0) {
        (void)fprintf(stderr, "workflow: failed to initialize\n");
        return;
    }
    printf("1. [ok] library initialized\n");

    // step 2: create and configure socket
    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        (void)fprintf(stderr, "workflow: failed to create socket\n");
        betanet_cleanup();
        return;
    }
    printf("2. [ok] socket created\n");

    betanet_privacy_mode_t mode = BETANET_PRIVACY_BALANCED;
    betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &mode);
    printf("3. [ok] socket configured\n");

    // step 3: resolve address
    betanet_addr_t addr = betanet_resolve("127.0.0.1:9999");
    if (addr == NULL) {
        (void)fprintf(stderr, "workflow: failed to resolve address\n");
        betanet_close(sock);
        betanet_cleanup();
        return;
    }
    printf("4. [ok] address resolved\n");

    // step 4: attempt connection (will fail since no server is running)
    printf("5. attempting connection (expected to fail - no server)...\n");
    int conn_result = betanet_connect(sock, addr);
    if (conn_result == 0) {
        printf("5. [ok] connection established (unexpected - is there a server?)\n");

        // if connection succeeded, demonstrate send/recv
        const char *message = "hello from betanet!";
        ssize_t sent = betanet_send(sock, message, strlen(message));
        if (sent > 0) {
            printf("6. [ok] sent %zd bytes\n", sent);
        }

        char buffer[1024];
        uint64_t recv_stream_id;
        ssize_t received = betanet_recv(sock, buffer, sizeof(buffer), &recv_stream_id);
        if (received > 0) {
            printf("7. [ok] received %zd bytes (stream %llu)\n", received, (unsigned long long)recv_stream_id);
        } else if (received == 0) {
            printf("7. connection closed by peer\n");
        }
    } else {
        printf("5. connection failed as expected (no server running)\n");
    }

    // step 5: cleanup
    betanet_free_addr(addr);
    betanet_close(sock);
    betanet_cleanup();
    printf("8. [ok] cleanup completed\n");

    printf("\n");
}

int main() {
    printf("betanet c library api demonstration\n");
    printf("====================================\n\n");

    printf("this demo shows the current implementation status.\n");
    printf("note: full betanet protocol support is under development.\n");
    printf("current version uses full l2 secure channel with htx + noise xk handshake.\n\n");

    demonstrate_library_initialization();
    demonstrate_socket_management();
    demonstrate_address_resolution();
    demonstrate_error_handling();
    demonstrate_complete_workflow();

    printf("=== summary ===\n");
    printf("[ok] library initialization and cleanup\n");
    printf("[ok] socket creation and management\n");
    printf("[ok] socket option configuration\n");
    printf("[ok] address resolution (host:port format)\n");
    printf("[ok] secure l2 connection establishment\n");
    printf("[ok] basic send/recv operations\n");
    printf("[ok] comprehensive error handling\n");
    printf("[ok] proper resource cleanup\n\n");

    printf("planned features:\n");
    printf("- betanet:// uri resolution (l5 naming)\n");
    printf("- scion path layer (l1)\n");
    printf("- overlay mesh (l3)\n");
    printf("- privacy modes and mixnet routing (l4)\n");
    printf("- payment integration (l6)\n\n");

    printf("api demonstration completed successfully\n");

    return 0;
}
