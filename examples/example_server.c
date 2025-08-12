#include <stdio.h>
#include "betanet.h"

int main(int argc, char** argv) {
    if (betanet_init(NULL) != 0) {
        fprintf(stderr, "failed to initialize betanet\\n");
        return 1;
    }

    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        fprintf(stderr, "failed to create socket\\n");
        betanet_cleanup();
        return 1;
    }

    // in a real server, we'd resolve a local alias to bind to
    // for now, we just listen for incoming connections
    if (betanet_listen(sock, 10) != 0) {
        fprintf(stderr, "failed to listen\\n");
        betanet_close(sock);
        betanet_cleanup();
        return 1;
    }

    printf("listening for connections...\\n");

    while (1) {
        betanet_addr_t client_addr = NULL;
        betanet_socket_t client_sock = betanet_accept(sock, &client_addr);
        if (client_sock == NULL) {
            fprintf(stderr, "failed to accept connection\\n");
            continue;
        }

        printf("accepted connection!\\n");

        char buffer[1024];
        ssize_t received = betanet_recv(client_sock, buffer, sizeof(buffer) - 1);
        if (received > 0) {
            buffer[received] = '\0';
            printf("received: %s\\n", buffer);
        }

        betanet_close(client_sock);
        betanet_free_addr(client_addr);
    }

    betanet_close(sock);
    betanet_cleanup();

    return 0;
}
