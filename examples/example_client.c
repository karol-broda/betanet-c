#include <stdio.h>
#include <string.h>
#include "betanet.h"

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <betanet-uri>\\n", argv[0]);
        return 1;
    }

    if (betanet_init(NULL) != 0) {
        fprintf(stderr, "failed to initialize betanet\\n");
        return 1;
    }

    const char* uri = argv[1];
    printf("resolving uri: %s\\n", uri);

    betanet_addr_t addr = betanet_resolve(uri);
    if (addr == NULL) {
        fprintf(stderr, "failed to resolve uri\\n");
        betanet_cleanup();
        return 1;
    }

    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        fprintf(stderr, "failed to create socket\\n");
        betanet_free_addr(addr);
        betanet_cleanup();
        return 1;
    }

    printf("connecting...\\n");
    if (betanet_connect(sock, addr) != 0) {
        fprintf(stderr, "failed to connect\\n");
        betanet_close(sock);
        betanet_free_addr(addr);
        betanet_cleanup();
        return 1;
    }

    printf("connected! sending message.\\n");
    const char* message = "hello, betanet!";
    ssize_t sent = betanet_send(sock, message, strlen(message));
    if (sent < 0) {
        fprintf(stderr, "failed to send message\\n");
    }

    betanet_close(sock);
    betanet_free_addr(addr);
    betanet_cleanup();

    return 0;
}
