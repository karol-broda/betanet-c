#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cmocka.h>

#include "betanet_internal.h"

#define TEST_PORT 8888
#define TEST_MESSAGE "hello, betanet server!"

typedef struct {
    int ready;
    int success;
} server_thread_state_t;

// server thread function
static void *server_thread_func(void *arg) {
    server_thread_state_t *state = (server_thread_state_t *)arg;
    state->success = 0;

    betanet_socket_t listen_sock = betanet_socket();
    if (listen_sock == NULL) {
        return NULL;
    }

    char addr_str[256];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", TEST_PORT);

    betanet_addr_t local_addr = betanet_resolve(addr_str);
    if (local_addr == NULL) {
        betanet_close(listen_sock);
        return NULL;
    }

    if (betanet_bind(listen_sock, local_addr) != 0) {
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        return NULL;
    }

    if (betanet_listen(listen_sock, 1) != 0) {
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        return NULL;
    }

    state->ready = 1; // signal that server is ready

    betanet_addr_t client_addr = NULL;
    betanet_socket_t client_sock = betanet_accept(listen_sock, &client_addr);
    if (client_sock == NULL) {
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        return NULL;
    }

    // receive data from client
    char buffer[1024];
    uint64_t request_stream_id;
    ssize_t received = betanet_recv(client_sock, buffer, sizeof(buffer) - 1, &request_stream_id);
    if (received <= 0) {
        betanet_free_addr(client_addr);
        betanet_close(client_sock);
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        return NULL;
    }

    buffer[received] = '\0';

    // check if received message is correct
    if (strcmp(buffer, TEST_MESSAGE) != 0) {
        betanet_free_addr(client_addr);
        betanet_close(client_sock);
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        return NULL;
    }

    // send response
    const char *response = "hello, client!";
    if (betanet_send(client_sock, response, strlen(response)) <= 0) {
        betanet_free_addr(client_addr);
        betanet_close(client_sock);
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        return NULL;
    }

    state->success = 1;

    // cleanup
    betanet_free_addr(client_addr);
    betanet_close(client_sock);
    betanet_free_addr(local_addr);
    betanet_close(listen_sock);

    return NULL;
}

static void test_betanet_server_basic(void **state) {
    (void)state;

    // initialize library
    assert_int_equal(betanet_init(NULL), 0);

    // test basic server operations without full handshake
    betanet_socket_t server_sock = betanet_socket();
    assert_non_null(server_sock);

    char addr_str[256];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", TEST_PORT);

    betanet_addr_t local_addr = betanet_resolve(addr_str);
    assert_non_null(local_addr);

    // test bind
    assert_int_equal(betanet_bind(server_sock, local_addr), 0);

    // test listen
    assert_int_equal(betanet_listen(server_sock, 1), 0);

    // cleanup
    betanet_close(server_sock);
    betanet_free_addr(local_addr);
    betanet_cleanup();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_betanet_server_basic),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
