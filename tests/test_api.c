#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cmocka.h>

#include "betanet_internal.h"

// test library initialization
static void test_betanet_init_default(void **state) {
    (void)state;

    // test default initialization
    int result = betanet_init(NULL);
    assert_int_equal(result, 0);

    // test double initialization (should succeed)
    result = betanet_init(NULL);
    assert_int_equal(result, 0);

    betanet_cleanup();
}

static void test_betanet_init_with_options(void **state) {
    (void)state;

    betanet_init_options_t options = {.cache_path = "/tmp/test_betanet_cache"};

    int result = betanet_init(&options);
    assert_int_equal(result, 0);

    betanet_cleanup();
}

// test socket creation and management
static void test_betanet_socket_creation(void **state) {
    (void)state;

    betanet_socket_t sock = betanet_socket();
    assert_non_null(sock);

    int result = betanet_close(sock);
    assert_int_equal(result, 0);
}

static void test_betanet_socket_options(void **state) {
    (void)state;

    betanet_socket_t sock = betanet_socket();
    assert_non_null(sock);

    // test privacy mode setting
    betanet_privacy_mode_t mode = BETANET_PRIVACY_STRICT;
    int result = betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &mode);
    assert_int_equal(result, 0);

    // test timeout setting
    int timeout = 60000;
    result = betanet_setsockopt(sock, BETANET_OPT_CONNECT_TIMEOUT_MS, &timeout);
    assert_int_equal(result, 0);

    betanet_close(sock);
}

static void test_betanet_socket_options_invalid(void **state) {
    (void)state;

    betanet_socket_t sock = betanet_socket();
    assert_non_null(sock);

    // test null socket
    betanet_privacy_mode_t mode = BETANET_PRIVACY_BALANCED;
    int result = betanet_setsockopt(NULL, BETANET_OPT_PRIVACY_MODE, &mode);
    assert_int_equal(result, -1);

    // test null value
    result = betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, NULL);
    assert_int_equal(result, -1);

    // test invalid privacy mode
    betanet_privacy_mode_t invalid_mode = 999;
    result = betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &invalid_mode);
    assert_int_equal(result, -1);

    // test invalid timeout
    int invalid_timeout = -1;
    result = betanet_setsockopt(sock, BETANET_OPT_CONNECT_TIMEOUT_MS, &invalid_timeout);
    assert_int_equal(result, -1);

    betanet_close(sock);
}

// test address resolution
static void test_betanet_resolve_success(void **state) {
    (void)state;

    betanet_addr_t addr = betanet_resolve("127.0.0.1:8080");
    assert_non_null(addr);

    betanet_free_addr(addr);
}

static void test_betanet_resolve_invalid(void **state) {
    (void)state;

    // test null uri
    betanet_addr_t addr = betanet_resolve(NULL);
    assert_null(addr);

    // test invalid format (no port)
    addr = betanet_resolve("127.0.0.1");
    assert_null(addr);

    // test invalid format (no host)
    addr = betanet_resolve(":8080");
    assert_null(addr);

    // test invalid port
    addr = betanet_resolve("127.0.0.1:0");
    assert_null(addr);

    addr = betanet_resolve("127.0.0.1:99999");
    assert_null(addr);
}

// test connection establishment
static void test_betanet_connect_invalid_params(void **state) {
    (void)state;

    betanet_addr_t addr = betanet_resolve("127.0.0.1:8080");

    // test null socket
    int result = betanet_connect(NULL, addr);
    assert_int_equal(result, -1);

    betanet_free_addr(addr);
}

static void test_betanet_connect_discovery(void **state) {
    (void)state;

    betanet_socket_t sock = betanet_socket();

    // test discovery (will fail because it can't connect)
    int result = betanet_connect(sock, NULL);
    assert_int_equal(result, -1);

    betanet_close(sock);
}

// test send/recv functions
static void test_betanet_send_recv_invalid_params(void **state) {
    (void)state;

    betanet_socket_t sock = betanet_socket();
    char buffer[100];

    // test send with null socket
    ssize_t result = betanet_send(NULL, buffer, sizeof(buffer));
    assert_int_equal(result, -1);

    // test send with null buffer
    result = betanet_send(sock, NULL, sizeof(buffer));
    assert_int_equal(result, -1);

    // test send on unconnected socket
    result = betanet_send(sock, buffer, sizeof(buffer));
    assert_int_equal(result, -1);

    // test recv with null socket
    uint64_t stream_id;
    result = betanet_recv(NULL, buffer, sizeof(buffer), &stream_id);
    assert_int_equal(result, -1);

    // test recv with null buffer
    result = betanet_recv(sock, NULL, sizeof(buffer), &stream_id);
    assert_int_equal(result, -1);

    // test recv on unconnected socket
    result = betanet_recv(sock, buffer, sizeof(buffer), &stream_id);
    assert_int_equal(result, -1);

    betanet_close(sock);
}

// test socket cleanup
static void test_betanet_close_invalid(void **state) {
    (void)state;

    // test closing null socket
    int result = betanet_close(NULL);
    assert_int_equal(result, -1);
}

// test complete api workflow
static void test_betanet_api_workflow(void **state) {
    (void)state;

    // initialize library
    betanet_init_options_t options = {.cache_path = "/tmp/test_workflow_cache"};
    int result = betanet_init(&options);
    assert_int_equal(result, 0);

    // create socket
    betanet_socket_t sock = betanet_socket();
    assert_non_null(sock);

    // set socket options
    betanet_privacy_mode_t mode = BETANET_PRIVACY_BALANCED;
    result = betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &mode);
    assert_int_equal(result, 0);

    // resolve address
    betanet_addr_t addr = betanet_resolve("127.0.0.1:9999");
    assert_non_null(addr);

    // note: we don't test actual connection as it requires a server
    // the connection logic is tested separately

    // cleanup
    betanet_free_addr(addr);
    betanet_close(sock);
    betanet_cleanup();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_betanet_init_default),
        cmocka_unit_test(test_betanet_init_with_options),
        cmocka_unit_test(test_betanet_socket_creation),
        cmocka_unit_test(test_betanet_socket_options),
        cmocka_unit_test(test_betanet_socket_options_invalid),
        cmocka_unit_test(test_betanet_resolve_success),
        cmocka_unit_test(test_betanet_resolve_invalid),
        cmocka_unit_test(test_betanet_connect_invalid_params),
        cmocka_unit_test(test_betanet_connect_discovery),
        cmocka_unit_test(test_betanet_send_recv_invalid_params),
        cmocka_unit_test(test_betanet_close_invalid),
        cmocka_unit_test(test_betanet_api_workflow),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
