#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>

#include "betanet_internal.h"

// test access ticket generation
static void test_htx_generate_access_ticket_success(void **state) {
    (void)state;

    // create mock server info
    htx_server_ticket_info_t server_info;
    memset(&server_info, 0, sizeof(server_info));

    // set up a test server public key
    for (int i = 0; i < 32; i++) {
        server_info.ticket_pub[i] = (uint8_t)i;
    }

    // set up ticket key id
    for (int i = 0; i < 8; i++) {
        server_info.ticket_key_id[i] = (uint8_t)(i + 0x10);
    }

    server_info.min_len = 120; // must be larger than base structure (105 bytes)
    server_info.max_len = 180;

    // test ticket generation
    uint8_t payload[200];
    size_t payload_len = sizeof(payload);

    int result =
        htx_generate_access_ticket(payload, &payload_len, &server_info, HTX_CARRIER_COOKIE);

    assert_int_equal(result, 0);
    assert_true(payload_len >= server_info.min_len);
    assert_true(payload_len <= server_info.max_len);

    // verify structure
    assert_int_equal(payload[0], 0x01); // version

    // verify ticket key id is copied correctly
    assert_memory_equal(&payload[1 + 32], server_info.ticket_key_id, 8);
}

static void test_htx_generate_access_ticket_invalid_params(void **state) {
    (void)state;

    htx_server_ticket_info_t server_info;
    uint8_t payload[200];
    size_t payload_len = sizeof(payload);

    // test null payload
    int result = htx_generate_access_ticket(NULL, &payload_len, &server_info, HTX_CARRIER_COOKIE);
    assert_int_equal(result, -1);

    // test null payload_len
    result = htx_generate_access_ticket(payload, NULL, &server_info, HTX_CARRIER_COOKIE);
    assert_int_equal(result, -1);

    // test null server_info
    result = htx_generate_access_ticket(payload, &payload_len, NULL, HTX_CARRIER_COOKIE);
    assert_int_equal(result, -1);
}

// test base64url encoding
static void test_htx_encode_base64url_success(void **state) {
    (void)state;

    uint8_t input[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    char encoded[100];
    size_t encoded_len = sizeof(encoded);

    int result = htx_encode_base64url(encoded, &encoded_len, input, sizeof(input));

    assert_int_equal(result, 0);
    assert_true(encoded_len > 0);
    assert_true(encoded_len < sizeof(encoded));

    // verify it's null-terminated
    assert_int_equal(encoded[encoded_len], '\0');

    // verify no padding characters (base64url should not have padding)
    assert_null(strchr(encoded, '='));
}

static void test_htx_encode_base64url_invalid_params(void **state) {
    (void)state;

    uint8_t input[] = {0x01, 0x02, 0x03};
    char encoded[100];
    size_t encoded_len = sizeof(encoded);

    // test null encoded buffer
    int result = htx_encode_base64url(NULL, &encoded_len, input, sizeof(input));
    assert_int_equal(result, -1);

    // test null encoded_len
    result = htx_encode_base64url(encoded, NULL, input, sizeof(input));
    assert_int_equal(result, -1);

    // test null input
    result = htx_encode_base64url(encoded, &encoded_len, NULL, sizeof(input));
    assert_int_equal(result, -1);
}

// test http request construction
static void test_htx_construct_http_request_cookie(void **state) {
    (void)state;

    char request[2048];
    size_t request_len = sizeof(request);
    const char *host = "example.com";
    const char *path = "/test";
    const char *payload = "dGVzdHBheWxvYWQ";

    int result =
        htx_construct_http_request(request, &request_len, host, path, payload, HTX_CARRIER_COOKIE);

    assert_int_equal(result, 0);
    assert_true(request_len > 0);
    assert_true(request_len < sizeof(request));

    // verify it contains expected elements
    assert_non_null(strstr(request, "GET /test HTTP/1.1"));
    assert_non_null(strstr(request, "Host: example.com"));
    assert_non_null(strstr(request, "__Host-example.com=dGVzdHBheWxvYWQ"));
    assert_non_null(strstr(request, "Cookie:"));
}

static void test_htx_construct_http_request_query(void **state) {
    (void)state;

    char request[2048];
    size_t request_len = sizeof(request);
    const char *host = "example.com";
    const char *path = "/test";
    const char *payload = "dGVzdHBheWxvYWQ";

    int result =
        htx_construct_http_request(request, &request_len, host, path, payload, HTX_CARRIER_QUERY);

    assert_int_equal(result, 0);
    assert_true(request_len > 0);

    // verify it contains expected elements
    assert_non_null(strstr(request, "GET /test?bn1=dGVzdHBheWxvYWQ HTTP/1.1"));
    assert_non_null(strstr(request, "Host: example.com"));
}

static void test_htx_construct_http_request_body(void **state) {
    (void)state;

    char request[2048];
    size_t request_len = sizeof(request);
    const char *host = "example.com";
    const char *path = "/test";
    const char *payload = "dGVzdHBheWxvYWQ";

    int result =
        htx_construct_http_request(request, &request_len, host, path, payload, HTX_CARRIER_BODY);

    assert_int_equal(result, 0);
    assert_true(request_len > 0);

    // verify it contains expected elements
    assert_non_null(strstr(request, "POST /test HTTP/1.1"));
    assert_non_null(strstr(request, "Host: example.com"));
    assert_non_null(strstr(request, "Content-Type: application/x-www-form-urlencoded"));
    assert_non_null(strstr(request, "bn1=dGVzdHBheWxvYWQ"));
}

static void test_htx_construct_http_request_invalid_params(void **state) {
    (void)state;

    char request[2048];
    size_t request_len = sizeof(request);
    const char *host = "example.com";
    const char *path = "/test";
    const char *payload = "dGVzdHBheWxvYWQ";

    // test null request buffer
    int result =
        htx_construct_http_request(NULL, &request_len, host, path, payload, HTX_CARRIER_COOKIE);
    assert_int_equal(result, -1);

    // test null host
    result =
        htx_construct_http_request(request, &request_len, NULL, path, payload, HTX_CARRIER_COOKIE);
    assert_int_equal(result, -1);

    // test invalid carrier type
    result = htx_construct_http_request(request, &request_len, host, path, payload, 99);
    assert_int_equal(result, -1);
}

// integration test: full access ticket flow
static void test_htx_access_ticket_integration(void **state) {
    (void)state;

    // create server info
    htx_server_ticket_info_t server_info;
    memset(&server_info, 0, sizeof(server_info));

    // generate server keypair for testing
    uint8_t server_priv[32];
    assert_int_equal(betanet_x25519_keypair(server_info.ticket_pub, server_priv), 0);

    // set ticket key id
    memcpy(server_info.ticket_key_id, "testkey1", 8);

    server_info.min_len = 120; // must be larger than base structure (105 bytes)
    server_info.max_len = 180;

    // generate access ticket
    uint8_t payload[200];
    size_t payload_len = sizeof(payload);

    int result =
        htx_generate_access_ticket(payload, &payload_len, &server_info, HTX_CARRIER_COOKIE);
    assert_int_equal(result, 0);

    // encode as base64url
    char encoded[400];
    size_t encoded_len = sizeof(encoded);

    result = htx_encode_base64url(encoded, &encoded_len, payload, payload_len);
    assert_int_equal(result, 0);

    // construct http request
    char request[2048];
    size_t request_len = sizeof(request);

    result = htx_construct_http_request(request, &request_len, "test.example.com", "/path", encoded,
                                        HTX_CARRIER_COOKIE);
    assert_int_equal(result, 0);

    // verify the complete request looks reasonable
    assert_non_null(strstr(request, "GET /path HTTP/1.1"));
    assert_non_null(strstr(request, "Host: test.example.com"));
    assert_non_null(strstr(request, "Cookie: __Host-test.example.com="));

    printf("Generated HTTP request:\n%s\n", request);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_htx_generate_access_ticket_success),
        cmocka_unit_test(test_htx_generate_access_ticket_invalid_params),
        cmocka_unit_test(test_htx_encode_base64url_success),
        cmocka_unit_test(test_htx_encode_base64url_invalid_params),
        cmocka_unit_test(test_htx_construct_http_request_cookie),
        cmocka_unit_test(test_htx_construct_http_request_query),
        cmocka_unit_test(test_htx_construct_http_request_body),
        cmocka_unit_test(test_htx_construct_http_request_invalid_params),
        cmocka_unit_test(test_htx_access_ticket_integration),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
