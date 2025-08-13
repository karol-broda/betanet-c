/**
 * @file test_integration_client_server.c
 * @brief comprehensive integration tests for client-server communication
 * 
 * these tests specifically cover the scenarios that should have caught
 * the frame header parsing bug that was allowing betanet_recv to fail
 * immediately after handshake completion.
 */

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
#include <errno.h>

#include "betanet_internal.h"

#define TEST_PORT_BASE 9000
#define TEST_MESSAGE "hello from client!"
#define TEST_RESPONSE "hello from server!"
#define MAX_RETRY_ATTEMPTS 5

// server thread state for integration tests
typedef struct {
    int port;
    int ready;
    int client_connected;
    int message_received;
    int response_sent;
    int test_passed;
    char received_message[256];
    pthread_mutex_t mutex;
    pthread_cond_t ready_cond;
} integration_server_state_t;

// server thread that performs complete betanet protocol
static void *integration_server_thread(void *arg) {
    integration_server_state_t *state = (integration_server_state_t *)arg;
    
    pthread_mutex_lock(&state->mutex);
    state->ready = 0;
    state->client_connected = 0;
    state->message_received = 0;
    state->response_sent = 0;
    state->test_passed = 0;
    pthread_mutex_unlock(&state->mutex);

    // initialize betanet
    if (betanet_init(NULL) != 0) {
        printf("[SERVER] failed to initialize betanet\n");
        return NULL;
    }

    // create and configure server socket
    betanet_socket_t listen_sock = betanet_socket();
    if (listen_sock == NULL) {
        printf("[SERVER] failed to create socket\n");
        betanet_cleanup();
        return NULL;
    }

    char addr_str[256];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", state->port);

    betanet_addr_t local_addr = betanet_resolve(addr_str);
    if (local_addr == NULL) {
        printf("[SERVER] failed to resolve %s\n", addr_str);
        betanet_close(listen_sock);
        betanet_cleanup();
        return NULL;
    }

    // bind and listen
    if (betanet_bind(listen_sock, local_addr) != 0) {
        printf("[SERVER] failed to bind to %s\n", addr_str);
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        betanet_cleanup();
        return NULL;
    }

    if (betanet_listen(listen_sock, 1) != 0) {
        printf("[SERVER] failed to listen\n");
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        betanet_cleanup();
        return NULL;
    }

    // signal that server is ready
    pthread_mutex_lock(&state->mutex);
    state->ready = 1;
    pthread_cond_signal(&state->ready_cond);
    pthread_mutex_unlock(&state->mutex);

    printf("[SERVER] listening on %s, waiting for client...\n", addr_str);

    // accept client connection
    betanet_addr_t client_addr = NULL;
    betanet_socket_t client_sock = betanet_accept(listen_sock, &client_addr);
    if (client_sock == NULL) {
        printf("[SERVER] failed to accept client connection\n");
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        betanet_cleanup();
        return NULL;
    }

    pthread_mutex_lock(&state->mutex);
    state->client_connected = 1;
    pthread_mutex_unlock(&state->mutex);

    printf("[SERVER] client connected, performing handshake...\n");

    // this is the critical test: betanet_recv after handshake completion
    // this was the exact point where the bug occurred
    char buffer[1024];
    uint64_t request_stream_id;
    printf("[SERVER] calling betanet_recv to read first message...\n");
    ssize_t received = betanet_recv(client_sock, buffer, sizeof(buffer) - 1, &request_stream_id);
    
    if (received <= 0) {
        printf("[SERVER] CRITICAL: betanet_recv failed with %zd, errno=%d (%s)\n", 
               received, errno, strerror(errno));
        pthread_mutex_lock(&state->mutex);
        state->test_passed = 0;  // explicit failure
        pthread_mutex_unlock(&state->mutex);
        
        betanet_close(client_sock);
        if (client_addr) betanet_free_addr(client_addr);
        betanet_free_addr(local_addr);
        betanet_close(listen_sock);
        betanet_cleanup();
        return NULL;
    }

    buffer[received] = '\0';
    printf("[SERVER] successfully received %zd bytes: '%s' on stream %llu\n", 
           received, buffer, (unsigned long long)request_stream_id);

    pthread_mutex_lock(&state->mutex);
    state->message_received = 1;
    strncpy(state->received_message, buffer, sizeof(state->received_message) - 1);
    state->received_message[sizeof(state->received_message) - 1] = '\0';
    pthread_mutex_unlock(&state->mutex);

    // send response back to client
    printf("[SERVER] sending response...\n");
    ssize_t sent = betanet_send_response(client_sock, TEST_RESPONSE, strlen(TEST_RESPONSE), request_stream_id);
    if (sent <= 0) {
        printf("[SERVER] failed to send response\n");
        pthread_mutex_lock(&state->mutex);
        state->test_passed = 0;
        pthread_mutex_unlock(&state->mutex);
    } else {
        printf("[SERVER] sent response (%zd bytes)\n", sent);
        pthread_mutex_lock(&state->mutex);
        state->response_sent = 1;
        state->test_passed = 1;
        pthread_mutex_unlock(&state->mutex);
    }

    // cleanup
    betanet_close(client_sock);
    if (client_addr) betanet_free_addr(client_addr);
    betanet_free_addr(local_addr);
    betanet_close(listen_sock);
    betanet_cleanup();

    printf("[SERVER] thread completed\n");
    return NULL;
}

// test complete client-server communication with handshake
static void test_client_server_basic_communication(void **state) {
    (void)state;

    // choose a test port
    int test_port = TEST_PORT_BASE + 1;

    // initialize server state
    integration_server_state_t server_state = {0};
    server_state.port = test_port;
    pthread_mutex_init(&server_state.mutex, NULL);
    pthread_cond_init(&server_state.ready_cond, NULL);

    // start server thread
    pthread_t server_thread;
    int thread_result = pthread_create(&server_thread, NULL, integration_server_thread, &server_state);
    assert_int_equal(thread_result, 0);

    // wait for server to be ready
    pthread_mutex_lock(&server_state.mutex);
    while (!server_state.ready) {
        pthread_cond_wait(&server_state.ready_cond, &server_state.mutex);
    }
    pthread_mutex_unlock(&server_state.mutex);

    printf("[CLIENT] server is ready, starting client...\n");

    // small delay to ensure server is fully listening
    usleep(100000); // 100ms

    // initialize client
    assert_int_equal(betanet_init(NULL), 0);

    betanet_socket_t client_sock = betanet_socket();
    assert_non_null(client_sock);

    // connect to server
    char addr_str[256];
    snprintf(addr_str, sizeof(addr_str), "127.0.0.1:%d", test_port);
    
    betanet_addr_t server_addr = betanet_resolve(addr_str);
    assert_non_null(server_addr);

    printf("[CLIENT] connecting to %s...\n", addr_str);
    int connect_result = betanet_connect(client_sock, server_addr);
    assert_int_equal(connect_result, 0);

    printf("[CLIENT] connected successfully, sending message...\n");

    // send test message
    ssize_t sent = betanet_send(client_sock, TEST_MESSAGE, strlen(TEST_MESSAGE));
    assert_true(sent > 0);
    printf("[CLIENT] sent %zd bytes\n", sent);

    // wait for response
    char response_buffer[1024];
    uint64_t response_stream_id;
    printf("[CLIENT] waiting for response...\n");
    ssize_t received = betanet_recv(client_sock, response_buffer, sizeof(response_buffer) - 1, &response_stream_id);
    assert_true(received > 0);

    response_buffer[received] = '\0';
    printf("[CLIENT] received response: '%s' on stream %llu\n", 
           response_buffer, (unsigned long long)response_stream_id);

    // verify response content
    assert_string_equal(response_buffer, TEST_RESPONSE);

    // cleanup client
    betanet_free_addr(server_addr);
    betanet_close(client_sock);
    betanet_cleanup();

    // wait for server thread to complete
    pthread_join(server_thread, NULL);

    // verify server state
    pthread_mutex_lock(&server_state.mutex);
    assert_int_equal(server_state.client_connected, 1);
    assert_int_equal(server_state.message_received, 1);
    assert_int_equal(server_state.response_sent, 1);
    assert_int_equal(server_state.test_passed, 1);
    assert_string_equal(server_state.received_message, TEST_MESSAGE);
    pthread_mutex_unlock(&server_state.mutex);

    pthread_mutex_destroy(&server_state.mutex);
    pthread_cond_destroy(&server_state.ready_cond);

    printf("[TEST] client-server basic communication test PASSED\n");
}

// test multiple sequential messages
static void test_client_server_multiple_messages(void **state) {
    (void)state;

    int test_port = TEST_PORT_BASE + 2;

    integration_server_state_t server_state = {0};
    server_state.port = test_port;
    pthread_mutex_init(&server_state.mutex, NULL);
    pthread_cond_init(&server_state.ready_cond, NULL);

    // custom server for multiple messages
    // (implementation simplified for this example - would need more complex server logic)
    
    printf("[TEST] multiple messages test - currently simplified\n");
    // todo: implement full multi-message server logic
    
    pthread_mutex_destroy(&server_state.mutex);
    pthread_cond_destroy(&server_state.ready_cond);
}

// test different frame sizes to catch header parsing edge cases
static void test_client_server_various_frame_sizes(void **state) {
    (void)state;

    printf("[TEST] testing various frame sizes to catch header parsing bugs...\n");

    // test different payload sizes that affect frame structure
    size_t test_sizes[] = {
        1,      // tiny payload
        26,     // exactly what the examples use
        63,     // near varint boundary
        64,     // varint boundary
        100,    // medium payload
        1000,   // large payload
        16383,  // varint boundary
        16384   // larger varint
    };

    // for each size, we should be able to construct and parse frames correctly
    for (size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++) {
        size_t payload_size = test_sizes[i];
        printf("[TEST] testing payload size %zu\n", payload_size);

        // create test payload
        uint8_t *test_payload = malloc(payload_size);
        assert_non_null(test_payload);
        
        for (size_t j = 0; j < payload_size; j++) {
            test_payload[j] = (uint8_t)(j % 256);
        }

        // construct frame
        uint8_t frame[payload_size + 100]; // extra space for header
        size_t frame_len = sizeof(frame);
        
        int result = htx_construct_stream_frame(frame, &frame_len, 1, test_payload, payload_size, NULL);
        assert_int_equal(result, 0);
        
        // parse frame to verify header parsing works
        uint64_t parsed_stream_id;
        uint8_t *parsed_payload = malloc(payload_size + 100);
        assert_non_null(parsed_payload);
        size_t parsed_len = payload_size + 100;
        
        result = htx_parse_stream_frame(frame, frame_len, &parsed_stream_id, parsed_payload, &parsed_len, NULL);
        assert_int_equal(result, 0);
        assert_int_equal(parsed_stream_id, 1);
        assert_int_equal(parsed_len, payload_size);
        assert_memory_equal(parsed_payload, test_payload, payload_size);

        free(test_payload);
        free(parsed_payload);
    }

    printf("[TEST] frame size variation test PASSED\n");
}

// test that specifically reproduces the original bug scenario
static void test_regression_header_parsing_bug(void **state) {
    (void)state;
    
    printf("[TEST] regression test for header parsing bug...\n");

    // this test reproduces the exact scenario that was broken:
    // 1. client sends 47-byte frame with 5-byte header: [00 00 2A 00 01] + payload
    // 2. server calls betanet_recv and tries to parse header
    // 3. before fix: server only read 4 bytes, missing stream_id byte
    // 4. after fix: server should read 5 bytes and parse correctly

    const char *test_payload = "hello from betanet client!"; // 26 bytes, same as example
    size_t payload_len = strlen(test_payload);

    // construct the exact frame that was causing issues
    uint8_t frame[100];
    size_t frame_len = sizeof(frame);
    
    int result = htx_construct_stream_frame(frame, &frame_len, 1, (const uint8_t *)test_payload, payload_len, NULL);
    assert_int_equal(result, 0);
    
    printf("[TEST] constructed frame of %zu bytes\n", frame_len);
    
    // verify the frame header is exactly what we expect
    assert_int_equal(frame[0], 0x00);  // length high byte
    assert_int_equal(frame[1], 0x00);  // length middle byte  
    assert_int_equal(frame[2], 0x2A);  // length low byte (42 decimal = 0x2A)
    assert_int_equal(frame[3], 0x00);  // frame type (HTX_FRAME_TYPE_STREAM = 0)
    assert_int_equal(frame[4], 0x01);  // stream_id varint (1)
    
    // now test that header parsing works correctly when given the right amount of data
    uint32_t parsed_length;
    uint8_t parsed_type;
    uint64_t parsed_stream_id;
    
    // test with only 4 bytes (this was the bug - should fail)
    int header_len = htx_deserialize_frame_header(frame, 4, &parsed_length, &parsed_type, &parsed_stream_id);
    assert_int_equal(header_len, -1); // should fail because stream frame needs stream_id
    
    // test with 5 bytes (the fix - should succeed)
    header_len = htx_deserialize_frame_header(frame, 5, &parsed_length, &parsed_type, &parsed_stream_id);
    assert_int_equal(header_len, 5);
    assert_int_equal(parsed_length, 42);  // payload + auth tag length
    assert_int_equal(parsed_type, 0);     // HTX_FRAME_TYPE_STREAM
    assert_int_equal(parsed_stream_id, 1);
    
    // test full frame parsing
    uint64_t final_stream_id;
    uint8_t final_payload[100];
    size_t final_payload_len = sizeof(final_payload);
    
    result = htx_parse_stream_frame(frame, frame_len, &final_stream_id, final_payload, &final_payload_len, NULL);
    assert_int_equal(result, 0);
    assert_int_equal(final_stream_id, 1);
    assert_int_equal(final_payload_len, payload_len);
    assert_memory_equal(final_payload, test_payload, payload_len);

    printf("[TEST] regression test for header parsing bug PASSED\n");
}

int main(void) {
    printf("=== integration client-server communication tests ===\n");
    printf("these tests are designed to catch the frame header parsing bug\n");
    printf("that allowed betanet_recv to fail immediately after handshake\n\n");

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_regression_header_parsing_bug),
        cmocka_unit_test(test_client_server_various_frame_sizes),
        cmocka_unit_test(test_client_server_basic_communication),
        cmocka_unit_test(test_client_server_multiple_messages),
    };

    int result = cmocka_run_group_tests(tests, NULL, NULL);
    
    if (result == 0) {
        printf("\n=== all integration tests PASSED ===\n");
        printf("the frame header parsing bug has been successfully fixed\n");
        printf("and these tests will prevent regression in the future\n");
    } else {
        printf("\n=== integration tests FAILED ===\n");
        printf("there are still issues with client-server communication\n");
    }
    
    return result;
}
