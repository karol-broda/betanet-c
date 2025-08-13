/**
 * @file test_smoke_client_server.c
 * @brief lightweight smoke test for basic client-server functionality
 * 
 * this is a fast, simple test that should be run in CI to catch
 * fundamental regressions like the frame header parsing bug.
 * 
 * unlike the full integration test, this focuses on the core
 * functionality without complex threading or timing dependencies.
 */

#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <cmocka.h>

#include "betanet_internal.h"

// test frame construction and parsing which was the source of the bug
static void test_smoke_frame_header_parsing(void **state) {
    (void)state;

    printf("[SMOKE] testing frame header parsing...\n");

    // this test reproduces the exact frame structure that was broken
    const char *test_message = "hello from betanet client!";
    size_t msg_len = strlen(test_message);

    // create frame exactly like betanet_send does
    uint8_t frame[100];
    size_t frame_len = sizeof(frame);

    int result = htx_construct_stream_frame(frame, &frame_len, 1, 
                                           (const uint8_t *)test_message, msg_len, NULL);
    assert_int_equal(result, 0);

    printf("[SMOKE] frame constructed: %zu bytes\n", frame_len);

    // verify frame header structure (this was the bug)
    // frame should be: [00 00 2A 00 01] + payload
    assert_int_equal(frame[0], 0x00);  // length[23:16]
    assert_int_equal(frame[1], 0x00);  // length[15:8] 
    assert_int_equal(frame[2], 0x2A);  // length[7:0] = 42 (26 payload + 16 auth tag)
    assert_int_equal(frame[3], 0x00);  // frame type = HTX_FRAME_TYPE_STREAM
    assert_int_equal(frame[4], 0x01);  // stream_id = 1 (varint encoded)

    // test header parsing with different byte counts
    uint32_t length;
    uint8_t type;
    uint64_t stream_id;

    // test with 4 bytes (the original bug case) - should fail
    int header_len = htx_deserialize_frame_header(frame, 4, &length, &type, &stream_id);
    assert_int_equal(header_len, -1);  // must fail for stream frames

    // test with 5 bytes (the fix) - should succeed  
    header_len = htx_deserialize_frame_header(frame, 5, &length, &type, &stream_id);
    assert_int_equal(header_len, 5);
    assert_int_equal(length, 42);
    assert_int_equal(type, 0);  // HTX_FRAME_TYPE_STREAM
    assert_int_equal(stream_id, 1);

    // test full frame parsing
    uint64_t parsed_stream_id;
    uint8_t parsed_payload[100];
    size_t parsed_len = sizeof(parsed_payload);

    result = htx_parse_stream_frame(frame, frame_len, &parsed_stream_id, 
                                   parsed_payload, &parsed_len, NULL);
    assert_int_equal(result, 0);
    assert_int_equal(parsed_stream_id, 1);
    assert_int_equal(parsed_len, msg_len);
    assert_memory_equal(parsed_payload, test_message, msg_len);

    printf("[SMOKE] frame header parsing test PASSED\n");
}

// test that simulates betanet_recv behavior without full network stack
static void test_smoke_recv_frame_parsing(void **state) {
    (void)state;

    printf("[SMOKE] testing betanet_recv-style frame parsing...\n");

    // create test frame
    const char *test_payload = "test payload for recv";
    uint8_t frame[100];
    size_t frame_len = sizeof(frame);

    int result = htx_construct_stream_frame(frame, &frame_len, 42, 
                                           (const uint8_t *)test_payload, strlen(test_payload), NULL);
    assert_int_equal(result, 0);

    // simulate the exact betanet_recv parsing logic
    // step 1: parse header (this was failing before)
    uint32_t payload_len;
    uint8_t frame_type;
    uint64_t stream_id;

    int header_len = htx_deserialize_frame_header(frame, frame_len, &payload_len, &frame_type, &stream_id);
    assert_true(header_len > 0);  // must succeed
    assert_int_equal(frame_type, HTX_FRAME_TYPE_STREAM);
    assert_int_equal(stream_id, 42);

    // step 2: parse complete frame
    uint64_t final_stream_id;
    uint8_t final_payload[100];
    size_t final_len = sizeof(final_payload);

    result = htx_parse_stream_frame(frame, frame_len, &final_stream_id, final_payload, &final_len, NULL);
    assert_int_equal(result, 0);
    assert_int_equal(final_stream_id, 42);
    assert_int_equal(final_len, strlen(test_payload));
    assert_memory_equal(final_payload, test_payload, strlen(test_payload));

    printf("[SMOKE] recv-style frame parsing test PASSED\n");
}

// test various stream IDs to ensure varint parsing works
static void test_smoke_stream_id_varints(void **state) {
    (void)state;

    printf("[SMOKE] testing stream ID varint encoding/decoding...\n");

    // test different stream IDs that use different varint sizes
    uint64_t test_stream_ids[] = {
        1,       // 1-byte varint
        63,      // max 1-byte varint  
        64,      // min 2-byte varint
        16383,   // max 2-byte varint
        16384,   // min 4-byte varint
        1000000  // larger 4-byte varint
    };

    for (size_t i = 0; i < sizeof(test_stream_ids) / sizeof(test_stream_ids[0]); i++) {
        uint64_t test_stream_id = test_stream_ids[i];
        printf("[SMOKE] testing stream_id %llu\n", (unsigned long long)test_stream_id);

        uint8_t frame[100];
        size_t frame_len = sizeof(frame);
        const char *payload = "test";

        // construct frame
        int result = htx_construct_stream_frame(frame, &frame_len, test_stream_id, 
                                               (const uint8_t *)payload, strlen(payload), NULL);
        assert_int_equal(result, 0);

        // parse header
        uint32_t length;
        uint8_t type;
        uint64_t parsed_stream_id;

        int header_len = htx_deserialize_frame_header(frame, frame_len, &length, &type, &parsed_stream_id);
        assert_true(header_len > 0);
        assert_int_equal(type, HTX_FRAME_TYPE_STREAM);
        assert_int_equal(parsed_stream_id, test_stream_id);

        // parse full frame
        uint64_t final_stream_id;
        uint8_t final_payload[100];
        size_t final_len = sizeof(final_payload);

        result = htx_parse_stream_frame(frame, frame_len, &final_stream_id, final_payload, &final_len, NULL);
        assert_int_equal(result, 0);
        assert_int_equal(final_stream_id, test_stream_id);
    }

    printf("[SMOKE] stream ID varint test PASSED\n");
}

// test boundary conditions that could trigger parsing bugs
static void test_smoke_boundary_conditions(void **state) {
    (void)state;

    printf("[SMOKE] testing boundary conditions...\n");

    // test minimum valid frame
    uint8_t frame[50];
    size_t frame_len = sizeof(frame);

    int result = htx_construct_stream_frame(frame, &frame_len, 1, NULL, 0, NULL);
    assert_int_equal(result, 0);

    uint32_t length;
    uint8_t type;
    uint64_t stream_id;

    int header_len = htx_deserialize_frame_header(frame, frame_len, &length, &type, &stream_id);
    assert_true(header_len > 0);
    assert_int_equal(type, HTX_FRAME_TYPE_STREAM);
    assert_int_equal(stream_id, 1);

    // test with maximum single-byte varint
    frame_len = sizeof(frame);
    result = htx_construct_stream_frame(frame, &frame_len, 63, NULL, 0, NULL);
    assert_int_equal(result, 0);

    header_len = htx_deserialize_frame_header(frame, frame_len, &length, &type, &stream_id);
    assert_true(header_len > 0);
    assert_int_equal(stream_id, 63);

    printf("[SMOKE] boundary conditions test PASSED\n");
}

int main(void) {
    printf("=== smoke test for client-server functionality ===\n");
    printf("this test catches fundamental frame parsing bugs that break basic communication\n\n");

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_smoke_frame_header_parsing),
        cmocka_unit_test(test_smoke_recv_frame_parsing), 
        cmocka_unit_test(test_smoke_stream_id_varints),
        cmocka_unit_test(test_smoke_boundary_conditions),
    };

    int result = cmocka_run_group_tests(tests, NULL, NULL);

    if (result == 0) {
        printf("\n=== smoke test PASSED ===\n");
        printf("basic frame parsing functionality is working correctly\n");
    } else {
        printf("\n=== smoke test FAILED ===\n"); 
        printf("fundamental frame parsing is broken - check betanet_recv logic\n");
    }

    return result;
}
