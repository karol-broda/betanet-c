#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include <cmocka.h>

#include "betanet_internal.h"

// test varint encoding/decoding through frame headers
static void test_htx_frame_header_serialization_basic(void **state) {
    (void)state;

    uint8_t buffer[64];

    // test basic stream frame header
    int header_len =
        htx_serialize_frame_header(buffer, sizeof(buffer), 100, HTX_FRAME_TYPE_STREAM, 1);
    assert_true(header_len > 0);
    assert_true(header_len <= sizeof(buffer));

    // verify 24-bit length encoding (network byte order)
    assert_int_equal(buffer[0], 0);   // high byte
    assert_int_equal(buffer[1], 0);   // middle byte
    assert_int_equal(buffer[2], 100); // low byte
    assert_int_equal(buffer[3], HTX_FRAME_TYPE_STREAM);

    // stream id 1 should be encoded as single byte varint
    assert_int_equal(buffer[4], 1);

    assert_int_equal(header_len, 5); // 3 + 1 + 1
}

static void test_htx_frame_header_serialization_large_stream_id(void **state) {
    (void)state;

    uint8_t buffer[64];

    // test with larger stream id that requires multi-byte varint
    uint64_t large_stream_id = 16384; // requires 4-byte varint encoding
    int header_len = htx_serialize_frame_header(buffer, sizeof(buffer), 500, HTX_FRAME_TYPE_STREAM,
                                                large_stream_id);
    assert_true(header_len > 0);

    // length should be encoded correctly
    assert_int_equal((buffer[0] << 16) | (buffer[1] << 8) | buffer[2], 500);
    assert_int_equal(buffer[3], HTX_FRAME_TYPE_STREAM);

    // stream id should use 4-byte varint (10xxxxxx pattern)
    assert_int_equal(buffer[4] & 0xc0, 0x80); // 10 prefix

    assert_int_equal(header_len, 8); // 3 + 1 + 4
}

static void test_htx_frame_header_serialization_non_stream(void **state) {
    (void)state;

    uint8_t buffer[64];

    // test ping frame (no stream id)
    int header_len = htx_serialize_frame_header(buffer, sizeof(buffer), 0, HTX_FRAME_TYPE_PING, 0);
    assert_true(header_len > 0);

    // should only be length + type, no stream id
    assert_int_equal(header_len, 4); // 3 + 1
    assert_int_equal(buffer[3], HTX_FRAME_TYPE_PING);
}

static void test_htx_frame_header_deserialization(void **state) {
    (void)state;

    uint8_t buffer[64];
    uint32_t length;
    uint8_t type;
    uint64_t stream_id;

    // serialize a frame header first
    int header_len =
        htx_serialize_frame_header(buffer, sizeof(buffer), 1234, HTX_FRAME_TYPE_STREAM, 42);
    assert_true(header_len > 0);

    // now deserialize it
    int parsed_len = htx_deserialize_frame_header(buffer, header_len, &length, &type, &stream_id);
    assert_int_equal(parsed_len, header_len);
    assert_int_equal(length, 1234);
    assert_int_equal(type, HTX_FRAME_TYPE_STREAM);
    assert_int_equal(stream_id, 42);
}

static void test_htx_frame_header_roundtrip(void **state) {
    (void)state;

    // test various combinations
    struct {
        uint32_t length;
        uint8_t type;
        uint64_t stream_id;
    } test_cases[] = {
        {0, HTX_FRAME_TYPE_PING, 0},
        {100, HTX_FRAME_TYPE_STREAM, 1},
        {65535, HTX_FRAME_TYPE_STREAM, 63},             // max 1-byte varint
        {1000000, HTX_FRAME_TYPE_STREAM, 16383},        // max 2-byte varint
        {50, HTX_FRAME_TYPE_WINDOW_UPDATE, 1073741823}, // max 4-byte varint
    };

    for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
        uint8_t buffer[64];
        uint32_t out_length;
        uint8_t out_type;
        uint64_t out_stream_id;

        // serialize
        int header_len = htx_serialize_frame_header(buffer, sizeof(buffer), test_cases[i].length,
                                                    test_cases[i].type, test_cases[i].stream_id);
        assert_true(header_len > 0);

        // deserialize
        int parsed_len = htx_deserialize_frame_header(buffer, header_len, &out_length, &out_type,
                                                      &out_stream_id);
        assert_int_equal(parsed_len, header_len);
        assert_int_equal(out_length, test_cases[i].length);
        assert_int_equal(out_type, test_cases[i].type);
        assert_int_equal(out_stream_id, test_cases[i].stream_id);
    }
}

// test stream frame construction
static void test_htx_construct_stream_frame_basic(void **state) {
    (void)state;

    uint8_t frame[1024];
    size_t frame_len = sizeof(frame);
    const char *payload = "hello world";
    size_t payload_len = strlen(payload);

    int result =
        htx_construct_stream_frame(frame, &frame_len, 1, (const uint8_t *)payload, payload_len,
                                   NULL); // no encryption
    assert_int_equal(result, 0);
    assert_true(frame_len > payload_len); // should include header

    // verify we can parse it back
    uint64_t parsed_stream_id;
    uint8_t parsed_payload[256];
    size_t parsed_payload_len = sizeof(parsed_payload);

    result = htx_parse_stream_frame(frame, frame_len, &parsed_stream_id, parsed_payload,
                                    &parsed_payload_len, NULL);
    assert_int_equal(result, 0);
    assert_int_equal(parsed_stream_id, 1);
    assert_int_equal(parsed_payload_len, payload_len);
    assert_memory_equal(parsed_payload, payload, payload_len);
}

static void test_htx_construct_stream_frame_empty_payload(void **state) {
    (void)state;

    uint8_t frame[1024];
    size_t frame_len = sizeof(frame);

    int result = htx_construct_stream_frame(frame, &frame_len, 5, NULL, 0, NULL);
    assert_int_equal(result, 0);
    assert_true(frame_len > 0); // should have header

    // verify parsing
    uint64_t parsed_stream_id;
    uint8_t parsed_payload[256];
    size_t parsed_payload_len = sizeof(parsed_payload);

    result = htx_parse_stream_frame(frame, frame_len, &parsed_stream_id, parsed_payload,
                                    &parsed_payload_len, NULL);
    assert_int_equal(result, 0);
    assert_int_equal(parsed_stream_id, 5);
    assert_int_equal(parsed_payload_len, 0);
}

static void test_htx_construct_stream_frame_large_payload(void **state) {
    (void)state;

    uint8_t frame[2048];
    size_t frame_len = sizeof(frame);

    // create large payload
    uint8_t large_payload[1000];
    for (int i = 0; i < 1000; i++) {
        large_payload[i] = (uint8_t)(i % 256);
    }

    int result = htx_construct_stream_frame(frame, &frame_len, 100, large_payload,
                                            sizeof(large_payload), NULL);
    assert_int_equal(result, 0);

    // verify parsing
    uint64_t parsed_stream_id;
    uint8_t parsed_payload[1200];
    size_t parsed_payload_len = sizeof(parsed_payload);

    result = htx_parse_stream_frame(frame, frame_len, &parsed_stream_id, parsed_payload,
                                    &parsed_payload_len, NULL);
    assert_int_equal(result, 0);
    assert_int_equal(parsed_stream_id, 100);
    assert_int_equal(parsed_payload_len, sizeof(large_payload));
    assert_memory_equal(parsed_payload, large_payload, sizeof(large_payload));
}

// test ping frame construction
static void test_htx_construct_ping_frame(void **state) {
    (void)state;

    uint8_t frame[64];
    size_t frame_len = sizeof(frame);

    int result = htx_construct_ping_frame(frame, &frame_len);
    assert_int_equal(result, 0);
    assert_int_equal(frame_len, 4); // should be just header with 0 length

    // verify frame structure
    assert_int_equal(frame[0], 0); // length high
    assert_int_equal(frame[1], 0); // length middle
    assert_int_equal(frame[2], 0); // length low
    assert_int_equal(frame[3], HTX_FRAME_TYPE_PING);
}

// test window update frame construction
static void test_htx_construct_window_update_frame(void **state) {
    (void)state;

    uint8_t frame[64];
    size_t frame_len = sizeof(frame);
    uint32_t window_increment = 65536;

    int result = htx_construct_window_update_frame(frame, &frame_len, 42, window_increment);
    assert_int_equal(result, 0);
    assert_true(frame_len > 4); // header + 4-byte payload

    // verify frame structure by parsing header
    uint32_t length;
    uint8_t type;
    uint64_t stream_id;

    int header_len = htx_deserialize_frame_header(frame, frame_len, &length, &type, &stream_id);
    assert_true(header_len > 0);
    assert_int_equal(length, 4); // window increment is 4 bytes
    assert_int_equal(type, HTX_FRAME_TYPE_WINDOW_UPDATE);
    assert_int_equal(stream_id, 42);

    // verify window increment payload (network byte order)
    uint32_t parsed_increment = (frame[header_len] << 24) | (frame[header_len + 1] << 16) |
                                (frame[header_len + 2] << 8) | frame[header_len + 3];
    assert_int_equal(parsed_increment, window_increment);
}

// test error conditions
static void test_htx_frame_serialization_errors(void **state) {
    (void)state;

    uint8_t buffer[64];

    // test null buffer
    int result = htx_serialize_frame_header(NULL, sizeof(buffer), 100, HTX_FRAME_TYPE_STREAM, 1);
    assert_int_equal(result, -1);

    // test buffer too small
    result = htx_serialize_frame_header(buffer, 3, // too small for header
                                        100, HTX_FRAME_TYPE_STREAM, 1);
    assert_int_equal(result, -1);

    // test length too large (> 24 bits)
    result = htx_serialize_frame_header(buffer, sizeof(buffer), 16777216, HTX_FRAME_TYPE_STREAM,
                                        1); // 2^24
    assert_int_equal(result, -1);
}

static void test_htx_frame_deserialization_errors(void **state) {
    (void)state;

    uint8_t buffer[64];
    uint32_t length;
    uint8_t type;
    uint64_t stream_id;

    // test null buffer
    int result = htx_deserialize_frame_header(NULL, sizeof(buffer), &length, &type, &stream_id);
    assert_int_equal(result, -1);

    // test buffer too small
    result = htx_deserialize_frame_header(buffer, 3, // too small
                                          &length, &type, &stream_id);
    assert_int_equal(result, -1);

    // test null output parameters
    result = htx_deserialize_frame_header(buffer, sizeof(buffer), NULL, &type, &stream_id);
    assert_int_equal(result, -1);
}

static void test_htx_stream_frame_errors(void **state) {
    (void)state;

    uint8_t frame[1024];
    size_t frame_len = sizeof(frame);
    const char *payload = "test";

    // test null frame buffer
    int result = htx_construct_stream_frame(NULL, &frame_len, 1, (const uint8_t *)payload,
                                            strlen(payload), NULL);
    assert_int_equal(result, -1);

    // test null frame_len
    result =
        htx_construct_stream_frame(frame, NULL, 1, (const uint8_t *)payload, strlen(payload), NULL);
    assert_int_equal(result, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_htx_frame_header_serialization_basic),
        cmocka_unit_test(test_htx_frame_header_serialization_large_stream_id),
        cmocka_unit_test(test_htx_frame_header_serialization_non_stream),
        cmocka_unit_test(test_htx_frame_header_deserialization),
        cmocka_unit_test(test_htx_frame_header_roundtrip),
        cmocka_unit_test(test_htx_construct_stream_frame_basic),
        cmocka_unit_test(test_htx_construct_stream_frame_empty_payload),
        cmocka_unit_test(test_htx_construct_stream_frame_large_payload),
        cmocka_unit_test(test_htx_construct_ping_frame),
        cmocka_unit_test(test_htx_construct_window_update_frame),
        cmocka_unit_test(test_htx_frame_serialization_errors),
        cmocka_unit_test(test_htx_frame_deserialization_errors),
        cmocka_unit_test(test_htx_stream_frame_errors),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
