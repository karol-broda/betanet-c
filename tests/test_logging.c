#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "betanet_log.h"

// test data for hex dump testing
static const uint8_t test_hex_data[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
    0x41, 0x42, 0x43, 0x44  // "ABCD" in ascii
};

// helper function to capture stdout/stderr
static char captured_output[4096];
static int capture_pipe[2];
static int saved_stdout;
static int saved_stderr;

static void setup_capture(void) {
    saved_stdout = dup(STDOUT_FILENO);
    saved_stderr = dup(STDERR_FILENO);
    pipe(capture_pipe);
    captured_output[0] = '\0';
}

static void teardown_capture(void) {
    close(capture_pipe[0]);
    close(capture_pipe[1]);
    dup2(saved_stdout, STDOUT_FILENO);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stdout);
    close(saved_stderr);
}

static void capture_stdout_stderr(void) {
    // redirect stdout and stderr to our pipe
    dup2(capture_pipe[1], STDOUT_FILENO);
    dup2(capture_pipe[1], STDERR_FILENO);
}

static void read_captured_output(void) {
    fflush(stdout);
    fflush(stderr);
    close(capture_pipe[1]); // Close the write end of the pipe
    ssize_t len = read(capture_pipe[0], captured_output, sizeof(captured_output) - 1);
    if (len > 0) {
        captured_output[len] = '\0';
    } else {
        captured_output[0] = '\0';
    }
}

// test that debug logs are compiled out in release builds
static void test_debug_log_level_control(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    // these should only produce output if BETANET_LOG_LEVEL >= 3
    BETANET_LOG_DEBUG("test debug message");
    
    read_captured_output();
    
#if BETANET_LOG_LEVEL >= 3
    assert_string_equal(captured_output, "[DEBUG] test debug message\n");
#else
    assert_string_equal(captured_output, "");
#endif
    
    teardown_capture();
}

// test that info logs work at appropriate levels
static void test_info_log_level_control(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    BETANET_LOG_INFO("test info message");
    
    read_captured_output();
    
#if BETANET_LOG_LEVEL >= 2
    assert_string_equal(captured_output, "[INFO] test info message\n");
#else
    assert_string_equal(captured_output, "");
#endif
    
    teardown_capture();
}

// test that warning logs work at appropriate levels
static void test_warn_log_level_control(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    BETANET_LOG_WARN("test warning message");
    
    read_captured_output();
    
#if BETANET_LOG_LEVEL >= 1
    assert_string_equal(captured_output, "[WARN] test warning message\n");
#else
    assert_string_equal(captured_output, "");
#endif
    
    teardown_capture();
}

// test that error logs work at appropriate levels
static void test_error_log_level_control(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    BETANET_LOG_ERROR("test error message");
    
    read_captured_output();
    
#if BETANET_LOG_LEVEL >= 0
    assert_string_equal(captured_output, "[ERROR] test error message\n");
#else
    assert_string_equal(captured_output, "");
#endif
    
    teardown_capture();
}

// test that hex dump works correctly in debug builds
static void test_hex_dump_functionality(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    BETANET_LOG_HEX("test data", test_hex_data, 20);
    
    read_captured_output();
    
#if BETANET_LOG_LEVEL >= 3
    // check that output contains expected hex values
    assert_non_null(strstr(captured_output, "01 23 45 67"));
    assert_non_null(strstr(captured_output, "FE DC BA 98"));
    assert_non_null(strstr(captured_output, "41 42 43 44")); // ABCD
#else
    assert_string_equal(captured_output, "");
#endif
    
    teardown_capture();
}

// test log formatting with arguments
static void test_log_formatting(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    int test_value = 42;
    const char *test_string = "hello";
    
    BETANET_LOG_DEBUG("formatted message: %s = %d", test_string, test_value);
    
    read_captured_output();
    
#if BETANET_LOG_LEVEL >= 3
    assert_non_null(strstr(captured_output, "hello = 42"));
#else
    assert_string_equal(captured_output, "");
#endif
    
    teardown_capture();
}

// test that hex dump handles edge cases
static void test_hex_dump_edge_cases(void **state) {
    (void) state;
    
    setup_capture();
    capture_stdout_stderr();
    
    // test empty data
    BETANET_LOG_HEX("empty", NULL, 0);
    
    // test single byte
    uint8_t single_byte = 0xFF;
    BETANET_LOG_HEX("single", &single_byte, 1);
    
    read_captured_output();
    
    // should not crash and produce reasonable output
    // exact output depends on implementation
    
    teardown_capture();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_debug_log_level_control),
        cmocka_unit_test(test_info_log_level_control),
        cmocka_unit_test(test_warn_log_level_control),
        cmocka_unit_test(test_error_log_level_control),
        cmocka_unit_test(test_hex_dump_functionality),
        cmocka_unit_test(test_log_formatting),
        cmocka_unit_test(test_hex_dump_edge_cases),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
