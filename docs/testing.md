# testing guide

this guide covers running tests, writing new tests, and understanding the test architecture.

## running tests

### quick test run

```bash
# in nix development shell
cd build
ctest
```

### detailed test output

```bash
ctest --verbose
```

### running specific tests

```bash
# run individual test suites
./test_core
./test_crypto  
./test_htx
./test_noise
./test_htx_frames
./test_api
./test_l2_secure_channel
./test_server

# run specific test with ctest
ctest -R test_crypto
```

### test output interpretation

successful test output:
```
[==========] tests: Running 5 test(s).
[ RUN      ] test_sha256
[       OK ] test_sha256
...
[==========] tests: 5 test(s) run.
[  PASSED  ] 5 test(s).
```

failed test output:
```
[ RUN      ] test_example
[  ERROR   ] --- 0x5 != 0x3
[   LINE   ] --- /path/to/test.c:42: error: Failure!
[  FAILED  ] test_example
```

## test architecture

### testing strategy

betanet employs a comprehensive multi-layered testing approach designed to catch issues at different levels:

#### test categories

1. **unit tests**: test individual functions and components in isolation
2. **integration tests**: test complete workflows and component interactions
3. **smoke tests**: fast regression tests for critical functionality
4. **end-to-end tests**: full client-server communication scenarios

#### test pyramid

```
         /\
        /e2e\      <- full system tests (slowest, comprehensive)
       /------\
      /integrn\    <- component integration (medium speed)
     /--------\
    /   unit   \   <- individual functions (fastest, focused)
   /----------\
```

this structure ensures:
- **fast feedback**: unit tests run quickly during development
- **comprehensive coverage**: integration tests catch component interaction bugs  
- **regression prevention**: smoke tests catch breaking changes
- **real-world validation**: e2e tests mirror actual usage

### test framework

the project uses [cmocka](https://cmocka.org/) for unit testing:

- **assertions:** `assert_int_equal()`, `assert_memory_equal()`, `assert_non_null()`, etc.
- **setup/teardown:** per-test and per-group setup/cleanup functions
- **mocking:** function mocking and parameter capture (not currently used)

### test organization

```
tests/
├── betanet_internal.h              # internal api exposure for testing
├── test_core.c                     # library initialization tests
├── test_crypto.c                   # cryptographic function tests
├── test_htx.c                      # htx access-ticket tests
├── test_noise.c                    # noise xk handshake tests
├── test_htx_frames.c               # htx frame format tests
├── test_api.c                      # public api function tests
├── test_l2_secure_channel.c        # l2 secure channel integration tests
├── test_server.c                   # server-side functionality tests
├── test_smoke_client_server.c      # fast smoke tests for basic functionality
└── test_integration_client_server.c # full end-to-end communication tests
```

### test suites overview

| **test suite** | **type** | **coverage** | **runtime** |
|--|--|--|--|
| `test_core` | unit | library init/cleanup | <1s |
| `test_crypto` | unit | sha-256, ed25519, x25519, aead, hkdf | <2s |
| `test_htx` | unit | access tickets, base64url, http requests | <2s |
| `test_noise` | unit | handshake init, message flow, key derivation | <3s |
| `test_htx_frames` | unit | frame serialization, varint encoding, stream handling | <1s |
| `test_api` | unit | socket api, address resolution, error handling | <2s |
| `test_l2_secure_channel` | integration | l2 integration tests with crypto and htx components | <5s |
| `test_server` | integration | server-side api functionality (bind, listen, accept) | <3s |
| `test_smoke_client_server` | smoke | frame parsing, basic protocol validation | <5s |
| `test_integration_client_server` | e2e | complete client-server communication | <30s |

### critical path testing

certain functionality is tested with extra rigor due to its critical nature:

#### protocol-level features
- frame header parsing and serialization
- varint encoding/decoding
- handshake completion and state transitions
- post-handshake data exchange

#### error conditions
- invalid frame structures
- network failures and timeouts
- buffer boundary conditions
- malformed protocol messages

#### edge cases
- empty payloads and zero-length frames
- maximum frame sizes and large payloads
- varint encoding boundaries
- concurrent connection handling

## writing new tests

### basic test structure

```c
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "betanet_internal.h"

static void test_example_function(void **state) {
    (void) state; // unused parameter
    
    // arrange
    int input = 5;
    int expected = 10;
    
    // act
    int result = example_function(input);
    
    // assert
    assert_int_equal(result, expected);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_example_function),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

### common assertion patterns

```c
// integer comparisons
assert_int_equal(actual, expected);
assert_int_not_equal(actual, unexpected);

// memory comparisons  
assert_memory_equal(buffer1, buffer2, size);
assert_memory_not_equal(buffer1, buffer2, size);

// pointer checks
assert_non_null(pointer);
assert_null(pointer);

// string comparisons
assert_string_equal(str1, str2);
assert_string_not_equal(str1, str2);

// boolean conditions
assert_true(condition);
assert_false(condition);

// custom conditions
assert_in_range(value, min, max);
```

### testing error conditions

always test both success and failure paths:

```c
static void test_function_success(void **state) {
    (void) state;
    
    uint8_t buffer[100];
    size_t buffer_len = sizeof(buffer);
    
    int result = target_function(buffer, &buffer_len, valid_params);
    assert_int_equal(result, 0);
    assert_true(buffer_len > 0);
}

static void test_function_null_params(void **state) {
    (void) state;
    
    uint8_t buffer[100];
    size_t buffer_len = sizeof(buffer);
    
    // test null buffer
    int result = target_function(NULL, &buffer_len, valid_params);
    assert_int_equal(result, -1);
    
    // test null length
    result = target_function(buffer, NULL, valid_params);
    assert_int_equal(result, -1);
}
```

### integration tests

test complete workflows:

```c
static void test_complete_workflow(void **state) {
    (void) state;
    
    // this is a simplified example. see `tests/test_integration.c` for a
    // realistic client-server test using separate threads.
    betanet_socket_t client_sock = betanet_socket();
    betanet_socket_t server_sock = betanet_socket();

    // setup server
    // ... bind, listen ...

    // setup client and connect
    // ... connect ...

    // send/receive
    betanet_send(client_sock, "ping", 4);
    char buffer[10];
    betanet_recv(server_sock, buffer, sizeof(buffer));
    assert_memory_equal(buffer, "ping", 4);

    // cleanup
    betanet_close(client_sock);
    betanet_close(server_sock);
}
```

### adding internal function access

to test internal functions, add them to `tests/betanet_internal.h`:

```c
// add function declaration
extern int internal_function(uint8_t* data, size_t len);

// add any required types
typedef struct {
    uint8_t field1[32];
    uint32_t field2;
} internal_struct_t;
```

### cmake integration

add new test files to `CMakeLists.txt`:

```cmake
add_executable(test_new_module tests/test_new_module.c)
target_link_libraries(test_new_module PRIVATE betanet ${CMOCKA_LIBRARIES})
target_include_directories(test_new_module PRIVATE ${CMOCKA_INCLUDE_DIRS})
add_test(NAME test_new_module COMMAND test_new_module)

set_property(TARGET test_new_module PROPERTY C_STANDARD 11)
set_property(TARGET test_new_module PROPERTY C_STANDARD_REQUIRED ON)
```

## test examples

### crypto function test

```c
static void test_sha256_basic(void **state) {
    (void) state;
    
    const char* input = "hello world";
    uint8_t output[32];
    uint8_t expected[32] = {
        0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08,
        0xa5, 0x2e, 0x52, 0xd7, 0xda, 0x7d, 0xab, 0xfa,
        0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53, 0x80, 0xee,
        0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9
    };
    
    int result = betanet_hash_sha256(output, (const uint8_t*)input, strlen(input));
    assert_int_equal(result, BETANET_CRYPTO_OK);
    assert_memory_equal(output, expected, 32);
}
```

### protocol flow test

```c
static void test_access_ticket_generation(void **state) {
    (void) state;
    
    // setup server info
    htx_server_ticket_info_t server_info;
    setup_test_server_info(&server_info);
    
    // generate ticket
    uint8_t payload[200];
    size_t payload_len = sizeof(payload);
    
    int result = htx_generate_access_ticket(payload, &payload_len,
                                           &server_info, HTX_CARRIER_COOKIE);
    assert_int_equal(result, 0);
    assert_true(payload_len >= server_info.min_len);
    assert_true(payload_len <= server_info.max_len);
    
    // verify structure
    assert_int_equal(payload[0], 0x01); // version
    
    // verify key id is correct
    assert_memory_equal(&payload[33], server_info.ticket_key_id, 8);
}
```

## debugging tests

### using gdb

```bash
cd build
gdb ./test_crypto
(gdb) break test_sha256_basic
(gdb) run
(gdb) step
```

### adding debug output

```c
static void test_with_debug(void **state) {
    (void) state;
    
    uint8_t buffer[64];
    size_t len = sizeof(buffer);
    
    printf("testing with buffer size: %zu\n", len);
    
    int result = function_under_test(buffer, &len);
    
    printf("result: %d, final length: %zu\n", result, len);
    
    assert_int_equal(result, 0);
}
```

### memory debugging

```bash
# run tests under valgrind
valgrind --leak-check=full --track-origins=yes ./test_crypto

# check for memory errors
valgrind --tool=memcheck ./test_crypto
```

## development workflow

### local testing workflow

#### before committing
```bash
# quick validation of critical functionality
cd build
make test_smoke_client_server && ./test_smoke_client_server

# run all unit tests
ctest --output-on-failure
```

#### during development
```bash
# run tests for specific module you're working on
./test_htx_frames
./test_crypto

# run integration tests if making protocol changes
./test_integration_client_server
```

#### full validation before merge
```bash
# comprehensive test run
make && ctest --verbose

# optional: run example applications
make example_server example_client
# test in separate terminals
```

### test selection guidelines

**when to write unit tests:**
- new functions or significant function changes
- cryptographic operations
- data structure manipulation
- error handling paths

**when to write integration tests:**
- new protocol features
- multi-component workflows
- complex state transitions
- client-server interactions

**when to write smoke tests:**
- critical path validation
- regression prevention for major bugs
- fast ci/cd validation
- boundary condition checking

### regression testing

when fixing bugs:

1. **create regression test**: write a test that reproduces the bug
2. **verify test fails**: ensure the test catches the bug before fixing
3. **implement fix**: make the minimal change to fix the issue
4. **verify test passes**: ensure the regression test now passes
5. **add to test suite**: integrate the test into appropriate test file

example regression test pattern:
```c
static void test_regression_example_parsing_bug(void **state) {
    (void)state;
    
    // create the exact scenario that was broken
    uint8_t problematic_input[] = {0x00, 0x00, 0x2A, 0x00}; // only 4 bytes
    
    // verify parsing fails correctly (as it should)
    int result = parse_function(problematic_input, 4, &output);
    assert_int_equal(result, -1);
    
    // verify parsing succeeds with correct input
    uint8_t correct_input[] = {0x00, 0x00, 0x2A, 0x00, 0x01}; // 5 bytes
    result = parse_function(correct_input, 5, &output);
    assert_int_equal(result, 5);
}
```

## continuous integration

### ci/cd pipeline integration

tests are designed to run in automated environments:

```yaml
# example github actions integration
test-suite:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v3
    - uses: cachix/install-nix-action@v20
    
    # fast smoke tests (required for all commits)
    - name: smoke tests
      run: |
        nix develop --command bash -c "
          cd build && cmake .. && 
          make test_smoke_client_server && 
          ./test_smoke_client_server
        "
    
    # comprehensive test suite (required for PRs)  
    - name: full test suite
      run: |
        nix develop --command bash -c "
          cd build && 
          make && 
          ctest --output-on-failure
        "
```

### test execution matrix

- **smoke tests**: every commit, PR, merge (required)
- **unit tests**: PR validation, merge, nightly builds (required)
- **integration tests**: PR validation, release builds (required)
- **end-to-end tests**: release validation, nightly builds (optional)

### ci requirements

- all tests must pass for successful builds
- tests run in isolated environments (nix containers)
- no external dependencies or network access required
- deterministic results across different systems
- test execution time limits: smoke <30s, full suite <5min

## best practices

### test naming

- use descriptive names: `test_function_name_scenario`
- group related tests: `test_crypto_sha256_*`, `test_htx_ticket_*`
- indicate test type: `test_function_success`, `test_function_invalid_params`

### test organization

- one test file per module
- group tests by functionality
- include both positive and negative test cases
- test edge cases and boundary conditions

### test data

- use realistic test data when possible
- include edge cases (empty data, maximum sizes, etc.)
- use known test vectors for cryptographic functions
- generate deterministic random data for reproducible tests

### assertions

- use the most specific assertion available
- include descriptive failure messages when helpful
- test one concept per test function
- prefer multiple specific assertions over complex conditions

### maintenance

- update tests when changing functionality
- remove obsolete tests when removing features
- keep tests simple and focused
- ensure tests are fast and reliable
