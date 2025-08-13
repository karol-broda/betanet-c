# contributing guide

this guide covers how to contribute to the betanet c library project.

## getting started

### development setup

1. **fork and clone the repository:**
   ```bash
   git clone https://github.com/your-username/betanet-c.git
   cd betanet-c
   ```

2. **set up development environment:**
   ```bash
   nix develop
   ```

3. **build and test:**
   ```bash
   mkdir build && cd build
   cmake .. && make
   ctest --verbose
   ```

### development workflow

1. **create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **make your changes** following the coding standards below

3. **test your changes:**
   ```bash
   make && ctest --verbose
   ```

4. **commit your changes:**
   ```bash
   git add .
   git commit -m "descriptive commit message"
   ```

5. **push and create pull request:**
   ```bash
   git push origin feature/your-feature-name
   ```

## coding standards

### c style guide

**naming conventions:**
- functions: `snake_case` (e.g., `betanet_connect()`)
- variables: `snake_case` (e.g., `socket_handle`)
- constants: `UPPER_SNAKE_CASE` (e.g., `BETANET_HASH_SIZE`)
- types: `snake_case_t` (e.g., `betanet_socket_t`)
- private functions: prefix with module name (e.g., `htx_generate_ticket()`)

**formatting:**
- **indentation:** 4 spaces, no tabs
- **line length:** prefer 80-100 characters, hard limit 120
- **braces:** opening brace on same line for functions, control structures
- **spacing:** spaces around operators, after commas

**example:**
```c
int betanet_example_function(const uint8_t* input, size_t input_len,
                            uint8_t* output, size_t* output_len) {
    if (input == NULL || output == NULL || output_len == NULL) {
        return -1;
    }
    
    if (input_len == 0 || *output_len < MINIMUM_SIZE) {
        return -1;
    }
    
    for (size_t i = 0; i < input_len; i++) {
        output[i] = process_byte(input[i]);
    }
    
    *output_len = input_len;
    return 0;
}
```

### security guidelines

**memory safety:**
- always check for null pointers
- validate array bounds before access
- clear sensitive data with `sodium_memzero()`
- use `const` for read-only parameters

**error handling:**
- check all return values
- propagate errors appropriately
- clean up resources on error paths
- don't assume operations will succeed

**cryptographic code:**
- use only approved primitives from libsodium
- follow the betanet specification exactly
- include test vectors for verification
- clear intermediate values

**example:**
```c
int secure_function(const uint8_t* secret, size_t secret_len,
                   uint8_t* result, size_t result_len) {
    if (secret == NULL || result == NULL || secret_len == 0) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }
    
    uint8_t intermediate[64];
    int ret = crypto_operation(secret, secret_len, intermediate, sizeof(intermediate));
    if (ret != 0) {
        sodium_memzero(intermediate, sizeof(intermediate));
        return BETANET_CRYPTO_ERROR;
    }
    
    if (result_len < REQUIRED_OUTPUT_SIZE) {
        sodium_memzero(intermediate, sizeof(intermediate));
        return BETANET_CRYPTO_INVALID_PARAM;
    }
    
    memcpy(result, intermediate, REQUIRED_OUTPUT_SIZE);
    sodium_memzero(intermediate, sizeof(intermediate));
    
    return BETANET_CRYPTO_OK;
}
```

### documentation standards

**function documentation:**
```c
/**
 * @brief brief description of what the function does
 * @param param1 description of first parameter
 * @param param2 description of second parameter
 * @return description of return value and possible error codes
 */
int example_function(int param1, const char* param2);
```

**inline comments:**
- explain non-obvious logic
- reference specification sections
- avoid stating the obvious
- use lowercase for consistency

```c
// derive access ticket using hkdf (spec §5.2 step 8)
if (betanet_kdf_hkdf_sha256(ticket->access_ticket, HTX_ACCESS_TICKET_SIZE,
                           shared_secret, sizeof(shared_secret),
                           salt, sizeof(salt), NULL, 0) != BETANET_CRYPTO_OK) {
    return -1;
}
```

## testing requirements

### test coverage

all new code must include comprehensive tests:

- **unit tests** for individual functions
- **integration tests** for multi-component features
- **error condition tests** for all failure modes
- **security tests** for cryptographic functions

### test structure

```c
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "betanet_internal.h"

static void test_function_success(void **state) {
    (void) state;
    
    // arrange
    setup_test_data();
    
    // act
    int result = function_under_test(valid_params);
    
    // assert
    assert_int_equal(result, 0);
    assert_true(validate_result());
}

static void test_function_invalid_params(void **state) {
    (void) state;
    
    // test null parameters
    int result = function_under_test(NULL);
    assert_int_equal(result, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_function_success),
        cmocka_unit_test(test_function_invalid_params),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
```

### adding tests for new modules

1. **create test file:** `tests/test_module.c`
2. **add to cmake:** update `CMakeLists.txt`
3. **expose internal functions:** add to `tests/betanet_internal.h`
4. **run tests:** `ctest --verbose`

## contribution types

### bug fixes

- **identify the issue** clearly in the pull request description
- **include reproduction steps** if applicable
- **add regression tests** to prevent future occurrences
- **verify the fix** doesn't break existing functionality

### new features

- **discuss the feature** in an issue before implementing
- **follow the specification** exactly for protocol features
- **include comprehensive tests** covering all aspects
- **update documentation** including api reference if needed

### performance improvements

- **benchmark before and after** to quantify improvements
- **ensure correctness** is not compromised
- **test edge cases** thoroughly
- **document any tradeoffs** made

### documentation improvements

- **keep documentation current** with code changes
- **use clear, simple language** avoiding jargon where possible
- **include practical examples** for complex topics
- **follow the existing style** and structure

## review process

### pull request guidelines

**title and description:**
- use clear, descriptive titles
- explain what the change does and why
- reference related issues with `fixes #123` or `closes #123`
- include testing information

**code quality:**
- ensure all tests pass
- follow coding standards consistently
- include appropriate documentation updates
- keep changes focused and atomic

### review criteria

reviewers will check:

- **correctness:** does the code work as intended?
- **security:** are there any security vulnerabilities?
- **performance:** are there any performance regressions?
- **maintainability:** is the code easy to understand and modify?
- **testing:** is the code adequately tested?
- **documentation:** is the documentation complete and accurate?

## project governance

### maintainer responsibilities

project maintainers are responsible for:

- reviewing and merging pull requests
- maintaining code quality standards
- ensuring specification compliance
- coordinating releases
- managing project roadmap

### decision making

- **technical decisions** are made through discussion and consensus
- **breaking changes** require careful consideration and migration paths
- **security issues** are handled with priority and may bypass normal process
- **specification changes** must be coordinated with the broader betanet community

## getting help

### communication channels

- **github issues** for bug reports and feature requests
- **github discussions** for general questions and ideas
- **pull request comments** for code-specific discussions

### resources

- [development guide](development.md) for setup and building
- [testing guide](testing.md) for test-related information
- [api reference](api.md) for understanding the public interface
- [architecture overview](architecture.md) for understanding the codebase
- [betanet specification](../spec/betanet.md) for protocol details

### common questions

**q: how do i add a new cryptographic function?**
a: add the implementation to `src/crypto.c`, expose it in `include/betanet.h`, and create comprehensive tests in `tests/test_crypto.c`. ensure you follow the specification and include known test vectors.

**q: how do i test internal functions?**
a: add function declarations to `tests/betanet_internal.h` and create tests in the appropriate test file. make sure the functions are not static in the implementation.

**q: how do i handle breaking changes?**
a: breaking changes should be avoided when possible. if necessary, discuss in an issue first and provide migration guidance in the pull request.

**q: what if my contribution doesn't follow all the guidelines?**
a: don't worry! maintainers will help you improve your contribution during the review process. the guidelines are meant to help, not to discourage contributions.

## recognition

contributors are recognized in several ways:

- **git commit history** preserves authorship information
- **release notes** acknowledge significant contributions
- **documentation** may reference contributors for major features
- **maintainer status** may be offered to regular contributors

thank you for contributing to betanet! your efforts help build a more open and censorship-resistant internet.
