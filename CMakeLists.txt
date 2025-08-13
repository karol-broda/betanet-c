cmake_minimum_required(VERSION 3.10)

# ensure we use the correct clang compiler, not clang-cl
if(NOT CMAKE_C_COMPILER)
    find_program(CLANG_EXECUTABLE NAMES clang)
    if(CLANG_EXECUTABLE)
        set(CMAKE_C_COMPILER ${CLANG_EXECUTABLE})
    endif()
endif()

project(betanet C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# set default build type to Debug if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# logging level configuration based on build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    # debug builds: enable all logging (level 3)
    add_compile_definitions(BETANET_LOG_LEVEL=3)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0 -Wall -Wextra")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    # release builds: only errors (level 0)
    add_compile_definitions(BETANET_LOG_LEVEL=0 NDEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3 -DNDEBUG")
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    # release with debug info: errors and warnings (level 1)
    add_compile_definitions(BETANET_LOG_LEVEL=1)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2")
elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    # minimal size release: no logging at all (level -1)
    add_compile_definitions(BETANET_LOG_LEVEL=-1 NDEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Os -DNDEBUG")
endif()

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
# find_package(liboqs REQUIRED) # for post-quantum crypto
# find_package(libuv REQUIRED)   # for async i/o
# find_package(libcbor REQUIRED) # for cbor

find_package(Threads REQUIRED)

# add the main library target
add_library(betanet src/betanet.c src/crypto.c src/htx.c src/noise.c)
target_link_libraries(betanet PUBLIC ${SODIUM_LIBRARIES})
target_include_directories(betanet PUBLIC ${SODIUM_INCLUDE_DIRS})

target_include_directories(betanet PUBLIC include)

target_sources(betanet PRIVATE
    src/betanet.c
    src/htx.c
    src/scion.c
    src/noise.c
    src/crypto.c
    src/naming.c
    src/nym.c
    src/cashu.c
    src/debug.c
)

target_link_libraries(betanet PRIVATE OpenSSL::SSL OpenSSL::Crypto ${SODIUM_LIBRARIES})
target_include_directories(betanet PRIVATE ${SODIUM_INCLUDE_DIRS})
target_compile_options(betanet PRIVATE ${SODIUM_CFLAGS_OTHER})
target_link_directories(betanet PRIVATE ${SODIUM_LIBRARY_DIRS})

enable_testing()

pkg_check_modules(CMOCKA cmocka)
if(CMOCKA_FOUND)
    add_executable(test_core tests/test_core.c)
    target_link_libraries(test_core PRIVATE betanet cmocka)
    target_include_directories(test_core PRIVATE ${CMOCKA_INCLUDE_DIRS})
    target_compile_options(test_core PRIVATE ${CMOCKA_CFLAGS_OTHER})
    add_test(NAME test_core COMMAND test_core)

    add_executable(test_crypto tests/test_crypto.c)
    target_link_libraries(test_crypto PRIVATE betanet cmocka)
    target_include_directories(test_crypto PRIVATE ${CMOCKA_INCLUDE_DIRS})
    target_compile_options(test_crypto PRIVATE ${CMOCKA_CFLAGS_OTHER})
    add_test(NAME test_crypto COMMAND test_crypto)

    add_executable(test_htx tests/test_htx.c)
    target_link_libraries(test_htx PRIVATE betanet ${CMOCKA_LIBRARIES})
    target_include_directories(test_htx PRIVATE ${CMOCKA_INCLUDE_DIRS})
    target_compile_options(test_htx PRIVATE ${CMOCKA_CFLAGS_OTHER})
    add_test(NAME test_htx COMMAND test_htx)

    add_executable(test_noise tests/test_noise.c)
    target_link_libraries(test_noise PRIVATE betanet ${CMOCKA_LIBRARIES})
    target_include_directories(test_noise PRIVATE ${CMOCKA_INCLUDE_DIRS})
    target_compile_options(test_noise PRIVATE ${CMOCKA_CFLAGS_OTHER})
    add_test(NAME test_noise COMMAND test_noise)

    add_executable(test_l2_secure_channel tests/test_l2_secure_channel.c)
    target_link_libraries(test_l2_secure_channel PRIVATE betanet cmocka)
    add_test(NAME test_l2_secure_channel COMMAND test_l2_secure_channel)

    add_executable(test_htx_frames tests/test_htx_frames.c src/htx.c src/crypto.c)
    target_link_libraries(test_htx_frames PRIVATE betanet cmocka)
    add_test(NAME test_htx_frames COMMAND test_htx_frames)

    add_executable(test_api tests/test_api.c)
    target_link_libraries(test_api PRIVATE betanet cmocka)
    add_test(NAME test_api COMMAND test_api)

    add_executable(test_server tests/test_server.c)
    target_link_libraries(test_server PRIVATE betanet cmocka Threads::Threads)
    add_test(NAME test_server COMMAND test_server)

    # integration test that specifically catches client-server communication bugs
    add_executable(test_integration_client_server tests/test_integration_client_server.c)
    target_link_libraries(test_integration_client_server PRIVATE betanet cmocka Threads::Threads)
    add_test(NAME test_integration_client_server COMMAND test_integration_client_server)

    # fast smoke test for basic functionality - should be run in CI
    add_executable(test_smoke_client_server tests/test_smoke_client_server.c)
    target_link_libraries(test_smoke_client_server PRIVATE betanet cmocka)
    add_test(NAME test_smoke_client_server COMMAND test_smoke_client_server)

    # logging system tests
    add_executable(test_logging tests/test_logging.c)
    target_link_libraries(test_logging PRIVATE betanet cmocka)
    target_include_directories(test_logging PRIVATE ${CMOCKA_INCLUDE_DIRS})
    target_compile_options(test_logging PRIVATE ${CMOCKA_CFLAGS_OTHER})
    add_test(NAME test_logging COMMAND test_logging)

    # ensure test files are included in the compilation database
    # for vscode linter support
    set_property(TARGET test_core PROPERTY C_STANDARD 11)
    set_property(TARGET test_core PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_crypto PROPERTY C_STANDARD 11)
    set_property(TARGET test_crypto PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_htx PROPERTY C_STANDARD 11)
    set_property(TARGET test_htx PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_noise PROPERTY C_STANDARD 11)
    set_property(TARGET test_noise PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_htx_frames PROPERTY C_STANDARD 11)
    set_property(TARGET test_htx_frames PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_api PROPERTY C_STANDARD 11)
    set_property(TARGET test_api PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_l2_secure_channel PROPERTY C_STANDARD 11)
    set_property(TARGET test_l2_secure_channel PROPERTY C_STANDARD_REQUIRED ON)
    set_property(TARGET test_logging PROPERTY C_STANDARD 11)
    set_property(TARGET test_logging PROPERTY C_STANDARD_REQUIRED ON)
endif()

add_executable(example_client examples/example_client.c)
target_link_libraries(example_client PRIVATE betanet)

add_executable(example_server examples/example_server.c)
target_link_libraries(example_server PRIVATE betanet)

add_executable(api_demo examples/api_demo.c)
target_link_libraries(api_demo PRIVATE betanet)

# formatting and linting targets
find_program(CLANG_FORMAT_EXECUTABLE NAMES clang-format)
find_program(CLANG_TIDY_EXECUTABLE NAMES clang-tidy)

if(CLANG_FORMAT_EXECUTABLE)
    # collect all source files
    file(GLOB_RECURSE ALL_SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/src/*.c
        ${CMAKE_SOURCE_DIR}/src/*.h
        ${CMAKE_SOURCE_DIR}/include/*.h
        ${CMAKE_SOURCE_DIR}/tests/*.c
        ${CMAKE_SOURCE_DIR}/tests/*.h
        ${CMAKE_SOURCE_DIR}/examples/*.c
    )

    # format target
    add_custom_target(format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} -i ${ALL_SOURCE_FILES}
        COMMENT "formatting source files with clang-format"
        VERBATIM
    )

    # check format target
    add_custom_target(check-format
        COMMAND ${CLANG_FORMAT_EXECUTABLE} --dry-run --Werror ${ALL_SOURCE_FILES}
        COMMENT "checking source file formatting with clang-format"
        VERBATIM
    )
endif()

if(CLANG_TIDY_EXECUTABLE)
    # collect source files for linting (only main source files for now)
    file(GLOB LINT_SOURCE_FILES
        ${CMAKE_SOURCE_DIR}/src/*.c
        ${CMAKE_SOURCE_DIR}/examples/*.c
    )
    
    # lint target - only analyze our source files, ignore system headers
    add_custom_target(lint
        COMMAND ${CLANG_TIDY_EXECUTABLE} 
            ${LINT_SOURCE_FILES}
            "--header-filter=^${CMAKE_SOURCE_DIR}/(src|include|tests)/.*\\.(h|hpp)$$"
            --
            -I${CMAKE_SOURCE_DIR}/include
            ${SODIUM_CFLAGS_OTHER}
            -I${SODIUM_INCLUDE_DIRS}
            -I${CMOCKA_INCLUDE_DIRS}
            -isystem${SODIUM_INCLUDE_DIRS}
            -isystem${CMOCKA_INCLUDE_DIRS}
        COMMENT "running clang-tidy static analysis (ignoring system headers)"
        VERBATIM
        DEPENDS betanet
    )
endif()
