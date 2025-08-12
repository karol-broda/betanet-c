cmake_minimum_required(VERSION 3.10)
project(betanet C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
# find_package(liboqs REQUIRED) # for post-quantum crypto
# find_package(libuv REQUIRED)   # for async i/o
# find_package(libcbor REQUIRED) # for cbor


add_library(betanet STATIC)

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
)

target_link_libraries(betanet PRIVATE OpenSSL::SSL OpenSSL::Crypto)

enable_testing()

find_package(cmocka REQUIRED)
if(CMOCKA_FOUND)
    add_executable(test_core tests/test_core.c)
    target_link_libraries(test_core PRIVATE betanet cmocka)
    target_include_directories(test_core PRIVATE
        $<TARGET_PROPERTY:cmocka,INTERFACE_INCLUDE_DIRECTORIES>)
    add_test(NAME test_core COMMAND test_core)

    # ensure test files are included in the compilation database
    # for vscode linter support
    set_property(TARGET test_core PROPERTY C_STANDARD 11)
    set_property(TARGET test_core PROPERTY C_STANDARD_REQUIRED ON)
endif()

add_executable(example_client examples/example_client.c)
target_link_libraries(example_client PRIVATE betanet)

add_executable(example_server examples/example_server.c)
target_link_libraries(example_server PRIVATE betanet)
