#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include "betanet.h"

static void test_peer_id_create_success(void **state) {
    (void) state;

    // arrange
    uint8_t public_key[BETANET_PUBKEY_SIZE];
    memset(public_key, 0x42, BETANET_PUBKEY_SIZE);
    betanet_peer_id_t peer_id;

    // act
    int result = betanet_peer_id_create(&peer_id, public_key);

    // assert
    assert_int_equal(result, BETANET_CRYPTO_OK);
    assert_int_equal(peer_id.data[0], 0x12);
    assert_int_equal(peer_id.data[1], 0x20);
}

static void test_peer_id_create_invalid_params(void **state) {
    (void) state;

    // arrange
    uint8_t public_key[BETANET_PUBKEY_SIZE];
    betanet_peer_id_t peer_id;

    // act & assert
    assert_int_equal(betanet_peer_id_create(NULL, public_key), BETANET_CRYPTO_INVALID_PARAM);
    assert_int_equal(betanet_peer_id_create(&peer_id, NULL), BETANET_CRYPTO_INVALID_PARAM);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_peer_id_create_success),
        cmocka_unit_test(test_peer_id_create_invalid_params),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
