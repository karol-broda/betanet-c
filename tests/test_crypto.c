#include <stddef.h>
#include <setjmp.h>
#include <stdarg.h>
#include <string.h>
#include <cmocka.h>

#include "betanet.h"

// test sha-256 hashing
static void test_sha256(void **state) {
    (void)state; // unused

    const char *input = "hello world";
    uint8_t output[BETANET_HASH_SIZE];

    int result = betanet_hash_sha256(output, (const uint8_t *)input, strlen(input));
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // expected sha256 of "hello world"
    uint8_t expected[] = {0xb9, 0x4d, 0x27, 0xb9, 0x93, 0x4d, 0x3e, 0x08, 0xa5, 0x2e, 0x52,
                          0xd7, 0xda, 0x7d, 0xab, 0xfa, 0xc4, 0x84, 0xef, 0xe3, 0x7a, 0x53,
                          0x80, 0xee, 0x90, 0x88, 0xf7, 0xac, 0xe2, 0xef, 0xcd, 0xe9};

    assert_memory_equal(output, expected, BETANET_HASH_SIZE);
}

// test ed25519 keypair generation and signing
static void test_ed25519(void **state) {
    (void)state; // unused

    uint8_t public_key[BETANET_PUBKEY_SIZE];
    uint8_t private_key[BETANET_PRIVKEY_SIZE];

    // generate keypair
    int result = betanet_ed25519_keypair(public_key, private_key);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // sign a message
    const char *message = "test message";
    uint8_t signature[BETANET_SIGNATURE_SIZE];

    result =
        betanet_ed25519_sign(signature, (const uint8_t *)message, strlen(message), private_key);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // verify the signature
    result =
        betanet_ed25519_verify(signature, (const uint8_t *)message, strlen(message), public_key);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // verify should fail with wrong message
    const char *wrong_message = "wrong message";
    result = betanet_ed25519_verify(signature, (const uint8_t *)wrong_message,
                                    strlen(wrong_message), public_key);
    assert_int_equal(result, BETANET_CRYPTO_VERIFY_FAILED);
}

// test x25519 key exchange
static void test_x25519(void **state) {
    (void)state; // unused

    uint8_t alice_public[BETANET_DH_PUBKEY_SIZE];
    uint8_t alice_private[BETANET_DH_PRIVKEY_SIZE];
    uint8_t bob_public[BETANET_DH_PUBKEY_SIZE];
    uint8_t bob_private[BETANET_DH_PRIVKEY_SIZE];

    // generate keypairs for alice and bob
    int result = betanet_x25519_keypair(alice_public, alice_private);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    result = betanet_x25519_keypair(bob_public, bob_private);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // compute shared secrets
    uint8_t alice_shared[BETANET_DH_SHARED_SIZE];
    uint8_t bob_shared[BETANET_DH_SHARED_SIZE];

    result = betanet_x25519_shared_secret(alice_shared, alice_private, bob_public);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    result = betanet_x25519_shared_secret(bob_shared, bob_private, alice_public);
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // shared secrets should be identical
    assert_memory_equal(alice_shared, bob_shared, BETANET_DH_SHARED_SIZE);
}

// test chacha20-poly1305 aead
static void test_aead(void **state) {
    (void)state; // unused

    const char *plaintext = "secret message";
    const char *additional_data = "header info";
    uint8_t key[BETANET_AEAD_KEY_SIZE] = {0};     // zero key for test
    uint8_t nonce[BETANET_AEAD_NONCE_SIZE] = {0}; // zero nonce for test

    // encrypt
    uint8_t ciphertext[256];
    size_t ciphertext_len;

    int result = betanet_aead_encrypt(ciphertext, &ciphertext_len, (const uint8_t *)plaintext,
                                      strlen(plaintext), nonce, key,
                                      (const uint8_t *)additional_data, strlen(additional_data));
    assert_int_equal(result, BETANET_CRYPTO_OK);
    assert_int_equal(ciphertext_len, strlen(plaintext) + BETANET_AEAD_TAG_SIZE);

    // decrypt
    uint8_t decrypted[256];
    size_t decrypted_len;

    result = betanet_aead_decrypt(decrypted, &decrypted_len, ciphertext, ciphertext_len, nonce, key,
                                  (const uint8_t *)additional_data, strlen(additional_data));
    assert_int_equal(result, BETANET_CRYPTO_OK);
    assert_int_equal(decrypted_len, strlen(plaintext));
    assert_memory_equal(decrypted, plaintext, strlen(plaintext));

    // decryption should fail with wrong additional data
    const char *wrong_ad = "wrong header";
    result = betanet_aead_decrypt(decrypted, &decrypted_len, ciphertext, ciphertext_len, nonce, key,
                                  (const uint8_t *)wrong_ad, strlen(wrong_ad));
    assert_int_equal(result, BETANET_CRYPTO_VERIFY_FAILED);
}

// test hkdf key derivation
static void test_hkdf(void **state) {
    (void)state; // unused

    const char *ikm = "input key material";
    const char *salt = "salt";
    const char *info = "context info";
    uint8_t okm[32];

    int result = betanet_kdf_hkdf_sha256(okm, sizeof(okm), (const uint8_t *)ikm, strlen(ikm),
                                         (const uint8_t *)salt, strlen(salt), (const uint8_t *)info,
                                         strlen(info));
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // derive again with same inputs - should get same result
    uint8_t okm2[32];
    result = betanet_kdf_hkdf_sha256(okm2, sizeof(okm2), (const uint8_t *)ikm, strlen(ikm),
                                     (const uint8_t *)salt, strlen(salt), (const uint8_t *)info,
                                     strlen(info));
    assert_int_equal(result, BETANET_CRYPTO_OK);
    assert_memory_equal(okm, okm2, sizeof(okm));

    // derive with different info - should get different result
    const char *info2 = "different context";
    uint8_t okm3[32];
    result = betanet_kdf_hkdf_sha256(okm3, sizeof(okm3), (const uint8_t *)ikm, strlen(ikm),
                                     (const uint8_t *)salt, strlen(salt), (const uint8_t *)info2,
                                     strlen(info2));
    assert_int_equal(result, BETANET_CRYPTO_OK);

    // results should be different
    int same = 1;
    for (int i = 0; i < 32; i++) {
        if (okm[i] != okm3[i]) {
            same = 0;
            break;
        }
    }
    assert_int_equal(same, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sha256), cmocka_unit_test(test_ed25519),
        cmocka_unit_test(test_x25519), cmocka_unit_test(test_aead),
        cmocka_unit_test(test_hkdf),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
