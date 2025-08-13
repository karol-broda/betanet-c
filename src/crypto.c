#include "betanet.h"
#include <sodium.h>
#include <stdint.h>
#include <string.h>

static int crypto_initialized = 0;

static int ensure_crypto_init(void) {
    if (!crypto_initialized) {
        if (sodium_init() < 0) {
            return BETANET_CRYPTO_ERROR;
        }
        crypto_initialized = 1;
    }
    return BETANET_CRYPTO_OK;
}

int betanet_hash_sha256(uint8_t *out, const uint8_t *in, size_t in_len) {
    if (out == NULL || in == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    crypto_hash_sha256(out, in, in_len);
    return BETANET_CRYPTO_OK;
}

int betanet_aead_encrypt(uint8_t *ciphertext, size_t *ciphertext_len, const uint8_t *plaintext,
                         size_t plaintext_len, const uint8_t *nonce, const uint8_t *key,
                         const uint8_t *ad, size_t ad_len) {
    if (ciphertext == NULL || ciphertext_len == NULL || plaintext == NULL || nonce == NULL ||
        key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    unsigned long long cipher_len;
    int result = crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &cipher_len, plaintext,
                                                           plaintext_len, ad, ad_len,
                                                           NULL, // nsec (not used in ietf version)
                                                           nonce, key);

    if (result != 0) {
        return BETANET_CRYPTO_ERROR;
    }

    *ciphertext_len = cipher_len;
    return BETANET_CRYPTO_OK;
}

int betanet_aead_decrypt(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *ciphertext,
                         size_t ciphertext_len, const uint8_t *nonce, const uint8_t *key,
                         const uint8_t *ad, size_t ad_len) {
    if (plaintext == NULL || plaintext_len == NULL || ciphertext == NULL || nonce == NULL ||
        key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    unsigned long long plain_len;
    int result = crypto_aead_chacha20poly1305_ietf_decrypt(plaintext, &plain_len,
                                                           NULL, // nsec (not used)
                                                           ciphertext, ciphertext_len, ad, ad_len,
                                                           nonce, key);

    if (result != 0) {
        return BETANET_CRYPTO_VERIFY_FAILED;
    }

    *plaintext_len = plain_len;
    return BETANET_CRYPTO_OK;
}

int betanet_kdf_hkdf_sha256(uint8_t *okm, size_t okm_len, const uint8_t *ikm, size_t ikm_len,
                            const uint8_t *salt, size_t salt_len, const uint8_t *info,
                            size_t info_len) {
    if (okm == NULL || ikm == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    // if salt is provided, we need to do the full hkdf (extract + expand)
    uint8_t prk[crypto_auth_hmacsha256_BYTES];

    if (salt != NULL && salt_len > 0) {
        // extract phase: prk = hmac-sha256(salt, ikm)
        crypto_auth_hmacsha256_state state;
        crypto_auth_hmacsha256_init(&state, salt, salt_len);
        crypto_auth_hmacsha256_update(&state, ikm, ikm_len);
        crypto_auth_hmacsha256_final(&state, prk);
    } else {
        // no salt provided, use ikm directly as prk (truncated/padded to 32 bytes)
        memset(prk, 0, sizeof(prk));
        size_t copy_len = ikm_len < sizeof(prk) ? ikm_len : sizeof(prk);
        memcpy(prk, ikm, copy_len);
    }

    // expand phase -  okm = hkdf-expand(prk, info, okm_len)
    int result = crypto_kdf_hkdf_sha256_expand(okm, okm_len, (const char *)info, info_len, prk);

    // clear the prk from memory
    sodium_memzero(prk, sizeof(prk));

    if (result != 0) {
        return BETANET_CRYPTO_ERROR;
    }

    return BETANET_CRYPTO_OK;
}

int betanet_ed25519_keypair(uint8_t *public_key, uint8_t *private_key) {
    if (public_key == NULL || private_key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    crypto_sign_keypair(public_key, private_key);
    return BETANET_CRYPTO_OK;
}

int betanet_ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len,
                         const uint8_t *private_key) {
    if (signature == NULL || message == NULL || private_key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    unsigned long long sig_len;
    int result = crypto_sign_detached(signature, &sig_len, message, message_len, private_key);

    if (result != 0 || sig_len != BETANET_SIGNATURE_SIZE) {
        return BETANET_CRYPTO_ERROR;
    }

    return BETANET_CRYPTO_OK;
}

int betanet_ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len,
                           const uint8_t *public_key) {
    if (signature == NULL || message == NULL || public_key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    int result = crypto_sign_verify_detached(signature, message, message_len, public_key);

    if (result != 0) {
        return BETANET_CRYPTO_VERIFY_FAILED;
    }

    return BETANET_CRYPTO_OK;
}

int betanet_x25519_keypair(uint8_t *public_key, uint8_t *private_key) {
    if (public_key == NULL || private_key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    crypto_box_keypair(public_key, private_key);
    return BETANET_CRYPTO_OK;
}

int betanet_x25519_shared_secret(uint8_t *shared_secret, const uint8_t *private_key,
                                 const uint8_t *public_key) {
    if (shared_secret == NULL || private_key == NULL || public_key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    if (ensure_crypto_init() != BETANET_CRYPTO_OK) {
        return BETANET_CRYPTO_ERROR;
    }

    int result = crypto_scalarmult(shared_secret, private_key, public_key);

    if (result != 0) {
        return BETANET_CRYPTO_ERROR;
    }

    return BETANET_CRYPTO_OK;
}
