#include "betanet.h"
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// noise xk constants (spec §5.3)
#define NOISE_MAX_DHLEN 32     // x25519 key size
#define NOISE_MAX_HASHLEN 32   // sha-256 hash size
#define NOISE_TAGLEN 16        // chacha20-poly1305 tag size
#define NOISE_MAX_MSGLEN 65535 // maximum message length
#define NOISE_PROTOCOL_NAME "Noise_XK_25519_ChaChaPoly_SHA256"

// noise handshake state
typedef struct {
    // symmetric state
    uint8_t h[NOISE_MAX_HASHLEN];     // handshake hash
    uint8_t ck[NOISE_MAX_HASHLEN];    // chaining key
    uint8_t k[BETANET_AEAD_KEY_SIZE]; // encryption key (when available)
    uint64_t n;                       // nonce counter

    // key pairs
    uint8_t s[BETANET_DH_PRIVKEY_SIZE];    // local static private key
    uint8_t s_pub[BETANET_DH_PUBKEY_SIZE]; // local static public key
    uint8_t e[BETANET_DH_PRIVKEY_SIZE];    // local ephemeral private key
    uint8_t e_pub[BETANET_DH_PUBKEY_SIZE]; // local ephemeral public key
    uint8_t rs[BETANET_DH_PUBKEY_SIZE];    // remote static public key
    uint8_t re[BETANET_DH_PUBKEY_SIZE];    // remote ephemeral public key

    // handshake state
    int initiator;                 // 1 if initiator, 0 if responder
    int message_patterns_complete; // number of message patterns completed
    int has_key;                   // 1 if k is available for encryption
} noise_handshake_state_t;

// transport state (post-handshake)
typedef struct {
    uint8_t k_send[BETANET_AEAD_KEY_SIZE];    // sending key
    uint8_t k_recv[BETANET_AEAD_KEY_SIZE];    // receiving key
    uint8_t ns_send[BETANET_AEAD_NONCE_SIZE]; // sending nonce salt
    uint8_t ns_recv[BETANET_AEAD_NONCE_SIZE]; // receiving nonce salt
    uint64_t n_send;                          // sending counter
    uint64_t n_recv;                          // receiving counter
} noise_transport_state_t;

/**
 * @brief initialize noise handshake state for xk pattern
 * @param state handshake state to initialize
 * @param initiator 1 if initiator, 0 if responder
 * @param local_static_key local static private key (32 bytes, can be null for ephemeral-only)
 * @param remote_static_key remote static public key (32 bytes, required for xk)
 * @return 0 on success, -1 on error
 */
int noise_handshake_init(noise_handshake_state_t *state, int initiator,
                         const uint8_t *local_static_key, const uint8_t *remote_static_key) {
    if (state == NULL) {
        return -1;
    }
    
    // in xk pattern, only initiator needs remote static key upfront
    if (initiator && remote_static_key == NULL) {
        return -1;
    }

    if (sodium_init() < 0) {
        return -1;
    }

    printf("[DEBUG] NOISE XK INIT: Starting handshake initialization\n");
    printf("[DEBUG] NOISE XK INIT: Role: %s\n", initiator ? "INITIATOR" : "RESPONDER");

    memset(state, 0, sizeof(*state));
    state->initiator = initiator;
    state->message_patterns_complete = 0;
    state->has_key = 0;
    state->n = 0;

    // Step 1: initialize h = hash(protocol_name)
    const char *protocol_name = NOISE_PROTOCOL_NAME;
    printf("[DEBUG] NOISE XK INIT: Step 1 - Hashing protocol name: %s\n", protocol_name);
    if (betanet_hash_sha256(state->h, (const uint8_t *)protocol_name, strlen(protocol_name)) !=
        BETANET_CRYPTO_OK) {
        return -1;
    }

    printf("[DEBUG] NOISE XK INIT: h = hash('%s') = ", protocol_name);
    for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
    printf("\n");

    // Step 2: initialize ck = h  
    memcpy(state->ck, state->h, NOISE_MAX_HASHLEN);
    printf("[DEBUG] NOISE XK INIT: Step 2 - ck = h\n");

    // Step 3: In XK pattern, both parties mix responder's static key
    if (remote_static_key != NULL) {
        printf("[DEBUG] NOISE XK INIT: Step 3 - Mixing responder's static key (XK pattern)\n");
        memcpy(state->rs, remote_static_key, BETANET_DH_PUBKEY_SIZE);

        printf("[DEBUG] NOISE XK INIT: rs = ");
        for(int i = 0; i < 32; i++) printf("%02x", state->rs[i]);
        printf("\n");

        // h = hash(h || rs)
        uint8_t temp_h[NOISE_MAX_HASHLEN + BETANET_DH_PUBKEY_SIZE];
        memcpy(temp_h, state->h, NOISE_MAX_HASHLEN);
        memcpy(temp_h + NOISE_MAX_HASHLEN, state->rs, BETANET_DH_PUBKEY_SIZE);
        if (betanet_hash_sha256(state->h, temp_h, sizeof(temp_h)) != BETANET_CRYPTO_OK) {
            return -1;
        }

        printf("[DEBUG] NOISE XK INIT: h = hash(h || rs) = ");
        for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
        printf("\n");
    } else {
        printf("[DEBUG] NOISE XK INIT: Step 3 - No remote static key provided\n");
    }

    // Step 4: Set local static key
    if (local_static_key != NULL) {
        printf("[DEBUG] NOISE XK INIT: Step 4 - Setting local static key\n");
        memcpy(state->s, local_static_key, BETANET_DH_PRIVKEY_SIZE);
        // derive public key
        if (crypto_scalarmult_base(state->s_pub, state->s) != 0) {
            return -1;
        }
        printf("[DEBUG] NOISE XK INIT: Local static public key: ");
        for(int i = 0; i < 32; i++) printf("%02x", state->s_pub[i]);
        printf("\n");
    }

    printf("[DEBUG] NOISE XK INIT: Initialization complete - Ready for message patterns\n");
    return 0;
}

/**
 * @brief mix key into chaining key using hkdf
 * @param state handshake state
 * @param input_key_material key material to mix
 * @return 0 on success, -1 on error
 */
static int noise_mix_key(noise_handshake_state_t *state, const uint8_t *input_key_material) {
    if (state == NULL || input_key_material == NULL) {
        return -1;
    }

    uint8_t output[64]; // temp_k (32) + new_ck (32)

    if (betanet_kdf_hkdf_sha256(output, 64, input_key_material, BETANET_DH_SHARED_SIZE, state->ck,
                                NOISE_MAX_HASHLEN, NULL, 0) != BETANET_CRYPTO_OK) {
        return -1;
    }

    // update ck and k
    memcpy(state->ck, output, 32);
    memcpy(state->k, output + 32, 32);
    state->has_key = 1;
    state->n = 0; // reset nonce

    // clear temporary output
    sodium_memzero(output, sizeof(output));
    return 0;
}

/**
 * @brief mix hash with data
 * @param state handshake state
 * @param data data to mix into hash
 * @param data_len length of data
 * @return 0 on success, -1 on error
 */
static int noise_mix_hash(noise_handshake_state_t *state, const uint8_t *data, size_t data_len) {
    if (state == NULL || data == NULL) {
        return -1;
    }

    printf("[DEBUG] NOISE MIX_HASH: mixing %zu bytes, initiator=%d\n", data_len, state->initiator);
    printf("[DEBUG] NOISE MIX_HASH: old_h=");
    for(int i = 0; i < 16; i++) printf("%02x", state->h[i]);
    printf("...\n");

    uint8_t temp_h[NOISE_MAX_HASHLEN + data_len];
    memcpy(temp_h, state->h, NOISE_MAX_HASHLEN);
    memcpy(temp_h + NOISE_MAX_HASHLEN, data, data_len);

    int result = betanet_hash_sha256(state->h, temp_h, sizeof(temp_h));
    
    printf("[DEBUG] NOISE MIX_HASH: new_h=");
    for(int i = 0; i < 16; i++) printf("%02x", state->h[i]);
    printf("...\n");

    return result;
}

/**
 * @brief encrypt and authenticate plaintext
 * @param state handshake state
 * @param ciphertext output buffer (must be at least plaintext_len + NOISE_TAGLEN)
 * @param ciphertext_len output: actual ciphertext length
 * @param plaintext input plaintext
 * @param plaintext_len length of plaintext
 * @return 0 on success, -1 on error
 */
static int noise_encrypt_with_ad(noise_handshake_state_t *state, uint8_t *ciphertext,
                                 size_t *ciphertext_len, const uint8_t *plaintext,
                                 size_t plaintext_len) {
    if (state == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return -1;
    }

    if (!state->has_key) {
        // no encryption key available, just copy plaintext
        if (plaintext != NULL && plaintext_len > 0) {
            memcpy(ciphertext, plaintext, plaintext_len);
        }
        *ciphertext_len = plaintext_len;
        return 0;
    }

    // construct nonce: n as little-endian uint64 + 4 zero bytes
    uint8_t nonce[BETANET_AEAD_NONCE_SIZE];
    memset(nonce, 0, sizeof(nonce));
    for (int i = 0; i < 8; i++) {
        nonce[i] = (state->n >> (i * 8)) & 0xff;
    }

    printf("[DEBUG] NOISE ENCRYPT: nonce=%llu, has_key=%d\n", (unsigned long long)state->n, state->has_key);
    printf("[DEBUG] NOISE ENCRYPT: hash=");
    for(int i = 0; i < 16; i++) printf("%02x", state->h[i]);
    printf("...\n");

    int result = betanet_aead_encrypt(ciphertext, ciphertext_len, plaintext, plaintext_len, nonce,
                                      state->k, state->h, NOISE_MAX_HASHLEN);

    if (result == BETANET_CRYPTO_OK) {
        state->n++;
    }

    return result == BETANET_CRYPTO_OK ? 0 : -1;
}

/**
 * @brief decrypt and verify ciphertext
 * @param state handshake state
 * @param plaintext output buffer
 * @param plaintext_len output: actual plaintext length
 * @param ciphertext input ciphertext
 * @param ciphertext_len length of ciphertext
 * @return 0 on success, -1 on error
 */
static int noise_decrypt_with_ad(noise_handshake_state_t *state, uint8_t *plaintext,
                                 size_t *plaintext_len, const uint8_t *ciphertext,
                                 size_t ciphertext_len) {
    if (state == NULL || plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    if (!state->has_key) {
        // no encryption key available, just copy ciphertext
        if (ciphertext != NULL && ciphertext_len > 0) {
            memcpy(plaintext, ciphertext, ciphertext_len);
        }
        *plaintext_len = ciphertext_len;
        return 0;
    }

    // construct nonce: n as little-endian uint64 + 4 zero bytes
    uint8_t nonce[BETANET_AEAD_NONCE_SIZE];
    memset(nonce, 0, sizeof(nonce));
    for (int i = 0; i < 8; i++) {
        nonce[i] = (state->n >> (i * 8)) & 0xff;
    }

    printf("[DEBUG] NOISE DECRYPT: nonce=%llu, has_key=%d\n", (unsigned long long)state->n, state->has_key);
    printf("[DEBUG] NOISE DECRYPT: hash=");
    for(int i = 0; i < 16; i++) printf("%02x", state->h[i]);
    printf("...\n");

    int result = betanet_aead_decrypt(plaintext, plaintext_len, ciphertext, ciphertext_len, nonce,
                                      state->k, state->h, NOISE_MAX_HASHLEN);

    if (result == BETANET_CRYPTO_OK) {
        state->n++;
    }

    return result == BETANET_CRYPTO_OK ? 0 : -1;
}

/**
 * @brief write handshake message (initiator -> responder or responder -> initiator)
 * @param state handshake state
 * @param message output buffer
 * @param message_len input: buffer size, output: actual message length
 * @param payload optional payload to include
 * @param payload_len length of payload
 * @return 0 on success, -1 on error
 */
int noise_write_message(noise_handshake_state_t *state, uint8_t *message, size_t *message_len,
                        const uint8_t *payload, size_t payload_len) {
    if (state == NULL || message == NULL || message_len == NULL) {
        return -1;
    }

    printf("[DEBUG] NOISE XK WRITE: %s writing message %d\n", 
           state->initiator ? "INITIATOR" : "RESPONDER", 
           state->message_patterns_complete + 1);
    
    // XK Pattern:
    // Message 1: -> e              (initiator sends ephemeral)
    // Message 2: <- e, ee, s, es   (responder sends ephemeral, does ee+es DH, sends encrypted static)  
    // Message 3: -> s, se          (initiator sends encrypted static, does se DH)

    size_t offset = 0;
    size_t remaining = *message_len;

    if (state->initiator) {
        // initiator message patterns
        switch (state->message_patterns_complete) {
        case 0: {
            // XK Message 1: -> e
            printf("[DEBUG] NOISE XK MSG1: Initiator generating ephemeral keypair\n");
            if (betanet_x25519_keypair(state->e_pub, state->e) != BETANET_CRYPTO_OK) {
                printf("[DEBUG] NOISE XK MSG1: Failed to generate ephemeral keypair\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG1: Generated e_pub = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->e_pub[i]);
            printf("\n");

            // write e
            if (remaining < BETANET_DH_PUBKEY_SIZE) {
                printf("[DEBUG] NOISE XK MSG1: Insufficient buffer space\n");
                return -1;
            }
            memcpy(message + offset, state->e_pub, BETANET_DH_PUBKEY_SIZE);
            offset += BETANET_DH_PUBKEY_SIZE;
            remaining -= BETANET_DH_PUBKEY_SIZE;

            printf("[DEBUG] NOISE XK MSG1: Current h before mixing e = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            // mix hash with e: h = hash(h || e)
            if (noise_mix_hash(state, state->e_pub, BETANET_DH_PUBKEY_SIZE) != 0) {
                printf("[DEBUG] NOISE XK MSG1: Failed to mix hash with e\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG1: h after mixing e = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            break;
        }

        case 2: {
            // -> s, se

            // encrypt and write s
            size_t s_ciphertext_len = remaining;
            if (noise_encrypt_with_ad(state, message + offset, &s_ciphertext_len, state->s_pub,
                                      BETANET_DH_PUBKEY_SIZE) != 0) {
                return -1;
            }
            offset += s_ciphertext_len;
            remaining -= s_ciphertext_len;

            // mix hash with encrypted s
            if (noise_mix_hash(state, message + offset - s_ciphertext_len, s_ciphertext_len) != 0) {
                return -1;
            }

            // perform se dh
            uint8_t dh_output[BETANET_DH_SHARED_SIZE];
            if (betanet_x25519_shared_secret(dh_output, state->s, state->re) != BETANET_CRYPTO_OK) {
                return -1;
            }

            // mix key with se
            if (noise_mix_key(state, dh_output) != 0) {
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            sodium_memzero(dh_output, sizeof(dh_output));
            break;
        }

        default:
            return -1; // invalid state
        }
    } else {
        // responder message patterns
        switch (state->message_patterns_complete) {
        case 1: {
            // XK Message 2: <- e, ee, s, es
            printf("[DEBUG] NOISE XK MSG2: Responder generating message 2\n");
            printf("[DEBUG] NOISE XK MSG2: Current h = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            // Step 1: Generate ephemeral keypair and write e
            printf("[DEBUG] NOISE XK MSG2: Step 1 - Generating ephemeral keypair\n");
            if (betanet_x25519_keypair(state->e_pub, state->e) != BETANET_CRYPTO_OK) {
                printf("[DEBUG] NOISE XK MSG2: Failed to generate ephemeral keypair\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: Generated e_pub = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->e_pub[i]);
            printf("\n");

            // write e
            if (remaining < BETANET_DH_PUBKEY_SIZE) {
                printf("[DEBUG] NOISE XK MSG2: Insufficient buffer space for e\n");
                return -1;
            }
            memcpy(message + offset, state->e_pub, BETANET_DH_PUBKEY_SIZE);
            offset += BETANET_DH_PUBKEY_SIZE;
            remaining -= BETANET_DH_PUBKEY_SIZE;

            // mix hash with e: h = hash(h || e)
            printf("[DEBUG] NOISE XK MSG2: h before mixing responder e = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            if (noise_mix_hash(state, state->e_pub, BETANET_DH_PUBKEY_SIZE) != 0) {
                printf("[DEBUG] NOISE XK MSG2: Failed to mix hash with e\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: h after mixing responder e = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            // Step 2: Perform ee DH
            printf("[DEBUG] NOISE XK MSG2: Step 2 - Computing ee DH\n");
            printf("[DEBUG] NOISE XK MSG2: Responder e_priv with initiator e_pub (re)\n");
            printf("[DEBUG] NOISE XK MSG2: re = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->re[i]);
            printf("\n");

            uint8_t dh_output[BETANET_DH_SHARED_SIZE];
            if (betanet_x25519_shared_secret(dh_output, state->e, state->re) != BETANET_CRYPTO_OK) {
                printf("[DEBUG] NOISE XK MSG2: Failed to compute ee DH\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: ee DH result = ");
            for(int i = 0; i < 32; i++) printf("%02x", dh_output[i]);
            printf("\n");

            // mix key with ee: ck, k = HKDF(ck, ee)
            printf("[DEBUG] NOISE XK MSG2: ck before mix_key = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->ck[i]);
            printf("\n");

            if (noise_mix_key(state, dh_output) != 0) {
                printf("[DEBUG] NOISE XK MSG2: Failed to mix key with ee\n");
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: ck after mix_key = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->ck[i]);
            printf("\n");
            printf("[DEBUG] NOISE XK MSG2: k after mix_key = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->k[i]);
            printf("\n");

            // Step 3: Encrypt and write s
            printf("[DEBUG] NOISE XK MSG2: Step 3 - Encrypting static key\n");
            printf("[DEBUG] NOISE XK MSG2: s_pub to encrypt = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->s_pub[i]);
            printf("\n");

            size_t s_ciphertext_len = remaining;
            if (noise_encrypt_with_ad(state, message + offset, &s_ciphertext_len, state->s_pub,
                                      BETANET_DH_PUBKEY_SIZE) != 0) {
                printf("[DEBUG] NOISE XK MSG2: Failed to encrypt static key\n");
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }
            offset += s_ciphertext_len;
            remaining -= s_ciphertext_len;
            printf("[DEBUG] NOISE XK MSG2: Encrypted s into %zu bytes\n", s_ciphertext_len);

            // mix hash with encrypted s: h = hash(h || encrypted_s)
            printf("[DEBUG] NOISE XK MSG2: h before mixing encrypted s = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            if (noise_mix_hash(state, message + offset - s_ciphertext_len, s_ciphertext_len) != 0) {
                printf("[DEBUG] NOISE XK MSG2: Failed to mix hash with encrypted s\n");
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: h after mixing encrypted s = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            // Step 4: Perform es DH (initiator ephemeral with responder static)
            printf("[DEBUG] NOISE XK MSG2: Step 4 - Computing es DH\n");
            printf("[DEBUG] NOISE XK MSG2: Responder s_priv with initiator e_pub (re)\n");
            if (betanet_x25519_shared_secret(dh_output, state->s, state->re) != BETANET_CRYPTO_OK) {
                printf("[DEBUG] NOISE XK MSG2: Failed to compute es DH\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: es DH result = ");
            for(int i = 0; i < 32; i++) printf("%02x", dh_output[i]);
            printf("\n");

            // mix key with es: ck, k = HKDF(ck, es)
            if (noise_mix_key(state, dh_output) != 0) {
                printf("[DEBUG] NOISE XK MSG2: Failed to mix key with es\n");
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2: Final ck = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->ck[i]);
            printf("\n");
            printf("[DEBUG] NOISE XK MSG2: Final k = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->k[i]);
            printf("\n");
            printf("[DEBUG] NOISE XK MSG2: Final h = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            sodium_memzero(dh_output, sizeof(dh_output));
            break;
        }

        default:
            return -1; // invalid state
        }
    }

    // encrypt and write payload if present
    if (payload != NULL && payload_len > 0) {
        size_t payload_ciphertext_len = remaining;
        if (noise_encrypt_with_ad(state, message + offset, &payload_ciphertext_len, payload,
                                  payload_len) != 0) {
            return -1;
        }
        offset += payload_ciphertext_len;

        // mix hash with encrypted payload
        if (noise_mix_hash(state, message + offset - payload_ciphertext_len,
                           payload_ciphertext_len) != 0) {
            return -1;
        }
    }

    state->message_patterns_complete++;
    *message_len = offset;
    return 0;
}

/**
 * @brief read handshake message (responder -> initiator or initiator -> responder)
 * @param state handshake state
 * @param message input message
 * @param message_len length of message
 * @param payload output buffer for payload
 * @param payload_len input: buffer size, output: actual payload length
 * @return 0 on success, -1 on error
 */
int noise_read_message(noise_handshake_state_t *state, const uint8_t *message, size_t message_len,
                       uint8_t *payload, size_t *payload_len) {
    if (state == NULL || message == NULL) {
        return -1;
    }

    printf("[DEBUG] NOISE XK READ: %s reading message %d\n", 
           state->initiator ? "INITIATOR" : "RESPONDER", 
           state->message_patterns_complete + 1);

    size_t offset = 0;
    size_t remaining = message_len;

    if (state->initiator) {
        // initiator reading responder messages
        switch (state->message_patterns_complete) {
        case 1: {
            // XK Message 2 read: <- e, ee, s, es  
            printf("[DEBUG] NOISE XK MSG2 READ: Initiator processing message 2\n");
            printf("[DEBUG] NOISE XK MSG2 READ: Current h = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            // Step 1: Read responder's ephemeral key
            printf("[DEBUG] NOISE XK MSG2 READ: Step 1 - Reading responder ephemeral key\n");
            if (remaining < BETANET_DH_PUBKEY_SIZE) {
                printf("[DEBUG] NOISE XK MSG2 READ: Insufficient bytes for ephemeral key\n");
                return -1;
            }
            memcpy(state->re, message + offset, BETANET_DH_PUBKEY_SIZE);
            offset += BETANET_DH_PUBKEY_SIZE;
            remaining -= BETANET_DH_PUBKEY_SIZE;

            printf("[DEBUG] NOISE XK MSG2 READ: Read re = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->re[i]);
            printf("\n");

            // mix hash with responder's e: h = hash(h || re)
            printf("[DEBUG] NOISE XK MSG2 READ: h before mixing responder e = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            if (noise_mix_hash(state, state->re, BETANET_DH_PUBKEY_SIZE) != 0) {
                printf("[DEBUG] NOISE XK MSG2 READ: Failed to mix hash with responder e\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2 READ: h after mixing responder e = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->h[i]);
            printf("\n");

            // Step 2: Perform ee DH
            printf("[DEBUG] NOISE XK MSG2 READ: Step 2 - Computing ee DH\n");
            printf("[DEBUG] NOISE XK MSG2 READ: Initiator e_priv with responder e_pub (re)\n");
            printf("[DEBUG] NOISE XK MSG2 READ: e_priv (partial) = ");
            for(int i = 0; i < 16; i++) printf("%02x", state->e[i]);
            printf("...\n");

            uint8_t dh_output[BETANET_DH_SHARED_SIZE];
            if (betanet_x25519_shared_secret(dh_output, state->e, state->re) != BETANET_CRYPTO_OK) {
                printf("[DEBUG] NOISE XK MSG2 READ: Failed to compute ee DH\n");
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2 READ: ee DH result = ");
            for(int i = 0; i < 32; i++) printf("%02x", dh_output[i]);
            printf("\n");

            // mix key with ee: ck, k = HKDF(ck, ee)
            printf("[DEBUG] NOISE XK MSG2 READ: ck before mix_key = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->ck[i]);
            printf("\n");

            if (noise_mix_key(state, dh_output) != 0) {
                printf("[DEBUG] NOISE XK MSG2 READ: Failed to mix key with ee\n");
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2 READ: ck after mix_key = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->ck[i]);
            printf("\n");
            printf("[DEBUG] NOISE XK MSG2 READ: k after mix_key = ");
            for(int i = 0; i < 32; i++) printf("%02x", state->k[i]);
            printf("\n");

            // Step 3: Read and decrypt responder's static key
            printf("[DEBUG] NOISE XK MSG2 READ: Step 3 - Decrypting responder static key\n");
            size_t s_ciphertext_len = BETANET_DH_PUBKEY_SIZE + NOISE_TAGLEN;
            if (remaining < s_ciphertext_len) {
                printf("[DEBUG] NOISE XK MSG2 READ: Insufficient bytes for encrypted static key (need %zu, have %zu)\n", 
                       s_ciphertext_len, remaining);
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2 READ: Encrypted static key (first 16 bytes) = ");
            for(int i = 0; i < 16; i++) printf("%02x", message[offset + i]);
            printf("...\n");

            uint8_t s_plaintext[BETANET_DH_PUBKEY_SIZE];
            size_t s_plaintext_len = sizeof(s_plaintext);
            if (noise_decrypt_with_ad(state, s_plaintext, &s_plaintext_len, message + offset,
                                      s_ciphertext_len) != 0) {
                printf("[DEBUG] NOISE XK MSG2 READ: Failed to decrypt static key\n");
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            printf("[DEBUG] NOISE XK MSG2 READ: Decrypted rs = ");
            for(int i = 0; i < 32; i++) printf("%02x", s_plaintext[i]);
            printf("\n");

            // mix hash with encrypted s
            if (noise_mix_hash(state, message + offset, s_ciphertext_len) != 0) {
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            offset += s_ciphertext_len;
            remaining -= s_ciphertext_len;

            // perform es dh
            if (betanet_x25519_shared_secret(dh_output, state->e, s_plaintext) !=
                BETANET_CRYPTO_OK) {
                return -1;
            }

            // mix key with es
            if (noise_mix_key(state, dh_output) != 0) {
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            sodium_memzero(dh_output, sizeof(dh_output));
            break;
        }

        default:
            return -1; // invalid state
        }
    } else {
        // responder reading initiator messages
        switch (state->message_patterns_complete) {
        case 0: {
            // -> e

            // read e
            if (remaining < BETANET_DH_PUBKEY_SIZE) {
                return -1;
            }
            memcpy(state->re, message + offset, BETANET_DH_PUBKEY_SIZE);
            offset += BETANET_DH_PUBKEY_SIZE;
            remaining -= BETANET_DH_PUBKEY_SIZE;

            // mix hash with e
            if (noise_mix_hash(state, state->re, BETANET_DH_PUBKEY_SIZE) != 0) {
                return -1;
            }

            break;
        }

        case 2: {
            // -> s, se

            // read and decrypt s
            size_t s_ciphertext_len = BETANET_DH_PUBKEY_SIZE + NOISE_TAGLEN;
            if (remaining < s_ciphertext_len) {
                return -1;
            }

            uint8_t s_plaintext[BETANET_DH_PUBKEY_SIZE];
            size_t s_plaintext_len = sizeof(s_plaintext);
            if (noise_decrypt_with_ad(state, s_plaintext, &s_plaintext_len, message + offset,
                                      s_ciphertext_len) != 0) {
                return -1;
            }

            // store remote static key
            memcpy(state->rs, s_plaintext, BETANET_DH_PUBKEY_SIZE);

            // mix hash with encrypted s
            if (noise_mix_hash(state, message + offset, s_ciphertext_len) != 0) {
                return -1;
            }

            offset += s_ciphertext_len;
            remaining -= s_ciphertext_len;

            // perform se dh
            uint8_t dh_output[BETANET_DH_SHARED_SIZE];
            if (betanet_x25519_shared_secret(dh_output, state->s, state->re) != BETANET_CRYPTO_OK) {
                return -1;
            }

            // mix key with se
            if (noise_mix_key(state, dh_output) != 0) {
                sodium_memzero(dh_output, sizeof(dh_output));
                return -1;
            }

            sodium_memzero(dh_output, sizeof(dh_output));
            break;
        }

        default:
            return -1; // invalid state
        }
    }

    // decrypt payload if present
    if (remaining > 0 && payload != NULL && payload_len != NULL) {
        if (noise_decrypt_with_ad(state, payload, payload_len, message + offset, remaining) != 0) {
            return -1;
        }

        // mix hash with encrypted payload
        if (noise_mix_hash(state, message + offset, remaining) != 0) {
            return -1;
        }
    } else if (payload_len != NULL) {
        *payload_len = 0;
    }

    state->message_patterns_complete++;
    return 0;
}

/**
 * @brief finalize handshake and derive transport keys
 * @param state handshake state
 * @param transport output transport state
 * @return 0 on success, -1 on error
 */
int noise_handshake_finalize(noise_handshake_state_t *state, noise_transport_state_t *transport) {
    if (state == NULL || transport == NULL) {
        return -1;
    }

    if (state->message_patterns_complete < 3) {
        return -1; // handshake not complete
    }

    // derive transport keys using split
    uint8_t output[64]; // k1 (32) + k2 (32)

    if (betanet_kdf_hkdf_sha256(output, 64, state->ck, NOISE_MAX_HASHLEN, NULL, 0, NULL, 0) !=
        BETANET_CRYPTO_OK) {
        return -1;
    }

    if (state->initiator) {
        memcpy(transport->k_send, output, 32);
        memcpy(transport->k_recv, output + 32, 32);
    } else {
        memcpy(transport->k_send, output + 32, 32);
        memcpy(transport->k_recv, output, 32);
    }

    // derive nonce salts
    if (betanet_kdf_hkdf_sha256(transport->ns_send, BETANET_AEAD_NONCE_SIZE, transport->k_send, 32,
                                (const uint8_t *)"ns", 2, NULL, 0) != BETANET_CRYPTO_OK) {
        sodium_memzero(output, sizeof(output));
        return -1;
    }

    if (betanet_kdf_hkdf_sha256(transport->ns_recv, BETANET_AEAD_NONCE_SIZE, transport->k_recv, 32,
                                (const uint8_t *)"ns", 2, NULL, 0) != BETANET_CRYPTO_OK) {
        sodium_memzero(output, sizeof(output));
        return -1;
    }

    transport->n_send = 0;
    transport->n_recv = 0;

    // clear sensitive handshake state
    sodium_memzero(state, sizeof(*state));
    sodium_memzero(output, sizeof(output));

    return 0;
}

/**
 * @brief encrypt transport data using derived keys
 * @param transport transport state
 * @param ciphertext output buffer (must be at least plaintext_len + BETANET_AEAD_TAG_SIZE)
 * @param ciphertext_len output: actual ciphertext length
 * @param plaintext input plaintext
 * @param plaintext_len length of plaintext
 * @return 0 on success, -1 on error
 */
int noise_transport_encrypt(noise_transport_state_t *transport, uint8_t *ciphertext,
                            size_t *ciphertext_len, const uint8_t *plaintext,
                            size_t plaintext_len) {
    if (transport == NULL || ciphertext == NULL || ciphertext_len == NULL) {
        return -1;
    }

    // construct nonce: ns_send + n_send as little-endian uint64
    uint8_t nonce[BETANET_AEAD_NONCE_SIZE];
    memcpy(nonce, transport->ns_send, BETANET_AEAD_NONCE_SIZE);

    // overlay counter at the end of nonce (last 8 bytes)
    for (int i = 0; i < 8; i++) {
        nonce[BETANET_AEAD_NONCE_SIZE - 8 + i] = (transport->n_send >> (i * 8)) & 0xff;
    }

    int result = betanet_aead_encrypt(ciphertext, ciphertext_len, plaintext, plaintext_len, nonce,
                                      transport->k_send, NULL, 0);

    if (result == BETANET_CRYPTO_OK) {
        transport->n_send++;
    }

    return result == BETANET_CRYPTO_OK ? 0 : -1;
}

/**
 * @brief decrypt transport data using derived keys
 * @param transport transport state
 * @param plaintext output buffer
 * @param plaintext_len output: actual plaintext length
 * @param ciphertext input ciphertext
 * @param ciphertext_len length of ciphertext
 * @return 0 on success, -1 on error
 */
int noise_transport_decrypt(noise_transport_state_t *transport, uint8_t *plaintext,
                            size_t *plaintext_len, const uint8_t *ciphertext,
                            size_t ciphertext_len) {
    if (transport == NULL || plaintext == NULL || plaintext_len == NULL) {
        return -1;
    }

    // construct nonce: ns_recv + n_recv as little-endian uint64
    uint8_t nonce[BETANET_AEAD_NONCE_SIZE];
    memcpy(nonce, transport->ns_recv, BETANET_AEAD_NONCE_SIZE);

    // overlay counter at the end of nonce (last 8 bytes)
    for (int i = 0; i < 8; i++) {
        nonce[BETANET_AEAD_NONCE_SIZE - 8 + i] = (transport->n_recv >> (i * 8)) & 0xff;
    }

    int result = betanet_aead_decrypt(plaintext, plaintext_len, ciphertext, ciphertext_len, nonce,
                                      transport->k_recv, NULL, 0);

    if (result == BETANET_CRYPTO_OK) {
        transport->n_recv++;
    }

    return result == BETANET_CRYPTO_OK ? 0 : -1;
}
