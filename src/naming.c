#include "betanet.h"
#include <string.h>

int betanet_peer_id_create(betanet_peer_id_t *peer_id, const uint8_t *public_key) {
    if (peer_id == NULL || public_key == NULL) {
        return BETANET_CRYPTO_INVALID_PARAM;
    }

    // 1. hash the public key
    uint8_t hash[BETANET_HASH_SIZE];
    int result = betanet_hash_sha256(hash, public_key, BETANET_PUBKEY_SIZE);
    if (result != BETANET_CRYPTO_OK) {
        return result;
    }

    // 2. construct the multihash
    // multihash format: <multihash_code><digest_size><digest>
    // for sha2-256, code is 0x12, size is 32 (0x20)
    peer_id->data[0] = 0x12; // sha2-256 multihash code
    peer_id->data[1] = 0x20; // 32-byte digest size
    memcpy(&peer_id->data[2], hash, BETANET_HASH_SIZE);

    return BETANET_CRYPTO_OK;
}
