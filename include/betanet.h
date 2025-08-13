#ifndef BETANET_H
#define BETANET_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

// opaque structure for a betanet socket
typedef struct betanet_socket_struct *betanet_socket_t;

// opaque structure for a betanet address
typedef struct betanet_addr_struct *betanet_addr_t;

// library initialization options
typedef struct {
    const char *cache_path; // for storing peer info, tickets, etc.
    // ... other global settings
} betanet_init_options_t;

// socket options
typedef enum {
    BETANET_OPT_PRIVACY_MODE, // set to 'strict', 'balanced', 'performance'
    BETANET_OPT_CONNECT_TIMEOUT_MS,
    // ... other socket-level options
} betanet_sockopt_t;

typedef enum {
    BETANET_PRIVACY_STRICT,
    BETANET_PRIVACY_BALANCED,
    BETANET_PRIVACY_PERFORMANCE,
} betanet_privacy_mode_t;

// cryptographic constants (per betanet spec §2)
#define BETANET_HASH_SIZE 32       // sha-256
#define BETANET_AEAD_KEY_SIZE 32   // chacha20-poly1305
#define BETANET_AEAD_NONCE_SIZE 12 // chacha20-poly1305 ietf
#define BETANET_AEAD_TAG_SIZE 16   // poly1305
#define BETANET_SIGNATURE_SIZE 64  // ed25519
#define BETANET_PUBKEY_SIZE 32     // ed25519
#define BETANET_PRIVKEY_SIZE 32    // ed25519
#define BETANET_DH_PUBKEY_SIZE 32  // x25519
#define BETANET_DH_PRIVKEY_SIZE 32 // x25519
#define BETANET_DH_SHARED_SIZE 32  // x25519

// cryptographic function return codes
typedef enum {
    BETANET_CRYPTO_OK = 0,
    BETANET_CRYPTO_ERROR = -1,
    BETANET_CRYPTO_INVALID_PARAM = -2,
    BETANET_CRYPTO_VERIFY_FAILED = -3
} betanet_crypto_result_t;

// cryptographic functions (per betanet spec §2)

/**
 * @brief compute sha-256 hash
 * @param out output buffer (must be BETANET_HASH_SIZE bytes)
 * @param in input data
 * @param in_len length of input data
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_hash_sha256(uint8_t *out, const uint8_t *in, size_t in_len);

/**
 * @brief encrypt data using chacha20-poly1305 aead
 * @param ciphertext output buffer (must be at least plaintext_len + BETANET_AEAD_TAG_SIZE)
 * @param ciphertext_len will be set to actual ciphertext length
 * @param plaintext input plaintext
 * @param plaintext_len length of plaintext
 * @param nonce 12-byte nonce
 * @param key 32-byte key
 * @param ad additional authenticated data (may be null)
 * @param ad_len length of additional data
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_aead_encrypt(uint8_t *ciphertext, size_t *ciphertext_len, const uint8_t *plaintext,
                         size_t plaintext_len, const uint8_t *nonce, const uint8_t *key,
                         const uint8_t *ad, size_t ad_len);

/**
 * @brief decrypt data using chacha20-poly1305 aead
 * @param plaintext output buffer (must be at least ciphertext_len - BETANET_AEAD_TAG_SIZE)
 * @param plaintext_len will be set to actual plaintext length
 * @param ciphertext input ciphertext (including tag)
 * @param ciphertext_len length of ciphertext
 * @param nonce 12-byte nonce
 * @param key 32-byte key
 * @param ad additional authenticated data (may be null)
 * @param ad_len length of additional data
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_aead_decrypt(uint8_t *plaintext, size_t *plaintext_len, const uint8_t *ciphertext,
                         size_t ciphertext_len, const uint8_t *nonce, const uint8_t *key,
                         const uint8_t *ad, size_t ad_len);

/**
 * @brief derive key using hkdf-sha256
 * @param okm output key material
 * @param okm_len desired length of output key material
 * @param ikm input key material
 * @param ikm_len length of input key material
 * @param salt salt value (may be null)
 * @param salt_len length of salt
 * @param info context info (may be null)
 * @param info_len length of info
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_kdf_hkdf_sha256(uint8_t *okm, size_t okm_len, const uint8_t *ikm, size_t ikm_len,
                            const uint8_t *salt, size_t salt_len, const uint8_t *info,
                            size_t info_len);

/**
 * @brief generate ed25519 keypair
 * @param public_key output public key (BETANET_PUBKEY_SIZE bytes)
 * @param private_key output private key (BETANET_PRIVKEY_SIZE bytes)
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_ed25519_keypair(uint8_t *public_key, uint8_t *private_key);

/**
 * @brief sign message using ed25519
 * @param signature output signature (BETANET_SIGNATURE_SIZE bytes)
 * @param message message to sign
 * @param message_len length of message
 * @param private_key private key (BETANET_PRIVKEY_SIZE bytes)
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_ed25519_sign(uint8_t *signature, const uint8_t *message, size_t message_len,
                         const uint8_t *private_key);

/**
 * @brief verify ed25519 signature
 * @param signature signature to verify (BETANET_SIGNATURE_SIZE bytes)
 * @param message original message
 * @param message_len length of message
 * @param public_key public key (BETANET_PUBKEY_SIZE bytes)
 * @return BETANET_CRYPTO_OK on success, BETANET_CRYPTO_VERIFY_FAILED on verification failure
 */
int betanet_ed25519_verify(const uint8_t *signature, const uint8_t *message, size_t message_len,
                           const uint8_t *public_key);

/**
 * @brief generate x25519 keypair
 * @param public_key output public key (BETANET_DH_PUBKEY_SIZE bytes)
 * @param private_key output private key (BETANET_DH_PRIVKEY_SIZE bytes)
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_x25519_keypair(uint8_t *public_key, uint8_t *private_key);

/**
 * @brief compute x25519 shared secret
 * @param shared_secret output shared secret (BETANET_DH_SHARED_SIZE bytes)
 * @param private_key our private key (BETANET_DH_PRIVKEY_SIZE bytes)
 * @param public_key peer's public key (BETANET_DH_PUBKEY_SIZE bytes)
 * @return BETANET_CRYPTO_OK on success, error code otherwise
 */
int betanet_x25519_shared_secret(uint8_t *shared_secret, const uint8_t *private_key,
                                 const uint8_t *public_key);

/**
 * @brief initialize the betanet library. must be called once at startup.
 */
int betanet_init(const betanet_init_options_t *options);

/**
 * @brief clean up and de-allocate all resources used by the library.
 */
void betanet_cleanup(void);

/**
 * @brief create a betanet socket.
 * @return a new socket handle, or null on error.
 */
betanet_socket_t betanet_socket(void);

/**
 * @brief set an option on a betanet socket.
 */
int betanet_setsockopt(betanet_socket_t sock, betanet_sockopt_t option, const void *value);

/**
 * @brief resolve a betanet uri (e.g., "betanet://my-alias") into an address.
 * this handles the l5 naming & trust logic.
 * @return a new address handle, or null on error. the user must free it.
 */
betanet_addr_t betanet_resolve(const char *uri);

/**
 * @brief free a resolved address handle.
 */
void betanet_free_addr(betanet_addr_t addr);

/**
 * @brief connect a socket to a remote betanet address.
 * this is the most complex client-side function. it will perform:
 * - l1 path discovery
 * - l2 htx handshake (tls mirror, ticket bootstrap, noise xk)
 * - l3 peer connection
 * - l4 mixnet setup (if required)
 * @return 0 on success, -1 on error.
 */
int betanet_connect(betanet_socket_t sock, betanet_addr_t addr);

/**
 * @brief send data over a connected socket.
 * @return number of bytes sent, or -1 on error.
 */
ssize_t betanet_send(betanet_socket_t sock, const void *buffer, size_t length);

/**
 * @brief receive data from a connected socket.
 * @param sock connected socket
 * @param buffer output buffer for received data
 * @param length maximum bytes to receive
 * @param received_stream_id optional output parameter for stream_id of received frame
 * @return number of bytes received, or -1 on error.
 */
ssize_t betanet_recv(betanet_socket_t sock, void *buffer, size_t length, uint64_t *received_stream_id);

/**
 * @brief send response data over a connected socket on specified stream.
 * @param sock connected socket
 * @param buffer data to send
 * @param length number of bytes to send
 * @param response_stream_id stream_id to send response on (from corresponding request)
 * @return number of bytes sent, or -1 on error.
 */
ssize_t betanet_send_response(betanet_socket_t sock, const void *buffer, size_t length, uint64_t response_stream_id);

/**
 * @brief close a betanet socket and tear down the connection.
 */
int betanet_close(betanet_socket_t sock);

// server-side functions
int betanet_bind(betanet_socket_t sock, betanet_addr_t local_addr);
int betanet_listen(betanet_socket_t sock, int backlog);
betanet_socket_t betanet_accept(betanet_socket_t sock, betanet_addr_t *client_addr);

#endif // BETANET_H
