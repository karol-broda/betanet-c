# api reference

this document provides comprehensive documentation for the betanet c library public api.

## overview

the betanet library provides a socket-like api for secure, censorship-resistant networking. the api is designed to be familiar to developers who have worked with berkeley sockets.

## library initialization

### betanet_init

```c
int betanet_init(const betanet_init_options_t* options);
```

initialize the betanet library. must be called once at startup before using any other functions.

**parameters:**
- `options` - initialization options (can be null for defaults)

**returns:**
- `0` on success
- `-1` on error

**example:**
```c
betanet_init_options_t opts = {
    .cache_path = "/tmp/betanet_cache"
};

if (betanet_init(&opts) != 0) {
    fprintf(stderr, "failed to initialize betanet\n");
    exit(1);
}
```

### betanet_cleanup

```c
void betanet_cleanup(void);
```

clean up and deallocate all resources used by the library. should be called before program exit.

## socket management

### betanet_socket

```c
betanet_socket_t betanet_socket(void);
```

create a new betanet socket.

**returns:**
- socket handle on success
- `NULL` on error

**example:**
```c
betanet_socket_t sock = betanet_socket();
if (sock == NULL) {
    fprintf(stderr, "failed to create socket\n");
    return -1;
}
```

### betanet_close

```c
int betanet_close(betanet_socket_t sock);
```

close a betanet socket and tear down the connection.

**parameters:**
- `sock` - socket to close

**returns:**
- `0` on success
- `-1` on error

## socket configuration

### betanet_setsockopt

```c
int betanet_setsockopt(betanet_socket_t sock, betanet_sockopt_t option, const void* value);
```

set socket options.

**parameters:**
- `sock` - socket handle
- `option` - option to set
- `value` - pointer to option value

**options:**
- `BETANET_OPT_PRIVACY_MODE` - set privacy mode (`betanet_privacy_mode_t`)
- `BETANET_OPT_CONNECT_TIMEOUT_MS` - connection timeout in milliseconds (`int`)

**example:**
```c
betanet_privacy_mode_t mode = BETANET_PRIVACY_BALANCED;
betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &mode);

int timeout = 30000; // 30 seconds
betanet_setsockopt(sock, BETANET_OPT_CONNECT_TIMEOUT_MS, &timeout);
```

## address resolution

### betanet_resolve

```c
betanet_addr_t betanet_resolve(const char* uri);
```

resolve a betanet uri into an address. handles l5 naming & trust logic.

**parameters:**
- `uri` - betanet uri (e.g., "betanet://my-alias" or "betanet://hash")

**returns:**
- address handle on success
- `NULL` on error

**current implementation:**
the current implementation supports a simplified "host:port" format. full `betanet://` uri support is planned.

**example:**
```c
// current implementation - host:port format
betanet_addr_t addr = betanet_resolve("127.0.0.1:8080");
if (addr == NULL) {
    fprintf(stderr, "failed to resolve address\n");
    return -1;
}

// future implementation - betanet uri format
// betanet_addr_t addr = betanet_resolve("betanet://example-service");
```

### betanet_free_addr

```c
void betanet_free_addr(betanet_addr_t addr);
```

free a resolved address handle.

**parameters:**
- `addr` - address to free

## client operations

### betanet_connect

```c
int betanet_connect(betanet_socket_t sock, betanet_addr_t addr);
```

connect a socket to a remote betanet address.

**implementation details:**
this function now performs the full, secure l2 handshake:
- establishes a tcp connection.
- orchestrates the htx access-ticket bootstrap.
- executes the noise xk handshake to establish a secure, forward-secret channel.

all subsequent data sent via `betanet_send` is encrypted.

**parameters:**
- `sock` - socket handle
- `addr` - resolved address

**returns:**
- `0` on success
- `-1` on error

**example:**
```c
betanet_socket_t sock = betanet_socket();
betanet_addr_t addr = betanet_resolve("127.0.0.1:8080");

if (betanet_connect(sock, addr) != 0) {
    fprintf(stderr, "connection failed\n");
    betanet_free_addr(addr);
    betanet_close(sock);
    betanet_cleanup();
    return -1;
}

betanet_free_addr(addr);
```

### betanet_send

```c
ssize_t betanet_send(betanet_socket_t sock, const void* buffer, size_t length);
```

send data over a connected socket.

**implementation details:**
data is wrapped in an htx `stream` frame and encrypted using the transport keys established during the handshake before being sent over the underlying tcp connection.

**parameters:**
- `sock` - connected socket
- `buffer` - data to send
- `length` - number of bytes to send

**returns:**
- number of bytes sent on success
- `-1` on error

**example:**
```c
const char* message = "hello, betanet!";
ssize_t sent = betanet_send(sock, message, strlen(message));
if (sent < 0) {
    fprintf(stderr, "send failed\n");
} else {
    printf("sent %zd bytes\n", sent);
}
```

### betanet_recv

```c
ssize_t betanet_recv(betanet_socket_t sock, void* buffer, size_t length);
```

receive data from a connected socket.

**implementation details:**
the function reads encrypted htx frames from the underlying connection, decrypts them, and extracts the payload into the user-provided buffer. it handles frame parsing and manages the stream.

**parameters:**
- `sock` - connected socket
- `buffer` - buffer to receive data into
- `length` - size of buffer

**returns:**
- number of bytes received on success
- `0` on connection closed
- `-1` on error

**example:**
```c
char buffer[1024];
ssize_t received = betanet_recv(sock, buffer, sizeof(buffer));
if (received > 0) {
    printf("received %zd bytes: %.*s\n", received, (int)received, buffer);
} else if (received == 0) {
    printf("connection closed\n");
} else {
    fprintf(stderr, "receive failed\n");
}
```

## server operations

### betanet_bind

```c
int betanet_bind(betanet_socket_t sock, betanet_addr_t local_addr);
```

bind a socket to a local address.

**parameters:**
- `sock` - socket handle
- `local_addr` - local address to bind to

**returns:**
- `0` on success
- `-1` on error

### betanet_listen

```c
int betanet_listen(betanet_socket_t sock, int backlog);
```

listen for incoming connections.

**parameters:**
- `sock` - bound socket
- `backlog` - maximum number of pending connections

**returns:**
- `0` on success
- `-1` on error

### betanet_accept

```c
betanet_socket_t betanet_accept(betanet_socket_t sock, betanet_addr_t* client_addr);
```

accept an incoming connection.

**parameters:**
- `sock` - listening socket
- `client_addr` - pointer to store client address (can be null)

**returns:**
- new socket handle for the connection on success
- `NULL` on error

**example server:**
```c
betanet_socket_t server_sock = betanet_socket();
betanet_addr_t local_addr = betanet_resolve("betanet://my-server");

betanet_bind(server_sock, local_addr);
betanet_listen(server_sock, 10);

while (1) {
    betanet_addr_t client_addr;
    betanet_socket_t client_sock = betanet_accept(server_sock, &client_addr);
    
    if (client_sock != NULL) {
        // handle client connection
        handle_client(client_sock);
        betanet_close(client_sock);
        betanet_free_addr(client_addr); // remember to free the client address
    }
}
```

## cryptographic functions

the library exposes cryptographic primitives used internally. these follow the betanet specification (§2).

### hash functions

#### betanet_hash_sha256

```c
int betanet_hash_sha256(uint8_t* out, const uint8_t* in, size_t in_len);
```

compute sha-256 hash.

**parameters:**
- `out` - output buffer (must be 32 bytes)
- `in` - input data
- `in_len` - length of input data

**returns:**
- `BETANET_CRYPTO_OK` on success
- error code on failure

### authenticated encryption

#### betanet_aead_encrypt

```c
int betanet_aead_encrypt(uint8_t* ciphertext, size_t* ciphertext_len,
                        const uint8_t* plaintext, size_t plaintext_len,
                        const uint8_t* nonce, const uint8_t* key,
                        const uint8_t* ad, size_t ad_len);
```

encrypt data using chacha20-poly1305 aead.

**parameters:**
- `ciphertext` - output buffer (must be at least `plaintext_len + 16`)
- `ciphertext_len` - input: buffer size, output: actual ciphertext length
- `plaintext` - input plaintext
- `plaintext_len` - length of plaintext
- `nonce` - 12-byte nonce
- `key` - 32-byte key
- `ad` - additional authenticated data (can be null)
- `ad_len` - length of additional data

#### betanet_aead_decrypt

```c
int betanet_aead_decrypt(uint8_t* plaintext, size_t* plaintext_len,
                        const uint8_t* ciphertext, size_t ciphertext_len,
                        const uint8_t* nonce, const uint8_t* key,
                        const uint8_t* ad, size_t ad_len);
```

decrypt data using chacha20-poly1305 aead.

### key derivation

#### betanet_kdf_hkdf_sha256

```c
int betanet_kdf_hkdf_sha256(uint8_t* okm, size_t okm_len,
                           const uint8_t* ikm, size_t ikm_len,
                           const uint8_t* salt, size_t salt_len,
                           const uint8_t* info, size_t info_len);
```

derive key using hkdf-sha256.

### digital signatures

#### betanet_ed25519_keypair

```c
int betanet_ed25519_keypair(uint8_t* public_key, uint8_t* private_key);
```

generate ed25519 keypair.

**parameters:**
- `public_key` - output public key (32 bytes)
- `private_key` - output private key (32 bytes)

#### betanet_ed25519_sign

```c
int betanet_ed25519_sign(uint8_t* signature,
                        const uint8_t* message, size_t message_len,
                        const uint8_t* private_key);
```

sign message using ed25519.

#### betanet_ed25519_verify

```c
int betanet_ed25519_verify(const uint8_t* signature,
                          const uint8_t* message, size_t message_len,
                          const uint8_t* public_key);
```

verify ed25519 signature.

### key exchange

#### betanet_x25519_keypair

```c
int betanet_x25519_keypair(uint8_t* public_key, uint8_t* private_key);
```

generate x25519 keypair.

#### betanet_x25519_shared_secret

```c
int betanet_x25519_shared_secret(uint8_t* shared_secret,
                                const uint8_t* private_key,
                                const uint8_t* public_key);
```

compute x25519 shared secret.

## data types

### betanet_socket_t

opaque handle representing a betanet socket.

### betanet_addr_t

opaque handle representing a resolved betanet address.

### betanet_init_options_t

```c
typedef struct {
    const char* cache_path; // path for storing peer info, tickets, etc.
    // additional options may be added in future versions
} betanet_init_options_t;
```

### betanet_sockopt_t

socket option identifiers:
- `BETANET_OPT_PRIVACY_MODE`
- `BETANET_OPT_CONNECT_TIMEOUT_MS`

### betanet_privacy_mode_t

privacy mode settings:
- `BETANET_PRIVACY_STRICT` - every stream through ≥3 nym hops
- `BETANET_PRIVACY_BALANCED` - ≥2 hops until peer-trust ≥0.8 (default)
- `BETANET_PRIVACY_PERFORMANCE` - no mixnet unless destination requires it

### error codes

cryptographic function return codes:
- `BETANET_CRYPTO_OK` (0) - success
- `BETANET_CRYPTO_ERROR` (-1) - general error
- `BETANET_CRYPTO_INVALID_PARAM` (-2) - invalid parameter
- `BETANET_CRYPTO_VERIFY_FAILED` (-3) - verification failed

## constants

cryptographic constants (per betanet spec §2):
- `BETANET_HASH_SIZE` (32) - sha-256 output size
- `BETANET_AEAD_KEY_SIZE` (32) - chacha20-poly1305 key size
- `BETANET_AEAD_NONCE_SIZE` (12) - chacha20-poly1305 nonce size
- `BETANET_AEAD_TAG_SIZE` (16) - poly1305 tag size
- `BETANET_SIGNATURE_SIZE` (64) - ed25519 signature size
- `BETANET_PUBKEY_SIZE` (32) - ed25519 public key size
- `BETANET_PRIVKEY_SIZE` (32) - ed25519 private key size
- `BETANET_DH_PUBKEY_SIZE` (32) - x25519 public key size
- `BETANET_DH_PRIVKEY_SIZE` (32) - x25519 private key size
- `BETANET_DH_SHARED_SIZE` (32) - x25519 shared secret size

## complete example

```c
#include "betanet.h"
#include <stdio.h>
#include <string.h>

int main() {
    // initialize library
    if (betanet_init(NULL) != 0) {
        fprintf(stderr, "failed to initialize betanet\n");
        return 1;
    }

    // create socket
    betanet_socket_t sock = betanet_socket();
    if (sock == NULL) {
        fprintf(stderr, "failed to create socket\n");
        betanet_cleanup();
        return 1;
    }

    // set privacy mode
    betanet_privacy_mode_t mode = BETANET_PRIVACY_BALANCED;
    betanet_setsockopt(sock, BETANET_OPT_PRIVACY_MODE, &mode);

    // resolve address
    // note: using host:port format until full l5 naming is implemented
    betanet_addr_t addr = betanet_resolve("127.0.0.1:8080");
    if (addr == NULL) {
        fprintf(stderr, "failed to resolve address\n");
        betanet_close(sock);
        betanet_cleanup();
        return 1;
    }

    // connect
    if (betanet_connect(sock, addr) != 0) {
        fprintf(stderr, "connection failed\n");
        betanet_free_addr(addr);
        betanet_close(sock);
        betanet_cleanup();
        return 1;
    }

    // send message
    const char* message = "hello from betanet!";
    ssize_t sent = betanet_send(sock, message, strlen(message));
    if (sent > 0) {
        printf("sent: %s\n", message);
    }

    // receive response
    char buffer[1024];
    ssize_t received = betanet_recv(sock, buffer, sizeof(buffer) - 1);
    if (received > 0) {
        buffer[received] = '\0';
        printf("received: %s\n", buffer);
    }

    // cleanup
    betanet_free_addr(addr);
    betanet_close(sock);
    betanet_cleanup();
    
    return 0;
}
```

## thread safety

the betanet library is **not thread-safe**. if you need to use betanet from multiple threads:

- use separate socket handles per thread
- protect shared resources with mutexes
- call `betanet_init()` only once from the main thread
- call `betanet_cleanup()` only after all threads have finished using betanet

## memory management

- the library manages internal memory automatically
- you are responsible for freeing addresses with `betanet_free_addr()`
- socket handles are automatically cleaned up when closed
- the library clears sensitive data from memory when possible

## error handling

- most functions return `0` on success, `-1` on error
- cryptographic functions use specific error codes
- check return values and handle errors appropriately
- use standard c library functions like `perror()` for system errors
