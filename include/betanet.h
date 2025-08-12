#ifndef BETANET_H
#define BETANET_H

#include <stddef.h>
#include <unistd.h>

// opaque structure for a betanet socket
typedef struct betanet_socket_struct* betanet_socket_t;

// opaque structure for a betanet address
typedef struct betanet_addr_struct* betanet_addr_t;

// library initialization options
typedef struct {
    const char* cache_path; // for storing peer info, tickets, etc.
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


/**
 * @brief initialize the betanet library. must be called once at startup.
 */
int betanet_init(const betanet_init_options_t* options);

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
int betanet_setsockopt(betanet_socket_t sock, betanet_sockopt_t option, const void* value);

/**
 * @brief resolve a betanet uri (e.g., "betanet://my-alias") into an address.
 * this handles the l5 naming & trust logic.
 * @return a new address handle, or null on error. the user must free it.
 */
betanet_addr_t betanet_resolve(const char* uri);

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
ssize_t betanet_send(betanet_socket_t sock, const void* buffer, size_t length);

/**
 * @brief receive data from a connected socket.
 * @return number of bytes received, or -1 on error.
 */
ssize_t betanet_recv(betanet_socket_t sock, void* buffer, size_t length);

/**
 * @brief close a betanet socket and tear down the connection.
 */
int betanet_close(betanet_socket_t sock);

// server-side functions
int betanet_bind(betanet_socket_t sock, betanet_addr_t local_addr);
int betanet_listen(betanet_socket_t sock, int backlog);
betanet_socket_t betanet_accept(betanet_socket_t sock, betanet_addr_t* client_addr);

#endif // BETANET_H
