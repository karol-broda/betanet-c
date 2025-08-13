#include "betanet.h"
#include "betanet_log.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sodium.h>
#include <sys/socket.h>

typedef struct noise_handshake_state_struct {
    // symmetric state
    uint8_t h[32];  // handshake hash
    uint8_t ck[32]; // chaining key
    uint8_t k[32];  // encryption key (when available)
    uint64_t n;     // nonce counter

    // key pairs
    uint8_t s[32];     // local static private key
    uint8_t s_pub[32]; // local static public key
    uint8_t e[32];     // local ephemeral private key
    uint8_t e_pub[32]; // local ephemeral public key
    uint8_t rs[32];    // remote static public key
    uint8_t re[32];    // remote ephemeral public key

    // handshake state
    int initiator;                 // 1 if initiator, 0 if responder
    int message_patterns_complete; // number of message patterns completed
    int has_key;                   // 1 if k is available for encryption
} noise_handshake_state_t;

typedef struct noise_transport_state_struct {
    uint8_t k_send[32];  // sending key
    uint8_t k_recv[32];  // receiving key
    uint8_t ns_send[12]; // sending nonce salt
    uint8_t ns_recv[12]; // receiving nonce salt
    uint64_t n_send;     // sending counter
    uint64_t n_recv;     // receiving counter
} noise_transport_state_t;

// forward declarations for functions we'll use
extern int noise_handshake_init(noise_handshake_state_t *state, int initiator,
                                const uint8_t *local_static_key, const uint8_t *remote_static_key);
extern int noise_write_message(noise_handshake_state_t *state, uint8_t *message,
                               size_t *message_len, const uint8_t *payload, size_t payload_len);
extern int noise_read_message(noise_handshake_state_t *state, const uint8_t *message,
                              size_t message_len, uint8_t *payload, size_t *payload_len);
extern int noise_handshake_finalize(noise_handshake_state_t *state,
                                    noise_transport_state_t *transport);

// htx types (defined in htx.c)
typedef enum {
    HTX_CARRIER_COOKIE = 0x01,
    HTX_CARRIER_QUERY = 0x02,
    HTX_CARRIER_BODY = 0x03
} htx_carrier_type_t;

typedef struct {
    uint8_t ticket_pub[32];                 // server's x25519 public key
    uint8_t ticket_key_id[8];               // key identifier
    htx_carrier_type_t allowed_carriers[3]; // allowed carrier types
    float carrier_probabilities[3];         // probabilities for each carrier
    size_t min_len;                         // minimum payload length
    size_t max_len;                         // maximum payload length
} htx_server_ticket_info_t;

// htx function declarations
extern int htx_generate_access_ticket(uint8_t *payload, size_t *payload_len,
                                      const htx_server_ticket_info_t *server_info,
                                      htx_carrier_type_t carrier_type);
extern int htx_encode_base64url(char *encoded, size_t *encoded_len, const uint8_t *payload,
                                size_t payload_len);
extern int htx_construct_http_request(char *request, size_t *request_len, const char *host,
                                      const char *path, const char *payload,
                                      htx_carrier_type_t carrier_type);
extern int htx_construct_stream_frame(uint8_t *frame, size_t *frame_len, uint64_t stream_id,
                                      const uint8_t *payload, size_t payload_len,
                                      void *transport_state);
extern int htx_parse_stream_frame(const uint8_t *frame, size_t frame_len, uint64_t *stream_id,
                                  uint8_t *payload, size_t *payload_len, void *transport_state);
extern int htx_deserialize_frame_header(const uint8_t *buf, size_t buf_len, uint32_t *length,
                                        uint8_t *type, uint64_t *stream_id);

/**
 * @brief perform htx access ticket bootstrap
 * @param tcp_fd connected tcp socket
 * @param host target hostname
 * @param server_info server ticket information
 * @return 0 on success, -1 on error
 */
static int perform_htx_bootstrap(int tcp_fd, const char *host,
                                 const htx_server_ticket_info_t *server_info) {
    if (tcp_fd < 0 || host == NULL || server_info == NULL) {
        return -1;
    }

    // generate access ticket payload
    uint8_t ticket_payload[512];
    size_t payload_len = sizeof(ticket_payload);

    if (htx_generate_access_ticket(ticket_payload, &payload_len, server_info, HTX_CARRIER_COOKIE) !=
        0) {
        return -1;
    }

    // encode as base64url
    char encoded_ticket[1024];
    size_t encoded_len = sizeof(encoded_ticket);

    if (htx_encode_base64url(encoded_ticket, &encoded_len, ticket_payload, payload_len) != 0) {
        return -1;
    }

    // construct http request
    char http_request[2048];
    size_t request_len = sizeof(http_request);

    if (htx_construct_http_request(http_request, &request_len, host, "/", encoded_ticket,
                                   HTX_CARRIER_COOKIE) != 0) {
        return -1;
    }

    // send http request
    ssize_t sent = send(tcp_fd, http_request, request_len, 0);
    if (sent < 0 || (size_t)sent != request_len) {
        BETANET_LOG_ERROR("HTX: Failed to send HTTP request");
        return -1;
    }

    // receive and parse http response (simplified - just read some data)
    char response[1024];
    ssize_t received = recv(tcp_fd, response, sizeof(response) - 1, 0);
    if (received <= 0) {
        BETANET_LOG_ERROR("HTX: Failed to receive HTTP response");
        return -1;
    }

    response[received] = '\0';
    BETANET_LOG_DEBUG("HTX: Received response: %.100s...", response);

    // check for successful response (simplified - look for 200 OK)
    if (strstr(response, "200 OK") == NULL) {
        BETANET_LOG_ERROR("HTX: HTTP response not 200 OK");
        return -1;
    }
    BETANET_LOG_DEBUG("HTX: Bootstrap completed successfully");

    return 0;
}

/**
 * @brief perform noise xk handshake as initiator
 * @param tcp_fd connected tcp socket
 * @param server_static_key server's static public key
 * @param transport_state output transport state
 * @return 0 on success, -1 on error
 */
static int perform_noise_handshake(int tcp_fd, const uint8_t *server_static_key,
                                   noise_transport_state_t *transport_state) {
    if (tcp_fd < 0 || server_static_key == NULL || transport_state == NULL) {
        return -1;
    }

    // allocate handshake state
    noise_handshake_state_t *handshake = malloc(sizeof(noise_handshake_state_t));
    if (handshake == NULL) {
        return -1;
    }

    // generate ephemeral static key for this connection (in real implementation, would be persistent)
    uint8_t client_static_priv[BETANET_DH_PRIVKEY_SIZE];
    uint8_t client_static_pub[BETANET_DH_PUBKEY_SIZE];
    if (betanet_x25519_keypair(client_static_pub, client_static_priv) != 0) {
        free(handshake);
        return -1;
    }

    // initialize handshake as initiator with static key
    if (noise_handshake_init(handshake, 1, client_static_priv, server_static_key) != 0) {
        free(handshake);
        return -1;
    }

    // message 1: -> e
    uint8_t msg1[128];
    size_t msg1_len = sizeof(msg1);

    if (noise_write_message(handshake, msg1, &msg1_len, NULL, 0) != 0) {
        free(handshake);
        return -1;
    }

    // send message 1
    BETANET_LOG_DEBUG("NOISE CLIENT: Sending message 1 (%zu bytes)", msg1_len);
    if (send(tcp_fd, msg1, msg1_len, 0) != (ssize_t)msg1_len) {
        BETANET_LOG_ERROR("NOISE CLIENT: Failed to send message 1");
        free(handshake);
        return -1;
    }

    // receive message 2: <- e, ee, s, es
    uint8_t msg2[256];
    BETANET_LOG_DEBUG("NOISE CLIENT: Waiting for message 2...");
    ssize_t msg2_received = recv(tcp_fd, msg2, sizeof(msg2), 0);
    if (msg2_received <= 0) {
        BETANET_LOG_ERROR("NOISE CLIENT: Failed to receive message 2");
        free(handshake);
        return -1;
    }
    BETANET_LOG_DEBUG("NOISE CLIENT: Received message 2 (%zd bytes)", msg2_received);

    if (noise_read_message(handshake, msg2, msg2_received, NULL, NULL) != 0) {
        BETANET_LOG_ERROR("NOISE CLIENT: Failed to process message 2");
        free(handshake);
        return -1;
    }
    BETANET_LOG_DEBUG("NOISE CLIENT: Processed message 2 successfully");

    // message 3: -> s, se (with empty payload for now)
    uint8_t msg3[128];
    size_t msg3_len = sizeof(msg3);

    if (noise_write_message(handshake, msg3, &msg3_len, NULL, 0) != 0) {
        BETANET_LOG_ERROR("NOISE CLIENT: Failed to generate message 3");
        free(handshake);
        return -1;
    }

    // send message 3
    BETANET_LOG_DEBUG("NOISE CLIENT: Sending message 3 (%zu bytes)", msg3_len);
    if (send(tcp_fd, msg3, msg3_len, 0) != (ssize_t)msg3_len) {
        BETANET_LOG_ERROR("NOISE CLIENT: Failed to send message 3");
        free(handshake);
        return -1;
    }
    BETANET_LOG_DEBUG("NOISE CLIENT: Sent message 3 successfully");

    // finalize handshake and derive transport keys
    if (noise_handshake_finalize(handshake, transport_state) != 0) {
        free(handshake);
        return -1;
    }

    free(handshake);
    return 0;
}

// internal socket state
typedef struct betanet_socket_struct {
    int tcp_fd;    // underlying tcp socket
    int connected; // 1 if connection is established
    int listening; // 1 if socket is in listening state

    // connection parameters
    char *host; // target host
    int port;   // target port

    // htx state
    uint64_t next_stream_id;   // next stream id to use
    uint64_t flow_window_send; // sending flow control window
    uint64_t flow_window_recv; // receiving flow control window

    // noise states
    noise_handshake_state_t *handshake_state; // handshake crypto state
    noise_transport_state_t *transport_state; // post-handshake crypto state

    // server-specific state
    uint8_t server_static_priv[BETANET_DH_PRIVKEY_SIZE]; // for listening sockets
    uint8_t server_static_pub[BETANET_DH_PUBKEY_SIZE];  // for listening sockets

    // socket options
    betanet_privacy_mode_t privacy_mode; // privacy mode setting
    int connect_timeout_ms;              // connection timeout
} betanet_socket_struct_t;

// internal address structure
typedef struct betanet_addr_struct {
    char *host;                                        // resolved host/ip
    int port;                                          // resolved port
    uint8_t server_static_key[BETANET_DH_PUBKEY_SIZE]; // server's static public key
} betanet_addr_struct_t;

// external function declarations (implemented in other modules)
// (declarations moved to top of file to avoid redundancy)

// global library state
static struct {
    int initialized;
    char *cache_path;
} g_betanet_state = {0, NULL};

int betanet_init(const betanet_init_options_t *options) {
    if (g_betanet_state.initialized) {
        return 0; // already initialized
    }

    // initialize cryptographic library
    if (sodium_init() < 0) {
        return -1;
    }

    // set cache path
    if (options != NULL && options->cache_path != NULL) {
        g_betanet_state.cache_path = strdup(options->cache_path);
        if (g_betanet_state.cache_path == NULL) {
            return -1;
        }
    } else {
        // use default cache path
        g_betanet_state.cache_path = strdup("/tmp/betanet_cache");
        if (g_betanet_state.cache_path == NULL) {
            return -1;
        }
    }

    g_betanet_state.initialized = 1;
    return 0;
}

void betanet_cleanup(void) {
    if (!g_betanet_state.initialized) {
        return; // not initialized
    }

    // free cache path
    free(g_betanet_state.cache_path);
    g_betanet_state.cache_path = NULL;

    g_betanet_state.initialized = 0;
}

betanet_socket_t betanet_socket(void) {
    if (sodium_init() < 0) {
        return NULL;
    }

    betanet_socket_struct_t *sock = malloc(sizeof(betanet_socket_struct_t));
    if (sock == NULL) {
        return NULL;
    }

    // initialize socket state
    memset(sock, 0, sizeof(*sock));
    sock->tcp_fd = -1;
    sock->connected = 0;
    sock->listening = 0;
    sock->host = NULL;
    sock->port = 0;
    sock->next_stream_id = 1;       // client streams start at 1
    sock->flow_window_send = 65535; // initial window size
    sock->flow_window_recv = 65535;
    sock->handshake_state = NULL;
    sock->transport_state = NULL;
    memset(sock->server_static_priv, 0, BETANET_DH_PRIVKEY_SIZE);
    memset(sock->server_static_pub, 0, BETANET_DH_PUBKEY_SIZE);
    sock->privacy_mode = BETANET_PRIVACY_BALANCED; // default
    sock->connect_timeout_ms = 30000;              // 30 second default

    return (betanet_socket_t)sock;
}

int betanet_setsockopt(betanet_socket_t sock, betanet_sockopt_t option, const void *value) {
    if (sock == NULL || value == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;

    switch (option) {
    case BETANET_OPT_PRIVACY_MODE: {
        betanet_privacy_mode_t mode = *(const betanet_privacy_mode_t *)value;
        if (mode < BETANET_PRIVACY_STRICT || mode > BETANET_PRIVACY_PERFORMANCE) {
            return -1;
        }
        s->privacy_mode = mode;
        return 0;
    }

    case BETANET_OPT_CONNECT_TIMEOUT_MS: {
        int timeout = *(const int *)value;
        if (timeout <= 0) {
            return -1;
        }
        s->connect_timeout_ms = timeout;
        return 0;
    }

    default:
        return -1; // unknown option
    }
}

betanet_addr_t betanet_resolve(const char *uri) {
    if (uri == NULL) {
        return NULL;
    }

    // for now, expect format "host:port" (simplified - no betanet:// scheme)
    // in the future this will handle full betanet URIs and naming resolution

    betanet_addr_struct_t *addr = malloc(sizeof(betanet_addr_struct_t));
    if (addr == NULL) {
        return NULL;
    }

    memset(addr, 0, sizeof(*addr));

    // parse host:port
    char *uri_copy = strdup(uri);
    if (uri_copy == NULL) {
        free(addr);
        return NULL;
    }

    char *colon = strchr(uri_copy, ':');
    if (colon == NULL) {
        free(uri_copy);
        free(addr);
        return NULL;
    }

    *colon = '\0';

    // check for empty host
    if (strlen(uri_copy) == 0) {
        free(uri_copy);
        free(addr);
        return NULL;
    }

    addr->host = strdup(uri_copy);

    // use strtol for better error handling than atoi
    char *endptr;
    long port_long = strtol(colon + 1, &endptr, 10);

    free(uri_copy);

    if (addr->host == NULL || *endptr != '\0' || port_long <= 0 || port_long > 65535) {
        free(addr->host);
        free(addr);
        return NULL;
    }

    addr->port = (int)port_long;

    // for development: use a fixed server static key (in real implementation, this would be resolved)
    // this represents the server's long-term x25519 public key
    // this must match the key used by the server in betanet_bind()
    static const uint8_t dev_server_pubkey[BETANET_DH_PUBKEY_SIZE] = {
        0xd0, 0xb7, 0x6a, 0x5f, 0xf2, 0xbf, 0xfc, 0x1f, 
        0xaf, 0xa7, 0x6d, 0xc5, 0x59, 0x0d, 0x1b, 0x93, 
        0xe8, 0x90, 0xc7, 0x57, 0x50, 0x04, 0x1b, 0x09, 
        0xb7, 0x68, 0x36, 0xbd, 0xee, 0xac, 0x32, 0x6c
    };
    memcpy(addr->server_static_key, dev_server_pubkey, BETANET_DH_PUBKEY_SIZE);

    return (betanet_addr_t)addr;
}

void betanet_free_addr(betanet_addr_t addr) {
    if (addr == NULL) {
        return;
    }

    betanet_addr_struct_t *a = (betanet_addr_struct_t *)addr;
    free(a->host);
    free(a);
}

int betanet_connect(betanet_socket_t sock, betanet_addr_t addr) {
    if (sock == NULL || addr == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;
    betanet_addr_struct_t *a = (betanet_addr_struct_t *)addr;

    if (s->connected) {
        return -1; // already connected
    }

    // step 1: establish raw tcp connection
    s->tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->tcp_fd < 0) {
        return -1;
    }

    // resolve hostname to ip address
    struct hostent *host_entry = gethostbyname(a->host);
    if (host_entry == NULL) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        return -1;
    }

    // setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(a->port);
    memcpy(&server_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);

    // connect to server
    if (connect(s->tcp_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        return -1;
    }

    // store connection info
    free(s->host);
    s->host = strdup(a->host);
    s->port = a->port;

    if (s->host == NULL) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        return -1;
    }

    // step 2: perform access-ticket bootstrap
    htx_server_ticket_info_t server_info;
    memcpy(server_info.ticket_pub, a->server_static_key, 32);
    memset(server_info.ticket_key_id, 0x01, 8); // dummy key id
    server_info.min_len = 128;
    server_info.max_len = 256;

    if (perform_htx_bootstrap(s->tcp_fd, s->host, &server_info) != 0) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        free(s->host);
        s->host = NULL;
        return -1;
    }

    // step 3: allocate and perform noise xk handshake
    s->transport_state = malloc(sizeof(noise_transport_state_t));
    if (s->transport_state == NULL) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        free(s->host);
        s->host = NULL;
        return -1;
    }

    if (perform_noise_handshake(s->tcp_fd, a->server_static_key, s->transport_state) != 0) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        free(s->host);
        s->host = NULL;
        free(s->transport_state);
        s->transport_state = NULL;
        return -1;
    }

    s->connected = 1;
    return 0;
}

ssize_t betanet_send(betanet_socket_t sock, const void *buffer, size_t length) {
    if (sock == NULL || buffer == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;

    if (!s->connected || s->tcp_fd < 0) {
        return -1; // not connected
    }

    // construct htx stream frame with encrypted payload
    uint8_t frame_buffer[length + 256]; // extra space for frame header + auth tag
    size_t frame_len = sizeof(frame_buffer);

    BETANET_LOG_DEBUG("BETANET_SEND: Constructing frame for %zu bytes, stream_id=%llu", 
           length, (unsigned long long)s->next_stream_id);

    if (htx_construct_stream_frame(frame_buffer, &frame_len, s->next_stream_id,
                                   (const uint8_t *)buffer, length, s->transport_state) != 0) {
        BETANET_LOG_ERROR("BETANET_SEND: Failed to construct HTX frame");
        return -1;
    }

    BETANET_LOG_DEBUG("BETANET_SEND: Frame constructed successfully, frame_len=%zu", frame_len);
    BETANET_LOG_HEX("BETANET_SEND: Complete frame", frame_buffer, frame_len);

    // send the complete frame over tcp
    BETANET_LOG_DEBUG("BETANET_SEND: Sending %zu bytes to socket fd=%d", frame_len, s->tcp_fd);
    ssize_t sent = send(s->tcp_fd, frame_buffer, frame_len, 0);
    BETANET_LOG_DEBUG("BETANET_SEND: send() returned %zd", sent);
    if (sent < 0) {
        BETANET_LOG_ERROR("BETANET_SEND: send() failed with errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    if (sent != (ssize_t)frame_len) {
        BETANET_LOG_WARN("BETANET_SEND: Warning: partial send - wanted %zu, sent %zd", frame_len, sent);
    }

    // keep same stream_id for request-response cycle
    // only increment when opening a new stream 
    // (this change fixes the protocol deadlock)

    // return original payload length on success
    return (ssize_t)length;
}

ssize_t betanet_recv(betanet_socket_t sock, void *buffer, size_t length, uint64_t *received_stream_id) {
    if (sock == NULL || buffer == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;

    if (!s->connected || s->tcp_fd < 0) {
        BETANET_LOG_DEBUG("BETANET_RECV: Socket not connected (connected=%d, fd=%d)", s->connected, s->tcp_fd);
        return -1; // not connected
    }
    
    BETANET_LOG_DEBUG("BETANET_RECV: Socket state - connected=%d, fd=%d", s->connected, s->tcp_fd);

    // receive htx frame header first (read 5 bytes to handle stream frames)
    uint8_t header_buf[16];                                      // max header size
    BETANET_LOG_DEBUG("BETANET_RECV: About to call recv() for header...");
    ssize_t header_received = recv(s->tcp_fd, header_buf, 5, 0); // read 5 bytes for stream frames
    BETANET_LOG_DEBUG("BETANET_RECV: recv() returned %zd for header", header_received);
    if (header_received < 4) {
        BETANET_LOG_ERROR("BETANET_RECV: Failed to read frame header (got %zd bytes), errno=%d (%s)", 
               header_received, errno, strerror(errno));
        return -1;
    }
    BETANET_LOG_DEBUG("BETANET_RECV: Successfully read %zd header bytes", header_received);
    BETANET_LOG_HEX("BETANET_RECV: Header bytes", header_buf, header_received);

    // parse frame header to get payload length and stream id
    uint32_t payload_len;
    uint8_t frame_type;
    uint64_t stream_id;

    BETANET_LOG_DEBUG("BETANET_RECV: About to parse frame header...");
    int header_len = htx_deserialize_frame_header(header_buf, header_received, &payload_len,
                                                  &frame_type, &stream_id);
    BETANET_LOG_DEBUG("BETANET_RECV: htx_deserialize_frame_header returned %d", header_len);
    if (header_len < 0) {
        BETANET_LOG_ERROR("BETANET_RECV: Frame header parsing failed");
        return -1;
    }
    BETANET_LOG_DEBUG("BETANET_RECV: Parsed frame - payload_len=%u, frame_type=%u, stream_id=%llu, header_len=%d", 
           payload_len, frame_type, (unsigned long long)stream_id, header_len);

    // read additional header bytes if needed
    if (header_len > header_received) {
        ssize_t additional =
            recv(s->tcp_fd, header_buf + header_received, header_len - header_received, 0);
        if (additional < 0) {
            return -1;
        }
        header_received += additional;
    }

    // allocate buffer for complete frame
    uint8_t *frame_buffer = malloc(header_len + payload_len);
    if (frame_buffer == NULL) {
        return -1;
    }

    // copy header and receive payload
    memcpy(frame_buffer, header_buf, header_len);

    if (payload_len > 0) {
        ssize_t payload_received = recv(s->tcp_fd, frame_buffer + header_len, payload_len, 0);
        if (payload_received != (ssize_t)payload_len) {
            free(frame_buffer);
            return -1;
        }
    }

    // parse and decrypt the frame
    uint64_t frame_stream_id;
    size_t decrypted_len = length;

    BETANET_LOG_DEBUG("BETANET_RECV: Parsing frame, total_len=%zu, payload_len=%u", 
           (size_t)(header_len + payload_len), payload_len);

    if (htx_parse_stream_frame(frame_buffer, header_len + payload_len, &frame_stream_id,
                               (uint8_t *)buffer, &decrypted_len, s->transport_state) != 0) {
        BETANET_LOG_ERROR("BETANET_RECV: Failed to parse/decrypt HTX frame");
        free(frame_buffer);
        return -1;
    }

    BETANET_LOG_DEBUG("BETANET_RECV: Frame parsed successfully, decrypted_len=%zu, stream_id=%llu",
           decrypted_len, (unsigned long long)frame_stream_id);

    // return stream_id if caller wants it
    if (received_stream_id != NULL) {
        *received_stream_id = frame_stream_id;
    }

    free(frame_buffer);
    return (ssize_t)decrypted_len;
}

ssize_t betanet_send_response(betanet_socket_t sock, const void *buffer, size_t length, uint64_t response_stream_id) {
    if (sock == NULL || buffer == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;

    if (!s->connected || s->tcp_fd < 0) {
        return -1; // not connected
    }

    // construct htx stream frame with encrypted payload using the specified stream_id
    uint8_t frame_buffer[length + 256]; // extra space for frame header + auth tag
    size_t frame_len = sizeof(frame_buffer);

    BETANET_LOG_DEBUG("BETANET_SEND_RESPONSE: Constructing frame for %zu bytes, response_stream_id=%llu", 
           length, (unsigned long long)response_stream_id);

    if (htx_construct_stream_frame(frame_buffer, &frame_len, response_stream_id,
                                   (const uint8_t *)buffer, length, s->transport_state) != 0) {
        BETANET_LOG_ERROR("BETANET_SEND_RESPONSE: Failed to construct HTX frame");
        return -1;
    }

    BETANET_LOG_DEBUG("BETANET_SEND_RESPONSE: Frame constructed, total_len=%zu", frame_len);

    // send the frame over tcp
    ssize_t sent = send(s->tcp_fd, frame_buffer, frame_len, 0);
    if (sent < 0) {
        BETANET_LOG_ERROR("BETANET_SEND_RESPONSE: send() failed with errno=%d (%s)", errno, strerror(errno));
        return -1;
    }
    if (sent != (ssize_t)frame_len) {
        BETANET_LOG_WARN("BETANET_SEND_RESPONSE: Warning: partial send - wanted %zu, sent %zd", frame_len, sent);
    }

    // return original payload length on success
    return (ssize_t)length;
}

int betanet_close(betanet_socket_t sock) {
    if (sock == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;

    // close tcp connection if open
    if (s->tcp_fd >= 0) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
    }

    // free allocated resources
    free(s->host);
    s->host = NULL;

    // free noise states if allocated
    free(s->handshake_state);
    s->handshake_state = NULL;

    free(s->transport_state);
    s->transport_state = NULL;

    s->connected = 0;

    // free the socket structure itself
    free(s);

    return 0;
}

int betanet_bind(betanet_socket_t sock, betanet_addr_t local_addr) {
    if (sock == NULL || local_addr == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;
    betanet_addr_struct_t *a = (betanet_addr_struct_t *)local_addr;

    if (s->tcp_fd >= 0) {
        return -1; // already has a socket
    }

    // create a tcp socket
    s->tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (s->tcp_fd < 0) {
        return -1;
    }

    // allow reusing the address to avoid "address already in use" errors on restart
    int reuse = 1;
    if (setsockopt(s->tcp_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        return -1;
    }

    // setup server address structure
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(a->port);
    server_addr.sin_addr.s_addr = INADDR_ANY; // bind to all interfaces

    // bind the socket
    if (bind(s->tcp_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        close(s->tcp_fd);
        s->tcp_fd = -1;
        return -1;
    }

    // store the port we are bound to
    s->port = a->port;

    // for development: use a fixed server static keypair (in real implementation, keys would be managed securely)
    // this must match the key expected by clients in betanet_resolve()
    static const uint8_t dev_server_privkey[BETANET_DH_PRIVKEY_SIZE] = {
        0x24, 0x2b, 0x1d, 0x91, 0x2f, 0x0d, 0x4d, 0x14, 
        0x4f, 0xbf, 0x17, 0x6b, 0x27, 0x20, 0x0f, 0xc3, 
        0xcf, 0x18, 0x49, 0xb4, 0x4a, 0xbd, 0x1a, 0xd7, 
        0x43, 0x4b, 0x78, 0x64, 0x72, 0x5e, 0x9e, 0xb6
    };
    static const uint8_t dev_server_pubkey[BETANET_DH_PUBKEY_SIZE] = {
        0xd0, 0xb7, 0x6a, 0x5f, 0xf2, 0xbf, 0xfc, 0x1f, 
        0xaf, 0xa7, 0x6d, 0xc5, 0x59, 0x0d, 0x1b, 0x93, 
        0xe8, 0x90, 0xc7, 0x57, 0x50, 0x04, 0x1b, 0x09, 
        0xb7, 0x68, 0x36, 0xbd, 0xee, 0xac, 0x32, 0x6c
    };
    
    memcpy(s->server_static_priv, dev_server_privkey, BETANET_DH_PRIVKEY_SIZE);
    memcpy(s->server_static_pub, dev_server_pubkey, BETANET_DH_PUBKEY_SIZE);

    // copy public key to the address struct so the caller can inspect it
    memcpy(a->server_static_key, s->server_static_pub, BETANET_DH_PUBKEY_SIZE);

    return 0;
}

int betanet_listen(betanet_socket_t sock, int backlog) {
    if (sock == NULL) {
        return -1;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)sock;

    if (s->tcp_fd < 0) {
        return -1; // socket not bound
    }

    if (listen(s->tcp_fd, backlog) < 0) {
        return -1;
    }

    s->listening = 1;
    return 0;
}

static int perform_noise_handshake_responder(int tcp_fd, const uint8_t *server_static_priv,
                                             noise_transport_state_t *transport_state) {
    if (tcp_fd < 0 || server_static_priv == NULL || transport_state == NULL) {
        return -1;
    }

    noise_handshake_state_t *handshake = malloc(sizeof(noise_handshake_state_t));
    if (handshake == NULL) {
        return -1;
    }

    // In XK pattern, the responder's static key is known, so both sides should mix it
    // The server needs to derive its own public key to mix into the handshake hash
    uint8_t server_static_pub[BETANET_DH_PUBKEY_SIZE];
    if (crypto_scalarmult_base(server_static_pub, server_static_priv) != 0) {
        BETANET_LOG_ERROR("NOISE SERVER: Failed to derive static public key");
        free(handshake);
        return -1;
    }

    if (noise_handshake_init(handshake, 0, server_static_priv, server_static_pub) != 0) {
        BETANET_LOG_ERROR("NOISE SERVER: Failed to initialize handshake");
        free(handshake);
        return -1;
    }
    BETANET_LOG_DEBUG("NOISE SERVER: Handshake initialized successfully");

    // receive message 1: -> e
    uint8_t msg1[128];
    BETANET_LOG_DEBUG("NOISE SERVER: Waiting for message 1...");
    ssize_t msg1_received = recv(tcp_fd, msg1, sizeof(msg1), 0);
    if (msg1_received <= 0) {
        BETANET_LOG_ERROR("NOISE SERVER: Failed to receive message 1");
        free(handshake);
        return -1;
    }
    BETANET_LOG_DEBUG("NOISE SERVER: Received message 1 (%zd bytes)", msg1_received);
    BETANET_LOG_HEX("NOISE SERVER: Message 1 first 16 bytes", msg1, msg1_received < 16 ? msg1_received : 16);

    if (noise_read_message(handshake, msg1, msg1_received, NULL, NULL) != 0) {
        BETANET_LOG_ERROR("NOISE SERVER: Failed to process message 1");
        free(handshake);
        return -1;
    }

    // message 2: <- e, ee, s, es
    uint8_t msg2[256];
    size_t msg2_len = sizeof(msg2);

    if (noise_write_message(handshake, msg2, &msg2_len, NULL, 0) != 0) {
        BETANET_LOG_ERROR("NOISE SERVER: Failed to generate message 2");
        free(handshake);
        return -1;
    }

    BETANET_LOG_DEBUG("NOISE SERVER: Sending message 2 (%zu bytes)", msg2_len);
    if (send(tcp_fd, msg2, msg2_len, 0) != (ssize_t)msg2_len) {
        BETANET_LOG_ERROR("NOISE SERVER: Failed to send message 2");
        free(handshake);
        return -1;
    }

    // receive message 3: -> s, se
    uint8_t msg3[128];
    ssize_t msg3_received = recv(tcp_fd, msg3, sizeof(msg3), 0);
    if (msg3_received <= 0) {
        free(handshake);
        return -1;
    }

    if (noise_read_message(handshake, msg3, msg3_received, NULL, NULL) != 0) {
        free(handshake);
        return -1;
    }

    // finalize and derive transport keys
    if (noise_handshake_finalize(handshake, transport_state) != 0) {
        free(handshake);
        return -1;
    }

    free(handshake);
    return 0;
}

betanet_socket_t betanet_accept(betanet_socket_t sock, betanet_addr_t *client_addr) {
    if (sock == NULL) {
        return NULL;
    }

    betanet_socket_struct_t *listening_sock = (betanet_socket_struct_t *)sock;

    if (!listening_sock->listening) {
        return NULL; // not a listening socket
    }

    // accept a new tcp connection
    struct sockaddr_in client_sockaddr;
    socklen_t client_addr_len = sizeof(client_sockaddr);
    int new_tcp_fd =
        accept(listening_sock->tcp_fd, (struct sockaddr *)&client_sockaddr, &client_addr_len);
    if (new_tcp_fd < 0) {
        return NULL;
    }

    // receive and discard the http request from the client
    char http_request_buffer[2048];
    ssize_t http_received = recv(new_tcp_fd, http_request_buffer, sizeof(http_request_buffer) - 1, 0);
    if (http_received <= 0) {
        close(new_tcp_fd);
        return NULL;
    }
    BETANET_LOG_DEBUG("SERVER: Received HTTP request (%zd bytes)", http_received);
    
    // send http response to let the client proceed
    const char *http_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    if (send(new_tcp_fd, http_response, strlen(http_response), 0) < 0) {
        close(new_tcp_fd);
        return NULL;
    }

    // create a new betanet socket for the client
    betanet_socket_t new_sock = betanet_socket();
    if (new_sock == NULL) {
        close(new_tcp_fd);
        return NULL;
    }

    betanet_socket_struct_t *s = (betanet_socket_struct_t *)new_sock;
    s->tcp_fd = new_tcp_fd;

    // perform noise xk handshake as responder
    s->transport_state = malloc(sizeof(noise_transport_state_t));
    if (s->transport_state == NULL) {
        betanet_close(new_sock);
        return NULL;
    }

    if (perform_noise_handshake_responder(s->tcp_fd, listening_sock->server_static_priv,
                                          s->transport_state) != 0) {
        betanet_close(new_sock);
        return NULL;
    }

    s->connected = 1;
    s->next_stream_id = 2; // server streams start at 2

    // if requested, fill in client address information
    if (client_addr != NULL) {
        *client_addr = malloc(sizeof(betanet_addr_struct_t));
        if (*client_addr != NULL) {
            betanet_addr_struct_t *ca = (betanet_addr_struct_t *)*client_addr;
            memset(ca, 0, sizeof(*ca));
            ca->port = ntohs(client_sockaddr.sin_port);
            ca->host = strdup(inet_ntoa(client_sockaddr.sin_addr));

            // note: client's static key is not known at this layer in xk pattern
            // a more advanced handshake would be needed to exchange identities
        }
    }

    return new_sock;
}
