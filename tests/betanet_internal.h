#ifndef BETANET_INTERNAL_H
#define BETANET_INTERNAL_H

#include "betanet.h"

// internal structures for testing
typedef struct betanet_addr_struct {
    char *host;                                        // resolved host/ip
    int port;                                          // resolved port
    uint8_t server_static_key[BETANET_DH_PUBKEY_SIZE]; // server's static public key
} betanet_addr_struct_t;
typedef enum {
    HTX_CARRIER_COOKIE = 0x01,
    HTX_CARRIER_QUERY = 0x02,
    HTX_CARRIER_BODY = 0x03
} htx_carrier_type_t;

typedef struct {
    uint8_t ticket_pub[32];
    uint8_t ticket_key_id[8];
    htx_carrier_type_t allowed_carriers[3];
    float carrier_probabilities[3];
    size_t min_len;
    size_t max_len;
} htx_server_ticket_info_t;

// frame type constants
#define HTX_FRAME_TYPE_STREAM 0
#define HTX_FRAME_TYPE_PING 1
#define HTX_FRAME_TYPE_CLOSE 2
#define HTX_FRAME_TYPE_KEY_UPDATE 3
#define HTX_FRAME_TYPE_WINDOW_UPDATE 4

// internal htx functions for testing
extern int htx_generate_access_ticket(uint8_t *payload, size_t *payload_len,
                                      const htx_server_ticket_info_t *server_info,
                                      htx_carrier_type_t carrier_type);
extern int htx_encode_base64url(char *encoded, size_t *encoded_len, const uint8_t *payload,
                                size_t payload_len);
extern int htx_construct_http_request(char *request, size_t *request_len, const char *host,
                                      const char *path, const char *payload,
                                      htx_carrier_type_t carrier_type);
extern int htx_serialize_frame_header(uint8_t *buf, size_t buf_len, uint32_t length, uint8_t type,
                                      uint64_t stream_id);
extern int htx_deserialize_frame_header(const uint8_t *buf, size_t buf_len, uint32_t *length,
                                        uint8_t *type, uint64_t *stream_id);
extern int htx_construct_stream_frame(uint8_t *frame, size_t *frame_len, uint64_t stream_id,
                                      const uint8_t *payload, size_t payload_len,
                                      void *transport_state);
extern int htx_parse_stream_frame(const uint8_t *frame, size_t frame_len, uint64_t *stream_id,
                                  uint8_t *payload, size_t *payload_len, void *transport_state);
extern int htx_construct_ping_frame(uint8_t *frame, size_t *frame_len);
extern int htx_construct_window_update_frame(uint8_t *frame, size_t *frame_len, uint64_t stream_id,
                                             uint32_t window_increment);

// internal noise functions for testing
extern int noise_handshake_init(void *state, int initiator, const uint8_t *local_static_key,
                                const uint8_t *remote_static_key);
extern int noise_write_message(void *state, uint8_t *message, size_t *message_len,
                               const uint8_t *payload, size_t payload_len);
extern int noise_read_message(void *state, const uint8_t *message, size_t message_len,
                              uint8_t *payload, size_t *payload_len);
extern int noise_handshake_finalize(void *state, void *transport);

#endif // BETANET_INTERNAL_H
