#include "betanet.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// forward declaration for noise transport functions
extern int noise_transport_encrypt(void *transport, uint8_t *ciphertext, size_t *ciphertext_len,
                                   const uint8_t *plaintext, size_t plaintext_len);
extern int noise_transport_decrypt(void *transport, uint8_t *plaintext, size_t *plaintext_len,
                                   const uint8_t *ciphertext, size_t ciphertext_len);
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#include <machine/endian.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#else
#include <arpa/inet.h>
#include <endian.h>
#endif
#include <sodium.h>

#define HTX_TICKET_PUB_SIZE 32 // x25519 public key
#define HTX_TICKET_KEY_ID_SIZE 8 // ticket key identifier
#define HTX_NONCE32_SIZE 32 // 32-byte nonce
#define HTX_ACCESS_TICKET_SIZE 32 // derived access ticket
#define HTX_MIN_PADDING 24 // minimum padding per spec
#define HTX_MAX_PADDING 64 // maximum padding per spec

typedef enum {
    HTX_CARRIER_COOKIE = 0x01,
    HTX_CARRIER_QUERY = 0x02,
    HTX_CARRIER_BODY = 0x03
} htx_carrier_type_t;

typedef struct {
    uint8_t version; // 0x01
    uint8_t cli_pub[HTX_TICKET_PUB_SIZE]; // client x25519 public key
    uint8_t ticket_key_id[HTX_TICKET_KEY_ID_SIZE]; // server ticket key id
    uint8_t nonce32[HTX_NONCE32_SIZE]; // 32-byte nonce
    uint8_t access_ticket[HTX_ACCESS_TICKET_SIZE]; // derived ticket
    // variable padding follows
} htx_access_ticket_payload_t;

typedef struct {
    uint8_t ticket_pub[HTX_TICKET_PUB_SIZE]; // server's x25519 public key
    uint8_t ticket_key_id[HTX_TICKET_KEY_ID_SIZE]; // key identifier
    htx_carrier_type_t allowed_carriers[3]; // allowed carrier types
    float carrier_probabilities[3]; // probabilities for each carrier
    size_t min_len; // minimum payload length
    size_t max_len; // maximum payload length
} htx_server_ticket_info_t;

/**
 * @brief generate access ticket payload according to spec §5.2
 * @param payload output buffer for the ticket payload
 * @param payload_len input: buffer size, output: actual payload size
 * @param server_info server ticket information
 * @param carrier_type chosen carrier type
 * @return 0 on success, -1 on error
 */
int htx_generate_access_ticket(uint8_t *payload, size_t *payload_len,
                               const htx_server_ticket_info_t *server_info,
                               htx_carrier_type_t carrier_type) {
    if (payload == NULL || payload_len == NULL || server_info == NULL) {
        return -1;
    }

    size_t target_len =
        server_info->min_len + (rand() % (server_info->max_len - server_info->min_len + 1));
    size_t base_size = sizeof(htx_access_ticket_payload_t);

    if (*payload_len < target_len || target_len < base_size) {
        return -1;
    }

    htx_access_ticket_payload_t *ticket = (htx_access_ticket_payload_t *)payload;

    ticket->version = 0x01;

    uint8_t cli_priv[BETANET_DH_PRIVKEY_SIZE];
    if (betanet_x25519_keypair(ticket->cli_pub, cli_priv) != BETANET_CRYPTO_OK) {
        return -1;
    }

    memcpy(ticket->ticket_key_id, server_info->ticket_key_id, HTX_TICKET_KEY_ID_SIZE);

    if (sodium_init() < 0) {
        return -1;
    }
    randombytes_buf(ticket->nonce32, HTX_NONCE32_SIZE);

    uint8_t shared_secret[BETANET_DH_SHARED_SIZE];
    if (betanet_x25519_shared_secret(shared_secret, cli_priv, server_info->ticket_pub) !=
        BETANET_CRYPTO_OK) {
        // clear private key from memory
        sodium_memzero(cli_priv, sizeof(cli_priv));
        return -1;
    }

    // clear private key from memory
    sodium_memzero(cli_priv, sizeof(cli_priv));

    time_t now = time(NULL);
    uint64_t hour = (uint64_t)(now / 3600);
    uint64_t hour_be = htobe64(hour);

    uint8_t salt_input[19 + HTX_TICKET_KEY_ID_SIZE + 8]; // "betanet-ticket-v1" + key_id + hour
    memcpy(salt_input, "betanet-ticket-v1", 17);
    memcpy(salt_input + 17, server_info->ticket_key_id, HTX_TICKET_KEY_ID_SIZE);
    memcpy(salt_input + 17 + HTX_TICKET_KEY_ID_SIZE, &hour_be, 8);

    uint8_t salt[BETANET_HASH_SIZE];
    if (betanet_hash_sha256(salt, salt_input, sizeof(salt_input)) != BETANET_CRYPTO_OK) {
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    if (betanet_kdf_hkdf_sha256(ticket->access_ticket, HTX_ACCESS_TICKET_SIZE, shared_secret,
                                sizeof(shared_secret), salt, sizeof(salt), NULL,
                                0) != BETANET_CRYPTO_OK) {
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    // clear shared secret from memory
    sodium_memzero(shared_secret, sizeof(shared_secret));

    size_t padding_size = target_len - base_size;
    if (padding_size > 0) {
        randombytes_buf(payload + base_size, padding_size);
    }

    *payload_len = target_len;
    return 0;
}

/**
 * @brief encode access ticket payload as base64url
 * @param encoded output buffer for base64url encoded data
 * @param encoded_len input: buffer size, output: actual encoded length
 * @param payload raw ticket payload
 * @param payload_len length of raw payload
 * @return 0 on success, -1 on error
 */
int htx_encode_base64url(char *encoded, size_t *encoded_len, const uint8_t *payload,
                         size_t payload_len) {
    if (encoded == NULL || encoded_len == NULL || payload == NULL) {
        return -1;
    }

    // base64 encoding produces 4 chars for every 3 bytes, plus padding
    size_t required_len = ((payload_len + 2) / 3) * 4 + 1; // +1 for null terminator

    if (*encoded_len < required_len) {
        return -1;
    }

    // use sodium's base64 encoding
    char *result = sodium_bin2base64(encoded, *encoded_len, payload, payload_len,
                                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    if (result == NULL) {
        return -1;
    }

    *encoded_len = strlen(encoded);
    return 0;
}

/**
 * @brief construct http request with access ticket
 * @param request output buffer for http request
 * @param request_len input: buffer size, output: actual request length
 * @param host target host
 * @param path target path
 * @param payload encoded access ticket payload
 * @param carrier_type type of carrier to use
 * @return 0 on success, -1 on error
 */
int htx_construct_http_request(char *request, size_t *request_len, const char *host,
                               const char *path, const char *payload,
                               htx_carrier_type_t carrier_type) {
    if (request == NULL || request_len == NULL || host == NULL || path == NULL || payload == NULL) {
        return -1;
    }

    int written = 0;

    switch (carrier_type) {
    case HTX_CARRIER_COOKIE:
        written =
            snprintf(request, *request_len,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Cookie: __Host-%s=%s\r\n"
                     "User-Agent: Mozilla/5.0 (compatible)\r\n"
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                     "Accept-Language: en-US,en;q=0.5\r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "Connection: keep-alive\r\n"
                     "Upgrade-Insecure-Requests: 1\r\n"
                     "\r\n",
                     path, host, host, payload);
        break;

    case HTX_CARRIER_QUERY:
        written =
            snprintf(request, *request_len,
                     "GET %s%sbn1=%s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: Mozilla/5.0 (compatible)\r\n"
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                     "Accept-Language: en-US,en;q=0.5\r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "Connection: keep-alive\r\n"
                     "Upgrade-Insecure-Requests: 1\r\n"
                     "\r\n",
                     path, (strchr(path, '?') ? "&" : "?"), payload, host);
        break;

    case HTX_CARRIER_BODY: {
        char body[512];
        int body_len = snprintf(body, sizeof(body), "bn1=%s", payload);

        written =
            snprintf(request, *request_len,
                     "POST %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Content-Type: application/x-www-form-urlencoded\r\n"
                     "Content-Length: %d\r\n"
                     "User-Agent: Mozilla/5.0 (compatible)\r\n"
                     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                     "Accept-Language: en-US,en;q=0.5\r\n"
                     "Accept-Encoding: gzip, deflate\r\n"
                     "Connection: keep-alive\r\n"
                     "\r\n"
                     "%s",
                     path, host, body_len, body);
        break;
    }

    default:
        return -1;
    }

    if (written < 0 || (size_t)written >= *request_len) {
        return -1;
    }

    *request_len = written;
    return 0;
}

#define HTX_FRAME_TYPE_STREAM 0
#define HTX_FRAME_TYPE_PING 1
#define HTX_FRAME_TYPE_CLOSE 2
#define HTX_FRAME_TYPE_KEY_UPDATE 3
#define HTX_FRAME_TYPE_WINDOW_UPDATE 4

#define HTX_MAX_FRAME_SIZE (16777215) // 2^24 - 1 (3 bytes)
#define HTX_FLOW_CONTROL_WINDOW 65535 // initial window size

typedef struct {
    uint32_t length; // 24-bit length (network byte order)
    uint8_t type; // frame type
    // varint stream_id follows for STREAM and WINDOW_UPDATE frames
    // uint8_t ciphertext[] follows
} htx_frame_header_t;

typedef struct {
    uint64_t next_stream_id; // next stream id to use
    uint64_t flow_window_send; // sending flow control window
    uint64_t flow_window_recv; // receiving flow control window
    uint8_t transport_keys_valid; // 1 if transport keys are available
    // transport state would be stored here in full implementation
} htx_connection_state_t;

/**
 * @brief encode varint according to quic rfc 9000 §16
 * @param buf output buffer
 * @param buf_len buffer length
 * @param value value to encode
 * @return number of bytes written, or -1 on error
 */
static int htx_encode_varint(uint8_t *buf, size_t buf_len, uint64_t value) {
    if (buf == NULL) {
        return -1;
    }

    if (value < 64) {
        // 1-byte encoding: 00xxxxxx
        if (buf_len < 1) {
            return -1;
        }
        buf[0] = (uint8_t)value;
        return 1;
    } else if (value < 16384) {
        // 2-byte encoding: 01xxxxxx xxxxxxxx
        if (buf_len < 2) {
            return -1;
        }
        buf[0] = 0x40 | ((value >> 8) & 0x3f);
        buf[1] = value & 0xff;
        return 2;
    } else if (value < 1073741824) {
        // 4-byte encoding: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if (buf_len < 4) {
            return -1;
        }
        buf[0] = 0x80 | ((value >> 24) & 0x3f);
        buf[1] = (value >> 16) & 0xff;
        buf[2] = (value >> 8) & 0xff;
        buf[3] = value & 0xff;
        return 4;
    } else {
        // 8-byte encoding: 11xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
        if (buf_len < 8) {
            return -1;
        }
        buf[0] = 0xc0 | ((value >> 56) & 0x3f);
        buf[1] = (value >> 48) & 0xff;
        buf[2] = (value >> 40) & 0xff;
        buf[3] = (value >> 32) & 0xff;
        buf[4] = (value >> 24) & 0xff;
        buf[5] = (value >> 16) & 0xff;
        buf[6] = (value >> 8) & 0xff;
        buf[7] = value & 0xff;
        return 8;
    }
}

/**
 * @brief decode varint according to quic rfc 9000 §16
 * @param buf input buffer
 * @param buf_len buffer length
 * @param value output value
 * @return number of bytes consumed, or -1 on error
 */
static int htx_decode_varint(const uint8_t *buf, size_t buf_len, uint64_t *value) {
    if (buf == NULL || value == NULL || buf_len < 1) {
        return -1;
    }

    uint8_t first_byte = buf[0];
    int len = 1 << ((first_byte & 0xc0) >> 6);

    if (buf_len < (size_t)len) {
        return -1;
    }

    *value = first_byte & 0x3f;

    for (int i = 1; i < len; i++) {
        *value = (*value << 8) | buf[i];
    }

    return len;
}

/**
 * @brief serialize htx frame header
 * @param buf output buffer
 * @param buf_len buffer length
 * @param length frame payload length (24-bit)
 * @param type frame type
 * @param stream_id stream id (for stream and window_update frames, 0 otherwise)
 * @return number of bytes written, or -1 on error
 */
int htx_serialize_frame_header(uint8_t *buf, size_t buf_len, uint32_t length, uint8_t type,
                               uint64_t stream_id) {
    if (buf == NULL || length > HTX_MAX_FRAME_SIZE) {
        return -1;
    }

    // minimum: 3 bytes length + 1 byte type
    if (buf_len < 4) {
        return -1;
    }

    size_t offset = 0;

    // write 24-bit length in network byte order
    buf[offset++] = (length >> 16) & 0xff;
    buf[offset++] = (length >> 8) & 0xff;
    buf[offset++] = length & 0xff;

    // write frame type
    buf[offset++] = type;

    // write stream_id for applicable frame types
    if (type == HTX_FRAME_TYPE_STREAM || type == HTX_FRAME_TYPE_WINDOW_UPDATE) {
        int varint_len = htx_encode_varint(buf + offset, buf_len - offset, stream_id);
        if (varint_len < 0) {
            return -1;
        }
        offset += varint_len;
    }

    return offset;
}

/**
 * @brief deserialize htx frame header
 * @param buf input buffer
 * @param buf_len buffer length
 * @param length output frame payload length
 * @param type output frame type
 * @param stream_id output stream id (set to 0 for non-stream frames)
 * @return number of bytes consumed, or -1 on error
 */
int htx_deserialize_frame_header(const uint8_t *buf, size_t buf_len, uint32_t *length,
                                 uint8_t *type, uint64_t *stream_id) {
    if (buf == NULL || length == NULL || type == NULL || stream_id == NULL) {
        return -1;
    }

    // minimum header size
    if (buf_len < 4) {
        return -1;
    }

    size_t offset = 0;

    // read 24-bit length
    *length = ((uint32_t)buf[offset] << 16) | ((uint32_t)buf[offset + 1] << 8) |
              (uint32_t)buf[offset + 2];
    offset += 3;

    if (*length > HTX_MAX_FRAME_SIZE) {
        return -1;
    }

    // read frame type
    *type = buf[offset++];

    // read stream_id for applicable frame types
    if (*type == HTX_FRAME_TYPE_STREAM || *type == HTX_FRAME_TYPE_WINDOW_UPDATE) {
        int varint_len = htx_decode_varint(buf + offset, buf_len - offset, stream_id);
        if (varint_len < 0) {
            return -1;
        }
        offset += varint_len;
    } else {
        *stream_id = 0;
    }

    return offset;
}

/**
 * @brief construct htx stream frame with encrypted payload
 * @param frame output buffer for complete frame
 * @param frame_len input: buffer size, output: actual frame length
 * @param stream_id stream identifier
 * @param payload plaintext payload
 * @param payload_len length of payload
 * @param transport_state transport encryption state (null for unencrypted)
 * @return 0 on success, -1 on error
 */
int htx_construct_stream_frame(uint8_t *frame, size_t *frame_len, uint64_t stream_id,
                               const uint8_t *payload, size_t payload_len, void *transport_state) {
    if (frame == NULL || frame_len == NULL) {
        return -1;
    }

    // calculate header size
    uint8_t temp_header[16]; // max possible header size
    int header_len = htx_serialize_frame_header(temp_header, sizeof(temp_header), 0,
                                                HTX_FRAME_TYPE_STREAM, stream_id);
    if (header_len < 0) {
        return -1;
    }

    size_t ciphertext_len = payload_len;
    if (transport_state != NULL) {
        ciphertext_len += BETANET_AEAD_TAG_SIZE; // add space for auth tag
    }

    if (*frame_len < header_len + ciphertext_len) {
        return -1;
    }

    // write header with correct payload length
    header_len = htx_serialize_frame_header(frame, *frame_len, (uint32_t)ciphertext_len,
                                            HTX_FRAME_TYPE_STREAM, stream_id);
    if (header_len < 0) {
        return -1;
    }

    // encrypt payload if transport state is available
    if (transport_state != NULL && payload != NULL && payload_len > 0) {
        // encrypt using noise transport keys
        size_t max_ciphertext_len = *frame_len - header_len;
        ciphertext_len = max_ciphertext_len;

        if (noise_transport_encrypt(transport_state, frame + header_len, &ciphertext_len, payload,
                                    payload_len) != 0) {
            return -1;
        }

        // update header with actual ciphertext length
        header_len = htx_serialize_frame_header(frame, *frame_len, (uint32_t)ciphertext_len,
                                                HTX_FRAME_TYPE_STREAM, stream_id);
        if (header_len < 0) {
            return -1;
        }
    } else {
        // no encryption, just copy payload
        ciphertext_len = payload_len;
        if (payload != NULL && payload_len > 0) {
            memcpy(frame + header_len, payload, payload_len);
        }
    }

    *frame_len = header_len + ciphertext_len;
    return 0;
}

/**
 * @brief parse htx stream frame and decrypt payload
 * @param frame input frame buffer
 * @param frame_len length of frame
 * @param stream_id output stream identifier
 * @param payload output buffer for decrypted payload
 * @param payload_len input: buffer size, output: actual payload length
 * @param transport_state transport decryption state (null for unencrypted)
 * @return 0 on success, -1 on error
 */
int htx_parse_stream_frame(const uint8_t *frame, size_t frame_len, uint64_t *stream_id,
                           uint8_t *payload, size_t *payload_len, void *transport_state) {
    if (frame == NULL || stream_id == NULL || payload_len == NULL) {
        return -1;
    }

    uint32_t ciphertext_len;
    uint8_t type;

    int header_len =
        htx_deserialize_frame_header(frame, frame_len, &ciphertext_len, &type, stream_id);
    if (header_len < 0 || type != HTX_FRAME_TYPE_STREAM) {
        return -1;
    }

    if (frame_len < header_len + ciphertext_len) {
        return -1;
    }

    // decrypt payload if transport state is available
    if (transport_state != NULL && ciphertext_len > 0) {
        // decrypt using noise transport keys
        if (noise_transport_decrypt(transport_state, payload, payload_len, frame + header_len,
                                    ciphertext_len) != 0) {
            return -1;
        }
    } else {
        // no decryption, just copy ciphertext
        if (*payload_len < ciphertext_len) {
            return -1;
        }

        if (payload != NULL && ciphertext_len > 0) {
            memcpy(payload, frame + header_len, ciphertext_len);
        }
        *payload_len = ciphertext_len;
    }

    return 0;
}

/**
 * @brief construct htx ping frame
 * @param frame output buffer
 * @param frame_len input: buffer size, output: actual frame length
 * @return 0 on success, -1 on error
 */
int htx_construct_ping_frame(uint8_t *frame, size_t *frame_len) {
    if (frame == NULL || frame_len == NULL) {
        return -1;
    }

    int header_len = htx_serialize_frame_header(frame, *frame_len, 0, HTX_FRAME_TYPE_PING, 0);
    if (header_len < 0) {
        return -1;
    }

    *frame_len = header_len;
    return 0;
}

/**
 * @brief construct htx window update frame
 * @param frame output buffer
 * @param frame_len input: buffer size, output: actual frame length
 * @param stream_id stream identifier
 * @param window_increment window size increment
 * @return 0 on success, -1 on error
 */
int htx_construct_window_update_frame(uint8_t *frame, size_t *frame_len, uint64_t stream_id,
                                      uint32_t window_increment) {
    if (frame == NULL || frame_len == NULL) {
        return -1;
    }

    // window update payload is 4 bytes (window increment)
    int header_len =
        htx_serialize_frame_header(frame, *frame_len, 4, HTX_FRAME_TYPE_WINDOW_UPDATE, stream_id);
    if (header_len < 0) {
        return -1;
    }

    if (*frame_len < header_len + 4) {
        return -1;
    }

    // write window increment in network byte order
    frame[header_len] = (window_increment >> 24) & 0xff;
    frame[header_len + 1] = (window_increment >> 16) & 0xff;
    frame[header_len + 2] = (window_increment >> 8) & 0xff;
    frame[header_len + 3] = window_increment & 0xff;

    *frame_len = header_len + 4;
    return 0;
}
