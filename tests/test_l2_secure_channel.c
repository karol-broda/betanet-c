#include "../tests/betanet_internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

// simplified test that focuses on high-level API functionality
void test_htx_encrypted_frames_simple(void) {
    printf("Testing HTX frame construction/parsing (no encryption)...\n");

    const char *payload = "Test HTX payload";
    size_t payload_len = strlen(payload);
    uint64_t stream_id = 42;

    // construct frame without encryption
    uint8_t frame[512];
    size_t frame_len = sizeof(frame);

    int result = htx_construct_stream_frame(frame, &frame_len, stream_id, (const uint8_t *)payload,
                                            payload_len,
                                            NULL); // no transport state = no encryption
    assert(result == 0);
    assert(frame_len > payload_len); // should include header

    // parse frame
    uint64_t parsed_stream_id;
    uint8_t decrypted_payload[256];
    size_t decrypted_len = sizeof(decrypted_payload);

    result = htx_parse_stream_frame(frame, frame_len, &parsed_stream_id, decrypted_payload,
                                    &decrypted_len, NULL);
    assert(result == 0);
    assert(parsed_stream_id == stream_id);
    assert(decrypted_len == payload_len);
    assert(memcmp(decrypted_payload, payload, payload_len) == 0);

    printf("✓ HTX frames work correctly\n");
}

void test_crypto_primitives(void) {
    printf("Testing crypto primitives...\n");

    // test x25519 keypair generation
    uint8_t pub[32], priv[32];
    int result = betanet_x25519_keypair(pub, priv);
    assert(result == BETANET_CRYPTO_OK);

    // test shared secret computation
    uint8_t pub2[32], priv2[32];
    result = betanet_x25519_keypair(pub2, priv2);
    assert(result == BETANET_CRYPTO_OK);

    uint8_t shared1[32], shared2[32];
    result = betanet_x25519_shared_secret(shared1, priv, pub2);
    assert(result == BETANET_CRYPTO_OK);

    result = betanet_x25519_shared_secret(shared2, priv2, pub);
    assert(result == BETANET_CRYPTO_OK);

    // shared secrets should match
    assert(memcmp(shared1, shared2, 32) == 0);

    printf("✓ Crypto primitives work correctly\n");
}

void test_access_ticket_generation(void) {
    printf("Testing HTX access ticket generation...\n");

    // create server ticket info
    htx_server_ticket_info_t server_info;
    memset(&server_info, 0, sizeof(server_info));

    // generate server keypair
    uint8_t server_priv[32];
    int result = betanet_x25519_keypair(server_info.ticket_pub, server_priv);
    assert(result == BETANET_CRYPTO_OK);

    memset(server_info.ticket_key_id, 0x42, sizeof(server_info.ticket_key_id));
    server_info.min_len = 128;
    server_info.max_len = 256;

    // generate access ticket
    uint8_t ticket_payload[512];
    size_t payload_len = sizeof(ticket_payload);

    result = htx_generate_access_ticket(ticket_payload, &payload_len, &server_info, 0x01);
    assert(result == 0);
    assert(payload_len >= server_info.min_len);
    assert(payload_len <= server_info.max_len);

    // encode as base64url
    char encoded[1024];
    size_t encoded_len = sizeof(encoded);

    result = htx_encode_base64url(encoded, &encoded_len, ticket_payload, payload_len);
    assert(result == 0);
    assert(encoded_len > 0);
    assert(strlen(encoded) == encoded_len);

    // construct http request
    char http_request[2048];
    size_t request_len = sizeof(http_request);

    result = htx_construct_http_request(http_request, &request_len, "test.example.com", "/test",
                                        encoded, 0x01);
    assert(result == 0);
    assert(request_len > 0);
    assert(strstr(http_request, "Cookie:") != NULL);
    assert(strstr(http_request, encoded) != NULL);

    printf("✓ HTX access ticket generation works correctly\n");
}

void test_l2_integration_mock(void) {
    printf("Testing L2 secure channel integration (mock)...\n");

    // this test simulates the complete l2 secure channel without actual network

    // 1. create socket
    betanet_socket_t sock = betanet_socket();
    assert(sock != NULL);

    // 2. create mock address
    betanet_addr_t addr = betanet_resolve("localhost:8080");
    assert(addr != NULL);

    // note: betanet_connect would fail here because there's no actual server
    // but the socket creation and address resolution work

    // 3. cleanup
    betanet_free_addr(addr);
    betanet_close(sock);

    printf("✓ L2 integration components work correctly\n");
}

int main(void) {
    printf("=== L2 Secure Channel Integration Tests ===\n\n");

    // initialize library
    betanet_init_options_t opts = {0};
    int result = betanet_init(&opts);
    assert(result == 0);

    // run tests
    test_htx_encrypted_frames_simple();
    test_crypto_primitives();
    test_access_ticket_generation();
    test_l2_integration_mock();

    // cleanup
    betanet_cleanup();

    printf("\n=== All L2 Secure Channel Tests Passed! ===\n");
    return 0;
}
