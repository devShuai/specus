#define _POSIX_C_SOURCE 200809L

#include "crypto.h"
#include "stun_turn.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define COOKIE 0x2112a442U

typedef struct {
    unsigned char bytes[2048];
    size_t len;
} packet_builder;

static void u16(unsigned char *out, unsigned value)
{
    out[0] = (unsigned char)(value >> 8U);
    out[1] = (unsigned char)value;
}

static void u32(unsigned char *out, unsigned value)
{
    out[0] = (unsigned char)(value >> 24U);
    out[1] = (unsigned char)(value >> 16U);
    out[2] = (unsigned char)(value >> 8U);
    out[3] = (unsigned char)value;
}

static unsigned r16(const unsigned char *in)
{
    return ((unsigned)in[0] << 8U) | in[1];
}

static unsigned r32(const unsigned char *in)
{
    return ((unsigned)in[0] << 24U) | ((unsigned)in[1] << 16U)
        | ((unsigned)in[2] << 8U) | in[3];
}

static void start(packet_builder *builder, unsigned type, unsigned seed)
{
    memset(builder, 0, sizeof(*builder));
    builder->len = 20U;
    u16(builder->bytes, type);
    u32(builder->bytes + 4U, COOKIE);
    for (size_t i = 0; i < 12U; ++i) builder->bytes[8U + i] = (unsigned char)(seed + i);
}

static void attr(packet_builder *builder, unsigned type, const void *value, size_t len)
{
    size_t padded = (len + 3U) & ~3U;
    u16(builder->bytes + builder->len, type);
    u16(builder->bytes + builder->len + 2U, (unsigned)len);
    memcpy(builder->bytes + builder->len + 4U, value, len);
    memset(builder->bytes + builder->len + 4U + len, 0, padded - len);
    builder->len += 4U + padded;
    u16(builder->bytes + 2U, (unsigned)(builder->len - 20U));
}

static void integrity(packet_builder *builder, const unsigned char key[16])
{
    unsigned char mac[20];
    u16(builder->bytes + 2U, (unsigned)(builder->len + 24U - 20U));
    st_hmac_sha1(key, 16U, builder->bytes, builder->len, mac);
    attr(builder, 0x0008U, mac, sizeof(mac));
}

static const unsigned char *find_attr(const unsigned char *packet,
                                      size_t len,
                                      unsigned type,
                                      size_t *attr_len)
{
    size_t end = 20U + r16(packet + 2U);
    if (end > len) return NULL;
    for (size_t offset = 20U; offset + 4U <= end;) {
        size_t value_len = r16(packet + offset + 2U);
        if (offset + 4U + value_len > end) return NULL;
        if (r16(packet + offset) == type) {
            *attr_len = value_len;
            return packet + offset + 4U;
        }
        offset += 4U + ((value_len + 3U) & ~3U);
    }
    return NULL;
}

static int udp_socket(struct sockaddr_in *bound)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(bound, 0, sizeof(*bound));
    bound->sin_family = AF_INET;
    bound->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)bound, sizeof(*bound)) != 0) return -1;
    socklen_t len = sizeof(*bound);
    if (getsockname(fd, (struct sockaddr *)bound, &len) != 0) return -1;
    struct timeval timeout = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    return fd;
}

static int exchange(int fd,
                    const struct sockaddr_in *server,
                    const packet_builder *request,
                    unsigned char *response,
                    size_t response_size)
{
    if (sendto(fd, request->bytes, request->len, 0,
               (const struct sockaddr *)server, sizeof(*server)) != (ssize_t)request->len) return -1;
    return (int)recvfrom(fd, response, response_size, 0, NULL, NULL);
}

static int exchange_from(int fd,
                         const struct sockaddr_in *server,
                         const packet_builder *request,
                         unsigned char *response,
                         size_t response_size,
                         struct sockaddr_in *source)
{
    if (sendto(fd, request->bytes, request->len, 0,
               (const struct sockaddr *)server, sizeof(*server)) != (ssize_t)request->len) return -1;
    socklen_t source_len = sizeof(*source);
    return (int)recvfrom(fd, response, response_size, 0,
                         (struct sockaddr *)source, &source_len);
}

static void add_auth(packet_builder *request,
                     const char *username,
                     const unsigned char key[16])
{
    unsigned char transport[4] = {17, 0, 0, 0};
    attr(request, 0x0019U, transport, sizeof(transport));
    attr(request, 0x0006U, username, strlen(username));
    attr(request, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(request, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
    integrity(request, key);
}

static void add_xor_peer(packet_builder *request, const struct sockaddr_in *peer)
{
    unsigned char encoded[8] = {0, 1, 0, 0, 0, 0, 0, 0};
    u16(encoded + 2U, ntohs(peer->sin_port) ^ (COOKIE >> 16U));
    u32(encoded + 4U, ntohl(peer->sin_addr.s_addr) ^ COOKIE);
    attr(request, 0x0012U, encoded, sizeof(encoded));
}

int main(void)
{
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", "0", 1);
    setenv("SPECUS_PEER_MESH_BIND_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_RELAY_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS", "true", 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", "55000", 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT", "55100", 1);
    setenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET", "peer-test-secret", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "2", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", "2", 1);
    st_stun_turn_server *server = NULL;
    if (st_stun_turn_server_start(&server) != 0 || st_stun_turn_server_port(server) <= 0) {
        fprintf(stderr, "STUN/TURN start failed\n");
        return 1;
    }
    struct sockaddr_in server_address = {0};
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    server_address.sin_port = htons((unsigned short)st_stun_turn_server_port(server));
    struct sockaddr_in client_address;
    int client = udp_socket(&client_address);
    unsigned char response[2048];
    packet_builder request;

    start(&request, 0x0001U, 1U);
    int received = exchange(client, &server_address, &request, response, sizeof(response));
    size_t value_len = 0;
    const unsigned char *mapped = received > 0 ? find_attr(response, (size_t)received, 0x0020U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0101U || mapped == NULL || value_len != 8U
        || (r16(mapped + 2U) ^ (COOKIE >> 16U)) != ntohs(client_address.sin_port)) {
        fprintf(stderr, "STUN binding response mismatch\n");
        return 1;
    }
    start(&request, 0x0001U, 2U);
    unsigned char basic_change[4];
    u32(basic_change, 2U);
    attr(&request, 0x0003U, basic_change, sizeof(basic_change));
    received = exchange(client, &server_address, &request, response, sizeof(response));
    const unsigned char *unknown = received > 0
        ? find_attr(response, (size_t)received, 0x000aU, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0111U || unknown == NULL || value_len != 2U
        || r16(unknown) != 0x0003U) {
        fprintf(stderr, "basic STUN change-request rejection mismatch\n");
        return 1;
    }

    start(&request, 0x0003U, 20U);
    unsigned char transport[4] = {17, 0, 0, 0};
    attr(&request, 0x0019U, transport, sizeof(transport));
    received = exchange(client, &server_address, &request, response, sizeof(response));
    if (received < 20 || r16(response) != 0x0113U
        || find_attr(response, (size_t)received, 0x0014U, &value_len) == NULL
        || find_attr(response, (size_t)received, 0x0015U, &value_len) == NULL) {
        fprintf(stderr, "TURN authentication challenge mismatch\n");
        return 1;
    }

    char username[192];
    char credential[64];
    unsigned char long_term_key[16];
    if (st_turn_auth_issue("public-transfer-test", username, sizeof(username), credential, sizeof(credential)) != 0
        || credential[0] == '\0' || st_turn_auth_long_term_key(username, long_term_key) != 0) {
        fprintf(stderr, "TURN credential generation mismatch\n");
        return 1;
    }
    start(&request, 0x0003U, 40U);
    add_auth(&request, username, long_term_key);
    received = exchange(client, &server_address, &request, response, sizeof(response));
    const unsigned char *relayed = received > 0
        ? find_attr(response, (size_t)received, 0x0016U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0103U || relayed == NULL || value_len != 8U) {
        fprintf(stderr, "TURN allocation response mismatch\n");
        return 1;
    }
    struct sockaddr_in relay = {0};
    relay.sin_family = AF_INET;
    relay.sin_port = htons((unsigned short)(r16(relayed + 2U) ^ (COOKIE >> 16U)));
    relay.sin_addr.s_addr = htonl(r32(relayed + 4U) ^ COOKIE);

    struct sockaddr_in client2_address;
    int client2 = udp_socket(&client2_address);
    start(&request, 0x0003U, 50U);
    add_auth(&request, username, long_term_key);
    received = exchange(client2, &server_address, &request, response, sizeof(response));
    relayed = received > 0 ? find_attr(response, (size_t)received, 0x0016U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0103U || relayed == NULL || value_len != 8U) {
        fprintf(stderr, "second TURN allocation response mismatch\n");
        return 1;
    }
    struct sockaddr_in relay2 = {0};
    relay2.sin_family = AF_INET;
    relay2.sin_port = htons((unsigned short)(r16(relayed + 2U) ^ (COOKIE >> 16U)));
    relay2.sin_addr.s_addr = htonl(r32(relayed + 4U) ^ COOKIE);

    start(&request, 0x0008U, 51U);
    add_xor_peer(&request, &relay2);
    attr(&request, 0x0006U, username, strlen(username));
    attr(&request, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(&request, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
    integrity(&request, long_term_key);
    received = exchange(client, &server_address, &request, response, sizeof(response));
    if (received < 20 || r16(response) != 0x0108U) {
        fprintf(stderr, "first cross-allocation permission mismatch\n");
        return 1;
    }
    start(&request, 0x0008U, 52U);
    add_xor_peer(&request, &relay);
    attr(&request, 0x0006U, username, strlen(username));
    attr(&request, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(&request, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
    integrity(&request, long_term_key);
    received = exchange(client2, &server_address, &request, response, sizeof(response));
    if (received < 20 || r16(response) != 0x0108U) {
        fprintf(stderr, "second cross-allocation permission mismatch\n");
        return 1;
    }
    start(&request, 0x0016U, 53U);
    add_xor_peer(&request, &relay2);
    attr(&request, 0x0013U, "cross", 5U);
    if (sendto(client, request.bytes, request.len, 0,
               (struct sockaddr *)&server_address, sizeof(server_address)) != (ssize_t)request.len) return 1;
    received = (int)recvfrom(client2, response, sizeof(response), 0, NULL, NULL);
    const unsigned char *cross_data = received > 0
        ? find_attr(response, (size_t)received, 0x0013U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0017U || cross_data == NULL || value_len != 5U
        || memcmp(cross_data, "cross", 5U) != 0) {
        fprintf(stderr, "cross-allocation TURN relay mismatch\n");
        return 1;
    }

    struct sockaddr_in client3_address;
    int client3 = udp_socket(&client3_address);
    start(&request, 0x0003U, 54U);
    add_auth(&request, username, long_term_key);
    received = exchange(client3, &server_address, &request, response, sizeof(response));
    const unsigned char *quota_error = received > 0
        ? find_attr(response, (size_t)received, 0x0009U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0113U || quota_error == NULL || value_len < 4U
        || quota_error[2] != 4U || quota_error[3] != 86U) {
        fprintf(stderr, "TURN general relay allocation quota mismatch\n");
        return 1;
    }
    close(client3);

    struct sockaddr_in peer_address;
    int peer = udp_socket(&peer_address);
    start(&request, 0x0008U, 60U);
    add_xor_peer(&request, &peer_address);
    attr(&request, 0x0006U, username, strlen(username));
    attr(&request, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(&request, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
    integrity(&request, long_term_key);
    received = exchange(client, &server_address, &request, response, sizeof(response));
    if (received < 20 || r16(response) != 0x0108U) {
        fprintf(stderr, "TURN CreatePermission mismatch\n");
        return 1;
    }

    start(&request, 0x0016U, 80U);
    add_xor_peer(&request, &peer_address);
    attr(&request, 0x0013U, "hello", 5U);
    if (sendto(client, request.bytes, request.len, 0,
               (struct sockaddr *)&server_address, sizeof(server_address)) != (ssize_t)request.len) return 1;
    unsigned char peer_data[32];
    if (recvfrom(peer, peer_data, sizeof(peer_data), 0, NULL, NULL) != 5
        || memcmp(peer_data, "hello", 5U) != 0) {
        fprintf(stderr, "TURN Send indication relay mismatch\n");
        return 1;
    }
    if (sendto(peer, "world", 5U, 0, (struct sockaddr *)&relay, sizeof(relay)) != 5) return 1;
    received = (int)recvfrom(client, response, sizeof(response), 0, NULL, NULL);
    const unsigned char *data = received > 0
        ? find_attr(response, (size_t)received, 0x0013U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0017U || data == NULL || value_len != 5U
        || memcmp(data, "world", 5U) != 0) {
        fprintf(stderr, "TURN Data indication mismatch\n");
        return 1;
    }

    close(peer);
    close(client2);
    close(client);
    st_stun_turn_server_stop(server);

    struct sockaddr_in reserved_primary;
    struct sockaddr_in reserved_alternate;
    int reserve_primary = udp_socket(&reserved_primary);
    int reserve_alternate = udp_socket(&reserved_alternate);
    if (reserve_primary < 0 || reserve_alternate < 0) return 1;
    int primary_port = ntohs(reserved_primary.sin_port);
    int alternate_port = ntohs(reserved_alternate.sin_port);
    close(reserve_primary);
    close(reserve_alternate);
    if (primary_port == alternate_port) return 1;
    char primary_port_text[16];
    char alternate_port_text[16];
    snprintf(primary_port_text, sizeof(primary_port_text), "%d", primary_port);
    snprintf(alternate_port_text, sizeof(alternate_port_text), "%d", alternate_port);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", primary_port_text, 1);
    setenv("SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT", alternate_port_text, 1);
    setenv("SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS", "127.0.0.2", 1);
    setenv("SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS", "127.0.0.2", 1);
    setenv("SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT", "true", 1);
    server = NULL;
    if (st_stun_turn_server_start(&server) != 0
        || st_stun_turn_server_port(server) != primary_port) {
        fprintf(stderr, "RFC5780 STUN topology start failed\n");
        return 1;
    }
    server_address.sin_port = htons((unsigned short)primary_port);
    client = udp_socket(&client_address);
    start(&request, 0x0001U, 100U);
    unsigned char change_both[4];
    u32(change_both, 6U);
    attr(&request, 0x0003U, change_both, sizeof(change_both));
    struct sockaddr_in response_source = {0};
    received = exchange_from(client, &server_address, &request, response, sizeof(response), &response_source);
    const unsigned char *origin = received > 0
        ? find_attr(response, (size_t)received, 0x802bU, &value_len) : NULL;
    const unsigned char *other = received > 0
        ? find_attr(response, (size_t)received, 0x802cU, &value_len) : NULL;
    struct in_addr expected_alternate;
    inet_pton(AF_INET, "127.0.0.2", &expected_alternate);
    if (received < 20 || r16(response) != 0x0101U
        || ntohs(response_source.sin_port) != alternate_port
        || response_source.sin_addr.s_addr != expected_alternate.s_addr
        || origin == NULL || r16(origin + 2U) != (unsigned)alternate_port
        || r32(origin + 4U) != ntohl(expected_alternate.s_addr)
        || other == NULL || r16(other + 2U) != (unsigned)alternate_port
        || r32(other + 4U) != ntohl(expected_alternate.s_addr)) {
        fprintf(stderr, "RFC5780 change-address/change-port response mismatch\n");
        return 1;
    }

    start(&request, 0x0001U, 120U);
    unsigned char request_padding[100] = {0};
    attr(&request, 0x0026U, request_padding, sizeof(request_padding));
    received = exchange(client, &server_address, &request, response, sizeof(response));
    const unsigned char *response_padding = received > 0
        ? find_attr(response, (size_t)received, 0x0026U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0101U
        || response_padding == NULL || value_len != sizeof(request_padding)) {
        fprintf(stderr, "RFC5780 padding response mismatch\n");
        return 1;
    }
    close(client);
    st_stun_turn_server_stop(server);
    printf("STUN/TURN tests passed\n");
    return 0;
}
