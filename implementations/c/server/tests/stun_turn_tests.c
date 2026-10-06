#define _POSIX_C_SOURCE 200809L

#include "crypto.h"
#include "storage.h"
#include "stun_turn.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
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

/* Allocates a relay for one Peer Mesh client, authenticated as the control channel would issue it
 * (subject pm-<clientId>), and returns the relayed address. */
static int allocate_peer_relay(int fd,
                               const struct sockaddr_in *server,
                               long long client_id,
                               unsigned seed,
                               char username[192],
                               unsigned char key[16],
                               struct sockaddr_in *relay)
{
    char subject[64];
    char credential[64];
    snprintf(subject, sizeof(subject), "pm-%lld", client_id);
    if (st_turn_auth_issue(subject, username, 192U, credential, sizeof(credential)) != 0
        || st_turn_auth_long_term_key(username, key) != 0) return -1;
    packet_builder request;
    unsigned char response[2048];
    size_t value_len = 0;
    start(&request, 0x0003U, seed);
    add_auth(&request, username, key);
    int received = exchange(fd, server, &request, response, sizeof(response));
    const unsigned char *relayed = received > 0
        ? find_attr(response, (size_t)received, 0x0016U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0103U || relayed == NULL || value_len != 8U) return -1;
    memset(relay, 0, sizeof(*relay));
    relay->sin_family = AF_INET;
    relay->sin_port = htons((unsigned short)(r16(relayed + 2U) ^ (COOKIE >> 16U)));
    relay->sin_addr.s_addr = htonl(r32(relayed + 4U) ^ COOKIE);
    return 0;
}

static int permit_peer(int fd,
                       const struct sockaddr_in *server,
                       const char *username,
                       const unsigned char key[16],
                       const struct sockaddr_in *peer,
                       unsigned seed)
{
    packet_builder request;
    unsigned char response[2048];
    start(&request, 0x0008U, seed);
    add_xor_peer(&request, peer);
    attr(&request, 0x0006U, username, strlen(username));
    attr(&request, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(&request, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
    integrity(&request, key);
    int received = exchange(fd, server, &request, response, sizeof(response));
    return received >= 20 && r16(response) == 0x0108U ? 0 : -1;
}

/* Sends payload from one allocation to another's relayed address with a Send indication and reports
 * whether it arrived, intact, as a Data indication at the other client. */
static int relayed(int from_fd,
                   const struct sockaddr_in *server,
                   const struct sockaddr_in *to_relay,
                   int to_fd,
                   const char *payload,
                   unsigned seed)
{
    packet_builder request;
    unsigned char response[2048];
    size_t value_len = 0;
    start(&request, 0x0016U, seed);
    add_xor_peer(&request, to_relay);
    attr(&request, 0x0013U, payload, strlen(payload));
    if (sendto(from_fd, request.bytes, request.len, 0,
               (const struct sockaddr *)server, sizeof(*server)) != (ssize_t)request.len) return 0;
    int received = (int)recvfrom(to_fd, response, sizeof(response), 0, NULL, NULL);
    const unsigned char *data = received > 0
        ? find_attr(response, (size_t)received, 0x0013U, &value_len) : NULL;
    return received >= 20 && r16(response) == 0x0017U && data != NULL
        && value_len == strlen(payload) && memcmp(data, payload, value_len) == 0;
}

/* Peer Mesh relaying is authorized per datagram against the session the control channel granted:
 * a connectivity check crosses only with that session's token. The session lives in the server's
 * database, SPECUS_DATABASE_PATH, so this is also what proves the relay reads the same database as
 * the rest of the server. */
static int peer_mesh_relay_tests(const struct sockaddr_in *server)
{
    char path[] = "/tmp/specus_c_stun_turn_peer_mesh.XXXXXX";
    int temp_fd = mkstemp(path);
    if (temp_fd < 0) return 1;
    close(temp_fd);
    st_storage_client source;
    st_storage_client target;
    st_storage_peer_mesh_device source_device;
    st_storage_peer_mesh_device target_device;
    st_storage_peer_mesh_session session;
    const char *token = "stun-turn-test-session-token";
    uint8_t token_digest[ST_SHA256_LEN];
    char token_hash[ST_SHA256_HEX_LEN + 1U];
    st_sha256((const uint8_t *)token, strlen(token), token_digest);
    st_hex_encode(token_digest, sizeof(token_digest), token_hash);
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "tenant-relay", "relay-source", "owner", 1, 60, &source) != 0
        || st_storage_upsert_client(path, 0, "tenant-relay", "relay-target", "owner", 1, 60, &target) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &source, 1, &source_device) != 0
        || st_storage_update_peer_mesh_device_enabled(path, &target, 1, &target_device) != 0
        || st_storage_create_peer_mesh_session(path, &source, &target, "RELAY", token_hash, 3600,
                                               &session) != 0) {
        fprintf(stderr, "Peer Mesh relay test database setup failed\n");
        unlink(path);
        return 1;
    }
    setenv("SPECUS_DATABASE_PATH", path, 1);

    struct sockaddr_in source_address;
    struct sockaddr_in target_address;
    struct sockaddr_in source_relay;
    struct sockaddr_in target_relay;
    char source_user[192];
    char target_user[192];
    unsigned char source_key[16];
    unsigned char target_key[16];
    int source_fd = udp_socket(&source_address);
    int target_fd = udp_socket(&target_address);
    int failed = source_fd < 0 || target_fd < 0
        || allocate_peer_relay(source_fd, server, source.id, 200U, source_user, source_key, &source_relay) != 0
        || allocate_peer_relay(target_fd, server, target.id, 210U, target_user, target_key, &target_relay) != 0
        || permit_peer(source_fd, server, source_user, source_key, &target_relay, 220U) != 0
        || permit_peer(target_fd, server, target_user, target_key, &source_relay, 230U) != 0;
    if (failed) fprintf(stderr, "Peer Mesh relay allocation/permission mismatch\n");

    char check[512];
    char forged[512];
    char reply[512];
    snprintf(check, sizeof(check),
             "{\"magic\":\"specus-peer-mesh\",\"type\":\"check\",\"sessionId\":%lld,"
             "\"fromClientId\":%lld,\"toClientId\":%lld,\"nonce\":\"n1\",\"token\":\"%s\"}",
             session.id, source.id, target.id, token);
    snprintf(forged, sizeof(forged),
             "{\"magic\":\"specus-peer-mesh\",\"type\":\"check\",\"sessionId\":%lld,"
             "\"fromClientId\":%lld,\"toClientId\":%lld,\"nonce\":\"n2\",\"token\":\"not-the-token\"}",
             session.id, source.id, target.id);
    snprintf(reply, sizeof(reply),
             "{\"magic\":\"specus-peer-mesh\",\"type\":\"check-response\",\"sessionId\":%lld,"
             "\"fromClientId\":%lld,\"toClientId\":%lld,\"nonce\":\"n1\",\"token\":\"%s\"}",
             session.id, target.id, source.id, token);
    if (!failed && !relayed(source_fd, server, &target_relay, target_fd, check, 240U)) {
        fprintf(stderr, "Peer Mesh check with the session token was not relayed\n");
        failed = 1;
    }
    if (!failed && !relayed(target_fd, server, &source_relay, source_fd, reply, 250U)) {
        fprintf(stderr, "Peer Mesh check-response with the session token was not relayed\n");
        failed = 1;
    }
    if (!failed && relayed(source_fd, server, &target_relay, target_fd, forged, 260U)) {
        fprintf(stderr, "Peer Mesh check with a forged token was relayed\n");
        failed = 1;
    }
    if (source_fd >= 0) close(source_fd);
    if (target_fd >= 0) close(target_fd);
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(path);
    return failed;
/* ---- RFC 5766 / RFC 8656 behaviour beyond Allocate, CreatePermission and Send ------------- */

#define STALE_NONCE "stale-nonce-from-a-previous-server-run"

typedef struct {
    st_stun_turn_server *server;
    struct sockaddr_in address;
} turn_fixture;

typedef struct {
    char username[192];
    unsigned char key[16];
} turn_credential;

static void sleep_ms(long milliseconds)
{
    struct timespec delay = {milliseconds / 1000L, (milliseconds % 1000L) * 1000000L};
    while (nanosleep(&delay, &delay) != 0) {
    }
}

static void wait_until_second(time_t second)
{
    while (time(NULL) < second) sleep_ms(10L);
}

static void set_receive_timeout(int fd, long milliseconds)
{
    struct timeval timeout = {milliseconds / 1000L, (milliseconds % 1000L) * 1000L};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

/* A dropped datagram can only be observed as nothing arriving within a short window. */
static int stays_silent(int fd)
{
    unsigned char scratch[2048];
    set_receive_timeout(fd, 200L);
    ssize_t received = recvfrom(fd, scratch, sizeof(scratch), 0, NULL, NULL);
    set_receive_timeout(fd, 2000L);
    return received < 0;
}

static int error_code(const unsigned char *packet, int len)
{
    size_t value_len = 0U;
    const unsigned char *value = len >= 20 ? find_attr(packet, (size_t)len, 0x0009U, &value_len) : NULL;
    return value == NULL || value_len < 4U ? -1 : (int)(value[2] & 0x07U) * 100 + value[3];
}

static int expect_error(const unsigned char *packet, int len, unsigned type, int code, const char *label)
{
    if (len >= 20 && r16(packet) == type && error_code(packet, len) == code) return 0;
    fprintf(stderr, "%s: expected 0x%04x/%d, got 0x%04x/%d\n", label, type, code,
            len >= 20 ? r16(packet) : 0U, error_code(packet, len));
    return -1;
}

static int text_attr_equals(const unsigned char *packet, int len, unsigned type, const char *expected)
{
    size_t value_len = 0U;
    const unsigned char *value = len >= 20 ? find_attr(packet, (size_t)len, type, &value_len) : NULL;
    return value != NULL && value_len == strlen(expected) && memcmp(value, expected, value_len) == 0;
}

static int lifetime_attr(const unsigned char *packet, int len)
{
    size_t value_len = 0U;
    const unsigned char *value = len >= 20 ? find_attr(packet, (size_t)len, 0x000dU, &value_len) : NULL;
    return value == NULL || value_len != 4U ? -1 : (int)r32(value);
}

/* Success responses to authenticated requests are signed with the same long-term key. */
static int integrity_valid(const unsigned char *packet, int len, const unsigned char key[16])
{
    size_t value_len = 0U;
    const unsigned char *mac = len >= 20 ? find_attr(packet, (size_t)len, 0x0008U, &value_len) : NULL;
    if (mac == NULL || value_len != 20U) return 0;
    size_t offset = (size_t)(mac - packet) - 4U;
    unsigned char copy[2048];
    unsigned char expected[20];
    memcpy(copy, packet, offset);
    u16(copy + 2U, (unsigned)(offset + 24U - 20U));
    st_hmac_sha1(key, 16U, copy, offset, expected);
    return memcmp(expected, mac, sizeof(expected)) == 0;
}

static int issue_credential(const char *subject, turn_credential *out)
{
    char credential[64];
    return st_turn_auth_issue(subject, out->username, sizeof(out->username), credential, sizeof(credential)) == 0
        && st_turn_auth_long_term_key(out->username, out->key) == 0 ? 0 : -1;
}

static void sign(packet_builder *request, const turn_credential *credential, const char *nonce)
{
    attr(request, 0x0006U, credential->username, strlen(credential->username));
    attr(request, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(request, 0x0015U, nonce, strlen(nonce));
    integrity(request, credential->key);
}

static int peer_from_text(const char *text, unsigned port, struct sockaddr_in *out)
{
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons((unsigned short)port);
    return inet_pton(AF_INET, text, &out->sin_addr) == 1 ? 0 : -1;
}

/* IPv6 XOR-PEER-ADDRESS: the address is XORed with the magic cookie and the transaction ID. */
static int add_xor_peer6(packet_builder *request, const char *text, unsigned port)
{
    unsigned char address[16];
    unsigned char key[16];
    unsigned char encoded[20] = {0, 2};
    if (inet_pton(AF_INET6, text, address) != 1) return -1;
    u16(encoded + 2U, port ^ (COOKIE >> 16U));
    u32(key, COOKIE);
    memcpy(key + 4U, request->bytes + 8U, 12U);
    for (size_t i = 0; i < 16U; ++i) encoded[4U + i] = address[i] ^ key[i];
    attr(request, 0x0012U, encoded, sizeof(encoded));
    return 0;
}

static int turn_fixture_start(turn_fixture *fixture,
                              int allow_private_peers,
                              const char *relay_min_port,
                              const char *relay_max_port,
                              const char *permission_and_channel_ttl)
{
    static const char *const cleared[] = {
        "SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT", "SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS",
        "SPECUS_PEER_MESH_PUBLIC_ADDRESS", "SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS",
        "SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS", "SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT",
        "SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS", "SPECUS_PEER_MESH_TURN_ALLOCATION_TTL_SECONDS",
        "SPECUS_PEER_MESH_TURN_PERMISSION_TTL_SECONDS", "SPECUS_PEER_MESH_TURN_CHANNEL_TTL_SECONDS"
    };
    for (size_t i = 0; i < sizeof(cleared) / sizeof(cleared[0]); ++i) unsetenv(cleared[i]);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", "0", 1);
    setenv("SPECUS_PEER_MESH_BIND_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_RELAY_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", relay_min_port, 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT", relay_max_port, 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "16", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", "16", 1);
    if (allow_private_peers) setenv("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS", "true", 1);
    else unsetenv("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS");
    if (permission_and_channel_ttl != NULL) {
        setenv("SPECUS_PEER_MESH_TURN_PERMISSION_TTL_SECONDS", permission_and_channel_ttl, 1);
        setenv("SPECUS_PEER_MESH_TURN_CHANNEL_TTL_SECONDS", permission_and_channel_ttl, 1);
    }
    fixture->server = NULL;
    if (st_stun_turn_server_start(&fixture->server) != 0 || st_stun_turn_server_port(fixture->server) <= 0) {
        fprintf(stderr, "STUN/TURN fixture start failed\n");
        return -1;
    }
    memset(&fixture->address, 0, sizeof(fixture->address));
    fixture->address.sin_family = AF_INET;
    fixture->address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    fixture->address.sin_port = htons((unsigned short)st_stun_turn_server_port(fixture->server));
    return 0;
}

static int allocate(int fd,
                    const turn_fixture *fixture,
                    const turn_credential *credential,
                    unsigned seed,
                    struct sockaddr_in *relay)
{
    packet_builder request;
    unsigned char response[2048];
    unsigned char transport[4] = {17, 0, 0, 0};
    start(&request, 0x0003U, seed);
    attr(&request, 0x0019U, transport, sizeof(transport));
    sign(&request, credential, st_turn_auth_nonce());
    int received = exchange(fd, &fixture->address, &request, response, sizeof(response));
    size_t value_len = 0U;
    const unsigned char *relayed = received >= 20
        ? find_attr(response, (size_t)received, 0x0016U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0103U || relayed == NULL || value_len != 8U) {
        fprintf(stderr, "TURN allocate (seed %u) failed: 0x%04x/%d\n", seed,
                received >= 20 ? r16(response) : 0U, error_code(response, received));
        return -1;
    }
    if (relay != NULL) {
        memset(relay, 0, sizeof(*relay));
        relay->sin_family = AF_INET;
        relay->sin_port = htons((unsigned short)(r16(relayed + 2U) ^ (COOKIE >> 16U)));
        relay->sin_addr.s_addr = htonl(r32(relayed + 4U) ^ COOKIE);
    }
    return 0;
}

static int create_permission(int fd,
                             const turn_fixture *fixture,
                             const turn_credential *credential,
                             const struct sockaddr_in *peer,
                             unsigned seed,
                             unsigned char *response,
                             size_t response_size)
{
    packet_builder request;
    start(&request, 0x0008U, seed);
    add_xor_peer(&request, peer);
    sign(&request, credential, st_turn_auth_nonce());
    return exchange(fd, &fixture->address, &request, response, response_size);
}

static int create_permission6(int fd,
                              const turn_fixture *fixture,
                              const turn_credential *credential,
                              const char *peer,
                              unsigned seed,
                              unsigned char *response,
                              size_t response_size)
{
    packet_builder request;
    start(&request, 0x0008U, seed);
    if (add_xor_peer6(&request, peer, 50000U) != 0) return -1;
    sign(&request, credential, st_turn_auth_nonce());
    return exchange(fd, &fixture->address, &request, response, response_size);
}

static int channel_bind(int fd,
                        const turn_fixture *fixture,
                        const turn_credential *credential,
                        unsigned number,
                        const struct sockaddr_in *peer,
                        unsigned seed,
                        unsigned char *response,
                        size_t response_size)
{
    packet_builder request;
    unsigned char channel[4] = {0, 0, 0, 0};
    u16(channel, number);
    start(&request, 0x0009U, seed);
    attr(&request, 0x000cU, channel, sizeof(channel));
    add_xor_peer(&request, peer);
    sign(&request, credential, st_turn_auth_nonce());
    return exchange(fd, &fixture->address, &request, response, response_size);
}

/* lifetime < 0 leaves LIFETIME out; credential NULL sends the request unauthenticated. */
static int refresh(int fd,
                   const turn_fixture *fixture,
                   const turn_credential *credential,
                   const char *nonce,
                   long lifetime,
                   unsigned seed,
                   unsigned char *response,
                   size_t response_size)
{
    packet_builder request;
    start(&request, 0x0004U, seed);
    if (lifetime >= 0) {
        unsigned char value[4];
        u32(value, (unsigned)lifetime);
        attr(&request, 0x000dU, value, sizeof(value));
    }
    if (credential != NULL) sign(&request, credential, nonce);
    return exchange(fd, &fixture->address, &request, response, response_size);
}

static int send_indication(int fd, const turn_fixture *fixture, const struct sockaddr_in *peer,
                           const char *data, unsigned seed)
{
    packet_builder request;
    start(&request, 0x0016U, seed);
    add_xor_peer(&request, peer);
    attr(&request, 0x0013U, data, strlen(data));
    return sendto(fd, request.bytes, request.len, 0, (const struct sockaddr *)&fixture->address,
                  sizeof(fixture->address)) == (ssize_t)request.len ? 0 : -1;
}

/* ChannelData over UDP may carry padding after the payload; the length field is authoritative. */
static int send_channel_data(int fd, const turn_fixture *fixture, unsigned number,
                             const char *data, size_t padding)
{
    unsigned char frame[256] = {0};
    size_t len = strlen(data);
    u16(frame, number);
    u16(frame + 2U, (unsigned)len);
    memcpy(frame + 4U, data, len);
    size_t total = 4U + len + padding;
    return sendto(fd, frame, total, 0, (const struct sockaddr *)&fixture->address,
                  sizeof(fixture->address)) == (ssize_t)total ? 0 : -1;
}

static int receive_exact(int fd, const char *expected, const struct sockaddr_in *expected_source,
                         const char *label)
{
    unsigned char data[2048];
    struct sockaddr_in source;
    socklen_t source_len = sizeof(source);
    ssize_t received = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&source, &source_len);
    if (received == (ssize_t)strlen(expected) && memcmp(data, expected, strlen(expected)) == 0
        && (expected_source == NULL
            || (source.sin_port == expected_source->sin_port
                && source.sin_addr.s_addr == expected_source->sin_addr.s_addr))) return 0;
    fprintf(stderr, "%s: expected \"%s\", received %zd bytes\n", label, expected, received);
    return -1;
}

/* Permissions are per IP address (RFC 5766 section 8), so a second peer needs its own address. */
static int udp_socket_on(const char *address, struct sockaddr_in *bound)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(bound, 0, sizeof(*bound));
    bound->sin_family = AF_INET;
    if (fd < 0 || inet_pton(AF_INET, address, &bound->sin_addr) != 1
        || bind(fd, (struct sockaddr *)bound, sizeof(*bound)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    socklen_t len = sizeof(*bound);
    if (getsockname(fd, (struct sockaddr *)bound, &len) != 0) {
        close(fd);
        return -1;
    }
    set_receive_timeout(fd, 2000L);
    return fd;
}

static int test_channel_bind_and_channel_data(void)
{
    turn_fixture fixture;
    turn_credential credential;
    if (turn_fixture_start(&fixture, 1, "55200", "55299", NULL) != 0
        || issue_credential("public-transfer-channel", &credential) != 0) return -1;
    struct sockaddr_in client_address, peer_address, other_address, stranger_address, relay;
    int client = udp_socket(&client_address);
    int peer = udp_socket(&peer_address);
    int other = udp_socket_on("127.0.0.2", &other_address);
    int stranger = udp_socket(&stranger_address);
    unsigned char response[2048];
    int failed = client < 0 || peer < 0 || other < 0 || stranger < 0
        || allocate(client, &fixture, &credential, 200U, &relay) != 0;

    /* ChannelBind needs an allocation of its own. */
    int received = failed ? -1 : channel_bind(stranger, &fixture, &credential, 0x4000U, &peer_address,
                                               201U, response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0119U, 437, "ChannelBind without allocation") != 0;

    received = failed ? -1 : channel_bind(client, &fixture, &credential, 0x4000U, &peer_address,
                                           202U, response, sizeof(response));
    if (!failed && (received < 20 || r16(response) != 0x0109U
                    || !integrity_valid(response, received, credential.key))) {
        fprintf(stderr, "ChannelBind success response mismatch\n");
        failed = 1;
    }
    /* Client to peer: the relay forwards exactly the ChannelData payload, ignoring UDP padding. */
    failed = failed || send_channel_data(client, &fixture, 0x4000U, "chan-out", 0U) != 0
        || receive_exact(peer, "chan-out", &relay, "ChannelData client to peer") != 0
        || send_channel_data(client, &fixture, 0x4000U, "hello", 3U) != 0
        || receive_exact(peer, "hello", &relay, "padded ChannelData client to peer") != 0;
    /* Peer to client: a bound peer arrives as ChannelData, not as a Data indication. */
    if (!failed) {
        unsigned char frame[64];
        failed = sendto(peer, "chan-in", 7U, 0, (struct sockaddr *)&relay, sizeof(relay)) != 7;
        received = failed ? -1 : (int)recvfrom(client, frame, sizeof(frame), 0, NULL, NULL);
        if (!failed && (received != 11 || r16(frame) != 0x4000U || r16(frame + 2U) != 7U
                        || memcmp(frame + 4U, "chan-in", 7U) != 0)) {
            fprintf(stderr, "ChannelData peer to client mismatch (%d bytes)\n", received);
            failed = 1;
        }
    }
    /* A channel number that was never bound relays nothing. */
    if (!failed && (send_channel_data(client, &fixture, 0x4001U, "unbound", 0U) != 0
                    || !stays_silent(peer) || !stays_silent(other))) {
        fprintf(stderr, "ChannelData on an unbound channel was relayed\n");
        failed = 1;
    }
    /* RFC 5766 section 11.2: a bound number cannot be moved to another peer while it lives. */
    received = failed ? -1 : channel_bind(client, &fixture, &credential, 0x4000U, &other_address,
                                           203U, response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0119U, 400, "ChannelBind of a channel in use") != 0
        || send_channel_data(client, &fixture, 0x4000U, "still-first", 0U) != 0
        || receive_exact(peer, "still-first", &relay, "ChannelData after a refused rebind") != 0;
    /* The refused bind installed no permission for the other peer's address either. */
    if (!failed && (sendto(other, "sneak", 5U, 0, (struct sockaddr *)&relay, sizeof(relay)) != 5
                    || !stays_silent(client))) {
        fprintf(stderr, "a refused ChannelBind left a permission behind\n");
        failed = 1;
    }
    /* Binding the same number to the same peer again refreshes it. */
    received = failed ? -1 : channel_bind(client, &fixture, &credential, 0x4000U, &peer_address,
                                           204U, response, sizeof(response));
    if (!failed && (received < 20 || r16(response) != 0x0109U)) {
        fprintf(stderr, "ChannelBind refresh mismatch\n");
        failed = 1;
    }
    received = failed ? -1 : channel_bind(client, &fixture, &credential, 0x3fffU, &other_address,
                                           205U, response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0119U, 400, "ChannelBind below 0x4000") != 0;

    close(stranger);
    close(other);
    close(peer);
    close(client);
    st_stun_turn_server_stop(fixture.server);
    return failed ? -1 : 0;
}

static int test_refresh_and_deallocation(void)
{
    turn_fixture fixture;
    turn_credential credential;
    if (turn_fixture_start(&fixture, 1, "55300", "55399", NULL) != 0
        || issue_credential("public-transfer-refresh", &credential) != 0) return -1;
    struct sockaddr_in client_address, peer_address, stranger_address, relay;
    int client = udp_socket(&client_address);
    int peer = udp_socket(&peer_address);
    int stranger = udp_socket(&stranger_address);
    unsigned char response[2048];
    int failed = client < 0 || peer < 0 || stranger < 0
        || allocate(client, &fixture, &credential, 300U, &relay) != 0;

    int received = failed ? -1 : refresh(client, &fixture, NULL, NULL, -1, 301U, response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0114U, 401, "unauthenticated Refresh") != 0;
    if (!failed && (!text_attr_equals(response, received, 0x0014U, st_turn_auth_realm())
                    || !text_attr_equals(response, received, 0x0015U, st_turn_auth_nonce()))) {
        fprintf(stderr, "Refresh challenge carries no realm and nonce\n");
        failed = 1;
    }
    received = failed ? -1 : refresh(stranger, &fixture, &credential, st_turn_auth_nonce(), -1, 302U,
                                     response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0114U, 437, "Refresh without allocation") != 0;
    /* Without LIFETIME the server grants its own allocation lifetime (300 s by default). */
    received = failed ? -1 : refresh(client, &fixture, &credential, st_turn_auth_nonce(), -1, 303U,
                                     response, sizeof(response));
    if (!failed && (received < 20 || r16(response) != 0x0104U || lifetime_attr(response, received) != 300
                    || !integrity_valid(response, received, credential.key))) {
        fprintf(stderr, "Refresh success response mismatch (lifetime %d)\n", lifetime_attr(response, received));
        failed = 1;
    }
    received = failed ? -1 : create_permission(client, &fixture, &credential, &peer_address, 304U,
                                               response, sizeof(response));
    if (!failed && (received < 20 || r16(response) != 0x0108U
                    || sendto(peer, "before", 6U, 0, (struct sockaddr *)&relay, sizeof(relay)) != 6)) {
        fprintf(stderr, "Refresh test permission setup failed\n");
        failed = 1;
    }
    if (!failed) {
        received = (int)recvfrom(client, response, sizeof(response), 0, NULL, NULL);
        if (received < 20 || r16(response) != 0x0017U) {
            fprintf(stderr, "Data indication before deallocation missing\n");
            failed = 1;
        }
    }
    /* LIFETIME 0 deletes the allocation at once (RFC 5766 section 7). */
    received = failed ? -1 : refresh(client, &fixture, &credential, st_turn_auth_nonce(), 0, 305U,
                                     response, sizeof(response));
    if (!failed && (received < 20 || r16(response) != 0x0104U || lifetime_attr(response, received) != 0)) {
        fprintf(stderr, "Refresh with lifetime 0 response mismatch\n");
        failed = 1;
    }
    if (!failed && (sendto(peer, "after", 5U, 0, (struct sockaddr *)&relay, sizeof(relay)) != 5
                    || !stays_silent(client))) {
        fprintf(stderr, "a deleted allocation still relayed peer data\n");
        failed = 1;
    }
    received = failed ? -1 : create_permission(client, &fixture, &credential, &peer_address, 306U,
                                               response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0118U, 437, "CreatePermission after deallocation") != 0;
    received = failed ? -1 : refresh(client, &fixture, &credential, st_turn_auth_nonce(), -1, 307U,
                                     response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0114U, 437, "Refresh after deallocation") != 0;
    /* The same 5-tuple can allocate again afterwards. */
    failed = failed || allocate(client, &fixture, &credential, 308U, NULL) != 0;

    close(stranger);
    close(peer);
    close(client);
    st_stun_turn_server_stop(fixture.server);
    return failed ? -1 : 0;
}

static int test_stale_nonce(void)
{
    turn_fixture fixture;
    turn_credential credential;
    if (turn_fixture_start(&fixture, 1, "55400", "55499", NULL) != 0
        || issue_credential("public-transfer-nonce", &credential) != 0) return -1;
    struct sockaddr_in client_address;
    int client = udp_socket(&client_address);
    unsigned char response[2048];
    packet_builder request;
    unsigned char transport[4] = {17, 0, 0, 0};
    /* A nonce the server no longer issues, e.g. one a client cached before a restart. */
    start(&request, 0x0003U, 400U);
    attr(&request, 0x0019U, transport, sizeof(transport));
    sign(&request, &credential, STALE_NONCE);
    int received = client < 0 ? -1 : exchange(client, &fixture.address, &request, response, sizeof(response));
    int failed = expect_error(response, received, 0x0113U, 438, "Allocate with a stale nonce") != 0;
    if (!failed && (!text_attr_equals(response, received, 0x0015U, st_turn_auth_nonce())
                    || !text_attr_equals(response, received, 0x0014U, st_turn_auth_realm()))) {
        fprintf(stderr, "438 response does not carry the current realm and nonce\n");
        failed = 1;
    }
    /* Retrying with the nonce from the 438 response succeeds. */
    failed = failed || allocate(client, &fixture, &credential, 401U, NULL) != 0;
    received = failed ? -1 : refresh(client, &fixture, &credential, STALE_NONCE, -1, 402U,
                                     response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0114U, 438, "Refresh with a stale nonce") != 0;
    /* A wrong realm or a wrong key is not a stale nonce. */
    if (!failed) {
        start(&request, 0x0004U, 403U);
        attr(&request, 0x0006U, credential.username, strlen(credential.username));
        attr(&request, 0x0014U, "another-realm", 13U);
        attr(&request, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
        integrity(&request, credential.key);
        received = exchange(client, &fixture.address, &request, response, sizeof(response));
        failed = expect_error(response, received, 0x0114U, 401, "Refresh with another realm") != 0;
    }
    turn_credential forged = credential;
    forged.key[0] ^= 0xffU;
    received = failed ? -1 : refresh(client, &fixture, &forged, st_turn_auth_nonce(), -1, 404U,
                                     response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0114U, 401, "Refresh with a bad integrity") != 0;

    close(client);
    st_stun_turn_server_stop(fixture.server);
    return failed ? -1 : 0;
}

/* Without SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS the general relay only reaches public peers. */
static int test_default_private_peer_refusal(void)
{
    turn_fixture fixture;
    turn_credential general;
    turn_credential mesh;
    if (turn_fixture_start(&fixture, 0, "55500", "55599", NULL) != 0
        || issue_credential("public-transfer-policy", &general) != 0
        || issue_credential("pm-7", &mesh) != 0) return -1;
    struct sockaddr_in client_address, mesh_address, local_address, peer;
    int client = udp_socket(&client_address);
    int mesh_client = udp_socket(&mesh_address);
    int local = udp_socket(&local_address);
    unsigned char response[2048];
    int failed = client < 0 || mesh_client < 0 || local < 0
        || allocate(client, &fixture, &general, 500U, NULL) != 0
        || allocate(mesh_client, &fixture, &mesh, 501U, NULL) != 0;
    unsigned seed = 510U;

    static const char *const refused_ipv4[] = {
        "127.0.0.1", "10.0.0.5", "172.16.0.1", "192.168.1.10", "169.254.1.10", "239.1.1.1", "0.0.0.0"
    };
    for (size_t i = 0; !failed && i < sizeof(refused_ipv4) / sizeof(refused_ipv4[0]); ++i) {
        int received = peer_from_text(refused_ipv4[i], 50000U, &peer) != 0 ? -1
            : create_permission(client, &fixture, &general, &peer, seed++, response, sizeof(response));
        failed = expect_error(response, received, 0x0118U, 403, refused_ipv4[i]) != 0;
    }
    static const char *const refused_ipv6[] = {
        "::1", "::", "fd00::1", "fe80::1", "fec0::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:192.168.1.10"
    };
    for (size_t i = 0; !failed && i < sizeof(refused_ipv6) / sizeof(refused_ipv6[0]); ++i) {
        int received = create_permission6(client, &fixture, &general, refused_ipv6[i], seed++,
                                          response, sizeof(response));
        failed = expect_error(response, received, 0x0118U, 403, refused_ipv6[i]) != 0;
    }
    /* Port 0 is never a peer, even on a public address. */
    int received = failed || peer_from_text("203.0.113.10", 0U, &peer) != 0 ? -1
        : create_permission(client, &fixture, &general, &peer, seed++, response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0118U, 403, "public peer on port 0") != 0;
    /* ChannelBind installs a permission too, so it applies the same policy. */
    received = failed || peer_from_text("192.168.1.10", 50000U, &peer) != 0 ? -1
        : channel_bind(client, &fixture, &general, 0x4000U, &peer, seed++, response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0119U, 403, "ChannelBind to a private peer") != 0;

    /* Public unicast peers stay allowed, including RFC 6598 CGNAT space and IPv4-mapped IPv6. */
    static const char *const allowed_ipv4[] = {"203.0.113.10", "100.64.0.2"};
    for (size_t i = 0; !failed && i < sizeof(allowed_ipv4) / sizeof(allowed_ipv4[0]); ++i) {
        received = peer_from_text(allowed_ipv4[i], 50000U, &peer) != 0 ? -1
            : create_permission(client, &fixture, &general, &peer, seed++, response, sizeof(response));
        if (received < 20 || r16(response) != 0x0108U) {
            fprintf(stderr, "public peer %s was refused\n", allowed_ipv4[i]);
            failed = 1;
        }
    }
    static const char *const allowed_ipv6[] = {"2001:db8::10", "::ffff:203.0.113.10"};
    for (size_t i = 0; !failed && i < sizeof(allowed_ipv6) / sizeof(allowed_ipv6[0]); ++i) {
        received = create_permission6(client, &fixture, &general, allowed_ipv6[i], seed++,
                                      response, sizeof(response));
        if (received < 20 || r16(response) != 0x0108U) {
            fprintf(stderr, "public peer %s was refused\n", allowed_ipv6[i]);
            failed = 1;
        }
    }
    /* A refused loopback peer never receives relayed data. */
    received = failed ? -1 : create_permission(client, &fixture, &general, &local_address, seed++,
                                               response, sizeof(response));
    failed = failed || expect_error(response, received, 0x0118U, 403, "loopback peer socket") != 0;
    if (!failed && (send_indication(client, &fixture, &local_address, "leak", seed++) != 0
                    || !stays_silent(local))) {
        fprintf(stderr, "general relay reached a refused loopback peer\n");
        failed = 1;
    }
    /* Peer Mesh allocations are exempt: their peers are this server's own relay endpoints. */
    received = failed ? -1 : create_permission(mesh_client, &fixture, &mesh, &local_address, seed++,
                                               response, sizeof(response));
    if (!failed && (received < 20 || r16(response) != 0x0108U)) {
        fprintf(stderr, "Peer Mesh permission to a loopback relay was refused\n");
        failed = 1;
    }

    close(local);
    close(mesh_client);
    close(client);
    st_stun_turn_server_stop(fixture.server);
    return failed ? -1 : 0;
}

/*
 * One-second permission, channel and allocation lifetimes. Everything is installed early in one
 * wall-clock second so it has expired once the next second begins; the first request after that
 * reaches the server before its periodic sweep, which therefore cannot hide a missing expiry check.
 */
static int expiry_round(const turn_fixture *fixture, const turn_credential *credential, int *retry)
{
    struct sockaddr_in a_address, b_address, one_address, two_address, relay;
    int a = udp_socket(&a_address);
    int b = udp_socket(&b_address);
    int one = udp_socket(&one_address);
    int two = udp_socket(&two_address);
    unsigned char response[2048];
    int failed = a < 0 || b < 0 || one < 0 || two < 0
        || allocate(a, fixture, credential, 600U, &relay) != 0
        || allocate(b, fixture, credential, 601U, NULL) != 0;
    time_t second = time(NULL);
    if (!failed) {
        wait_until_second(second + 1);
        sleep_ms(300L);
        second = time(NULL);
    }
    int received = failed ? -1 : create_permission(a, fixture, credential, &one_address, 602U,
                                                   response, sizeof(response));
    failed = failed || received < 20 || r16(response) != 0x0108U;
    received = failed ? -1 : channel_bind(a, fixture, credential, 0x4000U, &two_address, 603U,
                                          response, sizeof(response));
    failed = failed || received < 20 || r16(response) != 0x0109U
        || send_indication(a, fixture, &one_address, "live-send", 604U) != 0
        || receive_exact(one, "live-send", &relay, "Send before expiry") != 0
        || send_channel_data(a, fixture, 0x4000U, "live-channel", 0U) != 0
        || receive_exact(two, "live-channel", &relay, "ChannelData before expiry") != 0;
    received = failed ? -1 : refresh(b, fixture, credential, st_turn_auth_nonce(), 1, 605U,
                                     response, sizeof(response));
    failed = failed || received < 20 || r16(response) != 0x0104U;
    if (failed) fprintf(stderr, "TURN expiry setup failed\n");
    /* A scheduler stall that pushed the setup into the next second leaves nothing to observe. */
    *retry = !failed && time(NULL) != second;
    if (!failed && !*retry) {
        wait_until_second(second + 1);
        sleep_ms(50L);
        received = refresh(b, fixture, credential, st_turn_auth_nonce(), -1, 606U, response, sizeof(response));
        failed = expect_error(response, received, 0x0114U, 437, "Refresh of an expired allocation") != 0;
        if (!failed && (send_channel_data(a, fixture, 0x4000U, "late-channel", 0U) != 0 || !stays_silent(two)
                        || send_indication(a, fixture, &one_address, "late-send", 607U) != 0
                        || !stays_silent(one)
                        || sendto(one, "late-peer", 9U, 0, (struct sockaddr *)&relay, sizeof(relay)) != 9
                        || !stays_silent(a))) {
            fprintf(stderr, "an expired permission or channel still relayed data\n");
            failed = 1;
        }
        /* The allocation itself outlives its permissions and channels. */
        received = failed ? -1 : refresh(a, fixture, credential, st_turn_auth_nonce(), -1, 608U,
                                         response, sizeof(response));
        if (!failed && (received < 20 || r16(response) != 0x0104U)) {
            fprintf(stderr, "allocation did not outlive its permissions\n");
            failed = 1;
        }
    }
    close(two);
    close(one);
    close(b);
    close(a);
    return failed ? -1 : 0;
}

static int test_expiry(void)
{
    turn_fixture fixture;
    turn_credential credential;
    if (turn_fixture_start(&fixture, 1, "55600", "55699", "1") != 0
        || issue_credential("public-transfer-expiry", &credential) != 0) return -1;
    int failed = 0;
    int retry = 1;
    for (int attempt = 0; attempt < 3 && retry && !failed; ++attempt) {
        failed = expiry_round(&fixture, &credential, &retry) != 0;
    }
    st_stun_turn_server_stop(fixture.server);
    if (!failed && retry) fprintf(stderr, "TURN expiry setup never fit into one second\n");
    return failed || retry ? -1 : 0;
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
    if (peer_mesh_relay_tests(&server_address) != 0) return 1;
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

    if (test_channel_bind_and_channel_data() != 0
        || test_refresh_and_deallocation() != 0
        || test_stale_nonce() != 0
        || test_default_private_peer_refusal() != 0
        || test_expiry() != 0) {
        fprintf(stderr, "TURN channel, refresh, nonce, peer policy or expiry tests failed\n");
        return 1;
    }
    printf("STUN/TURN tests passed\n");
    return 0;
}
