#define _POSIX_C_SOURCE 200809L

#include "stun_turn.h"

#include "crypto.h"
#include "instant.h"
#include "json.h"
#include "storage.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STUN_COOKIE 0x2112a442U
#define STUN_HEADER_SIZE 20U
#define STUN_MAX_PACKET 65535U
#define TURN_MAX_PERMISSIONS 32U
#define TURN_MAX_CHANNELS 32U

#define STUN_BINDING_REQUEST 0x0001U
#define STUN_BINDING_SUCCESS 0x0101U
#define TURN_ALLOCATE_REQUEST 0x0003U
#define TURN_ALLOCATE_SUCCESS 0x0103U
#define TURN_REFRESH_REQUEST 0x0004U
#define TURN_REFRESH_SUCCESS 0x0104U
#define TURN_SEND_INDICATION 0x0016U
#define TURN_DATA_INDICATION 0x0017U
#define TURN_CREATE_PERMISSION_REQUEST 0x0008U
#define TURN_CREATE_PERMISSION_SUCCESS 0x0108U
#define TURN_CHANNEL_BIND_REQUEST 0x0009U
#define TURN_CHANNEL_BIND_SUCCESS 0x0109U

#define ATTR_USERNAME 0x0006U
#define ATTR_MAPPED_ADDRESS 0x0001U
#define ATTR_MESSAGE_INTEGRITY 0x0008U
#define ATTR_ERROR_CODE 0x0009U
#define ATTR_UNKNOWN_ATTRIBUTES 0x000aU
#define ATTR_CHANNEL_NUMBER 0x000cU
#define ATTR_LIFETIME 0x000dU
#define ATTR_XOR_PEER_ADDRESS 0x0012U
#define ATTR_DATA 0x0013U
#define ATTR_REALM 0x0014U
#define ATTR_NONCE 0x0015U
#define ATTR_XOR_RELAYED_ADDRESS 0x0016U
#define ATTR_REQUESTED_TRANSPORT 0x0019U
#define ATTR_XOR_MAPPED_ADDRESS 0x0020U
#define ATTR_CHANGE_REQUEST 0x0003U
#define ATTR_PADDING 0x0026U
#define ATTR_RESPONSE_PORT 0x0027U
#define ATTR_SOFTWARE 0x8022U
#define ATTR_RESPONSE_ORIGIN 0x802bU
#define ATTR_OTHER_ADDRESS 0x802cU
#define STUN_MAX_ENDPOINTS 4U
#define STUN_SOFTWARE "specus-standard-stun-turn"
/* Java PeerMeshService: RELAY_AUTH_CACHE_TTL_NANOS and relay-traffic-flush-interval-ms. */
#define RELAY_GRANT_TTL_MS 30000LL
#define RELAY_TRAFFIC_FLUSH_DEFAULT_MS 5000L

typedef struct {
    int used;
    struct sockaddr_storage address;
    socklen_t address_len;
    time_t expires_at;
} turn_permission;

typedef struct {
    int used;
    uint16_t number;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    time_t expires_at;
} turn_channel;

typedef struct {
    int used;
    int relay_fd;
    struct sockaddr_storage client;
    socklen_t client_len;
    struct sockaddr_storage relay;
    socklen_t relay_len;
    char username[192];
    unsigned long long relayed_bytes;
    time_t expires_at;
    turn_permission permissions[TURN_MAX_PERMISSIONS];
    turn_channel channels[TURN_MAX_CHANNELS];
} turn_allocation;

typedef struct {
    int fd;
    int address_slot;
    int port_slot;
    struct sockaddr_storage advertised;
    socklen_t advertised_len;
} stun_server_endpoint;

/*
 * A Peer Mesh session the relay has seen (Java relayAuthorizationCache plus pendingRelayBytes).
 * The grant answers its frames for RELAY_GRANT_TTL_MS while the session neither expires nor is
 * withdrawn (closed or given a new status, which the storage reports per session); the bytes of
 * its outbound frames wait in pending_bytes for the next batch. Keyed by database and session,
 * since the database path is read per frame.
 */
typedef struct {
    char *database_path;
    long long session_id;
    st_storage_peer_mesh_relay_grant grant;
    int granted;
    long long grant_expires_ms;
    long long pending_bytes;
} relay_session;

/* Sessions withdrawn lately, so that a grant read while one was withdrawn is not kept. */
#define RELAY_WITHDRAWAL_RING 64U

struct st_stun_turn_server {
    int control_fd;
    int port;
    stun_server_endpoint endpoints[STUN_MAX_ENDPOINTS];
    size_t endpoint_count;
    int rfc5780;
    atomic_int running;
    int auth_required;
    int allow_private_peers;
    int allocation_ttl;
    int permission_ttl;
    int channel_ttl;
    int relay_min_port;
    int relay_max_port;
    int general_relay_max_allocations;
    int general_relay_max_allocations_per_address;
    long long general_relay_max_bytes;
    /* Java configureUdpSocket: buffer sizes (<= 0 keeps the kernel's) and IP_TOS (outside 0..255 keeps it). */
    int udp_receive_buffer;
    int udp_send_buffer;
    int udp_traffic_class;
    /* XOR-RELAYED-ADDRESS of every allocation (Java turnAdvertisedAddress). */
    struct in_addr relay_address;
    pthread_t thread;
    /*
     * Every allocation, without a fixed limit (Java keeps them in an unbounded map: the relay
     * port range and the descriptor limit bound them). Each is allocated on its own, so pointers
     * to it survive the table growing; one closed during a poll pass is freed after that pass.
     */
    turn_allocation **allocations;
    size_t allocation_count;
    size_t allocation_capacity;
    time_t last_entry_sweep;
    /* The poll set of one pass and the allocation each relay entry belongs to (NULL: endpoint). */
    struct pollfd *poll_fds;
    turn_allocation **poll_owners;
    size_t poll_capacity;
    /*
     * Relay sessions, shared by the STUN/TURN thread, the flusher and the storage's listener.
     * relay_lock guards the table, the withdrawals and flush_stopping and is never held over
     * database work; flush_lock lets one batch be written at a time, and only a flush removes
     * entries. next_live and live belong to live_servers_lock.
     */
    pthread_mutex_t relay_lock;
    pthread_cond_t relay_wake;
    pthread_mutex_t flush_lock;
    int sync_ready;
    relay_session *relay_sessions;
    size_t relay_session_count;
    size_t relay_session_capacity;
    unsigned long long withdrawals;
    long long withdrawn_sessions[RELAY_WITHDRAWAL_RING];
    st_stun_turn_server *next_live;
    int live;
    long flush_interval_ms;
    int flush_stopping;
    int flusher_started;
    pthread_t flusher;
};

typedef struct {
    uint16_t type;
    const uint8_t *value;
    uint16_t length;
    size_t offset;
} stun_attribute;

typedef struct {
    uint8_t data[STUN_MAX_PACKET];
    size_t len;
} stun_builder;

static uint16_t read_u16(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8U) | data[1]);
}

static uint32_t read_u32(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24U) | ((uint32_t)data[1] << 16U)
        | ((uint32_t)data[2] << 8U) | data[3];
}

static void write_u16(uint8_t *data, uint16_t value)
{
    data[0] = (uint8_t)(value >> 8U);
    data[1] = (uint8_t)value;
}

static void write_u32(uint8_t *data, uint32_t value)
{
    data[0] = (uint8_t)(value >> 24U);
    data[1] = (uint8_t)(value >> 16U);
    data[2] = (uint8_t)(value >> 8U);
    data[3] = (uint8_t)value;
}

static int env_bool_value(const char *name, int default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    return strcmp(value, "1") == 0 || strcmp(value, "true") == 0
        || strcmp(value, "TRUE") == 0 || strcmp(value, "yes") == 0;
}

static int env_int_value(const char *name, int default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    return end != value && *end == '\0' && parsed >= 0 && parsed <= 65535
        ? (int)parsed : default_value;
}

static long long env_i64_value(const char *name, long long default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' ? parsed : default_value;
}

/* A Java int property: any decimal int, negative values included (they switch a setting off). */
static int env_signed_int_value(const char *name, int default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return default_value;
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' && errno == 0 && parsed >= INT_MIN && parsed <= INT_MAX
        ? (int)parsed : default_value;
}

static int env_int_alias(const char *name, const char *legacy_name, int default_value)
{
    const char *value = getenv(name);
    return value != NULL && *value != '\0'
        ? env_int_value(name, default_value)
        : env_int_value(legacy_name, default_value);
}

static int env_signed_int_alias(const char *name, const char *legacy_name, int default_value)
{
    const char *value = getenv(name);
    return value != NULL && *value != '\0'
        ? env_signed_int_value(name, default_value)
        : env_signed_int_value(legacy_name, default_value);
}

/* Java InetAddress.getLocalHost: this host's name resolved (IPv4, as every socket here is). */
/* Java InetAddress.getByName, for IPv4 sockets: a literal, else the first IPv4 address of the name. */
static int resolve_ipv4(const char *text, struct in_addr *out)
{
    if (text == NULL || *text == '\0') return -1;
    if (inet_pton(AF_INET, text, out) == 1) return 0;
    struct addrinfo hints;
    struct addrinfo *found = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(text, NULL, &hints, &found) != 0 || found == NULL) return -1;
    *out = ((const struct sockaddr_in *)found->ai_addr)->sin_addr;
    freeaddrinfo(found);
    return 0;
}

static void local_host_address(struct in_addr *out)
{
    char name[256];
    if (gethostname(name, sizeof(name)) != 0) name[0] = '\0';
    name[sizeof(name) - 1U] = '\0';
    if (resolve_ipv4(name, out) != 0) out->s_addr = htonl(INADDR_LOOPBACK);
}

static int sockaddr_equal(const struct sockaddr_storage *left,
                          const struct sockaddr_storage *right,
                          int include_port)
{
    if (left->ss_family != right->ss_family) return 0;
    if (left->ss_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)left;
        const struct sockaddr_in *b = (const struct sockaddr_in *)right;
        return a->sin_addr.s_addr == b->sin_addr.s_addr
            && (!include_port || a->sin_port == b->sin_port);
    }
    if (left->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)left;
        const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)right;
        return memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0
            && (!include_port || a->sin6_port == b->sin6_port);
    }
    return 0;
}

static int stun_packet_valid(const uint8_t *packet, size_t len)
{
    return packet != NULL && len >= STUN_HEADER_SIZE && (packet[0] & 0xc0U) == 0U
        && read_u32(packet + 4U) == STUN_COOKIE
        && read_u16(packet + 2U) % 4U == 0U
        && (size_t)read_u16(packet + 2U) + STUN_HEADER_SIZE <= len;
}

static int find_attribute(const uint8_t *packet,
                          size_t len,
                          uint16_t type,
                          stun_attribute *out)
{
    if (!stun_packet_valid(packet, len)) return -1;
    size_t end = STUN_HEADER_SIZE + read_u16(packet + 2U);
    for (size_t offset = STUN_HEADER_SIZE; offset + 4U <= end;) {
        uint16_t attr_type = read_u16(packet + offset);
        uint16_t attr_len = read_u16(packet + offset + 2U);
        if (offset + 4U + attr_len > end) return -1;
        if (attr_type == type) {
            if (out != NULL) {
                out->type = attr_type;
                out->value = packet + offset + 4U;
                out->length = attr_len;
                out->offset = offset;
            }
            return 0;
        }
        offset += 4U + ((attr_len + 3U) & ~3U);
    }
    return 1;
}

static int builder_start(stun_builder *builder, uint16_t type, const uint8_t transaction[12])
{
    memset(builder, 0, sizeof(*builder));
    builder->len = STUN_HEADER_SIZE;
    write_u16(builder->data, type);
    write_u32(builder->data + 4U, STUN_COOKIE);
    memcpy(builder->data + 8U, transaction, 12U);
    return 0;
}

static int builder_attr(stun_builder *builder, uint16_t type, const void *value, size_t len)
{
    size_t padded = (len + 3U) & ~3U;
    if (len > UINT16_MAX || builder->len + 4U + padded > sizeof(builder->data)) return -1;
    write_u16(builder->data + builder->len, type);
    write_u16(builder->data + builder->len + 2U, (uint16_t)len);
    if (len > 0U) memcpy(builder->data + builder->len + 4U, value, len);
    if (padded > len) memset(builder->data + builder->len + 4U + len, 0, padded - len);
    builder->len += 4U + padded;
    write_u16(builder->data + 2U, (uint16_t)(builder->len - STUN_HEADER_SIZE));
    return 0;
}

static int builder_u32(stun_builder *builder, uint16_t type, uint32_t value)
{
    uint8_t encoded[4];
    write_u32(encoded, value);
    return builder_attr(builder, type, encoded, sizeof(encoded));
}

static int encode_address(const struct sockaddr_storage *address,
                          const uint8_t transaction[12],
                          int xor_address,
                          uint8_t out[20],
                          size_t *out_len)
{
    memset(out, 0, 20U);
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        out[1] = 0x01U;
        uint16_t port = ntohs(ipv4->sin_port);
        if (xor_address) port ^= (uint16_t)(STUN_COOKIE >> 16U);
        write_u16(out + 2U, port);
        uint32_t ip = ntohl(ipv4->sin_addr.s_addr);
        if (xor_address) ip ^= STUN_COOKIE;
        write_u32(out + 4U, ip);
        *out_len = 8U;
        return 0;
    }
    if (address->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        out[1] = 0x02U;
        uint16_t port = ntohs(ipv6->sin6_port);
        if (xor_address) port ^= (uint16_t)(STUN_COOKIE >> 16U);
        write_u16(out + 2U, port);
        memcpy(out + 4U, &ipv6->sin6_addr, 16U);
        if (xor_address) {
            uint8_t key[16];
            write_u32(key, STUN_COOKIE);
            memcpy(key + 4U, transaction, 12U);
            for (size_t i = 0; i < 16U; ++i) out[4U + i] ^= key[i];
        }
        *out_len = 20U;
        return 0;
    }
    return -1;
}

static int decode_xor_address(const stun_attribute *attribute,
                              const uint8_t transaction[12],
                              struct sockaddr_storage *out,
                              socklen_t *out_len)
{
    if (attribute == NULL || attribute->length < 8U) return -1;
    uint16_t port = read_u16(attribute->value + 2U) ^ (uint16_t)(STUN_COOKIE >> 16U);
    memset(out, 0, sizeof(*out));
    if (attribute->value[1] == 0x01U && attribute->length == 8U) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)out;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        ipv4->sin_addr.s_addr = htonl(read_u32(attribute->value + 4U) ^ STUN_COOKIE);
        *out_len = sizeof(*ipv4);
        return 0;
    }
    if (attribute->value[1] == 0x02U && attribute->length == 20U) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)out;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        uint8_t key[16];
        write_u32(key, STUN_COOKIE);
        memcpy(key + 4U, transaction, 12U);
        for (size_t i = 0; i < 16U; ++i) ((uint8_t *)&ipv6->sin6_addr)[i] = attribute->value[4U + i] ^ key[i];
        *out_len = sizeof(*ipv6);
        return 0;
    }
    return -1;
}

static int builder_address(stun_builder *builder,
                           uint16_t type,
                           const struct sockaddr_storage *address,
                           int xor_address)
{
    uint8_t encoded[20];
    size_t len = 0U;
    if (encode_address(address, builder->data + 8U, xor_address, encoded, &len) != 0) return -1;
    return builder_attr(builder, type, encoded, len);
}

static int builder_integrity(stun_builder *builder, const uint8_t key[16])
{
    if (builder->len + 24U > sizeof(builder->data)) return -1;
    write_u16(builder->data + 2U, (uint16_t)(builder->len + 24U - STUN_HEADER_SIZE));
    uint8_t mac[ST_SHA1_LEN];
    st_hmac_sha1(key, 16U, builder->data, builder->len, mac);
    return builder_attr(builder, ATTR_MESSAGE_INTEGRITY, mac, sizeof(mac));
}

/*
 * Java StunTurnServer.authenticate, in its order: NULL for a request signed with a valid credential
 * (its username is left in username), otherwise the reason and *code of the refusal. Without this
 * realm, a user or a nonce it is 401 unauthorized; with another nonce 438 stale-nonce, which comes
 * with a fresh nonce so the client retries once instead of treating its credential as wrong (RFC
 * 5389 section 10.2.2); with an unknown or expired credential 401 unauthorized, and with a wrong
 * MESSAGE-INTEGRITY 401 bad-message-integrity.
 */
static const char *authentication_failure(const uint8_t *packet, size_t len, char username[192], int *code)
{
    stun_attribute user;
    stun_attribute realm;
    stun_attribute nonce;
    stun_attribute integrity;
    const char *current = st_turn_auth_nonce();
    *code = 401;
    if (find_attribute(packet, len, ATTR_USERNAME, &user) != 0 || user.length == 0U || user.length >= 192U
        || find_attribute(packet, len, ATTR_REALM, &realm) != 0
        || realm.length != strlen(st_turn_auth_realm())
        || memcmp(realm.value, st_turn_auth_realm(), realm.length) != 0
        || find_attribute(packet, len, ATTR_NONCE, &nonce) != 0 || nonce.length == 0U) return "unauthorized";
    if (nonce.length != strlen(current) || memcmp(nonce.value, current, nonce.length) != 0) {
        *code = 438;
        return "stale-nonce";
    }
    memcpy(username, user.value, user.length);
    username[user.length] = '\0';
    uint8_t key[16];
    if (st_turn_auth_long_term_key(username, key) != 0) return "unauthorized";
    if (find_attribute(packet, len, ATTR_MESSAGE_INTEGRITY, &integrity) != 0
        || integrity.length != ST_SHA1_LEN) return "bad-message-integrity";
    uint8_t *copy = (uint8_t *)malloc(integrity.offset);
    if (copy == NULL) return "bad-message-integrity";
    memcpy(copy, packet, integrity.offset);
    write_u16(copy + 2U, (uint16_t)(integrity.offset + 24U - STUN_HEADER_SIZE));
    uint8_t mac[ST_SHA1_LEN];
    st_hmac_sha1(key, sizeof(key), copy, integrity.offset, mac);
    free(copy);
    return st_constant_time_eq(mac, integrity.value, sizeof(mac)) ? NULL : "bad-message-integrity";
}

/* Java errorType: requests of other methods are answered as Binding errors. */
static uint16_t stun_error_type(uint16_t request_type)
{
    switch (request_type) {
        case TURN_ALLOCATE_REQUEST: return 0x0113U;
        case TURN_REFRESH_REQUEST: return 0x0114U;
        case TURN_CREATE_PERMISSION_REQUEST: return 0x0118U;
        case TURN_CHANNEL_BIND_REQUEST: return 0x0119U;
        default: return 0x0111U;
    }
}

/* An error answer with ERROR-CODE only, for Binding (which adds its own attributes after it). */
static int builder_error_code(stun_builder *builder,
                              uint16_t request_type,
                              const uint8_t transaction[12],
                              int code,
                              const char *reason)
{
    builder_start(builder, stun_error_type(request_type), transaction);
    uint8_t value[256] = {0};
    size_t reason_len = strlen(reason);
    if (reason_len > sizeof(value) - 4U) reason_len = sizeof(value) - 4U;
    value[2] = (uint8_t)(code / 100);
    value[3] = (uint8_t)(code % 100);
    memcpy(value + 4U, reason, reason_len);
    return builder_attr(builder, ATTR_ERROR_CODE, value, reason_len + 4U);
}

/*
 * A TURN error answer as Java sendError builds it: ERROR-CODE with Java's (and Go's) reason
 * phrase, SOFTWARE, and for a challenge the realm and the current nonce.
 */
static int builder_error(stun_builder *builder,
                         uint16_t request_type,
                         const uint8_t transaction[12],
                         int code,
                         const char *reason,
                         int add_challenge)
{
    if (builder_error_code(builder, request_type, transaction, code, reason) != 0
        || builder_attr(builder, ATTR_SOFTWARE, STUN_SOFTWARE, strlen(STUN_SOFTWARE)) != 0) return -1;
    if (add_challenge && (builder_attr(builder, ATTR_REALM, st_turn_auth_realm(), strlen(st_turn_auth_realm())) != 0
                          || builder_attr(builder, ATTR_NONCE, st_turn_auth_nonce(), strlen(st_turn_auth_nonce())) != 0)) return -1;
    return 0;
}

/*
 * Java configureUdpSocket, before every listening and relay socket is bound: buffers of at least
 * one maximal datagram so bursts on the main port and the relays are not dropped by the kernel,
 * and the traffic class. A platform that refuses either keeps its default and the socket is used.
 */
static void configure_udp_socket(const st_stun_turn_server *server, int fd)
{
    if (server->udp_receive_buffer > 0) {
        int size = server->udp_receive_buffer < 65507 ? 65507 : server->udp_receive_buffer;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) != 0) {
            fprintf(stderr, "[peer-mesh] unable to configure UDP receive buffer: %s\n", strerror(errno));
        }
    }
    if (server->udp_send_buffer > 0) {
        int size = server->udp_send_buffer < 65507 ? 65507 : server->udp_send_buffer;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) != 0) {
            fprintf(stderr, "[peer-mesh] unable to configure UDP send buffer: %s\n", strerror(errno));
        }
    }
    if (server->udp_traffic_class >= 0 && server->udp_traffic_class <= 255) {
        int traffic_class = server->udp_traffic_class;
        (void)setsockopt(fd, IPPROTO_IP, IP_TOS, &traffic_class, sizeof(traffic_class));
    }
}

/*
 * reuse_address is for the listening endpoints only. A relay socket must fail to bind a port
 * another relay holds: on Linux SO_REUSEADDR lets two UDP sockets share one, and the second
 * allocation would then take the first one's datagrams (Java's DatagramSocket does not set it).
 */
static int create_udp_socket(const st_stun_turn_server *server,
                             const char *bind_address,
                             int port,
                             int reuse_address,
                             int *actual_port)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_address, &address.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    if (fd >= 0) configure_udp_socket(server, fd);
    if (fd < 0
        || (reuse_address && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0)
        || bind(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    socklen_t len = sizeof(address);
    if (getsockname(fd, (struct sockaddr *)&address, &len) != 0) {
        close(fd);
        return -1;
    }
    *actual_port = ntohs(address.sin_port);
    return fd;
}

static stun_server_endpoint *find_stun_endpoint(st_stun_turn_server *server, int fd)
{
    for (size_t i = 0; i < server->endpoint_count; ++i) {
        if (server->endpoints[i].fd == fd) return &server->endpoints[i];
    }
    return NULL;
}

static stun_server_endpoint *find_stun_endpoint_slots(st_stun_turn_server *server,
                                                       int address_slot,
                                                       int port_slot)
{
    for (size_t i = 0; i < server->endpoint_count; ++i) {
        if (server->endpoints[i].address_slot == address_slot
            && server->endpoints[i].port_slot == port_slot) return &server->endpoints[i];
    }
    return NULL;
}

static int add_stun_endpoint(st_stun_turn_server *server,
                             const char *bind_address,
                             const char *advertised_address,
                             int port,
                             int address_slot,
                             int port_slot)
{
    if (server->endpoint_count >= STUN_MAX_ENDPOINTS) return -1;
    int actual_port = 0;
    int fd = create_udp_socket(server, bind_address, port, 1, &actual_port);
    if (fd < 0) return -1;
    stun_server_endpoint *endpoint = &server->endpoints[server->endpoint_count];
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->fd = fd;
    endpoint->address_slot = address_slot;
    endpoint->port_slot = port_slot;
    struct sockaddr_in *advertised = (struct sockaddr_in *)&endpoint->advertised;
    advertised->sin_family = AF_INET;
    advertised->sin_port = htons((uint16_t)actual_port);
    /* Java resolvePrimaryAdvertisedAddress: the public address, a name resolved (one that does not
     * resolve keeps the STUN/TURN server from starting, as in Java), else the bind address unless
     * it is the wildcard, else this host's address. */
    if (advertised_address != NULL && *advertised_address != '\0') {
        if (resolve_ipv4(advertised_address, &advertised->sin_addr) != 0) {
            fprintf(stderr, "[peer-mesh] cannot resolve the advertised STUN/TURN address %s\n", advertised_address);
            close(fd);
            return -1;
        }
    } else if (bind_address == NULL || inet_pton(AF_INET, bind_address, &advertised->sin_addr) != 1
               || advertised->sin_addr.s_addr == htonl(INADDR_ANY)) {
        local_host_address(&advertised->sin_addr);
    }
    endpoint->advertised_len = sizeof(*advertised);
    ++server->endpoint_count;
    return actual_port;
}

static void close_stun_endpoints(st_stun_turn_server *server, int use_shutdown)
{
    for (size_t i = 0; i < server->endpoint_count; ++i) {
        if (server->endpoints[i].fd < 0) continue;
        if (use_shutdown) shutdown(server->endpoints[i].fd, SHUT_RDWR);
        else {
            close(server->endpoints[i].fd);
            server->endpoints[i].fd = -1;
        }
    }
    if (!use_shutdown) server->endpoint_count = 0U;
}

/*
 * An allocation whose lifetime has passed is gone even before the periodic sweep closes it, so a
 * request that arrives in between is answered like Java and Go do (437) instead of reviving it.
 */
static turn_allocation *find_allocation_by_client(st_stun_turn_server *server,
                                                   const struct sockaddr_storage *client)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < server->allocation_count; ++i) {
        turn_allocation *allocation = server->allocations[i];
        if (allocation->used && allocation->expires_at > now
            && sockaddr_equal(&allocation->client, client, 1)) return allocation;
    }
    return NULL;
}

static turn_allocation *find_allocation_by_relay(st_stun_turn_server *server,
                                                  const struct sockaddr_storage *relay)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < server->allocation_count; ++i) {
        turn_allocation *allocation = server->allocations[i];
        if (allocation->used && allocation->expires_at > now
            && sockaddr_equal(&allocation->relay, relay, 1)) return allocation;
    }
    return NULL;
}

static long long username_client_id(const char *username)
{
    return st_turn_auth_peer_mesh_client_id(username);
}

static int username_is_general(const char *username)
{
    return st_turn_auth_is_general_relay_subject(username);
}

static long long allocation_client_id(const turn_allocation *allocation)
{
    return allocation == NULL ? 0 : username_client_id(allocation->username);
}

static int allocation_is_general(const turn_allocation *allocation)
{
    return allocation != NULL && username_is_general(allocation->username);
}

/*
 * Java Allocation.matchesClient and Go's ClientID check: Refresh, CreatePermission and ChannelBind
 * act on an allocation only when they are signed by the identity that created it. Otherwise a
 * general relay credential could install permissions on a Peer Mesh allocation, which the
 * destination policy exempts, and either identity could delete the other's allocation.
 */
static int allocation_matches_identity(const turn_allocation *allocation, const char *username)
{
    return allocation != NULL
        && allocation_is_general(allocation) == username_is_general(username)
        && allocation_client_id(allocation) == username_client_id(username);
}

static void close_allocation(turn_allocation *allocation);
static void format_endpoint(const struct sockaddr_storage *address, char *out, size_t out_len);

/* General relay allocations other than exclude, and how many of them come from client's address. */
static int count_general_relays(st_stun_turn_server *server,
                                const struct sockaddr_storage *client,
                                const turn_allocation *exclude,
                                int *same_address)
{
    int total = 0;
    *same_address = 0;
    for (size_t i = 0; i < server->allocation_count; ++i) {
        turn_allocation *candidate = server->allocations[i];
        if (!candidate->used || candidate == exclude || !allocation_is_general(candidate)) continue;
        ++total;
        if (client != NULL && sockaddr_equal(&candidate->client, client, 0)) ++*same_address;
    }
    return total;
}

/*
 * Java generalRelayQuotaRejection: NULL when a general relay allocation is admitted, otherwise the
 * reason, which the audit line and the 486 carry. exclude is the allocation of the same endpoint
 * that this one replaces, so a client re-allocating is not refused for the room it holds itself.
 */
static const char *general_relay_quota_rejection(st_stun_turn_server *server,
                                                 const struct sockaddr_storage *client,
                                                 const turn_allocation *exclude)
{
    if (server->general_relay_max_allocations <= 0) return "general-relay-disabled";
    int same_address = 0;
    if (count_general_relays(server, client, exclude, &same_address) >= server->general_relay_max_allocations) {
        return "general-relay-allocation-quota";
    }
    if (server->general_relay_max_allocations_per_address > 0
        && same_address >= server->general_relay_max_allocations_per_address) return "general-relay-address-quota";
    return NULL;
}

/*
 * Java allowGeneralRelayTraffic: a general relay allocation that has relayed more than its byte
 * quota in both directions is closed (not throttled), with an audit line written once, as it closes.
 */
static int allow_general_relay_traffic(st_stun_turn_server *server,
                                       turn_allocation *allocation,
                                       size_t bytes)
{
    if (!allocation_is_general(allocation)) return 1;
    int overflow = bytes > ULLONG_MAX - allocation->relayed_bytes;
    allocation->relayed_bytes = overflow ? ULLONG_MAX : allocation->relayed_bytes + bytes;
    if (overflow || (server->general_relay_max_bytes > 0
                     && allocation->relayed_bytes > (unsigned long long)server->general_relay_max_bytes)) {
        char client[INET6_ADDRSTRLEN + 16];
        format_endpoint(&allocation->client, client, sizeof(client));
        fprintf(stderr, "[peer-mesh][audit] general TURN byte quota exhausted, closing allocation: "
                "client=%s, bytes=%llu\n", client, allocation->relayed_bytes);
        close_allocation(allocation);
        return 0;
    }
    return 1;
}

static uint64_t read_u64(const uint8_t *data)
{
    return ((uint64_t)read_u32(data) << 32U) | read_u32(data + 4U);
}

static long long monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

static long long saturated_add(long long current, long long delta)
{
    return delta > 0 && current > LLONG_MAX - delta ? LLONG_MAX : current + delta;
}

/* Caller holds relay_lock. */
static relay_session *find_relay_session(st_stun_turn_server *server, const char *database_path,
                                         long long session_id)
{
    for (size_t i = 0; i < server->relay_session_count; ++i) {
        relay_session *entry = &server->relay_sessions[i];
        if (entry->session_id == session_id && strcmp(entry->database_path, database_path) == 0) return entry;
    }
    return NULL;
}

/* Caller holds relay_lock. */
static relay_session *add_relay_session(st_stun_turn_server *server, const char *database_path,
                                        long long session_id)
{
    if (server->relay_session_count == server->relay_session_capacity) {
        size_t capacity = server->relay_session_capacity == 0U ? 16U : server->relay_session_capacity * 2U;
        if (capacity > SIZE_MAX / sizeof(*server->relay_sessions)) return NULL;
        relay_session *grown = (relay_session *)realloc(server->relay_sessions, capacity * sizeof(*grown));
        if (grown == NULL) return NULL;
        server->relay_sessions = grown;
        server->relay_session_capacity = capacity;
    }
    char *path = strdup(database_path);
    if (path == NULL) return NULL;
    relay_session *entry = &server->relay_sessions[server->relay_session_count++];
    memset(entry, 0, sizeof(*entry));
    entry->database_path = path;
    entry->session_id = session_id;
    return entry;
}

/* Caller holds relay_lock. Whether session_id was withdrawn after the count `since` was noted. */
static int withdrawn_since(const st_stun_turn_server *server, unsigned long long since, long long session_id)
{
    if (server->withdrawals - since > RELAY_WITHDRAWAL_RING) return 1;
    for (unsigned long long seq = since; seq < server->withdrawals; ++seq) {
        if (server->withdrawn_sessions[seq % RELAY_WITHDRAWAL_RING] == session_id) return 1;
    }
    return 0;
}

/* Every running server, for the storage's session listener; normally there is one. */
static pthread_mutex_t live_servers_lock = PTHREAD_MUTEX_INITIALIZER;
static st_stun_turn_server *live_servers;

/*
 * The storage's listener (st_storage_set_peer_mesh_session_listener): a session was closed or
 * given a new status, so its cached grant is read again on its next frame, as Java drops that
 * session's relayAuthorizationCache entry. Grants of other sessions are untouched.
 */
static void withdraw_relay_grant(long long session_id)
{
    pthread_mutex_lock(&live_servers_lock);
    for (st_stun_turn_server *server = live_servers; server != NULL; server = server->next_live) {
        pthread_mutex_lock(&server->relay_lock);
        server->withdrawn_sessions[server->withdrawals % RELAY_WITHDRAWAL_RING] = session_id;
        ++server->withdrawals;
        for (size_t i = 0; i < server->relay_session_count; ++i) {
            if (server->relay_sessions[i].session_id == session_id) server->relay_sessions[i].granted = 0;
        }
        pthread_mutex_unlock(&server->relay_lock);
    }
    pthread_mutex_unlock(&live_servers_lock);
}

static void set_server_live(st_stun_turn_server *server, int live)
{
    pthread_mutex_lock(&live_servers_lock);
    if (live && !server->live) {
        server->next_live = live_servers;
        live_servers = server;
        st_storage_set_peer_mesh_session_listener(withdraw_relay_grant);
    } else if (!live && server->live) {
        st_stun_turn_server **link = &live_servers;
        while (*link != NULL && *link != server) link = &(*link)->next_live;
        if (*link == server) *link = server->next_live;
    }
    server->live = live;
    pthread_mutex_unlock(&live_servers_lock);
}

/* Java RelayAuthorization.matches: 0/0 is TURN authentication off, where only the session counts. */
static int relay_grant_matches(const st_storage_peer_mesh_relay_grant *grant, long long from, long long to)
{
    return (from <= 0 && to <= 0)
        || (from == grant->source_client_id && to == grant->target_client_id)
        || (from == grant->target_client_id && to == grant->source_client_id);
}

/*
 * One SPM2 frame against its session, as Java PeerMeshService.authorizeRelayFrameForRelay does it.
 * A grant read in the last RELAY_GRANT_TTL_MS answers from memory while the session has neither
 * expired nor changed, and an outbound frame's bytes join the session's pending batch, so the
 * STUN/TURN thread does not touch the database for it. Otherwise the session is read (the first
 * frame activates a NEGOTIATING session on the relay path) and its grant kept for the next frames.
 */
static int authorize_relay_frame(st_stun_turn_server *server,
                                 const char *database_path,
                                 long long session_id,
                                 long long from_client_id,
                                 long long to_client_id,
                                 long long bytes,
                                 int account_traffic)
{
    int identified = from_client_id > 0 && to_client_id > 0;
    if ((!identified && (from_client_id != 0 || to_client_id != 0))
        || (identified && from_client_id == to_client_id)) return 0;
    long long now_ms = monotonic_ms();
    char now[ST_INSTANT_CAPACITY];
    int have_now = st_instant_now(now) == 0;
    pthread_mutex_lock(&server->relay_lock);
    relay_session *entry = find_relay_session(server, database_path, session_id);
    if (entry != NULL && entry->granted && entry->grant_expires_ms > now_ms
        && (entry->grant.expires_at[0] == '\0' || (have_now && strcmp(entry->grant.expires_at, now) > 0))) {
        int allowed = relay_grant_matches(&entry->grant, from_client_id, to_client_id);
        if (allowed && account_traffic) entry->pending_bytes = saturated_add(entry->pending_bytes, bytes);
        pthread_mutex_unlock(&server->relay_lock);
        return allowed;
    }
    /* Noted before the session is read: a withdrawal committed meanwhile must not be cached over. */
    unsigned long long withdrawals = server->withdrawals;
    pthread_mutex_unlock(&server->relay_lock);
    st_storage_peer_mesh_relay_grant grant;
    int allowed = st_storage_authorize_peer_mesh_relay_grant(database_path, session_id, from_client_id,
                                                             to_client_id, &grant) == 1;
    pthread_mutex_lock(&server->relay_lock);
    entry = find_relay_session(server, database_path, session_id);
    if (allowed && entry == NULL) entry = add_relay_session(server, database_path, session_id);
    if (allowed && entry != NULL) {
        entry->grant = grant;
        entry->granted = !withdrawn_since(server, withdrawals, session_id);
        entry->grant_expires_ms = now_ms + RELAY_GRANT_TTL_MS;
        if (account_traffic) entry->pending_bytes = saturated_add(entry->pending_bytes, bytes);
    } else if (allowed) {
        /* No memory to count it in: a frame that cannot be counted is not relayed. */
        allowed = 0;
    } else if (entry != NULL) {
        entry->granted = 0;
    }
    pthread_mutex_unlock(&server->relay_lock);
    return allowed;
}

void st_stun_turn_server_flush_relay_traffic(st_stun_turn_server *server)
{
    if (server == NULL || !server->sync_ready) return;
    pthread_mutex_lock(&server->flush_lock);
    /* Take the batch, then write it without holding up the hot path. Only a flush removes
     * entries, so the paths stay valid until the end of this one. */
    pthread_mutex_lock(&server->relay_lock);
    size_t pending = 0U;
    for (size_t i = 0; i < server->relay_session_count; ++i) pending += server->relay_sessions[i].pending_bytes > 0;
    relay_session *batch = pending == 0U ? NULL : (relay_session *)calloc(pending, sizeof(*batch));
    size_t batch_count = 0U;
    for (size_t i = 0; batch != NULL && i < server->relay_session_count; ++i) {
        relay_session *entry = &server->relay_sessions[i];
        if (entry->pending_bytes <= 0) continue;
        batch[batch_count++] = *entry;
        entry->pending_bytes = 0;
    }
    pthread_mutex_unlock(&server->relay_lock);
    for (size_t i = 0; i < batch_count; ++i) {
        int result = st_storage_record_peer_mesh_relay_traffic(batch[i].database_path, batch[i].session_id,
                                                               batch[i].pending_bytes);
        if (result < 0) {
            fprintf(stderr, "[peer-mesh] relay traffic flush failed: session=%lld, bytes=%lld\n",
                    batch[i].session_id, batch[i].pending_bytes);
        }
        pthread_mutex_lock(&server->relay_lock);
        relay_session *entry = find_relay_session(server, batch[i].database_path, batch[i].session_id);
        if (entry != NULL && result < 0) {
            /* Java restoreRelayTrafficBatch: kept for the next batch. */
            entry->pending_bytes = saturated_add(entry->pending_bytes, batch[i].pending_bytes);
        } else if (entry != NULL && result > 0) {
            /* Closed or gone: the next frame reads the session again. */
            entry->granted = 0;
            if (result == 2) entry->pending_bytes = 0;
        }
        pthread_mutex_unlock(&server->relay_lock);
    }
    free(batch);
    /* Sessions that can no longer answer a frame and have nothing waiting are forgotten. */
    long long now_ms = monotonic_ms();
    pthread_mutex_lock(&server->relay_lock);
    size_t kept = 0U;
    for (size_t i = 0; i < server->relay_session_count; ++i) {
        relay_session *entry = &server->relay_sessions[i];
        if (entry->pending_bytes <= 0 && (!entry->granted || entry->grant_expires_ms <= now_ms)) {
            free(entry->database_path);
        } else {
            server->relay_sessions[kept++] = *entry;
        }
    }
    server->relay_session_count = kept;
    pthread_mutex_unlock(&server->relay_lock);
    pthread_mutex_unlock(&server->flush_lock);
}

/* Writes the pending relay bytes every flush_interval_ms until the server stops. */
static void *relay_flush_thread(void *raw)
{
    st_stun_turn_server *server = (st_stun_turn_server *)raw;
    pthread_mutex_lock(&server->relay_lock);
    while (!server->flush_stopping) {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += server->flush_interval_ms / 1000L;
        deadline.tv_nsec += (server->flush_interval_ms % 1000L) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        int waited = 0;
        while (!server->flush_stopping && waited != ETIMEDOUT) {
            waited = pthread_cond_timedwait(&server->relay_wake, &server->relay_lock, &deadline);
        }
        if (server->flush_stopping) break;
        pthread_mutex_unlock(&server->relay_lock);
        st_stun_turn_server_flush_relay_traffic(server);
        pthread_mutex_lock(&server->relay_lock);
    }
    pthread_mutex_unlock(&server->relay_lock);
    return NULL;
}

/*
 * identified is whether TURN authentication is on. With it off an allocation carries no client id
 * (the credential has none), so, as in Java StunTurnServer.authorizeRelayPayload, both sides go to
 * the session check as 0 and only the session itself is checked: insisting on ids there would
 * drop every Peer Mesh datagram, probes included, and leave the relay unusable.
 */
static int authorize_relay_payload(st_stun_turn_server *server,
                                   const uint8_t *payload,
                                   size_t payload_len,
                                   const turn_allocation *source,
                                   const turn_allocation *target,
                                   int account_traffic,
                                   int identified)
{
    if (allocation_is_general(source) || allocation_is_general(target)) return 1;
    if (source == NULL || target == NULL) return 0;
    long long source_id = identified ? allocation_client_id(source) : 0;
    long long target_id = identified ? allocation_client_id(target) : 0;
    if (identified && (source_id <= 0 || target_id <= 0)) return 0;
    /* The same database the control channel grants sessions in. Reading any other variable here
     * leaves Peer Mesh relaying with no session to check against, so every relayed datagram is
     * dropped while allocations, permissions and channel binds all still succeed. */
    const char *database_path = getenv("SPECUS_DATABASE_PATH");
    if (database_path == NULL || *database_path == '\0') return 0;
    if (payload_len >= 36U && read_u32(payload) == 0x53504d32U) {
        long long session_id = (long long)read_u64(payload + 4U);
        long long sequence = (long long)read_u64(payload + 12U);
        return session_id > 0 && sequence > 0
            && authorize_relay_frame(server, database_path, session_id, source_id, target_id,
                                     (long long)payload_len, account_traffic);
    }
    if (payload_len < 2U || payload_len > 2048U || payload[0] != '{'
        || payload[payload_len - 1U] != '}') return 0;
    char *json = (char *)malloc(payload_len + 1U);
    if (json == NULL) return 0;
    memcpy(json, payload, payload_len);
    json[payload_len] = '\0';
    char *magic = st_json_get_top_level_string(json, "magic");
    char *type = st_json_get_top_level_string(json, "type");
    char *token = st_json_get_top_level_string(json, "token");
    long long session_id = 0;
    long long from_id = 0;
    long long to_id = 0;
    int valid = magic != NULL && strcmp(magic, "specus-peer-mesh") == 0
        && type != NULL && (strcmp(type, "check") == 0 || strcmp(type, "check-response") == 0)
        && st_json_get_i64(json, "sessionId", &session_id) == 0
        && st_json_get_i64(json, "fromClientId", &from_id) == 0
        && st_json_get_i64(json, "toClientId", &to_id) == 0
        && (!identified || (from_id == source_id && to_id == target_id))
        && st_storage_verify_peer_mesh_probe(database_path, session_id, from_id, to_id, token) == 1;
    free(json); free(magic); free(type); free(token);
    return valid;
}

static void close_allocation(turn_allocation *allocation)
{
    if (allocation->relay_fd >= 0) close(allocation->relay_fd);
    memset(allocation, 0, sizeof(*allocation));
    allocation->relay_fd = -1;
}

static int ipv4_peer_relayable(uint32_t ip)
{
    return !((ip & 0xff000000U) == 0x7f000000U || (ip & 0xff000000U) == 0x0a000000U
             || (ip & 0xfff00000U) == 0xac100000U || (ip & 0xffff0000U) == 0xc0a80000U
             || (ip & 0xffff0000U) == 0xa9fe0000U || (ip & 0xf0000000U) == 0xe0000000U
             || ip == 0U);
}

/*
 * General relay destinations come from the browser, so only public unicast peers are allowed, as
 * in Java isRelayableDestination: IPv6 unspecified, loopback, link-local, site-local, multicast
 * and ULA (fc00::/7) are refused like their IPv4 counterparts, an IPv4-mapped address is judged
 * as the IPv4 address it carries, and port 0 is never a valid peer.
 */
static int peer_address_allowed(st_stun_turn_server *server,
                                const struct sockaddr_storage *peer)
{
    if (server->allow_private_peers) return 1;
    if (peer->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)peer;
        return ipv4->sin_port != 0 && ipv4_peer_relayable(ntohl(ipv4->sin_addr.s_addr));
    }
    if (peer->ss_family != AF_INET6) return 0;
    const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)peer;
    const struct in6_addr *address = &ipv6->sin6_addr;
    if (ipv6->sin6_port == 0) return 0;
    if (IN6_IS_ADDR_V4MAPPED(address)) return ipv4_peer_relayable(read_u32(address->s6_addr + 12U));
    return !IN6_IS_ADDR_UNSPECIFIED(address) && !IN6_IS_ADDR_LOOPBACK(address)
        && !IN6_IS_ADDR_LINKLOCAL(address) && !IN6_IS_ADDR_SITELOCAL(address)
        && !IN6_IS_ADDR_MULTICAST(address) && (address->s6_addr[0] & 0xfeU) != 0xfcU;
}

/*
 * Every XOR-PEER-ADDRESS of a request: RFC 5766 section 9.1 lets one CreatePermission name several
 * peers, and Java and Go install (and policy-check) all of them. Attributes after
 * MESSAGE-INTEGRITY are not covered by it and are ignored (RFC 5389 section 15.4). A request with
 * no peer, an undecodable peer or more peers than one allocation can hold is malformed.
 */
static int collect_peer_addresses(const uint8_t *packet,
                                  size_t len,
                                  struct sockaddr_storage *peers,
                                  socklen_t *peer_lens,
                                  size_t capacity,
                                  size_t *count)
{
    *count = 0U;
    if (!stun_packet_valid(packet, len)) return -1;
    size_t end = STUN_HEADER_SIZE + read_u16(packet + 2U);
    for (size_t offset = STUN_HEADER_SIZE; offset + 4U <= end;) {
        stun_attribute attribute;
        attribute.type = read_u16(packet + offset);
        attribute.length = read_u16(packet + offset + 2U);
        attribute.value = packet + offset + 4U;
        attribute.offset = offset;
        if (offset + 4U + attribute.length > end) return -1;
        if (attribute.type == ATTR_MESSAGE_INTEGRITY) break;
        if (attribute.type == ATTR_XOR_PEER_ADDRESS) {
            if (*count >= capacity
                || decode_xor_address(&attribute, packet + 8U, &peers[*count], &peer_lens[*count]) != 0) return -1;
            ++*count;
        }
        offset += 4U + ((attribute.length + 3U) & ~3U);
    }
    return *count > 0U ? 0 : -1;
}

static void format_endpoint(const struct sockaddr_storage *address, char *out, size_t out_len)
{
    char host[INET6_ADDRSTRLEN] = "?";
    unsigned port = 0U;
    if (address->ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        (void)inet_ntop(AF_INET, &ipv4->sin_addr, host, sizeof(host));
        port = ntohs(ipv4->sin_port);
        snprintf(out, out_len, "%s:%u", host, port);
        return;
    }
    if (address->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        (void)inet_ntop(AF_INET6, &ipv6->sin6_addr, host, sizeof(host));
        port = ntohs(ipv6->sin6_port);
    }
    snprintf(out, out_len, "[%s]:%u", host, port);
}

/* The audit line Java and Go write when the destination policy refuses a general relay peer. */
static void log_refused_peer(uint16_t message_type,
                             const struct sockaddr_storage *client,
                             const struct sockaddr_storage *peer)
{
    char client_text[INET6_ADDRSTRLEN + 16];
    char peer_text[INET6_ADDRSTRLEN + 16];
    format_endpoint(client, client_text, sizeof(client_text));
    format_endpoint(peer, peer_text, sizeof(peer_text));
    fprintf(stderr, "[peer-mesh][audit] general TURN %s refused: client=%s, peer=%s\n",
            message_type == TURN_CHANNEL_BIND_REQUEST ? "channel bind" : "permission",
            client_text, peer_text);
}

static turn_allocation *create_allocation(st_stun_turn_server *server,
                                           const struct sockaddr_storage *client,
                                           socklen_t client_len,
                                           const char *username)
{
    if (server->allocation_count == server->allocation_capacity) {
        size_t capacity = server->allocation_capacity == 0U ? 16U : server->allocation_capacity * 2U;
        if (capacity > SIZE_MAX / sizeof(*server->allocations)) return NULL;
        turn_allocation **grown = (turn_allocation **)realloc(server->allocations,
                                                              capacity * sizeof(*grown));
        if (grown == NULL) return NULL;
        server->allocations = grown;
        server->allocation_capacity = capacity;
    }
    const char *bind_address = getenv("SPECUS_PEER_MESH_BIND_ADDRESS");
    if (bind_address == NULL || *bind_address == '\0') bind_address = "0.0.0.0";
    int relay_fd = -1;
    int relay_port = 0;
    /* Java bindRelaySocket: the first port is random, so the next relay port cannot be predicted,
     * and at most clamp(range, 16, 128) ports are tried, so a crowded range cannot hold this thread
     * in thousands of bind calls. */
    int range = server->relay_max_port - server->relay_min_port + 1;
    int attempts = range < 16 ? 16 : (range > 128 ? 128 : range);
    unsigned int random = 0U;
    if (RAND_bytes((unsigned char *)&random, (int)sizeof(random)) != 1) random = (unsigned int)time(NULL);
    int first = (int)(random % (unsigned int)range);
    for (int i = 0; i < attempts && relay_fd < 0; ++i) {
        relay_fd = create_udp_socket(server, bind_address, server->relay_min_port + (first + i) % range, 0,
                                     &relay_port);
    }
    if (relay_fd < 0) return NULL;
    turn_allocation *slot = (turn_allocation *)calloc(1, sizeof(*slot));
    if (slot == NULL) {
        close(relay_fd);
        return NULL;
    }
    server->allocations[server->allocation_count++] = slot;
    slot->used = 1;
    slot->relay_fd = relay_fd;
    slot->client = *client;
    slot->client_len = client_len;
    slot->expires_at = time(NULL) + server->allocation_ttl;
    snprintf(slot->username, sizeof(slot->username), "%s", username == NULL ? "" : username);
    struct sockaddr_in *relay = (struct sockaddr_in *)&slot->relay;
    relay->sin_family = AF_INET;
    relay->sin_port = htons((uint16_t)relay_port);
    relay->sin_addr = server->relay_address;
    slot->relay_len = sizeof(*relay);
    /* Java createAllocation logs every allocation at info. */
    char client_text[INET6_ADDRSTRLEN + 16];
    char relay_text[INET6_ADDRSTRLEN + 16];
    format_endpoint(client, client_text, sizeof(client_text));
    format_endpoint(&slot->relay, relay_text, sizeof(relay_text));
    printf("[peer-mesh] TURN allocation created: client=%s, relay=%s\n", client_text, relay_text);
    fflush(stdout);
    return slot;
}

static int allocation_has_permission(turn_allocation *allocation,
                                     const struct sockaddr_storage *peer)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < TURN_MAX_PERMISSIONS; ++i) {
        if (allocation->permissions[i].used && allocation->permissions[i].expires_at > now
            && sockaddr_equal(&allocation->permissions[i].address, peer, 0)) return 1;
    }
    return 0;
}

/*
 * Where a permission for this peer's address goes: its own entry, else one that is free or has
 * expired. Java keeps permissions in an unbounded map and drops expired ones; here an allocation
 * holds TURN_MAX_PERMISSIONS live ones, and NULL means all of them are live for other peers.
 */
static turn_permission *permission_slot(turn_allocation *allocation, const struct sockaddr_storage *peer)
{
    time_t now = time(NULL);
    turn_permission *slot = NULL;
    for (size_t i = 0; i < TURN_MAX_PERMISSIONS; ++i) {
        turn_permission *candidate = &allocation->permissions[i];
        if (candidate->used && sockaddr_equal(&candidate->address, peer, 0)) return candidate;
        if (slot == NULL && (!candidate->used || candidate->expires_at <= now)) slot = candidate;
    }
    return slot;
}

static int add_permission(turn_allocation *allocation,
                          const struct sockaddr_storage *peer,
                          socklen_t peer_len,
                          int ttl)
{
    turn_permission *slot = permission_slot(allocation, peer);
    if (slot == NULL) return -1;
    slot->used = 1;
    slot->address = *peer;
    slot->address_len = peer_len;
    slot->expires_at = time(NULL) + ttl;
    return 0;
}

static turn_channel *find_channel_by_number(turn_allocation *allocation, uint16_t number)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < TURN_MAX_CHANNELS; ++i) {
        if (allocation->channels[i].used && allocation->channels[i].expires_at > now
            && allocation->channels[i].number == number) return &allocation->channels[i];
    }
    return NULL;
}

static turn_channel *find_channel_by_peer(turn_allocation *allocation,
                                          const struct sockaddr_storage *peer)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < TURN_MAX_CHANNELS; ++i) {
        if (allocation->channels[i].used && allocation->channels[i].expires_at > now
            && sockaddr_equal(&allocation->channels[i].peer, peer, 1)) return &allocation->channels[i];
    }
    return NULL;
}

static int bind_channel(turn_allocation *allocation,
                        uint16_t number,
                        const struct sockaddr_storage *peer,
                        socklen_t peer_len,
                        int ttl)
{
    turn_channel *slot = find_channel_by_number(allocation, number);
    /* RFC 5766 section 11.2: a live channel number may only be refreshed for the same peer (-2). */
    if (slot != NULL && !sockaddr_equal(&slot->peer, peer, 1)) return -2;
    /* Java channelBind: the peer leaves the number it was bound to before, so its data comes in
     * on the new one and the old number is free. Expired bindings give their entries back. */
    time_t now = time(NULL);
    for (size_t i = 0; i < TURN_MAX_CHANNELS; ++i) {
        turn_channel *other = &allocation->channels[i];
        if (other->used && other != slot && (other->expires_at <= now || sockaddr_equal(&other->peer, peer, 1))) {
            other->used = 0;
        }
    }
    for (size_t i = 0; slot == NULL && i < TURN_MAX_CHANNELS; ++i) {
        if (!allocation->channels[i].used) slot = &allocation->channels[i];
    }
    if (slot == NULL) return -1;
    slot->used = 1;
    slot->number = number;
    slot->peer = *peer;
    slot->peer_len = peer_len;
    slot->expires_at = time(NULL) + ttl;
    return 0;
}

static int send_builder(int fd,
                        const stun_builder *builder,
                        const struct sockaddr_storage *target,
                        socklen_t target_len)
{
    return sendto(fd, builder->data, builder->len, 0,
                  (const struct sockaddr *)target, target_len) == (ssize_t)builder->len ? 0 : -1;
}

static int authenticate_request(st_stun_turn_server *server,
                                int fd,
                                const uint8_t *packet,
                                size_t len,
                                const struct sockaddr_storage *client,
                                socklen_t client_len,
                                char username[192])
{
    if (!server->auth_required) {
        username[0] = '\0';
        return 0;
    }
    int code = 0;
    const char *failure = authentication_failure(packet, len, username, &code);
    if (failure == NULL) return 0;
    stun_builder error;
    builder_error(&error, read_u16(packet), packet + 8U, code, failure, 1);
    send_builder(fd, &error, client, client_len);
    return -1;
}

/* Success answers carry SOFTWARE, and MESSAGE-INTEGRITY when the request was authenticated. */
static void finish_success(st_stun_turn_server *server, stun_builder *response, const char *username)
{
    (void)builder_attr(response, ATTR_SOFTWARE, STUN_SOFTWARE, strlen(STUN_SOFTWARE));
    uint8_t key[16];
    if (server->auth_required && st_turn_auth_long_term_key(username, key) == 0) builder_integrity(response, key);
}

static void handle_binding(st_stun_turn_server *server,
                           int received_fd,
                           const uint8_t *packet,
                           size_t packet_len,
                           const struct sockaddr_storage *client,
                           socklen_t client_len)
{
    stun_server_endpoint *incoming = find_stun_endpoint(server, received_fd);
    if (incoming == NULL) return;
    struct sockaddr_storage response_target = *client;
    socklen_t response_target_len = client_len;
    stun_attribute response_port;
    stun_attribute padding;
    int has_response_port = find_attribute(packet, packet_len, ATTR_RESPONSE_PORT, &response_port) == 0;
    int has_padding = find_attribute(packet, packet_len, ATTR_PADDING, &padding) == 0;
    int error_code = 0;
    const char *error_reason = NULL;
    uint16_t unknown_attribute = 0U;
    if (has_response_port && has_padding) {
        error_code = 400;
        error_reason = "response-port-and-padding-are-mutually-exclusive";
    } else if (has_response_port) {
        if (response_port.length != 2U || read_u16(response_port.value) == 0U) {
            error_code = 400;
            error_reason = "invalid-response-port";
        } else if (response_target.ss_family == AF_INET) {
            ((struct sockaddr_in *)&response_target)->sin_port = htons(read_u16(response_port.value));
        } else if (response_target.ss_family == AF_INET6) {
            ((struct sockaddr_in6 *)&response_target)->sin6_port = htons(read_u16(response_port.value));
        }
    }
    uint32_t flags = 0U;
    stun_attribute change;
    if (error_code == 0 && find_attribute(packet, packet_len, ATTR_CHANGE_REQUEST, &change) == 0) {
        if (change.length != 4U) {
            error_code = 400;
            error_reason = "invalid-change-request";
        } else {
            flags = read_u32(change.value);
            if ((flags & ~0x06U) != 0U) {
                error_code = 400;
                error_reason = "invalid-change-request-flags";
            } else if (!server->rfc5780) {
                error_code = 420;
                error_reason = "unsupported-change-request";
                unknown_attribute = ATTR_CHANGE_REQUEST;
            }
        }
    }
    if (error_code != 0) {
        stun_builder error;
        builder_error_code(&error, STUN_BINDING_REQUEST, packet + 8U, error_code, error_reason);
        if (unknown_attribute != 0U) {
            uint8_t encoded[2];
            write_u16(encoded, unknown_attribute);
            (void)builder_attr(&error, ATTR_UNKNOWN_ATTRIBUTES, encoded, sizeof(encoded));
        }
        (void)builder_attr(&error, ATTR_SOFTWARE, STUN_SOFTWARE, strlen(STUN_SOFTWARE));
        (void)send_builder(received_fd, &error, &response_target, response_target_len);
        return;
    }
    int response_address_slot = incoming->address_slot ^ ((flags & 0x04U) != 0U);
    int response_port_slot = incoming->port_slot ^ ((flags & 0x02U) != 0U);
    stun_server_endpoint *response_endpoint = find_stun_endpoint_slots(
        server, response_address_slot, response_port_slot);
    if (response_endpoint == NULL) response_endpoint = incoming;
    stun_builder response;
    builder_start(&response, STUN_BINDING_SUCCESS, packet + 8U);
    (void)builder_address(&response, ATTR_MAPPED_ADDRESS, client, 0);
    (void)builder_address(&response, ATTR_XOR_MAPPED_ADDRESS, client, 1);
    (void)builder_attr(&response, ATTR_SOFTWARE, STUN_SOFTWARE, strlen(STUN_SOFTWARE));
    (void)builder_address(&response, ATTR_RESPONSE_ORIGIN, &response_endpoint->advertised,
                          server->rfc5780 ? 0 : 1);
    stun_server_endpoint *other = server->rfc5780
        ? find_stun_endpoint_slots(server, incoming->address_slot ^ 1, incoming->port_slot ^ 1)
        : find_stun_endpoint_slots(server, incoming->address_slot, incoming->port_slot ^ 1);
    if (other != NULL) {
        (void)builder_address(&response, ATTR_OTHER_ADDRESS, &other->advertised,
                              server->rfc5780 ? 0 : 1);
    }
    if (has_padding) {
        size_t bounded = packet_len > STUN_HEADER_SIZE ? packet_len - STUN_HEADER_SIZE : 0U;
        size_t padding_len = padding.length;
        if (padding_len > 1472U) padding_len = 1472U;
        if (padding_len > bounded) padding_len = bounded;
        uint8_t zeros[1472] = {0};
        (void)builder_attr(&response, ATTR_PADDING, zeros, padding_len);
    }
    (void)send_builder(response_endpoint->fd, &response, &response_target, response_target_len);
}

static void handle_allocate(st_stun_turn_server *server,
                            int fd,
                            const uint8_t *packet,
                            size_t len,
                            const struct sockaddr_storage *client,
                            socklen_t client_len)
{
    char username[192];
    if (authenticate_request(server, fd, packet, len, client, client_len, username) != 0) return;
    stun_attribute transport;
    if (find_attribute(packet, len, ATTR_REQUESTED_TRANSPORT, &transport) != 0
        || transport.length != 4U || transport.value[0] != 17U) {
        stun_builder error;
        builder_error(&error, TURN_ALLOCATE_REQUEST, packet + 8U, 442, "unsupported-transport", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    turn_allocation *allocation = find_allocation_by_client(server, client);
    const char *rejection = NULL;
    int general_relay = username_is_general(username);
    int created = 0;
    if (allocation == NULL || !allocation_matches_identity(allocation, username)) {
        /* A new allocation, or one replacing this endpoint's allocation of another identity. */
        if (general_relay) rejection = general_relay_quota_rejection(server, client, allocation);
        if (rejection == NULL) {
            if (allocation != NULL) close_allocation(allocation);
            allocation = create_allocation(server, client, client_len, username);
            created = allocation != NULL;
        } else {
            allocation = NULL;
        }
    }
    char client_text[INET6_ADDRSTRLEN + 16];
    format_endpoint(client, client_text, sizeof(client_text));
    if (rejection != NULL) {
        /* Java: the general relay follows the public ICE configuration, so a refusal must be traceable. */
        fprintf(stderr, "[peer-mesh][audit] general TURN allocation rejected: client=%s, reason=%s\n",
                client_text, rejection);
    }
    if (allocation == NULL) {
        /* 486 names the quota that refused it, as in Java; 508 (no relay port or socket free) is
         * C's own answer where Java fails the request without one. */
        stun_builder error;
        builder_error(&error, TURN_ALLOCATE_REQUEST, packet + 8U, rejection != NULL ? 486 : 508,
                      rejection != NULL ? rejection : "insufficient-capacity", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    if (created && general_relay) {
        int same_address = 0;
        char relay_text[INET6_ADDRSTRLEN + 16];
        format_endpoint(&allocation->relay, relay_text, sizeof(relay_text));
        printf("[peer-mesh][audit] general TURN allocation created: client=%s, relay=%s, active=%d\n",
               client_text, relay_text, count_general_relays(server, NULL, NULL, &same_address));
        fflush(stdout);
    }
    allocation->expires_at = time(NULL) + server->allocation_ttl;
    stun_builder response;
    builder_start(&response, TURN_ALLOCATE_SUCCESS, packet + 8U);
    builder_address(&response, ATTR_XOR_RELAYED_ADDRESS, &allocation->relay, 1);
    builder_address(&response, ATTR_XOR_MAPPED_ADDRESS, client, 1);
    builder_u32(&response, ATTR_LIFETIME, (uint32_t)server->allocation_ttl);
    finish_success(server, &response, username);
    send_builder(fd, &response, client, client_len);
}

static void handle_refresh(st_stun_turn_server *server,
                           int fd,
                           const uint8_t *packet,
                           size_t len,
                           const struct sockaddr_storage *client,
                           socklen_t client_len)
{
    char username[192];
    if (authenticate_request(server, fd, packet, len, client, client_len, username) != 0) return;
    turn_allocation *allocation = find_allocation_by_client(server, client);
    if (!allocation_matches_identity(allocation, username)) {
        stun_builder error;
        builder_error(&error, TURN_REFRESH_REQUEST, packet + 8U, 437, "allocation-mismatch", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    uint32_t lifetime = (uint32_t)server->allocation_ttl;
    stun_attribute requested;
    if (find_attribute(packet, len, ATTR_LIFETIME, &requested) == 0 && requested.length == 4U) {
        lifetime = read_u32(requested.value);
        if (lifetime > (uint32_t)server->allocation_ttl) lifetime = (uint32_t)server->allocation_ttl;
    }
    /* Java and Go answer the configured lifetime (0 for a deletion), whatever shorter one the
     * allocation is kept for. */
    stun_builder response;
    builder_start(&response, TURN_REFRESH_SUCCESS, packet + 8U);
    builder_u32(&response, ATTR_LIFETIME, lifetime == 0U ? 0U : (uint32_t)server->allocation_ttl);
    finish_success(server, &response, username);
    send_builder(fd, &response, client, client_len);
    if (lifetime == 0U) close_allocation(allocation);
    else allocation->expires_at = time(NULL) + lifetime;
}

static void handle_permission_or_channel(st_stun_turn_server *server,
                                         int fd,
                                         uint16_t message_type,
                                         const uint8_t *packet,
                                         size_t len,
                                         const struct sockaddr_storage *client,
                                         socklen_t client_len)
{
    char username[192];
    if (authenticate_request(server, fd, packet, len, client, client_len, username) != 0) return;
    turn_allocation *allocation = find_allocation_by_client(server, client);
    struct sockaddr_storage peers[TURN_MAX_PERMISSIONS];
    socklen_t peer_lens[TURN_MAX_PERMISSIONS];
    size_t peer_count = 0U;
    int channel_bind = message_type == TURN_CHANNEL_BIND_REQUEST;
    stun_attribute channel;
    uint16_t number = 0U;
    int refusal = 0;
    const char *refusal_reason = NULL;
    /* Java's order and reasons: identity, then a ChannelBind's number and peer, then the policy. */
    if (!allocation_matches_identity(allocation, username)) {
        refusal = 437;
        refusal_reason = "allocation-mismatch";
    } else if (collect_peer_addresses(packet, len, peers, peer_lens, TURN_MAX_PERMISSIONS, &peer_count) != 0
               || (channel_bind && (find_attribute(packet, len, ATTR_CHANNEL_NUMBER, &channel) != 0
                                    || channel.length != 4U || (number = read_u16(channel.value)) < 0x4000U
                                    || number > 0x7fffU))) {
        refusal = 400;
        refusal_reason = channel_bind ? "bad-channel-bind" : "bad-request";
    } else if (allocation_is_general(allocation)) {
        /* Every named peer is checked before any permission is installed, as Go does: one refused
         * peer refuses the whole request instead of letting the peers before it through. */
        for (size_t i = 0; i < peer_count && refusal == 0; ++i) {
            if (peer_address_allowed(server, &peers[i])) continue;
            log_refused_peer(message_type, client, &peers[i]);
            refusal = 403;
            refusal_reason = "forbidden-peer-address";
        }
    }
    if (refusal != 0) {
        stun_builder error;
        builder_error(&error, message_type, packet + 8U, refusal, refusal_reason, 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    int rc = 0;
    const char *failure = "bad-request";
    uint16_t success_type = TURN_CREATE_PERMISSION_SUCCESS;
    if (channel_bind) {
        /* The permission it installs must fit before the binding changes anything. */
        if (permission_slot(allocation, &peers[0]) == NULL) rc = -1;
        else rc = bind_channel(allocation, number, &peers[0], peer_lens[0], server->channel_ttl);
        if (rc == -2) failure = "channel-in-use";
        success_type = TURN_CHANNEL_BIND_SUCCESS;
        /* A ChannelBind binds the first peer it names; the others were only policy-checked. */
        peer_count = 1U;
    }
    /* A refused ChannelBind must not leave the permission it would have installed behind. */
    for (size_t i = 0; i < peer_count && rc == 0; ++i) {
        rc = add_permission(allocation, &peers[i], peer_lens[i], server->permission_ttl);
    }
    stun_builder response;
    if (rc != 0) {
        /* bad-request: more live permissions or channels than an allocation holds, which Java,
         * keeping them in maps, never refuses. */
        builder_error(&response, message_type, packet + 8U, 400, failure, 0);
    } else {
        builder_start(&response, success_type, packet + 8U);
        finish_success(server, &response, username);
    }
    send_builder(fd, &response, client, client_len);
}

static void handle_send_indication(st_stun_turn_server *server,
                                   const uint8_t *packet,
                                   size_t len,
                                   const struct sockaddr_storage *client)
{
    turn_allocation *allocation = find_allocation_by_client(server, client);
    stun_attribute peer_attr;
    stun_attribute data;
    struct sockaddr_storage peer;
    socklen_t peer_len = 0;
    if (allocation == NULL || find_attribute(packet, len, ATTR_XOR_PEER_ADDRESS, &peer_attr) != 0
        || find_attribute(packet, len, ATTR_DATA, &data) != 0
        || decode_xor_address(&peer_attr, packet + 8U, &peer, &peer_len) != 0
        || !allocation_has_permission(allocation, &peer)) return;
    turn_allocation *target = find_allocation_by_relay(server, &peer);
    if (!authorize_relay_payload(server, data.value, data.length, allocation, target, 1,
                                 server->auth_required)) return;
    if (!allow_general_relay_traffic(server, allocation, data.length)) return;
    (void)sendto(allocation->relay_fd, data.value, data.length, 0,
                 (struct sockaddr *)&peer, peer_len);
}

static void handle_channel_data(st_stun_turn_server *server,
                                const uint8_t *packet,
                                size_t len,
                                const struct sockaddr_storage *client)
{
    if (len < 4U) return;
    turn_allocation *allocation = find_allocation_by_client(server, client);
    uint16_t number = read_u16(packet);
    uint16_t data_len = read_u16(packet + 2U);
    turn_channel *channel = allocation == NULL ? NULL : find_channel_by_number(allocation, number);
    if (channel == NULL || 4U + data_len > len || !allocation_has_permission(allocation, &channel->peer)) return;
    turn_allocation *target = find_allocation_by_relay(server, &channel->peer);
    if (!authorize_relay_payload(server, packet + 4U, data_len, allocation, target, 1,
                                 server->auth_required)) return;
    if (!allow_general_relay_traffic(server, allocation, data_len)) return;
    (void)sendto(allocation->relay_fd, packet + 4U, data_len, 0,
                 (struct sockaddr *)&channel->peer, channel->peer_len);
}

static void handle_control_packet(st_stun_turn_server *server,
                                  int fd,
                                  const uint8_t *packet,
                                  size_t len,
                                  const struct sockaddr_storage *client,
                                  socklen_t client_len)
{
    /* Java reads ChannelData on the main port only; elsewhere it is no STUN message either. */
    if (len >= 4U && (packet[0] & 0xc0U) == 0x40U) {
        if (fd == server->control_fd) handle_channel_data(server, packet, len, client);
        return;
    }
    if (!stun_packet_valid(packet, len)) return;
    uint16_t type = read_u16(packet);
    /*
     * Java answers a TURN message on another endpoint with 400 unsupported-endpoint and one of an
     * unknown method with 400 unsupported-method instead of letting the client retransmit until it
     * times out. Only requests are answered here: an answer to an indication or a response could
     * bounce between two servers (or a spoofed server and itself) for ever.
     */
    int request = (type & 0x0110U) == 0U;
    if (fd != server->control_fd && type != STUN_BINDING_REQUEST) {
        if (request) {
            stun_builder error;
            builder_error(&error, type, packet + 8U, 400, "unsupported-endpoint", 0);
            (void)send_builder(fd, &error, client, client_len);
        }
        return;
    }
    switch (type) {
        case STUN_BINDING_REQUEST: handle_binding(server, fd, packet, len, client, client_len); break;
        case TURN_ALLOCATE_REQUEST: handle_allocate(server, fd, packet, len, client, client_len); break;
        case TURN_REFRESH_REQUEST: handle_refresh(server, fd, packet, len, client, client_len); break;
        case TURN_CREATE_PERMISSION_REQUEST:
        case TURN_CHANNEL_BIND_REQUEST:
            handle_permission_or_channel(server, fd, type, packet, len, client, client_len); break;
        case TURN_SEND_INDICATION: handle_send_indication(server, packet, len, client); break;
        default:
            if (request) {
                stun_builder error;
                builder_error(&error, type, packet + 8U, 400, "unsupported-method", 0);
                (void)send_builder(fd, &error, client, client_len);
            }
            break;
    }
}

static void handle_relay_packet(st_stun_turn_server *server, turn_allocation *allocation)
{
    uint8_t packet[STUN_MAX_PACKET];
    struct sockaddr_storage peer;
    socklen_t peer_len = sizeof(peer);
    ssize_t received = recvfrom(allocation->relay_fd, packet, sizeof(packet), 0,
                                (struct sockaddr *)&peer, &peer_len);
    if (received <= 0 || !allocation_has_permission(allocation, &peer)) return;
    turn_allocation *source = find_allocation_by_relay(server, &peer);
    if (!authorize_relay_payload(server, packet, (size_t)received, source, allocation, 0,
                                 server->auth_required)) return;
    if (!allow_general_relay_traffic(server, allocation, (size_t)received)) return;
    turn_channel *channel = find_channel_by_peer(allocation, &peer);
    if (channel != NULL) {
        uint8_t channel_packet[STUN_MAX_PACKET];
        if ((size_t)received + 4U > sizeof(channel_packet)) return;
        write_u16(channel_packet, channel->number);
        write_u16(channel_packet + 2U, (uint16_t)received);
        memcpy(channel_packet + 4U, packet, (size_t)received);
        (void)sendto(server->control_fd, channel_packet, (size_t)received + 4U, 0,
                     (struct sockaddr *)&allocation->client, allocation->client_len);
        return;
    }
    uint8_t transaction[12];
    if (RAND_bytes(transaction, sizeof(transaction)) != 1) memset(transaction, 0, sizeof(transaction));
    stun_builder indication;
    builder_start(&indication, TURN_DATA_INDICATION, transaction);
    builder_address(&indication, ATTR_XOR_PEER_ADDRESS, &peer, 1);
    builder_attr(&indication, ATTR_DATA, packet, (size_t)received);
    (void)send_builder(server->control_fd, &indication, &allocation->client, allocation->client_len);
}

/*
 * The periodic sweep (Java cleanupExpiredAllocations): expired allocations after every pass, and
 * once a second (lifetimes are whole seconds) the expired permissions and channels of the others.
 */
static void expire_allocations(st_stun_turn_server *server)
{
    time_t now = time(NULL);
    int sweep_entries = now != server->last_entry_sweep;
    server->last_entry_sweep = now;
    for (size_t i = 0; i < server->allocation_count; ++i) {
        turn_allocation *allocation = server->allocations[i];
        if (!allocation->used) continue;
        if (allocation->expires_at <= now) {
            close_allocation(allocation);
            continue;
        }
        for (size_t k = 0; sweep_entries && k < TURN_MAX_PERMISSIONS; ++k) {
            if (allocation->permissions[k].expires_at <= now) allocation->permissions[k].used = 0;
        }
        for (size_t k = 0; sweep_entries && k < TURN_MAX_CHANNELS; ++k) {
            if (allocation->channels[k].expires_at <= now) allocation->channels[k].used = 0;
        }
    }
}

/* Frees the allocations closed during the pass that just ended; nothing points at them any more. */
static void reap_closed_allocations(st_stun_turn_server *server)
{
    size_t kept = 0U;
    for (size_t i = 0; i < server->allocation_count; ++i) {
        if (server->allocations[i]->used) server->allocations[kept++] = server->allocations[i];
        else free(server->allocations[i]);
    }
    server->allocation_count = kept;
}

static int reserve_poll_set(st_stun_turn_server *server, size_t needed)
{
    if (needed <= server->poll_capacity) return 0;
    size_t capacity = server->poll_capacity == 0U ? 32U : server->poll_capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2U / sizeof(*server->poll_owners)) return -1;
        capacity *= 2U;
    }
    struct pollfd *fds = (struct pollfd *)realloc(server->poll_fds, capacity * sizeof(*fds));
    if (fds == NULL) return -1;
    server->poll_fds = fds;
    turn_allocation **owners = (turn_allocation **)realloc(server->poll_owners, capacity * sizeof(*owners));
    if (owners == NULL) return -1;
    server->poll_owners = owners;
    server->poll_capacity = capacity;
    return 0;
}

/*
 * One thread serves every endpoint and relay socket. poll, not select: a process with many
 * connections hands out socket numbers at and past FD_SETSIZE (the systemd unit allows 1048576
 * descriptors), which an fd_set cannot hold. As before, each ready socket gives up one datagram
 * per pass, endpoints first.
 */
static void *stun_turn_thread(void *raw)
{
    st_stun_turn_server *server = (st_stun_turn_server *)raw;
    while (server->running) {
        if (reserve_poll_set(server, server->endpoint_count + server->allocation_count) != 0) {
            fprintf(stderr, "[peer-mesh] STUN/TURN poll set allocation failed\n");
            struct timespec pause = {0, 100000000L};
            nanosleep(&pause, NULL);
            continue;
        }
        nfds_t count = 0U;
        for (size_t i = 0; i < server->endpoint_count; ++i) {
            if (server->endpoints[i].fd < 0) continue;
            server->poll_fds[count] = (struct pollfd){server->endpoints[i].fd, POLLIN, 0};
            server->poll_owners[count++] = NULL;
        }
        nfds_t endpoint_entries = count;
        for (size_t i = 0; i < server->allocation_count; ++i) {
            turn_allocation *allocation = server->allocations[i];
            if (!allocation->used) continue;
            server->poll_fds[count] = (struct pollfd){allocation->relay_fd, POLLIN, 0};
            server->poll_owners[count++] = allocation;
        }
        int ready = poll(server->poll_fds, count, 1000);
        if (ready < 0 && errno != EINTR) {
            fprintf(stderr, "[peer-mesh] STUN/TURN poll failed: %s\n", strerror(errno));
            struct timespec pause = {0, 100000000L};
            nanosleep(&pause, NULL);
        }
        for (nfds_t k = 0; ready > 0 && k < endpoint_entries; ++k) {
            if ((server->poll_fds[k].revents & (POLLIN | POLLERR | POLLHUP)) == 0) continue;
            int fd = server->poll_fds[k].fd;
            uint8_t packet[STUN_MAX_PACKET];
            struct sockaddr_storage client;
            socklen_t client_len = sizeof(client);
            ssize_t received = recvfrom(fd, packet, sizeof(packet), 0,
                                        (struct sockaddr *)&client, &client_len);
            if (received > 0) handle_control_packet(server, fd, packet, (size_t)received,
                                                    &client, client_len);
        }
        for (nfds_t k = endpoint_entries; ready > 0 && k < count; ++k) {
            turn_allocation *allocation = server->poll_owners[k];
            /* Closed earlier in this pass (its number may even belong to a new relay by now). */
            if ((server->poll_fds[k].revents & (POLLIN | POLLERR | POLLHUP)) == 0
                || !allocation->used || allocation->relay_fd != server->poll_fds[k].fd) continue;
            handle_relay_packet(server, allocation);
        }
        expire_allocations(server);
        reap_closed_allocations(server);
    }
    return NULL;
}

static int init_relay_sync(st_stun_turn_server *server)
{
    pthread_condattr_t attributes;
    if (pthread_condattr_init(&attributes) != 0) return -1;
    int rc = pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) == 0
        && pthread_cond_init(&server->relay_wake, &attributes) == 0 ? 0 : -1;
    pthread_condattr_destroy(&attributes);
    if (rc != 0) return -1;
    if (pthread_mutex_init(&server->relay_lock, NULL) != 0) {
        pthread_cond_destroy(&server->relay_wake);
        return -1;
    }
    if (pthread_mutex_init(&server->flush_lock, NULL) != 0) {
        pthread_mutex_destroy(&server->relay_lock);
        pthread_cond_destroy(&server->relay_wake);
        return -1;
    }
    server->sync_ready = 1;
    return 0;
}

static void stop_relay_flusher(st_stun_turn_server *server)
{
    if (!server->flusher_started) return;
    pthread_mutex_lock(&server->relay_lock);
    server->flush_stopping = 1;
    pthread_cond_signal(&server->relay_wake);
    pthread_mutex_unlock(&server->relay_lock);
    pthread_join(server->flusher, NULL);
    server->flusher_started = 0;
}

/* Releases a server whose threads are not running (any more). */
static void discard_server(st_stun_turn_server *server)
{
    if (server->sync_ready) set_server_live(server, 0);
    for (size_t i = 0; i < server->allocation_count; ++i) {
        if (server->allocations[i]->used) close_allocation(server->allocations[i]);
    }
    reap_closed_allocations(server);
    close_stun_endpoints(server, 0);
    for (size_t i = 0; i < server->relay_session_count; ++i) free(server->relay_sessions[i].database_path);
    if (server->sync_ready) {
        pthread_mutex_destroy(&server->flush_lock);
        pthread_mutex_destroy(&server->relay_lock);
        pthread_cond_destroy(&server->relay_wake);
    }
    free(server->relay_sessions);
    free(server->allocations);
    free(server->poll_fds);
    free(server->poll_owners);
    free(server);
}

int st_stun_turn_server_start(st_stun_turn_server **out_server)
{
    if (out_server == NULL) return -1;
    *out_server = NULL;
    st_stun_turn_server *server = (st_stun_turn_server *)calloc(1, sizeof(*server));
    if (server == NULL) return -1;
    server->control_fd = -1;
    if (init_relay_sync(server) != 0) {
        free(server);
        return -1;
    }
    long long flush_interval = env_i64_value("SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS",
                                             RELAY_TRAFFIC_FLUSH_DEFAULT_MS);
    server->flush_interval_ms = flush_interval <= 0 ? RELAY_TRAFFIC_FLUSH_DEFAULT_MS
        : (flush_interval > 86400000LL ? 86400000L : (long)flush_interval);
    server->auth_required = env_bool_value("SPECUS_PEER_MESH_TURN_AUTH_REQUIRED", 1);
    server->allow_private_peers = env_bool_value("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS", 0);
    server->allocation_ttl = env_int_alias("SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS",
                                           "SPECUS_PEER_MESH_TURN_ALLOCATION_TTL_SECONDS", 300);
    server->permission_ttl = env_int_value("SPECUS_PEER_MESH_TURN_PERMISSION_TTL_SECONDS", 300);
    server->channel_ttl = env_int_value("SPECUS_PEER_MESH_TURN_CHANNEL_TTL_SECONDS", 600);
    /* Java bindRelaySocket: each end clamped to 1..65535, a reversed range put in order. */
    int relay_min_port = env_signed_int_alias("SPECUS_PEER_MESH_RELAY_MIN_PORT",
                                              "SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", 49152);
    int relay_max_port = env_signed_int_alias("SPECUS_PEER_MESH_RELAY_MAX_PORT",
                                              "SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT", 65535);
    relay_min_port = relay_min_port < 1 ? 1 : (relay_min_port > 65535 ? 65535 : relay_min_port);
    relay_max_port = relay_max_port < 1 ? 1 : (relay_max_port > 65535 ? 65535 : relay_max_port);
    server->relay_min_port = relay_min_port <= relay_max_port ? relay_min_port : relay_max_port;
    server->relay_max_port = relay_min_port <= relay_max_port ? relay_max_port : relay_min_port;
    /* Java int properties: a total <= 0 switches the general relay off, a per-address limit <= 0
     * lifts that limit. */
    server->general_relay_max_allocations = env_signed_int_value(
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", 256);
    server->general_relay_max_allocations_per_address = env_signed_int_value(
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", 4);
    server->general_relay_max_bytes = env_i64_value(
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_BYTES", 512LL * 1024LL * 1024LL);
    server->udp_receive_buffer = env_signed_int_value("SPECUS_PEER_MESH_UDP_RECEIVE_BUFFER_BYTES", 4 * 1024 * 1024);
    server->udp_send_buffer = env_signed_int_value("SPECUS_PEER_MESH_UDP_SEND_BUFFER_BYTES", 4 * 1024 * 1024);
    server->udp_traffic_class = env_signed_int_value("SPECUS_PEER_MESH_UDP_TRAFFIC_CLASS", 0x10);
    const char *primary_bind = getenv("SPECUS_PEER_MESH_STUN_PRIMARY_BIND_ADDRESS");
    int primary_explicit = primary_bind != NULL && *primary_bind != '\0';
    if (!primary_explicit) primary_bind = getenv("SPECUS_PEER_MESH_BIND_ADDRESS");
    if (primary_bind == NULL || *primary_bind == '\0') primary_bind = "0.0.0.0";
    const char *primary_public = getenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    const char *alternate_bind = getenv("SPECUS_PEER_MESH_STUN_ALTERNATE_BIND_ADDRESS");
    const char *alternate_public = getenv("SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS");
    int configured_port = env_int_value("SPECUS_PEER_MESH_STUN_TURN_PORT", 3478);
    int alternate_port = env_int_value("SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT", 3479);
    int full_rfc5780 = primary_explicit
        && primary_public != NULL && *primary_public != '\0'
        && alternate_bind != NULL && *alternate_bind != '\0'
        && alternate_public != NULL && *alternate_public != '\0'
        && configured_port > 0 && alternate_port > 0 && configured_port != alternate_port
        && strcmp(primary_bind, alternate_bind) != 0
        && strcmp(primary_public, alternate_public) != 0;
    if (env_bool_value("SPECUS_PEER_MESH_STUN_BEHAVIOR_STRICT", 0) && !full_rfc5780) {
        discard_server(server);
        return -1;
    }
    int primary_actual = add_stun_endpoint(server, primary_bind, primary_public,
                                           configured_port, 0, 0);
    if (primary_actual <= 0) {
        discard_server(server);
        return -1;
    }
    server->port = primary_actual;
    server->control_fd = server->endpoints[0].fd;
    if (full_rfc5780) {
        if (add_stun_endpoint(server, primary_bind, primary_public,
                              alternate_port, 0, 1) <= 0
            || add_stun_endpoint(server, alternate_bind, alternate_public,
                                 configured_port, 1, 0) <= 0
            || add_stun_endpoint(server, alternate_bind, alternate_public,
                                 alternate_port, 1, 1) <= 0) {
            discard_server(server);
            return -1;
        }
        server->rfc5780 = 1;
    } else if (configured_port != 0 && alternate_port > 0 && alternate_port != primary_actual) {
        (void)add_stun_endpoint(server, primary_bind, primary_public,
                                alternate_port, 0, 1);
    }
    /* SPECUS_PEER_MESH_RELAY_ADDRESS is C's own override, resolved like the public address;
     * otherwise, as Java's turnAdvertisedAddress, the main listener's advertised address. */
    const char *relay_address = getenv("SPECUS_PEER_MESH_RELAY_ADDRESS");
    server->relay_address = ((const struct sockaddr_in *)&server->endpoints[0].advertised)->sin_addr;
    if (relay_address != NULL && *relay_address != '\0'
        && resolve_ipv4(relay_address, &server->relay_address) != 0) {
        fprintf(stderr, "[peer-mesh] cannot resolve SPECUS_PEER_MESH_RELAY_ADDRESS %s\n", relay_address);
        discard_server(server);
        return -1;
    }
    set_server_live(server, 1);
    if (pthread_create(&server->flusher, NULL, relay_flush_thread, server) != 0) {
        discard_server(server);
        return -1;
    }
    server->flusher_started = 1;
    server->running = 1;
    if (pthread_create(&server->thread, NULL, stun_turn_thread, server) != 0) {
        stop_relay_flusher(server);
        discard_server(server);
        return -1;
    }
    *out_server = server;
    return 0;
}

int st_stun_turn_server_port(const st_stun_turn_server *server)
{
    return server == NULL ? 0 : server->port;
}

void st_stun_turn_server_stop(st_stun_turn_server *server)
{
    if (server == NULL) return;
    server->running = 0;
    close_stun_endpoints(server, 1);
    pthread_join(server->thread, NULL);
    stop_relay_flusher(server);
    /* Nothing relays any more: what is still counted is written now, not lost. */
    st_stun_turn_server_flush_relay_traffic(server);
    discard_server(server);
}
