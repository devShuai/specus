#define _POSIX_C_SOURCE 200809L

#include "stun_turn.h"

#include "crypto.h"
#include "json.h"
#include "storage.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define STUN_COOKIE 0x2112a442U
#define STUN_HEADER_SIZE 20U
#define STUN_MAX_PACKET 65535U
#define TURN_MAX_ALLOCATIONS 256U
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

struct st_stun_turn_server {
    int control_fd;
    int port;
    stun_server_endpoint endpoints[STUN_MAX_ENDPOINTS];
    size_t endpoint_count;
    int rfc5780;
    int running;
    int auth_required;
    int allow_private_peers;
    int allocation_ttl;
    int permission_ttl;
    int channel_ttl;
    int relay_min_port;
    int relay_max_port;
    int next_relay_port;
    int general_relay_max_allocations;
    int general_relay_max_allocations_per_address;
    long long general_relay_max_bytes;
    pthread_t thread;
    turn_allocation allocations[TURN_MAX_ALLOCATIONS];
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

static int env_int_alias(const char *name, const char *legacy_name, int default_value)
{
    const char *value = getenv(name);
    return value != NULL && *value != '\0'
        ? env_int_value(name, default_value)
        : env_int_value(legacy_name, default_value);
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

static int validate_integrity(const uint8_t *packet, size_t len, char username[192])
{
    stun_attribute user;
    stun_attribute realm;
    stun_attribute nonce;
    stun_attribute integrity;
    if (find_attribute(packet, len, ATTR_USERNAME, &user) != 0 || user.length == 0U || user.length >= 192U
        || find_attribute(packet, len, ATTR_REALM, &realm) != 0
        || find_attribute(packet, len, ATTR_NONCE, &nonce) != 0
        || find_attribute(packet, len, ATTR_MESSAGE_INTEGRITY, &integrity) != 0
        || integrity.length != ST_SHA1_LEN
        || realm.length != strlen(st_turn_auth_realm())
        || memcmp(realm.value, st_turn_auth_realm(), realm.length) != 0
        || nonce.length != strlen(st_turn_auth_nonce())
        || memcmp(nonce.value, st_turn_auth_nonce(), nonce.length) != 0) return -1;
    memcpy(username, user.value, user.length);
    username[user.length] = '\0';
    uint8_t key[16];
    if (st_turn_auth_long_term_key(username, key) != 0) return -1;
    uint8_t *copy = (uint8_t *)malloc(integrity.offset);
    if (copy == NULL) return -1;
    memcpy(copy, packet, integrity.offset);
    write_u16(copy + 2U, (uint16_t)(integrity.offset + 24U - STUN_HEADER_SIZE));
    uint8_t mac[ST_SHA1_LEN];
    st_hmac_sha1(key, sizeof(key), copy, integrity.offset, mac);
    free(copy);
    return st_constant_time_eq(mac, integrity.value, sizeof(mac)) ? 0 : -1;
}

static uint16_t stun_error_type(uint16_t request_type)
{
    switch (request_type) {
        case STUN_BINDING_REQUEST: return 0x0111U;
        case TURN_ALLOCATE_REQUEST: return 0x0113U;
        case TURN_REFRESH_REQUEST: return 0x0114U;
        case TURN_CREATE_PERMISSION_REQUEST: return 0x0118U;
        case TURN_CHANNEL_BIND_REQUEST: return 0x0119U;
        default: return 0x0110U;
    }
}

static int builder_error(stun_builder *builder,
                         uint16_t request_type,
                         const uint8_t transaction[12],
                         int code,
                         const char *reason,
                         int add_challenge)
{
    builder_start(builder, stun_error_type(request_type), transaction);
    uint8_t value[256] = {0};
    size_t reason_len = strlen(reason);
    if (reason_len > sizeof(value) - 4U) reason_len = sizeof(value) - 4U;
    value[2] = (uint8_t)(code / 100);
    value[3] = (uint8_t)(code % 100);
    memcpy(value + 4U, reason, reason_len);
    if (builder_attr(builder, ATTR_ERROR_CODE, value, reason_len + 4U) != 0) return -1;
    if (add_challenge && (builder_attr(builder, ATTR_REALM, st_turn_auth_realm(), strlen(st_turn_auth_realm())) != 0
                          || builder_attr(builder, ATTR_NONCE, st_turn_auth_nonce(), strlen(st_turn_auth_nonce())) != 0)) return -1;
    return 0;
}

static int create_udp_socket(const char *bind_address, int port, int *actual_port)
{
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_address, &address.sin_addr) != 1) return -1;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    int reuse = 1;
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0
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
    int fd = create_udp_socket(bind_address, port, &actual_port);
    if (fd < 0) return -1;
    stun_server_endpoint *endpoint = &server->endpoints[server->endpoint_count];
    memset(endpoint, 0, sizeof(*endpoint));
    endpoint->fd = fd;
    endpoint->address_slot = address_slot;
    endpoint->port_slot = port_slot;
    struct sockaddr_in *advertised = (struct sockaddr_in *)&endpoint->advertised;
    advertised->sin_family = AF_INET;
    advertised->sin_port = htons((uint16_t)actual_port);
    const char *selected = advertised_address;
    if (selected == NULL || inet_pton(AF_INET, selected, &advertised->sin_addr) != 1) {
        selected = bind_address;
        if (selected == NULL || inet_pton(AF_INET, selected, &advertised->sin_addr) != 1
            || advertised->sin_addr.s_addr == htonl(INADDR_ANY)) {
            advertised->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
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

static turn_allocation *find_allocation_by_client(st_stun_turn_server *server,
                                                   const struct sockaddr_storage *client)
{
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
        if (server->allocations[i].used
            && sockaddr_equal(&server->allocations[i].client, client, 1)) return &server->allocations[i];
    }
    return NULL;
}

static turn_allocation *find_allocation_by_relay(st_stun_turn_server *server,
                                                  const struct sockaddr_storage *relay)
{
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
        if (server->allocations[i].used
            && sockaddr_equal(&server->allocations[i].relay, relay, 1)) return &server->allocations[i];
    }
    return NULL;
}

static long long allocation_client_id(const turn_allocation *allocation)
{
    if (allocation == NULL) return 0;
    const char *first = strchr(allocation->username, ':');
    if (first == NULL || strncmp(first + 1, "pm-", 3U) != 0) return 0;
    char *end = NULL;
    long long id = strtoll(first + 4, &end, 10);
    return id > 0 && end != first + 4 && *end == ':' ? id : 0;
}

static int allocation_is_general(const turn_allocation *allocation)
{
    if (allocation == NULL) return 0;
    const char *first = strchr(allocation->username, ':');
    return first != NULL && strncmp(first + 1, "public-transfer", 15U) == 0;
}

static void close_allocation(turn_allocation *allocation);

static int username_is_general(const char *username)
{
    const char *first = username == NULL ? NULL : strchr(username, ':');
    return first != NULL && strncmp(first + 1, "public-transfer", 15U) == 0;
}

static int general_relay_quota_allows(st_stun_turn_server *server,
                                      const struct sockaddr_storage *client,
                                      const turn_allocation *exclude)
{
    if (server->general_relay_max_allocations <= 0) return 0;
    int total = 0;
    int same_address = 0;
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
        turn_allocation *candidate = &server->allocations[i];
        if (!candidate->used || candidate == exclude || !allocation_is_general(candidate)) continue;
        ++total;
        if (sockaddr_equal(&candidate->client, client, 0)) ++same_address;
    }
    return total < server->general_relay_max_allocations
        && (server->general_relay_max_allocations_per_address <= 0
            || same_address < server->general_relay_max_allocations_per_address);
}

static int allow_general_relay_traffic(st_stun_turn_server *server,
                                       turn_allocation *allocation,
                                       size_t bytes)
{
    if (!allocation_is_general(allocation)) return 1;
    if (bytes > ULLONG_MAX - allocation->relayed_bytes) {
        close_allocation(allocation);
        return 0;
    }
    allocation->relayed_bytes += bytes;
    if (server->general_relay_max_bytes > 0
        && allocation->relayed_bytes > (unsigned long long)server->general_relay_max_bytes) {
        close_allocation(allocation);
        return 0;
    }
    return 1;
}

static uint64_t read_u64(const uint8_t *data)
{
    return ((uint64_t)read_u32(data) << 32U) | read_u32(data + 4U);
}

static int authorize_relay_payload(const uint8_t *payload,
                                   size_t payload_len,
                                   const turn_allocation *source,
                                   const turn_allocation *target,
                                   int account_traffic)
{
    if (allocation_is_general(source) || allocation_is_general(target)) return 1;
    long long source_id = allocation_client_id(source);
    long long target_id = allocation_client_id(target);
    if (source_id <= 0 || target_id <= 0) return 0;
    const char *database_path = getenv("SPECUS_DB_PATH");
    if (database_path == NULL || *database_path == '\0') return 0;
    if (payload_len >= 36U && read_u32(payload) == 0x53504d32U) {
        long long session_id = (long long)read_u64(payload + 4U);
        long long sequence = (long long)read_u64(payload + 12U);
        return session_id > 0 && sequence > 0
            && st_storage_authorize_peer_mesh_relay(database_path, session_id,
                                                    source_id, target_id,
                                                    (long long)payload_len,
                                                    account_traffic) == 1;
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
        && from_id == source_id && to_id == target_id
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

static int peer_address_allowed(st_stun_turn_server *server,
                                const struct sockaddr_storage *peer)
{
    if (server->allow_private_peers) return 1;
    if (peer->ss_family != AF_INET) return peer->ss_family == AF_INET6;
    uint32_t ip = ntohl(((const struct sockaddr_in *)peer)->sin_addr.s_addr);
    if ((ip & 0xff000000U) == 0x7f000000U || (ip & 0xff000000U) == 0x0a000000U
        || (ip & 0xfff00000U) == 0xac100000U || (ip & 0xffff0000U) == 0xc0a80000U
        || (ip & 0xffff0000U) == 0xa9fe0000U || (ip & 0xf0000000U) == 0xe0000000U
        || ip == 0U) return 0;
    return 1;
}

static turn_allocation *create_allocation(st_stun_turn_server *server,
                                           const struct sockaddr_storage *client,
                                           socklen_t client_len,
                                           const char *username)
{
    turn_allocation *slot = NULL;
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
        if (!server->allocations[i].used) {
            slot = &server->allocations[i];
            break;
        }
    }
    if (slot == NULL) return NULL;
    const char *bind_address = getenv("SPECUS_PEER_MESH_BIND_ADDRESS");
    if (bind_address == NULL || *bind_address == '\0') bind_address = "0.0.0.0";
    int relay_fd = -1;
    int relay_port = 0;
    int range = server->relay_max_port - server->relay_min_port + 1;
    for (int i = 0; i < range; ++i) {
        int port = server->relay_min_port
            + ((server->next_relay_port - server->relay_min_port + i) % range);
        relay_fd = create_udp_socket(bind_address, port, &relay_port);
        if (relay_fd >= 0) {
            server->next_relay_port = port == server->relay_max_port ? server->relay_min_port : port + 1;
            break;
        }
    }
    if (relay_fd < 0) return NULL;
    memset(slot, 0, sizeof(*slot));
    slot->used = 1;
    slot->relay_fd = relay_fd;
    slot->client = *client;
    slot->client_len = client_len;
    slot->expires_at = time(NULL) + server->allocation_ttl;
    snprintf(slot->username, sizeof(slot->username), "%s", username == NULL ? "" : username);
    struct sockaddr_in *relay = (struct sockaddr_in *)&slot->relay;
    relay->sin_family = AF_INET;
    relay->sin_port = htons((uint16_t)relay_port);
    const char *advertised = getenv("SPECUS_PEER_MESH_RELAY_ADDRESS");
    if (advertised == NULL || *advertised == '\0') advertised = getenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    if (advertised == NULL || inet_pton(AF_INET, advertised, &relay->sin_addr) != 1) {
        relay->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    }
    slot->relay_len = sizeof(*relay);
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

static int add_permission(turn_allocation *allocation,
                          const struct sockaddr_storage *peer,
                          socklen_t peer_len,
                          int ttl)
{
    turn_permission *slot = NULL;
    for (size_t i = 0; i < TURN_MAX_PERMISSIONS; ++i) {
        if (allocation->permissions[i].used
            && sockaddr_equal(&allocation->permissions[i].address, peer, 0)) {
            slot = &allocation->permissions[i];
            break;
        }
        if (slot == NULL && !allocation->permissions[i].used) slot = &allocation->permissions[i];
    }
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
    if (slot == NULL) {
        for (size_t i = 0; i < TURN_MAX_CHANNELS; ++i) {
            if (!allocation->channels[i].used) {
                slot = &allocation->channels[i];
                break;
            }
        }
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
    if (validate_integrity(packet, len, username) == 0) return 0;
    stun_builder error;
    builder_error(&error, read_u16(packet), packet + 8U, 401, "Unauthorized", 1);
    send_builder(fd, &error, client, client_len);
    return -1;
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
        builder_error(&error, STUN_BINDING_REQUEST, packet + 8U, error_code, error_reason, 0);
        if (unknown_attribute != 0U) {
            uint8_t encoded[2];
            write_u16(encoded, unknown_attribute);
            (void)builder_attr(&error, ATTR_UNKNOWN_ATTRIBUTES, encoded, sizeof(encoded));
        }
        (void)builder_attr(&error, ATTR_SOFTWARE, "specus-standard-stun-turn", 25U);
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
    (void)builder_attr(&response, ATTR_SOFTWARE, "specus-standard-stun-turn", 25U);
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
        builder_error(&error, TURN_ALLOCATE_REQUEST, packet + 8U, 442, "Unsupported Transport", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    turn_allocation *allocation = find_allocation_by_client(server, client);
    int quota_rejected = 0;
    int general_relay = username_is_general(username);
    long long authenticated_client_id = 0;
    if (!general_relay) {
        turn_allocation identity = {0};
        snprintf(identity.username, sizeof(identity.username), "%s", username);
        authenticated_client_id = allocation_client_id(&identity);
    }
    if (allocation != NULL
        && (allocation_is_general(allocation) != general_relay
            || (!general_relay && allocation_client_id(allocation) != authenticated_client_id))) {
        if (general_relay && !general_relay_quota_allows(server, client, allocation)) {
            quota_rejected = 1;
            allocation = NULL;
        }
        else {
            close_allocation(allocation);
            allocation = create_allocation(server, client, client_len, username);
        }
    } else if (allocation == NULL) {
        if (!general_relay || general_relay_quota_allows(server, client, NULL))
            allocation = create_allocation(server, client, client_len, username);
        else quota_rejected = 1;
    }
    if (allocation == NULL) {
        stun_builder error;
        builder_error(&error, TURN_ALLOCATE_REQUEST, packet + 8U,
                      quota_rejected ? 486 : 508,
                      quota_rejected ? "Allocation Quota Reached" : "Insufficient Capacity", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    allocation->expires_at = time(NULL) + server->allocation_ttl;
    stun_builder response;
    builder_start(&response, TURN_ALLOCATE_SUCCESS, packet + 8U);
    builder_address(&response, ATTR_XOR_RELAYED_ADDRESS, &allocation->relay, 1);
    builder_address(&response, ATTR_XOR_MAPPED_ADDRESS, client, 1);
    builder_u32(&response, ATTR_LIFETIME, (uint32_t)server->allocation_ttl);
    if (server->auth_required) {
        uint8_t key[16];
        if (st_turn_auth_long_term_key(username, key) == 0) builder_integrity(&response, key);
    }
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
    if (allocation == NULL) {
        stun_builder error;
        builder_error(&error, TURN_REFRESH_REQUEST, packet + 8U, 437, "Allocation Mismatch", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    uint32_t lifetime = (uint32_t)server->allocation_ttl;
    stun_attribute requested;
    if (find_attribute(packet, len, ATTR_LIFETIME, &requested) == 0 && requested.length == 4U) {
        lifetime = read_u32(requested.value);
        if (lifetime > (uint32_t)server->allocation_ttl) lifetime = (uint32_t)server->allocation_ttl;
    }
    stun_builder response;
    builder_start(&response, TURN_REFRESH_SUCCESS, packet + 8U);
    builder_u32(&response, ATTR_LIFETIME, lifetime);
    uint8_t key[16];
    if (server->auth_required && st_turn_auth_long_term_key(username, key) == 0) builder_integrity(&response, key);
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
    stun_attribute peer_attr;
    struct sockaddr_storage peer;
    socklen_t peer_len = 0;
    if (allocation == NULL || find_attribute(packet, len, ATTR_XOR_PEER_ADDRESS, &peer_attr) != 0
        || decode_xor_address(&peer_attr, packet + 8U, &peer, &peer_len) != 0
        || (allocation != NULL && allocation_is_general(allocation)
            && !peer_address_allowed(server, &peer))) {
        stun_builder error;
        builder_error(&error, message_type, packet + 8U,
                      allocation == NULL ? 437 : 403,
                      allocation == NULL ? "Allocation Mismatch" : "Forbidden Peer", 0);
        send_builder(fd, &error, client, client_len);
        return;
    }
    int rc = add_permission(allocation, &peer, peer_len, server->permission_ttl);
    uint16_t success_type = TURN_CREATE_PERMISSION_SUCCESS;
    if (message_type == TURN_CHANNEL_BIND_REQUEST) {
        stun_attribute channel;
        uint16_t number = 0U;
        if (find_attribute(packet, len, ATTR_CHANNEL_NUMBER, &channel) != 0 || channel.length != 4U
            || (number = read_u16(channel.value)) < 0x4000U || number > 0x7fffU) rc = -1;
        else rc = bind_channel(allocation, number, &peer, peer_len, server->channel_ttl);
        success_type = TURN_CHANNEL_BIND_SUCCESS;
    }
    stun_builder response;
    if (rc != 0) {
        builder_error(&response, message_type, packet + 8U, 400, "Bad Request", 0);
    } else {
        builder_start(&response, success_type, packet + 8U);
        uint8_t key[16];
        if (server->auth_required && st_turn_auth_long_term_key(username, key) == 0) builder_integrity(&response, key);
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
    if (!authorize_relay_payload(data.value, data.length, allocation, target, 1)) return;
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
    if (!authorize_relay_payload(packet + 4U, data_len, allocation, target, 1)) return;
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
    if (len >= 4U && (packet[0] & 0xc0U) == 0x40U) {
        handle_channel_data(server, packet, len, client);
        return;
    }
    if (!stun_packet_valid(packet, len)) return;
    uint16_t type = read_u16(packet);
    if (fd != server->control_fd && type != STUN_BINDING_REQUEST) return;
    switch (type) {
        case STUN_BINDING_REQUEST: handle_binding(server, fd, packet, len, client, client_len); break;
        case TURN_ALLOCATE_REQUEST: handle_allocate(server, fd, packet, len, client, client_len); break;
        case TURN_REFRESH_REQUEST: handle_refresh(server, fd, packet, len, client, client_len); break;
        case TURN_CREATE_PERMISSION_REQUEST:
        case TURN_CHANNEL_BIND_REQUEST:
            handle_permission_or_channel(server, fd, type, packet, len, client, client_len); break;
        case TURN_SEND_INDICATION: handle_send_indication(server, packet, len, client); break;
        default: break;
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
    if (!authorize_relay_payload(packet, (size_t)received, source, allocation, 0)) return;
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

static void expire_allocations(st_stun_turn_server *server)
{
    time_t now = time(NULL);
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
        if (server->allocations[i].used && server->allocations[i].expires_at <= now) {
            close_allocation(&server->allocations[i]);
        }
    }
}

static void *stun_turn_thread(void *raw)
{
    st_stun_turn_server *server = (st_stun_turn_server *)raw;
    while (server->running) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        int max_fd = -1;
        for (size_t i = 0; i < server->endpoint_count; ++i) {
            int fd = server->endpoints[i].fd;
            if (fd >= 0) {
                FD_SET(fd, &read_fds);
                if (fd > max_fd) max_fd = fd;
            }
        }
        for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
            if (server->allocations[i].used) {
                FD_SET(server->allocations[i].relay_fd, &read_fds);
                if (server->allocations[i].relay_fd > max_fd) max_fd = server->allocations[i].relay_fd;
            }
        }
        struct timeval timeout = {1, 0};
        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0 && errno != EINTR) break;
        for (size_t which = 0; which < server->endpoint_count; ++which) {
            int fd = server->endpoints[which].fd;
            if (fd >= 0 && FD_ISSET(fd, &read_fds)) {
                uint8_t packet[STUN_MAX_PACKET];
                struct sockaddr_storage client;
                socklen_t client_len = sizeof(client);
                ssize_t received = recvfrom(fd, packet, sizeof(packet), 0,
                                            (struct sockaddr *)&client, &client_len);
                if (received > 0) handle_control_packet(server, fd, packet, (size_t)received,
                                                        &client, client_len);
            }
        }
        for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
            if (server->allocations[i].used
                && FD_ISSET(server->allocations[i].relay_fd, &read_fds)) {
                handle_relay_packet(server, &server->allocations[i]);
            }
        }
        expire_allocations(server);
    }
    return NULL;
}

int st_stun_turn_server_start(st_stun_turn_server **out_server)
{
    if (out_server == NULL) return -1;
    *out_server = NULL;
    st_stun_turn_server *server = (st_stun_turn_server *)calloc(1, sizeof(*server));
    if (server == NULL) return -1;
    server->control_fd = -1;
    server->auth_required = env_bool_value("SPECUS_PEER_MESH_TURN_AUTH_REQUIRED", 1);
    server->allow_private_peers = env_bool_value("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS", 0);
    server->allocation_ttl = env_int_alias("SPECUS_PEER_MESH_ALLOCATION_TTL_SECONDS",
                                           "SPECUS_PEER_MESH_TURN_ALLOCATION_TTL_SECONDS", 300);
    server->permission_ttl = env_int_value("SPECUS_PEER_MESH_TURN_PERMISSION_TTL_SECONDS", 300);
    server->channel_ttl = env_int_value("SPECUS_PEER_MESH_TURN_CHANNEL_TTL_SECONDS", 600);
    server->relay_min_port = env_int_alias("SPECUS_PEER_MESH_RELAY_MIN_PORT",
                                          "SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", 49152);
    server->relay_max_port = env_int_alias("SPECUS_PEER_MESH_RELAY_MAX_PORT",
                                          "SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT", 65535);
    server->general_relay_max_allocations = env_int_value(
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", 256);
    server->general_relay_max_allocations_per_address = env_int_value(
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", 4);
    server->general_relay_max_bytes = env_i64_value(
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_BYTES", 512LL * 1024LL * 1024LL);
    if (server->relay_min_port <= 0 || server->relay_max_port < server->relay_min_port) {
        free(server);
        return -1;
    }
    server->next_relay_port = server->relay_min_port;
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) server->allocations[i].relay_fd = -1;
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
        free(server);
        return -1;
    }
    int primary_actual = add_stun_endpoint(server, primary_bind, primary_public,
                                           configured_port, 0, 0);
    if (primary_actual <= 0) {
        close_stun_endpoints(server, 0);
        free(server);
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
            close_stun_endpoints(server, 0);
            free(server);
            return -1;
        }
        server->rfc5780 = 1;
    } else if (configured_port != 0 && alternate_port > 0 && alternate_port != primary_actual) {
        (void)add_stun_endpoint(server, primary_bind, primary_public,
                                alternate_port, 0, 1);
    }
    server->running = 1;
    if (pthread_create(&server->thread, NULL, stun_turn_thread, server) != 0) {
        close_stun_endpoints(server, 0);
        free(server);
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
    for (size_t i = 0; i < TURN_MAX_ALLOCATIONS; ++i) {
        if (server->allocations[i].used) close_allocation(&server->allocations[i]);
    }
    close_stun_endpoints(server, 0);
    free(server);
}
