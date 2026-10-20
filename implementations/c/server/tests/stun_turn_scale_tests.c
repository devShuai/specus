#define _POSIX_C_SOURCE 200809L

/*
 * STUN/TURN capacity: socket numbers past FD_SETSIZE and more allocations than the old fixed
 * table held. Java gives every socket its own (virtual) thread and keeps allocations in an
 * unbounded map, so neither is a limit there.
 */

#include "crypto.h"
#include "stun_turn.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define COOKIE 0x2112a442U

typedef struct {
    unsigned char bytes[1024];
    size_t len;
} packet_builder;

typedef struct {
    char username[192];
    unsigned char key[16];
} turn_credential;

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
    return ((unsigned)in[0] << 24U) | ((unsigned)in[1] << 16U) | ((unsigned)in[2] << 8U) | in[3];
}

static void start(packet_builder *builder, unsigned type, unsigned seed)
{
    memset(builder, 0, sizeof(*builder));
    builder->len = 20U;
    u16(builder->bytes, type);
    u32(builder->bytes + 4U, COOKIE);
    for (size_t i = 0; i < 12U; ++i) builder->bytes[8U + i] = (unsigned char)(seed >> (i % 4U * 8U)) ^ (unsigned char)i;
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

static void sign(packet_builder *builder, const turn_credential *credential)
{
    unsigned char mac[20];
    attr(builder, 0x0006U, credential->username, strlen(credential->username));
    attr(builder, 0x0014U, st_turn_auth_realm(), strlen(st_turn_auth_realm()));
    attr(builder, 0x0015U, st_turn_auth_nonce(), strlen(st_turn_auth_nonce()));
    u16(builder->bytes + 2U, (unsigned)(builder->len + 24U - 20U));
    st_hmac_sha1(credential->key, 16U, builder->bytes, builder->len, mac);
    attr(builder, 0x0008U, mac, sizeof(mac));
}

static const unsigned char *find_attr(const unsigned char *packet, size_t len, unsigned type, size_t *attr_len)
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

static int error_code(const unsigned char *packet, int len)
{
    size_t value_len = 0U;
    const unsigned char *value = len >= 20 ? find_attr(packet, (size_t)len, 0x0009U, &value_len) : NULL;
    return value == NULL || value_len < 4U ? -1 : (int)(value[2] & 0x07U) * 100 + value[3];
}

static int udp_socket(struct sockaddr_in *bound)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(bound, 0, sizeof(*bound));
    bound->sin_family = AF_INET;
    bound->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || bind(fd, (struct sockaddr *)bound, sizeof(*bound)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    socklen_t len = sizeof(*bound);
    struct timeval timeout = {2, 0};
    if (getsockname(fd, (struct sockaddr *)bound, &len) != 0
        || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int exchange(int fd, const struct sockaddr_in *server, const packet_builder *request,
                    unsigned char *response, size_t response_size)
{
    if (sendto(fd, request->bytes, request->len, 0, (const struct sockaddr *)server, sizeof(*server))
        != (ssize_t)request->len) return -1;
    return (int)recvfrom(fd, response, response_size, 0, NULL, NULL);
}

static int issue(const char *subject, turn_credential *out)
{
    char credential[64];
    return st_turn_auth_issue(subject, out->username, sizeof(out->username), credential, sizeof(credential)) == 0
        && st_turn_auth_long_term_key(out->username, out->key) == 0 ? 0 : -1;
}

/* 0 with the relayed address on success, otherwise the error code of the answer (-1 for none). */
static int allocate(int fd, const struct sockaddr_in *server, const turn_credential *credential,
                    unsigned seed, struct sockaddr_in *relay)
{
    packet_builder request;
    unsigned char response[1024];
    unsigned char transport[4] = {17, 0, 0, 0};
    start(&request, 0x0003U, seed);
    attr(&request, 0x0019U, transport, sizeof(transport));
    sign(&request, credential);
    int received = exchange(fd, server, &request, response, sizeof(response));
    size_t value_len = 0U;
    const unsigned char *relayed = received >= 20
        ? find_attr(response, (size_t)received, 0x0016U, &value_len) : NULL;
    if (received < 20 || r16(response) != 0x0103U || relayed == NULL || value_len != 8U) {
        int code = error_code(response, received);
        return code > 0 ? code : -1;
    }
    memset(relay, 0, sizeof(*relay));
    relay->sin_family = AF_INET;
    relay->sin_port = htons((unsigned short)(r16(relayed + 2U) ^ (COOKIE >> 16U)));
    relay->sin_addr.s_addr = htonl(r32(relayed + 4U) ^ COOKIE);
    return 0;
}

static void add_xor_peer(packet_builder *request, const struct sockaddr_in *peer)
{
    unsigned char encoded[8] = {0, 1, 0, 0, 0, 0, 0, 0};
    u16(encoded + 2U, ntohs(peer->sin_port) ^ (COOKIE >> 16U));
    u32(encoded + 4U, ntohl(peer->sin_addr.s_addr) ^ COOKIE);
    attr(request, 0x0012U, encoded, sizeof(encoded));
}

/*
 * The full relay round trip of one allocation: CreatePermission for the peer, a Send indication
 * that must reach it from the relayed address, and a datagram back that must reach the client as
 * a Data indication. 0 when all of it worked.
 */
static int relays_both_ways(int client, const struct sockaddr_in *server, const turn_credential *credential,
                            const struct sockaddr_in *relay, unsigned seed)
{
    struct sockaddr_in peer_address;
    int peer = udp_socket(&peer_address);
    if (peer < 0) return -1;
    packet_builder request;
    unsigned char response[1024];
    start(&request, 0x0008U, seed);
    add_xor_peer(&request, &peer_address);
    sign(&request, credential);
    int received = exchange(client, server, &request, response, sizeof(response));
    int failed = received < 20 || r16(response) != 0x0108U;
    if (!failed) {
        start(&request, 0x0016U, seed + 1U);
        add_xor_peer(&request, &peer_address);
        attr(&request, 0x0013U, "out", 3U);
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);
        char data[16];
        failed = sendto(client, request.bytes, request.len, 0, (const struct sockaddr *)server, sizeof(*server))
                != (ssize_t)request.len
            || recvfrom(peer, data, sizeof(data), 0, (struct sockaddr *)&source, &source_len) != 3
            || memcmp(data, "out", 3U) != 0 || source.sin_port != relay->sin_port;
    }
    if (!failed) {
        size_t value_len = 0U;
        failed = sendto(peer, "back", 4U, 0, (const struct sockaddr *)relay, sizeof(*relay)) != 4;
        received = failed ? -1 : (int)recvfrom(client, response, sizeof(response), 0, NULL, NULL);
        const unsigned char *data = received >= 20
            ? find_attr(response, (size_t)received, 0x0013U, &value_len) : NULL;
        failed = failed || r16(response) != 0x0017U || data == NULL || value_len != 4U
            || memcmp(data, "back", 4U) != 0;
    }
    close(peer);
    return failed ? -1 : 0;
}

static int binding_answered(int fd, const struct sockaddr_in *server, unsigned seed)
{
    packet_builder request;
    unsigned char response[1024];
    start(&request, 0x0001U, seed);
    int received = exchange(fd, server, &request, response, sizeof(response));
    return received >= 20 && r16(response) == 0x0101U;
}

static int start_server(st_stun_turn_server **server, struct sockaddr_in *address,
                        const char *relay_min_port, const char *relay_max_port)
{
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", relay_min_port, 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT", relay_max_port, 1);
    *server = NULL;
    if (st_stun_turn_server_start(server) != 0 || st_stun_turn_server_port(*server) <= 0) {
        fprintf(stderr, "STUN/TURN start failed\n");
        return -1;
    }
    memset(address, 0, sizeof(*address));
    address->sin_family = AF_INET;
    address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address->sin_port = htons((unsigned short)st_stun_turn_server_port(*server));
    return 0;
}

/*
 * A process with many connections open hands the STUN/TURN thread socket numbers at and past
 * FD_SETSIZE (the systemd unit allows 1048576 descriptors). Those sockets, the listener's and the
 * relay's alike, must be served like any other: select() could not even represent them, and a
 * fortified build aborted the whole process in FD_SET.
 */
static int test_sockets_past_fd_setsize(void)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return -1;
    rlim_t wanted = (rlim_t)FD_SETSIZE + 512U;
    if (limit.rlim_cur < wanted) {
        limit.rlim_cur = limit.rlim_max == RLIM_INFINITY || limit.rlim_max > wanted ? wanted : limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0 || limit.rlim_cur < wanted) {
            fprintf(stderr, "cannot raise RLIMIT_NOFILE past FD_SETSIZE; skipping\n");
            return 0;
        }
    }
    int fillers[FD_SETSIZE + 64];
    size_t filler_count = 0U;
    int failed = 0;
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            failed = 1;
            break;
        }
        fillers[filler_count++] = fd;
        if (fd >= (int)FD_SETSIZE + 16 || filler_count == sizeof(fillers) / sizeof(fillers[0])) break;
    }
    st_stun_turn_server *server = NULL;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    struct sockaddr_in relay;
    turn_credential credential;
    int client = -1;
    failed = failed || start_server(&server, &server_address, "56000", "56099") != 0
        || issue("public-transfer-fd", &credential) != 0
        || (client = udp_socket(&client_address)) < (int)FD_SETSIZE;
    if (failed) fprintf(stderr, "fd-limit fixture setup failed (client fd %d)\n", client);
    int code = failed ? -1 : allocate(client, &server_address, &credential, 10U, &relay);
    if (!failed && code != 0) {
        fprintf(stderr, "Allocate with descriptors past FD_SETSIZE failed: %d\n", code);
        failed = 1;
    }
    if (!failed && relays_both_ways(client, &server_address, &credential, &relay, 20U) != 0) {
        fprintf(stderr, "a relay socket past FD_SETSIZE did not relay both ways\n");
        failed = 1;
    }
    if (!failed && !binding_answered(client, &server_address, 30U)) {
        fprintf(stderr, "the STUN/TURN thread stopped answering after a relay socket past FD_SETSIZE\n");
        failed = 1;
    }
    if (client >= 0) close(client);
    if (server != NULL) st_stun_turn_server_stop(server);
    for (size_t i = 0; i < filler_count; ++i) close(fillers[i]);
    return failed ? -1 : 0;
}

/*
 * Java keeps allocations in an unbounded map: Peer Mesh relays are bounded only by the relay port
 * range, and the general relay only by its own quota (486 when spent). The old fixed table of 256
 * slots answered 508 past 256 allocations of either kind, so the general relay could crowd out
 * every Peer Mesh relay and a general quota above 256 did nothing.
 */
#define GENERAL_ALLOCATIONS 260
#define MESH_ALLOCATIONS 12

static int test_allocations_beyond_256(void)
{
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "260", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", "0", 1);
    st_stun_turn_server *server = NULL;
    struct sockaddr_in server_address;
    turn_credential general;
    static int clients[GENERAL_ALLOCATIONS + 1 + MESH_ALLOCATIONS];
    static turn_credential mesh[MESH_ALLOCATIONS];
    static unsigned char port_taken[65536];
    memset(port_taken, 0, sizeof(port_taken));
    size_t client_count = 0U;
    struct sockaddr_in client_address;
    struct sockaddr_in relay;
    int failed = start_server(&server, &server_address, "56100", "57099") != 0
        || issue("public-transfer-scale", &general) != 0;
    for (int i = 0; !failed && i < GENERAL_ALLOCATIONS; ++i) {
        int fd = udp_socket(&client_address);
        if (fd < 0) {
            failed = 1;
            break;
        }
        clients[client_count++] = fd;
        int code = allocate(fd, &server_address, &general, 1000U + (unsigned)i, &relay);
        if (code != 0) {
            fprintf(stderr, "general relay allocation %d of %d failed: %d\n", i + 1, GENERAL_ALLOCATIONS, code);
            failed = 1;
        } else if (port_taken[ntohs(relay.sin_port)]++ != 0U) {
            /* Two allocations on one port would take each other's datagrams. */
            fprintf(stderr, "relay port %u handed to two allocations\n", ntohs(relay.sin_port));
            failed = 1;
        }
    }
    /* The last of them is served like the first. */
    if (!failed && relays_both_ways(clients[client_count - 1U], &server_address, &general, &relay, 5000U) != 0) {
        fprintf(stderr, "allocation %d did not relay\n", GENERAL_ALLOCATIONS);
        failed = 1;
    }
    /* The general quota, not a table size, refuses the next general relay. */
    if (!failed) {
        int fd = udp_socket(&client_address);
        int code = fd < 0 ? -1 : allocate(fd, &server_address, &general, 6000U, &relay);
        if (fd >= 0) clients[client_count++] = fd;
        if (code != 486) {
            fprintf(stderr, "general relay past its quota: want 486, got %d\n", code);
            failed = 1;
        }
    }
    /* Peer Mesh relays are not held to the general quota and still find room. */
    for (int i = 0; !failed && i < MESH_ALLOCATIONS; ++i) {
        char subject[32];
        snprintf(subject, sizeof(subject), "pm-%d", 9000 + i);
        int fd = udp_socket(&client_address);
        int code = fd < 0 || issue(subject, &mesh[i]) != 0 ? -1
            : allocate(fd, &server_address, &mesh[i], 7000U + (unsigned)i, &relay);
        if (fd >= 0) clients[client_count++] = fd;
        if (code != 0) {
            fprintf(stderr, "Peer Mesh allocation %d next to a full general quota failed: %d\n", i + 1, code);
            failed = 1;
        }
    }
    for (size_t i = 0; i < client_count; ++i) close(clients[i]);
    if (server != NULL) st_stun_turn_server_stop(server);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "16", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", "16", 1);
    return failed ? -1 : 0;
}

/* With an argument, only the named case runs: fd-setsize or allocations. */
static int selected(int argc, char **argv, const char *name)
{
    return argc < 2 || strcmp(argv[1], name) == 0;
}

int main(int argc, char **argv)
{
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", "0", 1);
    setenv("SPECUS_PEER_MESH_BIND_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_RELAY_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS", "true", 1);
    setenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET", "peer-scale-secret", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "16", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS", "16", 1);
    unsetenv("SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("SPECUS_DATABASE_PATH");
    if ((selected(argc, argv, "fd-setsize") && test_sockets_past_fd_setsize() != 0)
        || (selected(argc, argv, "allocations") && test_allocations_beyond_256() != 0)) {
        fprintf(stderr, "STUN/TURN scale tests failed\n");
        return 1;
    }
    printf("STUN/TURN scale tests passed\n");
    return 0;
}
