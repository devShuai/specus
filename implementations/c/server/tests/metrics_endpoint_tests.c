#define _POSIX_C_SOURCE 200809L

/*
 * The actuator metrics endpoint of a real specus-server-c process (Java's
 * /actuator/metrics/{requiredMetricName} with management.endpoints.web.exposure.include=metrics),
 * scraped after real traffic: refused control frames, TURN allocations refused by quota, peers
 * refused by the destination policy, general relay bytes up to the byte quota, a relay send the
 * kernel refuses, and Peer Mesh relay bytes waiting for and written by the relay traffic flush.
 */

#include "crypto.h"
#include "server_harness.h"
#include "storage.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define COOKIE 0x2112a442U
#define TURN_SECRET "metrics-endpoint-turn-secret"

/* ---- HTTP ------------------------------------------------------------------------------------ */

typedef struct {
    int status;
    char *raw;
    const char *headers;
    const char *body;
} reply;

/* One request on its own connection; the listener answers and closes it. */
static int http_raw(int port, const char *method, const char *target, const char *extra_headers, reply *out)
{
    memset(out, 0, sizeof(*out));
    int fd = connect_local(port);
    if (fd < 0) {
        return -1;
    }
    char request[1024];
    int len = snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%sConnection: close\r\n\r\n",
                       method, target, port, extra_headers == NULL ? "" : extra_headers);
    if (len < 0 || (size_t)len >= sizeof(request) || send_all(fd, (const uint8_t *)request, (size_t)len) != 0) {
        close(fd);
        return -1;
    }
    size_t capacity = 16384U;
    size_t used = 0U;
    char *data = (char *)malloc(capacity + 1U);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (data != NULL) {
        if (used == capacity) {
            char *grown = (char *)realloc(data, capacity * 2U + 1U);
            if (grown == NULL) break;
            data = grown;
            capacity *= 2U;
        }
        struct pollfd ready = {fd, POLLIN, 0};
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) break;
        ssize_t received = recv(fd, data + used, capacity - used, 0);
        if (received <= 0) break;
        used += (size_t)received;
    }
    close(fd);
    if (data == NULL) {
        return -1;
    }
    data[used] = '\0';
    out->raw = data;
    (void)sscanf(data, "HTTP/1.1 %d", &out->status);
    char *end = strstr(data, "\r\n\r\n");
    if (end == NULL) {
        return -1;
    }
    end[2] = '\0';
    out->headers = data;
    out->body = end + 4;
    return 0;
}

static void reply_free(reply *value)
{
    free(value->raw);
    value->raw = NULL;
}

static int header_present(const reply *value, const char *line)
{
    char needle[256];
    snprintf(needle, sizeof(needle), "\r\n%s\r\n", line);
    return value->headers != NULL && strstr(value->headers, needle) != NULL;
}

/* The single measurement of /actuator/metrics/<name><query>, as the text Java's Double.toString gives. */
static int scrape(const test_server *server, const char *name, const char *query, char *value, size_t value_len)
{
    char target[256];
    snprintf(target, sizeof(target), "/actuator/metrics/%s%s", name, query == NULL ? "" : query);
    reply answer;
    if (http_raw(server->admin_port, "GET", target, NULL, &answer) != 0 || answer.status != 200) {
        fprintf(stderr, "GET %s: %d %s\n", target, answer.status, answer.raw == NULL ? "" : answer.raw);
        reply_free(&answer);
        return -1;
    }
    const char *start = strstr(answer.body, "\"value\":");
    const char *end = start == NULL ? NULL : strchr(start, '}');
    if (start == NULL || end == NULL || (size_t)(end - start - 8) >= value_len) {
        reply_free(&answer);
        return -1;
    }
    start += 8;
    memcpy(value, start, (size_t)(end - start));
    value[end - start] = '\0';
    reply_free(&answer);
    return 0;
}

/*
 * Waits up to 2 s for the measurement to read expected: a datagram the test sent without an answer
 * (a Send indication) is counted when the STUN/TURN thread gets to it, not before sendto returns.
 */
static int expect_value(const test_server *server, const char *name, const char *query, const char *expected)
{
    char value[64] = "";
    long long deadline = monotonic_ms() + 2000;
    for (;;) {
        int rc = scrape(server, name, query, value, sizeof(value));
        if (rc == 0 && strcmp(value, expected) == 0) {
            return 0;
        }
        if (rc != 0 || monotonic_ms() >= deadline) {
            break;
        }
        sleep_ms(20);
    }
    fprintf(stderr, "%s%s is %s, want %s\n", name, query == NULL ? "" : query, value, expected);
    return -1;
}

/* ---- the control channel --------------------------------------------------------------------- */

/* Sends raw bytes as a fresh connection's first frame and waits for the server to close it. */
static int refused_frame(const test_server *server, const uint8_t *frame, size_t frame_len)
{
    int fd = connect_local(server->control_port);
    if (fd < 0 || send_all(fd, frame, frame_len) != 0) {
        close_fd(&fd);
        return -1;
    }
    int rc = expect_channel_closed(fd, IO_TIMEOUT_MS);
    close_fd(&fd);
    return rc;
}

static void frame_header(uint8_t out[ST_HEADER_SIZE], uint32_t magic, uint8_t version, uint8_t command,
                         uint32_t length)
{
    out[0] = (uint8_t)(magic >> 24U);
    out[1] = (uint8_t)(magic >> 16U);
    out[2] = (uint8_t)(magic >> 8U);
    out[3] = (uint8_t)magic;
    out[4] = version;
    out[5] = ST_SERIALIZER_COMPACT_BINARY;
    out[6] = command;
    out[7] = (uint8_t)(length >> 24U);
    out[8] = (uint8_t)(length >> 16U);
    out[9] = (uint8_t)(length >> 8U);
    out[10] = (uint8_t)length;
}

/* ---- TURN ------------------------------------------------------------------------------------ */

typedef struct {
    unsigned char bytes[2048];
    size_t len;
} packet;

typedef struct {
    struct sockaddr_in server;
    char realm[128];
    char nonce[128];
} turn_target;

typedef struct {
    int fd;
    char username[192];
    unsigned char key[16];
    struct sockaddr_in relay;
} turn_client;

static void put16(unsigned char *out, unsigned value)
{
    out[0] = (unsigned char)(value >> 8U);
    out[1] = (unsigned char)value;
}

static void put32(unsigned char *out, unsigned value)
{
    out[0] = (unsigned char)(value >> 24U);
    out[1] = (unsigned char)(value >> 16U);
    out[2] = (unsigned char)(value >> 8U);
    out[3] = (unsigned char)value;
}

static unsigned get16(const unsigned char *in)
{
    return ((unsigned)in[0] << 8U) | in[1];
}

static unsigned get32(const unsigned char *in)
{
    return ((unsigned)in[0] << 24U) | ((unsigned)in[1] << 16U) | ((unsigned)in[2] << 8U) | in[3];
}

static void packet_start(packet *out, unsigned type, unsigned seed)
{
    memset(out, 0, sizeof(*out));
    out->len = 20U;
    put16(out->bytes, type);
    put32(out->bytes + 4U, COOKIE);
    for (size_t i = 0; i < 12U; ++i) out->bytes[8U + i] = (unsigned char)(seed * 13U + i);
}

static void packet_attr(packet *out, unsigned type, const void *value, size_t len)
{
    size_t padded = (len + 3U) & ~3U;
    put16(out->bytes + out->len, type);
    put16(out->bytes + out->len + 2U, (unsigned)len);
    memcpy(out->bytes + out->len + 4U, value, len);
    memset(out->bytes + out->len + 4U + len, 0, padded - len);
    out->len += 4U + padded;
    put16(out->bytes + 2U, (unsigned)(out->len - 20U));
}

static void packet_peer(packet *out, const struct sockaddr_in *peer)
{
    unsigned char encoded[8] = {0, 1, 0, 0, 0, 0, 0, 0};
    put16(encoded + 2U, ntohs(peer->sin_port) ^ (COOKIE >> 16U));
    put32(encoded + 4U, ntohl(peer->sin_addr.s_addr) ^ COOKIE);
    packet_attr(out, 0x0012U, encoded, sizeof(encoded));
}

static void packet_sign(packet *out, const turn_target *target, const turn_client *client)
{
    unsigned char mac[20];
    packet_attr(out, 0x0006U, client->username, strlen(client->username));
    packet_attr(out, 0x0014U, target->realm, strlen(target->realm));
    packet_attr(out, 0x0015U, target->nonce, strlen(target->nonce));
    put16(out->bytes + 2U, (unsigned)(out->len + 24U - 20U));
    st_hmac_sha1(client->key, 16U, out->bytes, out->len, mac);
    packet_attr(out, 0x0008U, mac, sizeof(mac));
}

static const unsigned char *packet_find(const unsigned char *data, size_t len, unsigned type, size_t *value_len)
{
    size_t end = 20U + get16(data + 2U);
    if (len < 20U || end > len) return NULL;
    for (size_t offset = 20U; offset + 4U <= end;) {
        size_t length = get16(data + offset + 2U);
        if (offset + 4U + length > end) return NULL;
        if (get16(data + offset) == type) {
            *value_len = length;
            return data + offset + 4U;
        }
        offset += 4U + ((length + 3U) & ~3U);
    }
    return NULL;
}

static int udp_open(struct sockaddr_in *bound)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(bound, 0, sizeof(*bound));
    bound->sin_family = AF_INET;
    bound->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t len = sizeof(*bound);
    if (fd < 0 || bind(fd, (struct sockaddr *)bound, sizeof(*bound)) != 0
        || getsockname(fd, (struct sockaddr *)bound, &len) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    struct timeval timeout = {2, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    return fd;
}

/* Sends request and returns the answer's length (or -1); its type in *type. */
static int turn_exchange(int fd, const turn_target *target, const packet *request, unsigned char *response,
                         size_t response_size)
{
    if (sendto(fd, request->bytes, request->len, 0, (const struct sockaddr *)&target->server,
               sizeof(target->server)) != (ssize_t)request->len) return -1;
    return (int)recvfrom(fd, response, response_size, 0, NULL, NULL);
}

static int error_code(const unsigned char *response, int len)
{
    size_t value_len = 0;
    const unsigned char *error = len >= 20 ? packet_find(response, (size_t)len, 0x0009U, &value_len) : NULL;
    return error == NULL || value_len < 4U ? 0 : (int)(error[2] & 7U) * 100 + error[3];
}

/* The UDP port the next server's STUN/TURN listener is given. */
static int stun_port;

static void use_fresh_stun_port(void)
{
    struct sockaddr_in bound;
    int fd = udp_open(&bound);
    stun_port = fd < 0 ? 0 : ntohs(bound.sin_port);
    if (fd >= 0) close(fd);
    char value[16];
    snprintf(value, sizeof(value), "%d", stun_port);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", value, 1);
}

/* The realm and nonce of the server, from the 401 an unauthenticated Allocate gets. */
static int turn_challenge(turn_target *target)
{
    int port = stun_port;
    memset(target, 0, sizeof(*target));
    target->server.sin_family = AF_INET;
    target->server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target->server.sin_port = htons((unsigned short)port);
    struct sockaddr_in bound;
    int fd = udp_open(&bound);
    packet request;
    unsigned char response[2048];
    unsigned char transport[4] = {17, 0, 0, 0};
    packet_start(&request, 0x0003U, 1U);
    packet_attr(&request, 0x0019U, transport, sizeof(transport));
    int len = fd < 0 ? -1 : turn_exchange(fd, target, &request, response, sizeof(response));
    if (fd >= 0) close(fd);
    size_t realm_len = 0;
    size_t nonce_len = 0;
    const unsigned char *realm = len >= 20 ? packet_find(response, (size_t)len, 0x0014U, &realm_len) : NULL;
    const unsigned char *nonce = len >= 20 ? packet_find(response, (size_t)len, 0x0015U, &nonce_len) : NULL;
    if (error_code(response, len) != 401 || realm == NULL || nonce == NULL || realm_len >= sizeof(target->realm)
        || nonce_len >= sizeof(target->nonce)) {
        fprintf(stderr, "no TURN challenge (%d bytes, error %d)\n", len, error_code(response, len));
        return -1;
    }
    memcpy(target->realm, realm, realm_len);
    memcpy(target->nonce, nonce, nonce_len);
    return 0;
}

/* Allocates for subject; 0 with the relayed address, otherwise the error code (or -1). */
static int turn_allocate(const turn_target *target, const char *subject, unsigned seed, turn_client *client)
{
    char credential[64];
    struct sockaddr_in bound;
    client->fd = udp_open(&bound);
    if (client->fd < 0 || st_turn_auth_issue(subject, client->username, sizeof(client->username), credential,
                                             sizeof(credential)) != 0
        || st_turn_auth_long_term_key(client->username, client->key) != 0) return -1;
    packet request;
    unsigned char response[2048];
    unsigned char transport[4] = {17, 0, 0, 0};
    packet_start(&request, 0x0003U, seed);
    packet_attr(&request, 0x0019U, transport, sizeof(transport));
    packet_sign(&request, target, client);
    int len = turn_exchange(client->fd, target, &request, response, sizeof(response));
    size_t value_len = 0;
    const unsigned char *relayed = len >= 20 ? packet_find(response, (size_t)len, 0x0016U, &value_len) : NULL;
    if (len < 20 || get16(response) != 0x0103U || relayed == NULL || value_len != 8U) {
        int code = error_code(response, len);
        return code > 0 ? code : -1;
    }
    memset(&client->relay, 0, sizeof(client->relay));
    client->relay.sin_family = AF_INET;
    client->relay.sin_port = htons((unsigned short)(get16(relayed + 2U) ^ (COOKIE >> 16U)));
    client->relay.sin_addr.s_addr = htonl(get32(relayed + 4U) ^ COOKIE);
    return 0;
}

/* CreatePermission (0x0008) or ChannelBind (0x0009) for peer; 0 on success, else the error code. */
static int turn_permit(const turn_target *target, const turn_client *client, unsigned type,
                       const struct sockaddr_in *peer, unsigned seed)
{
    packet request;
    unsigned char response[2048];
    packet_start(&request, type, seed);
    if (type == 0x0009U) {
        unsigned char channel[4] = {0x40, 0x00, 0, 0};
        packet_attr(&request, 0x000cU, channel, sizeof(channel));
    }
    packet_peer(&request, peer);
    packet_sign(&request, target, client);
    int len = turn_exchange(client->fd, target, &request, response, sizeof(response));
    if (len >= 20 && (get16(response) == 0x0108U || get16(response) == 0x0109U)) return 0;
    int code = error_code(response, len);
    return code > 0 ? code : -1;
}

/* A Send indication carrying payload to peer through the client's allocation. */
static int turn_send(const turn_target *target, const turn_client *client, const struct sockaddr_in *peer,
                     const void *payload, size_t payload_len, unsigned seed)
{
    packet request;
    packet_start(&request, 0x0016U, seed);
    packet_peer(&request, peer);
    packet_attr(&request, 0x0013U, payload, payload_len);
    return sendto(client->fd, request.bytes, request.len, 0, (const struct sockaddr *)&target->server,
                  sizeof(target->server)) == (ssize_t)request.len ? 0 : -1;
}

/* Waits up to timeout_ms for a datagram of exactly len bytes (raw, or as a Data indication's DATA). */
static int datagram_arrives(int fd, size_t len, int data_indication, long timeout_ms)
{
    struct timeval timeout = {timeout_ms / 1000L, (timeout_ms % 1000L) * 1000L};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    unsigned char data[2048];
    int received = (int)recvfrom(fd, data, sizeof(data), 0, NULL, NULL);
    if (!data_indication) return received == (int)len;
    size_t value_len = 0;
    return received >= 20 && get16(data) == 0x0017U && packet_find(data, (size_t)received, 0x0013U, &value_len) != NULL
        && value_len == len;
}

static void turn_client_close(turn_client *client)
{
    if (client->fd >= 0) close(client->fd);
    client->fd = -1;
}

/* ---- scenarios ------------------------------------------------------------------------------- */

static const char java_names[] =
    "{\"names\":[\"specus.control.plaintext.deployment.rejected\",\"specus.control.preauth.oversize.rejected\","
    "\"specus.control.protocol.rejected\",\"specus.control.tls.certificate.expiry.epoch.seconds\","
    "\"specus.control.tls.mode\",\"specus.peer_mesh.relay.traffic.flush.failures\","
    "\"specus.peer_mesh.relay.traffic.flush.lag.seconds\",\"specus.peer_mesh.relay.traffic.pending.bytes\","
    "\"specus.peer_mesh.turn.general_relay.bytes\",\"specus.peer_mesh.turn.general_relay.destination.forbidden\","
    "\"specus.peer_mesh.turn.general_relay.quota.closed\",\"specus.peer_mesh.turn.general_relay.quota.rejected\","
    "\"specus.peer_mesh.turn.relay.queue.depth\",\"specus.peer_mesh.turn.relay.queue.dropped\","
    "\"specus.peer_mesh.turn.relay.queue.high.water\",\"specus.peer_mesh.turn.relay.send.failures\"]}";

static void peer_mesh_environment(const char *flush_interval_ms)
{
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    use_fresh_stun_port();
    setenv("SPECUS_PEER_MESH_BIND_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_RELAY_ADDRESS", "127.0.0.1", 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", "58500", 1);
    setenv("SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT", "58599", 1);
    setenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET", TURN_SECRET, 1);
    setenv("SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS", flush_interval_ms, 1);
}

static void clear_environment(void)
{
    static const char *const names[] = {
        "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_EXCLUDE",
        "SPECUS_PEER_MESH_ENABLED", "SPECUS_PEER_MESH_STUN_TURN_PORT", "SPECUS_PEER_MESH_BIND_ADDRESS",
        "SPECUS_PEER_MESH_RELAY_ADDRESS", "SPECUS_PEER_MESH_TURN_RELAY_MIN_PORT", "SPECUS_PEER_MESH_TURN_RELAY_MAX_PORT",
        "SPECUS_PEER_MESH_RELAY_TRAFFIC_FLUSH_INTERVAL_MS", "SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS",
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS_PER_ADDRESS",
        "SPECUS_PEER_MESH_GENERAL_RELAY_MAX_BYTES",
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) unsetenv(names[i]);
    setenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET", TURN_SECRET, 1);
}

/* Spring Boot exposes health alone over the web unless told otherwise: no metrics routes. */
static int scenario_not_exposed(test_server *server)
{
    static const char *const targets[] = {"/actuator/metrics", "/actuator/metrics/specus.control.tls.mode"};
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        reply answer;
        int rc = http_raw(server->admin_port, "GET", targets[i], NULL, &answer);
        int ok = rc == 0 && answer.status == 404 && strstr(answer.body, "specus.") == NULL;
        if (!ok) fprintf(stderr, "GET %s without exposure: %d %s\n", targets[i], answer.status, answer.raw);
        reply_free(&answer);
        CHECK(ok, "the metrics endpoint answered without being exposed");
    }
    return 0;
}

/* Refused control frames, then general TURN allocations refused by quota and peers by the policy. */
static int scenario_control_and_turn_policy(test_server *server)
{
    reply answer;
    CHECK(http_raw(server->admin_port, "GET", "/actuator/metrics", NULL, &answer) == 0 && answer.status == 200
              && strcmp(answer.body, java_names) == 0
              && header_present(&answer, "Content-Type: application/vnd.spring-boot.actuator.v3+json"),
          "names: %d %s", answer.status, answer.raw);
    reply_free(&answer);
    /* Java leaves /actuator open: a token, even a bad one, changes nothing. */
    CHECK(http_raw(server->admin_port, "GET", "/actuator/metrics/specus.control.tls.mode",
                   "Authorization: Bearer garbage\r\nAccept: application/json\r\n", &answer) == 0
              && answer.status == 200 && header_present(&answer, "Content-Type: application/json")
              && header_present(&answer, "Content-Disposition: inline;filename=f.txt")
              && strcmp(answer.body, "{\"availableTags\":[{\"tag\":\"mode\",\"values\":[\"disabled\"]}],"
                                     "\"measurements\":[{\"statistic\":\"VALUE\",\"value\":1.0}],"
                                     "\"name\":\"specus.control.tls.mode\"}") == 0,
          "tls mode: %d %s", answer.status, answer.raw);
    reply_free(&answer);
    CHECK(http_raw(server->admin_port, "GET", "/actuator/metrics", "Accept: text/plain\r\n", &answer) == 0
              && answer.status == 406,
          "Accept text/plain: %d", answer.status);
    reply_free(&answer);
    CHECK(http_raw(server->admin_port, "POST", "/actuator/metrics", "Content-Length: 0\r\n", &answer) == 0
              && answer.status == 405 && header_present(&answer, "Allow: GET"),
          "POST: %d", answer.status);
    reply_free(&answer);

    uint8_t frame[ST_HEADER_SIZE + 16U];
    frame_header(frame, 0U, ST_VERSION, ST_CMD_LOGIN_REQUEST, 0U);
    CHECK(refused_frame(server, frame, ST_HEADER_SIZE) == 0, "a frame with a bad magic was not refused");
    frame_header(frame, ST_MAGIC, 9U, ST_CMD_LOGIN_REQUEST, 0U);
    CHECK(refused_frame(server, frame, ST_HEADER_SIZE) == 0, "a frame of version 9 was not refused");
    /* Too long before login: refused from the length field, whatever the rest says. */
    frame_header(frame, 0U, 9U, 99U, 1U << 20U);
    CHECK(refused_frame(server, frame, ST_HEADER_SIZE) == 0, "an oversized pre-auth frame was not refused");
    /* A login body with a byte after its last field. */
    static const uint8_t login[] = {2, 'c', 0, 2, 't', 8, 'c', 'o', 'n', 't', 'r', 'o', 'l', 0};
    frame_header(frame, ST_MAGIC, ST_VERSION, ST_CMD_LOGIN_REQUEST, (uint32_t)sizeof(login));
    memcpy(frame + ST_HEADER_SIZE, login, sizeof(login));
    CHECK(refused_frame(server, frame, ST_HEADER_SIZE + sizeof(login)) == 0, "a malformed login was not refused");
    CHECK(expect_value(server, "specus.control.protocol.rejected", "?tag=reason:invalid_magic", "1.0") == 0
              && expect_value(server, "specus.control.protocol.rejected", "?tag=reason:unsupported_version",
                              "1.0") == 0
              && expect_value(server, "specus.control.protocol.rejected", "?tag=reason:malformed_body", "1.0") == 0
              && expect_value(server, "specus.control.protocol.rejected", "?tag=reason:invalid_length", "0.0") == 0
              && expect_value(server, "specus.control.protocol.rejected", NULL, "3.0") == 0
              && expect_value(server, "specus.control.preauth.oversize.rejected", NULL, "1.0") == 0,
          "control-channel rejections were not counted");

    turn_target target;
    CHECK(turn_challenge(&target) == 0, "no TURN challenge");
    turn_client first = {-1, "", {0}, {0}};
    turn_client second = {-1, "", {0}, {0}};
    int allocated = turn_allocate(&target, "public-transfer", 10U, &first);
    int refused = turn_allocate(&target, "public-transfer", 11U, &second);
    struct sockaddr_in loopback = {0};
    loopback.sin_family = AF_INET;
    loopback.sin_port = htons(9U);
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    struct sockaddr_in private_peer = loopback;
    private_peer.sin_addr.s_addr = htonl(0x0a000001U);
    int permission = allocated == 0 ? turn_permit(&target, &first, 0x0008U, &loopback, 12U) : -1;
    int channel = allocated == 0 ? turn_permit(&target, &first, 0x0009U, &private_peer, 13U) : -1;
    turn_client_close(&first);
    turn_client_close(&second);
    CHECK(allocated == 0 && refused == 486, "general relay allocations: %d then %d, want 0 then 486", allocated,
          refused);
    CHECK(permission == 403 && channel == 403, "private peers: %d and %d, want 403", permission, channel);
    CHECK(expect_value(server, "specus.peer_mesh.turn.general_relay.quota.rejected", NULL, "1.0") == 0
              && expect_value(server, "specus.peer_mesh.turn.general_relay.destination.forbidden", NULL, "2.0") == 0
              && expect_value(server, "specus.peer_mesh.turn.general_relay.bytes", NULL, "0.0") == 0
              && expect_value(server, "specus.peer_mesh.turn.relay.queue.dropped", NULL, "0.0") == 0
              && expect_value(server, "specus.control.tls.certificate.expiry.epoch.seconds", NULL, "0.0") == 0,
          "TURN refusals were not counted");
    return 0;
}

/* General relay bytes up to the byte quota, a send the kernel refuses, and the quota closing. */
static int scenario_general_relay_bytes(test_server *server)
{
    turn_target target;
    CHECK(turn_challenge(&target) == 0, "no TURN challenge");
    turn_client client = {-1, "", {0}, {0}};
    struct sockaddr_in peer_address;
    int peer = udp_open(&peer_address);
    struct sockaddr_in broadcast = {0};
    broadcast.sin_family = AF_INET;
    broadcast.sin_port = htons(9U);
    broadcast.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    char payload[40];
    memset(payload, 'r', sizeof(payload));
    int ok = peer >= 0 && turn_allocate(&target, "public-transfer", 20U, &client) == 0
        && turn_permit(&target, &client, 0x0008U, &peer_address, 21U) == 0
        && turn_permit(&target, &client, 0x0008U, &broadcast, 22U) == 0
        && turn_send(&target, &client, &peer_address, payload, sizeof(payload), 23U) == 0
        && datagram_arrives(peer, sizeof(payload), 0, 2000L);
    if (!ok) {
        turn_client_close(&client);
        if (peer >= 0) close(peer);
        CHECK(0, "a general relay datagram did not arrive");
    }
    /* Counted, then refused by the kernel: no SO_BROADCAST on the relay socket. */
    ok = turn_send(&target, &client, &broadcast, payload, sizeof(payload), 24U) == 0
        && expect_value(server, "specus.peer_mesh.turn.general_relay.bytes", NULL, "80.0") == 0
        && expect_value(server, "specus.peer_mesh.turn.relay.send.failures", NULL, "1.0") == 0;
    /* 120 bytes is past the 100-byte quota: the allocation closes and this datagram is not relayed. */
    ok = ok && turn_send(&target, &client, &peer_address, payload, sizeof(payload), 25U) == 0
        && !datagram_arrives(peer, sizeof(payload), 0, 300L)
        && expect_value(server, "specus.peer_mesh.turn.general_relay.quota.closed", NULL, "1.0") == 0
        && expect_value(server, "specus.peer_mesh.turn.general_relay.bytes", NULL, "80.0") == 0;
    turn_client_close(&client);
    close(peer);
    CHECK(ok, "general relay bytes, send failures or the byte quota were not counted");
    return 0;
}

typedef struct {
    st_storage_client source;
    st_storage_client target;
    st_storage_peer_mesh_session session;
} relay_fixture;

/* Two enabled Peer Mesh devices and an open session between them, in the server's database. */
static int relay_fixture_setup(const test_server *server, relay_fixture *fixture)
{
    st_storage_peer_mesh_device device;
    uint8_t digest[ST_SHA256_LEN];
    char token_hash[ST_SHA256_HEX_LEN + 1U];
    st_sha256((const uint8_t *)"metrics-relay-token", strlen("metrics-relay-token"), digest);
    st_hex_encode(digest, sizeof(digest), token_hash);
    return st_storage_upsert_client(server->db_path, 0, "tenant-metrics", "metrics-source", "owner", 1, 60,
                                    &fixture->source) == 0
        && st_storage_upsert_client(server->db_path, 0, "tenant-metrics", "metrics-target", "owner", 1, 60,
                                    &fixture->target) == 0
        && st_storage_update_peer_mesh_device_enabled(server->db_path, &fixture->source, 1, &device) == 0
        && st_storage_update_peer_mesh_device_enabled(server->db_path, &fixture->target, 1, &device) == 0
        && st_storage_create_peer_mesh_session(server->db_path, &fixture->source, &fixture->target, "DIRECT",
                                               token_hash, 3600, &fixture->session) == 0
        ? 0 : -1;
}

/* An SPM2 data frame (magic, session id, sequence, 32 opaque bytes) relayed from source to target. */
static int relay_spm2_frame(const turn_target *target, const relay_fixture *fixture)
{
    char source_subject[64];
    char target_subject[64];
    snprintf(source_subject, sizeof(source_subject), "pm-%lld", fixture->source.id);
    snprintf(target_subject, sizeof(target_subject), "pm-%lld", fixture->target.id);
    turn_client source = {-1, "", {0}, {0}};
    turn_client destination = {-1, "", {0}, {0}};
    unsigned char frame[52];
    memset(frame, 0xa5, sizeof(frame));
    put32(frame, 0x53504d32U);
    put32(frame + 4U, (unsigned)((unsigned long long)fixture->session.id >> 32U));
    put32(frame + 8U, (unsigned)fixture->session.id);
    put32(frame + 12U, 0U);
    put32(frame + 16U, 1U);
    int ok = turn_allocate(target, source_subject, 30U, &source) == 0
        && turn_allocate(target, target_subject, 31U, &destination) == 0
        && turn_permit(target, &source, 0x0008U, &destination.relay, 32U) == 0
        && turn_permit(target, &destination, 0x0008U, &source.relay, 33U) == 0
        && turn_send(target, &source, &destination.relay, frame, sizeof(frame), 34U) == 0
        && datagram_arrives(destination.fd, sizeof(frame), 1, 2000L);
    turn_client_close(&source);
    turn_client_close(&destination);
    return ok ? 0 : -1;
}

/* No batch is due for ten minutes: the relayed frame's bytes wait, and nothing was written yet. */
static int scenario_relay_bytes_pending(test_server *server)
{
    turn_target target;
    relay_fixture fixture;
    CHECK(relay_fixture_setup(server, &fixture) == 0, "Peer Mesh relay fixture setup failed");
    CHECK(turn_challenge(&target) == 0, "no TURN challenge");
    CHECK(relay_spm2_frame(&target, &fixture) == 0, "the SPM2 frame was not relayed");
    CHECK(expect_value(server, "specus.peer_mesh.relay.traffic.pending.bytes", NULL, "52.0") == 0
              && expect_value(server, "specus.peer_mesh.relay.traffic.flush.lag.seconds", NULL, "0.0") == 0
              && expect_value(server, "specus.peer_mesh.relay.traffic.flush.failures", NULL, "0.0") == 0,
          "pending relay bytes were not shown");
    return 0;
}

/* Batches every 200 ms: the bytes reach the session row and the flush lag starts counting. */
static int scenario_relay_bytes_flushed(test_server *server)
{
    turn_target target;
    relay_fixture fixture;
    CHECK(relay_fixture_setup(server, &fixture) == 0, "Peer Mesh relay fixture setup failed");
    CHECK(turn_challenge(&target) == 0, "no TURN challenge");
    CHECK(relay_spm2_frame(&target, &fixture) == 0, "the SPM2 frame was not relayed");
    long long deadline = monotonic_ms() + 5000;
    st_storage_peer_mesh_session session;
    memset(&session, 0, sizeof(session));
    while (monotonic_ms() < deadline
           && !(st_storage_get_peer_mesh_session(server->db_path, "tenant-metrics", fixture.session.id, &session) == 0
                && session.relay_bytes == 52)) {
        sleep_ms(50);
    }
    CHECK(session.relay_bytes == 52, "the relay batch was not written: %lld bytes", session.relay_bytes);
    char lag[64] = "";
    CHECK(expect_value(server, "specus.peer_mesh.relay.traffic.pending.bytes", NULL, "0.0") == 0
              && expect_value(server, "specus.peer_mesh.relay.traffic.flush.failures", NULL, "0.0") == 0
              && scrape(server, "specus.peer_mesh.relay.traffic.flush.lag.seconds", NULL, lag, sizeof(lag)) == 0,
          "the written batch was not shown");
    double seconds = strtod(lag, NULL);
    CHECK(seconds >= 0.0 && seconds < 5.0, "flush lag %s after a written batch", lag);
    return 0;
}

/* Java fails to start on an endpoint id it cannot read; so does C. */
static int refused_start(const char *label, const char *variable, const char *value, const char *reason)
{
    test_server server;
    CHECK(server_prepare(&server) == 0, "cannot prepare the server directory");
    setenv(variable, value, 1);
    int started = server_start(&server) == 0;
    unsetenv(variable);
    FILE *log = fopen(server.log_path, "r");
    char line[512];
    int reported = 0;
    while (log != NULL && fgets(line, sizeof(line), log) != NULL) {
        reported = reported || strstr(line, reason) != NULL;
    }
    if (log != NULL) fclose(log);
    int failed = started || !reported;
    server_cleanup(&server, failed);
    printf("%s %s\n", failed ? "FAIL" : "ok  ", label);
    return failed;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    clear_environment();
    int failures = run_on_fresh_server("no metrics routes without exposure", scenario_not_exposed, NULL);
    failures += refused_start("an invalid exposure setting stops the start", "MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE",
                              "health,Metrics", "'value' must not start with an uppercase letter");
    /* Spring Boot: a management address needs a management port of its own. */
    failures += refused_start("a management address without its own port stops the start", "MANAGEMENT_SERVER_ADDRESS",
                              "127.0.0.2", "Management-specific server address cannot be configured");
    /* Exposed, but Java serves it on another port, or not at all: nothing on this listener. */
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "metrics", 1);
    setenv("MANAGEMENT_SERVER_PORT", "9", 1);
    failures += run_on_fresh_server("no metrics routes when the management port is another", scenario_not_exposed, NULL);
    unsetenv("MANAGEMENT_SERVER_PORT");
    setenv("MANAGEMENT_ENDPOINT_METRICS_ACCESS", "none", 1);
    failures += run_on_fresh_server("no metrics routes when the endpoint's access is none", scenario_not_exposed, NULL);
    unsetenv("MANAGEMENT_ENDPOINT_METRICS_ACCESS");
    unsetenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE");

    peer_mesh_environment("600000");
    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "health,metrics", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS", "1", 1);
    failures += run_on_fresh_server("refused control frames and TURN refusals", scenario_control_and_turn_policy,
                                    NULL);
    unsetenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_ALLOCATIONS");

    setenv("MANAGEMENT_ENDPOINTS_WEB_EXPOSURE_INCLUDE", "*", 1);
    setenv("SPECUS_PEER_MESH_TURN_ALLOW_PRIVATE_PEERS", "true", 1);
    setenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_BYTES", "100", 1);
    use_fresh_stun_port();
    failures += run_on_fresh_server("general relay bytes, send failures and the byte quota",
                                    scenario_general_relay_bytes, NULL);
    unsetenv("SPECUS_PEER_MESH_GENERAL_RELAY_MAX_BYTES");

    use_fresh_stun_port();
    failures += run_on_fresh_server("Peer Mesh relay bytes waiting for a batch", scenario_relay_bytes_pending, NULL);
    peer_mesh_environment("200");
    failures += run_on_fresh_server("Peer Mesh relay bytes written by the flush", scenario_relay_bytes_flushed, NULL);
    clear_environment();
    return failures == 0 ? 0 : 1;
}
