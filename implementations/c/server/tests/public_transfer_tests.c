/*
 * Public transfer parity against the Java reference: PublicTransferDiscoveryWebSocketHandlerTests,
 * PublicTransferRelayFrameTests, WebSocketTicketServiceTests, PublicTransferRoomResourceTests and
 * PublicTransferRoomServiceTests.
 *
 * The admin server runs in this process and the checks speak real HTTP and WebSocket over loopback.
 * SPECUS_TRUSTED_PROXIES trusts loopback, so X-Real-IP chooses each participant's public address.
 * Only the participants whose resolved address must be "unknown" or blank, which no loopback
 * request resolves to, drive the discovery handler over a socketpair with that address.
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "json.h"
#include "public_discovery.h"
#include "public_room.h"
#include "security.h"
#include "storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#define JWT_SECRET "public-transfer-parity-jwt-secret-with-more-than-32-bytes"
#define FRAME_CAP 65536U
#define TEXT_CAP 16384U

#define CHECK(condition, ...)                                   \
    do {                                                        \
        if (!(condition)) {                                     \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
            return 1;                                           \
        }                                                       \
    } while (0)

static int admin_port = -1;
static char db_path[128];

static int contains(const char *haystack, const char *needle)
{
    return haystack != NULL && strstr(haystack, needle) != NULL;
}

/* ---- sockets and HTTP ---------------------------------------------------------------------- */

static int connect_admin(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)admin_port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    size_t sent = 0U;
    while (sent < len) {
        ssize_t written = send(fd, bytes + sent, len - sent, MSG_NOSIGNAL);
        if (written <= 0) return -1;
        sent += (size_t)written;
    }
    return 0;
}

static int recv_all(int fd, void *data, size_t len)
{
    uint8_t *bytes = (uint8_t *)data;
    size_t received = 0U;
    while (received < len) {
        ssize_t got = recv(fd, bytes + received, len - received, 0);
        if (got <= 0) return -1;
        received += (size_t)got;
    }
    return 0;
}

/* One request on a fresh connection; returns the status code and keeps the whole response. */
static int http_call(const char *method, const char *path, const char *headers, const char *body,
                     char *response, size_t response_len)
{
    char request[8192];
    size_t body_len = body == NULL ? 0U : strlen(body);
    int len = snprintf(request, sizeof(request),
                       "%s %s HTTP/1.1\r\nHost: localhost\r\n%sContent-Type: application/json\r\n"
                       "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
                       method, path, headers == NULL ? "" : headers, body_len, body == NULL ? "" : body);
    response[0] = '\0';
    int fd = len < 0 || (size_t)len >= sizeof(request) ? -1 : connect_admin();
    if (fd < 0) return -1;
    if (send_all(fd, request, (size_t)len) != 0) {
        close(fd);
        return -1;
    }
    (void)shutdown(fd, SHUT_WR);
    size_t received = 0U;
    while (received + 1U < response_len) {
        ssize_t got = recv(fd, response + received, response_len - 1U - received, 0);
        if (got <= 0) break;
        received += (size_t)got;
    }
    response[received] = '\0';
    close(fd);
    return strncmp(response, "HTTP/1.1 ", 9U) == 0 ? atoi(response + 9) : -1;
}

static const char *http_body(const char *response)
{
    const char *body = strstr(response, "\r\n\r\n");
    return body == NULL ? "" : body + 4;
}

/* ---- WebSocket client -------------------------------------------------------------------- */

static int read_handshake(int fd)
{
    char response[2048];
    size_t received = 0U;
    while (received + 1U < sizeof(response) && recv(fd, response + received, 1U, 0) == 1) {
        ++received;
        response[received] = '\0';
        if (received >= 4U && strcmp(response + received - 4U, "\r\n\r\n") == 0) break;
    }
    response[received] = '\0';
    return strncmp(response, "HTTP/1.1 ", 9U) == 0 ? atoi(response + 9) : -1;
}

/* Sends an upgrade; returns the socket after a 101, otherwise -1 with *status the HTTP status. */
static int ws_upgrade(const char *path, const char *headers, int *status)
{
    *status = -1;
    int fd = connect_admin();
    if (fd < 0) return -1;
    char request[2048];
    int len = snprintf(request, sizeof(request),
                       "GET %s HTTP/1.1\r\nHost: localhost\r\n%sConnection: Upgrade\r\nUpgrade: websocket\r\n"
                       "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                       path, headers == NULL ? "" : headers);
    if (len < 0 || (size_t)len >= sizeof(request) || send_all(fd, request, (size_t)len) != 0) {
        close(fd);
        return -1;
    }
    *status = read_handshake(fd);
    if (*status != 101) {
        close(fd);
        return -1;
    }
    return fd;
}

static int ws_send(int fd, uint8_t opcode, const void *data, size_t len)
{
    static const uint8_t mask[4] = {0x37U, 0xfaU, 0x21U, 0x3dU};
    uint8_t header[8];
    size_t header_len = 0U;
    header[header_len++] = (uint8_t)(0x80U | opcode);
    if (len <= 125U) {
        header[header_len++] = (uint8_t)(0x80U | len);
    } else if (len <= 65535U) {
        header[header_len++] = 0x80U | 126U;
        header[header_len++] = (uint8_t)(len >> 8U);
        header[header_len++] = (uint8_t)len;
    } else {
        return -1;
    }
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);
    uint8_t *masked = (uint8_t *)malloc(len == 0U ? 1U : len);
    if (masked == NULL) return -1;
    for (size_t i = 0U; i < len; ++i) masked[i] = ((const uint8_t *)data)[i] ^ mask[i % 4U];
    int rc = send_all(fd, header, header_len) == 0 && send_all(fd, masked, len) == 0 ? 0 : -1;
    free(masked);
    return rc;
}

static int ws_send_text(int fd, const char *text)
{
    return ws_send(fd, 0x1U, text, strlen(text));
}

/* 1 = one frame read (payload NUL-terminated), 0 = nothing within timeout_ms, -1 = closed. */
static int ws_read(int fd, int timeout_ms, uint8_t *opcode, char *payload, size_t cap, size_t *len)
{
    struct pollfd poller = {.fd = fd, .events = POLLIN, .revents = 0};
    int ready = poll(&poller, 1, timeout_ms);
    if (ready == 0) return 0;
    uint8_t header[2];
    if (ready < 0 || recv_all(fd, header, sizeof(header)) != 0 || (header[1] & 0x80U) != 0U) return -1;
    uint64_t length = header[1] & 0x7fU;
    if (length == 126U) {
        uint8_t extended[2];
        if (recv_all(fd, extended, sizeof(extended)) != 0) return -1;
        length = ((uint64_t)extended[0] << 8U) | extended[1];
    } else if (length == 127U) {
        uint8_t extended[8];
        if (recv_all(fd, extended, sizeof(extended)) != 0) return -1;
        length = 0U;
        for (size_t i = 0U; i < sizeof(extended); ++i) length = (length << 8U) | extended[i];
    }
    if (length + 1U > cap || (length > 0U && recv_all(fd, payload, (size_t)length) != 0)) return -1;
    payload[length] = '\0';
    *opcode = header[0] & 0x0fU;
    *len = (size_t)length;
    return 1;
}

/* The next frame must be text; returns 0 and the payload. */
static int ws_text(int fd, char *payload, size_t cap)
{
    uint8_t opcode = 0U;
    size_t len = 0U;
    return ws_read(fd, 5000, &opcode, payload, cap, &len) == 1 && opcode == 0x1U ? 0 : -1;
}

/* The error message Java sends before closing, then the close frame with code 1008. */
static int expect_error_and_close(int fd, const char *error)
{
    static char payload[FRAME_CAP];
    uint8_t opcode = 0U;
    size_t len = 0U;
    char needle[256];
    snprintf(needle, sizeof(needle), "{\"type\":\"error\",\"error\":\"%s\"}", error);
    if (ws_text(fd, payload, sizeof(payload)) != 0 || !contains(payload, needle)) {
        fprintf(stderr, "expected error %s, got %s\n", error, payload);
        return -1;
    }
    if (ws_read(fd, 5000, &opcode, payload, sizeof(payload), &len) != 1 || opcode != 0x8U || len < 2U
        || (((uint8_t)payload[0] << 8U) | (uint8_t)payload[1]) != 1008U) {
        fprintf(stderr, "expected a 1008 close after %s\n", error);
        return -1;
    }
    return 0;
}

static void ws_close(int *fd)
{
    if (*fd < 0) return;
    static const uint8_t close_frame[] = {0x88U, 0x80U, 1U, 2U, 3U, 4U};
    (void)send_all(*fd, close_frame, sizeof(close_frame));
    (void)shutdown(*fd, SHUT_RDWR);
    close(*fd);
    *fd = -1;
}

/* ---- discovery participants -------------------------------------------------------------- */

typedef struct {
    const char *address;
    const char *room;
    const char *token;
    const char *peer;
    const char *name;
    int hidden;
} participant;

static void ticket_body(const participant *who, char *body, size_t len)
{
    snprintf(body, len,
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"%s\",\"displayName\":\"%s\"%s}",
             who->room, who->token == NULL ? "" : who->token, who->peer, who->name,
             who->hidden ? ",\"discoverable\":false" : "");
}

/* POST /api/public/transfer/ws-tickets from address; returns the status, the ticket on 200. */
static int issue_ticket(const char *address, const char *body, char *ticket, size_t ticket_len)
{
    char headers[128];
    static char response[8192];
    snprintf(headers, sizeof(headers), "X-Real-IP: %s\r\n", address);
    int status = http_call("POST", "/api/public/transfer/ws-tickets", headers, body, response, sizeof(response));
    ticket[0] = '\0';
    if (status == 200) {
        char *value = st_json_get_top_level_string(http_body(response), "ticket");
        if (value == NULL || strlen(value) >= ticket_len) status = -1;
        else memcpy(ticket, value, strlen(value) + 1U);
        free(value);
        if (!contains(response, "Cache-Control: no-store")) status = -1;
    }
    return status;
}

static int discovery_upgrade(const char *ticket, const char *address, int *status)
{
    char path[256];
    char headers[128];
    snprintf(path, sizeof(path), "/ws/public-transfer/discovery?ticket=%s", ticket);
    snprintf(headers, sizeof(headers), "X-Real-IP: %s\r\n", address);
    return ws_upgrade(path, headers, status);
}

/* Opens discovery with a fresh ticket and returns the socket right after the 101. */
static int discovery_open(const participant *who)
{
    char body[2048];
    char ticket[160];
    int status = -1;
    ticket_body(who, body, sizeof(body));
    if (issue_ticket(who->address, body, ticket, sizeof(ticket)) != 200) return -1;
    return discovery_upgrade(ticket, who->address, &status);
}

/* Joins and consumes the hello; the rosters stay queued for drain(). */
static int discovery_join(const participant *who)
{
    static char payload[FRAME_CAP];
    int fd = discovery_open(who);
    if (fd >= 0 && (ws_text(fd, payload, sizeof(payload)) != 0 || !contains(payload, "\"type\":\"hello\""))) {
        fprintf(stderr, "%s did not receive hello: %s\n", who->peer, payload);
        close(fd);
        fd = -1;
    }
    if (fd < 0) fprintf(stderr, "%s could not join\n", who->peer);
    return fd;
}

typedef struct {
    char roster[TEXT_CAP]; /* the last roster before the pong, "" when there was none */
    int rosters;
    int others;            /* frames that were neither a roster nor the pong */
    char other[TEXT_CAP];  /* the last of those */
} drained;

/* Copies text into a fixed buffer, cutting it at the buffer's size. */
static void keep_text(char *out, size_t cap, const char *text)
{
    size_t len = strlen(text);
    if (len >= cap) len = cap - 1U;
    memcpy(out, text, len);
    out[len] = '\0';
}

/*
 * Pings and reads every frame up to the pong. The server answers the ping on the socket's own
 * thread after everything other threads wrote to that socket before, so the frames read here are
 * all the server sent to it until then.
 */
static int drain(int fd, drained *out)
{
    static char payload[FRAME_CAP];
    memset(out, 0, sizeof(*out));
    if (ws_send_text(fd, "{\"type\":\"ping\"}") != 0) return -1;
    for (;;) {
        uint8_t opcode = 0U;
        size_t len = 0U;
        if (ws_read(fd, 5000, &opcode, payload, sizeof(payload), &len) != 1) return -1;
        if (opcode == 0x1U && contains(payload, "\"type\":\"pong\"")) return 0;
        if (opcode == 0x1U && contains(payload, "\"type\":\"roster\"")) {
            keep_text(out->roster, sizeof(out->roster), payload);
            ++out->rosters;
        } else {
            keep_text(out->other, sizeof(out->other), opcode == 0x1U ? payload : "(binary or control)");
            ++out->others;
        }
    }
}

/*
 * The roster's peers are exactly the expected ones, each written "peerId=1" (sameRoom true) or
 * "peerId=0" (sameRoom false), in any order.
 */
static int roster_is(const char *roster, const char *const *expected, size_t count)
{
    char **peers = NULL;
    size_t peers_len = 0U;
    if (st_json_get_raw_array(roster, "peers", &peers, &peers_len) != 0) return 0;
    int ok = peers_len == count;
    for (size_t i = 0U; ok && i < count; ++i) {
        const char *separator = strchr(expected[i], '=');
        size_t name_len = (size_t)(separator - expected[i]);
        int found = 0;
        for (size_t p = 0U; p < peers_len && !found; ++p) {
            char *peer_id = st_json_get_top_level_string(peers[p], "peerId");
            char *same_room = st_json_get_top_level_raw(peers[p], "sameRoom");
            if (peer_id != NULL && strlen(peer_id) == name_len && memcmp(peer_id, expected[i], name_len) == 0) {
                found = 1;
                ok = same_room != NULL && strcmp(same_room, separator[1] == '1' ? "true" : "false") == 0;
            }
            free(peer_id);
            free(same_room);
        }
        ok = ok && found;
    }
    st_json_free_string_array(peers, peers_len);
    return ok;
}

#define ROSTER_IS(roster, ...) \
    roster_is((roster), (const char *const[]){__VA_ARGS__}, \
              sizeof((const char *const[]){__VA_ARGS__}) / sizeof(const char *))

/* A participant whose address is fixed in-process (e.g. "unknown"), served over a socketpair. */
typedef struct {
    int server_fd;
    char path[256];
    char address[64];
    pthread_t thread;
    int started;
} socketpair_peer;

static void *socketpair_peer_thread(void *argument)
{
    socketpair_peer *peer = (socketpair_peer *)argument;
    char request[512];
    snprintf(request, sizeof(request),
             "GET %s HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
             "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
             peer->path);
    (void)st_public_discovery_handle_websocket(peer->server_fd, "GET", peer->path, request, peer->address);
    close(peer->server_fd);
    return NULL;
}

/* Issues the ticket for address in-process and joins over a socketpair; returns the client end. */
static int socketpair_join(socketpair_peer *peer, const participant *who)
{
    char body[2048];
    static char response[8192];
    static char payload[FRAME_CAP];
    ticket_body(who, body, sizeof(body));
    int len = st_public_discovery_issue_ticket_response(body, who->address, response, sizeof(response));
    char *ticket = len > 0 && contains(response, "200 OK") ? st_json_get_top_level_string(http_body(response), "ticket")
                                                         : NULL;
    int pair[2] = {-1, -1};
    memset(peer, 0, sizeof(*peer));
    if (ticket == NULL || socketpair(AF_UNIX, SOCK_STREAM, 0, pair) != 0) {
        free(ticket);
        return -1;
    }
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(pair[1], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    peer->server_fd = pair[0];
    snprintf(peer->path, sizeof(peer->path), "/ws/public-transfer/discovery?ticket=%s", ticket);
    snprintf(peer->address, sizeof(peer->address), "%s", who->address);
    free(ticket);
    if (pthread_create(&peer->thread, NULL, socketpair_peer_thread, peer) != 0) {
        close(pair[0]);
        close(pair[1]);
        return -1;
    }
    peer->started = 1;
    if (read_handshake(pair[1]) != 101 || ws_text(pair[1], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"hello\"")) {
        close(pair[1]);
        return -1;
    }
    return pair[1];
}

static void socketpair_leave(socketpair_peer *peer, int *client)
{
    ws_close(client);
    if (peer->started) (void)pthread_join(peer->thread, NULL);
    peer->started = 0;
}

/* ---- PublicTransferDiscoveryWebSocketHandlerTests ------------------------------------------ */

/* duplicatePeerIdInSameGroupIsRejectedBeforeJoin and the same-net and cross-net variants. */
static int test_duplicate_peer_ids(void)
{
    const participant first = {"203.0.113.21", "dup-room-a", "dup-owner-token", "dup-peer", "Dup First", 0};
    const participant same_group = {"203.0.113.21", "dup-room-a", "dup-owner-token", "dup-peer", "Dup Second", 0};
    /* Another room, no token, same public address: visible through the net, so the ID collides. */
    const participant same_net = {"203.0.113.21", "dup-room-b", NULL, "dup-peer", "Dup Third", 0};
    /* The same token room from another network: the group keeps the ID unique. */
    const participant other_net = {"198.51.100.21", "dup-room-a", "dup-owner-token", "dup-peer", "Dup Fourth", 0};
    /* Neither the same group nor the same net: the ID may be reused. */
    const participant unrelated = {"192.0.2.21", "dup-room-c", NULL, "dup-peer", "Dup Fifth", 0};
    drained state;
    int fd = discovery_join(&first);
    CHECK(fd >= 0 && drain(fd, &state) == 0, "first duplicate-test peer");
    const participant *const duplicates[] = {&same_group, &same_net, &other_net};
    for (size_t i = 0U; i < sizeof(duplicates) / sizeof(duplicates[0]); ++i) {
        int duplicate = discovery_open(duplicates[i]);
        CHECK(duplicate >= 0 && expect_error_and_close(duplicate, "peer id is already connected") == 0,
              "duplicate peer %s was not refused", duplicates[i]->name);
        close(duplicate);
    }
    /* The refused joins never reached the first connection (no roster, no message). */
    CHECK(drain(fd, &state) == 0 && state.rosters == 0 && state.others == 0,
          "a refused duplicate notified the first peer: %s", state.roster);
    int reuse = discovery_join(&unrelated);
    CHECK(reuse >= 0, "an invisible peer could not reuse the peer ID");
    ws_close(&reuse);
    ws_close(&fd);
    return 0;
}

/* clientNameIsUniqueAcrossRoomsAndAvailabilityIsCaseInsensitive, with non-ASCII case folding. */
static int test_client_name_uniqueness(void)
{
    static char response[8192];
    const participant alice = {"203.0.113.22", "name-room-a", "name-token-a", "name-peer-1", "Alice-PT", 0};
    const participant lower = {"198.51.100.22", "name-room-b", "name-token-b", "name-peer-2", "alice-pt", 0};
    const participant elodie = {"203.0.113.22", "name-room-c", NULL, "name-peer-3", "\xC3\x89lodie-PT", 0};
    const participant folded = {"192.0.2.22", "name-room-d", NULL, "name-peer-4", "\xC3\xA9LODIE-pt", 0};
    int first = discovery_join(&alice);
    int second = discovery_join(&elodie);
    CHECK(first >= 0 && second >= 0, "name test peers");
    CHECK(http_call("GET", "/api/public/transfer/clients/name-availability?clientName=+ALICE-PT+&excludePeerId=name-peer-2",
                    NULL, NULL, response, sizeof(response)) == 200
              && contains(response, "\"clientName\":\"ALICE-PT\"") && contains(response, "\"available\":false"),
          "occupied name availability: %s", response);
    CHECK(http_call("GET", "/api/public/transfer/clients/name-availability?clientName=Alice-PT&excludePeerId=name-peer-1",
                    NULL, NULL, response, sizeof(response)) == 200 && contains(response, "\"available\":true"),
          "own name availability: %s", response);
    CHECK(http_call("GET", "/api/public/transfer/clients/name-availability?clientName=%C3%A9LODIE-pt",
                    NULL, NULL, response, sizeof(response)) == 200 && contains(response, "\"available\":false"),
          "non-ASCII name availability ignored case: %s", response);
    int duplicate = discovery_open(&lower);
    CHECK(duplicate >= 0 && expect_error_and_close(duplicate, "client name is already in use") == 0,
          "a name differing in case was accepted in another room");
    close(duplicate);
    duplicate = discovery_open(&folded);
    CHECK(duplicate >= 0 && expect_error_and_close(duplicate, "client name is already in use") == 0,
          "a non-ASCII name differing in case was accepted");
    close(duplicate);
    /* Java normalizeDisplayName also refuses ISO control characters at join. */
    const participant control = {"192.0.2.22", "name-room-e", NULL, "name-peer-5", "Bad\\u0007Name", 0};
    duplicate = discovery_open(&control);
    CHECK(duplicate >= 0 && expect_error_and_close(duplicate, "client name contains invalid characters") == 0,
          "a name with a control character was accepted");
    close(duplicate);
    ws_close(&first);
    ws_close(&second);
    return 0;
}

/*
 * mergedRosterShowsSameNetAndSameRoomPeersWithSameRoomFlags, peersOnSameNetSeeEachOtherAcrossRoomIds
 * and directedSignalReachesSameNetPeerAcrossRooms.
 */
static int test_merged_rosters(void)
{
    const participant nearby = {"203.0.113.23", "merge-room", NULL, "merge-nearby", "Merge Nearby", 0};
    const participant room_mate = {"203.0.113.23", "merge-room", "merge-token", "merge-room-mate", "Merge Mate", 0};
    const participant remote = {"198.51.100.23", "merge-room", "merge-token", "merge-remote", "Merge Remote", 0};
    drained state;
    int nearby_fd = discovery_join(&nearby);
    int mate_fd = discovery_join(&room_mate);
    int remote_fd = discovery_join(&remote);
    CHECK(nearby_fd >= 0 && mate_fd >= 0 && remote_fd >= 0, "merged roster peers");
    CHECK(drain(nearby_fd, &state) == 0 && ROSTER_IS(state.roster, "merge-nearby=1", "merge-room-mate=0"),
          "nearby roster: %s", state.roster);
    CHECK(drain(mate_fd, &state) == 0
              && ROSTER_IS(state.roster, "merge-room-mate=1", "merge-nearby=0", "merge-remote=1"),
          "room-mate roster: %s", state.roster);
    CHECK(drain(remote_fd, &state) == 0 && ROSTER_IS(state.roster, "merge-remote=1", "merge-room-mate=1"),
          "remote room-mate roster: %s", state.roster);

    /* Two token rooms with different room IDs on one net see each other, not as the same room. */
    const participant first = {"203.0.113.24", "net-room-a", "net-token-a", "net-peer-1", "Net One", 0};
    const participant second = {"203.0.113.24", "net-room-b", "net-token-b", "net-peer-2", "Net Two", 0};
    int first_fd = discovery_join(&first);
    int second_fd = discovery_join(&second);
    CHECK(first_fd >= 0 && second_fd >= 0, "same-net peers");
    CHECK(drain(first_fd, &state) == 0 && ROSTER_IS(state.roster, "net-peer-1=1", "net-peer-2=0"),
          "same-net roster across room IDs: %s", state.roster);
    CHECK(drain(second_fd, &state) == 0 && ROSTER_IS(state.roster, "net-peer-2=1", "net-peer-1=0"),
          "same-net roster across room IDs (second): %s", state.roster);
    /* A directed signal reaches the same-net peer in the other room, with the authenticated source. */
    CHECK(ws_send_text(first_fd, "{\"type\":\"signal\",\"targetPeerId\":\"net-peer-2\",\"payload\":{}}") == 0
              && drain(first_fd, &state) == 0 && drain(second_fd, &state) == 0 && state.others == 1
              && contains(state.other, "\"type\":\"signal\"") && contains(state.other, "\"sourcePeerId\":\"net-peer-1\""),
          "directed signal across rooms on one net: %s", state.other);
    ws_close(&first_fd);
    ws_close(&second_fd);
    ws_close(&nearby_fd);
    ws_close(&mate_fd);
    ws_close(&remote_fd);
    return 0;
}

/* directedSignalToInvisiblePeerIsNotDelivered. */
static int test_signal_to_invisible_peer(void)
{
    const participant nearby = {"203.0.113.25", "invisible-room", NULL, "inv-nearby", "Inv Nearby", 0};
    const participant outsider = {"198.51.100.25", "invisible-room", "inv-token", "inv-outsider", "Inv Outsider", 0};
    drained state;
    int nearby_fd = discovery_join(&nearby);
    int outsider_fd = discovery_join(&outsider);
    CHECK(nearby_fd >= 0 && outsider_fd >= 0 && drain(outsider_fd, &state) == 0, "invisible-signal peers");
    /* The source's own pong proves its signal was routed (or dropped) before the outsider drains. */
    CHECK(ws_send_text(nearby_fd, "{\"type\":\"signal\",\"targetPeerId\":\"inv-outsider\",\"payload\":{}}") == 0
              && drain(nearby_fd, &state) == 0 && state.others == 0,
          "the source got a reply to its signal: %s", state.other);
    CHECK(drain(outsider_fd, &state) == 0 && state.others == 0,
          "a signal reached a peer outside the source's group and net: %s", state.other);
    ws_close(&nearby_fd);
    ws_close(&outsider_fd);
    return 0;
}

/* unknownPublicAddressIsNeverTreatedAsSameNet, for "unknown" and for a blank address. */
static int test_unidentifiable_addresses(void)
{
    static const char *const addresses[] = {"unknown", "   "};
    for (size_t i = 0U; i < sizeof(addresses) / sizeof(addresses[0]); ++i) {
        char peer1[32], peer2[32], peer3[32], name1[32], name2[32], name3[32];
        snprintf(peer1, sizeof(peer1), "unk-%zu-1", i);
        snprintf(peer2, sizeof(peer2), "unk-%zu-2", i);
        snprintf(peer3, sizeof(peer3), "unk-%zu-3", i);
        snprintf(name1, sizeof(name1), "Unknown %zu one", i);
        snprintf(name2, sizeof(name2), "Unknown %zu two", i);
        snprintf(name3, sizeof(name3), "Unknown %zu three", i);
        const participant first = {addresses[i], "unk-room-a", "unk-token", peer1, name1, 0};
        const participant second = {addresses[i], "unk-room-b", "unk-token", peer2, name2, 0};
        const participant room_mate = {addresses[i], "unk-room-a", "unk-token", peer3, name3, 0};
        socketpair_peer first_peer, second_peer, mate_peer;
        drained state;
        int first_fd = socketpair_join(&first_peer, &first);
        int second_fd = socketpair_join(&second_peer, &second);
        int mate_fd = socketpair_join(&mate_peer, &room_mate);
        CHECK(first_fd >= 0 && second_fd >= 0 && mate_fd >= 0, "participants at address '%s'", addresses[i]);
        char self1[48], self2[48], self3[48];
        snprintf(self1, sizeof(self1), "%s=1", peer1);
        snprintf(self2, sizeof(self2), "%s=1", peer2);
        snprintf(self3, sizeof(self3), "%s=1", peer3);
        /* Equal but unidentifiable addresses do not make a net; the shared group still does. */
        CHECK(drain(first_fd, &state) == 0 && ROSTER_IS(state.roster, self1, self3),
              "roster at address '%s': %s", addresses[i], state.roster);
        CHECK(drain(second_fd, &state) == 0 && ROSTER_IS(state.roster, self2),
              "isolated roster at address '%s': %s", addresses[i], state.roster);
        char signal[128];
        snprintf(signal, sizeof(signal), "{\"type\":\"signal\",\"targetPeerId\":\"%s\",\"payload\":{}}", peer2);
        CHECK(ws_send_text(first_fd, signal) == 0 && drain(first_fd, &state) == 0
                  && drain(second_fd, &state) == 0 && state.others == 0,
              "a signal crossed rooms at address '%s'", addresses[i]);
        socketpair_leave(&first_peer, &first_fd);
        socketpair_leave(&second_peer, &second_fd);
        socketpair_leave(&mate_peer, &mate_fd);
    }
    return 0;
}

/* broadcastWithoutTargetStaysWithinGroup. */
static int test_broadcast_stays_in_group(void)
{
    const participant source = {"203.0.113.26", "cast-room", NULL, "cast-source", "Cast Source", 0};
    const participant same_group = {"203.0.113.26", "cast-room", NULL, "cast-group", "Cast Group", 0};
    const participant same_net = {"203.0.113.26", "cast-room", "cast-token", "cast-net", "Cast Net", 0};
    drained state;
    int source_fd = discovery_join(&source);
    int group_fd = discovery_join(&same_group);
    int net_fd = discovery_join(&same_net);
    CHECK(source_fd >= 0 && group_fd >= 0 && net_fd >= 0, "broadcast peers");
    CHECK(drain(group_fd, &state) == 0 && drain(net_fd, &state) == 0
              && ROSTER_IS(state.roster, "cast-source=0", "cast-group=0", "cast-net=1"),
          "the same-net member does not see the others: %s", state.roster);
    CHECK(ws_send_text(source_fd, "{\"type\":\"clipboard\",\"payload\":{}}") == 0
              && drain(source_fd, &state) == 0 && state.others == 0,
          "the broadcast came back to its source: %s", state.other);
    CHECK(drain(group_fd, &state) == 0 && state.others == 1 && contains(state.other, "\"type\":\"clipboard\"")
              && contains(state.other, "\"targetPeerId\":null"),
          "the group member did not get the broadcast: %s", state.other);
    CHECK(drain(net_fd, &state) == 0 && state.others == 0,
          "a broadcast left the group for a same-net member: %s", state.other);
    ws_close(&source_fd);
    ws_close(&group_fd);
    ws_close(&net_fd);
    return 0;
}

/* hiddenPeerIsFilteredFromMergedRosterButStillReceivesRoster. */
static int test_hidden_peer(void)
{
    const participant hidden = {"203.0.113.27", "hide-room", "hide-token", "hide-hidden", "Hide Hidden", 1};
    const participant visible = {"203.0.113.27", "hide-room", "hide-token", "hide-visible", "Hide Visible", 0};
    drained state;
    int hidden_fd = discovery_join(&hidden);
    int visible_fd = discovery_join(&visible);
    CHECK(hidden_fd >= 0 && visible_fd >= 0, "hidden-peer participants");
    CHECK(drain(visible_fd, &state) == 0 && ROSTER_IS(state.roster, "hide-visible=1"),
          "a hidden peer was listed: %s", state.roster);
    CHECK(drain(hidden_fd, &state) == 0 && state.rosters > 0 && ROSTER_IS(state.roster, "hide-visible=1"),
          "the hidden peer did not receive the roster: %s", state.roster);
    /* The hidden connection still signals: a directed signal reaches the visible peer. */
    CHECK(ws_send_text(hidden_fd, "{\"type\":\"offer\",\"targetPeerId\":\"hide-visible\",\"payload\":{}}") == 0
              && drain(hidden_fd, &state) == 0 && drain(visible_fd, &state) == 0
              && contains(state.other, "\"sourcePeerId\":\"hide-hidden\""),
          "a hidden peer could not signal: %s", state.other);
    ws_close(&hidden_fd);
    ws_close(&visible_fd);
    return 0;
}

/* roomCapacityIsStillCountedPerGroup. */
static int test_room_capacity_per_group(void)
{
    const participant first = {"203.0.113.28", "cap-room", "cap-token", "cap-peer-1", "Cap Alpha", 0};
    const participant same_group = {"198.51.100.28", "cap-room", "cap-token", "cap-peer-2", "Cap Beta", 0};
    const participant same_net = {"203.0.113.28", "cap-room", NULL, "cap-peer-3", "Cap Gamma", 0};
    drained state;
    setenv("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM", "1", 1);
    int first_fd = discovery_join(&first);
    int full = discovery_open(&same_group);
    int full_refused = full >= 0 && expect_error_and_close(full, "room is full") == 0;
    if (full >= 0) close(full);
    int other_fd = discovery_join(&same_net);
    unsetenv("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM");
    CHECK(first_fd >= 0 && full_refused, "the second member of a one-peer room was not refused");
    CHECK(other_fd >= 0 && drain(other_fd, &state) == 0 && ROSTER_IS(state.roster, "cap-peer-1=0", "cap-peer-3=1"),
          "a same-net member of another group was counted against the full room: %s", state.roster);
    ws_close(&first_fd);
    ws_close(&other_fd);
    return 0;
}

/* viewerCannotRelayWhiteboardUpdates (text messages; the binary relay is in admin_http_tests). */
static int test_viewer_text_messages(void)
{
    static char response[8192];
    char body[512];
    snprintf(body, sizeof(body),
             "{\"roomId\":\"viewer-room\",\"roomToken\":\"viewer-owner-token\",\"peerId\":\"viewer-owner\","
             "\"role\":\"VIEWER\",\"label\":\"Read only\"}");
    CHECK(http_call("POST", "/api/public/transfer/rooms/access-tokens", NULL, body, response, sizeof(response)) == 200,
          "viewer invite: %s", response);
    char *token = st_json_get_top_level_string(http_body(response), "token");
    CHECK(token != NULL, "viewer invite token");
    const participant viewer = {"203.0.113.29", "viewer-room", token, "viewer-peer", "Viewer Peer", 0};
    drained state;
    int fd = discovery_join(&viewer);
    free(token);
    CHECK(fd >= 0 && drain(fd, &state) == 0, "viewer join");
    static const char *const refused[] = {"whiteboard", "clipboard", "attachment"};
    for (size_t i = 0U; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        char message[96];
        snprintf(message, sizeof(message), "{\"type\":\"%s\",\"payload\":{}}", refused[i]);
        CHECK(ws_send_text(fd, message) == 0 && drain(fd, &state) == 0 && state.others == 1
                  && contains(state.other, "{\"type\":\"error\",\"error\":\"viewer is read-only\"}"),
              "a viewer %s message was not refused: %s", refused[i], state.other);
    }
    /* signal stays allowed so a viewer can open a receiving channel; nobody is listening here. */
    CHECK(ws_send_text(fd, "{\"type\":\"signal\",\"payload\":{}}") == 0 && drain(fd, &state) == 0
              && state.others == 0, "a viewer signal was refused: %s", state.other);
    ws_close(&fd);
    return 0;
}

/* ---- PublicTransferRelayFrameTests --------------------------------------------------------- */

static void write_u16(uint8_t *out, size_t value)
{
    out[0] = (uint8_t)(value >> 8U);
    out[1] = (uint8_t)value;
}

static void write_u32(uint8_t *out, size_t value)
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

/* A STAP2 frame of one chunk whose header declares payload_len bytes; actual_len bytes follow. */
static size_t app_frame(uint8_t *out, uint8_t type, size_t payload_len, size_t actual_len)
{
    memset(out, 0, 72U + actual_len);
    memcpy(out, "STAP", 4U);
    out[4] = 2U;
    out[5] = type;
    write_u32(out + 28U, 1U);
    write_u32(out + 32U, payload_len);
    write_u32(out + 36U, payload_len);
    for (size_t i = 0U; i < actual_len; ++i) out[72U + i] = (uint8_t)(4U + i);
    return 72U + actual_len;
}

static size_t relay_frame(uint8_t *out, const char *target, size_t target_len, const char *source,
                          const uint8_t *app, size_t app_len)
{
    size_t source_len = strlen(source);
    memcpy(out, "STWR", 4U);
    out[4] = 2U;
    out[5] = 0U;
    write_u16(out + 6U, target_len);
    write_u16(out + 8U, source_len);
    write_u32(out + 10U, app_len);
    memcpy(out + 14U, target, target_len);
    memcpy(out + 14U + target_len, source, source_len);
    memcpy(out + 14U + target_len + source_len, app, app_len);
    return 14U + target_len + source_len + app_len;
}

/* decodesClientFrameAndAddsAuthenticatedSource and rejectsSpoofedSourceAndTrailingAppBytes. */
static int test_relay_frames(void)
{
    const participant sender = {"203.0.113.30", "relay-room", "relay-token", "relay-a", "Relay A", 0};
    const participant receiver = {"203.0.113.30", "relay-room", "relay-token", "relay-b", "Relay B", 0};
    static char payload[FRAME_CAP];
    uint8_t app[128], frame[256], expected[256];
    drained state;
    int sender_fd = discovery_join(&sender);
    int receiver_fd = discovery_join(&receiver);
    CHECK(sender_fd >= 0 && receiver_fd >= 0 && drain(receiver_fd, &state) == 0, "relay peers");
    size_t app_len = app_frame(app, 2U, 3U, 3U);
    size_t frame_len = relay_frame(frame, "relay-b", 7U, "", app, app_len);
    size_t expected_len = relay_frame(expected, "relay-b", 7U, "relay-a", app, app_len);
    uint8_t opcode = 0U;
    size_t len = 0U;
    CHECK(ws_send(sender_fd, 0x2U, frame, frame_len) == 0
              && ws_read(receiver_fd, 5000, &opcode, payload, sizeof(payload), &len) == 1 && opcode == 0x2U
              && len == expected_len && memcmp(payload, expected, expected_len) == 0,
          "the relayed STWR2 frame is not the client frame with the authenticated source");
    ws_close(&receiver_fd);
    ws_close(&sender_fd);

    struct {
        const char *label;
        const char *target;
        size_t target_len;
        const char *source;
        size_t declared;
        size_t actual;
    } refused[] = {
        {"a spoofed source", "relay-b", 7U, "spoofed", 1U, 1U},
        {"a trailing application byte", "relay-b", 7U, "", 1U, 2U},
        {"a control character in the target", "relay\nb", 7U, "", 1U, 1U},
        {"a NUL in the target", "relay\0b", 7U, "", 1U, 1U},
        {"a blank target", "   ", 3U, "", 1U, 1U},
        {"an ideographic-space target", "\xE3\x80\x80", 3U, "", 1U, 1U},
    };
    for (size_t i = 0U; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        char peer[32], name[32];
        snprintf(peer, sizeof(peer), "relay-bad-%zu", i);
        snprintf(name, sizeof(name), "Relay Bad %zu", i);
        const participant bad = {"203.0.113.30", "relay-room", "relay-token", peer, name, 0};
        int fd = discovery_join(&bad);
        CHECK(fd >= 0 && drain(fd, &state) == 0, "relay sender %zu", i);
        app_len = app_frame(app, 1U, refused[i].declared, refused[i].actual);
        frame_len = relay_frame(frame, refused[i].target, refused[i].target_len, refused[i].source, app, app_len);
        CHECK(ws_send(fd, 0x2U, frame, frame_len) == 0
                  && expect_error_and_close(fd, "invalid binary relay frame") == 0,
              "a relay frame with %s was not refused", refused[i].label);
        ws_close(&fd);
    }
    return 0;
}

/* ---- WebSocketTicketServiceTests ----------------------------------------------------------- */

static int admin_ticket(const char *authorization, const char *endpoint, const char *address,
                        char *ticket, size_t ticket_len)
{
    char headers[2600];
    char body[96];
    static char response[8192];
    snprintf(headers, sizeof(headers), "Authorization: %s\r\nX-Real-IP: %s\r\n", authorization, address);
    snprintf(body, sizeof(body), "{\"endpoint\":\"%s\"}", endpoint);
    int status = http_call("POST", "/api/admin/ws-tickets", headers, body, response, sizeof(response));
    char *value = status == 200 ? st_json_get_top_level_string(http_body(response), "ticket") : NULL;
    int ok = value != NULL && strlen(value) < ticket_len;
    if (ok) memcpy(ticket, value, strlen(value) + 1U);
    else fprintf(stderr, "admin %s ticket failed: %s\n", endpoint, response);
    free(value);
    return ok ? 0 : -1;
}

/* Upgrades to path?ticket= from address; returns the status, closing any accepted socket. */
static int upgrade_status(const char *endpoint, const char *ticket, const char *address)
{
    char path[256];
    char headers[128];
    int status = -1;
    snprintf(path, sizeof(path), "%s?ticket=%s", endpoint, ticket);
    snprintf(headers, sizeof(headers), "X-Real-IP: %s\r\n", address);
    int fd = ws_upgrade(path, headers, &status);
    ws_close(&fd);
    return status;
}

/* ticketIsScopedAddressBoundAndConsumedOnce, for the public and both management scopes. */
static int test_ticket_scope_and_address(void)
{
    char token[2048];
    char authorization[2100];
    st_storage_management_user user;
    CHECK(st_storage_create_management_user(db_path, "ticket-admin", "default", "unused-password-hash", "ADMIN", 1,
                                            &user) == 0
              && st_security_issue_local_token("ticket-admin", "default", "ADMIN", JWT_SECRET, 600, token,
                                               sizeof(token)) == 0,
          "management identity for tickets");
    snprintf(authorization, sizeof(authorization), "Bearer %s", token);

    /* A public-transfer ticket: refused by both management endpoints and from another address. */
    char ticket[160];
    char body[512];
    const participant who = {"192.0.2.31", "ticket-room", NULL, "ticket-peer", "Ticket Peer", 0};
    ticket_body(&who, body, sizeof(body));
    CHECK(issue_ticket(who.address, body, ticket, sizeof(ticket)) == 200, "public ticket");
    CHECK(upgrade_status("/ws/connections", ticket, who.address) == 403, "a public ticket opened /ws/connections");
    CHECK(upgrade_status("/ws/client-messages", ticket, who.address) == 403,
          "a public ticket opened /ws/client-messages");
    CHECK(upgrade_status("/ws/public-transfer/discovery", ticket, "192.0.2.32") == 403,
          "a public ticket was accepted from another address");
    /* None of the refused attempts consumed it; the first matching use does, and only once. */
    CHECK(upgrade_status("/ws/public-transfer/discovery", ticket, who.address) == 101,
          "a refused attempt consumed the public ticket");
    CHECK(upgrade_status("/ws/public-transfer/discovery", ticket, who.address) == 403, "a public ticket was reused");

    /* Management tickets: refused by discovery and by the other management scope, address bound. */
    static const char *const scopes[][2] = {{"connections", "/ws/client-messages"},
                                            {"client-messages", "/ws/connections"}};
    for (size_t i = 0U; i < 2U; ++i) {
        char own[48];
        snprintf(own, sizeof(own), "/ws/%s", scopes[i][0]);
        CHECK(admin_ticket(authorization, scopes[i][0], "192.0.2.33", ticket, sizeof(ticket)) == 0,
              "%s ticket", scopes[i][0]);
        CHECK(upgrade_status("/ws/public-transfer/discovery", ticket, "192.0.2.33") == 403,
              "a %s ticket opened discovery", scopes[i][0]);
        CHECK(upgrade_status(scopes[i][1], ticket, "192.0.2.33") == 403,
              "a %s ticket opened %s", scopes[i][0], scopes[i][1]);
        CHECK(upgrade_status(own, ticket, "192.0.2.34") == 403, "a %s ticket was accepted from another address",
              scopes[i][0]);
        CHECK(upgrade_status(own, ticket, "192.0.2.33") == 101, "a refused attempt consumed the %s ticket",
              scopes[i][0]);
        CHECK(upgrade_status(own, ticket, "192.0.2.33") == 403, "a %s ticket was reused", scopes[i][0]);
    }
    return 0;
}

/* ---- PublicTransferRoomResourceTests --------------------------------------------------------- */

static int redeem_status(const char *headers, const char *code)
{
    char body[96];
    static char response[8192];
    snprintf(body, sizeof(body), "{\"code\":\"%s\",\"peerId\":\"guest\"}", code);
    int status = http_call("POST", "/api/public/transfer/rooms/pairing-codes/redeem", headers, body, response,
                           sizeof(response));
    return status > 0 && contains(response, "Cache-Control: no-store") ? status : -1;
}

/*
 * pairingCodeResponsesAreNoStoreAndRedeemUsesTrustedClientAddress and
 * redeemIgnoresForwardedHeadersFromUntrustedPeers: the redemption limit (one attempt per source in
 * this test) shows which address the server keyed it by.
 */
static int test_redeem_client_address(void)
{
    static char response[8192];
    char body[512];
    setenv("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP", "1", 1);

    /* Behind the trusted loopback proxy the last untrusted X-Forwarded-For hop wins over X-Real-IP. */
    st_public_room_reset_for_tests();
    snprintf(body, sizeof(body),
             "{\"roomId\":\"redeem-room\",\"roomToken\":\"redeem-owner-token\",\"peerId\":\"owner\","
             "\"role\":\"EDITOR\",\"label\":\"guest\",\"maxUses\":1}");
    CHECK(http_call("POST", "/api/public/transfer/rooms/pairing-codes", NULL, body, response, sizeof(response)) == 200
              && contains(response, "Cache-Control: no-store"), "pairing code create: %s", response);
    char *code = st_json_get_top_level_string(http_body(response), "code");
    CHECK(code != NULL, "pairing code");
    int redeemed = redeem_status("X-Forwarded-For: 192.0.2.7, 198.51.100.9\r\nX-Real-IP: 203.0.113.5\r\n", code);
    free(code);
    CHECK(redeemed == 200, "redeem through the trusted proxy: %d", redeemed);
    CHECK(redeem_status("X-Forwarded-For: 198.51.100.9\r\n", "00000000") == 429,
          "the redemption was not keyed by the last untrusted X-Forwarded-For hop");
    CHECK(redeem_status("X-Real-IP: 203.0.113.5\r\n", "00000000") == 400,
          "X-Real-IP was used although X-Forwarded-For named the client");

    /* Without trusted proxies a direct client cannot choose its own source address. */
    unsetenv("SPECUS_TRUSTED_PROXIES");
    st_public_room_reset_for_tests();
    int first = redeem_status("X-Forwarded-For: 1.2.3.4\r\nX-Real-IP: 5.6.7.8\r\n", "00000000");
    int second = redeem_status("X-Forwarded-For: 9.9.9.9\r\nX-Real-IP: 8.8.8.8\r\n", "00000000");
    setenv("SPECUS_TRUSTED_PROXIES", "127.0.0.1/32", 1);
    unsetenv("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP");
    st_public_room_reset_for_tests();
    CHECK(first == 400 && second == 429,
          "forwarded headers from an untrusted peer changed the redemption source (%d, %d)", first, second);
    return 0;
}

/* ---- PublicTransferRoomServiceTests ---------------------------------------------------------- */

static long long db_count(const char *sql, const char *text)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long count = -1;
    if (sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && (text == NULL || sqlite3_bind_text(stmt, 1, text, -1, SQLITE_TRANSIENT) == SQLITE_OK)
        && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

static int db_exec(const char *sql, const char *text)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && (text == NULL || sqlite3_bind_text(stmt, 1, text, -1, SQLITE_TRANSIENT) == SQLITE_OK)
        && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

/* Creates an invitation; returns its status and, on 200, the token and the whole response. */
static int create_invite(const char *room, const char *owner_token, const char *extra, char *token, size_t token_len,
                         char *response, size_t response_len)
{
    char body[512];
    snprintf(body, sizeof(body),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner\",\"role\":\"EDITOR\","
             "\"label\":\"invite\"%s}", room, owner_token, extra);
    int status = http_call("POST", "/api/public/transfer/rooms/access-tokens", NULL, body, response, response_len);
    if (status == 200) {
        char *value = st_json_get_top_level_string(http_body(response), "token");
        if (value == NULL || strlen(value) >= token_len) status = -1;
        else memcpy(token, value, strlen(value) + 1U);
        free(value);
    }
    return status;
}

/* The ws-ticket endpoint resolves the room credential like Java's resolve(). */
static int room_ticket_status(const char *room, const char *token)
{
    char body[512];
    char ticket[160];
    const participant who = {"192.0.2.40", room, token, "room-peer", "Room Peer", 0};
    ticket_body(&who, body, sizeof(body));
    return issue_ticket(who.address, body, ticket, sizeof(ticket));
}

static int iso_seconds(const char *text, long long *seconds)
{
    struct tm parsed;
    memset(&parsed, 0, sizeof(parsed));
    if (text == NULL || sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d", &parsed.tm_year, &parsed.tm_mon, &parsed.tm_mday,
                               &parsed.tm_hour, &parsed.tm_min, &parsed.tm_sec) != 6) {
        return -1;
    }
    long long year = parsed.tm_year;
    long long month = parsed.tm_mon;
    /* Days from civil (proleptic Gregorian), UTC. */
    year -= month <= 2;
    long long era = (year >= 0 ? year : year - 399) / 400;
    long long yoe = year - era * 400;
    long long doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + parsed.tm_mday - 1;
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = era * 146097 + doe - 719468;
    *seconds = days * 86400 + parsed.tm_hour * 3600 + parsed.tm_min * 60 + parsed.tm_sec;
    return 0;
}

/* An ISO instant member of the invitation view ({"access":{...},"token":...}) in epoch seconds. */
static long long access_instant(const char *response_body, const char *key)
{
    char *access = st_json_get_top_level_raw(response_body, "access");
    char *value = access == NULL ? NULL : st_json_get_top_level_string(access, key);
    free(access);
    long long seconds = -1;
    if (iso_seconds(value, &seconds) != 0) seconds = -1;
    free(value);
    return seconds;
}

static int test_room_credentials(void)
{
    static char response[8192];
    char token[128];

    /* firstRoomTokenBecomesOwnerAndOnlyHashIsStored. */
    CHECK(room_ticket_status("svc-room", "svc-owner-secret") == 200, "first room token");
    CHECK(db_count("SELECT COUNT(*) FROM public_transfer_room WHERE room_name='svc-room' "
                   "AND length(owner_token_hash)=64 AND owner_token_hash<>?", "svc-owner-secret") == 1,
          "the owner token was not stored as a SHA-256 hash");

    /* unknownInviteShapedTokenCannotCreateShadowOwnerRoom. */
    long long rooms = db_count("SELECT COUNT(*) FROM public_transfer_room", NULL);
    CHECK(room_ticket_status("svc-room", "st-editor-deleted-token") == 403
              && room_ticket_status("svc-room", "st-viewer-deleted-token") == 403,
          "an unknown invitation-shaped token was accepted");
    CHECK(http_call("POST", "/api/public/transfer/rooms/access-tokens/list", NULL,
                    "{\"roomId\":\"svc-room\",\"roomToken\":\"st-editor-deleted-token\",\"peerId\":\"x\"}",
                    response, sizeof(response)) == 403, "an unknown invitation listed the room: %s", response);
    CHECK(db_count("SELECT COUNT(*) FROM public_transfer_room", NULL) == rooms,
          "an unknown invitation-shaped token created a shadow OWNER room");

    /* expiredInviteIsForbiddenInsteadOfCreatingShadowOwnerRoom (and the revoked variant). */
    CHECK(create_invite("svc-room", "svc-owner-secret", ",\"expiresInSeconds\":300", token, sizeof(token),
                        response, sizeof(response)) == 200, "expiring invite: %s", response);
    CHECK(room_ticket_status("svc-room", token) == 200, "an active invitation was refused");
    CHECK(db_exec("UPDATE public_transfer_room_access SET expires_at='2000-01-01T00:00:00Z' WHERE label='invite'",
                  NULL) == 0, "expire the invitation");
    CHECK(room_ticket_status("svc-room", token) == 403, "an expired invitation was accepted");
    int access_id = 0;
    CHECK(create_invite("svc-room", "svc-owner-secret", "", token, sizeof(token), response, sizeof(response)) == 200
              && st_json_get_int(http_body(response), "id", &access_id) == 0, "revocable invite");
    char path[128];
    snprintf(path, sizeof(path), "/api/public/transfer/rooms/access-tokens/%d/revoke", access_id);
    CHECK(http_call("POST", path, NULL, "{\"roomId\":\"svc-room\",\"roomToken\":\"svc-owner-secret\",\"peerId\":\"o\"}",
                    response, sizeof(response)) == 200, "revoke: %s", response);
    CHECK(room_ticket_status("svc-room", token) == 403, "a revoked invitation was accepted");
    CHECK(db_count("SELECT COUNT(*) FROM public_transfer_room", NULL) == rooms,
          "an expired or revoked invitation created a shadow OWNER room");

    /* accessTokenWithoutExpiryRemainsBackwardCompatible, accessTokenExpiryMustBeBetweenFiveMinutesAndSevenDays. */
    CHECK(create_invite("svc-room", "svc-owner-secret", "", token, sizeof(token), response, sizeof(response)) == 200
              && contains(http_body(response), "\"expiresAt\":null"), "an invitation without expiry: %s", response);
    static const struct {
        long long seconds;
        int status;
    } expiries[] = {{299, 400}, {300, 200}, {604800, 200}, {604801, 400}};
    for (size_t i = 0U; i < sizeof(expiries) / sizeof(expiries[0]); ++i) {
        char extra[64];
        snprintf(extra, sizeof(extra), ",\"expiresInSeconds\":%lld", expiries[i].seconds);
        int status = create_invite("svc-room", "svc-owner-secret", extra, token, sizeof(token), response,
                                   sizeof(response));
        CHECK(status == expiries[i].status, "expiresInSeconds %lld answered %d", expiries[i].seconds, status);
        if (status == 200) {
            long long created = access_instant(http_body(response), "createdAt");
            long long expires = access_instant(http_body(response), "expiresAt");
            CHECK(created > 0 && expires - created == expiries[i].seconds,
                  "expiresInSeconds %lld gave %s", expiries[i].seconds, http_body(response));
        }
    }

    /*
     * pairingCodeIsEightDigitsAndOnlyHmacIsPersisted (one use by default, expiring after creation),
     * then redeemingPairingCodeAtomicallyMintsTwentyFourHourRoleToken.
     */
    CHECK(http_call("POST", "/api/public/transfer/rooms/pairing-codes", NULL,
                    "{\"roomId\":\"svc-room\",\"roomToken\":\"svc-owner-secret\",\"peerId\":\"o\","
                    "\"role\":\"EDITOR\",\"label\":\"svc-guest\"}", response, sizeof(response)) == 200,
          "pairing code: %s", response);
    char *code = st_json_get_top_level_string(http_body(response), "code");
    char *created_text = st_json_get_top_level_string(http_body(response), "createdAt");
    char *expiry_text = st_json_get_top_level_string(http_body(response), "expiresAt");
    long long created_at = -1;
    long long expires_at = -1;
    int code_ok = code != NULL && strlen(code) == 8U && strspn(code, "0123456789") == 8U
        && contains(http_body(response), "\"maxUses\":1") && iso_seconds(created_text, &created_at) == 0
        && iso_seconds(expiry_text, &expires_at) == 0 && expires_at > created_at
        && db_count("SELECT COUNT(*) FROM public_transfer_room_pairing_code WHERE label='svc-guest' "
                    "AND length(code_hash)=64 AND code_hash<>?", code) == 1;
    free(created_text);
    free(expiry_text);
    CHECK(code_ok, "pairing code shape or persisted digest mismatch: %s", http_body(response));
    char body[128];
    snprintf(body, sizeof(body), "{\"code\":\"%s\",\"peerId\":\"guest\"}", code == NULL ? "" : code);
    free(code);
    long long before = (long long)time(NULL);
    st_public_room_reset_for_tests();
    CHECK(http_call("POST", "/api/public/transfer/rooms/pairing-codes/redeem", "X-Real-IP: 192.0.2.41\r\n", body,
                    response, sizeof(response)) == 200, "redeem: %s", response);
    char *expires_value = st_json_get_top_level_string(http_body(response), "expiresAt");
    long long expires = -1;
    if (iso_seconds(expires_value, &expires) != 0) expires = -1;
    free(expires_value);
    char *redeemed = st_json_get_top_level_string(http_body(response), "roomToken");
    char *expires_text = st_json_get_top_level_string(http_body(response), "expiresAt");
    long long stored = db_count("SELECT COUNT(*) FROM public_transfer_room_access WHERE label='svc-guest' "
                                "AND role='EDITOR' AND expires_at=?", expires_text);
    free(expires_text);
    CHECK(stored == 1, "the redeemed token's stored expiry differs from the response");
    CHECK(redeemed != NULL && strncmp(redeemed, "st-editor-", 10U) == 0
              && contains(http_body(response), "\"role\":\"EDITOR\"")
              && contains(http_body(response), "\"roomId\":\"svc-room\"")
              && expires - before >= 86399 && expires - before <= 86401,
          "the redeemed token is not a 24-hour EDITOR token: %s", http_body(response));
    free(redeemed);

    /* ownerSnapshotIsDecodedBeforeOrmPersistence: "yjs-state" in base64. */
    CHECK(http_call("POST", "/api/public/transfer/rooms/diagram/versions", NULL,
                    "{\"roomId\":\"svc-room\",\"roomToken\":\"svc-owner-secret\",\"peerId\":\"o\","
                    "\"name\":\"checkpoint\",\"update\":\"eWpzLXN0YXRl\"}", response, sizeof(response)) == 200
              && contains(http_body(response), "\"sizeBytes\":9"), "diagram version: %s", response);
    CHECK(db_count("SELECT COUNT(*) FROM public_transfer_diagram_version WHERE name='checkpoint' "
                   "AND snapshot_data=CAST(? AS BLOB) AND size_bytes=9", "yjs-state") == 1,
          "the snapshot was not stored decoded");
    return 0;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", JWT_SECRET, 1);
    setenv("SPECUS_TRUSTED_PROXIES", "127.0.0.1/32", 1);
    snprintf(db_path, sizeof(db_path), "/tmp/specus_c_public_transfer_%ld.db", (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    if (st_storage_init(db_path, 0) != 0) {
        fprintf(stderr, "storage init failed\n");
        return 1;
    }
    st_public_discovery_reset_for_tests();
    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (st_admin_server_start(&server, 0, "") != 0
        || getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0) {
        fprintf(stderr, "admin server start failed\n");
        return 1;
    }
    admin_port = ntohs(address.sin_port);

    int failed = test_duplicate_peer_ids()
        || test_client_name_uniqueness()
        || test_merged_rosters()
        || test_signal_to_invisible_peer()
        || test_unidentifiable_addresses()
        || test_broadcast_stays_in_group()
        || test_hidden_peer()
        || test_room_capacity_per_group()
        || test_viewer_text_messages()
        || test_relay_frames()
        || test_ticket_scope_and_address()
        || test_redeem_client_address()
        || test_room_credentials();

    (void)shutdown(server.fd, SHUT_RDWR);
    close(server.fd);
    unlink(db_path);
    if (failed) return 1;
    puts("public transfer tests passed");
    return 0;
}
