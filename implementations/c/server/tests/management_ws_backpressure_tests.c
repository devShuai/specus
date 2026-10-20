/*
 * Slow readers of the management WebSockets (/ws/connections, /ws/client-messages) against Java's
 * ConnectionEventsWebSocketHandler and ClientMessagesWebSocketHandler on Tomcat, whose blocking
 * send gives up on a message after 20 s (BLOCKING_SEND_TIMEOUT, left at its default) and closes
 * that session, 1001 "Write timeout", and no other:
 *
 *   1. A real specus-server-c: an administrator's client-messages socket stops reading while a
 *      client sends it 12 MB. The client's control session goes on, and the other management
 *      sockets are served within 2 s: a login failure's event, a new socket's hello, a revoked
 *      account's 1008. The stalled socket is closed 20 s after its write blocked, not before.
 *   2. An in-process admin listener: a connections socket that stops reading while 12000 events
 *      are broadcast is closed once 4096 frames wait behind it (the bound on C's per-socket queue,
 *      which Java's blocking sender does without), having got an unbroken prefix of the events,
 *      while a socket that reads gets every event in order.
 *   3. A real server: admin-to-client writes in flight are bounded at 64 per socket. Past that a
 *      command is answered failed / target-write-failed at once, where Java would queue it (a
 *      documented platform difference); the 64 fail when the target's connection does.
 *
 *   management_ws_backpressure_tests <specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "json.h"
#include "protocol.h"
#include "security.h"
#include "server_harness.h"
#include "storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

/* Within this a socket counts as served at once; a stalled one held them up indefinitely. */
#define PROMPT_MS 2000
/* Java's BLOCKING_SEND_TIMEOUT default, which the server matches. */
#define SEND_TIMEOUT_MS 20000LL
/* A receive buffer this small makes the server's writes block soon after the reader stops. */
#define STALLED_RCVBUF 4096
#define STALL_MESSAGES 200
#define MESSAGE_CHARS 60000U
#define RITA_PASSWORD "rita-backpressure-password-2026"

/* ------------------------------------------------------------------------------------------- */
/* WebSocket client                                                                              */

static int contains(const char *haystack, const char *needle)
{
    return haystack != NULL && strstr(haystack, needle) != NULL;
}

static int ws_send_frame(int fd, uint8_t opcode, const uint8_t *data, size_t len)
{
    uint8_t header[14];
    size_t header_len = 0U;
    header[header_len++] = (uint8_t)(0x80U | opcode);
    if (len < 126U) {
        header[header_len++] = (uint8_t)(0x80U | len);
    } else if (len <= 0xffffU) {
        header[header_len++] = 0x80U | 126U;
        header[header_len++] = (uint8_t)(len >> 8);
        header[header_len++] = (uint8_t)len;
    } else {
        return -1;
    }
    static const uint8_t mask[4] = {0x12U, 0x34U, 0x56U, 0x78U};
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);
    uint8_t *frame = (uint8_t *)malloc(header_len + len);
    if (frame == NULL) return -1;
    memcpy(frame, header, header_len);
    for (size_t i = 0; i < len; ++i) frame[header_len + i] = data[i] ^ mask[i % 4U];
    int rc = send_all(fd, frame, header_len + len);
    free(frame);
    return rc;
}

/*
 * Reads one server frame: 1 with its opcode and payload (NUL-terminated, cut to out_len - 1 bytes),
 * 0 when none started before the timeout, -1 when the connection ended or broke off mid-frame.
 */
static int ws_read_frame(int fd, int timeout_ms, uint8_t *opcode, char *out, size_t out_len)
{
    long long deadline = monotonic_ms() + timeout_ms;
    uint8_t header[2];
    int rc = recv_exact(fd, header, sizeof(header), deadline);
    if (rc == -2) return 0;
    if (rc != 1) return -1;
    /* A frame that has started is read to its end, however long the timeout was. */
    deadline = monotonic_ms() + IO_TIMEOUT_MS;
    uint64_t len = header[1] & 0x7fU;
    if (len == 126U || len == 127U) {
        uint8_t extended[8];
        size_t extended_len = len == 126U ? 2U : 8U;
        if (recv_exact(fd, extended, extended_len, deadline) != 1) return -1;
        len = 0U;
        for (size_t i = 0; i < extended_len; ++i) len = (len << 8) | extended[i];
    }
    size_t kept = 0U;
    while (len > 0U) {
        uint8_t chunk[16384];
        size_t want = len < sizeof(chunk) ? (size_t)len : sizeof(chunk);
        if (recv_exact(fd, chunk, want, deadline) != 1) return -1;
        size_t room = out_len - 1U - kept;
        size_t copy = want < room ? want : room;
        memcpy(out + kept, chunk, copy);
        kept += copy;
        len -= want;
    }
    out[kept] = '\0';
    *opcode = header[0] & 0x0fU;
    return 1;
}

/* 1 once a text message holding needle arrived (others are skipped), 0 on timeout, -1 if closed. */
static int ws_expect_text(int fd, const char *needle, int timeout_ms, char *text, size_t text_len)
{
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) return 0;
        uint8_t opcode = 0U;
        int rc = ws_read_frame(fd, (int)remaining, &opcode, text, text_len);
        if (rc != 1) return rc;
        if (opcode == 0x8U) return -1;
        if (opcode == 0x1U && contains(text, needle)) return 1;
    }
}

/* The code of the CLOSE the socket gets next, skipping text; -1 when none came. */
static int ws_expect_close(int fd, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    char payload[256];
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        uint8_t opcode = 0U;
        if (remaining <= 0 || ws_read_frame(fd, (int)remaining, &opcode, payload, sizeof(payload)) != 1) return -1;
        if (opcode == 0x8U) return ((uint8_t)payload[0] << 8) | (uint8_t)payload[1];
    }
}

static int ws_ping_answered(int fd)
{
    if (ws_send_frame(fd, 0x9U, (const uint8_t *)"p", 1U) != 0) return 0;
    char payload[256];
    uint8_t opcode = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (monotonic_ms() < deadline) {
        if (ws_read_frame(fd, (int)(deadline - monotonic_ms()), &opcode, payload, sizeof(payload)) != 1) return 0;
        if (opcode == 0xAU) return 1;
    }
    return 0;
}

/* 1 when the connection ends (EOF or reset) within the timeout; what was buffered is read past. */
static int ws_ends_within(int fd, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    uint8_t buffer[65536];
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) return 0;
        struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
        int polled = poll(&ready, 1, (int)remaining);
        if (polled < 0 && errno == EINTR) continue;
        if (polled <= 0) return 0;
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received == 0 || (received < 0 && (errno == ECONNRESET || errno == EPIPE))) return 1;
        if (received < 0 && errno != EINTR) return 0;
    }
}

/*
 * A loopback connection, with the given receive buffer when rcvbuf > 0. It is set before connecting
 * so the window stays small: a reader that stops then holds the sender's writes for good, where a
 * larger buffer would now and then free room and let a write trickle on.
 */
static int connect_with_rcvbuf(int port, int rcvbuf)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (fd < 0 || (rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0)
        || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

static char *management_login(int port, const char *username, const char *password)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
    int status = 0;
    char *response = NULL;
    char *token = NULL;
    if (http_request(port, "POST", "/auth/login", body, NULL, &status, &response) == 0 && status == 200) {
        token = st_json_get_string(response, "accessToken");
    } else {
        fprintf(stderr, "login of %s: %d %s\n", username, status, response == NULL ? "" : response);
    }
    free(response);
    return token;
}

/*
 * Opens /ws/<endpoint> with a fresh ticket over connect_with_rcvbuf; for client-messages the hello
 * is read within hello_ms. The socket, or -1.
 */
static int ws_open(int port, const char *token, const char *endpoint, int rcvbuf, int hello_ms)
{
    char request_body[64];
    snprintf(request_body, sizeof(request_body), "{\"endpoint\":\"%s\"}", endpoint);
    int status = 0;
    char *response = NULL;
    char *ticket = NULL;
    if (http_request(port, "POST", "/api/admin/ws-tickets", request_body, token, &status, &response) == 0
        && status == 200) {
        ticket = st_json_get_string(response, "ticket");
    }
    free(response);
    if (ticket == NULL) return -1;
    char request[1024];
    snprintf(request, sizeof(request),
             "GET /ws/%s?ticket=%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\n"
             "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
             endpoint, ticket);
    free(ticket);
    int fd = connect_with_rcvbuf(port, rcvbuf);
    if (fd < 0 || send_all(fd, (const uint8_t *)request, strlen(request)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char head[1024] = {0};
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used + 1U < sizeof(head) && recv_exact(fd, (uint8_t *)head + used, 1U, deadline) == 1) {
        ++used;
        if (used >= 4U && memcmp(head + used - 4U, "\r\n\r\n", 4U) == 0) break;
    }
    char hello[1024];
    if (strncmp(head, "HTTP/1.1 101", 12U) != 0
        || (strcmp(endpoint, "client-messages") == 0
            && ws_expect_text(fd, "\"type\":\"hello\"", hello_ms, hello, sizeof(hello)) != 1)) {
        fprintf(stderr, "/ws/%s upgrade: %s\n", endpoint, head);
        close(fd);
        return -1;
    }
    return fd;
}

static int log_contains(const test_server *server, const char *needle)
{
    FILE *file = fopen(server->log_path, "rb");
    if (file == NULL) return 0;
    size_t capacity = 65536U;
    size_t used = 0U;
    char *text = (char *)malloc(capacity + 1U);
    while (text != NULL) {
        if (used == capacity) {
            char *grown = (char *)realloc(text, capacity * 2U + 1U);
            if (grown == NULL) break;
            text = grown;
            capacity *= 2U;
        }
        size_t read_len = fread(text + used, 1U, capacity - used, file);
        if (read_len == 0U) break;
        used += read_len;
    }
    fclose(file);
    int found = 0;
    if (text != NULL) {
        text[used] = '\0';
        found = strstr(text, needle) != NULL;
    }
    free(text);
    return found;
}

static int send_client_message(int control, const char *client_name, const char *to, const char *text)
{
    st_buffer frame = st_protocol_encode_message_response(client_name, to, ST_MESSAGE_TYPE_CLIENT_TO_CLIENT, text);
    if (frame.data == NULL) return -1;
    frame.data[6] = (uint8_t)ST_CMD_MESSAGE_REQUEST;
    return send_buffer(control, &frame);
}

static char *repeated(char unit, size_t count)
{
    char *text = (char *)malloc(count + 1U);
    if (text != NULL) {
        memset(text, unit, count);
        text[count] = '\0';
    }
    return text;
}

/* ------------------------------------------------------------------------------------------- */
/* 1. A stalled client-messages reader on a real server                                          */

static int scenario_stalled_reader(test_server *server)
{
    int port = server->admin_port;
    char reason[256];
    runtime_session runtime;
    int control = -1;
    harness_login_environment_extra = ",\"receiveMessages\":true,\"sendMessages\":true";
    CHECK(create_credential(server->db_path, "ck_stall", "stall-secret", 2) == 0, "credential");
    int logged_in = http_client_login(server, "ck_stall", "stall-secret", "machine-stall", "sam", &runtime);
    harness_login_environment_extra = "";
    CHECK(logged_in == 0, "client login");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    /* A server that stops reading this connection fails the sends below instead of hanging them. */
    struct timeval send_timeout = {.tv_sec = 10, .tv_usec = 0};
    CHECK(setsockopt(control, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) == 0, "send timeout");

    char *admin = management_login(port, ADMIN_USERNAME, ADMIN_PASSWORD);
    CHECK(admin != NULL, "admin login");
    int status = 0;
    char *body = NULL;
    CHECK(http_request(port, "POST", "/api/admin/users",
                       "{\"username\":\"rita\",\"password\":\"" RITA_PASSWORD "\",\"role\":\"USER\",\"enabled\":true}",
                       admin, &status, &body) == 0 && status == 201,
          "create rita: %d %s", status, body == NULL ? "" : body);
    free(body);
    char *rita = management_login(port, "rita", RITA_PASSWORD);
    CHECK(rita != NULL, "rita login");

    int events = ws_open(port, admin, "connections", 0, 0);
    int stalled = ws_open(port, admin, "client-messages", STALLED_RCVBUF, IO_TIMEOUT_MS);
    int rita_messages = ws_open(port, rita, "client-messages", 0, IO_TIMEOUT_MS);
    free(rita);
    CHECK(events >= 0 && ws_ping_answered(events) && stalled >= 0 && rita_messages >= 0, "sockets");

    /* 12 MB for the administrator, whose socket reads nothing after its hello. */
    char *message = repeated('x', MESSAGE_CHARS);
    CHECK(message != NULL, "message");
    char to_admin[64];
    snprintf(to_admin, sizeof(to_admin), "admin:%s", ADMIN_USERNAME);
    long long fill_started = monotonic_ms();
    int sent = 0;
    while (sent < STALL_MESSAGES && send_client_message(control, runtime.client_name, to_admin, message) == 0) ++sent;
    free(message);
    /* Answered only once the 200 messages before it were handled: none waits on the stalled browser. */
    int control_served = sent == STALL_MESSAGES && expect_channel_alive(control) == 0;
    long long filled = monotonic_ms();

    /* Meanwhile the other management sockets are served at once: a login failure's event... */
    runtime_session probe;
    memset(&probe, 0, sizeof(probe));
    snprintf(probe.client_name, sizeof(probe.client_name), "stall-probe");
    probe.session_id = 1;
    snprintf(probe.access_token, sizeof(probe.access_token), "not-a-token");
    int probe_fd = -1;
    CHECK(channel_login(server->control_port, &probe, "control", &probe_fd, reason, sizeof(reason)) == 0,
          "the probe's login must be refused");
    char text[131072];
    int event_served = ws_expect_text(events, "\"clientName\":\"stall-probe\"", PROMPT_MS, text, sizeof(text)) == 1;
    /* ...a new socket's hello... */
    long long started = monotonic_ms();
    int fresh = ws_open(port, admin, "client-messages", 0, PROMPT_MS);
    int hello_served = fresh >= 0 && monotonic_ms() - started <= PROMPT_MS;
    /* ...and a revocation, answered and closing the account's socket. */
    started = monotonic_ms();
    int revocation_answered = http_request(port, "PUT", "/api/admin/users/rita", "{\"enabled\":false}", admin,
                                           &status, &body) == 0
        && status == 200 && monotonic_ms() - started <= PROMPT_MS;
    free(body);
    int rita_code = ws_expect_close(rita_messages, PROMPT_MS);
    int events_open = ws_ping_answered(events);
    CHECK(control_served && event_served && hello_served && revocation_answered && rita_code == 1008 && events_open,
          "with one socket stalled, everything else must be served within 2 s: the sending client's %d of %d "
          "messages and heartbeat %d, a connection event %d, a new socket's hello %d, the revocation's answer %d "
          "(status %d) and 1008 (%d), a ping on /ws/connections %d", sent, STALL_MESSAGES, control_served,
          event_served, hello_served, revocation_answered, status, rita_code, events_open);

    /* The stalled socket is closed after Java's 20 s send timeout, counted from the blocked write... */
    char stalled_line[160];
    snprintf(stalled_line, sizeof(stalled_line), "client-messages WebSocket of default/%s: write timed out",
             ADMIN_USERNAME);
    long long early = fill_started + SEND_TIMEOUT_MS - 1000LL;
    if (monotonic_ms() < early) sleep_ms((int)(early - monotonic_ms()));
    CHECK(!log_contains(server, stalled_line), "the stalled socket was closed before Java's 20 s send timeout");
    long long deadline = filled + SEND_TIMEOUT_MS + 5000LL;
    while (!log_contains(server, stalled_line) && monotonic_ms() < deadline) sleep_ms(100);
    CHECK(log_contains(server, stalled_line), "the stalled socket was not closed 20 s after its write blocked");
    /* ...which ends once what went out is read, while the administrator's other socket goes on. */
    CHECK(ws_ends_within(stalled, IO_TIMEOUT_MS), "the stalled socket did not end");
    CHECK(send_client_message(control, runtime.client_name, to_admin, "after the stall") == 0
              && ws_expect_text(fresh, "\"message\":\"after the stall\"", PROMPT_MS, text, sizeof(text)) == 1,
          "the administrator's other socket must get later messages");

    free(admin);
    close(events);
    close(stalled);
    close(rita_messages);
    close(fresh);
    close_fd(&control);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* 2. A connections reader that falls 4096 frames behind, in process                            */

#define FLOOD_EVENTS 12000LL
/* How far the broadcaster may run ahead of the socket that reads. */
#define FLOOD_WINDOW 256LL

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    long long acknowledged;
    int stop;
} flood_pacing;

static void flood_event(long long id)
{
    st_storage_connection connection;
    memset(&connection, 0, sizeof(connection));
    connection.id = id;
    snprintf(connection.tenant_id, sizeof(connection.tenant_id), "default");
    /* Long fields make each event about 1 KiB, so the stalled socket's buffers fill sooner. */
    memset(connection.client_name, 'c', 200U);
    memset(connection.channel_id, 'h', 100U);
    memset(connection.failure_reason, 'r', 200U);
    snprintf(connection.remote_address, sizeof(connection.remote_address), "203.0.113.7");
    snprintf(connection.connected_at, sizeof(connection.connected_at), "2026-10-20T00:00:00Z");
    st_admin_broadcast_connection_event("default", "created", &connection);
}

static void *flood_thread(void *arg)
{
    flood_pacing *pacing = (flood_pacing *)arg;
    for (long long id = 1; id <= FLOOD_EVENTS; ++id) {
        pthread_mutex_lock(&pacing->lock);
        while (!pacing->stop && id - pacing->acknowledged > FLOOD_WINDOW) {
            pthread_cond_wait(&pacing->cond, &pacing->lock);
        }
        int stop = pacing->stop;
        pthread_mutex_unlock(&pacing->lock);
        if (stop) break;
        flood_event(id);
    }
    return NULL;
}

static long long event_id(const char *text)
{
    const char *at = strstr(text, "\"connection\":{\"id\":");
    return at == NULL ? -1 : strtoll(at + strlen("\"connection\":{\"id\":"), NULL, 10);
}

static int test_backlog_bound(void)
{
    char dir[] = "/tmp/specus-c-ws-backlog-XXXXXX";
    CHECK(mkdtemp(dir) != NULL, "temporary directory");
    char path[256];
    snprintf(path, sizeof(path), "%s/backlog.db", dir);
    static const char secret[] = "ws-backlog-jwt-secret-long-enough-2026";
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    setenv("SPECUS_DATABASE_PATH", path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", secret, 1);
    st_storage_management_user user;
    CHECK(st_storage_init(path, 0) == 0
              && st_storage_create_management_user(path, "flood-admin", "default", "unused-password-hash", "ADMIN", 1,
                                                   &user) == 0,
          "account");
    char token[1024];
    CHECK(st_security_issue_local_token("flood-admin", "default", "ADMIN", secret, 600, token, sizeof(token)) == 0,
          "token");
    /* The listener thread outlives this function. */
    static st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    CHECK(st_admin_server_start(&server, 0, "") == 0
              && getsockname(server.fd, (struct sockaddr *)&address, &address_len) == 0,
          "listener");
    int port = ntohs(address.sin_port);
    int reader = ws_open(port, token, "connections", 0, 0);
    int stalled = ws_open(port, token, "connections", STALLED_RCVBUF, 0);
    CHECK(reader >= 0 && ws_ping_answered(reader) && stalled >= 0 && ws_ping_answered(stalled), "sockets");

    /* Static as well: on failure the broadcaster is left behind, possibly stuck for good. */
    static flood_pacing pacing;
    memset(&pacing, 0, sizeof(pacing));
    pthread_mutex_init(&pacing.lock, NULL);
    pthread_cond_init(&pacing.cond, NULL);
    pthread_t broadcaster;
    long long started = monotonic_ms();
    CHECK(pthread_create(&broadcaster, NULL, flood_thread, &pacing) == 0, "broadcaster");
    char text[8192];
    long long stopped_at = 0;
    long long got = 0;
    for (long long expected = 1; stopped_at == 0 && expected <= FLOOD_EVENTS; ++expected) {
        uint8_t opcode = 0U;
        int rc = ws_read_frame(reader, IO_TIMEOUT_MS, &opcode, text, sizeof(text));
        long long id = rc == 1 && opcode == 0x1U ? event_id(text) : -1;
        if (id != expected) {
            stopped_at = expected;
            got = id;
        }
        pthread_mutex_lock(&pacing.lock);
        pacing.acknowledged = id;
        pacing.stop = stopped_at != 0;
        pthread_cond_signal(&pacing.cond);
        pthread_mutex_unlock(&pacing.lock);
    }
    /* The broadcaster may be stuck on the stalled socket for good; it is not waited for then. */
    CHECK(stopped_at == 0, "the reading socket stopped at event %lld (got %lld): a stalled socket held up the "
                           "fan-out", stopped_at, got);
    pthread_join(broadcaster, NULL);

    /* The stalled socket was closed when its backlog overflowed, not 20 s later, and what it got
     * is every event from the first on, without a gap. */
    long long delivered = 0;
    int ended = 0;
    int close_code = 0;
    for (;;) {
        uint8_t opcode = 0U;
        int rc = ws_read_frame(stalled, IO_TIMEOUT_MS, &opcode, text, sizeof(text));
        if (rc == 0) break;
        if (rc < 0) {
            ended = 1;
            break;
        }
        if (opcode == 0x8U) {
            close_code = ((uint8_t)text[0] << 8) | (uint8_t)text[1];
            ended = ws_ends_within(stalled, IO_TIMEOUT_MS);
            break;
        }
        if (opcode != 0x1U || event_id(text) != delivered + 1) break;
        ++delivered;
    }
    long long elapsed = monotonic_ms() - started;
    int reader_open = ws_ping_answered(reader);
    close(reader);
    close(stalled);
    unlink(path);
    rmdir(dir);
    CHECK(ended && (close_code == 0 || close_code == 1001),
          "the stalled socket must end, unbroken (after %lld events, close %d)", delivered, close_code);
    CHECK(delivered > 0 && delivered < FLOOD_EVENTS - 4096, "the stalled socket got %lld events", delivered);
    CHECK(elapsed < SEND_TIMEOUT_MS - 5000LL, "the overflow did not close the stalled socket at once (%lld ms)",
          elapsed);
    CHECK(reader_open, "the reading socket must stay open");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* 3. Admin-to-client writes in flight                                                           */

#define IN_FLIGHT_COMMANDS 200
#define IN_FLIGHT_PER_SOCKET 64

static int scenario_in_flight_bound(test_server *server)
{
    int port = server->admin_port;
    char reason[256];
    runtime_session runtime;
    int target = -1;
    harness_login_environment_extra = ",\"receiveMessages\":true,\"sendMessages\":true";
    CHECK(create_credential(server->db_path, "ck_target", "target-secret", 2) == 0, "credential");
    int logged_in = http_client_login(server, "ck_target", "target-secret", "machine-target", "tia", &runtime);
    harness_login_environment_extra = "";
    CHECK(logged_in == 0, "client login");
    /* The target never reads its control connection again: the server's writes to it block. */
    target = connect_with_rcvbuf(server->control_port, STALLED_RCVBUF);
    int command_id = 0;
    int success = 0;
    CHECK(target >= 0 && send_login_request(target, &runtime, "control") == 0
              && read_login_response(target, IO_TIMEOUT_MS, &command_id, &success, reason, sizeof(reason)) == 1
              && success,
          "control login: %s", reason);
    char *admin = management_login(port, ADMIN_USERNAME, ADMIN_PASSWORD);
    CHECK(admin != NULL, "admin login");
    int socket_fd = ws_open(port, admin, "client-messages", 0, IO_TIMEOUT_MS);
    free(admin);
    CHECK(socket_fd >= 0, "client-messages socket");

    char *message = repeated('y', MESSAGE_CHARS);
    CHECK(message != NULL, "message");
    size_t command_cap = MESSAGE_CHARS + 512U;
    char *command = (char *)malloc(command_cap);
    CHECK(command != NULL, "command");
    int sent_ok = 1;
    for (int i = 0; sent_ok && i < IN_FLIGHT_COMMANDS; ++i) {
        int len = snprintf(command, command_cap, "{\"type\":\"message\",\"messageId\":\"m-%d\",\"toClientName\":\"%s\","
                                                 "\"message\":\"%s\"}", i, runtime.client_name, message);
        sent_ok = len > 0 && ws_send_frame(socket_fd, 0x1U, (const uint8_t *)command, (size_t)len) == 0;
    }
    free(command);
    free(message);
    CHECK(sent_ok, "commands");
    long long sent_at = monotonic_ms();

    /* While the target stalls, 64 writes stay in flight and every other command is answered: written
     * while the target's buffers took it, failed at once after that. */
    char text[1024];
    int written = 0;
    int failed = 0;
    int other = 0;
    while (written + failed + other < IN_FLIGHT_COMMANDS - IN_FLIGHT_PER_SOCKET && monotonic_ms() < sent_at + 5000) {
        uint8_t opcode = 0U;
        if (ws_read_frame(socket_fd, 500, &opcode, text, sizeof(text)) != 1) continue;
        if (contains(text, "\"type\":\"written\"")) ++written;
        else if (contains(text, "\"type\":\"failed\"") && contains(text, "\"error\":\"target-write-failed\"")) ++failed;
        else ++other;
    }
    uint8_t opcode = 0U;
    int quiet = ws_read_frame(socket_fd, 500, &opcode, text, sizeof(text)) == 0;
    CHECK(other == 0 && written + failed == IN_FLIGHT_COMMANDS - IN_FLIGHT_PER_SOCKET && failed > 0 && quiet,
          "with the target stalled, exactly 64 writes must stay in flight and the rest be answered at once "
          "(written %d, failed %d, other %d, quiet %d)", written, failed, other, quiet);
    /* The target goes away with unread data (a reset): the blocked write fails, and the 64 with it,
     * as Java's write futures fail when the channel closes. */
    close_fd(&target);
    long long closed_at = monotonic_ms();
    int late_failed = 0;
    int late_other = 0;
    text[0] = '\0';
    while (late_failed + late_other < IN_FLIGHT_PER_SOCKET && monotonic_ms() < closed_at + IO_TIMEOUT_MS) {
        if (ws_read_frame(socket_fd, 500, &opcode, text, sizeof(text)) != 1) continue;
        if (contains(text, "\"type\":\"failed\"") && contains(text, "\"error\":\"target-write-failed\"")) ++late_failed;
        else ++late_other;
    }
    CHECK(late_failed == IN_FLIGHT_PER_SOCKET, "the writes in flight must fail with the target's connection (%d "
                                               "failed, %d other, last %.200s)", late_failed, late_other, text);
    close(socket_fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    (void)signal(SIGPIPE, SIG_IGN);
    /* Each scenario runs whatever the others did, so that each symptom is reported on its own. */
    int failed = run_on_fresh_server("a stalled client-messages reader holds up no one and is closed after 20 s",
                                     scenario_stalled_reader, NULL);
    failed |= run_on_fresh_server("64 admin-to-client writes in flight per socket", scenario_in_flight_bound, NULL);
    /* In process, and last: on failure its broadcaster may be stuck for good. */
    int backlog_failed = test_backlog_bound();
    printf("%s a connections reader 4096 frames behind is closed at once\n", backlog_failed ? "FAIL" : "ok  ");
    failed |= backlog_failed;
    if (failed) return 1;
    printf("management WebSocket backpressure tests passed\n");
    return 0;
}
