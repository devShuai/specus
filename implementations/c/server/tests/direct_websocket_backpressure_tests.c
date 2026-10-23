/*
 * A browser that stops reading a route WebSocket, against a real specus-server-c process. Java
 * writes client frames to the browser with Tomcat's blocking send on the data connection's event
 * loop (NatServerHandler.processWsData -> WebSocketSpecusHandler.writeFrame), so a stalled browser
 * holds that connection for at most BLOCKING_SEND_TIMEOUT (20 s, left at its default), after which
 * Tomcat closes just that session. The C server must never let one browser hold the data
 * connection's only reader at all:
 *
 *   - while one browser reads nothing and the client has used up that stream's window, the same
 *     data connection answers a heartbeat, serves an HTTP request and relays a TCP stream within a
 *     few seconds, and another WebSocket on it whose browser reads slowly but steadily keeps
 *     receiving;
 *   - the stalled stream gets no WINDOW_UPDATE while its frames wait, so the client's window bounds
 *     what the server holds for it;
 *   - 20 s after its write blocked (not before) the stalled WebSocket is closed and the client gets
 *     RST 31 for it, while the slow reader, whose every frame goes out well within 20 s, gets all of
 *     its 512 KiB over more than 20 s and is never closed;
 *   - afterwards the data connection serves HTTP and TCP as before.
 *
 *   direct_websocket_backpressure_tests <specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "json.h"
#include "protocol.h"
#include "storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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

#define ROUTE "app"
#define INITIAL_WINDOW (1024U * 1024U)
#define SWS2_HEADER 12U
/* One SWS2 envelope fills a 64 KiB NAT DATA. */
#define FLOOD_PAYLOAD (64U * 1024U - SWS2_HEADER)
/* Java's BLOCKING_SEND_TIMEOUT default, which the server matches. */
#define SEND_TIMEOUT_MS 20000LL
/* Within this a stream counts as served at once; a held data connection never serves it. */
#define PROMPT_MS 3000
/* No WINDOW_UPDATE for this long with the window used up: the stalled stream's writer is stuck. */
#define STALL_QUIET_MS 1500
/* A receive buffer and segment size this small keep the server's send buffer near 46 KB. */
#define STALLED_RCVBUF 4096
#define NARROW_MSS 1000
/* The slow reader: 64 frames of 8 KiB, read 2 KiB per 100 ms, about 25 s in all. */
#define SLOW_FRAMES 64U
#define SLOW_PAYLOAD (8U * 1024U)
#define SLOW_READ_BYTES 2048U
#define SLOW_READ_PAUSE_MS 100
#define RESPONSE_HEAD                                                                              \
    "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,\"headers\":[\"Content-Type: text/plain\"]," \
    "\"trailerNames\":[]}"

typedef struct {
    runtime_session runtime;
    int control;
    int data;
    int public_port;
} client_pair;

/* ------------------------------------------------------------------------------------------- */
/* Client side of the data connection                                                            */

static int send_nat(int fd, int type, uint8_t flags, uint32_t stream_id, uint32_t value,
                    const char *meta, const void *data, size_t data_len)
{
    st_buffer frame = st_protocol_encode_nat_message(type, flags, stream_id, value, meta,
                                                     (const uint8_t *)data, data_len);
    return send_buffer(fd, &frame);
}

/* The next NAT frame within timeout_ms: 1 with *message filled, -2 on timeout, otherwise -1. */
static int next_nat_frame(int fd, int timeout_ms, st_nat_message *message)
{
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -2;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(fd, (int)remaining, &header, &body);
        if (rc != 1) {
            return rc == -2 ? -2 : -1;
        }
        if (header.command != ST_CMD_NAT_MESSAGE) {
            free(body);
            continue;
        }
        int decoded = st_protocol_decode_nat_message(body, header.length, message);
        free(body);
        return decoded == 0 ? 1 : -1;
    }
}

/* One SWS2 binary envelope (FIN set) of len bytes, all `fill`. */
static uint8_t *sws2_binary(size_t len, uint8_t fill, size_t *encoded_len)
{
    uint8_t *encoded = (uint8_t *)malloc(SWS2_HEADER + len);
    if (encoded == NULL) {
        return NULL;
    }
    memcpy(encoded, "SWS2", 4U);
    encoded[4] = 0x2U;
    encoded[5] = 0x01U;
    encoded[6] = 0U;
    encoded[7] = 0U;
    encoded[8] = (uint8_t)(len >> 24U);
    encoded[9] = (uint8_t)(len >> 16U);
    encoded[10] = (uint8_t)(len >> 8U);
    encoded[11] = (uint8_t)len;
    memset(encoded + SWS2_HEADER, fill, len);
    *encoded_len = SWS2_HEADER + len;
    return encoded;
}

static int pair_up(test_server *server, client_pair *pair)
{
    char reason[256];
    memset(pair, 0, sizeof(*pair));
    pair->control = -1;
    pair->data = -1;
    pair->public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_wsbp", "wsbp-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_wsbp", "wsbp-secret", "machine-wsbp", "wsbp", &pair->runtime) == 0,
          "http login");
    CHECK(create_mapping(server->db_path, pair->runtime.client_id, pair->public_port) == 0, "mapping");
    st_storage_http_route route;
    CHECK(st_storage_create_http_route_for_client(server->db_path, pair->runtime.client_id, ROUTE,
                                                  "http://127.0.0.1:9", 1, 0, 0, 0, 0, 0, NULL, NULL,
                                                  &route) == 0,
          "HTTP route");
    CHECK(channel_login(server->control_port, &pair->runtime, "control", &pair->control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    CHECK(channel_login(server->control_port, &pair->runtime, "data", &pair->data, reason, sizeof(reason)) == 1,
          "data login: %s", reason);
    /* A server that stops reading the data connection fails the test's sends instead of hanging them. */
    struct timeval send_timeout = {.tv_sec = 10, .tv_usec = 0};
    CHECK(setsockopt(pair->data, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout)) == 0, "send timeout");
    CHECK(nat_register(pair->data, pair->runtime.client_name, pair->public_port, 9) == 0, "REGISTER");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Browser side                                                                                  */

static void url_encode(const char *value, char *out, size_t out_len)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t used = 0U;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0' && used + 4U < out_len; ++cursor) {
        unsigned char c = *cursor;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~') {
            out[used++] = (char)c;
        } else {
            out[used++] = '%';
            out[used++] = hex[c >> 4U];
            out[used++] = hex[c & 0x0fU];
        }
    }
    out[used] = '\0';
}

/*
 * A loopback connection whose receive buffer and segment size are set before connecting, so a
 * reader that stops holds the server's writes for good, and a slow one paces them.
 */
static int connect_narrow(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int rcvbuf = STALLED_RCVBUF;
    int mss = NARROW_MSS;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) != 0
        || setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss)) != 0
        || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    return fd;
}

/*
 * Upgrades a narrow browser socket on the client's route and waits for the client's OPEN of the
 * stream; the 101 is read byte by byte so no frame after it is consumed.
 */
static int open_websocket(const test_server *server, const client_pair *pair, const char *path,
                          int *browser, uint32_t *stream_id)
{
    char client[768];
    char request[2048];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "GET /http/%s/%s%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\n"
                       "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                       "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                       client, ROUTE, path);
    *browser = connect_narrow(server->admin_port);
    CHECK(*browser >= 0 && len > 0 && send_all(*browser, (const uint8_t *)request, (size_t)len) == 0,
          "browser upgrade request");
    st_nat_message open;
    CHECK(expect_nat_frame(pair->data, ST_NAT_OPEN, &open) == 0, "no OPEN for the WebSocket");
    int is_ws = open.meta_json != NULL && strstr(open.meta_json, "\"source\":\"ws\"") != NULL;
    *stream_id = open.stream_id;
    st_nat_message_free(&open);
    CHECK(is_ws, "the OPEN is not a WebSocket stream");
    char head[1024] = {0};
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used + 1U < sizeof(head) && recv_exact(*browser, (uint8_t *)head + used, 1U, deadline) == 1) {
        ++used;
        if (used >= 4U && memcmp(head + used - 4U, "\r\n\r\n", 4U) == 0) break;
    }
    CHECK(strncmp(head, "HTTP/1.1 101", 12U) == 0, "upgrade answered: %s", head);
    return 0;
}

/* Reads a browser HTTP response to EOF within timeout_ms; 0 when it is a 200 carrying body_text. */
static int expect_ok_response(int fd, int timeout_ms, const char *body_text)
{
    char response[8192];
    size_t used = 0U;
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) {
            break;
        }
        ssize_t received = recv(fd, response + used, sizeof(response) - 1U - used, 0);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) {
            response[used] = '\0';
            return strncmp(response, "HTTP/1.1 200", 12U) == 0 && strstr(response, body_text) != NULL ? 0 : -1;
        }
        used += (size_t)received;
        if (used + 1U >= sizeof(response)) break;
    }
    response[used] = '\0';
    fprintf(stderr, "browser response incomplete after %d ms: %s\n", timeout_ms, response);
    return -1;
}

/* An HTTP request through the data connection gets its whole response within timeout_ms. */
static int expect_http_served(const test_server *server, client_pair *pair, int timeout_ms)
{
    char client[768];
    char request[2048];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "GET /http/%s/%s/served HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                       client, ROUTE);
    int browser = connect_local(server->admin_port);
    CHECK(browser >= 0 && send_all(browser, (const uint8_t *)request, (size_t)len) == 0, "HTTP request");
    st_nat_message open;
    long long deadline = monotonic_ms() + timeout_ms;
    int found = 0;
    while (!found && monotonic_ms() < deadline) {
        int rc = next_nat_frame(pair->data, (int)(deadline - monotonic_ms()), &open);
        if (rc != 1) break;
        found = open.type == ST_NAT_OPEN;
        if (!found) st_nat_message_free(&open);
    }
    if (!found) close(browser);
    CHECK(found, "no request OPEN within %d ms", timeout_ms);
    uint32_t stream_id = open.stream_id;
    st_nat_message_free(&open);
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0
              && send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "served", 6U) == 0
              && send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0,
          "HTTP response frames");
    int rc = expect_ok_response(browser, (int)(deadline - monotonic_ms() > 0 ? deadline - monotonic_ms() : 1), "served");
    close(browser);
    CHECK(rc == 0, "the HTTP response did not reach the browser within %d ms", timeout_ms);
    return 0;
}

/* A public TCP stream on the data connection relays the client's DATA within timeout_ms. */
static int expect_tcp_served(client_pair *pair, int timeout_ms)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "ping", 4U) == 0, "TCP DATA");
    char buffer[4];
    int rc = recv_exact(public_fd, (uint8_t *)buffer, sizeof(buffer), monotonic_ms() + timeout_ms);
    CHECK(rc == 1 && memcmp(buffer, "ping", 4U) == 0, "the TCP DATA did not reach the public peer within %d ms",
          timeout_ms);
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 0U, NULL, NULL, 0U) == 0, "TCP RST");
    close(public_fd);
    return 0;
}

/* The data connection answers a heartbeat within timeout_ms (frames before the answer are skipped). */
static int expect_heartbeat_answered(int data, int timeout_ms)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    CHECK(send_buffer(data, &heartbeat) == 0, "heartbeat");
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        CHECK(remaining > 0, "no heartbeat answer within %d ms", timeout_ms);
        st_frame_header header;
        uint8_t *body = NULL;
        CHECK(read_frame(data, (int)remaining, &header, &body) == 1, "no heartbeat answer within %d ms", timeout_ms);
        free(body);
        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) return 0;
    }
}

/* ------------------------------------------------------------------------------------------- */
/* The slow but steady browser                                                                   */

typedef struct {
    int fd;
    size_t frames;
    size_t bytes;
    int intact;
    int closed_early;
    long long finished_ms;
} slow_reader;

/* Reads SLOW_FRAMES binary frames, SLOW_READ_BYTES at a time with a pause in between. */
static void *slow_reader_thread(void *arg)
{
    slow_reader *reader = (slow_reader *)arg;
    reader->intact = 1;
    uint8_t buffer[SLOW_READ_BYTES];
    size_t frame_left = 0U;
    size_t header_have = 0U;
    uint8_t header[4];
    long long deadline = monotonic_ms() + 120000LL;
    while (reader->frames < SLOW_FRAMES && monotonic_ms() < deadline) {
        size_t want = frame_left > 0U ? (frame_left < sizeof(buffer) ? frame_left : sizeof(buffer))
                                      : sizeof(header) - header_have;
        int rc = recv_exact(reader->fd, frame_left > 0U ? buffer : header + header_have, want,
                            monotonic_ms() + 30000LL);
        if (rc != 1) {
            reader->closed_early = 1;
            break;
        }
        if (frame_left > 0U) {
            for (size_t i = 0U; i < want; ++i) {
                if (buffer[i] != (uint8_t)('a' + reader->frames % 26U)) reader->intact = 0;
            }
            frame_left -= want;
            reader->bytes += want;
            if (frame_left == 0U) ++reader->frames;
            sleep_ms(SLOW_READ_PAUSE_MS);
            continue;
        }
        header_have += want;
        if (header_have < sizeof(header)) continue;
        /* 0x82, 126 and a 16-bit length: an unmasked final binary frame of SLOW_PAYLOAD bytes. */
        if (header[0] != 0x82U || header[1] != 126U || (size_t)((header[2] << 8) | header[3]) != SLOW_PAYLOAD) {
            reader->intact = 0;
            reader->closed_early = 1;
            break;
        }
        header_have = 0U;
        frame_left = SLOW_PAYLOAD;
    }
    reader->finished_ms = monotonic_ms();
    return NULL;
}

/* 1 when the connection ends (EOF or reset) within timeout_ms; what was buffered is read past. */
static int ends_within(int fd, int timeout_ms)
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

/* ------------------------------------------------------------------------------------------- */
/* The scenario                                                                                  */

static int scenario_stalled_browser(test_server *server)
{
    client_pair pair;
    if (pair_up(server, &pair) != 0) {
        return 1;
    }
    int stalled = -1;
    int slow = -1;
    uint32_t stalled_id = 0U;
    uint32_t slow_id = 0U;
    if (open_websocket(server, &pair, "/stalled", &stalled, &stalled_id) != 0
        || open_websocket(server, &pair, "/slow", &slow, &slow_id) != 0) {
        return 1;
    }

    /* The client fills the stalled stream's window and keeps it full until no credit comes back. */
    size_t flood_len = 0U;
    uint8_t *flood = sws2_binary(FLOOD_PAYLOAD, 'x', &flood_len);
    CHECK(flood != NULL, "flood envelope");
    uint64_t credit = INITIAL_WINDOW;
    uint64_t flooded = 0U;
    uint64_t credited = 0U;
    long long last_credit_ms = monotonic_ms();
    int stalled_reset = 0;
    for (;;) {
        while (credit >= flood_len && flooded < 64ULL * 1024ULL * 1024ULL) {
            if (send_nat(pair.data, ST_NAT_DATA, 0U, stalled_id, 0U, NULL, flood, flood_len) != 0) {
                free(flood);
                CHECK(0, "the server stopped reading the data connection after %llu bytes",
                      (unsigned long long)flooded);
            }
            credit -= flood_len;
            flooded += flood_len;
        }
        st_nat_message message;
        int rc = next_nat_frame(pair.data, STALL_QUIET_MS, &message);
        if (rc == -2) break;
        if (rc != 1) {
            free(flood);
            CHECK(0, "data connection failed while flooding");
        }
        if (message.type == ST_NAT_WINDOW_UPDATE && message.stream_id == stalled_id) {
            credit += message.value;
            credited += message.value;
            last_credit_ms = monotonic_ms();
        } else if (message.type == ST_NAT_RST && message.stream_id == stalled_id) {
            stalled_reset = 1;
        }
        st_nat_message_free(&message);
    }
    free(flood);
    CHECK(!stalled_reset && flooded < 64ULL * 1024ULL * 1024ULL,
          "the stalled browser never held the stream's credit (%llu bytes sent)", (unsigned long long)flooded);
    /* Credit only comes back for what was written: the client's window bounds what waits. */
    CHECK(flooded - credited <= INITIAL_WINDOW, "%llu bytes outstanding beyond the window",
          (unsigned long long)(flooded - credited));

    /* Meanwhile the rest of the data connection is served at once. */
    CHECK(expect_heartbeat_answered(pair.data, PROMPT_MS) == 0,
          "a stalled browser held the data connection: no heartbeat answer");
    CHECK(expect_http_served(server, &pair, PROMPT_MS) == 0, "a stalled browser held an HTTP stream");
    CHECK(expect_tcp_served(&pair, PROMPT_MS) == 0, "a stalled browser held a TCP stream");

    /* Another WebSocket on the same connection keeps flowing to a browser that reads slowly. */
    slow_reader reader = {.fd = slow};
    pthread_t reader_thread;
    CHECK(pthread_create(&reader_thread, NULL, slow_reader_thread, &reader) == 0, "reader thread");
    long long slow_started = monotonic_ms();
    uint64_t slow_credit = INITIAL_WINDOW;
    size_t slow_sent = 0U;
    long long reset_ms = 0;
    uint32_t reset_code = 0U;
    int slow_reset = 0;
    long long deadline = last_credit_ms + SEND_TIMEOUT_MS + 15000LL;
    while (monotonic_ms() < deadline && (reset_ms == 0 || slow_sent < SLOW_FRAMES)) {
        while (slow_sent < SLOW_FRAMES && slow_credit >= SWS2_HEADER + SLOW_PAYLOAD) {
            size_t envelope_len = 0U;
            uint8_t *envelope = sws2_binary(SLOW_PAYLOAD, (uint8_t)('a' + slow_sent % 26U), &envelope_len);
            int sent = envelope != NULL
                && send_nat(pair.data, ST_NAT_DATA, 0U, slow_id, 0U, NULL, envelope, envelope_len) == 0;
            free(envelope);
            if (!sent) break;
            slow_credit -= envelope_len;
            ++slow_sent;
        }
        st_nat_message message;
        int rc = next_nat_frame(pair.data, 200, &message);
        if (rc == -2) continue;
        if (rc != 1) break;
        if (message.type == ST_NAT_WINDOW_UPDATE && message.stream_id == slow_id) {
            slow_credit += message.value;
        } else if (message.type == ST_NAT_RST && message.stream_id == stalled_id && reset_ms == 0) {
            reset_ms = monotonic_ms();
            reset_code = message.value;
        } else if (message.type == ST_NAT_RST && message.stream_id == slow_id) {
            slow_reset = 1;
        }
        st_nat_message_free(&message);
        if (slow_reset) break;
    }
    pthread_join(reader_thread, NULL);
    CHECK(!slow_reset, "the slowly read WebSocket was reset");
    CHECK(reset_ms != 0, "the stalled WebSocket was never closed (no RST %llu ms after its last credit)",
          (unsigned long long)(monotonic_ms() - last_credit_ms));
    /* Its write blocked once the last credit came back: closed 20 s after that, not before. */
    long long held = reset_ms - last_credit_ms;
    CHECK(held >= SEND_TIMEOUT_MS - 1000LL && held <= SEND_TIMEOUT_MS + 10000LL,
          "the stalled WebSocket was reset %lld ms after its write blocked, want Java's 20 s send timeout", held);
    CHECK(reset_code == 31U, "the stalled WebSocket was reset with %u, want 31", reset_code);
    /* The browser reads what reached it and then the end of the connection. */
    CHECK(ends_within(stalled, IO_TIMEOUT_MS), "the stalled browser's connection was not ended");
    CHECK(!reader.closed_early && reader.intact && reader.frames == SLOW_FRAMES
              && reader.bytes == (size_t)SLOW_FRAMES * SLOW_PAYLOAD,
          "the slow reader got %zu of %u frames (%zu bytes, intact %d, ended early %d)", reader.frames,
          SLOW_FRAMES, reader.bytes, reader.intact, reader.closed_early);
    CHECK(reader.finished_ms - slow_started > SEND_TIMEOUT_MS,
          "the slow reader finished in %lld ms; it must take longer than one send timeout to prove frames are timed "
          "one by one", reader.finished_ms - slow_started);

    /* Afterwards the data connection works as before. */
    CHECK(expect_heartbeat_answered(pair.data, PROMPT_MS) == 0, "no heartbeat answer after the reset");
    CHECK(expect_http_served(server, &pair, PROMPT_MS) == 0, "HTTP after the reset");
    CHECK(expect_tcp_served(&pair, PROMPT_MS) == 0, "TCP after the reset");

    close(stalled);
    close(slow);
    close_fd(&pair.data);
    close_fd(&pair.control);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    static const char *const long_idle[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900", NULL};
    int failures = run_on_fresh_server("a stalled browser WebSocket holds up nothing but itself",
                                       scenario_stalled_browser, long_idle);
    if (failures != 0) {
        fprintf(stderr, "direct WebSocket backpressure tests failed\n");
        return 1;
    }
    printf("direct WebSocket backpressure tests passed\n");
    return 0;
}
