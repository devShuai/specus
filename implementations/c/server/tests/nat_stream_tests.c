/*
 * NAT stream semantics of the data connection against a real specus-server-c process
 * (protocol/spec/control-protocol.md "NAT stream v2" and "HTTP streaming"), aligned with Java
 * NatServerHandler / HttpStreamExchange / RemoteSpecusHandler and Go clientSession:
 *
 *   - a frame one stream cannot take resets only that stream; the data connection and its other
 *     streams carry on (DATA before an HTTP response head, a second head, a second FIN, DATA after
 *     a TCP FIN, a client OPEN for a TCP stream, a response beyond 64 MiB, the 4 MiB TCP queue);
 *   - DATA and FIN for unknown streams are answered with RST 7, a late RST for a recently closed
 *     stream is ignored, and an RST for a never-opened stream or a WINDOW_UPDATE that overflows the
 *     send window closes the data connection;
 *   - DATA|END_STREAM is DATA followed by FIN, a response head may leave out trailerNames,
 *     HEARTBEAT_RESPONSE is accepted on both roles, request bodies over 16 MiB get 413 and the
 *     1025th pending HTTP stream gets 502.
 *
 * The test plays the client on real control/data sockets and the browser and the public peer on
 * real HTTP and TCP sockets. Every check runs on its own server, so each one shows on its own
 * whether the server keeps to its rule.
 *
 * Usage: specus_c_nat_stream_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "protocol.h"
#include "storage.h"
#include "stream_tombstones.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#define ROUTE "app"
#define DATA_CHUNK (64U * 1024U)
#define INITIAL_WINDOW (1024U * 1024U)
#define MAX_WINDOW (16U * 1024U * 1024U)
#define RESPONSE_LIMIT (64U * 1024U * 1024U)
#define REQUEST_BODY_LIMIT (16U * 1024U * 1024U)
#define PENDING_STREAM_LIMIT 1024U
/* Well beyond the 4 MiB queue plus whatever the kernel socket buffers absorb. */
#define QUEUE_FLOOD (16U * 1024U * 1024U)
#define UNKNOWN_STREAM_BASE 0x7fff0000U
#define RESPONSE_HEAD                                                                              \
    "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,\"headers\":[\"Content-Type: text/plain\"]," \
    "\"trailerNames\":[]}"
/* trailerNames is optional in a response head (protocol/spec/control-protocol.md). */
#define RESPONSE_HEAD_WITHOUT_TRAILER_NAMES \
    "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,\"headers\":[\"Content-Type: text/plain\"]}"

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

/* The next NAT frame before the deadline: 1 with *message filled, 0 when closed, -1 otherwise. */
static int next_nat_frame(int fd, long long deadline, st_nat_message *message)
{
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(fd, (int)remaining, &header, &body);
        if (rc != 1) {
            return rc == 0 ? 0 : -1;
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

/* Waits for the RST of one stream, skipping every other frame, and returns its error code. */
static int wait_rst(int fd, uint32_t stream_id, uint32_t *code)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        st_nat_message message;
        int rc = next_nat_frame(fd, deadline, &message);
        if (rc != 1) {
            fprintf(stderr, "no RST for stream %u (rc=%d)\n", stream_id, rc);
            return -1;
        }
        int match = message.type == ST_NAT_RST && message.stream_id == stream_id;
        *code = message.value;
        st_nat_message_free(&message);
        if (match) {
            return 0;
        }
    }
}

static int expect_rst(int fd, uint32_t stream_id, uint32_t code)
{
    uint32_t actual = 0U;
    if (wait_rst(fd, stream_id, &actual) != 0) {
        return -1;
    }
    if (actual != code) {
        fprintf(stderr, "stream %u reset with %u, expected %u\n", stream_id, actual, code);
        return -1;
    }
    return 0;
}

/* The data connection still answers a heartbeat and sent no RST for the stream before it. */
static int expect_alive_without_rst(int fd, uint32_t stream_id)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    if (send_buffer(fd, &heartbeat) != 0) {
        return -1;
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        if (read_frame(fd, (int)remaining, &header, &body) != 1) {
            fprintf(stderr, "data connection closed or silent\n");
            return -1;
        }
        int reset = 0;
        if (header.command == ST_CMD_NAT_MESSAGE) {
            st_nat_message message;
            if (st_protocol_decode_nat_message(body, header.length, &message) == 0) {
                reset = message.type == ST_NAT_RST && message.stream_id == stream_id;
                st_nat_message_free(&message);
            }
        }
        free(body);
        if (reset) {
            fprintf(stderr, "stream %u was reset\n", stream_id);
            return -1;
        }
        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) {
            return 0;
        }
    }
}

/* Waits for the server's request OPEN of the next HTTP stream. */
static int expect_http_open(int data_fd, uint32_t *stream_id)
{
    st_nat_message open;
    if (expect_nat_frame(data_fd, ST_NAT_OPEN, &open) != 0) {
        return -1;
    }
    *stream_id = open.stream_id;
    st_nat_message_free(&open);
    return 0;
}

static int login_data(test_server *server, client_pair *pair)
{
    char reason[256];
    CHECK(channel_login(server->control_port, &pair->runtime, "data", &pair->data, reason, sizeof(reason)) == 1,
          "data login: %s", reason);
    /* A data connection that just closed releases its public ports as the last step of its teardown. */
    int registered = -1;
    for (int attempt = 0; registered != 0 && attempt < 20; ++attempt) {
        if (attempt > 0) {
            sleep_ms(100);
        }
        registered = nat_register(pair->data, pair->runtime.client_name, pair->public_port, 9);
    }
    CHECK(registered == 0, "REGISTER");
    return 0;
}

/* A logged-in client with one TCP mapping and one HTTP route, its port registered. */
static int pair_up(test_server *server, const char *tag, client_pair *pair)
{
    char api_key[64];
    char secret[64];
    char fingerprint[64];
    char reason[256];
    memset(pair, 0, sizeof(*pair));
    pair->control = -1;
    pair->data = -1;
    pair->public_port = pick_free_port();
    snprintf(api_key, sizeof(api_key), "ck_%s", tag);
    snprintf(secret, sizeof(secret), "%s-secret", tag);
    snprintf(fingerprint, sizeof(fingerprint), "machine-%s", tag);
    CHECK(create_credential(server->db_path, api_key, secret, 2) == 0, "credential");
    CHECK(http_client_login(server, api_key, secret, fingerprint, tag, &pair->runtime) == 0, "http login");
    CHECK(create_mapping(server->db_path, pair->runtime.client_id, pair->public_port) == 0, "mapping");
    st_storage_http_route route;
    CHECK(st_storage_create_http_route_for_client(server->db_path, pair->runtime.client_id, ROUTE,
                                                  "http://127.0.0.1:9", 1, 0, 0, 0, 0, 0, NULL, NULL,
                                                  &route) == 0,
          "HTTP route");
    CHECK(channel_login(server->control_port, &pair->runtime, "control", &pair->control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    return login_data(server, pair);
}

static void pair_close(client_pair *pair)
{
    close_fd(&pair->data);
    close_fd(&pair->control);
}

/* ------------------------------------------------------------------------------------------- */
/* Browser and public peer                                                                       */

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

/* Sends a Direct HTTP GET for the client's route and returns the browser socket. */
static int browser_get(const test_server *server, const client_pair *pair, const char *path)
{
    char client[768];
    char request[1536];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "GET /http/%s/%s%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                       client, ROUTE, path);
    int fd = connect_local(server->admin_port);
    if (fd >= 0 && (len <= 0 || (size_t)len >= sizeof(request)
                    || send_all(fd, (const uint8_t *)request, (size_t)len) != 0)) {
        close_fd(&fd);
    }
    return fd;
}

typedef struct {
    int fd;
    int timeout_ms;
    int status;
    int eof;
    size_t total;
    char head[4096];
    size_t head_len;
    char tail[8];
    size_t tail_len;
} browser_response;

/* Reads a browser response to EOF, keeping its first 4 KiB and its last bytes. */
static void read_browser_response(browser_response *response)
{
    long long deadline = monotonic_ms() + response->timeout_ms;
    char buffer[65536];
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready = {.fd = response->fd, .events = POLLIN, .revents = 0};
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) {
            break;
        }
        ssize_t received = recv(response->fd, buffer, sizeof(buffer), 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            response->eof = 1;
            break;
        }
        size_t length = (size_t)received;
        size_t head_room = sizeof(response->head) - 1U - response->head_len;
        size_t head_copy = length < head_room ? length : head_room;
        memcpy(response->head + response->head_len, buffer, head_copy);
        response->head_len += head_copy;
        response->head[response->head_len] = '\0';
        size_t keep = length < sizeof(response->tail) ? length : sizeof(response->tail);
        if (response->tail_len + keep > sizeof(response->tail)) {
            size_t drop = response->tail_len + keep - sizeof(response->tail);
            memmove(response->tail, response->tail + drop, response->tail_len - drop);
            response->tail_len -= drop;
        }
        memcpy(response->tail + response->tail_len, buffer + length - keep, keep);
        response->tail_len += keep;
        response->total += length;
    }
    if (sscanf(response->head, "HTTP/1.1 %d", &response->status) != 1) {
        response->status = 0;
    }
}

static void *read_browser_response_thread(void *arg)
{
    read_browser_response((browser_response *)arg);
    return NULL;
}

/* A chunked response the server finished: it ends with the last-chunk and an empty trailer. */
static int response_complete(const browser_response *response)
{
    return response->tail_len >= 5U
        && memcmp(response->tail + response->tail_len - 5U, "0\r\n\r\n", 5U) == 0;
}

static int expect_browser_status_within(int fd, int timeout_ms, int status, const char *body_text, int complete)
{
    browser_response response;
    memset(&response, 0, sizeof(response));
    response.fd = fd;
    response.timeout_ms = timeout_ms;
    read_browser_response(&response);
    if (!response.eof || response.status != status
        || (body_text != NULL && strstr(response.head, body_text) == NULL)
        || (complete >= 0 && response_complete(&response) != complete)) {
        fprintf(stderr, "browser response: eof=%d status=%d (expected %d) complete=%d (expected %d)\n%s\n",
                response.eof, response.status, status, response_complete(&response), complete, response.head);
        return -1;
    }
    return 0;
}

static int expect_browser_status(int fd, int status, const char *body_text, int complete)
{
    return expect_browser_status_within(fd, IO_TIMEOUT_MS, status, body_text, complete);
}

/* Reads and discards whatever a public peer still has buffered until the server closes it. */
static int drain_until_eof(int fd, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    uint8_t buffer[65536];
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) {
            return -1;
        }
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received == 0 || (received < 0 && (errno == ECONNRESET || errno == EPIPE))) {
            return 0;
        }
        if (received < 0) {
            return -1;
        }
    }
}

static int expect_public_bytes(int fd, const char *expected)
{
    size_t len = strlen(expected);
    char buffer[64];
    if (len >= sizeof(buffer) || recv_exact(fd, (uint8_t *)buffer, len, monotonic_ms() + IO_TIMEOUT_MS) != 1) {
        return -1;
    }
    return memcmp(buffer, expected, len) == 0 ? 0 : -1;
}

/* A public TCP stream relays client DATA to the public peer, proving the stream is served. */
static int expect_tcp_stream_served(client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "ping", 4U) == 0, "DATA");
    CHECK(expect_public_bytes(public_fd, "ping") == 0, "DATA not relayed to the public peer");
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 0U, NULL, NULL, 0U) == 0, "RST");
    CHECK(drain_until_eof(public_fd, IO_TIMEOUT_MS) == 0, "RST did not close the public peer");
    close_fd(&public_fd);
    return 0;
}

/* An HTTP request through the data connection gets a complete response, proving it is served. */
static int expect_http_stream_served(const test_server *server, client_pair *pair)
{
    uint32_t stream_id = 0U;
    int browser = browser_get(server, pair, "/served");
    CHECK(browser >= 0, "browser connect");
    CHECK(expect_http_open(pair->data, &stream_id) == 0, "no HTTP OPEN: the data connection is not routed");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0, "head");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "served", 6U) == 0, "DATA");
    CHECK(send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0, "FIN");
    CHECK(expect_browser_status(browser, 200, "served", 1) == 0, "served response");
    close_fd(&browser);
    return 0;
}

/* Both kinds of stream still work on the data connection after a check reset one of them. */
static int expect_data_connection_served(const test_server *server, client_pair *pair)
{
    CHECK(expect_http_stream_served(server, pair) == 0,
          "HTTP after the stream reset: the data connection was taken out of routing");
    CHECK(expect_tcp_stream_served(pair) == 0, "TCP after the stream reset");
    return 0;
}

static int open_http_stream(const test_server *server, client_pair *pair, const char *path,
                            int *browser, uint32_t *stream_id)
{
    *browser = browser_get(server, pair, path);
    CHECK(*browser >= 0, "browser connect");
    CHECK(expect_http_open(pair->data, stream_id) == 0, "no request OPEN for %s", path);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* HTTP stream checks                                                                            */

/* DATA before the response head resets that stream with RST 8 (Java and Go), nothing else. */
static int check_http_data_before_head(test_server *server, client_pair *pair)
{
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/data-before-head", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "x", 1U) == 0, "DATA before head");
    CHECK(expect_rst(pair->data, stream_id, 8U) == 0, "DATA before the response head must reset the stream");
    CHECK(expect_browser_status(browser, 502, NULL, -1) == 0, "browser of the reset stream");
    close_fd(&browser);
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 8U, NULL, NULL, 0U) == 0, "late RST");
    CHECK(expect_alive_without_rst(pair->data, stream_id) == 0, "a late RST of a closed stream must be ignored");
    return expect_data_connection_served(server, pair);
}

/* A second response head resets that stream with RST 8; the browser sees the response cut short. */
static int check_http_second_head(test_server *server, client_pair *pair)
{
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/two-heads", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0
              && send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0,
          "two heads");
    CHECK(expect_rst(pair->data, stream_id, 8U) == 0, "a second response head must reset the stream");
    CHECK(expect_browser_status(browser, 200, NULL, 0) == 0, "the browser must see the response cut short");
    close_fd(&browser);
    return expect_data_connection_served(server, pair);
}

/*
 * DATA|END_STREAM is that DATA followed by a FIN: the browser gets the payload and the end of the
 * response, and a FIN after it is a duplicate that resets the stream.
 */
static int check_http_end_stream(test_server *server, client_pair *pair)
{
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/end-stream", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0, "head");
    CHECK(send_nat(pair->data, ST_NAT_DATA, ST_NAT_FLAG_END_STREAM, stream_id, 0U, NULL, "hello", 5U) == 0,
          "DATA|END_STREAM");
    CHECK(expect_browser_status(browser, 200, "\r\n5\r\nhello\r\n0\r\n\r\n", 1) == 0,
          "DATA|END_STREAM must deliver the payload and then end the response");
    close_fd(&browser);

    CHECK(open_http_stream(server, pair, "/fin-after-end-stream", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0
              && send_nat(pair->data, ST_NAT_DATA, ST_NAT_FLAG_END_STREAM, stream_id, 0U, NULL, "bye", 3U) == 0
              && send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0,
          "head, DATA|END_STREAM, FIN");
    /* RST 8 while the stream is still pending, RST 7 once it already finished: a reset either way. */
    uint32_t code = 0U;
    CHECK(wait_rst(pair->data, stream_id, &code) == 0 && (code == 8U || code == 7U),
          "a FIN after DATA|END_STREAM must reset the stream as a duplicate FIN (code %u)", code);
    CHECK(expect_browser_status(browser, 200, "\r\n3\r\nbye\r\n0\r\n\r\n", 1) == 0,
          "the response ended by DATA|END_STREAM");
    close_fd(&browser);
    return expect_data_connection_served(server, pair);
}

/* A response head without the optional trailerNames is a valid head, as Java reads it. */
static int check_http_head_without_trailer_names(test_server *server, client_pair *pair)
{
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/no-trailer-names", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD_WITHOUT_TRAILER_NAMES, NULL, 0U) == 0
              && send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "plain", 5U) == 0
              && send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0,
          "response");
    CHECK(expect_browser_status(browser, 200, "\r\n5\r\nplain\r\n0\r\n\r\n", 1) == 0,
          "a response head without trailerNames must be relayed");
    close_fd(&browser);
    return 0;
}

/* A response beyond 64 MiB resets that stream with RST 4 (Go); the data connection is unharmed. */
static int check_http_response_limit(test_server *server, client_pair *pair)
{
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/large", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0, "head");

    browser_response response;
    memset(&response, 0, sizeof(response));
    response.fd = browser;
    response.timeout_ms = 120000;
    pthread_t reader;
    CHECK(pthread_create(&reader, NULL, read_browser_response_thread, &response) == 0, "browser reader");

    uint8_t *chunk = (uint8_t *)calloc(1U, DATA_CHUNK);
    uint64_t credit = INITIAL_WINDOW;
    uint64_t sent = 0U;
    int failed = chunk == NULL;
    while (!failed && sent <= RESPONSE_LIMIT) {
        /* The full 64 MiB within the window, then one byte more: only that byte is over the limit. */
        size_t length = sent < RESPONSE_LIMIT ? DATA_CHUNK : 1U;
        long long deadline = monotonic_ms() + 20000;
        while (!failed && credit < length) {
            st_nat_message message;
            if (next_nat_frame(pair->data, deadline, &message) != 1) {
                fprintf(stderr, "no WINDOW_UPDATE after %llu bytes\n", (unsigned long long)sent);
                failed = 1;
                break;
            }
            if (message.stream_id == stream_id && message.type == ST_NAT_WINDOW_UPDATE) {
                credit += message.value;
            } else if (message.stream_id == stream_id && message.type == ST_NAT_RST) {
                fprintf(stderr, "stream reset with %u after %llu bytes\n", message.value, (unsigned long long)sent);
                failed = 1;
            }
            st_nat_message_free(&message);
        }
        if (!failed && send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, chunk, length) != 0) {
            failed = 1;
        }
        credit -= length;
        sent += length;
    }
    free(chunk);
    int reset_rc = failed ? -1 : expect_rst(pair->data, stream_id, 4U);
    if (failed) {
        shutdown(browser, SHUT_RDWR);
    }
    pthread_join(reader, NULL);
    close_fd(&browser);
    CHECK(!failed, "the first 64 MiB must be accepted");
    CHECK(reset_rc == 0, "a response beyond 64 MiB must reset the stream with RST 4");
    /* All 64 MiB reach the browser (plus headers and chunk framing), the extra byte never does. */
    CHECK(response.eof && response.status == 200 && !response_complete(&response)
              && response.total > (size_t)RESPONSE_LIMIT && response.total < (size_t)RESPONSE_LIMIT + DATA_CHUNK,
          "the browser must get the 64 MiB and then see the response cut short (eof=%d status=%d total=%zu)",
          response.eof, response.status, response.total);
    return expect_data_connection_served(server, pair);
}

/* ------------------------------------------------------------------------------------------- */
/* TCP stream checks                                                                             */

/* DATA after the client's FIN is a stream-state violation: RST 7, as Java and Go (was RST 6). */
static int check_tcp_data_after_fin(test_server *server, client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0, "client FIN");
    CHECK(expect_socket_eof(public_fd, IO_TIMEOUT_MS) == 0, "the client FIN must half-close the public peer");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "late", 4U) == 0, "DATA after FIN");
    CHECK(expect_rst(pair->data, stream_id, 7U) == 0, "DATA after FIN must reset the stream with RST 7");
    close_fd(&public_fd);
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 7U, NULL, NULL, 0U) == 0, "late RST");
    CHECK(expect_alive_without_rst(pair->data, stream_id) == 0, "a late RST of a closed stream must be ignored");
    return expect_data_connection_served(server, pair);
}

/* An empty DATA|END_STREAM is a bare FIN, so a FIN after it is a duplicate: RST 7. */
static int check_tcp_end_stream_and_duplicate_fin(test_server *server, client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(send_nat(pair->data, ST_NAT_DATA, ST_NAT_FLAG_END_STREAM, stream_id, 0U, NULL, NULL, 0U) == 0,
          "bare END_STREAM");
    CHECK(expect_socket_eof(public_fd, IO_TIMEOUT_MS) == 0, "an empty DATA|END_STREAM must half-close the public peer");
    CHECK(send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0, "FIN");
    CHECK(expect_rst(pair->data, stream_id, 7U) == 0, "a second FIN must reset the stream with RST 7");
    close_fd(&public_fd);
    return expect_data_connection_served(server, pair);
}

/* A client OPEN for a TCP stream resets it with RST 8 (Java and Go) and closes its public peer. */
static int check_tcp_client_open(test_server *server, client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0, "client OPEN");
    CHECK(expect_rst(pair->data, stream_id, 8U) == 0, "a client OPEN for a TCP stream must reset it with RST 8");
    CHECK(drain_until_eof(public_fd, IO_TIMEOUT_MS) == 0, "the reset stream's public peer must be closed");
    close_fd(&public_fd);
    return expect_data_connection_served(server, pair);
}

/*
 * DATA and FIN for streams that do not exist get RST 7 and the id is tombstoned, so the client's
 * crossing RST is ignored; credit for an unknown stream is ignored as well.
 */
static int check_unknown_streams(test_server *server, client_pair *pair)
{
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, UNKNOWN_STREAM_BASE + 1U, 0U, NULL, "?", 1U) == 0, "DATA");
    CHECK(expect_rst(pair->data, UNKNOWN_STREAM_BASE + 1U, 7U) == 0, "DATA for an unknown stream must get RST 7");
    CHECK(send_nat(pair->data, ST_NAT_FIN, 0U, UNKNOWN_STREAM_BASE + 2U, 0U, NULL, NULL, 0U) == 0, "FIN");
    CHECK(expect_rst(pair->data, UNKNOWN_STREAM_BASE + 2U, 7U) == 0, "FIN for an unknown stream must get RST 7");
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, UNKNOWN_STREAM_BASE + 1U, 7U, NULL, NULL, 0U) == 0, "crossing RST");
    CHECK(expect_alive_without_rst(pair->data, UNKNOWN_STREAM_BASE + 1U) == 0,
          "an RST for a stream the server just reset must be ignored");
    CHECK(send_nat(pair->data, ST_NAT_WINDOW_UPDATE, 0U, UNKNOWN_STREAM_BASE + 3U, MAX_WINDOW, NULL, NULL, 0U) == 0,
          "WINDOW_UPDATE");
    CHECK(expect_alive_without_rst(pair->data, UNKNOWN_STREAM_BASE + 3U) == 0,
          "credit for an unknown stream must be ignored");
    return expect_data_connection_served(server, pair);
}

/* An RST for a stream that was never opened is a data-connection protocol violation. */
static int check_rst_for_never_opened_stream(test_server *server, client_pair *pair)
{
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, UNKNOWN_STREAM_BASE + 9U, 8U, NULL, NULL, 0U) == 0, "RST");
    CHECK(expect_channel_closed(pair->data, IO_TIMEOUT_MS) == 0,
          "an RST for a never-opened stream must close the data connection");
    close_fd(&pair->data);
    CHECK(expect_channel_alive(pair->control) == 0, "the control connection must stay");
    CHECK(login_data(server, pair) == 0, "data re-login");
    return expect_data_connection_served(server, pair);
}

/*
 * Credit up to the 16 MiB window is accepted; a WINDOW_UPDATE beyond it closes the data connection
 * and its streams, as Java StreamFlowController and Go do (it used to only stop routing to it).
 */
static int check_window_overflow(test_server *server, client_pair *pair)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(send_nat(pair->data, ST_NAT_WINDOW_UPDATE, 0U, stream_id, MAX_WINDOW - INITIAL_WINDOW, NULL, NULL, 0U) == 0,
          "credit up to the window");
    CHECK(expect_alive_without_rst(pair->data, stream_id) == 0, "credit within the window must be accepted");
    CHECK(send_nat(pair->data, ST_NAT_WINDOW_UPDATE, 0U, stream_id, 1U, NULL, NULL, 0U) == 0, "overflowing credit");
    CHECK(expect_channel_closed(pair->data, IO_TIMEOUT_MS) == 0,
          "a WINDOW_UPDATE beyond the 16 MiB window must close the data connection");
    CHECK(drain_until_eof(public_fd, IO_TIMEOUT_MS) == 0, "the data connection's streams must be closed");
    close_fd(&public_fd);
    close_fd(&pair->data);
    CHECK(expect_channel_alive(pair->control) == 0, "the control connection must stay");
    CHECK(login_data(server, pair) == 0, "data re-login");
    return expect_data_connection_served(server, pair);
}

/* HEARTBEAT_RESPONSE is a heartbeat and allowed on both roles; it needs no answer. */
static int check_heartbeat_response(test_server *server, client_pair *pair)
{
    st_buffer response = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    CHECK(send_buffer(pair->control, &response) == 0, "control HEARTBEAT_RESPONSE");
    response = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    CHECK(send_buffer(pair->data, &response) == 0, "data HEARTBEAT_RESPONSE");
    CHECK(expect_channel_alive(pair->control) == 0, "HEARTBEAT_RESPONSE closed the control connection");
    CHECK(expect_channel_alive(pair->data) == 0, "HEARTBEAT_RESPONSE closed the data connection");
    return expect_data_connection_served(server, pair);
}

/*
 * More client data than the 4 MiB client-to-public queue holds resets that stream with RST 6
 * ("stream send queue exceeded", as Java StreamFlowController); the data connection carries on.
 */
static int check_tcp_queue_overflow(test_server *server, client_pair *pair)
{
    /* The public peer never reads and keeps a small receive buffer, so what the socket buffers
     * cannot take piles up in the server's queue for the stream. */
    int public_fd = socket(AF_INET, SOCK_STREAM, 0);
    int small = 4096;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)pair->public_port);
    CHECK(public_fd >= 0 && setsockopt(public_fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0
              && connect(public_fd, (struct sockaddr *)&address, sizeof(address)) == 0,
          "public peer");
    st_nat_message open;
    CHECK(expect_nat_frame(pair->data, ST_NAT_OPEN, &open) == 0, "public OPEN");
    uint32_t stream_id = open.stream_id;
    st_nat_message_free(&open);

    uint8_t *chunk = (uint8_t *)calloc(1U, DATA_CHUNK);
    int sent_ok = chunk != NULL;
    for (size_t sent = 0U; sent_ok && sent < QUEUE_FLOOD; sent += DATA_CHUNK) {
        sent_ok = send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, chunk, DATA_CHUNK) == 0;
    }
    free(chunk);
    CHECK(sent_ok, "flooding the stream");
    CHECK(expect_rst(pair->data, stream_id, 6U) == 0, "a full client-to-public queue must reset the stream with RST 6");
    CHECK(drain_until_eof(public_fd, 30000) == 0, "the reset stream's public peer must be closed");
    close_fd(&public_fd);
    return expect_data_connection_served(server, pair);
}

/*
 * A data connection holds at most 1024 pending HTTP streams; the next request is refused with
 * 502 "HTTP 流创建失败" (Java HttpSpecusController) instead of a response timeout, and the pending
 * streams and later requests are unaffected.
 */
static int check_pending_stream_limit(test_server *server, client_pair *pair)
{
    int *browsers = (int *)malloc(PENDING_STREAM_LIMIT * sizeof(int));
    uint32_t *streams = (uint32_t *)malloc(PENDING_STREAM_LIMIT * sizeof(uint32_t));
    int failed = browsers == NULL || streams == NULL;
    for (size_t i = 0U; !failed && i < PENDING_STREAM_LIMIT; ++i) {
        browsers[i] = -1;
    }
    long long started = monotonic_ms();
    for (size_t i = 0U; !failed && i < PENDING_STREAM_LIMIT; ++i) {
        /* Answered with a head and left open: a pending stream without a header timeout. */
        failed = open_http_stream(server, pair, "/pending", &browsers[i], &streams[i]) != 0
            || send_nat(pair->data, ST_NAT_OPEN, 0U, streams[i], 0U, RESPONSE_HEAD, NULL, 0U) != 0;
        if (failed) {
            fprintf(stderr, "pending stream %zu could not be opened\n", i);
        }
    }
    if (!failed) {
        printf("     %u pending streams opened in %lld ms\n", PENDING_STREAM_LIMIT, monotonic_ms() - started);
        int refused = browser_get(server, pair, "/one-too-many");
        failed = refused < 0 || expect_browser_status(refused, 502, "HTTP 流创建失败", -1) != 0;
        if (failed) {
            fprintf(stderr, "the request beyond %u pending streams was not refused with 502\n",
                    PENDING_STREAM_LIMIT);
        }
        close_fd(&refused);
    }
    for (size_t i = 0U; !failed && i < PENDING_STREAM_LIMIT; ++i) {
        failed = send_nat(pair->data, ST_NAT_FIN, 0U, streams[i], 0U, NULL, NULL, 0U) != 0;
    }
    for (size_t i = 0U; !failed && i < PENDING_STREAM_LIMIT; ++i) {
        /* Every finished request writes its traffic records at once, so closing can take a while. */
        failed = expect_browser_status_within(browsers[i], 60000, 200, NULL, 1) != 0;
        if (failed) {
            fprintf(stderr, "pending stream %zu did not complete\n", i);
        }
    }
    for (size_t i = 0U; browsers != NULL && i < PENDING_STREAM_LIMIT; ++i) {
        close_fd(&browsers[i]);
    }
    free(browsers);
    free(streams);
    CHECK(!failed, "1024 pending streams");
    return expect_data_connection_served(server, pair);
}

/* ------------------------------------------------------------------------------------------- */
/* Request body limit (no client needed)                                                         */

/* Sends a Direct HTTP POST with a body of the given size, by Content-Length or chunked. */
static int send_direct_post(const test_server *server, const char *headers, size_t body_len, int chunked,
                            int over_limit)
{
    int fd = connect_local(server->admin_port);
    if (fd < 0) {
        return -1;
    }
    char head[512];
    int head_len = snprintf(head, sizeof(head),
                            "POST /http/offline-client/%s/upload HTTP/1.1\r\nHost: 127.0.0.1\r\n%s"
                            "Connection: close\r\n\r\n",
                            ROUTE, headers);
    int rc = head_len > 0 && (size_t)head_len < sizeof(head)
        ? send_all(fd, (const uint8_t *)head, (size_t)head_len) : -1;
    uint8_t *block = (uint8_t *)calloc(1U, 1024U * 1024U);
    rc = rc == 0 && block != NULL ? 0 : -1;
    for (size_t sent = 0U; rc == 0 && sent < body_len; sent += 1024U * 1024U) {
        size_t length = body_len - sent < 1024U * 1024U ? body_len - sent : 1024U * 1024U;
        char size_line[32];
        int size_len = snprintf(size_line, sizeof(size_line), "%zx\r\n", length);
        rc = (chunked && send_all(fd, (const uint8_t *)size_line, (size_t)size_len) != 0)
            || send_all(fd, block, length) != 0
            || (chunked && send_all(fd, (const uint8_t *)"\r\n", 2U) != 0) ? -1 : 0;
    }
    free(block);
    if (rc == 0 && chunked) {
        /* One byte more announces the excess; the terminating chunk ends a body within the limit. */
        const char *last = over_limit ? "1\r\n" : "0\r\n\r\n";
        rc = send_all(fd, (const uint8_t *)last, strlen(last));
    }
    if (rc != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * Request bodies over 16 MiB get 413 "HTTP 请求体超过限制" before anything is forwarded, by
 * Content-Length (Java HttpSpecusBodyLimitFilter) and by chunked length (HttpSpecusController);
 * exactly 16 MiB is read and forwarded.
 */
static int test_request_body_limit(test_server *server)
{
    char headers[128];
    snprintf(headers, sizeof(headers), "Content-Length: %u\r\n", REQUEST_BODY_LIMIT + 1U);
    int fd = send_direct_post(server, headers, 0U, 0, 1);
    CHECK(fd >= 0, "oversized Content-Length request");
    CHECK(expect_browser_status(fd, 413, "HTTP 请求体超过限制", -1) == 0, "Content-Length over 16 MiB");
    close_fd(&fd);

    fd = send_direct_post(server, "Transfer-Encoding: chunked\r\n", REQUEST_BODY_LIMIT, 1, 1);
    CHECK(fd >= 0, "oversized chunked request");
    CHECK(expect_browser_status(fd, 413, "HTTP 请求体超过限制", -1) == 0, "chunked body over 16 MiB");
    close_fd(&fd);

    /* At the limit the body is read and forwarded; the client is offline, hence 502, not 413. */
    snprintf(headers, sizeof(headers), "Content-Length: %u\r\n", REQUEST_BODY_LIMIT);
    fd = send_direct_post(server, headers, REQUEST_BODY_LIMIT, 0, 0);
    CHECK(fd >= 0, "Content-Length request at the limit");
    CHECK(expect_browser_status(fd, 502, NULL, -1) == 0, "Content-Length of exactly 16 MiB");
    close_fd(&fd);
    fd = send_direct_post(server, "Transfer-Encoding: chunked\r\n", REQUEST_BODY_LIMIT, 1, 0);
    CHECK(fd >= 0, "chunked request at the limit");
    CHECK(expect_browser_status(fd, 502, NULL, -1) == 0, "chunked body of exactly 16 MiB");
    close_fd(&fd);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */

static int test_tombstones(void)
{
    st_stream_tombstones *tombstones = (st_stream_tombstones *)calloc(1U, sizeof(*tombstones));
    CHECK(tombstones != NULL, "allocation");
    for (uint32_t id = 1U; id <= ST_STREAM_TOMBSTONE_LIMIT; ++id) {
        st_stream_tombstones_add(tombstones, id);
    }
    CHECK(st_stream_tombstones_contains(tombstones, 1U)
              && st_stream_tombstones_contains(tombstones, ST_STREAM_TOMBSTONE_LIMIT),
          "every id up to the limit is kept");
    st_stream_tombstones_add(tombstones, 1U);
    st_stream_tombstones_add(tombstones, ST_STREAM_TOMBSTONE_LIMIT + 1U);
    CHECK(st_stream_tombstones_contains(tombstones, 1U) && !st_stream_tombstones_contains(tombstones, 2U)
              && st_stream_tombstones_contains(tombstones, ST_STREAM_TOMBSTONE_LIMIT + 1U),
          "re-adding refreshes an id and the oldest one is evicted");
    st_stream_tombstones_remove(tombstones, 500U);
    CHECK(!st_stream_tombstones_contains(tombstones, 500U) && st_stream_tombstones_contains(tombstones, 501U)
              && st_stream_tombstones_contains(tombstones, 499U),
          "remove forgets exactly one id");
    st_stream_tombstones_add(tombstones, 2U);
    CHECK(st_stream_tombstones_contains(tombstones, 2U) && st_stream_tombstones_contains(tombstones, 3U),
          "the slot a removal freed is reused without an eviction");
    st_stream_tombstones_add(tombstones, ST_STREAM_TOMBSTONE_LIMIT + 2U);
    CHECK(!st_stream_tombstones_contains(tombstones, 3U) && st_stream_tombstones_contains(tombstones, 4U)
              && st_stream_tombstones_contains(tombstones, 1U) && st_stream_tombstones_contains(tombstones, 2U),
          "eviction resumes with the oldest id once the history is full again");
    free(tombstones);
    printf("ok   stream tombstones\n");
    return 0;
}

/* The pending-stream check needs more descriptors than the usual soft limit of 1024. */
static int raise_descriptor_limit(rlim_t wanted)
{
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) != 0) {
        return -1;
    }
    if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < wanted) {
        limit.rlim_cur = limit.rlim_max == RLIM_INFINITY || limit.rlim_max >= wanted ? wanted : limit.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &limit) != 0) {
            return -1;
        }
    }
    return limit.rlim_cur == RLIM_INFINITY || limit.rlim_cur >= wanted ? 0 : -1;
}

typedef int (*pair_check)(test_server *server, client_pair *pair);

static pair_check current_check = NULL;

static int run_current_check(test_server *server)
{
    client_pair pair;
    int rc = pair_up(server, "nat", &pair) != 0 || current_check(server, &pair) != 0;
    pair_close(&pair);
    return rc;
}

/*
 * Every check runs on its own server and client. The checks leave the control connection silent
 * for longer than the default read-idle timeout, after which the server would close it and its
 * data connection with it.
 */
static const char *const long_idle[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=900", NULL};

static int run_check(const char *name, pair_check check)
{
    current_check = check;
    return run_on_fresh_server(name, run_current_check, long_idle);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    int failures = test_tombstones();
    failures += run_check("HTTP DATA before the response head resets only that stream", check_http_data_before_head);
    failures += run_check("HTTP second response head resets only that stream", check_http_second_head);
    failures += run_check("HTTP DATA|END_STREAM is DATA then FIN", check_http_end_stream);
    failures += run_check("HTTP response head without trailerNames", check_http_head_without_trailer_names);
    failures += run_check("HTTP response beyond 64 MiB resets only that stream", check_http_response_limit);
    failures += run_check("TCP DATA after FIN gets RST 7", check_tcp_data_after_fin);
    failures += run_check("TCP empty DATA|END_STREAM is a FIN; a second FIN gets RST 7",
                          check_tcp_end_stream_and_duplicate_fin);
    failures += run_check("TCP client OPEN gets RST 8", check_tcp_client_open);
    failures += run_check("unknown streams get RST 7 and are tombstoned", check_unknown_streams);
    failures += run_check("RST for a never-opened stream closes the data connection",
                          check_rst_for_never_opened_stream);
    failures += run_check("WINDOW_UPDATE overflow closes the data connection", check_window_overflow);
    failures += run_check("HEARTBEAT_RESPONSE is accepted on both roles", check_heartbeat_response);
    failures += run_check("4 MiB client-to-public queue overflow resets only that stream", check_tcp_queue_overflow);
    failures += run_on_fresh_server("413 for request bodies over 16 MiB", test_request_body_limit, long_idle);
    if (raise_descriptor_limit(4096) == 0) {
        failures += run_check("1025th pending HTTP stream gets 502", check_pending_stream_limit);
    } else {
        fprintf(stderr, "cannot raise the descriptor limit to 4096 for the pending-stream check\n");
        failures += 1;
    }
    if (failures != 0) {
        fprintf(stderr, "%d NAT stream check(s) failed\n", failures);
        return 1;
    }
    printf("NAT stream tests passed\n");
    return 0;
}

