/*
 * The public listener's connection handling against a real specus-server-c process, as the Java
 * server's Tomcat connector does it with Spring Boot's defaults, and the answers Java
 * HttpSpecusController gives when a route request fails (issue #35 item 45):
 *
 *   - server.tomcat.connection-timeout bounds every blocking read and write of a request and its
 *     answer: an idle connection and a stalled request head are dropped without a word, a stalled
 *     body is answered, and a caller that stops reading a streamed response has its NAT stream reset
 *     with RST 8 and the exchange recorded as Java records a client abort; an upgraded WebSocket is
 *     not subject to it;
 *   - server.tomcat.max-connections: once that many sockets are open, further connections wait in
 *     the backlog until one closes;
 *   - "Expect: 100-continue" on an HTTP/1.1 request gets Tomcat's interim 100 before the body;
 *   - a response head that does not come answers 504 "TimeoutException" with RST 8, and a stream this
 *     server resets or loses with its data connection answers 502 "HTTP 转发请求失败", not the
 *     "客户端不在线" of a client that was never there.
 *
 * It reuses the client, browser and detail helpers of nat_stream_tests.
 *
 * Usage: specus_c_http_connector_tests <path-to-specus-server-c>
 */
#define main st_prior_nat_stream_test_entry
#include "nat_stream_tests.c"
#undef main
#include "admin_http.h"
#include "http_share.h"

/* ------------------------------------------------------------------------------------------- */
/* Helpers                                                                                       */

/*
 * Milliseconds until the server ends the connection (EOF or reset), counting what arrived before in
 * *bytes; -1 when it is still open after timeout_ms.
 */
static long long ended_after(int fd, int timeout_ms, size_t *bytes)
{
    long long started = monotonic_ms();
    long long deadline = started + timeout_ms;
    *bytes = 0U;
    char buffer[4096];
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
        if (remaining <= 0) {
            return -1;
        }
        int polled = poll(&ready, 1, (int)remaining);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled <= 0) {
            return -1;
        }
        ssize_t received = recv(fd, buffer, sizeof(buffer), 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            return monotonic_ms() - started;
        }
        *bytes += (size_t)received;
    }
}

/* Nothing arrives on fd within ms. */
static int silent_for(int fd, int ms)
{
    struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
    return poll(&ready, 1, ms) == 0;
}

/* A heartbeat barrier on the data connection: no stream was opened before it was answered. */
static int expect_no_stream_opened(int data_fd)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    CHECK(send_buffer(data_fd, &heartbeat) == 0, "heartbeat");
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        CHECK(remaining > 0, "no heartbeat answer");
        st_frame_header header;
        uint8_t *body = NULL;
        CHECK(read_frame(data_fd, (int)remaining, &header, &body) == 1, "data connection closed or silent");
        int opened = 0;
        if (header.command == ST_CMD_NAT_MESSAGE) {
            st_nat_message message;
            if (st_protocol_decode_nat_message(body, header.length, &message) == 0) {
                opened = message.type == ST_NAT_OPEN;
                st_nat_message_free(&message);
            }
        }
        free(body);
        CHECK(!opened, "a stream was opened for the request");
        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) {
            return 0;
        }
    }
}

/* Turns on detail capture for the pair's route (the server switch comes from the environment). */
static int enable_route_capture(const test_server *server, const client_pair *pair)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    int ok = sqlite3_open(server->db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "UPDATE http_route_mapping SET detail_capture_enabled=1 WHERE client_name=? AND route=?",
                              -1, &statement, NULL) == SQLITE_OK
        && sqlite3_bind_text(statement, 1, pair->runtime.client_name, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_bind_text(statement, 2, ROUTE, -1, SQLITE_STATIC) == SQLITE_OK
        && sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return ok ? 0 : -1;
}

/* The newest exchange recorded for relative_path: field equals expected ('~': contains it). */
static int exchange_of(const test_server *server, const char *relative_path, const char *field, const char *expected)
{
    char sql[256];
    char value[2048] = "";
    snprintf(sql, sizeof(sql),
             "SELECT COALESCE(%s, '') FROM specus_http_traffic_exchange WHERE relative_path = ? ORDER BY id DESC LIMIT 1",
             field);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (db_scalar(server->db_path, sql, relative_path, 0, value, sizeof(value)) != 0) {
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "no exchange recorded for %s\n", relative_path);
            return -1;
        }
        sleep_ms(50);
    }
    int contains_only = expected[0] == '~';
    int matches = contains_only ? strstr(value, expected + 1) != NULL : strcmp(value, expected) == 0;
    if (!matches) {
        fprintf(stderr, "%s: %s is \"%s\", expected %s\"%s\"\n", relative_path, field, value,
                contains_only ? "it to contain " : "", expected + contains_only);
    }
    return matches ? 0 : -1;
}

/* A browser that receives into a 4 KiB buffer and never reads, asking for path on the pair's route. */
static int stalled_browser(const test_server *server, const client_pair *pair, const char *path)
{
    char client[768];
    char request[1024];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "GET /http/%s/%s%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                       client, ROUTE, path);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int small = 4096;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)server->admin_port);
    if (fd >= 0 && (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) != 0
                    || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0
                    || send_all(fd, (const uint8_t *)request, (size_t)len) != 0)) {
        close_fd(&fd);
    }
    return fd;
}

static char *management_token(const test_server *server)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    int status = 0;
    char *response = NULL;
    char *token = NULL;
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) == 0 && status == 200) {
        token = st_json_get_string(response, "accessToken");
    }
    free(response);
    return token;
}

/* One masked client frame with a payload of at most 125 bytes. */
static int ws_send_small(int fd, uint8_t opcode, const char *payload, size_t len)
{
    uint8_t frame[2 + 4 + 125];
    static const uint8_t mask[4] = {0x11U, 0x22U, 0x33U, 0x44U};
    if (len > 125U) {
        return -1;
    }
    frame[0] = (uint8_t)(0x80U | opcode);
    frame[1] = (uint8_t)(0x80U | len);
    memcpy(frame + 2, mask, sizeof(mask));
    for (size_t i = 0U; i < len; ++i) {
        frame[6 + i] = (uint8_t)payload[i] ^ mask[i % 4U];
    }
    return send_all(fd, frame, 6U + len);
}

/* Reads server frames until one of the given opcode comes; 0 when it did within timeout_ms. */
static int ws_expect_opcode(int fd, uint8_t wanted, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        uint8_t header[2];
        if (recv_exact(fd, header, sizeof(header), deadline) != 1) {
            return -1;
        }
        uint64_t len = header[1] & 0x7fU;
        if (len == 126U || len == 127U) {
            uint8_t extended[8];
            size_t extended_len = len == 126U ? 2U : 8U;
            if (recv_exact(fd, extended, extended_len, deadline) != 1) {
                return -1;
            }
            len = 0U;
            for (size_t i = 0U; i < extended_len; ++i) {
                len = (len << 8U) | extended[i];
            }
        }
        uint8_t skip[512];
        while (len > 0U) {
            size_t part = len < sizeof(skip) ? (size_t)len : sizeof(skip);
            if (recv_exact(fd, skip, part, deadline) != 1) {
                return -1;
            }
            len -= part;
        }
        if ((header[0] & 0x0fU) == wanted) {
            return 0;
        }
    }
}

/* ------------------------------------------------------------------------------------------- */
/* server.tomcat.connection-timeout                                                              */

/*
 * With the connection timeout at 1 s, an idle connection and a request head that stops are dropped
 * without an answer, as Tomcat drops them. The old listener set no timeout: both waited for good,
 * each holding a thread.
 */
static int test_idle_and_stalled_head(test_server *server)
{
    size_t bytes = 0U;
    int idle = connect_local(server->admin_port);
    CHECK(idle >= 0, "idle connection");
    long long ended = ended_after(idle, 8000, &bytes);
    close_fd(&idle);
    CHECK(ended >= 700 && ended <= 5000 && bytes == 0U,
          "an idle connection must be dropped silently after the 1 s timeout (after %lld ms, %zu bytes)", ended, bytes);

    static const char partial_head[] = "GET /api/admin/clients HTTP/1.1\r\nHost: 127.0.0.1\r\n";
    int head = browser_raw(server, partial_head, sizeof(partial_head) - 1U);
    CHECK(head >= 0, "partial head");
    ended = ended_after(head, 8000, &bytes);
    close_fd(&head);
    CHECK(ended >= 700 && ended <= 5000 && bytes == 0U,
          "a stalled request head must be dropped silently after the 1 s timeout (after %lld ms, %zu bytes)", ended,
          bytes);
    return 0;
}

/*
 * A route request body that stops is answered once the 1 s timeout ran out, and no NAT stream was
 * opened for it: the C server reads the body before it opens the stream (see the API inventory).
 * The old listener waited for the rest of the body for good.
 */
static int check_stalled_body(test_server *server, client_pair *pair)
{
    char client[768];
    char request[1536];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "POST /http/%s/%s/partial HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 100\r\n"
                       "Connection: close\r\n\r\n0123456789",
                       client, ROUTE);
    long long started = monotonic_ms();
    int body = browser_raw(server, request, (size_t)len);
    CHECK(body >= 0, "partial body");
    CHECK(expect_browser_status_within(body, 8000, 400, "HTTP 请求体不完整", -1) == 0, "a stalled request body");
    long long answered = monotonic_ms() - started;
    close_fd(&body);
    CHECK(answered >= 700 && answered <= 5000, "a stalled body must be answered after the 1 s timeout (%lld ms)",
          answered);
    CHECK(expect_no_stream_opened(pair->data) == 0, "the stalled body must not have opened a stream");
    return expect_data_connection_served(server, pair);
}

/*
 * A browser that stops reading a streamed response: once the server's write made no progress for the
 * 1 s timeout, the stream is reset with RST 8 and the exchange is recorded with the client's status
 * and no failure, as Java records a client abort (Tomcat's ClientAbortException on the write). The
 * old listener's write waited for good, holding the thread, the device's upstream request and one of
 * the data connection's 1024 pending streams.
 */
static int check_stalled_reader(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    /* The device keeps streaming while the server grants credit. */
    int browser = stalled_browser(server, pair, "/stalled-reader");
    CHECK(browser >= 0, "stalled browser");
    uint32_t stream_id = 0U;
    CHECK(expect_http_open(pair->data, &stream_id) == 0, "no request OPEN");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0, "head");
    uint8_t *chunk = (uint8_t *)calloc(1U, DATA_CHUNK);
    CHECK(chunk != NULL, "chunk");
    uint64_t credit = INITIAL_WINDOW;
    uint64_t sent = 0U;
    long long last_credit = monotonic_ms();
    long long give_up = last_credit + 20000;
    int reset = 0;
    uint32_t code = 0U;
    int failed = 0;
    while (!reset && !failed && monotonic_ms() < give_up) {
        while (!failed && credit >= DATA_CHUNK && sent < 48U * 1024U * 1024U) {
            failed = send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, chunk, DATA_CHUNK) != 0;
            credit -= DATA_CHUNK;
            sent += DATA_CHUNK;
        }
        st_nat_message message;
        int rc = next_nat_frame(pair->data, monotonic_ms() + 200, &message);
        if (rc == 0) {
            failed = 1;
        } else if (rc == 1) {
            if (message.stream_id == stream_id && message.type == ST_NAT_WINDOW_UPDATE) {
                credit += message.value;
                last_credit = monotonic_ms();
            } else if (message.stream_id == stream_id && message.type == ST_NAT_RST) {
                reset = 1;
                code = message.value;
            }
            st_nat_message_free(&message);
        }
    }
    long long stalled_for = monotonic_ms() - last_credit;
    free(chunk);
    close_fd(&browser);
    printf("     the reader stalled after %llu bytes, reset %lld ms after the last credit\n",
           (unsigned long long)sent, stalled_for);
    CHECK(!failed, "the data connection failed while streaming");
    CHECK(reset && code == ST_ADMIN_DIRECT_HTTP_LOCAL_RESET_CODE,
          "a browser that stops reading must get its stream reset with RST 8 (reset=%d code=%u)", reset, code);
    CHECK(stalled_for >= 500 && stalled_for <= 8000,
          "the reset must come about the 1 s timeout after the writes stopped (%lld ms)", stalled_for);
    CHECK(exchange_of(server, "/stalled-reader", "status_code", "200") == 0
              && exchange_of(server, "/stalled-reader", "success", "1") == 0
              && exchange_of(server, "/stalled-reader", "error", "") == 0,
          "the abandoned exchange must be recorded as Java records a client abort");
    return expect_data_connection_served(server, pair);
}

/* An upgraded WebSocket is not subject to the connection timeout, as in Tomcat: idle past it, it stays open. */
static int test_websocket_outlives_timeout(test_server *server)
{
    char request[1536];
    char *token = management_token(server);
    CHECK(token != NULL, "management login");
    int status = 0;
    char *ticket_response = NULL;
    int ticket_rc = http_request(server->admin_port, "POST", "/api/admin/ws-tickets", "{\"endpoint\":\"connections\"}",
                                 token, &status, &ticket_response);
    free(token);
    char *ticket = ticket_rc == 0 && status == 200 ? st_json_get_string(ticket_response, "ticket") : NULL;
    free(ticket_response);
    CHECK(ticket != NULL, "WebSocket ticket (%d)", status);
    int len = snprintf(request, sizeof(request),
                       "GET /ws/connections?ticket=%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\n"
                       "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                       ticket);
    free(ticket);
    int ws = browser_raw(server, request, (size_t)len);
    CHECK(ws >= 0, "WebSocket connect");
    char handshake[512] = "";
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used + 1U < sizeof(handshake) && strstr(handshake, "\r\n\r\n") == NULL
           && recv_exact(ws, (uint8_t *)handshake + used, 1U, deadline) == 1) {
        handshake[++used] = '\0';
    }
    if (strncmp(handshake, "HTTP/1.1 101", 12U) != 0) {
        close_fd(&ws);
    }
    CHECK(ws >= 0, "WebSocket upgrade: %s", handshake);
    sleep_ms(2500);
    int answered_ping = ws_send_small(ws, 0x9U, "idle", 4U) == 0 && ws_expect_opcode(ws, 0xAU, IO_TIMEOUT_MS) == 0;
    close_fd(&ws);
    CHECK(answered_ping, "a WebSocket idle for 2.5 s must still answer a ping");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* server.tomcat.max-connections                                                                 */

/*
 * With max-connections at 2, two open connections hold the listener: a third is accepted by the
 * kernel (the backlog of accept-count) but not served until one of them closes, as Tomcat's
 * acceptor waits on its LimitLatch. The old listener started a thread for every connection.
 */
static int test_connection_limit(test_server *server)
{
    sleep_ms(300); /* the harness's readiness probe connection is closed by now */
    int first = connect_local(server->admin_port);
    int second = connect_local(server->admin_port);
    CHECK(first >= 0 && second >= 0, "two connections");
    sleep_ms(300);
    static const char request[] = "GET /api/admin/clients HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
    int third = browser_raw(server, request, sizeof(request) - 1U);
    CHECK(third >= 0, "third connection");
    int waited = silent_for(third, 1500);
    close_fd(&first);
    int served = expect_browser_status(third, 401, NULL, -1) == 0;
    close_fd(&second);
    close_fd(&third);
    CHECK(waited, "a third connection must wait while two are open");
    CHECK(served, "the third connection must be served once one of the two closed");
    return 0;
}

/*
 * A failed accept (here: the server out of descriptors) must not end the listener, as it does not
 * end Tomcat's acceptor, which pauses and tries again. The server runs with a soft limit of 64
 * descriptors while 100 connections are opened; once they are closed, a request is served again.
 * The old listener thread returned on the first failed accept, and the management listener with
 * every route and share was gone until the process restarted.
 */
static int test_accept_failure_recovers(void)
{
    struct rlimit saved;
    if (getrlimit(RLIMIT_NOFILE, &saved) != 0) {
        return 1;
    }
    test_server server;
    if (server_prepare(&server) != 0) {
        return 1;
    }
    struct rlimit low = saved;
    low.rlim_cur = 64;
    int limited = setrlimit(RLIMIT_NOFILE, &low) == 0;
    int started = limited && server_start(&server) == 0;
    (void)setrlimit(RLIMIT_NOFILE, &saved);
    int failed = !started;
    enum { FLOOD = 100 };
    int fds[FLOOD];
    for (size_t i = 0U; i < FLOOD; ++i) {
        fds[i] = started ? connect_local(server.admin_port) : -1;
    }
    if (started) {
        sleep_ms(1000);
    }
    for (size_t i = 0U; i < FLOOD; ++i) {
        close_fd(&fds[i]);
    }
    if (started) {
        static const char request[] = "GET /api/admin/clients HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        int fd = browser_raw(&server, request, sizeof(request) - 1U);
        failed = fd < 0 || expect_browser_status_within(fd, 15000, 401, NULL, -1) != 0;
        close_fd(&fd);
        if (failed) {
            fprintf(stderr, "FAIL the listener did not serve again after running out of descriptors\n");
        }
    }
    if (started && server_stop(&server, 20000) != 0) {
        failed = 1;
    }
    server_cleanup(&server, failed);
    printf("%s a failed accept does not end the listener\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ------------------------------------------------------------------------------------------- */
/* Expect: 100-continue                                                                          */

/* Reads exactly Tomcat's interim response within timeout_ms. */
static int expect_interim_continue(int fd, int timeout_ms)
{
    static const char interim[] = "HTTP/1.1 100 \r\n\r\n";
    char received[sizeof(interim)] = "";
    int rc = recv_exact(fd, (uint8_t *)received, sizeof(interim) - 1U, monotonic_ms() + timeout_ms);
    if (rc != 1 || memcmp(received, interim, sizeof(interim) - 1U) != 0) {
        fprintf(stderr, "no interim 100 (rc=%d): %.*s\n", rc, (int)(sizeof(interim) - 1U), received);
        return -1;
    }
    return 0;
}

/*
 * Tomcat answers "Expect: 100-continue" of an HTTP/1.1 request with "HTTP/1.1 100 " once the
 * request is mapped, before any filter or handler (continueResponseTiming "immediately"): a route
 * request and a management request alike. Not for HTTP/1.0. The C listener used to answer nothing,
 * so curl waited a second before each upload and a client that waits for the 100 hung.
 */
static int check_expect_continue(test_server *server, client_pair *pair)
{
    char client[768];
    char request[1536];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "POST /http/%s/%s/upload HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\n"
                       "Content-Length: 5\r\nConnection: close\r\n\r\n",
                       client, ROUTE);
    int browser = browser_raw(server, request, (size_t)len);
    CHECK(browser >= 0, "upload");
    CHECK(expect_interim_continue(browser, 2000) == 0, "a route upload must get the interim 100 before its body");
    CHECK(send_all(browser, (const uint8_t *)"hello", 5U) == 0, "body");
    uint32_t stream_id = 0U;
    char *open_meta = NULL;
    char body[64];
    char *fin_meta = NULL;
    CHECK(expect_open_meta(pair->data, &stream_id, &open_meta) == 0, "request OPEN");
    free(open_meta);
    CHECK(expect_request_fin(pair->data, stream_id, body, sizeof(body), &fin_meta) == 0 && strcmp(body, "hello") == 0,
          "the body after the 100");
    free(fin_meta);
    CHECK(answer_empty(pair->data, stream_id) == 0, "response");
    CHECK(expect_browser_status(browser, 200, NULL, 1) == 0, "the response after the 100");
    close_fd(&browser);

    len = snprintf(request, sizeof(request),
                   "POST /http/%s/%s/upload10 HTTP/1.0\r\nHost: 127.0.0.1\r\nExpect: 100-continue\r\n"
                   "Content-Length: 5\r\n\r\n",
                   client, ROUTE);
    browser = browser_raw(server, request, (size_t)len);
    CHECK(browser >= 0, "HTTP/1.0 upload");
    CHECK(silent_for(browser, 700), "an HTTP/1.0 request must not get an interim 100");
    CHECK(send_all(browser, (const uint8_t *)"world", 5U) == 0, "HTTP/1.0 body");
    CHECK(expect_open_meta(pair->data, &stream_id, &open_meta) == 0, "HTTP/1.0 request OPEN");
    free(open_meta);
    CHECK(expect_request_fin(pair->data, stream_id, body, sizeof(body), &fin_meta) == 0 && strcmp(body, "world") == 0,
          "the HTTP/1.0 body");
    free(fin_meta);
    CHECK(answer_empty(pair->data, stream_id) == 0, "HTTP/1.0 response");
    CHECK(expect_browser_status(browser, 200, NULL, -1) == 0, "the HTTP/1.0 response");
    close_fd(&browser);

    static const char management[] =
        "POST /api/admin/clients HTTP/1.1\r\nHost: 127.0.0.1\r\nExpect: 100-Continue \r\nContent-Length: 2\r\n"
        "Connection: close\r\n\r\n";
    browser = browser_raw(server, management, sizeof(management) - 1U);
    CHECK(browser >= 0, "management request");
    CHECK(expect_interim_continue(browser, 2000) == 0, "a management request must get the interim 100 as well");
    CHECK(send_all(browser, (const uint8_t *)"{}", 2U) == 0, "management body");
    CHECK(expect_browser_status(browser, 401, NULL, -1) == 0, "the management answer after the 100");
    close_fd(&browser);
    return expect_data_connection_served(server, pair);
}

/* ------------------------------------------------------------------------------------------- */
/* Failure answers                                                                               */

/*
 * Java HttpSpecusController's answers, with SPECUS_HTTP_TIMEOUT_MS at 1 s and detail capture on:
 *   - no response head in time: 504 "TimeoutException" and RST 8 with that reason (C answered
 *     "direct http response timeout" and reset with 30);
 *   - a response head it cannot use, or DATA before any head: this server cancels the stream with
 *     RST 8 and answers 502 "HTTP 转发请求失败" (C reset the first with 31 and answered both with
 *     "客户端不在线");
 *   - the data connection lost before the head: 502 "HTTP 转发请求失败", recorded with Java's
 *     "control channel closed" (C answered "客户端不在线").
 */
static const char reset_body[] = "{\"error\":\"" ST_ADMIN_DIRECT_HTTP_RESET_BODY "\"}";

static int check_head_timeout_answer(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    int browser = -1;
    uint32_t stream_id = 0U;
    uint32_t code = 0U;
    CHECK(open_http_stream(server, pair, "/no-head", &browser, &stream_id) == 0, "request");
    CHECK(wait_rst(pair->data, stream_id, &code) == 0 && code == ST_ADMIN_DIRECT_HTTP_LOCAL_RESET_CODE,
          "a response head timeout must reset the stream with RST 8 (code %u)", code);
    CHECK(expect_browser_status(browser, 504, "{\"error\":\"TimeoutException\"}", -1) == 0,
          "a response head timeout must answer 504 TimeoutException");
    close_fd(&browser);
    CHECK(exchange_of(server, "/no-head", "status_code", "504") == 0
              && exchange_of(server, "/no-head", "error", "TimeoutException") == 0,
          "the timed-out exchange's record");
    return expect_data_connection_served(server, pair);
}

static int check_local_reset_answers(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    int browser = -1;
    uint32_t stream_id = 0U;
    uint32_t code = 0U;
    CHECK(open_http_stream(server, pair, "/bad-head", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U,
                   "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,\"headers\":\"not-a-list\"}", NULL,
                   0U) == 0,
          "unusable head");
    CHECK(wait_rst(pair->data, stream_id, &code) == 0 && code == ST_ADMIN_DIRECT_HTTP_LOCAL_RESET_CODE,
          "an unusable response head must reset the stream with RST 8 (code %u)", code);
    CHECK(expect_browser_status(browser, 502, reset_body, -1) == 0, "an unusable response head must answer the reset");
    close_fd(&browser);
    CHECK(exchange_of(server, "/bad-head", "status_code", "502") == 0
              && exchange_of(server, "/bad-head", "error", "invalid HTTP response headers") == 0,
          "the unusable head's record");
    return expect_data_connection_served(server, pair);
}

static int check_rejected_frame_answer(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/data-first", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "x", 1U) == 0, "DATA before head");
    CHECK(expect_rst(pair->data, stream_id, 8U) == 0, "DATA before the head must reset the stream");
    CHECK(expect_browser_status(browser, 502, reset_body, -1) == 0, "DATA before the head must answer the reset");
    close_fd(&browser);
    CHECK(exchange_of(server, "/data-first", "error", "HTTP DATA is invalid for the stream state") == 0,
          "the reset stream's record");
    return expect_data_connection_served(server, pair);
}

static int check_connection_lost_answer(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_http_stream(server, pair, "/connection-lost", &browser, &stream_id) == 0, "request");
    close_fd(&pair->data);
    CHECK(expect_browser_status(browser, 502, reset_body, -1) == 0,
          "a data connection lost under the stream must answer the reset, not the offline client");
    close_fd(&browser);
    CHECK(exchange_of(server, "/connection-lost", "status_code", "502") == 0
              && exchange_of(server, "/connection-lost", "error", "control channel closed") == 0,
          "the lost stream's record");
    CHECK(login_data(server, pair) == 0, "data re-login");
    return expect_data_connection_served(server, pair);
}

/* ------------------------------------------------------------------------------------------- */
/* Temporary HTTP shares                                                                         */

/*
 * Creates a share of the pair's route through the management API: its id and visitor token. Only a
 * protected route can be shared, so the route gets Basic credentials first.
 */
static int create_route_share(const test_server *server, const client_pair *pair, const char *body,
                              long long *route_id, char share_id[ST_HTTP_SHARE_ID_LEN + 1U],
                              char token[ST_HTTP_SHARE_TOKEN_LEN + 1U])
{
    uint8_t digest[ST_SHA256_LEN];
    char password_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"s3cret", 6U, digest);
    st_hex_encode(digest, sizeof(digest), password_hash);
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    int protected_route = sqlite3_open(server->db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "UPDATE http_route_mapping SET auth_enabled = 1, auth_username = 'viewer', "
                                  "auth_password_hash = ? WHERE client_name = ? AND route = 'app'",
                              -1, &statement, NULL) == SQLITE_OK
        && sqlite3_bind_text(statement, 1, password_hash, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_bind_text(statement, 2, pair->runtime.client_name, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    sqlite3_close(db);
    CHECK(protected_route, "protect the route");
    char value[32] = "";
    CHECK(db_scalar(server->db_path, "SELECT id FROM http_route_mapping WHERE client_name = ? AND route = 'app'",
                    pair->runtime.client_name, 0, value, sizeof(value)) == 0,
          "route id");
    *route_id = atoll(value);
    char *bearer = management_token(server);
    CHECK(bearer != NULL, "management login");
    char path[96];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/shares", *route_id);
    int status = 0;
    char *response = NULL;
    int rc = http_request(server->admin_port, "POST", path, body, bearer, &status, &response);
    free(bearer);
    char *created = rc == 0 && status == 201 ? st_json_get_string(response, "token") : NULL;
    int ok = created != NULL && strlen(created) == ST_HTTP_SHARE_TOKEN_LEN;
    if (ok) {
        snprintf(token, ST_HTTP_SHARE_TOKEN_LEN + 1U, "%s", created);
        memcpy(share_id, created + 4, ST_HTTP_SHARE_ID_LEN);
        share_id[ST_HTTP_SHARE_ID_LEN] = '\0';
    } else {
        fprintf(stderr, "share create answered %d: %s\n", status, response == NULL ? "" : response);
    }
    free(created);
    free(response);
    return ok ? 0 : -1;
}

/*
 * A share cut while the device has not answered: the device's stream is reset with RST 8 "HTTP share
 * ended" (Java cancelHttpStream, .NET as well; C reset with 31), the visitor's connection is closed
 * without an answer (temporary-http-share.md 6.6; Java answers 502 before its response is committed),
 * and the exchange is recorded as Java records it, 502 with "HTTP share ended" (C recorded nothing).
 */
static int check_share_cut_before_head(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    long long route_id = 0;
    char share_id[ST_HTTP_SHARE_ID_LEN + 1U];
    char token[ST_HTTP_SHARE_TOKEN_LEN + 1U];
    CHECK(create_route_share(server, pair, "{\"expiresInSeconds\":3600}", &route_id, share_id, token) == 0, "share");
    char request[1024];
    int len = snprintf(request, sizeof(request),
                       "GET /http-share/%s/slow HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: " ST_HTTP_SHARE_COOKIE_NAME
                       "=%s\r\nConnection: close\r\n\r\n",
                       share_id, token);
    int visitor = browser_raw(server, request, (size_t)len);
    CHECK(visitor >= 0, "visitor");
    uint32_t stream_id = 0U;
    CHECK(expect_http_open(pair->data, &stream_id) == 0, "no request OPEN for the share");
    char *bearer = management_token(server);
    CHECK(bearer != NULL, "management login");
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/shares/%s/revoke", route_id, share_id);
    int status = 0;
    char *response = NULL;
    int rc = http_request(server->admin_port, "POST", path, NULL, bearer, &status, &response);
    free(bearer);
    free(response);
    CHECK(rc == 0 && status == 200, "revoke answered %d", status);
    uint32_t code = 0U;
    CHECK(wait_rst(pair->data, stream_id, &code) == 0 && code == ST_ADMIN_HTTP_SHARE_RESET_CODE && code == 8U,
          "the cut share's stream must be reset with RST 8 (code %u)", code);
    size_t bytes = 0U;
    long long ended = ended_after(visitor, IO_TIMEOUT_MS, &bytes);
    close_fd(&visitor);
    CHECK(ended >= 0 && bytes == 0U, "the visitor must be cut off without an answer (%zu bytes)", bytes);
    CHECK(exchange_of(server, "/slow", "status_code", "502") == 0
              && exchange_of(server, "/slow", "success", "0") == 0
              && exchange_of(server, "/slow", "error", ST_ADMIN_HTTP_SHARE_RESET_REASON) == 0,
          "the cut exchange's record");
    /* The route is protected now, so a TCP stream shows the data connection still serves. */
    return expect_tcp_stream_served(pair);
}

/*
 * A share request whose body is over SPECUS_HTTP_MAX_REQUEST_BODY_SIZE (1 KiB here) is refused 413
 * and recorded as Java ShareRelay records it: by Content-Length before anything of the request was
 * taken, so without headers or body; a chunked body while it is read, with the headers the device
 * would have got (no share cookie) and the body's start. C recorded neither. Nothing reaches the
 * device either way: C reads the body before it opens the stream.
 */
static int check_share_body_refusals(test_server *server, client_pair *pair)
{
    CHECK(enable_route_capture(server, pair) == 0, "route detail capture");
    long long route_id = 0;
    char share_id[ST_HTTP_SHARE_ID_LEN + 1U];
    char token[ST_HTTP_SHARE_TOKEN_LEN + 1U];
    CHECK(create_route_share(server, pair, "{\"expiresInSeconds\":3600,\"access\":\"full\"}", &route_id, share_id,
                             token) == 0,
          "share");
    char request[4096];
    int len = snprintf(request, sizeof(request),
                       "POST /http-share/%s/upload?x=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: " ST_HTTP_SHARE_COOKIE_NAME
                       "=%s\r\nX-Test: kept\r\nContent-Length: 2048\r\nConnection: close\r\n\r\n",
                       share_id, token);
    int visitor = browser_raw(server, request, (size_t)len);
    CHECK(visitor >= 0, "visitor");
    CHECK(expect_browser_status(visitor, 413, "HTTP 请求体超过限制", -1) == 0, "Content-Length over the limit");
    close_fd(&visitor);
    CHECK(exchange_of(server, "/upload", "status_code", "413") == 0
              && exchange_of(server, "/upload", "error", "HTTP 请求体超过限制") == 0
              && exchange_of(server, "/upload", "request_headers", "") == 0
              && exchange_of(server, "/upload", "request_bytes", "0") == 0
              && exchange_of(server, "/upload", "raw_query", "x=1") == 0,
          "the share's 413 by Content-Length must be recorded without headers or body");

    len = snprintf(request, sizeof(request),
                   "POST /http-share/%s/chunked HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: " ST_HTTP_SHARE_COOKIE_NAME
                   "=%s\r\nX-Test: kept\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n800\r\n",
                   share_id, token);
    size_t total = (size_t)len + 2048U + 7U;
    char *chunked = (char *)malloc(total);
    CHECK(chunked != NULL, "chunked request");
    memcpy(chunked, request, (size_t)len);
    memset(chunked + len, 'c', 2048U);
    memcpy(chunked + len + 2048U, "\r\n0\r\n\r\n", 7U);
    visitor = browser_raw(server, chunked, total);
    free(chunked);
    CHECK(visitor >= 0, "chunked visitor");
    CHECK(expect_browser_status(visitor, 413, "HTTP 请求体超过限制", -1) == 0, "chunked body over the limit");
    close_fd(&visitor);
    CHECK(exchange_of(server, "/chunked", "status_code", "413") == 0
              && exchange_of(server, "/chunked", "request_headers", "~X-Test:kept") == 0
              && exchange_of(server, "/chunked", "request_preview_text", "~cccc") == 0,
          "the share's chunked 413 must be recorded with the forwarded headers and the body's start");
    char value[32] = "";
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) FROM specus_http_traffic_exchange WHERE request_headers LIKE '%' || ? || '%'",
                    token, 0, value, sizeof(value)) == 0 && strcmp(value, "0") == 0,
          "a recorded share request must not carry the share token");
    CHECK(expect_no_stream_opened(pair->data) == 0, "a refused share body must not open a stream");
    return expect_tcp_stream_served(pair);
}

/* ------------------------------------------------------------------------------------------- */

static const char *const connection_timeout_env[] = {
    "SPECUS_CONTROL_READ_IDLE_SECONDS=900", "SERVER_TOMCAT_CONNECTION_TIMEOUT=1s",
    "SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED=true", NULL
};

static const char *const connection_limit_env[] = {"SERVER_TOMCAT_MAXCONNECTIONS=2", NULL};

static const char *const failure_answer_env[] = {
    "SPECUS_CONTROL_READ_IDLE_SECONDS=900", "SPECUS_HTTP_TIMEOUT_MS=1000",
    "SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED=true", NULL
};

/* An unusable connection timeout refuses the start, as Spring's binding failure does. */
static int test_invalid_connection_timeout(void)
{
    static const char *const values[] = {"60 s", "1x", "PT", "P1DT", "s"};
    int failures = 0;
    for (size_t i = 0U; i < sizeof(values) / sizeof(values[0]); ++i) {
        test_server server;
        if (server_prepare(&server) != 0) {
            return 1;
        }
        char assignment[64];
        snprintf(assignment, sizeof(assignment), "SERVER_TOMCAT_CONNECTION_TIMEOUT=%s", values[i]);
        server.extra_env[0] = assignment;
        int started = server_start(&server) == 0;
        if (started) {
            fprintf(stderr, "FAIL the server started with SERVER_TOMCAT_CONNECTION_TIMEOUT=%s\n", values[i]);
            ++failures;
            (void)server_stop(&server, 20000);
        }
        server_cleanup(&server, 0);
    }
    printf("%s an unusable server.tomcat.connection-timeout refuses the start\n", failures == 0 ? "ok  " : "FAIL");
    return failures != 0;
}

/* The ISO-8601 form of the same 1 s, a little of check_connection_timeouts. */
static int test_iso_connection_timeout(test_server *server)
{
    size_t bytes = 0U;
    int idle = connect_local(server->admin_port);
    CHECK(idle >= 0, "idle connection");
    long long ended = ended_after(idle, 8000, &bytes);
    close_fd(&idle);
    CHECK(ended >= 700 && ended <= 5000 && bytes == 0U, "PT1S must time out an idle connection (after %lld ms)", ended);
    return 0;
}

static const char *const iso_timeout_env[] = {"SERVER_TOMCAT_CONNECTIONTIMEOUT=pt1.000S", NULL};

static const char *const share_env[] = {
    "SPECUS_CONTROL_READ_IDLE_SECONDS=900", "SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED=true",
    "SPECUS_HTTP_MAX_REQUEST_BODY_SIZE=1024", NULL
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());
    int failures = 0;
    failures += run_scenario("connection timeout drops an idle connection and a stalled head",
                             test_idle_and_stalled_head, connection_timeout_env);
    current_check = check_stalled_body;
    failures += run_scenario("connection timeout answers a stalled body", run_current_check, connection_timeout_env);
    current_check = check_stalled_reader;
    failures += run_scenario("connection timeout resets the stream of a browser that stopped reading",
                             run_current_check, connection_timeout_env);
    failures += run_scenario("connection timeout leaves an idle WebSocket open", test_websocket_outlives_timeout,
                             connection_timeout_env);
    failures += run_scenario("connection timeout in ISO-8601", test_iso_connection_timeout, iso_timeout_env);
    if (selected("connection timeout refuses")) {
        failures += test_invalid_connection_timeout();
    }
    failures += run_scenario("max-connections holds further connections in the backlog", test_connection_limit,
                             connection_limit_env);
    if (selected("a failed accept does not end the listener")) {
        failures += test_accept_failure_recovers();
    }
    failures += run_check("Expect: 100-continue gets the interim 100", check_expect_continue);
    current_check = check_head_timeout_answer;
    failures += run_scenario("a response head timeout answers 504 TimeoutException with RST 8", run_current_check,
                             failure_answer_env);
    current_check = check_local_reset_answers;
    failures += run_scenario("an unusable response head is reset with RST 8 and answers 502 HTTP 转发请求失败",
                             run_current_check, failure_answer_env);
    current_check = check_rejected_frame_answer;
    failures += run_scenario("a stream reset for a frame it refused answers 502 HTTP 转发请求失败", run_current_check,
                             failure_answer_env);
    current_check = check_connection_lost_answer;
    failures += run_scenario("a stream lost with its data connection answers 502 HTTP 转发请求失败",
                             run_current_check, failure_answer_env);
    current_check = check_share_cut_before_head;
    failures += run_scenario("a share cut before the head resets with RST 8 and is recorded", run_current_check,
                             share_env);
    current_check = check_share_body_refusals;
    failures += run_scenario("a share's 413 is recorded as Java's", run_current_check, share_env);
    if (failures != 0) {
        fprintf(stderr, "%d HTTP connector check(s) failed\n", failures);
        return 1;
    }
    printf("HTTP connector tests passed\n");
    return 0;
}
