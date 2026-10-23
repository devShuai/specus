/*
 * Traffic usage of a real specus-server-c process, against Java TrafficUsageService and the places
 * that feed it (RemoteSpecusHandler, NatServerHandler.processWsData, HttpSpecusController.relay):
 *
 *   - a TCP mapping counts what the client writes to the public peer as upload and what the public
 *     peer sends the client as download, on the client's day and on its tcp:<port> row;
 *   - an HTTP exchange counts the request body bytes read from the public caller (each chunk once
 *     read, before it waits for the window, as Java) and the response bytes the client sent, whatever the outcome: completed, reset by the client after its head or before
 *     it, cut while the request body was going up, or left by the public caller mid-body;
 *   - every client-to-browser SWS2 envelope of a route WebSocket, header included and valid or
 *     not, is the client's upload; the browser's direction is not counted and no resource row is
 *     written;
 *   - an HTTP route's row is named "route -> targetBaseUrl" in full;
 *   - the counts are kept in memory and written where Java flushes them: periodically, before
 *     the reads that ask for it, and at shutdown; a flush that fails keeps them for the next.
 *
 * The values are read the way an operator reads them, through /api/admin/traffic and
 * /api/admin/traffic/resources with flush=true.
 *
 * Usage: specus_c_traffic_usage_tests <path-to-specus-server-c>
 */
#define main st_prior_nat_stream_test_entry
#include "nat_stream_tests.c"
#undef main
#include "admin_http.h"
#include "traffic_usage.h"

typedef struct {
    int found;
    long long upload;
    long long download;
    long long resource_id;
    char resource_name[1024];
} usage_row;

static char admin_token[1024];

static int admin_login(const test_server *server)
{
    int status = 0;
    char *response = NULL;
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    char *token = http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) == 0
                          && status == 200
                      ? st_json_get_top_level_string(response, "accessToken")
                      : NULL;
    free(response);
    int ok = token != NULL && strlen(token) < sizeof(admin_token);
    if (ok) {
        snprintf(admin_token, sizeof(admin_token), "%s", token);
    }
    free(token);
    return ok ? 0 : -1;
}

/*
 * The client's row of the day (resource_key NULL) or its row of one resource, read through the
 * management API with flush=true. found is 0 when the API lists no such row.
 */
static int read_usage(const test_server *server, long long client_id, const char *resource_type,
                      const char *resource_key, usage_row *row)
{
    memset(row, 0, sizeof(*row));
    char path[256];
    if (resource_key == NULL) {
        snprintf(path, sizeof(path), "/api/admin/traffic?clientId=%lld&flush=true", client_id);
    } else {
        snprintf(path, sizeof(path), "/api/admin/traffic/resources?clientId=%lld&type=%s&flush=true", client_id,
                 resource_type);
    }
    int status = 0;
    char *body = NULL;
    if (http_request(server->admin_port, "GET", path, NULL, admin_token, &status, &body) != 0 || status != 200
        || body == NULL) {
        fprintf(stderr, "GET %s: status %d\n%s\n", path, status, body == NULL ? "" : body);
        free(body);
        return -1;
    }
    size_t wrapped_len = strlen(body) + 16U;
    char *wrapped = (char *)malloc(wrapped_len);
    char **rows = NULL;
    size_t row_count = 0U;
    int rc = wrapped == NULL ? -1 : 0;
    if (rc == 0) {
        snprintf(wrapped, wrapped_len, "{\"rows\":%s}", body);
        rc = st_json_get_raw_array(wrapped, "rows", &rows, &row_count);
    }
    /* A run across UTC midnight splits the counts over two days: their rows are summed. Two rows of
     * one day would be a keying fault. */
    char seen_dates[4][16];
    size_t seen = 0U;
    for (size_t i = 0U; rc == 0 && i < row_count; ++i) {
        char *key = st_json_get_string(rows[i], "resourceKey");
        int match = resource_key == NULL || (key != NULL && strcmp(key, resource_key) == 0);
        free(key);
        if (!match) {
            continue;
        }
        char *date = st_json_get_string(rows[i], "usageDate");
        int repeated = date == NULL || seen == sizeof(seen_dates) / sizeof(seen_dates[0]);
        for (size_t d = 0U; !repeated && d < seen; ++d) {
            repeated = strcmp(seen_dates[d], date) == 0;
        }
        if (!repeated) {
            snprintf(seen_dates[seen++], sizeof(seen_dates[0]), "%s", date);
        }
        free(date);
        if (repeated) {
            fprintf(stderr, "GET %s lists the row twice\n%s\n", path, body);
            rc = -1;
            break;
        }
        row->found = 1;
        long long upload = 0;
        long long download = 0;
        if (st_json_get_i64(rows[i], "uploadBytes", &upload) != 0
            || st_json_get_i64(rows[i], "downloadBytes", &download) != 0) {
            rc = -1;
        }
        row->upload += upload;
        row->download += download;
        if (st_json_get_i64(rows[i], "resourceId", &row->resource_id) != 0) {
            row->resource_id = 0;
        }
        char *name = st_json_get_string(rows[i], "resourceName");
        snprintf(row->resource_name, sizeof(row->resource_name), "%s", name == NULL ? "" : name);
        free(name);
    }
    st_json_free_string_array(rows, row_count);
    free(wrapped);
    free(body);
    return rc;
}

/* Waits until the row holds exactly these counts; the server counts once the bytes have moved. */
static int expect_usage(const test_server *server, long long client_id, const char *resource_type,
                        const char *resource_key, long long upload, long long download, usage_row *row)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        if (read_usage(server, client_id, resource_type, resource_key, row) != 0) {
            return -1;
        }
        if (row->found && row->upload == upload && row->download == download) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "%s %s: found=%d upload=%lld download=%lld, expected %lld/%lld\n",
                    resource_type == NULL ? "day" : resource_type, resource_key == NULL ? "" : resource_key,
                    row->found, row->upload, row->download, upload, download);
            return -1;
        }
        sleep_ms(50);
    }
}

/* ------------------------------------------------------------------------------------------- */
/* TCP                                                                                           */

/*
 * One public TCP stream on the client's port: the public peer sends public_bytes, the client
 * answers client_bytes, and the client resets the stream once both have arrived.
 */
static int relay_tcp(client_pair *pair, size_t public_bytes, size_t client_bytes)
{
    int public_fd = -1;
    uint32_t stream_id = 0U;
    uint8_t buffer[4096];
    CHECK(public_bytes <= sizeof(buffer) && client_bytes <= sizeof(buffer), "relay sizes");
    CHECK(open_public_stream_id(pair->data, pair->public_port, &public_fd, &stream_id) == 0, "public OPEN");
    memset(buffer, 'p', public_bytes);
    CHECK(send_all(public_fd, buffer, public_bytes) == 0, "public send");
    size_t received = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (received < public_bytes) {
        st_nat_message message;
        CHECK(next_nat_frame(pair->data, deadline, &message) == 1, "public bytes reached the client: %zu", received);
        if (message.stream_id == stream_id && message.type == ST_NAT_DATA) {
            received += message.data_len;
        }
        st_nat_message_free(&message);
    }
    CHECK(received == public_bytes, "the client got %zu bytes", received);
    memset(buffer, 'c', client_bytes);
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, buffer, client_bytes) == 0, "client DATA");
    CHECK(recv_exact(public_fd, buffer, client_bytes, monotonic_ms() + IO_TIMEOUT_MS) == 1,
          "client bytes reached the public peer");
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 0U, NULL, NULL, 0U) == 0, "RST");
    CHECK(drain_until_eof(public_fd, IO_TIMEOUT_MS) == 0, "public peer closed");
    close_fd(&public_fd);
    return 0;
}

/*
 * The public peer sends 3000 bytes and the client answers 700: Java (and Go and .NET) count 700
 * as upload and 3000 as download, on the client's day and on tcp:<port>, whose row names the
 * mapping. C had the two the other way round.
 */
static int check_tcp_direction(test_server *server, client_pair *pair)
{
    CHECK(admin_login(server) == 0, "admin login");
    CHECK(relay_tcp(pair, 3000U, 700U) == 0, "relay");
    char key[32];
    snprintf(key, sizeof(key), "tcp:%d", pair->public_port);
    usage_row row;
    CHECK(expect_usage(server, pair->runtime.client_id, NULL, NULL, 700, 3000, &row) == 0,
          "the client's day must count 700 up (client to public) and 3000 down (public to client)");
    CHECK(expect_usage(server, pair->runtime.client_id, "TCP_SPECUS", key, 700, 3000, &row) == 0,
          "the mapping's row must count the same");
    char name[64];
    snprintf(name, sizeof(name), "%d -> 127.0.0.1:9", pair->public_port);
    CHECK(row.resource_id > 0 && strcmp(row.resource_name, name) == 0, "mapping row %lld %s, expected %s",
          row.resource_id, row.resource_name, name);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* HTTP                                                                                          */

/* Sends a POST with a body of body_len bytes for the client's route and returns the browser socket. */
static int browser_post(const test_server *server, const client_pair *pair, const char *path, size_t body_len)
{
    char client[768];
    char head[1536];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int head_len = snprintf(head, sizeof(head),
                            "POST /http/%s/%s%s HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: %zu\r\n"
                            "Connection: close\r\n\r\n",
                            client, ROUTE, path, body_len);
    if (head_len <= 0 || (size_t)head_len >= sizeof(head)) {
        return -1;
    }
    size_t total = (size_t)head_len + body_len;
    char *request = (char *)malloc(total);
    if (request == NULL) {
        return -1;
    }
    memcpy(request, head, (size_t)head_len);
    memset(request + head_len, 'u', body_len);
    int fd = browser_raw(server, request, total);
    free(request);
    return fd;
}

/* Counts the request DATA of one stream until its FIN (or until want bytes when want is not 0). */
static int read_request_body(int data_fd, uint32_t stream_id, size_t want, size_t *received)
{
    *received = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        st_nat_message message;
        if (next_nat_frame(data_fd, deadline, &message) != 1) {
            return -1;
        }
        int done = 0;
        if (message.stream_id == stream_id && message.type == ST_NAT_DATA) {
            *received += message.data_len;
            done = want != 0U && *received >= want;
        } else if (message.stream_id == stream_id && message.type == ST_NAT_FIN) {
            done = 1;
        }
        st_nat_message_free(&message);
        if (done) {
            return 0;
        }
    }
}

/*
 * One route, five exchanges, the route's counts checked after each: what Java's finally block adds.
 *
 *   1. GET answered in full with 500 bytes: 0 up, 500 down.
 *   2. GET whose client resets the stream after its head and 1000 bytes: 1000 more down.
 *   3. POST of 64 KiB the client reads to its FIN and then resets before any head: 64 KiB more up.
 *   4. POST of 1 MiB + 1 that the client resets once the first 1 MiB (its window) is up: 1 MiB
 *      and the byte waiting for the window more up: all that was read from the caller.
 *   5. GET whose public caller leaves after the head while the client keeps sending: whatever the
 *      server took from the client before it gave up, at least one chunk, at most what was sent.
 *
 * C counted only the first one.
 */
static int check_http_outcomes(test_server *server, client_pair *pair)
{
    CHECK(admin_login(server) == 0, "admin login");
    const char *key = "http:" ROUTE;
    long long up = 0;
    long long down = 0;
    usage_row row;
    int browser = -1;
    uint32_t stream_id = 0U;
    uint8_t chunk[DATA_CHUNK];
    memset(chunk, 'd', sizeof(chunk));

    /* 1 */
    CHECK(open_http_stream(server, pair, "/complete", &browser, &stream_id) == 0, "complete request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0
              && send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, chunk, 500U) == 0
              && send_nat(pair->data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) == 0,
          "complete response");
    CHECK(expect_browser_status(browser, 200, NULL, 1) == 0, "complete response relayed");
    close_fd(&browser);
    down += 500;
    CHECK(expect_usage(server, pair->runtime.client_id, "HTTP_ROUTE", key, up, down, &row) == 0, "completed exchange");
    char expected_name[256];
    snprintf(expected_name, sizeof(expected_name), "%s -> http://127.0.0.1:9", ROUTE);
    CHECK(row.resource_id > 0 && strcmp(row.resource_name, expected_name) == 0, "route row %lld %s",
          row.resource_id, row.resource_name);

    /* 2 */
    CHECK(open_http_stream(server, pair, "/reset-after-head", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0
              && send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, chunk, 1000U) == 0,
          "head and 1000 bytes");
    browser_response response;
    memset(&response, 0, sizeof(response));
    response.fd = browser;
    response.timeout_ms = 2000;
    read_browser_response(&response);
    CHECK(response.status == 200 && response.total > 1000U, "the browser got the head and the bytes (%zu)",
          response.total);
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 1U, NULL, NULL, 0U) == 0, "client RST");
    memset(&response, 0, sizeof(response));
    response.fd = browser;
    response.timeout_ms = IO_TIMEOUT_MS;
    read_browser_response(&response);
    CHECK(response.eof && !response_complete(&response), "the reset response must end cut short");
    close_fd(&browser);
    down += 1000;
    CHECK(expect_usage(server, pair->runtime.client_id, "HTTP_ROUTE", key, up, down, &row) == 0,
          "an exchange the client reset after its head must count the 1000 bytes it relayed");

    /* 3 */
    size_t received = 0U;
    browser = browser_post(server, pair, "/reset-before-head", 65536U);
    CHECK(browser >= 0 && expect_http_open(pair->data, &stream_id) == 0, "POST request");
    CHECK(read_request_body(pair->data, stream_id, 0U, &received) == 0 && received == 65536U,
          "the client got the 64 KiB body (%zu)", received);
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 1U, NULL, NULL, 0U) == 0, "client RST before head");
    CHECK(expect_browser_status(browser, 502, NULL, -1) == 0, "502 for the reset exchange");
    close_fd(&browser);
    up += 65536;
    CHECK(expect_usage(server, pair->runtime.client_id, "HTTP_ROUTE", key, up, down, &row) == 0,
          "an exchange reset before any head must count the request body the client got");

    /* 4 */
    browser = browser_post(server, pair, "/cut-upload", INITIAL_WINDOW + 1U);
    CHECK(browser >= 0 && expect_http_open(pair->data, &stream_id) == 0, "large POST request");
    CHECK(read_request_body(pair->data, stream_id, INITIAL_WINDOW, &received) == 0 && received == INITIAL_WINDOW,
          "the client got its window of the body (%zu)", received);
    CHECK(send_nat(pair->data, ST_NAT_RST, 0U, stream_id, 1U, NULL, NULL, 0U) == 0, "client RST during upload");
    CHECK(expect_browser_status(browser, 502, NULL, -1) == 0, "502 for the cut upload");
    close_fd(&browser);
    /* Java counts what it read from the caller: the last byte, read and waiting for the window, too. */
    up += INITIAL_WINDOW + 1U;
    CHECK(expect_usage(server, pair->runtime.client_id, "HTTP_ROUTE", key, up, down, &row) == 0,
          "an upload cut short must count the body bytes read from the caller");

    /* 5 */
    CHECK(open_http_stream(server, pair, "/caller-leaves", &browser, &stream_id) == 0, "request");
    CHECK(send_nat(pair->data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) == 0, "head");
    memset(&response, 0, sizeof(response));
    response.fd = browser;
    response.timeout_ms = 2000;
    read_browser_response(&response);
    CHECK(response.status == 200, "the browser got the head");
    close_fd(&browser);
    long long sent = 0;
    int reset = 0;
    for (int i = 0; !reset && sent + (long long)DATA_CHUNK <= (long long)INITIAL_WINDOW; ++i) {
        CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, chunk, sizeof(chunk)) == 0, "DATA");
        sent += (long long)sizeof(chunk);
        long long wait_until = monotonic_ms() + 100;
        st_nat_message message;
        while (!reset && next_nat_frame(pair->data, wait_until, &message) == 1) {
            reset = message.stream_id == stream_id && message.type == ST_NAT_RST;
            st_nat_message_free(&message);
        }
    }
    uint32_t reset_code = 0U;
    CHECK(reset || wait_rst(pair->data, stream_id, &reset_code) == 0,
          "the server must reset the stream once the public caller is gone");
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        CHECK(read_usage(server, pair->runtime.client_id, "HTTP_ROUTE", key, &row) == 0, "route row");
        if (row.found && row.upload == up && row.download > down) {
            break;
        }
        CHECK(monotonic_ms() < deadline, "an exchange its caller left must count what was relayed: %lld/%lld after %lld",
              row.upload, row.download, down);
        sleep_ms(50);
    }
    CHECK(row.download - down >= (long long)DATA_CHUNK && row.download - down <= sent,
          "counted %lld of the %lld bytes the client sent", row.download - down, sent);
    down = row.download;
    CHECK(expect_usage(server, pair->runtime.client_id, NULL, NULL, up, down, &row) == 0,
          "the client's day must hold the route's counts");
    return 0;
}

/*
 * A route whose target is long and not ASCII: the row is named "route -> targetBaseUrl" in full,
 * as Java writes it, where C cut the target at 380 bytes, inside a character here.
 */
static int check_http_resource_name(test_server *server)
{
    CHECK(admin_login(server) == 0, "admin login");
    char target[512];
    size_t used = (size_t)snprintf(target, sizeof(target), "http://127.0.0.1:9/");
    while (used + 3U < 460U) {
        memcpy(target + used, "\xe8\xb7\xaf", 3U); /* 路 */
        used += 3U;
    }
    target[used] = '\0';
    client_pair pair;
    memset(&pair, 0, sizeof(pair));
    pair.control = -1;
    pair.data = -1;
    pair.public_port = pick_free_port();
    char reason[256];
    st_storage_http_route route;
    CHECK(create_credential(server->db_path, "ck_long_route", "long-route-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_long_route", "long-route-secret", "machine-long-route", "long-route",
                            &pair.runtime) == 0,
          "http login");
    CHECK(create_mapping(server->db_path, pair.runtime.client_id, pair.public_port) == 0, "mapping");
    CHECK(st_storage_create_http_route_for_client(server->db_path, pair.runtime.client_id, ROUTE, target, 1, 0, 0, 0,
                                                  0, 0, NULL, NULL, &route) == 0,
          "HTTP route");
    CHECK(channel_login(server->control_port, &pair.runtime, "control", &pair.control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    int failed = login_data(server, &pair) != 0;
    int browser = -1;
    uint32_t stream_id = 0U;
    failed = failed || open_http_stream(server, &pair, "/", &browser, &stream_id) != 0
        || send_nat(pair.data, ST_NAT_OPEN, 0U, stream_id, 0U, RESPONSE_HEAD, NULL, 0U) != 0
        || send_nat(pair.data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "ok", 2U) != 0
        || send_nat(pair.data, ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U) != 0
        || expect_browser_status(browser, 200, NULL, 1) != 0;
    close_fd(&browser);
    usage_row row;
    failed = failed || expect_usage(server, pair.runtime.client_id, "HTTP_ROUTE", "http:" ROUTE, 0, 2, &row) != 0;
    char expected[1024];
    snprintf(expected, sizeof(expected), "%s -> %s", ROUTE, target);
    if (!failed && (row.resource_id != route.id || strcmp(row.resource_name, expected) != 0)) {
        fprintf(stderr, "route row %lld named %zu bytes \"%s\", expected %lld and %zu bytes\n", row.resource_id,
                strlen(row.resource_name), row.resource_name, route.id, strlen(expected));
        failed = 1;
    }
    pair_close(&pair);
    return failed;
}

/* ------------------------------------------------------------------------------------------- */
/* WebSocket                                                                                     */

/* Opens a route WebSocket: the browser socket after its 101, and the stream the client was given. */
static int open_route_websocket(const test_server *server, const client_pair *pair, int *browser, uint32_t *stream_id)
{
    char client[768];
    char request[1536];
    url_encode(pair->runtime.client_name, client, sizeof(client));
    int len = snprintf(request, sizeof(request),
                       "GET /http/%s/%s/socket HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\n"
                       "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Sec-WebSocket-Version: 13\r\n\r\n",
                       client, ROUTE);
    *browser = len > 0 && (size_t)len < sizeof(request) ? browser_raw(server, request, (size_t)len) : -1;
    CHECK(*browser >= 0, "browser connect");
    CHECK(expect_http_open(pair->data, stream_id) == 0, "no WebSocket OPEN reached the client");
    char head[1024];
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used + 1U < sizeof(head) && (used < 4U || memcmp(head + used - 4U, "\r\n\r\n", 4U) != 0)) {
        CHECK(recv_exact(*browser, (uint8_t *)head + used, 1U, deadline) == 1, "101 head");
        ++used;
    }
    head[used] = '\0';
    CHECK(strncmp(head, "HTTP/1.1 101 ", 13U) == 0, "upgrade answered %s", head);
    return 0;
}

/* One SWS2 binary envelope of payload_len bytes, as the client sends it. */
static int send_envelope(int data_fd, uint32_t stream_id, size_t payload_len, size_t *encoded_len)
{
    uint8_t payload[256];
    memset(payload, 'w', sizeof(payload));
    st_admin_sws2_frame frame = {.opcode = 0x2U, .fin = 1, .rsv = 0U, .close_code = 0U,
                                 .payload = payload, .payload_len = payload_len};
    uint8_t *encoded = st_admin_sws2_encode(&frame, encoded_len);
    int rc = encoded == NULL ? -1 : send_nat(data_fd, ST_NAT_DATA, 0U, stream_id, 0U, NULL, encoded, *encoded_len);
    free(encoded);
    return rc;
}

/*
 * Three 100-byte binary messages from the client, two 50-byte ones from the browser, then 20
 * bytes that are no envelope: Java counts 3 x 112 + 20 = 356 bytes up for the client, before it
 * checks them, nothing down and no resource row. C counted nothing.
 */
static int check_websocket_upload(test_server *server, client_pair *pair)
{
    CHECK(admin_login(server) == 0, "admin login");
    int browser = -1;
    uint32_t stream_id = 0U;
    CHECK(open_route_websocket(server, pair, &browser, &stream_id) == 0, "route WebSocket");
    long long counted = 0;
    for (int i = 0; i < 3; ++i) {
        size_t encoded_len = 0U;
        CHECK(send_envelope(pair->data, stream_id, 100U, &encoded_len) == 0 && encoded_len == 112U,
              "client envelope (%zu bytes)", encoded_len);
        counted += (long long)encoded_len;
        uint8_t frame[102];
        CHECK(recv_exact(browser, frame, sizeof(frame), monotonic_ms() + IO_TIMEOUT_MS) == 1
                  && frame[0] == 0x82U && frame[1] == 100U,
              "the browser got message %d", i);
    }
    for (int i = 0; i < 2; ++i) {
        uint8_t frame[56];
        frame[0] = 0x82U;
        frame[1] = 0x80U | 50U;
        memset(frame + 2, 0x5a, 4U);
        memset(frame + 6, 'b' ^ 0x5a, 50U);
        CHECK(send_all(browser, frame, sizeof(frame)) == 0, "browser message");
        st_nat_message message;
        CHECK(expect_nat_frame(pair->data, ST_NAT_DATA, &message) == 0 && message.stream_id == stream_id,
              "the browser's message reached the client");
        st_nat_message_free(&message);
    }
    usage_row row;
    CHECK(expect_usage(server, pair->runtime.client_id, NULL, NULL, counted, 0, &row) == 0,
          "the client's envelopes must be its upload, the browser's not counted");
    CHECK(send_nat(pair->data, ST_NAT_DATA, 0U, stream_id, 0U, NULL, "not an SWS2 envelope", 20U) == 0,
          "invalid envelope");
    CHECK(expect_rst(pair->data, stream_id, ST_ADMIN_DIRECT_WS_RST_INVALID_SWS2) == 0, "RST 30 for the invalid envelope");
    counted += 20;
    CHECK(expect_usage(server, pair->runtime.client_id, NULL, NULL, counted, 0, &row) == 0,
          "an envelope is counted before it is checked");
    close_fd(&browser);
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/traffic/resources?clientId=%lld&flush=true", pair->runtime.client_id);
    int status = 0;
    char *body = NULL;
    CHECK(http_request(server->admin_port, "GET", path, NULL, admin_token, &status, &body) == 0 && status == 200,
          "resource list");
    int empty = body != NULL && strcmp(body, "[]") == 0;
    if (!empty) fprintf(stderr, "resource rows: %s\n", body == NULL ? "" : body);
    free(body);
    CHECK(empty, "WebSocket traffic must not write a resource row");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* When the counts are written                                                                   */

/* "<upload>/<download>" of the client's day as stored, "-1/-1" when there is no row. */
static int stored_day(const char *db_path, long long client_id, char *out, size_t out_len)
{
    return db_scalar(db_path,
                     "SELECT COALESCE(SUM(upload_bytes), -1) || '/' || COALESCE(SUM(download_bytes), -1) "
                     "FROM traffic_usage WHERE client_id = ?",
                     NULL, client_id, out, out_len);
}

/* GETs path as the administrator until the stored day reads expected: each such GET flushes. */
static int expect_flushed_by(const test_server *server, long long client_id, const char *path, const char *expected)
{
    char stored[64] = "";
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        int status = 0;
        char *body = NULL;
        int rc = http_request(server->admin_port, "GET", path, NULL, admin_token, &status, &body);
        free(body);
        CHECK(rc == 0 && status == 200, "GET %s answered %d", path, status);
        CHECK(stored_day(server->db_path, client_id, stored, sizeof(stored)) == 0, "stored day");
        if (strcmp(stored, expected) == 0) {
            return 0;
        }
        CHECK(monotonic_ms() < deadline, "GET %s left the day at %s, expected %s", path, stored, expected);
        sleep_ms(50);
    }
}

/*
 * With an hour between periodic flushes, the counts reach the database only where Java's
 * TrafficUsageService flushes them: not on each chunk (C wrote two rows per chunk), not on a read
 * of /api/admin/traffic without flush, but on one with flush=true, on GET /api/admin/overview,
 * /api/admin/clients and /api/admin/clients/{id}, and at shutdown.
 */
static int check_flush_points(test_server *server, client_pair *pair)
{
    CHECK(admin_login(server) == 0, "admin login");
    long long id = pair->runtime.client_id;
    char stored[64] = "";
    char path[128];
    CHECK(relay_tcp(pair, 3000U, 700U) == 0, "relay");
    sleep_ms(300);
    CHECK(stored_day(server->db_path, id, stored, sizeof(stored)) == 0 && strcmp(stored, "-1/-1") == 0,
          "the bytes must stay in memory until a flush, the day already reads %s", stored);
    snprintf(path, sizeof(path), "/api/admin/traffic?clientId=%lld", id);
    int status = 0;
    char *body = NULL;
    CHECK(http_request(server->admin_port, "GET", path, NULL, admin_token, &status, &body) == 0 && status == 200
              && body != NULL && strcmp(body, "[]") == 0,
          "a read without flush=true must not flush: %s", body == NULL ? "" : body);
    free(body);
    snprintf(path, sizeof(path), "/api/admin/traffic?clientId=%lld&flush=true", id);
    CHECK(expect_flushed_by(server, id, path, "700/3000") == 0, "flush=true");

    CHECK(relay_tcp(pair, 1000U, 100U) == 0, "relay");
    CHECK(expect_flushed_by(server, id, "/api/admin/overview", "800/4000") == 0, "overview");
    char *overview = NULL;
    CHECK(http_request(server->admin_port, "GET", "/api/admin/overview", NULL, admin_token, &status, &overview) == 0
              && status == 200 && overview != NULL && strstr(overview, "\"uploadBytes\":800,\"downloadBytes\":4000") != NULL,
          "the overview counts the flushed bytes: %s", overview == NULL ? "" : overview);
    free(overview);
    CHECK(relay_tcp(pair, 500U, 50U) == 0, "relay");
    CHECK(expect_flushed_by(server, id, "/api/admin/clients", "850/4500") == 0, "client list");
    CHECK(relay_tcp(pair, 20U, 2U) == 0, "relay");
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", id);
    CHECK(expect_flushed_by(server, id, path, "852/4520") == 0, "client detail");

    CHECK(relay_tcp(pair, 7U, 3U) == 0, "relay");
    sleep_ms(300);
    CHECK(stored_day(server->db_path, id, stored, sizeof(stored)) == 0 && strcmp(stored, "852/4520") == 0,
          "nothing asked for a flush, the day reads %s", stored);
    CHECK(server_stop(server, 20000) == 0, "server stop");
    CHECK(stored_day(server->db_path, id, stored, sizeof(stored)) == 0 && strcmp(stored, "855/4527") == 0,
          "the shutdown must flush what was still counted, the day reads %s", stored);
    return 0;
}

/* With SPECUS_TRAFFIC_FLUSH_INTERVAL_MS=200 the counts reach the database on their own. */
static int check_periodic_flush(test_server *server, client_pair *pair)
{
    CHECK(relay_tcp(pair, 3000U, 700U) == 0, "relay");
    char stored[64] = "";
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (stored_day(server->db_path, pair->runtime.client_id, stored, sizeof(stored)) == 0
           && strcmp(stored, "700/3000") != 0 && monotonic_ms() < deadline) {
        sleep_ms(50);
    }
    CHECK(strcmp(stored, "700/3000") == 0, "the periodic flush did not write the day: %s", stored);
    return 0;
}

static long long db_number(const char *db_path, const char *sql)
{
    char text[64];
    return db_scalar(db_path, sql, NULL, 0, text, sizeof(text)) == 0 && text[0] != '\0' ? atoll(text) : -1;
}

/*
 * In this process, without a server: counts stay in memory until a flush; a flush that cannot
 * write (a database that cannot be opened) keeps them, and the next one writes them with what was
 * counted since, as Java adds a failed flush's bytes back to its counters. A client that does not
 * exist is dropped. Resource rows take the resource as the flush finds it: the mapping and the
 * route by id and full name, then "端口 9300" and no id once the mapping is gone.
 */
static int test_failed_flush_keeps_counts(void)
{
    char dir[] = "/tmp/specus-c-traffic-flush-XXXXXX";
    CHECK(mkdtemp(dir) != NULL, "scratch directory");
    char path[128];
    char missing[160];
    snprintf(path, sizeof(path), "%s/usage.db", dir);
    snprintf(missing, sizeof(missing), "%s/missing/usage.db", dir);
    st_storage_client client;
    st_storage_mapping mapping;
    st_storage_http_route route;
    int failed = st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "tenant-flush", "flush-client", "owner", 1, 30, &client) != 0
        || st_storage_create_mapping_for_client(path, client.id, 9300, "10.0.0.5", 22, 1, 0, &mapping) != 0
        || st_storage_create_http_route_for_client(path, client.id, "web", "http://10.0.0.6:8080/app", 1, 0, 0, 0, 0,
                                                   0, NULL, NULL, &route) != 0;
    if (!failed) {
        st_traffic_usage_record_tcp("flush-client", 9300, 10, 20);
        st_traffic_usage_record_http("flush-client", "web", 1, 2);
        st_traffic_usage_record_tcp("no-such-client", 9300, 5, 5);
        failed = db_number(path, "SELECT COUNT(*) FROM traffic_usage") != 0
            || db_number(path, "SELECT COUNT(*) FROM resource_traffic_usage") != 0;
        if (failed) fprintf(stderr, "counts were written before a flush\n");
    }
    if (!failed && st_traffic_usage_flush(missing) != -1) {
        fprintf(stderr, "a flush into a database that cannot be opened did not fail\n");
        failed = 1;
    }
    st_traffic_usage_record_tcp("flush-client", 9300, 100, 200);
    if (!failed && st_traffic_usage_flush(path) != 0) {
        fprintf(stderr, "the flush after the failed one failed\n");
        failed = 1;
    }
    char expected[512];
    char text[512];
    if (!failed) {
        snprintf(expected, sizeof(expected),
                 "day 111/222|HTTP_ROUTE http:web %lld web -> http://10.0.0.6:8080/app 1/2|"
                 "TCP_SPECUS tcp:9300 %lld 9300 -> 10.0.0.5:22 110/220",
                 route.id, mapping.id);
        failed = db_scalar(path,
                           "SELECT (SELECT 'day ' || upload_bytes || '/' || download_bytes FROM traffic_usage) || '|' || "
                           "(SELECT group_concat(row, '|') FROM (SELECT resource_type || ' ' || resource_key || ' ' || "
                           "COALESCE(resource_id, '-') || ' ' || resource_name || ' ' || upload_bytes || '/' || "
                           "download_bytes AS row FROM resource_traffic_usage ORDER BY resource_type))",
                           NULL, 0, text, sizeof(text)) != 0
            || strcmp(text, expected) != 0
            || db_number(path, "SELECT COUNT(*) FROM traffic_usage") != 1;
        if (failed) fprintf(stderr, "flushed rows\n%s\nexpected\n%s\n", text, expected);
    }
    if (!failed && (st_traffic_usage_flush(path) != 0
                    || db_number(path, "SELECT upload_bytes FROM traffic_usage") != 111)) {
        fprintf(stderr, "a flush with nothing counted changed the day\n");
        failed = 1;
    }
    if (!failed) {
        st_traffic_usage_record_tcp("flush-client", 9300, 1, 1);
        failed = st_storage_delete_mapping_by_id(path, mapping.id) != 0 || st_traffic_usage_flush(path) != 0
            || db_scalar(path, "SELECT COALESCE(resource_id, '-') || ' ' || resource_name || ' ' || upload_bytes "
                               "FROM resource_traffic_usage WHERE resource_key = 'tcp:9300'",
                         NULL, 0, text, sizeof(text)) != 0
            || strcmp(text, "- 端口 9300 111") != 0;
        if (failed) fprintf(stderr, "the row of a deleted mapping reads %s\n", text);
    }
    /* After the shutdown flush, a count (an exchange still finishing) is written at once. */
    if (!failed) {
        long long before = db_number(path, "SELECT upload_bytes FROM traffic_usage");
        setenv("SPECUS_TRAFFIC_FLUSH_INTERVAL_MS", "3600000", 1);
        failed = st_traffic_usage_start(path) != 0;
        st_traffic_usage_stop();
        unsetenv("SPECUS_TRAFFIC_FLUSH_INTERVAL_MS");
        st_traffic_usage_record_tcp("flush-client", 0, 5, 0);
        long long after = db_number(path, "SELECT upload_bytes FROM traffic_usage");
        failed = failed || after != before + 5;
        if (failed) fprintf(stderr, "a count after the shutdown flush: %lld, then %lld\n", before, after);
    }
    unlink(path);
    char journal[160];
    snprintf(journal, sizeof(journal), "%s-journal", path);
    unlink(journal);
    rmdir(dir);
    printf("%s a failed flush keeps its counts for the next one\n", failed ? "FAIL" : "ok  ");
    return failed;
}

static const char *const hour_between_flushes[] = {
    "SPECUS_CONTROL_READ_IDLE_SECONDS=900", "SPECUS_TRAFFIC_FLUSH_INTERVAL_MS=3600000", NULL
};

static const char *const quick_flushes[] = {
    "SPECUS_CONTROL_READ_IDLE_SECONDS=900", "SPECUS_TRAFFIC_FLUSH_INTERVAL_MS=200", NULL
};

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    int failures = test_failed_flush_keeps_counts();
    failures += run_check("TCP traffic: client to public is upload, public to client download", check_tcp_direction);
    failures += run_check("HTTP traffic counted on every outcome once the stream is open", check_http_outcomes);
    failures += run_scenario("HTTP route row named route -> target in full", check_http_resource_name, long_idle);
    failures += run_check("WebSocket envelopes from the client are its upload", check_websocket_upload);
    current_check = check_flush_points;
    failures += run_scenario("counts are written where Java flushes them", run_current_check, hour_between_flushes);
    current_check = check_periodic_flush;
    failures += run_scenario("counts are written by the periodic flush", run_current_check, quick_flushes);
    if (failures != 0) {
        fprintf(stderr, "%d traffic usage check(s) failed\n", failures);
        return 1;
    }
    printf("traffic usage tests passed\n");
    return 0;
}
