/* Reuse the real HTTP/JWT/SQLite/control/data harness, not its original test entry point.
 * Only the three cases below run here; nat_stream_tests still runs separately, unchanged. */
#define main st_prior_nat_stream_test_entry
#include "nat_stream_tests.c"
#undef main
#include "admin_http.h"

static int reference_mode;

static int reset_reason_case(test_server *server, client_pair *pair)
{
    int browser = -1;
    uint32_t stream = 0U;
    int failed = 1;
    const char *stage = "enable actual route detail capture";
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    int configured = sqlite3_open(server->db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "UPDATE http_route_mapping SET detail_capture_enabled=1 WHERE client_name=? AND route='app'",
                             -1, &statement, NULL) == SQLITE_OK
        && sqlite3_bind_text(statement, 1, pair->runtime.client_name, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    sqlite3_close(db);
    if (!configured) goto cleanup;
    const char *path = reference_mode == 0 ? "/admin/internal" : "/nul-log";
    const char *query = reference_mode == 0 ? "token=s3cret&user=root" : "token=s3cret";
    const char *method = reference_mode == 2 ? "POST" : "GET";
    stage = "open actual public HTTP stream";
    if (reference_mode == 2) {
        char client[768], head[1536];
        url_encode(pair->runtime.client_name, client, sizeof(client));
        int length = snprintf(head, sizeof(head), "POST /http/%s/app%s?%s HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            "Content-Length: %u\r\nConnection: close\r\n\r\n", client, path, query, INITIAL_WINDOW+1U);
        size_t total = (size_t)length + INITIAL_WINDOW + 1U;
        char *request = length <= 0 || (size_t)length >= sizeof(head) ? NULL : malloc(total);
        if (request == NULL) goto cleanup;
        memcpy(request, head, (size_t)length);
        memset(request+length, 'x', INITIAL_WINDOW+1U);
        browser = browser_raw(server, request, total);
        free(request);
        if (browser < 0 || expect_http_open(pair->data, &stream) != 0) goto cleanup;
    } else {
        char target[128];
        snprintf(target, sizeof(target), "%s?%s", path, query);
        if (open_http_stream(server, pair, target, &browser, &stream) != 0) goto cleanup;
    }
    stage = reference_mode == 2 ? "consume exact initial upload credit with no FIN possible"
        : "wait actual request FIN before sending upstream reset";
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    size_t uploaded = 0U;
    for (;;) {
        st_nat_message packet;
        if (next_nat_frame(pair->data, deadline, &packet) != 1) goto cleanup;
        if (packet.stream_id == stream && packet.type == ST_NAT_DATA) uploaded += packet.data_len;
        int finished = packet.stream_id == stream && packet.type == ST_NAT_FIN;
        st_nat_message_free(&packet);
        if (reference_mode == 2) {
            if (finished || uploaded > INITIAL_WINDOW) goto cleanup;
            if (uploaded == INITIAL_WINDOW) break;
        } else if (finished) break;
    }
    const char *metadata = reference_mode == 0
        ? "{\"reason\":\"dial http://10.20.30.40:8080/admin/internal?token=s3cret&user=root failed: connection refused\\r\\nX-Forged: yes\",\"failure\":\"connect-refused\"}"
        : "{\"reason\":\"a\\r\\nb\\tc\\u0000d\\u2028e\\\\f\",\"failure\":\"connect-refused\"}";
    const char *expected_reason = reference_mode == 0
        ? "dial http://10.20.30.40:8080/admin/internal?token=s3cret&user=root failed: connection refused\\r\\nX-Forged: yes"
        : "a\\r\\nb\\tc\\u0000d\\u2028e\\\\f";
    stage = "send classified client RST before any response head";
    if (send_nat(pair->data, ST_NAT_RST, 0U, stream, 1U, metadata, NULL, 0U) != 0) goto cleanup;
    browser_response response = {.fd=browser, .timeout_ms=IO_TIMEOUT_MS};
    read_browser_response(&response);
    stage = "generic public 502 must remain unchanged";
    const char *body = strstr(response.head, "\r\n\r\n");
    if (!response.eof || response.status != 502 || body == NULL
        || strcmp(body+4, "{\"error\":\"" ST_ADMIN_DIRECT_HTTP_RESET_BODY "\"}") != 0
        || strstr(response.head, "connect-refused") != NULL
        || strstr(response.head, "X-Forged") != NULL || strstr(response.head, "10.20.30.40") != NULL
        || strstr(response.head, "s3cret") != NULL || strstr(response.head, "http://") != NULL) goto cleanup;
    stage = "recorded method/path/query/error and zero upstream response bytes";
    if (wait_exchange_count(server, 1) != 0
        || exchange_field(server, ROUTE, 502, "client_name", pair->runtime.client_name) != 0
        || exchange_field(server, ROUTE, 502, "method", method) != 0
        || exchange_field(server, ROUTE, 502, "relative_path", path) != 0
        || exchange_field(server, ROUTE, 502, "raw_query", query) != 0
        || exchange_field(server, ROUTE, 502, "success", "0") != 0
        || exchange_field(server, ROUTE, 502, "error", expected_reason) != 0
        || exchange_field(server, ROUTE, 502, "response_bytes", "0") != 0) goto cleanup;
    if (reference_mode != 2 && exchange_field(server, ROUTE, 502, "request_bytes", "0") != 0) goto cleanup;
    stage = "same data connection remains usable";
    if (expect_data_connection_served(server, pair) != 0) goto cleanup;
    stage = "log contains the entire escaped reason and no raw carriage return";
    FILE *log = fopen(server->log_path, "rb");
    if (log == NULL) goto cleanup;
    char text[32768];
    size_t length = fread(text, 1U, sizeof(text)-1U, log);
    int read_failed = ferror(log);
    fclose(log);
    text[length] = '\0';
    if (read_failed || length == sizeof(text)-1U
        || strstr(text, expected_reason) == NULL || strchr(text, '\r') != NULL) goto cleanup;
    failed = 0;
cleanup:
    close_fd(&browser);
    if (failed) fprintf(stderr, "FAIL HTTP reset reason reference mode%d stage=%s\n", reference_mode, stage);
    else printf("HTTP reset reason reference mode%d: fixed public502, safe full reason and recorded fields, zero upstream bytes, same HTTP/TCP session alive passed\n", reference_mode);
    return failed;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    current_check = reset_reason_case;
    int failed = 0;
    const char *names[] = {"HTTP reset leaky reason after FIN", "HTTP reset NUL reason after FIN", "HTTP reset NUL reason during upload"};
    for (reference_mode=0; reference_mode<3; ++reference_mode)
        failed |= run_on_fresh_server(names[reference_mode], run_current_check, long_idle_with_capture);
    return failed;
}
