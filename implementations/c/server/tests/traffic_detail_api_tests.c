/*
 * The traffic detail API (/api/admin/traffic/http-exchanges, tcp-frames, tcp-streams and
 * inspection-status) against the semantics of Java TrafficResource, TrafficViewService and the two
 * Java stores (SpringDataElasticsearch*Store, Jpa*Store):
 *
 *   1. Elasticsearch, in process: exchanges recorded through the store, read over real HTTP from an
 *      admin listener on loopback with real management tokens. Field codes, whitespace tokens that
 *      must all match, case-insensitive substring on keyword fields with wildcard characters taken
 *      literally, numeric id/client/status matches, the method term, the body type filter with its
 *      Content-Type patterns, route trimming, the administrator's tenant-wide view (deleted
 *      clients included) and owner scoping; the write queue and flush=true.
 *   2. Elasticsearch, real server process: TCP frames captured from a relayed stream reach the fake
 *      cluster through the write queue, the stream reads in capture order a page at a time, and
 *      what is still queued at SIGTERM is written out.
 *   3. SQLite, in process: the same stream contract, a 1000-frame page and list pages larger than
 *      the listener's 32 KiB default answer, and the body type filter.
 *
 * Run by scripts/elasticsearch_traffic_test.sh, which starts the fake cluster:
 *   traffic_detail_api_tests <database> <specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "elasticsearch_traffic.h"
#include "json.h"
#include "protocol.h"
#include "security.h"
#include "server_harness.h"
#include "storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define JWT_SECRET "traffic-detail-api-jwt-secret-long-enough-2026"

static char db_path[512];
static int listener_port = 0;

/* ------------------------------------------------------------------------------------------- */
/* Fixture                                                                                       */

static int sql_exec(const char *statement)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, statement, NULL, NULL, &error) == SQLITE_OK ? 0 : -1;
    if (rc != 0) fprintf(stderr, "sql failed (%s): %s\n", statement, error == NULL ? "sqlite error" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

static long long create_client(const char *tenant, const char *name, const char *owner)
{
    char statement[512];
    snprintf(statement, sizeof(statement),
             "INSERT INTO client_account(tenant_id, client_name, owner_username) VALUES ('%s', '%s', '%s')",
             tenant, name, owner);
    if (sql_exec(statement) != 0) return -1;
    char id[32];
    if (db_scalar(db_path, "SELECT id FROM client_account WHERE client_name = ?", name, 0, id, sizeof(id)) != 0) {
        return -1;
    }
    return strtoll(id, NULL, 10);
}

static int create_user(const char *username, const char *tenant, const char *role)
{
    st_storage_management_user user;
    return st_storage_create_management_user(db_path, username, tenant, "unused-password-hash", role, 1, &user);
}

static int issue_token(const char *username, const char *tenant, const char *role, char *out, size_t out_len)
{
    return st_security_issue_local_token(username, tenant, role, JWT_SECRET, 600, out, out_len);
}

static int start_listener(st_admin_server *server)
{
    memset(server, 0, sizeof(*server));
    server->fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (st_admin_server_start(server, 0, "") != 0
        || getsockname(server->fd, (struct sockaddr *)&address, &address_len) != 0) {
        return -1;
    }
    listener_port = ntohs(address.sin_port);
    return 0;
}

/* GET on the in-process listener (port > 0) or a server's admin port; *body is the caller's. */
static int api_get(int port, const char *path, const char *token, char **body)
{
    int status = 0;
    *body = NULL;
    if (http_request(port, "GET", path, NULL, token, &status, body) != 0) return -1;
    return status;
}

static long long json_number(const char *json, const char *key)
{
    long long value = -1;
    return st_json_get_i64(json, key, &value) == 0 ? value : -1;
}

/* The statusCode of every item, in order: "404,200". */
static void item_status_codes(const char *body, char *out, size_t out_len)
{
    char **items = NULL;
    size_t count = 0U;
    out[0] = '\0';
    if (st_json_get_raw_array(body, "items", &items, &count) != 0) {
        snprintf(out, out_len, "<no items>");
        return;
    }
    size_t used = 0U;
    for (size_t i = 0; i < count; ++i) {
        long long code = json_number(items[i], "statusCode");
        int written = snprintf(out + used, out_len - used, "%s%lld", i == 0 ? "" : ",", code);
        if (written < 0 || (size_t)written >= out_len - used) break;
        used += (size_t)written;
    }
    st_json_free_string_array(items, count);
}

/* Each frame as direction initial and index, in order: "P0,P1,C0". */
static void item_frames(const char *body, char *out, size_t out_len)
{
    char **items = NULL;
    size_t count = 0U;
    out[0] = '\0';
    if (st_json_get_raw_array(body, "items", &items, &count) != 0) {
        snprintf(out, out_len, "<no items>");
        return;
    }
    size_t used = 0U;
    for (size_t i = 0; i < count; ++i) {
        char *direction = st_json_get_top_level_string(items[i], "direction");
        int written = snprintf(out + used, out_len - used, "%s%c%lld", i == 0 ? "" : ",",
                               direction != NULL && direction[0] == 'C' ? 'C' : 'P',
                               json_number(items[i], "frameIndex"));
        free(direction);
        if (written < 0 || (size_t)written >= out_len - used) break;
        used += (size_t)written;
    }
    st_json_free_string_array(items, count);
}

typedef struct {
    const char *tenant;
    long long client_id;
    const char *client_name;
    const char *route;
    const char *method;
    const char *path;
    int status;
    const char *error;
    const char *remote;
    const char *response_content_type;
    const char *stored_body_type;
    const char *request_headers;
    const char *response_body;
} exchange_spec;

static int record_exchange(const exchange_spec *spec)
{
    size_t response_len = spec->response_body == NULL ? 0U : strlen(spec->response_body);
    st_storage_http_exchange_record record = {
        .tenant_id = spec->tenant,
        .client_id = spec->client_id,
        .client_name = spec->client_name,
        .route = spec->route,
        .resource_id = 7,
        .resource_name = "Traffic API route",
        .method = spec->method,
        .relative_path = spec->path,
        .raw_query = "page=1",
        .status_code = spec->status,
        .success = spec->status < 400,
        .error = spec->error,
        .remote_address = spec->remote == NULL ? "192.0.2.10" : spec->remote,
        .request_bytes = 0,
        .response_bytes = (long long)response_len,
        .elapsed_ms = 3,
        .request_content_type = "text/plain",
        .response_content_type = spec->response_content_type,
        .response_body_type = spec->stored_body_type,
        .request_headers = spec->request_headers == NULL ? "Accept: */*" : spec->request_headers,
        .response_headers = "Server: test",
        .response_body = (const uint8_t *)spec->response_body,
        .response_body_len = response_len,
        .captured_at = "2026-10-07T01:02:03Z"
    };
    return st_storage_record_http_exchange(db_path, &record);
}

/* ------------------------------------------------------------------------------------------- */
/* 1. Elasticsearch search semantics over the management API                                     */

static char admin_token[1024];
static char owner_token[1024];
static char foreign_token[1024];
static long long owned_id = 0;
static long long other_id = 0;
static long long gone_id = 0;

/* GET path as the administrator; checks the status, total and the items' status codes. */
static int expect_exchanges(const char *token, const char *path, long long total, const char *codes)
{
    char *body = NULL;
    int status = api_get(listener_port, path, token, &body);
    char seen[256];
    item_status_codes(body == NULL ? "" : body, seen, sizeof(seen));
    long long seen_total = body == NULL ? -1 : json_number(body, "total");
    int ok = status == 200 && seen_total == total && strcmp(seen, codes) == 0;
    if (!ok) {
        fprintf(stderr, "GET %s: status %d, total %lld, items [%s]; expected total %lld, items [%s]\n%s\n",
                path, status, seen_total, seen, total, codes, body == NULL ? "" : body);
    }
    free(body);
    return ok ? 0 : -1;
}

static int test_elasticsearch_search(void)
{
    CHECK(create_user("es-admin", "t-es", "ADMIN") == 0 && create_user("es-owner", "t-es", "USER") == 0
              && create_user("es-other", "t-es", "USER") == 0 && create_user("es-foreign", "t-foreign", "ADMIN") == 0,
          "management users");
    CHECK(issue_token("es-admin", "t-es", "ADMIN", admin_token, sizeof(admin_token)) == 0
              && issue_token("es-owner", "t-es", "USER", owner_token, sizeof(owner_token)) == 0
              && issue_token("es-foreign", "t-foreign", "ADMIN", foreign_token, sizeof(foreign_token)) == 0,
          "tokens");
    owned_id = create_client("t-es", "es-owned", "es-owner");
    other_id = create_client("t-es", "es-other-client", "es-other");
    gone_id = create_client("t-es", "es-gone", "es-owner");
    long long foreign_id = create_client("t-foreign", "es-foreign-client", "es-foreign");
    CHECK(owned_id > 0 && other_id > 0 && gone_id > 0 && foreign_id > 0, "clients");

    /* Each exchange has its own status code, which the checks below list. */
    exchange_spec specs[] = {
        /* A JSON response whose stored type says otherwise: found for json by its Content-Type. */
        {"t-es", owned_id, "es-owned", "api", "GET", "/v1/items", 200, NULL, "192.0.2.10",
         "application/json; charset=utf-8", "binary", NULL, "{\"a\":1}"},
        {"t-es", owned_id, "es-owned", "files", "POST", "/upload/report", 404, "upstream timed out", "10.0.0.7",
         "text/html", NULL, "X-Trace: Alpha-42", "<p>hello world</p>"},
        {"t-es", other_id, "es-other-client", "api", "GET", "/v1/other", 500, NULL, "192.0.2.11",
         "text/plain", NULL, NULL, "boom"},
        /* An empty body; its client is deleted below. */
        {"t-es", gone_id, "es-gone", "legacy", "DELETE", "/old", 204, NULL, "192.0.2.12",
         NULL, NULL, NULL, NULL},
        {"t-foreign", foreign_id, "es-foreign-client", "api", "GET", "/v1/foreign", 202, NULL, "192.0.2.13",
         "application/json", NULL, NULL, "{}"},
    };
    for (size_t i = 0; i < sizeof(specs) / sizeof(specs[0]); ++i) {
        CHECK(record_exchange(&specs[i]) == 0, "record exchange %zu", i);
    }
    CHECK(sql_exec("DELETE FROM client_account WHERE client_name = 'es-gone'") == 0, "delete es-gone");

    /* Nothing is written before the writer runs (its interval is long here); flush=true sends it. */
    char *body = NULL;
    CHECK(api_get(listener_port, "/api/admin/traffic/inspection-status", admin_token, &body) == 200
              && json_number(body, "pendingHttp") == 5 && strstr(body, "\"lastFlushedAt\":null") != NULL,
          "five exchanges must wait in the queue: %s", body == NULL ? "" : body);
    free(body);
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges", 0, "") == 0,
          "queued exchanges must not be searchable before a flush");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?flush=true", 4, "204,500,404,200") == 0,
          "flush=true and the administrator's tenant-wide view, deleted client included");
    CHECK(api_get(listener_port, "/api/admin/traffic/inspection-status", admin_token, &body) == 200
              && json_number(body, "pendingHttp") == 0 && strstr(body, "\"lastFlushedAt\":\"20") != NULL,
          "the queue must be empty after the flush: %s", body == NULL ? "" : body);
    free(body);

    /* HttpTrafficSearchField: summary keyword fields match a case-insensitive substring. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?q=get", 2, "500,200") == 0, "q=get");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?q=OWNED", 2, "404,200") == 0,
          "q=OWNED matches the client name");
    /* The method field is one upper-cased term. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=method&q=post", 1, "404") == 0,
          "field=method");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=METHOD&q=pos", 0, "") == 0,
          "the method is a whole term");
    /* Numbers: status code, id and client id in the summary; the status field holds codes only. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?q=404", 1, "404") == 0, "q=404");
    char path[256];
    snprintf(path, sizeof(path), "/api/admin/traffic/http-exchanges?field=client&q=%lld", other_id);
    CHECK(expect_exchanges(admin_token, path, 1, "500") == 0, "field=client with a client id");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=status&q=abc", 0, "") == 0,
          "a word in the status field matches nothing");
    /* Every token must match. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?q=upstream%20timed", 1, "404") == 0,
          "two tokens");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?q=upstream%20nothing", 0, "") == 0,
          "a token without a match");
    /* Wildcard characters in the search text are literal. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=remote&q=0.0.7", 1, "404") == 0,
          "field=remote substring");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=remote&q=10.0.0.%2A", 0, "") == 0,
          "* is not a wildcard");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=remote&q=10.0.0.%3F", 0, "") == 0,
          "? is not a wildcard");
    /* Header and body fields; their constant names work too; unknown codes search the summary. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=requestHeaders&q=x-trace", 1, "404") == 0,
          "field=requestHeaders");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=REQUEST_HEADERS&q=alpha", 1, "404") == 0,
          "field=REQUEST_HEADERS");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=headers&q=alpha", 0, "") == 0,
          "an unknown field code is the summary, which leaves headers out");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=all&q=alpha", 1, "404") == 0,
          "field=all reads headers");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=responseBody&q=hello", 1, "404") == 0,
          "field=responseBody");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?field=path&q=items", 1, "200") == 0,
          "field=path");

    /* responseBodyType: normalized, matched by stored type, empty body or Content-Type. */
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?responseBodyType=JSON", 1, "200") == 0,
          "responseBodyType=JSON");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?responseBodyType=empty", 1, "204") == 0,
          "responseBodyType=empty");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?responseBodyType=nonsense", 4,
                           "204,500,404,200") == 0,
          "an unknown body type filters nothing");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?responseBodyType=%20&responseDataType=html",
                           1, "404") == 0,
          "a blank responseBodyType gives way to responseDataType");
    CHECK(expect_exchanges(admin_token, "/api/admin/traffic/http-exchanges?route=%20api%20", 2, "500,200") == 0,
          "the route is trimmed");

    /* Scope: the administrator names a deleted client; an owner sees its own clients only. */
    snprintf(path, sizeof(path), "/api/admin/traffic/http-exchanges?clientId=%lld", gone_id);
    CHECK(expect_exchanges(admin_token, path, 1, "204") == 0, "an administrator filters by a deleted client");
    CHECK(expect_exchanges(owner_token, "/api/admin/traffic/http-exchanges", 2, "404,200") == 0, "owner view");
    snprintf(path, sizeof(path), "/api/admin/traffic/http-exchanges?clientId=%lld", other_id);
    CHECK(expect_exchanges(owner_token, path, 0, "") == 0, "an owner naming another's client");
    CHECK(expect_exchanges(foreign_token, "/api/admin/traffic/http-exchanges", 1, "202") == 0, "another tenant");

    /* Detail: by id within the same scope; the paging fields of the list. */
    CHECK(api_get(listener_port, "/api/admin/traffic/http-exchanges?q=500&size=1", admin_token, &body) == 200
              && json_number(body, "size") == 1 && json_number(body, "totalPages") == 1,
          "paging fields: %s", body == NULL ? "" : body);
    char **items = NULL;
    size_t count = 0U;
    char *exchange_id = NULL;
    if (st_json_get_raw_array(body, "items", &items, &count) == 0 && count == 1U) {
        exchange_id = st_json_get_top_level_string(items[0], "id");
    }
    st_json_free_string_array(items, count);
    free(body);
    CHECK(exchange_id != NULL, "exchange id");
    snprintf(path, sizeof(path), "/api/admin/traffic/http-exchanges/%s", exchange_id);
    free(exchange_id);
    CHECK(api_get(listener_port, path, admin_token, &body) == 200 && json_number(body, "statusCode") == 500,
          "administrator detail: %s", body == NULL ? "" : body);
    free(body);
    CHECK(api_get(listener_port, path, owner_token, &body) == 404, "another owner's exchange must be 404");
    free(body);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* 2. Elasticsearch through a real server process                                                 */

static int expect_data_payload(int data_fd, const char *payload)
{
    st_nat_message message;
    if (expect_nat_frame(data_fd, ST_NAT_DATA, &message) != 0) return -1;
    int ok = message.data_len == strlen(payload) && memcmp(message.data, payload, message.data_len) == 0;
    st_nat_message_free(&message);
    return ok ? 0 : -1;
}

static int client_data(int data_fd, uint32_t stream_id, int public_fd, const char *payload)
{
    st_buffer frame = st_protocol_encode_nat_message(ST_NAT_DATA, 0U, stream_id, 0U, NULL,
                                                     (const uint8_t *)payload, strlen(payload));
    if (send_buffer(data_fd, &frame) != 0) return -1;
    char received[64] = {0};
    return recv_exact(public_fd, (uint8_t *)received, strlen(payload), monotonic_ms() + IO_TIMEOUT_MS) == 1
               && strcmp(received, payload) == 0 ? 0 : -1;
}

static int pending_tcp(const test_server *server, const char *token)
{
    char *body = NULL;
    int status = api_get(server->admin_port, "/api/admin/traffic/inspection-status", token, &body);
    long long pending = status == 200 ? json_number(body, "pendingTcp") : -1;
    free(body);
    return (int)pending;
}

static int scenario_relayed_stream(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control = -1;
    int data = -1;
    int public_fd = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_traffic_es", "traffic-es-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_traffic_es", "traffic-es-secret", "machine-traffic-es", "tess", &runtime) == 0,
          "client login");
    CHECK(create_mapping(server->db_path, runtime.client_id, public_port) == 0, "mapping");
    sqlite3 *db = NULL;
    int updated = sqlite3_open(server->db_path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, "UPDATE specus_mapping SET detail_capture_enabled = 1", NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    CHECK(updated, "mapping detail capture");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    CHECK(channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) == 1,
          "data login: %s", reason);
    CHECK(nat_register(data, runtime.client_name, public_port, 9) == 0, "REGISTER");
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(data, public_port, &public_fd, &stream_id) == 0, "public OPEN");

    /* Two frames from the public side, then one from the client: capture order P0, P1, C0. */
    CHECK(send_all(public_fd, (const uint8_t *)"pub-0", 5U) == 0 && expect_data_payload(data, "pub-0") == 0,
          "pub-0 relayed");
    CHECK(send_all(public_fd, (const uint8_t *)"pub-1", 5U) == 0 && expect_data_payload(data, "pub-1") == 0,
          "pub-1 relayed");
    CHECK(client_data(data, stream_id, public_fd, "cli-0") == 0, "cli-0 relayed");

    int status = 0;
    char *body = NULL;
    char login[256];
    snprintf(login, sizeof(login), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    CHECK(http_request(server->admin_port, "POST", "/auth/login", login, NULL, &status, &body) == 0 && status == 200,
          "admin login %d", status);
    char *token = st_json_get_string(body, "accessToken");
    free(body);
    CHECK(token != NULL, "access token");
    char token_copy[1024];
    snprintf(token_copy, sizeof(token_copy), "%s", token);
    free(token);

    /* The relay did not wait for Elasticsearch: the frames are queued until a flush. */
    long long queued_deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (pending_tcp(server, token_copy) < 3 && monotonic_ms() < queued_deadline) sleep_ms(50);
    CHECK(pending_tcp(server, token_copy) == 3, "three captured frames must be queued, not %d",
          pending_tcp(server, token_copy));
    CHECK(api_get(server->admin_port, "/api/admin/traffic/tcp-frames?flush=true&size=10", token_copy, &body) == 200
              && json_number(body, "total") == 3,
          "tcp-frames after flush=true: %s", body == NULL ? "" : body);
    char **items = NULL;
    size_t count = 0U;
    char *channel_id = NULL;
    if (st_json_get_raw_array(body, "items", &items, &count) == 0 && count > 0U) {
        channel_id = st_json_get_top_level_string(items[0], "channelId");
    }
    st_json_free_string_array(items, count);
    free(body);
    CHECK(channel_id != NULL && channel_id[0] != '\0', "channel id");
    CHECK(pending_tcp(server, token_copy) == 0, "the flush emptied the queue");

    /* Capture order across both directions, a page at a time (Java sorts the stream by id). */
    char path[512];
    char frames[128];
    snprintf(path, sizeof(path), "/api/admin/traffic/tcp-streams?channelId=%s&page=0&size=2", channel_id);
    CHECK(api_get(server->admin_port, path, token_copy, &body) == 200, "tcp-streams page 0");
    item_frames(body, frames, sizeof(frames));
    int first_page_ok = strcmp(frames, "P0,P1") == 0 && json_number(body, "total") == 3
        && json_number(body, "page") == 0 && json_number(body, "size") == 2 && json_number(body, "limit") == 2
        && json_number(body, "totalPages") == 2 && strstr(body, "\"truncated\":true") != NULL
        && strstr(body, "\"payloadBase64\":\"cHViLTA=\"") != NULL;
    if (!first_page_ok) fprintf(stderr, "page 0 [%s]: %s\n", frames, body);
    free(body);
    CHECK(first_page_ok, "tcp-streams page 0");
    snprintf(path, sizeof(path), "/api/admin/traffic/tcp-streams?channelId=%s&page=1&size=2", channel_id);
    CHECK(api_get(server->admin_port, path, token_copy, &body) == 200, "tcp-streams page 1");
    item_frames(body, frames, sizeof(frames));
    int second_page_ok = strcmp(frames, "C0") == 0 && strstr(body, "\"truncated\":false") != NULL;
    if (!second_page_ok) fprintf(stderr, "page 1 [%s]: %s\n", frames, body);
    free(body);
    CHECK(second_page_ok, "tcp-streams page 1");

    /* A frame still queued at SIGTERM is written out before the process ends. */
    CHECK(client_data(data, stream_id, public_fd, "cli-1") == 0, "cli-1 relayed");
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (pending_tcp(server, token_copy) != 1 && monotonic_ms() < deadline) sleep_ms(50);
    CHECK(pending_tcp(server, token_copy) == 1, "cli-1 must be queued");
    close_fd(&public_fd);
    close_fd(&data);
    close_fd(&control);
    CHECK(server_stop(server, 20000) == 0, "the server must stop cleanly");
    st_storage_tcp_frame *stored = (st_storage_tcp_frame *)calloc(10U, sizeof(*stored));
    size_t stored_count = 0U;
    long long stored_total = 0;
    int listed = stored != NULL
        && st_storage_list_tcp_stream_visible(db_path, channel_id, "default", "unused", 1, 0, 10,
                                              stored, 10U, &stored_count, &stored_total) == 0;
    for (size_t i = 0; i < stored_count; ++i) st_storage_tcp_frame_free(&stored[i]);
    free(stored);
    free(channel_id);
    CHECK(listed && stored_total == 4, "the frame queued at shutdown must be in Elasticsearch (%lld)", stored_total);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* 3. SQLite                                                                                     */

static int record_frame(long long client_id, const char *channel, const char *direction, long long index,
                        const char *payload)
{
    st_storage_tcp_frame_record record = {
        .tenant_id = "t-sql",
        .client_id = client_id,
        .client_name = "sql-client",
        .listen_port = 18080,
        .resource_id = 1,
        .resource_name = "TCP 18080",
        .channel_id = channel,
        .direction = direction,
        .remote_address = "192.0.2.20:40000",
        .source_address = "192.0.2.20",
        .source_port = 40000,
        .destination_address = "127.0.0.1",
        .destination_port = 9,
        .stream_offset = index * 8,
        .frame_index = index,
        .payload_data = (const uint8_t *)payload,
        .payload_data_len = strlen(payload),
        .frame_time = "2026-10-07T02:03:04Z"
    };
    return st_storage_record_tcp_frame(db_path, &record);
}

static int test_sqlite_stream_and_pages(void)
{
    CHECK(create_user("sql-admin", "t-sql", "ADMIN") == 0, "sql admin");
    char token[1024];
    CHECK(issue_token("sql-admin", "t-sql", "ADMIN", token, sizeof(token)) == 0, "sql token");
    long long client_id = create_client("t-sql", "sql-client", "sql-admin");
    CHECK(client_id > 0, "sql client");

    /* Capture order P0, P1, C0: frame indexes count each direction on its own. */
    CHECK(record_frame(client_id, "sql-ch", "PUBLIC_TO_CLIENT", 0, "pub-0") == 0
              && record_frame(client_id, "sql-ch", "PUBLIC_TO_CLIENT", 1, "pub-1") == 0
              && record_frame(client_id, "sql-ch", "CLIENT_TO_PUBLIC", 0, "cli-0") == 0,
          "frames");
    char *body = NULL;
    char frames[8192];
    CHECK(api_get(listener_port, "/api/admin/traffic/tcp-streams?channelId=sql-ch&size=2", token, &body) == 200,
          "sqlite stream page 0");
    item_frames(body, frames, sizeof(frames));
    int ok = strcmp(frames, "P0,P1") == 0 && json_number(body, "total") == 3 && json_number(body, "totalPages") == 2
        && strstr(body, "\"truncated\":true") != NULL;
    if (!ok) fprintf(stderr, "[%s] %s\n", frames, body);
    free(body);
    CHECK(ok, "sqlite stream page 0");
    CHECK(api_get(listener_port, "/api/admin/traffic/tcp-streams?channelId=%20sql-ch%20&page=1&size=2", token, &body) == 200,
          "sqlite stream page 1");
    item_frames(body, frames, sizeof(frames));
    ok = strcmp(frames, "C0") == 0 && strstr(body, "\"channelId\":\" sql-ch \"") != NULL
        && strstr(body, "\"truncated\":false") != NULL;
    if (!ok) fprintf(stderr, "[%s] %s\n", frames, body);
    free(body);
    CHECK(ok, "sqlite stream page 1 (the channel id is trimmed for the lookup, echoed as given)");
    CHECK(api_get(listener_port, "/api/admin/traffic/tcp-streams?channelId=", token, &body) == 200
              && json_number(body, "total") == 0 && json_number(body, "totalPages") == 1,
          "a blank channel id is an empty page: %s", body == NULL ? "" : body);
    free(body);
    CHECK(api_get(listener_port, "/api/admin/traffic/tcp-streams", token, &body) == 400, "channelId is required");
    free(body);

    /* A 1000-frame page (Java's bound) and its payloads: well past the listener's 32 KiB buffer. */
    for (int i = 0; i < 1001; ++i) {
        char payload[32];
        snprintf(payload, sizeof(payload), "bulk-frame-%04d", i);
        CHECK(record_frame(client_id, "sql-bulk", "PUBLIC_TO_CLIENT", i, payload) == 0, "bulk frame %d", i);
    }
    CHECK(api_get(listener_port, "/api/admin/traffic/tcp-streams?channelId=sql-bulk&limit=1000", token, &body) == 200,
          "a 1000-frame page must be answered");
    char **items = NULL;
    size_t count = 0U;
    ok = st_json_get_raw_array(body, "items", &items, &count) == 0 && count == 1000U
        && json_number(body, "total") == 1001 && json_number(body, "limit") == 1000
        && strstr(body, "\"truncated\":true") != NULL;
    st_json_free_string_array(items, count);
    if (!ok) fprintf(stderr, "1000-frame page: %zu items, %.300s\n", count, body == NULL ? "" : body);
    free(body);
    CHECK(ok, "1000-frame page");

    /* A full exchange page is larger than 32 KiB too; the body type filter as Java's JPA store. */
    for (int i = 0; i < 120; ++i) {
        exchange_spec spec = {"t-sql", client_id, "sql-client", "bulk", "GET", "/bulk/page/listing", 200 + (i % 2),
                              NULL, NULL, i == 0 ? "application/json" : "text/plain", i == 0 ? "binary" : NULL,
                              NULL, "payload"};
        CHECK(record_exchange(&spec) == 0, "exchange %d", i);
    }
    CHECK(api_get(listener_port, "/api/admin/traffic/http-exchanges?size=120", token, &body) == 200
              && json_number(body, "total") == 120,
          "a 120-exchange page must be answered");
    count = 0U;
    ok = st_json_get_raw_array(body, "items", &items, &count) == 0 && count == 120U;
    st_json_free_string_array(items, count);
    free(body);
    CHECK(ok, "120 exchanges in the page");
    CHECK(api_get(listener_port, "/api/admin/traffic/http-exchanges?responseBodyType=%20JSON%20", token, &body) == 200
              && json_number(body, "total") == 1,
          "responseBodyType JSON by Content-Type: %s", body == NULL ? "" : body);
    free(body);
    CHECK(api_get(listener_port, "/api/admin/traffic/http-exchanges?responseBodyType=nonsense", token, &body) == 200
              && json_number(body, "total") == 120,
          "an unknown body type filters nothing: %s", body == NULL ? "" : body);
    free(body);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <database> <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[2];
    snprintf(db_path, sizeof(db_path), "%s", argv[1]);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", JWT_SECRET, 1);
    setenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", "true", 1);
    /* The writer would flush on its own every 2 s; here only flush=true and shutdown do. */
    setenv("SPECUS_TRAFFIC_CAPTURE_FLUSH_INTERVAL_MS", "600000", 1);
    if (st_storage_init(db_path, 0) != 0 || st_elasticsearch_traffic_initialize_current() != 0) {
        fprintf(stderr, "fixture setup failed\n");
        return 1;
    }
    st_admin_server server;
    if (start_listener(&server) != 0) {
        fprintf(stderr, "admin listener start failed\n");
        return 1;
    }

    int failed = test_elasticsearch_search();
    printf("%s elasticsearch search over the management API\n", failed ? "FAIL" : "ok  ");
    if (!failed) {
        static const char *const env[] = {"SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED=true", NULL};
        failed = run_on_fresh_server("elasticsearch capture from a real server", scenario_relayed_stream, env);
    }
    st_elasticsearch_traffic_shutdown();
    if (!failed) {
        const char *uris = getenv("SPECUS_ELASTICSEARCH_URIS");
        char saved[512];
        snprintf(saved, sizeof(saved), "%s", uris == NULL ? "" : uris);
        unsetenv("SPECUS_ELASTICSEARCH_URIS");
        snprintf(db_path, sizeof(db_path), "%s.sqlite", argv[1]);
        setenv("SPECUS_DATABASE_PATH", db_path, 1);
        failed = st_storage_init(db_path, 0) != 0 || test_sqlite_stream_and_pages();
        printf("%s sqlite stream contract and large pages\n", failed ? "FAIL" : "ok  ");
        unlink(db_path);
        if (saved[0] != '\0') setenv("SPECUS_ELASTICSEARCH_URIS", saved, 1);
    }
    if (failed) return 1;
    printf("traffic detail API tests passed\n");
    return 0;
}
