#define _POSIX_C_SOURCE 200809L
#include "admin_http.h"
#include "json.h"
#include "public_room.h"
#include "security.h"
#include "storage.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(ok, why) do { if (!(ok)) { fprintf(stderr, "SQLite reference: %s (line%d)\n", why, __LINE__); return 1; } } while (0)
static const uint8_t png[] = {0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0x0d, 'I', 'H', 'D', 'R', 0xff, 0};
static const char png64[] = "iVBORw0KGgoAAAANSUhEUv8A";
static const char tenant[] = "default";
static const char owner[] = "sqlite-lob-owner";
typedef struct { char path[256]; st_storage_client client; char auth[2300]; } fixture;

static int scalar(sqlite3 *db, const char *sql, long long expected)
{
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_INTEGER
        && sqlite3_column_int64(stmt, 0) == expected && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static int setup(fixture *f)
{
    memset(f, 0, sizeof(*f));
    snprintf(f->path, sizeof(f->path), "/tmp/specus-sqlite-reference-XXXXXX");
    int fd = mkstemp(f->path);
    CHECK(fd >= 0, "private database");
    close(fd);
    CHECK(setenv("SPECUS_DATABASE_PATH", f->path, 1) == 0
        && setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0
        && setenv("SPECUS_AUTH_JWT_SECRET", "sqlite-reference-test-key", 1) == 0, "fixture environment");
    CHECK(st_storage_init(f->path, 0) == 0, "real storage schema");
    st_storage_management_user user;
    CHECK(st_storage_create_management_user(f->path, owner, tenant, "unused-password-hash", "USER", 1, &user) == 0,
          "stored management owner");
    CHECK(st_storage_upsert_client(f->path, 0, tenant, "LobClient", owner, 1, 0, &f->client) == 0, "stored client");
    char token[2048];
    CHECK(st_security_issue_local_token(owner, tenant, "USER", getenv("SPECUS_AUTH_JWT_SECRET"), 600,
                                        token, sizeof(token)) == 0, "real signed token");
    int n = snprintf(f->auth, sizeof(f->auth), "Bearer %s", token);
    CHECK(n > 0 && (size_t)n < sizeof(f->auth), "bounded bearer");
    st_public_room_access access;
    CHECK(st_public_room_resolve("lob-room", "lob-owner-token", "web-owner", &access) == 0, "real room schema");
    return 0;
}

static const char *body(const char *response)
{
    const char *start = strstr(response, "\r\n\r\n");
    return start == NULL ? "" : start + 4;
}

static int text_equals(const char *json, const char *key, const char *expected)
{
    char *raw = st_json_get_top_level_raw(json, key);
    size_t len = 0U;
    char *value = raw == NULL ? NULL : st_json_decode_string(raw, &len);
    int ok = value != NULL && len == strlen(expected) && memcmp(value, expected, len) == 0;
    free(raw);
    free(value);
    return ok;
}

static int api(fixture *f, const char *method, const char *path, const char *request, char *out, size_t cap)
{
    int n = st_admin_build_response_with_auth(method, path, f->auth, request, out, cap);
    CHECK(n > 0 && strncmp(out, "HTTP/1.1 200 ", 13U) == 0 && st_json_is_valid(body(out)), "actual authenticated API response");
    return 0;
}

static int http_singleton(fixture *f)
{
    char response[32768]; char **items = NULL; size_t count = 0;
    CHECK(api(f, "GET", "/api/admin/traffic/http-exchanges?page=0&size=20", NULL, response, sizeof(response)) == 0
        && st_json_get_raw_array(body(response), "items", &items, &count) == 0 && count == 1U,
          "actual parsed HTTP list singleton");
    long long id = 0, total = 0;
    int ok = st_json_get_i64(items[0], "id", &id) == 0 && id == 1
        && st_json_get_i64(body(response), "total", &total) == 0 && total == 1;
    st_json_free_string_array(items, count);
    CHECK(ok, "HTTP list exact row identity and total");
    return 0;
}

static int blob_equals(sqlite3 *db, const char *sql, const uint8_t *bytes, size_t len)
{
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_BLOB
        && sqlite3_column_bytes(stmt, 0) == (int)len && sqlite3_column_blob(stmt, 0) != NULL
        && memcmp(sqlite3_column_blob(stmt, 0), bytes, len) == 0 && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static int schema_types(fixture *f)
{
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(f->path, &db) == SQLITE_OK, "schema connection");
    const char *columns[][3] = {
        {"specus_http_traffic_exchange", "request_body_data", "blob"},
        {"specus_http_traffic_exchange", "response_body_data", "blob"},
        {"specus_http_traffic_exchange", "request_preview_text", "text"},
        {"specus_tcp_traffic_frame", "payload_data", "blob"},
        {"public_transfer_diagram_version", "snapshot_data", "blob"}
    };
    for (size_t i = 0; i < sizeof(columns) / sizeof(columns[0]); ++i) {
        sqlite3_stmt *stmt = NULL;
        int ok = sqlite3_prepare_v2(db, "SELECT lower(type) FROM pragma_table_info(?1) WHERE name=?2", -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_bind_text(stmt, 1, columns[i][0], -1, SQLITE_STATIC) == SQLITE_OK
            && sqlite3_bind_text(stmt, 2, columns[i][1], -1, SQLITE_STATIC) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_type(stmt, 0) == SQLITE_TEXT
            && strcmp((const char *)sqlite3_column_text(stmt, 0), columns[i][2]) == 0
            && sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
        CHECK(ok, "actual BLOB/TEXT column type");
    }
    /* C holds websocket tickets in memory; there is no JDBC attributes_json CLOB column. */
    CHECK(scalar(db, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='specus_websocket_ticket'", 0),
          "ticket table absence is a limited schema difference, not ticket behavior acceptance");
    sqlite3_close(db);
    return 0;
}

static int seed_exchange(fixture *f, int captured)
{
    static const uint8_t request[] = "{\"order\":42}";
    st_storage_http_exchange_record r = {0};
    r.tenant_id = tenant; r.client_id = f->client.id; r.client_name = f->client.client_name;
    r.route = "api"; r.resource_name = "api -> http://127.0.0.1:8080";
    r.method = captured ? "POST" : "GET"; r.relative_path = captured ? "/thumbnails" : "/legacy";
    r.status_code = 200; r.success = 1; r.captured_at = "2026-10-19T00:00:00Z";
    if (captured) {
        r.request_content_type = "application/json"; r.response_content_type = "image/png";
        r.request_headers = "Content-Type: application/json"; r.response_headers = "Content-Type: image/png";
        r.request_body = request; r.request_body_len = sizeof(request) - 1U; r.request_bytes = (long long)r.request_body_len;
        r.response_body = png; r.response_body_len = sizeof(png); r.response_bytes = (long long)sizeof(png);
    }
    CHECK(st_storage_record_http_exchange(f->path, &r) == 0, "actual HTTP storage writer");
    return 0;
}

static int http_binary(fixture *f)
{
    CHECK(seed_exchange(f, 1) == 0, "captured HTTP fixture");
    CHECK(http_singleton(f) == 0, "captured bodies list before detail");
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(f->path, &db) == SQLITE_OK
        && blob_equals(db, "SELECT response_body_data FROM specus_http_traffic_exchange", png, sizeof(png)), "binary PNG NUL/ff full SQLite readback");
    static const uint8_t request[] = "{\"order\":42}";
    CHECK(blob_equals(db, "SELECT request_body_data FROM specus_http_traffic_exchange", request, sizeof(request) - 1U), "request BLOB complete readback");
    sqlite3_close(db);
    st_storage_http_exchange detail = {0};
    int found = 0;
    CHECK(st_storage_get_http_exchange_visible(f->path, 1, tenant, owner, 0, &detail, &found) == 0 && found
        && detail.request_body_data_len == sizeof(request) - 1U && detail.request_body_data != NULL
        && memcmp(detail.request_body_data, request, sizeof(request) - 1U) == 0
        && detail.response_body_data_len == sizeof(png) && detail.response_body_data != NULL
        && memcmp(detail.response_body_data, png, sizeof(png)) == 0, "actual storage detail materializes both complete BLOBs");
    st_storage_http_exchange_free_bodies(&detail);
    char response[32768];
    CHECK(api(f, "GET", "/api/admin/traffic/http-exchanges/1", NULL, response, sizeof(response)) == 0
        && text_equals(body(response), "requestPreviewText", "{\"order\":42}")
        && text_equals(body(response), "responsePreviewText", "data:image/png;base64,iVBORw0KGgoAAAANSUhEUv8A"), "exact parsed captured body views");
    return 0;
}

static int http_legacy_null(fixture *f)
{
    CHECK(seed_exchange(f, 0) == 0, "legacy HTTP fixture");
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(f->path, &db) == SQLITE_OK && sqlite3_exec(db,
        "UPDATE specus_http_traffic_exchange SET request_preview_text='request preview',response_preview_text='response preview'",
        NULL, NULL, NULL) == SQLITE_OK
        && scalar(db, "SELECT count(*) FROM specus_http_traffic_exchange WHERE request_body_data IS NULL AND response_body_data IS NULL", 1), "actual SQL NULL bodies with stored previews");
    sqlite3_close(db);
    st_storage_http_exchange detail = {0}; int found = 0;
    CHECK(http_singleton(f) == 0, "legacy NULL bodies list before detail");
    CHECK(st_storage_get_http_exchange_visible(f->path, 1, tenant, owner, 0, &detail, &found) == 0 && found
        && detail.request_body_data == NULL && detail.request_body_data_len == 0U
        && detail.response_body_data == NULL && detail.response_body_data_len == 0U, "NULL bodies load successfully");
    st_storage_http_exchange_free_bodies(&detail);
    char response[32768];
    CHECK(api(f, "GET", "/api/admin/traffic/http-exchanges/1", NULL, response, sizeof(response)) == 0
        && text_equals(body(response), "requestPreviewText", "request preview")
        && text_equals(body(response), "responsePreviewText", "response preview"), "legacy previews survive API detail");
    return 0;
}

static int tcp_binary(fixture *f)
{
    st_storage_tcp_frame_record r = {0};
    r.tenant_id = tenant; r.client_id = f->client.id; r.client_name = f->client.client_name;
    r.listen_port = 15432; r.resource_name = "postgres"; r.channel_id = "channel-1";
    r.direction = "CLIENT_TO_PUBLIC"; r.payload_data = png; r.payload_data_len = sizeof(png);
    r.frame_time = "2026-10-19T00:00:00Z";
    CHECK(st_storage_record_tcp_frame(f->path, &r) == 0, "actual TCP BLOB writer");
    st_storage_tcp_frame rows[2] = {{0}}; size_t n = 0; long long total = 0;
    CHECK(st_storage_list_tcp_frames_visible(f->path, 0, ST_STORAGE_ANY_LISTEN_PORT, tenant, owner, 0, 0, 20,
                                              rows, 2, &n, &total) == 0 && n == 1U && total == 1
        && rows[0].id == 1 && rows[0].payload_bytes == (long long)sizeof(png), "actual TCP list and exact identity");
    st_storage_tcp_frame_free(&rows[0]);
    st_storage_tcp_frame detail = {0};
    CHECK(st_storage_get_tcp_frame_visible(f->path, 1, tenant, owner, 0, &detail) == 0
        && detail.payload_data != NULL && detail.payload_data_len == sizeof(png)
        && memcmp(detail.payload_data, png, sizeof(png)) == 0, "TCP detail materializes full NUL/ff payload");
    st_storage_tcp_frame_free(&detail);
    char response[32768]; char **items = NULL; size_t count = 0;
    CHECK(api(f, "GET", "/api/admin/traffic/tcp-frames?page=0&size=20", NULL, response, sizeof(response)) == 0
        && st_json_get_raw_array(body(response), "items", &items, &count) == 0 && count == 1U, "actual parsed TCP list singleton");
    long long id = 0;
    int ok = st_json_get_i64(items[0], "id", &id) == 0 && id == 1;
    st_json_free_string_array(items, count);
    CHECK(ok && api(f, "GET", "/api/admin/traffic/tcp-frames/1", NULL, response, sizeof(response)) == 0
        && text_equals(body(response), "payloadBase64", png64), "exact parsed TCP detail payloadBase64");
    return 0;
}

static int diagram_binary(fixture *f)
{
    char response[32768], request[1024], path[128]; long long ids[2] = {0};
    const char *names[] = {"first", "second"}; const char *updates[] = {png64, "c2Vjb25k"};
    for (int i = 0; i < 2; ++i) {
        snprintf(request, sizeof(request), "{\"roomId\":\"lob-room\",\"roomToken\":\"lob-owner-token\",\"peerId\":\"web-owner\",\"name\":\"%s\",\"update\":\"%s\"}", names[i], updates[i]);
        CHECK(api(f, "POST", "/api/public/transfer/rooms/diagram/versions", request, response, sizeof(response)) == 0
            && st_json_get_i64(body(response), "id", &ids[i]) == 0 && ids[i] > 0, "actual diagram create and pruning read");
    }
    CHECK(ids[0] != ids[1], "two distinct diagram IDs");
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(f->path, &db) == SQLITE_OK
        && blob_equals(db, "SELECT snapshot_data FROM public_transfer_diagram_version WHERE name='first'", png, sizeof(png)), "diagram BLOB retains every PNG byte");
    sqlite3_close(db);
    const char *credentials = "{\"roomId\":\"lob-room\",\"roomToken\":\"lob-owner-token\",\"peerId\":\"web-owner\"}";
    CHECK(api(f, "POST", "/api/public/transfer/rooms/diagram/versions/list", credentials, response, sizeof(response)) == 0, "actual diagram list");
    char wrapped[33000];
    int len = snprintf(wrapped, sizeof(wrapped), "{\"items\":%s}", body(response));
    char **items = NULL; size_t count = 0;
    CHECK(len > 0 && (size_t)len < sizeof(wrapped) && st_json_get_raw_array(wrapped, "items", &items, &count) == 0 && count == 2U, "parsed diagram list exact two rows");
    int seen[2] = {0};
    for (size_t i = 0; i < count; ++i) {
        long long id = 0;
        for (int j = 0; j < 2; ++j) {
            if (text_equals(items[i], "name", names[j]) && st_json_get_i64(items[i], "id", &id) == 0 && id == ids[j]) ++seen[j];
        }
    }
    st_json_free_string_array(items, count);
    CHECK(seen[0] == 1 && seen[1] == 1, "exact diagram name/id set");
    for (int i = 0; i < 2; ++i) {
        snprintf(path, sizeof(path), "/api/public/transfer/rooms/diagram/versions/%lld", ids[i]);
        CHECK(api(f, "POST", path, credentials, response, sizeof(response)) == 0
            && text_equals(body(response), "update", updates[i]), "each diagram detail restores exact snapshot");
    }
    return 0;
}

static int media_unique(fixture *f)
{
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(f->path, &db) == SQLITE_OK && sqlite3_extended_result_codes(db, 1) == SQLITE_OK, "actual media schema connection");
    const char *insert = "INSERT INTO specus_http_media_capture(tenant_id,client_id,client_name,route,source_url,resource_key,deduplication_key,method,status_code,media_kind,object_key,state,captured_at,expires_at) VALUES('default',1,'client','media','https://example.test/video.mp4','resource','jpa-duplicate','GET',206,'video','object','STARTING','2026-10-07T00:00:00Z','2026-10-08T00:00:00Z')";
    CHECK(sqlite3_exec(db, insert, NULL, NULL, NULL) == SQLITE_OK, "first actual-schema media insert");
    int rc = sqlite3_exec(db, insert, NULL, NULL, NULL);
    CHECK(rc == SQLITE_CONSTRAINT_UNIQUE && sqlite3_extended_errcode(db) == SQLITE_CONSTRAINT_UNIQUE
        && strstr(sqlite3_errmsg(db), "UNIQUE constraint failed: specus_http_media_capture.deduplication_key") != NULL,
          "actual media deduplication unique code and column");
    CHECK(scalar(db, "SELECT count(*) FROM specus_http_media_capture", 1)
        && scalar(db, "SELECT count(*) FROM specus_http_media_capture WHERE deduplication_key='jpa-duplicate' AND state='STARTING' AND object_key='object' AND status_code=206", 1), "failed duplicate retains original row");
    sqlite3_close(db);
    return 0;
}

static int raw_constraints(fixture *f)
{
    sqlite3 *db = NULL;
    CHECK(sqlite3_open(f->path, &db) == SQLITE_OK && sqlite3_extended_result_codes(db, 1) == SQLITE_OK
        && sqlite3_exec(db, "CREATE TABLE probe(id INTEGER PRIMARY KEY,code TEXT NOT NULL);CREATE UNIQUE INDEX uk_probe_code ON probe(code);INSERT INTO probe VALUES(1,'a')", NULL, NULL, NULL) == SQLITE_OK,
          "real SQLite JDBC-equivalent probe");
    CHECK(sqlite3_exec(db, "INSERT INTO probe VALUES(2,'a')", NULL, NULL, NULL) == SQLITE_CONSTRAINT_UNIQUE
        && strstr(sqlite3_errmsg(db), "UNIQUE constraint failed: probe.code") != NULL, "unique violation");
    CHECK(sqlite3_exec(db, "INSERT INTO probe VALUES(1,'b')", NULL, NULL, NULL) == SQLITE_CONSTRAINT_PRIMARYKEY, "primary-key violation");
    CHECK(sqlite3_exec(db, "INSERT INTO probe VALUES(2,NULL)", NULL, NULL, NULL) == SQLITE_CONSTRAINT_NOTNULL
        && strstr(sqlite3_errmsg(db), "NOT NULL constraint failed: probe.code") != NULL, "not-null violation");
    CHECK(sqlite3_exec(db, "INSERT INTO missing(id) VALUES(1)", NULL, NULL, NULL) == SQLITE_ERROR
        && strstr(sqlite3_errmsg(db), "no such table") != NULL, "nonconstraint missing-table remains distinct");
    CHECK(scalar(db, "SELECT count(*) FROM probe", 1) && sqlite3_exec(db, "INSERT INTO probe VALUES(2,'b')", NULL, NULL, NULL) == SQLITE_OK
        && scalar(db, "SELECT count(*) FROM probe", 2), "refusals preserve rows and connection remains usable");
    st_storage_http_exchange detail = {0}; int found = 99;
    CHECK(st_storage_get_http_exchange_visible(f->path, 999, tenant, owner, 0, &detail, &found) == 0 && found == 0,
          "real storage missing row is successful not-found");
    CHECK(sqlite3_exec(db, "ALTER TABLE specus_http_traffic_exchange RENAME TO broken_exchange_fixture", NULL, NULL, NULL) == SQLITE_OK,
          "isolated actual storage query failure setup");
    found = 99;
    CHECK(st_storage_get_http_exchange_visible(f->path, 1, tenant, owner, 0, &detail, &found) == -1 && found == 0,
          "real storage missing-table failure is not a successful empty result");
    CHECK(sqlite3_exec(db, "ALTER TABLE broken_exchange_fixture RENAME TO specus_http_traffic_exchange", NULL, NULL, NULL) == SQLITE_OK,
          "restore isolated query fixture");
    found = 99;
    CHECK(st_storage_get_http_exchange_visible(f->path, 999, tenant, owner, 0, &detail, &found) == 0 && found == 0,
          "real storage reads recover after query fixture restoration");
    sqlite3_close(db);
    return 0;
}

int main(void)
{
    CHECK(text_equals("{\"v\":\"ok\"}", "v", "ok")
        && !text_equals("{\"v\":\"ok\\u0000suffix\"}", "v", "ok")
        && !text_equals("{\"v\":null}", "v", "ok")
        && !text_equals("{}", "v", "ok"), "length-aware parsed string positive/NUL/null/missing calibration");
    const struct { const char *name; int (*run)(fixture *); } cases[] = {
        {"actual BLOB/TEXT schema and bounded ticket-table difference", schema_types},
        {"HTTP complete binary bodies and exact captured API views", http_binary},
        {"legacy SQL NULL bodies retain exact API previews", http_legacy_null},
        {"TCP list/detail full binary payload", tcp_binary},
        {"two diagram snapshots list/detail and byte-exact BLOB", diagram_binary},
        {"actual media deduplication unique violation retains row", media_unique},
        {"real unique primary-key not-null and missing-table distinction", raw_constraints}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fixture f;
        int rc = setup(&f);
        if (rc == 0) rc = cases[i].run(&f);
        st_public_room_reset_for_tests();
        if (f.path[0] != '\0') unlink(f.path);
        unsetenv("SPECUS_DATABASE_PATH");
        if (rc != 0) return rc;
        printf("SQLite reference case%zu: %s passed\n", i, cases[i].name);
    }
    puts("SQLite reference:7 isolated actual core/API scenarios passed; JDBC/JPA/Spring types are not C APIs");
    return 0;
}
