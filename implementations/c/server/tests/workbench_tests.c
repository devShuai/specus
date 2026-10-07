#define _POSIX_C_SOURCE 200809L

/*
 * Service workbench (protocol/spec/service-workbench.md): the shared vector replayed through the
 * real admin request handling (routing, the shared authentication layer that re-reads the account,
 * the handler and SQLite), plus HTTP-level isolation checks and the cascades of the existing
 * delete endpoints.
 */

#include "admin_http.h"
#include "json.h"
#include "security.h"
#include "storage.h"
#include "workbench.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef ST_WORKBENCH_VECTOR_FILE
#define ST_WORKBENCH_VECTOR_FILE "../../../protocol/test-vectors/service-workbench-v1.json"
#endif

#define WB_RESPONSE_BYTES 32768U
#define WB_MAX_IDENTITIES 16U
#define WB_MAX_OBJECTS 128U
#define WB_MAX_ROWS 256U

static long long test_clock_ms = 0;

static long long test_clock(void)
{
    return test_clock_ms;
}

static char test_db_path[256];
static int test_db_serial = 0;

/* ---- Small helpers ------------------------------------------------------------------------ */

static int open_fresh_database(void)
{
    if (test_db_path[0] != '\0') {
        unlink(test_db_path);
    }
    snprintf(test_db_path, sizeof(test_db_path), "/tmp/specus-c-workbench-%ld-%d.db",
             (long)getpid(), ++test_db_serial);
    unlink(test_db_path);
    setenv("SPECUS_DATABASE_PATH", test_db_path, 1);
    if (st_storage_init(test_db_path, 0) != 0) {
        fprintf(stderr, "workbench test database init failed\n");
        return -1;
    }
    st_workbench_rate_limit_reset();
    return 0;
}

static int exec_sql(const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(test_db_path, &db) == SQLITE_OK
        ? sqlite3_exec(db, sql, NULL, NULL, &error) : SQLITE_ERROR;
    if (rc != SQLITE_OK) {
        fprintf(stderr, "test sql failed: %s: %s\n", sql, error == NULL ? "?" : error);
    }
    sqlite3_free(error);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

/* Runs sql with text and integer parameters given as "t" / "i" in types; returns 0 when done. */
static int exec_bound(const char *sql, const char *types, const char *const *texts, const long long *ints)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_open(test_db_path, &db) == SQLITE_OK
        ? sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) : SQLITE_ERROR;
    size_t text_index = 0U;
    size_t int_index = 0U;
    for (size_t i = 0; rc == SQLITE_OK && types[i] != '\0'; ++i) {
        rc = types[i] == 't'
            ? sqlite3_bind_text(stmt, (int)i + 1, texts[text_index++], -1, SQLITE_TRANSIENT)
            : sqlite3_bind_int64(stmt, (int)i + 1, ints[int_index++]);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt) == SQLITE_DONE ? SQLITE_OK : SQLITE_ERROR;
    }
    if (rc != SQLITE_OK) {
        fprintf(stderr, "test sql failed: %s: %s\n", sql, db == NULL ? "?" : sqlite3_errmsg(db));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

static long long query_i64(const char *sql, const char *text)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long value = -1;
    if (sqlite3_open(test_db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (text != NULL) {
            sqlite3_bind_text(stmt, 1, text, -1, SQLITE_TRANSIENT);
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            value = sqlite3_column_int64(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

static int issue_bearer(const char *username, const char *tenant_id, char *out, size_t out_len)
{
    char token[2048];
    if (st_security_issue_local_token(username, tenant_id, "USER", getenv("SPECUS_AUTH_JWT_SECRET"), 3600,
                                      token, sizeof(token)) != 0) {
        fprintf(stderr, "token for %s/%s could not be issued\n", tenant_id, username);
        return -1;
    }
    int written = snprintf(out, out_len, "Bearer %s", token);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

typedef struct {
    int status;
    char cache_control[64];
    char retry_after[32];
    int has_retry_after;
    const char *body;
} wb_response;

static int header_value(const char *response, const char *name, char *out, size_t out_len)
{
    const char *end = strstr(response, "\r\n\r\n");
    char needle[64];
    snprintf(needle, sizeof(needle), "\r\n%s: ", name);
    const char *found = strstr(response, needle);
    if (end == NULL || found == NULL || found > end) {
        return 0;
    }
    found += strlen(needle);
    const char *line_end = strstr(found, "\r\n");
    size_t len = line_end == NULL ? 0U : (size_t)(line_end - found);
    if (len >= out_len) {
        len = out_len - 1U;
    }
    memcpy(out, found, len);
    out[len] = '\0';
    return 1;
}

static int call(const char *method, const char *path, const char *authorization, const char *body,
                char *buffer, size_t buffer_len, wb_response *response)
{
    memset(response, 0, sizeof(*response));
    int len = st_admin_build_response_with_auth(method, path, authorization, body, buffer, buffer_len);
    if (len <= 0 || sscanf(buffer, "HTTP/1.1 %d", &response->status) != 1) {
        fprintf(stderr, "%s %s produced no response\n", method, path);
        return -1;
    }
    (void)header_value(buffer, "Cache-Control", response->cache_control, sizeof(response->cache_control));
    response->has_retry_after = header_value(buffer, "Retry-After", response->retry_after,
                                             sizeof(response->retry_after));
    const char *separator = strstr(buffer, "\r\n\r\n");
    response->body = separator == NULL ? "" : separator + 4;
    return 0;
}

static char *body_code(const char *body)
{
    return st_json_get_top_level_string(body, "code");
}

/* JSON text without the whitespace outside strings, so a pretty-printed document compares exactly. */
static char *minify_json(const char *raw)
{
    char *out = (char *)malloc(strlen(raw) + 1U);
    if (out == NULL) {
        return NULL;
    }
    size_t used = 0U;
    int in_string = 0;
    for (const char *p = raw; *p != '\0'; ++p) {
        if (in_string) {
            out[used++] = *p;
            if (*p == '\\' && p[1] != '\0') {
                out[used++] = *++p;
            } else if (*p == '"') {
                in_string = 0;
            }
        } else if (*p == '"') {
            in_string = 1;
            out[used++] = *p;
        } else if (*p != ' ' && *p != '\n' && *p != '\r' && *p != '\t') {
            out[used++] = *p;
        }
    }
    out[used] = '\0';
    return out;
}

/* ---- Vector access ------------------------------------------------------------------------ */

static int vec_array(const char *object, const char *key, char ***items, size_t *count)
{
    *items = NULL;
    *count = 0U;
    char *raw = st_json_get_top_level_raw(object, key);
    if (raw == NULL) {
        return -1;
    }
    size_t len = strlen(raw) + 8U;
    char *wrapped = (char *)malloc(len);
    int rc = -1;
    if (wrapped != NULL) {
        snprintf(wrapped, len, "{\"a\":%s}", raw);
        rc = st_json_get_raw_array(wrapped, "a", items, count);
    }
    free(wrapped);
    free(raw);
    return rc;
}

static int vec_i64(const char *object, const char *key, long long *out)
{
    char *raw = st_json_get_top_level_raw(object, key);
    char *end = NULL;
    int rc = raw == NULL ? -1 : 0;
    if (rc == 0) {
        *out = strtoll(raw, &end, 10);
        rc = end != raw && *end == '\0' ? 0 : -1;
    }
    free(raw);
    return rc;
}

static int vec_bool(const char *object, const char *key)
{
    char *raw = st_json_get_top_level_raw(object, key);
    int value = raw != NULL && strcmp(raw, "true") == 0;
    free(raw);
    return value;
}

/* Copies the string under key into out; "" when it is missing. */
static void vec_text(const char *object, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(object, key);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
    free(value);
}

/* ---- Scenario state ----------------------------------------------------------------------- */

/*
 * Login names are unique per tenant (protocol/spec/management-accounts.md), so the vector's
 * (t2, alice) is an account named alice next to (t1, alice): accounts, tokens, owners and rows
 * carry the vector's names as they are.
 */

typedef struct {
    char tenant_id[32];
    char username[64];
    char bearer[2400];
} wb_identity;

typedef struct {
    char kind[16];
    long long id;
    char tenant_id[32];
} wb_object;

typedef struct {
    long long base_ms;
    wb_identity identities[WB_MAX_IDENTITIES];
    size_t identity_count;
    wb_object objects[WB_MAX_OBJECTS];
    size_t object_count;
    int next_listen_port;
} wb_scenario;

static wb_identity *find_identity(wb_scenario *scenario, const char *tenant_id, const char *username)
{
    for (size_t i = 0; i < scenario->identity_count; ++i) {
        if (strcmp(scenario->identities[i].tenant_id, tenant_id) == 0
            && strcmp(scenario->identities[i].username, username) == 0) {
            return &scenario->identities[i];
        }
    }
    return NULL;
}

/* Remembers a bearer token for the identity, issued now (before any later deletion). */
static int remember_identity(wb_scenario *scenario, const char *tenant_id, const char *username)
{
    wb_identity *identity = find_identity(scenario, tenant_id, username);
    if (identity == NULL) {
        if (scenario->identity_count == WB_MAX_IDENTITIES) {
            return -1;
        }
        identity = &scenario->identities[scenario->identity_count++];
        snprintf(identity->tenant_id, sizeof(identity->tenant_id), "%s", tenant_id);
        snprintf(identity->username, sizeof(identity->username), "%s", username);
    }
    return issue_bearer(username, tenant_id, identity->bearer, sizeof(identity->bearer));
}

/* A tenant administrator outside the vector, used only to drive the existing management endpoints. */
static int operator_bearer(const char *tenant_id, char *out, size_t out_len)
{
    char username[64];
    snprintf(username, sizeof(username), "wbops-%s", tenant_id);
    st_storage_management_user user;
    if (st_storage_get_management_user_in_tenant(test_db_path, tenant_id, username, &user) != 0
        && st_storage_create_management_user(test_db_path, username, tenant_id, "unused-password-hash",
                                             "ADMIN", 1, NULL) != 0) {
        fprintf(stderr, "operator %s could not be created\n", username);
        return -1;
    }
    return issue_bearer(username, tenant_id, out, out_len);
}

static long long ensure_client(const char *tenant_id, const char *owner)
{
    char name[160];
    snprintf(name, sizeof(name), "wb-%s-%s", tenant_id, owner);
    const char *texts[] = {tenant_id, name, owner};
    if (exec_bound("INSERT OR IGNORE INTO client_account(tenant_id, client_name, owner_username, enabled) "
                   "VALUES(?,?,?,1)", "ttt", texts, NULL) != 0) {
        return -1;
    }
    return query_i64("SELECT rowid FROM client_account WHERE client_name = ?", name);
}

/* Creates a route, mapping or Peer service with exactly the given id on the owner's client. */
static int create_object(wb_scenario *scenario, const char *kind, long long id,
                         const char *tenant_id, const char *owner)
{
    long long client_id = ensure_client(tenant_id, owner);
    if (client_id <= 0 || scenario->object_count == WB_MAX_OBJECTS) {
        return -1;
    }
    char client_name[160];
    char label[64];
    snprintf(client_name, sizeof(client_name), "wb-%s-%s", tenant_id, owner);
    snprintf(label, sizeof(label), "wb-%lld", id);
    int rc;
    if (strcmp(kind, "http-route") == 0) {
        const char *texts[] = {client_name, label};
        long long ints[] = {id};
        rc = exec_bound("INSERT INTO http_route_mapping(id, client_name, route, target_base_url, enabled) "
                        "VALUES(?,?,?,'http://127.0.0.1:8080',1)", "itt", texts, ints);
    } else if (strcmp(kind, "tcp-mapping") == 0) {
        const char *texts[] = {client_name};
        long long ints[] = {id, scenario->next_listen_port++};
        rc = exec_bound("INSERT INTO specus_mapping(id, client_name, listen_port, target_address, target_port) "
                        "VALUES(?,?,?,'127.0.0.1',22)", "iti", texts, ints);
    } else {
        const char *texts[] = {tenant_id, client_name, label, label};
        long long ints[] = {id, client_id, scenario->next_listen_port++};
        rc = exec_bound("INSERT INTO peer_mesh_shared_service(id, tenant_id, client_id, client_name, service_id, "
                        "name, transport, application, target_host, target_port, published_port, enabled) "
                        "VALUES(?,?,?,?,?,?,'TCP','GENERIC','127.0.0.1',22,?,1)",
                        "itittti", texts, ints);
    }
    if (rc == 0) {
        wb_object *object = &scenario->objects[scenario->object_count++];
        snprintf(object->kind, sizeof(object->kind), "%s", kind);
        object->id = id;
        snprintf(object->tenant_id, sizeof(object->tenant_id), "%s", tenant_id);
    }
    return rc;
}

static wb_object *find_object(wb_scenario *scenario, const char *kind, long long id)
{
    for (size_t i = 0; i < scenario->object_count; ++i) {
        if (strcmp(scenario->objects[i].kind, kind) == 0 && scenario->objects[i].id == id) {
            return &scenario->objects[i];
        }
    }
    return NULL;
}

/* Moves the object to a client of the new owner: the owner of a service is that of its client. */
static int change_owner(wb_scenario *scenario, const char *kind, long long id, const char *owner)
{
    wb_object *object = find_object(scenario, kind, id);
    long long client_id = object == NULL ? -1 : ensure_client(object->tenant_id, owner);
    if (client_id <= 0) {
        return -1;
    }
    char client_name[160];
    snprintf(client_name, sizeof(client_name), "wb-%s-%s", object->tenant_id, owner);
    const char *texts[] = {client_name};
    if (strcmp(kind, "http-route") == 0) {
        long long ints[] = {id};
        return exec_bound("UPDATE http_route_mapping SET client_name = ? WHERE id = ?", "ti", texts, ints);
    }
    if (strcmp(kind, "tcp-mapping") == 0) {
        long long ints[] = {id};
        return exec_bound("UPDATE specus_mapping SET client_name = ? WHERE id = ?", "ti", texts, ints);
    }
    long long ints[] = {client_id, id};
    return exec_bound("UPDATE peer_mesh_shared_service SET client_name = ?, client_id = ? WHERE id = ?",
                      "tii", texts, ints);
}

typedef struct {
    char tenant_id[32];
    char username[64];
    char list[16];
    char kind[16];
    long long id;
    long long at_ms;
} wb_row;

static int kind_order(const char *kind)
{
    return strcmp(kind, "http-route") == 0 ? 0 : strcmp(kind, "tcp-mapping") == 0 ? 1 : 2;
}

static int compare_rows(const void *left_raw, const void *right_raw)
{
    const wb_row *left = (const wb_row *)left_raw;
    const wb_row *right = (const wb_row *)right_raw;
    int rc = strcmp(left->tenant_id, right->tenant_id);
    if (rc == 0) rc = strcmp(left->username, right->username);
    if (rc == 0) rc = strcmp(left->list, right->list);
    if (rc == 0) rc = kind_order(left->kind) - kind_order(right->kind);
    if (rc == 0) rc = left->id < right->id ? -1 : left->id > right->id ? 1 : 0;
    return rc;
}

/* Every stored workbench row, times relative to base. */
static int dump_rows(long long base_ms, wb_row *rows, size_t max_rows, size_t *count)
{
    *count = 0U;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_open(test_db_path, &db) == SQLITE_OK
        ? sqlite3_prepare_v2(db, "SELECT tenant_id, username, list, kind, object_id, at_ms "
                                 "FROM management_workbench_item", -1, &stmt, NULL)
        : SQLITE_ERROR;
    while (rc == SQLITE_OK && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*count == max_rows) {
            rc = SQLITE_ERROR;
            break;
        }
        wb_row *row = &rows[(*count)++];
        snprintf(row->tenant_id, sizeof(row->tenant_id), "%s", (const char *)sqlite3_column_text(stmt, 0));
        snprintf(row->username, sizeof(row->username), "%s", (const char *)sqlite3_column_text(stmt, 1));
        snprintf(row->list, sizeof(row->list), "%s", (const char *)sqlite3_column_text(stmt, 2));
        snprintf(row->kind, sizeof(row->kind), "%s", (const char *)sqlite3_column_text(stmt, 3));
        row->id = sqlite3_column_int64(stmt, 4);
        row->at_ms = sqlite3_column_int64(stmt, 5) - base_ms;
        rc = SQLITE_OK;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "workbench rows could not be read\n");
        return -1;
    }
    qsort(rows, *count, sizeof(*rows), compare_rows);
    return 0;
}

static int rows_equal(const wb_row *left, size_t left_count, const wb_row *right, size_t right_count)
{
    if (left_count != right_count) {
        return 0;
    }
    for (size_t i = 0; i < left_count; ++i) {
        if (compare_rows(&left[i], &right[i]) != 0 || left[i].at_ms != right[i].at_ms) {
            return 0;
        }
    }
    return 1;
}

static void print_rows(const char *label, const wb_row *rows, size_t count)
{
    fprintf(stderr, "  %s (%zu):\n", label, count);
    for (size_t i = 0; i < count; ++i) {
        fprintf(stderr, "    %s %s %s %s %lld at %lld\n", rows[i].tenant_id, rows[i].username, rows[i].list,
                rows[i].kind, rows[i].id, rows[i].at_ms);
    }
}

static int parse_row(const char *raw, wb_row *row)
{
    memset(row, 0, sizeof(*row));
    vec_text(raw, "tenantId", row->tenant_id, sizeof(row->tenant_id));
    vec_text(raw, "username", row->username, sizeof(row->username));
    vec_text(raw, "list", row->list, sizeof(row->list));
    vec_text(raw, "kind", row->kind, sizeof(row->kind));
    return vec_i64(raw, "id", &row->id) == 0 && vec_i64(raw, "atMs", &row->at_ms) == 0 ? 0 : -1;
}

/* ---- Vector replay ------------------------------------------------------------------------ */

static int civil_days(int year, int month, int day)
{
    year -= month <= 2;
    int era = (year >= 0 ? year : year - 399) / 400;
    int yoe = year - era * 400;
    int doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static int parse_base_time(const char *text, long long *out)
{
    int year, month, day, hour, minute, second;
    if (sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2dZ", &year, &month, &day, &hour, &minute, &second) != 6) {
        return -1;
    }
    *out = ((long long)civil_days(year, month, day) * 86400LL + hour * 3600LL + minute * 60LL + second) * 1000LL;
    return 0;
}

static int replay_event(wb_scenario *scenario, const char *step, const char *name)
{
    char tenant_id[32];
    char username[64];
    char kind[16];
    char bearer[2400];
    char path[192];
    static char buffer[WB_RESPONSE_BYTES];
    wb_response response;
    long long id = 0;
    vec_text(step, "tenantId", tenant_id, sizeof(tenant_id));
    vec_text(step, "username", username, sizeof(username));
    vec_text(step, "kind", kind, sizeof(kind));
    (void)vec_i64(step, "id", &id);
    if (strcmp(name, "delete-object") == 0) {
        /* Through the existing delete endpoint, as a tenant administrator. */
        wb_object *object = find_object(scenario, kind, id);
        const char *prefix = strcmp(kind, "http-route") == 0 ? "/api/admin/http-routes/"
            : strcmp(kind, "tcp-mapping") == 0 ? "/api/admin/specus-mappings/" : "/api/admin/peer-mesh/services/";
        snprintf(path, sizeof(path), "%s%lld", prefix, id);
        if (object == NULL || operator_bearer(object->tenant_id, bearer, sizeof(bearer)) != 0
            || call("DELETE", path, bearer, NULL, buffer, sizeof(buffer), &response) != 0
            || response.status != 204) {
            fprintf(stderr, "delete-object %s %lld failed: %.200s\n", kind, id, buffer);
            return -1;
        }
        object->kind[0] = '\0';
        return 0;
    }
    if (strcmp(name, "create-object") == 0) {
        char owner[64];
        vec_text(step, "ownerUsername", owner, sizeof(owner));
        return create_object(scenario, kind, id, tenant_id, owner);
    }
    if (strcmp(name, "change-owner") == 0) {
        char owner[64];
        wb_object *object = find_object(scenario, kind, id);
        if (object == NULL) {
            return -1;
        }
        vec_text(step, "ownerUsername", owner, sizeof(owner));
        return change_owner(scenario, kind, id, owner);
    }
    if (strcmp(name, "set-admin") == 0 || strcmp(name, "delete-user") == 0 || strcmp(name, "create-user") == 0) {
        /* Through the existing account management endpoints, as a tenant administrator. */
        if (operator_bearer(tenant_id, bearer, sizeof(bearer)) != 0) {
            return -1;
        }
        char body[256];
        int expected;
        int rc;
        if (strcmp(name, "set-admin") == 0) {
            snprintf(path, sizeof(path), "/api/admin/users/%s", username);
            snprintf(body, sizeof(body), "{\"role\":\"%s\"}", vec_bool(step, "admin") ? "ADMIN" : "USER");
            expected = 200;
            rc = call("PUT", path, bearer, body, buffer, sizeof(buffer), &response);
        } else if (strcmp(name, "delete-user") == 0) {
            snprintf(path, sizeof(path), "/api/admin/users/%s", username);
            expected = 204;
            rc = call("DELETE", path, bearer, NULL, buffer, sizeof(buffer), &response);
        } else {
            snprintf(body, sizeof(body),
                     "{\"username\":\"%s\",\"password\":\"wb-password-1\",\"role\":\"%s\",\"enabled\":true}",
                     username, vec_bool(step, "admin") ? "ADMIN" : "USER");
            expected = 201;
            rc = call("POST", "/api/admin/users", bearer, body, buffer, sizeof(buffer), &response);
            if (rc == 0 && response.status == expected) {
                rc = remember_identity(scenario, tenant_id, username);
            }
        }
        if (rc != 0 || response.status != expected) {
            fprintf(stderr, "%s %s/%s failed: %.200s\n", name, tenant_id, username, buffer);
            return -1;
        }
        return 0;
    }
    if (strcmp(name, "store-down") == 0) {
        return exec_sql("ALTER TABLE management_workbench_item RENAME TO management_workbench_item_down");
    }
    if (strcmp(name, "store-up") == 0) {
        return exec_sql("ALTER TABLE management_workbench_item_down RENAME TO management_workbench_item");
    }
    if (strcmp(name, "sweep") == 0) {
        return st_workbench_sweep(test_db_path);
    }
    fprintf(stderr, "unknown vector event %s\n", name);
    return -1;
}

static int replay_call(wb_scenario *scenario, const char *scenario_name, size_t index, const char *step)
{
    static char buffer[WB_RESPONSE_BYTES];
    static wb_row before[WB_MAX_ROWS];
    static wb_row after[WB_MAX_ROWS];
    char method[16];
    char path[192];
    vec_text(step, "method", method, sizeof(method));
    vec_text(step, "path", path, sizeof(path));
    char *as = st_json_get_top_level_raw(step, "as");
    char *expect = st_json_get_top_level_raw(step, "expect");
    const char *bearer = NULL;
    int failed = as == NULL || expect == NULL || method[0] == '\0' || path[0] == '\0';
    if (!failed && strcmp(as, "null") != 0) {
        char tenant_id[32];
        char username[64];
        vec_text(as, "tenantId", tenant_id, sizeof(tenant_id));
        vec_text(as, "username", username, sizeof(username));
        wb_identity *identity = find_identity(scenario, tenant_id, username);
        failed = identity == NULL;
        bearer = identity == NULL ? NULL : identity->bearer;
    }
    int session_rejected = !failed && vec_bool(expect, "sessionRejected");
    size_t before_count = 0U;
    size_t after_count = 0U;
    if (!failed && session_rejected) {
        failed = dump_rows(scenario->base_ms, before, WB_MAX_ROWS, &before_count) != 0;
    }
    wb_response response;
    if (!failed) {
        failed = call(method, path, bearer, NULL, buffer, sizeof(buffer), &response) != 0;
    }
    if (!failed && session_rejected) {
        /* A token of a deleted account is refused by the shared layer (403 here) and writes nothing. */
        failed = (response.status >= 200 && response.status < 300)
            || strcmp(response.cache_control, "private, no-store") != 0;
        if (!failed) {
            failed = dump_rows(scenario->base_ms, after, WB_MAX_ROWS, &after_count) != 0
                || !rows_equal(before, before_count, after, after_count);
        }
    } else if (!failed) {
        long long status = 0;
        long long retry_after = 0;
        failed = vec_i64(expect, "httpStatus", &status) != 0 || response.status != (int)status;
        if (!failed && strcmp(response.cache_control, "private, no-store") != 0) {
            fprintf(stderr, "missing Cache-Control: private, no-store\n");
            failed = 1;
        }
        if (!failed && vec_i64(expect, "retryAfterSeconds", &retry_after) == 0) {
            failed = !response.has_retry_after || strtoll(response.retry_after, NULL, 10) != retry_after;
        } else if (!failed) {
            failed = response.has_retry_after;
        }
        char *expected_body = failed ? NULL : st_json_get_top_level_raw(expect, "body");
        if (!failed && expected_body != NULL && status == 200) {
            char *minified = minify_json(expected_body);
            failed = minified == NULL || strcmp(minified, response.body) != 0;
            if (failed) {
                fprintf(stderr, "  expected body %s\n", minified == NULL ? "?" : minified);
            }
            free(minified);
        } else if (!failed && expected_body != NULL) {
            char *expected_code = body_code(expected_body);
            char *actual_code = body_code(response.body);
            failed = expected_code == NULL || actual_code == NULL || strcmp(expected_code, actual_code) != 0;
            free(expected_code);
            free(actual_code);
        }
        free(expected_body);
    }
    if (failed) {
        fprintf(stderr, "workbench vector %s step %zu (%s %s) failed; expected %s, got: %.600s\n",
                scenario_name, index, method, path, expect == NULL ? "?" : expect, buffer);
    }
    free(as);
    free(expect);
    return failed ? -1 : 0;
}

static int replay_scenario(const char *raw, long long base_ms, size_t *steps_replayed)
{
    static wb_scenario scenario;
    static wb_row expected_rows[WB_MAX_ROWS];
    static wb_row actual_rows[WB_MAX_ROWS];
    char name[96];
    vec_text(raw, "name", name, sizeof(name));
    memset(&scenario, 0, sizeof(scenario));
    scenario.base_ms = base_ms;
    scenario.next_listen_port = 20000;
    if (open_fresh_database() != 0) {
        return -1;
    }
    char **users = NULL;
    char **objects = NULL;
    char **rows = NULL;
    char **steps = NULL;
    char **rows_after = NULL;
    size_t users_len = 0U, objects_len = 0U, rows_len = 0U, steps_len = 0U, rows_after_len = 0U;
    int rc = vec_array(raw, "users", &users, &users_len) == 0
        && vec_array(raw, "objects", &objects, &objects_len) == 0
        && vec_array(raw, "rows", &rows, &rows_len) == 0
        && vec_array(raw, "steps", &steps, &steps_len) == 0
        && vec_array(raw, "rowsAfter", &rows_after, &rows_after_len) == 0 ? 0 : -1;
    if (rc != 0) {
        fprintf(stderr, "scenario %s is not readable\n", name);
    }
    for (size_t i = 0; rc == 0 && i < users_len; ++i) {
        char tenant_id[32];
        char username[64];
        vec_text(users[i], "tenantId", tenant_id, sizeof(tenant_id));
        vec_text(users[i], "username", username, sizeof(username));
        rc = st_storage_create_management_user(test_db_path, username, tenant_id, "unused-password-hash",
                                               vec_bool(users[i], "admin") ? "ADMIN" : "USER", 1, NULL);
        if (rc == 0) {
            rc = remember_identity(&scenario, tenant_id, username);
        }
    }
    for (size_t i = 0; rc == 0 && i < objects_len; ++i) {
        char kind[16];
        char tenant_id[32];
        char owner[64];
        long long id = 0;
        vec_text(objects[i], "kind", kind, sizeof(kind));
        vec_text(objects[i], "tenantId", tenant_id, sizeof(tenant_id));
        vec_text(objects[i], "ownerUsername", owner, sizeof(owner));
        rc = vec_i64(objects[i], "id", &id) == 0 ? create_object(&scenario, kind, id, tenant_id, owner) : -1;
    }
    for (size_t i = 0; rc == 0 && i < rows_len; ++i) {
        wb_row row;
        rc = parse_row(rows[i], &row);
        const char *texts[] = {row.tenant_id, row.username, row.list, row.kind};
        long long ints[] = {row.id, base_ms + row.at_ms};
        if (rc == 0) {
            rc = exec_bound("INSERT INTO management_workbench_item(tenant_id, username, list, kind, object_id, at_ms) "
                            "VALUES(?,?,?,?,?,?)", "ttttii", texts, ints);
        }
    }
    if (rc != 0) {
        fprintf(stderr, "scenario %s setup failed\n", name);
    }
    st_workbench_rate_limit_reset();
    for (size_t i = 0; rc == 0 && i < steps_len; ++i) {
        long long at_ms = 0;
        char event[32];
        rc = vec_i64(steps[i], "atMs", &at_ms);
        test_clock_ms = base_ms + at_ms;
        vec_text(steps[i], "event", event, sizeof(event));
        if (rc == 0 && event[0] != '\0') {
            rc = replay_event(&scenario, steps[i], event);
            if (rc != 0) {
                fprintf(stderr, "workbench vector %s step %zu event %s failed\n", name, i, event);
            }
        } else if (rc == 0) {
            rc = replay_call(&scenario, name, i, steps[i]);
        }
        if (rc == 0) {
            ++*steps_replayed;
        }
    }
    size_t expected_count = 0U;
    size_t actual_count = 0U;
    for (size_t i = 0; rc == 0 && i < rows_after_len; ++i) {
        if (expected_count == WB_MAX_ROWS) {
            rc = -1;
            break;
        }
        rc = parse_row(rows_after[i], &expected_rows[expected_count++]);
    }
    if (rc == 0) {
        qsort(expected_rows, expected_count, sizeof(expected_rows[0]), compare_rows);
        rc = dump_rows(base_ms, actual_rows, WB_MAX_ROWS, &actual_count);
    }
    if (rc == 0 && !rows_equal(expected_rows, expected_count, actual_rows, actual_count)) {
        fprintf(stderr, "workbench vector %s: stored rows differ from rowsAfter\n", name);
        print_rows("expected", expected_rows, expected_count);
        print_rows("stored", actual_rows, actual_count);
        rc = -1;
    }
    st_json_free_string_array(users, users_len);
    st_json_free_string_array(objects, objects_len);
    st_json_free_string_array(rows, rows_len);
    st_json_free_string_array(steps, steps_len);
    st_json_free_string_array(rows_after, rows_after_len);
    return rc;
}

static int test_workbench_vector(void)
{
    FILE *file = fopen(ST_WORKBENCH_VECTOR_FILE, "rb");
    if (file == NULL) {
        perror(ST_WORKBENCH_VECTOR_FILE);
        return 1;
    }
    char *vector = NULL;
    long size = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (size > 0 && fseek(file, 0, SEEK_SET) == 0) {
        vector = (char *)malloc((size_t)size + 1U);
        if (vector != NULL && fread(vector, 1, (size_t)size, file) == (size_t)size) {
            vector[size] = '\0';
        } else {
            free(vector);
            vector = NULL;
        }
    }
    fclose(file);
    if (vector == NULL) {
        fprintf(stderr, "workbench vector could not be read\n");
        return 1;
    }
    char base_time[32];
    char *limits = st_json_get_top_level_raw(vector, "limits");
    char *rate = st_json_get_top_level_raw(vector, "rate");
    long long base_ms = 0;
    long long max_favorites = 0, max_recents = 0, retention_ms = 0, max_id = 0, interval = 0, burst = 0;
    vec_text(vector, "baseTime", base_time, sizeof(base_time));
    int failed = limits == NULL || rate == NULL || parse_base_time(base_time, &base_ms) != 0
        || vec_i64(limits, "maxFavorites", &max_favorites) != 0 || max_favorites != ST_STORAGE_WORKBENCH_MAX_FAVORITES
        || vec_i64(limits, "maxRecents", &max_recents) != 0 || max_recents != ST_STORAGE_WORKBENCH_MAX_RECENTS
        || vec_i64(limits, "recentRetentionMs", &retention_ms) != 0
        || retention_ms != ST_STORAGE_WORKBENCH_RECENT_RETENTION_MS
        || vec_i64(limits, "maxObjectId", &max_id) != 0 || max_id != ST_WORKBENCH_MAX_OBJECT_ID
        || vec_i64(rate, "intervalMs", &interval) != 0 || interval != ST_WORKBENCH_RATE_INTERVAL_MS
        || vec_i64(rate, "burst", &burst) != 0 || burst != ST_WORKBENCH_RATE_BURST;
    free(limits);
    free(rate);
    if (failed) {
        fprintf(stderr, "workbench vector limits, rate or baseTime differ from the implementation\n");
        free(vector);
        return 1;
    }
    char **scenarios = NULL;
    size_t scenario_count = 0U;
    if (vec_array(vector, "scenarios", &scenarios, &scenario_count) != 0 || scenario_count == 0U) {
        fprintf(stderr, "workbench vector has no scenarios\n");
        free(vector);
        return 1;
    }
    size_t step_total = 0U;
    size_t steps_replayed = 0U;
    size_t scenarios_replayed = 0U;
    for (size_t i = 0; i < scenario_count; ++i) {
        char **steps = NULL;
        size_t steps_len = 0U;
        if (vec_array(scenarios[i], "steps", &steps, &steps_len) == 0) {
            step_total += steps_len;
        }
        st_json_free_string_array(steps, steps_len);
        if (replay_scenario(scenarios[i], base_ms, &steps_replayed) == 0) {
            ++scenarios_replayed;
        } else {
            failed = 1;
        }
    }
    st_json_free_string_array(scenarios, scenario_count);
    free(vector);
    printf("workbench vector: replayed %zu/%zu scenarios, %zu/%zu steps\n",
           scenarios_replayed, scenario_count, steps_replayed, step_total);
    if (failed || scenarios_replayed != scenario_count || steps_replayed != step_total) {
        fprintf(stderr, "workbench vector replay incomplete\n");
        return 1;
    }
    return 0;
}

/* ---- HTTP-level isolation, auth and headers ------------------------------------------------ */

static int expect_response(const char *label, const wb_response *response, int status, const char *code)
{
    /* Every workbench answer is private, the shared layer's 401 and 403 included. */
    int ok = response->status == status && strcmp(response->cache_control, "private, no-store") == 0;
    if (ok && code != NULL) {
        char *actual = body_code(response->body);
        ok = actual != NULL && strcmp(actual, code) == 0;
        free(actual);
    }
    if (!ok) {
        fprintf(stderr, "%s: expected %d %s, got %d (Cache-Control %s): %s\n", label, status,
                code == NULL ? "" : code, response->status, response->cache_control, response->body);
    }
    return ok ? 0 : 1;
}

static int expect_document(const char *label, const wb_response *response, const char *favorites,
                           const char *recents)
{
    char *actual_favorites = st_json_get_top_level_raw(response->body, "favorites");
    char *actual_recents = st_json_get_top_level_raw(response->body, "recents");
    int ok = response->status == 200 && strcmp(response->cache_control, "private, no-store") == 0
        && actual_favorites != NULL && actual_recents != NULL
        && strcmp(actual_favorites, favorites) == 0 && strcmp(actual_recents, recents) == 0;
    if (!ok) {
        fprintf(stderr, "%s: expected favorites %s recents %s, got %d: %s\n", label, favorites, recents,
                response->status, response->body);
    }
    free(actual_favorites);
    free(actual_recents);
    return ok ? 0 : 1;
}

static int test_workbench_http_isolation(void)
{
    static char buffer[WB_RESPONSE_BYTES];
    static wb_scenario scenario;
    wb_response response;
    memset(&scenario, 0, sizeof(scenario));
    scenario.next_listen_port = 21000;
    if (open_fresh_database() != 0
        || st_storage_create_management_user(test_db_path, "alice", "t1", "unused", "USER", 1, NULL) != 0
        || st_storage_create_management_user(test_db_path, "root", "t1", "unused", "ADMIN", 1, NULL) != 0
        || create_object(&scenario, "http-route", 1, "t1", "alice") != 0
        || create_object(&scenario, "tcp-mapping", 5, "t1", "alice") != 0) {
        return 1;
    }
    test_clock_ms = 1791244800000LL;
    char alice[2400];
    char root[2400];
    char builtin[2400];
    if (issue_bearer("alice", "t1", alice, sizeof(alice)) != 0 || issue_bearer("root", "t1", root, sizeof(root)) != 0
        || issue_bearer("admin", "default", builtin, sizeof(builtin)) != 0) {
        return 1;
    }
    int failures = 0;
    /* No session: the shared layer answers 401 before the path is looked at. */
    const char *const unauthenticated[][2] = {
        {"GET", "/api/admin/workbench"},
        {"PUT", "/api/admin/workbench/favorites/http-route/1"},
        {"PUT", "/api/admin/workbench/favorites/bad/042"},
        {"DELETE", "/api/admin/workbench/recents"},
    };
    for (size_t i = 0; i < sizeof(unauthenticated) / sizeof(unauthenticated[0]); ++i) {
        failures += call(unauthenticated[i][0], unauthenticated[i][1], NULL, NULL, buffer, sizeof(buffer), &response) != 0
            || expect_response("unauthenticated", &response, 401, NULL);
    }
    failures += call("GET", "/api/admin/workbench", "Bearer not-a-token", NULL, buffer, sizeof(buffer), &response) != 0
        || expect_response("invalid token", &response, 401, NULL);
    /* 042 is not 42: the id is checked on the raw path text, and 400 carries the header too. */
    failures += call("PUT", "/api/admin/workbench/favorites/http-route/042", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || expect_response("leading zero", &response, 400, "WORKBENCH_REQUEST_INVALID");
    failures += call("POST", "/api/admin/workbench/recents/http-route/%31", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || expect_response("percent-encoded id", &response, 400, "WORKBENCH_REQUEST_INVALID");
    failures += call("PUT", "/api/admin/workbench/favorites/http-route/77", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || expect_response("missing target", &response, 404, "WORKBENCH_TARGET_NOT_FOUND");
    /* The body is never read: it cannot name another identity or another reference. */
    failures += call("PUT", "/api/admin/workbench/favorites/http-route/1", alice,
                     "{\"tenantId\":\"t1\",\"username\":\"root\",\"kind\":\"tcp-mapping\",\"id\":5}",
                     buffer, sizeof(buffer), &response) != 0
        || expect_document("body ignored", &response,
                           "[{\"kind\":\"http-route\",\"id\":1,\"addedAt\":\"2026-10-06T00:00:00.000Z\"}]", "[]");
    test_clock_ms += 1;
    failures += call("POST", "/api/admin/workbench/recents/tcp-mapping/5?username=root", alice, NULL, buffer,
                     sizeof(buffer), &response) != 0
        || expect_document("query ignored", &response,
                           "[{\"kind\":\"http-route\",\"id\":1,\"addedAt\":\"2026-10-06T00:00:00.000Z\"}]",
                           "[{\"kind\":\"tcp-mapping\",\"id\":5,\"visitedAt\":\"2026-10-06T00:00:00.001Z\"}]");
    /* An administrator reads and clears only their own lists; there is no path to anyone else's. */
    failures += call("GET", "/api/admin/workbench", root, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("admin reads own", &response, "[]", "[]");
    failures += call("GET", "/api/admin/workbench?username=alice", root, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("admin query", &response, "[]", "[]");
    failures += call("GET", "/api/admin/workbench/alice", root, NULL, buffer, sizeof(buffer), &response) != 0
        || response.status != 404;
    failures += call("DELETE", "/api/admin/workbench/favorites", root, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("admin clears own favourites", &response, "[]", "[]");
    failures += call("DELETE", "/api/admin/workbench/recents", root, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("admin clears own recents", &response, "[]", "[]");
    failures += call("GET", "/api/admin/workbench", alice, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("alice untouched", &response,
                           "[{\"kind\":\"http-route\",\"id\":1,\"addedAt\":\"2026-10-06T00:00:00.000Z\"}]",
                           "[{\"kind\":\"tcp-mapping\",\"id\":5,\"visitedAt\":\"2026-10-06T00:00:00.001Z\"}]");
    /* The built-in administrator is the identity (default tenant, configured name). */
    failures += call("GET", "/api/admin/workbench", builtin, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("built-in admin", &response, "[]", "[]");
    /* A disabled account is refused by the shared layer and writes nothing; disabling deletes nothing. */
    st_storage_management_user user;
    failures += st_storage_update_management_user(test_db_path, "t1", "alice", NULL, NULL, 0, &user) != 0;
    failures += call("DELETE", "/api/admin/workbench/favorites", alice, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_response("disabled account", &response, 403, NULL);
    failures += st_storage_update_management_user(test_db_path, "t1", "alice", NULL, NULL, 1, &user) != 0;
    failures += query_i64("SELECT COUNT(*) FROM management_workbench_item WHERE username = ?", "alice") != 2;
    /* 429 carries Retry-After and the private header; the limiter key is the identity. */
    st_workbench_rate_limit_reset();
    for (int i = 0; i < 30; ++i) {
        failures += call("POST", "/api/admin/workbench/recents/http-route/1", alice, NULL, buffer, sizeof(buffer),
                         &response) != 0 || response.status != 200;
    }
    failures += call("PUT", "/api/admin/workbench/favorites/http-route/1", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || expect_response("rate limited", &response, 429, "WORKBENCH_RATE_LIMITED")
        || !response.has_retry_after || strcmp(response.retry_after, "1") != 0;
    failures += call("PUT", "/api/admin/workbench/favorites/http-route/1", root, NULL, buffer, sizeof(buffer),
                     &response) != 0 || response.status != 200;
    /*
     * A broken store is 503, never empty lists; reads included. The store is touched before the
     * target is looked at, so a missing object answers 503 rather than 404 while it is down.
     */
    st_workbench_rate_limit_reset();
    failures += exec_sql("ALTER TABLE management_workbench_item RENAME TO management_workbench_item_down") != 0;
    failures += call("GET", "/api/admin/workbench", alice, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_response("store down read", &response, 503, "WORKBENCH_UNAVAILABLE");
    failures += call("PUT", "/api/admin/workbench/favorites/http-route/77", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || expect_response("store down before visibility", &response, 503, "WORKBENCH_UNAVAILABLE");
    failures += call("DELETE", "/api/admin/workbench/recents/http-route/1", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || expect_response("store down removal", &response, 503, "WORKBENCH_UNAVAILABLE");
    failures += exec_sql("ALTER TABLE management_workbench_item_down RENAME TO management_workbench_item") != 0;
    /* Without a database there is no store at all. */
    unsetenv("SPECUS_DATABASE_PATH");
    failures += call("GET", "/api/admin/workbench", builtin, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_response("no database", &response, 503, "WORKBENCH_UNAVAILABLE");
    setenv("SPECUS_DATABASE_PATH", test_db_path, 1);
    if (failures != 0) {
        fprintf(stderr, "workbench HTTP isolation test failed (%d)\n", failures);
    }
    return failures == 0 ? 0 : 1;
}

/* Within one millisecond the kind order decides before the id, in both lists. */
static int test_workbench_kind_order(void)
{
    static char buffer[WB_RESPONSE_BYTES];
    static wb_scenario scenario;
    wb_response response;
    memset(&scenario, 0, sizeof(scenario));
    scenario.next_listen_port = 23000;
    char alice[2400];
    if (open_fresh_database() != 0
        || st_storage_create_management_user(test_db_path, "alice", "t1", "unused", "USER", 1, NULL) != 0
        || create_object(&scenario, "peer-service", 3, "t1", "alice") != 0
        || create_object(&scenario, "tcp-mapping", 4, "t1", "alice") != 0
        || create_object(&scenario, "http-route", 7, "t1", "alice") != 0
        || issue_bearer("alice", "t1", alice, sizeof(alice)) != 0) {
        return 1;
    }
    test_clock_ms = 1791244800000LL + 5LL;
    const char *const paths[] = {
        "/api/admin/workbench/favorites/peer-service/3",
        "/api/admin/workbench/favorites/http-route/7",
        "/api/admin/workbench/favorites/tcp-mapping/4",
        "/api/admin/workbench/recents/peer-service/3",
        "/api/admin/workbench/recents/http-route/7",
        "/api/admin/workbench/recents/tcp-mapping/4",
    };
    int failures = 0;
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        failures += call(i < 3U ? "PUT" : "POST", paths[i], alice, NULL, buffer, sizeof(buffer), &response) != 0
            || response.status != 200;
    }
    failures += expect_document("kind order", &response,
                                "[{\"kind\":\"http-route\",\"id\":7,\"addedAt\":\"2026-10-06T00:00:00.005Z\"},"
                                "{\"kind\":\"tcp-mapping\",\"id\":4,\"addedAt\":\"2026-10-06T00:00:00.005Z\"},"
                                "{\"kind\":\"peer-service\",\"id\":3,\"addedAt\":\"2026-10-06T00:00:00.005Z\"}]",
                                "[{\"kind\":\"http-route\",\"id\":7,\"visitedAt\":\"2026-10-06T00:00:00.005Z\"},"
                                "{\"kind\":\"tcp-mapping\",\"id\":4,\"visitedAt\":\"2026-10-06T00:00:00.005Z\"},"
                                "{\"kind\":\"peer-service\",\"id\":3,\"visitedAt\":\"2026-10-06T00:00:00.005Z\"}]");
    return failures == 0 ? 0 : 1;
}

/* The limiter's key bound: idle keys are evicted, active ones make a new key wait one second. */
static int test_workbench_rate_limit_key_bound(void)
{
    st_workbench_rate_limit_reset();
    char username[32];
    for (unsigned int i = 0; i < ST_WORKBENCH_RATE_MAX_KEYS; ++i) {
        snprintf(username, sizeof(username), "user-%u", i);
        if (st_workbench_rate_limit_acquire("t1", username, 1000) != 0) {
            fprintf(stderr, "rate limit key %u refused\n", i);
            return 1;
        }
    }
    long long wait_ms = st_workbench_rate_limit_acquire("t1", "one-more", 1500);
    int failed = wait_ms <= 0 || st_workbench_retry_after_seconds(wait_ms) != 1;
    /* An existing key is still served while the table is full. */
    failed = failed || st_workbench_rate_limit_acquire("t1", "user-7", 1500) != 0;
    /* At 2000 every other key's TAT (2000) is due, so they are evicted and the new key fits. */
    failed = failed || st_workbench_rate_limit_acquire("t1", "one-more", 2000) != 0;
    failed = failed || st_workbench_retry_after_seconds(1) != 1 || st_workbench_retry_after_seconds(1001) != 2;
    st_workbench_rate_limit_reset();
    if (failed) {
        fprintf(stderr, "workbench rate limit key bound failed\n");
    }
    return failed ? 1 : 0;
}

/* ---- Cascades through the existing delete endpoints ---------------------------------------- */

static long long count_rows(const char *kind, long long id)
{
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM management_workbench_item WHERE kind = ? AND object_id = %lld", id);
    return query_i64(sql, kind);
}

static int add_both_lists(const char *bearer, const char *kind, long long id)
{
    static char buffer[WB_RESPONSE_BYTES];
    wb_response response;
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/workbench/favorites/%s/%lld", kind, id);
    if (call("PUT", path, bearer, NULL, buffer, sizeof(buffer), &response) != 0 || response.status != 200) {
        fprintf(stderr, "favourite %s %lld failed: %s\n", kind, id, buffer);
        return 1;
    }
    snprintf(path, sizeof(path), "/api/admin/workbench/recents/%s/%lld", kind, id);
    if (call("POST", path, bearer, NULL, buffer, sizeof(buffer), &response) != 0 || response.status != 200) {
        fprintf(stderr, "open %s %lld failed: %s\n", kind, id, buffer);
        return 1;
    }
    return 0;
}

static int test_workbench_cascades(void)
{
    static char buffer[WB_RESPONSE_BYTES];
    static wb_scenario scenario;
    wb_response response;
    memset(&scenario, 0, sizeof(scenario));
    scenario.next_listen_port = 22000;
    if (open_fresh_database() != 0
        || st_storage_create_management_user(test_db_path, "alice", "t1", "unused", "USER", 1, NULL) != 0
        || st_storage_create_management_user(test_db_path, "root", "t1", "unused", "ADMIN", 1, NULL) != 0
        || create_object(&scenario, "http-route", 11, "t1", "alice") != 0
        || create_object(&scenario, "tcp-mapping", 12, "t1", "alice") != 0
        || create_object(&scenario, "peer-service", 13, "t1", "alice") != 0
        || create_object(&scenario, "http-route", 21, "t1", "carrier") != 0
        || create_object(&scenario, "tcp-mapping", 22, "t1", "carrier") != 0
        || create_object(&scenario, "peer-service", 23, "t1", "carrier") != 0
        || create_object(&scenario, "http-route", 31, "t1", "alice") != 0) {
        return 1;
    }
    /* carrier's client is owned by someone else; root (admin) references its services. */
    test_clock_ms = 1791244800000LL;
    char alice[2400];
    char root[2400];
    if (issue_bearer("alice", "t1", alice, sizeof(alice)) != 0 || issue_bearer("root", "t1", root, sizeof(root)) != 0) {
        return 1;
    }
    int failures = 0;
    const char *kinds[] = {"http-route", "tcp-mapping", "peer-service"};
    for (int i = 0; i < 3; ++i) {
        failures += add_both_lists(alice, kinds[i], 11 + i);
        failures += add_both_lists(root, kinds[i], 11 + i);
        failures += add_both_lists(root, kinds[i], 21 + i);
        test_clock_ms += 10;
    }
    failures += add_both_lists(alice, "http-route", 31);
    failures += add_both_lists(root, "http-route", 31);
    if (failures != 0) {
        return 1;
    }
    /* Route, mapping and Peer service deletions remove every identity's references to them. */
    failures += call("DELETE", "/api/admin/http-routes/11", alice, NULL, buffer, sizeof(buffer), &response) != 0
        || response.status != 204 || count_rows("http-route", 11) != 0;
    failures += call("DELETE", "/api/admin/specus-mappings/12", alice, NULL, buffer, sizeof(buffer), &response) != 0
        || response.status != 204 || count_rows("tcp-mapping", 12) != 0;
    failures += call("DELETE", "/api/admin/peer-mesh/services/13", root, NULL, buffer, sizeof(buffer), &response) != 0
        || response.status != 204 || count_rows("peer-service", 13) != 0;
    failures += count_rows("http-route", 21) != 2 || count_rows("http-route", 31) != 4;
    if (failures != 0) {
        fprintf(stderr, "object deletions did not cascade: %s\n", buffer);
        return 1;
    }
    /* A client deletion removes the references to its routes, mappings and Peer services. */
    long long carrier = query_i64("SELECT rowid FROM client_account WHERE client_name = ?", "wb-t1-carrier");
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", carrier);
    failures += call("DELETE", path, root, NULL, buffer, sizeof(buffer), &response) != 0 || response.status != 204;
    failures += count_rows("http-route", 21) != 0 || count_rows("tcp-mapping", 22) != 0
        || count_rows("peer-service", 23) != 0 || count_rows("http-route", 31) != 4;
    if (failures != 0) {
        fprintf(stderr, "client deletion did not cascade: %s\n", buffer);
        return 1;
    }
    /* Deleting an account deletes its rows only; a token issued before is refused and writes nothing. */
    failures += call("DELETE", "/api/admin/users/alice", root, NULL, buffer, sizeof(buffer), &response) != 0
        || response.status != 204;
    failures += query_i64("SELECT COUNT(*) FROM management_workbench_item WHERE username = ?", "alice") != 0
        || query_i64("SELECT COUNT(*) FROM management_workbench_item WHERE username = ?", "root") != 2;
    failures += call("POST", "/api/admin/workbench/recents/http-route/31", alice, NULL, buffer, sizeof(buffer),
                     &response) != 0
        || response.status != 403
        || query_i64("SELECT COUNT(*) FROM management_workbench_item WHERE username = ?", "alice") != 0;
    /* The same name created again starts with empty lists. */
    failures += call("POST", "/api/admin/users", root,
                     "{\"username\":\"alice\",\"password\":\"wb-password-1\",\"role\":\"USER\",\"enabled\":true}",
                     buffer, sizeof(buffer), &response) != 0
        || response.status != 201;
    failures += call("GET", "/api/admin/workbench", alice, NULL, buffer, sizeof(buffer), &response) != 0
        || expect_document("recreated account", &response, "[]", "[]");
    if (failures != 0) {
        fprintf(stderr, "account deletion did not cascade: %s\n", buffer);
    }
    return failures == 0 ? 0 : 1;
}

int main(void)
{
    setenv("SPECUS_AUTH_JWT_SECRET", "c-workbench-test-secret", 1);
    setenv("SPECUS_AUTH_PASSWORD", "admin", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    unsetenv("SPECUS_AUTH_USERNAME");
    unsetenv("SPECUS_AUTH_TENANT_ID");
    st_workbench_set_clock(test_clock);
    int failures = 0;
    failures += test_workbench_vector();
    failures += test_workbench_http_isolation();
    failures += test_workbench_kind_order();
    failures += test_workbench_rate_limit_key_bound();
    failures += test_workbench_cascades();
    st_workbench_set_clock(NULL);
    if (test_db_path[0] != '\0') {
        unlink(test_db_path);
    }
    if (failures != 0) {
        fprintf(stderr, "workbench tests failed: %d\n", failures);
        return 1;
    }
    printf("workbench tests passed\n");
    return 0;
}
