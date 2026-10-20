#define _POSIX_C_SOURCE 200809L

/*
 * Temporary HTTP shares (protocol/spec/temporary-http-share.md). The shared vector is replayed
 * section by section through the real code: a real SQLite database seeded with the vector's world,
 * the real management, exchange and /http-share/ handlers behind a real listening socket, and a
 * fake device in place of the client that records the NAT OPEN metadata it would have received.
 * HTTP-level tests then cover cookies, header rewriting, revocation, in-flight cuts and cascades.
 */

#include "admin_http.h"
#include "http_share.h"
#include "json.h"
#include "security.h"
#include "storage.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#ifndef ST_SHARE_VECTOR_FILE
#define ST_SHARE_VECTOR_FILE "../../../protocol/test-vectors/temporary-http-share-v1.json"
#endif

#define VECTOR_NOW "2026-10-06T08:00:00Z"
#define RESPONSE_CAP (256U * 1024U)

static char db_path[256];
static char *vector_json = NULL;
static int server_port = 0;
static st_admin_server admin_server;

/* ------------------------------------------------------------------------------------------------
 * A small JSON reader for the vector
 */

static const char *jws(const char *p)
{
    while (*p != '\0' && isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

static const char *jskip_string(const char *p)
{
    if (*p != '"') {
        return NULL;
    }
    for (++p; *p != '\0'; ++p) {
        if (*p == '\\') {
            if (p[1] == '\0') {
                return NULL;
            }
            ++p;
        } else if (*p == '"') {
            return p + 1;
        }
    }
    return NULL;
}

static const char *jskip_value(const char *p)
{
    p = jws(p);
    if (*p == '"') {
        return jskip_string(p);
    }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p != '\0') {
            if (*p == '"') {
                p = jskip_string(p);
                if (p == NULL) {
                    return NULL;
                }
                continue;
            }
            if (*p == '{' || *p == '[') {
                ++depth;
            } else if ((*p == '}' || *p == ']') && --depth == 0) {
                return p + 1;
            }
            ++p;
        }
        return NULL;
    }
    while (*p != '\0' && *p != ',' && *p != '}' && *p != ']' && !isspace((unsigned char)*p)) {
        ++p;
    }
    return p;
}

static char *jdup(const char *start, size_t len)
{
    char *copy = (char *)malloc(len + 1U);
    if (copy != NULL) {
        memcpy(copy, start, len);
        copy[len] = '\0';
    }
    return copy;
}

typedef struct {
    char *key;
    char *value;
} jmember;

/* Members of an object as decoded keys and raw values; returns how many (at most max). */
static size_t jmembers(const char *object, jmember *out, size_t max)
{
    size_t count = 0U;
    const char *p = jws(object);
    if (*p != '{') {
        return 0U;
    }
    p = jws(p + 1);
    while (*p == '"' && count < max) {
        const char *key_end = jskip_string(p);
        char *raw_key = jdup(p, (size_t)(key_end - p));
        out[count].key = st_json_decode_string(raw_key, NULL);
        free(raw_key);
        p = jws(key_end);
        p = jws(p + 1); /* ':' */
        const char *value_end = jskip_value(p);
        out[count].value = jdup(p, (size_t)(value_end - p));
        ++count;
        p = jws(value_end);
        if (*p == ',') {
            p = jws(p + 1);
        }
    }
    return count;
}

static void jmembers_free(jmember *members, size_t count)
{
    for (size_t i = 0U; i < count; ++i) {
        free(members[i].key);
        free(members[i].value);
    }
}

/* Raw items of an array; *count receives how many (at most max). */
static size_t jitems(const char *array, char **out, size_t max)
{
    size_t count = 0U;
    const char *p = jws(array);
    if (*p != '[') {
        return 0U;
    }
    p = jws(p + 1);
    while (*p != ']' && *p != '\0' && count < max) {
        const char *end = jskip_value(p);
        out[count++] = jdup(p, (size_t)(end - p));
        p = jws(end);
        if (*p == ',') {
            p = jws(p + 1);
        }
    }
    return count;
}

static void jitems_free(char **items, size_t count)
{
    for (size_t i = 0U; i < count; ++i) {
        free(items[i]);
    }
}

/* The raw value of key in an object, malloc'd, or NULL. */
static char *jget(const char *object, const char *key)
{
    if (object == NULL) {
        return NULL;
    }
    jmember members[64];
    size_t count = jmembers(object, members, 64U);
    char *found = NULL;
    for (size_t i = 0U; i < count; ++i) {
        if (found == NULL && members[i].key != NULL && strcmp(members[i].key, key) == 0) {
            found = members[i].value;
            members[i].value = NULL;
        }
    }
    jmembers_free(members, count);
    return found;
}

/* A raw JSON string decoded (len optional), or NULL when it is not a string. */
static char *jstring(const char *raw, size_t *len)
{
    if (raw == NULL || *jws(raw) != '"') {
        return NULL;
    }
    return st_json_decode_string(raw, len);
}

static char *jget_string(const char *object, const char *key)
{
    char *raw = jget(object, key);
    char *value = jstring(raw, NULL);
    free(raw);
    return value;
}

static int jget_int(const char *object, const char *key, long long *out)
{
    char *raw = jget(object, key);
    if (raw == NULL || (*raw != '-' && !isdigit((unsigned char)*raw))) {
        free(raw);
        return -1;
    }
    *out = strtoll(raw, NULL, 10);
    free(raw);
    return 0;
}

static int jget_bool(const char *object, const char *key, int fallback)
{
    char *raw = jget(object, key);
    int value = raw == NULL ? fallback : strcmp(raw, "true") == 0;
    free(raw);
    return value;
}

static int jis_null(const char *raw)
{
    return raw == NULL || strcmp(jws(raw), "null") == 0;
}

/* Structural equality of two JSON texts (object member order ignored). */
static int jequal(const char *a, const char *b)
{
    a = jws(a);
    b = jws(b);
    if (*a == '{' || *b == '{') {
        if (*a != '{' || *b != '{') {
            return 0;
        }
        jmember am[64];
        jmember bm[64];
        size_t an = jmembers(a, am, 64U);
        size_t bn = jmembers(b, bm, 64U);
        int equal = an == bn;
        for (size_t i = 0U; equal && i < an; ++i) {
            int matched = 0;
            for (size_t j = 0U; j < bn && !matched; ++j) {
                if (strcmp(am[i].key, bm[j].key) == 0) {
                    matched = 1;
                    equal = jequal(am[i].value, bm[j].value);
                }
            }
            equal = equal && matched;
        }
        jmembers_free(am, an);
        jmembers_free(bm, bn);
        return equal;
    }
    if (*a == '[' || *b == '[') {
        if (*a != '[' || *b != '[') {
            return 0;
        }
        char *ai[64];
        char *bi[64];
        size_t an = jitems(a, ai, 64U);
        size_t bn = jitems(b, bi, 64U);
        int equal = an == bn;
        for (size_t i = 0U; equal && i < an; ++i) {
            equal = jequal(ai[i], bi[i]);
        }
        jitems_free(ai, an);
        jitems_free(bi, bn);
        return equal;
    }
    if (*a == '"' || *b == '"') {
        size_t al = 0U;
        size_t bl = 0U;
        const char *ae = jskip_value(a);
        const char *be = jskip_value(b);
        char *ar = jdup(a, (size_t)(ae - a));
        char *br = jdup(b, (size_t)(be - b));
        char *as = jstring(ar, &al);
        char *bs = jstring(br, &bl);
        int equal = as != NULL && bs != NULL && al == bl && memcmp(as, bs, al) == 0;
        free(ar);
        free(br);
        free(as);
        free(bs);
        return equal;
    }
    const char *ae = jskip_value(a);
    const char *be = jskip_value(b);
    return ae - a == be - b && memcmp(a, b, (size_t)(ae - a)) == 0;
}

/* ------------------------------------------------------------------------------------------------
 * Time
 */

static long long days_from_civil(long long y, int m, int d)
{
    y -= m <= 2;
    long long era = (y >= 0 ? y : y - 399) / 400;
    long long yoe = y - era * 400;
    long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static long long iso_seconds(const char *text)
{
    int y = 0, mo = 0, d = 0, h = 0, mi = 0, s = 0;
    if (text == NULL || sscanf(text, "%d-%d-%dT%d:%d:%dZ", &y, &mo, &d, &h, &mi, &s) != 6) {
        return -1;
    }
    return days_from_civil(y, mo, d) * 86400LL + h * 3600LL + mi * 60LL + s;
}

static long long monotonic_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

/* ------------------------------------------------------------------------------------------------
 * Database
 */

static int sql_exec(const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sql failed: %s: %s\n", sql, error == NULL ? sqlite3_errmsg(db) : error);
    }
    sqlite3_free(error);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

/* The single integer a query answers, or -1. */
static long long count_rows(const char *sql)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long value = -1;
    if (sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        value = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

/* The vector's world: users, clients (named client-<id>) and routes with their vector ids. */
static int seed_world(void)
{
    unlink(db_path);
    char journal[300];
    snprintf(journal, sizeof(journal), "%s-journal", db_path);
    unlink(journal);
    if (st_storage_init(db_path, 0) != 0) {
        return -1;
    }
    char *world = jget(vector_json, "world");
    char *users = jget(world, "users");
    char *clients = jget(world, "clients");
    char *routes = jget(world, "routes");
    jmember members[32];
    int rc = 0;
    size_t count = jmembers(users, members, 32U);
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        char *tenant = jget_string(members[i].value, "tenantId");
        char *role = jget_string(members[i].value, "role");
        char *sql = sqlite3_mprintf(
            "INSERT INTO specus_management_user(username, login_name, login_name_normalized, tenant_id, "
            "password_hash, role, enabled) VALUES(%Q,%Q,lower(%Q),%Q,'x',%Q,%d)",
            members[i].key, members[i].key, members[i].key, tenant, role,
            jget_bool(members[i].value, "enabled", 1));
        rc = sql_exec(sql);
        sqlite3_free(sql);
        free(tenant);
        free(role);
    }
    jmembers_free(members, count);
    count = jmembers(clients, members, 32U);
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        char *tenant = jget_string(members[i].value, "tenantId");
        char *owner = jget_string(members[i].value, "owner");
        char *sql = sqlite3_mprintf(
            "INSERT INTO client_account(rowid, tenant_id, client_name, owner_username, enabled) "
            "VALUES(%s,%Q,'client-%s',%Q,%d)",
            members[i].key, tenant, members[i].key, owner, jget_bool(members[i].value, "enabled", 1));
        rc = sql_exec(sql);
        sqlite3_free(sql);
        free(tenant);
        free(owner);
    }
    jmembers_free(members, count);
    count = jmembers(routes, members, 32U);
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        long long client_id = 0;
        char *name = jget_string(members[i].value, "name");
        (void)jget_int(members[i].value, "clientId", &client_id);
        int auth = jget_bool(members[i].value, "authEnabled", 0);
        char *sql = sqlite3_mprintf(
            "INSERT INTO http_route_mapping(id, client_name, route, target_base_url, enabled, auth_enabled, "
            "auth_username, auth_password_hash) VALUES(%s,'client-%lld',%Q,'http://127.0.0.1:9/',%d,%d,%Q,%Q)",
            members[i].key, client_id, name, jget_bool(members[i].value, "enabled", 1), auth,
            auth ? "basic-user" : "",
            auth ? "0000000000000000000000000000000000000000000000000000000000000000" : "");
        rc = sql_exec(sql);
        sqlite3_free(sql);
        free(name);
    }
    jmembers_free(members, count);
    free(world);
    free(users);
    free(clients);
    free(routes);
    return rc;
}

/* {"table":..,"key":..,"set":{..}} or {..,"deleted":true}, as worldChanges and silent-change say. */
static int apply_change(const char *change)
{
    char *table = jget_string(change, "table");
    char *key_raw = jget(change, "key");
    char *key_text = jstring(key_raw, NULL);
    const char *key = key_text != NULL ? key_text : key_raw;
    char *set = jget(change, "set");
    int deleted = jget_bool(change, "deleted", 0);
    int rc = 0;
    const char *sql_table = strcmp(table, "users") == 0 ? "specus_management_user"
        : strcmp(table, "clients") == 0 ? "client_account" : "http_route_mapping";
    const char *key_column = strcmp(table, "users") == 0 ? "username"
        : strcmp(table, "clients") == 0 ? "rowid" : "id";
    char *where = strcmp(table, "users") == 0 ? sqlite3_mprintf("%s = %Q", key_column, key)
                                              : sqlite3_mprintf("%s = %s", key_column, key);
    if (deleted) {
        char *sql = sqlite3_mprintf("DELETE FROM %s WHERE %s", sql_table, where);
        rc = sql_exec(sql);
        sqlite3_free(sql);
    } else {
        jmember fields[8];
        size_t count = jmembers(set, fields, 8U);
        for (size_t i = 0U; rc == 0 && i < count; ++i) {
            char *sql = NULL;
            if (strcmp(fields[i].key, "enabled") == 0) {
                sql = sqlite3_mprintf("UPDATE %s SET enabled = %d WHERE %s", sql_table,
                                      strcmp(fields[i].value, "true") == 0, where);
            } else if (strcmp(fields[i].key, "authEnabled") == 0) {
                sql = sqlite3_mprintf("UPDATE %s SET auth_enabled = %d WHERE %s", sql_table,
                                      strcmp(fields[i].value, "true") == 0, where);
            } else if (strcmp(fields[i].key, "role") == 0) {
                char *role = jstring(fields[i].value, NULL);
                sql = sqlite3_mprintf("UPDATE %s SET role = %Q WHERE %s", sql_table, role, where);
                free(role);
            } else {
                fprintf(stderr, "unknown world change field %s\n", fields[i].key);
                rc = -1;
            }
            if (sql != NULL) {
                rc = sql_exec(sql);
                sqlite3_free(sql);
            }
        }
        jmembers_free(fields, count);
    }
    sqlite3_free(where);
    free(table);
    free(key_raw);
    free(key_text);
    free(set);
    return rc;
}

static int insert_share_row(const char *row)
{
    char *share_id = jget_string(row, "shareId");
    char *tenant = jget_string(row, "tenantId");
    char *hash = jget_string(row, "tokenSha256");
    char *access = jget_string(row, "access");
    char *prefix = jget_string(row, "pathPrefix");
    char *label = jget_string(row, "label");
    char *created_by = jget_string(row, "createdBy");
    char *created_at = jget_string(row, "createdAt");
    char *expires_at = jget_string(row, "expiresAt");
    char *revoked_at = jget_string(row, "revokedAt");
    char *revoked_by = jget_string(row, "revokedBy");
    char *reason = jget_string(row, "revokeReason");
    long long route_id = 0;
    (void)jget_int(row, "routeId", &route_id);
    char revoked_at_sql[32] = "NULL";
    if (revoked_at != NULL) {
        snprintf(revoked_at_sql, sizeof(revoked_at_sql), "%lld", iso_seconds(revoked_at));
    }
    char *sql = sqlite3_mprintf(
        "INSERT INTO http_share(share_id, tenant_id, route_id, token_sha256, access, path_prefix, label, created_by, "
        "created_at, expires_at, revoked_at, revoked_by, revoke_reason, expiry_recorded) "
        "VALUES(%Q,%Q,%lld,%Q,%Q,%Q,%Q,%Q,%lld,%lld,%s,%Q,%Q,0)",
        share_id, tenant, route_id, hash, access, prefix, label, created_by, iso_seconds(created_at),
        iso_seconds(expires_at), revoked_at_sql, revoked_by, reason);
    int rc = sql_exec(sql);
    sqlite3_free(sql);
    free(share_id);
    free(tenant);
    free(hash);
    free(access);
    free(prefix);
    free(label);
    free(created_by);
    free(created_at);
    free(expires_at);
    free(revoked_at);
    free(revoked_by);
    free(reason);
    return rc;
}

/* World, the case's worldChanges and its stored shares. */
static int prepare_case(const char *input)
{
    if (seed_world() != 0) {
        return -1;
    }
    char *changes = jget(input, "worldChanges");
    char *items[32];
    size_t count = changes == NULL ? 0U : jitems(changes, items, 32U);
    int rc = 0;
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        rc = apply_change(items[i]);
    }
    jitems_free(items, count);
    free(changes);
    char *shares = jget(input, "shares");
    count = shares == NULL ? 0U : jitems(shares, items, 32U);
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        rc = insert_share_row(items[i]);
    }
    jitems_free(items, count);
    free(shares);
    return rc;
}

typedef struct {
    char action[48];
    long long at;
    char actor[64];
    int has_actor;
    long long route_id;
    char share_id[24];
    int has_share_id;
    char detail[512];
} audit_row;

static size_t read_audit(audit_row *rows, size_t max)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    size_t count = 0U;
    if (sqlite3_open(db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT action, occurred_at, actor, route_id, share_id, detail_json "
                                  "FROM http_access_audit ORDER BY id", -1, &stmt, NULL) == SQLITE_OK) {
        while (count < max && sqlite3_step(stmt) == SQLITE_ROW) {
            audit_row *row = &rows[count++];
            memset(row, 0, sizeof(*row));
            snprintf(row->action, sizeof(row->action), "%s", (const char *)sqlite3_column_text(stmt, 0));
            row->at = sqlite3_column_int64(stmt, 1);
            row->has_actor = sqlite3_column_type(stmt, 2) != SQLITE_NULL;
            if (row->has_actor) {
                snprintf(row->actor, sizeof(row->actor), "%s", (const char *)sqlite3_column_text(stmt, 2));
            }
            row->route_id = sqlite3_column_int64(stmt, 3);
            row->has_share_id = sqlite3_column_type(stmt, 4) != SQLITE_NULL;
            if (row->has_share_id) {
                snprintf(row->share_id, sizeof(row->share_id), "%s", (const char *)sqlite3_column_text(stmt, 4));
            }
            snprintf(row->detail, sizeof(row->detail), "%s", (const char *)sqlite3_column_text(stmt, 5));
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

/*
 * Compares the audit table with an expected "audit" array, field by field (auditId excluded).
 * route_map maps a vector route id to the id the database assigned (0 entries: identity).
 */
static int expect_audit(const char *label, const char *expected, const long long route_map[][2], size_t map_len)
{
    audit_row rows[64];
    size_t count = read_audit(rows, 64U);
    char *items[64];
    size_t expected_count = expected == NULL ? 0U : jitems(expected, items, 64U);
    int ok = count == expected_count;
    for (size_t i = 0U; ok && i < count; ++i) {
        char *action = jget_string(items[i], "action");
        char *at = jget_string(items[i], "at");
        char *actor = jget(items[i], "actor");
        char *actor_text = jstring(actor, NULL);
        char *share = jget(items[i], "shareId");
        char *share_text = jstring(share, NULL);
        char *detail = jget(items[i], "detail");
        long long route_id = 0;
        (void)jget_int(items[i], "routeId", &route_id);
        for (size_t m = 0U; m < map_len; ++m) {
            if (route_map[m][0] == route_id) {
                route_id = route_map[m][1];
            }
        }
        ok = action != NULL && strcmp(action, rows[i].action) == 0
            && iso_seconds(at) == rows[i].at
            && (jis_null(actor) ? !rows[i].has_actor : (rows[i].has_actor && strcmp(actor_text, rows[i].actor) == 0))
            && route_id == rows[i].route_id
            && (jis_null(share) ? !rows[i].has_share_id
                                : (rows[i].has_share_id && strcmp(share_text, rows[i].share_id) == 0))
            && detail != NULL && jequal(detail, rows[i].detail);
        if (!ok) {
            fprintf(stderr, "%s: audit row %zu is %s at %lld by %s route %lld share %s %s; expected %s\n", label, i,
                    rows[i].action, rows[i].at, rows[i].has_actor ? rows[i].actor : "null", rows[i].route_id,
                    rows[i].has_share_id ? rows[i].share_id : "null", rows[i].detail, items[i]);
        }
        free(action);
        free(at);
        free(actor);
        free(actor_text);
        free(share);
        free(share_text);
        free(detail);
    }
    if (count != expected_count) {
        fprintf(stderr, "%s: %zu audit rows, expected %zu\n", label, count, expected_count);
        for (size_t i = 0U; i < count; ++i) {
            fprintf(stderr, "  %s route %lld share %s %s\n", rows[i].action, rows[i].route_id,
                    rows[i].has_share_id ? rows[i].share_id : "null", rows[i].detail);
        }
    }
    jitems_free(items, expected_count);
    return ok;
}

typedef struct {
    int found;
    int revoked;
    long long revoked_at;
    char revoked_by[64];
    int has_revoked_by;
    char reason[48];
    long long expires_at;
    char token_sha256[65];
    char label[256];
    int has_label;
} share_state;

static share_state read_share(const char *share_id)
{
    share_state state;
    memset(&state, 0, sizeof(state));
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_open(db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT revoked_at, revoked_by, revoke_reason, expires_at, token_sha256, label "
                                  "FROM http_share WHERE share_id = ?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, share_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            state.found = 1;
            state.revoked = sqlite3_column_type(stmt, 0) != SQLITE_NULL;
            state.revoked_at = sqlite3_column_int64(stmt, 0);
            state.has_revoked_by = sqlite3_column_type(stmt, 1) != SQLITE_NULL;
            if (state.has_revoked_by) {
                snprintf(state.revoked_by, sizeof(state.revoked_by), "%s", (const char *)sqlite3_column_text(stmt, 1));
            }
            if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
                snprintf(state.reason, sizeof(state.reason), "%s", (const char *)sqlite3_column_text(stmt, 2));
            }
            state.expires_at = sqlite3_column_int64(stmt, 3);
            if (sqlite3_column_type(stmt, 4) != SQLITE_NULL) {
                snprintf(state.token_sha256, sizeof(state.token_sha256), "%s",
                         (const char *)sqlite3_column_text(stmt, 4));
            }
            state.has_label = sqlite3_column_type(stmt, 5) != SQLITE_NULL;
            if (state.has_label) {
                snprintf(state.label, sizeof(state.label), "%s", (const char *)sqlite3_column_text(stmt, 5));
            }
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return state;
}

/* ------------------------------------------------------------------------------------------------
 * The fake device: the forwarder and WebSocket handlers a client session would provide
 */

#define DEVICE_PLAIN 0
#define DEVICE_HEADERS 1
#define DEVICE_STREAM 2
#define DEVICE_HTML 3

typedef struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int mode;
    int ws_accept;
    int http_calls;
    int ws_calls;
    char client_name[256];
    char route[128];
    char method[16];
    char relative_path[512];
    char raw_query[512];
    int cookie_headers;
    char cookie[1024];
    char authorization[256];
    /* The Origin, Referer and Sec-Fetch-Site lines the device received, joined with '|'. */
    char browser_headers[512];
    /* Every header line the device received, one per line. */
    char all_headers[8192];
    int streaming;
    int cancelled;
    int stream_returned;
    st_admin_direct_ws_stream *ws_stream;
    int ws_closed;
    uint32_t ws_reset_code;
} fake_device;

static fake_device device = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .cond = PTHREAD_COND_INITIALIZER
};

static void device_reset(int mode)
{
    pthread_mutex_lock(&device.lock);
    st_admin_direct_ws_stream *ws = device.ws_stream;
    device.mode = mode;
    device.ws_accept = 0;
    device.http_calls = 0;
    device.ws_calls = 0;
    device.client_name[0] = '\0';
    device.route[0] = '\0';
    device.method[0] = '\0';
    device.relative_path[0] = '\0';
    device.raw_query[0] = '\0';
    device.cookie_headers = 0;
    device.cookie[0] = '\0';
    device.authorization[0] = '\0';
    device.browser_headers[0] = '\0';
    device.all_headers[0] = '\0';
    device.streaming = 0;
    device.cancelled = 0;
    device.stream_returned = 0;
    device.ws_stream = NULL;
    device.ws_closed = 0;
    device.ws_reset_code = 0U;
    pthread_mutex_unlock(&device.lock);
    st_admin_direct_ws_release(ws);
}

static void device_capture_headers(char *const *headers, size_t headers_len)
{
    for (size_t i = 0U; i < headers_len; ++i) {
        if (headers[i] == NULL) {
            continue;
        }
        size_t all_used = strlen(device.all_headers);
        snprintf(device.all_headers + all_used, sizeof(device.all_headers) - all_used, "%s\n", headers[i]);
        if (strncasecmp(headers[i], "Cookie:", 7U) == 0) {
            ++device.cookie_headers;
            snprintf(device.cookie, sizeof(device.cookie), "%s", headers[i] + 7);
        } else if (strncasecmp(headers[i], "Authorization:", 14U) == 0) {
            snprintf(device.authorization, sizeof(device.authorization), "%s", headers[i] + 14);
        } else if (strncasecmp(headers[i], "Origin:", 7U) == 0 || strncasecmp(headers[i], "Referer:", 8U) == 0
                   || strncasecmp(headers[i], "Sec-Fetch-Site:", 15U) == 0) {
            size_t used = strlen(device.browser_headers);
            snprintf(device.browser_headers + used, sizeof(device.browser_headers) - used, "%s%s",
                     used == 0U ? "" : "|", headers[i]);
        }
    }
}

static void device_cancel(void *ctx)
{
    (void)ctx;
    pthread_mutex_lock(&device.lock);
    device.cancelled = 1;
    pthread_cond_broadcast(&device.cond);
    pthread_mutex_unlock(&device.lock);
}

static int device_forward(void *ctx,
                          const char *client_name,
                          const st_direct_http_request *request,
                          const st_admin_direct_http_sink *sink)
{
    (void)ctx;
    pthread_mutex_lock(&device.lock);
    ++device.http_calls;
    snprintf(device.client_name, sizeof(device.client_name), "%s", client_name);
    snprintf(device.route, sizeof(device.route), "%s", request->route);
    snprintf(device.method, sizeof(device.method), "%s", request->request_method);
    snprintf(device.relative_path, sizeof(device.relative_path), "%s", request->relative_path);
    snprintf(device.raw_query, sizeof(device.raw_query), "%s", request->raw_query);
    device_capture_headers(request->headers, request->headers_len);
    int mode = device.mode;
    pthread_mutex_unlock(&device.lock);
    if (mode == DEVICE_HEADERS) {
        char *headers[] = {
            "Content-Type: text/plain",
            "Set-Cookie: sid=abc; Path=/; Domain=example.com; HttpOnly",
            "Set-Cookie: __Host-csrf=1; Path=/; Secure",
            "Set-Cookie: " ST_HTTP_SHARE_COOKIE_NAME "=evil; Path=/",
            "Set-Cookie: rel=1",
            "Cache-Control: public, max-age=60",
            "Expires: Wed, 21 Oct 2026 07:28:00 GMT",
            "Clear-Site-Data: \"*\""
        };
        static const uint8_t body[] = "rewritten";
        return sink->on_headers(sink->ctx, 200, headers, sizeof(headers) / sizeof(headers[0]), NULL, 0U) == 0
            && sink->on_data(sink->ctx, body, sizeof(body) - 1U) == 0
            && sink->on_end(sink->ctx, NULL, 0U) == 0 ? 0 : -1;
    }
    if (mode == DEVICE_HTML) {
        char *headers[] = {"Content-Type: text/html; charset=utf-8"};
        static const uint8_t body[] = "<html><body><a href=\"/app/page\">x</a></body></html>";
        return sink->on_headers(sink->ctx, 200, headers, 1U, NULL, 0U) == 0
            && sink->on_data(sink->ctx, body, sizeof(body) - 1U) == 0
            && sink->on_end(sink->ctx, NULL, 0U) == 0 ? 0 : -1;
    }
    if (mode == DEVICE_STREAM) {
        /* A long response: one event, then silence until the share is cut (or 20 s pass). */
        if (sink->bind_cancel != NULL) {
            sink->bind_cancel(sink->ctx, device_cancel, NULL);
        }
        char *headers[] = {"Content-Type: text/event-stream"};
        static const uint8_t first[] = "data: first\n\n";
        int rc = sink->on_headers(sink->ctx, 200, headers, 1U, NULL, 0U) == 0
            && sink->on_data(sink->ctx, first, sizeof(first) - 1U) == 0 ? 0 : -1;
        struct timespec until;
        clock_gettime(CLOCK_REALTIME, &until);
        until.tv_sec += 20;
        pthread_mutex_lock(&device.lock);
        device.streaming = 1;
        pthread_cond_broadcast(&device.cond);
        while (rc == 0 && !device.cancelled) {
            if (pthread_cond_timedwait(&device.cond, &device.lock, &until) == ETIMEDOUT) {
                break;
            }
        }
        int cancelled = device.cancelled;
        pthread_mutex_unlock(&device.lock);
        if (sink->bind_cancel != NULL) {
            sink->bind_cancel(sink->ctx, NULL, NULL);
        }
        pthread_mutex_lock(&device.lock);
        device.stream_returned = 1;
        pthread_cond_broadcast(&device.cond);
        pthread_mutex_unlock(&device.lock);
        if (cancelled) {
            return ST_ADMIN_DIRECT_HTTP_STREAM_CANCELLED; /* the client would have sent RST */
        }
        return rc == 0 && sink->on_end(sink->ctx, NULL, 0U) == 0 ? 0 : -1;
    }
    char *headers[] = {"Content-Type: text/plain"};
    static const uint8_t body[] = "forwarded";
    return sink->on_headers(sink->ctx, 200, headers, 1U, NULL, 0U) == 0
        && sink->on_data(sink->ctx, body, sizeof(body) - 1U) == 0
        && sink->on_end(sink->ctx, NULL, 0U) == 0 ? 0 : -1;
}

static int device_ws_open(void *ctx, const st_admin_direct_ws_request *request)
{
    (void)ctx;
    pthread_mutex_lock(&device.lock);
    ++device.ws_calls;
    snprintf(device.client_name, sizeof(device.client_name), "%s", request->client_name);
    snprintf(device.route, sizeof(device.route), "%s", request->route);
    snprintf(device.method, sizeof(device.method), "%s", "GET");
    snprintf(device.relative_path, sizeof(device.relative_path), "%s", request->relative_path);
    snprintf(device.raw_query, sizeof(device.raw_query), "%s", request->raw_query);
    device_capture_headers(request->headers, request->headers_len);
    int accept = device.ws_accept;
    if (accept) {
        st_admin_direct_ws_retain(request->stream);
        device.ws_stream = request->stream;
    }
    pthread_mutex_unlock(&device.lock);
    return accept ? 0 : -1;
}

static int device_ws_data(void *ctx, const char *channel_id, const uint8_t *payload, size_t payload_len)
{
    (void)ctx;
    (void)channel_id;
    (void)payload;
    (void)payload_len;
    return 0;
}

static void device_ws_close(void *ctx, const char *channel_id, uint32_t reset_code, const char *reason)
{
    (void)ctx;
    (void)channel_id;
    (void)reason;
    pthread_mutex_lock(&device.lock);
    device.ws_closed = 1;
    device.ws_reset_code = reset_code;
    pthread_cond_broadcast(&device.cond);
    pthread_mutex_unlock(&device.lock);
}

/* ------------------------------------------------------------------------------------------------
 * HTTP over the real socket, and management calls in process
 */

static int connect_server(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)server_port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_text(int fd, const char *text, size_t len)
{
    size_t sent = 0U;
    while (sent < len) {
        ssize_t written = send(fd, text + sent, len - sent, 0);
        if (written <= 0) {
            return -1;
        }
        sent += (size_t)written;
    }
    return 0;
}

/* One request and the whole answer (the server closes every connection). */
static int http_roundtrip(const char *request, size_t request_len, char *response, size_t response_cap)
{
    int fd = connect_server();
    if (fd < 0 || send_text(fd, request, request_len) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    (void)shutdown(fd, SHUT_WR);
    size_t received = 0U;
    while (received + 1U < response_cap) {
        ssize_t got = recv(fd, response + received, response_cap - 1U - received, 0);
        if (got <= 0) {
            break;
        }
        received += (size_t)got;
    }
    response[received] = '\0';
    close(fd);
    return received > 0U ? 0 : -1;
}

static int response_status(const char *response)
{
    int status = 0;
    return sscanf(response, "HTTP/1.1 %d", &status) == 1 ? status : 0;
}

/* The index-th value of a response header (exact name, case-insensitive); 1 when found. */
static int response_header(const char *response, const char *name, size_t index, char *out, size_t out_len)
{
    const char *end = strstr(response, "\r\n\r\n");
    const char *line = strstr(response, "\r\n");
    size_t name_len = strlen(name);
    size_t seen = 0U;
    while (line != NULL && end != NULL && line < end) {
        line += 2;
        const char *next = strstr(line, "\r\n");
        const char *colon = next == NULL ? NULL : memchr(line, ':', (size_t)(next - line));
        if (colon != NULL && (size_t)(colon - line) == name_len && strncasecmp(line, name, name_len) == 0) {
            if (seen++ == index) {
                const char *value = colon + 1;
                while (*value == ' ') {
                    ++value;
                }
                snprintf(out, out_len, "%.*s", (int)(next - value), value);
                return 1;
            }
        }
        line = next;
    }
    return 0;
}

static const char *response_body(const char *response)
{
    const char *body = strstr(response, "\r\n\r\n");
    return body == NULL ? "" : body + 4;
}

static char *bearer_for(const char *username)
{
    char token[2048];
    /* eve is of tenant t2, the built-in admin "root" of the default tenant, everyone else of t1. */
    const char *tenant = strcmp(username, "eve") == 0 ? "t2" : (strcmp(username, "root") == 0 ? "default" : "t1");
    if (st_security_issue_local_token(username, tenant, "USER", getenv("SPECUS_AUTH_JWT_SECRET"), 600,
                                      token, sizeof(token)) != 0) {
        return NULL;
    }
    size_t len = strlen(token) + 8U;
    char *authorization = (char *)malloc(len);
    if (authorization != NULL) {
        snprintf(authorization, len, "Bearer %s", token);
    }
    return authorization;
}

/* A management call as username (NULL: no credentials at all). */
static int manage(const char *method, const char *path, const char *username, const char *body,
                  char *response, size_t response_cap)
{
    char *authorization = username == NULL ? NULL : bearer_for(username);
    int len = st_admin_build_response_with_auth(method, path, authorization, body, response, response_cap);
    free(authorization);
    return len > 0 ? response_status(response) : 0;
}

static int body_has_code(const char *response, const char *code)
{
    char needle[96];
    snprintf(needle, sizeof(needle), "\"code\":\"%s\"", code);
    return strstr(response_body(response), needle) != NULL;
}

static long long vector_now_ms(const char *input)
{
    char *now = jget_string(input, "now");
    long long seconds = iso_seconds(now != NULL ? now : VECTOR_NOW);
    free(now);
    return seconds * 1000LL;
}

static int code_matches(const char *expect, const char *response)
{
    char *code = jget_string(expect, "code");
    int ok = code == NULL || body_has_code(response, code);
    free(code);
    return ok;
}

/* ------------------------------------------------------------------------------------------------
 * Vector sections
 */

static int fail_count = 0;

#define CHECK(condition, ...)                                   \
    do {                                                        \
        if (!(condition)) {                                     \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
            ++fail_count;                                       \
            ok = 0;                                             \
        }                                                       \
    } while (0)

static int string_list_matches(const char *raw, const char *const *expected, size_t count)
{
    char *items[16];
    size_t n = jitems(raw, items, 16U);
    int ok = n == count;
    for (size_t i = 0U; ok && i < n; ++i) {
        char *value = jstring(items[i], NULL);
        ok = value != NULL && strcmp(value, expected[i]) == 0;
        free(value);
    }
    jitems_free(items, n);
    return ok;
}

static int constant_int(const char *constants, const char *key, long long expected)
{
    long long value = 0;
    return jget_int(constants, key, &value) == 0 && value == expected;
}

static int constant_string(const char *constants, const char *key, const char *expected)
{
    char *value = jget_string(constants, key);
    int ok = value != NULL && strcmp(value, expected) == 0;
    free(value);
    return ok;
}

static void test_constants(void)
{
    char *constants = jget(vector_json, "constants");
    int ok = 1;
    CHECK(constant_string(constants, "tokenVersion", ST_HTTP_SHARE_TOKEN_VERSION), "tokenVersion");
    CHECK(constant_int(constants, "shareIdBytes", ST_HTTP_SHARE_ID_BYTES), "shareIdBytes");
    CHECK(constant_int(constants, "secretBytes", ST_HTTP_SHARE_SECRET_BYTES), "secretBytes");
    CHECK(constant_string(constants, "tokenPattern", ST_HTTP_SHARE_TOKEN_PATTERN), "tokenPattern");
    CHECK(constant_string(constants, "cookieName", ST_HTTP_SHARE_COOKIE_NAME), "cookieName");
    CHECK(constant_int(constants, "maxCookieCandidates", ST_HTTP_SHARE_MAX_COOKIE_CANDIDATES), "maxCookieCandidates");
    CHECK(constant_string(constants, "sharePathRoot", ST_HTTP_SHARE_PATH_ROOT), "sharePathRoot");
    CHECK(constant_string(constants, "linkRoot", ST_HTTP_SHARE_LINK_ROOT), "linkRoot");
    CHECK(constant_int(constants, "minExpiresInSeconds", ST_HTTP_SHARE_MIN_EXPIRES_SECONDS), "minExpiresInSeconds");
    CHECK(constant_int(constants, "maxExpiresInSeconds", ST_HTTP_SHARE_MAX_EXPIRES_SECONDS), "maxExpiresInSeconds");
    CHECK(constant_int(constants, "maxActiveSharesPerRoute", ST_HTTP_SHARE_MAX_ACTIVE_PER_ROUTE), "maxActiveSharesPerRoute");
    CHECK(constant_int(constants, "labelMaxCodePoints", ST_HTTP_SHARE_LABEL_MAX_CODE_POINTS), "labelMaxCodePoints");
    CHECK(constant_int(constants, "pathPrefixMaxBytes", ST_HTTP_SHARE_PREFIX_MAX_BYTES), "pathPrefixMaxBytes");
    CHECK(constant_int(constants, "maxConcurrentPerShare", ST_HTTP_SHARE_MAX_CONCURRENT), "maxConcurrentPerShare");
    CHECK(constant_int(constants, "shareRetentionDays", ST_HTTP_SHARE_RETENTION_DAYS), "shareRetentionDays");
    CHECK(constant_int(constants, "auditRetentionDays", ST_HTTP_SHARE_AUDIT_RETENTION_DAYS), "auditRetentionDays");
    long long sweep_max = 0;
    long long recheck_max = 0;
    CHECK(jget_int(constants, "sweepIntervalMaxSeconds", &sweep_max) == 0
              && ST_HTTP_SHARE_SWEEP_INTERVAL_SECONDS <= sweep_max, "sweep interval above the maximum");
    /* A remote revoke is noticed after at most one recheck interval plus one tick. */
    CHECK(jget_int(constants, "streamRecheckMaxSeconds", &recheck_max) == 0
              && ST_HTTP_SHARE_RECHECK_INTERVAL_MS + ST_HTTP_SHARE_EXPIRY_CHECK_MS <= recheck_max * 1000LL,
          "stream recheck above the maximum");
    char *methods = jget(constants, "readMethods");
    char *reasons = jget(constants, "revokeReasons");
    char *actions = jget(constants, "auditActions");
    CHECK(string_list_matches(methods, st_http_share_read_methods, ST_HTTP_SHARE_READ_METHOD_COUNT), "readMethods");
    CHECK(string_list_matches(reasons, st_http_share_revoke_reasons, ST_HTTP_SHARE_REVOKE_REASON_COUNT), "revokeReasons");
    CHECK(string_list_matches(actions, st_http_share_audit_actions, ST_HTTP_SHARE_AUDIT_ACTION_COUNT), "auditActions");
    char *rate = jget(vector_json, "rate");
    char *exchange = jget(rate, "exchange");
    char *share = jget(rate, "share");
    CHECK(constant_int(exchange, "intervalMs", ST_HTTP_SHARE_EXCHANGE_INTERVAL_MS)
              && constant_int(exchange, "burst", ST_HTTP_SHARE_EXCHANGE_BURST), "exchange limiter constants");
    CHECK(constant_int(share, "intervalMs", ST_HTTP_SHARE_REQUEST_INTERVAL_MS)
              && constant_int(share, "burst", ST_HTTP_SHARE_REQUEST_BURST), "share limiter constants");
    /* Every refusal code the vector names, per endpoint, is one the implementation answers with. */
    char *codes = jget(vector_json, "codes");
    jmember sections[8];
    size_t section_count = jmembers(codes, sections, 8U);
    size_t code_count = 0U;
    for (size_t s = 0U; s < section_count; ++s) {
        char *names[32];
        size_t n = jitems(sections[s].value, names, 32U);
        for (size_t c = 0U; c < n; ++c) {
            char *code = jstring(names[c], NULL);
            int known = 0;
            for (size_t k = 0U; code != NULL && k < ST_HTTP_SHARE_CODE_COUNT; ++k) {
                known = known || strcmp(code, st_http_share_codes[k]) == 0;
            }
            CHECK(known, "codes.%s: %s is not a code of the implementation", sections[s].key, names[c]);
            ++code_count;
            free(code);
        }
        jitems_free(names, n);
    }
    CHECK(section_count == 3U && code_count > 0U, "codes: %zu sections, %zu codes", section_count, code_count);
    jmembers_free(sections, section_count);
    free(codes);
    free(methods);
    free(reasons);
    free(actions);
    free(rate);
    free(exchange);
    free(share);
    free(constants);
    printf("constants: %s\n", ok ? "all match" : "MISMATCH");
}

/* The injected random source: the vector's share id bytes, then its secret bytes. */
static uint8_t injected_id[12];
static uint8_t injected_secret[32];

static int injected_random(uint8_t *out, size_t len)
{
    if (len == sizeof(injected_id)) {
        memcpy(out, injected_id, len);
        return 0;
    }
    if (len == sizeof(injected_secret)) {
        memcpy(out, injected_secret, len);
        return 0;
    }
    return -1;
}

static void hex_bytes(const char *hex, uint8_t *out, size_t len)
{
    for (size_t i = 0U; i < len; ++i) {
        unsigned value = 0U;
        sscanf(hex + i * 2U, "%2x", &value);
        out[i] = (uint8_t)value;
    }
}

static void inject_share_bytes(const char *object)
{
    char *id_hex = jget_string(object, "shareIdBytesHex");
    char *secret_hex = jget_string(object, "secretBytesHex");
    hex_bytes(id_hex, injected_id, sizeof(injected_id));
    hex_bytes(secret_hex, injected_secret, sizeof(injected_secret));
    free(id_hex);
    free(secret_hex);
    st_http_share_set_random_for_testing(injected_random);
}

static void test_token(void)
{
    char *token = jget(vector_json, "token");
    char *examples = jget(token, "examples");
    char *parse = jget(token, "parse");
    char *items[64];
    size_t passed = 0U;
    size_t count = jitems(examples, items, 64U);
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        inject_share_bytes(items[i]);
        char share_id[ST_HTTP_SHARE_ID_LEN + 1U];
        char value[ST_HTTP_SHARE_TOKEN_LEN + 1U];
        char hash[65];
        CHECK(st_http_share_new_token(share_id, value) == 0, "token example %zu: generation failed", i);
        st_http_share_token_hash(value, strlen(value), hash);
        char share_path[64];
        char link_path[128];
        snprintf(share_path, sizeof(share_path), "%s%s/", ST_HTTP_SHARE_PATH_ROOT, share_id);
        snprintf(link_path, sizeof(link_path), "%s%s", ST_HTTP_SHARE_LINK_ROOT, value);
        char *expected_id = jget_string(items[i], "shareId");
        char *expected_token = jget_string(items[i], "token");
        char *expected_hash = jget_string(items[i], "tokenSha256");
        char *expected_share_path = jget_string(items[i], "sharePath");
        char *expected_link = jget_string(items[i], "linkPath");
        CHECK(strcmp(share_id, expected_id) == 0 && strcmp(value, expected_token) == 0
                  && strcmp(hash, expected_hash) == 0 && strcmp(share_path, expected_share_path) == 0
                  && strcmp(link_path, expected_link) == 0,
              "token example %zu: got %s %s %s", i, share_id, value, hash);
        free(expected_id);
        free(expected_token);
        free(expected_hash);
        free(expected_share_path);
        free(expected_link);
        passed += ok;
    }
    st_http_share_set_random_for_testing(NULL);
    jitems_free(items, count);
    size_t parse_passed = 0U;
    size_t parse_count = jitems(parse, items, 64U);
    for (size_t i = 0U; i < parse_count; ++i) {
        int ok = 1;
        char *input_raw = jget(items[i], "input");
        char *expected = jget_string(items[i], "shareId");
        size_t len = 0U;
        char *input = jstring(input_raw, &len);
        char share_id[ST_HTTP_SHARE_ID_LEN + 1U] = "";
        /* A JSON null (no string at all) parses to nothing, like any malformed token. */
        int parsed = input != NULL && st_http_share_parse_token(input, len, share_id) == 0;
        CHECK(expected == NULL ? !parsed : (parsed && strcmp(share_id, expected) == 0),
              "token parse %zu: %s", i, input_raw);
        free(input_raw);
        free(expected);
        free(input);
        parse_passed += ok;
    }
    jitems_free(items, parse_count);
    printf("token: %zu/%zu examples, %zu/%zu parse cases\n", passed, count, parse_passed, parse_count);
    free(token);
    free(examples);
    free(parse);
}

static void test_path_prefix(void)
{
    char *cases = jget(vector_json, "pathPrefix");
    char *items[64];
    size_t count = jitems(cases, items, 64U);
    size_t passed = 0U;
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *input_raw = jget(items[i], "input");
        char *expected = jget_string(items[i], "canonical");
        size_t len = 0U;
        char *input = jstring(input_raw, &len);
        char canonical[ST_HTTP_SHARE_PREFIX_MAX_BYTES + 1U] = "";
        int accepted = input != NULL && st_http_share_canonical_prefix(input, len, canonical) == 0;
        CHECK(expected == NULL ? !accepted : (accepted && strcmp(canonical, expected) == 0),
              "pathPrefix %zu: %s gave %s", i, input_raw, accepted ? canonical : "rejected");
        /* The same through the create body, which also sees non-string values. */
        size_t body_len = strlen(input_raw) + 64U;
        char *body = (char *)malloc(body_len);
        snprintf(body, body_len, "{\"expiresInSeconds\":3600,\"pathPrefix\":%s}", input_raw);
        st_http_share_create_fields fields;
        int body_ok = st_http_share_parse_create_body(body, strlen(body), &fields) == 0;
        CHECK(expected == NULL ? !body_ok : (body_ok && strcmp(fields.path_prefix, expected) == 0),
              "pathPrefix %zu through the create body: %s", i, input_raw);
        free(body);
        free(input_raw);
        free(expected);
        free(input);
        passed += ok;
    }
    jitems_free(items, count);
    free(cases);
    printf("pathPrefix: %zu/%zu cases\n", passed, count);
}

static void test_create(void)
{
    char *cases = jget(vector_json, "create");
    char *new_share = jget(vector_json, "newShare");
    char *new_share_id = jget_string(new_share, "shareId");
    char *new_token = jget_string(new_share, "token");
    char new_token_hash[65];
    st_http_share_token_hash(new_token, strlen(new_token), new_token_hash);
    char *items[64];
    size_t count = jitems(cases, items, 64U);
    size_t passed = 0U;
    char *response = (char *)malloc(RESPONSE_CAP);
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *name = jget_string(items[i], "name");
        char *input = jget(items[i], "input");
        char *expect = jget(items[i], "expect");
        CHECK(prepare_case(input) == 0, "create %s: world setup failed", name);
        st_http_share_set_clock_for_testing(vector_now_ms(input));
        inject_share_bytes(new_share);
        int authenticated = jget_bool(input, "authenticated", 1);
        int readable = jget_bool(input, "readable", 1);
        char *caller = jget_string(input, "caller");
        long long route_id = 0;
        (void)jget_int(input, "routeId", &route_id);
        char *body = jget(input, "body");
        char path[96];
        snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/shares", route_id);
        st_storage_http_share_fail_for_testing(!readable);
        int status = manage("POST", path, authenticated ? caller : NULL, body, response, RESPONSE_CAP);
        st_storage_http_share_fail_for_testing(0);
        long long expected_status = 0;
        (void)jget_int(expect, "httpStatus", &expected_status);
        CHECK(status == expected_status, "create %s: status %d, expected %lld: %.300s", name, status,
              expected_status, response);
        CHECK(code_matches(expect, response), "create %s: code mismatch: %.300s", name, response);
        char cache[64] = "";
        /* Every answer, the authentication layer's 401 included. */
        CHECK(response_header(response, "Cache-Control", 0U, cache, sizeof(cache))
                  && strcmp(cache, "private, no-store") == 0, "create %s: Cache-Control %s", name, cache);
        char *expected_body = jget(expect, "body");
        char *expected_code = jget_string(expect, "code");
        share_state stored = read_share(new_share_id);
        if (expected_body != NULL) {
            CHECK(jequal(expected_body, response_body(response)), "create %s: body %s, expected %s", name,
                  response_body(response), expected_body);
            /* The row keeps the hash of the token the answer carried, and the label as answered. */
            char *share = jget(expected_body, "share");
            char *label = jget_string(share, "label");
            CHECK(stored.found && strcmp(stored.token_sha256, new_token_hash) == 0
                      && (label == NULL ? !stored.has_label : (stored.has_label && strcmp(stored.label, label) == 0)),
                  "create %s: stored hash %s label %s", name, stored.token_sha256,
                  stored.has_label ? stored.label : "null");
            free(share);
            free(label);
        } else if (expected_code != NULL) {
            CHECK(!stored.found, "create %s: a refused creation stored share %s", name, new_share_id);
        }
        free(expected_code);
        char *expected_audit = jget(expect, "audit");
        CHECK(expect_audit(name, expected_audit, NULL, 0U), "create %s: audit mismatch", name);
        free(expected_audit);
        free(expected_body);
        free(caller);
        free(body);
        free(name);
        free(input);
        free(expect);
        passed += ok;
    }
    st_http_share_set_random_for_testing(NULL);
    jitems_free(items, count);
    free(response);
    free(cases);
    free(new_share);
    free(new_share_id);
    free(new_token);
    printf("create: %zu/%zu cases\n", passed, count);
}

/* An expected structured cookie as the one Set-Cookie line the server must send. */
static void expected_cookie_line(const char *cookie, char *out, size_t out_len)
{
    char *name = jget_string(cookie, "name");
    char *value = jget_string(cookie, "value");
    char *path = jget_string(cookie, "path");
    long long max_age = -1;
    (void)jget_int(cookie, "maxAge", &max_age);
    char *same_site = jget_string(cookie, "sameSite");
    snprintf(out, out_len, "%s=%s; Path=%s; Max-Age=%lld%s%s; SameSite=%s", name, value, path, max_age,
             jget_bool(cookie, "httpOnly", 0) ? "; HttpOnly" : "", jget_bool(cookie, "secure", 0) ? "; Secure" : "",
             same_site);
    free(name);
    free(value);
    free(path);
    free(same_site);
}

/*
 * Every share of the case carries the read-time revocation (system actor, the case's now) when the
 * vector expects one, and otherwise exactly the revoke columns it was stored with.
 */
static int expect_revoke_columns(const char *label, const char *input, const char *expect, long long now_ms)
{
    char *revoke = jget(expect, "revoke");
    char *reason = jget_string(revoke, "reason");
    char *shares = jget(input, "shares");
    char *rows[32];
    size_t count = shares == NULL ? 0U : jitems(shares, rows, 32U);
    int ok = 1;
    for (size_t i = 0U; i < count; ++i) {
        char *share_id = jget_string(rows[i], "shareId");
        share_state state = read_share(share_id);
        if (revoke != NULL) {
            CHECK(state.found && state.revoked && !state.has_revoked_by && strcmp(state.reason, reason) == 0
                      && state.revoked_at == now_ms / 1000LL,
                  "%s: share %s revoke columns %d %s %s %lld", label, share_id, state.revoked,
                  state.has_revoked_by ? state.revoked_by : "null", state.reason, state.revoked_at);
        } else {
            char *revoked_at = jget_string(rows[i], "revokedAt");
            char *revoked_by = jget_string(rows[i], "revokedBy");
            char *stored_reason = jget_string(rows[i], "revokeReason");
            CHECK(state.found
                      && (revoked_at == NULL ? !state.revoked
                                             : (state.revoked && state.revoked_at == iso_seconds(revoked_at)))
                      && (revoked_by == NULL ? !state.has_revoked_by
                                             : (state.has_revoked_by && strcmp(state.revoked_by, revoked_by) == 0))
                      && (stored_reason == NULL ? state.reason[0] == '\0' : strcmp(state.reason, stored_reason) == 0),
                  "%s: share %s revoke columns changed to %d %lld %s %s", label, share_id, state.revoked,
                  state.revoked_at, state.has_revoked_by ? state.revoked_by : "null", state.reason);
            free(revoked_at);
            free(revoked_by);
            free(stored_reason);
        }
        free(share_id);
    }
    jitems_free(rows, count);
    free(shares);
    free(reason);
    free(revoke);
    return ok;
}

static void test_exchange(void)
{
    char *cases = jget(vector_json, "exchange");
    char *items[64];
    size_t count = jitems(cases, items, 64U);
    size_t passed = 0U;
    char *response = (char *)malloc(RESPONSE_CAP);
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *name = jget_string(items[i], "name");
        char *input = jget(items[i], "input");
        char *expect = jget(items[i], "expect");
        CHECK(prepare_case(input) == 0, "exchange %s: world setup failed", name);
        long long now_ms = vector_now_ms(input);
        st_http_share_set_clock_for_testing(now_ms);
        st_http_share_gcra *limiter = st_http_share_exchange_limiter();
        st_http_share_gcra_reset(limiter);
        long long limited_ms = 0;
        if (jget_int(input, "rateLimitedMs", &limited_ms) == 0) {
            /* The source address already used its burst: the wait is exactly rateLimitedMs. */
            st_http_share_gcra_set_tat(limiter, "127.0.0.1", now_ms + st_http_share_gcra_tolerance(limiter) + limited_ms);
        }
        char *content_type = jget_string(input, "contentType");
        char *body = jget(input, "body");
        char request[8192];
        int request_len = snprintf(request, sizeof(request),
                                   "POST /api/public/http-shares/exchange HTTP/1.1\r\nHost: share.test\r\n"
                                   "Content-Type: %s\r\nContent-Length: %zu\r\n\r\n%s",
                                   content_type != NULL ? content_type : "application/json", strlen(body), body);
        st_storage_http_share_fail_for_testing(!jget_bool(input, "readable", 1));
        int sent = http_roundtrip(request, (size_t)request_len, response, RESPONSE_CAP);
        st_storage_http_share_fail_for_testing(0);
        int status = sent == 0 ? response_status(response) : 0;
        long long expected_status = 0;
        (void)jget_int(expect, "httpStatus", &expected_status);
        CHECK(status == expected_status, "exchange %s: status %d, expected %lld: %.300s", name, status,
              expected_status, response);
        CHECK(code_matches(expect, response), "exchange %s: code mismatch: %.300s", name, response);
        char header[512] = "";
        CHECK(response_header(response, "Cache-Control", 0U, header, sizeof(header)) && strcmp(header, "no-store") == 0,
              "exchange %s: Cache-Control %s", name, header);
        char *expected_body = jget(expect, "body");
        if (expected_body != NULL) {
            CHECK(jequal(expected_body, response_body(response)), "exchange %s: body %s", name, response_body(response));
        }
        char *cookie = jget(expect, "setCookie");
        if (cookie != NULL) {
            char expected_line[512];
            expected_cookie_line(cookie, expected_line, sizeof(expected_line));
            CHECK(response_header(response, "Set-Cookie", 0U, header, sizeof(header))
                      && strcmp(header, expected_line) == 0 && !response_header(response, "Set-Cookie", 1U, header, 1U),
                  "exchange %s: Set-Cookie %s, expected %s", name, header, expected_line);
            CHECK(response_header(response, "Referrer-Policy", 0U, header, sizeof(header))
                      && strcmp(header, "no-referrer") == 0, "exchange %s: Referrer-Policy", name);
        } else {
            CHECK(!response_header(response, "Set-Cookie", 0U, header, sizeof(header)),
                  "exchange %s: unexpected Set-Cookie %s", name, header);
        }
        long long retry = 0;
        if (jget_int(expect, "retryAfterSeconds", &retry) == 0) {
            CHECK(response_header(response, "Retry-After", 0U, header, sizeof(header)) && atoll(header) == retry,
                  "exchange %s: Retry-After %s, expected %lld", name, header, retry);
        }
        char *expected_audit = jget(expect, "audit");
        CHECK(expect_audit(name, expected_audit, NULL, 0U), "exchange %s: audit mismatch", name);
        ok = expect_revoke_columns(name, input, expect, now_ms) && ok;
        free(expected_audit);
        free(cookie);
        free(expected_body);
        free(content_type);
        free(body);
        free(name);
        free(input);
        free(expect);
        passed += ok;
    }
    jitems_free(items, count);
    free(response);
    free(cases);
    printf("exchange: %zu/%zu cases\n", passed, count);
}

static void test_access(void)
{
    char *cases = jget(vector_json, "access");
    char *items[64];
    size_t count = jitems(cases, items, 64U);
    size_t passed = 0U;
    char *response = (char *)malloc(RESPONSE_CAP);
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *name = jget_string(items[i], "name");
        char *input = jget(items[i], "input");
        char *expect = jget(items[i], "expect");
        char *request_object = jget(input, "request");
        CHECK(prepare_case(input) == 0, "access %s: world setup failed", name);
        long long now_ms = vector_now_ms(input);
        st_http_share_set_clock_for_testing(now_ms);
        st_http_share_gcra *limiter = st_http_share_request_limiter();
        st_http_share_gcra_reset(limiter);
        st_admin_http_share_release_for_testing();
        device_reset(DEVICE_PLAIN);
        char *shares = jget(input, "shares");
        char *first = NULL;
        char *share_id = NULL;
        if (shares != NULL && jitems(shares, &first, 1U) == 1U) {
            share_id = jget_string(first, "shareId");
        }
        char *admission = jget_string(input, "admission");
        if (admission != NULL && strcmp(admission, "share-busy") == 0) {
            CHECK(st_admin_http_share_occupy_for_testing(share_id, ST_HTTP_SHARE_MAX_CONCURRENT) == 0,
                  "access %s: occupy failed", name);
        } else if (admission != NULL && strcmp(admission, "rate-limited") == 0) {
            /* The share already spent its burst: the next request waits one interval. */
            st_http_share_gcra_set_tat(limiter, share_id,
                                       now_ms + st_http_share_gcra_tolerance(limiter) + st_http_share_gcra_interval(limiter));
        }
        char *method = jget_string(request_object, "method");
        char *path = jget_string(request_object, "path");
        char *raw_query = jget_string(request_object, "rawQuery");
        char *authorization = jget_string(request_object, "authorization");
        int upgrade = jget_bool(request_object, "upgrade", 0);
        char *cookies_raw = jget(request_object, "cookies");
        char *cookies[16];
        size_t cookie_count = cookies_raw == NULL ? 0U : jitems(cookies_raw, cookies, 16U);
        char request[8192];
        int len = snprintf(request, sizeof(request), "%s %s%s%s HTTP/1.1\r\nHost: share.test\r\n", method, path,
                           raw_query != NULL && *raw_query != '\0' ? "?" : "", raw_query != NULL ? raw_query : "");
        for (size_t c = 0U; c < cookie_count; ++c) {
            char *value = jstring(cookies[c], NULL);
            len += snprintf(request + len, sizeof(request) - (size_t)len, "Cookie: %s\r\n", value);
            free(value);
        }
        if (authorization != NULL) {
            len += snprintf(request + len, sizeof(request) - (size_t)len, "Authorization: %s\r\n", authorization);
        }
        if (upgrade) {
            len += snprintf(request + len, sizeof(request) - (size_t)len,
                            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n");
            /* The device accepts the stream, so an admitted upgrade completes with 101. */
            pthread_mutex_lock(&device.lock);
            device.ws_accept = 1;
            pthread_mutex_unlock(&device.lock);
        }
        len += snprintf(request + len, sizeof(request) - (size_t)len, "\r\n");
        st_storage_http_share_fail_for_testing(!jget_bool(input, "readable", 1));
        int sent = http_roundtrip(request, (size_t)len, response, RESPONSE_CAP);
        st_storage_http_share_fail_for_testing(0);
        int status = sent == 0 ? response_status(response) : 0;
        char *status_raw = jget(expect, "httpStatus");
        char header[512] = "";
        if (status_raw != NULL && status_raw[0] == '"') {
            /* "forwarded": the device got exactly this OPEN; the token went nowhere. */
            char *forward = jget(expect, "forward");
            char *route = jget_string(forward, "route");
            char *expected_method = jget_string(forward, "method");
            char *relative_path = jget_string(forward, "relativePath");
            char *expected_query = jget_string(forward, "rawQuery");
            char *cookie_raw = jget(forward, "cookie");
            char *cookie = jstring(cookie_raw, NULL);
            /* The visitor got the device's answer: its 200, or the 101 of an accepted WebSocket. */
            CHECK(status == (upgrade ? 101 : 200), "access %s: visitor status %d: %.300s", name, status, response);
            pthread_mutex_lock(&device.lock);
            CHECK(device.http_calls + device.ws_calls == 1 && (upgrade ? device.ws_calls == 1 : device.http_calls == 1)
                      && strcmp(device.client_name, "client-7") == 0 && strcmp(device.route, route) == 0
                      && strcmp(device.method, expected_method) == 0
                      && strcmp(device.relative_path, relative_path) == 0
                      && strcmp(device.raw_query, expected_query) == 0,
                  "access %s: device saw %d/%d calls %s %s %s %s ?%s", name, device.http_calls, device.ws_calls,
                  device.client_name, device.route, device.method, device.relative_path, device.raw_query);
            CHECK(cookie == NULL ? device.cookie_headers == 0
                                 : (device.cookie_headers == 1 && strcmp(device.cookie, cookie) == 0),
                  "access %s: device Cookie (%d headers) %s, expected %s", name, device.cookie_headers, device.cookie,
                  cookie == NULL ? "none" : cookie);
            CHECK(strstr(device.all_headers, "hs1.") == NULL && strstr(device.relative_path, "hs1.") == NULL
                      && strstr(device.raw_query, "hs1.") == NULL,
                  "access %s: the token reached the device", name);
            pthread_mutex_unlock(&device.lock);
            free(forward);
            free(route);
            free(expected_method);
            free(relative_path);
            free(expected_query);
            free(cookie_raw);
            free(cookie);
        } else {
            long long expected_status = status_raw == NULL ? 0 : atoll(status_raw);
            CHECK(status == expected_status, "access %s: status %d, expected %lld: %.300s", name, status,
                  expected_status, response);
            CHECK(code_matches(expect, response), "access %s: code mismatch: %.300s", name, response);
            pthread_mutex_lock(&device.lock);
            CHECK(device.http_calls == 0 && device.ws_calls == 0, "access %s: refused request reached the device", name);
            pthread_mutex_unlock(&device.lock);
            char *location = jget_string(expect, "location");
            if (location != NULL) {
                CHECK(response_header(response, "Location", 0U, header, sizeof(header)) && strcmp(header, location) == 0,
                      "access %s: Location %s, expected %s", name, header, location);
            }
            char *allow = jget_string(expect, "allow");
            if (allow != NULL) {
                CHECK(response_header(response, "Allow", 0U, header, sizeof(header)) && strcmp(header, allow) == 0,
                      "access %s: Allow %s", name, header);
            }
            long long retry = 0;
            if (jget_int(expect, "retryAfterSeconds", &retry) == 0) {
                CHECK(response_header(response, "Retry-After", 0U, header, sizeof(header)) && atoll(header) == retry,
                      "access %s: Retry-After %s, expected %lld", name, header, retry);
            }
            char *cookie = jget(expect, "setCookie");
            if (cookie != NULL) {
                char expected_line[512];
                expected_cookie_line(cookie, expected_line, sizeof(expected_line));
                CHECK(response_header(response, "Set-Cookie", 0U, header, sizeof(header))
                          && strcmp(header, expected_line) == 0
                          && !response_header(response, "Set-Cookie", 1U, header, 1U),
                      "access %s: Set-Cookie %s, expected exactly %s", name, header, expected_line);
            } else {
                CHECK(!response_header(response, "Set-Cookie", 0U, header, sizeof(header)),
                      "access %s: unexpected Set-Cookie %s", name, header);
            }
            /* Every refusal, the redirect included, is no-store; the redirect has no body at all. */
            CHECK(response_header(response, "Cache-Control", 0U, header, sizeof(header))
                      && strcmp(header, "no-store") == 0, "access %s: Cache-Control %s", name, header);
            if (expected_status == 308) {
                CHECK(response_body(response)[0] == '\0', "access %s: redirect body %s", name, response_body(response));
            }
            free(location);
            free(allow);
            free(cookie);
        }
        char *expected_audit = jget(expect, "audit");
        CHECK(expect_audit(name, expected_audit, NULL, 0U), "access %s: audit mismatch", name);
        ok = expect_revoke_columns(name, input, expect, now_ms) && ok;
        st_admin_http_share_release_for_testing();
        /* An accepted WebSocket ends once the visitor's socket closed; give that a moment. */
        long long drain_deadline = monotonic_ms() + 3000;
        while (st_admin_http_share_stream_count(NULL) != 0U && monotonic_ms() < drain_deadline) {
            struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000L};
            nanosleep(&pause, NULL);
        }
        CHECK(st_admin_http_share_stream_count(NULL) == 0U, "access %s: streams left registered", name);
        free(expected_audit);
        free(status_raw);
        jitems_free(cookies, cookie_count);
        free(cookies_raw);
        free(method);
        free(path);
        free(raw_query);
        free(authorization);
        free(admission);
        free(share_id);
        free(first);
        free(shares);
        free(request_object);
        free(name);
        free(input);
        free(expect);
        passed += ok;
    }
    jitems_free(items, count);
    free(response);
    free(cases);
    printf("access: %zu/%zu cases\n", passed, count);
}

static void test_headers(void)
{
    char *headers = jget(vector_json, "headers");
    char *request_cookie = jget(headers, "requestCookie");
    char *response_cases = jget(headers, "response");
    char *items[32];
    size_t count = jitems(request_cookie, items, 32U);
    size_t passed = 0U;
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *cookie_headers = jget(items[i], "cookieHeaders");
        char *expected = jget_string(items[i], "forwardedCookie");
        char *values_raw[16];
        char *values[16];
        size_t n = jitems(cookie_headers, values_raw, 16U);
        for (size_t v = 0U; v < n; ++v) {
            values[v] = jstring(values_raw[v], NULL);
        }
        char *forwarded = NULL;
        CHECK(st_http_share_forwarded_cookie(values, n, &forwarded) == 0
                  && (expected == NULL ? forwarded == NULL : (forwarded != NULL && strcmp(forwarded, expected) == 0)),
              "requestCookie %zu: %s, expected %s", i, forwarded == NULL ? "none" : forwarded,
              expected == NULL ? "none" : expected);
        free(forwarded);
        /* The same through the request-header rewriting the share entry applies: other headers kept. */
        char request[4096];
        int request_len = snprintf(request, sizeof(request), "GET /http-share/x/ HTTP/1.1\r\nAccept: */*\r\n");
        for (size_t v = 0U; v < n; ++v) {
            request_len += snprintf(request + request_len, sizeof(request) - (size_t)request_len, "Cookie: %s\r\n",
                                    values[v]);
        }
        snprintf(request + request_len, sizeof(request) - (size_t)request_len, "\r\n");
        char **relayed = NULL;
        size_t relayed_len = 0U;
        char expected_line[1024] = "";
        if (expected != NULL) {
            snprintf(expected_line, sizeof(expected_line), "Cookie:%s", expected);
        }
        CHECK(st_admin_http_share_forward_headers_for_testing(request, &relayed, &relayed_len) == 0
                  && relayed_len == (expected == NULL ? 1U : 2U) && strcmp(relayed[0], "Accept:*/*") == 0
                  && (expected == NULL || strcmp(relayed[1], expected_line) == 0),
              "requestCookie %zu: relayed %zu headers, last %s, expected %s", i, relayed_len,
              relayed_len > 0U ? relayed[relayed_len - 1U] : "none", expected == NULL ? "Accept only" : expected_line);
        st_http_share_free_strings(relayed, relayed_len);
        for (size_t v = 0U; v < n; ++v) {
            free(values[v]);
        }
        jitems_free(values_raw, n);
        free(cookie_headers);
        free(expected);
        passed += ok;
    }
    jitems_free(items, count);
    printf("headers.requestCookie: %zu/%zu cases\n", passed, count);
    count = jitems(response_cases, items, 32U);
    passed = 0U;
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *name = jget_string(items[i], "name");
        char *share_id = jget_string(items[i], "shareId");
        long long status = 0;
        (void)jget_int(items[i], "status", &status);
        char *upstream = jget(items[i], "upstream");
        char *relayed = jget(items[i], "relayed");
        char *upstream_raw[16];
        char *upstream_values[16];
        char *relayed_raw[16];
        size_t upstream_count = jitems(upstream, upstream_raw, 16U);
        size_t relayed_count = jitems(relayed, relayed_raw, 16U);
        for (size_t v = 0U; v < upstream_count; ++v) {
            upstream_values[v] = jstring(upstream_raw[v], NULL);
        }
        char **out = NULL;
        size_t out_len = 0U;
        CHECK(st_http_share_rewrite_response_headers((int)status, upstream_values, upstream_count, share_id,
                                                     &out, &out_len) == 0 && out_len == relayed_count,
              "headers.response %s: %zu headers, expected %zu", name, out_len, relayed_count);
        for (size_t v = 0U; ok && v < relayed_count; ++v) {
            char *expected = jstring(relayed_raw[v], NULL);
            CHECK(strcmp(out[v], expected) == 0, "headers.response %s: %s, expected %s", name, out[v], expected);
            free(expected);
        }
        st_http_share_free_strings(out, out_len);
        for (size_t v = 0U; v < upstream_count; ++v) {
            free(upstream_values[v]);
        }
        jitems_free(upstream_raw, upstream_count);
        jitems_free(relayed_raw, relayed_count);
        free(upstream);
        free(relayed);
        free(name);
        free(share_id);
        passed += ok;
    }
    jitems_free(items, count);
    printf("headers.response: %zu/%zu cases\n", passed, count);
    free(headers);
    free(request_cookie);
    free(response_cases);
}

static long long response_route_id(const char *response)
{
    long long id = 0;
    return jget_int(response_body(response), "id", &id) == 0 ? id : 0;
}

/* One lifecycle event through the real management code path. */
static int replay_event(const char *event, long long route_map[][2], size_t *map_len, char *response,
                        int *status)
{
    char *kind = jget_string(event, "kind");
    char *actor = jget_string(event, "actor");
    long long route_id = 0;
    long long client_id = 0;
    (void)jget_int(event, "routeId", &route_id);
    (void)jget_int(event, "clientId", &client_id);
    for (size_t m = 0U; m < *map_len; ++m) {
        if (route_map[m][0] == route_id) {
            route_id = route_map[m][1];
        }
    }
    char path[160];
    char body[512];
    *status = 0;
    int rc = 0;
    if (strcmp(kind, "revoke") == 0) {
        char *share_id = jget_string(event, "shareId");
        snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/shares/%s/revoke", route_id, share_id);
        *status = manage("POST", path, actor, NULL, response, RESPONSE_CAP);
        free(share_id);
    } else if (strcmp(kind, "route-created") == 0) {
        char *route = jget(event, "route");
        char *name = jget_string(route, "name");
        long long vector_id = 0;
        (void)jget_int(route, "routeId", &vector_id);
        (void)jget_int(route, "clientId", &client_id);
        int auth = jget_bool(route, "authEnabled", 0);
        snprintf(body, sizeof(body),
                 "{\"route\":\"%s\",\"targetBaseUrl\":\"http://127.0.0.1:9/\",\"enabled\":%s,\"authEnabled\":%s%s}",
                 name, jget_bool(route, "enabled", 1) ? "true" : "false", auth ? "true" : "false",
                 auth ? ",\"authUsername\":\"basic-user\",\"authPassword\":\"basic-secret\"" : "");
        snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", client_id);
        *status = manage("POST", path, actor, body, response, RESPONSE_CAP);
        route_map[*map_len][0] = vector_id;
        route_map[*map_len][1] = response_route_id(response);
        ++*map_len;
        free(route);
        free(name);
        rc = *status == 201 ? 0 : -1;
    } else if (strcmp(kind, "route-updated") == 0) {
        size_t used = (size_t)snprintf(body, sizeof(body), "{");
        char *enabled = jget(event, "enabled");
        char *auth = jget(event, "authEnabled");
        if (enabled != NULL) {
            used += (size_t)snprintf(body + used, sizeof(body) - used, "\"enabled\":%s,", enabled);
        }
        if (auth != NULL) {
            used += (size_t)snprintf(body + used, sizeof(body) - used, "\"authEnabled\":%s,", auth);
        }
        if (jget_bool(event, "credentialsChanged", 0)) {
            /* New Basic credentials: a new username and a new password. */
            used += (size_t)snprintf(body + used, sizeof(body) - used,
                                     "\"authUsername\":\"rotated-user\",\"authPassword\":\"rotated-secret\",");
        }
        if (used > 1U) {
            --used;
        }
        snprintf(body + used, sizeof(body) - used, "}");
        snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", route_id);
        *status = manage("PUT", path, actor, body, response, RESPONSE_CAP);
        free(enabled);
        free(auth);
        rc = *status == 200 ? 0 : -1;
    } else if (strcmp(kind, "route-deleted") == 0) {
        snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", route_id);
        *status = manage("DELETE", path, actor, NULL, response, RESPONSE_CAP);
        rc = *status == 204 ? 0 : -1;
    } else if (strcmp(kind, "client-disabled") == 0) {
        snprintf(path, sizeof(path), "/api/admin/clients/%lld", client_id);
        *status = manage("PUT", path, actor, "{\"enabled\":false}", response, RESPONSE_CAP);
        rc = *status == 200 ? 0 : -1;
    } else if (strcmp(kind, "client-deleted") == 0) {
        snprintf(path, sizeof(path), "/api/admin/clients/%lld", client_id);
        *status = manage("DELETE", path, actor, NULL, response, RESPONSE_CAP);
        rc = *status == 204 ? 0 : -1;
    } else if (strcmp(kind, "user-updated") == 0 || strcmp(kind, "user-deleted") == 0) {
        char *username = jget_string(event, "username");
        snprintf(path, sizeof(path), "/api/admin/users/%s", username);
        if (strcmp(kind, "user-deleted") == 0) {
            *status = manage("DELETE", path, actor, NULL, response, RESPONSE_CAP);
            rc = *status == 204 ? 0 : -1;
        } else {
            size_t used = (size_t)snprintf(body, sizeof(body), "{");
            char *enabled = jget(event, "enabled");
            char *role = jget(event, "role");
            if (enabled != NULL) {
                used += (size_t)snprintf(body + used, sizeof(body) - used, "\"enabled\":%s,", enabled);
            }
            if (role != NULL) {
                used += (size_t)snprintf(body + used, sizeof(body) - used, "\"role\":%s,", role);
            }
            if (used > 1U) {
                --used;
            }
            snprintf(body + used, sizeof(body) - used, "}");
            *status = manage("PUT", path, actor, body, response, RESPONSE_CAP);
            rc = *status == 200 ? 0 : -1;
            free(enabled);
            free(role);
        }
        free(username);
    } else if (strcmp(kind, "sweep") == 0) {
        rc = st_admin_http_share_sweep();
    } else if (strcmp(kind, "silent-change") == 0) {
        /* A change that bypassed every hook: straight into the database. */
        rc = apply_change(event);
    } else {
        rc = -1;
    }
    if (rc != 0) {
        fprintf(stderr, "lifecycle event %s failed (status %d): %.300s\n", kind, *status, response);
    }
    free(kind);
    free(actor);
    return rc;
}

static void test_lifecycle(void)
{
    char *cases = jget(vector_json, "lifecycle");
    char *items[64];
    size_t count = jitems(cases, items, 64U);
    size_t passed = 0U;
    char *response = (char *)malloc(RESPONSE_CAP);
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        char *name = jget_string(items[i], "name");
        char *input = jget(items[i], "input");
        char *expect = jget(items[i], "expect");
        CHECK(prepare_case(input) == 0, "lifecycle %s: world setup failed", name);
        char *events_raw = jget(input, "events");
        char *events[16];
        size_t event_count = jitems(events_raw, events, 16U);
        char *responses_raw = jget(expect, "responses");
        char *responses[16];
        size_t response_count = responses_raw == NULL ? 0U : jitems(responses_raw, responses, 16U);
        long long route_map[8][2];
        size_t map_len = 0U;
        size_t revoke_index = 0U;
        long long last_ms = 0;
        for (size_t e = 0U; e < event_count; ++e) {
            char *at = jget_string(events[e], "at");
            last_ms = iso_seconds(at) * 1000LL;
            st_http_share_set_clock_for_testing(last_ms);
            free(at);
            int status = 0;
            char *kind = jget_string(events[e], "kind");
            int revoke = strcmp(kind, "revoke") == 0;
            int rc = replay_event(events[e], route_map, &map_len, response, &status);
            if (revoke) {
                /* Each revoke answer: its status and the share's status or the refusal code. */
                long long expected_status = 0;
                char *expected_state = NULL;
                char *expected_code = NULL;
                if (revoke_index < response_count) {
                    (void)jget_int(responses[revoke_index], "httpStatus", &expected_status);
                    expected_state = jget_string(responses[revoke_index], "status");
                    expected_code = jget_string(responses[revoke_index], "code");
                }
                char *share = jget(response_body(response), "share");
                char *state = jget_string(share, "status");
                CHECK(status == expected_status
                          && (expected_state == NULL || (state != NULL && strcmp(state, expected_state) == 0))
                          && (expected_code == NULL || body_has_code(response, expected_code)),
                      "lifecycle %s: revoke %zu answered %d %.200s", name, revoke_index, status, response_body(response));
                ++revoke_index;
                free(share);
                free(state);
                free(expected_state);
                free(expected_code);
            } else {
                CHECK(rc == 0, "lifecycle %s: event %zu failed", name, e);
            }
            free(kind);
        }
        CHECK(revoke_index == response_count, "lifecycle %s: %zu revoke answers, expected %zu", name, revoke_index,
              response_count);
        char *expected_audit = jget(expect, "audit");
        CHECK(expect_audit(name, expected_audit, (const long long (*)[2])route_map, map_len),
              "lifecycle %s: audit mismatch", name);
        char *expected_shares = jget(expect, "shares");
        jmember shares[16];
        size_t share_count = jmembers(expected_shares, shares, 16U);
        long long stored_rows = count_rows("SELECT COUNT(*) FROM http_share");
        CHECK(stored_rows == (long long)share_count, "lifecycle %s: %lld share rows, expected %zu", name, stored_rows,
              share_count);
        for (size_t s = 0U; s < share_count; ++s) {
            share_state state = read_share(shares[s].key);
            char *status = jget_string(shares[s].value, "status");
            char *reason = jget_string(shares[s].value, "revokeReason");
            char *revoked_by = jget_string(shares[s].value, "revokedBy");
            const char *actual = state.revoked ? "revoked" : (last_ms >= state.expires_at * 1000LL ? "expired" : "active");
            CHECK(state.found && strcmp(actual, status) == 0
                      && (reason == NULL ? state.reason[0] == '\0' : strcmp(state.reason, reason) == 0)
                      && (revoked_by == NULL ? !state.has_revoked_by
                                             : (state.has_revoked_by && strcmp(state.revoked_by, revoked_by) == 0)),
                  "lifecycle %s: share %s is %s %s by %s", name, shares[s].key, actual, state.reason,
                  state.has_revoked_by ? state.revoked_by : "null");
            free(status);
            free(reason);
            free(revoked_by);
        }
        jmembers_free(shares, share_count);
        free(expected_shares);
        free(expected_audit);
        jitems_free(events, event_count);
        jitems_free(responses, response_count);
        free(events_raw);
        free(responses_raw);
        free(name);
        free(input);
        free(expect);
        passed += ok;
    }
    jitems_free(items, count);
    free(response);
    free(cases);
    printf("lifecycle: %zu/%zu cases\n", passed, count);
}

static size_t replay_rate(const char *section, size_t *total)
{
    char *rate = jget(vector_json, "rate");
    char *config = jget(rate, section);
    long long interval = 0;
    long long burst = 0;
    (void)jget_int(config, "intervalMs", &interval);
    (void)jget_int(config, "burst", &burst);
    char *events_raw = jget(config, "events");
    char *events[32];
    size_t count = jitems(events_raw, events, 32U);
    st_http_share_gcra *limiter = st_http_share_gcra_create(interval, burst, ST_HTTP_SHARE_LIMITER_MAX_KEYS);
    size_t passed = 0U;
    for (size_t i = 0U; i < count; ++i) {
        int ok = 1;
        long long at = 0;
        long long requests = 0;
        long long admitted_expected = 0;
        long long retry_expected = 0;
        (void)jget_int(events[i], "atMs", &at);
        (void)jget_int(events[i], "requests", &requests);
        (void)jget_int(events[i], "admitted", &admitted_expected);
        int has_retry = jget_int(events[i], "retryAfterSeconds", &retry_expected) == 0;
        char *key = jget_string(events[i], "key");
        long long admitted = 0;
        long long retry = 0;
        for (long long r = 0; r < requests; ++r) {
            long long wait = st_http_share_gcra_take(limiter, key, at);
            if (wait == 0) {
                ++admitted;
            } else if (retry == 0) {
                retry = wait;
            }
        }
        CHECK(admitted == admitted_expected && (has_retry ? retry == retry_expected : retry == 0),
              "rate.%s event %zu: admitted %lld retry %lld", section, i, admitted, retry);
        free(key);
        passed += ok;
    }
    st_http_share_gcra_free(limiter);
    jitems_free(events, count);
    free(events_raw);
    free(config);
    free(rate);
    *total = count;
    return passed;
}

static void test_rate(void)
{
    size_t exchange_total = 0U;
    size_t share_total = 0U;
    size_t exchange = replay_rate("exchange", &exchange_total);
    size_t share = replay_rate("share", &share_total);
    printf("rate: exchange %zu/%zu events, share %zu/%zu events\n", exchange, exchange_total, share, share_total);
}

/* ------------------------------------------------------------------------------------------------
 * HTTP-level tests
 */

/* Creates a share through the API and returns its token (and id) as the response gave them. */
static int create_share(const char *caller, long long route_id, const char *body, char token[65], char share_id[17])
{
    char *response = (char *)malloc(RESPONSE_CAP);
    char path[96];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/shares", route_id);
    int status = manage("POST", path, caller, body, response, RESPONSE_CAP);
    char *value = jget_string(response_body(response), "token");
    int ok = status == 201 && value != NULL && strlen(value) == ST_HTTP_SHARE_TOKEN_LEN;
    if (ok) {
        snprintf(token, 65U, "%s", value);
        memcpy(share_id, value + 4, 16U);
        share_id[16] = '\0';
    } else {
        fprintf(stderr, "share create failed: %.300s\n", response);
    }
    free(value);
    free(response);
    return ok ? 0 : -1;
}

static int share_get(const char *share_id, const char *tail, const char *extra_headers, char *response)
{
    char request[4096];
    int len = snprintf(request, sizeof(request), "GET /http-share/%s%s HTTP/1.1\r\nHost: share.test\r\n%s\r\n",
                       share_id, tail, extra_headers);
    return http_roundtrip(request, (size_t)len, response, RESPONSE_CAP) == 0 ? response_status(response) : 0;
}

static void test_exchange_cookie_attributes(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL + 250LL);
    CHECK(seed_world() == 0 && create_share("alice", 42, "{\"expiresInSeconds\":3600,\"pathPrefix\":\"/docs\"}",
                                            token, share_id) == 0, "cookie test: setup failed");
    st_http_share_gcra_reset(st_http_share_exchange_limiter());
    char request[1024];
    int len = snprintf(request, sizeof(request),
                       "POST /api/public/http-shares/exchange HTTP/1.1\r\nHost: share.test\r\n"
                       "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n{\"token\":\"%s\"}",
                       strlen(token) + 12U, token);
    CHECK(http_roundtrip(request, (size_t)len, response, RESPONSE_CAP) == 0 && response_status(response) == 200,
          "cookie test: exchange failed: %.300s", response);
    char header[512] = "";
    char expected[512];
    /* Created a quarter second into the second: 3600 s after the whole second, less 0.25 s, rounded up. */
    snprintf(expected, sizeof(expected),
             ST_HTTP_SHARE_COOKIE_NAME "=%s; Path=/http-share/%s/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict",
             token, share_id);
    CHECK(response_header(response, "Set-Cookie", 0U, header, sizeof(header)) && strcmp(header, expected) == 0,
          "cookie test: Set-Cookie %s", header);
    CHECK(strstr(header, "Domain") == NULL && strstr(header, "Expires") == NULL, "cookie test: Domain or Expires");
    CHECK(response_header(response, "Cache-Control", 0U, header, sizeof(header)) && strcmp(header, "no-store") == 0,
          "cookie test: Cache-Control %s", header);
    CHECK(response_header(response, "Referrer-Policy", 0U, header, sizeof(header))
              && strcmp(header, "no-referrer") == 0, "cookie test: Referrer-Policy %s", header);
    CHECK(strstr(response_body(response), token) == NULL, "cookie test: the token came back in the body");
    char *location = jget_string(response_body(response), "location");
    char expected_location[64];
    snprintf(expected_location, sizeof(expected_location), "/http-share/%s/docs/", share_id);
    CHECK(location != NULL && strcmp(location, expected_location) == 0, "cookie test: location %s", location);
    free(location);
    /* The management answers never show the token again. */
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/http-routes/42/shares/%s", share_id);
    CHECK(manage("GET", path, "alice", NULL, response, RESPONSE_CAP) == 200 && strstr(response, token) == NULL
              && strstr(response, "\"status\":\"active\"") != NULL, "cookie test: share view %.300s", response);
    free(response);
    printf("http: exchange cookie attributes %s\n", ok ? "ok" : "FAILED");
}

static void test_cookie_stripped_authorization_kept(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    CHECK(seed_world() == 0 && create_share("alice", 42, "{\"expiresInSeconds\":3600,\"pathPrefix\":\"/docs/\"}",
                                            token, share_id) == 0, "cookie strip test: setup failed");
    st_http_share_gcra_reset(st_http_share_request_limiter());
    device_reset(DEVICE_PLAIN);
    char headers[1024];
    snprintf(headers, sizeof(headers),
             "Cookie: theme=dark; " ST_HTTP_SHARE_COOKIE_NAME "=%s; sid=abc\r\n"
             "Cookie: extra=1\r\nAuthorization: Bearer upstream-token\r\n"
             "Origin: https://share.test\r\nReferer: https://share.test/http-share/%s/docs/\r\n"
             "Sec-Fetch-Site: cross-site\r\n", token, share_id);
    int status = share_get(share_id, "/docs/a%20b+c?q=%2F1+2", headers, response);
    CHECK(status == 200 && strstr(response, "forwarded") != NULL, "cookie strip test: status %d %.300s", status, response);
    pthread_mutex_lock(&device.lock);
    CHECK(device.http_calls == 1 && device.cookie_headers == 1 && strcmp(device.cookie, "theme=dark; sid=abc; extra=1") == 0,
          "cookie strip test: device Cookie (%d) %s", device.cookie_headers, device.cookie);
    CHECK(strcmp(device.authorization, "Bearer upstream-token") == 0, "cookie strip test: Authorization %s",
          device.authorization);
    CHECK(strcmp(device.relative_path, "/docs/a%20b+c") == 0 && strcmp(device.raw_query, "q=%2F1+2") == 0
              && strcmp(device.route, "api") == 0,
          "cookie strip test: raw path %s ?%s route %s", device.relative_path, device.raw_query, device.route);
    /* Java UpstreamBrowserHeaders on the share path too: the route target's origin, not the share's. */
    char expected_browser_headers[256];
    snprintf(expected_browser_headers, sizeof(expected_browser_headers),
             "Origin:http://127.0.0.1:9|Referer:http://127.0.0.1:9/http-share/%s/docs/|Sec-Fetch-Site:same-origin",
             share_id);
    CHECK(strcmp(device.browser_headers, expected_browser_headers) == 0, "cookie strip test: browser headers %s",
          device.browser_headers);
    /* The token went in no header at all, whatever its name. */
    CHECK(strstr(device.all_headers, token) == NULL && strstr(device.all_headers, "hs1.") == NULL,
          "cookie strip test: the token reached the device in %s", device.all_headers);
    pthread_mutex_unlock(&device.lock);
    /* No portal headers on the share path: the target's own policy stands. */
    char header[256];
    CHECK(!response_header(response, "Content-Security-Policy", 0U, header, sizeof(header))
              && !response_header(response, "X-Frame-Options", 0U, header, sizeof(header))
              && !response_header(response, "Referrer-Policy", 0U, header, sizeof(header)),
          "cookie strip test: portal headers on a share response");
    free(response);
    printf("http: share cookie stripped, other cookies and Authorization relayed %s\n", ok ? "ok" : "FAILED");
}

static void test_response_rewriting(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    CHECK(seed_world() == 0 && sql_exec("UPDATE http_route_mapping SET path_rewrite_enabled = 1 WHERE id = 42") == 0
              && create_share("alice", 42, "{\"expiresInSeconds\":3600,\"access\":\"full\"}", token, share_id) == 0,
          "rewrite test: setup failed");
    st_http_share_gcra_reset(st_http_share_request_limiter());
    device_reset(DEVICE_HEADERS);
    char headers[256];
    snprintf(headers, sizeof(headers), "Cookie: " ST_HTTP_SHARE_COOKIE_NAME "=%s\r\n", token);
    int status = share_get(share_id, "/", headers, response);
    char header[512] = "";
    char expected[128];
    snprintf(expected, sizeof(expected), "sid=abc; Path=/http-share/%s/; HttpOnly", share_id);
    CHECK(status == 200, "rewrite test: status %d", status);
    CHECK(response_header(response, "Set-Cookie", 0U, header, sizeof(header)) && strcmp(header, expected) == 0,
          "rewrite test: first Set-Cookie %s", header);
    CHECK(response_header(response, "Set-Cookie", 1U, header, sizeof(header)) && strcmp(header, "rel=1") == 0
              && !response_header(response, "Set-Cookie", 2U, header, sizeof(header)),
          "rewrite test: second Set-Cookie %s", header);
    CHECK(strstr(response, "__Host-") == NULL && strstr(response, "evil") == NULL, "rewrite test: dropped cookies relayed");
    CHECK(!response_header(response, "Clear-Site-Data", 0U, header, sizeof(header))
              && !response_header(response, "Expires", 0U, header, sizeof(header)),
          "rewrite test: Clear-Site-Data or Expires relayed");
    /* Nor does the portal add its own policy headers to a relayed answer. */
    CHECK(!response_header(response, "Content-Security-Policy", 0U, header, sizeof(header))
              && !response_header(response, "X-Frame-Options", 0U, header, sizeof(header))
              && !response_header(response, "Referrer-Policy", 0U, header, sizeof(header)),
          "rewrite test: portal headers on a relayed answer");
    pthread_mutex_lock(&device.lock);
    CHECK(strstr(device.all_headers, token) == NULL, "rewrite test: the token reached the device");
    pthread_mutex_unlock(&device.lock);
    CHECK(response_header(response, "Cache-Control", 0U, header, sizeof(header))
              && strcmp(header, "private, no-cache") == 0
              && !response_header(response, "Cache-Control", 1U, header, sizeof(header)),
          "rewrite test: Cache-Control %s", header);
    /* pathRewrite uses the share prefix, never the route's own /http/{client}/{route}. */
    device_reset(DEVICE_HTML);
    status = share_get(share_id, "/index.html", headers, response);
    char link[96];
    snprintf(link, sizeof(link), "href=\"/http-share/%s/app/page\"", share_id);
    CHECK(status == 200 && strstr(response, link) != NULL && strstr(response, "/http/") == NULL,
          "rewrite test: path rewrite %.400s", response);
    free(response);
    printf("http: upstream Set-Cookie, Cache-Control and Clear-Site-Data rewritten %s\n", ok ? "ok" : "FAILED");
}

/* A request over the real socket with an Authorization value (NULL: none) and a JSON body (NULL: none). */
static int http_call(const char *method, const char *path, const char *authorization, const char *body,
                     char *response)
{
    char request[8192];
    int len = snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\nHost: share.test\r\n", method, path);
    if (authorization != NULL) {
        len += snprintf(request + len, sizeof(request) - (size_t)len, "Authorization: %s\r\n", authorization);
    }
    if (body != NULL) {
        len += snprintf(request + len, sizeof(request) - (size_t)len,
                        "Content-Type: application/json\r\nContent-Length: %zu\r\n\r\n%s", strlen(body), body);
    } else {
        len += snprintf(request + len, sizeof(request) - (size_t)len, "\r\n");
    }
    if (len < 0 || (size_t)len >= sizeof(request)) {
        return 0;
    }
    return http_roundtrip(request, (size_t)len, response, RESPONSE_CAP) == 0 ? response_status(response) : 0;
}

/* Exactly one Cache-Control header, with this value. */
static int cache_control_is(const char *response, const char *expected)
{
    char value[128] = "";
    char extra[8];
    return response_header(response, "Cache-Control", 0U, value, sizeof(value)) && strcmp(value, expected) == 0
        && !response_header(response, "Cache-Control", 1U, extra, sizeof(extra));
}

/* A protected route created by owner through the API (so route.created is audited); its id, or 0. */
static long long create_route_via_api(const char *owner, long long client_id, const char *name)
{
    char *response = (char *)malloc(RESPONSE_CAP);
    char path[96];
    char body[256];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", client_id);
    snprintf(body, sizeof(body),
             "{\"route\":\"%s\",\"targetBaseUrl\":\"http://127.0.0.1:9/\",\"enabled\":true,"
             "\"authEnabled\":true,\"authUsername\":\"basic\",\"authPassword\":\"basic-secret\"}", name);
    int status = manage("POST", path, owner, body, response, RESPONSE_CAP);
    long long id = status == 201 ? response_route_id(response) : 0;
    if (id == 0) {
        fprintf(stderr, "route create failed: %.300s\n", response);
    }
    free(response);
    return id;
}

/* The entries of an access-audit listing answer: how many, with their raw objects in items. */
static size_t audit_listing(const char *response, char **items, size_t max)
{
    char *entries = jget(response_body(response), "entries");
    size_t count = entries == NULL ? 0U : jitems(entries, items, max);
    free(entries);
    return count;
}

/* The listing's actions, newest first, are exactly expected. */
static int audit_actions_are(char *const *items, size_t count, const char *const *expected, size_t expected_count)
{
    int same = count == expected_count;
    for (size_t i = 0U; same && i < count; ++i) {
        char *action = jget_string(items[i], "action");
        same = action != NULL && strcmp(action, expected[i]) == 0;
        free(action);
    }
    if (!same) {
        for (size_t i = 0U; i < count; ++i) {
            fprintf(stderr, "  listed %s\n", items[i]);
        }
    }
    return same;
}

static int entry_string_is(const char *entry, const char *key, const char *expected)
{
    char *value = jget_string(entry, key);
    int same = value != NULL && strcmp(value, expected) == 0;
    free(value);
    return same;
}

static int entry_detail_is(const char *entry, const char *expected)
{
    char *detail = jget(entry, "detail");
    int same = detail != NULL && jequal(detail, expected);
    free(detail);
    return same;
}

static void test_revoke_then_gone(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    long long route_id = seed_world() == 0 ? create_route_via_api("alice", 7, "app") : 0;
    CHECK(route_id > 0 && create_share("alice", route_id, "{\"expiresInSeconds\":3600}", token, share_id) == 0,
          "revoke test: setup failed");
    st_http_share_gcra_reset(st_http_share_request_limiter());
    device_reset(DEVICE_PLAIN);
    char headers[256];
    snprintf(headers, sizeof(headers), "Cookie: " ST_HTTP_SHARE_COOKIE_NAME "=%s\r\n", token);
    CHECK(share_get(share_id, "/", headers, response) == 200, "revoke test: share not usable: %.300s", response);
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/shares/%s/revoke", route_id, share_id);
    char *share = NULL;
    char *state = NULL;
    CHECK(manage("POST", path, "alice", "{}", response, RESPONSE_CAP) == 200
              && (share = jget(response_body(response), "share")) != NULL
              && (state = jget_string(share, "status")) != NULL && strcmp(state, "revoked") == 0
              && strstr(response, "\"revokeReason\":\"revoked-by-user\"") != NULL
              && strstr(response, "\"revokedBy\":\"alice\"") != NULL,
          "revoke test: revoke answered %.300s", response);
    free(share);
    free(state);
    CHECK(manage("POST", path, "alice", NULL, response, RESPONSE_CAP) == 200, "revoke test: second revoke");
    CHECK(manage("POST", path, "alice", "{\"x\":1}", response, RESPONSE_CAP) == 400
              && body_has_code(response, "SHARE_REQUEST_INVALID"), "revoke test: revoke with a body");
    int status = share_get(share_id, "/", headers, response);
    char header[256] = "";
    char expected[160];
    snprintf(expected, sizeof(expected),
             ST_HTTP_SHARE_COOKIE_NAME "=; Path=/http-share/%s/; Max-Age=0; HttpOnly; Secure; SameSite=Strict", share_id);
    CHECK(status == 410 && body_has_code(response, "SHARE_REVOKED")
              && response_header(response, "Set-Cookie", 0U, header, sizeof(header)) && strcmp(header, expected) == 0
              && !response_header(response, "Set-Cookie", 1U, header, 1U) && cache_control_is(response, "no-store"),
          "revoke test: after revoke %d %s %.200s", status, header, response);
    pthread_mutex_lock(&device.lock);
    CHECK(device.http_calls == 1, "revoke test: the device saw %d requests", device.http_calls);
    pthread_mutex_unlock(&device.lock);
    /* The route's audit through its endpoint, newest first: revoked once, created, route created. */
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/access-audit", route_id);
    char *items[64];
    CHECK(manage("GET", path, "alice", NULL, response, RESPONSE_CAP) == 200, "revoke test: audit %.300s", response);
    size_t count = audit_listing(response, items, 64U);
    static const char *const actions[] = {"share.revoked", "share.created", "route.created"};
    CHECK(audit_actions_are(items, count, actions, 3U), "revoke test: %zu audit entries", count);
    if (count == 3U) {
        char *detail = jget(items[0], "detail");
        CHECK(entry_string_is(items[0], "actor", "alice") && entry_string_is(detail, "reason", "revoked-by-user"),
              "revoke test: revoked entry %s", items[0]);
        free(detail);
        detail = jget(items[2], "detail");
        CHECK(entry_string_is(detail, "exposure", "protected"), "revoke test: route entry %s", items[2]);
        free(detail);
    }
    jitems_free(items, count);
    free(response);
    printf("http: revoke, then 410 with the clearing cookie; the route's audit lists it %s\n", ok ? "ok" : "FAILED");
}

/* Java disablingTheRouteThroughTheApiEndsItsShares: the route endpoint ends the share for good. */
static void test_route_disable_through_api(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    long long route_id = seed_world() == 0 ? create_route_via_api("alice", 7, "app") : 0;
    CHECK(route_id > 0 && create_share("alice", route_id, "{\"expiresInSeconds\":3600}", token, share_id) == 0,
          "route disable test: setup failed");
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", route_id);
    static const char disable[] = "{\"route\":\"app\",\"targetBaseUrl\":\"http://127.0.0.1:9/\",\"enabled\":false}";
    static const char enable[] = "{\"route\":\"app\",\"targetBaseUrl\":\"http://127.0.0.1:9/\",\"enabled\":true}";
    CHECK(manage("PUT", path, "alice", disable, response, RESPONSE_CAP) == 200,
          "route disable test: disable answered %.300s", response);
    share_state state = read_share(share_id);
    CHECK(state.revoked && strcmp(state.reason, "route-disabled") == 0 && strcmp(state.revoked_by, "alice") == 0,
          "route disable test: share %s by %s", state.reason, state.revoked_by);
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/access-audit", route_id);
    char *items[64];
    CHECK(manage("GET", path, "alice", NULL, response, RESPONSE_CAP) == 200, "route disable test: audit %.300s",
          response);
    size_t count = audit_listing(response, items, 64U);
    static const char *const actions[] = {"share.revoked", "route.exposure-changed", "share.created", "route.created"};
    CHECK(audit_actions_are(items, count, actions, 4U)
              && entry_detail_is(items[1], "{\"from\":\"protected\",\"to\":\"disabled\"}"),
          "route disable test: %zu audit entries", count);
    jitems_free(items, count);
    /* Enabling the route again does not bring the share back. */
    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld", route_id);
    CHECK(manage("PUT", path, "alice", enable, response, RESPONSE_CAP) == 200,
          "route disable test: enable answered %.300s", response);
    share_state after = read_share(share_id);
    CHECK(after.revoked && after.revoked_at == state.revoked_at && strcmp(after.reason, "route-disabled") == 0
              && strcmp(after.revoked_by, "alice") == 0,
          "route disable test: after enabling the route %s by %s", after.reason, after.revoked_by);
    free(response);
    printf("http: disabling the route through the API ends its share for good %s\n", ok ? "ok" : "FAILED");
}

/* Java disablingTheCreatorThroughTheApiEndsTheCreatorsShares: re-enabling the user revives nothing. */
static void test_user_disable_then_reenable(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    CHECK(seed_world() == 0 && create_share("alice", 42, "{\"expiresInSeconds\":3600}", token, share_id) == 0,
          "user disable test: setup failed");
    CHECK(manage("PUT", "/api/admin/users/alice", "admin", "{\"enabled\":false}", response, RESPONSE_CAP) == 200,
          "user disable test: disable answered %.300s", response);
    share_state state = read_share(share_id);
    CHECK(state.revoked && strcmp(state.reason, "creator-lost-access") == 0 && strcmp(state.revoked_by, "admin") == 0,
          "user disable test: share %s by %s", state.reason, state.revoked_by);
    CHECK(manage("PUT", "/api/admin/users/alice", "admin", "{\"enabled\":true}", response, RESPONSE_CAP) == 200,
          "user disable test: enable answered %.300s", response);
    share_state after = read_share(share_id);
    CHECK(after.revoked && after.revoked_at == state.revoked_at && strcmp(after.reason, "creator-lost-access") == 0
              && strcmp(after.revoked_by, "admin") == 0,
          "user disable test: after enabling the user %s by %s", after.reason, after.revoked_by);
    free(response);
    printf("http: disabling the creator ends the share, enabling it again does not revive it %s\n",
           ok ? "ok" : "FAILED");
}

/* Java deletingTheClientThroughTheApiDeletesItsRoutesAndEndsTheirShares, with the tenant listing. */
static void test_client_delete_through_api(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    long long route_id = seed_world() == 0 ? create_route_via_api("alice", 7, "app") : 0;
    CHECK(route_id > 0 && create_share("alice", route_id, "{\"expiresInSeconds\":3600}", token, share_id) == 0,
          "client delete test: setup failed");
    CHECK(manage("DELETE", "/api/admin/clients/7", "admin", NULL, response, RESPONSE_CAP) == 204,
          "client delete test: delete answered %.300s", response);
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM http_route_mapping WHERE id = %lld", route_id);
    CHECK(count_rows(sql) == 0, "client delete test: the route row is still there");
    share_state state = read_share(share_id);
    CHECK(state.revoked && strcmp(state.reason, "client-deleted") == 0 && strcmp(state.revoked_by, "admin") == 0,
          "client delete test: share %s by %s", state.reason, state.revoked_by);
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/http-access-audit?routeId=%lld", route_id);
    char *items[64];
    CHECK(manage("GET", path, "admin", NULL, response, RESPONSE_CAP) == 200, "client delete test: audit %.300s",
          response);
    size_t count = audit_listing(response, items, 64U);
    static const char *const actions[] = {"share.revoked", "route.deleted", "share.created", "route.created"};
    CHECK(audit_actions_are(items, count, actions, 4U) && entry_detail_is(items[1], "{\"exposure\":\"protected\"}")
              && entry_string_is(items[1], "actor", "admin"),
          "client delete test: %zu audit entries", count);
    jitems_free(items, count);
    CHECK(manage("GET", "/api/admin/http-access-audit", "alice", NULL, response, RESPONSE_CAP) == 403
              && body_has_code(response, "SHARE_FORBIDDEN"), "client delete test: tenant audit for a user");
    free(response);
    printf("http: deleting the client through the API deletes its route and ends the share %s\n", ok ? "ok" : "FAILED");
}

/*
 * Java refusalsBeforeAnyControllerArePrivateOnPrivateEndpoints: without a bearer, or with one that
 * is no token at all, the share, audit, workbench and connectivity-check endpoints answer 401 with
 * exactly "private, no-store". Other admin endpoints keep their usual header: Java's portal header
 * writer adds "no-cache, no-store, max-age=0, must-revalidate" (with Pragma and Expires) to every
 * non-/http answer that sets no Cache-Control of its own, successes included, where C's JSON
 * answers all say "no-store"; that platform difference is kept, so the 401 here is "no-store".
 */
static void test_refusals_private_on_private_endpoints(void)
{
    int ok = 1;
    char *response = (char *)malloc(RESPONSE_CAP);
    CHECK(seed_world() == 0, "private refusal test: setup failed");
    static const char *const calls[][2] = {
        {"POST", "/api/admin/http-routes/1/shares"},
        {"GET", "/api/admin/http-routes/1/shares"},
        {"GET", "/api/admin/http-routes/1/shares/abc"},
        {"POST", "/api/admin/http-routes/1/shares/abc/revoke"},
        {"GET", "/api/admin/http-routes/1/access-audit"},
        {"GET", "/api/admin/http-access-audit"},
        {"GET", "/api/admin/workbench"},
        {"POST", "/api/admin/http-routes/1/connectivity-check"}
    };
    static const char *const bearers[] = {NULL, "Bearer not-a-token"};
    for (size_t i = 0U; i < sizeof(calls) / sizeof(calls[0]); ++i) {
        for (size_t b = 0U; b < sizeof(bearers) / sizeof(bearers[0]); ++b) {
            int is_post = strcmp(calls[i][0], "POST") == 0;
            int status = http_call(calls[i][0], calls[i][1], bearers[b], is_post ? "{}" : NULL, response);
            CHECK(status == 401 && cache_control_is(response, "private, no-store"),
                  "private refusal test: %s %s with %s answered %.300s", calls[i][0], calls[i][1],
                  bearers[b] == NULL ? "no bearer" : bearers[b], response);
        }
    }
    int status = http_call("GET", "/api/admin/clients", NULL, NULL, response);
    CHECK(status == 401 && cache_control_is(response, "no-store"), "private refusal test: clients answered %.300s",
          response);
    free(response);
    printf("http: refusals before any handler are private on private endpoints %s\n", ok ? "ok" : "FAILED");
}

typedef struct {
    pthread_barrier_t *start;
    const char *authorization;
    int status;
    int private_no_store;
    int limit_reached;
    char body[512];
} create_racer;

static void *create_racer_thread(void *arg)
{
    create_racer *racer = (create_racer *)arg;
    char *response = (char *)malloc(RESPONSE_CAP);
    pthread_barrier_wait(racer->start);
    racer->status = http_call("POST", "/api/admin/http-routes/42/shares", racer->authorization,
                              "{\"expiresInSeconds\": 3600}", response);
    racer->private_no_store = cache_control_is(response, "private, no-store");
    racer->limit_reached = body_has_code(response, "SHARE_LIMIT_REACHED");
    snprintf(racer->body, sizeof(racer->body), "%s", response_body(response));
    free(response);
    return NULL;
}

/* Java creationsRacingForTheLastSlotStopAtTheLimit: one slot left, eight concurrent creations. */
static void test_creation_race(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    st_http_share_set_random_for_testing(NULL);
    CHECK(seed_world() == 0, "race test: setup failed");
    for (int i = 0; ok && i < ST_HTTP_SHARE_MAX_ACTIVE_PER_ROUTE - 1; ++i) {
        CHECK(create_share("alice", 42, "{\"expiresInSeconds\": 3600}", token, share_id) == 0,
              "race test: share %d not created", i);
    }
    enum { RACERS = 8 };
    char *authorization = bearer_for("alice");
    pthread_barrier_t start;
    pthread_barrier_init(&start, NULL, RACERS);
    create_racer racers[RACERS];
    pthread_t threads[RACERS];
    for (int i = 0; i < RACERS; ++i) {
        memset(&racers[i], 0, sizeof(racers[i]));
        racers[i].start = &start;
        racers[i].authorization = authorization;
        pthread_create(&threads[i], NULL, create_racer_thread, &racers[i]);
    }
    int created = 0;
    int refused = 0;
    for (int i = 0; i < RACERS; ++i) {
        pthread_join(threads[i], NULL);
        CHECK(racers[i].private_no_store, "race test: racer %d without private, no-store", i);
        if (racers[i].status == 201) {
            ++created;
        } else {
            CHECK(racers[i].status == 409 && racers[i].limit_reached, "race test: racer %d answered %d %s", i,
                  racers[i].status, racers[i].body);
            ++refused;
        }
    }
    pthread_barrier_destroy(&start);
    free(authorization);
    char sql[160];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM http_share WHERE route_id = 42 AND revoked_at IS NULL AND expires_at > %lld",
             iso_seconds(VECTOR_NOW));
    long long active = count_rows(sql);
    CHECK(created == 1 && refused == RACERS - 1 && active == ST_HTTP_SHARE_MAX_ACTIVE_PER_ROUTE,
          "race test: %d created, %d refused, %lld active", created, refused, active);
    printf("http: %d creations racing for the last slot: %d created, %d refused %s\n", RACERS, created, refused,
           ok ? "ok" : "FAILED");
}

/* Java anInvalidBodyIsRefusedBeforeAnyLock: the body is judged before the share store is touched. */
static void test_invalid_body_before_store(void)
{
    int ok = 1;
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    CHECK(seed_world() == 0, "invalid body test: setup failed");
    st_storage_http_share_fail_for_testing(1);
    int invalid = manage("POST", "/api/admin/http-routes/42/shares", "alice", "{}", response, RESPONSE_CAP);
    int invalid_code = body_has_code(response, "SHARE_REQUEST_INVALID");
    int invalid_private = cache_control_is(response, "private, no-store");
    /* Control: a valid body with the same failing store does reach it. */
    int valid = manage("POST", "/api/admin/http-routes/42/shares", "alice", "{\"expiresInSeconds\":3600}", response,
                       RESPONSE_CAP);
    int valid_code = body_has_code(response, "SHARE_UNAVAILABLE");
    st_storage_http_share_fail_for_testing(0);
    CHECK(invalid == 400 && invalid_code && invalid_private, "invalid body test: {} answered %d", invalid);
    CHECK(valid == 503 && valid_code, "invalid body test: the failing store answered %d", valid);
    CHECK(count_rows("SELECT COUNT(*) FROM http_share") == 0
              && count_rows("SELECT COUNT(*) FROM http_access_audit") == 0,
          "invalid body test: rows written");
    free(response);
    printf("http: an invalid create body is refused before the share store %s\n", ok ? "ok" : "FAILED");
}

typedef struct {
    atomic_int stop;
    pthread_t thread;
} ticker_state;

/* The maintenance thread's one-second tick (main.c), run here since no session thread exists. */
static void *ticker_thread(void *arg)
{
    ticker_state *state = (ticker_state *)arg;
    while (!atomic_load(&state->stop)) {
        st_admin_http_share_tick();
        struct timespec pause = {.tv_sec = 1, .tv_nsec = 0};
        nanosleep(&pause, NULL);
    }
    return NULL;
}

/* Everything a visitor received of one response, as it arrived. */
typedef struct {
    char data[16384];
    size_t len;
} stream_capture;

/* Opens a long GET through the share and waits until the first event arrived; returns the socket. */
static int open_stream(const char *share_id, const char *token, stream_capture *capture)
{
    capture->len = 0U;
    capture->data[0] = '\0';
    int fd = connect_server();
    char request[512];
    int len = snprintf(request, sizeof(request),
                       "GET /http-share/%s/events HTTP/1.1\r\nHost: share.test\r\nCookie: " ST_HTTP_SHARE_COOKIE_NAME
                       "=%s\r\n\r\n", share_id, token);
    if (fd < 0 || send_text(fd, request, (size_t)len) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        return -1;
    }
    while (capture->len + 1U < sizeof(capture->data)) {
        ssize_t got = recv(fd, capture->data + capture->len, sizeof(capture->data) - 1U - capture->len, 0);
        if (got <= 0) {
            close(fd);
            return -1;
        }
        capture->len += (size_t)got;
        capture->data[capture->len] = '\0';
        if (strstr(capture->data, "data: first") != NULL) {
            return fd;
        }
    }
    close(fd);
    return -1;
}

/* Milliseconds until the server closes the socket; whatever else arrives is added to capture. */
static long long wait_closed(int fd, long long started, stream_capture *capture)
{
    char buffer[1024];
    for (;;) {
        ssize_t got = recv(fd, buffer, sizeof(buffer), 0);
        if (got == 0 || (got < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK)) {
            return monotonic_ms() - started;
        }
        if (got < 0) {
            return -1; /* the 10 s receive timeout ran out */
        }
        size_t room = sizeof(capture->data) - 1U - capture->len;
        size_t kept = (size_t)got < room ? (size_t)got : room;
        memcpy(capture->data + capture->len, buffer, kept);
        capture->len += kept;
        capture->data[capture->len] = '\0';
    }
}

/*
 * 1 when the captured response came to its framed end: the last chunk of a chunked body, or the
 * whole Content-Length. A response cut off mid-body has neither, so its client sees an error (Java
 * HttpClient's readAllBytes throws) instead of a complete body; a close-delimited body has no end
 * that tells the two apart and counts as ended.
 */
static int response_framed_end(const stream_capture *capture)
{
    const char *head_end = strstr(capture->data, "\r\n\r\n");
    if (head_end == NULL) {
        return 0;
    }
    const char *body = head_end + 4;
    size_t body_len = capture->len - (size_t)(body - capture->data);
    char value[64];
    if (response_header(capture->data, "Transfer-Encoding", 0U, value, sizeof(value))
        && strcasecmp(value, "chunked") == 0) {
        size_t at = 0U;
        for (;;) {
            const char *line_end = memchr(body + at, '\n', body_len - at);
            if (line_end == NULL) {
                return 0;
            }
            unsigned long long size = strtoull(body + at, NULL, 16);
            at = (size_t)(line_end - body) + 1U;
            if (size == 0ULL) {
                return 1; /* the last chunk; trailers, if any, follow */
            }
            if (size + 2ULL > (unsigned long long)(body_len - at)) {
                return 0;
            }
            at += (size_t)size + 2U;
        }
    }
    if (response_header(capture->data, "Content-Length", 0U, value, sizeof(value))) {
        return body_len >= (size_t)strtoull(value, NULL, 10);
    }
    return 1;
}

static int device_wait_cancelled(int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    pthread_mutex_lock(&device.lock);
    while (!(device.cancelled && device.stream_returned) && monotonic_ms() < deadline) {
        pthread_mutex_unlock(&device.lock);
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000L};
        nanosleep(&pause, NULL);
        pthread_mutex_lock(&device.lock);
    }
    int cancelled = device.cancelled && device.stream_returned;
    pthread_mutex_unlock(&device.lock);
    return cancelled;
}

static void test_remote_revoke_cuts_stream(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    /* Real time: the tick compares with the wall clock like the server's maintenance thread. */
    st_http_share_set_clock_for_testing(0);
    CHECK(seed_world() == 0 && create_share("alice", 42, "{\"expiresInSeconds\":3600}", token, share_id) == 0,
          "remote revoke test: setup failed");
    st_http_share_gcra_reset(st_http_share_request_limiter());
    device_reset(DEVICE_STREAM);
    ticker_state ticker;
    atomic_init(&ticker.stop, 0);
    pthread_create(&ticker.thread, NULL, ticker_thread, &ticker);
    static stream_capture capture;
    int fd = open_stream(share_id, token, &capture);
    CHECK(fd >= 0 && st_admin_http_share_stream_count(share_id) == 1U, "remote revoke test: stream not open");
    /* Another instance revokes: only the database changes, no hook runs here. */
    char *sql = sqlite3_mprintf("UPDATE http_share SET revoked_at = %lld, revoked_by = 'elsewhere', "
                                "revoke_reason = 'revoked-by-user' WHERE share_id = %Q",
                                (long long)time(NULL), share_id);
    long long started = monotonic_ms();
    CHECK(sql_exec(sql) == 0, "remote revoke test: update failed");
    sqlite3_free(sql);
    long long elapsed = fd >= 0 ? wait_closed(fd, started, &capture) : -1;
    CHECK(elapsed >= 0 && elapsed <= 5000, "remote revoke test: stream cut after %lld ms", elapsed);
    /* Cut off, not completed: the chunked body never got its last chunk. */
    char framing[64] = "";
    CHECK(response_header(capture.data, "Transfer-Encoding", 0U, framing, sizeof(framing))
              && strcmp(framing, "chunked") == 0 && !response_framed_end(&capture),
          "remote revoke test: the response ended cleanly: %s", capture.data);
    CHECK(device_wait_cancelled(2000), "remote revoke test: the NAT stream was not reset");
    if (fd >= 0) {
        close(fd);
    }
    atomic_store(&ticker.stop, 1);
    pthread_join(ticker.thread, NULL);
    long long deadline = monotonic_ms() + 2000;
    while (st_admin_http_share_stream_count(share_id) != 0U && monotonic_ms() < deadline) {
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000L};
        nanosleep(&pause, NULL);
    }
    CHECK(st_admin_http_share_stream_count(share_id) == 0U, "remote revoke test: stream left registered");
    printf("http: a revoke on another instance cut the in-flight stream in %lld ms %s\n", elapsed, ok ? "ok" : "FAILED");
}

static int websocket_read_close_code(int fd)
{
    uint8_t header[2];
    size_t got = 0U;
    while (got < 2U) {
        ssize_t n = recv(fd, header + got, 2U - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    size_t len = header[1] & 0x7fU;
    uint8_t payload[128];
    got = 0U;
    while (got < len) {
        ssize_t n = recv(fd, payload + got, len - got, 0);
        if (n <= 0) {
            return -1;
        }
        got += (size_t)n;
    }
    return (header[0] & 0x0fU) == 0x8U && len >= 2U ? (payload[0] << 8) | payload[1] : -1;
}

static void test_local_cascade_cuts_websocket_and_stream(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(0);
    CHECK(seed_world() == 0 && create_share("alice", 42, "{\"expiresInSeconds\":3600,\"access\":\"full\"}",
                                            token, share_id) == 0, "websocket test: setup failed");
    st_http_share_gcra_reset(st_http_share_request_limiter());
    /* A WebSocket through a full share, then a revoke on this instance: 1008 and RST at once. */
    device_reset(DEVICE_PLAIN);
    pthread_mutex_lock(&device.lock);
    device.ws_accept = 1;
    pthread_mutex_unlock(&device.lock);
    int fd = connect_server();
    char request[1024];
    int len = snprintf(request, sizeof(request),
                       "GET /http-share/%s/live HTTP/1.1\r\nHost: share.test\r\nConnection: Upgrade\r\n"
                       "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                       "Origin: https://share.test\r\nSec-Fetch-Site: cross-site\r\n"
                       "Cookie: " ST_HTTP_SHARE_COOKIE_NAME "=%s\r\n\r\n", share_id, token);
    char handshake[512] = "";
    ssize_t got = fd >= 0 && send_text(fd, request, (size_t)len) == 0 ? recv(fd, handshake, sizeof(handshake) - 1U, 0) : -1;
    if (got > 0) {
        handshake[got] = '\0';
    }
    CHECK(got > 0 && strstr(handshake, "101 Switching Protocols") != NULL, "websocket test: no 101: %s", handshake);
    pthread_mutex_lock(&device.lock);
    CHECK(strcmp(device.browser_headers, "Origin:http://127.0.0.1:9|Sec-Fetch-Site:same-origin") == 0,
          "websocket test: browser headers %s", device.browser_headers);
    pthread_mutex_unlock(&device.lock);
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/http-routes/42/shares/%s/revoke", share_id);
    long long started = monotonic_ms();
    CHECK(manage("POST", path, "alice", NULL, response, RESPONSE_CAP) == 200, "websocket test: revoke failed");
    int code = fd >= 0 ? websocket_read_close_code(fd) : -1;
    CHECK(code == 1008 && monotonic_ms() - started < 2000, "websocket test: close code %d", code);
    long long deadline = monotonic_ms() + 3000;
    pthread_mutex_lock(&device.lock);
    while (!device.ws_closed && monotonic_ms() < deadline) {
        pthread_mutex_unlock(&device.lock);
        struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000L};
        nanosleep(&pause, NULL);
        pthread_mutex_lock(&device.lock);
    }
    CHECK(device.ws_closed && device.ws_reset_code == ST_ADMIN_HTTP_SHARE_RESET_CODE,
          "websocket test: device stream ended with %u", device.ws_reset_code);
    pthread_mutex_unlock(&device.lock);
    if (fd >= 0) {
        close(fd);
    }
    /* A long HTTP response, then the owner disables the route: the hook cuts it at once. */
    CHECK(create_share("alice", 42, "{\"expiresInSeconds\":3600}", token, share_id) == 0, "cascade test: share");
    device_reset(DEVICE_STREAM);
    static stream_capture capture;
    fd = open_stream(share_id, token, &capture);
    CHECK(fd >= 0, "cascade test: stream not open");
    started = monotonic_ms();
    CHECK(manage("PUT", "/api/admin/http-routes/42", "alice", "{\"enabled\":false}", response, RESPONSE_CAP) == 200,
          "cascade test: route update failed: %.300s", response);
    long long elapsed = fd >= 0 ? wait_closed(fd, started, &capture) : -1;
    CHECK(elapsed >= 0 && elapsed < 1000, "cascade test: stream cut after %lld ms (no ticker runs)", elapsed);
    CHECK(!response_framed_end(&capture), "cascade test: the response ended cleanly: %s", capture.data);
    CHECK(device_wait_cancelled(2000), "cascade test: the NAT stream was not reset");
    if (fd >= 0) {
        close(fd);
    }
    share_state state = read_share(share_id);
    CHECK(state.revoked && strcmp(state.reason, "route-disabled") == 0 && strcmp(state.revoked_by, "alice") == 0,
          "cascade test: share %s by %s", state.reason, state.revoked_by);
    audit_row rows[16];
    size_t count = read_audit(rows, 16U);
    CHECK(count == 5U && strcmp(rows[3].action, "route.exposure-changed") == 0
              && strcmp(rows[3].detail, "{\"from\":\"protected\",\"to\":\"disabled\"}") == 0
              && strcmp(rows[4].action, "share.revoked") == 0,
          "cascade test: %zu audit rows", count);
    free(response);
    printf("http: local revoke closes a WebSocket with 1008, a route hook cuts a stream %s\n", ok ? "ok" : "FAILED");
}

static void test_cascades_from_endpoints(void)
{
    int ok = 1;
    char token[65];
    char share_a[17];
    char share_b[17];
    char share_c[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    CHECK(seed_world() == 0
              && create_share("bob", 50, "{\"expiresInSeconds\":3600}", token, share_a) == 0
              && create_share("admin", 50, "{\"expiresInSeconds\":3600}", token, share_b) == 0
              && create_share("alice", 42, "{\"expiresInSeconds\":3600}", token, share_c) == 0,
          "endpoint cascades: setup failed");
    /*
     * Deleting bob ends bob's share and leaves the admin's share of the same route. An account that
     * still owns a client is not deleted (management-accounts.md 7.1): client 8 goes to admin first.
     */
    CHECK(manage("DELETE", "/api/admin/users/bob", "carol", NULL, response, RESPONSE_CAP) == 409
              && sql_exec("UPDATE client_account SET owner_username = 'admin' WHERE id = 8;") == 0,
          "endpoint cascades: refused user delete");
    CHECK(manage("DELETE", "/api/admin/users/bob", "carol", NULL, response, RESPONSE_CAP) == 204,
          "endpoint cascades: user delete");
    share_state a = read_share(share_a);
    share_state b = read_share(share_b);
    CHECK(a.revoked && strcmp(a.reason, "creator-lost-access") == 0 && strcmp(a.revoked_by, "carol") == 0 && !b.revoked,
          "endpoint cascades: after user delete %s %s", a.reason, b.reason);
    /* Deleting client 8 deletes route 50 (route.deleted) and ends the admin's share. */
    CHECK(manage("DELETE", "/api/admin/clients/8", "admin", NULL, response, RESPONSE_CAP) == 204,
          "endpoint cascades: client delete");
    b = read_share(share_b);
    CHECK(b.revoked && strcmp(b.reason, "client-deleted") == 0 && strcmp(b.revoked_by, "admin") == 0,
          "endpoint cascades: after client delete %s", b.reason);
    /* Disabling client 7 ends alice's share of route 42. */
    CHECK(manage("PUT", "/api/admin/clients/7", "admin", "{\"enabled\":false}", response, RESPONSE_CAP) == 200,
          "endpoint cascades: client disable");
    share_state c = read_share(share_c);
    CHECK(c.revoked && strcmp(c.reason, "client-disabled") == 0, "endpoint cascades: after client disable %s", c.reason);
    audit_row rows[16];
    size_t count = read_audit(rows, 16U);
    const char *expected[] = {"share.created", "share.created", "share.created", "share.revoked",
                              "route.deleted", "share.revoked", "share.revoked"};
    int sequence = count == sizeof(expected) / sizeof(expected[0]);
    for (size_t i = 0U; sequence && i < count; ++i) {
        sequence = strcmp(rows[i].action, expected[i]) == 0;
    }
    CHECK(sequence && strcmp(rows[4].detail, "{\"exposure\":\"protected\"}") == 0, "endpoint cascades: %zu audit rows", count);
    /* The audit endpoints: per route for whoever manages it, per tenant for admins only. */
    CHECK(manage("GET", "/api/admin/http-routes/42/access-audit?limit=1", "alice", NULL, response, RESPONSE_CAP) == 200
              && strstr(response, "\"action\":\"share.revoked\"") != NULL
              && strstr(response, "\"nextBefore\":") != NULL && strstr(response, "\"nextBefore\":null") == NULL,
          "endpoint cascades: route audit %.300s", response);
    CHECK(manage("GET", "/api/admin/http-access-audit?routeId=50", "alice", NULL, response, RESPONSE_CAP) == 403
              && body_has_code(response, "SHARE_FORBIDDEN"), "endpoint cascades: tenant audit for a user");
    CHECK(manage("GET", "/api/admin/http-access-audit?routeId=50&limit=200", "admin", NULL, response, RESPONSE_CAP) == 200
              && strstr(response, "\"routeId\":50") != NULL && strstr(response, "\"nextBefore\":null") != NULL,
          "endpoint cascades: tenant audit of a deleted route %.300s", response);
    CHECK(manage("GET", "/api/admin/http-access-audit?limit=0", "admin", NULL, response, RESPONSE_CAP) == 400,
          "endpoint cascades: bad limit");
    CHECK(manage("GET", "/api/admin/http-access-audit", "eve", NULL, response, RESPONSE_CAP) == 200
              && strstr(response, "\"entries\":[]") != NULL, "endpoint cascades: other tenant sees nothing");
    static const char *const anonymous[][2] = {
        {"POST", "/api/admin/http-routes/42/shares"},
        {"GET", "/api/admin/http-routes/42/shares"},
        {"GET", "/api/admin/http-routes/42/shares/abcdefghijklmnop"},
        {"POST", "/api/admin/http-routes/42/shares/abcdefghijklmnop/revoke"},
        {"GET", "/api/admin/http-routes/42/access-audit"},
        {"GET", "/api/admin/http-access-audit"}
    };
    for (size_t i = 0U; i < sizeof(anonymous) / sizeof(anonymous[0]); ++i) {
        char cache[64] = "";
        CHECK(manage(anonymous[i][0], anonymous[i][1], NULL, NULL, response, RESPONSE_CAP) == 401
                  && response_header(response, "Cache-Control", 0U, cache, sizeof(cache))
                  && strcmp(cache, "private, no-store") == 0,
              "endpoint cascades: anonymous %s %s answered %.200s", anonymous[i][0], anonymous[i][1], response);
    }
    CHECK(manage("GET", "/api/admin/http-routes/abc/shares", "admin", NULL, response, RESPONSE_CAP) == 404
              && body_has_code(response, "SHARE_ROUTE_NOT_FOUND"), "endpoint cascades: non-numeric route id");
    free(response);
    printf("http: cascades from the user, client and route endpoints %s\n", ok ? "ok" : "FAILED");
}

static void test_builtin_admin_share(void)
{
    int ok = 1;
    char token[65];
    char share_id[17];
    char *response = (char *)malloc(RESPONSE_CAP);
    st_http_share_set_clock_for_testing(iso_seconds(VECTOR_NOW) * 1000LL);
    CHECK(seed_world() == 0
              && sql_exec("INSERT INTO client_account(rowid, tenant_id, client_name, owner_username, enabled) "
                          "VALUES(9,'default','client-9','someone',1);"
                          "INSERT INTO http_route_mapping(id, client_name, route, target_base_url, enabled, "
                          "auth_enabled, auth_username, auth_password_hash) VALUES(70,'client-9','lab',"
                          "'http://127.0.0.1:9/',1,1,'u','0000000000000000000000000000000000000000000000000000000000000000')") == 0
              && create_share("root", 70, "{\"expiresInSeconds\":3600}", token, share_id) == 0,
          "built-in admin test: setup failed");
    st_http_share_gcra_reset(st_http_share_request_limiter());
    device_reset(DEVICE_PLAIN);
    char headers[256];
    snprintf(headers, sizeof(headers), "Cookie: " ST_HTTP_SHARE_COOKIE_NAME "=%s\r\n", token);
    CHECK(share_get(share_id, "/", headers, response) == 200, "built-in admin test: share of the built-in admin %.200s",
          response);
    /* Once the built-in admin may not sign in any more, its shares end. */
    unsetenv("SPECUS_AUTH_PASSWORD");
    int status = share_get(share_id, "/", headers, response);
    setenv("SPECUS_AUTH_PASSWORD", "root-password", 1);
    share_state state = read_share(share_id);
    CHECK(status == 410 && strcmp(state.reason, "creator-lost-access") == 0, "built-in admin test: %d %s", status,
          state.reason);
    free(response);
    printf("http: shares of the built-in admin %s\n", ok ? "ok" : "FAILED");
}

static char *read_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long len = ftell(file);
    rewind(file);
    char *data = (char *)malloc((size_t)len + 1U);
    if (data != NULL && fread(data, 1U, (size_t)len, file) == (size_t)len) {
        data[len] = '\0';
    } else {
        free(data);
        data = NULL;
    }
    fclose(file);
    return data;
}

int main(void)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    /* The in-process admin server can still be writing to a socket the test has closed. */
    (void)signal(SIGPIPE, SIG_IGN);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "c-http-share-test-secret", 1);
    /* "admin" is a stored user of the vector's world, so the built-in admin goes by another name. */
    setenv("SPECUS_AUTH_USERNAME", "root", 1);
    setenv("SPECUS_AUTH_PASSWORD", "root-password", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    unsetenv("SPECUS_TRUSTED_PROXIES");
    unsetenv("SPECUS_AUTH_TENANT_ID");
    /* Every case reseeds the database; on tmpfs its fsyncs cost nothing. */
    struct stat shm;
    const char *db_dir = stat("/dev/shm", &shm) == 0 && S_ISDIR(shm.st_mode) ? "/dev/shm" : "/tmp";
    snprintf(db_path, sizeof(db_path), "%s/specus-c-http-share-%ld.db", db_dir, (long)getpid());
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    vector_json = read_file(ST_SHARE_VECTOR_FILE);
    if (vector_json == NULL || !st_json_is_valid_object(vector_json)) {
        fprintf(stderr, "cannot read %s\n", ST_SHARE_VECTOR_FILE);
        return 1;
    }
    if (st_admin_server_start_with_handlers(&admin_server, 0, "", device_forward, NULL, device_ws_open,
                                            device_ws_data, device_ws_close, NULL) != 0) {
        fprintf(stderr, "admin server did not start\n");
        return 1;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (getsockname(admin_server.fd, (struct sockaddr *)&address, &address_len) != 0) {
        return 1;
    }
    server_port = ntohs(address.sin_port);

    test_constants();
    test_token();
    test_path_prefix();
    test_create();
    test_exchange();
    test_access();
    test_headers();
    test_lifecycle();
    test_rate();
    test_exchange_cookie_attributes();
    test_cookie_stripped_authorization_kept();
    test_response_rewriting();
    test_revoke_then_gone();
    test_route_disable_through_api();
    test_user_disable_then_reenable();
    test_client_delete_through_api();
    test_refusals_private_on_private_endpoints();
    test_creation_race();
    test_invalid_body_before_store();
    test_remote_revoke_cuts_stream();
    test_local_cascade_cuts_websocket_and_stream();
    test_cascades_from_endpoints();
    test_builtin_admin_share();

    st_http_share_set_clock_for_testing(0);
    device_reset(DEVICE_PLAIN);
    (void)shutdown(admin_server.fd, SHUT_RDWR);
    close(admin_server.fd);
    unlink(db_path);
    free(vector_json);
    if (fail_count != 0) {
        fprintf(stderr, "http share tests: %d failures\n", fail_count);
        return 1;
    }
    printf("http share tests passed\n");
    return 0;
}
