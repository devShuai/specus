#define _POSIX_C_SOURCE 200809L

/*
 * Opt-in product metrics (protocol/spec/product-metrics.md).
 *
 * 1. Replays protocol/test-vectors/product-metrics-v1.json through the real admin request handling
 *    (routing, the shared Bearer authentication that re-reads the account, the handlers and
 *    SQLite): the bucket and rate tables, every ingest validation case and every scenario op, with
 *    the product metrics clock pinned to each op's time and the four tables compared at every
 *    checkpoint. milestone / userDeleted / sweep ops call the server-internal hooks directly.
 * 2. Closed-schema, deployment-flag, storage-failure and private-header checks beyond the vector.
 * 3. The write paths that fire the onboarding hooks, through the real endpoints.
 * 4. With the server binary as argv[1]: a real specus-server-c process, where a control-connection
 *    login fires client_online in main.c and the HTTP layer hands a 4097-byte body to the handler.
 *
 * Usage: specus_c_product_metrics_tests <path-to-specus-server-c>
 */

#include "server_harness.h"

#include "admin_http.h"
#include "json.h"
#include "password_hash.h"
#include "product_metrics.h"
#include "registration.h"
#include "security.h"
#include "storage.h"

#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ST_PRODUCT_METRICS_VECTOR_FILE
#define ST_PRODUCT_METRICS_VECTOR_FILE "../../../protocol/test-vectors/product-metrics-v1.json"
#endif

#define PM_TEST_JWT_SECRET "product-metrics-test-jwt-secret-that-is-long-and-random-2026"
#define PM_TEST_BUILTIN_USER "pm-builtin"
#define PM_TEST_BUILTIN_PASSWORD "pm-builtin-password-2026"
#define PM_RESPONSE_BYTES 262144U
#define PM_MAX_ACTORS 32U

static int failures = 0;

#define EXPECT(condition, ...)                                          \
    do {                                                                \
        if (!(condition)) {                                             \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);        \
            fprintf(stderr, __VA_ARGS__);                               \
            fprintf(stderr, "\n");                                      \
            ++failures;                                                 \
        }                                                               \
    } while (0)

/* ---- A small JSON tree (test only) ------------------------------------------------------------- */

typedef enum { JV_NULL, JV_BOOL, JV_NUMBER, JV_STRING, JV_ARRAY, JV_OBJECT } jv_kind;

typedef struct jv {
    jv_kind kind;
    int boolean;
    double number;
    char *text;
    size_t text_len;
    struct jv **items;
    char **keys;
    size_t count;
    /* The value's source text, for request bodies taken verbatim from the vector. */
    const char *raw;
    size_t raw_len;
} jv;

static void jv_free(jv *value)
{
    if (value == NULL) {
        return;
    }
    for (size_t i = 0; i < value->count; ++i) {
        jv_free(value->items[i]);
        if (value->keys != NULL) {
            free(value->keys[i]);
        }
    }
    free(value->items);
    free(value->keys);
    free(value->text);
    free(value);
}

static const char *jv_ws(const char *p)
{
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        ++p;
    }
    return p;
}

static int jv_hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int jv_put(char **out, size_t *len, size_t *cap, unsigned char byte)
{
    if (*len + 2U > *cap) {
        size_t next = *cap == 0U ? 32U : *cap * 2U;
        char *grown = (char *)realloc(*out, next);
        if (grown == NULL) {
            return -1;
        }
        *out = grown;
        *cap = next;
    }
    (*out)[(*len)++] = (char)byte;
    (*out)[*len] = '\0';
    return 0;
}

static int jv_put_code_point(char **out, size_t *len, size_t *cap, unsigned int cp)
{
    if (cp <= 0x7fU) {
        return jv_put(out, len, cap, (unsigned char)cp);
    }
    if (cp <= 0x7ffU) {
        return jv_put(out, len, cap, (unsigned char)(0xc0U | (cp >> 6)))
            || jv_put(out, len, cap, (unsigned char)(0x80U | (cp & 0x3fU)));
    }
    if (cp <= 0xffffU) {
        return jv_put(out, len, cap, (unsigned char)(0xe0U | (cp >> 12)))
            || jv_put(out, len, cap, (unsigned char)(0x80U | ((cp >> 6) & 0x3fU)))
            || jv_put(out, len, cap, (unsigned char)(0x80U | (cp & 0x3fU)));
    }
    return jv_put(out, len, cap, (unsigned char)(0xf0U | (cp >> 18)))
        || jv_put(out, len, cap, (unsigned char)(0x80U | ((cp >> 12) & 0x3fU)))
        || jv_put(out, len, cap, (unsigned char)(0x80U | ((cp >> 6) & 0x3fU)))
        || jv_put(out, len, cap, (unsigned char)(0x80U | (cp & 0x3fU)));
}

static unsigned int jv_hex4(const char **p, int *ok)
{
    unsigned int value = 0U;
    for (int i = 0; i < 4; ++i) {
        int digit = jv_hex((*p)[i]);
        if (digit < 0) {
            *ok = 0;
            return 0U;
        }
        value = (value << 4U) | (unsigned int)digit;
    }
    *p += 4;
    return value;
}

static char *jv_string(const char **cursor, size_t *out_len)
{
    const char *p = *cursor;
    if (*p != '"') {
        return NULL;
    }
    ++p;
    char *out = NULL;
    size_t len = 0U;
    size_t cap = 0U;
    if (jv_put(&out, &len, &cap, 0U) != 0) {
        return NULL;
    }
    len = 0U;
    while (*p != '"') {
        if (*p == '\0') {
            free(out);
            return NULL;
        }
        if (*p != '\\') {
            if (jv_put(&out, &len, &cap, (unsigned char)*p++) != 0) {
                free(out);
                return NULL;
            }
            continue;
        }
        ++p;
        unsigned int cp = 0U;
        int ok = 1;
        switch (*p++) {
        case '"': cp = '"'; break;
        case '\\': cp = '\\'; break;
        case '/': cp = '/'; break;
        case 'b': cp = '\b'; break;
        case 'f': cp = '\f'; break;
        case 'n': cp = '\n'; break;
        case 'r': cp = '\r'; break;
        case 't': cp = '\t'; break;
        case 'u':
            cp = jv_hex4(&p, &ok);
            if (ok && cp >= 0xd800U && cp <= 0xdbffU && p[0] == '\\' && p[1] == 'u') {
                p += 2;
                unsigned int low = jv_hex4(&p, &ok);
                cp = 0x10000U + ((cp - 0xd800U) << 10U) + (low - 0xdc00U);
            }
            break;
        default:
            ok = 0;
            break;
        }
        if (!ok || jv_put_code_point(&out, &len, &cap, cp) != 0) {
            free(out);
            return NULL;
        }
    }
    *cursor = p + 1;
    *out_len = len;
    return out;
}

static jv *jv_value(const char **cursor, int depth);

static int jv_append(jv *container, jv *item, char *key)
{
    jv **items = (jv **)realloc(container->items, (container->count + 1U) * sizeof(jv *));
    if (items == NULL) {
        return -1;
    }
    container->items = items;
    if (container->kind == JV_OBJECT) {
        char **keys = (char **)realloc(container->keys, (container->count + 1U) * sizeof(char *));
        if (keys == NULL) {
            return -1;
        }
        container->keys = keys;
        container->keys[container->count] = key;
    }
    container->items[container->count++] = item;
    return 0;
}

static jv *jv_value(const char **cursor, int depth)
{
    const char *p = jv_ws(*cursor);
    if (depth > 64) {
        return NULL;
    }
    jv *value = (jv *)calloc(1U, sizeof(jv));
    if (value == NULL) {
        return NULL;
    }
    value->raw = p;
    if (*p == '{' || *p == '[') {
        int object = *p == '{';
        char closing = object ? '}' : ']';
        value->kind = object ? JV_OBJECT : JV_ARRAY;
        p = jv_ws(p + 1);
        if (*p == closing) {
            ++p;
        } else {
            for (;;) {
                char *key = NULL;
                if (object) {
                    size_t key_len = 0U;
                    key = jv_string(&p, &key_len);
                    p = key == NULL ? p : jv_ws(p);
                    if (key == NULL || *p != ':') {
                        free(key);
                        jv_free(value);
                        return NULL;
                    }
                    ++p;
                }
                jv *item = jv_value(&p, depth + 1);
                if (item == NULL || jv_append(value, item, key) != 0) {
                    free(key);
                    jv_free(item);
                    jv_free(value);
                    return NULL;
                }
                p = jv_ws(p);
                if (*p == ',') {
                    p = jv_ws(p + 1);
                    continue;
                }
                if (*p != closing) {
                    jv_free(value);
                    return NULL;
                }
                ++p;
                break;
            }
        }
    } else if (*p == '"') {
        value->kind = JV_STRING;
        value->text = jv_string(&p, &value->text_len);
        if (value->text == NULL) {
            jv_free(value);
            return NULL;
        }
    } else if (strncmp(p, "true", 4U) == 0 || strncmp(p, "false", 5U) == 0) {
        value->kind = JV_BOOL;
        value->boolean = *p == 't';
        p += value->boolean ? 4 : 5;
    } else if (strncmp(p, "null", 4U) == 0) {
        value->kind = JV_NULL;
        p += 4;
    } else {
        char *end = NULL;
        value->kind = JV_NUMBER;
        value->number = strtod(p, &end);
        if (end == p) {
            jv_free(value);
            return NULL;
        }
        p = end;
    }
    value->raw_len = (size_t)(p - value->raw);
    *cursor = p;
    return value;
}

static jv *jv_parse(const char *text)
{
    if (text == NULL) {
        return NULL;
    }
    const char *p = text;
    jv *value = jv_value(&p, 0);
    if (value != NULL && *jv_ws(p) != '\0') {
        jv_free(value);
        return NULL;
    }
    return value;
}

static const jv *jv_get(const jv *object, const char *key)
{
    if (object == NULL || object->kind != JV_OBJECT) {
        return NULL;
    }
    for (size_t i = 0; i < object->count; ++i) {
        if (strcmp(object->keys[i], key) == 0) {
            return object->items[i];
        }
    }
    return NULL;
}

static const char *jv_text(const jv *object, const char *key)
{
    const jv *value = jv_get(object, key);
    return value != NULL && value->kind == JV_STRING ? value->text : NULL;
}

/* jv_text, or "" when the key is missing or not a string. */
static const char *jv_str(const jv *object, const char *key)
{
    const char *text = jv_text(object, key);
    return text == NULL ? "" : text;
}

static long long jv_int(const jv *object, const char *key, long long fallback)
{
    const jv *value = jv_get(object, key);
    return value != NULL && value->kind == JV_NUMBER ? (long long)value->number : fallback;
}

/* Semantic equality: object keys in any order, arrays in order, numbers by value. */
static int jv_equal(const jv *a, const jv *b)
{
    if (a == NULL || b == NULL || a->kind != b->kind) {
        return 0;
    }
    switch (a->kind) {
    case JV_NULL: return 1;
    case JV_BOOL: return a->boolean == b->boolean;
    case JV_NUMBER: return a->number == b->number;
    case JV_STRING: return a->text_len == b->text_len && memcmp(a->text, b->text, a->text_len) == 0;
    case JV_ARRAY:
        if (a->count != b->count) return 0;
        for (size_t i = 0; i < a->count; ++i) {
            if (!jv_equal(a->items[i], b->items[i])) return 0;
        }
        return 1;
    case JV_OBJECT:
        if (a->count != b->count) return 0;
        for (size_t i = 0; i < a->count; ++i) {
            if (!jv_equal(a->items[i], jv_get(b, a->keys[i]))) return 0;
        }
        return 1;
    }
    return 0;
}

/* ---- Clock, dates, database ------------------------------------------------------------------- */

static long long test_now_ms = 0;

static long long test_clock(void)
{
    return test_now_ms;
}

static long long days_from_civil(long long year, unsigned month, unsigned day)
{
    year -= month <= 2U;
    long long era = (year >= 0 ? year : year - 399) / 400;
    unsigned year_of_era = (unsigned)(year - era * 400);
    unsigned day_of_year = (153U * (month > 2U ? month - 3U : month + 9U) + 2U) / 5U + day - 1U;
    unsigned day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
    return era * 146097LL + (long long)day_of_era - 719468LL;
}

/* "YYYY-MM-DDTHH:MM:SSZ" as epoch milliseconds, -1 when malformed. */
static long long instant_ms(const char *text)
{
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (text == NULL || strlen(text) != 20U
        || sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2dZ", &year, &month, &day, &hour, &minute, &second) != 6) {
        return -1;
    }
    long long days = days_from_civil(year, (unsigned)month, (unsigned)day);
    return ((days * 86400LL) + hour * 3600LL + minute * 60LL + second) * 1000LL;
}

static char db_path[320];
static int db_serial = 0;

static void drop_database(void)
{
    if (db_path[0] == '\0') {
        return;
    }
    const char *suffixes[] = {"", "-journal", "-wal", "-shm"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        char path[400];
        snprintf(path, sizeof(path), "%s%s", db_path, suffixes[i]);
        unlink(path);
    }
    db_path[0] = '\0';
}

/* A fresh SQLite database per scenario, on /dev/shm when there is one (much faster). */
static int fresh_database(void)
{
    drop_database();
    const char *dir = access("/dev/shm", W_OK) == 0 ? "/dev/shm" : "/tmp";
    snprintf(db_path, sizeof(db_path), "%s/specus-c-product-metrics-%ld-%d.db", dir, (long)getpid(), ++db_serial);
    drop_database();
    snprintf(db_path, sizeof(db_path), "%s/specus-c-product-metrics-%ld-%d.db", dir, (long)getpid(), db_serial);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    st_product_metrics_limiter_reset();
    if (st_storage_init(db_path, 0) != 0) {
        fprintf(stderr, "product metrics test database init failed\n");
        return -1;
    }
    return 0;
}

static int sql_exec(const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK ? sqlite3_exec(db, sql, NULL, NULL, &error) : SQLITE_ERROR;
    if (rc != SQLITE_OK) {
        fprintf(stderr, "test sql failed: %s: %s\n", sql, error == NULL ? "?" : error);
    }
    sqlite3_free(error);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

static long long sql_scalar(const char *sql)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long value = -1;
    if (sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        value = sqlite3_column_type(stmt, 0) == SQLITE_NULL ? -2 : sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

static long long transfer_total(void)
{
    long long total = sql_scalar("SELECT COALESCE(SUM(count), 0) FROM product_metrics_transfer_daily");
    return total < 0 ? 0 : total;
}

/* Every row of a query as "a|b|c" (NULL as "null"), sorted. */
typedef struct {
    char **rows;
    size_t count;
} row_list;

static void row_list_free(row_list *list)
{
    for (size_t i = 0; i < list->count; ++i) {
        free(list->rows[i]);
    }
    free(list->rows);
    list->rows = NULL;
    list->count = 0U;
}

static int row_list_add(row_list *list, const char *row)
{
    char **rows = (char **)realloc(list->rows, (list->count + 1U) * sizeof(char *));
    if (rows == NULL) {
        return -1;
    }
    list->rows = rows;
    list->rows[list->count] = strdup(row);
    return list->rows[list->count++] == NULL ? -1 : 0;
}

static int compare_text(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int table_rows(const char *sql, row_list *list)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        ? 0 : -1;
    int step = SQLITE_DONE;
    while (rc == 0 && (step = sqlite3_step(stmt)) == SQLITE_ROW) {
        char row[1024] = "";
        size_t used = 0U;
        for (int column = 0; column < sqlite3_column_count(stmt); ++column) {
            const char *separator = column == 0 ? "" : "|";
            int written;
            if (sqlite3_column_type(stmt, column) == SQLITE_NULL) {
                written = snprintf(row + used, sizeof(row) - used, "%snull", separator);
            } else if (sqlite3_column_type(stmt, column) == SQLITE_INTEGER) {
                written = snprintf(row + used, sizeof(row) - used, "%s%lld", separator,
                                   (long long)sqlite3_column_int64(stmt, column));
            } else {
                written = snprintf(row + used, sizeof(row) - used, "%s%s", separator,
                                   (const char *)sqlite3_column_text(stmt, column));
            }
            used += written > 0 ? (size_t)written : 0U;
            if (used >= sizeof(row)) {
                rc = -1;
                break;
            }
        }
        if (rc == 0) {
            rc = row_list_add(list, row);
        }
    }
    if (rc == 0 && step != SQLITE_DONE) {
        rc = -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    qsort(list->rows, list->count, sizeof(char *), compare_text);
    return rc;
}

/* ---- Requests --------------------------------------------------------------------------------- */

typedef struct {
    int status;
    char cache_control[64];
    const char *body;
} pm_response;

static char response_buffer[PM_RESPONSE_BYTES];

static void header_value(const char *response, const char *name, char *out, size_t out_len)
{
    out[0] = '\0';
    const char *end = strstr(response, "\r\n\r\n");
    char needle[64];
    snprintf(needle, sizeof(needle), "\r\n%s: ", name);
    const char *found = strstr(response, needle);
    if (end == NULL || found == NULL || found > end) {
        return;
    }
    found += strlen(needle);
    const char *line_end = strstr(found, "\r\n");
    size_t len = line_end == NULL ? 0U : (size_t)(line_end - found);
    snprintf(out, out_len, "%.*s", (int)(len < out_len ? len : out_len - 1U), found);
}

/*
 * One request through st_admin_build_response_*: with an Authorization header the exact body bytes
 * go in with their length (NUL bytes included); without one the shared layer must refuse it.
 */
static int call(const char *method, const char *path, const char *authorization, const char *body, size_t body_len,
                pm_response *response)
{
    memset(response, 0, sizeof(*response));
    int len = authorization == NULL
        ? st_admin_build_response_with_auth(method, path, NULL, body, response_buffer, sizeof(response_buffer))
        : st_admin_build_response_with_content(method, path, authorization, "application/json",
                                               (const uint8_t *)body, body == NULL ? 0U : body_len,
                                               response_buffer, sizeof(response_buffer));
    if (len <= 0 || sscanf(response_buffer, "HTTP/1.1 %d", &response->status) != 1) {
        fprintf(stderr, "%s %s produced no response\n", method, path);
        return -1;
    }
    header_value(response_buffer, "Cache-Control", response->cache_control, sizeof(response->cache_control));
    const char *separator = strstr(response_buffer, "\r\n\r\n");
    response->body = separator == NULL ? "" : separator + 4;
    return 0;
}

static int call_text(const char *method, const char *path, const char *authorization, const char *body,
                     pm_response *response)
{
    return call(method, path, authorization, body, body == NULL ? 0U : strlen(body), response);
}

static int bearer_for(const char *username, const char *tenant_id, char *out, size_t out_len)
{
    char token[2048];
    if (st_security_issue_local_token(username, tenant_id, "USER", PM_TEST_JWT_SECRET, 3600, token, sizeof(token)) != 0) {
        return -1;
    }
    int written = snprintf(out, out_len, "Bearer %s", token);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

/* The body's {"code": ...}, or "" when there is none. */
static void body_code(const char *body, char *out, size_t out_len)
{
    jv *parsed = jv_parse(body);
    const char *code = jv_text(parsed, "code");
    snprintf(out, out_len, "%s", code == NULL ? "" : code);
    jv_free(parsed);
}

static int is_private(const pm_response *response)
{
    return strcmp(response->cache_control, "private, no-store") == 0;
}

/* ---- Vector actors ------------------------------------------------------------------------------ */

typedef struct {
    char username[81];
    char tenant_id[64];
    char authorization[2200];
} vector_actor;

static vector_actor actors[PM_MAX_ACTORS];
static size_t actor_count = 0U;
static char actor_password_hash[ST_PASSWORD_HASH_MAX_LEN + 1U];

/* The vector's actor as a real account of its tenant with its role, and a real bearer token. */
static const char *actor_authorization(const jv *actor)
{
    if (actor == NULL || actor->kind != JV_OBJECT) {
        return NULL;
    }
    const char *username = jv_str(actor, "username");
    const char *tenant_id = jv_str(actor, "tenantId");
    const char *role = jv_str(actor, "role");
    for (size_t i = 0; i < actor_count; ++i) {
        if (strcmp(actors[i].username, username) == 0) {
            EXPECT(strcmp(actors[i].tenant_id, tenant_id) == 0, "actor %s appears in two tenants", username);
            return actors[i].authorization;
        }
    }
    if (actor_count == PM_MAX_ACTORS) {
        return NULL;
    }
    st_storage_management_user user;
    vector_actor *slot = &actors[actor_count];
    snprintf(slot->username, sizeof(slot->username), "%s", username);
    snprintf(slot->tenant_id, sizeof(slot->tenant_id), "%s", tenant_id);
    if (st_storage_create_management_user(db_path, username, tenant_id, actor_password_hash, role, 1, &user) != 0
        || bearer_for(username, tenant_id, slot->authorization, sizeof(slot->authorization)) != 0) {
        fprintf(stderr, "cannot create actor %s/%s\n", tenant_id, username);
        return NULL;
    }
    ++actor_count;
    return slot->authorization;
}

/* ---- Vector state ------------------------------------------------------------------------------- */

static void format_ms(const jv *value, char *out, size_t out_len)
{
    if (value == NULL || value->kind != JV_STRING) {
        snprintf(out, out_len, "null");
    } else {
        snprintf(out, out_len, "%lld", instant_ms(value->text));
    }
}

static void format_text(const jv *value, char *out, size_t out_len)
{
    snprintf(out, out_len, "%s", value == NULL || value->kind != JV_STRING ? "null" : value->text);
}

/* A checkpoint state as the same sorted row lists the database produces; times as instants. */
static int state_rows(const jv *state, row_list lists[4])
{
    const jv *switches = jv_get(state, "switches");
    for (size_t i = 0; switches != NULL && i < switches->count; ++i) {
        const jv *row = switches->items[i];
        char by[128];
        char updated[32];
        char purged[32];
        char line[512];
        format_text(jv_get(row, "updatedBy"), by, sizeof(by));
        format_ms(jv_get(row, "updatedAt"), updated, sizeof(updated));
        format_ms(jv_get(row, "purgedAt"), purged, sizeof(purged));
        const jv *enabled = jv_get(row, "enabled");
        snprintf(line, sizeof(line), "%s|%d|%s|%s|%s", jv_str(row, "tenantId"),
                 enabled != NULL && enabled->boolean ? 1 : 0, by, updated, purged);
        if (row_list_add(&lists[0], line) != 0) return -1;
    }
    const jv *progress = jv_get(state, "progress");
    for (size_t i = 0; progress != NULL && i < progress->count; ++i) {
        const jv *row = progress->items[i];
        char started[32];
        char signed_in[32];
        char credential[32];
        char online[32];
        char line[512];
        format_ms(jv_get(row, "startedAt"), started, sizeof(started));
        format_ms(jv_get(row, "signedInAt"), signed_in, sizeof(signed_in));
        format_ms(jv_get(row, "credentialCreatedAt"), credential, sizeof(credential));
        format_ms(jv_get(row, "clientOnlineAt"), online, sizeof(online));
        snprintf(line, sizeof(line), "%s|%s|%s|%s|%s|%s", jv_str(row, "tenantId"), jv_str(row, "username"),
                 started, signed_in, credential, online);
        if (row_list_add(&lists[1], line) != 0) return -1;
    }
    const jv *onboarding = jv_get(state, "onboardingDaily");
    for (size_t i = 0; onboarding != NULL && i < onboarding->count; ++i) {
        const jv *row = onboarding->items[i];
        char line[512];
        snprintf(line, sizeof(line), "%s|%s|%s|%s|%lld", jv_str(row, "tenantId"), jv_str(row, "cohortDay"),
                 jv_str(row, "reachedStep"), jv_str(row, "durationBucket"), jv_int(row, "users", -1));
        if (row_list_add(&lists[2], line) != 0) return -1;
    }
    const jv *transfers = jv_get(state, "transferDaily");
    for (size_t i = 0; transfers != NULL && i < transfers->count; ++i) {
        const jv *row = transfers->items[i];
        char line[512];
        snprintf(line, sizeof(line), "%s|%s|%s|%s|%s|%s|%s|%lld", jv_str(row, "tenantId"), jv_str(row, "day"),
                 jv_str(row, "mode"), jv_str(row, "path"), jv_str(row, "sizeBucket"), jv_str(row, "attempt"),
                 jv_str(row, "outcome"), jv_int(row, "count", -1));
        if (row_list_add(&lists[3], line) != 0) return -1;
    }
    for (size_t i = 0; i < 4U; ++i) {
        qsort(lists[i].rows, lists[i].count, sizeof(char *), compare_text);
    }
    return 0;
}

static const char *const state_tables[4] = {
    "product_metrics_switch", "product_metrics_onboarding_progress", "product_metrics_onboarding_daily",
    "product_metrics_transfer_daily"
};
static const char *const state_queries[4] = {
    "SELECT tenant_id, enabled, updated_by, updated_at, purged_at FROM product_metrics_switch",
    "SELECT tenant_id, username, started_at, signed_in_at, credential_created_at, client_online_at "
    "FROM product_metrics_onboarding_progress",
    "SELECT tenant_id, cohort_day, reached_step, duration_bucket, users FROM product_metrics_onboarding_daily",
    "SELECT tenant_id, day, mode, path, size_bucket, attempt, outcome, count FROM product_metrics_transfer_daily"
};

static int compare_state(const char *label, const jv *state)
{
    row_list want[4];
    row_list got[4];
    memset(want, 0, sizeof(want));
    memset(got, 0, sizeof(got));
    int ok = state_rows(state, want) == 0;
    for (size_t t = 0; ok && t < 4U; ++t) {
        ok = table_rows(state_queries[t], &got[t]) == 0;
        int same = ok && got[t].count == want[t].count;
        for (size_t i = 0; same && i < got[t].count; ++i) {
            same = strcmp(got[t].rows[i], want[t].rows[i]) == 0;
        }
        if (!same) {
            fprintf(stderr, "%s: %s differs\n  got:", label, state_tables[t]);
            for (size_t i = 0; i < got[t].count; ++i) fprintf(stderr, "\n    %s", got[t].rows[i]);
            fprintf(stderr, "\n  want:");
            for (size_t i = 0; i < want[t].count; ++i) fprintf(stderr, "\n    %s", want[t].rows[i]);
            fprintf(stderr, "\n");
            ok = 0;
        }
    }
    for (size_t t = 0; t < 4U; ++t) {
        row_list_free(&want[t]);
        row_list_free(&got[t]);
    }
    return ok ? 0 : -1;
}

static int bind_ms(sqlite3_stmt *stmt, int index, const jv *value)
{
    return value == NULL || value->kind != JV_STRING
        ? sqlite3_bind_null(stmt, index)
        : sqlite3_bind_int64(stmt, index, instant_ms(value->text));
}

static int bind_text_or_null(sqlite3_stmt *stmt, int index, const jv *value)
{
    return value == NULL || value->kind != JV_STRING
        ? sqlite3_bind_null(stmt, index)
        : sqlite3_bind_text(stmt, index, value->text, -1, SQLITE_TRANSIENT);
}

/* Writes a scenario's initialState into the four tables. */
static int load_state(const jv *state)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int rc = 0;
    const jv *switches = jv_get(state, "switches");
    for (size_t i = 0; rc == 0 && switches != NULL && i < switches->count; ++i) {
        const jv *row = switches->items[i];
        sqlite3_stmt *stmt = NULL;
        const jv *enabled = jv_get(row, "enabled");
        rc = sqlite3_prepare_v2(db, "INSERT INTO product_metrics_switch VALUES (?, ?, ?, ?, ?)", -1, &stmt, NULL)
            == SQLITE_OK
            && sqlite3_bind_text(stmt, 1, jv_str(row, "tenantId"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_int(stmt, 2, enabled != NULL && enabled->boolean) == SQLITE_OK
            && bind_text_or_null(stmt, 3, jv_get(row, "updatedBy")) == SQLITE_OK
            && bind_ms(stmt, 4, jv_get(row, "updatedAt")) == SQLITE_OK
            && bind_ms(stmt, 5, jv_get(row, "purgedAt")) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    const jv *progress = jv_get(state, "progress");
    for (size_t i = 0; rc == 0 && progress != NULL && i < progress->count; ++i) {
        const jv *row = progress->items[i];
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db, "INSERT INTO product_metrics_onboarding_progress VALUES (?, ?, ?, ?, ?, ?)",
                                -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_bind_text(stmt, 1, jv_str(row, "tenantId"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 2, jv_str(row, "username"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && bind_ms(stmt, 3, jv_get(row, "startedAt")) == SQLITE_OK
            && bind_ms(stmt, 4, jv_get(row, "signedInAt")) == SQLITE_OK
            && bind_ms(stmt, 5, jv_get(row, "credentialCreatedAt")) == SQLITE_OK
            && bind_ms(stmt, 6, jv_get(row, "clientOnlineAt")) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    const jv *onboarding = jv_get(state, "onboardingDaily");
    for (size_t i = 0; rc == 0 && onboarding != NULL && i < onboarding->count; ++i) {
        const jv *row = onboarding->items[i];
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db, "INSERT INTO product_metrics_onboarding_daily VALUES (?, ?, ?, ?, ?)",
                                -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_bind_text(stmt, 1, jv_str(row, "tenantId"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 2, jv_str(row, "cohortDay"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 3, jv_str(row, "reachedStep"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 4, jv_str(row, "durationBucket"), -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 5, jv_int(row, "users", 0)) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
        sqlite3_finalize(stmt);
    }
    const jv *transfers = jv_get(state, "transferDaily");
    for (size_t i = 0; rc == 0 && transfers != NULL && i < transfers->count; ++i) {
        const jv *row = transfers->items[i];
        static const char *const keys[] = {"tenantId", "day", "mode", "path", "sizeBucket", "attempt", "outcome"};
        sqlite3_stmt *stmt = NULL;
        rc = sqlite3_prepare_v2(db, "INSERT INTO product_metrics_transfer_daily VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                -1, &stmt, NULL) == SQLITE_OK ? 0 : -1;
        for (int k = 0; rc == 0 && k < 7; ++k) {
            rc = sqlite3_bind_text(stmt, k + 1, jv_str(row, keys[k]), -1, SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
        }
        if (rc == 0) {
            rc = sqlite3_bind_int64(stmt, 8, jv_int(row, "count", 0)) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE
                ? 0 : -1;
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    return rc;
}

/* ---- Vector replay ------------------------------------------------------------------------------ */

/* Compares a response with an op's expectation: status, the private header, and the body when given. */
static int compare_response(const char *label, const jv *expect, const pm_response *response)
{
    long long status = jv_int(expect, "status", -1);
    int ok = 1;
    if (response->status != status) {
        fprintf(stderr, "%s: status %d, want %lld (%s)\n", label, response->status, status, response->body);
        ok = 0;
    }
    if (!is_private(response)) {
        fprintf(stderr, "%s: Cache-Control \"%s\", want \"private, no-store\"\n", label, response->cache_control);
        ok = 0;
    }
    const jv *want = jv_get(expect, "body");
    if (ok && want != NULL) {
        jv *got = jv_parse(response->body);
        if (!jv_equal(got, want)) {
            fprintf(stderr, "%s: body\n  got  %s\n  want %.*s\n", label, response->body, (int)want->raw_len, want->raw);
            ok = 0;
        }
        jv_free(got);
    }
    return ok ? 0 : -1;
}

static int replay_tables(const jv *vector)
{
    const jv *sizes = jv_get(vector, "sizeBuckets");
    const jv *durations = jv_get(vector, "durationBuckets");
    const jv *rates = jv_get(vector, "rates");
    int before = failures;
    EXPECT(sizes != NULL && sizes->count > 0U && durations != NULL && durations->count > 0U && rates != NULL
               && rates->count > 0U,
           "vector has no bucket or rate cases");
    for (size_t i = 0; sizes != NULL && i < sizes->count; ++i) {
        const jv *item = sizes->items[i];
        const char *want = jv_text(item, "bucket");
        const char *got = st_product_metrics_size_bucket(jv_int(item, "sizeBytes", 0));
        EXPECT((want == NULL && got == NULL) || (want != NULL && got != NULL && strcmp(want, got) == 0),
               "size %lld: got %s want %s", jv_int(item, "sizeBytes", 0), got == NULL ? "null" : got,
               want == NULL ? "null" : want);
    }
    for (size_t i = 0; durations != NULL && i < durations->count; ++i) {
        const jv *item = durations->items[i];
        const char *want = jv_text(item, "bucket");
        const char *got = st_product_metrics_duration_bucket(jv_int(item, "seconds", 0));
        EXPECT((want == NULL && got == NULL) || (want != NULL && got != NULL && strcmp(want, got) == 0),
               "duration %lld: got %s want %s", jv_int(item, "seconds", 0), got == NULL ? "null" : got,
               want == NULL ? "null" : want);
    }
    for (size_t i = 0; rates != NULL && i < rates->count; ++i) {
        const jv *item = rates->items[i];
        const jv *want = jv_get(item, "rateBp");
        long long got = 0;
        int has = st_product_metrics_rate_bp(jv_int(item, "numerator", 0), jv_int(item, "denominator", 0), &got);
        EXPECT(want != NULL && (want->kind == JV_NULL ? !has : (has && (double)got == want->number)),
               "rate %lld/%lld: got %s%lld", jv_int(item, "numerator", 0), jv_int(item, "denominator", 0),
               has ? "" : "null ", got);
    }
    printf("ok   vector tables: %zu sizes, %zu durations, %zu rates\n", sizes == NULL ? 0U : sizes->count,
           durations == NULL ? 0U : durations->count, rates == NULL ? 0U : rates->count);
    return failures == before ? 0 : -1;
}

static int replay_ingest_validation(const jv *vector)
{
    const jv *validation = jv_get(vector, "ingestValidation");
    const jv *context = jv_get(validation, "context");
    const jv *cases = jv_get(validation, "cases");
    if (cases == NULL || cases->count == 0U || fresh_database() != 0) {
        fprintf(stderr, "vector has no validation cases\n");
        return -1;
    }
    actor_count = 0U;
    const jv *actor = jv_get(context, "actor");
    const char *authorization = actor_authorization(actor);
    test_now_ms = instant_ms(jv_text(context, "at"));
    char sql[256];
    snprintf(sql, sizeof(sql), "INSERT INTO product_metrics_switch VALUES ('%s', 1, 'root', %lld, NULL)",
             jv_str(actor, "tenantId"), test_now_ms);
    if (authorization == NULL || sql_exec(sql) != 0) {
        return -1;
    }
    size_t replayed = 0U;
    int bad = 0;
    for (size_t i = 0; i < cases->count; ++i) {
        const jv *item = cases->items[i];
        const char *name = jv_str(item, "name");
        const jv *body = jv_get(item, "bodyText");
        const jv *expect = jv_get(item, "expect");
        char label[160];
        snprintf(label, sizeof(label), "ingestValidation %s", name);
        if (body == NULL || (long long)body->text_len != jv_int(item, "bodyBytes", -1)) {
            fprintf(stderr, "%s: body has %zu bytes, vector says %lld\n", label, body == NULL ? 0U : body->text_len,
                    jv_int(item, "bodyBytes", -1));
            bad = 1;
            continue;
        }
        st_product_metrics_limiter_reset();
        long long before = transfer_total();
        pm_response response;
        if (call("POST", "/api/admin/product-metrics/transfer-outcomes", authorization, body->text, body->text_len,
                 &response) != 0
            || compare_response(label, expect, &response) != 0) {
            bad = 1;
            continue;
        }
        long long accepted = jv_int(expect, "status", 0) == 200 ? jv_int(jv_get(expect, "body"), "accepted", 0) : 0;
        long long after = transfer_total();
        if (after != before + accepted) {
            fprintf(stderr, "%s: counted %lld events, want %lld\n", label, after - before, accepted);
            bad = 1;
            continue;
        }
        ++replayed;
    }
    EXPECT(replayed == cases->count, "replayed %zu of %zu validation cases", replayed, cases->count);
    printf("%s vector ingestValidation: %zu/%zu cases\n", bad ? "FAIL" : "ok  ", replayed, cases->count);
    return bad || replayed != cases->count ? -1 : 0;
}

static void summary_path(const jv *query, char *out, size_t out_len)
{
    size_t used = (size_t)snprintf(out, out_len, "/api/admin/product-metrics/summary");
    for (size_t i = 0; query != NULL && query->kind == JV_OBJECT && i < query->count && used < out_len; ++i) {
        used += (size_t)snprintf(out + used, out_len - used, "%s%s=%s", i == 0 ? "?" : "&", query->keys[i],
                                 query->items[i]->text);
    }
}

static int replay_scenario(const jv *scenario, size_t *replayed)
{
    const char *name = jv_str(scenario, "name");
    const jv *limits = jv_get(scenario, "limits");
    const jv *ops = jv_get(scenario, "ops");
    if (fresh_database() != 0 || ops == NULL) {
        return -1;
    }
    st_product_metrics_set_limits((int)jv_int(limits, "perUserEventsPerMinute", 0),
                                  (int)jv_int(limits, "perTenantEventsPerMinute", 0));
    if (load_state(jv_get(scenario, "initialState")) != 0) {
        fprintf(stderr, "%s: initial state could not be loaded\n", name);
        return -1;
    }
    actor_count = 0U;
    for (size_t i = 0; i < ops->count; ++i) {
        const jv *actor = jv_get(ops->items[i], "actor");
        if (actor != NULL && actor->kind == JV_OBJECT && actor_authorization(actor) == NULL) {
            return -1;
        }
    }
    int bad = 0;
    for (size_t i = 0; i < ops->count; ++i) {
        const jv *op = ops->items[i];
        const char *kind = jv_str(op, "op");
        const char *at = jv_str(op, "at");
        const jv *expect = jv_get(op, "expect");
        const jv *actor = jv_get(op, "actor");
        const char *authorization = actor != NULL && actor->kind == JV_OBJECT ? actor_authorization(actor) : NULL;
        char label[160];
        snprintf(label, sizeof(label), "%s op %zu (%s at %s)", name, i, kind, at);
        test_now_ms = instant_ms(at);
        pm_response response;
        int rc = 0;
        if (strcmp(kind, "milestone") == 0 || strcmp(kind, "userDeleted") == 0) {
            const char *effect = strcmp(kind, "milestone") == 0
                ? st_product_metrics_milestone(db_path, jv_text(op, "tenantId"), jv_text(op, "username"),
                                               jv_text(op, "step"))
                : st_product_metrics_user_deleted(db_path, jv_text(op, "tenantId"), jv_text(op, "username"));
            const char *want = jv_text(expect, "effect");
            if (want == NULL || strcmp(effect, want) != 0) {
                fprintf(stderr, "%s: effect %s, want %s\n", label, effect, want == NULL ? "?" : want);
                rc = -1;
            }
        } else if (strcmp(kind, "sweep") == 0) {
            rc = st_product_metrics_sweep(db_path);
            if (rc != 0) {
                fprintf(stderr, "%s: sweep failed\n", label);
            }
        } else if (strcmp(kind, "checkpoint") == 0) {
            rc = compare_state(label, jv_get(expect, "state"));
        } else if (strcmp(kind, "getSettings") == 0) {
            rc = call("GET", "/api/admin/product-metrics/settings", authorization, NULL, 0U, &response) == 0
                ? compare_response(label, expect, &response) : -1;
        } else if (strcmp(kind, "putSettings") == 0) {
            const jv *body = jv_get(op, "body");
            char *text = body == NULL ? NULL : strndup(body->raw, body->raw_len);
            rc = text != NULL && call("PUT", "/api/admin/product-metrics/settings", authorization, text,
                                      strlen(text), &response) == 0
                ? compare_response(label, expect, &response) : -1;
            free(text);
        } else if (strcmp(kind, "purge") == 0) {
            rc = call("DELETE", "/api/admin/product-metrics/data", authorization, NULL, 0U, &response) == 0
                ? compare_response(label, expect, &response) : -1;
        } else if (strcmp(kind, "ingest") == 0) {
            const jv *body = jv_get(op, "bodyText");
            rc = body != NULL && call("POST", "/api/admin/product-metrics/transfer-outcomes", authorization,
                                      body->text, body->text_len, &response) == 0
                ? compare_response(label, expect, &response) : -1;
        } else if (strcmp(kind, "summary") == 0) {
            char path[256];
            summary_path(jv_get(op, "query"), path, sizeof(path));
            rc = call("GET", path, authorization, NULL, 0U, &response) == 0
                ? compare_response(label, expect, &response) : -1;
        } else {
            fprintf(stderr, "%s: unknown op\n", label);
            rc = -1;
        }
        if (rc != 0) {
            bad = 1;
            continue;
        }
        ++*replayed;
    }
    printf("%s vector scenario %s: %zu ops\n", bad ? "FAIL" : "ok  ", name, ops->count);
    return bad ? -1 : 0;
}

static int replay_scenarios(const jv *vector)
{
    const jv *scenarios = jv_get(vector, "scenarios");
    if (scenarios == NULL || scenarios->count == 0U) {
        fprintf(stderr, "vector has no scenarios\n");
        return -1;
    }
    size_t want = 0U;
    size_t replayed = 0U;
    int bad = 0;
    for (size_t i = 0; i < scenarios->count; ++i) {
        const jv *ops = jv_get(scenarios->items[i], "ops");
        want += ops == NULL ? 0U : ops->count;
        bad |= replay_scenario(scenarios->items[i], &replayed) != 0;
    }
    EXPECT(replayed == want, "replayed %zu of %zu scenario ops", replayed, want);
    printf("%s vector scenarios: %zu scenarios, %zu/%zu ops\n", bad || replayed != want ? "FAIL" : "ok  ",
           scenarios->count, replayed, want);
    return bad || replayed != want ? -1 : 0;
}

/* ---- Beyond the vector: closed schema, flag, storage failures, private refusals ---------------- */

#define SAMPLE_EVENT "{\"mode\":\"device\",\"path\":\"direct\",\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"success\"}"

static void expect_answer(const char *label, const pm_response *response, int status, const char *code)
{
    char got_code[64];
    body_code(response->body, got_code, sizeof(got_code));
    EXPECT(response->status == status && is_private(response) && strcmp(got_code, code == NULL ? "" : code) == 0,
           "%s: got %d %s (Cache-Control %s), want %d %s", label, response->status, response->body,
           response->cache_control, status, code == NULL ? "" : code);
}

static void expect_ingest(const char *label, const char *authorization, const char *body, size_t body_len,
                          int status, const char *code, long long accepted)
{
    st_product_metrics_limiter_reset();
    long long before = transfer_total();
    pm_response response;
    if (call("POST", "/api/admin/product-metrics/transfer-outcomes", authorization, body, body_len, &response) != 0) {
        EXPECT(0, "%s: no response", label);
        return;
    }
    expect_answer(label, &response, status, code);
    long long counted = transfer_total() - before;
    EXPECT(counted == accepted, "%s: counted %lld events, want %lld", label, counted, accepted);
    if (status == 200 && accepted > 0) {
        char want[64];
        snprintf(want, sizeof(want), "\"accepted\":%lld", accepted);
        EXPECT(strstr(response.body, want) != NULL, "%s: body %s lacks %s", label, response.body, want);
    }
}

static void expect_put(const char *label, const char *authorization, const char *body, int status, const char *code)
{
    pm_response response;
    if (call_text("PUT", "/api/admin/product-metrics/settings", authorization, body, &response) != 0) {
        EXPECT(0, "%s: no response", label);
        return;
    }
    expect_answer(label, &response, status, code);
}

static void expect_summary(const char *label, const char *authorization, const char *query, int status, const char *code)
{
    char path[256];
    snprintf(path, sizeof(path), "/api/admin/product-metrics/summary%s", query);
    pm_response response;
    if (call_text("GET", path, authorization, NULL, &response) != 0) {
        EXPECT(0, "%s: no response", label);
        return;
    }
    expect_answer(label, &response, status, code);
}

static int closed_schema_checks(void)
{
    int before = failures;
    if (fresh_database() != 0) {
        return -1;
    }
    actor_count = 0U;
    test_now_ms = instant_ms("2026-09-10T00:00:00Z");
    char root_auth[2200];
    char user_auth[2200];
    st_storage_management_user user;
    if (st_storage_create_management_user(db_path, "cs-root", "t1", actor_password_hash, "ADMIN", 1, &user) != 0
        || st_storage_create_management_user(db_path, "cs-user", "t1", actor_password_hash, "USER", 1, &user) != 0
        || bearer_for("cs-root", "t1", root_auth, sizeof(root_auth)) != 0
        || bearer_for("cs-user", "t1", user_auth, sizeof(user_auth)) != 0) {
        return -1;
    }
    expect_put("enable", root_auth, "{\"enabled\":true,\"disclosureVersion\":1}", 200, NULL);

    /* Ingest: duplicate keys, number spellings of the version, trailing content, encodings. */
    static const struct {
        const char *label;
        const char *body;
        int status;
        long long accepted;
    } ingest_cases[] = {
        {"duplicate schemaVersion", "{\"schemaVersion\":1,\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"duplicate events", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "],\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"duplicate event field", "{\"schemaVersion\":1,\"events\":[{\"mode\":\"device\",\"mode\":\"device\","
                                  "\"path\":\"direct\",\"sizeBucket\":\"lt1m\",\"attempt\":\"first\","
                                  "\"outcome\":\"success\"}]}", 400, 0},
        {"schemaVersion 1.0", "{\"schemaVersion\":1.0,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"schemaVersion 1e0", "{\"schemaVersion\":1e0,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"schemaVersion 01", "{\"schemaVersion\":01,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"schemaVersion -1", "{\"schemaVersion\":-1,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"schemaVersion null", "{\"schemaVersion\":null,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"trailing garbage", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}x", 400, 0},
        {"trailing second document", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}{}", 400, 0},
        {"trailing comma", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT ",]}", 400, 0},
        {"unterminated", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]", 400, 0},
        {"empty body", "", 400, 0},
        {"byte order mark", "\xef\xbb\xbf{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}", 400, 0},
        {"invalid UTF-8 in a value", "{\"schemaVersion\":1,\"events\":[{\"mode\":\"device\",\"path\":\"direct\","
                                     "\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"succ\xff\"}]}", 400, 0},
        {"overlong UTF-8 slash", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}\xc0\xaf", 400, 0},
        {"raw control character in a string", "{\"schemaVersion\":1,\"events\":[{\"mode\":\"dev\tice\","
                                               "\"path\":\"direct\",\"sizeBucket\":\"lt1m\",\"attempt\":\"first\","
                                               "\"outcome\":\"success\"}]}", 400, 0},
        {"escaped key spelling", "{\"schema\\u0056ersion\":1,\"events\":[{\"mode\":\"dev\\u0069ce\",\"path\":\"direct\","
                                 "\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"success\"}]}", 200, 1},
        {"trailing whitespace", "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "," SAMPLE_EVENT "]} \r\n\t", 200, 2}
    };
    for (size_t i = 0; i < sizeof(ingest_cases) / sizeof(ingest_cases[0]); ++i) {
        expect_ingest(ingest_cases[i].label, user_auth, ingest_cases[i].body, strlen(ingest_cases[i].body),
                      ingest_cases[i].status, ingest_cases[i].status == 200 ? NULL : ST_PRODUCT_METRICS_CODE_INVALID,
                      ingest_cases[i].accepted);
    }
    static const char nul_body[] = "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}\0";
    expect_ingest("NUL byte after the document", user_auth, nul_body, sizeof(nul_body) - 1U, 400,
                  ST_PRODUCT_METRICS_CODE_INVALID, 0);
    /* The size check precedes parsing: 4097 bytes of an otherwise valid batch are too large. */
    char padded[4200];
    int prefix = snprintf(padded, sizeof(padded), "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}");
    memset(padded + prefix, ' ', sizeof(padded) - (size_t)prefix);
    expect_ingest("4096 bytes", user_auth, padded, 4096U, 200, NULL, 1);
    expect_ingest("4097 bytes", user_auth, padded, 4097U, 413, ST_PRODUCT_METRICS_CODE_TOO_LARGE, 0);

    /* PUT settings: the closed body. */
    expect_put("put duplicate enabled", root_auth, "{\"enabled\":true,\"enabled\":true,\"disclosureVersion\":1}", 400,
               ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put disclosureVersion 1.0", root_auth, "{\"enabled\":true,\"disclosureVersion\":1.0}", 400,
               ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put disclosureVersion string", root_auth, "{\"enabled\":true,\"disclosureVersion\":\"1\"}", 400,
               ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put disclosureVersion boolean", root_auth, "{\"enabled\":true,\"disclosureVersion\":true}", 400,
               ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put enabled null", root_auth, "{\"enabled\":null}", 400, ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put missing enabled", root_auth, "{\"disclosureVersion\":1}", 400, ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put trailing content", root_auth, "{\"enabled\":true,\"disclosureVersion\":1} 1", 400,
               ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put empty body", root_auth, "", 400, ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put tenant in body", root_auth, "{\"enabled\":true,\"disclosureVersion\":1,\"tenantId\":\"t2\"}", 400,
               ST_PRODUCT_METRICS_CODE_INVALID);
    expect_put("put large integer version", root_auth, "{\"enabled\":true,\"disclosureVersion\":100000000000000000000}",
               400, ST_PRODUCT_METRICS_CODE_DISCLOSURE_REQUIRED);
    expect_put("put USER refused before the body", user_auth, "not json", 403, NULL);

    /* Summary ranges: malformed days answer like out-of-range ones. */
    expect_summary("summary impossible date", root_auth, "?from=2026-02-30&to=2026-09-10", 400,
                   ST_PRODUCT_METRICS_CODE_RANGE);
    expect_summary("summary short date", root_auth, "?from=2026-9-1", 400, ST_PRODUCT_METRICS_CODE_RANGE);
    expect_summary("summary empty to", root_auth, "?to=", 400, ST_PRODUCT_METRICS_CODE_RANGE);
    expect_summary("summary bare to", root_auth, "?to", 400, ST_PRODUCT_METRICS_CODE_RANGE);
    expect_summary("summary NUL in date", root_auth, "?to=2026-09-10%00", 400, ST_PRODUCT_METRICS_CODE_RANGE);
    expect_summary("summary escaped date", root_auth, "?to=2026%2D09%2D10", 200, NULL);
    expect_summary("summary explicit range", root_auth, "?from=2026-08-01&to=2026-09-10", 200, NULL);
    expect_summary("summary first value wins", root_auth, "?to=2026-09-10&to=garbage", 200, NULL);

    /* Unknown endpoints under the prefix and the shared layer's refusals are private too. */
    pm_response response;
    if (call_text("GET", "/api/admin/product-metrics/unknown", root_auth, NULL, &response) == 0) {
        EXPECT(response.status == 404 && is_private(&response), "unknown path: %d %s", response.status,
               response.cache_control);
    }
    if (call_text("POST", "/api/admin/product-metrics/settings", root_auth, "{}", &response) == 0) {
        EXPECT(response.status == 404 && is_private(&response), "wrong method: %d %s", response.status,
               response.cache_control);
    }
    if (call_text("GET", "/api/admin/product-metrics/settings", "Bearer not-a-token", NULL, &response) == 0) {
        EXPECT(response.status == 401 && is_private(&response), "invalid bearer: %d %s", response.status,
               response.cache_control);
    }
    if (call_text("GET", "/api/admin/product-metrics/settings", NULL, NULL, &response) == 0) {
        EXPECT(response.status == 401 && is_private(&response), "missing bearer: %d %s", response.status,
               response.cache_control);
    }
    /* A valid token of an account that is gone: the shared layer's 403. */
    char gone_auth[2200];
    if (bearer_for("cs-gone", "t1", gone_auth, sizeof(gone_auth)) == 0
        && call_text("GET", "/api/admin/product-metrics/settings", gone_auth, NULL, &response) == 0) {
        EXPECT(response.status == 403 && is_private(&response), "gone account: %d %s", response.status,
               response.cache_control);
    }
    if (call_text("GET", "/api/admin/product-metrics/summary", user_auth, NULL, &response) == 0) {
        EXPECT(response.status == 403 && is_private(&response), "USER summary: %d %s", response.status,
               response.cache_control);
    }
    if (call_text("DELETE", "/api/admin/product-metrics/data", user_auth, NULL, &response) == 0) {
        EXPECT(response.status == 403 && is_private(&response), "USER purge: %d %s", response.status,
               response.cache_control);
    }
    if (call_text("GET", "/api/admin/product-metrics/settings", user_auth, NULL, &response) == 0) {
        EXPECT(response.status == 200 && strstr(response.body, "updatedBy") == NULL
                   && strstr(response.body, "\"enabled\":true") != NULL,
               "USER settings must hide updatedBy: %s", response.body);
    }

    /* The deployment flag: settings show off, enabling is refused, nothing is collected. */
    setenv("SPECUS_PRODUCT_METRICS_ALLOWED", "false", 1);
    if (call_text("GET", "/api/admin/product-metrics/settings", root_auth, NULL, &response) == 0) {
        EXPECT(response.status == 200 && strstr(response.body, "\"enabled\":false") != NULL,
               "not allowed: settings %s", response.body);
    }
    expect_put("not allowed: enable", root_auth, "{\"enabled\":true,\"disclosureVersion\":1}", 409,
               ST_PRODUCT_METRICS_CODE_NOT_ALLOWED);
    expect_ingest("not allowed: ingest", user_auth, padded, (size_t)prefix, 200, NULL, 0);
    if (call_text("POST", "/api/admin/product-metrics/transfer-outcomes", user_auth,
                  "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}", &response) == 0) {
        EXPECT(response.status == 200 && strstr(response.body, "\"collecting\":false") != NULL
                   && strstr(response.body, "\"accepted\":0") != NULL,
               "not allowed: ingest answer %s", response.body);
    }
    EXPECT(strcmp(st_product_metrics_milestone(db_path, "t1", "cs-user", ST_PRODUCT_METRICS_STEP_ACCOUNT_CREATED),
                  "ignored") == 0,
           "not allowed: milestone must be ignored");
    expect_put("not allowed: disable still works", root_auth, "{\"enabled\":false}", 200, NULL);
    unsetenv("SPECUS_PRODUCT_METRICS_ALLOWED");

    /* Storage failures answer 503 UNAVAILABLE, after the checks that need no storage. */
    setenv("SPECUS_AUTH_USERNAME", PM_TEST_BUILTIN_USER, 1);
    setenv("SPECUS_AUTH_PASSWORD", PM_TEST_BUILTIN_PASSWORD, 1);
    char builtin_auth[2200];
    if (bearer_for(PM_TEST_BUILTIN_USER, "default", builtin_auth, sizeof(builtin_auth)) == 0) {
        setenv("SPECUS_DATABASE_PATH", "/proc/specus-product-metrics-unwritable/db", 1);
        if (call_text("GET", "/api/admin/product-metrics/settings", builtin_auth, NULL, &response) == 0) {
            expect_answer("storage down: settings", &response, 503, ST_PRODUCT_METRICS_CODE_UNAVAILABLE);
        }
        unsetenv("SPECUS_DATABASE_PATH");
        if (call("POST", "/api/admin/product-metrics/transfer-outcomes", builtin_auth, padded, 4097U, &response) == 0) {
            expect_answer("storage down: oversize first", &response, 413, ST_PRODUCT_METRICS_CODE_TOO_LARGE);
        }
        if (call_text("POST", "/api/admin/product-metrics/transfer-outcomes", builtin_auth, "[]", &response) == 0) {
            expect_answer("storage down: schema first", &response, 400, ST_PRODUCT_METRICS_CODE_INVALID);
        }
        if (call_text("POST", "/api/admin/product-metrics/transfer-outcomes", builtin_auth,
                      "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}", &response) == 0) {
            expect_answer("storage down: ingest", &response, 503, ST_PRODUCT_METRICS_CODE_UNAVAILABLE);
        }
        expect_put("storage down: put", builtin_auth, "{\"enabled\":true,\"disclosureVersion\":1}", 503,
                   ST_PRODUCT_METRICS_CODE_UNAVAILABLE);
        expect_summary("storage down: summary", builtin_auth, "", 503, ST_PRODUCT_METRICS_CODE_UNAVAILABLE);
        setenv("SPECUS_DATABASE_PATH", db_path, 1);
    }
    unsetenv("SPECUS_AUTH_USERNAME");
    unsetenv("SPECUS_AUTH_PASSWORD");
    printf("%s closed schema, deployment flag, storage failures and private refusals\n",
           failures == before ? "ok  " : "FAIL");
    return failures == before ? 0 : -1;
}

/* ---- The sweep decides on the switch when it deletes (section 9) ------------------------------- */

/*
 * Runs between the sweep's read of the switches and its deletes: the tenant is switched back on,
 * then a transfer, a started account and a completed one are collected.
 */
static void switch_back_on_mid_sweep(void *context)
{
    const char *root_auth = (const char *)context;
    expect_put("mid-sweep: enable", root_auth, "{\"enabled\":true,\"disclosureVersion\":1}", 200, NULL);
    static const char batch[] = "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}";
    expect_ingest("mid-sweep: ingest", root_auth, batch, sizeof(batch) - 1U, 200, NULL, 1);
    static const struct {
        const char *username;
        const char *step;
        const char *effect;
    } milestones[] = {
        {"sw-bob", ST_PRODUCT_METRICS_STEP_ACCOUNT_CREATED, "started"},
        {"sw-carol", ST_PRODUCT_METRICS_STEP_ACCOUNT_CREATED, "started"},
        {"sw-carol", ST_PRODUCT_METRICS_STEP_SERVICE_PUBLISHED, "completed"}
    };
    for (size_t i = 0; i < sizeof(milestones) / sizeof(milestones[0]); ++i) {
        const char *effect = st_product_metrics_milestone(db_path, "t1", milestones[i].username, milestones[i].step);
        EXPECT(strcmp(effect, milestones[i].effect) == 0, "mid-sweep: %s %s: %s", milestones[i].username,
               milestones[i].step, effect);
    }
}

/*
 * Steps 1 and 4 check the switch again in the statement that deletes: a tenant that is off and
 * purged when the sweep reads the switches, but switched back on before the deletes, keeps the
 * progress and counts it collected since.
 */
static int sweep_rechecks_the_switch(void)
{
    int before = failures;
    if (fresh_database() != 0) {
        return -1;
    }
    actor_count = 0U;
    test_now_ms = instant_ms("2026-09-01T08:00:00Z");
    char root_auth[2200];
    st_storage_management_user user;
    if (st_storage_create_management_user(db_path, "sw-root", "t1", actor_password_hash, "ADMIN", 1, &user) != 0
        || bearer_for("sw-root", "t1", root_auth, sizeof(root_auth)) != 0) {
        return -1;
    }
    expect_put("enable", root_auth, "{\"enabled\":true,\"disclosureVersion\":1}", 200, NULL);
    expect_put("disable", root_auth, "{\"enabled\":false}", 200, NULL);
    pm_response response;
    if (call_text("DELETE", "/api/admin/product-metrics/data", root_auth, NULL, &response) == 0) {
        expect_answer("purge", &response, 200, NULL);
    }
    EXPECT(sql_scalar("SELECT COUNT(*) FROM product_metrics_switch WHERE enabled = 0 AND purged_at IS NOT NULL") == 1,
           "the tenant must be off and purged before the sweep");

    st_product_metrics_set_sweep_hook_for_testing(switch_back_on_mid_sweep, root_auth);
    int swept = st_product_metrics_sweep(db_path);
    st_product_metrics_set_sweep_hook_for_testing(NULL, NULL);
    EXPECT(swept == 0, "sweep failed");
    EXPECT(sql_scalar("SELECT COUNT(*) FROM product_metrics_onboarding_progress WHERE username = 'sw-bob'") == 1
               && sql_scalar("SELECT COUNT(*) FROM product_metrics_onboarding_progress") == 1,
           "the started account must keep its progress row");
    EXPECT(sql_scalar("SELECT COALESCE(SUM(users), 0) FROM product_metrics_onboarding_daily") == 1,
           "the completed account must stay counted");
    EXPECT(transfer_total() == 1, "the transfer must stay counted, got %lld", transfer_total());

    /* When the deployment does not allow metrics no tenant collects: step 1 drops the row anyway. */
    setenv("SPECUS_PRODUCT_METRICS_ALLOWED", "false", 1);
    EXPECT(st_product_metrics_sweep(db_path) == 0, "sweep failed while not allowed");
    unsetenv("SPECUS_PRODUCT_METRICS_ALLOWED");
    EXPECT(sql_scalar("SELECT COUNT(*) FROM product_metrics_onboarding_progress") == 0,
           "a disallowed deployment keeps no progress rows");
    printf("%s sweep re-checks the switch when it deletes\n", failures == before ? "ok  " : "FAIL");
    return failures == before ? 0 : -1;
}

/* ---- Write paths fire the onboarding hooks ------------------------------------------------------ */

static long long progress_column(const char *username, const char *column)
{
    char sql[256];
    snprintf(sql, sizeof(sql),
             "SELECT %s FROM product_metrics_onboarding_progress WHERE tenant_id = 'default' AND username = '%s'",
             column, username);
    return sql_scalar(sql);
}

static int create_user(const char *admin_auth, const char *username)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s-password-2026\",\"role\":\"USER\"}",
             username, username);
    pm_response response;
    return call_text("POST", "/api/admin/users", admin_auth, body, &response) == 0 && response.status == 201 ? 0 : -1;
}

/* Creates a client owned by the caller and returns its id, or -1. */
static long long create_client(const char *authorization, const char *client_name)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"clientName\":\"%s\"}", client_name);
    pm_response response;
    long long id = -1;
    if (call_text("POST", "/api/admin/clients", authorization, body, &response) != 0 || response.status != 201
        || st_json_get_i64(response.body, "id", &id) != 0) {
        fprintf(stderr, "client create failed: %d %s\n", response.status, response.body);
        return -1;
    }
    return id;
}

typedef struct {
    char code[16];
    int emails;
} registration_mailbox;

static int fake_registration_email(void *ctx, const char *email, const char *username, const char *code,
                                   long long ttl_seconds)
{
    (void)email;
    (void)username;
    (void)ttl_seconds;
    registration_mailbox *mailbox = (registration_mailbox *)ctx;
    snprintf(mailbox->code, sizeof(mailbox->code), "%s", code);
    ++mailbox->emails;
    return 0;
}

static int fake_registration_turnstile(void *ctx, const char *response_token, const char *expected_action)
{
    (void)ctx;
    return response_token != NULL && expected_action != NULL && strcmp(response_token, "turnstile-ok") == 0 ? 0 : -1;
}

static const char *const registration_env[][2] = {
    {"SPECUS_AUTH_REGISTRATION_ENABLED", "true"},
    {"SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED", "true"},
    {"SPECUS_AUTH_EMAIL_FROM_ADDRESS", "noreply@example.com"},
    {"SPECUS_AUTH_SMTP_HOST", "smtp.example.com"},
    {"SPECUS_AUTH_TURNSTILE_ENABLED", "true"},
    {"SPECUS_AUTH_TURNSTILE_SITE_KEY", "site-key"},
    {"SPECUS_AUTH_TURNSTILE_SECRET_KEY", "secret-key"},
    {"SPECUS_AUTH_TURNSTILE_VERIFY_URL", "https://verify.example.com"},
    {"SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", "specus.example.com"}
};

static int wiring_checks(void)
{
    int before = failures;
    if (fresh_database() != 0) {
        return -1;
    }
    setenv("SPECUS_AUTH_USERNAME", PM_TEST_BUILTIN_USER, 1);
    setenv("SPECUS_AUTH_PASSWORD", PM_TEST_BUILTIN_PASSWORD, 1);
    char admin_auth[2200];
    if (bearer_for(PM_TEST_BUILTIN_USER, "default", admin_auth, sizeof(admin_auth)) != 0) {
        return -1;
    }
    const long long t0 = instant_ms("2026-09-10T08:00:00Z");
    test_now_ms = t0;
    pm_response response;

    /* Before opt-in nothing enters a cohort, and the built-in admin never does. */
    EXPECT(create_user(admin_auth, "wire-early") == 0, "early user create failed");
    EXPECT(progress_column("wire-early", "started_at") == -1, "an account created before opt-in got a row");
    expect_put("wiring enable", admin_auth, "{\"enabled\":true,\"disclosureVersion\":1}", 200, NULL);

    /* account_created: an admin creates a user. */
    EXPECT(create_user(admin_auth, "wire") == 0, "user create failed");
    EXPECT(progress_column("wire", "started_at") == t0, "account_created not recorded: %lld",
           progress_column("wire", "started_at"));

    /* signed_in: password login of a database user (the built-in admin's login adds nothing). */
    test_now_ms = t0 + 60000LL;
    EXPECT(call_text("POST", "/auth/login", NULL,
                     "{\"username\":\"" PM_TEST_BUILTIN_USER "\",\"password\":\"" PM_TEST_BUILTIN_PASSWORD "\"}",
                     &response) == 0 && response.status == 200,
           "built-in login failed: %d", response.status);
    EXPECT(call_text("POST", "/auth/login", NULL, "{\"username\":\"wire\",\"password\":\"wire-password-2026\"}",
                     &response) == 0 && response.status == 200,
           "user login failed: %d %s", response.status, response.body);
    EXPECT(progress_column("wire", "signed_in_at") == t0 + 60000LL, "signed_in not recorded");
    EXPECT(sql_scalar("SELECT COUNT(*) FROM product_metrics_onboarding_progress") == 1,
           "the built-in admin or the early account entered the cohort");
    /* A failed login records nothing. */
    test_now_ms = t0 + 61000LL;
    EXPECT(call_text("POST", "/auth/login", NULL, "{\"username\":\"wire\",\"password\":\"wrong\"}", &response) == 0
               && response.status == 401,
           "wrong password accepted");
    EXPECT(progress_column("wire", "signed_in_at") == t0 + 60000LL, "a failed login changed signed_in_at");

    /* credential_created: the owner creates an access credential. */
    char wire_auth[2200];
    if (bearer_for("wire", "default", wire_auth, sizeof(wire_auth)) != 0) {
        return -1;
    }
    test_now_ms = t0 + 120000LL;
    EXPECT(call_text("POST", "/api/admin/client-credentials", wire_auth, "{}", &response) == 0 && response.status == 201,
           "credential create failed: %d %s", response.status, response.body);
    EXPECT(progress_column("wire", "credential_created_at") == t0 + 120000LL, "credential_created not recorded");

    /* client_online happens on the control connection (main.c); the e2e scenario drives it for real. */
    test_now_ms = t0 + 180000LL;
    EXPECT(strcmp(st_product_metrics_milestone(db_path, "default", "wire", ST_PRODUCT_METRICS_STEP_CLIENT_ONLINE),
                  "recorded") == 0,
           "client_online hook");

    /* service_published: an HTTP route for a client the user owns closes the row as completed. */
    long long wire_client = create_client(wire_auth, "pm-wire-client");
    test_now_ms = t0 + 240000LL;
    EXPECT(wire_client > 0, "client create failed");
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", wire_client);
    EXPECT(call_text("POST", path, wire_auth, "{\"route\":\"pm-wire\",\"targetBaseUrl\":\"http://127.0.0.1:9\"}",
                     &response) == 0 && response.status == 201,
           "route create failed: %d %s", response.status, response.body);
    EXPECT(progress_column("wire", "started_at") == -1, "service_published did not close the row");
    EXPECT(sql_scalar("SELECT users FROM product_metrics_onboarding_daily WHERE tenant_id = 'default' "
                      "AND cohort_day = '2026-09-10' AND reached_step = 'service_published' "
                      "AND duration_bucket = 'lt10m'") == 1,
           "completion not counted");

    /* service_published by a TCP mapping, for a second account. */
    test_now_ms = t0 + 300000LL;
    EXPECT(create_user(admin_auth, "wire-tcp") == 0, "second user create failed");
    char tcp_auth[2200];
    if (bearer_for("wire-tcp", "default", tcp_auth, sizeof(tcp_auth)) != 0) {
        return -1;
    }
    long long tcp_client = create_client(tcp_auth, "pm-wire-tcp-client");
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/specus-mappings", tcp_client);
    test_now_ms = t0 + 300000LL + 3600000LL;
    EXPECT(call_text("POST", path, tcp_auth, "{\"listenPort\":28080,\"targetAddress\":\"127.0.0.1\",\"targetPort\":9}",
                     &response) == 0 && response.status == 201,
           "mapping create failed: %d %s", response.status, response.body);
    EXPECT(progress_column("wire-tcp", "started_at") == -1, "a TCP mapping did not close the row");
    EXPECT(sql_scalar("SELECT users FROM product_metrics_onboarding_daily WHERE tenant_id = 'default' "
                      "AND reached_step = 'service_published' AND duration_bucket = '30m-2h'") == 1,
           "mapping completion not counted in its bucket");

    /* Deleting a user drops the progress row without counting it. */
    EXPECT(create_user(admin_auth, "wire-gone") == 0, "third user create failed");
    EXPECT(progress_column("wire-gone", "started_at") > 0, "third user has no row");
    long long counts_before = sql_scalar("SELECT COALESCE(SUM(users), 0) FROM product_metrics_onboarding_daily");
    EXPECT(call_text("DELETE", "/api/admin/users/WIRE-GONE", admin_auth, NULL, &response) == 0
               && response.status == 204,
           "user delete failed: %d %s", response.status, response.body);
    EXPECT(progress_column("wire-gone", "started_at") == -1, "user deletion left the progress row");
    EXPECT(sql_scalar("SELECT COALESCE(SUM(users), 0) FROM product_metrics_onboarding_daily") == counts_before,
           "user deletion was counted");

    /* account_created and signed_in by registration verification. */
    registration_mailbox mailbox;
    memset(&mailbox, 0, sizeof(mailbox));
    for (size_t i = 0; i < sizeof(registration_env) / sizeof(registration_env[0]); ++i) {
        setenv(registration_env[i][0], registration_env[i][1], 1);
    }
    st_registration_set_handlers(fake_registration_turnstile, fake_registration_email, &mailbox);
    test_now_ms = t0 + 400000LL;
    EXPECT(call_text("POST", "/auth/register", NULL,
                     "{\"username\":\"wire-reg\",\"email\":\"wire-reg@example.com\",\"password\":\"wire-reg-password-1\","
                     "\"turnstileToken\":\"turnstile-ok\"}",
                     &response) == 0 && response.status == 202 && mailbox.emails == 1,
           "registration request failed: %d %s", response.status, response.body);
    jv *challenge = jv_parse(response.body);
    char verify_body[256];
    snprintf(verify_body, sizeof(verify_body), "{\"registrationId\":\"%s\",\"code\":\"%s\"}",
             jv_text(challenge, "registrationId") == NULL ? "" : jv_text(challenge, "registrationId"), mailbox.code);
    jv_free(challenge);
    test_now_ms = t0 + 460000LL;
    EXPECT(call_text("POST", "/auth/register/verify", NULL, verify_body, &response) == 0 && response.status == 200,
           "registration verify failed: %d %s", response.status, response.body);
    EXPECT(progress_column("wire-reg", "started_at") == t0 + 460000LL
               && progress_column("wire-reg", "signed_in_at") == t0 + 460000LL,
           "registration did not record account_created and signed_in");
    st_registration_set_handlers(NULL, NULL, NULL);
    for (size_t i = 0; i < sizeof(registration_env) / sizeof(registration_env[0]); ++i) {
        unsetenv(registration_env[i][0]);
    }

    /* Switching off drops every progress row of the tenant; the daily counts stay. */
    EXPECT(create_user(admin_auth, "wire-pending") == 0, "fourth user create failed");
    long long daily_before = sql_scalar("SELECT COALESCE(SUM(users), 0) FROM product_metrics_onboarding_daily");
    expect_put("wiring disable", admin_auth, "{\"enabled\":false}", 200, NULL);
    EXPECT(sql_scalar("SELECT COUNT(*) FROM product_metrics_onboarding_progress WHERE tenant_id = 'default'") == 0,
           "switching off left progress rows");
    EXPECT(sql_scalar("SELECT COALESCE(SUM(users), 0) FROM product_metrics_onboarding_daily") == daily_before,
           "switching off changed the daily counts");
    /* While off, write paths record nothing. */
    EXPECT(create_user(admin_auth, "wire-late") == 0, "fifth user create failed");
    EXPECT(progress_column("wire-late", "started_at") == -1, "an account created while off got a row");

    unsetenv("SPECUS_AUTH_USERNAME");
    unsetenv("SPECUS_AUTH_PASSWORD");
    printf("%s write paths fire the onboarding hooks\n", failures == before ? "ok  " : "FAIL");
    return failures == before ? 0 : -1;
}

/* ---- A real specus-server-c process ----------------------------------------------------------- */

typedef struct {
    int status;
    char cache_control[64];
    char body[4096];
} raw_response;

/* One HTTP/1.1 exchange with Connection: close over a real socket, reading until the server closes. */
static int raw_exchange(int port, const char *method, const char *path, const char *bearer, const char *body,
                        size_t body_len, raw_response *out)
{
    memset(out, 0, sizeof(*out));
    int fd = connect_local(port);
    if (fd < 0) {
        return -1;
    }
    char head[4096];
    char authorization[2300] = "";
    if (bearer != NULL) {
        snprintf(authorization, sizeof(authorization), "Authorization: Bearer %s\r\n", bearer);
    }
    int head_len = snprintf(head, sizeof(head),
                            "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
                            "%sContent-Length: %zu\r\nConnection: close\r\n\r\n",
                            method, path, port, authorization, body_len);
    if (head_len < 0 || (size_t)head_len >= sizeof(head)
        || send_all(fd, (const uint8_t *)head, (size_t)head_len) != 0
        || (body_len > 0U && send_all(fd, (const uint8_t *)body, body_len) != 0)) {
        close(fd);
        return -1;
    }
    char response[8192];
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        if (used + 1U >= sizeof(response)) {
            break;
        }
        int rc = recv_exact(fd, (uint8_t *)response + used, 1U, deadline);
        if (rc != 1) {
            break;
        }
        ++used;
    }
    close(fd);
    response[used] = '\0';
    if (sscanf(response, "HTTP/1.1 %d", &out->status) != 1) {
        return -1;
    }
    header_value(response, "Cache-Control", out->cache_control, sizeof(out->cache_control));
    const char *separator = strstr(response, "\r\n\r\n");
    snprintf(out->body, sizeof(out->body), "%s", separator == NULL ? "" : separator + 4);
    return 0;
}

static int e2e_scenario(test_server *server)
{
    char admin_token[2048];
    CHECK(st_security_issue_local_token(ADMIN_USERNAME, "default", "ADMIN", ADMIN_JWT_SECRET, 3600, admin_token,
                                        sizeof(admin_token)) == 0, "admin token");
    raw_response raw;
    const char *enable = "{\"enabled\":true,\"disclosureVersion\":1}";
    CHECK(raw_exchange(server->admin_port, "PUT", "/api/admin/product-metrics/settings", admin_token, enable,
                       strlen(enable), &raw) == 0
          && raw.status == 200 && strcmp(raw.cache_control, "private, no-store") == 0
          && strstr(raw.body, "\"enabled\":true") != NULL,
          "enable over HTTP: %d %s %s", raw.status, raw.cache_control, raw.body);

    int status = 0;
    char *response = NULL;
    CHECK(http_request(server->admin_port, "POST", "/api/admin/users",
                       "{\"username\":\"pm-e2e\",\"password\":\"pm-e2e-password-2026\",\"role\":\"USER\"}",
                       admin_token, &status, &response) == 0 && status == 201,
          "user create: %d %s", status, response == NULL ? "" : response);
    free(response);
    response = NULL;
    CHECK(http_request(server->admin_port, "POST", "/auth/login",
                       "{\"username\":\"pm-e2e\",\"password\":\"pm-e2e-password-2026\"}", NULL, &status,
                       &response) == 0 && status == 200,
          "user login: %d", status);
    char *user_token = st_json_get_top_level_string(response, "accessToken");
    free(response);
    response = NULL;
    CHECK(user_token != NULL, "login token");
    int ok = http_request(server->admin_port, "POST", "/api/admin/client-credentials",
                          "{\"apiKey\":\"pm-e2e-key-0001\",\"secret\":\"pm-e2e-secret-0001\"}", user_token, &status,
                          &response) == 0 && status == 201;
    free(response);
    response = NULL;
    if (!ok) {
        free(user_token);
        CHECK(0, "credential create: %d", status);
    }

    runtime_session runtime;
    int control_fd = -1;
    char reason[256];
    ok = http_client_login(server, "pm-e2e-key-0001", "pm-e2e-secret-0001", "pm-e2e-machine", "pm-e2e-os-user",
                           &runtime) == 0
        && channel_login(server->control_port, &runtime, "control", &control_fd, reason, sizeof(reason)) == 1;
    if (!ok) {
        free(user_token);
        close_fd(&control_fd);
        CHECK(0, "client login: %s", reason);
    }
    /* main.c records client_online right after the login response; poll for it. */
    char value[64] = "";
    long long deadline = monotonic_ms() + 5000;
    while (monotonic_ms() < deadline) {
        if (db_scalar(server->db_path,
                      "SELECT client_online_at FROM product_metrics_onboarding_progress "
                      "WHERE tenant_id = 'default' AND username = ?", "pm-e2e", 0, value, sizeof(value)) == 0
            && value[0] != '\0') {
            break;
        }
        sleep_ms(50);
    }
    char signed_in[64] = "";
    char credential[64] = "";
    (void)db_scalar(server->db_path, "SELECT signed_in_at FROM product_metrics_onboarding_progress "
                    "WHERE tenant_id = 'default' AND username = ?", "pm-e2e", 0, signed_in, sizeof(signed_in));
    (void)db_scalar(server->db_path, "SELECT credential_created_at FROM product_metrics_onboarding_progress "
                    "WHERE tenant_id = 'default' AND username = ?", "pm-e2e", 0, credential, sizeof(credential));
    ok = value[0] != '\0' && signed_in[0] != '\0' && credential[0] != '\0';
    if (!ok) {
        free(user_token);
        close_fd(&control_fd);
        CHECK(0, "control login did not record client_online (online=%s signed=%s credential=%s)", value, signed_in,
              credential);
    }

    char path[160];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", runtime.client_id);
    ok = http_request(server->admin_port, "POST", path,
                      "{\"route\":\"pm-e2e\",\"targetBaseUrl\":\"http://127.0.0.1:9\"}", user_token, &status,
                      &response) == 0 && status == 201;
    free(response);
    response = NULL;
    char users[32] = "";
    (void)db_scalar(server->db_path, "SELECT users FROM product_metrics_onboarding_daily WHERE tenant_id = ? "
                    "AND reached_step = 'service_published' AND duration_bucket = 'lt10m'",
                    "default", 0, users, sizeof(users));
    char remaining[32] = "";
    (void)db_scalar(server->db_path, "SELECT COUNT(*) FROM product_metrics_onboarding_progress WHERE tenant_id = ?",
                    "default", 0, remaining, sizeof(remaining));
    ok = ok && strcmp(users, "1") == 0 && strcmp(remaining, "0") == 0;
    if (!ok) {
        free(user_token);
        close_fd(&control_fd);
        CHECK(0, "route create did not complete the onboarding (status=%d users=%s remaining=%s)", status, users,
              remaining);
    }

    /* The real HTTP layer hands a 4097-byte body to the handler, which answers 413 itself. */
    char body[4200];
    int prefix = snprintf(body, sizeof(body), "{\"schemaVersion\":1,\"events\":[" SAMPLE_EVENT "]}");
    memset(body + prefix, ' ', sizeof(body) - (size_t)prefix);
    int too_large = raw_exchange(server->admin_port, "POST", "/api/admin/product-metrics/transfer-outcomes",
                                 user_token, body, 4097U, &raw) == 0
        && raw.status == 413 && strcmp(raw.cache_control, "private, no-store") == 0
        && strstr(raw.body, ST_PRODUCT_METRICS_CODE_TOO_LARGE) != NULL;
    int accepted = raw_exchange(server->admin_port, "POST", "/api/admin/product-metrics/transfer-outcomes",
                                user_token, body, 4096U, &raw) == 0
        && raw.status == 200 && strstr(raw.body, "\"accepted\":1") != NULL;
    int anonymous = raw_exchange(server->admin_port, "POST", "/api/admin/product-metrics/transfer-outcomes", NULL,
                                 body, (size_t)prefix, &raw) == 0
        && raw.status == 401 && strcmp(raw.cache_control, "private, no-store") == 0;
    free(user_token);
    close_fd(&control_fd);
    CHECK(too_large && accepted && anonymous, "HTTP layer: 413=%d 4096=%d 401=%d (%d %s)", too_large, accepted,
          anonymous, raw.status, raw.body);
    return 0;
}

/* ---- Main --------------------------------------------------------------------------------------- */

static char *read_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        return NULL;
    }
    char *data = NULL;
    if (fseek(file, 0, SEEK_END) == 0) {
        long size = ftell(file);
        if (size > 0 && fseek(file, 0, SEEK_SET) == 0) {
            data = (char *)malloc((size_t)size + 1U);
            if (data != NULL && fread(data, 1U, (size_t)size, file) == (size_t)size) {
                data[size] = '\0';
            } else {
                free(data);
                data = NULL;
            }
        }
    }
    fclose(file);
    return data;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    setenv("SPECUS_AUTH_JWT_SECRET", PM_TEST_JWT_SECRET, 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    unsetenv("SPECUS_PRODUCT_METRICS_ALLOWED");
    unsetenv("SPECUS_AUTH_USERNAME");
    unsetenv("SPECUS_AUTH_PASSWORD");
    unsetenv("SPECUS_AUTH_TENANT_ID");
    st_product_metrics_set_clock(test_clock);
    if (st_password_hash("product-metrics-actor-password", actor_password_hash) != 0) {
        fprintf(stderr, "password hash failed\n");
        return 1;
    }

    char *text = read_file(ST_PRODUCT_METRICS_VECTOR_FILE);
    jv *vector = jv_parse(text);
    if (vector == NULL) {
        fprintf(stderr, "cannot read %s\n", ST_PRODUCT_METRICS_VECTOR_FILE);
        free(text);
        return 1;
    }
    int bad = 0;
    bad |= replay_tables(vector) != 0;
    bad |= replay_ingest_validation(vector) != 0;
    bad |= replay_scenarios(vector) != 0;
    bad |= closed_schema_checks() != 0;
    bad |= sweep_rechecks_the_switch() != 0;
    bad |= wiring_checks() != 0;
    jv_free(vector);
    free(text);
    drop_database();
    st_product_metrics_set_clock(NULL);

    if (argc >= 2) {
        server_binary = argv[1];
        unsetenv("SPECUS_DATABASE_PATH");
        bad |= run_on_fresh_server("product metrics on a real server: client_online, completion, HTTP body limits",
                                   e2e_scenario, NULL) != 0;
    } else {
        printf("skip real-server scenario: pass the specus-server-c binary as the first argument\n");
    }
    if (bad || failures != 0) {
        fprintf(stderr, "product metrics tests failed (%d failed expectations)\n", failures);
        return 1;
    }
    printf("product metrics tests passed\n");
    return 0;
}
