#define _POSIX_C_SOURCE 200809L

#include "connectivity_check.h"

#include <openssl/rand.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "json.h"

#define ST_CONNECTIVITY_MAX_CONCURRENT 32U
#define ST_CONNECTIVITY_ROUTE_INTERVAL_MS 10000LL
#define ST_CONNECTIVITY_ROUTE_BURST 1LL
#define ST_CONNECTIVITY_USER_INTERVAL_MS 30000LL
#define ST_CONNECTIVITY_USER_BURST 10LL
/*
 * Each key table holds at most this many entries. An entry whose time is not after now is dead and
 * may go at any time; a live one is never evicted, since that would hand it a fresh allowance.
 */
#define ST_CONNECTIVITY_MAX_KEYS 10000U
/* A rate-limited caller is logged at most once a minute. */
#define ST_CONNECTIVITY_REFUSAL_LOG_INTERVAL_MS 60000LL
#define ST_CONNECTIVITY_KEY_MAX 256U

static const char *const stage_names[4] = {
    "configured", "device-online", "target-reachable", "access-succeeded"
};

enum { STAGE_CONFIGURED = 0, STAGE_DEVICE_ONLINE, STAGE_TARGET_REACHABLE, STAGE_ACCESS };

/* RST metadata.failure a capable client may send, and the stage and code each decides (6.2). */
static const struct {
    const char *failure;
    int stage;
    const char *code;
} rst_failures[] = {
    {"route-not-loaded", STAGE_DEVICE_ONLINE, "DEVICE_ROUTE_NOT_LOADED"},
    {"target-invalid", STAGE_TARGET_REACHABLE, "TARGET_ADDRESS_INVALID"},
    {"connect-refused", STAGE_TARGET_REACHABLE, "TARGET_CONNECT_REFUSED"},
    {"connect-timeout", STAGE_TARGET_REACHABLE, "TARGET_CONNECT_TIMEOUT"},
    {"dns-failed", STAGE_TARGET_REACHABLE, "TARGET_DNS_FAILED"},
    {"tls-failed", STAGE_TARGET_REACHABLE, "TARGET_TLS_FAILED"},
    {"unreachable", STAGE_TARGET_REACHABLE, "TARGET_UNREACHABLE"},
    {"protocol-error", STAGE_TARGET_REACHABLE, "TARGET_PROTOCOL_ERROR"},
};

typedef struct {
    char key[ST_CONNECTIVITY_KEY_MAX];
    long long value;
} key_entry;

typedef struct {
    key_entry *entries;
    size_t len;
    size_t cap;
} key_table;

struct st_connectivity_checker {
    st_connectivity_device device;
    pthread_mutex_t lock;
    long long running[ST_CONNECTIVITY_MAX_CONCURRENT];
    size_t running_len;
    key_table route_tat;
    key_table user_tat;
    key_table refusal_log;
};

/* ---- key tables ------------------------------------------------------------------------------ */

static key_entry *table_find(key_table *table, const char *key)
{
    for (size_t i = 0; i < table->len; ++i) {
        if (strcmp(table->entries[i].key, key) == 0) {
            return &table->entries[i];
        }
    }
    return NULL;
}

/* Drops entries for which dead(value) holds, keeping the order of the rest. */
static void table_purge(key_table *table, long long now_ms, long long keep_window_ms)
{
    size_t kept = 0;
    for (size_t i = 0; i < table->len; ++i) {
        int dead = keep_window_ms < 0
            ? table->entries[i].value <= now_ms
            : now_ms - table->entries[i].value >= keep_window_ms;
        if (!dead) {
            if (kept != i) {
                table->entries[kept] = table->entries[i];
            }
            ++kept;
        }
    }
    table->len = kept;
}

/* Whether key is present or can be added; purges dead entries when the table is full. */
static int table_has_room(key_table *table, const char *key, long long now_ms, long long keep_window_ms)
{
    if (table_find(table, key) != NULL || table->len < ST_CONNECTIVITY_MAX_KEYS) {
        return 1;
    }
    table_purge(table, now_ms, keep_window_ms);
    return table->len < ST_CONNECTIVITY_MAX_KEYS;
}

static int table_put(key_table *table, const char *key, long long value)
{
    key_entry *entry = table_find(table, key);
    if (entry != NULL) {
        entry->value = value;
        return 0;
    }
    if (table->len == table->cap) {
        size_t next = table->cap == 0U ? 64U : table->cap * 2U;
        if (next > ST_CONNECTIVITY_MAX_KEYS) {
            next = ST_CONNECTIVITY_MAX_KEYS;
        }
        if (next <= table->cap) {
            return -1;
        }
        key_entry *grown = (key_entry *)realloc(table->entries, next * sizeof(*grown));
        if (grown == NULL) {
            return -1;
        }
        table->entries = grown;
        table->cap = next;
    }
    snprintf(table->entries[table->len].key, sizeof(table->entries[table->len].key), "%s", key);
    table->entries[table->len].value = value;
    ++table->len;
    return 0;
}

/* Keys carry the tenant's length so a tenant ending in "/" cannot collide with another. */
static void route_key(char *out, size_t out_len, const char *tenant, long long route_id)
{
    snprintf(out, out_len, "%zu:%s/%lld", strlen(tenant), tenant, route_id);
}

static void user_key(char *out, size_t out_len, const char *tenant, const char *username)
{
    snprintf(out, out_len, "%zu:%s/%s", strlen(tenant), tenant, username);
}

/*
 * GCRA: one theoretical arrival time (TAT) per key, integer ms. A request at now conforms when
 * now >= TAT - tolerance, tolerance = (burst - 1) * interval; conforming moves TAT to
 * max(TAT, now) + interval.
 */
static long long gcra_wait(key_table *table, const char *key, long long now_ms, long long interval_ms, long long burst)
{
    key_entry *entry = table_find(table, key);
    long long tat = entry == NULL ? now_ms : entry->value;
    long long wait = tat - (burst - 1) * interval_ms - now_ms;
    return wait > 0 ? wait : 0;
}

static int gcra_take(key_table *table, const char *key, long long now_ms, long long interval_ms)
{
    key_entry *entry = table_find(table, key);
    long long tat = entry == NULL || entry->value < now_ms ? now_ms : entry->value;
    return table_put(table, key, tat + interval_ms);
}

/* ---- checker --------------------------------------------------------------------------------- */

static long long system_now_ms(void *ctx)
{
    (void)ctx;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

st_connectivity_checker *st_connectivity_checker_new(const st_connectivity_device *device)
{
    if (device == NULL || device->presence == NULL || device->probe == NULL) {
        return NULL;
    }
    st_connectivity_checker *checker = (st_connectivity_checker *)calloc(1, sizeof(*checker));
    if (checker == NULL) {
        return NULL;
    }
    checker->device = *device;
    if (checker->device.now_ms == NULL) {
        checker->device.now_ms = system_now_ms;
    }
    pthread_mutex_init(&checker->lock, NULL);
    return checker;
}

void st_connectivity_checker_free(st_connectivity_checker *checker)
{
    if (checker == NULL) {
        return;
    }
    pthread_mutex_destroy(&checker->lock);
    free(checker->route_tat.entries);
    free(checker->user_tat.entries);
    free(checker->refusal_log.entries);
    free(checker);
}

static void checker_log(st_connectivity_checker *checker, const char *format, ...)
{
    char line[512];
    va_list args;
    va_start(args, format);
    vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (checker->device.log != NULL) {
        checker->device.log(checker->device.ctx, line);
    } else {
        printf("%s\n", line);
        fflush(stdout);
    }
}

static int rate_locked(st_connectivity_checker *checker,
                       const char *tenant_id,
                       const char *username,
                       long long route_id,
                       long long now_ms,
                       st_connectivity_refusal *refusal)
{
    char route[ST_CONNECTIVITY_KEY_MAX];
    char user[ST_CONNECTIVITY_KEY_MAX];
    route_key(route, sizeof(route), tenant_id, route_id);
    user_key(user, sizeof(user), tenant_id, username);
    long long route_wait = gcra_wait(&checker->route_tat, route, now_ms,
                                     ST_CONNECTIVITY_ROUTE_INTERVAL_MS, ST_CONNECTIVITY_ROUTE_BURST);
    long long user_wait = gcra_wait(&checker->user_tat, user, now_ms,
                                    ST_CONNECTIVITY_USER_INTERVAL_MS, ST_CONNECTIVITY_USER_BURST);
    long long wait = route_wait > user_wait ? route_wait : user_wait;
    if (wait > 0) {
        long long seconds = (wait + 999LL) / 1000LL;
        refusal->status = 429;
        refusal->code = "CHECK_RATE_LIMITED";
        refusal->retry_after_seconds = seconds < 1 ? 1 : (int)seconds;
        refusal->limited_by = route_wait >= user_wait ? "route" : "user";
        return -1;
    }
    if (!table_has_room(&checker->route_tat, route, now_ms, -1)
        || !table_has_room(&checker->user_tat, user, now_ms, -1)
        || gcra_take(&checker->route_tat, route, now_ms, ST_CONNECTIVITY_ROUTE_INTERVAL_MS) != 0
        || gcra_take(&checker->user_tat, user, now_ms, ST_CONNECTIVITY_USER_INTERVAL_MS) != 0) {
        refusal->status = 503;
        refusal->code = "CHECK_BUSY";
        refusal->retry_after_seconds = 1;
        refusal->limited_by = NULL;
        return -1;
    }
    return 0;
}

int st_connectivity_rate(st_connectivity_checker *checker,
                         const char *tenant_id,
                         const char *username,
                         long long route_id,
                         long long now_ms,
                         st_connectivity_refusal *refusal)
{
    pthread_mutex_lock(&checker->lock);
    int rc = rate_locked(checker, tenant_id, username, route_id, now_ms, refusal);
    pthread_mutex_unlock(&checker->lock);
    return rc;
}

int st_connectivity_admit(st_connectivity_checker *checker,
                          const char *tenant_id,
                          const char *username,
                          long long route_id,
                          long long now_ms,
                          st_connectivity_refusal *refusal)
{
    pthread_mutex_lock(&checker->lock);
    for (size_t i = 0; i < checker->running_len; ++i) {
        if (checker->running[i] == route_id) {
            pthread_mutex_unlock(&checker->lock);
            *refusal = (st_connectivity_refusal){429, "CHECK_IN_PROGRESS", 1, NULL};
            return -1;
        }
    }
    if (checker->running_len >= ST_CONNECTIVITY_MAX_CONCURRENT) {
        pthread_mutex_unlock(&checker->lock);
        *refusal = (st_connectivity_refusal){503, "CHECK_BUSY", 1, NULL};
        return -1;
    }
    if (rate_locked(checker, tenant_id, username, route_id, now_ms, refusal) != 0) {
        pthread_mutex_unlock(&checker->lock);
        return -1;
    }
    checker->running[checker->running_len++] = route_id;
    pthread_mutex_unlock(&checker->lock);
    return 0;
}

void st_connectivity_release(st_connectivity_checker *checker, long long route_id)
{
    pthread_mutex_lock(&checker->lock);
    for (size_t i = 0; i < checker->running_len; ++i) {
        if (checker->running[i] == route_id) {
            checker->running[i] = checker->running[--checker->running_len];
            break;
        }
    }
    pthread_mutex_unlock(&checker->lock);
}

static int should_log_refusal(st_connectivity_checker *checker, const char *tenant_id, const char *username, long long now_ms)
{
    char user[ST_CONNECTIVITY_KEY_MAX];
    user_key(user, sizeof(user), tenant_id, username);
    pthread_mutex_lock(&checker->lock);
    key_entry *entry = table_find(&checker->refusal_log, user);
    int log = 0;
    if (entry != NULL) {
        if (now_ms - entry->value >= ST_CONNECTIVITY_REFUSAL_LOG_INTERVAL_MS) {
            entry->value = now_ms;
            log = 1;
        }
    } else if (table_has_room(&checker->refusal_log, user, now_ms, ST_CONNECTIVITY_REFUSAL_LOG_INTERVAL_MS)) {
        log = table_put(&checker->refusal_log, user, now_ms) == 0;
    }
    pthread_mutex_unlock(&checker->lock);
    return log;
}

/* ---- request ---------------------------------------------------------------------------------- */

static int is_hex(char value)
{
    return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
}

int st_connectivity_valid_path(const char *path)
{
    if (path == NULL) {
        return 0;
    }
    size_t len = strlen(path);
    if (len < 1U || len > ST_CONNECTIVITY_MAX_PATH_BYTES || path[0] != '/' || (len > 1U && path[1] == '/')) {
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        char c = path[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
            || strchr("-._~!$&'()*+,;=:@/", c) != NULL) {
            continue;
        }
        if (c == '%' && i + 2U < len && is_hex(path[i + 1U]) && is_hex(path[i + 2U])) {
            i += 2U;
            continue;
        }
        return 0;
    }
    /* No "." or ".." segment, also when the dot is percent-encoded. */
    const char *segment = path;
    while (segment != NULL) {
        const char *end = strchr(segment, '/');
        size_t segment_len = end == NULL ? strlen(segment) : (size_t)(end - segment);
        size_t dots = 0;
        size_t i = 0;
        int only_dots = 1;
        while (i < segment_len) {
            if (segment[i] == '.') {
                ++dots;
                ++i;
            } else if (segment[i] == '%' && i + 2U < segment_len
                       && segment[i + 1U] == '2' && (segment[i + 2U] == 'e' || segment[i + 2U] == 'E')) {
                ++dots;
                i += 3U;
            } else {
                only_dots = 0;
                break;
            }
        }
        if (only_dots && (dots == 1U || dots == 2U)) {
            return 0;
        }
        segment = end == NULL ? NULL : end + 1;
    }
    return 1;
}

static const char *skip_space(const char *cursor, const char *end)
{
    while (cursor < end && (*cursor == ' ' || *cursor == '\t' || *cursor == '\r' || *cursor == '\n')) {
        ++cursor;
    }
    return cursor;
}

/*
 * Decodes one JSON string starting at *cursor (the opening quote) into out. Only ASCII results are
 * accepted: a valid probe path and the only valid key are ASCII, so anything else is refused here.
 */
static int decode_ascii_string(const char **cursor, const char *end, char *out, size_t out_len)
{
    const char *p = *cursor;
    if (p >= end || *p != '"') {
        return -1;
    }
    ++p;
    size_t written = 0;
    while (p < end && *p != '"') {
        unsigned char c = (unsigned char)*p;
        char decoded;
        if (c < 0x20U || c >= 0x80U) {
            return -1;
        }
        if (c == '\\') {
            if (++p >= end) {
                return -1;
            }
            switch (*p) {
            case '"': decoded = '"'; break;
            case '\\': decoded = '\\'; break;
            case '/': decoded = '/'; break;
            case 'b': decoded = '\b'; break;
            case 'f': decoded = '\f'; break;
            case 'n': decoded = '\n'; break;
            case 'r': decoded = '\r'; break;
            case 't': decoded = '\t'; break;
            case 'u': {
                if (end - p < 5) {
                    return -1;
                }
                unsigned value = 0;
                for (int i = 1; i <= 4; ++i) {
                    char h = p[i];
                    if (!is_hex(h)) {
                        return -1;
                    }
                    value = value * 16U + (unsigned)(h <= '9' ? h - '0' : (h | 0x20) - 'a' + 10);
                }
                if (value == 0U || value >= 0x80U) {
                    return -1;
                }
                decoded = (char)value;
                p += 4;
                break;
            }
            default:
                return -1;
            }
        } else {
            decoded = (char)c;
        }
        if (written + 1U >= out_len) {
            return -1;
        }
        out[written++] = decoded;
        ++p;
    }
    if (p >= end) {
        return -1;
    }
    out[written] = '\0';
    *cursor = p + 1;
    return 0;
}

int st_connectivity_parse_body(const char *body, size_t body_len, char *path, size_t path_len)
{
    if (path == NULL || path_len < 2U || body_len > ST_CONNECTIVITY_MAX_BODY_BYTES) {
        return -1;
    }
    snprintf(path, path_len, "/");
    if (body == NULL) {
        return 0;
    }
    const char *end = body + body_len;
    const char *cursor = skip_space(body, end);
    if (cursor == end) {
        return 0;
    }
    if (*cursor != '{') {
        return -1;
    }
    cursor = skip_space(cursor + 1, end);
    int seen_path = 0;
    if (cursor < end && *cursor == '}') {
        ++cursor;
    } else {
        for (;;) {
            char key[8];
            char value[ST_CONNECTIVITY_MAX_PATH_BYTES + 2U];
            if (decode_ascii_string(&cursor, end, key, sizeof(key)) != 0 || strcmp(key, "path") != 0 || seen_path) {
                return -1;
            }
            cursor = skip_space(cursor, end);
            if (cursor >= end || *cursor != ':') {
                return -1;
            }
            cursor = skip_space(cursor + 1, end);
            if (decode_ascii_string(&cursor, end, value, sizeof(value)) != 0) {
                return -1;
            }
            snprintf(path, path_len, "%s", value);
            seen_path = 1;
            cursor = skip_space(cursor, end);
            if (cursor < end && *cursor == ',') {
                cursor = skip_space(cursor + 1, end);
                continue;
            }
            if (cursor < end && *cursor == '}') {
                ++cursor;
                break;
            }
            return -1;
        }
    }
    if (skip_space(cursor, end) != end) {
        return -1;
    }
    return st_connectivity_valid_path(path) ? 0 : -1;
}

int st_connectivity_valid_target_base_url(const char *url)
{
    if (url == NULL) {
        return 0;
    }
    const char *authority;
    if (strncasecmp(url, "http://", 7U) == 0) {
        authority = url + 7;
    } else if (strncasecmp(url, "https://", 8U) == 0) {
        authority = url + 8;
    } else {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)url; *p != '\0'; ++p) {
        if (*p <= 0x20U || *p == 0x7fU) {
            return 0;
        }
    }
    size_t authority_len = strcspn(authority, "/?#");
    const char *host = authority;
    for (size_t i = 0; i < authority_len; ++i) {
        if (authority[i] == '@') {
            host = authority + i + 1;
        }
    }
    size_t host_len = authority_len - (size_t)(host - authority);
    if (host_len == 0U) {
        return 0;
    }
    if (host[0] == '[') {
        const char *close = memchr(host, ']', host_len);
        return close != NULL && close > host + 1;
    }
    return host[0] != ':';
}

/* ---- the check -------------------------------------------------------------------------------- */

typedef struct {
    const char *result;
    const char *code;
    long long at_ms;
} stage_decision;

typedef struct {
    stage_decision stages[4];
    size_t decided;
    const char *requests[2];
    size_t requests_len;
    int status_class;
} check_result;

typedef struct {
    int kind;          /* a ST_CONNECTIVITY_PROBE_* value, folded as below */
    int status;
    int trusted;
    const char *failure_code;
    int failure_stage;
    long long at_ms;
} check_answer;

static void decide(check_result *result, const char *outcome, const char *code, long long at_ms)
{
    if (result->decided < 4U) {
        result->stages[result->decided++] = (stage_decision){outcome, code, at_ms};
    }
}

static long long elapsed_ms(st_connectivity_checker *checker, long long start_ms)
{
    long long elapsed = checker->device.now_ms(checker->device.ctx) - start_ms;
    if (elapsed < 0) {
        return 0;
    }
    return elapsed > ST_CONNECTIVITY_BUDGET_MS ? ST_CONNECTIVITY_BUDGET_MS : elapsed;
}

static void random_request_id(char out[33])
{
    unsigned char bytes[16];
    if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        snprintf(out, 33, "%016llx%016llx", (unsigned long long)now.tv_sec, (unsigned long long)now.tv_nsec);
        return;
    }
    for (size_t i = 0; i < sizeof(bytes); ++i) {
        snprintf(out + i * 2U, 3, "%02x", bytes[i]);
    }
}

static char *probe_metadata(const char *method, const char *route, const char *path)
{
    char request_id[33];
    random_request_id(request_id);
    char *route_escaped = st_json_escape(route);
    char *path_escaped = st_json_escape(path);
    char *metadata = NULL;
    if (route_escaped != NULL && path_escaped != NULL) {
        const char *format = "{\"source\":\"http\",\"phase\":\"request\",\"requestId\":\"%s\",\"method\":\"%s\","
                             "\"route\":\"%s\",\"relativePath\":\"%s\",\"rawQuery\":\"\","
                             "\"headers\":[\"Accept:*/*\",\"User-Agent:" ST_CONNECTIVITY_USER_AGENT "\"]}";
        int len = snprintf(NULL, 0, format, request_id, method, route_escaped, path_escaped);
        if (len > 0) {
            metadata = (char *)malloc((size_t)len + 1U);
            if (metadata != NULL) {
                snprintf(metadata, (size_t)len + 1U, format, request_id, method, route_escaped, path_escaped);
            }
        }
    }
    free(route_escaped);
    free(path_escaped);
    return metadata;
}

/* Sends one probe request and folds the device's first answer within the budget. */
static check_answer exchange(st_connectivity_checker *checker,
                             check_result *result,
                             long long start_ms,
                             const st_connectivity_route *route,
                             const char *method,
                             const char *path)
{
    result->requests[result->requests_len++] = method;
    check_answer folded = {0};
    char *metadata = probe_metadata(method, route->route, path);
    if (metadata == NULL) {
        folded.kind = ST_CONNECTIVITY_PROBE_WRITE_FAILED;
        folded.at_ms = elapsed_ms(checker, start_ms);
        return folded;
    }
    long long remaining = start_ms + ST_CONNECTIVITY_BUDGET_MS - checker->device.now_ms(checker->device.ctx);
    st_connectivity_probe_answer answer;
    memset(&answer, 0, sizeof(answer));
    answer.kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
    checker->device.probe(checker->device.ctx, route->client_name, metadata, remaining > 0 ? remaining : 0, &answer);
    free(metadata);
    long long at = elapsed_ms(checker, start_ms);
    folded.kind = answer.kind;
    folded.at_ms = at;
    switch (answer.kind) {
    case ST_CONNECTIVITY_PROBE_WRITE_FAILED:
    case ST_CONNECTIVITY_PROBE_STREAM_LIMIT:
        return folded;
    case ST_CONNECTIVITY_PROBE_RESPONSE:
        folded.status = answer.status_code;
        break;
    case ST_CONNECTIVITY_PROBE_RESET:
        answer.failure[sizeof(answer.failure) - 1U] = '\0';
        folded.trusted = 0;
        if (answer.capability >= 1) {
            for (size_t i = 0; i < sizeof(rst_failures) / sizeof(rst_failures[0]); ++i) {
                if (strcmp(answer.failure, rst_failures[i].failure) == 0) {
                    folded.trusted = 1;
                    folded.failure_code = rst_failures[i].code;
                    folded.failure_stage = rst_failures[i].stage;
                }
            }
        }
        break;
    case ST_CONNECTIVITY_PROBE_LINK_LOST:
        break;
    default:
        /* Budget spent: nobody reads a later answer. */
        folded.kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
        folded.at_ms = ST_CONNECTIVITY_BUDGET_MS;
        return folded;
    }
    if (at >= ST_CONNECTIVITY_BUDGET_MS) {
        folded.kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
        folded.at_ms = ST_CONNECTIVITY_BUDGET_MS;
    }
    return folded;
}

static void access_code(int status, const char **outcome, const char **code)
{
    if (status >= 200 && status <= 399) {
        *outcome = "passed";
        *code = "ACCESS_OK";
    } else if (status == 401 || status == 403 || status == 407) {
        /* The target wants its own credentials; the check never sends any. */
        *outcome = "unverified";
        *code = "ACCESS_AUTH_REQUIRED";
    } else if (status == 404 || status == 410) {
        *outcome = "failed";
        *code = "ACCESS_NOT_FOUND";
    } else if (status >= 400 && status <= 499) {
        *outcome = "failed";
        *code = "ACCESS_CLIENT_ERROR";
    } else {
        *outcome = "failed";
        *code = "ACCESS_SERVER_ERROR";
    }
}

static void run_check(st_connectivity_checker *checker,
                      long long start_ms,
                      const st_connectivity_route *route,
                      const char *path,
                      check_result *result)
{
    /* Stage 1: the server's own records. */
    if (!route->route_enabled) {
        decide(result, "failed", "ROUTE_DISABLED", 0);
        return;
    }
    if (!route->client_enabled) {
        decide(result, "failed", "CLIENT_DISABLED", 0);
        return;
    }
    if (!st_connectivity_valid_target_base_url(route->target_base_url)) {
        decide(result, "failed", "ROUTE_TARGET_INVALID", 0);
        return;
    }
    decide(result, "passed", "CONFIGURED", 0);

    /* Stage 2 preconditions: a control session and its data connection, as they are now. */
    int control_online = 0;
    int data_online = 0;
    checker->device.presence(checker->device.ctx, route->client_name, &control_online, &data_online);
    if (!control_online) {
        decide(result, "failed", "DEVICE_OFFLINE", 0);
        return;
    }
    if (!data_online) {
        decide(result, "failed", "DEVICE_DATA_CHANNEL_DOWN", 0);
        return;
    }

    check_answer head = exchange(checker, result, start_ms, route, "HEAD", path);
    switch (head.kind) {
    case ST_CONNECTIVITY_PROBE_WRITE_FAILED:
        decide(result, "failed", "DEVICE_LINK_LOST", head.at_ms);
        return;
    case ST_CONNECTIVITY_PROBE_STREAM_LIMIT:
        decide(result, "failed", "DEVICE_BUSY", head.at_ms);
        return;
    case ST_CONNECTIVITY_PROBE_TIMEOUT:
        decide(result, "passed", "DEVICE_ONLINE", ST_CONNECTIVITY_BUDGET_MS);
        decide(result, "failed", "TARGET_TIMEOUT", ST_CONNECTIVITY_BUDGET_MS);
        return;
    case ST_CONNECTIVITY_PROBE_LINK_LOST:
        decide(result, "failed", "DEVICE_LINK_LOST", head.at_ms);
        return;
    case ST_CONNECTIVITY_PROBE_RESET:
        if (head.trusted) {
            if (head.failure_stage == STAGE_DEVICE_ONLINE) {
                decide(result, "failed", head.failure_code, head.at_ms);
                return;
            }
            decide(result, "passed", "DEVICE_ONLINE", head.at_ms);
            decide(result, "failed", head.failure_code, head.at_ms);
            return;
        }
        /* An older client, no classification, or one this server does not know: never guess. */
        decide(result, "passed", "DEVICE_ONLINE", head.at_ms);
        decide(result, "unverified", "TARGET_UNVERIFIED", head.at_ms);
        return;
    default:
        break;
    }

    decide(result, "passed", "DEVICE_ONLINE", head.at_ms);
    if (head.status < 200 || head.status > 599) {
        /* Not a final answer the target could have meant; clients never relay one. */
        decide(result, "failed", "TARGET_PROTOCOL_ERROR", head.at_ms);
        return;
    }
    decide(result, "passed", "TARGET_ANSWERED", head.at_ms);
    const char *outcome;
    const char *code;
    if (head.status != 405 && head.status != 501) {
        access_code(head.status, &outcome, &code);
        decide(result, outcome, code, head.at_ms);
        result->status_class = head.status;
        return;
    }

    /* HEAD refused by method: one GET within what is left of the same budget. */
    check_answer get = exchange(checker, result, start_ms, route, "GET", path);
    if (get.kind == ST_CONNECTIVITY_PROBE_RESPONSE && get.status >= 200 && get.status <= 599) {
        access_code(get.status, &outcome, &code);
        decide(result, outcome, code, get.at_ms);
        result->status_class = get.status;
        return;
    }
    decide(result, "failed", "ACCESS_NO_ANSWER",
           get.kind == ST_CONNECTIVITY_PROBE_TIMEOUT ? ST_CONNECTIVITY_BUDGET_MS : get.at_ms);
}

static char *refusal_body(const char *code)
{
    size_t len = strlen(code) + 12U;
    char *body = (char *)malloc(len);
    if (body != NULL) {
        snprintf(body, len, "{\"code\":\"%s\"}", code);
    }
    return body;
}

static int refuse(st_connectivity_response *response, int status, const char *code, int retry_after_seconds)
{
    response->status = status;
    response->retry_after_seconds = retry_after_seconds;
    response->body = refusal_body(code);
    return response->body == NULL ? -1 : 0;
}

static const char *outcome_of(const char *result)
{
    if (strcmp(result, "passed") == 0) {
        return "succeeded";
    }
    return strcmp(result, "failed") == 0 ? "failed" : "unverified";
}

static char *result_body(const check_result *result, long long route_id, const char *checked_at)
{
    const stage_decision *last = &result->stages[result->decided - 1U];
    const char *outcome = outcome_of(last->result);
    char stopped_at[40];
    if (strcmp(outcome, "succeeded") == 0) {
        snprintf(stopped_at, sizeof(stopped_at), "null");
    } else {
        snprintf(stopped_at, sizeof(stopped_at), "\"%s\"", stage_names[result->decided - 1U]);
    }
    char requests[32] = "";
    for (size_t i = 0; i < result->requests_len; ++i) {
        size_t used = strlen(requests);
        snprintf(requests + used, sizeof(requests) - used, "%s\"%s\"", i == 0U ? "" : ",", result->requests[i]);
    }
    char stages[1024] = "";
    for (size_t i = 0; i < 4U; ++i) {
        size_t used = strlen(stages);
        if (i < result->decided) {
            snprintf(stages + used, sizeof(stages) - used,
                     "%s{\"stage\":\"%s\",\"result\":\"%s\",\"code\":\"%s\",\"atMs\":%lld}",
                     i == 0U ? "" : ",", stage_names[i], result->stages[i].result, result->stages[i].code,
                     result->stages[i].at_ms);
        } else {
            snprintf(stages + used, sizeof(stages) - used, "%s{\"stage\":\"%s\",\"result\":\"skipped\"}",
                     i == 0U ? "" : ",", stage_names[i]);
        }
    }
    char status_class[32] = "";
    if (result->status_class != 0) {
        snprintf(status_class, sizeof(status_class), ",\"statusClass\":\"%dxx\"", result->status_class / 100);
    }
    const char *format = "{\"schemaVersion\":1,\"kind\":\"http-route\",\"routeId\":%lld,\"checkedAt\":\"%s\","
                         "\"outcome\":\"%s\",\"stoppedAt\":%s,\"code\":\"%s\",\"totalMs\":%lld,"
                         "\"requests\":[%s],\"stages\":[%s]%s}";
    int len = snprintf(NULL, 0, format, route_id, checked_at, outcome, stopped_at, last->code, last->at_ms,
                       requests, stages, status_class);
    if (len <= 0) {
        return NULL;
    }
    char *body = (char *)malloc((size_t)len + 1U);
    if (body != NULL) {
        snprintf(body, (size_t)len + 1U, format, route_id, checked_at, outcome, stopped_at, last->code,
                 last->at_ms, requests, stages, status_class);
    }
    return body;
}

static int parse_route_id(const char *text, long long *route_id)
{
    if (text == NULL || *text == '\0' || strlen(text) > 18U) {
        return -1;
    }
    long long value = 0;
    for (const char *p = text; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return -1;
        }
        value = value * 10LL + (*p - '0');
    }
    if (value <= 0) {
        return -1;
    }
    *route_id = value;
    return 0;
}

int st_connectivity_handle(st_connectivity_checker *checker,
                           const st_connectivity_request *request,
                           st_connectivity_route_loader loader,
                           void *loader_ctx,
                           st_connectivity_response *response)
{
    if (checker == NULL || request == NULL || loader == NULL || response == NULL) {
        return -1;
    }
    memset(response, 0, sizeof(*response));
    long long start_ms = checker->device.now_ms(checker->device.ctx);
    char checked_at[32];
    time_t wall = time(NULL);
    struct tm utc;
    gmtime_r(&wall, &utc);
    strftime(checked_at, sizeof(checked_at), "%Y-%m-%dT%H:%M:%SZ", &utc);

    if (!request->authenticated) {
        response->status = 401;
        return 0;
    }
    char path[ST_CONNECTIVITY_MAX_PATH_BYTES + 2U];
    if (st_connectivity_parse_body(request->body, request->body_len, path, sizeof(path)) != 0) {
        return refuse(response, 400, "CHECK_REQUEST_INVALID", 0);
    }
    long long route_id = 0;
    if (parse_route_id(request->route_id, &route_id) != 0) {
        return refuse(response, 404, "CHECK_TARGET_NOT_FOUND", 0);
    }
    st_connectivity_route route;
    memset(&route, 0, sizeof(route));
    int loaded = loader(loader_ctx, route_id, &route);
    if (loaded == ST_CONNECTIVITY_ROUTE_ABSENT) {
        return refuse(response, 404, "CHECK_TARGET_NOT_FOUND", 0);
    }
    if (loaded != ST_CONNECTIVITY_ROUTE_FOUND) {
        return refuse(response, 503, "CHECK_UNAVAILABLE", 1);
    }

    const char *tenant = request->tenant_id == NULL ? "" : request->tenant_id;
    const char *username = request->username == NULL ? "" : request->username;
    st_connectivity_refusal refusal;
    if (st_connectivity_admit(checker, tenant, username, route.id,
                              checker->device.now_ms(checker->device.ctx), &refusal) != 0) {
        if (strcmp(refusal.code, "CHECK_RATE_LIMITED") == 0
            && should_log_refusal(checker, tenant, username, checker->device.now_ms(checker->device.ctx))) {
            checker_log(checker, "[connectivity-check] tenant=%s user=%s route=%lld refused code=%s retryAfter=%d",
                        tenant, username, route.id, refusal.code, refusal.retry_after_seconds);
        }
        return refuse(response, refusal.status, refusal.code, refusal.retry_after_seconds);
    }

    check_result result;
    memset(&result, 0, sizeof(result));
    run_check(checker, start_ms, &route, path, &result);
    st_connectivity_release(checker, route.id);

    const stage_decision *last = &result.stages[result.decided - 1U];
    const char *outcome = outcome_of(last->result);
    checker_log(checker,
                "[connectivity-check] tenant=%s user=%s route=%lld outcome=%s stage=%s code=%s totalMs=%lld",
                tenant, username, route.id, outcome,
                strcmp(outcome, "succeeded") == 0 ? "-" : stage_names[result.decided - 1U],
                last->code, last->at_ms);
    response->status = 200;
    response->body = result_body(&result, route.id, checked_at);
    return response->body == NULL ? -1 : 0;
}

void st_connectivity_response_free(st_connectivity_response *response)
{
    if (response != NULL) {
        free(response->body);
        response->body = NULL;
    }
}
