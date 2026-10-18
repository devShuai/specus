#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#include "admin_http.h"
#include "security.h"
#include "storage.h"
#include "connectivity_check_test_support.h"

/* No listening socket: like Java MockMvc, this exercises the production endpoint/response builder.
 * Unlike a fabricated auth context or loader, JWT resolution and route visibility use real SQLite.
 * Each case gets a child process: the production checker has process lifetime, not a test reset API. */
typedef struct {
    fake_device target;
    pthread_mutex_t mutex;
    pthread_cond_t changed;
    int hold_target;
    int blocked;
    int release;
    int capture;
    int timed_out;
    int done;
} http_device;

typedef struct {
    http_device *device;
    char authorization[2300];
    char path[128];
    char response[8192];
    int result;
    pthread_t thread;
} occupant;

static struct timespec deadline(void)
{
    struct timespec out;
    if (clock_gettime(CLOCK_REALTIME, &out) != 0) abort();
    out.tv_sec += 10;
    return out;
}

static int is_held(const http_device *device, const char *client)
{
    return device->hold_target || strcmp(client, "device-42") != 0;
}

static void http_presence(void *ctx, const char *client, int *control, int *data)
{
    http_device *device = ctx;
    pthread_mutex_lock(&device->mutex);
    if (is_held(device, client)) *control = *data = 1;
    else fake_presence(&device->target, client, control, data);
    pthread_mutex_unlock(&device->mutex);
}

static void http_probe(void *ctx, const char *client, const char *metadata,
                       long long timeout_ms, st_connectivity_probe_answer *answer)
{
    http_device *device = ctx;
    pthread_mutex_lock(&device->mutex);
    if (is_held(device, client)) {
        ++device->blocked;
        pthread_cond_broadcast(&device->changed);
        struct timespec until = deadline();
        while (!device->release) {
            int rc = pthread_cond_timedwait(&device->changed, &device->mutex, &until);
            if (rc != 0) { device->timed_out = 1; break; }
        }
        memset(answer, 0, sizeof(*answer));
        answer->capability = 1;
        answer->kind = ST_CONNECTIVITY_PROBE_RESPONSE;
        answer->status_code = 200;
    } else fake_probe(&device->target, client, metadata, timeout_ms, answer);
    pthread_mutex_unlock(&device->mutex);
}

static long long http_now(void *ctx)
{
    http_device *device = ctx;
    pthread_mutex_lock(&device->mutex);
    long long now = device->target.now;
    pthread_mutex_unlock(&device->mutex);
    return now;
}

static void http_log(void *ctx, const char *line)
{
    http_device *device = ctx;
    pthread_mutex_lock(&device->mutex);
    if (device->capture) fake_log(&device->target, line);
    pthread_mutex_unlock(&device->mutex);
}

static int exec_sql(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int failed = sqlite3_open(path, &db) != SQLITE_OK;
    if (!failed && sqlite3_exec(db, sql, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "fixture SQL: %s\n", sqlite3_errmsg(db));
        failed = 1;
    }
    sqlite3_close(db);
    return failed;
}

static int create_bearer(const char *db, const char *user, const char *role,
                         char *out, size_t out_len)
{
    st_storage_management_user row;
    char token[2048];
    if (st_storage_create_management_user(db, user, "t1", "unused-password-hash", role, 1, &row) != 0
        || st_security_issue_local_token(user, "t1", role, getenv("SPECUS_AUTH_JWT_SECRET"),
                                         600, token, sizeof(token)) != 0) return 1;
    int written = snprintf(out, out_len, "Bearer %s", token);
    return written < 0 || (size_t)written >= out_len;
}

static int create_route(const char *db, long long id, const char *owner,
                        int client_enabled, int route_enabled, int target_valid)
{
    st_storage_client client;
    st_storage_http_route route;
    char client_name[64];
    snprintf(client_name, sizeof(client_name), "device-%lld", id);
    if (st_storage_upsert_client(db, 0, "t1", client_name, owner, client_enabled, 0, &client) != 0
        || st_storage_create_http_route_for_client(db, client.id, "api", "http://127.0.0.1:8080/base",
                route_enabled, 0, 0, 0, 0, 0, "", "", &route) != 0) return 1;
    /* Stable vector IDs, plus a legacy invalid target that the management creation API rejects. */
    char sql[512];
    snprintf(sql, sizeof(sql), "UPDATE http_route_mapping SET id=%lld,target_base_url='%s' WHERE id=%lld",
             id, target_valid ? "http://127.0.0.1:8080/base" : "ftp://127.0.0.1/", route.id);
    return exec_sql(db, sql);
}

static void *run_occupant(void *ctx)
{
    occupant *held = ctx;
    held->result = st_admin_build_response_with_auth("POST", held->path, held->authorization,
                     "{\"path\":\"/healthz\"}", held->response, sizeof(held->response));
    pthread_mutex_lock(&held->device->mutex);
    ++held->device->done;
    pthread_cond_broadcast(&held->device->changed);
    pthread_mutex_unlock(&held->device->mutex);
    return NULL;
}

/* Exactly one header, case-insensitive name, and exact value (or absent when value == NULL). */
static int assert_header(const char *raw, const char *name, const char *value)
{
    const char *p = strstr(raw, "\r\n");
    int count = 0;
    int match = 0;
    size_t name_len = strlen(name);
    while (p != NULL && p[2] != '\r' && p[2] != '\0') {
        p += 2;
        const char *end = strstr(p, "\r\n");
        if (end == NULL) return 1;
        if ((size_t)(end - p) > name_len && strncasecmp(p, name, name_len) == 0 && p[name_len] == ':') {
            const char *start = p + name_len + 1;
            while (start < end && (*start == ' ' || *start == '\t')) ++start;
            ++count;
            match = value != NULL && (size_t)(end - start) == strlen(value)
                && memcmp(start, value, strlen(value)) == 0;
        }
        p = end;
    }
    if (value == NULL ? count != 0 : count != 1 || !match) {
        fprintf(stderr, "HTTP header %s differs (want %s, count %d)\n", name, value ? value : "absent", count);
        return 1;
    }
    return 0;
}

static int assert_http(const char *name, const char *expect, const http_device *device, const char *raw)
{
    int status = 0;
    const char *body = strstr(raw, "\r\n\r\n");
    if (sscanf(raw, "HTTP/1.1 %d", &status) != 1 || body == NULL) return 1;
    body += 4;
    int want_status = 0, retry = 0;
    (void)st_json_get_int(expect, "httpStatus", &want_status);
    if (st_json_get_int(expect, "retryAfterSeconds", &retry) != 0)
        retry = want_status == 429 || want_status == 503 ? 1 : 0;
    char retry_string[32], length[32];
    snprintf(retry_string, sizeof(retry_string), "%d", retry);
    snprintf(length, sizeof(length), "%zu", strlen(body));
    int failed = assert_header(raw, "Cache-Control", "private, no-store")
        | assert_header(raw, "Retry-After", retry ? retry_string : NULL)
        | assert_header(raw, "Content-Length", length)
        | assert_header(raw, "Content-Type", "application/json");
    if (status == 401) {
        /* Java's framework refusal has no top-level code; C's framework supplies its own error. */
        char *code = st_json_get_top_level_raw(body, "code");
        if (code != NULL || strcmp(body, "{\"error\":\"missing or invalid bearer token\"}") != 0) failed = 1;
        free(code);
    }
    st_connectivity_response normalized = {
        .status = status, .retry_after_seconds = retry,
        .body = status == 401 ? NULL : (char *)body,
    };
    return failed | assert_vector_response(name, expect, &device->target, &normalized);
}

static int replay(const char *raw_case, const char *db)
{
    char name[96], admission[32];
    copy_string(raw_case, "name", name, sizeof(name));
    char *input = st_json_get_top_level_raw(raw_case, "input");
    char *expect = st_json_get_top_level_raw(raw_case, "expect");
    if (input == NULL || expect == NULL) { free(input); free(expect); return 1; }
    char *route = st_json_get_top_level_raw(input, "route");
    char *device_raw = st_json_get_top_level_raw(input, "device");
    http_device device = {0};
    device.target.now = device.target.check_start = CHECK_START_MS;
    device.target.control_online = bool_or(device_raw, "controlOnline", 1);
    device.target.data_online = bool_or(device_raw, "dataOnline", 1);
    if (device_raw) (void)st_json_get_int(device_raw, "httpRouteCapability", &device.target.capability);
    pthread_mutex_init(&device.mutex, NULL);
    pthread_cond_init(&device.changed, NULL);
    device.capture = 1;
    char **answers = NULL;
    size_t answer_count = 0;
    int failed = 0;
    if (st_json_get_raw_array(input, "answers", &answers, &answer_count) == 0) {
        if (answer_count > 4U) failed = 1;
        for (size_t i = 0; i < answer_count && i < 4U; ++i) {
            scripted_answer *answer = &device.target.answers[device.target.answers_len++];
            copy_string(answers[i], "kind", answer->kind, sizeof(answer->kind));
            copy_string(answers[i], "failure", answer->failure, sizeof(answer->failure));
            copy_string(answers[i], "cause", answer->cause, sizeof(answer->cause));
            (void)st_json_get_int(answers[i], "status", &answer->status);
            (void)st_json_get_i64(answers[i], "atMs", &answer->at_ms);
        }
    }
    st_json_free_string_array(answers, answer_count);
    copy_string(input, "admission", admission, sizeof(admission));
    device.hold_target = strcmp(admission, "route-in-progress") == 0;
    int count = device.hold_target ? 1 : strcmp(admission, "server-busy") == 0 ? 32 : 0;
    occupant held[32] = {0};
    int started = 0;
    char authorization[2300] = {0};
    setenv("SPECUS_DATABASE_PATH", db, 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "connectivity-http-vector-only-secret-32-bytes", 1);
    setenv("SPECUS_AUTH_USERNAME", "fixture-builtin-admin", 1);
    setenv("SPECUS_AUTH_TENANT_ID", "fixture-builtin-tenant", 1);
    failed |= st_storage_init(db, 0) != 0;
    if (!failed) failed |= create_bearer(db, "alice", "USER", authorization, sizeof(authorization));
    if (!failed) failed |= create_route(db, 42, bool_or(input, "routeVisible", 1) ? "alice" : "bob",
                bool_or(device_raw, "enabled", 1), bool_or(route, "enabled", 1), bool_or(route, "targetValid", 1));
    for (int i = 0; !failed && i < count; ++i) {
        long long id = device.hold_target ? 42 : 1001 + i;
        char user[64];
        snprintf(user, sizeof(user), "occupant-%lld", id);
        held[i].device = &device;
        snprintf(held[i].path, sizeof(held[i].path), "/api/admin/http-routes/%lld/connectivity-check", id);
        failed |= create_bearer(db, user, "ADMIN", held[i].authorization, sizeof(held[i].authorization));
        if (!failed && id != 42) failed |= create_route(db, id, "alice", 1, 1, 1);
    }
    if (!failed && !bool_or(input, "configReadable", 1)) {
        /* Keep authentication readable; only the route configuration is unavailable. */
        failed |= exec_sql(db, "DROP TABLE http_route_mapping; CREATE TABLE http_route_mapping (id INTEGER PRIMARY KEY)");
    }
    st_connectivity_device callbacks = {http_presence, http_probe, http_now, http_log, &device};
    if (!failed) st_admin_set_connectivity_device(&callbacks);
    for (int i = 0; !failed && i < count; ++i) {
        if (pthread_create(&held[i].thread, NULL, run_occupant, &held[i]) != 0) failed = 1;
        else ++started;
    }
    pthread_mutex_lock(&device.mutex);
    struct timespec until = deadline();
    while (!failed && device.blocked < count) {
        if (pthread_cond_timedwait(&device.changed, &device.mutex, &until) != 0) failed = 1;
    }
    pthread_mutex_unlock(&device.mutex);
    char response[16384] = {0};
    if (!failed) {
        const char *body = bool_or(input, "requestValid", 1)
            ? "{\"path\":\"/healthz\"}" : "{\"path\":\"/status/../admin\"}";
        int rc = st_admin_build_response_with_auth("POST", "/api/admin/http-routes/42/connectivity-check",
                bool_or(input, "authenticated", 1) ? authorization : NULL, body, response, sizeof(response));
        failed |= rc < 0;
        if (!failed) failed |= assert_http(name, expect, &device, response);
    }
    pthread_mutex_lock(&device.mutex);
    device.capture = 0;
    device.release = 1;
    pthread_cond_broadcast(&device.changed);
    until = deadline();
    while (device.done < started) {
        if (pthread_cond_timedwait(&device.changed, &device.mutex, &until) != 0) {
            /* The parent sees failure, and the child cannot leak a hung worker to another case. */
            fprintf(stderr, "%s: occupant completion exceeded original 10s bound\n", name);
            _exit(1);
        }
    }
    failed |= device.timed_out;
    pthread_mutex_unlock(&device.mutex);
    for (int i = 0; i < started; ++i) {
        pthread_join(held[i].thread, NULL);
        if (held[i].result < 0 || strncmp(held[i].response, "HTTP/1.1 200 ", 13) != 0) {
            fprintf(stderr, "%s: occupant %d did not complete successfully\n", name, i);
            failed = 1;
        }
    }
    pthread_cond_destroy(&device.changed);
    pthread_mutex_destroy(&device.mutex);
    if (failed) fprintf(stderr, "%s: HTTP vector failed\n%s\n", name, response);
    free(route); free(device_raw); free(input); free(expect);
    return failed;
}

int main(void)
{
    char *vector = read_vector();
    char **cases = NULL;
    size_t count = 0;
    int budget = 0, per_route = 0, per_server = 0;
    char *rate = vector ? st_json_get_top_level_raw(vector, "rate") : NULL;
    int failed = assert_minify_bounds() || vector == NULL || rate == NULL
        || st_json_get_int(vector, "checkBudgetMs", &budget) != 0 || budget != ST_CONNECTIVITY_BUDGET_MS
        || st_json_get_int(rate, "maxConcurrentPerRoute", &per_route) != 0 || per_route != 1
        || st_json_get_int(rate, "maxConcurrentPerServer", &per_server) != 0 || per_server != 32
        || st_json_get_raw_array(vector, "cases", &cases, &count) != 0 || count != 38U;
    for (size_t i = 0; !failed && i < count; ++i) {
        char directory[] = "/tmp/specus-connectivity-http-XXXXXX";
        if (mkdtemp(directory) == NULL) { failed = 1; break; }
        char db[256];
        snprintf(db, sizeof(db), "%s/vector.db", directory);
        fflush(NULL);
        pid_t child = fork();
        if (child == 0) {
            alarm(30);
            int rc = replay(cases[i], db);
            fflush(NULL);
            exit(rc ? 1 : 0);
        }
        int status = 0;
        if (child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            failed = 1;
        const char *suffixes[] = {"", "-wal", "-shm", "-journal"};
        for (size_t j = 0; j < sizeof(suffixes) / sizeof(suffixes[0]); ++j) {
            char file[280];
            snprintf(file, sizeof(file), "%s%s", db, suffixes[j]);
            if (unlink(file) != 0 && errno != ENOENT) failed = 1;
        }
        if (rmdir(directory) != 0) failed = 1;
        if (!failed) {
            char name[96];
            copy_string(cases[i], "name", name, sizeof(name));
            printf("connectivity HTTP vector: %s passed\n", name);
        }
    }
    if (!failed) puts("connectivity HTTP vectors: 38/38; production JWT/SQLite/headers, real held route/32-process slots passed");
    st_json_free_string_array(cases, count);
    free(rate); free(vector);
    return failed ? 1 : 0;
}
