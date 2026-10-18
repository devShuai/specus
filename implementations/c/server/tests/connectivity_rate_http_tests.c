#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "connectivity_http_test_support.h"

#define CLOCK_ORIGIN_MS 123456789LL

typedef struct { fake_device device; size_t presences; } rate_device;

static void presence(void *ctx, const char *client, int *control, int *data)
{
    rate_device *state = ctx;
    ++state->presences;
    fake_presence(&state->device, client, control, data);
}
static void probe(void *ctx, const char *client, const char *meta, long long timeout,
                   st_connectivity_probe_answer *answer)
{
    fake_probe(&((rate_device *)ctx)->device, client, meta, timeout, answer);
}
static long long now_ms(void *ctx) { return ((rate_device *)ctx)->device.now; }
static void log_line(void *ctx, const char *line) { fake_log(&((rate_device *)ctx)->device, line); }

static int parameters(const char *vector)
{
    char *rate = st_json_get_top_level_raw(vector, "rate");
    char *algorithm = rate ? st_json_get_top_level_string(rate, "algorithm") : NULL;
    char *route = rate ? st_json_get_top_level_raw(rate, "perRoute") : NULL;
    char *user = rate ? st_json_get_top_level_raw(rate, "perUser") : NULL;
    long long route_interval = 0, route_burst = 0, user_interval = 0, user_burst = 0;
    int failed = !rate || !algorithm || !route || !user || strcmp(algorithm, "gcra") != 0
        || st_json_get_i64(route, "intervalMs", &route_interval) != 0 || route_interval != ST_CONNECTIVITY_ROUTE_INTERVAL_MS
        || st_json_get_i64(route, "burst", &route_burst) != 0 || route_burst != ST_CONNECTIVITY_ROUTE_BURST
        || st_json_get_i64(user, "intervalMs", &user_interval) != 0 || user_interval != ST_CONNECTIVITY_USER_INTERVAL_MS
        || st_json_get_i64(user, "burst", &user_burst) != 0 || user_burst != ST_CONNECTIVITY_USER_BURST
        || ST_CONNECTIVITY_MAX_KEYS != 10000U;
    free(rate); free(algorithm); free(route); free(user);
    if (failed) fprintf(stderr, "shared GCRA rate declarations differ from production constants\n");
    return failed;
}

/* Only fixture writes are batched. Every admission below still does real JWT/user resolution and
 * the unmodified production HTTP/route loading path. No smaller limiter or private checker access. */
static int fixture(const char *path, int routes, int users)
{
    setenv("SPECUS_DATABASE_PATH", path, 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "connectivity-rate-test-only-secret-32-bytes", 1);
    setenv("SPECUS_AUTH_USERNAME", "fixture-builtin-admin", 1);
    setenv("SPECUS_AUTH_TENANT_ID", "fixture-builtin-tenant", 1);
    st_storage_client client;
    if (st_storage_init(path, 0) != 0
        || st_storage_upsert_client(path, 0, "t1", "rate-fixture", "alice", 1, 0, &client) != 0) return 1;
    sqlite3 *db = NULL;
    sqlite3_stmt *route = NULL, *user = NULL;
    int failed = sqlite3_open(path, &db) != SQLITE_OK
        || sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK
        || sqlite3_prepare_v2(db, "INSERT INTO http_route_mapping(id,client_name,route,target_base_url,enabled) "
                                "VALUES(?1,'rate-fixture',?2,'http://127.0.0.1/base',1)", -1, &route, NULL) != SQLITE_OK;
    if (!failed && users > 0) failed = sqlite3_prepare_v2(db,
        "INSERT INTO specus_management_user(username,login_name,login_name_normalized,tenant_id,password_hash,role,enabled) "
        "VALUES(?1,?1,?1,'t1','unused-password-hash','ADMIN',1)", -1, &user, NULL) != SQLITE_OK;
    for (int id = 1; !failed && id <= routes; ++id) {
        char name[32]; snprintf(name, sizeof(name), "r-%d", id);
        failed = sqlite3_bind_int64(route, 1, id) != SQLITE_OK
            || sqlite3_bind_text(route, 2, name, -1, SQLITE_TRANSIENT) != SQLITE_OK
            || sqlite3_step(route) != SQLITE_DONE || sqlite3_reset(route) != SQLITE_OK;
    }
    for (int id = 1; !failed && id <= users; ++id) {
        char name[32]; snprintf(name, sizeof(name), "u%d", id);
        failed = sqlite3_bind_text(user, 1, name, -1, SQLITE_TRANSIENT) != SQLITE_OK
            || sqlite3_step(user) != SQLITE_DONE || sqlite3_reset(user) != SQLITE_OK;
    }
    if (!failed) failed = sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK;
    if (failed) fprintf(stderr, "rate fixture failed: %s\n", db ? sqlite3_errmsg(db) : "no database");
    sqlite3_finalize(route); sqlite3_finalize(user); sqlite3_close(db);
    (void)client;
    return failed;
}

static int token(const char *user, const char *role, char *authorization, size_t capacity)
{
    char raw[2048];
    if (st_security_issue_local_token(user, "t1", role, getenv("SPECUS_AUTH_JWT_SECRET"), 600, raw, sizeof(raw))) return 1;
    int length = snprintf(authorization, capacity, "Bearer %s", raw);
    return length < 0 || (size_t)length >= capacity;
}

static int request(const char *authorization, long long id, char *response, size_t capacity)
{
    char path[128]; snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/connectivity-check", id);
    return st_admin_build_response_with_auth("POST", path, authorization, "", response, capacity) < 0;
}

static int response_matches(const char *response, long long id, int status, const char *code, int retry)
{
    const char *body = strstr(response, "\r\n\r\n");
    if (!body) return 1;
    body += 4;
    char prefix[32], retry_value[32], length[32], expected[2048];
    snprintf(prefix, sizeof(prefix), "HTTP/1.1 %d ", status);
    snprintf(retry_value, sizeof(retry_value), "%d", retry);
    snprintf(length, sizeof(length), "%zu", strlen(body));
    if (status != 200) snprintf(expected, sizeof(expected), "{\"code\":\"%s\"}", code);
    else snprintf(expected, sizeof(expected),
        "{\"schemaVersion\":1,\"kind\":\"http-route\",\"routeId\":%lld,\"checkedAt\":\"" CHECKED_AT "\","
        "\"outcome\":\"failed\",\"stoppedAt\":\"device-online\",\"code\":\"DEVICE_OFFLINE\",\"totalMs\":0,\"requests\":[],"
        "\"stages\":[{\"stage\":\"configured\",\"result\":\"passed\",\"code\":\"CONFIGURED\",\"atMs\":0},"
        "{\"stage\":\"device-online\",\"result\":\"failed\",\"code\":\"DEVICE_OFFLINE\",\"atMs\":0},"
        "{\"stage\":\"target-reachable\",\"result\":\"skipped\"},{\"stage\":\"access-succeeded\",\"result\":\"skipped\"}]}", id);
    int failed = strncmp(response, prefix, strlen(prefix)) != 0 || strcmp(body, expected) != 0;
    failed |= assert_header(response, "Cache-Control", "private, no-store")
        | assert_header(response, "Retry-After", retry ? retry_value : NULL)
        | assert_header(response, "Content-Type", "application/json")
        | assert_header(response, "Content-Length", length);
    if (failed) fprintf(stderr, "rate HTTP route%lld expected%d/%s retry%d, got:\n%s\n", id, status, code, retry, response);
    return failed;
}

static int events(const char *vector, const char *db)
{
    char *rate = st_json_get_top_level_raw(vector, "rate");
    char **items = NULL; size_t count = 0;
    int failed = !rate || st_json_get_raw_array(rate, "events", &items, &count) != 0 || count == 0;
    long long max_route = 0;
    for (size_t i = 0; !failed && i < count; ++i) {
        long long id = 0; if (st_json_get_i64(items[i], "routeId", &id) || id <= 0 || id > 10000) failed = 1;
        if (id > max_route) max_route = id;
    }
    char alice[2300], admin[2300];
    if (!failed) failed = fixture(db, (int)max_route, 0)
        || create_bearer(db, "alice", "USER", alice, sizeof(alice))
        || create_bearer(db, "admin", "ADMIN", admin, sizeof(admin));
    rate_device state = {.device = {.now = CLOCK_ORIGIN_MS, .check_start = CLOCK_ORIGIN_MS}};
    st_connectivity_device callbacks = {presence, probe, now_ms, log_line, &state};
    if (!failed) st_admin_set_connectivity_device(&callbacks);
    size_t admitted_count = 0;
    for (size_t i = 0; !failed && i < count; ++i) {
        long long at = 0, id = 0; int admitted = 0, status = 0, retry = 0; char user[32], code[64];
        failed = st_json_get_i64(items[i], "atMs", &at) || st_json_get_i64(items[i], "routeId", &id)
            || st_json_get_bool(items[i], "admitted", &admitted);
        copy_string(items[i], "username", user, sizeof(user)); copy_string(items[i], "code", code, sizeof(code));
        if (strcmp(user, "alice") != 0 && strcmp(user, "admin") != 0) failed = 1;
        if (!admitted) failed |= st_json_get_int(items[i], "httpStatus", &status)
            || st_json_get_int(items[i], "retryAfterSeconds", &retry);
        state.device.now = CLOCK_ORIGIN_MS + at;
        char response[4096] = {0};
        if (!failed) failed = request(strcmp(user, "admin") == 0 ? admin : alice, id, response, sizeof(response))
            || response_matches(response, id, admitted ? 200 : status, admitted ? "DEVICE_OFFLINE" : code, retry);
        if (admitted) ++admitted_count;
        if (!failed && (state.presences != admitted_count || state.device.probes != 0U)) failed = 1;
        if (!failed) printf("connectivity rate HTTP event %zu passed\n", i);
    }
    if (!failed) failed = state.device.refusal_logs != 2U || state.device.logs != admitted_count + 2U
        || strcmp(state.device.refusal_lines[0], "[connectivity-check] tenant=t1 user=alice route=1 refused code=CHECK_RATE_LIMITED retryAfter=10") != 0
        || strcmp(state.device.refusal_lines[1], "[connectivity-check] tenant=t1 user=admin route=1 refused code=CHECK_RATE_LIMITED retryAfter=10") != 0;
    if (failed) fprintf(stderr, "rate HTTP event replay/log/suppression differs\n");
    else printf("connectivity rate HTTP:all%zu events/private headers/full bodies/two throttled refusal logs passed\n", count);
    st_json_free_string_array(items, count); free(rate);
    return failed;
}

static int capacity(const char *db)
{
    int failed = fixture(db, (int)ST_CONNECTIVITY_MAX_KEYS + 1, (int)ST_CONNECTIVITY_MAX_KEYS + 1);
    rate_device state = {.device = {.now = CLOCK_ORIGIN_MS, .check_start = CLOCK_ORIGIN_MS}};
    st_connectivity_device callbacks = {presence, probe, now_ms, log_line, &state};
    if (!failed) st_admin_set_connectivity_device(&callbacks);
    for (unsigned key = 1; !failed && key <= ST_CONNECTIVITY_MAX_KEYS; ++key) {
        char user[32], bearer[2300], response[4096] = {0}; snprintf(user, sizeof(user), "u%u", key);
        failed = token(user, "ADMIN", bearer, sizeof(bearer))
            || request(bearer, key, response, sizeof(response))
            || response_matches(response, key, 200, "DEVICE_OFFLINE", 0)
            || state.presences != key || state.device.probes != 0U || state.device.logs != key;
        if (!failed && key % 1000U == 0U) { printf("connectivity rate HTTP capacity: %u actual route/user keys admitted\n", key); fflush(stdout); }
    }
    char fresh[2300], first[2300], response[4096] = {0};
    if (!failed) failed = token("u10001", "ADMIN", fresh, sizeof(fresh)) || token("u1", "ADMIN", first, sizeof(first));
    if (!failed) {
        state.device.now = CLOCK_ORIGIN_MS + 1;
        failed = request(fresh, 10001, response, sizeof(response))
            || response_matches(response, 10001, 503, "CHECK_BUSY", 1)
            || state.presences != ST_CONNECTIVITY_MAX_KEYS || state.device.logs != ST_CONNECTIVITY_MAX_KEYS;
    }
    if (!failed) {
        failed = request(first, 1, response, sizeof(response))
            || response_matches(response, 1, 429, "CHECK_RATE_LIMITED", 10)
            || state.presences != ST_CONNECTIVITY_MAX_KEYS || state.device.refusal_logs != 1U;
    }
    if (!failed) {
        state.device.now = CLOCK_ORIGIN_MS + ST_CONNECTIVITY_ROUTE_INTERVAL_MS;
        failed = request(fresh, 10001, response, sizeof(response))
            || response_matches(response, 10001, 503, "CHECK_BUSY", 1)
            || state.presences != ST_CONNECTIVITY_MAX_KEYS || state.device.logs != ST_CONNECTIVITY_MAX_KEYS + 1U;
    }
    if (!failed) {
        state.device.now = CLOCK_ORIGIN_MS + ST_CONNECTIVITY_USER_INTERVAL_MS;
        failed = request(fresh, 10001, response, sizeof(response))
            || response_matches(response, 10001, 200, "DEVICE_OFFLINE", 0)
            || state.presences != ST_CONNECTIVITY_MAX_KEYS + 1U || state.device.logs != ST_CONNECTIVITY_MAX_KEYS + 2U;
    }
    if (!failed && state.device.probes != 0U) failed = 1;
    if (failed) fprintf(stderr, "actual10000 HTTP key-table boundary differs\n");
    else puts("connectivity rate HTTP capacity:actual10000 keys,503/no-run,live-key preserved,10s user-full,30s recovery passed");
    return failed;
}

static int isolated(int full, const char *vector)
{
    char directory[] = "/tmp/specus-connectivity-rate-http-XXXXXX";
    if (!mkdtemp(directory)) return 1;
    char db[256]; snprintf(db, sizeof(db), "%s/rate.db", directory);
    fflush(NULL);
    pid_t child = fork();
    if (child == 0) { alarm(110); int failed = full ? capacity(db) : events(vector, db); fflush(NULL); exit(failed ? 1 : 0); }
    int status = 0;
    int failed = child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
    const char *suffixes[] = {"", "-wal", "-shm", "-journal"};
    for (size_t i = 0; i < 4U; ++i) {
        char file[280]; snprintf(file, sizeof(file), "%s%s", db, suffixes[i]);
        if (unlink(file) != 0 && errno != ENOENT) failed = 1;
    }
    if (rmdir(directory) != 0) failed = 1;
    return failed;
}

int main(int argc, char **argv)
{
    int run_events = argc == 1 || (argc == 2 && strcmp(argv[1], "--events") == 0);
    int run_capacity = argc == 1 || (argc == 2 && strcmp(argv[1], "--capacity") == 0);
    if (!run_events && !run_capacity) return 1;
    char *vector = read_vector();
    int failed = !vector || parameters(vector);
    if (!failed && run_events) failed = isolated(0, vector);
    if (!failed && run_capacity) failed = isolated(1, vector);
    free(vector);
    return failed ? 1 : 0;
}
