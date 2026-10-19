#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "connectivity_http_test_support.h"

/* Observe every production SQLite connection, without adding a production loader/test hook.
 * Count any authorization action naming the route table, not just successful SELECT results.
 * Each no-interaction scenario finishes with a real successful request as a positive control. */
static unsigned route_actions;
static unsigned observed_connections;

static int observe_table(void *ctx, int action, const char *first, const char *second,
                         const char *database, const char *trigger)
{
    (void)ctx; (void)action; (void)database; (void)trigger;
    if ((first && strcmp(first, "http_route_mapping") == 0)
        || (second && strcmp(second, "http_route_mapping") == 0)) ++route_actions;
    return SQLITE_OK;
}

static int observe_connection(sqlite3 *db, const char **error, const struct sqlite3_api_routines *api)
{
    (void)error; (void)api;
    ++observed_connections;
    return sqlite3_set_authorizer(db, observe_table, NULL);
}

static int resource_request(const char *id, const char *bearer, const char *body,
                             const char *type, char *response, size_t capacity)
{
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/http-routes/%s/connectivity-check", id);
    /* with_content(NULL auth) is a legacy default-admin helper; the socket path does not allow
     * that fallback. Use the strict wrapper for the genuinely unauthenticated scenario. */
    if (bearer == NULL)
        return st_admin_build_response_with_auth("POST", path, NULL, body, response, capacity);
    return st_admin_build_response_with_content("POST", path, bearer, type,
              (const uint8_t *)body, body == NULL ? 0U : strlen(body), response, capacity);
}

static int expect_response(const char *label, const char *raw, int status, const char *body, int retry)
{
    char prefix[32], retry_value[32], length[32];
    snprintf(prefix, sizeof(prefix), "HTTP/1.1 %d ", status);
    snprintf(retry_value, sizeof(retry_value), "%d", retry);
    const char *actual = strstr(raw, "\r\n\r\n");
    if (actual == NULL) return 1;
    actual += 4;
    snprintf(length, sizeof(length), "%zu", strlen(actual));
    int failed = strncmp(raw, prefix, strlen(prefix)) != 0 || strcmp(actual, body) != 0;
    failed |= assert_header(raw, "Cache-Control", "private, no-store")
        | assert_header(raw, "Retry-After", retry ? retry_value : NULL)
        | assert_header(raw, "Content-Type", "application/json")
        | assert_header(raw, "Content-Length", length);
    if (failed) fprintf(stderr, "%s: response differs\n%s\nwant body: %s\n", label, raw, body);
    return failed;
}

static int expect_offline_id(const char *label, const char *response, const char *id)
{
    char body[2048];
    snprintf(body, sizeof(body), "{\"schemaVersion\":1,\"kind\":\"http-route\",\"routeId\":%s,"
        "\"checkedAt\":\"" CHECKED_AT "\",\"outcome\":\"failed\",\"stoppedAt\":\"device-online\","
        "\"code\":\"DEVICE_OFFLINE\",\"totalMs\":0,\"requests\":[],\"stages\":["
        "{\"stage\":\"configured\",\"result\":\"passed\",\"code\":\"CONFIGURED\",\"atMs\":0},"
        "{\"stage\":\"device-online\",\"result\":\"failed\",\"code\":\"DEVICE_OFFLINE\",\"atMs\":0},"
        "{\"stage\":\"target-reachable\",\"result\":\"skipped\"},"
        "{\"stage\":\"access-succeeded\",\"result\":\"skipped\"}]}", id);
    return expect_response(label, response, 200, body, 0)
        || strstr(response, "10.0.0.5") != NULL || strstr(response, "/base") != NULL;
}

static int expect_offline(const char *label, const char *response)
{
    return expect_offline_id(label, response, "7");
}

static int positive_observer_control(const char *root)
{
    char response[8192] = {0};
    route_actions = observed_connections = 0;
    int failed = resource_request("7", root, "", "application/json", response, sizeof(response)) < 0
        || expect_offline("SQLite observer positive control", response)
        || route_actions == 0U || observed_connections == 0U;
    if (failed) fprintf(stderr, "SQLite observer did not see a normal route lookup\n");
    return failed;
}

static int invalid_body(const char *root, const char *body, fake_device *device)
{
    char response[8192] = {0};
    route_actions = 0;
    int failed = resource_request("999", root, body, "application/json", response, sizeof(response)) < 0
        || expect_response("invalid body before unknown route", response, 400,
                              "{\"code\":\"CHECK_REQUEST_INVALID\"}", 0)
        || route_actions != 0U || device->probes != 0U || device->logs != 0U;
    if (failed) fprintf(stderr, "invalid body reached route table (%u actions): %s\n", route_actions, body);
    return failed;
}

static int invalid_corpus(const char *root, fake_device *device)
{
    static const char *const bodies[] = {
        "[]", "null", "1", "\"/\"", "{", "{} {}", "{}x", "{\"path\":1}", "{\"path\":null}",
        "{\"path\":[\"/\"]}", "{\"path\":{}}", "{\"other\":\"/\"}", "{\"path\":\"/\",\"timeoutMs\":5}"
    };
    static const char *const paths[] = {
        "", "healthz", "//evil.example/x", "/a?b=1", "/a#frag", "/a b", "/a\\\\b", "/a\\tb",
        "/%zz", "/%2", "/a%", "/./a", "/a/..", "/a/%2e%2E/b", "/%2E", "/caf\\u00e9",
        "/a\\\"b", "/a<b>", "/a[0]"
    };
    int failed = 0;
    size_t count = 0;
    for (size_t i = 0; i < sizeof(bodies) / sizeof(bodies[0]); ++i) {
        failed |= invalid_body(root, bodies[i], device); ++count;
    }
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
        char body[256];
        snprintf(body, sizeof(body), "{\"path\":\"%s\"}", paths[i]);
        failed |= invalid_body(root, body, device); ++count;
    }
    const size_t lengths[] = {4090U, 256U};
    for (size_t i = 0; i < 2U; ++i) {
        char path[4092], body[4120];
        path[0] = '/'; memset(path + 1, 'a', lengths[i]); path[lengths[i] + 1U] = '\0';
        snprintf(body, sizeof(body), "{\"path\":\"%s\"}", path);
        failed |= invalid_body(root, body, device); ++count;
    }
    if (count != 34U) failed = 1;
    if (!failed) failed |= positive_observer_control(root);
    if (!failed) puts("connectivity HTTP resource: all34 invalid bodies rejected before route-table access; observer positive control passed");
    return failed;
}

/* Modes: owner/admin offline; seven visibility/ID cases; unauthenticated; invalid corpus;
 * twelve valid request forms (fresh checker each); unreadable route records; shared route rate. */
static int resource_scenario(int mode, const char *db)
{
    fake_device device = {.now = CHECK_START_MS, .check_start = CHECK_START_MS};
    st_connectivity_device callbacks = {fake_presence, fake_probe, fake_now, fake_log, &device};
    char alice[2300], root[2300], bob[2300], other[2300];
    setenv("SPECUS_DATABASE_PATH", db, 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "connectivity-resource-test-only-secret-32-bytes", 1);
    setenv("SPECUS_AUTH_USERNAME", "fixture-builtin-admin", 1);
    setenv("SPECUS_AUTH_TENANT_ID", "fixture-builtin-tenant", 1);
    int failed = st_storage_init(db, 0) != 0
        || create_bearer(db, "alice", "USER", alice, sizeof(alice))
        || create_bearer(db, "root", "ADMIN", root, sizeof(root))
        || create_bearer(db, "bob", "USER", bob, sizeof(bob))
        || create_bearer_in_tenant(db, "t2", "root", "ADMIN", other, sizeof(other))
        || create_route(db, 7, "alice", 1, 1, 1)
        || exec_sql(db, "UPDATE http_route_mapping SET target_base_url='http://10.0.0.5:8080/base' WHERE id=7");
    if (failed) return 1;
    st_admin_set_connectivity_device(&callbacks);
    if (mode == 17) {
        if (exec_sql(db, "DROP TABLE http_route_mapping; CREATE TABLE http_route_mapping(id INTEGER PRIMARY KEY)")) return 1;
    }
    route_actions = observed_connections = 0;
    if (sqlite3_auto_extension((void (*)(void))observe_connection) != SQLITE_OK) return 1;
    char response[8192] = {0};
    if (mode <= 1) {
        failed = resource_request("7", mode == 0 ? alice : root, "", "application/json", response, sizeof(response)) < 0
            || expect_offline(mode == 0 ? "owner offline" : "tenant admin offline", response)
            || device.probes != 0U || device.logs != 1U || route_actions == 0U;
    } else if (mode == 2) {
        const char *ids[] = {"999", "7", "7", "abc", "0", "-7", "99999999999999999999"};
        const char *tokens[] = {root, bob, other, alice, alice, alice, alice};
        for (size_t i = 0; i < 7U; ++i) {
            failed |= resource_request(ids[i], tokens[i], "", "application/json", response, sizeof(response)) < 0
                || expect_response("same404 visibility and IDs", response, 404,
                                      "{\"code\":\"CHECK_TARGET_NOT_FOUND\"}", 0);
        }
        failed |= device.probes != 0U || device.logs != 0U;
    } else if (mode == 3) {
        failed = resource_request("7", NULL, "{\"path\":\"/\"}", "application/json", response, sizeof(response)) < 0
            || expect_response("no management session", response, 401,
                                  "{\"error\":\"missing or invalid bearer token\"}", 0)
            || route_actions != 0U || device.probes != 0U || device.logs != 0U;
        if (!failed) failed |= positive_observer_control(root);
        if (!failed) puts("connectivity HTTP resource:401 no route-table access; observer positive control passed");
    } else if (mode == 4) {
        failed = invalid_corpus(root, &device);
    } else if (mode <= 16) {
        static const char *const bodies[] = {NULL, " \r\n\t", "{}", "{\"path\":\"/\"}",
            "{\"path\":\"/a//b\"}", "{\"path\":\"/%2Fx/%41\"}", "{\"path\":\"/.well-known/health\"}",
            "{\"path\":\"/a..b/...\"}", "{\"path\":\"/-._~!$&'()*+,;=:@\"}", NULL,
            "{\"path\":\"/healthz\"}", "{\"path\":\"/healthz\"}"};
        int index = mode - 5;
        char longest[280];
        const char *body = bodies[index];
        if (index == 9) {
            char path[257]; path[0] = '/'; memset(path + 1, 'a', 255U); path[256] = '\0';
            snprintf(longest, sizeof(longest), "{\"path\":\"%s\"}", path); body = longest;
        }
        const char *type = index == 10 ? "text/plain" : index == 11 ? NULL : "application/json";
        failed = resource_request("7", root, body, type, response, sizeof(response)) < 0
            || expect_offline("valid request corpus", response) || device.probes != 0U || device.logs != 1U;
    } else if (mode == 17) {
        failed = resource_request("7", root, "", "application/json", response, sizeof(response)) < 0
            || expect_response("unreadable route records", response, 503, "{\"code\":\"CHECK_UNAVAILABLE\"}", 1)
            || device.probes != 0U || device.logs != 0U || route_actions == 0U;
    } else if (mode == 18) {
        failed = resource_request("7", alice, "", "application/json", response, sizeof(response)) < 0
            || expect_offline("owner check before shared rate", response);
        failed |= resource_request("7", root, "", "application/json", response, sizeof(response)) < 0
            || expect_response("tenant admin shares route rate", response, 429,
                                  "{\"code\":\"CHECK_RATE_LIMITED\"}", 10)
            || device.probes != 0U;
    } else if (mode <= 27) {
        static const char *const ids[] = {"9223372036854775807", "+7", "000000000000000000007",
            "9223372036854775808", "+", " 7", "7 ", "++7", "-0"};
        int index = mode - 19;
        if (index == 0) failed |= exec_sql(db, "UPDATE http_route_mapping SET id=9223372036854775807 WHERE id=7");
        route_actions = 0;
        failed |= resource_request(ids[index], root, "", "application/json", response, sizeof(response)) < 0;
        if (index < 3) {
            failed |= expect_offline_id("positive Java Long route ID", response, index == 0 ? ids[0] : "7")
                || route_actions == 0U || device.probes != 0U || device.logs != 1U;
        } else {
            failed |= expect_response("invalid/overflowing route ID", response, 404,
                                          "{\"code\":\"CHECK_TARGET_NOT_FOUND\"}", 0)
                || route_actions != 0U || device.probes != 0U || device.logs != 0U;
        }
    } else failed = 1;
    if (sqlite3_cancel_auto_extension((void (*)(void))observe_connection) != 1) failed = 1;
    if (failed) fprintf(stderr, "HTTP resource scenario %d failed\n", mode);
    return failed;
}

int run_connectivity_http_resource_tests(void)
{
    for (int mode = 0; mode < 28; ++mode) {
        char directory[] = "/tmp/specus-connectivity-resource-XXXXXX";
        if (mkdtemp(directory) == NULL) return 1;
        char db[256]; snprintf(db, sizeof(db), "%s/resource.db", directory);
        fflush(NULL);
        pid_t child = fork();
        if (child == 0) { alarm(30); int failed = resource_scenario(mode, db); fflush(NULL); exit(failed ? 1 : 0); }
        int status = 0;
        int failed = child < 0 || waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0;
        const char *suffixes[] = {"", "-wal", "-shm", "-journal"};
        for (size_t i = 0; i < 4U; ++i) {
            char file[280]; snprintf(file, sizeof(file), "%s%s", db, suffixes[i]);
            if (unlink(file) != 0 && errno != ENOENT) failed = 1;
        }
        if (rmdir(directory) != 0) failed = 1;
        if (failed) return 1;
        printf("connectivity HTTP resource scenario %d passed\n", mode);
    }
    puts("connectivity HTTP resource:7 reference methods,28 isolated scenarios,34 invalid/12 valid bodies and9 ASCII Long-ID boundaries passed");
    return 0;
}
