/* Reuse the real HTTP/WebSocket fixture with its process-local clock. */
#define main original_request_main
#include "websocket_ticket_request_tests.c"
#undef main

static pthread_barrier_t issue_barrier;
typedef struct { int scope, status; char ticket[64]; } issuer_result;
static void *issue_concurrently(void *argument)
{
    issuer_result *result = argument;
    int barrier = pthread_barrier_wait(&issue_barrier);
    CHECK(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
    char response[8192];
    result->status = http("POST", "/api/admin/ws-tickets", "127.16.0.1",
        result->scope ? "{\"endpoint\":\"client-messages\"}" : "{\"endpoint\":\"connections\"}", response);
    if (result->status == 200) {
        const char *body = strstr(response, "\r\n\r\n"); CHECK(body != NULL);
        CHECK(st_websocket_ticket_json_string(body+4, "ticket", result->ticket, sizeof(result->ticket), 1) == 0);
    }
    return NULL;
}
static int issue_status(int scope)
{
    char response[8192];
    const char *bodies[] = {"{\"endpoint\":\"connections\"}","{\"endpoint\":\"client-messages\"}",
        "{\"roomId\":\"quota-room\",\"peerId\":\"quota-peer\",\"displayName\":\"quota\"}"};
    return http("POST", scope == 2 ? "/api/public/transfer/ws-tickets" : "/api/admin/ws-tickets", "127.16.0.1", bodies[scope], response);
}
static void clear_persistent(void)
{
    sqlite3 *db = NULL; CHECK(sqlite3_open(database, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "DELETE FROM specus_websocket_ticket", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_close(db) == SQLITE_OK);
}
static void quota_scenarios(void)
{
    const char *management = "{\"tenantId\":\"default\",\"wsUser\":\"admin\",\"uid\":\"\",\"admin\":true}";
    const char *public_attributes = "{\"roomId\":\"quota-room\",\"peerId\":\"quota-peer\",\"displayName\":\"quota\",\"publicAddress\":\"127.16.0.1\",\"roomKey\":\"\",\"roomRole\":\"member\",\"sharedRoom\":false,\"discoverable\":true}";
    for (int persistent = 0; persistent < 2; ++persistent) {
        st_websocket_ticket_reset_memory_scope(NULL); clear_persistent();
        if (persistent) CHECK(setenv("SPECUS_DATABASE_PATH", database, 1) == 0);
        else CHECK(unsetenv("SPECUS_DATABASE_PATH") == 0);
        set_clock(base_seconds, 0L);
        char token[64], expiry[40];
        /* Prefill through the real shared service, then race actual HTTP issuers for the last slot. */
        for (unsigned i = 0U; i < 1023U; ++i) {
            CHECK(st_websocket_ticket_issue(i % 2U ? "connections" : "client-messages", management,
                "127.16.0.1", token, expiry) == 0);
        }
        issuer_result results[8] = {{0}}; pthread_t threads[8];
        CHECK(pthread_barrier_init(&issue_barrier, NULL, 9U) == 0);
        for (unsigned i = 0U; i < 8U; ++i) {
            results[i].scope = (int)(i % 2U);
            CHECK(pthread_create(&threads[i], NULL, issue_concurrently, &results[i]) == 0);
        }
        int barrier = pthread_barrier_wait(&issue_barrier);
        CHECK(barrier == 0 || barrier == PTHREAD_BARRIER_SERIAL_THREAD);
        unsigned successes = 0U, refusals = 0U, winner = 0U;
        for (unsigned i = 0U; i < 8U; ++i) {
            CHECK(pthread_join(threads[i], NULL) == 0);
            if (results[i].status == 200) { ++successes; winner = i; }
            else { CHECK(results[i].status == 429); ++refusals; }
        }
        CHECK(pthread_barrier_destroy(&issue_barrier) == 0);
        CHECK(successes == 1U && refusals == 7U);
        CHECK(issue_status(0) == 429 && issue_status(1) == 429);
        CHECK(issue_status(2) == 200);
        for (unsigned i = 0U; i < 1023U; ++i) {
            CHECK(st_websocket_ticket_issue("public-transfer", public_attributes, "127.16.0.1", token, expiry) == 0);
        }
        CHECK(issue_status(2) == 429);
        /* The public limit is per source: one full source does not lock out another browser. */
        char other_source[8192];
        CHECK(http("POST", "/api/public/transfer/ws-tickets", "127.16.0.2",
                   "{\"roomId\":\"quota-room\",\"peerId\":\"other-peer\",\"displayName\":\"other\"}", other_source) == 200);
        /* Free one management slot while the public group remains completely full. */
        char path[256];
        snprintf(path, sizeof(path), "%s?ticket=%s", ws_paths[results[winner].scope], results[winner].ticket);
        CHECK(websocket(path, "127.16.0.1") == 101 && websocket(path, "127.16.0.1") == 403);
        CHECK(issue_status(1 - results[winner].scope) == 200 && issue_status(2) == 429);
        set_clock(base_seconds + 45LL, 0L);
        CHECK(issue_status(0) == 429 && issue_status(1) == 429 && issue_status(2) == 429);
        set_clock(base_seconds + 45LL, 100L);
        CHECK(issue_status(0) == 200 && issue_status(2) == 200);
        if (persistent) {
            sqlite3 *db = NULL; CHECK(sqlite3_open(database, &db) == SQLITE_OK);
            CHECK(count(db, "SELECT count(*) FROM specus_websocket_ticket") == 2);
            CHECK(sqlite3_close(db) == SQLITE_OK);
        }
        printf("ticket quota: persistent%d management1024 shared across2 scopes; actual8 concurrent HTTP issuers exactly1 success/7 quota429; public1024 independent; consume recovers slot; exact expiry still full/+100ns strict purge passed\n", persistent);
    }
    st_websocket_ticket_reset_memory_scope(NULL); clear_persistent();
}
/* Public tickets: a per-source limit, and a total one that bounds memory across sources. */
static void public_limit_scenarios(void)
{
    const char *attributes = "{\"roomId\":\"limit-room\",\"peerId\":\"limit-peer\",\"displayName\":\"limit\",\"publicAddress\":\"127.16.0.9\",\"roomKey\":\"\",\"roomRole\":\"member\",\"sharedRoom\":false,\"discoverable\":true}";
    st_websocket_ticket_set_public_limits_for_tests(4U, 6U);
    for (int persistent = 0; persistent < 2; ++persistent) {
        st_websocket_ticket_reset_memory_scope(NULL); clear_persistent();
        if (persistent) CHECK(setenv("SPECUS_DATABASE_PATH", database, 1) == 0);
        else CHECK(unsetenv("SPECUS_DATABASE_PATH") == 0);
        set_clock(base_seconds, 0L);
        char token[64], expiry[40];
        for (unsigned i = 0U; i < 4U; ++i)
            CHECK(st_websocket_ticket_issue("public-transfer", attributes, "198.51.100.1", token, expiry) == 0);
        CHECK(st_websocket_ticket_issue("public-transfer", attributes, "198.51.100.1", token, expiry) == -2);
        CHECK(st_websocket_ticket_issue("public-transfer", attributes, "198.51.100.2", token, expiry) == 0);
        CHECK(st_websocket_ticket_issue("public-transfer", attributes, NULL, token, expiry) == 0);
        /* Six active public tickets: the total limit now refuses every source. */
        CHECK(st_websocket_ticket_issue("public-transfer", attributes, "198.51.100.3", token, expiry) == -2);
        CHECK(st_websocket_ticket_issue("public-transfer", attributes, NULL, token, expiry) == -2);
        printf("public ticket limits: persistent%d per-source4 refused the fifth, other sources admitted until total6\n",
               persistent);
    }
    st_websocket_ticket_set_public_limits_for_tests(1024U, 16384U);
    st_websocket_ticket_reset_memory_scope(NULL); clear_persistent();
}
int main(void)
{
    CHECK(atexit(cleanup) == 0);
    CHECK(setenv("SPECUS_AUTH_USERNAME", "admin", 1) == 0 && setenv("SPECUS_AUTH_TENANT_ID", "default", 1) == 0
        && setenv("SPECUS_AUTH_PASSWORD", "ticket-test-admin-pass", 1) == 0 && setenv("SPECUS_AUTH_JWT_SECRET", "ticket-test-jwt-key", 1) == 0
        && setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0 && setenv("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "0", 1) == 0
        && setenv("SPECUS_TRUSTED_PROXIES", "", 1) == 0);
    snprintf(database, sizeof(database), "/tmp/specus-ticket-quota-XXXXXX"); int fd = mkstemp(database); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(database, 0) == 0 && setenv("SPECUS_DATABASE_PATH", database, 1) == 0);
    char bearer[2200]; CHECK(st_security_issue_local_token("admin", "default", "ADMIN", "ticket-test-jwt-key", 600, bearer, sizeof(bearer)) == 0);
    CHECK(snprintf(auth, sizeof(auth), "Bearer %s", bearer) > 0);
    static st_admin_server server; start_api(&server); quota_scenarios(); public_limit_scenarios();
    puts("ticket quota:2 actual TCP memory/database scenarios passed; prefilling uses real shared service, not1024 simultaneous HTTP requests; account lifecycle and main restart have separate suites");
    return 0;
}
