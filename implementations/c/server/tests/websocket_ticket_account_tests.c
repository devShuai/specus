#define main original_request_main
#include "websocket_ticket_request_tests.c"
#undef main

static char root_authorization[2400];
static void actor(const st_storage_management_user *user)
{
    if (user == NULL) { strcpy(auth, root_authorization); return; }
    char bearer[2200];
    CHECK(st_security_issue_local_token_for_account(user->username, user->tenant_id, user->role, user->account_key,
        "ticket-test-jwt-key", 600, bearer, sizeof(bearer)) == 0);
    CHECK(snprintf(auth, sizeof(auth), "Bearer %s", bearer) > 0);
}
static int present(const char *token)
{
    uint8_t digest[ST_SHA256_LEN]; char hash[65];
    st_sha256((const uint8_t *)token, strlen(token), digest); st_hex_encode(digest, sizeof(digest), hash);
    sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_open(database, &db) == SQLITE_OK);
    CHECK(sqlite3_prepare_v2(db, "SELECT count(*) FROM specus_websocket_ticket WHERE token_hash=?1", -1, &stmt, NULL) == SQLITE_OK);
    CHECK(sqlite3_bind_text(stmt, 1, hash, -1, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW);
    int found = sqlite3_column_int(stmt, 0); CHECK(sqlite3_finalize(stmt) == SQLITE_OK && sqlite3_close(db) == SQLITE_OK); return found;
}
static void sql(const char *text)
{
    sqlite3 *db = NULL; CHECK(sqlite3_open(database, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, text, NULL, NULL, NULL) == SQLITE_OK); CHECK(sqlite3_close(db) == SQLITE_OK);
}
static void pair(const st_storage_management_user *user, char tokens[2][64])
{
    actor(user); char expiry[40];
    for (int scope = 0; scope < 2; ++scope) { issue(scope, "127.17.0.1", tokens[scope], expiry); CHECK(present(tokens[scope]) == 1); }
}
static void use_pair(char tokens[2][64], int expected)
{
    for (int scope = 0; scope < 2; ++scope) {
        char path[256]; snprintf(path, sizeof(path), "%s?ticket=%s", ws_paths[scope], tokens[scope]);
        CHECK(websocket(path, "127.17.0.1") == expected);
    }
}
static int mutate(const char *method, const char *body)
{
    actor(NULL); char response[8192];
    return http(method, "/api/admin/users/MIXED", "127.17.0.1", body, response);
}
static int authenticated_issue_status(const st_storage_management_user *user)
{
    actor(user); char response[8192];
    return http("POST", "/api/admin/ws-tickets", "127.17.0.1", "{\"endpoint\":\"connections\"}", response);
}
static int refresh_status(const st_storage_management_user *user)
{
    actor(user); char response[8192];
    return http("POST", "/auth/refresh", "127.17.0.1", NULL, response);
}
static void account_lifecycle(void)
{
    st_storage_management_user user, bystander, foreign, current;
    CHECK(st_storage_create_management_user(database, "MiXeD", "default", "unused", "USER", 1, &user) == 0);
    CHECK(st_storage_create_management_user(database, "Bystander", "default", "unused", "USER", 1, &bystander) == 0);
    CHECK(st_storage_create_management_user(database, "MiXeD", "foreign", "unused", "USER", 1, &foreign) == 0);
    char bystander_ticket[64], foreign_ticket[64], public_ticket[64], expiry[40];
    actor(&bystander); issue(0, "127.17.0.1", bystander_ticket, expiry);
    actor(&foreign); issue(1, "127.17.0.1", foreign_ticket, expiry);
    actor(NULL); issue(2, "127.17.0.1", public_ticket, expiry);
    char tokens[2][64]; pair(&user, tokens);
    sql("CREATE TRIGGER abort_account_tickets BEFORE DELETE ON specus_websocket_ticket BEGIN SELECT RAISE(ABORT,'controlled ticket rollback');END");
    /* Keep existing C failure classification explicit; this is not Java HTTP error-code acceptance. */
    CHECK(mutate("PUT", "{\"role\":\"USER\",\"enabled\":false}") == 409);
    CHECK(st_storage_get_management_user_in_tenant(database, "default", "mixed", &current) == 0 && current.enabled == 1 && strcmp(current.account_key, user.account_key) == 0);
    CHECK(present(tokens[0]) == 1 && present(tokens[1]) == 1);
    sql("DROP TRIGGER abort_account_tickets"); use_pair(tokens, 101);
    pair(&user, tokens);
    CHECK(mutate("PUT", "{\"role\":\"USER\",\"enabled\":false}") == 200);
    CHECK(present(tokens[0]) == 0 && present(tokens[1]) == 0);
    /* Java ManagementContextResolver: ordinary unresolved identity403; refresh401. */
    CHECK(authenticated_issue_status(&user) == 403 && refresh_status(&user) == 401);
    CHECK(mutate("PUT", "{\"role\":\"USER\",\"enabled\":true}") == 200);
    CHECK(st_storage_get_management_user_in_tenant(database, "default", "mixed", &current) == 0 && current.enabled == 1 && strcmp(current.account_key, user.account_key) == 0);
    use_pair(tokens, 403);
    pair(&user, tokens); use_pair(tokens, 101);
    puts("account ticket: actual HTTP disable rollback preserves account and both tickets; committed disable removes both scopes, re-enable preserves account ID but never revives old tickets; new tickets work");

    pair(&user, tokens);
    sql("CREATE TRIGGER abort_account_tickets BEFORE DELETE ON specus_websocket_ticket BEGIN SELECT RAISE(ABORT,'controlled ticket rollback');END");
    CHECK(mutate("DELETE", NULL) == 409);
    CHECK(st_storage_get_management_user_in_tenant(database, "default", "mixed", &current) == 0 && current.enabled == 1 && strcmp(current.account_key, user.account_key) == 0);
    CHECK(present(tokens[0]) == 1 && present(tokens[1]) == 1);
    sql("DROP TRIGGER abort_account_tickets"); use_pair(tokens, 101);
    pair(&user, tokens);
    CHECK(mutate("DELETE", NULL) == 204);
    CHECK(st_storage_get_management_user_in_tenant(database, "default", "mixed", &current) != 0);
    CHECK(present(tokens[0]) == 0 && present(tokens[1]) == 0);
    CHECK(authenticated_issue_status(&user) == 403 && refresh_status(&user) == 401);
    actor(NULL); char response[8192];
    CHECK(http("POST", "/api/admin/users", "127.17.0.1", "{\"username\":\"MiXeD\",\"password\":\"fresh-synthetic-password\",\"role\":\"USER\",\"enabled\":true}", response) == 201);
    CHECK(st_storage_get_management_user_in_tenant(database, "default", "mixed", &current) == 0 && strcmp(current.account_key, user.account_key) != 0);
    CHECK(authenticated_issue_status(&user) == 403 && refresh_status(&user) == 401); use_pair(tokens, 403);
    pair(&current, tokens); use_pair(tokens, 101);
    CHECK(present(bystander_ticket) == 1 && present(foreign_ticket) == 1 && present(public_ticket) == 1);
    char path[256];
    snprintf(path, sizeof(path), "/ws/connections?ticket=%s", bystander_ticket); CHECK(websocket(path, "127.17.0.1") == 101);
    snprintf(path, sizeof(path), "/ws/client-messages?ticket=%s", foreign_ticket); CHECK(websocket(path, "127.17.0.1") == 101);
    snprintf(path, sizeof(path), "/ws/public-transfer/discovery?ticket=%s", public_ticket); CHECK(websocket(path, "127.17.0.1") == 101);
    puts("account ticket: actual HTTP delete rollback preserves account and both tickets; committed delete removes tickets; same-name recreate has a new account ID, old JWT/tickets refused, fresh tickets work; same-tenant bystander, foreign namesake and public scope remain usable");
    puts("account ticket: existing C rollback statuses update409/delete404 recorded, not cross-language storage-error classification acceptance; JWTs are test-signed for actual account IDs, password login and CLI-main startup are not tested here");
}
int main(void)
{
    CHECK(atexit(cleanup) == 0);
    CHECK(setenv("SPECUS_AUTH_USERNAME", "admin", 1) == 0 && setenv("SPECUS_AUTH_TENANT_ID", "default", 1) == 0
        && setenv("SPECUS_AUTH_PASSWORD", "ticket-test-admin-pass", 1) == 0 && setenv("SPECUS_AUTH_JWT_SECRET", "ticket-test-jwt-key", 1) == 0
        && setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0 && setenv("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "0", 1) == 0
        && setenv("SPECUS_TRUSTED_PROXIES", "", 1) == 0);
    snprintf(database, sizeof(database), "/tmp/specus-ticket-account-XXXXXX"); int fd = mkstemp(database); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(database, 0) == 0 && setenv("SPECUS_DATABASE_PATH", database, 1) == 0);
    char bearer[2200]; CHECK(st_security_issue_local_token("admin", "default", "ADMIN", "ticket-test-jwt-key", 600, bearer, sizeof(bearer)) == 0);
    CHECK(snprintf(auth, sizeof(auth), "Bearer %s", bearer) > 0); strcpy(root_authorization, auth);
    set_clock(base_seconds, 123456700L); static st_admin_server server; start_api(&server); account_lifecycle();
    puts("account ticket: persistent-database real HTTP issuer/management/WS lifecycle passed; no unsupported memory-mode database accounts simulated");
    return 0;
}
