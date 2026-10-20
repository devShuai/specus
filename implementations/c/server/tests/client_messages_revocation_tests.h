/* Included by client_messages_tests.c: real sockets, shared vector, real SQLite rollback. */
#ifndef ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE
#define ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE "../../../protocol/test-vectors/management-accounts-v1.json"
#endif

static int revocation_sql(test_server *server, const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(server->db_path, &db);
    if (rc == SQLITE_OK) {
        sqlite3_busy_timeout(db, IO_TIMEOUT_MS);
        rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    }
    if (rc != SQLITE_OK) fprintf(stderr, "revocation fixture SQL: %s\n", error == NULL ? "open failed" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc == SQLITE_OK ? 0 : -1;
}

static int revocation_sign(const char *claims, char token[2048])
{
    char *name = st_json_get_top_level_string(claims, "sub");
    char *tenant = st_json_get_top_level_string(claims, "tenant_id");
    char *role = st_json_get_top_level_string(claims, "role");
    char *key = st_json_get_top_level_string(claims, "uid");
    int rc = name == NULL || tenant == NULL || role == NULL || key == NULL ? -1
        : st_security_issue_local_token_for_account(name, tenant, role, key, ADMIN_JWT_SECRET, 600, token, 2048U);
    free(name);
    free(tenant);
    free(role);
    free(key);
    return rc;
}

static char *revocation_vector(void)
{
    FILE *file = fopen(ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE, "rb");
    if (file == NULL) return NULL;
    long size = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    char *all = size > 0 ? malloc((size_t)size + 1U) : NULL;
    char *section = NULL;
    if (all != NULL && fseek(file, 0, SEEK_SET) == 0 && fread(all, 1, (size_t)size, file) == (size_t)size) {
        all[size] = '\0';
        section = st_json_get_top_level_raw(all, "webSocketRevocation");
    }
    free(all);
    fclose(file);
    return section;
}

static int revocation_seed(test_server *server, const char *vector)
{
    char **rows = NULL;
    size_t count = 0U;
    CHECK(st_json_get_raw_array(vector, "accounts", &rows, &count) == 0 && count > 0U, "vector accounts");
    for (size_t i = 0; i < count; ++i) {
        char *key = st_json_get_top_level_string(rows[i], "accountKey");
        char *name = st_json_get_top_level_string(rows[i], "loginName");
        char *tenant = st_json_get_top_level_string(rows[i], "tenantId");
        char *role = st_json_get_top_level_string(rows[i], "role");
        int enabled = 0;
        CHECK(key && name && tenant && role && st_json_get_bool(rows[i], "enabled", &enabled) == 0, "account fields");
        char *sql = sqlite3_mprintf("INSERT INTO specus_management_user"
            "(username,login_name,login_name_normalized,tenant_id,password_hash,role,enabled)"
            " VALUES(%Q,%Q,lower(%Q),%Q,'unused-hash',%Q,%d)", key, name, name, tenant, role, enabled);
        int rc = revocation_sql(server, sql);
        sqlite3_free(sql);
        free(key); free(name); free(tenant); free(role);
        CHECK(rc == 0, "seed vector account %zu", i);
    }
    st_json_free_string_array(rows, count);
    return 0;
}

static int scenario_revocation_vector(test_server *server)
{
    char *vector = revocation_vector();
    CHECK(vector != NULL && revocation_seed(server, vector) == 0, "load shared revocation vector");
    char *actor_claims = st_json_get_top_level_raw(vector, "actor");
    char actor[2048];
    CHECK(actor_claims != NULL && revocation_sign(actor_claims, actor) == 0, "actor token");
    free(actor_claims);
    char **bystanders = NULL;
    size_t bystander_count = 0U;
    CHECK(st_json_get_raw_array(vector, "bystanders", &bystanders, &bystander_count) == 0
        && bystander_count == 2U, "two vector bystanders");
    int bystander_fds[2];
    char *bystander_tickets[2];
    char *bystander_endpoints[2];
    char hello[4096];
    for (size_t i = 0; i < bystander_count; ++i) {
        char *claims = st_json_get_top_level_raw(bystanders[i], "claims");
        char token[2048];
        bystander_endpoints[i] = st_json_get_top_level_string(bystanders[i], "endpoint");
        CHECK(claims && bystander_endpoints[i] && revocation_sign(claims, token) == 0, "bystander claims");
        int messages = strcmp(bystander_endpoints[i], "client-messages") == 0;
        bystander_fds[i] = ws_open_endpoint(server->admin_port, token, bystander_endpoints[i],
            messages ? hello : NULL, sizeof(hello));
        bystander_tickets[i] = ws_ticket(server->admin_port, token, bystander_endpoints[i]);
        free(claims);
        CHECK(bystander_fds[i] >= 0 && bystander_tickets[i] && ws_ping_answered(bystander_fds[i]), "bystander ready");
    }
    char **cases = NULL;
    size_t count = 0U;
    CHECK(st_json_get_raw_array(vector, "cases", &cases, &count) == 0 && count == 6U, "six revocation cases");
    static const char *const endpoints[] = {"client-messages", "connections"};
    for (size_t i = 0; i < count; ++i) {
        char *target = st_json_get_top_level_raw(cases[i], "target");
        char *request = st_json_get_top_level_raw(cases[i], "request");
        char *expect = st_json_get_top_level_raw(cases[i], "expect");
        char token[2048];
        CHECK(target && request && expect && revocation_sign(target, token) == 0, "target case %zu", i);
        int sockets[2];
        char *unused[2];
        for (size_t j = 0; j < 2U; ++j) {
            sockets[j] = ws_open_endpoint(server->admin_port, token, endpoints[j], j == 0U ? hello : NULL, sizeof(hello));
            unused[j] = ws_ticket(server->admin_port, token, endpoints[j]);
            CHECK(sockets[j] >= 0 && unused[j] && ws_ping_answered(sockets[j]), "target ready %zu/%zu", i, j);
        }
        char *method = st_json_get_top_level_string(request, "method");
        char *name = st_json_get_top_level_string(request, "username");
        char *body = st_json_get_top_level_raw(request, "body");
        int expected_status = 0, revoked = 0, status = 0;
        CHECK(method && name && st_json_get_int(expect, "status", &expected_status) == 0
            && st_json_get_bool(expect, "revoked", &revoked) == 0, "request fields");
        char path[256];
        snprintf(path, sizeof(path), "/api/admin/users/%s", name);
        char *response = NULL;
        CHECK(http_request(server->admin_port, method, path, body, actor, &status, &response) == 0
            && status == expected_status, "case %zu mutation: %d %s", i, status, response ? response : "");
        free(response);
        for (size_t j = 0; j < 2U; ++j) {
            CHECK(revoked ? ws_read_close_code(sockets[j]) == 1008 : ws_ping_answered(sockets[j]),
                "case %zu endpoint %s close/keep", i, endpoints[j]);
            int extra = ws_use_ticket(server->admin_port, unused[j], endpoints[j], revoked ? 403 : 101,
                NULL, !revoked && j == 0U ? hello : NULL, sizeof(hello));
            CHECK(extra >= 0 && (revoked || ws_ping_answered(extra)), "case %zu unused ticket %s", i, endpoints[j]);
            close(extra); close(sockets[j]); free(unused[j]);
        }
        free(target); free(request); free(expect); free(method); free(name); free(body);
    }
    for (size_t i = 0; i < bystander_count; ++i) {
        CHECK(ws_ping_answered(bystander_fds[i]), "bystander %zu remains open", i);
        int extra = ws_use_ticket(server->admin_port, bystander_tickets[i], bystander_endpoints[i], 101, NULL,
            strcmp(bystander_endpoints[i], "client-messages") == 0 ? hello : NULL, sizeof(hello));
        CHECK(extra >= 0 && ws_ping_answered(extra), "bystander ticket remains valid");
        close(extra); close(bystander_fds[i]); free(bystander_tickets[i]); free(bystander_endpoints[i]);
    }
    st_json_free_string_array(cases, count);
    st_json_free_string_array(bystanders, bystander_count);
    free(vector);
    return 0;
}

static int scenario_revocation_edges(test_server *server)
{
    static const char *const endpoints[] = {"connections", "client-messages"};
    char hello[4096];
    for (size_t i = 0; i < 2U; ++i) {
        for (int change = 0; change < 4; ++change) {
            CHECK(revocation_sql(server, "DELETE FROM specus_management_user; INSERT INTO specus_management_user"
                "(username,login_name,login_name_normalized,tenant_id,password_hash,role,enabled)"
                " VALUES('original-key','stale-user','stale-user','default','unused','USER',1)") == 0, "stale account seed");
            char token[2048];
            CHECK(st_security_issue_local_token_for_account("stale-user", "default", "USER", "original-key",
                ADMIN_JWT_SECRET, 600, token, sizeof(token)) == 0, "stale token");
            char *ticket = ws_ticket(server->admin_port, token, endpoints[i]);
            CHECK(ticket != NULL, "issue stale ticket");
            const char *sql = change == 0 ? "UPDATE specus_management_user SET enabled=0"
                : change == 1 ? "UPDATE specus_management_user SET role='ADMIN'"
                : change == 2 ? "DELETE FROM specus_management_user; INSERT INTO specus_management_user"
                    "(username,login_name,login_name_normalized,tenant_id,password_hash,role,enabled)"
                    " VALUES('replacement-key','stale-user','stale-user','default','unused','USER',1)"
                : "SELECT 1";
            CHECK(revocation_sql(server, sql) == 0, "direct mutation");
            int fd = ws_use_ticket(server->admin_port, ticket, endpoints[i], change == 3 ? 101 : 403,
                change == 3 ? NULL : "X-Auth-Reason: identity revoked", change == 3 && i == 1U ? hello : NULL, sizeof(hello));
            CHECK(fd >= 0 && (change != 3 || ws_ping_answered(fd)), "stale ticket %zu/%d", i, change);
            close(fd);
            fd = ws_use_ticket(server->admin_port, ticket, endpoints[i], 403,
                "X-Auth-Reason: invalid or consumed ticket", NULL, 0U);
            CHECK(fd >= 0, "one-time ticket consumed even when identity rejected");
            close(fd); free(ticket);
            if (change == 2) {
                /* ManagementAccountsHttpTests: a token naming the recreated account's key opens it. */
                char replacement[2048];
                CHECK(st_security_issue_local_token_for_account("stale-user", "default", "USER", "replacement-key",
                    ADMIN_JWT_SECRET, 600, replacement, sizeof(replacement)) == 0, "replacement token");
                fd = ws_open_endpoint(server->admin_port, replacement, endpoints[i], i == 1U ? hello : NULL,
                                      sizeof(hello));
                CHECK(fd >= 0 && ws_ping_answered(fd), "recreated account opens %s", endpoints[i]);
                close(fd);
            }
        }
    }
    char actor[2048], token[2048];
    CHECK(st_security_issue_local_token(ADMIN_USERNAME, "default", "ADMIN", ADMIN_JWT_SECRET, 600,
        actor, sizeof(actor)) == 0, "rollback actor");
    CHECK(revocation_sql(server, "DELETE FROM specus_management_user; INSERT INTO specus_management_user"
        "(username,login_name,login_name_normalized,tenant_id,password_hash,role,enabled)"
        " VALUES('rollback-key','rollback-user','rollback-user','default','unused','USER',1);") == 0, "rollback seed");
    CHECK(st_security_issue_local_token_for_account("rollback-user", "default", "USER", "rollback-key",
        ADMIN_JWT_SECRET, 600, token, sizeof(token)) == 0, "rollback token");
    for (int delete = 0; delete < 2; ++delete) {
        int sockets[2]; char *tickets[2];
        for (size_t i = 0; i < 2U; ++i) {
            sockets[i] = ws_open_endpoint(server->admin_port, token, endpoints[i], i == 1U ? hello : NULL, sizeof(hello));
            tickets[i] = ws_ticket(server->admin_port, token, endpoints[i]);
            CHECK(sockets[i] >= 0 && tickets[i] && ws_ping_answered(sockets[i]), "rollback ready");
        }
        CHECK(revocation_sql(server, delete
            ? "CREATE TRIGGER rollback_failure BEFORE DELETE ON specus_management_user BEGIN SELECT RAISE(ABORT,'forced failure'); END;"
            : "CREATE TRIGGER rollback_failure BEFORE UPDATE ON specus_management_user BEGIN SELECT RAISE(ABORT,'forced failure'); END;"
            ) == 0, "install mutation failure");
        int status = 0; char *body = NULL;
        CHECK(http_request(server->admin_port, delete ? "DELETE" : "PUT", "/api/admin/users/rollback-user",
            delete ? NULL : "{\"enabled\":false}", actor, &status, &body) == 0 && status >= 400, "mutation must fail");
        free(body);
        CHECK(revocation_sql(server, "DROP TRIGGER rollback_failure") == 0, "remove failure injection");
        for (size_t i = 0; i < 2U; ++i) {
            CHECK(ws_ping_answered(sockets[i]), "rollback keeps open sockets");
            int extra = ws_use_ticket(server->admin_port, tickets[i], endpoints[i], 101, NULL,
                i == 1U ? hello : NULL, sizeof(hello));
            CHECK(extra >= 0 && ws_ping_answered(extra), "rollback keeps account and ticket valid");
            close(extra); close(sockets[i]); free(tickets[i]);
        }
    }
    return 0;
}
