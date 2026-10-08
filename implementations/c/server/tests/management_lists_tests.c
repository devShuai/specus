/*
 * Management lists past the fixed arrays C used to read them into. Java's lists have no row bound;
 * C answered 500 for every tenant once the whole database held more rows than its array: 129
 * clients, 65 TCP mappings or HTTP routes, 129 credentials, users or client catalogue links (every
 * released version stays in the catalogue, so a few targets reach that quickly). Each list is read
 * over real HTTP from an in-process admin listener with real management tokens.
 *
 * The Peer Mesh lists had their own bounds: 256 ACLs and services, 128 egress policies and activity
 * rows, 200 sessions closed at once, and 512 clients in the whole database behind an egress policy's
 * effective consumers. The session list takes Java's page/size/openOnly form. The connection list
 * shows a USER only the records of its clients' ids, not failed logins matched by name.
 *
 *   management_lists_tests
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "json.h"
#include "security.h"
#include "server_harness.h"
#include "storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define JWT_SECRET "management-lists-jwt-secret-long-enough-2026"
#define SHA_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

#define CLIENTS 150
#define OTHER_CLIENTS 20
#define MAPPINGS 70
#define ROUTES 70
#define CREDENTIALS 140
#define USERS 140
#define LINKS 140
#define PEER_ACLS 300
#define PEER_SERVICES 300
#define EGRESS_POLICIES 140
#define OPEN_SESSIONS 250
#define CLOSED_SESSIONS 10
#define BULK_CLIENTS 1100

static char db_path[320];
static int port = 0;

static int count_of(const char *haystack, const char *needle)
{
    int count = 0;
    for (const char *cursor = haystack; cursor != NULL && (cursor = strstr(cursor, needle)) != NULL;
         cursor += strlen(needle)) {
        ++count;
    }
    return count;
}

static int request(const char *method, const char *path, const char *request_body, const char *token, char **body)
{
    int status = 0;
    *body = NULL;
    return http_request(port, method, path, request_body, token, &status, body) == 0 ? status : -1;
}

static int get(const char *path, const char *token, char **body)
{
    return request("GET", path, NULL, token, body);
}

/* GET path; the answer must hold every needle. */
static int expect_text(const char *path, const char *token, const char *const *needles, size_t needle_count)
{
    char *body = NULL;
    int status = get(path, token, &body);
    int ok = status == 200;
    for (size_t i = 0; ok && i < needle_count; ++i) {
        ok = body != NULL && strstr(body, needles[i]) != NULL;
    }
    if (!ok) {
        fprintf(stderr, "GET %s: status %d, expected %s: %.400s\n", path, status,
                needle_count > 0U ? needles[0] : "", body == NULL ? "" : body);
    }
    free(body);
    return ok ? 0 : -1;
}

/* Runs statements built by the caller, in one transaction. */
static int exec_all(const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK ? 0 : -1;
    if (rc != 0) fprintf(stderr, "sql failed: %s\n", error == NULL ? "sqlite error" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

/* A growing SQL script. */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} script;

static int script_add(script *s, const char *format, ...)
{
    char line[1024];
    va_list args;
    va_start(args, format);
    int written = vsnprintf(line, sizeof(line), format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= sizeof(line)) return -1;
    if (s->len + (size_t)written + 1U > s->cap) {
        size_t next = s->cap == 0U ? 65536U : s->cap * 2U;
        while (s->len + (size_t)written + 1U > next) next *= 2U;
        char *grown = (char *)realloc(s->data, next);
        if (grown == NULL) return -1;
        s->data = grown;
        s->cap = next;
    }
    memcpy(s->data + s->len, line, (size_t)written + 1U);
    s->len += (size_t)written;
    return 0;
}

/*
 * The Peer Mesh rows of tenant t-lists, over its CLIENTS clients from first on: ACLs, services,
 * enabled egress policies with their activity, open and closed sessions, and the two enabled devices
 * an effective egress consumer needs. Another tenant holds BULK_CLIENTS clients whose names sort
 * before the t-lists ones, so a list cut at 512 or 1024 clients misses the egress device.
 */
static int seed_peer_mesh(long long first)
{
    script s = {0};
    char consumer[32];
    snprintf(consumer, sizeof(consumer), "%lld", first + 1);
    int rc = script_add(&s, "BEGIN;");
    for (int i = 0; rc == 0 && i < PEER_ACLS; ++i) {
        int source = i % CLIENTS;
        int target = (source + 1 + i / CLIENTS) % CLIENTS;
        rc = script_add(&s,
                        "INSERT INTO peer_mesh_acl(tenant_id, owner_username, source_client_id, source_client_name, "
                        "target_client_id, target_client_name, allowed, direction) "
                        "VALUES ('t-lists', 'lists-admin', %lld, 'lists-client-%03d', %lld, 'lists-client-%03d', 1, "
                        "'BOTH');",
                        first + source, source, first + target, target);
    }
    for (int i = 0; rc == 0 && i < PEER_SERVICES; ++i) {
        rc = script_add(&s,
                        "INSERT INTO peer_mesh_shared_service(tenant_id, client_id, client_name, service_id, name, "
                        "description, transport, application, target_host, target_port, published_port, path, "
                        "enabled, visibility) VALUES ('t-lists', %lld, 'lists-client-%03d', 'svc-%03d', "
                        "'Service %03d', 'seeded', 'tcp', 'tcp', '127.0.0.1', %d, %d, '', 1, 'OWNER');",
                        first + i % CLIENTS, i % CLIENTS, i, i, 10000 + i, 20000 + i);
    }
    for (int i = 0; rc == 0 && i < EGRESS_POLICIES; ++i) {
        /* The first device's policy names the second as its consumer. */
        rc = script_add(&s,
                        "INSERT INTO peer_mesh_egress_policy(tenant_id, owner_username, egress_client_id, "
                        "egress_client_name, enabled, scope, allowed_consumer_client_ids, destination_rules) "
                        "VALUES ('t-lists', 'lists-admin', %lld, 'lists-client-%03d', 1, 'PUBLIC', '%s', '[]');"
                        "INSERT INTO peer_mesh_egress_activity(tenant_id, egress_client_id, egress_client_name, "
                        "revision, active_flows, total_flows, rejected_flows, bytes_in, bytes_out, reported_at) "
                        "VALUES ('t-lists', %lld, 'lists-client-%03d', 1, 0, %d, '{}', 0, 0, '2026-10-08T00:00:00Z');",
                        first + i, i, i == 0 ? consumer : "", first + i, i, i);
    }
    for (int i = 0; rc == 0 && i < OPEN_SESSIONS + CLOSED_SESSIONS; ++i) {
        int closed = i >= OPEN_SESSIONS;
        rc = script_add(&s,
                        "INSERT INTO peer_mesh_session(tenant_id, source_client_id, source_client_name, "
                        "target_client_id, target_client_name, path_type, status, started_at, updated_at, "
                        "expires_at, closed_at) VALUES ('t-lists', %lld, 'lists-client-%03d', %lld, "
                        "'lists-client-%03d', 'DIRECT', '%s', '2026-10-08 00:00:00', '2026-10-08 00:%02d:%02d', "
                        "'2999-01-01 00:00:00', %s);",
                        first + i % CLIENTS, i % CLIENTS, first + (i + 1) % CLIENTS, (i + 1) % CLIENTS,
                        closed ? "CLOSED" : "ACTIVE", i / 60, i % 60, closed ? "'2026-10-08 01:00:00'" : "NULL");
    }
    for (int i = 0; rc == 0 && i < 2; ++i) {
        rc = script_add(&s,
                        "INSERT INTO peer_mesh_device(tenant_id, owner_username, client_id, client_name, enabled, "
                        "virtual_ip) VALUES ('t-lists', 'lists-admin', %lld, 'lists-client-%03d', 1, '100.96.0.%d');",
                        first + i, i, 10 + i);
    }
    for (int i = 0; rc == 0 && i < BULK_CLIENTS; ++i) {
        rc = script_add(&s,
                        "INSERT INTO client_account(tenant_id, client_name, owner_username) "
                        "VALUES ('t-bulk', 'bulk-client-%04d', 'bulk-admin');",
                        i);
    }
    if (rc == 0) rc = script_add(&s, "COMMIT;");
    if (rc == 0) rc = exec_all(s.data);
    free(s.data);
    return rc;
}

static int count_in(const char *path, const char *method, const char *token, const char *needle, int expected)
{
    char *body = NULL;
    int status = request(method, path, NULL, token, &body);
    int seen = count_of(body, needle);
    if (status != 200 || seen != expected) {
        fprintf(stderr, "%s %s: status %d, %d x %s, expected %d: %.300s\n", method, path, status, seen, needle,
                expected, body == NULL ? "" : body);
    }
    free(body);
    return status == 200 && seen == expected ? 0 : -1;
}

static int test_peer_mesh_lists(const char *token, long long first)
{
    char needle[128];
    snprintf(needle, sizeof(needle), "\"effectiveConsumerClientIds\":[%lld]", first + 1);
    static const char *const switch_needles[] = {"\"enabledPolicyCount\":140"};
    static const char *const sharing_needles[] = {"\"enabledServiceCount\":300"};
    static const char *const open_page[] = {"],\"total\":250,\"page\":1,\"size\":100,\"totalPages\":3}"};
    static const char *const any_page[] = {"],\"total\":260,\"page\":0,\"size\":100,\"totalPages\":3}"};
    static const char *const none_open[] = {"{\"items\":[],\"total\":0,\"page\":0,\"size\":1,\"totalPages\":1}"};
    const char *effective[] = {needle};
    if (count_in("/api/admin/peer-mesh/acls", "GET", token, "\"sourceClientId\":", PEER_ACLS)
        || count_in("/api/admin/peer-mesh/services", "GET", token, "\"serviceId\":\"svc-", PEER_SERVICES)
        || expect_text("/api/admin/peer-mesh/service-sharing", token, sharing_needles, 1U)
        || count_in("/api/admin/peer-mesh/egress/policies", "GET", token, "\"egressClientId\":", EGRESS_POLICIES)
        || expect_text("/api/admin/peer-mesh/egress/policies", token, effective, 1U)
        || count_in("/api/admin/peer-mesh/egress/activity", "GET", token, "\"egressClientId\":", EGRESS_POLICIES)
        || expect_text("/api/admin/peer-mesh/egress/switch", token, switch_needles, 1U)) {
        return -1;
    }
    /* A service saved past the 256th: the save read it back through a list cut at 256. */
    char body[512];
    snprintf(body, sizeof(body),
             "{\"clientId\":%lld,\"serviceId\":\"svc-saved\",\"name\":\"Saved service\",\"description\":\"d\","
             "\"transport\":\"tcp\",\"application\":\"tcp\",\"targetHost\":\"127.0.0.1\",\"targetPort\":9999,"
             "\"publishedPort\":29999,\"path\":\"\",\"enabled\":true,\"visibility\":\"OWNER\"}",
             first);
    char *answer = NULL;
    int status = request("POST", "/api/admin/peer-mesh/services", body, token, &answer);
    int saved = status == 201 && answer != NULL && strstr(answer, "\"serviceId\":\"svc-saved\"") != NULL;
    if (!saved) fprintf(stderr, "service save: %d %.300s\n", status, answer == NULL ? "" : answer);
    free(answer);
    if (!saved) return -1;

    /* Sessions: limit is 1..200; page and size (1..100) give Java's page, openOnly its filter. */
    if (count_in("/api/admin/peer-mesh/sessions?limit=500", "GET", token, "\"sourceClientId\":", 200)
        || count_in("/api/admin/peer-mesh/sessions?limit=0", "GET", token, "\"sourceClientId\":", 1)
        || count_in("/api/admin/peer-mesh/sessions?page=1&size=100&openOnly=true", "GET", token,
                    "\"status\":\"ACTIVE\"", 100)
        || expect_text("/api/admin/peer-mesh/sessions?page=1&size=100&openOnly=true", token, open_page, 1U)
        || expect_text("/api/admin/peer-mesh/sessions?page=0&size=1000", token, any_page, 1U)) {
        return -1;
    }
    /* Closing every open session answers all of them, well past the 32 KiB buffer. */
    if (count_in("/api/admin/peer-mesh/sessions", "DELETE", token, "\"status\":\"CLOSED\"", OPEN_SESSIONS)
        || expect_text("/api/admin/peer-mesh/sessions?page=0&size=1&openOnly=true", token, none_open, 1U)) {
        return -1;
    }
    return 0;
}

/* Java lists a USER's connection records by clientId only; a failed login by name has none. */
static int test_connection_visibility(const char *admin_token, const char *user_token)
{
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT INTO client_account(tenant_id, client_name, owner_username) "
             "VALUES ('t-lists', 'user-owned-client', 'lists-user-000');"
             "INSERT INTO connection_record(tenant_id, client_id, client_name, success) "
             "SELECT 't-lists', id, client_name, 1 FROM client_account WHERE client_name = 'user-owned-client';"
             "INSERT INTO connection_record(tenant_id, client_id, client_name, success, reason) "
             "VALUES ('t-lists', NULL, 'user-owned-client', 0, 'invalid token');");
    static const char *const one[] = {"\"total\":1,"};
    static const char *const two[] = {"\"total\":2,"};
    return exec_all(sql) != 0
        || expect_text("/api/admin/connections", user_token, one, 1U)
        || count_in("/api/admin/connections", "GET", user_token, "\"clientId\":null", 0)
        || expect_text("/api/admin/connections", admin_token, two, 1U) ? -1 : 0;
}

/* GET path, then count needle in the answer. */
static int expect_count(const char *path, const char *token, const char *needle, int expected)
{
    char *body = NULL;
    int status = get(path, token, &body);
    int seen = count_of(body, needle);
    if (status != 200 || seen != expected) {
        fprintf(stderr, "GET %s: status %d, %d x %s, expected %d: %.300s\n", path, status, seen, needle, expected,
                body == NULL ? "" : body);
    }
    free(body);
    return status == 200 && seen == expected ? 0 : -1;
}

static int seed(void)
{
    st_storage_management_user user;
    if (st_storage_create_management_user(db_path, "lists-admin", "t-lists", "unused", "ADMIN", 1, &user) != 0
        || st_storage_create_management_user(db_path, "other-admin", "t-other", "unused", "ADMIN", 1, &user) != 0) {
        return -1;
    }
    for (int i = 0; i < USERS; ++i) {
        char name[64];
        snprintf(name, sizeof(name), "lists-user-%03d", i);
        if (st_storage_create_management_user(db_path, name, "t-lists", "unused", "USER", 1, &user) != 0) return -1;
    }
    /* Clients in one transaction; ids follow the insertion order. */
    size_t capacity = (size_t)(CLIENTS + OTHER_CLIENTS) * 128U + 64U;
    char *sql = (char *)malloc(capacity);
    if (sql == NULL) return -1;
    size_t used = (size_t)snprintf(sql, capacity, "BEGIN;");
    for (int i = 0; i < CLIENTS + OTHER_CLIENTS; ++i) {
        int other = i >= CLIENTS;
        used += (size_t)snprintf(sql + used, capacity - used,
                                 "INSERT INTO client_account(tenant_id, client_name, owner_username) "
                                 "VALUES ('%s', '%s-%03d', '%s');",
                                 other ? "t-other" : "t-lists", other ? "other-client" : "lists-client", i,
                                 other ? "other-admin" : "lists-admin");
    }
    snprintf(sql + used, capacity - used, "COMMIT;");
    sqlite3 *db = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    sqlite3_close(db);
    free(sql);
    if (rc != 0) return -1;
    char first_id[32];
    if (db_scalar(db_path, "SELECT MIN(id) FROM client_account WHERE tenant_id = ?", "t-lists", 0,
                  first_id, sizeof(first_id)) != 0) {
        return -1;
    }
    long long first = strtoll(first_id, NULL, 10);
    for (int i = 0; i < MAPPINGS; ++i) {
        st_storage_mapping mapping;
        if (st_storage_create_mapping_for_client(db_path, first + i, 30000 + i, "127.0.0.1", 9, 1, 0, &mapping) != 0) {
            return -1;
        }
    }
    for (int i = 0; i < ROUTES; ++i) {
        char route_name[32];
        snprintf(route_name, sizeof(route_name), "r%03d", i);
        st_storage_http_route route;
        if (st_storage_create_http_route_for_client(db_path, first + i, route_name, "http://127.0.0.1:9", 1, 0, 0, 0,
                                                    0, 0, NULL, NULL, &route) != 0) {
            return -1;
        }
    }
    for (int i = 0; i < CREDENTIALS; ++i) {
        char api_key[32];
        snprintf(api_key, sizeof(api_key), "ck_list_%03d", i);
        st_storage_client_credential credential;
        if (st_storage_upsert_client_credential(db_path, 0, "t-lists", "lists-admin", api_key, "unused-hash", 1, 2,
                                                &credential) != 0) {
            return -1;
        }
    }
    /* One target released LINKS times through the catalogue API; the last release is the latest. */
    static char response[16384];
    for (int i = 0; i < LINKS; ++i) {
        char json[640];
        int latest = i == LINKS - 1;
        snprintf(json, sizeof(json),
                 "{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\",\"displayName\":\"List client\","
                 "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v1.0.%d/client.zip\","
                 "\"version\":\"1.0.%d\"%s}",
                 i, i, latest ? ",\"sha256\":\"" SHA_A "\",\"fileSize\":1024,\"isLatest\":true" : "");
        int len = st_admin_build_response_with_body("POST", "/api/admin/client-downloads", json, response,
                                                    sizeof(response));
        if (len <= 0 || strncmp(response, "HTTP/1.1 201", 12U) != 0) {
            fprintf(stderr, "catalogue link %d: %s\n", i, response);
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    const char *tmp = getenv("TMPDIR");
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/specus-c-lists-XXXXXX", tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(db_path, sizeof(db_path), "%s/lists.db", dir);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", JWT_SECRET, 1);
    setenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED", "false", 1);
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", "100000", 1);
    char data_dir[400];
    snprintf(data_dir, sizeof(data_dir), "%s/data", dir);
    setenv("SPECUS_CLIENT_PACKAGE_DATA_DIRECTORY", data_dir, 1);

    int failed = st_storage_init(db_path, 0) != 0 || seed() != 0;
    if (failed) fprintf(stderr, "seeding failed\n");
    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (!failed && (st_admin_server_start(&server, 0, "") != 0
                    || getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0)) {
        fprintf(stderr, "listener start failed\n");
        failed = 1;
    }
    char admin_token[1024];
    char other_token[1024];
    char user_token[1024];
    if (!failed && (st_security_issue_local_token("lists-admin", "t-lists", "ADMIN", JWT_SECRET, 600, admin_token,
                                                  sizeof(admin_token)) != 0
                    || st_security_issue_local_token("other-admin", "t-other", "ADMIN", JWT_SECRET, 600, other_token,
                                                     sizeof(other_token)) != 0
                    || st_security_issue_local_token("lists-user-000", "t-lists", "USER", JWT_SECRET, 600, user_token,
                                                     sizeof(user_token)) != 0)) {
        failed = 1;
    }
    if (!failed) {
        port = ntohs(address.sin_port);
        failed = expect_count("/api/admin/clients", admin_token, "\"clientName\":\"lists-client-", CLIENTS)
            || expect_count("/api/admin/clients", other_token, "\"clientName\":\"other-client-", OTHER_CLIENTS)
            || expect_count("/api/admin/clients", other_token, "lists-client-", 0)
            || expect_count("/api/admin/specus-mappings", admin_token, "\"listenPort\":", MAPPINGS)
            || expect_count("/api/admin/specus-mappings", other_token, "\"listenPort\":", 0)
            || expect_count("/api/admin/http-routes", admin_token, "\"route\":\"r", ROUTES)
            || expect_count("/api/admin/overview", admin_token, "\"tcpMappings\":70", 1)
            || expect_count("/api/admin/client-credentials", admin_token, "ck_list_", CREDENTIALS)
            || expect_count("/api/admin/users", admin_token, "lists-user-", USERS)
            || expect_count("/api/admin/client-downloads", admin_token, "\"displayName\":\"List client\"", LINKS)
            || expect_count("/api/public/client-downloads", NULL, "\"version\":\"1.0.139\"", 1)
            || expect_count("/api/public/client-version-check?implementation=go&platform=linux&arch=x64&current=1.0.0",
                            NULL, "\"latestVersion\":\"1.0.139\"", 1);
    }
    if (!failed) {
        char first_id[32];
        failed = db_scalar(db_path, "SELECT MIN(id) FROM client_account WHERE tenant_id = ?", "t-lists", 0,
                           first_id, sizeof(first_id)) != 0;
        long long first = failed ? 0 : strtoll(first_id, NULL, 10);
        failed = failed || seed_peer_mesh(first) != 0;
        if (failed) fprintf(stderr, "peer mesh seeding failed\n");
        failed = failed || test_peer_mesh_lists(admin_token, first) != 0;
        printf("%s peer mesh lists past their old bounds\n", failed ? "FAIL" : "ok  ");
        if (!failed) {
            failed = test_connection_visibility(admin_token, user_token) != 0;
            printf("%s connection records a USER sees\n", failed ? "FAIL" : "ok  ");
        }
    }
    unlink(db_path);
    char journal[400];
    snprintf(journal, sizeof(journal), "%s-journal", db_path);
    unlink(journal);
    rmdir(data_dir);
    rmdir(dir);
    if (failed) return 1;
    printf("management lists tests passed\n");
    return 0;
}
