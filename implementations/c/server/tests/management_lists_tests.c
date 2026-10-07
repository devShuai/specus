/*
 * Management lists past the fixed arrays C used to read them into. Java's lists have no row bound;
 * C answered 500 for every tenant once the whole database held more rows than its array: 129
 * clients, 65 TCP mappings or HTTP routes, 129 credentials, users or client catalogue links (every
 * released version stays in the catalogue, so a few targets reach that quickly). Each list is read
 * over real HTTP from an in-process admin listener with real management tokens.
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

static int get(const char *path, const char *token, char **body)
{
    int status = 0;
    *body = NULL;
    return http_request(port, "GET", path, NULL, token, &status, body) == 0 ? status : -1;
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
    if (!failed && (st_security_issue_local_token("lists-admin", "t-lists", "ADMIN", JWT_SECRET, 600, admin_token,
                                                  sizeof(admin_token)) != 0
                    || st_security_issue_local_token("other-admin", "t-other", "ADMIN", JWT_SECRET, 600, other_token,
                                                     sizeof(other_token)) != 0)) {
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
