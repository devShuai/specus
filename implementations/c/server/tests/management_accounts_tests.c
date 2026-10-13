#define _POSIX_C_SOURCE 200809L

/*
 * Account lifecycle (protocol/spec/management-accounts.md sections 5-7, issue #199), the
 * counterpart of Java's ManagementAccountsHttpTests: replays
 * protocol/test-vectors/management-accounts-v1.json through the real management handlers, walks
 * the delete-then-recreate path with tokens /auth/login really issued, and checks that an account's
 * email record goes with it and what becomes of the rest of its data (section 7.1, issue #225).
 */

#include "admin_http.h"
#include "crypto.h"
#include "json.h"
#include "login_rate_limiter.h"
#include "password_hash.h"
#include "security.h"
#include "storage.h"
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE
#define ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE "../../../protocol/test-vectors/management-accounts-v1.json"
#endif

#define JWT_SECRET "c-management-accounts-test-secret"
#define ADMIN_PASSWORD "admin-accounts-password"

static char db_path[256];
static char response[65536];

static int open_fresh_database(const char *label)
{
    snprintf(db_path, sizeof(db_path), "/tmp/specus-c-accounts-%s-%ld.db", label, (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", JWT_SECRET, 1);
    setenv("SPECUS_AUTH_PASSWORD", ADMIN_PASSWORD, 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    unsetenv("SPECUS_AUTH_TENANT_ID");
    unsetenv("SPECUS_AUTH_USERNAME");
    st_login_rate_limiter_reset();
    return st_storage_init(db_path, 0);
}

static int exec_sql(const char *sql)
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

/* The number of rows of a COUNT(*) query, or -1. */
static long long count_rows(const char *sql)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long count = -1;
    if (sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

/* An account row with exactly this account key, as the vector seeds it. */
static int seed_account(const char *account_key, const char *login_name, const char *tenant_id, const char *role,
                        int enabled)
{
    char hash[ST_PASSWORD_HASH_MAX_LEN + 1U];
    char normalized[96];
    char sql[1024];
    size_t i = 0U;
    for (; login_name[i] != '\0' && i + 1U < sizeof(normalized); ++i) {
        char c = login_name[i];
        normalized[i] = c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
    }
    normalized[i] = '\0';
    if (st_password_hash("vector-password", hash) != 0) {
        return -1;
    }
    snprintf(sql, sizeof(sql),
             "INSERT INTO specus_management_user(username, login_name, login_name_normalized, tenant_id,"
             " password_hash, role, enabled) VALUES('%s','%s','%s','%s','%s','%s',%d);",
             account_key, login_name, normalized, tenant_id, hash, role, enabled);
    return exec_sql(sql);
}

static int seed_email(const char *account_key, const char *email)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "INSERT INTO specus_management_user_email(username, email, verified_at, created_at, updated_at)"
             " VALUES('%s','%s','2026-07-31T00:00:00Z','2026-07-31T00:00:00Z','2026-07-31T00:00:00Z');",
             account_key, email);
    return exec_sql(sql);
}

static void base64url(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t w = 0U;
    for (size_t i = 0U; i < len && w + 5U < out_len; i += 3U) {
        uint32_t chunk = (uint32_t)data[i] << 16;
        if (i + 1U < len) chunk |= (uint32_t)data[i + 1U] << 8;
        if (i + 2U < len) chunk |= data[i + 2U];
        out[w++] = alphabet[(chunk >> 18) & 63U];
        out[w++] = alphabet[(chunk >> 12) & 63U];
        if (i + 1U < len) out[w++] = alphabet[(chunk >> 6) & 63U];
        if (i + 2U < len) out[w++] = alphabet[chunk & 63U];
    }
    out[w] = '\0';
}

/* Appends ,"name":"value" for a claim the vector gives (NULL leaves it out). */
static int append_claim(char *payload, size_t payload_len, const char *name, const char *value)
{
    if (value == NULL) {
        return 0;
    }
    char *escaped = st_json_escape(value);
    if (escaped == NULL) {
        return -1;
    }
    size_t used = strlen(payload);
    int written = snprintf(payload + used, payload_len - used, ",\"%s\":\"%s\"", name, escaped);
    free(escaped);
    return written < 0 || (size_t)written >= payload_len - used ? -1 : 0;
}

/* Signs the claims object as the server's own local token, with iss, iat and exp added. */
static int sign_claims(const char *claims_json, char *out, size_t out_len)
{
    static const char *const names[] = {"sub", "tenant_id", "role", "uid"};
    char payload[1024];
    long long now = (long long)time(NULL);
    snprintf(payload, sizeof(payload), "{\"iss\":\"specus\",\"iat\":%lld,\"exp\":%lld", now, now + 600);
    for (size_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i) {
        char *value = st_json_get_top_level_string(claims_json, names[i]);
        int rc = append_claim(payload, sizeof(payload), names[i], value);
        free(value);
        if (rc != 0) {
            return -1;
        }
    }
    strncat(payload, "}", sizeof(payload) - strlen(payload) - 1U);
    static const char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char header_segment[64];
    char payload_segment[1400];
    base64url((const uint8_t *)header, strlen(header), header_segment, sizeof(header_segment));
    base64url((const uint8_t *)payload, strlen(payload), payload_segment, sizeof(payload_segment));
    char signing_input[1500];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", header_segment, payload_segment);
    uint8_t key[ST_SHA256_LEN];
    uint8_t mac[ST_SHA256_LEN];
    st_sha256((const uint8_t *)JWT_SECRET, strlen(JWT_SECRET), key);
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)signing_input, strlen(signing_input), mac);
    char signature[64];
    base64url(mac, sizeof(mac), signature, sizeof(signature));
    int written = snprintf(out, out_len, "%s.%s", signing_input, signature);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static int call(const char *method, const char *path, const char *token, const char *body)
{
    char authorization[2300];
    snprintf(authorization, sizeof(authorization), "Bearer %s", token == NULL ? "" : token);
    return st_admin_build_response_with_auth(method, path, authorization, body, response, sizeof(response));
}

static int status_is(int len, const char *status)
{
    return len > 0 && strncmp(response, status, strlen(status)) == 0;
}

static const char *body_of_response(void)
{
    const char *body = strstr(response, "\r\n\r\n");
    return body == NULL ? "" : body + 4;
}

static char *read_vector(void)
{
    FILE *file = fopen(ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE, "rb");
    if (file == NULL) {
        perror(ST_MANAGEMENT_ACCOUNTS_VECTOR_FILE);
        return NULL;
    }
    char *vector = NULL;
    long size = fseek(file, 0, SEEK_END) == 0 ? ftell(file) : -1;
    if (size > 0 && fseek(file, 0, SEEK_SET) == 0) {
        vector = (char *)malloc((size_t)size + 1U);
        if (vector != NULL && fread(vector, 1, (size_t)size, file) == (size_t)size) {
            vector[size] = '\0';
        } else {
            free(vector);
            vector = NULL;
        }
    }
    fclose(file);
    return vector;
}

static int seed_vector_accounts(const char *vector)
{
    char **accounts = NULL;
    size_t count = 0U;
    if (st_json_get_raw_array(vector, "accounts", &accounts, &count) != 0) {
        return -1;
    }
    int rc = 0;
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        char *key = st_json_get_top_level_string(accounts[i], "accountKey");
        char *login = st_json_get_top_level_string(accounts[i], "loginName");
        char *tenant = st_json_get_top_level_string(accounts[i], "tenantId");
        char *role = st_json_get_top_level_string(accounts[i], "role");
        int enabled = 1;
        rc = key == NULL || login == NULL || tenant == NULL || role == NULL
            || st_json_get_bool(accounts[i], "enabled", &enabled) != 0
            ? -1 : seed_account(key, login, tenant, role, enabled);
        free(key);
        free(login);
        free(tenant);
        free(role);
    }
    st_json_free_string_array(accounts, count);
    return rc;
}

/* Compares one expected string field of expect with the same field of actual (NULL: missing). */
static int same_string(const char *expect, const char *actual_json, const char *field)
{
    char *want = st_json_get_top_level_string(expect, field);
    char *got = st_json_get_top_level_string(actual_json, field);
    int same = want != NULL && got != NULL && strcmp(want, got) == 0;
    free(want);
    free(got);
    return same;
}

static int replay_token_case(const char *name, const char *claims, const char *expect)
{
    char token[2048];
    if (sign_claims(claims, token, sizeof(token)) != 0) {
        fprintf(stderr, "%s: cannot sign the claims\n", name);
        return -1;
    }
    int me = call("GET", "/api/admin/me", token, NULL);
    int expect_null = strcmp(expect, "null") == 0;
    if (expect_null) {
        if (!status_is(me, "HTTP/1.1 401 ") && !status_is(me, "HTTP/1.1 403 ")) {
            fprintf(stderr, "%s: me answered %.40s\n", name, response);
            return -1;
        }
        if (!status_is(call("POST", "/auth/refresh", token, NULL), "HTTP/1.1 401 ")) {
            fprintf(stderr, "%s: refresh answered %.40s\n", name, response);
            return -1;
        }
        return 0;
    }
    int built_in = 0;
    int want_built_in = 0;
    if (!status_is(me, "HTTP/1.1 200 ") || !same_string(expect, body_of_response(), "username")
        || !same_string(expect, body_of_response(), "tenantId")
        || st_json_get_bool(body_of_response(), "builtIn", &built_in) != 0
        || st_json_get_bool(expect, "builtIn", &want_built_in) != 0 || built_in != want_built_in) {
        fprintf(stderr, "%s: me answered %s\n", name, response);
        return -1;
    }
    if (!status_is(call("POST", "/auth/refresh", token, NULL), "HTTP/1.1 200 ")) {
        fprintf(stderr, "%s: refresh answered %s\n", name, response);
        return -1;
    }
    char *refreshed = st_json_get_string(body_of_response(), "accessToken");
    st_security_token_claims refreshed_claims;
    memset(&refreshed_claims, 0, sizeof(refreshed_claims));
    char *want_user = st_json_get_top_level_string(expect, "username");
    char *want_tenant = st_json_get_top_level_string(expect, "tenantId");
    char *want_uid = st_json_get_top_level_string(expect, "uid");
    int ok = refreshed != NULL
        && st_security_validate_local_token(refreshed, JWT_SECRET, "default", "admin", &refreshed_claims) == 0
        && want_user != NULL && strcmp(refreshed_claims.username, want_user) == 0
        && want_tenant != NULL && strcmp(refreshed_claims.tenant_id, want_tenant) == 0
        && strcmp(refreshed_claims.account_key, want_uid == NULL ? "" : want_uid) == 0;
    if (!ok) {
        fprintf(stderr, "%s: refreshed token %s carries uid '%s', want '%s'\n", name,
                refreshed == NULL ? "(none)" : refreshed, refreshed_claims.account_key,
                want_uid == NULL ? "" : want_uid);
    }
    free(refreshed);
    free(want_user);
    free(want_tenant);
    free(want_uid);
    return ok ? 0 : -1;
}

static int test_token_resolution_vector(const char *vector)
{
    if (open_fresh_database("tokens") != 0 || seed_vector_accounts(vector) != 0) {
        fprintf(stderr, "token resolution fixture setup failed\n");
        return 1;
    }
    char **cases = NULL;
    size_t count = 0U;
    int failed = st_json_get_raw_array(vector, "tokenResolution", &cases, &count) != 0 || count == 0U;
    for (size_t i = 0U; !failed && i < count; ++i) {
        char *name = st_json_get_top_level_string(cases[i], "name");
        char *claims = st_json_get_top_level_raw(cases[i], "claims");
        char *expect = st_json_get_top_level_raw(cases[i], "expect");
        failed = name == NULL || claims == NULL || expect == NULL || replay_token_case(name, claims, expect) != 0;
        free(name);
        free(claims);
        free(expect);
    }
    st_json_free_string_array(cases, count);
    unlink(db_path);
    return failed ? 1 : 0;
}

/* "username@tenant builtIn" for each element of a JSON array of user views, joined by "; ". */
static int describe_users(const char *array_json, char *out, size_t out_len)
{
    size_t wrapped_len = strlen(array_json) + 16U;
    char *wrapped = malloc(wrapped_len);
    if (wrapped == NULL) {
        return -1;
    }
    snprintf(wrapped, wrapped_len, "{\"users\":%s}", array_json);
    char **users = NULL;
    size_t count = 0U;
    int rc = st_json_get_raw_array(wrapped, "users", &users, &count);
    free(wrapped);
    out[0] = '\0';
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        char *username = st_json_get_top_level_string(users[i], "username");
        char *tenant = st_json_get_top_level_string(users[i], "tenantId");
        int built_in = 0;
        if (username == NULL || tenant == NULL || st_json_get_bool(users[i], "builtIn", &built_in) != 0) {
            rc = -1;
        } else {
            size_t used = strlen(out);
            snprintf(out + used, out_len - used, "%s%s@%s%s", i == 0U ? "" : "; ", username, tenant,
                     built_in ? " built-in" : "");
        }
        free(username);
        free(tenant);
    }
    st_json_free_string_array(users, count);
    return rc;
}

static int test_user_list_vector(const char *vector)
{
    if (open_fresh_database("lists") != 0 || seed_vector_accounts(vector) != 0) {
        fprintf(stderr, "user list fixture setup failed\n");
        return 1;
    }
    char **cases = NULL;
    size_t count = 0U;
    int failed = st_json_get_raw_array(vector, "userLists", &cases, &count) != 0 || count == 0U;
    for (size_t i = 0U; !failed && i < count; ++i) {
        char *name = st_json_get_top_level_string(cases[i], "name");
        char *caller = st_json_get_top_level_raw(cases[i], "caller");
        char *expect = st_json_get_top_level_raw(cases[i], "expect");
        char token[2048];
        char want[1024] = "";
        char got[1024] = "";
        failed = name == NULL || caller == NULL || expect == NULL || sign_claims(caller, token, sizeof(token)) != 0
            || describe_users(expect, want, sizeof(want)) != 0
            || !status_is(call("GET", "/api/admin/users", token, NULL), "HTTP/1.1 200 ")
            || describe_users(body_of_response(), got, sizeof(got)) != 0
            || strcmp(want, got) != 0;
        if (failed) {
            fprintf(stderr, "%s: got [%s], want [%s]; %s\n", name == NULL ? "?" : name, got, want, response);
        }
        free(name);
        free(caller);
        free(expect);
    }
    st_json_free_string_array(cases, count);
    unlink(db_path);
    return failed ? 1 : 0;
}

/* POST /auth/login; the access token on 200 (the caller frees it), else NULL. */
static char *login(const char *username, const char *password, const char *tenant)
{
    char body[320];
    if (tenant == NULL) {
        snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
    } else {
        snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\",\"tenantId\":\"%s\"}",
                 username, password, tenant);
    }
    int len = st_admin_build_response_with_body("POST", "/auth/login", body, response, sizeof(response));
    return status_is(len, "HTTP/1.1 200 ") ? st_json_get_string(body_of_response(), "accessToken") : NULL;
}

static int token_uid(const char *token, char *out, size_t out_len)
{
    st_security_token_claims claims;
    if (token == NULL || st_security_validate_local_token(token, JWT_SECRET, "default", "admin", &claims) != 0) {
        return -1;
    }
    snprintf(out, out_len, "%s", claims.account_key);
    return 0;
}

/* Java ManagementAccountsHttpTests.deletedAccountTokensDoNotResolveToARecreatedAccountOfTheSameName. */
static int test_deleted_account_tokens_do_not_pass_to_a_recreated_account(void)
{
    char uid[96];
    char tenant_admin[2048];
    st_storage_management_user stored;
    char first_key[96] = "";
    int failed = open_fresh_database("recreate") != 0
        || seed_account("5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d", "erin", "tenant-a", "ADMIN", 1) != 0
        || sign_claims("{\"sub\":\"erin\",\"tenant_id\":\"tenant-a\",\"role\":\"ADMIN\"}", tenant_admin,
                       sizeof(tenant_admin)) != 0;
    if (failed) fprintf(stderr, "recreate fixture setup failed\n");
    if (!failed) {
        char *admin = login("admin", ADMIN_PASSWORD, NULL);
        failed = token_uid(admin, uid, sizeof(uid)) != 0 || uid[0] != '\0';
        if (failed) fprintf(stderr, "the built-in admin's token carries uid '%s'\n", uid);
        free(admin);
    }
    static const char create[] = "{\"username\":\"alice\",\"password\":\"alice-password\",\"role\":\"USER\"}";
    char *first = NULL;
    if (!failed) {
        failed = !status_is(call("POST", "/api/admin/users", tenant_admin, create), "HTTP/1.1 201 ");
        first = failed ? NULL : login("alice", "alice-password", "tenant-a");
        failed = failed || st_storage_get_management_user_in_tenant(db_path, "tenant-a", "alice", &stored) != 0
            || token_uid(first, uid, sizeof(uid)) != 0 || strcmp(uid, stored.account_key) != 0;
        if (failed) fprintf(stderr, "first alice's token does not carry her account key: %s\n", response);
        if (!failed) snprintf(first_key, sizeof(first_key), "%s", stored.account_key);
    }
    if (!failed) {
        failed = !status_is(call("DELETE", "/api/admin/users/alice", tenant_admin, NULL), "HTTP/1.1 204 ")
            || !status_is(call("POST", "/api/admin/users", tenant_admin, create), "HTTP/1.1 201 ")
            || st_storage_get_management_user_in_tenant(db_path, "tenant-a", "alice", &stored) != 0
            || strcmp(stored.account_key, first_key) == 0;
        if (failed) fprintf(stderr, "delete and recreate of alice failed: %s\n", response);
    }
    /* The first alice's token names an account row that is gone; it does not pass to the second. */
    if (!failed) {
        int me = call("GET", "/api/admin/me", first, NULL);
        failed = !status_is(me, "HTTP/1.1 401 ") && !status_is(me, "HTTP/1.1 403 ");
        failed = failed || !status_is(call("POST", "/auth/refresh", first, NULL), "HTTP/1.1 401 ");
        if (failed) fprintf(stderr, "first alice's token after the recreate: %.60s\n", response);
    }
    if (!failed) {
        char *second = login("alice", "alice-password", "tenant-a");
        failed = token_uid(second, uid, sizeof(uid)) != 0 || strcmp(uid, stored.account_key) != 0
            || !status_is(call("GET", "/api/admin/me", second, NULL), "HTTP/1.1 200 ")
            || !status_is(call("POST", "/auth/refresh", second, NULL), "HTTP/1.1 200 ");
        if (!failed) {
            char *refreshed = st_json_get_string(body_of_response(), "accessToken");
            failed = token_uid(refreshed, uid, sizeof(uid)) != 0 || strcmp(uid, stored.account_key) != 0;
            free(refreshed);
        }
        if (failed) fprintf(stderr, "second alice: %s\n", response);
        free(second);
    }
    free(first);
    unlink(db_path);
    return failed ? 1 : 0;
}

/* Java ManagementAccountsHttpTests.deletingAnAccountReleasesItsEmail. */
static int test_deleting_an_account_releases_its_email(void)
{
    char dora[2048];
    int failed = open_fresh_database("emails") != 0
        || seed_account("9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5", "dora", "default", "ADMIN", 1) != 0
        || seed_account("0f1e2d3c-4b5a-4968-8776-655443322110", "frank", "default", "USER", 1) != 0
        || seed_account("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "grace", "default", "USER", 1) != 0
        || seed_email("0f1e2d3c-4b5a-4968-8776-655443322110", "frank@example.com") != 0
        || seed_email("1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "grace@example.com") != 0
        || sign_claims("{\"sub\":\"dora\",\"tenant_id\":\"default\",\"role\":\"ADMIN\","
                       "\"uid\":\"9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5\"}", dora, sizeof(dora)) != 0;
    if (failed) fprintf(stderr, "email fixture setup failed\n");
    if (!failed) {
        failed = !status_is(call("DELETE", "/api/admin/users/FRANK", dora, NULL), "HTTP/1.1 204 ")
            || st_storage_management_email_exists(db_path, "frank@example.com") != 0
            || st_storage_management_email_exists(db_path, "grace@example.com") != 1
            || count_rows("SELECT COUNT(*) FROM specus_management_user "
                          "WHERE username = '0f1e2d3c-4b5a-4968-8776-655443322110'") != 0;
        if (failed) fprintf(stderr, "deleting frank did not release exactly his email: %s\n", response);
    }
    unlink(db_path);
    return failed ? 1 : 0;
}

/* The attachment tables as object storage creates them on first use (object_storage.c). */
static const char attachment_schema[] =
    "CREATE TABLE IF NOT EXISTS transfer_attachment ("
    "id INTEGER PRIMARY KEY,tenant_id TEXT,scope TEXT NOT NULL,room_id TEXT,"
    "room_token_hash TEXT,public_transfer_room_id INTEGER,owner_username TEXT,"
    "target_client_id INTEGER,object_key TEXT NOT NULL UNIQUE,file_name TEXT NOT NULL,"
    "mime_type TEXT NOT NULL,size_bytes INTEGER NOT NULL,sha256 TEXT,status TEXT NOT NULL,"
    "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,upload_expires_at TEXT NOT NULL,"
    "expires_at TEXT NOT NULL,uploaded_at TEXT);"
    "CREATE TABLE IF NOT EXISTS transfer_attachment_download_grant ("
    "id INTEGER PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,tenant_id TEXT NOT NULL,"
    "username TEXT NOT NULL,attachment_id INTEGER NOT NULL,created_at TEXT NOT NULL,"
    "expires_at TEXT NOT NULL,consumed_at TEXT,updated_at TEXT);"
    "CREATE TABLE IF NOT EXISTS transfer_attachment_download_usage ("
    "id INTEGER PRIMARY KEY,tenant_id TEXT NOT NULL,username TEXT NOT NULL,"
    "attachment_id INTEGER NOT NULL,size_bytes INTEGER NOT NULL,usage_month TEXT NOT NULL,"
    "created_at TEXT NOT NULL);";

static void utc_text(time_t value, char out[32])
{
    struct tm utc;
    gmtime_r(&value, &utc);
    strftime(out, 32U, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

/* Field text of a vector row, "" when it has none (the caller frees nothing). */
static const char *row_text(const char *row, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(row, key);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
    free(value);
    return out;
}

static long long row_id(const char *row, const char *key)
{
    long long value = 0;
    return st_json_get_i64(row, key, &value) == 0 ? value : -1;
}

/* Writes the accountDeletion seed rows of one table straight into storage. */
static int seed_deletion_rows(const char *seed, const char *table, const char *later)
{
    char **rows = NULL;
    size_t count = 0U;
    if (st_json_get_raw_array(seed, table, &rows, &count) != 0) {
        return -1;
    }
    int rc = 0;
    for (size_t i = 0U; rc == 0 && i < count; ++i) {
        char tenant[96], owner[96], other[96], sql[1024];
        long long id = row_id(rows[i], "id");
        row_text(rows[i], "tenantId", tenant, sizeof(tenant));
        row_text(rows[i], strcmp(table, "downloadGrants") == 0 || strcmp(table, "downloadUsage") == 0
                              ? "username" : "owner", owner, sizeof(owner));
        if (strcmp(table, "clients") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO client_account(id, tenant_id, client_name, owner_username) "
                     "VALUES(%lld,'%s','%s','%s');", id, tenant, row_text(rows[i], "clientName", other, sizeof(other)),
                     owner);
        } else if (strcmp(table, "credentials") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO specus_client_credential(id, tenant_id, owner_username, api_key, "
                     "secret_hash) VALUES(%lld,'%s','%s','acct-del-%lld','unused');", id, tenant, owner, id);
        } else if (strcmp(table, "diagrams") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO user_diagram_document(id, tenant_id, owner_username, name, "
                     "snapshot_data, size_bytes) VALUES(%lld,'%s','%s','acct-del-%lld',x'01',1);", id, tenant, owner, id);
        } else if (strcmp(table, "attachments") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO transfer_attachment(id, tenant_id, scope, owner_username, object_key, "
                     "file_name, mime_type, size_bytes, status, created_at, updated_at, upload_expires_at, expires_at) "
                     "VALUES(%lld,'%s','ADMIN_CLIENT_MESSAGE','%s','acct-del/%lld','file.bin',"
                     "'application/octet-stream',1,'%s','%s','%s','%s','%s');",
                     id, tenant, owner, id, row_text(rows[i], "status", other, sizeof(other)), later, later, later, later);
        } else if (strcmp(table, "downloadGrants") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO transfer_attachment_download_grant(id, token_hash, tenant_id, "
                     "username, attachment_id, created_at, expires_at) VALUES(%lld,'%064lld','%s','%s',%lld,'%s','%s');",
                     id, id, tenant, owner, row_id(rows[i], "attachmentId"), later, later);
        } else if (strcmp(table, "downloadUsage") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO transfer_attachment_download_usage(id, tenant_id, username, "
                     "attachment_id, size_bytes, usage_month, created_at) VALUES(%lld,'%s','%s',%lld,1,'%.7s','%s');",
                     id, tenant, owner, row_id(rows[i], "attachmentId"), later, later);
        } else if (strcmp(table, "acls") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO peer_mesh_acl(id, tenant_id, owner_username, source_client_id, "
                     "source_client_name, target_client_id, target_client_name) VALUES(%lld,'%s','%s',%lld,'acct-del-s',"
                     "%lld,'acct-del-t');", id, tenant, owner, row_id(rows[i], "sourceClientId"),
                     row_id(rows[i], "targetClientId"));
        } else if (strcmp(table, "egressPolicies") == 0) {
            snprintf(sql, sizeof(sql), "INSERT INTO peer_mesh_egress_policy(id, tenant_id, owner_username, "
                     "egress_client_id, egress_client_name) VALUES(%lld,'%s','%s',%lld,'acct-del-e');",
                     id, tenant, owner, row_id(rows[i], "egressClientId"));
        } else {
            snprintf(sql, sizeof(sql), "INSERT INTO peer_mesh_device(id, tenant_id, owner_username, client_id, "
                     "client_name, virtual_ip) VALUES(%lld,'%s','%s',%lld,'acct-del-d','10.77.0.%lld');",
                     id, tenant, owner, row_id(rows[i], "clientId"), id % 250);
        }
        rc = exec_sql(sql);
    }
    st_json_free_string_array(rows, count);
    return rc;
}

/* The owner text of one row (with " active"/" inactive" for an attachment): 1 found, 0 none, -1 error. */
static int stored_owner(const char *table, long long id, const char *now, char *out, size_t out_len)
{
    char sql[512];
    if (strcmp(table, "attachments") == 0) {
        snprintf(sql, sizeof(sql), "SELECT owner_username || CASE WHEN expires_at > '%s' AND (status <> 'PENDING' "
                 "OR upload_expires_at > '%s') THEN ' active' ELSE ' inactive' END FROM transfer_attachment "
                 "WHERE id = %lld", now, now, id);
    } else {
        static const char *const names[][3] = {
            {"clients", "client_account", "owner_username"},
            {"credentials", "specus_client_credential", "owner_username"},
            {"diagrams", "user_diagram_document", "owner_username"},
            {"downloadGrants", "transfer_attachment_download_grant", "username"},
            {"downloadUsage", "transfer_attachment_download_usage", "username"},
            {"acls", "peer_mesh_acl", "owner_username"},
            {"egressPolicies", "peer_mesh_egress_policy", "owner_username"},
            {"devices", "peer_mesh_device", "owner_username"},
        };
        size_t i = 0U;
        while (i < sizeof(names) / sizeof(names[0]) && strcmp(names[i][0], table) != 0) ++i;
        if (i == sizeof(names) / sizeof(names[0])) return -1;
        snprintf(sql, sizeof(sql), "SELECT %s FROM %s WHERE id = %lld", names[i][2], names[i][1], id);
    }
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int found = -1;
    if (sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        int step = sqlite3_step(stmt);
        found = step == SQLITE_ROW ? 1 : step == SQLITE_DONE ? 0 : -1;
        if (found == 1) snprintf(out, out_len, "%s", (const char *)sqlite3_column_text(stmt, 0));
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return found;
}

/* Of the seeded ids of table, exactly those of rowsAfter remain, with their owners. */
static int check_deletion_rows(const char *seed, const char *after, const char *table, const char *now)
{
    char **seeded = NULL, **expected = NULL;
    size_t seeded_count = 0U, expected_count = 0U;
    if (st_json_get_raw_array(seed, table, &seeded, &seeded_count) != 0
        || st_json_get_raw_array(after, table, &expected, &expected_count) != 0) {
        st_json_free_string_array(seeded, seeded_count);
        fprintf(stderr, "accountDeletion: %s missing from the vector\n", table);
        return -1;
    }
    int rc = 0;
    for (size_t i = 0U; i < seeded_count; ++i) {
        long long id = row_id(seeded[i], "id");
        char want[128] = "", got[128] = "";
        int listed = 0;
        for (size_t j = 0U; !listed && j < expected_count; ++j) {
            if (row_id(expected[j], "id") != id) continue;
            listed = 1;
            char owner[96];
            row_text(expected[j], strcmp(table, "downloadGrants") == 0 || strcmp(table, "downloadUsage") == 0
                                      ? "username" : "owner", owner, sizeof(owner));
            int active = 0;
            int has_active = st_json_get_bool(expected[j], "active", &active) == 0;
            snprintf(want, sizeof(want), "%s%s", owner, !has_active ? "" : active ? " active" : " inactive");
        }
        int found = stored_owner(table, id, now, got, sizeof(got));
        if (found < 0 || found != listed || (listed && strcmp(want, got) != 0)) {
            fprintf(stderr, "accountDeletion: %s %lld is '%s' (found %d), want '%s' (listed %d)\n", table, id, got,
                    found, want, listed);
            rc = -1;
        }
    }
    st_json_free_string_array(seeded, seeded_count);
    st_json_free_string_array(expected, expected_count);
    return rc;
}

static void trim_whitespace(const char *in, char *out, size_t out_len)
{
    size_t w = 0U;
    for (; *in != '\0' && w + 1U < out_len; ++in) {
        if (*in != ' ' && *in != '\n' && *in != '\r' && *in != '\t') out[w++] = *in;
    }
    out[w] = '\0';
}

/* Java ManagementAccountsHttpTests.replaysTheAccountDeletionVector (management-accounts.md 7.1). */
static int test_account_deletion_vector(const char *vector)
{
    static const char *const tables[] = {"clients", "credentials", "diagrams", "attachments", "downloadGrants",
                                         "downloadUsage", "acls", "egressPolicies", "devices"};
    char *deletion = st_json_get_top_level_raw(vector, "accountDeletion");
    char *seed = deletion == NULL ? NULL : st_json_get_top_level_raw(deletion, "seed");
    char *after = deletion == NULL ? NULL : st_json_get_top_level_raw(deletion, "rowsAfter");
    char *actor_claims = deletion == NULL ? NULL : st_json_get_top_level_raw(deletion, "actor");
    char actor[2048];
    char later[32];
    utc_text(time(NULL) + 3600, later);
    int failed = deletion == NULL || seed == NULL || after == NULL || actor_claims == NULL
        || open_fresh_database("deletion") != 0 || exec_sql(attachment_schema) != 0
        || seed_vector_accounts(deletion) != 0 || sign_claims(actor_claims, actor, sizeof(actor)) != 0;
    for (size_t i = 0U; !failed && i < sizeof(tables) / sizeof(tables[0]); ++i) {
        failed = seed_deletion_rows(seed, tables[i], later) != 0;
    }
    if (failed) fprintf(stderr, "account deletion fixture setup failed\n");
    char **steps = NULL;
    size_t step_count = 0U;
    failed = failed || st_json_get_raw_array(deletion, "steps", &steps, &step_count) != 0 || step_count == 0U;
    for (size_t i = 0U; !failed && i < step_count; ++i) {
        const char *step = steps[i];
        char *expect = st_json_get_top_level_raw(step, "expect");
        char *delete_user = st_json_get_top_level_string(step, "deleteUser");
        char *get = st_json_get_top_level_string(step, "get");
        char *fixture = st_json_get_top_level_string(step, "fixture");
        char path[256], sql[512], text[96], text2[96];
        long long status = 0;
        if (delete_user != NULL) {
            snprintf(path, sizeof(path), "/api/admin/users/%s", delete_user);
            snprintf(text, sizeof(text), "HTTP/1.1 %lld ",
                     expect != NULL && st_json_get_i64(expect, "status", &status) == 0 ? status : 0LL);
            failed = !status_is(call("DELETE", path, actor, NULL), text);
            if (!failed && status == 409) {
                long long clients = -1, credentials = -1, want_clients = -2, want_credentials = -2;
                char *error = st_json_get_top_level_string(body_of_response(), "error");
                failed = error == NULL || *error == '\0'
                    || st_json_get_i64(body_of_response(), "clients", &clients) != 0
                    || st_json_get_i64(body_of_response(), "credentials", &credentials) != 0
                    || st_json_get_i64(expect, "clients", &want_clients) != 0
                    || st_json_get_i64(expect, "credentials", &want_credentials) != 0
                    || clients != want_clients || credentials != want_credentials;
                free(error);
            }
        } else if (get != NULL) {
            char *as = st_json_get_top_level_raw(step, "as");
            char *body = expect == NULL ? NULL : st_json_get_top_level_raw(expect, "body");
            char token[2048], want[256], got[256];
            failed = as == NULL || body == NULL || sign_claims(as, token, sizeof(token)) != 0
                || st_json_get_i64(expect, "status", &status) != 0;
            snprintf(text, sizeof(text), "HTTP/1.1 %lld ", status);
            if (!failed) {
                failed = !status_is(call("GET", get, token, NULL), text);
                trim_whitespace(body, want, sizeof(want));
                trim_whitespace(body_of_response(), got, sizeof(got));
                failed = failed || strcmp(want, got) != 0;
            }
            free(as);
            free(body);
        } else if (fixture != NULL && strcmp(fixture, "transfer-client") == 0) {
            long long id = row_id(step, "id");
            row_text(step, "owner", text, sizeof(text));
            snprintf(sql, sizeof(sql), "UPDATE client_account SET owner_username = '%s' WHERE id = %lld;"
                     "UPDATE peer_mesh_device SET owner_username = '%s' WHERE client_id = %lld;", text, id, text, id);
            failed = exec_sql(sql) != 0;
        } else if (fixture != NULL && strcmp(fixture, "delete-client") == 0) {
            snprintf(sql, sizeof(sql), "DELETE FROM client_account WHERE id = %lld;", row_id(step, "id"));
            failed = exec_sql(sql) != 0;
        } else if (fixture != NULL && strcmp(fixture, "delete-credential") == 0) {
            snprintf(sql, sizeof(sql), "DELETE FROM specus_client_credential WHERE id = %lld;", row_id(step, "id"));
            failed = exec_sql(sql) != 0;
        } else if (fixture != NULL && strcmp(fixture, "create-account") == 0) {
            char key[96], role[16];
            failed = seed_account(row_text(step, "accountKey", key, sizeof(key)),
                                  row_text(step, "loginName", text, sizeof(text)),
                                  row_text(step, "tenantId", text2, sizeof(text2)),
                                  row_text(step, "role", role, sizeof(role)), 1) != 0;
        } else {
            failed = 1;
        }
        if (failed) fprintf(stderr, "accountDeletion step %zu %s: %s\n", i, step, response);
        free(expect);
        free(delete_user);
        free(get);
        free(fixture);
    }
    st_json_free_string_array(steps, step_count);
    char now[32];
    utc_text(time(NULL), now);
    for (size_t i = 0U; !failed && i < sizeof(tables) / sizeof(tables[0]); ++i) {
        failed = check_deletion_rows(seed, after, tables[i], now) != 0;
    }
    char **accounts = NULL;
    size_t account_count = 0U;
    if (!failed) {
        failed = st_json_get_raw_array(deletion, "accountsAfter", &accounts, &account_count) != 0;
        long long remaining = count_rows("SELECT COUNT(*) FROM specus_management_user "
                                         "WHERE tenant_id IN ('tenant-d','tenant-e')");
        failed = failed || remaining != (long long)account_count;
        for (size_t i = 0U; !failed && i < account_count; ++i) {
            char key[96], login_name[96], tenant[96], sql[512];
            snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM specus_management_user WHERE username = '%s' "
                     "AND login_name = '%s' AND tenant_id = '%s'",
                     row_text(accounts[i], "accountKey", key, sizeof(key)),
                     row_text(accounts[i], "loginName", login_name, sizeof(login_name)),
                     row_text(accounts[i], "tenantId", tenant, sizeof(tenant)));
            failed = count_rows(sql) != 1;
        }
        if (failed) fprintf(stderr, "accountDeletion: the accounts left do not match accountsAfter\n");
    }
    st_json_free_string_array(accounts, account_count);
    free(deletion);
    free(seed);
    free(after);
    free(actor_claims);
    unlink(db_path);
    return failed ? 1 : 0;
}

/* Java ManagementUserSchemaMigratorTests.removesEmailRecordsOfAccountsThatNoLongerExist. */
static int test_init_removes_email_records_of_deleted_accounts(void)
{
    int failed = open_fresh_database("orphans") != 0
        || seed_account("kept-key", "kept", "default", "USER", 1) != 0
        || seed_email("kept-key", "kept@example.com") != 0
        || seed_email("deleted-key", "released@example.com") != 0
        || st_storage_init(db_path, 0) != 0
        || st_storage_init(db_path, 0) != 0
        || count_rows("SELECT COUNT(*) FROM specus_management_user_email WHERE email = 'released@example.com'") != 0
        || count_rows("SELECT COUNT(*) FROM specus_management_user_email WHERE email = 'kept@example.com'") != 1;
    if (failed) fprintf(stderr, "init did not remove exactly the orphaned email record\n");
    unlink(db_path);
    return failed ? 1 : 0;
}

int main(void)
{
    char *vector = read_vector();
    if (vector == NULL) {
        fprintf(stderr, "management accounts vector could not be read\n");
        return 1;
    }
    int failed = test_token_resolution_vector(vector)
        | test_user_list_vector(vector)
        | test_deleted_account_tokens_do_not_pass_to_a_recreated_account()
        | test_deleting_an_account_releases_its_email()
        | test_init_removes_email_records_of_deleted_accounts()
        | test_account_deletion_vector(vector);
    free(vector);
    unsetenv("SPECUS_DATABASE_PATH");
    unsetenv("SPECUS_AUTH_PASSWORD");
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    if (failed) {
        return 1;
    }
    printf("management accounts tests passed\n");
    return 0;
}
