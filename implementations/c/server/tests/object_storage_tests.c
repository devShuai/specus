#define _POSIX_C_SOURCE 200809L

#include "object_storage.h"

#include "admin_http.h"
#include "json.h"
#include "public_room.h"
#include "security.h"
#include "storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static int configure(void)
{
    return setenv("SPECUS_OBJECT_STORAGE_PROVIDER", "aliyun-oss", 1)
        || setenv("SPECUS_OBJECT_STORAGE_ENDPOINT", "https://oss-cn-hangzhou.aliyuncs.com", 1)
        || setenv("SPECUS_OBJECT_STORAGE_REGION", "cn-hangzhou", 1)
        || setenv("SPECUS_OBJECT_STORAGE_BUCKET", "examplebucket", 1)
        || setenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID", "test-access-key", 1)
        || setenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET", "test-secret-key", 1)
        || setenv("SPECUS_OBJECT_STORAGE_PREFIX", "prefix", 1);
}

static int test_download_vector(void)
{
    unsetenv("SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL");
    char expires[41];
    char *url = st_object_storage_presign_for_tests(
        "GET", "prefix/example.txt", NULL, "grant-123", 600,
        1733197460LL, expires, NULL);
    int ok = url != NULL
        && strcmp(expires, "2024-12-03T03:54:20Z") == 0
        && strstr(url, "https://examplebucket.oss-cn-hangzhou.aliyuncs.com/prefix/example.txt?") == url
        && strstr(url, "x-oss-credential=test-access-key%2F20241203%2Fcn-hangzhou%2Foss%2Faliyun_v4_request") != NULL
        && strstr(url, "x-oss-date=20241203T034420Z") != NULL
        && strstr(url, "x-st-grant=grant-123") != NULL
        && strstr(url, "x-oss-signature=c2fae9c2ac1a8e6ec5d0ef73e0ac015f40deaf92c3ec5626139a7cacb71225ac") != NULL;
    if (!ok) fprintf(stderr, "OSS V4 Java parity vector mismatch: %s\n", url == NULL ? "(null)" : url);
    free(url);
    return ok ? 0 : -1;
}

static int test_upload_callback_header(void)
{
    if (setenv("SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL",
               "https://specus.example/api/public/transfer/oss-callback", 1) != 0) return -1;
    char expires[41];
    char *callback = NULL;
    char *url = st_object_storage_presign_for_tests(
        "PUT", "prefix/example.txt", "text/plain", NULL, 600,
        1733197460LL, expires, &callback);
    unsigned char decoded[4096];
    int decoded_len = callback == NULL ? -1
        : EVP_DecodeBlock(decoded, (const unsigned char *)callback, (int)strlen(callback));
    if (decoded_len >= 0) decoded[decoded_len] = '\0';
    int ok = url != NULL && callback != NULL && decoded_len > 0
        && strstr((const char *)decoded,
                  "\"callbackUrl\":\"https://specus.example/api/public/transfer/oss-callback\"") != NULL
        && strstr((const char *)decoded, "${object}") != NULL
        && strstr((const char *)decoded, "\"callbackBodyType\":\"application/json\"") != NULL
        && strstr((const char *)decoded, "\"callbackSNI\":true") != NULL;
    if (!ok) fprintf(stderr, "OSS callback header mismatch\n");
    free(url);
    free(callback);
    return ok ? 0 : -1;
}

static int test_expiration_cleanup(void)
{
    const char *database_path = "/tmp/specus_c_object_cleanup_tests.db";
    unlink(database_path);
    setenv("SPECUS_DATABASE_PATH", database_path, 1);
    setenv("SPECUS_OBJECT_STORAGE_PROVIDER", "disabled", 1);
    if (st_object_storage_cleanup_expired() != 0) return -1;
    sqlite3 *db = NULL;
    char *error = NULL;
    int ok = sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_exec(db,
            "INSERT INTO transfer_attachment(id,tenant_id,scope,owner_username,object_key,file_name,"
            "mime_type,size_bytes,status,created_at,updated_at,upload_expires_at,expires_at) VALUES("
            "1,'tenant','MANAGEMENT','owner','prefix/expired.bin','expired.bin',"
            "'application/octet-stream',1,'UPLOADED','2000-01-01T00:00:00Z',"
            "'2000-01-01T00:00:00Z','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z');"
            "INSERT INTO transfer_attachment_download_grant(id,token_hash,tenant_id,username,attachment_id,"
            "created_at,expires_at) VALUES(2,'hash','tenant','owner',1,"
            "'2000-01-01T00:00:00Z','2000-01-01T00:00:00Z');",
            NULL, NULL, &error) == SQLITE_OK;
    sqlite3_free(error);
    if (db != NULL) sqlite3_close(db);
    if (ok) ok = st_object_storage_cleanup_expired() == 0;
    sqlite3_stmt *stmt = NULL;
    if (ok) ok = sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
            "SELECT (SELECT status FROM transfer_attachment WHERE id=1),"
            "(SELECT COUNT(*) FROM transfer_attachment_download_grant)",
            -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW
        && strcmp((const char *)sqlite3_column_text(stmt, 0), "EXPIRED") == 0
        && sqlite3_column_int(stmt, 1) == 0;
    sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(database_path);
    return ok ? 0 : -1;
}

/* GET /api/public/transfer/attachments/capabilities (protocol/spec/transfer-capabilities.md). */

#define CAP_ROUTE "/api/public/transfer/attachments/capabilities"
#define CAP_SECRET "object-storage-capabilities-test-jwt-secret-2026"
/* Per-process paths: other builds may run this binary concurrently on the same machine. */
static char cap_db_path[96];
static char cap_missing_db_path[96];
#define CAP_DB cap_db_path
#define CAP_MISSING_DB cap_missing_db_path
#define CAP_FUTURE "2999-01-01T00:00:00Z"
#define CAP_PAST "2000-01-01T00:00:00Z"
#define CAP_GIB 1073741824LL
#define CAP_DEFAULT_MAX 536870912LL

typedef struct {
    long long id;
    const char *tenant;
    const char *owner;
    const char *scope;
    const char *status;
    long long size;
    const char *upload_expires_at;
    const char *expires_at;
} cap_attachment;

typedef struct {
    long long id;
    const char *tenant;
    const char *username;
    const char *month;
    long long size;
} cap_usage;

typedef struct {
    const char *enabled;
    long long max_bytes;
    long long retention;
    long long storage_quota;
    long long storage_used;
    long long storage_remaining;
    long long download_quota;
    long long download_used;
    long long download_remaining;
} cap_expected;

static void cap_set_limits(const char *storage_quota,
                           const char *download_quota,
                           const char *max_bytes,
                           const char *retention)
{
    static const char *const names[] = {
        "SPECUS_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES",
        "SPECUS_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES",
        "SPECUS_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES",
        "SPECUS_OBJECT_STORAGE_RETENTION_HOURS"
    };
    const char *values[] = {storage_quota, download_quota, max_bytes, retention};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (values[i] == NULL) unsetenv(names[i]);
        else setenv(names[i], values[i], 1);
    }
}

static int cap_exec(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int ok = sqlite3_open(path, &db) == SQLITE_OK && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    if (!ok) fprintf(stderr, "capabilities sql failed: %s\n", db == NULL ? "open" : sqlite3_errmsg(db));
    if (db != NULL) sqlite3_close(db);
    return ok ? 0 : -1;
}

/*
 * Creates the production schema through the module itself (the expiry sweep has nothing to do
 * on an empty database), then seeds rows over a separate connection.
 */
static int cap_create_database(const char *path,
                               const cap_attachment *attachments,
                               size_t attachment_count,
                               const cap_usage *usage,
                               size_t usage_count)
{
    unlink(path);
    setenv("SPECUS_DATABASE_PATH", path, 1);
    if (st_object_storage_cleanup_expired() != 0) return -1;
    sqlite3 *db = NULL;
    int ok = sqlite3_open(path, &db) == SQLITE_OK;
    for (size_t i = 0; ok && i < attachment_count; ++i) {
        const cap_attachment *row = &attachments[i];
        char key[64];
        snprintf(key, sizeof(key), "prefix/capabilities/%lld.bin", row->id);
        sqlite3_stmt *stmt = NULL;
        ok = sqlite3_prepare_v2(db,
                "INSERT INTO transfer_attachment(id,tenant_id,scope,owner_username,object_key,file_name,"
                "mime_type,size_bytes,status,created_at,updated_at,upload_expires_at,expires_at) "
                "VALUES(?,?,?,?,?,'a.bin','application/octet-stream',?,?,'2000-01-01T00:00:00Z',"
                "'2000-01-01T00:00:00Z',?,?)", -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 1, row->id) == SQLITE_OK
            && sqlite3_bind_text(stmt, 2, row->tenant, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 3, row->scope, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 4, row->owner, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 5, key, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 6, row->size) == SQLITE_OK
            && sqlite3_bind_text(stmt, 7, row->status, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 8, row->upload_expires_at, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 9, row->expires_at, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
    }
    for (size_t i = 0; ok && i < usage_count; ++i) {
        const cap_usage *row = &usage[i];
        sqlite3_stmt *stmt = NULL;
        ok = sqlite3_prepare_v2(db,
                "INSERT INTO transfer_attachment_download_usage(id,tenant_id,username,attachment_id,"
                "size_bytes,usage_month,created_at) VALUES(?,?,?,1,?,?,'2000-01-01T00:00:00Z')",
                -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 1, row->id) == SQLITE_OK
            && sqlite3_bind_text(stmt, 2, row->tenant, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_text(stmt, 3, row->username, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 4, row->size) == SQLITE_OK
            && sqlite3_bind_text(stmt, 5, row->month, -1, SQLITE_TRANSIENT) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
    }
    /* The admin entry point re-reads the account a bearer token names (as Java's
     * ManagementContextResolver does), so the accounts the HTTP checks use must exist. Usernames
     * are unique across tenants in the C store, so t2/alice is checked on the module directly. */
    if (ok) {
        ok = sqlite3_exec(db,
                "CREATE TABLE IF NOT EXISTS specus_management_user(username TEXT PRIMARY KEY,"
                "tenant_id TEXT NOT NULL DEFAULT 'default',password_hash TEXT NOT NULL,"
                "role TEXT NOT NULL DEFAULT 'USER',enabled INTEGER NOT NULL DEFAULT 1,"
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
                "INSERT OR REPLACE INTO specus_management_user(username,tenant_id,password_hash,role,enabled) "
                "VALUES('alice','t1','unused','USER',1),('bob','t1','unused','USER',1),"
                "('root','t1','unused','ADMIN',1);",
                NULL, NULL, NULL) == SQLITE_OK;
    }
    if (!ok) fprintf(stderr, "capabilities seed failed: %s\n", db == NULL ? "open" : sqlite3_errmsg(db));
    if (db != NULL) sqlite3_close(db);
    return ok ? 0 : -1;
}

static unsigned char *cap_read_file(const char *path, size_t *len)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL) return NULL;
    unsigned char *data = NULL;
    size_t capacity = 0U;
    *len = 0U;
    for (;;) {
        if (*len == capacity) {
            size_t next = capacity == 0U ? 65536U : capacity * 2U;
            unsigned char *grown = (unsigned char *)realloc(data, next);
            if (grown == NULL) {
                free(data);
                fclose(file);
                return NULL;
            }
            data = grown;
            capacity = next;
        }
        size_t read_len = fread(data + *len, 1U, capacity - *len, file);
        *len += read_len;
        if (read_len == 0U) break;
    }
    int failed = ferror(file);
    fclose(file);
    if (failed) {
        free(data);
        return NULL;
    }
    return data;
}

/* Byte-for-byte comparison: any committed write would at least bump the file change counter. */
static int cap_file_unchanged(const char *path, const unsigned char *before, size_t before_len)
{
    size_t after_len = 0U;
    unsigned char *after = cap_read_file(path, &after_len);
    char journal[256];
    snprintf(journal, sizeof(journal), "%s-journal", path);
    int ok = after != NULL && before != NULL && after_len == before_len
        && memcmp(after, before, before_len) == 0 && access(journal, F_OK) != 0;
    free(after);
    if (!ok) fprintf(stderr, "capabilities changed the database file %s\n", path);
    return ok ? 0 : -1;
}

static int cap_bearer(const char *username,
                      const char *tenant,
                      const char *role,
                      const char *secret,
                      char *out,
                      size_t out_len)
{
    char token[2048];
    if (st_security_issue_local_token(username, tenant, role, secret, 600, token, sizeof(token)) != 0) return -1;
    int written = snprintf(out, out_len, "Bearer %s", token);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

/* Goes through the admin HTTP entry point, so routing and bearer authentication are covered. */
static int cap_get(const char *path,
                   const char *username,
                   const char *tenant,
                   const char *role,
                   char *out,
                   size_t out_len)
{
    char authorization[2300];
    if (cap_bearer(username, tenant, role, CAP_SECRET, authorization, sizeof(authorization)) != 0) return -1;
    return st_admin_build_response_with_auth("GET", path, authorization, NULL, out, out_len);
}

/*
 * The route itself with an identity, bypassing the admin entry point. Used where the database is
 * missing or broken on purpose: through HTTP the account lookup would answer before the route.
 */
static int cap_get_module(const char *path,
                          const char *username,
                          const char *tenant,
                          char *out,
                          size_t out_len)
{
    const st_object_storage_identity identity = {tenant, username, 0, 1};
    return st_object_storage_build_response("GET", path, NULL, "", NULL, NULL, &identity, out, out_len);
}

static const char *cap_body(const char *response)
{
    const char *body = response == NULL ? NULL : strstr(response, "\r\n\r\n");
    return body == NULL ? NULL : body + 4;
}

/* Compares the raw JSON token, so numbers must be unquoted integers and strings exact. */
static int cap_expect_raw(const char *response, const char *key, const char *expected)
{
    const char *body = cap_body(response);
    char *raw = body == NULL ? NULL : st_json_get_top_level_raw(body, key);
    int ok = raw != NULL && strcmp(raw, expected) == 0;
    if (!ok) fprintf(stderr, "capabilities %s: expected %s, got %s\n", key, expected, raw == NULL ? "(missing)" : raw);
    free(raw);
    return ok ? 0 : -1;
}

static int cap_expect_i64(const char *response, const char *key, long long expected)
{
    char text[32];
    snprintf(text, sizeof(text), "%lld", expected);
    return cap_expect_raw(response, key, text);
}

static int cap_expect_text(const char *response, const char *key, const char *expected)
{
    char quoted[64];
    snprintf(quoted, sizeof(quoted), "\"%s\"", expected);
    return cap_expect_raw(response, key, quoted);
}

static int cap_expect_snapshot(int len, const char *response, const cap_expected *expected)
{
    const char *body = cap_body(response);
    if (len <= 0 || strncmp(response, "HTTP/1.1 200 OK\r\n", 17U) != 0
        || strstr(response, "\r\nCache-Control: private, no-store\r\n") == NULL
        || body == NULL || !st_json_is_valid_object(body)) {
        fprintf(stderr, "capabilities is not a private 200 JSON object: %s\n", len <= 0 ? "(none)" : response);
        return -1;
    }
    int failed = cap_expect_raw(response, "schemaVersion", "1")
        | cap_expect_raw(response, "storageEnabled", expected->enabled)
        | cap_expect_i64(response, "maxAttachmentBytes", expected->max_bytes)
        | cap_expect_i64(response, "retentionHours", expected->retention)
        | cap_expect_i64(response, "storageQuotaBytes", expected->storage_quota)
        | cap_expect_i64(response, "storageUsedBytes", expected->storage_used)
        | cap_expect_i64(response, "storageRemainingBytes", expected->storage_remaining)
        | cap_expect_i64(response, "monthlyDownloadQuotaBytes", expected->download_quota)
        | cap_expect_i64(response, "monthlyDownloadUsedBytes", expected->download_used)
        | cap_expect_i64(response, "monthlyDownloadRemainingBytes", expected->download_remaining)
        | cap_expect_raw(response, "downloadGrantSingleUse", "true");
    return failed ? -1 : 0;
}

/* A failed read must surface as an error status, never as a body carrying zero usage. */
static int cap_expect_failure(int len, const char *response, const char *status_line, const char *label)
{
    int ok = len > 0 && strncmp(response, status_line, strlen(status_line)) == 0
        && strstr(response, "storageUsedBytes") == NULL && strstr(response, "RemainingBytes") == NULL;
    if (!ok) fprintf(stderr, "capabilities %s: expected %s, got %s\n", label, status_line, len <= 0 ? "(none)" : response);
    return ok ? 0 : -1;
}

static int cap_month_text(int year, int month, char out[8])
{
    return snprintf(out, 8U, "%04d-%02d", year, month) == 7 ? 0 : -1;
}

static int cap_current_months(char previous[8], char current[8], char next[8], char resets_at[41])
{
    time_t now = time(NULL);
    struct tm value;
    if (gmtime_r(&now, &value) == NULL) return -1;
    int year = value.tm_year + 1900, month = value.tm_mon + 1;
    int next_year = month == 12 ? year + 1 : year, next_month = month == 12 ? 1 : month + 1;
    if (cap_month_text(month == 1 ? year - 1 : year, month == 1 ? 12 : month - 1, previous) != 0
        || cap_month_text(year, month, current) != 0
        || cap_month_text(next_year, next_month, next) != 0) return -1;
    return snprintf(resets_at, 41U, "%04d-%02d-01T00:00:00Z", next_year, next_month) == 20 ? 0 : -1;
}

static int cap_seed_single_account(void)
{
    const cap_attachment attachments[] = {
        {1, "t1", "alice", "PUBLIC_TRANSFER", "UPLOADED", 64, CAP_PAST, CAP_FUTURE},
    };
    return cap_create_database(CAP_DB, attachments, 1U, NULL, 0U);
}

static int test_capabilities_requires_authentication(void)
{
    if (configure() != 0 || cap_seed_single_account() != 0) return -1;
    char response[4096];
    int len = st_admin_build_response_with_auth("GET", CAP_ROUTE, NULL, NULL, response, sizeof(response));
    int failed = cap_expect_failure(len, response, "HTTP/1.1 401 ", "without credentials");
    len = st_admin_build_response_with_auth("GET", CAP_ROUTE, "Basic YWxpY2U6c2VjcmV0", NULL, response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 401 ", "with a non-bearer credential");
    char forged[2300];
    if (cap_bearer("alice", "t1", "USER", "another-secret-that-the-server-does-not-know", forged, sizeof(forged)) != 0) return -1;
    len = st_admin_build_response_with_auth("GET", CAP_ROUTE, forged, NULL, response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 401 ", "with a token signed by another key");
    /* The module refuses an unauthenticated or incomplete identity on its own as well. */
    const st_object_storage_identity anonymous = {"t1", "alice", 0, 0};
    const st_object_storage_identity nameless = {"t1", "", 0, 1};
    len = st_object_storage_build_response("GET", CAP_ROUTE, NULL, "", NULL, NULL, &anonymous, response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 401 ", "with an unauthenticated identity");
    len = st_object_storage_capabilities_for_tests(&nameless, 1798761599LL, response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 401 ", "without a username");
    /* Read-only resource: other methods are rejected before anything is read. */
    char authorization[2300];
    if (cap_bearer("alice", "t1", "USER", CAP_SECRET, authorization, sizeof(authorization)) != 0) return -1;
    len = st_admin_build_response_with_auth("POST", CAP_ROUTE, authorization, "{}", response, sizeof(response));
    if (len <= 0 || strncmp(response, "HTTP/1.1 405 ", 13U) != 0 || strstr(response, "\r\nAllow: GET\r\n") == NULL) {
        fprintf(stderr, "capabilities POST should be 405 with Allow: GET\n");
        failed = -1;
    }
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return failed ? -1 : 0;
}

/* Seeds two tenants and two accounts, then checks every account sees only its own records. */
static int cap_account_snapshots(const char *previous, const char *current, const char *next, const char *resets_at)
{
    const cap_attachment attachments[] = {
        /* Counted for t1/alice: both attachment scopes, a live reservation and live objects. */
        {1, "t1", "alice", "PUBLIC_TRANSFER", "UPLOADED", 100, CAP_PAST, CAP_FUTURE},
        {2, "t1", "alice", "ADMIN_CLIENT_MESSAGE", "UPLOADED", 200, CAP_PAST, CAP_FUTURE},
        {3, "t1", "alice", "PUBLIC_TRANSFER", "PENDING", 30, CAP_FUTURE, CAP_FUTURE},
        /* Not counted: a reservation whose upload window ended, an expired object, a swept row. */
        {4, "t1", "alice", "PUBLIC_TRANSFER", "PENDING", 4000, CAP_PAST, CAP_FUTURE},
        {5, "t1", "alice", "ADMIN_CLIENT_MESSAGE", "UPLOADED", 5000, CAP_PAST, CAP_PAST},
        {6, "t1", "alice", "PUBLIC_TRANSFER", "EXPIRED", 6000, CAP_FUTURE, CAP_FUTURE},
        /* The same username in another tenant, and another account in the same tenant. */
        {7, "t2", "alice", "PUBLIC_TRANSFER", "UPLOADED", 7000, CAP_PAST, CAP_FUTURE},
        {8, "t1", "bob", "PUBLIC_TRANSFER", "PENDING", 8000, CAP_FUTURE, CAP_FUTURE},
    };
    const cap_usage usage[] = {
        {1, "t1", "alice", current, 40},
        {2, "t1", "alice", current, 2},
        {3, "t1", "alice", previous, 9000},
        {4, "t1", "alice", next, 9100},
        {5, "t2", "alice", current, 9200},
        {6, "t1", "bob", current, 9300},
    };
    if (cap_create_database(CAP_DB, attachments, sizeof(attachments) / sizeof(attachments[0]),
                            usage, sizeof(usage) / sizeof(usage[0])) != 0) return -1;
    size_t before_len = 0U;
    unsigned char *before = cap_read_file(CAP_DB, &before_len);
    if (before == NULL) return -1;

    char response[4096];
    const cap_expected alice = {"true", 4096, 5, 1000, 330, 670, 50, 42, 8};
    int len = cap_get(CAP_ROUTE, "alice", "t1", "USER", response, sizeof(response));
    int failed = cap_expect_snapshot(len, response, &alice)
        | cap_expect_text(response, "downloadUsageMonth", current)
        | cap_expect_text(response, "downloadResetsAt", resets_at);
    const char *body = cap_body(response);
    char *checked_at = body == NULL ? NULL : st_json_get_top_level_raw(body, "checkedAt");
    if (checked_at == NULL || strlen(checked_at) != 22U || strncmp(checked_at + 1, current, 7U) != 0
        || checked_at[20] != 'Z') {
        fprintf(stderr, "capabilities checkedAt is not a UTC second in %s: %s\n", current,
                checked_at == NULL ? "(missing)" : checked_at);
        failed = -1;
    }
    free(checked_at);
    /* Selector-looking query parameters are ignored: identity comes from the token only. */
    len = cap_get(CAP_ROUTE "?tenantId=t2&username=bob&roomId=r&roomToken=x&fileName=f.bin",
                  "alice", "t1", "USER", response, sizeof(response));
    failed |= cap_expect_snapshot(len, response, &alice);
    /* Usage is reported uncapped while the remaining figures floor at zero. */
    const cap_expected bob = {"true", 4096, 5, 1000, 8000, 0, 50, 9300, 0};
    len = cap_get(CAP_ROUTE, "bob", "t1", "USER", response, sizeof(response));
    failed |= cap_expect_snapshot(len, response, &bob);
    const cap_expected other_tenant = {"true", 4096, 5, 1000, 7000, 0, 50, 9200, 0};
    len = cap_get_module(CAP_ROUTE, "alice", "t2", response, sizeof(response));
    failed |= cap_expect_snapshot(len, response, &other_tenant);
    /* An administrator still gets only its own account, never the tenant total. */
    const cap_expected administrator = {"true", 4096, 5, 1000, 0, 1000, 50, 0, 50};
    len = cap_get(CAP_ROUTE, "root", "t1", "ADMIN", response, sizeof(response));
    failed |= cap_expect_snapshot(len, response, &administrator);

    failed |= cap_file_unchanged(CAP_DB, before, before_len);
    free(before);
    return failed ? -1 : 0;
}

static int test_capabilities_account_snapshots(void)
{
    if (configure() != 0) return -1;
    cap_set_limits("1000", "50", "4096", "5");
    int rc = -1;
    /* Download rows are seeded for the current month; retry once if the month turns mid-test. */
    for (int attempt = 0; attempt < 2; ++attempt) {
        char previous[8], current[8], next[8], resets_at[41], after[8], ignored[8], ignored_next[8], ignored_reset[41];
        if (cap_current_months(previous, current, next, resets_at) != 0) return -1;
        rc = cap_account_snapshots(previous, current, next, resets_at);
        if (cap_current_months(ignored, after, ignored_next, ignored_reset) != 0) return -1;
        if (strcmp(current, after) == 0) break;
    }
    cap_set_limits(NULL, NULL, NULL, NULL);
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return rc;
}

static int cap_expect_exact(int len, const char *response, const char *expected_body, const char *label)
{
    const char *body = cap_body(response);
    int ok = len > 0 && strncmp(response, "HTTP/1.1 200 OK\r\n", 17U) == 0
        && strstr(response, "\r\nCache-Control: private, no-store\r\n") != NULL
        && body != NULL && strcmp(body, expected_body) == 0;
    if (!ok) fprintf(stderr, "capabilities %s mismatch:\n  expected %s\n  got      %s\n", label, expected_body,
                     body == NULL ? "(none)" : body);
    return ok ? 0 : -1;
}

/* A fixed instant makes the UTC month rollover and the strict expiry comparison deterministic. */
static int test_capabilities_month_and_expiry_boundaries(void)
{
    if (configure() != 0) return -1;
    cap_set_limits("100", "100", NULL, NULL);
    const cap_attachment attachments[] = {
        /* Live one second before the new month and expired exactly at it. */
        {1, "t1", "alice", "PUBLIC_TRANSFER", "UPLOADED", 19, "2026-12-31T00:15:00Z", "2027-01-01T00:00:00Z"},
        {2, "t1", "alice", "PUBLIC_TRANSFER", "PENDING", 23, "2027-01-01T00:00:00Z", "2027-01-04T00:00:00Z"},
        /* Live on both sides of the boundary. */
        {3, "t1", "alice", "ADMIN_CLIENT_MESSAGE", "UPLOADED", 29, "2026-12-31T00:15:00Z", "2027-01-04T00:00:00Z"},
        /* Upload window ending exactly at the first instant: expiry is strict, so never counted. */
        {4, "t1", "alice", "PUBLIC_TRANSFER", "PENDING", 31, "2026-12-31T23:59:59Z", "2027-01-04T00:00:00Z"},
    };
    const cap_usage usage[] = {
        {1, "t1", "alice", "2026-11", 17},
        {2, "t1", "alice", "2026-12", 11},
        {3, "t1", "alice", "2027-01", 13},
    };
    if (cap_create_database(CAP_DB, attachments, sizeof(attachments) / sizeof(attachments[0]),
                            usage, sizeof(usage) / sizeof(usage[0])) != 0) return -1;
    const st_object_storage_identity alice = {"t1", "alice", 0, 1};
    char response[4096];
    int len = st_object_storage_capabilities_for_tests(&alice, 1798761599LL, response, sizeof(response));
    int failed = cap_expect_exact(len, response,
        "{\"schemaVersion\":1,\"checkedAt\":\"2026-12-31T23:59:59Z\",\"storageEnabled\":true,"
        "\"maxAttachmentBytes\":536870912,\"retentionHours\":72,"
        "\"storageQuotaBytes\":100,\"storageUsedBytes\":71,\"storageRemainingBytes\":29,"
        "\"monthlyDownloadQuotaBytes\":100,\"monthlyDownloadUsedBytes\":11,"
        "\"monthlyDownloadRemainingBytes\":89,\"downloadUsageMonth\":\"2026-12\","
        "\"downloadResetsAt\":\"2027-01-01T00:00:00Z\",\"downloadGrantSingleUse\":true}",
        "last second of December");
    len = st_object_storage_capabilities_for_tests(&alice, 1798761600LL, response, sizeof(response));
    failed |= cap_expect_exact(len, response,
        "{\"schemaVersion\":1,\"checkedAt\":\"2027-01-01T00:00:00Z\",\"storageEnabled\":true,"
        "\"maxAttachmentBytes\":536870912,\"retentionHours\":72,"
        "\"storageQuotaBytes\":100,\"storageUsedBytes\":29,\"storageRemainingBytes\":71,"
        "\"monthlyDownloadQuotaBytes\":100,\"monthlyDownloadUsedBytes\":13,"
        "\"monthlyDownloadRemainingBytes\":87,\"downloadUsageMonth\":\"2027-01\","
        "\"downloadResetsAt\":\"2027-02-01T00:00:00Z\",\"downloadGrantSingleUse\":true}",
        "first second of January");
    len = st_object_storage_capabilities_for_tests(&alice, 1835438400LL, response, sizeof(response));
    failed |= cap_expect_exact(len, response,
        "{\"schemaVersion\":1,\"checkedAt\":\"2028-02-29T12:00:00Z\",\"storageEnabled\":true,"
        "\"maxAttachmentBytes\":536870912,\"retentionHours\":72,"
        "\"storageQuotaBytes\":100,\"storageUsedBytes\":0,\"storageRemainingBytes\":100,"
        "\"monthlyDownloadQuotaBytes\":100,\"monthlyDownloadUsedBytes\":0,"
        "\"monthlyDownloadRemainingBytes\":100,\"downloadUsageMonth\":\"2028-02\","
        "\"downloadResetsAt\":\"2028-03-01T00:00:00Z\",\"downloadGrantSingleUse\":true}",
        "leap day");
    cap_set_limits(NULL, NULL, NULL, NULL);
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return failed ? -1 : 0;
}

static int test_capabilities_storage_disabled(void)
{
    /* Nonpositive quotas fall back to the 1 GiB enforcement default. The C loader resolves a
     * nonpositive size limit or retention to the 512 MiB / 72 h its upload path enforces, so
     * those effective values are what the snapshot reports. */
    setenv("SPECUS_OBJECT_STORAGE_PROVIDER", "disabled", 1);
    cap_set_limits("0", "-5", "0", "-3");
    if (cap_seed_single_account() != 0) return -1;
    const cap_expected disabled = {"false", CAP_DEFAULT_MAX, 72, CAP_GIB, 64, CAP_GIB - 64, CAP_GIB, 0, CAP_GIB};
    char response[4096];
    int len = cap_get(CAP_ROUTE, "alice", "t1", "USER", response, sizeof(response));
    int failed = cap_expect_snapshot(len, response, &disabled);
    /* An incomplete provider configuration also disables upload, so it is reported as disabled. */
    if (configure() != 0) return -1;
    unsetenv("SPECUS_OBJECT_STORAGE_BUCKET");
    len = cap_get(CAP_ROUTE, "alice", "t1", "USER", response, sizeof(response));
    failed |= cap_expect_snapshot(len, response, &disabled);
    if (configure() != 0) return -1;
    cap_set_limits(NULL, NULL, NULL, NULL);
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return failed ? -1 : 0;
}

static int test_capabilities_read_failures(void)
{
    if (configure() != 0) return -1;
    char response[4096];
    unsetenv("SPECUS_DATABASE_PATH");
    int len = cap_get_module(CAP_ROUTE, "alice", "t1", response, sizeof(response));
    int failed = cap_expect_failure(len, response, "HTTP/1.1 503 ", "without a database");

    /* A missing file is unavailable persistence, and the read-only open must not create it. */
    unlink(CAP_MISSING_DB);
    setenv("SPECUS_DATABASE_PATH", CAP_MISSING_DB, 1);
    len = cap_get_module(CAP_ROUTE, "alice", "t1", response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 503 ", "with a missing database file");
    if (access(CAP_MISSING_DB, F_OK) == 0) {
        fprintf(stderr, "capabilities created a database file\n");
        failed = -1;
    }

    /* A file that is not a SQLite database. */
    FILE *garbage = fopen(CAP_DB, "wb");
    if (garbage == NULL) return -1;
    for (int i = 0; i < 64; ++i) fputs("not a sqlite database page ", garbage);
    fclose(garbage);
    setenv("SPECUS_DATABASE_PATH", CAP_DB, 1);
    len = cap_get_module(CAP_ROUTE, "alice", "t1", response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 500 ", "with a corrupt database");

    /* Attachment rows that cannot be read, then download usage that cannot be read. */
    unlink(CAP_DB);
    if (cap_exec(CAP_DB, "CREATE TABLE transfer_attachment(id INTEGER PRIMARY KEY);") != 0) return -1;
    len = cap_get_module(CAP_ROUTE, "alice", "t1", response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 500 ", "with an unreadable attachment table");
    if (cap_seed_single_account() != 0
        || cap_exec(CAP_DB, "DROP TABLE transfer_attachment_download_usage;"
                            "CREATE TABLE transfer_attachment_download_usage(id INTEGER PRIMARY KEY);") != 0) return -1;
    len = cap_get_module(CAP_ROUTE, "alice", "t1", response, sizeof(response));
    failed |= cap_expect_failure(len, response, "HTTP/1.1 500 ", "with an unreadable download usage table");

    /* No attachment was ever allocated, so the tables were never bootstrapped: that is a
     * successful read of zero records, and the snapshot must not create the schema itself. */
    unlink(CAP_DB);
    if (cap_exec(CAP_DB, "CREATE TABLE unrelated(id INTEGER PRIMARY KEY);") != 0) return -1;
    size_t before_len = 0U;
    unsigned char *before = cap_read_file(CAP_DB, &before_len);
    if (before == NULL) return -1;
    cap_set_limits("1000", "50", NULL, NULL);
    const cap_expected fresh = {"true", CAP_DEFAULT_MAX, 72, 1000, 0, 1000, 50, 0, 50};
    len = cap_get_module(CAP_ROUTE, "alice", "t1", response, sizeof(response));
    failed |= cap_expect_snapshot(len, response, &fresh);
    failed |= cap_file_unchanged(CAP_DB, before, before_len);
    free(before);
    cap_set_limits(NULL, NULL, NULL, NULL);
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return failed ? -1 : 0;
}

/*
 * The snapshot must not probe or sign anything against the object store. The provider endpoint
 * resolves to a local listener: any request would leave a pending connection in its backlog.
 */
static int test_capabilities_never_contacts_object_storage(void)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t address_len = sizeof(address);
    if (listener < 0 || bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(listener, 16) != 0
        || getsockname(listener, (struct sockaddr *)&address, &address_len) != 0
        || fcntl(listener, F_SETFL, O_NONBLOCK) != 0) {
        if (listener >= 0) close(listener);
        return -1;
    }
    char endpoint[96];
    snprintf(endpoint, sizeof(endpoint), "http://oss-cn-hangzhou.aliyuncs.com:%u", (unsigned int)ntohs(address.sin_port));
    if (configure() != 0 || setenv("SPECUS_OBJECT_STORAGE_ENDPOINT", endpoint, 1) != 0
        || setenv("SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS", "127.0.0.1", 1) != 0
        || cap_seed_single_account() != 0) {
        close(listener);
        return -1;
    }
    const cap_expected enabled = {"true", CAP_DEFAULT_MAX, 72, CAP_GIB, 64, CAP_GIB - 64, CAP_GIB, 0, CAP_GIB};
    char response[4096];
    int failed = 0;
    for (int i = 0; i < 3; ++i) {
        int len = cap_get(CAP_ROUTE, "alice", "t1", "USER", response, sizeof(response));
        failed |= cap_expect_snapshot(len, response, &enabled);
    }
    int accepted = accept(listener, NULL, NULL);
    int untouched = accepted < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    if (accepted >= 0) close(accepted);
    close(listener);
    if (!untouched) {
        fprintf(stderr, "capabilities contacted the object store\n");
        failed = -1;
    }
    unsetenv("SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS");
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return configure() != 0 || failed ? -1 : 0;
}

/*
 * Shared vector: protocol/test-vectors/transfer-capabilities-v1.json. Each case's rows go into the
 * module's own SQLite schema, the snapshot is read at the case instant through the fixed-clock
 * hook, and every field must match the vector, timestamps compared as instants.
 */
#ifndef ST_TRANSFER_VECTOR_DIR
#define ST_TRANSFER_VECTOR_DIR "../../../protocol/test-vectors/"
#endif
#define CAP_VECTOR_MAX_ROWS 32U

typedef struct {
    char tenant[64];
    char owner[64];
    char status[32];
    char upload_expires_at[32];
    char expires_at[32];
    char month[16];
} cap_vector_text;

static char *cap_read_vector(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s%s", ST_TRANSFER_VECTOR_DIR, name);
    size_t len = 0U;
    unsigned char *data = cap_read_file(path, &len);
    char *text = data == NULL ? NULL : (char *)realloc(data, len + 1U);
    if (text == NULL) {
        free(data);
        perror(path);
        return NULL;
    }
    text[len] = '\0';
    return text;
}

/* Copies a top-level string member; an absent, non-string or oversized value is an error. */
static int cap_member_text(const char *object, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(object, key);
    int ok = value != NULL && strlen(value) < out_len;
    if (ok) memcpy(out, value, strlen(value) + 1U);
    else fprintf(stderr, "capabilities vector: bad %s\n", key);
    free(value);
    return ok ? 0 : -1;
}

/* Copies the raw JSON token of a top-level member, such as a number or a boolean. */
static int cap_member_raw(const char *object, const char *key, char *out, size_t out_len)
{
    char *raw = object == NULL ? NULL : st_json_get_top_level_raw(object, key);
    int ok = raw != NULL && strlen(raw) < out_len;
    if (ok) memcpy(out, raw, strlen(raw) + 1U);
    else fprintf(stderr, "capabilities vector: bad %s\n", key);
    free(raw);
    return ok ? 0 : -1;
}

static long long cap_days_from_civil(long long year, unsigned int month, unsigned int day)
{
    year -= month <= 2U;
    long long era = (year >= 0 ? year : year - 399) / 400;
    unsigned int year_of_era = (unsigned int)(year - era * 400);
    unsigned int day_of_year = (153U * (month > 2U ? month - 3U : month + 9U) + 2U) / 5U + day - 1U;
    unsigned int day_of_era = year_of_era * 365U + year_of_era / 4U - year_of_era / 100U + day_of_year;
    return era * 146097 + (long long)day_of_era - 719468;
}

/* Parses a "YYYY-MM-DDTHH:MM:SSZ" instant into epoch seconds. */
static int cap_instant(const char *text, long long *out)
{
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    char zone = '\0';
    if (text == NULL || strlen(text) != 20U
        || sscanf(text, "%4d-%2d-%2dT%2d:%2d:%2d%c", &year, &month, &day, &hour, &minute, &second, &zone) != 7
        || zone != 'Z' || month < 1 || month > 12 || day < 1 || day > 31) return -1;
    *out = cap_days_from_civil(year, (unsigned int)month, (unsigned int)day) * 86400LL
        + hour * 3600LL + minute * 60LL + second;
    return 0;
}

static const char *cap_vector_scope(const char *scope)
{
    /* The vector's two scopes stand for two distinct attachment scopes: usage is account-wide. */
    if (strcmp(scope, "ROOM") == 0) return "PUBLIC_TRANSFER";
    if (strcmp(scope, "LINK") == 0) return "ADMIN_CLIENT_MESSAGE";
    return NULL;
}

static int cap_vector_seed(const char *test_case)
{
    char **attachment_rows = NULL, **usage_rows = NULL;
    size_t attachment_len = 0U, usage_len = 0U;
    cap_attachment attachments[CAP_VECTOR_MAX_ROWS];
    cap_usage usage[CAP_VECTOR_MAX_ROWS];
    cap_vector_text attachment_text[CAP_VECTOR_MAX_ROWS], usage_text[CAP_VECTOR_MAX_ROWS];
    int ok = st_json_get_raw_array(test_case, "attachments", &attachment_rows, &attachment_len) == 0
        && st_json_get_raw_array(test_case, "downloadUsage", &usage_rows, &usage_len) == 0
        && attachment_len <= CAP_VECTOR_MAX_ROWS && usage_len <= CAP_VECTOR_MAX_ROWS;
    for (size_t i = 0U; ok && i < attachment_len; ++i) {
        cap_vector_text *text = &attachment_text[i];
        char scope[32], size[32];
        ok = cap_member_text(attachment_rows[i], "tenantId", text->tenant, sizeof(text->tenant)) == 0
            && cap_member_text(attachment_rows[i], "username", text->owner, sizeof(text->owner)) == 0
            && cap_member_text(attachment_rows[i], "scope", scope, sizeof(scope)) == 0
            && cap_member_text(attachment_rows[i], "status", text->status, sizeof(text->status)) == 0
            && cap_member_raw(attachment_rows[i], "sizeBytes", size, sizeof(size)) == 0
            && cap_member_text(attachment_rows[i], "uploadExpiresAt", text->upload_expires_at,
                               sizeof(text->upload_expires_at)) == 0
            && cap_member_text(attachment_rows[i], "expiresAt", text->expires_at, sizeof(text->expires_at)) == 0
            && cap_vector_scope(scope) != NULL;
        if (ok) {
            attachments[i] = (cap_attachment){(long long)i + 1, text->tenant, text->owner, cap_vector_scope(scope),
                                              text->status, strtoll(size, NULL, 10), text->upload_expires_at,
                                              text->expires_at};
        }
    }
    for (size_t i = 0U; ok && i < usage_len; ++i) {
        cap_vector_text *text = &usage_text[i];
        char size[32];
        ok = cap_member_text(usage_rows[i], "tenantId", text->tenant, sizeof(text->tenant)) == 0
            && cap_member_text(usage_rows[i], "username", text->owner, sizeof(text->owner)) == 0
            && cap_member_text(usage_rows[i], "usageMonth", text->month, sizeof(text->month)) == 0
            && cap_member_raw(usage_rows[i], "sizeBytes", size, sizeof(size)) == 0;
        if (ok) {
            usage[i] = (cap_usage){(long long)i + 1, text->tenant, text->owner, text->month,
                                   strtoll(size, NULL, 10)};
        }
    }
    st_json_free_string_array(attachment_rows, attachment_len);
    st_json_free_string_array(usage_rows, usage_len);
    if (!ok) {
        fprintf(stderr, "capabilities vector: unreadable rows\n");
        return -1;
    }
    return cap_create_database(CAP_DB, attachments, attachment_len, usage, usage_len);
}

/* The size limit and retention are effective values, so they pass through the loader unchanged. */
static int cap_vector_configure(const char *config)
{
    char enabled[8], storage_quota[32], download_quota[32], max_bytes[32], retention[32];
    if (config == NULL
        || cap_member_raw(config, "storageEnabled", enabled, sizeof(enabled)) != 0
        || cap_member_raw(config, "storageQuotaBytes", storage_quota, sizeof(storage_quota)) != 0
        || cap_member_raw(config, "monthlyDownloadQuotaBytes", download_quota, sizeof(download_quota)) != 0
        || cap_member_raw(config, "maxAttachmentBytes", max_bytes, sizeof(max_bytes)) != 0
        || cap_member_raw(config, "retentionHours", retention, sizeof(retention)) != 0) return -1;
    if (configure() != 0) return -1;
    if (strcmp(enabled, "true") != 0 && setenv("SPECUS_OBJECT_STORAGE_PROVIDER", "disabled", 1) != 0) return -1;
    cap_set_limits(storage_quota, download_quota, max_bytes, retention);
    return 0;
}

static int cap_vector_compare(const char *name, const char *response, int len, const char *expect)
{
    static const char *const exact[] = {
        "schemaVersion", "storageEnabled", "maxAttachmentBytes", "retentionHours", "storageQuotaBytes",
        "storageUsedBytes", "storageRemainingBytes", "monthlyDownloadQuotaBytes", "monthlyDownloadUsedBytes",
        "monthlyDownloadRemainingBytes", "downloadUsageMonth", "downloadGrantSingleUse"
    };
    static const char *const instants[] = {"checkedAt", "downloadResetsAt"};
    const char *body = cap_body(response);
    if (len <= 0 || strncmp(response, "HTTP/1.1 200 OK\r\n", 17U) != 0
        || strstr(response, "\r\nCache-Control: private, no-store\r\n") == NULL
        || body == NULL || !st_json_is_valid_object(body)) {
        fprintf(stderr, "capabilities vector %s: not a private 200 JSON object: %s\n", name,
                len <= 0 ? "(none)" : response);
        return -1;
    }
    int failed = 0;
    for (size_t i = 0U; i < sizeof(exact) / sizeof(exact[0]); ++i) {
        char *want = st_json_get_top_level_raw(expect, exact[i]);
        char *got = st_json_get_top_level_raw(body, exact[i]);
        if (want == NULL || got == NULL || strcmp(want, got) != 0) {
            fprintf(stderr, "capabilities vector %s: %s expected %s, got %s\n", name, exact[i],
                    want == NULL ? "(missing)" : want, got == NULL ? "(missing)" : got);
            failed = -1;
        }
        free(want);
        free(got);
    }
    for (size_t i = 0U; i < sizeof(instants) / sizeof(instants[0]); ++i) {
        char *want = st_json_get_top_level_string(expect, instants[i]);
        char *got = st_json_get_top_level_string(body, instants[i]);
        long long want_epoch = 0, got_epoch = 0;
        if (cap_instant(want, &want_epoch) != 0 || cap_instant(got, &got_epoch) != 0 || want_epoch != got_epoch) {
            fprintf(stderr, "capabilities vector %s: %s expected %s, got %s\n", name, instants[i],
                    want == NULL ? "(missing)" : want, got == NULL ? "(missing)" : got);
            failed = -1;
        }
        free(want);
        free(got);
    }
    return failed;
}

static int cap_vector_case(const char *test_case)
{
    char name[128], now_text[32], tenant[64], username[64];
    char *account = st_json_get_top_level_raw(test_case, "account");
    char *config = st_json_get_top_level_raw(test_case, "config");
    char *expect = st_json_get_top_level_raw(test_case, "expect");
    long long now = 0;
    int failed = cap_member_text(test_case, "name", name, sizeof(name)) != 0
        || cap_member_text(test_case, "now", now_text, sizeof(now_text)) != 0
        || cap_instant(now_text, &now) != 0
        || account == NULL || expect == NULL
        || cap_member_text(account, "tenantId", tenant, sizeof(tenant)) != 0
        || cap_member_text(account, "username", username, sizeof(username)) != 0
        || cap_vector_configure(config) != 0
        || cap_vector_seed(test_case) != 0 ? -1 : 0;
    if (failed == 0) {
        const st_object_storage_identity identity = {tenant, username, 0, 1};
        char response[4096];
        int len = st_object_storage_capabilities_for_tests(&identity, now, response, sizeof(response));
        failed = cap_vector_compare(name, response, len, expect);
    } else {
        fprintf(stderr, "capabilities vector: cannot set up a case\n");
    }
    free(account);
    free(config);
    free(expect);
    cap_set_limits(NULL, NULL, NULL, NULL);
    unlink(CAP_DB);
    unsetenv("SPECUS_DATABASE_PATH");
    return failed;
}

static int test_capabilities_shared_vector(void)
{
    char *document = cap_read_vector("transfer-capabilities-v1.json");
    char **cases = NULL;
    size_t case_len = 0U;
    int failed = document == NULL || st_json_get_raw_array(document, "cases", &cases, &case_len) != 0
        || case_len == 0U ? -1 : 0;
    for (size_t i = 0U; i < case_len; ++i) {
        failed |= cap_vector_case(cases[i]);
    }
    st_json_free_string_array(cases, case_len);
    free(document);
    if (configure() != 0) return -1;
    if (failed == 0) printf("transfer capability vector: %zu cases passed\n", case_len);
    return failed ? -1 : 0;
}

/*
 * Attachment negative paths, mirroring Java TransferAttachmentServiceTests through the module's
 * request entry point. A local fake object store answers the HEAD and DELETE requests the server
 * signs, and records which objects were deleted.
 */

#define ATT_REMOTE "198.51.100.7"
#define ATT_ROOM "attachment-room"
#define ATT_OWNER_TOKEN "attachment-room-owner-token"
#define ATT_QUOTA_ROOM "attachment-quota-room"
#define ATT_QUOTA_TOKEN "attachment-quota-owner-token"
#define ATT_CALLBACK_ROOM "attachment-callback-room"
#define ATT_CALLBACK_TOKEN "attachment-callback-owner-token"
#define ATT_CALLBACK_PATH "/api/public/transfer/oss-callback"
#define ATT_MAX_OBJECTS 32U
#define ATT_STEP(expr) do { if (!failed && (expr) != 0) failed = 1; } while (0)

typedef struct {
    int listener;
    pthread_t thread;
    pthread_mutex_t lock;
    char keys[ATT_MAX_OBJECTS][256];
    long long sizes[ATT_MAX_OBJECTS];
    char deleted[ATT_MAX_OBJECTS][256];
    size_t deleted_count;
    int requests;
} att_fake_oss;

static att_fake_oss att_oss;
static char att_db_path[96];

static int att_oss_slot(const char *path)
{
    for (size_t i = 0; i < ATT_MAX_OBJECTS; ++i)
        if (att_oss.keys[i][0] != '\0' && strcmp(att_oss.keys[i], path) == 0) return (int)i;
    return -1;
}

/* Stores an object of the given size under "/<object key>", the path the server signs. */
static void att_oss_put(const char *object_key, long long size)
{
    char path[256];
    snprintf(path, sizeof(path), "/%s", object_key);
    pthread_mutex_lock(&att_oss.lock);
    int slot = att_oss_slot(path);
    for (size_t i = 0; slot < 0 && i < ATT_MAX_OBJECTS; ++i)
        if (att_oss.keys[i][0] == '\0') slot = (int)i;
    if (slot >= 0) {
        snprintf(att_oss.keys[slot], sizeof(att_oss.keys[slot]), "%s", path);
        att_oss.sizes[slot] = size;
    }
    pthread_mutex_unlock(&att_oss.lock);
}

static int att_oss_deleted(const char *object_key)
{
    char path[256];
    snprintf(path, sizeof(path), "/%s", object_key);
    pthread_mutex_lock(&att_oss.lock);
    int found = 0;
    for (size_t i = 0; i < att_oss.deleted_count; ++i) found |= strcmp(att_oss.deleted[i], path) == 0;
    found = found && att_oss_slot(path) < 0;
    pthread_mutex_unlock(&att_oss.lock);
    return found;
}

static int att_oss_requests(void)
{
    pthread_mutex_lock(&att_oss.lock);
    int requests = att_oss.requests;
    pthread_mutex_unlock(&att_oss.lock);
    return requests;
}

static void att_oss_serve(int fd)
{
    char request[8192];
    size_t len = 0U;
    while (len + 1U < sizeof(request)) {
        ssize_t got = recv(fd, request + len, sizeof(request) - 1U - len, 0);
        if (got <= 0) break;
        len += (size_t)got;
        request[len] = '\0';
        if (strstr(request, "\r\n\r\n") != NULL) break;
    }
    request[len] = '\0';
    char method[16] = {0};
    char target[1024] = {0};
    if (sscanf(request, "%15s %1023s", method, target) != 2) return;
    char *query = strchr(target, '?');
    if (query != NULL) *query = '\0';
    char reply[256];
    snprintf(reply, sizeof(reply), "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    pthread_mutex_lock(&att_oss.lock);
    ++att_oss.requests;
    int slot = att_oss_slot(target);
    if (strcmp(method, "HEAD") == 0) {
        if (slot >= 0) snprintf(reply, sizeof(reply), "HTTP/1.1 200 OK\r\nContent-Length: %lld\r\nConnection: close\r\n\r\n",
                                att_oss.sizes[slot]);
        else snprintf(reply, sizeof(reply), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    } else if (strcmp(method, "DELETE") == 0) {
        if (slot >= 0) att_oss.keys[slot][0] = '\0';
        if (att_oss.deleted_count < ATT_MAX_OBJECTS)
            snprintf(att_oss.deleted[att_oss.deleted_count++], sizeof(att_oss.deleted[0]), "%s", target);
        snprintf(reply, sizeof(reply), "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
    }
    pthread_mutex_unlock(&att_oss.lock);
    (void)send(fd, reply, strlen(reply), MSG_NOSIGNAL);
}

static void *att_oss_thread(void *argument)
{
    (void)argument;
    for (;;) {
        int fd = accept(att_oss.listener, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        struct timeval timeout = {2, 0};
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        att_oss_serve(fd);
        close(fd);
    }
    return NULL;
}

static int att_oss_start(int *port)
{
    memset(&att_oss, 0, sizeof(att_oss));
    pthread_mutex_init(&att_oss.lock, NULL);
    att_oss.listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t address_len = sizeof(address);
    if (att_oss.listener < 0 || bind(att_oss.listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(att_oss.listener, 16) != 0
        || getsockname(att_oss.listener, (struct sockaddr *)&address, &address_len) != 0
        || pthread_create(&att_oss.thread, NULL, att_oss_thread, NULL) != 0) {
        if (att_oss.listener >= 0) close(att_oss.listener);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return 0;
}

static void att_oss_stop(void)
{
    (void)shutdown(att_oss.listener, SHUT_RDWR);
    pthread_join(att_oss.thread, NULL);
    close(att_oss.listener);
    pthread_mutex_destroy(&att_oss.lock);
}

static int att_status(int len, const char *response)
{
    return len > 12 && strncmp(response, "HTTP/1.1 ", 9U) == 0 ? atoi(response + 9) : -1;
}

static int att_expect(int len, const char *response, int status, const char *needle, const char *label)
{
    int ok = att_status(len, response) == status && (needle == NULL || strstr(response, needle) != NULL);
    if (!ok) fprintf(stderr, "%s: expected %d%s%s, got %s\n", label, status, needle == NULL ? "" : " with ",
                     needle == NULL ? "" : needle, len > 0 ? response : "(none)");
    return ok ? 0 : -1;
}

static int att_post(const char *path, const char *body, const st_object_storage_identity *identity,
                    char *out, size_t out_len)
{
    return st_object_storage_build_response("POST", path, body, ATT_REMOTE, NULL, NULL, identity, out, out_len);
}

/* Presigns an upload; on 200 also returns the attachment ID and object key. */
static int att_upload(const st_object_storage_identity *identity, const char *body, int status,
                      const char *needle, long long *id, char key[256], const char *label)
{
    static const char public_path[] = "/api/public/transfer/attachments/presign-upload";
    static const char admin_path[] = "/api/admin/client-messages/attachments/presign-upload";
    char response[16384];
    int len = att_post(strstr(body, "targetClientId") != NULL ? admin_path : public_path, body, identity,
                       response, sizeof(response));
    if (att_expect(len, response, status, needle, label) != 0) return -1;
    if (status != 200) return 0;
    const char *json = cap_body(response);
    char *object_key = st_json_get_top_level_string(json, "objectKey");
    int ok = object_key != NULL && strlen(object_key) < 256U && st_json_get_i64(json, "attachmentId", id) == 0;
    if (ok) snprintf(key, 256U, "%s", object_key);
    else fprintf(stderr, "%s: upload response without ID or key\n", label);
    free(object_key);
    return ok ? 0 : -1;
}

static int att_public_upload(const st_object_storage_identity *identity, const char *room, const char *token,
                             long long size, int status, const char *needle, long long *id, char key[256],
                             const char *label)
{
    char body[512];
    snprintf(body, sizeof(body),
             "{\"fileName\":\"demo.txt\",\"mimeType\":\"text/plain\",\"sizeBytes\":%lld,"
             "\"roomId\":\"%s\",\"roomToken\":\"%s\"}", size, room, token);
    return att_upload(identity, body, status, needle, id, key, label);
}

/* POSTs {complete|presign-download} for an attachment in either scope. */
static int att_action(const st_object_storage_identity *identity, int public_scope, long long id,
                      const char *action, const char *room_token, int status, const char *needle,
                      char *response, size_t response_len, const char *label)
{
    char path[160];
    char body[256];
    snprintf(path, sizeof(path), "%s%lld/%s", public_scope ? "/api/public/transfer/attachments/"
             : "/api/admin/client-messages/attachments/", id, action);
    snprintf(body, sizeof(body), "{\"roomToken\":\"%s\"}", room_token == NULL ? "" : room_token);
    int len = att_post(path, room_token == NULL ? NULL : body, identity, response, response_len);
    return att_expect(len, response, status, needle, label);
}

static int att_row(long long id, const char *status, long long size, const char *label)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_open(att_db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT status,size_bytes FROM transfer_attachment WHERE id=?", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW
        && strcmp((const char *)sqlite3_column_text(stmt, 0), status) == 0
        && sqlite3_column_int64(stmt, 1) == size;
    sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    if (!ok) fprintf(stderr, "%s: attachment %lld is not %s with %lld bytes\n", label, id, status, size);
    return ok ? 0 : -1;
}

static long long att_count(const char *sql)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long count = -1;
    if (sqlite3_open(att_db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    return count;
}

static int att_room_token(const char *role, char out[128])
{
    char body[512];
    char response[4096];
    snprintf(body, sizeof(body), "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"role\":\"%s\"}",
             ATT_ROOM, ATT_OWNER_TOKEN, role);
    int len = st_public_room_build_response("POST", "/api/public/transfer/rooms/access-tokens", body,
                                            ATT_REMOTE, response, sizeof(response));
    char *token = att_status(len, response) == 200 ? st_json_get_top_level_string(cap_body(response), "token") : NULL;
    int ok = token != NULL && strlen(token) < 128U;
    if (ok) snprintf(out, 128U, "%s", token);
    else fprintf(stderr, "room %s token creation failed: %s\n", role, len > 0 ? response : "(none)");
    free(token);
    return ok ? 0 : -1;
}

static char *att_base64(const unsigned char *data, size_t len)
{
    char *out = (char *)malloc(4U * ((len + 2U) / 3U) + 1U);
    if (out != NULL) EVP_EncodeBlock((unsigned char *)out, data, (int)len);
    return out;
}

static EVP_PKEY *att_callback_key(char **pem_out)
{
    EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    if (context == NULL || EVP_PKEY_keygen_init(context) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0 || EVP_PKEY_keygen(context, &key) <= 0) {
        EVP_PKEY_CTX_free(context);
        return NULL;
    }
    EVP_PKEY_CTX_free(context);
    BIO *bio = BIO_new(BIO_s_mem());
    char *data = NULL;
    long len = bio != NULL && PEM_write_bio_PUBKEY(bio, key) == 1 ? BIO_get_mem_data(bio, &data) : -1;
    *pem_out = len > 0 ? (char *)malloc((size_t)len + 1U) : NULL;
    if (*pem_out != NULL) {
        memcpy(*pem_out, data, (size_t)len);
        (*pem_out)[len] = '\0';
    }
    BIO_free(bio);
    if (*pem_out == NULL) {
        EVP_PKEY_free(key);
        return NULL;
    }
    return key;
}

/* Stands in for gosspublic.alicdn.com: serves one PEM key and records the URLs requested. */
typedef struct {
    const char *pem;
    int calls;
    char last_url[256];
} att_key_server;

static char *att_fetch_callback_key(const char *url, void *context)
{
    att_key_server *server = (att_key_server *)context;
    ++server->calls;
    snprintf(server->last_url, sizeof(server->last_url), "%s", url);
    if (server->pem == NULL) return NULL;
    char *copy = (char *)malloc(strlen(server->pem) + 1U);
    if (copy != NULL) memcpy(copy, server->pem, strlen(server->pem) + 1U);
    return copy;
}

/* OSS callback signature: base64(RSA-MD5(url_decode(path) + query + "\n" + body)). */
static char *att_sign_callback(EVP_PKEY *key, const char *body)
{
    size_t signed_len = strlen(ATT_CALLBACK_PATH) + 1U + strlen(body);
    char *text = (char *)malloc(signed_len + 1U);
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char *signature = NULL;
    size_t signature_len = 0U;
    char *encoded = NULL;
    if (text != NULL) snprintf(text, signed_len + 1U, "%s\n%s", ATT_CALLBACK_PATH, body);
    if (text != NULL && context != NULL && EVP_DigestSignInit(context, NULL, EVP_md5(), NULL, key) == 1
        && EVP_DigestSignUpdate(context, text, signed_len) == 1
        && EVP_DigestSignFinal(context, NULL, &signature_len) == 1
        && (signature = (unsigned char *)malloc(signature_len)) != NULL
        && EVP_DigestSignFinal(context, signature, &signature_len) == 1) {
        encoded = att_base64(signature, signature_len);
    }
    EVP_MD_CTX_free(context);
    free(signature);
    free(text);
    return encoded;
}

static int att_callback(const char *body, const char *authorization, const char *key_url,
                        int status, const char *needle, const char *label)
{
    char response[4096];
    int len = st_object_storage_build_response("POST", ATT_CALLBACK_PATH, body, ATT_REMOTE, authorization,
                                               key_url, NULL, response, sizeof(response));
    return att_expect(len, response, status, needle, label);
}

static int att_signed_callback(EVP_PKEY *key, const char *key_url, const char *bucket, const char *object_key,
                               long long size, int status, const char *needle, const char *label)
{
    char body[512];
    snprintf(body, sizeof(body), "{\"bucket\":\"%s\",\"object\":\"%s\",\"size\":%lld,\"mimeType\":\"text/plain\"}",
             bucket, object_key, size);
    char *signature = att_sign_callback(key, body);
    int rc = signature == NULL ? -1 : att_callback(body, signature, key_url, status, needle, label);
    free(signature);
    return rc;
}

static int att_configure(int oss_port)
{
    char endpoint[96];
    snprintf(endpoint, sizeof(endpoint), "http://oss-cn-hangzhou.aliyuncs.com:%d", oss_port);
    snprintf(att_db_path, sizeof(att_db_path), "/tmp/specus_c_attachments_%ld.db", (long)getpid());
    unlink(att_db_path);
    cap_set_limits("100", "50", "64", NULL);
    st_object_storage_reset_for_tests();
    st_storage_client client;
    return configure() != 0 || setenv("SPECUS_OBJECT_STORAGE_ENDPOINT", endpoint, 1) != 0
        || setenv("SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS", "127.0.0.1", 1) != 0
        || setenv("SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL",
                  "https://specus.example/api/public/transfer/oss-callback", 1) != 0
        || setenv("SPECUS_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM", "2", 1) != 0
        || setenv("SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP", "1000", 1) != 0
        || setenv("SPECUS_DATABASE_PATH", att_db_path, 1) != 0
        || st_storage_init(att_db_path, 0) != 0
        || st_storage_upsert_client(att_db_path, 0, "t1", "erin-device", "erin", 1, 60, &client) != 0
        || st_storage_upsert_client(att_db_path, 0, "t1", "frank-device", "frank", 1, 60, &client) != 0
        || st_object_storage_cleanup_expired() != 0
        || cap_exec(att_db_path,
               "INSERT INTO transfer_attachment(id,tenant_id,scope,owner_username,object_key,file_name,"
               "mime_type,size_bytes,status,created_at,updated_at,upload_expires_at,expires_at) VALUES("
               "9001,'t1','PUBLIC_TRANSFER','dave','prefix/seed/9001.bin','seed.bin','application/octet-stream',"
               "50,'UPLOADED','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z',"
               "'2999-01-01T00:00:00Z')") != 0 ? -1 : 0;
}

static void att_unconfigure(void)
{
    static const char *const names[] = {
        "SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS", "SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL",
        "SPECUS_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM", "SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP",
        "SPECUS_DATABASE_PATH"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) unsetenv(names[i]);
    cap_set_limits(NULL, NULL, NULL, NULL);
    st_object_storage_set_callback_key_fetcher_for_tests(NULL, NULL);
    st_object_storage_reset_for_tests();
    unlink(att_db_path);
    (void)configure();
}

static long long att_client_id(const char *name)
{
    st_storage_client client;
    return st_storage_get_client_by_name(att_db_path, name, &client) == 0 ? client.id : -1;
}

/* Room roles, the room PENDING limit, HEAD verification at complete and both account quotas. */
static int att_public_paths(void)
{
    const st_object_storage_identity alice = {"t1", "alice", 0, 1};
    const st_object_storage_identity carol = {"t1", "carol", 0, 1};
    const st_object_storage_identity dave = {"t1", "dave", 0, 1};
    char viewer_token[128];
    char response[16384];
    char key1[256], key2[256], key3[256], ignored_key[256];
    long long id1 = 0, id2 = 0, id3 = 0, ignored = 0;
    char previous[8], month[8], next[8], resets_at[41];
    int failed = 0;
    ATT_STEP(cap_current_months(previous, month, next, resets_at));
    ATT_STEP(att_public_upload(&alice, ATT_ROOM, ATT_OWNER_TOKEN, 10, 200, NULL, &id1, key1, "first upload"));
    ATT_STEP(att_room_token("VIEWER", viewer_token));

    /* A VIEWER credential resolves the room but must not upload (403, nothing reserved). */
    long long rows = att_count("SELECT COUNT(*) FROM transfer_attachment");
    ATT_STEP(att_public_upload(&carol, ATT_ROOM, viewer_token, 10, 403, NULL, &ignored, ignored_key, "VIEWER upload"));
    if (!failed && att_count("SELECT COUNT(*) FROM transfer_attachment") != rows) {
        fprintf(stderr, "a refused VIEWER upload reserved an attachment\n");
        failed = 1;
    }
    /* Two PENDING uploads fill the room; a third is rate limited. */
    ATT_STEP(att_public_upload(&alice, ATT_ROOM, ATT_OWNER_TOKEN, 10, 200, NULL, &id2, key2, "second upload"));
    ATT_STEP(att_public_upload(&alice, ATT_ROOM, ATT_OWNER_TOKEN, 10, 429, "pending uploads", &ignored,
                               ignored_key, "room PENDING limit"));
    /* Complete without the object: refused, still PENDING, nothing deleted. */
    ATT_STEP(att_action(&alice, 1, id1, "complete", ATT_OWNER_TOKEN, 409, "not uploaded", response,
                        sizeof(response), "complete without object"));
    ATT_STEP(att_row(id1, "PENDING", 10, "after complete without object"));
    if (!failed && att_oss_deleted(key1)) {
        fprintf(stderr, "a missing object was deleted\n");
        failed = 1;
    }
    /* An object larger than max-attachment-bytes is deleted and the complete is refused. */
    att_oss_put(key1, 65);
    ATT_STEP(att_action(&alice, 1, id1, "complete", ATT_OWNER_TOKEN, 400, "too large", response,
                        sizeof(response), "complete of an oversized object"));
    ATT_STEP(att_row(id1, "PENDING", 10, "after oversized complete"));
    if (!failed && !att_oss_deleted(key1)) {
        fprintf(stderr, "the oversized object was not deleted\n");
        failed = 1;
    }
    /* The actual HEAD size replaces the declared one. */
    att_oss_put(key1, 9);
    ATT_STEP(att_action(&alice, 1, id1, "complete", ATT_OWNER_TOKEN, 200, "\"sizeBytes\":9", response,
                        sizeof(response), "complete with the actual size"));
    ATT_STEP(att_row(id1, "UPLOADED", 9, "after complete"));
    /* The limit counts PENDING only, so the room has room again. */
    ATT_STEP(att_public_upload(&alice, ATT_ROOM, ATT_OWNER_TOKEN, 10, 200, NULL, &id3, key3, "upload after complete"));

    /* VIEWER may not complete, but may download a finished attachment. */
    ATT_STEP(att_action(&carol, 1, id2, "complete", viewer_token, 403, NULL, response, sizeof(response),
                        "VIEWER complete"));
    ATT_STEP(att_action(&carol, 1, id1, "presign-download", viewer_token, 200, "/api/public/transfer/downloads/",
                        response, sizeof(response), "VIEWER download"));
    char *grant = failed ? NULL : st_json_get_top_level_string(cap_body(response), "downloadUrl");
    int len = grant == NULL ? -1 : st_object_storage_build_response("GET", grant, NULL, ATT_REMOTE, NULL, NULL,
                                                                     NULL, response, sizeof(response));
    ATT_STEP(att_expect(len, response, 302, "x-st-grant=", "first grant consume"));
    free(grant);
    /* Download quota (50): 9 charged so far, another grant passes the precheck at 18 bytes... */
    ATT_STEP(att_action(&carol, 1, id1, "presign-download", viewer_token, 200, NULL, response, sizeof(response),
                        "second download grant"));
    grant = failed ? NULL : st_json_get_top_level_string(cap_body(response), "downloadUrl");
    /* ...but if the month's usage grows to 44 first, consuming it would exceed the quota. */
    char usage[512];
    snprintf(usage, sizeof(usage),
             "INSERT INTO transfer_attachment_download_usage(id,tenant_id,username,attachment_id,size_bytes,"
             "usage_month,created_at) VALUES(9101,'t1','carol',9001,35,'%s','2000-01-01T00:00:00Z')", month);
    ATT_STEP(cap_exec(att_db_path, usage));
    len = grant == NULL ? -1 : st_object_storage_build_response("GET", grant, NULL, ATT_REMOTE, NULL, NULL,
                                                                 NULL, response, sizeof(response));
    ATT_STEP(att_expect(len, response, 429, "download quota", "grant consume over the download quota"));
    free(grant);
    if (!failed && att_count("SELECT COUNT(*) FROM transfer_attachment_download_grant WHERE consumed_at IS NOT NULL") != 1) {
        fprintf(stderr, "a grant refused by the download quota was consumed\n");
        failed = 1;
    }
    ATT_STEP(att_action(&carol, 1, id1, "presign-download", viewer_token, 429, "download quota", response,
                        sizeof(response), "download grant over the download quota"));

    /* Storage quota (100) for dave, who already stores 50 bytes. */
    long long dave_id = 0;
    char dave_key[256];
    ATT_STEP(att_public_upload(&dave, ATT_QUOTA_ROOM, ATT_QUOTA_TOKEN, 65, 400, NULL, &ignored, ignored_key,
                               "declared size over max-attachment-bytes"));
    ATT_STEP(att_public_upload(&dave, ATT_QUOTA_ROOM, ATT_QUOTA_TOKEN, 51, 429, "storage quota", &ignored,
                               ignored_key, "upload over the storage quota"));
    ATT_STEP(att_public_upload(&dave, ATT_QUOTA_ROOM, ATT_QUOTA_TOKEN, 50, 200, NULL, &dave_id, dave_key,
                               "upload filling the storage quota"));
    ATT_STEP(att_public_upload(&dave, ATT_QUOTA_ROOM, ATT_QUOTA_TOKEN, 1, 429, "storage quota", &ignored,
                               ignored_key, "upload past a full storage quota"));
    /* The actual size (51) would exceed the quota at complete: the object is deleted. */
    att_oss_put(dave_key, 51);
    ATT_STEP(att_action(&dave, 1, dave_id, "complete", ATT_QUOTA_TOKEN, 429, "storage quota", response,
                        sizeof(response), "complete over the storage quota"));
    ATT_STEP(att_row(dave_id, "PENDING", 50, "after complete over the storage quota"));
    if (!failed && !att_oss_deleted(dave_key)) {
        fprintf(stderr, "the object over the storage quota was not deleted\n");
        failed = 1;
    }
    return failed ? -1 : 0;
}

/* ADMIN_CLIENT_MESSAGE uploads: target access, tenant isolation and scope separation. */
static int att_admin_paths(void)
{
    const st_object_storage_identity erin = {"t1", "erin", 0, 1};
    const st_object_storage_identity frank = {"t1", "frank", 0, 1};
    const st_object_storage_identity root = {"t1", "root", 1, 1};
    const st_object_storage_identity stranger = {"t2", "erin", 0, 1};
    long long erin_client = att_client_id("erin-device");
    long long frank_client = att_client_id("frank-device");
    char body[256], response[16384], key[256], ignored_key[256];
    long long id = 0, ignored = 0;
    int failed = erin_client <= 0 || frank_client <= 0;
    snprintf(body, sizeof(body), "{\"fileName\":\"note.txt\",\"sizeBytes\":5,\"targetClientId\":%lld}", erin_client);
    ATT_STEP(att_upload(&erin, body, 200, "/admin-client-message/", &id, key, "admin upload to own client"));
    ATT_STEP(att_upload(&stranger, body, 400, NULL, &ignored, ignored_key, "admin upload from another tenant"));
    ATT_STEP(att_upload(&erin, "{\"fileName\":\"note.txt\",\"sizeBytes\":5,\"targetClientId\":0}", 400, NULL,
                        &ignored, ignored_key, "admin upload without a target"));
    snprintf(body, sizeof(body), "{\"fileName\":\"note.txt\",\"sizeBytes\":5,\"targetClientId\":%lld}", frank_client);
    ATT_STEP(att_upload(&erin, body, 400, NULL, &ignored, ignored_key, "admin upload to another owner's client"));
    ATT_STEP(att_upload(&root, body, 200, NULL, &ignored, ignored_key, "tenant administrator upload"));

    /* Another owner or tenant gets 400, as for an unknown attachment (section 5, Java). */
    ATT_STEP(att_action(&frank, 0, id, "complete", NULL, 400, NULL, response, sizeof(response),
                        "admin complete by another owner"));
    ATT_STEP(att_action(&stranger, 0, id, "complete", NULL, 400, NULL, response, sizeof(response),
                        "admin complete from another tenant"));
    ATT_STEP(att_action(&erin, 0, id, "complete", NULL, 409, "not uploaded", response, sizeof(response),
                        "admin complete without object"));
    att_oss_put(key, 5);
    ATT_STEP(att_action(&erin, 0, id, "complete", NULL, 200, "\"status\":\"UPLOADED\"", response, sizeof(response),
                        "admin complete"));
    ATT_STEP(att_action(&erin, 0, id, "presign-download", NULL, 200, "/api/public/transfer/downloads/", response,
                        sizeof(response), "admin download"));
    ATT_STEP(att_action(&frank, 0, id, "presign-download", NULL, 400, NULL, response, sizeof(response),
                        "admin download by another owner"));
    ATT_STEP(att_action(&root, 0, id, "presign-download", NULL, 200, NULL, response, sizeof(response),
                        "admin download by the tenant administrator"));
    /* Scopes never resolve each other's IDs, and an unknown ID is a bad request. */
    ATT_STEP(att_action(&erin, 1, id, "complete", ATT_OWNER_TOKEN, 400, "not found", response, sizeof(response),
                        "public complete of an admin attachment"));
    ATT_STEP(att_action(&erin, 0, 1, "presign-download", NULL, 400, "not found", response, sizeof(response),
                        "admin download of an unknown attachment"));
    return failed ? -1 : 0;
}

/* The attachment member of an upload response, decoded field by field. */
static char *att_view_text(const char *response, const char *key)
{
    char *attachment = st_json_get_top_level_raw(cap_body(response), "attachment");
    char *value = attachment == NULL ? NULL : st_json_get_top_level_string(attachment, key);
    free(attachment);
    return value;
}

static int att_ends_with(const char *value, const char *suffix)
{
    size_t value_len = value == NULL ? 0U : strlen(value);
    size_t suffix_len = strlen(suffix);
    return value != NULL && value_len >= suffix_len && strcmp(value + value_len - suffix_len, suffix) == 0;
}

/* Java createPublicUploadNormalizesMetadataAndPresignsClientPut. */
static int att_upload_normalization(void)
{
    static const char public_path[] = "/api/public/transfer/attachments/presign-upload";
    const st_object_storage_identity fiona = {"t1", "fiona", 0, 1};
    char response[16384];
    int len = att_post(public_path,
                       "{\"fileName\":\"../hello.txt\",\"mimeType\":\"text/plain\",\"sizeBytes\":10,"
                       "\"sha256\":\"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF\","
                       "\"roomId\":\" norm-room \",\"roomToken\":\"attachment-norm-token\"}",
                       &fiona, response, sizeof(response));
    if (att_expect(len, response, 200, "\"uploadUrl\":\"http", "normalised upload") != 0) return -1;
    char *object_key = st_json_get_top_level_string(cap_body(response), "objectKey");
    char *file_name = att_view_text(response, "fileName");
    char *sha256 = att_view_text(response, "sha256");
    char *status = att_view_text(response, "status");
    char *headers = st_json_get_top_level_raw(cap_body(response), "uploadHeaders");
    long long id = 0;
    int ok = st_json_get_i64(cap_body(response), "attachmentId", &id) == 0
        && object_key != NULL && strstr(object_key, "/public-transfer/") != NULL
        && att_ends_with(object_key, "/hello.txt")
        && file_name != NULL && strcmp(file_name, "hello.txt") == 0
        && sha256 != NULL && strcmp(sha256, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef") == 0
        && status != NULL && strcmp(status, "PENDING") == 0
        && headers != NULL && strstr(headers, "\"Content-Type\":\"text/plain\"") != NULL;
    free(object_key); free(file_name); free(sha256); free(status); free(headers);
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM transfer_attachment a JOIN public_transfer_room r "
             "ON r.id=a.public_transfer_room_id WHERE a.id=%lld AND a.file_name='hello.txt' "
             "AND a.room_id='norm-room' AND r.room_name='norm-room' AND a.tenant_id='t1' "
             "AND a.owner_username='fiona' AND a.scope='PUBLIC_TRANSFER' AND a.status='PENDING' "
             "AND a.sha256='0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' "
             "AND a.mime_type='text/plain' AND a.size_bytes=10", id);
    if (!ok || att_count(sql) != 1) {
        fprintf(stderr, "upload metadata was not normalised as Java does: %s\n", response);
        return -1;
    }
    return 0;
}

/*
 * Java fileNameNormalizationUsesUnicodeCodePointsAndSafeLengthBoundaries and the boundary table of
 * public-transfer.md 3.2.1, plus an over-long name ending in a dot (no extension).
 */
static int att_filename_normalization(void)
{
    static const char public_path[] = "/api/public/transfer/attachments/presign-upload";
    const st_object_storage_identity fiona = {"t1", "fiona", 0, 1};
    char inputs[16][512];
    char expected[16][256];
    size_t count = 0U;
    static const char *const literal[][2] = {
        /* JSON string bodies: a backslash is written \\ */
        {"mixed/path\\\\photo\xF0\x9F\x98\x80  \xE4\xB8\xAD\xE6\x96\x87.png", "photo_.png"},
        {"\xF0\x9F\x98\x80\xF0\x9F\x98\x80.txt", "_.txt"},
        {"folder/", "attachment"},
        {"folder\\\\", "attachment"},
        {"folder/...", "attachment"},
        {"archive..tar...gz", "archive.tar.gz"},
        {".env", ".env"},
        {"file.", "file."},
        {"   ", "_"},
        {"  photo .png  ", "_photo_.png_"},
    };
    for (size_t i = 0U; i < sizeof(literal) / sizeof(literal[0]); ++i, ++count) {
        snprintf(inputs[count], sizeof(inputs[count]), "%s", literal[i][0]);
        snprintf(expected[count], sizeof(expected[count]), "%s", literal[i][1]);
    }
    /* 200 a + ".txt" -> 176 a + ".txt" */
    memset(inputs[count], 'a', 200U); memcpy(inputs[count] + 200U, ".txt", 5U);
    memset(expected[count], 'a', 176U); memcpy(expected[count] + 176U, ".txt", 5U);
    ++count;
    /* "abcdefghij." + 178 b -> "a." + 178 b */
    memcpy(inputs[count], "abcdefghij.", 11U); memset(inputs[count] + 11U, 'b', 178U); inputs[count][189] = '\0';
    memcpy(expected[count], "a.", 2U); memset(expected[count] + 2U, 'b', 178U); expected[count][180] = '\0';
    ++count;
    /* "a." + 180 b -> its first 180 characters */
    memcpy(inputs[count], "a.", 2U); memset(inputs[count] + 2U, 'b', 180U); inputs[count][182] = '\0';
    memcpy(expected[count], "a.", 2U); memset(expected[count] + 2U, 'b', 178U); expected[count][180] = '\0';
    ++count;
    /* 181 x -> 180 x */
    memset(inputs[count], 'x', 181U); inputs[count][181] = '\0';
    memset(expected[count], 'x', 180U); expected[count][180] = '\0';
    ++count;
    /* 185 y + "." -> 180 y: a trailing dot does not define an extension */
    memset(inputs[count], 'y', 185U); memcpy(inputs[count] + 185U, ".", 2U);
    memset(expected[count], 'y', 180U); expected[count][180] = '\0';
    ++count;
    for (size_t i = 0U; i < count; ++i) {
        char body[1024];
        char response[16384];
        char suffix[260];
        snprintf(body, sizeof(body),
                 "{\"fileName\":\"%.511s\",\"mimeType\":\"application/octet-stream\",\"sizeBytes\":1,"
                 "\"roomId\":\"fname-room-%zu\",\"roomToken\":\"attachment-fname-token-%zu\"}", inputs[i], i, i);
        int len = att_post(public_path, body, &fiona, response, sizeof(response));
        char *file_name = att_status(len, response) == 200 ? att_view_text(response, "fileName") : NULL;
        char *object_key = file_name == NULL ? NULL : st_json_get_top_level_string(cap_body(response), "objectKey");
        snprintf(suffix, sizeof(suffix), "/%s", expected[i]);
        int ok = file_name != NULL && strcmp(file_name, expected[i]) == 0
            && att_ends_with(object_key, suffix) && strstr(object_key, "..") == NULL;
        if (!ok) fprintf(stderr, "file name case %zu (%s): expected %s, got %s\n", i, inputs[i], expected[i],
                         len > 0 ? response : "(none)");
        free(file_name);
        free(object_key);
        if (!ok) return -1;
    }
    return 0;
}

/* Java createPublicUploadRetriesWhenSaveHitsIdCollision. */
static int att_id_collision(void)
{
    const st_object_storage_identity fiona = {"t1", "fiona", 0, 1};
    static const long long ids[] = {778001LL, 778002LL};
    long long id = 0;
    char key[256];
    if (cap_exec(att_db_path,
                 "INSERT INTO transfer_attachment(id,tenant_id,scope,owner_username,object_key,file_name,"
                 "mime_type,size_bytes,status,created_at,updated_at,upload_expires_at,expires_at) VALUES("
                 "778001,'t2','PUBLIC_TRANSFER','someone','prefix/seed/778001.bin','seed.bin',"
                 "'application/octet-stream',1,'UPLOADED','2000-01-01T00:00:00Z','2000-01-01T00:00:00Z',"
                 "'2000-01-01T00:00:00Z','2999-01-01T00:00:00Z')") != 0) {
        return -1;
    }
    st_object_storage_set_ids_for_tests(ids, 2U);
    int rc = att_public_upload(&fiona, "collision-room", "attachment-collision-token", 1, 200, NULL, &id, key,
                               "upload whose first ID collides");
    st_object_storage_set_ids_for_tests(NULL, 0U);
    if (rc != 0) return -1;
    if (id != 778002LL || strstr(key, "/778002/") == NULL
        || att_count("SELECT COUNT(*) FROM transfer_attachment WHERE id=778001 AND tenant_id='t2'") != 1
        || att_count("SELECT COUNT(*) FROM transfer_attachment WHERE id=778002 AND object_key LIKE '%/778002/%'") != 1) {
        fprintf(stderr, "an ID collision was not retried with a new ID and key: %lld %s\n", id, key);
        return -1;
    }
    return 0;
}

/* Java createDownloadRejectsPendingAttachment: no grant, no object storage request. */
static int att_pending_download(void)
{
    const st_object_storage_identity fiona = {"t1", "fiona", 0, 1};
    char response[16384];
    char key[256];
    long long id = 0;
    if (att_public_upload(&fiona, "pending-room", "attachment-pending-token", 1, 200, NULL, &id, key,
                          "pending upload") != 0) {
        return -1;
    }
    int requests = att_oss_requests();
    char sql[160];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM transfer_attachment_download_grant WHERE attachment_id=%lld", id);
    if (att_action(&fiona, 1, id, "presign-download", "attachment-pending-token", 409, "not uploaded", response,
                   sizeof(response), "download of a PENDING attachment") != 0
        || att_count(sql) > 0 || att_oss_requests() != requests) {
        fprintf(stderr, "a PENDING attachment got a download grant or touched object storage\n");
        return -1;
    }
    return 0;
}

/* POST /api/public/transfer/oss-callback: RSA-MD5 signature, key URL pinning and body checks. */
static int att_callback_paths(void)
{
    const st_object_storage_identity alice = {"t1", "alice", 0, 1};
    char *pem = NULL;
    EVP_PKEY *key = att_callback_key(&pem);
    static const char key_location[] = "http://gosspublic.alicdn.com/callback_pub_key_v1.pem";
    static const char foreign_location[] = "https://keys.example/callback_pub_key_v1.pem";
    char *key_url = att_base64((const unsigned char *)key_location, strlen(key_location));
    char *foreign_url = att_base64((const unsigned char *)foreign_location, strlen(foreign_location));
    char response[16384], key1[256], key2[256], body[512];
    long long id1 = 0, id2 = 0;
    att_key_server key_server = {pem, 0, ""};
    int failed = key == NULL || key_url == NULL || foreign_url == NULL;
    st_object_storage_set_callback_key_fetcher_for_tests(att_fetch_callback_key, &key_server);
    ATT_STEP(att_public_upload(&alice, ATT_CALLBACK_ROOM, ATT_CALLBACK_TOKEN, 10, 200, NULL, &id1, key1,
                               "callback upload"));
    ATT_STEP(att_public_upload(&alice, ATT_CALLBACK_ROOM, ATT_CALLBACK_TOKEN, 10, 200, NULL, &id2, key2,
                               "oversized callback upload"));
    snprintf(body, sizeof(body), "{\"bucket\":\"examplebucket\",\"object\":\"%s\",\"size\":12}", key1);
    char *signature = failed ? NULL : att_sign_callback(key, body);
    failed = failed || signature == NULL;

    /* Invalid signatures: none, one over another body, and a valid one under a foreign key URL. */
    ATT_STEP(att_callback(body, NULL, key_url, 403, "signature", "callback without signature"));
    char *other = failed ? NULL : att_sign_callback(key, "{\"bucket\":\"examplebucket\"}");
    ATT_STEP(other == NULL ? -1 : att_callback(body, other, key_url, 403, "signature", "callback signed over another body"));
    free(other);
    ATT_STEP(att_callback(body, signature, foreign_url, 403, "signature", "callback key outside gosspublic"));
    ATT_STEP(att_row(id1, "PENDING", 10, "after refused callbacks"));
    /* A valid signature for another bucket or for an object the server never allocated. */
    ATT_STEP(att_signed_callback(key, key_url, "otherbucket", key1, 12, 403, "bucket", "callback for another bucket"));
    ATT_STEP(att_signed_callback(key, key_url, "examplebucket", "prefix/public-transfer/20260101/1/none.txt", 12,
                                 400, "not allocated", "callback for an unallocated object"));
    /* An oversized object reported by a valid callback is deleted and refused. */
    ATT_STEP(att_signed_callback(key, key_url, "examplebucket", key2, 65, 400, "too large", "oversized callback"));
    if (!failed && !att_oss_deleted(key2)) {
        fprintf(stderr, "the oversized callback object was not deleted\n");
        failed = 1;
    }
    ATT_STEP(att_row(id2, "PENDING", 10, "after oversized callback"));

    /* A valid callback completes the upload with the signed size, without a HEAD request... */
    int requests = att_oss_requests();
    ATT_STEP(att_callback(body, signature, key_url, 200, "\"Status\":\"OK\"", "valid callback"));
    ATT_STEP(att_row(id1, "UPLOADED", 12, "after valid callback"));
    ATT_STEP(att_callback(body, signature, key_url, 200, "\"Status\":\"OK\"", "replayed callback"));
    /* ...and the client's complete is idempotent on top of it. */
    ATT_STEP(att_action(&alice, 1, id1, "complete", ATT_CALLBACK_TOKEN, 200, "\"sizeBytes\":12", response,
                        sizeof(response), "complete after callback"));
    if (!failed && att_oss_requests() != requests) {
        fprintf(stderr, "a callback-completed upload was still verified with HEAD\n");
        failed = 1;
    }
    /*
     * Java uploadCallbackVerificationPinsAndCachesAliyunPublicKey: every verification so far used
     * one key, fetched once and over https although the header named http://.
     */
    if (!failed && (key_server.calls != 1
                    || strcmp(key_server.last_url, "https://gosspublic.alicdn.com/callback_pub_key_v1.pem") != 0)) {
        fprintf(stderr, "callback key fetched %d times, last from %s\n", key_server.calls, key_server.last_url);
        failed = 1;
    }
    /* A padded header (trimmed as in Java) names the cached key; another key path is fetched once. */
    char padded_url[512];
    snprintf(padded_url, sizeof(padded_url), "  %s  ", key_url == NULL ? "" : key_url);
    ATT_STEP(att_callback(body, signature, padded_url, 200, "\"Status\":\"OK\"", "callback with a padded key URL"));
    static const char second_location[] = "https://gosspublic.alicdn.com/callback_pub_key_v2.pem";
    char *second_url = att_base64((const unsigned char *)second_location, strlen(second_location));
    ATT_STEP(second_url == NULL ? -1 : att_callback(body, signature, second_url, 200, "\"Status\":\"OK\"",
                                                    "callback under a second key URL"));
    ATT_STEP(second_url == NULL ? -1 : att_callback(body, signature, second_url, 200, "\"Status\":\"OK\"",
                                                    "callback under the cached second key URL"));
    free(second_url);
    if (!failed && (key_server.calls != 2 || strcmp(key_server.last_url, second_location) != 0)) {
        fprintf(stderr, "second callback key fetched %d times in all, last from %s\n", key_server.calls,
                key_server.last_url);
        failed = 1;
    }
    /* A failed fetch is not cached: the next callback naming that key fetches again. */
    static const char third_location[] = "http://gosspublic.alicdn.com/callback_pub_key_v3.pem";
    char *third_url = att_base64((const unsigned char *)third_location, strlen(third_location));
    key_server.pem = NULL;
    ATT_STEP(third_url == NULL ? -1 : att_callback(body, signature, third_url, 403, "signature",
                                                   "callback whose key fetch fails"));
    ATT_STEP(third_url == NULL ? -1 : att_callback(body, signature, third_url, 403, "signature",
                                                   "callback whose key fetch fails again"));
    key_server.pem = pem;
    free(third_url);
    if (!failed && key_server.calls != 4) {
        fprintf(stderr, "a failed callback key fetch was cached (%d fetches)\n", key_server.calls);
        failed = 1;
    }
    /* Without a configured callback URL every callback is refused. */
    unsetenv("SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL");
    ATT_STEP(att_callback(body, signature, key_url, 403, "signature", "callback with callbacks disabled"));
    st_object_storage_set_callback_key_fetcher_for_tests(NULL, NULL);
    free(signature);
    free(foreign_url);
    free(key_url);
    free(pem);
    EVP_PKEY_free(key);
    return failed ? -1 : 0;
}

static int test_attachment_negative_paths(void)
{
    int port = 0;
    if (att_oss_start(&port) != 0) return -1;
    int failed = att_configure(port) != 0;
    if (failed) fprintf(stderr, "attachment fixture setup failed\n");
    failed = failed || att_public_paths() != 0 || att_admin_paths() != 0 || att_callback_paths() != 0
        || att_upload_normalization() != 0 || att_filename_normalization() != 0 || att_id_collision() != 0
        || att_pending_download() != 0;
    att_oss_stop();
    att_unconfigure();
    return failed ? -1 : 0;
}

int main(void)
{
    snprintf(cap_db_path, sizeof(cap_db_path), "/tmp/specus_c_capabilities_%ld.db", (long)getpid());
    snprintf(cap_missing_db_path, sizeof(cap_missing_db_path), "/tmp/specus_c_capabilities_missing_%ld.db",
             (long)getpid());
    if (setenv("SPECUS_AUTH_JWT_SECRET", CAP_SECRET, 1) != 0) return 1;
    if (configure() != 0 || test_download_vector() != 0 || test_upload_callback_header() != 0
        || test_expiration_cleanup() != 0) return 1;
    if (test_capabilities_requires_authentication() != 0
        || test_capabilities_account_snapshots() != 0
        || test_capabilities_month_and_expiry_boundaries() != 0
        || test_capabilities_storage_disabled() != 0
        || test_capabilities_read_failures() != 0
        || test_capabilities_never_contacts_object_storage() != 0
        || test_capabilities_shared_vector() != 0) {
        fprintf(stderr, "transfer capability tests failed\n");
        return 1;
    }
    if (test_attachment_negative_paths() != 0) {
        fprintf(stderr, "attachment negative path tests failed\n");
        return 1;
    }
    puts("object storage tests passed");
    return 0;
}
