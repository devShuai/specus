#define _POSIX_C_SOURCE 200809L

#include "object_storage.h"

#include "admin_http.h"
#include "json.h"
#include "security.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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
    puts("object storage tests passed");
    return 0;
}
