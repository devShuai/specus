#define _POSIX_C_SOURCE 200809L

#include "object_storage.h"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(void)
{
    if (configure() != 0 || test_download_vector() != 0 || test_upload_callback_header() != 0
        || test_expiration_cleanup() != 0) return 1;
    puts("object storage tests passed");
    return 0;
}
