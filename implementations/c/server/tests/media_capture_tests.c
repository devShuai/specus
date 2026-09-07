#define _POSIX_C_SOURCE 200809L

#include "media_capture.h"
#include "json.h"
#include "storage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int expect_capture(const char *database_path, long long expected_bytes)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
            "SELECT state,captured_bytes,object_etag,upload_id,media_kind,source_url "
            "FROM specus_http_media_capture ORDER BY id DESC LIMIT 1",
            -1, &stmt, NULL) == SQLITE_OK;
    if (ok && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *state = (const char *)sqlite3_column_text(stmt, 0);
        const char *etag = (const char *)sqlite3_column_text(stmt, 2);
        const char *kind = (const char *)sqlite3_column_text(stmt, 4);
        const char *source = (const char *)sqlite3_column_text(stmt, 5);
        ok = state != NULL && strcmp(state, "COMPLETE") == 0
            && sqlite3_column_int64(stmt, 1) == expected_bytes
            && etag != NULL && strcmp(etag, "\"complete-etag\"") == 0
            && sqlite3_column_type(stmt, 3) == SQLITE_NULL
            && kind != NULL && strcmp(kind, "PROGRESSIVE") == 0
            && source != NULL && strcmp(source, "/movie.mp4?token=redacted") == 0;
    } else {
        ok = 0;
    }
    sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    return ok;
}

static long long latest_capture_id(const char *database_path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long id = 0;
    if (sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT MAX(id) FROM specus_http_media_capture", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) id = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    return id;
}

int main(void)
{
    unsetenv("SPECUS_MEDIA_CAPTURE_ENABLED");
    if (st_media_capture_validate_current() != 0 || st_media_capture_ready_current()) {
        fprintf(stderr, "disabled media capture initialization mismatch\n");
        return 1;
    }
    const char *endpoint = getenv("SPECUS_MEDIA_CAPTURE_TEST_ENDPOINT");
    if (endpoint == NULL || *endpoint == '\0') {
        fprintf(stderr, "SPECUS_MEDIA_CAPTURE_TEST_ENDPOINT is required\n");
        return 1;
    }
    setenv("SPECUS_MEDIA_CAPTURE_ENABLED", "true", 1);
    setenv("SPECUS_MEDIA_CAPTURE_ENDPOINT", endpoint, 1);
    setenv("SPECUS_MEDIA_CAPTURE_REGION", "us-east-1", 1);
    setenv("SPECUS_MEDIA_CAPTURE_BUCKET", "media-bucket", 1);
    setenv("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_ID", "media-access", 1);
    setenv("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_SECRET", "media-secret", 1);
    setenv("SPECUS_MEDIA_CAPTURE_PREFIX", "specus/http-media", 1);
    setenv("SPECUS_MEDIA_CAPTURE_PATH_STYLE", "true", 1);
    setenv("SPECUS_MEDIA_CAPTURE_PART_SIZE_BYTES", "5242880", 1);
    if (st_media_capture_validate_current() != 0 || !st_media_capture_ready_current()) {
        fprintf(stderr, "media capture backend initialization failed\n");
        return 1;
    }
    char database_path[] = "/tmp/specus-c-media-XXXXXX";
    int fd = mkstemp(database_path);
    if (fd < 0) return 1;
    close(fd);
    if (st_storage_init(database_path, 1) != 0) {
        unlink(database_path);
        return 1;
    }
    st_storage_client client;
    st_storage_http_route route;
    if (st_storage_get_client_by_name(database_path, "Demo client", &client) != 0
        || st_storage_create_http_route_for_client(database_path, client.id, "media",
            "https://origin.example/media", 1, 0, 1, 0, 0, 0, "", "", &route) != 0
        || !route.media_capture_enabled) {
        fprintf(stderr, "media capture route fixture failed\n");
        unlink(database_path);
        return 1;
    }
    char *headers[] = {
        "Content-Type: video/mp4",
        "Content-Length: 5242883",
        "ETag: origin-etag"
    };
    st_media_capture_session *session = st_media_capture_open(database_path,
        "Demo client", "media", "GET", "/movie.mp4?token=redacted", 200,
        headers, sizeof(headers) / sizeof(headers[0]));
    if (session == NULL || !st_media_capture_externalized(session)) {
        fprintf(stderr, "media capture session did not open\n");
        unlink(database_path);
        return 1;
    }
    size_t first_len = 5U * 1024U * 1024U;
    unsigned char *first = (unsigned char *)malloc(first_len);
    if (first == NULL) return 1;
    memset(first, 'A', first_len);
    const unsigned char tail[] = {'E', 'N', 'D'};
    int append_ok = st_media_capture_append(session, first, first_len) == 0
        && st_media_capture_append(session, tail, sizeof(tail)) == 0;
    free(first);
    if (!append_ok) {
        fprintf(stderr, "media capture append failed\n");
        st_media_capture_free(session);
        unlink(database_path);
        return 1;
    }
    st_media_capture_complete(session);
    st_media_capture_free(session);
    if (!expect_capture(database_path, 5242883LL)) {
        fprintf(stderr, "completed media capture database mismatch\n");
        unlink(database_path);
        return 1;
    }
    long long capture_id = latest_capture_id(database_path);
    st_media_capture_identity identity = {
        .tenant_id = "default", .username = "admin", .admin = 1, .authenticated = 1
    };
    char *response = (char *)malloc(2U * 1024U * 1024U);
    if (response == NULL) return 1;
    int response_len = st_media_capture_build_response("GET",
        "/api/admin/traffic/media-captures?page=0&size=20", &identity,
        database_path, response, 2U * 1024U * 1024U);
    if (response_len <= 0 || strstr(response, "200 OK") == NULL
        || strstr(response, "\"total\":1") == NULL
        || strstr(response, "token=[REDACTED]") == NULL
        || strstr(response, "\"playable\":true") == NULL) {
        fprintf(stderr, "media capture management list mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }
    char ticket_path[256];
    snprintf(ticket_path, sizeof(ticket_path),
        "/api/admin/traffic/media-captures/%lld/playback-ticket?backfillMissing=true", capture_id);
    response_len = st_media_capture_build_response("POST", ticket_path, &identity,
        database_path, response, 2U * 1024U * 1024U);
    char *response_body = strstr(response, "\r\n\r\n");
    char *ticket = response_body == NULL ? NULL : st_json_get_string(response_body + 4, "ticket");
    if (response_len <= 0 || strstr(response, "200 OK") == NULL || ticket == NULL
        || strlen(ticket) != 43U || strstr(response, "\"backfillMissing\":true") == NULL) {
        fprintf(stderr, "media playback ticket mismatch\n");
        free(ticket);
        free(response);
        unlink(database_path);
        return 1;
    }
    char play_path[256];
    snprintf(play_path, sizeof(play_path), "/api/public/media-playback/%s/play", ticket);
    response_len = st_media_capture_build_response_with_range("GET", play_path,
        "bytes=5242880-5242882", NULL, database_path, response, 2U * 1024U * 1024U);
    free(ticket);
    if (response_len > 0 && response_len < 2 * 1024 * 1024) response[response_len] = '\0';
    char *play_body = strstr(response, "\r\n\r\n");
    if (response_len <= 0 || strstr(response, "206 Partial Content") == NULL
        || strstr(response, "Content-Range: bytes 5242880-5242882/5242883") == NULL
        || play_body == NULL || memcmp(play_body + 4, "END", 3U) != 0) {
        fprintf(stderr, "public media ranged playback mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }

    char *sparse_headers_a[] = {
        "Content-Type: video/mp4",
        "Content-Length: 3",
        "Content-Range: bytes 0-2/6",
        "ETag: sparse-etag"
    };
    session = st_media_capture_open(database_path, "Demo client", "media", "GET",
        "/sparse.mp4", 206, sparse_headers_a,
        sizeof(sparse_headers_a) / sizeof(sparse_headers_a[0]));
    if (session == NULL
        || st_media_capture_append(session, (const unsigned char *)"ABC", 3U) != 0) {
        fprintf(stderr, "first sparse media range capture failed\n");
        st_media_capture_free(session);
        free(response);
        unlink(database_path);
        return 1;
    }
    st_media_capture_complete(session);
    st_media_capture_free(session);
    char *sparse_headers_b[] = {
        "Content-Type: video/mp4",
        "Content-Length: 3",
        "Content-Range: bytes 3-5/6",
        "ETag: sparse-etag"
    };
    session = st_media_capture_open(database_path, "Demo client", "media", "GET",
        "/sparse.mp4", 206, sparse_headers_b,
        sizeof(sparse_headers_b) / sizeof(sparse_headers_b[0]));
    if (session == NULL
        || st_media_capture_append(session, (const unsigned char *)"DEF", 3U) != 0) {
        fprintf(stderr, "second sparse media range capture failed\n");
        st_media_capture_free(session);
        free(response);
        unlink(database_path);
        return 1;
    }
    st_media_capture_complete(session);
    st_media_capture_free(session);
    long long sparse_id = latest_capture_id(database_path);
    snprintf(ticket_path, sizeof(ticket_path),
        "/api/admin/traffic/media-captures/%lld/playback-ticket", sparse_id);
    response_len = st_media_capture_build_response("POST", ticket_path, &identity,
        database_path, response, 2U * 1024U * 1024U);
    response_body = strstr(response, "\r\n\r\n");
    ticket = response_body == NULL ? NULL : st_json_get_string(response_body + 4, "ticket");
    if (ticket == NULL) {
        fprintf(stderr, "sparse media playback ticket mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }
    snprintf(play_path, sizeof(play_path), "/api/public/media-playback/%s/play", ticket);
    response_len = st_media_capture_build_response_with_range("GET", play_path,
        "bytes=1-4", NULL, database_path, response, 2U * 1024U * 1024U);
    free(ticket);
    if (response_len > 0 && response_len < 2 * 1024 * 1024) response[response_len] = '\0';
    play_body = strstr(response, "\r\n\r\n");
    if (response_len <= 0 || strstr(response, "206 Partial Content") == NULL
        || strstr(response, "Content-Range: bytes 1-4/6") == NULL
        || play_body == NULL || memcmp(play_body + 4, "BCDE", 4U) != 0) {
        fprintf(stderr, "sparse media range stitching mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }

    const char manifest[] = "#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:4.0,\nsegment.ts\n#EXT-X-ENDLIST\n";
    char manifest_length_header[64];
    snprintf(manifest_length_header, sizeof(manifest_length_header), "Content-Length: %zu", strlen(manifest));
    char *manifest_headers[] = {
        "Content-Type: application/vnd.apple.mpegurl",
        manifest_length_header
    };
    session = st_media_capture_open(database_path, "Demo client", "media", "GET",
        "/live/index.m3u8", 200, manifest_headers,
        sizeof(manifest_headers) / sizeof(manifest_headers[0]));
    if (session == NULL
        || st_media_capture_append(session, (const unsigned char *)manifest, strlen(manifest)) != 0) {
        fprintf(stderr, "HLS media capture open or append failed\n");
        st_media_capture_free(session);
        free(response);
        unlink(database_path);
        return 1;
    }
    st_media_capture_complete(session);
    st_media_capture_free(session);
    long long manifest_id = latest_capture_id(database_path);
    char manifest_path[256];
    snprintf(manifest_path, sizeof(manifest_path),
        "/api/admin/traffic/media-captures/%lld/manifest", manifest_id);
    response_len = st_media_capture_build_response("GET", manifest_path, &identity,
        database_path, response, 2U * 1024U * 1024U);
    if (response_len <= 0 || strstr(response, "200 OK") == NULL
        || strstr(response, "Content-Type: application/vnd.apple.mpegurl") == NULL
        || strstr(response, "/api/admin/traffic/media-captures/") == NULL
        || strstr(response, "/asset?url=%2Flive%2Fsegment.ts") == NULL) {
        fprintf(stderr, "rewritten HLS manifest response mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }
    snprintf(ticket_path, sizeof(ticket_path),
        "/api/admin/traffic/media-captures/%lld/playback-ticket", manifest_id);
    response_len = st_media_capture_build_response("POST", ticket_path, &identity,
        database_path, response, 2U * 1024U * 1024U);
    response_body = strstr(response, "\r\n\r\n");
    ticket = response_body == NULL ? NULL : st_json_get_string(response_body + 4, "ticket");
    if (ticket == NULL) {
        fprintf(stderr, "HLS playback ticket mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }
    snprintf(play_path, sizeof(play_path), "/api/public/media-playback/%s/manifest", ticket);
    response_len = st_media_capture_build_response("GET", play_path, NULL,
        database_path, response, 2U * 1024U * 1024U);
    free(ticket);
    if (response_len <= 0 || strstr(response, "200 OK") == NULL
        || strstr(response, "/api/public/media-playback/") == NULL
        || strstr(response, "/asset?url=%2Flive%2Fsegment.ts") == NULL) {
        fprintf(stderr, "public rewritten HLS manifest response mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }
    sqlite3 *cleanup_db = NULL;
    sqlite3_stmt *cleanup_stmt = NULL;
    int cleanup_ok = sqlite3_open(database_path, &cleanup_db) == SQLITE_OK
        && sqlite3_prepare_v2(cleanup_db,
            "UPDATE specus_http_media_capture SET state='FAILED',expires_at='2000-01-01T00:00:00Z' WHERE id=?",
            -1, &cleanup_stmt, NULL) == SQLITE_OK;
    if (cleanup_ok) {
        sqlite3_bind_int64(cleanup_stmt, 1, manifest_id);
        cleanup_ok = sqlite3_step(cleanup_stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(cleanup_stmt);
    cleanup_stmt = NULL;
    if (cleanup_ok) cleanup_ok = st_media_capture_cleanup_expired(database_path) == 0
        && sqlite3_prepare_v2(cleanup_db,
            "SELECT COUNT(*) FROM specus_http_media_capture WHERE id=?",
            -1, &cleanup_stmt, NULL) == SQLITE_OK;
    if (cleanup_ok) {
        sqlite3_bind_int64(cleanup_stmt, 1, manifest_id);
        cleanup_ok = sqlite3_step(cleanup_stmt) == SQLITE_ROW
            && sqlite3_column_int(cleanup_stmt, 0) == 0;
    }
    sqlite3_finalize(cleanup_stmt);
    if (cleanup_db != NULL) sqlite3_close(cleanup_db);
    if (!cleanup_ok) {
        fprintf(stderr, "expired media capture cleanup mismatch\n");
        free(response);
        unlink(database_path);
        return 1;
    }
    free(response);
    unlink(database_path);
    puts("media capture tests passed");
    return 0;
}
