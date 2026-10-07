#define _POSIX_C_SOURCE 200809L

/*
 * HTTP media capture against a fake S3 (scripts/media_capture_test.sh), driven through a real admin
 * listener: responses are captured on the /http/{client}/{route} path while a scripted forwarder
 * plays the client's upstream, and playback goes through the real management and public endpoints.
 * The scenarios follow the Java HttpMediaCaptureServiceTests, HttpMediaManifestSupportTests,
 * HttpMediaPlaybackServiceTests, HttpMediaPlaybackTicketServiceTests and
 * PublicHttpMediaPlaybackResourceTests.
 */

#include "admin_http.h"
#include "json.h"
#include "media_capture.h"
#include "storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define RESPONSE_CAPACITY (8U * 1024U * 1024U)
#define MEDIA_ROUTE_PATH "/http/Demo%20client/media"
#define MAX_UPSTREAM_HEADERS 6U

static char g_database_path[64];
static const char *g_state_dir;
static int g_admin_port;
static char g_authorization[2400];
static char *g_response;

/* ------------------------------------------------------------------------------------------------
 * The client's upstream, as the forwarder plays it
 */

typedef struct {
    int status;
    const char *headers[MAX_UPSTREAM_HEADERS];
    size_t headers_len;
    const uint8_t *body;
    size_t body_len;
    /* Bytes delivered before the client resets the stream; 0 delivers the whole body. */
    size_t reset_after;
    /* Keeps the response open after its body until upstream_release(). */
    int hold;
} upstream_script;

static pthread_mutex_t g_upstream_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_upstream_cond = PTHREAD_COND_INITIALIZER;
static upstream_script g_upstream;
static int g_upstream_held;
static int g_upstream_released;

static int media_upstream_forwarder(void *ctx,
                                    const char *client_name,
                                    const st_direct_http_request *request,
                                    const st_admin_direct_http_sink *sink)
{
    (void)ctx;
    (void)client_name;
    (void)request;
    pthread_mutex_lock(&g_upstream_lock);
    upstream_script script = g_upstream;
    g_upstream.hold = 0;
    pthread_mutex_unlock(&g_upstream_lock);
    char *headers[MAX_UPSTREAM_HEADERS];
    for (size_t i = 0; i < script.headers_len; ++i) {
        headers[i] = (char *)script.headers[i];
    }
    if (sink->on_headers(sink->ctx, script.status, headers, script.headers_len, NULL, 0U) != 0) {
        return -1;
    }
    size_t limit = script.reset_after > 0U ? script.reset_after : script.body_len;
    for (size_t offset = 0; offset < limit;) {
        size_t chunk = limit - offset < 65536U ? limit - offset : 65536U;
        if (sink->on_data(sink->ctx, script.body + offset, chunk) != 0) {
            return -1;
        }
        offset += chunk;
    }
    if (script.hold) {
        pthread_mutex_lock(&g_upstream_lock);
        g_upstream_held = 1;
        pthread_cond_broadcast(&g_upstream_cond);
        while (!g_upstream_released) {
            pthread_cond_wait(&g_upstream_cond, &g_upstream_lock);
        }
        pthread_mutex_unlock(&g_upstream_lock);
    }
    if (script.reset_after > 0U) {
        /* The client's upstream broke off mid-body: the NAT stream ends with RST. */
        if (sink->on_reset != NULL) {
            sink->on_reset(sink->ctx, 1U, "upstream connection reset");
        }
        return ST_ADMIN_DIRECT_HTTP_STREAM_RESET;
    }
    return sink->on_end(sink->ctx, NULL, 0U) == 0 ? 0 : -1;
}

static upstream_script upstream(int status, const uint8_t *body, size_t body_len)
{
    upstream_script script;
    memset(&script, 0, sizeof(script));
    script.status = status;
    script.body = body;
    script.body_len = body_len;
    return script;
}

static void upstream_header(upstream_script *script, const char *header)
{
    if (script->headers_len < MAX_UPSTREAM_HEADERS) {
        script->headers[script->headers_len++] = header;
    }
}

/* ------------------------------------------------------------------------------------------------
 * HTTP over the real admin listener
 */

static int http_exchange(const char *request, char *response, size_t response_len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct timeval timeout = {.tv_sec = 15, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)g_admin_port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    size_t request_len = strlen(request);
    for (size_t sent = 0; sent < request_len;) {
        ssize_t written = send(fd, request + sent, request_len - sent, 0);
        if (written <= 0) {
            close(fd);
            return -1;
        }
        sent += (size_t)written;
    }
    (void)shutdown(fd, SHUT_WR);
    size_t received = 0;
    while (received + 1U < response_len) {
        ssize_t got = recv(fd, response + received, response_len - 1U - received, 0);
        if (got == 0) {
            break;
        }
        if (got < 0) {
            close(fd);
            return -1;
        }
        received += (size_t)got;
    }
    response[received] = '\0';
    close(fd);
    return received > 0U ? (int)received : -1;
}

/* Sends method path with the extra header lines; the response lands in g_response. */
static int http_call(const char *method, const char *path, const char *extra_headers)
{
    char request[4096];
    int written = snprintf(request, sizeof(request),
                           "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n%s%s\r\n",
                           method, path, extra_headers == NULL ? "" : extra_headers,
                           strcmp(method, "POST") == 0 ? "Content-Length: 0\r\n" : "");
    if (written < 0 || (size_t)written >= sizeof(request)) {
        return -1;
    }
    return http_exchange(request, g_response, RESPONSE_CAPACITY);
}

static int admin_call(const char *method, const char *path)
{
    return http_call(method, path, g_authorization);
}

static int public_call(const char *token, const char *suffix, const char *range)
{
    char path[1024];
    char headers[256];
    snprintf(path, sizeof(path), "/api/public/media-playback/%s%s", token, suffix);
    headers[0] = '\0';
    if (range != NULL) {
        snprintf(headers, sizeof(headers), "Range: %s\r\n", range);
    }
    return http_call("GET", path, headers);
}

static int response_status(const char *response)
{
    int status = 0;
    return sscanf(response, "HTTP/1.1 %d", &status) == 1 ? status : 0;
}

static const char *response_body(const char *response)
{
    const char *separator = strstr(response, "\r\n\r\n");
    return separator == NULL ? "" : separator + 4;
}

/* Whether the response head holds exactly this header line, e.g. "Content-Length: 50". */
static int response_has_header(const char *response, const char *line)
{
    const char *end = strstr(response, "\r\n\r\n");
    size_t line_len = strlen(line);
    for (const char *cursor = strstr(response, "\r\n"); cursor != NULL && cursor < end;
         cursor = strstr(cursor + 2, "\r\n")) {
        if (strncmp(cursor + 2, line, line_len) == 0
            && (cursor[2 + line_len] == '\r' || cursor[2 + line_len] == '\0')) {
            return 1;
        }
    }
    return 0;
}

/* Whether any header of the response head is called name (any value). */
static int response_has_header_named(const char *response, const char *name)
{
    const char *end = strstr(response, "\r\n\r\n");
    size_t name_len = strlen(name);
    for (const char *cursor = strstr(response, "\r\n"); cursor != NULL && cursor < end;
         cursor = strstr(cursor + 2, "\r\n")) {
        if (strncasecmp(cursor + 2, name, name_len) == 0 && cursor[2 + name_len] == ':') {
            return 1;
        }
    }
    return 0;
}

/* Captures one upstream response through /http/Demo client/media{path}. */
static int capture_via_http(const char *path, const upstream_script *script)
{
    pthread_mutex_lock(&g_upstream_lock);
    g_upstream = *script;
    pthread_mutex_unlock(&g_upstream_lock);
    char full_path[1024];
    snprintf(full_path, sizeof(full_path), "%s%s", MEDIA_ROUTE_PATH, path);
    return http_call("GET", full_path, NULL) > 0 && response_status(g_response) == script->status
        ? 0 : -1;
}

static void fill_pattern(uint8_t *out, long long start, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        out[i] = (uint8_t)('a' + (int)((start + (long long)i) % 26LL));
    }
}

static int body_matches_pattern(const char *response, long long start, size_t len)
{
    uint8_t *expected = (uint8_t *)malloc(len == 0U ? 1U : len);
    if (expected == NULL) {
        return 0;
    }
    fill_pattern(expected, start, len);
    int matches = memcmp(response_body(response), expected, len) == 0;
    free(expected);
    return matches;
}

/* Captures bytes start..end of a total-byte resource as one 206 response. */
static int capture_range(const char *path, long long start, long long end, long long total,
                         const char *extra_header)
{
    size_t len = (size_t)(end - start + 1LL);
    uint8_t *body = (uint8_t *)malloc(len);
    if (body == NULL) {
        return -1;
    }
    fill_pattern(body, start, len);
    char range[96];
    char length[64];
    snprintf(range, sizeof(range), "Content-Range: bytes %lld-%lld/%lld", start, end, total);
    snprintf(length, sizeof(length), "Content-Length: %zu", len);
    upstream_script script = upstream(206, body, len);
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, range);
    upstream_header(&script, length);
    if (extra_header != NULL) {
        upstream_header(&script, extra_header);
    }
    int rc = capture_via_http(path, &script);
    free(body);
    return rc;
}

/* ------------------------------------------------------------------------------------------------
 * What the database and the fake S3 hold
 */

typedef struct {
    long long id;
    char state[32];
    long long captured;
    int has_start;
    int has_end;
    int has_total;
    long long start;
    long long end;
    long long total;
    int has_dedup;
    char kind[32];
    int has_sequence;
    long long sequence;
    int initialization;
    int live;
    char object_key[1024];
    char captured_at[64];
    char expires_at[64];
    char method[17];
    char object_etag[128];
} capture_snapshot;

static void column_text(sqlite3_stmt *stmt, int column, char *out, size_t out_len)
{
    const char *value = (const char *)sqlite3_column_text(stmt, column);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
}

/* The newest capture of source_url, skipping the newest `skip` ones; 0 when found. */
static int capture_of(const char *source_url, int skip, capture_snapshot *out)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int found = 0;
    memset(out, 0, sizeof(*out));
    if (sqlite3_open(g_database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
            "SELECT id,state,captured_bytes,content_range_start,content_range_end,total_bytes,"
            "deduplication_key,media_kind,segment_sequence,initialization_segment,live_stream,"
            "object_key,captured_at,expires_at,method,object_etag "
            "FROM specus_http_media_capture WHERE source_url=? ORDER BY id DESC LIMIT 1 OFFSET ?",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, source_url, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 2, skip);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            out->id = sqlite3_column_int64(stmt, 0);
            column_text(stmt, 1, out->state, sizeof(out->state));
            out->captured = sqlite3_column_int64(stmt, 2);
            out->has_start = sqlite3_column_type(stmt, 3) != SQLITE_NULL;
            out->start = sqlite3_column_int64(stmt, 3);
            out->has_end = sqlite3_column_type(stmt, 4) != SQLITE_NULL;
            out->end = sqlite3_column_int64(stmt, 4);
            out->has_total = sqlite3_column_type(stmt, 5) != SQLITE_NULL;
            out->total = sqlite3_column_int64(stmt, 5);
            out->has_dedup = sqlite3_column_type(stmt, 6) != SQLITE_NULL;
            column_text(stmt, 7, out->kind, sizeof(out->kind));
            out->has_sequence = sqlite3_column_type(stmt, 8) != SQLITE_NULL;
            out->sequence = sqlite3_column_int64(stmt, 8);
            out->initialization = sqlite3_column_int(stmt, 9);
            out->live = sqlite3_column_int(stmt, 10);
            column_text(stmt, 11, out->object_key, sizeof(out->object_key));
            column_text(stmt, 12, out->captured_at, sizeof(out->captured_at));
            column_text(stmt, 13, out->expires_at, sizeof(out->expires_at));
            column_text(stmt, 14, out->method, sizeof(out->method));
            column_text(stmt, 15, out->object_etag, sizeof(out->object_etag));
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    if (db != NULL) {
        sqlite3_close(db);
    }
    return found ? 0 : -1;
}

static long long count_rows(const char *sql, const char *text, long long number)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long count = -1;
    if (sqlite3_open(g_database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        if (text != NULL) {
            sqlite3_bind_text(stmt, 1, text, -1, SQLITE_TRANSIENT);
        } else {
            sqlite3_bind_int64(stmt, 1, number);
        }
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            count = sqlite3_column_int64(stmt, 0);
        }
    }
    sqlite3_finalize(stmt);
    if (db != NULL) {
        sqlite3_close(db);
    }
    return count;
}

static long long captures_of(const char *source_url)
{
    return count_rows("SELECT COUNT(*) FROM specus_http_media_capture WHERE source_url=?", source_url, 0);
}

static int db_update_times(long long id, const char *captured_at, const char *expires_at)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int ok = sqlite3_open(g_database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
            "UPDATE specus_http_media_capture SET captured_at=?,expires_at=? WHERE id=?",
            -1, &stmt, NULL) == SQLITE_OK;
    if (ok) {
        sqlite3_bind_text(stmt, 1, captured_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, expires_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 3, id);
        ok = sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1;
    }
    sqlite3_finalize(stmt);
    if (db != NULL) {
        sqlite3_close(db);
    }
    return ok ? 0 : -1;
}

typedef struct {
    char relation[32];
    int has_sequence;
    long long sequence;
    char resolved[512];
} reference_snapshot;

/* The manifest's stored references in manifest order; returns how many were read. */
static int references_of(long long manifest_id, reference_snapshot *out, int max)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int count = 0;
    if (sqlite3_open(g_database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
            "SELECT relation_type,sequence_index,resolved_source_url FROM specus_http_media_reference "
            "WHERE manifest_capture_id=? ORDER BY id",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, manifest_id);
        while (count < max && sqlite3_step(stmt) == SQLITE_ROW) {
            column_text(stmt, 0, out[count].relation, sizeof(out[count].relation));
            out[count].has_sequence = sqlite3_column_type(stmt, 1) != SQLITE_NULL;
            out[count].sequence = sqlite3_column_int64(stmt, 1);
            column_text(stmt, 2, out[count].resolved, sizeof(out[count].resolved));
            ++count;
        }
    }
    sqlite3_finalize(stmt);
    if (db != NULL) {
        sqlite3_close(db);
    }
    return count;
}

static int reference_is(const reference_snapshot *reference, const char *relation,
                        long long sequence, const char *resolved)
{
    return strcmp(reference->relation, relation) == 0
        && (sequence < 0 ? !reference->has_sequence
                         : reference->has_sequence && reference->sequence == sequence)
        && strcmp(reference->resolved, resolved) == 0;
}

/* Lines of a fake S3 log (initiated.log, deleted.log) that contain needle (all when NULL). */
static int s3_log_lines(const char *name, const char *needle)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", g_state_dir, name);
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    char line[2048];
    int count = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        if (needle == NULL || strstr(line, needle) != NULL) {
            ++count;
        }
    }
    fclose(file);
    return count;
}

static void iso_time(time_t value, char out[64])
{
    struct tm utc;
    gmtime_r(&value, &utc);
    strftime(out, 64U, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

/* ------------------------------------------------------------------------------------------------
 * Management and public playback calls
 */

/* The capture's JSON object from the management list, into out. */
static int capture_view(long long id, char *out, size_t out_len)
{
    if (admin_call("GET", "/api/admin/traffic/media-captures?page=0&size=200") <= 0
        || response_status(g_response) != 200) {
        return -1;
    }
    char needle[64];
    snprintf(needle, sizeof(needle), "{\"id\":%lld,", id);
    const char *start = strstr(response_body(g_response), needle);
    const char *end = start == NULL ? NULL : strchr(start, '}');
    if (end == NULL || (size_t)(end - start) + 2U > out_len) {
        return -1;
    }
    memcpy(out, start, (size_t)(end - start) + 1U);
    out[end - start + 1] = '\0';
    return 0;
}

/* Creates a playback ticket; the ticket JSON stays in g_response and the token in token. */
static int create_ticket(long long capture_id, int backfill, char token[64])
{
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/traffic/media-captures/%lld/playback-ticket%s",
             capture_id, backfill ? "?backfillMissing=true" : "");
    if (admin_call("POST", path) <= 0 || response_status(g_response) != 200) {
        return -1;
    }
    char *value = st_json_get_string(response_body(g_response), "ticket");
    int ok = value != NULL && strlen(value) == 43U;
    if (ok) {
        snprintf(token, 64U, "%s", value);
    }
    free(value);
    return ok ? 0 : -1;
}

static int ticket_for_newest(const char *source_url, int backfill, char token[64])
{
    capture_snapshot capture;
    return capture_of(source_url, 0, &capture) == 0 ? create_ticket(capture.id, backfill, token) : -1;
}

/* ------------------------------------------------------------------------------------------------
 * HttpMediaCaptureServiceTests
 */

/* streamsLargeMediaResponseAsRustFsMultipartUpload, then list, ticket and ranged playback. */
static int test_large_response_is_a_multipart_upload(void)
{
    const size_t part = 5U * 1024U * 1024U;
    const size_t total = part + 3U;
    uint8_t *body = (uint8_t *)malloc(total);
    if (body == NULL) {
        return 1;
    }
    memset(body, 'A', part);
    memcpy(body + part, "END", 3U);
    upstream_script script = upstream(200, body, total);
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, "Content-Length: 5242883");
    upstream_header(&script, "ETag: origin-etag");
    int before = s3_log_lines("initiated.log", NULL);
    int rc = capture_via_http("/movie.mp4?token=redacted", &script);
    free(body);
    capture_snapshot capture;
    if (rc != 0 || capture_of("/movie.mp4?token=redacted", 0, &capture) != 0
        || strcmp(capture.state, "COMPLETE") != 0 || capture.captured != 5242883LL
        || strcmp(capture.object_etag, "\"complete-etag\"") != 0 || strcmp(capture.kind, "PROGRESSIVE") != 0
        || strcmp(capture.method, "GET") != 0
        || s3_log_lines("initiated.log", NULL) != before + 1) {
        fprintf(stderr, "completed media capture database mismatch\n");
        return 1;
    }
    char view[4096];
    if (capture_view(capture.id, view, sizeof(view)) != 0
        || strstr(view, "\"sourceUrl\":\"/movie.mp4?token=***\"") == NULL
        || strstr(view, "\"playable\":true,\"offlineReady\":true,\"playbackMessage\":null") == NULL) {
        fprintf(stderr, "media capture management list mismatch\n");
        return 1;
    }
    char token[64];
    if (create_ticket(capture.id, 1, token) != 0
        || strstr(response_body(g_response), "\"backfillMissing\":true") == NULL) {
        fprintf(stderr, "media playback ticket mismatch\n");
        return 1;
    }
    if (public_call(token, "/play", "bytes=5242880-5242882") <= 0
        || response_status(g_response) != 206
        || !response_has_header(g_response, "Content-Range: bytes 5242880-5242882/5242883")
        || !response_has_header(g_response, "ETag: origin-etag")
        || memcmp(response_body(g_response), "END", 3U) != 0) {
        fprintf(stderr, "public media ranged playback mismatch\n");
        return 1;
    }
    return 0;
}

/* acceptsStreamingMediaWithoutContentLength */
static int test_streaming_response_without_content_length(void)
{
    uint8_t body[37];
    memset(body, 'w', sizeof(body));
    upstream_script script = upstream(200, body, sizeof(body));
    upstream_header(&script, "Content-Type: video/webm");
    capture_snapshot capture;
    if (capture_via_http("/live.webm", &script) != 0 || capture_of("/live.webm", 0, &capture) != 0
        || strcmp(capture.state, "COMPLETE") != 0 || capture.captured != 37
        || !capture.has_total || capture.total != 37 || capture.start != 0
        || !capture.has_end || capture.end != 36) {
        fprintf(stderr, "streamed media without Content-Length was not captured completely\n");
        return 1;
    }
    /* Java gives such a response no deduplication key: the same stream is captured again. */
    if (capture.has_dedup || capture_via_http("/live.webm", &script) != 0
        || captures_of("/live.webm") != 2) {
        fprintf(stderr, "media of unknown length was deduplicated\n");
        return 1;
    }
    return 0;
}

/* retainsReceivedRangeWhenPlayerCancelsRequest */
static int test_interrupted_response_keeps_received_range(void)
{
    uint8_t body[1024];
    fill_pattern(body, 1024, sizeof(body));
    upstream_script script = upstream(206, body, sizeof(body));
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, "Content-Range: bytes 1024-2047/4096");
    upstream_header(&script, "Content-Length: 1024");
    script.reset_after = 37U;
    capture_snapshot capture;
    if (capture_via_http("/cancel.mp4", &script) != 0 || capture_of("/cancel.mp4", 0, &capture) != 0
        || strcmp(capture.state, "COMPLETE") != 0 || capture.captured != 37
        || capture.start != 1024 || capture.end != 1060 || capture.total != 4096 || capture.has_dedup) {
        fprintf(stderr, "interrupted media response did not keep exactly its received range\n");
        return 1;
    }
    char view[4096];
    char token[64];
    if (capture_view(capture.id, view, sizeof(view)) != 0
        || strstr(view, "\"contentRangeStart\":1024,\"contentRangeEnd\":1060,\"totalBytes\":4096") == NULL
        || create_ticket(capture.id, 0, token) != 0
        || strstr(response_body(g_response), "\"cachedRanges\":[{\"start\":1024,\"end\":1060}]") == NULL
        || public_call(token, "/play", "bytes=1061-1100") <= 0 || response_status(g_response) != 416) {
        fprintf(stderr, "interrupted media range view or playback mismatch\n");
        return 1;
    }
    return 0;
}

/* skipsRepeatedCompletedRangeWithoutSavingAnotherObject */
static int test_repeated_range_is_not_stored_again(void)
{
    int before = s3_log_lines("initiated.log", NULL);
    if (capture_range("/repeat.mp4", 0, 36, 100, NULL) != 0
        || capture_range("/repeat.mp4", 0, 36, 100, NULL) != 0
        || captures_of("/repeat.mp4") != 1 || s3_log_lines("initiated.log", NULL) != before + 1) {
        fprintf(stderr, "repeated media range was stored again\n");
        return 1;
    }
    char *headers[] = {"Content-Type: video/mp4", "Content-Range: bytes 0-36/100", "Content-Length: 37"};
    st_media_capture_session *duplicate = st_media_capture_open(g_database_path, "Demo client", "media",
        "GET", "/repeat.mp4", 206, headers, sizeof(headers) / sizeof(headers[0]));
    int externalized = duplicate != NULL && st_media_capture_externalized(duplicate)
        && !st_media_capture_active(duplicate);
    st_media_capture_free(duplicate);
    if (!externalized || captures_of("/repeat.mp4") != 1
        || s3_log_lines("initiated.log", NULL) != before + 1) {
        fprintf(stderr, "repeated media range was not an externalized duplicate\n");
        return 1;
    }
    return 0;
}

/* allowsRetryAfterOnlyPartOfRequestedRangeWasCaptured */
static int test_partial_range_can_be_retried(void)
{
    uint8_t body[100];
    fill_pattern(body, 0, sizeof(body));
    upstream_script script = upstream(206, body, sizeof(body));
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, "Content-Range: bytes 0-99/100");
    upstream_header(&script, "Content-Length: 100");
    script.reset_after = 37U;
    capture_snapshot capture;
    if (capture_via_http("/retry.mp4", &script) != 0 || capture_of("/retry.mp4", 0, &capture) != 0
        || strcmp(capture.state, "COMPLETE") != 0 || capture.captured != 37 || capture.has_dedup) {
        fprintf(stderr, "partially captured media range kept its deduplication key\n");
        return 1;
    }
    int before = s3_log_lines("initiated.log", NULL);
    script.reset_after = 0U;
    if (capture_via_http("/retry.mp4", &script) != 0 || captures_of("/retry.mp4") != 2
        || capture_of("/retry.mp4", 0, &capture) != 0 || strcmp(capture.state, "COMPLETE") != 0
        || capture.captured != 100 || !capture.has_dedup
        || s3_log_lines("initiated.log", NULL) != before + 1) {
        fprintf(stderr, "retry after a partially captured range was skipped\n");
        return 1;
    }
    return 0;
}

/* capturesDifferentRangesOfTheSameResourceSeparately */
static int test_different_ranges_are_separate_objects(void)
{
    int before = s3_log_lines("initiated.log", NULL);
    capture_snapshot first;
    capture_snapshot second;
    if (capture_range("/ranges.mp4", 0, 36, 100, NULL) != 0
        || capture_range("/ranges.mp4", 37, 73, 100, NULL) != 0
        || captures_of("/ranges.mp4") != 2
        || capture_of("/ranges.mp4", 0, &second) != 0 || capture_of("/ranges.mp4", 1, &first) != 0
        || strcmp(first.state, "COMPLETE") != 0 || strcmp(second.state, "COMPLETE") != 0
        || first.start != 0 || second.start != 37 || strcmp(first.object_key, second.object_key) == 0
        || s3_log_lines("initiated.log", NULL) != before + 2) {
        fprintf(stderr, "different ranges of one media resource were not captured separately\n");
        return 1;
    }
    return 0;
}

static void *held_capture_thread(void *arg)
{
    (void)arg;
    char *response = (char *)malloc(65536U);
    char request[256];
    snprintf(request, sizeof(request), "GET %s/race.mp4 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
             MEDIA_ROUTE_PATH);
    if (response != NULL) {
        (void)http_exchange(request, response, 65536U);
    }
    free(response);
    return NULL;
}

/*
 * treatsUniqueKeyRaceAsAnExternalizedDuplicate. C checks for a duplicate and inserts in one write
 * transaction, so the second response for a range still being captured finds the first one's
 * CAPTURING row instead of colliding on the unique key; the outcome Java asserts is the same.
 */
static int test_concurrent_duplicate_is_externalized(void)
{
    static uint8_t body[37];
    fill_pattern(body, 0, sizeof(body));
    upstream_script script = upstream(206, body, sizeof(body));
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, "Content-Range: bytes 0-36/100");
    upstream_header(&script, "Content-Length: 37");
    script.hold = 1;
    pthread_mutex_lock(&g_upstream_lock);
    g_upstream = script;
    g_upstream_held = 0;
    g_upstream_released = 0;
    pthread_mutex_unlock(&g_upstream_lock);
    int before = s3_log_lines("initiated.log", NULL);
    pthread_t first;
    if (pthread_create(&first, NULL, held_capture_thread, NULL) != 0) {
        return 1;
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += 15;
    pthread_mutex_lock(&g_upstream_lock);
    while (!g_upstream_held
           && pthread_cond_timedwait(&g_upstream_cond, &g_upstream_lock, &deadline) == 0) {
    }
    int held = g_upstream_held;
    pthread_mutex_unlock(&g_upstream_lock);
    capture_snapshot capture;
    int in_flight = held && capture_of("/race.mp4", 0, &capture) == 0
        && strcmp(capture.state, "CAPTURING") == 0;
    script.hold = 0;
    int second_ok = in_flight && capture_via_http("/race.mp4", &script) == 0;
    char *headers[] = {"Content-Type: video/mp4", "Content-Range: bytes 0-36/100", "Content-Length: 37"};
    st_media_capture_session *duplicate = in_flight
        ? st_media_capture_open(g_database_path, "Demo client", "media", "GET", "/race.mp4", 206,
                                headers, sizeof(headers) / sizeof(headers[0]))
        : NULL;
    int externalized = duplicate != NULL && st_media_capture_externalized(duplicate)
        && !st_media_capture_active(duplicate);
    st_media_capture_free(duplicate);
    int rows_while_held = (int)captures_of("/race.mp4");
    int uploads_while_held = s3_log_lines("initiated.log", NULL) - before;
    pthread_mutex_lock(&g_upstream_lock);
    g_upstream_released = 1;
    pthread_cond_broadcast(&g_upstream_cond);
    pthread_mutex_unlock(&g_upstream_lock);
    pthread_join(first, NULL);
    if (!in_flight || !second_ok || !externalized || rows_while_held != 1 || uploads_while_held != 1
        || capture_of("/race.mp4", 0, &capture) != 0 || strcmp(capture.state, "COMPLETE") != 0
        || capture.captured != 37) {
        fprintf(stderr, "concurrent capture of one media range was not an externalized duplicate\n");
        return 1;
    }
    return 0;
}

/* A keyed capture that no longer qualifies (expired, not yet cleaned) gives up its key. */
static int test_stale_deduplication_key_is_released(void)
{
    capture_snapshot stale;
    capture_snapshot fresh;
    if (capture_range("/stale.mp4", 0, 36, 100, NULL) != 0 || capture_of("/stale.mp4", 0, &stale) != 0
        || !stale.has_dedup || db_update_times(stale.id, stale.captured_at, "2000-01-01T00:00:00Z") != 0
        || capture_range("/stale.mp4", 0, 36, 100, NULL) != 0 || captures_of("/stale.mp4") != 2
        || capture_of("/stale.mp4", 0, &fresh) != 0 || capture_of("/stale.mp4", 1, &stale) != 0
        || !fresh.has_dedup || stale.has_dedup || strcmp(fresh.state, "COMPLETE") != 0) {
        fprintf(stderr, "expired media capture kept its deduplication key\n");
        return 1;
    }
    return 0;
}

/* redactsAuthenticationTokensFromSourceUrlView */
static int test_source_url_view_is_redacted(void)
{
    const char *source = "/Videos/movie/stream.mp4?deviceId=device-a&ApiKey=secret-value&Tag=etag";
    uint8_t body[4] = {'m', 'o', 'o', 'v'};
    upstream_script script = upstream(200, body, sizeof(body));
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, "Content-Length: 4");
    capture_snapshot capture;
    char view[4096];
    if (capture_via_http(source, &script) != 0 || capture_of(source, 0, &capture) != 0
        || capture_view(capture.id, view, sizeof(view)) != 0
        || strstr(view, "\"sourceUrl\":\"/Videos/movie/stream.mp4?deviceId=device-a&ApiKey=***&Tag=etag\"")
            == NULL) {
        fprintf(stderr, "media source URL token was not redacted\n");
        return 1;
    }
    return 0;
}

/* extendsExistingNonLiveCaptureWhenRetentionIsRaised and deletesNonLiveCaptureAfterConfiguredRetention */
static int test_retention_cleanup(void)
{
    const char manifest[] = "#EXTM3U\n#EXTINF:4,\nold-1.ts\n#EXT-X-ENDLIST\n";
    upstream_script script = upstream(200, (const uint8_t *)manifest, strlen(manifest));
    upstream_header(&script, "Content-Type: application/vnd.apple.mpegurl");
    capture_snapshot kept;
    capture_snapshot expired;
    if (capture_via_http("/old/index.m3u8", &script) != 0 || capture_of("/old/index.m3u8", 0, &expired) != 0
        || count_rows("SELECT COUNT(*) FROM specus_http_media_reference WHERE manifest_capture_id=?",
                      NULL, expired.id) != 1
        || capture_of("/live.webm", 0, &kept) != 0) {
        fprintf(stderr, "media retention fixture failed\n");
        return 1;
    }
    time_t now = time(NULL);
    char captured_at[64], expires_at[64], raised_expiry[64], extended_floor[64];
    iso_time(now - 2 * 86400, captured_at);
    iso_time(now - 86400, expires_at);
    iso_time(now - 2 * 86400 + 7 * 86400, raised_expiry);
    iso_time(now + 4 * 86400, extended_floor);
    char old_captured_at[64], old_expires_at[64];
    iso_time(now - 8 * 86400, old_captured_at);
    iso_time(now - 7 * 86400, old_expires_at);
    setenv("SPECUS_MEDIA_CAPTURE_RETENTION_SECONDS", "604800", 1);
    if (db_update_times(kept.id, captured_at, expires_at) != 0
        || db_update_times(expired.id, old_captured_at, old_expires_at) != 0
        || st_media_capture_cleanup_expired(g_database_path) != 0) {
        fprintf(stderr, "media retention cleanup failed\n");
        return 1;
    }
    capture_snapshot after;
    if (count_rows("SELECT COUNT(*) FROM specus_http_media_capture WHERE id=?", NULL, kept.id) != 1
        || capture_of("/live.webm", 0, &after) != 0 || after.id != kept.id
        || strcmp(after.expires_at, raised_expiry) != 0 || strcmp(after.expires_at, extended_floor) <= 0
        || s3_log_lines("deleted.log", kept.object_key) != 0) {
        fprintf(stderr, "raised media retention did not extend the capture\n");
        return 1;
    }
    if (count_rows("SELECT COUNT(*) FROM specus_http_media_capture WHERE id=?", NULL, expired.id) != 0
        || count_rows("SELECT COUNT(*) FROM specus_http_media_reference WHERE manifest_capture_id=?",
                      NULL, expired.id) != 0
        || s3_log_lines("deleted.log", expired.object_key) != 1) {
        fprintf(stderr, "expired media capture cleanup mismatch\n");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------
 * HttpMediaManifestSupportTests
 */

/* classifiesRangeAndOpaqueMediaResponsesOnEnabledMediaRoutes */
static int test_media_response_classification(void)
{
    uint8_t body[100];
    fill_pattern(body, 0, sizeof(body));
    upstream_script progressive = upstream(206, body, 100U);
    upstream_header(&progressive, "Content-Type: video/mp4");
    upstream_header(&progressive, "Content-Range: bytes 0-99/1000");
    upstream_header(&progressive, "Content-Length: 100");
    upstream_script opaque = upstream(200, body, 8U);
    upstream_header(&opaque, "Content-Type: application/octet-stream");
    upstream_script key = upstream(200, body, 16U);
    upstream_header(&key, "Content-Type: application/binary");
    upstream_script page = upstream(200, body, 10U);
    upstream_header(&page, "Content-Type: text/html");
    capture_snapshot capture;
    if (capture_via_http("/stream?id=42", &progressive) != 0 || capture_of("/stream?id=42", 0, &capture) != 0
        || strcmp(capture.kind, "PROGRESSIVE") != 0
        || capture_via_http("/segment?id=42", &opaque) != 0 || capture_of("/segment?id=42", 0, &capture) != 0
        || strcmp(capture.kind, "MEDIA_SEGMENT") != 0
        || capture_via_http("/keys/session.key", &key) != 0
        || capture_of("/keys/session.key", 0, &capture) != 0 || strcmp(capture.kind, "MEDIA_SEGMENT") != 0
        || capture_via_http("/page.html", &page) != 0 || captures_of("/page.html") != 0) {
        fprintf(stderr, "media response classification mismatch\n");
        return 1;
    }
    return 0;
}

/* rejectsInvalidContentRanges: an invalid Content-Range leaves the range to Content-Length. */
static int test_invalid_content_ranges(void)
{
    static const struct {
        const char *path;
        const char *content_range;
        size_t length;
        long long start;
        long long end;
        long long total;
    } cases[] = {
        {"/cr-valid.mp4", "Content-Range: bytes 10-19/20", 10U, 10, 19, 20},
        {"/cr-reversed.mp4", "Content-Range: bytes 20-10/30", 11U, 0, 10, 11},
        {"/cr-past-total.mp4", "Content-Range: bytes 0-30/30", 31U, 0, 30, 31},
        {"/cr-trailing.mp4", "Content-Range: bytes 10-19/20 trailing", 10U, 0, 9, 10},
        {"/cr-upper.mp4", "Content-Range: BYTES 10-19/20", 10U, 10, 19, 20}
    };
    uint8_t body[64];
    fill_pattern(body, 0, sizeof(body));
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char length[64];
        snprintf(length, sizeof(length), "Content-Length: %zu", cases[i].length);
        upstream_script script = upstream(206, body, cases[i].length);
        upstream_header(&script, "Content-Type: video/mp4");
        upstream_header(&script, cases[i].content_range);
        upstream_header(&script, length);
        capture_snapshot capture;
        if (capture_via_http(cases[i].path, &script) != 0 || capture_of(cases[i].path, 0, &capture) != 0
            || capture.start != cases[i].start || capture.end != cases[i].end
            || capture.total != cases[i].total || strcmp(capture.state, "COMPLETE") != 0) {
            fprintf(stderr, "Content-Range validation mismatch for %s\n", cases[i].path);
            return 1;
        }
    }
    return 0;
}

static char g_hls_token[64];

/* parsesAndRewritesHlsReferences, captured live and played through a ticket. */
static int test_live_hls_manifest(void)
{
    uint8_t segment[8];
    fill_pattern(segment, 0, sizeof(segment));
    upstream_script segment_script = upstream(200, segment, sizeof(segment));
    upstream_header(&segment_script, "Content-Type: video/iso.segment");
    upstream_script init_script = upstream(200, segment, sizeof(segment));
    upstream_header(&init_script, "Content-Type: video/mp4");
    const char manifest[] =
        "#EXTM3U\n"
        "#EXT-X-MEDIA-SEQUENCE:12\n"
        "#EXT-X-MAP:URI=\"init.mp4\"\n"
        "#EXT-X-KEY:METHOD=AES-128,URI=\"secret.key\"\n"
        "#EXTINF:4,\n"
        "part-12.m4s\n";
    upstream_script manifest_script = upstream(200, (const uint8_t *)manifest, strlen(manifest));
    upstream_header(&manifest_script, "Content-Type: application/vnd.apple.mpegurl");
    capture_snapshot part;
    capture_snapshot init;
    capture_snapshot playlist;
    if (capture_via_http("/media/live/part-12.m4s", &segment_script) != 0
        || capture_via_http("/media/live/init.mp4", &init_script) != 0
        || capture_via_http("/media/live/index.m3u8", &manifest_script) != 0
        || capture_of("/media/live/part-12.m4s", 0, &part) != 0
        || capture_of("/media/live/init.mp4", 0, &init) != 0
        || capture_of("/media/live/index.m3u8", 0, &playlist) != 0
        || strcmp(part.kind, "MEDIA_SEGMENT") != 0 || !part.has_sequence || part.sequence != 12
        || !init.initialization || strcmp(playlist.kind, "HLS_MANIFEST") != 0) {
        fprintf(stderr, "HLS media capture classification mismatch\n");
        return 1;
    }
    reference_snapshot references[8];
    if (references_of(playlist.id, references, 8) != 3
        || !reference_is(&references[0], "INITIALIZATION", -1, "/media/live/init.mp4")
        || !reference_is(&references[1], "KEY", -1, "/media/live/secret.key")
        || !reference_is(&references[2], "SEGMENT", 12, "/media/live/part-12.m4s")) {
        fprintf(stderr, "HLS manifest references mismatch\n");
        return 1;
    }
    /* Live: the playlist and the segments it names follow the 300 s live window. */
    time_t now = time(NULL);
    char window_low[64], window_high[64];
    iso_time(now + 240, window_low);
    iso_time(now + 360, window_high);
    if (!playlist.live || !part.live || !init.live
        || strcmp(playlist.expires_at, window_low) < 0 || strcmp(playlist.expires_at, window_high) > 0
        || strcmp(part.expires_at, window_low) < 0 || strcmp(part.expires_at, window_high) > 0) {
        fprintf(stderr, "live HLS manifest did not move its segments to the live window\n");
        return 1;
    }
    char view[4096];
    if (capture_view(playlist.id, view, sizeof(view)) != 0 || strstr(view, "\"liveStream\":true") == NULL
        || strstr(view, "\"playable\":true,\"offlineReady\":false") == NULL) {
        fprintf(stderr, "live HLS manifest view mismatch\n");
        return 1;
    }
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/traffic/media-captures/%lld/manifest", playlist.id);
    if (admin_call("GET", path) <= 0 || response_status(g_response) != 200
        || !response_has_header(g_response, "Content-Type: application/vnd.apple.mpegurl; charset=utf-8")
        || strstr(g_response, "/asset?url=%2Fmedia%2Flive%2Fpart-12.m4s") == NULL) {
        fprintf(stderr, "rewritten HLS manifest response mismatch\n");
        return 1;
    }
    if (create_ticket(playlist.id, 0, g_hls_token) != 0
        || strstr(response_body(g_response), "\"totalBytes\":0,\"initialRangeStart\":null,"
                                             "\"initialRangeEnd\":null,\"cachedRanges\":[]") == NULL) {
        fprintf(stderr, "HLS playback ticket mismatch\n");
        return 1;
    }
    char asset[160];
    snprintf(asset, sizeof(asset), "/api/public/media-playback/%s/asset?url=", g_hls_token);
    const char *body = NULL;
    if (public_call(g_hls_token, "/manifest", NULL) <= 0 || response_status(g_response) != 200
        || (body = response_body(g_response)) == NULL
        || strstr(body, "#EXT-X-MAP:URI=\"") == NULL
        || strstr(body, "url=%2Fmedia%2Flive%2Finit.mp4\"") == NULL
        || strstr(body, "url=%2Fmedia%2Flive%2Fsecret.key\"") == NULL
        || strstr(body, "url=%2Fmedia%2Flive%2Fpart-12.m4s") == NULL
        || strstr(body, asset) == NULL) {
        fprintf(stderr, "public rewritten HLS manifest response mismatch\n");
        return 1;
    }
    if (public_call(g_hls_token, "/asset?url=%2Fmedia%2Flive%2Fpart-12.m4s", NULL) <= 0
        || response_status(g_response) != 200 || !body_matches_pattern(g_response, 0, sizeof(segment))) {
        fprintf(stderr, "public HLS segment asset mismatch\n");
        return 1;
    }
    return 0;
}

static int gzip_text(const char *text, uint8_t *out, size_t out_capacity, size_t *out_len)
{
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
        return -1;
    }
    stream.next_in = (Bytef *)(uintptr_t)text;
    stream.avail_in = (uInt)strlen(text);
    stream.next_out = out;
    stream.avail_out = (uInt)out_capacity;
    int rc = deflate(&stream, Z_FINISH);
    *out_len = out_capacity - stream.avail_out;
    deflateEnd(&stream);
    return rc == Z_STREAM_END ? 0 : -1;
}

/* A gzip-encoded VOD playlist with CRLF lines and a "../" reference, as Java's resolver sees it. */
static int test_encoded_vod_hls_manifest(void)
{
    const char manifest[] =
        "#EXTM3U\r\n#EXT-X-TARGETDURATION:4\r\n#EXTINF:4,\r\n../vod/seg-1.ts\r\n#EXT-X-ENDLIST\r\n";
    const char rewritten_head[] = "#EXTM3U\n#EXT-X-TARGETDURATION:4\n#EXTINF:4,\n";
    uint8_t encoded[512];
    size_t encoded_len = 0U;
    if (gzip_text(manifest, encoded, sizeof(encoded), &encoded_len) != 0) {
        return 1;
    }
    char length[64];
    snprintf(length, sizeof(length), "Content-Length: %zu", encoded_len);
    upstream_script script = upstream(200, encoded, encoded_len);
    upstream_header(&script, "Content-Type: application/vnd.apple.mpegurl");
    upstream_header(&script, "Content-Encoding: gzip");
    upstream_header(&script, length);
    capture_snapshot playlist;
    reference_snapshot references[4];
    char token[64];
    if (capture_via_http("/media/live/vod.m3u8", &script) != 0
        || capture_of("/media/live/vod.m3u8", 0, &playlist) != 0 || playlist.live
        || references_of(playlist.id, references, 4) != 1
        || !reference_is(&references[0], "SEGMENT", 0, "/media/vod/seg-1.ts")
        || create_ticket(playlist.id, 0, token) != 0
        || public_call(token, "/manifest", NULL) <= 0 || response_status(g_response) != 200
        || strncmp(response_body(g_response), rewritten_head, strlen(rewritten_head)) != 0
        || strstr(response_body(g_response), "url=%2Fmedia%2Fvod%2Fseg-1.ts\n#EXT-X-ENDLIST\n") == NULL
        || strchr(response_body(g_response), '\r') != NULL
        || response_has_header_named(g_response, "Content-Encoding")) {
        fprintf(stderr, "encoded VOD HLS manifest mismatch\n");
        return 1;
    }
    return 0;
}

/* keepsDashTemplateTokensAvailableForThePlayer */
static int test_dash_template_tokens(void)
{
    const char manifest[] =
        "<MPD type=\"dynamic\">\n"
        "  <Period><AdaptationSet>\n"
        "    <SegmentTemplate initialization=\"init-$RepresentationID$.mp4\"\n"
        "                     media=\"chunk-$Number$.m4s\"/>\n"
        "  </AdaptationSet></Period>\n"
        "</MPD>\n";
    upstream_script script = upstream(200, (const uint8_t *)manifest, strlen(manifest));
    upstream_header(&script, "Content-Type: application/dash+xml");
    capture_snapshot mpd;
    reference_snapshot references[4];
    char token[64];
    if (capture_via_http("/dash/manifest.mpd", &script) != 0 || capture_of("/dash/manifest.mpd", 0, &mpd) != 0
        || strcmp(mpd.kind, "DASH_MANIFEST") != 0 || !mpd.live
        || references_of(mpd.id, references, 4) != 2
        || !reference_is(&references[0], "INITIALIZATION", -1, "/dash/init-$RepresentationID$.mp4")
        || !reference_is(&references[1], "SEGMENT", 0, "/dash/chunk-$Number$.m4s")
        || create_ticket(mpd.id, 0, token) != 0
        || public_call(token, "/manifest", NULL) <= 0 || response_status(g_response) != 200
        || !response_has_header(g_response, "Content-Type: application/dash+xml; charset=utf-8")
        || strstr(response_body(g_response), "$RepresentationID$") == NULL
        || strstr(response_body(g_response), "$Number$") == NULL
        || strstr(response_body(g_response), "media=\"/api/public/media-playback/") == NULL
        || strstr(response_body(g_response), "url=%2Fdash%2Fchunk-$Number$.m4s\"") == NULL) {
        fprintf(stderr, "DASH template tokens were not kept for the player\n");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------
 * HttpMediaPlaybackServiceTests (through the public play endpoint)
 */

/* assemblesOneRangeAcrossMultipleRustFsObjects and reportsAdjacentRangeCapturesAsPlayable */
static int test_range_across_objects(void)
{
    char token[64];
    capture_snapshot newest;
    char view[4096];
    if (capture_range("/plan-adjacent.mp4", 0, 99, 200, "ETag: adjacent") != 0
        || capture_range("/plan-adjacent.mp4", 100, 199, 200, "ETag: adjacent") != 0
        || capture_of("/plan-adjacent.mp4", 0, &newest) != 0
        || create_ticket(newest.id, 0, token) != 0) {
        fprintf(stderr, "adjacent media range fixture failed\n");
        return 1;
    }
    if (public_call(token, "/play", "bytes=50-149") <= 0 || response_status(g_response) != 206
        || !response_has_header(g_response, "Content-Range: bytes 50-149/200")
        || !response_has_header(g_response, "Content-Length: 100")
        || !body_matches_pattern(g_response, 50, 100U)) {
        fprintf(stderr, "sparse media range stitching mismatch\n");
        return 1;
    }
    if (capture_view(newest.id, view, sizeof(view)) != 0
        || strstr(view, "\"playable\":true,\"offlineReady\":true,\"playbackMessage\":null") == NULL
        || public_call(token, "/play", NULL) <= 0 || response_status(g_response) != 200
        || response_has_header_named(g_response, "Content-Range")
        || !response_has_header(g_response, "Content-Length: 200")
        || !body_matches_pattern(g_response, 0, 200U)) {
        fprintf(stderr, "adjacent media ranges were not reported or played as complete\n");
        return 1;
    }
    return 0;
}

/*
 * clipsPlaybackAtFirstUncachedByte, rejectsRangeThatStartsInsideUncachedHole and
 * reportsSparseCaptureAsUnavailableBeforeTicketCreation
 */
static int test_sparse_resource_playback(void)
{
    char token[64];
    capture_snapshot newest;
    char view[4096];
    if (capture_range("/plan-gap.mp4", 0, 49, 200, "ETag: gap") != 0
        || capture_range("/plan-gap.mp4", 100, 199, 200, "ETag: gap") != 0
        || capture_of("/plan-gap.mp4", 0, &newest) != 0
        || create_ticket(newest.id, 0, token) != 0) {
        fprintf(stderr, "sparse media range fixture failed\n");
        return 1;
    }
    if (public_call(token, "/play", "bytes=0-149") <= 0 || response_status(g_response) != 206
        || !response_has_header(g_response, "Content-Range: bytes 0-49/200")
        || !response_has_header(g_response, "Content-Length: 50")
        || !body_matches_pattern(g_response, 0, 50U)) {
        fprintf(stderr, "media playback was not clipped at the first uncached byte\n");
        return 1;
    }
    if (public_call(token, "/play", "bytes=50-99") <= 0 || response_status(g_response) != 416
        || !response_has_header(g_response, "Content-Range: bytes */200")
        || strstr(response_body(g_response), "请求位置尚未缓存，缺少字节 50") == NULL) {
        fprintf(stderr, "range starting inside an uncached hole was not refused\n");
        return 1;
    }
    if (capture_view(newest.id, view, sizeof(view)) != 0
        || strstr(view, "\"playable\":true,\"offlineReady\":false,"
                        "\"playbackMessage\":\"采集数据不完整，缺少字节 50；仅可播放已缓存区间\"") == NULL) {
        fprintf(stderr, "sparse media availability mismatch\n");
        return 1;
    }
    return 0;
}

/*
 * usesTheSelectedCachedBlockForARequestWithoutRange (and the resource test
 * returnsTheSelectedCachedBlockForAnInitialRequestWithoutRange): 206 bytes 100-149/300.
 */
static int test_initial_request_plays_selected_block(void)
{
    char token[64];
    if (capture_range("/plan-initial.mp4", 0, 49, 300, "ETag: initial") != 0
        || capture_range("/plan-initial.mp4", 100, 149, 300, "ETag: initial") != 0
        || ticket_for_newest("/plan-initial.mp4", 0, token) != 0
        || public_call(token, "/play", NULL) <= 0 || response_status(g_response) != 206
        || !response_has_header(g_response, "Content-Range: bytes 100-149/300")
        || !response_has_header(g_response, "Content-Length: 50")
        || !body_matches_pattern(g_response, 100, 50U)) {
        fprintf(stderr, "initial request did not play the selected cached block\n");
        return 1;
    }
    return 0;
}

/* mergesAllCachedBlocksForOfflinePlayback, as the ticket's cache layout */
static int test_offline_cache_layout(void)
{
    char token[64];
    if (capture_range("/plan-offline.mp4", 0, 49, 300, "ETag: offline") != 0
        || capture_range("/plan-offline.mp4", 50, 99, 300, "ETag: offline") != 0
        || capture_range("/plan-offline.mp4", 200, 249, 300, "ETag: offline") != 0
        || ticket_for_newest("/plan-offline.mp4", 0, token) != 0
        || strstr(response_body(g_response),
                  "\"totalBytes\":300,\"initialRangeStart\":200,\"initialRangeEnd\":249,"
                  "\"cachedRanges\":[{\"start\":0,\"end\":99},{\"start\":200,\"end\":249}]") == NULL) {
        fprintf(stderr, "offline media cache layout mismatch\n");
        return 1;
    }
    return 0;
}

/* supportsSuffixRangesAndPreservesContentEncoding */
static int test_suffix_range_keeps_content_encoding(void)
{
    uint8_t body[1000];
    fill_pattern(body, 0, sizeof(body));
    upstream_script script = upstream(200, body, sizeof(body));
    upstream_header(&script, "Content-Type: video/mp4");
    upstream_header(&script, "Content-Length: 1000");
    upstream_header(&script, "Content-Encoding: gzip");
    char token[64];
    if (capture_via_http("/plan-suffix.mp4", &script) != 0
        || ticket_for_newest("/plan-suffix.mp4", 0, token) != 0
        || public_call(token, "/play", "bytes=-128") <= 0 || response_status(g_response) != 206
        || !response_has_header(g_response, "Content-Range: bytes 872-999/1000")
        || !response_has_header(g_response, "Content-Encoding: gzip")
        || !body_matches_pattern(g_response, 872, 128U)) {
        fprintf(stderr, "suffix media range or Content-Encoding mismatch\n");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------
 * HttpMediaPlaybackTicketServiceTests
 */

/* allowsSparseProgressiveCaptureToUseCachedRangePlayback and recordsOptionalBackfillInPlaybackTicket */
static int test_playback_tickets(void)
{
    char token[64];
    char backfill_token[64];
    capture_snapshot capture;
    if (capture_range("/ticket-sparse.mp4", 0, 511, 1024, NULL) != 0
        || capture_of("/ticket-sparse.mp4", 0, &capture) != 0 || create_ticket(capture.id, 0, token) != 0) {
        fprintf(stderr, "sparse media playback ticket mismatch\n");
        return 1;
    }
    char play_url[160];
    snprintf(play_url, sizeof(play_url), "\"playUrl\":\"/api/public/media-playback/%s/play\"", token);
    const char *ticket = response_body(g_response);
    if (strstr(ticket, play_url) == NULL
        || strstr(ticket, "\"totalBytes\":1024,\"initialRangeStart\":0,\"initialRangeEnd\":511,"
                          "\"cachedRanges\":[{\"start\":0,\"end\":511}],\"backfillMissing\":false") == NULL) {
        fprintf(stderr, "sparse media playback ticket mismatch\n");
        return 1;
    }
    if (create_ticket(capture.id, 1, backfill_token) != 0
        || strstr(response_body(g_response), "\"backfillMissing\":true") == NULL) {
        fprintf(stderr, "media playback ticket did not record backfill\n");
        return 1;
    }
    /* What the ticket resolves to decides a miss: 416 without backfill, 307 with it. */
    if (public_call(token, "/play", "bytes=600-700") <= 0 || response_status(g_response) != 416
        || public_call(backfill_token, "/play", "bytes=600-700") <= 0
        || response_status(g_response) != 307
        || !response_has_header(g_response, "Location: /http/Demo%20client/media/ticket-sparse.mp4")) {
        fprintf(stderr, "resolved media playback ticket backfill mismatch\n");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------
 * PublicHttpMediaPlaybackResourceTests
 */

/* returnsRangeMissWithoutFallingBackToOriginalSpecusRoute and redirectsMissingRangeWhenOptionalBackfillIsEnabled */
static int test_public_range_miss(void)
{
    const char *source = "/Videos/movie/stream.mp4?ApiKey=secret";
    char token[64];
    char backfill_token[64];
    if (capture_range(source, 0, 36, 3197229691LL, NULL) != 0
        || ticket_for_newest(source, 0, token) != 0 || ticket_for_newest(source, 1, backfill_token) != 0) {
        fprintf(stderr, "public media range miss fixture failed\n");
        return 1;
    }
    if (public_call(token, "/play", "bytes=16777216-25165823") <= 0 || response_status(g_response) != 416
        || response_has_header_named(g_response, "Location")
        || !response_has_header(g_response, "Content-Range: bytes */3197229691")
        || !response_has_header(g_response, "Cache-Control: private, no-store")
        || !response_has_header(g_response, "Content-Type: text/plain;charset=UTF-8")
        || strstr(response_body(g_response), "缺少字节 16777216") == NULL) {
        fprintf(stderr, "public media range miss fell back or lost its reason\n");
        return 1;
    }
    if (public_call(backfill_token, "/play", "bytes=16777216-25165823") <= 0
        || response_status(g_response) != 307
        || !response_has_header(g_response, "Location: /http/Demo%20client/media/Videos/movie/stream.mp4?ApiKey=secret")
        || !response_has_header(g_response, "Cache-Control: private, no-store")
        || !response_has_header(g_response, "Content-Length: 0")) {
        fprintf(stderr, "public media range miss did not redirect to the origin route\n");
        return 1;
    }
    return 0;
}

/* returnsNotFoundForUncapturedManifestAsset and redirectsUncapturedManifestAssetWhenOptionalBackfillIsEnabled */
static int test_public_uncaptured_asset(void)
{
    capture_snapshot playlist;
    char backfill_token[64];
    if (capture_of("/media/live/index.m3u8", 0, &playlist) != 0
        || create_ticket(playlist.id, 1, backfill_token) != 0) {
        fprintf(stderr, "public media asset fixture failed\n");
        return 1;
    }
    if (public_call(g_hls_token, "/asset?url=%2Fhls%2Fsegment-8.ts", NULL) <= 0
        || response_status(g_response) != 404 || response_has_header_named(g_response, "Location")
        || strstr(response_body(g_response), "尚未缓存") == NULL) {
        fprintf(stderr, "uncaptured manifest asset was not a cache miss\n");
        return 1;
    }
    if (public_call(backfill_token, "/asset?url=%2Fhls%2Fsegment-8.ts", NULL) <= 0
        || response_status(g_response) != 307
        || !response_has_header(g_response, "Location: /http/Demo%20client/media/hls/segment-8.ts")) {
        fprintf(stderr, "uncaptured manifest asset did not redirect with backfill\n");
        return 1;
    }
    /* The asset URL is the caller's: CR/LF in it never reach the Location header. */
    if (public_call(backfill_token, "/asset?url=%2Fx%0D%0ASet-Cookie:%20injected=1", NULL) <= 0
        || response_status(g_response) != 307 || response_has_header_named(g_response, "Set-Cookie")
        || !response_has_header(g_response, "Location: /http/Demo%20client/media/xSet-Cookie:%20injected=1")) {
        fprintf(stderr, "media backfill Location header was not sanitized\n");
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------------ */

static int start_admin_server(st_admin_server *server)
{
    if (st_admin_server_start_with_forwarder(server, 0, "", media_upstream_forwarder, NULL) != 0) {
        return -1;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(server->fd, (struct sockaddr *)&address, &address_len) != 0) {
        return -1;
    }
    g_admin_port = ntohs(address.sin_port);
    return 0;
}

static int login(void)
{
    const char body[] = "{\"username\":\"admin\",\"password\":\"media-admin-password\"}";
    char request[512];
    snprintf(request, sizeof(request),
             "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\n\r\n%s", strlen(body), body);
    if (http_exchange(request, g_response, RESPONSE_CAPACITY) <= 0 || response_status(g_response) != 200) {
        return -1;
    }
    char *token = st_json_get_string(response_body(g_response), "accessToken");
    if (token == NULL) {
        return -1;
    }
    snprintf(g_authorization, sizeof(g_authorization), "Authorization: Bearer %s\r\n", token);
    free(token);
    return 0;
}

int main(void)
{
    unsetenv("SPECUS_MEDIA_CAPTURE_ENABLED");
    if (st_media_capture_validate_current() != 0 || st_media_capture_ready_current()) {
        fprintf(stderr, "disabled media capture initialization mismatch\n");
        return 1;
    }
    const char *endpoint = getenv("SPECUS_MEDIA_CAPTURE_TEST_ENDPOINT");
    g_state_dir = getenv("SPECUS_MEDIA_CAPTURE_TEST_STATE_DIR");
    if (endpoint == NULL || *endpoint == '\0' || g_state_dir == NULL || *g_state_dir == '\0') {
        fprintf(stderr, "SPECUS_MEDIA_CAPTURE_TEST_ENDPOINT and _STATE_DIR are required\n");
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
    snprintf(g_database_path, sizeof(g_database_path), "%s", "/tmp/specus-c-media-XXXXXX");
    int fd = mkstemp(g_database_path);
    if (fd < 0) {
        return 1;
    }
    close(fd);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DATABASE_PATH", g_database_path, 1);
    setenv("SPECUS_AUTH_PASSWORD", "media-admin-password", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "media-capture-test-jwt-secret", 1);
    g_response = (char *)malloc(RESPONSE_CAPACITY);
    st_storage_client client;
    st_storage_http_route route;
    st_admin_server server;
    if (g_response == NULL || st_storage_init(g_database_path, 1) != 0
        || st_storage_get_client_by_name(g_database_path, "Demo client", &client) != 0
        || st_storage_create_http_route_for_client(g_database_path, client.id, "media",
            "https://origin.example/media", 1, 0, 1, 0, 0, 0, "", "", &route) != 0
        || !route.media_capture_enabled || start_admin_server(&server) != 0 || login() != 0) {
        fprintf(stderr, "media capture fixture failed\n");
        free(g_response);
        unlink(g_database_path);
        return 1;
    }
    int (*const tests[])(void) = {
        test_large_response_is_a_multipart_upload,
        test_streaming_response_without_content_length,
        test_interrupted_response_keeps_received_range,
        test_repeated_range_is_not_stored_again,
        test_partial_range_can_be_retried,
        test_different_ranges_are_separate_objects,
        test_concurrent_duplicate_is_externalized,
        test_stale_deduplication_key_is_released,
        test_source_url_view_is_redacted,
        test_media_response_classification,
        test_invalid_content_ranges,
        test_live_hls_manifest,
        test_encoded_vod_hls_manifest,
        test_dash_template_tokens,
        test_range_across_objects,
        test_sparse_resource_playback,
        test_initial_request_plays_selected_block,
        test_offline_cache_layout,
        test_suffix_range_keeps_content_encoding,
        test_playback_tickets,
        test_public_range_miss,
        test_public_uncaptured_asset,
        test_retention_cleanup
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]) && !failed; ++i) {
        failed = tests[i]();
    }
    if (server.fd >= 0) {
        (void)shutdown(server.fd, SHUT_RDWR);
        close(server.fd);
    }
    free(g_response);
    unlink(g_database_path);
    if (failed) {
        return 1;
    }
    puts("media capture tests passed");
    return 0;
}
