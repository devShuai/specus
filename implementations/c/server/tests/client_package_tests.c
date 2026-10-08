/*
 * The client catalogue and hosted packages, checked against the Java tests of the same behaviour:
 * ClientDownloadLinkResourceTests, ClientDownloadLinkServiceTests, ClientPackageLifecycleTests,
 * ClientPackageRateLimiterTests and ClientPackageStorageTests.
 *
 * Everything goes through the real request handling: JSON and multipart administration and the
 * public catalogue and version check through st_admin_build_response*, package bytes through an
 * in-process admin listener on loopback, so Range, If-None-Match and HEAD arrive as real request
 * headers. The GitHub Release fallback is fed by a fake fetcher instead of the network.
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "client_package.h"
#include "crypto.h"
#include "github_release.h"
#include "json.h"
#include "storage.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h>
#include <poll.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition, ...)                                    \
    do {                                                         \
        if (!(condition)) {                                      \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                        \
            fprintf(stderr, "\n");                               \
            return 1;                                            \
        }                                                        \
    } while (0)

#define SHA_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

static char scratch_dir[256];
static char db_path[320];
static char data_dir[320];
static char packages_dir[400];
static int listener_port = 0;
static char response[262144];

/* ------------------------------------------------------------------------------------------- */
/* Fixture                                                                                       */

/* A new database and package directory per scenario: package ids restart at 1 in each. */
static int fresh_database(const char *name)
{
    snprintf(db_path, sizeof(db_path), "%s/%s.db", scratch_dir, name);
    snprintf(data_dir, sizeof(data_dir), "%s/%s-data", scratch_dir, name);
    snprintf(packages_dir, sizeof(packages_dir), "%s/packages", data_dir);
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_CLIENT_PACKAGE_DATA_DIRECTORY", data_dir, 1);
    st_client_package_rate_limit_reset();
    st_github_release_cache_reset();
    return st_storage_init(db_path, 0);
}

static int sql_exec(const char *statement)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK
        && sqlite3_exec(db, statement, NULL, NULL, &error) == SQLITE_OK ? 0 : -1;
    if (rc != 0) fprintf(stderr, "sql failed (%s): %s\n", statement, error == NULL ? "sqlite error" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

static long long sql_int(const char *query)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long value = -1000;
    if (sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        value = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return value;
}

/* Entries of data/packages whose name starts with prefix ("" for all). */
static int package_entries(const char *prefix)
{
    DIR *dir = opendir(packages_dir);
    if (dir == NULL) return errno == ENOENT ? 0 : -1;
    int count = 0;
    for (struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (strncmp(entry->d_name, prefix, strlen(prefix)) == 0) ++count;
    }
    closedir(dir);
    return count;
}

static int read_package_file(long long id, char *out, size_t out_len)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%lld", packages_dir, id);
    FILE *file = fopen(path, "rb");
    if (file == NULL) return -1;
    size_t read_len = fread(out, 1U, out_len - 1U, file);
    fclose(file);
    out[read_len] = '\0';
    return (int)read_len;
}

static int contains(const char *haystack, const char *needle)
{
    return haystack != NULL && strstr(haystack, needle) != NULL;
}

/* ------------------------------------------------------------------------------------------- */
/* Request handling without a socket                                                             */

static int status_of(int len)
{
    return len > 9 && strncmp(response, "HTTP/1.1 ", 9U) == 0 ? atoi(response + 9) : -1;
}

static const char *response_body(void)
{
    const char *body = strstr(response, "\r\n\r\n");
    return body == NULL ? "" : body + 4;
}

/* An administrator's request (the internal admin context). */
static int admin_call(const char *method, const char *path, const char *body)
{
    return status_of(st_admin_build_response_with_body(method, path, body, response, sizeof(response)));
}

/* An anonymous public request from the given source address. */
static int public_call(const char *path, const char *remote)
{
    return status_of(st_admin_build_response_with_remote("GET", path, NULL, remote, response, sizeof(response)));
}

static long long create_link(const char *json)
{
    long long id = -1;
    if (admin_call("POST", "/api/admin/client-downloads", json) != 201
        || st_json_get_i64(response_body(), "id", &id) != 0) {
        fprintf(stderr, "client download create failed: %s\n", response);
        return -1;
    }
    return id;
}

typedef struct {
    const char *name;
    const char *value;
} form_field;

/* POST /api/admin/client-packages; *id_out receives the new id on 201. Returns the status. */
static int upload_package(const form_field *fields, const void *file, size_t file_len, long long *id_out)
{
    static const char boundary[] = "specus-package-boundary";
    size_t capacity = file_len + 8192U;
    char *body = malloc(capacity);
    if (body == NULL) return -1;
    size_t used = 0U;
    for (const form_field *field = fields; field != NULL && field->name != NULL; ++field) {
        used += (size_t)snprintf(body + used, capacity - used,
                                 "--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n",
                                 boundary, field->name, field->value);
    }
    used += (size_t)snprintf(body + used, capacity - used,
                             "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"untrusted.bin\"\r\n"
                             "Content-Type: application/octet-stream\r\n\r\n", boundary);
    memcpy(body + used, file, file_len);
    used += file_len;
    used += (size_t)snprintf(body + used, capacity - used, "\r\n--%s--\r\n", boundary);
    char content_type[96];
    snprintf(content_type, sizeof(content_type), "multipart/form-data; boundary=%s", boundary);
    int status = status_of(st_admin_build_response_with_content("POST", "/api/admin/client-packages", NULL,
                                                                content_type, (const uint8_t *)body, used,
                                                                response, sizeof(response)));
    free(body);
    if (status == 201 && id_out != NULL && st_json_get_i64(response_body(), "id", id_out) != 0) return -1;
    return status;
}

/* ------------------------------------------------------------------------------------------- */
/* Real HTTP over loopback                                                                       */

typedef struct {
    int status;
    char head[8192];
    char body[65536];
    size_t body_len;
} http_reply;

static int http_exchange(const char *request, http_reply *reply)
{
    memset(reply, 0, sizeof(*reply));
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)listener_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    size_t request_len = strlen(request);
    if (send(fd, request, request_len, 0) != (ssize_t)request_len) {
        close(fd);
        return -1;
    }
    static char raw[sizeof(reply->head) + sizeof(reply->body)];
    size_t used = 0U;
    for (;;) {
        struct pollfd ready = {fd, POLLIN, 0};
        if (poll(&ready, 1, 5000) <= 0) break;
        ssize_t received = recv(fd, raw + used, sizeof(raw) - 1U - used, 0);
        if (received <= 0) break;
        used += (size_t)received;
        if (used == sizeof(raw) - 1U) break;
    }
    close(fd);
    raw[used] = '\0';
    char *separator = strstr(raw, "\r\n\r\n");
    if (separator == NULL || strncmp(raw, "HTTP/1.1 ", 9U) != 0) return -1;
    size_t head_len = (size_t)(separator - raw) + 2U;
    if (head_len >= sizeof(reply->head)) return -1;
    memcpy(reply->head, raw, head_len);
    reply->head[head_len] = '\0';
    reply->body_len = used - head_len - 2U;
    memcpy(reply->body, separator + 4, reply->body_len);
    reply->body[reply->body_len] = '\0';
    reply->status = atoi(raw + 9);
    return 0;
}

/* The value of the first header with this name, or "" when there is none. */
static const char *header_value(const http_reply *reply, const char *name, char *out, size_t out_len)
{
    out[0] = '\0';
    size_t name_len = strlen(name);
    for (const char *line = strstr(reply->head, "\r\n"); line != NULL && line[2] != '\0';
         line = strstr(line + 2, "\r\n")) {
        const char *start = line + 2;
        if (strncasecmp(start, name, name_len) == 0 && start[name_len] == ':') {
            const char *value = start + name_len + 1;
            while (*value == ' ') ++value;
            const char *end = strstr(value, "\r\n");
            size_t len = end == NULL ? strlen(value) : (size_t)(end - value);
            if (len >= out_len) len = out_len - 1U;
            memcpy(out, value, len);
            out[len] = '\0';
            return out;
        }
    }
    return out;
}

static int download(const char *method, long long id, const char *extra_headers, http_reply *reply)
{
    char request[1024];
    snprintf(request, sizeof(request),
             "%s /api/public/client-packages/%lld/download HTTP/1.1\r\nHost: 127.0.0.1\r\n%sConnection: close\r\n\r\n",
             method, id, extra_headers == NULL ? "" : extra_headers);
    return http_exchange(request, reply);
}

/* ------------------------------------------------------------------------------------------- */
/* GitHub Release fallback without the network                                                   */

static int fake_release_calls = 0;
static const char *fake_release_body = NULL;

static int fake_release_fetch(const char *endpoint,
                              const st_http_client_options *options,
                              long *status_code_out,
                              char **body_out)
{
    (void)endpoint;
    (void)options;
    ++fake_release_calls;
    *status_code_out = 200L;
    *body_out = strdup(fake_release_body == NULL ? "{}" : fake_release_body);
    return *body_out == NULL ? -1 : 0;
}

static const char release_v123[] =
    "{\"tag_name\":\"v1.2.3\",\"published_at\":\"2026-08-22T00:00:00Z\",\"assets\":["
    "{\"id\":73,\"name\":\"specus-client-java-v1.2.3.jar\",\"size\":1024,"
    "\"digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
    "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-java-v1.2.3.jar\"},"
    "{\"id\":74,\"name\":\"specus-client-go-v1.2.3-windows-x64.zip\",\"size\":1024,"
    "\"digest\":\"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\","
    "\"browser_download_url\":\"https://github.com/devShuai/specus/releases/download/v1.2.3/specus-client-go-v1.2.3-windows-x64.zip\"}]}";

static void use_release_fallback(const char *release_body)
{
    if (release_body == NULL) {
        setenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED", "false", 1);
    } else {
        setenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED", "true", 1);
    }
    fake_release_body = release_body;
    fake_release_calls = 0;
    st_github_release_cache_reset();
}

/* ------------------------------------------------------------------------------------------- */
/* ClientDownloadLinkResourceTests                                                               */

/*
 * packageGetAndHeadUseNoStoreAndApkAttachmentName, and the rest of what Spring does for the
 * ResponseEntity<Resource> the Java resource returns: byte ranges, 416, conditional GET.
 */
static int test_package_download_contract(void)
{
    CHECK(fresh_database("download") == 0, "database setup failed");
    use_release_fallback(NULL);
    static const char bytes[] = "android-apk";
    const form_field fields[] = {
        {"implementation", "android"}, {"platform", "android"}, {"arch", "any"}, {"version", "3.0.0"},
        {"displayName", "Specus Android"}, {NULL, NULL}
    };
    long long id = 0;
    CHECK(upload_package(fields, bytes, 11U, &id) == 201, "package upload failed: %s", response);
    uint8_t digest[ST_SHA256_LEN];
    char sha[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)bytes, 11U, digest);
    st_hex_encode(digest, sizeof(digest), sha);
    char etag[96];
    snprintf(etag, sizeof(etag), "\"sha256-%s\"", sha);

    http_reply reply;
    char value[512];
    CHECK(download("GET", id, NULL, &reply) == 0 && reply.status == 200, "GET status %d", reply.status);
    CHECK(strcmp(header_value(&reply, "Cache-Control", value, sizeof(value)), "no-store") == 0, "Cache-Control: %s", value);
    CHECK(strcmp(header_value(&reply, "Content-Disposition", value, sizeof(value)),
                 "attachment; filename=\"Specus Android.apk\"; filename*=UTF-8''Specus%20Android.apk") == 0,
          "Content-Disposition: %s", value);
    CHECK(strcmp(header_value(&reply, "ETag", value, sizeof(value)), etag) == 0, "ETag: %s", value);
    CHECK(strcmp(header_value(&reply, "X-Content-Type-Options", value, sizeof(value)), "nosniff") == 0, "nosniff");
    CHECK(strcmp(header_value(&reply, "X-Checksum-SHA256", value, sizeof(value)), sha) == 0, "checksum header");
    CHECK(strcmp(header_value(&reply, "Accept-Ranges", value, sizeof(value)), "bytes") == 0, "Accept-Ranges");
    CHECK(strcmp(header_value(&reply, "Content-Type", value, sizeof(value)), "application/octet-stream") == 0,
          "Content-Type: %s", value);
    CHECK(strcmp(header_value(&reply, "Content-Length", value, sizeof(value)), "11") == 0, "Content-Length");
    CHECK(reply.body_len == 11U && memcmp(reply.body, bytes, 11U) == 0, "GET body: %s", reply.body);

    CHECK(download("HEAD", id, NULL, &reply) == 0 && reply.status == 200, "HEAD status %d", reply.status);
    CHECK(strcmp(header_value(&reply, "Cache-Control", value, sizeof(value)), "no-store") == 0, "HEAD Cache-Control");
    CHECK(contains(header_value(&reply, "Content-Disposition", value, sizeof(value)), "Specus Android.apk"),
          "HEAD Content-Disposition");
    CHECK(strcmp(header_value(&reply, "ETag", value, sizeof(value)), etag) == 0, "HEAD ETag");
    CHECK(strcmp(header_value(&reply, "Content-Length", value, sizeof(value)), "11") == 0, "HEAD Content-Length");
    CHECK(reply.body_len == 0U, "HEAD sent a body");

    static const struct {
        const char *range;
        const char *content_range;
        const char *body;
    } ranges[] = {
        {"bytes=0-2", "bytes 0-2/11", "and"},
        {"bytes=-3", "bytes 8-10/11", "apk"},
        {"bytes=8-", "bytes 8-10/11", "apk"},
        {"bytes=5-100", "bytes 5-10/11", "id-apk"},
        {"bytes= 1-1 ,", "bytes 1-1/11", "n"},
        {"bytes=-100", "bytes 0-10/11", "android-apk"},
    };
    for (size_t i = 0; i < sizeof(ranges) / sizeof(ranges[0]); ++i) {
        char headers[128];
        snprintf(headers, sizeof(headers), "Range: %s\r\n", ranges[i].range);
        CHECK(download("GET", id, headers, &reply) == 0 && reply.status == 206, "%s: status %d", ranges[i].range,
              reply.status);
        CHECK(strcmp(header_value(&reply, "Content-Range", value, sizeof(value)), ranges[i].content_range) == 0,
              "%s: Content-Range %s", ranges[i].range, value);
        CHECK(strcmp(header_value(&reply, "Cache-Control", value, sizeof(value)), "no-store") == 0,
              "%s: Cache-Control", ranges[i].range);
        CHECK(reply.body_len == strlen(ranges[i].body) && memcmp(reply.body, ranges[i].body, reply.body_len) == 0,
              "%s: body %s", ranges[i].range, reply.body);
        CHECK(atoi(header_value(&reply, "Content-Length", value, sizeof(value))) == (int)reply.body_len,
              "%s: Content-Length", ranges[i].range);
    }
    CHECK(download("HEAD", id, "Range: bytes=0-2\r\n", &reply) == 0 && reply.status == 206
              && strcmp(header_value(&reply, "Content-Length", value, sizeof(value)), "3") == 0
              && reply.body_len == 0U,
          "HEAD with a range");

    /* Several ranges: multipart/byteranges, one part per range. */
    CHECK(download("GET", id, "Range: bytes=0-1,4-5\r\n", &reply) == 0 && reply.status == 206, "multi-range status");
    header_value(&reply, "Content-Type", value, sizeof(value));
    const char *boundary = strstr(value, "multipart/byteranges; boundary=");
    CHECK(boundary == value, "multi-range Content-Type: %s", value);
    boundary += strlen("multipart/byteranges; boundary=");
    char expected[2048];
    snprintf(expected, sizeof(expected),
             "\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes 0-1/11\r\n\r\nan"
             "\r\n--%s\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes 4-5/11\r\n\r\noi"
             "\r\n--%s--",
             boundary, boundary, boundary);
    CHECK(reply.body_len == strlen(expected) && strcmp(reply.body, expected) == 0, "multi-range body: %s", reply.body);
    char length_value[32];
    CHECK(atoi(header_value(&reply, "Content-Length", length_value, sizeof(length_value))) == (int)reply.body_len,
          "multi-range Content-Length");

    static const char *const unsatisfiable[] = {
        "bytes=11-", "bytes=5-2", "items=0-1", "bytes=0-5,6-10", "bytes=-0", "bytes=a-b", "bytes=0-1,x"
    };
    for (size_t i = 0; i < sizeof(unsatisfiable) / sizeof(unsatisfiable[0]); ++i) {
        char headers[128];
        snprintf(headers, sizeof(headers), "Range: %s\r\n", unsatisfiable[i]);
        CHECK(download("GET", id, headers, &reply) == 0 && reply.status == 416, "%s: status %d", unsatisfiable[i],
              reply.status);
        CHECK(strcmp(header_value(&reply, "Content-Range", value, sizeof(value)), "bytes */11") == 0,
              "%s: Content-Range %s", unsatisfiable[i], value);
    }

    /* A conditional GET that names the ETag, strong or weak, is answered 304 with the ETag. */
    char conditional[160];
    snprintf(conditional, sizeof(conditional), "If-None-Match: \"other\", %s\r\n", etag);
    CHECK(download("GET", id, conditional, &reply) == 0 && reply.status == 304 && reply.body_len == 0U
              && strcmp(header_value(&reply, "ETag", value, sizeof(value)), etag) == 0,
          "If-None-Match: status %d", reply.status);
    snprintf(conditional, sizeof(conditional), "If-None-Match: W/%s\r\n", etag);
    CHECK(download("HEAD", id, conditional, &reply) == 0 && reply.status == 304, "weak If-None-Match");
    CHECK(download("GET", id, "If-None-Match: \"sha256-other\"\r\n", &reply) == 0 && reply.status == 200,
          "a different ETag was not 200");
    CHECK(download("GET", id, "If-None-Match: *\r\n", &reply) == 0 && reply.status == 200,
          "a wildcard on GET was not 200");

    /* No such package: an unknown, zero or negative id, and a disabled row. */
    CHECK(download("GET", id + 1000, NULL, &reply) == 0 && reply.status == 404, "unknown id status %d", reply.status);
    CHECK(download("GET", 0, NULL, &reply) == 0 && reply.status == 404, "id 0 status %d", reply.status);
    CHECK(download("GET", -1, NULL, &reply) == 0 && reply.status == 404, "id -1 status %d", reply.status);

    /*
     * androidHostedDownloadGetsSafeApkFileNameWithoutDuplicatingExtension: the name follows the
     * row's current display name.
     */
    static const struct {
        const char *display_name;
        const char *disposition;
    } names[] = {
        {"Specus Android / universal",
         "attachment; filename=\"Specus Android _ universal.apk\"; filename*=UTF-8''Specus%20Android%20_%20universal.apk"},
        {"Specus-Android.APK", "attachment; filename=\"Specus-Android.APK\"; filename*=UTF-8''Specus-Android.APK"},
        {"\xe5\xae\x89\xe5\x8d\x93 Specus",
         "attachment; filename=\"__ Specus.apk\"; filename*=UTF-8''%E5%AE%89%E5%8D%93%20Specus.apk"},
    };
    char path[96];
    snprintf(path, sizeof(path), "/api/admin/client-downloads/%lld", id);
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        char body[256];
        snprintf(body, sizeof(body), "{\"displayName\":\"%s\"}", names[i].display_name);
        CHECK(admin_call("PUT", path, body) == 200, "rename: %s", response);
        CHECK(download("GET", id, NULL, &reply) == 0 && reply.status == 200
                  && strcmp(header_value(&reply, "Content-Disposition", value, sizeof(value)),
                            names[i].disposition) == 0,
              "Content-Disposition for %s: %s", names[i].display_name, value);
    }

    CHECK(admin_call("PUT", path, "{\"enabled\":false}") == 200, "disable: %s", response);
    CHECK(download("GET", id, NULL, &reply) == 0 && reply.status == 404, "disabled package status %d", reply.status);
    CHECK(admin_call("PUT", path, "{\"enabled\":true}") == 200, "enable: %s", response);

    /* Bytes that no longer match the catalogue: Java's IllegalStateException, 409. */
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "%s/%lld", packages_dir, id);
    FILE *file = fopen(file_path, "ab");
    CHECK(file != NULL && fputs("!", file) >= 0 && fclose(file) == 0, "cannot grow the package file");
    CHECK(download("GET", id, NULL, &reply) == 0 && reply.status == 409
              && contains(reply.body, "client package size no longer matches its catalogue metadata"),
          "a resized package answered %d", reply.status);
    CHECK(admin_call("DELETE", path, NULL) == 204, "delete: %s", response);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* ClientPackageRateLimiterTests                                                                 */

/*
 * limitsEachSourceIndependentlyAndFailsClosedForUnknownSource, on the public catalogue (the
 * budget is shared with the version check and the package bytes).
 */
static int test_rate_limits(void)
{
    CHECK(fresh_database("rate") == 0, "database setup failed");
    use_release_fallback(NULL);
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", "2", 1);
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_WINDOW_SECONDS", "60", 1);
    st_client_package_rate_limit_reset();
    const char *list = "/api/public/client-downloads";
    CHECK(public_call(list, "192.0.2.1") == 200, "first request");
    CHECK(public_call(list, "192.0.2.1") == 200, "second request");
    CHECK(public_call(list, "192.0.2.2") == 200, "another source was limited");
    CHECK(public_call(list, " 192.0.2.1 ") == 429, "third request of the first source (trimmed) was allowed");
    const char *retry = strstr(response, "Retry-After: ");
    CHECK(retry != NULL && atoi(retry + 13) >= 1 && atoi(retry + 13) <= 60, "Retry-After: %s", response);
    CHECK(public_call("/api/public/client-version-check?implementation=go&platform=linux&arch=x64&current=1.0.0",
                      "192.0.2.2") == 200,
          "the second source's budget was not its own");
    /* No address, an empty one and the literal "unknown" share one budget, and it runs out. */
    CHECK(public_call(list, NULL) == 200, "unknown source, first request");
    CHECK(public_call(list, "") == 200, "unknown source, second request");
    CHECK(public_call(list, "unknown") == 429, "an unknown source was not limited");
    CHECK(public_call(list, "   ") == 429, "a blank source was not the unknown source");

    /* The package bytes take from the same budget, here the listener's peer address. */
    http_reply reply;
    CHECK(download("GET", 1, NULL, &reply) == 0 && reply.status == 404, "download 1 status %d", reply.status);
    CHECK(download("GET", 1, NULL, &reply) == 0 && reply.status == 404, "download 2 status %d", reply.status);
    char value[32];
    CHECK(download("GET", 1, NULL, &reply) == 0 && reply.status == 429
              && atoi(header_value(&reply, "Retry-After", value, sizeof(value))) >= 1,
          "download 3 status %d", reply.status);
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", "100000", 1);
    unsetenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_WINDOW_SECONDS");
    st_client_package_rate_limit_reset();
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* ClientPackageStorageTests                                                                     */

static form_field go_linux_fields[] = {
    {"implementation", "go"}, {"platform", "linux"}, {"arch", "x64"}, {"version", "2.0.0"},
    {"displayName", "specus go"}, {NULL, NULL}
};

/* Each upload its own version: Java keeps at most one catalogue entry per target and version. */
static const form_field *go_linux_version(const char *version)
{
    go_linux_fields[3].value = version;
    return go_linux_fields;
}

static int test_package_storage(void)
{
    CHECK(fresh_database("storage") == 0, "database setup failed");
    use_release_fallback(NULL);
    /* stagesHashesAndAtomicallyPublishesInsidePackagesDirectory */
    long long id = 0;
    CHECK(upload_package(go_linux_version("2.0.0"), "specus-package", 14U, &id) == 201, "upload: %s", response);
    CHECK(contains(response_body(), "\"sha256\":\"5e471da0443561615e4cb8a9221f54dcf7f3ec80c4477e9612e6aa3a46fa9492\"")
              && contains(response_body(), "\"fileSize\":14"),
          "hash and size: %s", response_body());
    char stored[64];
    CHECK(read_package_file(id, stored, sizeof(stored)) == 14 && strcmp(stored, "specus-package") == 0,
          "the package is not at data/packages/<id>");
    CHECK(package_entries(".upload-") == 0, "a staged upload was left behind");

    /* enforcesActualStreamSizeAndRejectsEmptyOrInvalidIds: the limit applies to the bytes received. */
    setenv("SPECUS_CLIENT_PACKAGE_MAX_BYTES", "4", 1);
    long long before = sql_int("SELECT COUNT(*) FROM client_download_link");
    CHECK(upload_package(go_linux_version("2.0.1"), "12345", 5U, NULL) == 413
              && contains(response_body(), "file exceeds max package size of 4 bytes"),
          "a 5-byte package under a 4-byte limit: %s", response);
    CHECK(upload_package(go_linux_version("2.0.1"), "", 0U, NULL) == 400 && contains(response_body(), "file cannot be empty"),
          "an empty package: %s", response);
    CHECK(sql_int("SELECT COUNT(*) FROM client_download_link") == before && package_entries(".upload-") == 0,
          "a refused upload left a row or a staged file");
    long long small_id = 0;
    CHECK(upload_package(go_linux_version("2.0.1"), "1234", 4U, &small_id) == 201, "a package at the limit: %s", response);
    unsetenv("SPECUS_CLIENT_PACKAGE_MAX_BYTES");

    /* A file already at the destination is never overwritten: 409, nothing staged or catalogued. */
    long long next_id = sql_int("SELECT seq FROM sqlite_sequence WHERE name = 'client_download_link'") + 1;
    char occupied[512];
    snprintf(occupied, sizeof(occupied), "%s/%lld", packages_dir, next_id);
    FILE *file = fopen(occupied, "wb");
    CHECK(file != NULL && fputs("someone else's bytes", file) >= 0 && fclose(file) == 0, "cannot occupy %s", occupied);
    char message[96];
    snprintf(message, sizeof(message), "package file already exists: %lld", next_id);
    CHECK(upload_package(go_linux_version("2.0.2"), "new-bytes", 9U, NULL) == 409 && contains(response_body(), message),
          "an occupied destination: %s", response);
    char kept[64];
    char row_query[128];
    snprintf(row_query, sizeof(row_query), "SELECT COUNT(*) FROM client_download_link WHERE id = %lld", next_id);
    CHECK(read_package_file(next_id, kept, sizeof(kept)) > 0 && strcmp(kept, "someone else's bytes") == 0
              && sql_int(row_query) == 0 && package_entries(".upload-") == 0,
          "the occupied destination was touched or the upload left something behind");
    unlink(occupied);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* ClientPackageLifecycleTests                                                                   */

static int test_package_lifecycle(void)
{
    CHECK(fresh_database("lifecycle") == 0, "database setup failed");
    use_release_fallback(NULL);
    /* uploadPublishesAuthoritativeMetadataAndDeleteRemovesBytesAfterCommit */
    static const char bytes[] = "android-apk-content";
    const form_field fields[] = {
        {"implementation", "android"}, {"platform", "android"}, {"arch", "any"}, {"version", "2.0.0"},
        {"displayName", "specus Android 2.0.0.apk"}, {"description", "release"},
        {"changelogUrl", "https://example.test/changelog"}, {"minSupportedVersion", "1.5.0"},
        {"displayOrder", "1"}, {"enabled", "true"}, {"isLatest", "true"}, {NULL, NULL}
    };
    long long id = 0;
    CHECK(upload_package(fields, bytes, strlen(bytes), &id) == 201, "upload: %s", response);
    char expected[160];
    snprintf(expected, sizeof(expected), "\"downloadUrl\":\"/api/public/client-packages/%lld/download\"", id);
    char package_id[64];
    snprintf(package_id, sizeof(package_id), "\"packageId\":%lld", id);
    char *sha = st_json_get_string(response_body(), "sha256");
    int sha_ok = sha != NULL && strlen(sha) == 64U;
    free(sha);
    CHECK(contains(response_body(), "\"hosted\":true") && contains(response_body(), package_id)
              && contains(response_body(), expected) && sha_ok
              && contains(response_body(), "\"fileSize\":19") && contains(response_body(), "\"isLatest\":true")
              && contains(response_body(), "\"minSupportedVersion\":\"1.5.0\""),
          "uploaded metadata: %s", response_body());
    char stored[64];
    CHECK(read_package_file(id, stored, sizeof(stored)) == 19 && strcmp(stored, bytes) == 0, "stored bytes");

    /* The catalogue delete fails (the transaction rolls back): the bytes are back where they were. */
    char path[96];
    snprintf(path, sizeof(path), "/api/admin/client-downloads/%lld", id);
    CHECK(sql_exec("CREATE TRIGGER refuse_delete BEFORE DELETE ON client_download_link "
                   "BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;") == 0, "trigger setup");
    CHECK(admin_call("DELETE", path, NULL) == 500, "a failed delete answered: %s", response);
    char row_query[128];
    snprintf(row_query, sizeof(row_query), "SELECT COUNT(*) FROM client_download_link WHERE id = %lld", id);
    CHECK(read_package_file(id, stored, sizeof(stored)) == 19 && strcmp(stored, bytes) == 0
              && sql_int(row_query) == 1 && package_entries(".delete-") == 0,
          "a rolled back delete lost the bytes or the row");
    http_reply reply;
    CHECK(download("GET", id, NULL, &reply) == 0 && reply.status == 200 && strcmp(reply.body, bytes) == 0,
          "the package is not downloadable after the rollback");
    CHECK(sql_exec("DROP TRIGGER refuse_delete") == 0, "trigger drop");
    CHECK(admin_call("DELETE", path, NULL) == 204, "delete: %s", response);
    CHECK(read_package_file(id, stored, sizeof(stored)) < 0 && sql_int(row_query) == 0
              && package_entries("") == 0,
          "a committed delete left the bytes, the row or a quarantine file");
    CHECK(download("GET", id, NULL, &reply) == 0 && reply.status == 404, "a deleted package answered %d", reply.status);

    /* failedCatalogueInsertRemovesStagedUpload */
    CHECK(sql_exec("CREATE TRIGGER refuse_insert BEFORE INSERT ON client_download_link "
                   "BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;") == 0, "trigger setup");
    CHECK(upload_package(go_linux_version("2.0.0"), "uncommitted-package", 19U, NULL) == 409, "a failed insert: %s", response);
    CHECK(package_entries("") == 0, "a failed catalogue insert left %d file(s)", package_entries(""));
    CHECK(sql_exec("DROP TRIGGER refuse_insert") == 0, "trigger drop");

    /* The same when the second write, which publishes the row, fails after the bytes moved. */
    CHECK(sql_exec("CREATE TRIGGER refuse_publish BEFORE UPDATE ON client_download_link "
                   "WHEN NEW.download_url <> 'pending' BEGIN SELECT RAISE(ABORT, 'database unavailable'); END;") == 0,
          "trigger setup");
    CHECK(upload_package(go_linux_version("2.0.0"), "unpublished-package", 19U, NULL) == 409, "a failed publish: %s", response);
    CHECK(package_entries("") == 0 && sql_int("SELECT COUNT(*) FROM client_download_link") == 0,
          "a failed publish left a file or a row");
    CHECK(sql_exec("DROP TRIGGER refuse_publish") == 0, "trigger drop");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* ClientDownloadLinkServiceTests                                                                */

static int test_public_list_legacy_targets(void)
{
    /* publicListReturnsOnlyLatestForVersionedTargetAndPreservesPureLegacyTarget */
    CHECK(fresh_database("legacy-targets") == 0, "database setup failed");
    use_release_fallback(NULL);
    long long old_id = create_link("{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\","
        "\"displayName\":\"old\",\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v1.0.0/a\","
        "\"version\":\"1.0.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100,\"displayOrder\":1}");
    long long latest_id = create_link("{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\","
        "\"displayName\":\"latest\",\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v1.1.0/b\","
        "\"version\":\"1.1.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100,\"isLatest\":true,\"displayOrder\":5}");
    long long hidden_id = create_link("{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\","
        "\"displayName\":\"hidden legacy\",\"downloadUrl\":\"https://example.test/legacy-go\",\"displayOrder\":3}");
    long long visible_id = create_link("{\"implementation\":\"java\",\"platform\":\"any\",\"arch\":\"any\","
        "\"displayName\":\"visible legacy\",\"downloadUrl\":\"https://example.test/legacy-java\",\"displayOrder\":0}");
    CHECK(old_id > 0 && latest_id > 0 && hidden_id > 0 && visible_id > 0, "fixture rows");
    CHECK(public_call("/api/public/client-downloads", "198.51.100.1") == 200, "public list: %s", response);
    const char *body = response_body();
    const char *latest_pos = strstr(body, "\"displayName\":\"latest\"");
    const char *visible_pos = strstr(body, "\"displayName\":\"visible legacy\"");
    /* Implementation order (go before java) since the release fallback cannot add anything. */
    CHECK(latest_pos != NULL && visible_pos != NULL && latest_pos < visible_pos
              && !contains(body, "\"displayName\":\"old\"") && !contains(body, "\"displayName\":\"hidden legacy\""),
          "public list: %s", body);

    /* publicListDoesNotResurrectLegacyLinkWhenVersionedTargetIsDisabled */
    CHECK(create_link("{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\","
                      "\"displayName\":\"linux legacy\",\"downloadUrl\":\"https://example.test/legacy-linux\"}") > 0
              && create_link("{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\","
                             "\"displayName\":\"linux disabled\",\"downloadUrl\":\"https://example.test/linux-2\","
                             "\"version\":\"2.0.0\",\"enabled\":false}") > 0,
          "fixture rows");
    CHECK(public_call("/api/public/client-downloads", "198.51.100.1") == 200
              && !contains(response_body(), "linux legacy") && !contains(response_body(), "linux disabled"),
          "a disabled versioned target resurrected its legacy link: %s", response_body());
    return 0;
}

static int version_check(const char *query, const char *remote)
{
    char path[256];
    snprintf(path, sizeof(path), "/api/public/client-version-check?%s", query);
    return public_call(path, remote == NULL ? "198.51.100.2" : remote);
}

static int test_version_check_rules(void)
{
    /* versionCheckSupportsAuthoritativeExternalLatestThenSpecificityAndSemver */
    CHECK(fresh_database("version-specificity") == 0, "database setup failed");
    use_release_fallback(NULL);
    CHECK(create_link("{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\",\"displayName\":\"exact\","
                      "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v1.5.0/package-11\","
                      "\"version\":\"1.5.0\",\"minSupportedVersion\":\"1.4.0\",\"sha256\":\"" SHA_A "\","
                      "\"fileSize\":100,\"isLatest\":true}") > 0,
          "exact row");
    const form_field universal[] = {
        {"implementation", "go"}, {"platform", "any"}, {"arch", "any"}, {"version", "9.0.0"},
        {"displayName", "universal newer"}, {"isLatest", "true"}, {NULL, NULL}
    };
    CHECK(upload_package(universal, "universal", 9U, NULL) == 201, "universal hosted row: %s", response);
    CHECK(create_link("{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\",\"displayName\":\"newer\","
                      "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v10.0.0/package-13\","
                      "\"version\":\"10.0.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100}") > 0,
          "unmarked row");
    CHECK(version_check("implementation=GO&platform=windows&arch=x64&current=1.0.0", NULL) == 200,
          "version check: %s", response);
    const char *body = response_body();
    CHECK(contains(response, "Cache-Control: no-store") && contains(body, "\"updateAvailable\":true")
              && contains(body, "\"mandatory\":true") && contains(body, "\"latestVersion\":\"1.5.0\"")
              && contains(body, "\"packageId\":null")
              && contains(body, "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/")
              && contains(body, "\"sha256\":\"" SHA_A "\""),
          "specificity before version: %s", body);

    /* versionCheckNeverPublishesUnmarkedPackageAndReturnsNoneAfterLatestIsDeleted */
    CHECK(fresh_database("version-unmarked") == 0, "database setup failed");
    use_release_fallback(release_v123);
    long long published = create_link("{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\","
        "\"displayName\":\"published\",\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v2.0.0/p\","
        "\"version\":\"2.0.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100,\"isLatest\":true}");
    CHECK(published > 0 && create_link("{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\","
              "\"displayName\":\"staged\",\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v9.0.0/s\","
              "\"version\":\"9.0.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100}") > 0,
          "fixture rows");
    CHECK(version_check("implementation=go&platform=linux&arch=x64&current=1.0.0", NULL) == 200
              && contains(response_body(), "\"latestVersion\":\"2.0.0\""),
          "published latest: %s", response_body());
    char path[96];
    snprintf(path, sizeof(path), "/api/admin/client-downloads/%lld", published);
    CHECK(admin_call("DELETE", path, NULL) == 204, "delete: %s", response);
    CHECK(version_check("implementation=go&platform=linux&arch=x64&current=1.0.0", NULL) == 200
              && contains(response_body(), "\"updateAvailable\":false")
              && contains(response_body(), "\"latestVersion\":null")
              && contains(response_body(), "\"packageId\":null"),
          "an unmarked package was published after the latest went: %s", response_body());
    /* configuredTargetSuppressesGithubFallbackEvenWhenItHasNoEnabledLatest */
    CHECK(fake_release_calls == 0, "a configured target still asked GitHub (%d)", fake_release_calls);
    CHECK(create_link("{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"arm64\",\"displayName\":\"arm\","
                      "\"downloadUrl\":\"https://example.test/arm\",\"version\":\"2.0.0\",\"enabled\":false}") > 0,
          "disabled arm64 row");
    CHECK(version_check("implementation=go&platform=linux&arch=arm64&current=1.0.0", NULL) == 200
              && contains(response_body(), "\"latestVersion\":null") && fake_release_calls == 0,
          "a disabled configured target fell back to GitHub: %s (calls %d)", response_body(), fake_release_calls);

    /* versionCheckReturnsNoneWhenMatchingPackagesHaveNoExplicitLatest */
    CHECK(fresh_database("version-no-latest") == 0, "database setup failed");
    use_release_fallback(NULL);
    CHECK(create_link("{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\",\"displayName\":\"staged\","
                      "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v9.0.0/s\","
                      "\"version\":\"9.0.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100}") > 0,
          "staged row");
    CHECK(version_check("implementation=go&platform=linux&arch=x64&current=1.0.0", NULL) == 200
              && contains(response_body(), "\"updateAvailable\":false")
              && contains(response_body(), "\"latestVersion\":null"),
          "a package without an explicit latest was published: %s", response_body());

    /* versionCheckSupportsAndroidAnyAndReturnsNullOptionalsWhenNoPackageExists */
    CHECK(version_check("implementation=android&platform=android&arch=any&current=1.0.0", NULL) == 200
              && strcmp(response_body(),
                        "{\"updateAvailable\":false,\"mandatory\":false,\"latestVersion\":null,\"downloadUrl\":null,"
                        "\"sha256\":null,\"fileSize\":0,\"changelogUrl\":null,\"packageId\":null}") == 0,
          "android/any without a package: %s", response_body());

    /* versionCheckFallsBackToGithubReleaseAndNormalizesTagVersion */
    CHECK(fresh_database("version-release") == 0, "database setup failed");
    use_release_fallback(release_v123);
    CHECK(version_check("implementation=go&platform=windows&arch=x64&current=1.2.2", NULL) == 200
              && contains(response_body(), "\"updateAvailable\":true")
              && contains(response_body(), "\"latestVersion\":\"1.2.3\"")
              && contains(response_body(), "/releases/download/v1.2.3/")
              && contains(response_body(), "\"packageId\":null"),
          "release fallback: %s", response_body());
    CHECK(version_check("implementation=go&platform=windows&arch=x64&current=v1.2.3", NULL) == 200
              && contains(response_body(), "\"updateAvailable\":false")
              && contains(response_body(), "\"latestVersion\":\"1.2.3\"")
              && fake_release_calls == 1,
          "release fallback, current version: %s (calls %d)", response_body(), fake_release_calls);
    use_release_fallback(NULL);
    return 0;
}

static int test_public_list_release_fallback(void)
{
    /* publicListUsesReleaseAssetsOnlyForUnconfiguredTargets */
    CHECK(fresh_database("list-release") == 0, "database setup failed");
    use_release_fallback(release_v123);
    CHECK(create_link("{\"implementation\":\"java\",\"platform\":\"any\",\"arch\":\"any\",\"displayName\":\"configured java\","
                      "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v9.0.0/java\","
                      "\"version\":\"9.0.0\",\"sha256\":\"" SHA_A "\",\"fileSize\":100,\"isLatest\":true,"
                      "\"displayOrder\":72}") > 0,
          "configured java row");
    CHECK(public_call("/api/public/client-downloads", "198.51.100.3") == 200, "public list: %s", response);
    const char *body = response_body();
    const char *java_pos = strstr(body, "\"displayName\":\"configured java\"");
    const char *go_pos = strstr(body, "specus-client-go-v1.2.3-windows-x64.zip");
    CHECK(java_pos != NULL && go_pos != NULL && java_pos < go_pos
              && !contains(body, "specus-client-java-v1.2.3.jar") && fake_release_calls == 1,
          "release assets in the public list: %s", body);

    /* With every release target configured GitHub is not asked, and the list keeps implementation order. */
    CHECK(fresh_database("list-all-configured") == 0, "database setup failed");
    use_release_fallback(release_v123);
    static const char *const targets[][3] = {
        {"java", "any", "any"}, {"go", "macos", "arm64"}, {"go", "macos", "x64"}, {"go", "windows", "x64"},
        {"go", "windows", "arm64"}, {"go", "linux", "x64"}, {"go", "linux", "arm64"},
        {"csharp", "windows", "x64"}, {"csharp", "any", "any"}, {"android", "android", "any"},
    };
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); ++i) {
        char json[512];
        snprintf(json, sizeof(json),
                 "{\"implementation\":\"%s\",\"platform\":\"%s\",\"arch\":\"%s\",\"displayName\":\"row-%zu\","
                 "\"downloadUrl\":\"https://example.test/%zu\",\"displayOrder\":%d}",
                 targets[i][0], targets[i][1], targets[i][2], i, i, (int)i);
        CHECK(create_link(json) > 0, "target row %zu", i);
    }
    CHECK(public_call("/api/public/client-downloads", "198.51.100.3") == 200 && fake_release_calls == 0,
          "a fully configured catalogue asked GitHub (%d)", fake_release_calls);
    body = response_body();
    const char *android_pos = strstr(body, "\"implementation\":\"android\"");
    const char *csharp_pos = strstr(body, "\"implementation\":\"csharp\"");
    const char *go_first = strstr(body, "\"implementation\":\"go\"");
    const char *java_last = strstr(body, "\"implementation\":\"java\"");
    CHECK(android_pos != NULL && csharp_pos != NULL && go_first != NULL && java_last != NULL
              && android_pos < csharp_pos && csharp_pos < go_first && go_first < java_last,
          "implementation order: %s", body);
    use_release_fallback(NULL);
    return 0;
}

static int test_catalogue_mutations(void)
{
    CHECK(fresh_database("mutations") == 0, "database setup failed");
    use_release_fallback(NULL);
    /* jsonCrudAcceptsAndroidAndLegacyPayloadWhileKeepingLatestUnique */
    long long android_id = create_link("{\"implementation\":\"android\",\"platform\":\"android\",\"arch\":\"any\","
        "\"displayName\":\"Android APK\",\"downloadUrl\":\"https://example.test/client.apk\",\"displayOrder\":0,"
        "\"enabled\":true,\"version\":\"v1.2.3\",\"sha256\":\"" SHA_A "\",\"fileSize\":1024,\"isLatest\":true,"
        "\"minSupportedVersion\":\"v1.0.0\"}");
    CHECK(android_id > 0 && contains(response_body(), "\"implementation\":\"android\"")
              && contains(response_body(), "\"platform\":\"android\"")
              && contains(response_body(), "\"version\":\"1.2.3\"")
              && contains(response_body(), "\"minSupportedVersion\":\"1.0.0\"")
              && contains(response_body(), "\"isLatest\":true"),
          "android create: %s", response_body());
    long long legacy_id = create_link("{\"implementation\":\"java\",\"platform\":\"any\",\"arch\":\"any\","
        "\"displayName\":\"Legacy Java\",\"downloadUrl\":\"https://example.test/client.jar\",\"displayOrder\":1,"
        "\"enabled\":true}");
    CHECK(legacy_id > 0 && contains(response_body(), "\"version\":null")
              && contains(response_body(), "\"isLatest\":false"),
          "legacy create: %s", response_body());
    long long second_id = create_link("{\"implementation\":\"android\",\"platform\":\"android\",\"arch\":\"any\","
        "\"displayName\":\"Android APK 2\",\"downloadUrl\":\"https://example.test/client-2.apk\","
        "\"version\":\"1.2.4\",\"sha256\":\"" SHA_A "\",\"fileSize\":1024,\"isLatest\":true}");
    char query[160];
    snprintf(query, sizeof(query), "SELECT COUNT(*) FROM client_download_link WHERE is_latest = 1 AND id = %lld",
             second_id);
    CHECK(second_id > 0
              && sql_int("SELECT COUNT(*) FROM client_download_link WHERE implementation = 'android' AND is_latest = 1") == 1
              && sql_int(query) == 1,
          "the latest slot is not unique");

    /* rejectsDeadAndroidCatalogueCoordinates */
    static const struct {
        const char *json;
        const char *message;
    } dead[] = {
        {"{\"implementation\":\"android\",\"platform\":\"windows\",\"arch\":\"any\",\"displayName\":\"Android APK\","
         "\"downloadUrl\":\"https://example.test/client.apk\",\"version\":\"1.2.3\"}", "platform=android"},
        {"{\"implementation\":\"android\",\"platform\":\"android\",\"arch\":\"arm64\",\"displayName\":\"Android APK\","
         "\"downloadUrl\":\"https://example.test/client.apk\",\"version\":\"1.2.3\"}", "arch=any"},
        {"{\"implementation\":\"go\",\"platform\":\"android\",\"arch\":\"any\",\"displayName\":\"Wrong APK\","
         "\"downloadUrl\":\"https://example.test/client.apk\",\"version\":\"1.2.3\"}", "reserved"},
    };
    for (size_t i = 0; i < sizeof(dead) / sizeof(dead[0]); ++i) {
        CHECK(admin_call("POST", "/api/admin/client-downloads", dead[i].json) == 400
                  && contains(response_body(), dead[i].message),
              "dead coordinates %zu: %s", i, response);
    }
    CHECK(version_check("implementation=android&platform=windows&arch=any&current=1.0.0", NULL) == 400
              && contains(response_body(), "platform=android"),
          "a version check for dead coordinates: %s", response);

    /* createAndUpdateRejectDisabledLatestBeforeChangingLatestSlot */
    CHECK(admin_call("POST", "/api/admin/client-downloads",
                     "{\"implementation\":\"android\",\"platform\":\"android\",\"arch\":\"any\",\"displayName\":\"Android APK\","
                     "\"downloadUrl\":\"https://example.test/client.apk\",\"enabled\":false,\"version\":\"1.2.3\","
                     "\"isLatest\":true}") == 400
              && contains(response_body(), "disabled"),
          "a disabled latest was created: %s", response);
    char path[96];
    snprintf(path, sizeof(path), "/api/admin/client-downloads/%lld", second_id);
    CHECK(admin_call("PUT", path, "{\"implementation\":\"android\",\"platform\":\"android\",\"arch\":\"any\","
                     "\"displayName\":\"Android APK\",\"downloadUrl\":\"https://example.test/client.apk\","
                     "\"enabled\":false,\"version\":\"1.2.4\"}") == 400
              && contains(response_body(), "disabled"),
          "the latest row was disabled: %s", response);
    CHECK(sql_int(query) == 1, "a refused update changed the latest slot");

    /* externalLatestRequiresVerifiedHttpsReleaseMetadata */
    static const struct {
        const char *url;
        const char *sha;
        const char *message;
    } unsafe[] = {
        {"https://github.com/devShuai/specus/releases/download/v1.2.3/client.zip", NULL, "sha256"},
        {"https://github.com/devShuai/specus/releases/download/v1.2.3/client.zip?raw=1", SHA_A, "HTTPS"},
        {"https://github.com/devShuai/specus/releases/download/v1.2.3/client.zip#part", SHA_A, "HTTPS"},
        {"https://user@github.com/devShuai/specus/releases/download/v1.2.3/client.zip", SHA_A, "HTTPS"},
        {"http://github.com/devShuai/specus/releases/download/v1.2.3/client.zip", SHA_A, "HTTPS"},
    };
    for (size_t i = 0; i < sizeof(unsafe) / sizeof(unsafe[0]); ++i) {
        char json[640];
        snprintf(json, sizeof(json),
                 "{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\",\"displayName\":\"Go client\","
                 "\"downloadUrl\":\"%s\",\"version\":\"1.2.3\",%s%s%s\"fileSize\":1024,\"isLatest\":true}",
                 unsafe[i].url, unsafe[i].sha == NULL ? "" : "\"sha256\":\"", unsafe[i].sha == NULL ? "" : unsafe[i].sha,
                 unsafe[i].sha == NULL ? "" : "\",");
        CHECK(admin_call("POST", "/api/admin/client-downloads", json) == 400 && contains(response_body(), unsafe[i].message),
              "unsafe external latest %zu: %s", i, response);
    }
    CHECK(create_link("{\"implementation\":\"go\",\"platform\":\"windows\",\"arch\":\"x64\",\"displayName\":\"Go client\","
                      "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v1.2.3/client.zip?raw=1\","
                      "\"version\":\"1.2.3\"}") > 0,
          "a non-latest external link with a query was refused");

    /* markLatestRequiresEnabledValidSemanticVersion, on rows an older server stored. */
    CHECK(sql_exec("INSERT INTO client_download_link(id, implementation, platform, arch, display_name, download_url, "
                   "enabled, version, sha256, file_size, is_latest, min_supported_version, hosted) VALUES "
                   "(41, 'go', 'linux', 'x64', 'disabled', 'https://example.test/41', 0, '1.2.3', '" SHA_A "', 100, 0, NULL, 0),"
                   "(42, 'go', 'linux', 'x64', 'invalid', 'https://example.test/42', 1, 'not-semver', '" SHA_A "', 100, 0, NULL, 0),"
                   "(43, 'go', 'linux', 'x64', 'canonical', 'https://example.test/43', 1, 'v1.2.3', '" SHA_A "', 100, 0, 'v1.0.0', 0),"
                   "(44, 'go', 'linux', 'x64', 'unversioned', 'https://example.test/44', 1, NULL, NULL, 0, 0, NULL, 0),"
                   "(45, 'go', 'linux', 'x64', 'unsafe', 'https://example.test/45?raw=1', 1, '1.2.4', '" SHA_A "', 100, 0, NULL, 0)") == 0,
          "legacy rows");
    CHECK(admin_call("POST", "/api/admin/client-downloads/41/latest", NULL) == 400 && contains(response_body(), "disabled"),
          "a disabled row became latest: %s", response);
    CHECK(admin_call("POST", "/api/admin/client-downloads/42/latest", NULL) == 400 && contains(response_body(), "SemVer"),
          "an invalid version became latest: %s", response);
    CHECK(admin_call("POST", "/api/admin/client-downloads/44/latest", NULL) == 400
              && contains(response_body(), "has no version"),
          "an unversioned row became latest: %s", response);
    CHECK(admin_call("POST", "/api/admin/client-downloads/45/latest", NULL) == 400 && contains(response_body(), "HTTPS"),
          "an unsafe external row became latest: %s", response);
    CHECK(admin_call("POST", "/api/admin/client-downloads/43/latest", NULL) == 200
              && contains(response_body(), "\"version\":\"1.2.3\"")
              && contains(response_body(), "\"minSupportedVersion\":\"1.0.0\"")
              && contains(response_body(), "\"isLatest\":true"),
          "mark latest: %s", response);
    CHECK(sql_int("SELECT COUNT(*) FROM client_download_link WHERE id = 43 AND version = '1.2.3' "
                  "AND min_supported_version = '1.0.0' AND is_latest = 1") == 1,
          "mark latest did not store the canonical versions");
    /* An unknown id is Java's IllegalArgumentException: 400 with the id. */
    CHECK(admin_call("POST", "/api/admin/client-downloads/999/latest", NULL) == 400
              && contains(response_body(), "client download link not found: 999")
              && admin_call("PUT", "/api/admin/client-downloads/999", "{\"displayName\":\"x\"}") == 400
              && admin_call("DELETE", "/api/admin/client-downloads/999", NULL) == 400,
          "an unknown id: %s", response);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */

int main(void)
{
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    /* Generous by default; test_rate_limits sets its own budget. */
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", "100000", 1);
    const char *tmp = getenv("TMPDIR");
    const char *base = access("/dev/shm", W_OK) == 0 ? "/dev/shm" : (tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    snprintf(scratch_dir, sizeof(scratch_dir), "%s/specus-c-client-packages-XXXXXX", base);
    if (mkdtemp(scratch_dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    st_github_release_set_fetcher_for_testing(fake_release_fetch);

    st_admin_server server;
    memset(&server, 0, sizeof(server));
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (st_admin_server_start(&server, 0, "") != 0
        || getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0) {
        fprintf(stderr, "admin listener start failed\n");
        return 1;
    }
    listener_port = ntohs(address.sin_port);

    int failed = test_package_download_contract()
        || test_rate_limits()
        || test_package_storage()
        || test_package_lifecycle()
        || test_public_list_legacy_targets()
        || test_version_check_rules()
        || test_public_list_release_fallback()
        || test_catalogue_mutations();

    static const char *const databases[] = {
        "download", "rate", "storage", "lifecycle", "legacy-targets", "version-specificity", "version-unmarked",
        "version-no-latest", "version-release", "list-release", "list-all-configured", "mutations"
    };
    for (size_t i = 0; i < sizeof(databases) / sizeof(databases[0]); ++i) {
        char path[400];
        snprintf(path, sizeof(path), "%s/%s.db", scratch_dir, databases[i]);
        unlink(path);
        char packages[400];
        snprintf(packages, sizeof(packages), "%s/%s-data/packages", scratch_dir, databases[i]);
        DIR *dir = opendir(packages);
        if (dir != NULL) {
            for (struct dirent *entry = readdir(dir); entry != NULL; entry = readdir(dir)) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
                char file[700];
                snprintf(file, sizeof(file), "%s/%s", packages, entry->d_name);
                unlink(file);
            }
            closedir(dir);
        }
        rmdir(packages);
        snprintf(path, sizeof(path), "%s/%s-data", scratch_dir, databases[i]);
        rmdir(path);
    }
    rmdir(scratch_dir);
    if (failed) return 1;
    printf("client package tests passed\n");
    return 0;
}
