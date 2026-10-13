#define _POSIX_C_SOURCE 200809L

#include "media_capture.h"

#include "decompression_limits.h"
#include "json.h"
#include "storage.h"

#include <ctype.h>
#include <curl/curl.h>
#include <limits.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define ST_MEDIA_MIN_PART_SIZE (5U * 1024U * 1024U)
#define ST_MEDIA_DEFAULT_PART_SIZE (8U * 1024U * 1024U)
#define ST_MEDIA_MAX_PART_SIZE (512U * 1024U * 1024U)
#define ST_MEDIA_MAX_PARTS 10000U
#define ST_MEDIA_XML_LIMIT (20U * 1024U * 1024U)
#define ST_MEDIA_MAX_PLAYBACK_PARTS 4096U
#define ST_MEDIA_SOURCE_MAX 3072U

typedef struct {
    int enabled;
    char endpoint[512];
    char region[64];
    char bucket[256];
    char access_key_id[256];
    char access_key_secret[256];
    char object_prefix[256];
    int path_style;
    int create_bucket_if_missing;
    size_t part_size;
    long long retention_seconds;
    long long live_window_seconds;
    size_t manifest_max_bytes;
} st_media_config;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
    char etag[512];
    long status;
} st_media_http_response;

typedef struct {
    int number;
    char etag[512];
} st_media_completed_part;

struct st_media_capture_session {
    st_media_config cfg;
    char database_path[1024];
    long long id;
    char tenant_id[64];
    long long client_id;
    char route[128];
    char source_url[ST_MEDIA_SOURCE_MAX + 1U];
    char content_encoding[129];
    char media_kind[32];
    char object_key[1024];
    char upload_id[1024];
    long long range_start;
    long long range_end;
    long long total_bytes;
    long long expected_bytes;
    long long captured_bytes;
    int has_range_start;
    int has_range_end;
    int has_total_bytes;
    int manifest;
    int terminal;
    int failed;
    /* Java's externalized no-op: the same range is already stored or being stored. */
    int duplicate;
    uint8_t *part_buffer;
    size_t part_len;
    uint8_t *manifest_buffer;
    size_t manifest_len;
    int manifest_dropped;
    st_media_completed_part *parts;
    size_t parts_len;
    size_t parts_cap;
};

static int g_media_ready;

static const char *media_env(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value == NULL || *value == '\0' ? fallback : value;
}

static int media_env_bool(const char *name, int fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    return strcasecmp(value, "1") == 0 || strcasecmp(value, "true") == 0
        || strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0;
}

static long long media_env_i64(const char *name, long long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' ? parsed : fallback;
}

static void media_copy(char *out, size_t out_len, const char *value)
{
    if (out_len == 0U) return;
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
}

static st_media_config media_load_config(void)
{
    st_media_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = media_env_bool("SPECUS_MEDIA_CAPTURE_ENABLED", 0);
    media_copy(cfg.endpoint, sizeof(cfg.endpoint), media_env("SPECUS_MEDIA_CAPTURE_ENDPOINT", ""));
    media_copy(cfg.region, sizeof(cfg.region), media_env("SPECUS_MEDIA_CAPTURE_REGION", "us-east-1"));
    media_copy(cfg.bucket, sizeof(cfg.bucket), media_env("SPECUS_MEDIA_CAPTURE_BUCKET", ""));
    media_copy(cfg.access_key_id, sizeof(cfg.access_key_id), media_env("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_ID", ""));
    media_copy(cfg.access_key_secret, sizeof(cfg.access_key_secret), media_env("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_SECRET", ""));
    media_copy(cfg.object_prefix, sizeof(cfg.object_prefix), media_env("SPECUS_MEDIA_CAPTURE_PREFIX", "specus/http-media"));
    cfg.path_style = media_env_bool("SPECUS_MEDIA_CAPTURE_PATH_STYLE", 1);
    cfg.create_bucket_if_missing = media_env_bool("SPECUS_MEDIA_CAPTURE_CREATE_BUCKET_IF_MISSING", 0);
    long long part_size = media_env_i64("SPECUS_MEDIA_CAPTURE_PART_SIZE_BYTES", ST_MEDIA_DEFAULT_PART_SIZE);
    if (part_size < (long long)ST_MEDIA_MIN_PART_SIZE) part_size = ST_MEDIA_MIN_PART_SIZE;
    if (part_size > (long long)ST_MEDIA_MAX_PART_SIZE) part_size = ST_MEDIA_MAX_PART_SIZE;
    cfg.part_size = (size_t)part_size;
    cfg.retention_seconds = media_env_i64("SPECUS_MEDIA_CAPTURE_RETENTION_SECONDS", 604800LL);
    if (cfg.retention_seconds < 60LL) cfg.retention_seconds = 60LL;
    cfg.live_window_seconds = media_env_i64("SPECUS_MEDIA_CAPTURE_LIVE_WINDOW_SECONDS", 300LL);
    if (cfg.live_window_seconds < 60LL) cfg.live_window_seconds = 60LL;
    long long manifest_limit = media_env_i64("SPECUS_MEDIA_CAPTURE_MANIFEST_MAX_BYTES", 16LL * 1024LL * 1024LL);
    if (manifest_limit < 1LL) manifest_limit = 16LL * 1024LL * 1024LL;
    cfg.manifest_max_bytes = (size_t)manifest_limit;
    return cfg;
}

static int media_config_ready(const st_media_config *cfg)
{
    return cfg != NULL && cfg->enabled && cfg->endpoint[0] != '\0' && cfg->bucket[0] != '\0'
        && cfg->access_key_id[0] != '\0' && cfg->access_key_secret[0] != '\0';
}

static void media_hex(const unsigned char *input, size_t input_len, char *out)
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < input_len; ++i) {
        out[i * 2U] = digits[input[i] >> 4U];
        out[i * 2U + 1U] = digits[input[i] & 0x0fU];
    }
    out[input_len * 2U] = '\0';
}

static int media_base64url(const unsigned char *input, size_t input_len,
                           char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t needed = (input_len * 8U + 5U) / 6U;
    if (out_len <= needed) return -1;
    size_t source = 0U, target = 0U;
    while (source + 3U <= input_len) {
        uint32_t value = ((uint32_t)input[source] << 16U)
            | ((uint32_t)input[source + 1U] << 8U) | input[source + 2U];
        out[target++] = alphabet[(value >> 18U) & 63U];
        out[target++] = alphabet[(value >> 12U) & 63U];
        out[target++] = alphabet[(value >> 6U) & 63U];
        out[target++] = alphabet[value & 63U];
        source += 3U;
    }
    if (source < input_len) {
        uint32_t value = (uint32_t)input[source] << 16U;
        if (source + 1U < input_len) value |= (uint32_t)input[source + 1U] << 8U;
        out[target++] = alphabet[(value >> 18U) & 63U];
        out[target++] = alphabet[(value >> 12U) & 63U];
        if (source + 1U < input_len) out[target++] = alphabet[(value >> 6U) & 63U];
    }
    out[target] = '\0';
    return 0;
}

static void media_sha256_hex(const void *data, size_t data_len, char out[65])
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, data_len, digest);
    media_hex(digest, sizeof(digest), out);
}

static void media_hmac(const unsigned char *key, size_t key_len,
                       const char *value, unsigned char out[SHA256_DIGEST_LENGTH])
{
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), key, (int)key_len,
         (const unsigned char *)value, strlen(value), out, &out_len);
}

static int media_is_unreserved(unsigned char value)
{
    return isalnum(value) || value == '-' || value == '_' || value == '.' || value == '~';
}

static char *media_uri_encode(const char *value, int preserve_slash)
{
    size_t len = strlen(value);
    char *out = (char *)malloc(len * 3U + 1U);
    if (out == NULL) return NULL;
    static const char digits[] = "0123456789ABCDEF";
    size_t offset = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (media_is_unreserved(ch) || (preserve_slash && ch == '/')) {
            out[offset++] = (char)ch;
        } else {
            out[offset++] = '%';
            out[offset++] = digits[ch >> 4U];
            out[offset++] = digits[ch & 0x0fU];
        }
    }
    out[offset] = '\0';
    return out;
}

static int media_parse_endpoint(const st_media_config *cfg,
                                char *scheme, size_t scheme_len,
                                char *host, size_t host_len,
                                int *port,
                                char *base_path, size_t base_path_len)
{
    const char *sep = strstr(cfg->endpoint, "://");
    if (sep == NULL || sep == cfg->endpoint) return -1;
    size_t scheme_size = (size_t)(sep - cfg->endpoint);
    if (scheme_size >= scheme_len) return -1;
    memcpy(scheme, cfg->endpoint, scheme_size);
    scheme[scheme_size] = '\0';
    if (strcasecmp(scheme, "http") != 0 && strcasecmp(scheme, "https") != 0) return -1;
    const char *authority = sep + 3;
    const char *slash = strchr(authority, '/');
    const char *authority_end = slash == NULL ? authority + strlen(authority) : slash;
    const char *colon = NULL;
    if (*authority == '[') {
        const char *close = memchr(authority, ']', (size_t)(authority_end - authority));
        if (close == NULL) return -1;
        colon = close + 1 < authority_end && close[1] == ':' ? close + 1 : NULL;
    } else {
        colon = memchr(authority, ':', (size_t)(authority_end - authority));
    }
    size_t host_size = (size_t)((colon == NULL ? authority_end : colon) - authority);
    if (host_size == 0U || host_size >= host_len) return -1;
    memcpy(host, authority, host_size);
    host[host_size] = '\0';
    *port = strcasecmp(scheme, "https") == 0 ? 443 : 80;
    if (colon != NULL) {
        char port_text[16];
        size_t port_size = (size_t)(authority_end - colon - 1);
        if (port_size == 0U || port_size >= sizeof(port_text)) return -1;
        memcpy(port_text, colon + 1, port_size);
        port_text[port_size] = '\0';
        *port = atoi(port_text);
        if (*port < 1 || *port > 65535) return -1;
    }
    media_copy(base_path, base_path_len, slash == NULL ? "" : slash);
    size_t base_len = strlen(base_path);
    while (base_len > 0U && base_path[base_len - 1U] == '/') base_path[--base_len] = '\0';
    return 0;
}

static size_t media_response_write(char *data, size_t size, size_t count, void *ctx)
{
    st_media_http_response *response = (st_media_http_response *)ctx;
    size_t bytes = size * count;
    if (bytes > ST_MEDIA_XML_LIMIT - response->len) return 0;
    if (response->len + bytes + 1U > response->cap) {
        size_t next = response->cap == 0U ? 4096U : response->cap;
        while (next < response->len + bytes + 1U) next *= 2U;
        char *grown = (char *)realloc(response->data, next);
        if (grown == NULL) return 0;
        response->data = grown;
        response->cap = next;
    }
    memcpy(response->data + response->len, data, bytes);
    response->len += bytes;
    response->data[response->len] = '\0';
    return bytes;
}

static size_t media_response_header(char *data, size_t size, size_t count, void *ctx)
{
    st_media_http_response *response = (st_media_http_response *)ctx;
    size_t bytes = size * count;
    if (bytes > 5U && strncasecmp(data, "ETag:", 5U) == 0) {
        const char *start = data + 5;
        const char *end = data + bytes;
        while (start < end && isspace((unsigned char)*start)) ++start;
        while (end > start && isspace((unsigned char)end[-1])) --end;
        size_t len = (size_t)(end - start);
        if (len >= sizeof(response->etag)) len = sizeof(response->etag) - 1U;
        memcpy(response->etag, start, len);
        response->etag[len] = '\0';
    }
    return bytes;
}

static char *media_xml_value(const char *xml, const char *name)
{
    if (xml == NULL) return NULL;
    char open[64];
    char close[64];
    snprintf(open, sizeof(open), "<%s>", name);
    snprintf(close, sizeof(close), "</%s>", name);
    const char *start = strstr(xml, open);
    if (start == NULL) return NULL;
    start += strlen(open);
    const char *end = strstr(start, close);
    if (end == NULL) return NULL;
    size_t len = (size_t)(end - start);
    char *value = (char *)malloc(len + 1U);
    if (value == NULL) return NULL;
    memcpy(value, start, len);
    value[len] = '\0';
    return value;
}

static int media_s3_request(const st_media_config *cfg,
                            const char *method,
                            const char *object_key,
                            const char *canonical_query,
                            const char *content_type,
                            const char *content_encoding,
                            const uint8_t *body,
                            size_t body_len,
                            const char *range,
                            st_media_http_response *response)
{
    char scheme[16], endpoint_host[320], base_path[512];
    int port = 0;
    if (media_parse_endpoint(cfg, scheme, sizeof(scheme), endpoint_host, sizeof(endpoint_host),
                             &port, base_path, sizeof(base_path)) != 0) return -1;
    char request_host[640];
    if (cfg->path_style) {
        media_copy(request_host, sizeof(request_host), endpoint_host);
    } else {
        snprintf(request_host, sizeof(request_host), "%s.%s", cfg->bucket, endpoint_host);
    }
    char raw_path[2048];
    snprintf(raw_path, sizeof(raw_path), "%s/%s%s%s",
             base_path,
             cfg->path_style ? cfg->bucket : "",
             cfg->path_style && object_key != NULL && *object_key != '\0' ? "/" : "",
             object_key == NULL ? "" : object_key);
    if (raw_path[0] == '\0') media_copy(raw_path, sizeof(raw_path), "/");
    char *canonical_uri = media_uri_encode(raw_path, 1);
    if (canonical_uri == NULL) return -1;
    char url[4096];
    int default_port = strcasecmp(scheme, "https") == 0 ? 443 : 80;
    snprintf(url, sizeof(url), "%s://%s%s%d%s%s%s",
             scheme, request_host, port == default_port ? "" : ":",
             port == default_port ? 0 : port,
             canonical_uri,
             canonical_query != NULL && *canonical_query != '\0' ? "?" : "",
             canonical_query == NULL ? "" : canonical_query);
    if (port == default_port) {
        snprintf(url, sizeof(url), "%s://%s%s%s%s",
                 scheme, request_host, canonical_uri,
                 canonical_query != NULL && *canonical_query != '\0' ? "?" : "",
                 canonical_query == NULL ? "" : canonical_query);
    }

    char payload_hash[65];
    media_sha256_hex(body == NULL ? "" : (const void *)body, body == NULL ? 0U : body_len, payload_hash);
    time_t now = time(NULL);
    struct tm utc;
    gmtime_r(&now, &utc);
    char timestamp[17], date[9];
    strftime(timestamp, sizeof(timestamp), "%Y%m%dT%H%M%SZ", &utc);
    strftime(date, sizeof(date), "%Y%m%d", &utc);
    char host_header[700];
    if (port == default_port) media_copy(host_header, sizeof(host_header), request_host);
    else snprintf(host_header, sizeof(host_header), "%s:%d", request_host, port);
    char canonical_headers[1024];
    snprintf(canonical_headers, sizeof(canonical_headers),
             "host:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
             host_header, payload_hash, timestamp);
    const char *signed_headers = "host;x-amz-content-sha256;x-amz-date";
    size_t canonical_len = strlen(method) + strlen(canonical_uri)
        + strlen(canonical_query == NULL ? "" : canonical_query)
        + strlen(canonical_headers) + strlen(signed_headers) + strlen(payload_hash) + 8U;
    char *canonical_request = (char *)malloc(canonical_len);
    if (canonical_request == NULL) {
        free(canonical_uri);
        return -1;
    }
    snprintf(canonical_request, canonical_len, "%s\n%s\n%s\n%s\n%s\n%s",
             method, canonical_uri, canonical_query == NULL ? "" : canonical_query,
             canonical_headers, signed_headers, payload_hash);
    char canonical_hash[65];
    media_sha256_hex(canonical_request, strlen(canonical_request), canonical_hash);
    free(canonical_request);
    char scope[256];
    snprintf(scope, sizeof(scope), "%s/%s/s3/aws4_request", date, cfg->region);
    char string_to_sign[512];
    snprintf(string_to_sign, sizeof(string_to_sign), "AWS4-HMAC-SHA256\n%s\n%s\n%s",
             timestamp, scope, canonical_hash);
    unsigned char date_key[SHA256_DIGEST_LENGTH], region_key[SHA256_DIGEST_LENGTH];
    unsigned char service_key[SHA256_DIGEST_LENGTH], signing_key[SHA256_DIGEST_LENGTH];
    unsigned char signature_bytes[SHA256_DIGEST_LENGTH];
    char secret[300];
    snprintf(secret, sizeof(secret), "AWS4%s", cfg->access_key_secret);
    media_hmac((const unsigned char *)secret, strlen(secret), date, date_key);
    media_hmac(date_key, sizeof(date_key), cfg->region, region_key);
    media_hmac(region_key, sizeof(region_key), "s3", service_key);
    media_hmac(service_key, sizeof(service_key), "aws4_request", signing_key);
    media_hmac(signing_key, sizeof(signing_key), string_to_sign, signature_bytes);
    char signature[65];
    media_hex(signature_bytes, sizeof(signature_bytes), signature);
    char authorization[1024];
    snprintf(authorization, sizeof(authorization),
             "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
             cfg->access_key_id, scope, signed_headers, signature);
    char date_header[64], hash_header[128];
    snprintf(date_header, sizeof(date_header), "x-amz-date: %s", timestamp);
    snprintf(hash_header, sizeof(hash_header), "x-amz-content-sha256: %s", payload_hash);
    struct curl_slist *request_headers = NULL;
    request_headers = curl_slist_append(request_headers, authorization);
    request_headers = curl_slist_append(request_headers, date_header);
    request_headers = curl_slist_append(request_headers, hash_header);
    if (content_type != NULL && *content_type != '\0') {
        char header[512];
        snprintf(header, sizeof(header), "Content-Type: %s", content_type);
        request_headers = curl_slist_append(request_headers, header);
    }
    if (content_encoding != NULL && *content_encoding != '\0') {
        char header[256];
        snprintf(header, sizeof(header), "Content-Encoding: %s", content_encoding);
        request_headers = curl_slist_append(request_headers, header);
    }
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        curl_slist_free_all(request_headers);
        free(canonical_uri);
        return -1;
    }
    memset(response, 0, sizeof(*response));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, request_headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, media_response_write);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, media_response_header);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    if (strcasecmp(method, "GET") == 0) curl_easy_setopt(curl, CURLOPT_HTTP_CONTENT_DECODING, 0L);
    if (range != NULL && *range != '\0') curl_easy_setopt(curl, CURLOPT_RANGE, range);
    if (strcasecmp(method, "HEAD") == 0) curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    if (body != NULL) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
    } else if (strcasecmp(method, "POST") == 0 || strcasecmp(method, "PUT") == 0) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    }
    const char *resolve_address = getenv("SPECUS_MEDIA_CAPTURE_TEST_RESOLVE_ADDRESS");
    struct curl_slist *resolve = NULL;
    if (resolve_address != NULL && *resolve_address != '\0') {
        char entry[1024];
        snprintf(entry, sizeof(entry), "%s:%d:%s", request_host, port, resolve_address);
        resolve = curl_slist_append(resolve, entry);
        curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
    }
    CURLcode curl_rc = curl_easy_perform(curl);
    if (curl_rc == CURLE_OK) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status);
    curl_slist_free_all(resolve);
    curl_easy_cleanup(curl);
    curl_slist_free_all(request_headers);
    free(canonical_uri);
    return curl_rc == CURLE_OK ? 0 : -1;
}

static int media_s3_success(const st_media_http_response *response)
{
    return response->status >= 200L && response->status < 300L;
}

static void media_http_response_free(st_media_http_response *response)
{
    free(response->data);
    memset(response, 0, sizeof(*response));
}

static int media_s3_begin(const st_media_config *cfg, const char *object_key,
                          const char *content_type, const char *content_encoding,
                          char upload_id[1024])
{
    st_media_http_response response;
    if (media_s3_request(cfg, "POST", object_key, "uploads=", content_type,
                         content_encoding, NULL, 0U, NULL, &response) != 0) return -1;
    int ok = media_s3_success(&response);
    char *value = ok ? media_xml_value(response.data, "UploadId") : NULL;
    if (value == NULL || *value == '\0') ok = 0;
    if (ok) media_copy(upload_id, 1024U, value);
    free(value);
    media_http_response_free(&response);
    return ok ? 0 : -1;
}

static int media_s3_upload_part(st_media_capture_session *session,
                                int part_number,
                                const uint8_t *data,
                                size_t data_len,
                                char etag[512])
{
    char *upload = media_uri_encode(session->upload_id, 0);
    if (upload == NULL) return -1;
    char query[1400];
    snprintf(query, sizeof(query), "partNumber=%d&uploadId=%s", part_number, upload);
    free(upload);
    st_media_http_response response;
    if (media_s3_request(&session->cfg, "PUT", session->object_key, query,
                         NULL, NULL, data, data_len, NULL, &response) != 0) return -1;
    int ok = media_s3_success(&response) && response.etag[0] != '\0';
    if (ok) media_copy(etag, 512U, response.etag);
    media_http_response_free(&response);
    return ok ? 0 : -1;
}

static int media_s3_abort(const st_media_capture_session *session)
{
    if (session->upload_id[0] == '\0') return 0;
    char *upload = media_uri_encode(session->upload_id, 0);
    if (upload == NULL) return -1;
    char query[1400];
    snprintf(query, sizeof(query), "uploadId=%s", upload);
    free(upload);
    st_media_http_response response;
    if (media_s3_request(&session->cfg, "DELETE", session->object_key, query,
                         NULL, NULL, NULL, 0U, NULL, &response) != 0) return -1;
    int ok = media_s3_success(&response) || response.status == 404L;
    media_http_response_free(&response);
    return ok ? 0 : -1;
}

static int media_xml_append(char **buffer, size_t *len, size_t *cap, const char *value)
{
    size_t value_len = strlen(value);
    if (*len + value_len + 1U > *cap) {
        size_t next = *cap == 0U ? 1024U : *cap;
        while (next < *len + value_len + 1U) next *= 2U;
        char *grown = (char *)realloc(*buffer, next);
        if (grown == NULL) return -1;
        *buffer = grown;
        *cap = next;
    }
    memcpy(*buffer + *len, value, value_len);
    *len += value_len;
    (*buffer)[*len] = '\0';
    return 0;
}

static int media_s3_complete(st_media_capture_session *session, char etag[512])
{
    char *xml = NULL;
    size_t len = 0, cap = 0;
    if (media_xml_append(&xml, &len, &cap, "<CompleteMultipartUpload>") != 0) return -1;
    for (size_t i = 0; i < session->parts_len; ++i) {
        char part[800];
        snprintf(part, sizeof(part), "<Part><PartNumber>%d</PartNumber><ETag>%s</ETag></Part>",
                 session->parts[i].number, session->parts[i].etag);
        if (media_xml_append(&xml, &len, &cap, part) != 0) {
            free(xml);
            return -1;
        }
    }
    if (media_xml_append(&xml, &len, &cap, "</CompleteMultipartUpload>") != 0) {
        free(xml);
        return -1;
    }
    char *upload = media_uri_encode(session->upload_id, 0);
    if (upload == NULL) {
        free(xml);
        return -1;
    }
    char query[1400];
    snprintf(query, sizeof(query), "uploadId=%s", upload);
    free(upload);
    st_media_http_response response;
    int request_rc = media_s3_request(&session->cfg, "POST", session->object_key, query,
                                      "application/xml", NULL, (const uint8_t *)xml, len, NULL, &response);
    free(xml);
    if (request_rc != 0) return -1;
    int ok = media_s3_success(&response);
    char *xml_etag = ok ? media_xml_value(response.data, "ETag") : NULL;
    const char *selected = xml_etag != NULL && *xml_etag != '\0' ? xml_etag : response.etag;
    if (selected == NULL || *selected == '\0') ok = 0;
    if (ok) media_copy(etag, 512U, selected);
    free(xml_etag);
    media_http_response_free(&response);
    return ok ? 0 : -1;
}

int st_media_capture_validate_current(void)
{
    st_media_config cfg = media_load_config();
    g_media_ready = 0;
    if (!cfg.enabled) return 0;
    if (!media_config_ready(&cfg)) {
        fprintf(stderr, "media capture is enabled but RustFS/S3 configuration is incomplete\n");
        return -1;
    }
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) return -1;
    st_media_http_response response;
    if (media_s3_request(&cfg, "HEAD", "", "", NULL, NULL, NULL, 0U, NULL, &response) != 0) {
        fprintf(stderr, "media capture RustFS bucket verification failed\n");
        return -1;
    }
    long status = response.status;
    media_http_response_free(&response);
    if (status == 404L && cfg.create_bucket_if_missing) {
        if (media_s3_request(&cfg, "PUT", "", "", NULL, NULL, NULL, 0U, NULL, &response) != 0) return -1;
        status = response.status;
        media_http_response_free(&response);
    }
    if (status < 200L || status >= 300L) {
        fprintf(stderr, "media capture RustFS bucket verification returned HTTP %ld\n", status);
        return -1;
    }
    g_media_ready = 1;
    return 0;
}

int st_media_capture_ready_current(void)
{
    return g_media_ready;
}

static char *media_header_value(char *const *headers, size_t headers_len, const char *name)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i < headers_len; ++i) {
        const char *header = headers[i];
        const char *colon = header == NULL ? NULL : strchr(header, ':');
        if (colon == NULL || (size_t)(colon - header) != name_len
            || strncasecmp(header, name, name_len) != 0) continue;
        const char *start = colon + 1;
        while (*start != '\0' && isspace((unsigned char)*start)) ++start;
        const char *end = start + strlen(start);
        while (end > start && isspace((unsigned char)end[-1])) --end;
        size_t len = (size_t)(end - start);
        char *value = (char *)malloc(len + 1U);
        if (value == NULL) return NULL;
        memcpy(value, start, len);
        value[len] = '\0';
        return value;
    }
    return NULL;
}

static const char *media_kind(const char *source_url, const char *content_type,
                              int status_code, const char *content_range)
{
    char type[256];
    media_copy(type, sizeof(type), content_type == NULL ? "" : content_type);
    char *semicolon = strchr(type, ';');
    if (semicolon != NULL) *semicolon = '\0';
    for (char *p = type; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
    char path[3073];
    media_copy(path, sizeof(path), source_url == NULL ? "/" : source_url);
    char *query = strchr(path, '?');
    if (query != NULL) *query = '\0';
    for (char *p = path; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
    size_t len = strlen(path);
#define MEDIA_SUFFIX(s) (len >= strlen(s) && strcmp(path + len - strlen(s), (s)) == 0)
    if (strcmp(type, "application/vnd.apple.mpegurl") == 0
        || strcmp(type, "application/x-mpegurl") == 0 || strcmp(type, "audio/mpegurl") == 0
        || MEDIA_SUFFIX(".m3u8")) return "HLS_MANIFEST";
    if (strcmp(type, "application/dash+xml") == 0 || MEDIA_SUFFIX(".mpd")) return "DASH_MANIFEST";
    if (MEDIA_SUFFIX(".ts") || MEDIA_SUFFIX(".m4s") || MEDIA_SUFFIX(".cmfv")
        || MEDIA_SUFFIX(".cmfa") || MEDIA_SUFFIX(".aac") || MEDIA_SUFFIX(".vtt")
        || MEDIA_SUFFIX(".key") || strcmp(type, "video/mp2t") == 0
        || strcmp(type, "application/octet-stream") == 0) return "MEDIA_SEGMENT";
    if (strncmp(type, "video/", 6U) == 0 || strncmp(type, "audio/", 6U) == 0
        || MEDIA_SUFFIX(".mp4") || MEDIA_SUFFIX(".webm") || MEDIA_SUFFIX(".mkv")
        || MEDIA_SUFFIX(".mov") || MEDIA_SUFFIX(".m4v") || MEDIA_SUFFIX(".mp3")
        || MEDIA_SUFFIX(".m4a") || MEDIA_SUFFIX(".ogg") || MEDIA_SUFFIX(".opus")
        || MEDIA_SUFFIX(".wav") || MEDIA_SUFFIX(".flac")
        || (status_code == 206 && content_range != NULL && *content_range != '\0')) return "PROGRESSIVE";
#undef MEDIA_SUFFIX
    return NULL;
}

/* Java String.trim(): every character up to and including the space. */
static void media_trim_bounds(const char **start, size_t *len)
{
    while (*len > 0U && (unsigned char)**start <= ' ') {
        ++*start;
        --*len;
    }
    while (*len > 0U && (unsigned char)(*start)[*len - 1U] <= ' ') --*len;
}

/* Length of "scheme:" when value starts with an RFC 3986 scheme followed by "//", else 0. */
static size_t media_scheme_authority_prefix(const char *value, size_t len)
{
    if (len == 0U || !isalpha((unsigned char)value[0])) return 0U;
    size_t i = 1U;
    while (i < len && (isalnum((unsigned char)value[i]) || value[i] == '+'
                       || value[i] == '-' || value[i] == '.')) ++i;
    return i + 2U < len && value[i] == ':' && value[i + 1U] == '/' && value[i + 2U] == '/'
        ? i + 1U : 0U;
}

/* Appends at most what still fits below ST_MEDIA_SOURCE_MAX, as Java's 3072-character cap. */
static void media_source_append(char out[ST_MEDIA_SOURCE_MAX + 1U], size_t *used,
                                const char *value, size_t len)
{
    size_t room = ST_MEDIA_SOURCE_MAX - *used;
    if (len > room) len = room;
    memcpy(out + *used, value, len);
    *used += len;
    out[*used] = '\0';
}

/* The path and query after "scheme://authority" (or "//authority"), without a fragment. */
static void media_source_after_authority(const char *authority, const char *limit,
                                         char out[ST_MEDIA_SOURCE_MAX + 1U], size_t *used)
{
    const char *path = authority;
    while (path < limit && *path != '/' && *path != '?' && *path != '#') ++path;
    const char *fragment = memchr(path, '#', (size_t)(limit - path));
    if (fragment != NULL) limit = fragment;
    if (path == limit || *path != '/') media_source_append(out, used, "/", 1U);
    media_source_append(out, used, path, (size_t)(limit - path));
}

/*
 * Java HttpMediaManifestSupport.normalizeSourceUrl: a blank value is "/", an absolute URL keeps
 * only its path and query, anything else gets a leading slash, and the result is capped at 3072.
 */
static void media_normalize_source(const char *source_url, char out[ST_MEDIA_SOURCE_MAX + 1U])
{
    const char *start = source_url == NULL ? "" : source_url;
    size_t len = strlen(start);
    size_t used = 0U;
    out[0] = '\0';
    media_trim_bounds(&start, &len);
    if (len == 0U) {
        media_source_append(out, &used, "/", 1U);
        return;
    }
    size_t scheme = media_scheme_authority_prefix(start, len);
    if (scheme > 0U) {
        media_source_after_authority(start + scheme + 2U, start + len, out, &used);
        return;
    }
    if (*start != '/') media_source_append(out, &used, "/", 1U);
    media_source_append(out, &used, start, len);
}

static int media_parse_digits(const char **cursor, const char *limit, long long *out)
{
    const char *p = *cursor;
    long long value = 0;
    if (p >= limit || !isdigit((unsigned char)*p)) return -1;
    while (p < limit && isdigit((unsigned char)*p)) {
        int digit = *p - '0';
        if (value > (LLONG_MAX - digit) / 10LL) return -1;
        value = value * 10LL + digit;
        ++p;
    }
    *cursor = p;
    *out = value;
    return 0;
}

/*
 * Java HttpMediaManifestSupport.parseContentRange: exactly "bytes <start>-<end>/<total|*>" after
 * trimming, "bytes" in any case, with end >= start and end < total. Anything else is no range.
 */
static int media_parse_content_range(const char *value,
                                     long long *start, long long *end, long long *total,
                                     int *has_total)
{
    if (value == NULL) return -1;
    const char *p = value;
    size_t len = strlen(value);
    media_trim_bounds(&p, &len);
    const char *limit = p + len;
    if (len < 6U || strncasecmp(p, "bytes", 5U) != 0 || !isspace((unsigned char)p[5])) return -1;
    p += 5;
    while (p < limit && isspace((unsigned char)*p)) ++p;
    long long parsed_start = 0, parsed_end = 0, parsed_total = 0;
    if (media_parse_digits(&p, limit, &parsed_start) != 0 || p >= limit || *p++ != '-'
        || media_parse_digits(&p, limit, &parsed_end) != 0 || p >= limit || *p++ != '/') return -1;
    int total_known = 1;
    if (p + 1 == limit && *p == '*') total_known = 0;
    else if (media_parse_digits(&p, limit, &parsed_total) != 0 || p != limit) return -1;
    if (parsed_end < parsed_start || (total_known && parsed_end >= parsed_total)) return -1;
    *start = parsed_start;
    *end = parsed_end;
    *has_total = total_known;
    if (total_known) *total = parsed_total;
    return 0;
}

/* Java HttpMediaManifestSupport.inferSequence: the digits right before the final extension. */
static int media_infer_sequence(const char *source_url, long long *sequence)
{
    const char *query = strchr(source_url, '?');
    size_t len = query == NULL ? strlen(source_url) : (size_t)(query - source_url);
    const char *dot = NULL;
    for (size_t i = len; i > 0U; --i) {
        if (source_url[i - 1U] == '.') {
            dot = source_url + i - 1U;
            break;
        }
    }
    if (dot == NULL || (size_t)(dot - source_url) + 1U >= len) return -1;
    const char *digits = dot;
    while (digits > source_url && isdigit((unsigned char)digits[-1])) --digits;
    if (digits == dot) return -1;
    return media_parse_digits(&digits, dot, sequence);
}

/* Java HttpMediaManifestSupport.isInitializationSegment, on the file name of the path. */
static int media_is_initialization_segment(const char *source_url)
{
    char path[ST_MEDIA_SOURCE_MAX + 1U];
    media_copy(path, sizeof(path), source_url);
    char *query = strchr(path, '?');
    if (query != NULL) *query = '\0';
    for (char *p = path; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
    const char *slash = strrchr(path, '/');
    const char *file = slash == NULL ? path : slash + 1;
    return strncmp(file, "init.", 5U) == 0 || strncmp(file, "init-", 5U) == 0
        || strstr(file, "initialization") != NULL;
}

static void media_iso_time(time_t value, char out[64])
{
    struct tm utc;
    gmtime_r(&value, &utc);
    strftime(out, 64U, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

static char *media_join_headers(char *const *headers, size_t headers_len)
{
    size_t total = 1U;
    for (size_t i = 0; i < headers_len; ++i) total += strlen(headers[i] == NULL ? "" : headers[i]) + 1U;
    char *joined = (char *)malloc(total);
    if (joined == NULL) return NULL;
    size_t offset = 0;
    for (size_t i = 0; i < headers_len; ++i) {
        const char *value = headers[i] == NULL ? "" : headers[i];
        size_t len = strlen(value);
        memcpy(joined + offset, value, len);
        offset += len;
        if (i + 1U < headers_len) joined[offset++] = '\n';
    }
    joined[offset] = '\0';
    return joined;
}

static const char *media_extension(const char *source_url)
{
    static const char *extensions[] = {
        ".m3u8", ".mpd", ".mp4", ".webm", ".mkv", ".mov", ".m4v", ".mp3",
        ".m4a", ".ogg", ".opus", ".wav", ".flac", ".ts", ".m4s", ".cmfv",
        ".cmfa", ".aac", ".vtt", ".key"
    };
    char path[3073];
    media_copy(path, sizeof(path), source_url);
    char *query = strchr(path, '?');
    if (query != NULL) *query = '\0';
    size_t len = strlen(path);
    for (size_t i = 0; i < sizeof(extensions) / sizeof(extensions[0]); ++i) {
        size_t ext_len = strlen(extensions[i]);
        if (len >= ext_len && strcasecmp(path + len - ext_len, extensions[i]) == 0) return extensions[i];
    }
    return ".bin";
}

static void media_safe_segment(const char *value, char *out, size_t out_len)
{
    size_t offset = 0;
    for (const unsigned char *p = (const unsigned char *)(value == NULL ? "" : value);
         *p != '\0' && offset + 1U < out_len; ++p) {
        out[offset++] = isalnum(*p) || *p == '-' || *p == '_' || *p == '.' ? (char)*p : '_';
    }
    if (offset == 0U && out_len > 1U) out[offset++] = '_';
    out[offset] = '\0';
}

static int media_db_open(const char *path, sqlite3 **db)
{
    if (sqlite3_open(path, db) != SQLITE_OK) {
        if (*db != NULL) sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    sqlite3_busy_timeout(*db, 5000);
    return 0;
}

static void media_db_mark_failed(st_media_capture_session *session, const char *reason)
{
    sqlite3 *db = NULL;
    if (media_db_open(session->database_path, &db) != 0) return;
    sqlite3_stmt *stmt = NULL;
    const char *sql = "UPDATE specus_http_media_capture SET state='FAILED',deduplication_key=NULL,"
        "failure_reason=?,upload_id=NULL,completed_at=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, reason == NULL || *reason == '\0' ? "媒体采集失败" : reason, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, session->id);
        sqlite3_bind_text(stmt, 3, session->tenant_id, -1, SQLITE_TRANSIENT);
        (void)sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

static int media_add_part(st_media_capture_session *session, int number, const char *etag)
{
    if (session->parts_len >= ST_MEDIA_MAX_PARTS) return -1;
    if (session->parts_len == session->parts_cap) {
        size_t next = session->parts_cap == 0U ? 16U : session->parts_cap * 2U;
        st_media_completed_part *grown = (st_media_completed_part *)realloc(session->parts, next * sizeof(*grown));
        if (grown == NULL) return -1;
        session->parts = grown;
        session->parts_cap = next;
    }
    session->parts[session->parts_len].number = number;
    media_copy(session->parts[session->parts_len].etag,
               sizeof(session->parts[session->parts_len].etag), etag);
    ++session->parts_len;
    return 0;
}

static int media_flush_part(st_media_capture_session *session)
{
    if (session->part_len == 0U) return 0;
    char etag[512];
    int number = (int)session->parts_len + 1;
    if (media_s3_upload_part(session, number, session->part_buffer, session->part_len, etag) != 0
        || media_add_part(session, number, etag) != 0) return -1;
    session->part_len = 0U;
    return 0;
}

/*
 * Java HttpMediaCaptureService.isReusableCapture over (state, captured_bytes, content_range_start,
 * content_range_end, expires_at) at column offset: a capture still in flight always covers the
 * request; a complete one only while it holds exactly the requested range and has not expired.
 */
static int media_row_reusable(sqlite3_stmt *stmt, int offset,
                              const st_media_capture_session *session, const char *now_text)
{
    const char *state = (const char *)sqlite3_column_text(stmt, offset);
    if (state == NULL) return 0;
    if (strcmp(state, "STARTING") == 0 || strcmp(state, "CAPTURING") == 0) return 1;
    const char *expires = (const char *)sqlite3_column_text(stmt, offset + 4);
    return strcmp(state, "COMPLETE") == 0
        && sqlite3_column_int64(stmt, offset + 1) == session->expected_bytes
        && sqlite3_column_type(stmt, offset + 2) != SQLITE_NULL
        && sqlite3_column_int64(stmt, offset + 2) == session->range_start
        && sqlite3_column_type(stmt, offset + 3) != SQLITE_NULL
        && sqlite3_column_int64(stmt, offset + 3) == session->range_end
        && expires != NULL && strcmp(expires, now_text) > 0;
}

/*
 * Java HttpMediaCaptureService.hasReusableCapture: 1 when a capture already holds (or is still
 * receiving) this exact range, 0 when this response must be stored, -1 on a database error. A
 * keyed row that no longer qualifies gives up its deduplication key so the new row can take it.
 */
static int media_db_find_reusable(sqlite3 *db, const st_media_capture_session *session,
                                  const char *dedup_key, const char *resource_key,
                                  const char *now_text)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT id,state,captured_bytes,content_range_start,content_range_end,expires_at "
        "FROM specus_http_media_capture WHERE tenant_id=? AND deduplication_key=? LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, session->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, dedup_key, -1, SQLITE_TRANSIENT);
    int step = sqlite3_step(stmt);
    long long keyed_id = 0;
    int reusable = 0;
    if (step == SQLITE_ROW) {
        keyed_id = sqlite3_column_int64(stmt, 0);
        reusable = media_row_reusable(stmt, 1, session, now_text);
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_ROW && step != SQLITE_DONE) return -1;
    if (reusable) return 1;
    if (keyed_id > 0) {
        stmt = NULL;
        if (sqlite3_prepare_v2(db,
            "UPDATE specus_http_media_capture SET deduplication_key=NULL WHERE id=?",
            -1, &stmt, NULL) != SQLITE_OK) return -1;
        sqlite3_bind_int64(stmt, 1, keyed_id);
        step = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        if (step != SQLITE_DONE) return -1;
    }
    stmt = NULL;
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM specus_http_media_capture WHERE tenant_id=? AND resource_key=? "
        "AND media_kind=? AND content_range_start IS ? AND content_range_end IS ? "
        "AND total_bytes IS ? AND captured_bytes=? AND content_encoding IS ? "
        "AND state='COMPLETE' AND expires_at>? LIMIT 1",
        -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, session->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, resource_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, session->media_kind, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, session->range_start);
    sqlite3_bind_int64(stmt, 5, session->range_end);
    if (session->has_total_bytes) sqlite3_bind_int64(stmt, 6, session->total_bytes);
    else sqlite3_bind_null(stmt, 6);
    sqlite3_bind_int64(stmt, 7, session->expected_bytes);
    if (session->content_encoding[0] != '\0')
        sqlite3_bind_text(stmt, 8, session->content_encoding, -1, SQLITE_TRANSIENT);
    else sqlite3_bind_null(stmt, 8);
    sqlite3_bind_text(stmt, 9, now_text, -1, SQLITE_TRANSIENT);
    step = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return step == SQLITE_ROW ? 1 : (step == SQLITE_DONE ? 0 : -1);
}

/* Java normalizeMethod: trimmed, upper case, at most 16 characters, GET when absent. */
static void media_normalize_method(const char *method, char out[17])
{
    const char *start = method == NULL ? "GET" : method;
    size_t len = strlen(start);
    media_trim_bounds(&start, &len);
    if (len > 16U) len = 16U;
    for (size_t i = 0; i < len; ++i) out[i] = (char)toupper((unsigned char)start[i]);
    out[len] = '\0';
}

static int media_has_text(const char *value)
{
    if (value == NULL) return 0;
    for (; *value != '\0'; ++value) {
        if ((unsigned char)*value > ' ') return 1;
    }
    return 0;
}

st_media_capture_session *st_media_capture_open(const char *database_path,
                                                const char *client_name,
                                                const char *route,
                                                const char *method,
                                                const char *source_url,
                                                int status_code,
                                                char *const *headers,
                                                size_t headers_len)
{
    if (!g_media_ready || database_path == NULL || client_name == NULL || route == NULL
        || method == NULL || strcasecmp(method, "HEAD") == 0) return NULL;
    st_storage_http_route http_route;
    st_storage_client client;
    if (st_storage_get_http_route_by_client_route(database_path, client_name, route, &http_route) != 0
        || !http_route.enabled || !http_route.media_capture_enabled
        || st_storage_get_client(database_path, http_route.client_id, &client) != 0) return NULL;
    char normalized_source[ST_MEDIA_SOURCE_MAX + 1U];
    media_normalize_source(source_url, normalized_source);
    char *content_type = media_header_value(headers, headers_len, "Content-Type");
    char *content_encoding = media_header_value(headers, headers_len, "Content-Encoding");
    char *content_range = media_header_value(headers, headers_len, "Content-Range");
    char *content_length = media_header_value(headers, headers_len, "Content-Length");
    char *entity_tag = media_header_value(headers, headers_len, "ETag");
    char *last_modified = media_header_value(headers, headers_len, "Last-Modified");
    const char *kind = media_kind(normalized_source, content_type, status_code, content_range);
    if (kind == NULL) {
        free(content_type); free(content_encoding); free(content_range); free(content_length);
        free(entity_tag); free(last_modified);
        return NULL;
    }
    st_media_capture_session *session = (st_media_capture_session *)calloc(1, sizeof(*session));
    if (session == NULL) goto cleanup;
    session->cfg = media_load_config();
    media_copy(session->database_path, sizeof(session->database_path), database_path);
    media_copy(session->tenant_id, sizeof(session->tenant_id), client.tenant_id);
    session->client_id = client.id;
    media_copy(session->route, sizeof(session->route), route);
    media_copy(session->source_url, sizeof(session->source_url), normalized_source);
    media_copy(session->content_encoding, sizeof(session->content_encoding), content_encoding);
    media_copy(session->media_kind, sizeof(session->media_kind), kind);
    session->manifest = strcmp(kind, "HLS_MANIFEST") == 0 || strcmp(kind, "DASH_MANIFEST") == 0;
    session->expected_bytes = -1;
    if (media_parse_content_range(content_range, &session->range_start, &session->range_end,
                                  &session->total_bytes, &session->has_total_bytes) == 0) {
        session->has_range_start = session->has_range_end = 1;
        session->expected_bytes = session->range_end - session->range_start + 1LL;
    } else {
        session->range_start = 0;
        session->has_range_start = 1;
        if (content_length != NULL) {
            char *end = NULL;
            long long parsed = strtoll(content_length, &end, 10);
            if (end != content_length && *end == '\0' && parsed >= 0) {
                session->expected_bytes = parsed;
                session->total_bytes = parsed;
                session->has_total_bytes = 1;
                session->range_end = parsed - 1LL;
                session->has_range_end = parsed > 0;
            }
        }
    }
    char normalized_method[17];
    media_normalize_method(method, normalized_method);
    /* Java resourceKey: the validator is the ETag, else Last-Modified, else nothing. */
    const char *version = media_has_text(entity_tag) ? entity_tag
        : (media_has_text(last_modified) ? last_modified : "");
    char resource_input[8192];
    snprintf(resource_input, sizeof(resource_input), "%s\n%lld\n%s\n%s\n%s",
             client.tenant_id, client.id, route, normalized_source, version);
    char resource_key[65];
    media_sha256_hex(resource_input, strlen(resource_input), resource_key);
    /* Java deduplicationKey: none for manifests and for a response whose range end is unknown. */
    int deduplicate = !session->manifest && session->has_range_start && session->has_range_end
        && session->range_end >= session->range_start;
    char dedup_key[65];
    dedup_key[0] = '\0';
    if (deduplicate) {
        char encoding_lower[129];
        media_copy(encoding_lower, sizeof(encoding_lower), session->content_encoding);
        for (char *p = encoding_lower; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
        char total_text[32];
        total_text[0] = '\0';
        if (session->has_total_bytes) snprintf(total_text, sizeof(total_text), "%lld", session->total_bytes);
        char dedup_input[9000];
        snprintf(dedup_input, sizeof(dedup_input), "%s\n%s\n%s\n%lld\n%lld\n%s\n%s",
                 resource_key, normalized_method, kind, session->range_start, session->range_end,
                 total_text, encoding_lower);
        media_sha256_hex(dedup_input, strlen(dedup_input), dedup_key);
    }
    sqlite3 *db = NULL;
    if (media_db_open(database_path, &db) != 0) {
        free(session);
        session = NULL;
        goto cleanup;
    }
    time_t now = time(NULL);
    char now_text[64];
    media_iso_time(now, now_text);
    /*
     * The duplicate check and the insert share one write transaction, so two responses for the same
     * range cannot both pass the check: the later one sees the first one's STARTING/CAPTURING row
     * and becomes the externalized duplicate that Java reaches by catching the unique-key violation.
     */
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        free(session);
        session = NULL;
        goto cleanup;
    }
    if (deduplicate) {
        int reusable = media_db_find_reusable(db, session, dedup_key, resource_key, now_text);
        if (reusable != 0) {
            (void)sqlite3_exec(db, reusable > 0 ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
            sqlite3_close(db);
            if (reusable < 0) {
                free(session);
                session = NULL;
            } else {
                session->terminal = 1;
                session->duplicate = 1;
            }
            goto cleanup;
        }
    }
    unsigned char random[16];
    if (RAND_bytes(random, sizeof(random)) != 1) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        free(session);
        session = NULL;
        goto cleanup;
    }
    char random_hex[33];
    media_hex(random, sizeof(random), random_hex);
    struct tm utc;
    gmtime_r(&now, &utc);
    char date[32], safe_tenant[128], safe_route[256];
    strftime(date, sizeof(date), "%Y/%m/%d", &utc);
    media_safe_segment(client.tenant_id, safe_tenant, sizeof(safe_tenant));
    media_safe_segment(route, safe_route, sizeof(safe_route));
    char prefix[256];
    media_copy(prefix, sizeof(prefix), session->cfg.object_prefix);
    size_t prefix_len = strlen(prefix);
    while (prefix_len > 0U && prefix[prefix_len - 1U] == '/') prefix[--prefix_len] = '\0';
    const char *prefix_start = prefix;
    while (*prefix_start == '/') ++prefix_start;
    snprintf(session->object_key, sizeof(session->object_key), "%s%s%s/%s/%s/%s%s",
             prefix_start, *prefix_start == '\0' ? "" : "/", safe_tenant, date, safe_route,
             random_hex, media_extension(normalized_source));
    char captured_at[64], expires_at[64];
    media_iso_time(now, captured_at);
    media_iso_time(now + session->cfg.retention_seconds, expires_at);
    long long segment_sequence = 0;
    int has_segment_sequence = media_infer_sequence(normalized_source, &segment_sequence) == 0;
    char *response_headers = media_join_headers(headers, headers_len);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO specus_http_media_capture(tenant_id,client_id,client_name,route,resource_id,"
        "source_url,resource_key,deduplication_key,method,status_code,content_type,content_encoding,media_kind,"
        "entity_tag,last_modified,content_range_start,content_range_end,total_bytes,captured_bytes,"
        "segment_sequence,initialization_segment,live_stream,object_key,state,response_headers,captured_at,expires_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?,0,?,'STARTING',?,?,?)";
    int insert_ok = response_headers != NULL && sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK;
    if (insert_ok) {
        int index = 1;
        sqlite3_bind_text(stmt, index++, client.tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, index++, client.id);
        sqlite3_bind_text(stmt, index++, client.client_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, index++, http_route.id);
        sqlite3_bind_text(stmt, index++, normalized_source, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, resource_key, -1, SQLITE_TRANSIENT);
        if (deduplicate) sqlite3_bind_text(stmt, index++, dedup_key, -1, SQLITE_TRANSIENT);
        else sqlite3_bind_null(stmt, index++);
        sqlite3_bind_text(stmt, index++, normalized_method, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, index++, status_code);
        if (content_type == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, content_type, -1, SQLITE_TRANSIENT);
        if (content_encoding == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, session->content_encoding, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, kind, -1, SQLITE_TRANSIENT);
        if (entity_tag == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, entity_tag, -1, SQLITE_TRANSIENT);
        if (last_modified == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, last_modified, -1, SQLITE_TRANSIENT);
        if (session->has_range_start) sqlite3_bind_int64(stmt, index++, session->range_start); else sqlite3_bind_null(stmt, index++);
        if (session->has_range_end) sqlite3_bind_int64(stmt, index++, session->range_end); else sqlite3_bind_null(stmt, index++);
        if (session->has_total_bytes) sqlite3_bind_int64(stmt, index++, session->total_bytes); else sqlite3_bind_null(stmt, index++);
        if (has_segment_sequence) sqlite3_bind_int64(stmt, index++, segment_sequence); else sqlite3_bind_null(stmt, index++);
        sqlite3_bind_int(stmt, index++, media_is_initialization_segment(normalized_source));
        sqlite3_bind_text(stmt, index++, session->object_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, response_headers, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, captured_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, expires_at, -1, SQLITE_TRANSIENT);
        insert_ok = sqlite3_step(stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    free(response_headers);
    if (insert_ok) session->id = sqlite3_last_insert_rowid(db);
    if (!insert_ok || sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        sqlite3_close(db);
        free(session);
        session = NULL;
        goto cleanup;
    }
    sqlite3_close(db);
    if (media_s3_begin(&session->cfg, session->object_key, content_type, content_encoding,
                       session->upload_id) != 0) {
        media_db_mark_failed(session, "RustFS multipart upload initialization failed");
        free(session);
        session = NULL;
        goto cleanup;
    }
    if (media_db_open(database_path, &db) != 0) {
        (void)media_s3_abort(session);
        free(session);
        session = NULL;
        goto cleanup;
    }
    stmt = NULL;
    int update_ok = sqlite3_prepare_v2(db,
        "UPDATE specus_http_media_capture SET state='CAPTURING',upload_id=? WHERE id=? AND tenant_id=?",
        -1, &stmt, NULL) == SQLITE_OK;
    if (update_ok) {
        sqlite3_bind_text(stmt, 1, session->upload_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, session->id);
        sqlite3_bind_text(stmt, 3, session->tenant_id, -1, SQLITE_TRANSIENT);
        update_ok = sqlite3_step(stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (!update_ok) {
        (void)media_s3_abort(session);
        media_db_mark_failed(session, "media capture state update failed");
        free(session);
        session = NULL;
        goto cleanup;
    }
    session->part_buffer = (uint8_t *)malloc(session->cfg.part_size);
    if (session->part_buffer == NULL) {
        (void)media_s3_abort(session);
        media_db_mark_failed(session, "media capture buffer allocation failed");
        free(session);
        session = NULL;
        goto cleanup;
    }
    if (session->manifest) {
        session->manifest_buffer = (uint8_t *)malloc(session->cfg.manifest_max_bytes + 1U);
        if (session->manifest_buffer == NULL) session->manifest_dropped = 1;
    }
cleanup:
    free(content_type); free(content_encoding); free(content_range); free(content_length);
    free(entity_tag); free(last_modified);
    return session;
}

int st_media_capture_append(st_media_capture_session *session,
                            const uint8_t *data,
                            size_t data_len)
{
    if (session == NULL || session->terminal || session->failed || data == NULL || data_len == 0U) return 0;
    if (data_len > (size_t)(LLONG_MAX - session->captured_bytes)) return -1;
    if (session->manifest && !session->manifest_dropped) {
        if (data_len <= session->cfg.manifest_max_bytes - session->manifest_len) {
            memcpy(session->manifest_buffer + session->manifest_len, data, data_len);
            session->manifest_len += data_len;
            session->manifest_buffer[session->manifest_len] = '\0';
        } else {
            session->manifest_len = 0U;
            session->manifest_dropped = 1;
        }
    }
    session->captured_bytes += (long long)data_len;
    while (data_len > 0U) {
        size_t available = session->cfg.part_size - session->part_len;
        size_t copy = data_len < available ? data_len : available;
        memcpy(session->part_buffer + session->part_len, data, copy);
        session->part_len += copy;
        data += copy;
        data_len -= copy;
        if (session->part_len == session->cfg.part_size && media_flush_part(session) != 0) {
            session->failed = 1;
            return -1;
        }
    }
    return 0;
}

static void media_record_manifest(st_media_capture_session *session);

static void media_finish(st_media_capture_session *session, int accept_partial, const char *reason)
{
    if (session == NULL || session->terminal) return;
    session->terminal = 1;
    if (session->failed || session->captured_bytes == 0LL || media_flush_part(session) != 0) {
        (void)media_s3_abort(session);
        media_db_mark_failed(session, session->captured_bytes == 0LL ? "媒体响应正文为空" : "RustFS part upload failed");
        return;
    }
    char object_etag[512];
    if (media_s3_complete(session, object_etag) != 0) {
        (void)media_s3_abort(session);
        media_db_mark_failed(session, "RustFS multipart upload completion failed");
        return;
    }
    int retained_partial = accept_partial && !session->manifest && session->expected_bytes >= 0
        && session->captured_bytes != session->expected_bytes;
    int complete = retained_partial || session->expected_bytes < 0
        || session->captured_bytes == session->expected_bytes;
    sqlite3 *db = NULL;
    if (media_db_open(session->database_path, &db) != 0) return;
    sqlite3_stmt *stmt = NULL;
    /*
     * Java markComplete: a response cut short keeps only the bytes that arrived, so its range ends
     * at the last received byte rather than at the end the Content-Range announced.
     */
    const char *sql = "UPDATE specus_http_media_capture SET state=?,deduplication_key=CASE WHEN ? THEN deduplication_key ELSE NULL END,failure_reason=?,"
        "captured_bytes=?,content_range_end=CASE WHEN ? THEN content_range_start+?-1 "
        "ELSE COALESCE(content_range_end,content_range_start+?-1) END,"
        "total_bytes=CASE WHEN total_bytes IS NULL AND content_range_start=0 AND ? THEN ? ELSE total_bytes END,"
        "upload_id=NULL,object_etag=?,completed_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') "
        "WHERE id=? AND tenant_id=?";
    int updated = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, complete ? "COMPLETE" : "INCOMPLETE", -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 2, complete && !retained_partial ? 1 : 0);
        if (complete) sqlite3_bind_null(stmt, 3);
        else {
            char message[256];
            snprintf(message, sizeof(message), "响应正文长度不完整，预期 %lld 字节，实际 %lld 字节",
                     session->expected_bytes, session->captured_bytes);
            sqlite3_bind_text(stmt, 3, message, -1, SQLITE_TRANSIENT);
        }
        sqlite3_bind_int64(stmt, 4, session->captured_bytes);
        sqlite3_bind_int(stmt, 5, retained_partial ? 1 : 0);
        sqlite3_bind_int64(stmt, 6, session->captured_bytes);
        sqlite3_bind_int64(stmt, 7, session->captured_bytes);
        sqlite3_bind_int(stmt, 8, complete ? 1 : 0);
        sqlite3_bind_int64(stmt, 9, session->captured_bytes);
        sqlite3_bind_text(stmt, 10, object_etag, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 11, session->id);
        sqlite3_bind_text(stmt, 12, session->tenant_id, -1, SQLITE_TRANSIENT);
        updated = sqlite3_step(stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (updated && complete && session->manifest && !session->manifest_dropped
        && session->manifest_buffer != NULL) {
        media_record_manifest(session);
    }
    (void)reason;
}

void st_media_capture_complete(st_media_capture_session *session)
{
    media_finish(session, 0, NULL);
}

void st_media_capture_fail(st_media_capture_session *session, const char *reason)
{
    if (session == NULL || session->terminal) return;
    if (!session->manifest && session->captured_bytes > 0LL) {
        media_finish(session, 1, reason);
        return;
    }
    session->terminal = 1;
    (void)media_s3_abort(session);
    media_db_mark_failed(session, reason);
}

/* Java CaptureSession.externalized(): an active capture, or a duplicate of a stored range. */
int st_media_capture_externalized(const st_media_capture_session *session)
{
    return session != NULL && (session->duplicate || !session->terminal);
}

int st_media_capture_active(const st_media_capture_session *session)
{
    return session != NULL && !session->duplicate && !session->terminal;
}

void st_media_capture_free(st_media_capture_session *session)
{
    if (session == NULL) return;
    if (!session->terminal) st_media_capture_fail(session, "媒体响应中断");
    free(session->part_buffer);
    free(session->manifest_buffer);
    free(session->parts);
    free(session);
}

typedef struct {
    long long id;
    char tenant_id[64];
    long long client_id;
    char client_name[256];
    char route[128];
    long long resource_id;
    int has_resource_id;
    char source_url[3073];
    char resource_key[65];
    char method[17];
    int status_code;
    char content_type[256];
    char content_encoding[128];
    char media_kind[32];
    char entity_tag[513];
    long long range_start;
    long long range_end;
    long long total_bytes;
    int has_range_start;
    int has_range_end;
    int has_total_bytes;
    long long captured_bytes;
    long long segment_sequence;
    int has_segment_sequence;
    int initialization_segment;
    int live_stream;
    char object_key[1024];
    char object_etag[513];
    char state[32];
    char failure_reason[2049];
    char captured_at[64];
    char completed_at[64];
    char expires_at[64];
} st_media_capture_row;

typedef struct st_media_ticket {
    char token[65];
    char tenant_id[64];
    long long capture_id;
    time_t expires_at;
    int backfill_missing;
    struct st_media_ticket *next;
} st_media_ticket;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} st_media_builder;

typedef struct {
    char object_key[1024];
    long long start;
    long long end;
    long long total;
    int has_total;
} st_media_playback_part;

static pthread_mutex_t g_media_ticket_lock = PTHREAD_MUTEX_INITIALIZER;
static st_media_ticket *g_media_tickets;

static int media_builder_reserve(st_media_builder *builder, size_t extra)
{
    if (extra > SIZE_MAX - builder->len - 1U) return -1;
    size_t required = builder->len + extra + 1U;
    if (required <= builder->cap) return 0;
    size_t next = builder->cap == 0U ? 1024U : builder->cap;
    while (next < required) {
        if (next > SIZE_MAX / 2U) return -1;
        next *= 2U;
    }
    char *grown = (char *)realloc(builder->data, next);
    if (grown == NULL) return -1;
    builder->data = grown;
    builder->cap = next;
    return 0;
}

static int media_builder_append_len(st_media_builder *builder, const char *value, size_t value_len)
{
    if (media_builder_reserve(builder, value_len) != 0) return -1;
    memcpy(builder->data + builder->len, value, value_len);
    builder->len += value_len;
    builder->data[builder->len] = '\0';
    return 0;
}

static int media_builder_append(st_media_builder *builder, const char *value)
{
    return media_builder_append_len(builder, value, strlen(value));
}

static int media_builder_appendf(st_media_builder *builder, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || media_builder_reserve(builder, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    vsnprintf(builder->data + builder->len, builder->cap - builder->len, format, args);
    va_end(args);
    builder->len += (size_t)needed;
    return 0;
}

static int media_builder_json_string(st_media_builder *builder, const char *value)
{
    char *escaped = st_json_escape(value == NULL ? "" : value);
    if (escaped == NULL) return -1;
    int rc = media_builder_appendf(builder, "\"%s\"", escaped);
    free(escaped);
    return rc;
}

static int media_builder_nullable_string(st_media_builder *builder, const char *value)
{
    return value == NULL || *value == '\0'
        ? media_builder_append(builder, "null")
        : media_builder_json_string(builder, value);
}

static const char *media_reason(int status)
{
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 206: return "Partial Content";
        case 302: return "Found";
        case 307: return "Temporary Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 409: return "Conflict";
        case 416: return "Range Not Satisfiable";
        case 503: return "Service Unavailable";
        default: return "Internal Server Error";
    }
}

static int media_write_response(char *out, size_t out_len, int status,
                                const char *content_type,
                                const char *extra_headers,
                                const void *body, size_t body_len,
                                int include_body)
{
    int header_len = snprintf(out, out_len,
        "HTTP/1.1 %d %s\r\nContent-Type: %s\r\nCache-Control: private, no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n%sContent-Length: %zu\r\n\r\n",
        status, media_reason(status), content_type == NULL ? "application/json" : content_type,
        extra_headers == NULL ? "" : extra_headers, body_len);
    if (header_len < 0 || (size_t)header_len >= out_len
        || (include_body && body_len > out_len - (size_t)header_len)) return -1;
    if (include_body && body_len > 0U) memcpy(out + header_len, body, body_len);
    size_t response_len = (size_t)header_len + (include_body ? body_len : 0U);
    if (response_len < out_len) out[response_len] = '\0';
    return (int)response_len;
}

static int media_write_json_error(char *out, size_t out_len, int status, const char *message)
{
    st_media_builder body = {0};
    int rc = media_builder_append(&body, "{\"error\":") == 0
        && media_builder_json_string(&body, message) == 0
        && media_builder_append(&body, "}") == 0
        ? media_write_response(out, out_len, status, "application/json", NULL,
                               body.data, body.len, 1)
        : -1;
    free(body.data);
    return rc;
}

static void media_row_text(sqlite3_stmt *stmt, int column, char *out, size_t out_len)
{
    const char *value = (const char *)sqlite3_column_text(stmt, column);
    media_copy(out, out_len, value == NULL ? "" : value);
}

static int media_scan_row(sqlite3_stmt *stmt, st_media_capture_row *row)
{
    memset(row, 0, sizeof(*row));
    row->id = sqlite3_column_int64(stmt, 0);
    media_row_text(stmt, 1, row->tenant_id, sizeof(row->tenant_id));
    row->client_id = sqlite3_column_int64(stmt, 2);
    media_row_text(stmt, 3, row->client_name, sizeof(row->client_name));
    media_row_text(stmt, 4, row->route, sizeof(row->route));
    row->has_resource_id = sqlite3_column_type(stmt, 5) != SQLITE_NULL;
    row->resource_id = row->has_resource_id ? sqlite3_column_int64(stmt, 5) : 0;
    media_row_text(stmt, 6, row->source_url, sizeof(row->source_url));
    media_row_text(stmt, 7, row->resource_key, sizeof(row->resource_key));
    media_row_text(stmt, 8, row->method, sizeof(row->method));
    row->status_code = sqlite3_column_int(stmt, 9);
    media_row_text(stmt, 10, row->content_type, sizeof(row->content_type));
    media_row_text(stmt, 11, row->content_encoding, sizeof(row->content_encoding));
    media_row_text(stmt, 12, row->media_kind, sizeof(row->media_kind));
    media_row_text(stmt, 13, row->entity_tag, sizeof(row->entity_tag));
    row->has_range_start = sqlite3_column_type(stmt, 14) != SQLITE_NULL;
    row->range_start = row->has_range_start ? sqlite3_column_int64(stmt, 14) : 0;
    row->has_range_end = sqlite3_column_type(stmt, 15) != SQLITE_NULL;
    row->range_end = row->has_range_end ? sqlite3_column_int64(stmt, 15) : 0;
    row->has_total_bytes = sqlite3_column_type(stmt, 16) != SQLITE_NULL;
    row->total_bytes = row->has_total_bytes ? sqlite3_column_int64(stmt, 16) : 0;
    row->captured_bytes = sqlite3_column_int64(stmt, 17);
    row->has_segment_sequence = sqlite3_column_type(stmt, 18) != SQLITE_NULL;
    row->segment_sequence = row->has_segment_sequence ? sqlite3_column_int64(stmt, 18) : 0;
    row->initialization_segment = sqlite3_column_int(stmt, 19) != 0;
    row->live_stream = sqlite3_column_int(stmt, 20) != 0;
    media_row_text(stmt, 21, row->object_key, sizeof(row->object_key));
    media_row_text(stmt, 22, row->object_etag, sizeof(row->object_etag));
    media_row_text(stmt, 23, row->state, sizeof(row->state));
    media_row_text(stmt, 24, row->failure_reason, sizeof(row->failure_reason));
    media_row_text(stmt, 25, row->captured_at, sizeof(row->captured_at));
    media_row_text(stmt, 26, row->completed_at, sizeof(row->completed_at));
    media_row_text(stmt, 27, row->expires_at, sizeof(row->expires_at));
    return 0;
}

static const char *media_row_columns(void)
{
    return "m.id,m.tenant_id,m.client_id,m.client_name,m.route,m.resource_id,m.source_url,"
        "m.resource_key,m.method,m.status_code,m.content_type,m.content_encoding,m.media_kind,"
        "m.entity_tag,m.content_range_start,m.content_range_end,m.total_bytes,m.captured_bytes,"
        "m.segment_sequence,m.initialization_segment,m.live_stream,m.object_key,m.object_etag,"
        "m.state,m.failure_reason,m.captured_at,m.completed_at,m.expires_at";
}

static int media_load_row(sqlite3 *db, const char *tenant_id, long long id,
                          st_media_capture_row *row)
{
    char sql[2048];
    snprintf(sql, sizeof(sql), "SELECT %s FROM specus_http_media_capture m WHERE m.id=? AND m.tenant_id=?",
             media_row_columns());
    sqlite3_stmt *stmt = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        sqlite3_bind_text(stmt, 2, tenant_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            media_scan_row(stmt, row);
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found ? 0 : -1;
}

static int media_identity_can_access(sqlite3 *db,
                                     const st_media_capture_identity *identity,
                                     const st_media_capture_row *row)
{
    if (identity == NULL || !identity->authenticated || identity->tenant_id == NULL
        || strcmp(identity->tenant_id, row->tenant_id) != 0) return 0;
    if (identity->admin) return 1;
    sqlite3_stmt *stmt = NULL;
    int allowed = 0;
    if (sqlite3_prepare_v2(db,
        "SELECT 1 FROM client_account WHERE rowid=? AND tenant_id=? AND owner_username=? LIMIT 1",
        -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, row->client_id);
        sqlite3_bind_text(stmt, 2, row->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, identity->username == NULL ? "" : identity->username, -1, SQLITE_TRANSIENT);
        allowed = sqlite3_step(stmt) == SQLITE_ROW;
    }
    sqlite3_finalize(stmt);
    return allowed;
}

static char *media_query_value(const char *path, const char *name)
{
    const char *query = strchr(path, '?');
    if (query == NULL) return NULL;
    ++query;
    size_t name_len = strlen(name);
    while (*query != '\0') {
        const char *end = strchr(query, '&');
        if (end == NULL) end = query + strlen(query);
        const char *equals = memchr(query, '=', (size_t)(end - query));
        if (equals != NULL && (size_t)(equals - query) == name_len
            && strncmp(query, name, name_len) == 0) {
            size_t len = (size_t)(end - equals - 1);
            char *value = (char *)malloc(len + 1U);
            if (value == NULL) return NULL;
            size_t offset = 0;
            for (size_t i = 0; i < len; ++i) {
                unsigned char ch = (unsigned char)equals[1 + i];
                if (ch == '+' ) value[offset++] = ' ';
                else if (ch == '%' && i + 2U < len && isxdigit((unsigned char)equals[2 + i])
                         && isxdigit((unsigned char)equals[3 + i])) {
                    char hex[3] = {equals[2 + i], equals[3 + i], '\0'};
                    value[offset++] = (char)strtoul(hex, NULL, 16);
                    i += 2U;
                } else value[offset++] = (char)ch;
            }
            value[offset] = '\0';
            return value;
        }
        query = *end == '\0' ? end : end + 1;
    }
    return NULL;
}

static long long media_query_i64(const char *path, const char *name, long long fallback)
{
    char *value = media_query_value(path, name);
    if (value == NULL) return fallback;
    char *end = NULL;
    long long result = strtoll(value, &end, 10);
    if (end == value || *end != '\0') result = fallback;
    free(value);
    return result;
}

static int media_query_bool(const char *path, const char *name, int fallback)
{
    char *value = media_query_value(path, name);
    if (value == NULL) return fallback;
    int result = strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0;
    free(value);
    return result;
}

static int media_is_redacted_parameter(const char *name, size_t *name_len)
{
    static const char *names[] = {
        "api_key", "apikey", "access_token", "auth_token", "token", "x-emby-token"
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t len = strlen(names[i]);
        if (strncasecmp(name, names[i], len) == 0 && name[len] == '=') {
            *name_len = len;
            return 1;
        }
    }
    return 0;
}

/*
 * Java HttpMediaCaptureService.redactSourceUrl: the value of every api_key/apikey/access_token/
 * auth_token/token/x-emby-token parameter becomes "***", up to the next '&' or '#'.
 */
static void media_redact_source(const char *source, char out[ST_MEDIA_SOURCE_MAX + 1U])
{
    size_t used = 0U;
    out[0] = '\0';
    const char *cursor = source == NULL ? "" : source;
    while (*cursor != '\0') {
        size_t name_len = 0U;
        if ((*cursor == '?' || *cursor == '&')
            && media_is_redacted_parameter(cursor + 1, &name_len)) {
            media_source_append(out, &used, cursor, name_len + 2U);
            media_source_append(out, &used, "***", 3U);
            cursor += name_len + 2U;
            while (*cursor != '\0' && *cursor != '&' && *cursor != '#') ++cursor;
            continue;
        }
        media_source_append(out, &used, cursor, 1U);
        ++cursor;
    }
}

typedef struct {
    st_media_playback_part *items;
    size_t len;
    /* Java HttpMediaPlaybackService.totalBytes: the largest stated total, else the furthest end. */
    long long total;
} st_media_playback_parts;

typedef struct {
    long long start;
    long long end;
} st_media_byte_range;

/*
 * The complete, unexpired captures of the anchor's resource that hold bytes (Java usableCaptures),
 * newest first. Returns 0 with possibly no parts, -1 when the database cannot be read.
 */
static int media_load_playback_parts(sqlite3 *db,
                                     const st_media_capture_row *anchor,
                                     st_media_playback_parts *out)
{
    memset(out, 0, sizeof(*out));
    const char *sql =
        "SELECT object_key,content_range_start,content_range_end,total_bytes,captured_bytes "
        "FROM specus_http_media_capture WHERE tenant_id=? AND client_id=? AND resource_key=? "
        "AND state='COMPLETE' AND captured_bytes>0 "
        "AND (expires_at IS NULL OR expires_at>strftime('%Y-%m-%dT%H:%M:%SZ','now')) "
        "ORDER BY id DESC LIMIT ?";
    sqlite3_stmt *stmt = NULL;
    st_media_playback_part *parts = NULL;
    size_t len = 0U;
    long long stated_total = 0;
    long long furthest = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, anchor->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, anchor->client_id);
    sqlite3_bind_text(stmt, 3, anchor->resource_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)ST_MEDIA_MAX_PLAYBACK_PARTS);
    int step;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        long long captured = sqlite3_column_int64(stmt, 4);
        long long start = sqlite3_column_type(stmt, 1) == SQLITE_NULL
            ? 0 : sqlite3_column_int64(stmt, 1);
        const char *object_key = (const char *)sqlite3_column_text(stmt, 0);
        if (captured <= 0 || start < 0 || captured - 1LL > LLONG_MAX - start
            || object_key == NULL || *object_key == '\0') continue;
        long long end = start + captured - 1LL;
        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            long long declared_end = sqlite3_column_int64(stmt, 2);
            if (declared_end < start) continue;
            if (declared_end < end) end = declared_end;
        }
        st_media_playback_part *grown = (st_media_playback_part *)realloc(
            parts, (len + 1U) * sizeof(*parts));
        if (grown == NULL) {
            free(parts);
            sqlite3_finalize(stmt);
            return -1;
        }
        parts = grown;
        memset(&parts[len], 0, sizeof(parts[len]));
        media_copy(parts[len].object_key, sizeof(parts[len].object_key), object_key);
        parts[len].start = start;
        parts[len].end = end;
        if (sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            parts[len].total = sqlite3_column_int64(stmt, 3);
            parts[len].has_total = parts[len].total > 0;
            if (parts[len].has_total && parts[len].total > stated_total) stated_total = parts[len].total;
        }
        if (end < LLONG_MAX && end + 1LL > furthest) furthest = end + 1LL;
        ++len;
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE) {
        free(parts);
        return -1;
    }
    out->items = parts;
    out->len = len;
    out->total = stated_total > 0 ? stated_total : furthest;
    return 0;
}

/* The end of the part that covers offset and reaches furthest, or -1 when no part covers it. */
static long long media_parts_furthest_end(const st_media_playback_parts *parts, long long offset)
{
    long long selected = -1;
    for (size_t i = 0; i < parts->len; ++i) {
        if (parts->items[i].start <= offset && parts->items[i].end >= offset
            && parts->items[i].end > selected) selected = parts->items[i].end;
    }
    return selected;
}

/* Java HttpMediaPlaybackService.evaluateCoverage: 1 when every byte is cached, else 0 and why. */
static int media_parts_coverage(const st_media_playback_parts *parts, char *reason, size_t reason_len)
{
    if (parts->len == 0U) {
        media_copy(reason, reason_len, "媒体采集没有可回放的数据");
        return 0;
    }
    if (parts->total <= 0) {
        media_copy(reason, reason_len, "媒体总长度未知");
        return 0;
    }
    long long cursor = 0;
    while (cursor < parts->total) {
        long long selected = media_parts_furthest_end(parts, cursor);
        if (selected < cursor) {
            snprintf(reason, reason_len, "采集数据不完整，缺少字节 %lld", cursor);
            return 0;
        }
        if (selected >= parts->total - 1LL) break;
        cursor = selected + 1LL;
    }
    if (reason_len > 0U) reason[0] = '\0';
    return 1;
}

static int media_byte_range_compare(const void *left, const void *right)
{
    const st_media_byte_range *a = (const st_media_byte_range *)left;
    const st_media_byte_range *b = (const st_media_byte_range *)right;
    if (a->start != b->start) return a->start < b->start ? -1 : 1;
    if (a->end != b->end) return a->end < b->end ? -1 : 1;
    return 0;
}

/* Java mergeAvailableRanges: cached ranges inside the total, adjacent ones joined, in order. */
static int media_parts_merged_ranges(const st_media_playback_parts *parts,
                                     st_media_byte_range **out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0U;
    if (parts->total <= 0 || parts->len == 0U) return 0;
    st_media_byte_range *ranges = (st_media_byte_range *)calloc(parts->len, sizeof(*ranges));
    if (ranges == NULL) return -1;
    size_t len = 0U;
    for (size_t i = 0; i < parts->len; ++i) {
        long long start = parts->items[i].start < 0 ? 0 : parts->items[i].start;
        long long end = parts->items[i].end > parts->total - 1LL
            ? parts->total - 1LL : parts->items[i].end;
        if (end < start) continue;
        ranges[len].start = start;
        ranges[len].end = end;
        ++len;
    }
    qsort(ranges, len, sizeof(*ranges), media_byte_range_compare);
    size_t merged = 0U;
    for (size_t i = 0; i < len; ++i) {
        if (merged > 0U && ranges[i].start <= ranges[merged - 1U].end + 1LL) {
            if (ranges[i].end > ranges[merged - 1U].end) ranges[merged - 1U].end = ranges[i].end;
        } else {
            ranges[merged++] = ranges[i];
        }
    }
    if (merged == 0U) {
        free(ranges);
        return 0;
    }
    *out = ranges;
    *out_len = merged;
    return 0;
}

static int media_kind_is_manifest(const char *kind)
{
    return strcmp(kind, "HLS_MANIFEST") == 0 || strcmp(kind, "DASH_MANIFEST") == 0;
}

/* Java HttpMediaCaptureService.playbackStatus behind playable, offlineReady and playbackMessage. */
static void media_playback_status(sqlite3 *db, const st_media_capture_row *row,
                                  int *playable, int *offline_ready,
                                  char *message, size_t message_len)
{
    *playable = 0;
    *offline_ready = 0;
    message[0] = '\0';
    if (strcmp(row->state, "COMPLETE") != 0) {
        media_copy(message, message_len, "媒体采集尚未完成");
        return;
    }
    if (strcmp(row->media_kind, "MEDIA_SEGMENT") == 0 || row->initialization_segment) {
        *offline_ready = 1;
        media_copy(message, message_len, "媒体分段由 HLS/DASH 清单播放器按需加载");
        return;
    }
    if (media_kind_is_manifest(row->media_kind)) {
        *playable = row->captured_bytes > 0;
        media_copy(message, message_len, *playable ? "仅播放已缓存的媒体分段" : "媒体清单正文为空");
        return;
    }
    st_media_playback_parts parts;
    char reason[160];
    int covered = 0;
    if (media_load_playback_parts(db, row, &parts) == 0) {
        covered = media_parts_coverage(&parts, reason, sizeof(reason));
        free(parts.items);
    } else {
        media_copy(reason, sizeof(reason), "媒体采集没有可回放的数据");
    }
    if (covered) {
        *playable = 1;
        *offline_ready = 1;
    } else if (row->captured_bytes > 0) {
        *playable = 1;
        snprintf(message, message_len, "%s；仅可播放已缓存区间", reason);
    } else {
        media_copy(message, message_len, reason);
    }
}

static int media_append_optional_i64(st_media_builder *body, int present, long long value)
{
    return present ? media_builder_appendf(body, "%lld", value) : media_builder_append(body, "null");
}

static int media_append_capture_view(sqlite3 *db, st_media_builder *body,
                                     const st_media_capture_row *row)
{
    char source[ST_MEDIA_SOURCE_MAX + 1U];
    media_redact_source(row->source_url, source);
    int playable = 0, offline_ready = 0;
    char message[256];
    media_playback_status(db, row, &playable, &offline_ready, message, sizeof(message));
    int rc = media_builder_appendf(body, "{\"id\":%lld,\"clientId\":%lld,\"clientName\":",
                                   row->id, row->client_id);
    if (rc == 0) rc = media_builder_json_string(body, row->client_name);
    if (rc == 0) rc = media_builder_append(body, ",\"route\":");
    if (rc == 0) rc = media_builder_json_string(body, row->route);
    if (rc == 0) rc = media_builder_append(body, ",\"resourceId\":");
    if (rc == 0) rc = media_append_optional_i64(body, row->has_resource_id, row->resource_id);
    if (rc == 0) rc = media_builder_append(body, ",\"sourceUrl\":");
    if (rc == 0) rc = media_builder_json_string(body, source);
    if (rc == 0) rc = media_builder_append(body, ",\"method\":");
    if (rc == 0) rc = media_builder_json_string(body, row->method);
    if (rc == 0) rc = media_builder_appendf(body, ",\"statusCode\":%d,\"contentType\":", row->status_code);
    if (rc == 0) rc = media_builder_nullable_string(body, row->content_type);
    if (rc == 0) rc = media_builder_append(body, ",\"mediaKind\":");
    if (rc == 0) rc = media_builder_json_string(body, row->media_kind);
    if (rc == 0) rc = media_builder_append(body, ",\"entityTag\":");
    if (rc == 0) rc = media_builder_nullable_string(body, row->entity_tag);
    if (rc == 0) rc = media_builder_append(body, ",\"contentRangeStart\":");
    if (rc == 0) rc = media_append_optional_i64(body, row->has_range_start, row->range_start);
    if (rc == 0) rc = media_builder_append(body, ",\"contentRangeEnd\":");
    if (rc == 0) rc = media_append_optional_i64(body, row->has_range_end, row->range_end);
    if (rc == 0) rc = media_builder_append(body, ",\"totalBytes\":");
    if (rc == 0) rc = media_append_optional_i64(body, row->has_total_bytes, row->total_bytes);
    if (rc == 0) rc = media_builder_appendf(body,
        ",\"capturedBytes\":%lld,\"segmentSequence\":", row->captured_bytes);
    if (rc == 0) rc = media_append_optional_i64(body, row->has_segment_sequence, row->segment_sequence);
    if (rc == 0) rc = media_builder_appendf(body,
        ",\"initializationSegment\":%s,\"liveStream\":%s,\"state\":",
        row->initialization_segment ? "true" : "false", row->live_stream ? "true" : "false");
    if (rc == 0) rc = media_builder_json_string(body, row->state);
    if (rc == 0) rc = media_builder_append(body, ",\"failureReason\":");
    if (rc == 0) rc = media_builder_nullable_string(body, row->failure_reason);
    if (rc == 0) rc = media_builder_appendf(body,
        ",\"playable\":%s,\"offlineReady\":%s,\"playbackMessage\":",
        playable ? "true" : "false", offline_ready ? "true" : "false");
    if (rc == 0) rc = media_builder_nullable_string(body, message);
    if (rc == 0) rc = media_builder_append(body, ",\"capturedAt\":");
    if (rc == 0) rc = media_builder_json_string(body, row->captured_at);
    if (rc == 0) rc = media_builder_append(body, ",\"completedAt\":");
    if (rc == 0) rc = media_builder_nullable_string(body, row->completed_at);
    if (rc == 0) rc = media_builder_append(body, ",\"expiresAt\":");
    if (rc == 0) rc = media_builder_json_string(body, row->expires_at);
    if (rc == 0) rc = media_builder_append(body, "}");
    return rc;
}

static int media_list_response(const char *path,
                               const st_media_capture_identity *identity,
                               const char *database_path,
                               char *out, size_t out_len)
{
    if (!g_media_ready) return media_write_json_error(out, out_len, 503, "媒体采集服务不可用");
    sqlite3 *db = NULL;
    if (media_db_open(database_path, &db) != 0) return media_write_json_error(out, out_len, 500, "媒体采集列表失败");
    int page = (int)media_query_i64(path, "page", 0);
    int size = (int)media_query_i64(path, "size", 50);
    long long client_id = media_query_i64(path, "clientId", 0);
    char *route = media_query_value(path, "route");
    if (page < 0) page = 0;
    if (size < 1) size = 1;
    if (size > 200) size = 200;
    char where[1024];
    snprintf(where, sizeof(where),
        "m.tenant_id=? AND (? OR EXISTS(SELECT 1 FROM client_account c WHERE c.rowid=m.client_id "
        "AND c.tenant_id=m.tenant_id AND c.owner_username=?))%s%s",
        client_id > 0 ? " AND m.client_id=?" : "",
        route != NULL && *route != '\0' ? " AND m.route=?" : "");
    char count_sql[1400], list_sql[2500];
    snprintf(count_sql, sizeof(count_sql), "SELECT COUNT(*) FROM specus_http_media_capture m WHERE %s", where);
    snprintf(list_sql, sizeof(list_sql), "SELECT %s FROM specus_http_media_capture m WHERE %s ORDER BY m.id DESC LIMIT ? OFFSET ?",
             media_row_columns(), where);
    sqlite3_stmt *stmt = NULL;
    long long total = 0;
    int ok = sqlite3_prepare_v2(db, count_sql, -1, &stmt, NULL) == SQLITE_OK;
    int index = 1;
    if (ok) {
        sqlite3_bind_text(stmt, index++, identity->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, index++, identity->admin ? 1 : 0);
        sqlite3_bind_text(stmt, index++, identity->username, -1, SQLITE_TRANSIENT);
        if (client_id > 0) sqlite3_bind_int64(stmt, index++, client_id);
        if (route != NULL && *route != '\0') sqlite3_bind_text(stmt, index++, route, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) total = sqlite3_column_int64(stmt, 0); else ok = 0;
    }
    sqlite3_finalize(stmt);
    st_media_builder body = {0};
    if (ok) ok = media_builder_append(&body, "{\"items\":[") == 0;
    if (ok) ok = sqlite3_prepare_v2(db, list_sql, -1, &stmt, NULL) == SQLITE_OK;
    index = 1;
    if (ok) {
        sqlite3_bind_text(stmt, index++, identity->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, index++, identity->admin ? 1 : 0);
        sqlite3_bind_text(stmt, index++, identity->username, -1, SQLITE_TRANSIENT);
        if (client_id > 0) sqlite3_bind_int64(stmt, index++, client_id);
        if (route != NULL && *route != '\0') sqlite3_bind_text(stmt, index++, route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, index++, size);
        sqlite3_bind_int64(stmt, index++, (sqlite3_int64)page * size);
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            st_media_capture_row row;
            media_scan_row(stmt, &row);
            if ((!first && media_builder_append(&body, ",") != 0)
                || media_append_capture_view(db, &body, &row) != 0) {
                ok = 0;
                break;
            }
            first = 0;
        }
    }
    sqlite3_finalize(stmt);
    free(route);
    sqlite3_close(db);
    long long pages = total == 0 ? 0 : (total + size - 1) / size;
    if (ok) ok = media_builder_appendf(&body,
        "],\"total\":%lld,\"page\":%d,\"size\":%d,\"totalPages\":%lld}",
        total, page, size, pages) == 0;
    int result = ok ? media_write_response(out, out_len, 200, "application/json", NULL,
                                            body.data, body.len, 1)
                    : media_write_json_error(out, out_len, 500, "媒体采集列表失败");
    free(body.data);
    return result;
}

static int media_parse_capture_path(const char *path, long long *id, const char **suffix)
{
    const char *prefix = "/api/admin/traffic/media-captures/";
    if (strncmp(path, prefix, strlen(prefix)) != 0) return -1;
    const char *cursor = path + strlen(prefix);
    char *end = NULL;
    long long parsed = strtoll(cursor, &end, 10);
    if (end == cursor || parsed <= 0) return -1;
    *id = parsed;
    *suffix = end;
    return 0;
}

static void media_ticket_cleanup_locked(time_t now)
{
    st_media_ticket **cursor = &g_media_tickets;
    while (*cursor != NULL) {
        if ((*cursor)->expires_at <= now) {
            st_media_ticket *expired = *cursor;
            *cursor = expired->next;
            free(expired);
        } else cursor = &(*cursor)->next;
    }
}

static int media_s3_delete_object(const st_media_config *cfg, const char *object_key)
{
    st_media_http_response response;
    if (media_s3_request(cfg, "DELETE", object_key, NULL, NULL, NULL,
                         NULL, 0U, NULL, &response) != 0) return -1;
    int ok = media_s3_success(&response) || response.status == 404L;
    media_http_response_free(&response);
    return ok ? 0 : -1;
}

int st_media_capture_cleanup_expired(const char *database_path)
{
    time_t current = time(NULL);
    pthread_mutex_lock(&g_media_ticket_lock);
    media_ticket_cleanup_locked(current);
    pthread_mutex_unlock(&g_media_ticket_lock);
    if (!g_media_ready || database_path == NULL || *database_path == '\0') return 0;

    st_media_config cfg = media_load_config();
    sqlite3 *db = NULL;
    if (media_db_open(database_path, &db) != 0) return -1;
    char now[64];
    media_iso_time(current, now);
    sqlite3_stmt *stmt = NULL;
    const char *extend_sql =
        "UPDATE specus_http_media_capture SET expires_at="
        "strftime('%Y-%m-%dT%H:%M:%SZ',captured_at,'+'||?||' seconds') "
        "WHERE live_stream=0 AND state IN ('COMPLETE','INCOMPLETE') AND expires_at<? "
        "AND strftime('%Y-%m-%dT%H:%M:%SZ',captured_at,'+'||?||' seconds')>? "
        "AND strftime('%Y-%m-%dT%H:%M:%SZ',captured_at,'+'||?||' seconds')>expires_at";
    if (sqlite3_prepare_v2(db, extend_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, cfg.retention_seconds);
    sqlite3_bind_text(stmt, 2, now, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, cfg.retention_seconds);
    sqlite3_bind_text(stmt, 4, now, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 5, cfg.retention_seconds);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    if (rc != 0) {
        sqlite3_close(db);
        return -1;
    }

    typedef struct {
        long long id;
        char tenant_id[64];
        char state[32];
        char object_key[1024];
        char upload_id[1024];
    } cleanup_item;
    cleanup_item items[200];
    size_t count = 0U;
    const char *select_sql =
        "SELECT id,tenant_id,state,object_key,COALESCE(upload_id,'') "
        "FROM specus_http_media_capture WHERE state IN "
        "('STARTING','CAPTURING','COMPLETE','INCOMPLETE','FAILED') "
        "AND expires_at<? ORDER BY id ASC LIMIT 200";
    if (sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
    while (count < 200U && sqlite3_step(stmt) == SQLITE_ROW) {
        items[count].id = sqlite3_column_int64(stmt, 0);
        media_row_text(stmt, 1, items[count].tenant_id, sizeof(items[count].tenant_id));
        media_row_text(stmt, 2, items[count].state, sizeof(items[count].state));
        media_row_text(stmt, 3, items[count].object_key, sizeof(items[count].object_key));
        media_row_text(stmt, 4, items[count].upload_id, sizeof(items[count].upload_id));
        ++count;
    }
    sqlite3_finalize(stmt);
    stmt = NULL;
    for (size_t i = 0U; i < count; ++i) {
        int remote_rc = 0;
        if ((strcmp(items[i].state, "STARTING") == 0
             || strcmp(items[i].state, "CAPTURING") == 0)
            && items[i].upload_id[0] != '\0') {
            st_media_capture_session temporary;
            memset(&temporary, 0, sizeof(temporary));
            temporary.cfg = cfg;
            media_copy(temporary.object_key, sizeof(temporary.object_key), items[i].object_key);
            media_copy(temporary.upload_id, sizeof(temporary.upload_id), items[i].upload_id);
            remote_rc = media_s3_abort(&temporary);
        } else if (strcmp(items[i].state, "COMPLETE") == 0
                   || strcmp(items[i].state, "INCOMPLETE") == 0) {
            remote_rc = media_s3_delete_object(&cfg, items[i].object_key);
        }
        if (remote_rc != 0) {
            rc = -1;
            continue;
        }
        if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK) {
            rc = -1;
            continue;
        }
        int delete_ok = sqlite3_prepare_v2(db,
            "DELETE FROM specus_http_media_reference WHERE tenant_id=? AND manifest_capture_id=?",
            -1, &stmt, NULL) == SQLITE_OK;
        if (delete_ok) {
            sqlite3_bind_text(stmt, 1, items[i].tenant_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, items[i].id);
            delete_ok = sqlite3_step(stmt) == SQLITE_DONE;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (delete_ok) delete_ok = sqlite3_prepare_v2(db,
            "DELETE FROM specus_http_media_capture WHERE id=? AND tenant_id=?",
            -1, &stmt, NULL) == SQLITE_OK;
        if (delete_ok) {
            sqlite3_bind_int64(stmt, 1, items[i].id);
            sqlite3_bind_text(stmt, 2, items[i].tenant_id, -1, SQLITE_TRANSIENT);
            delete_ok = sqlite3_step(stmt) == SQLITE_DONE;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (delete_ok && sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) continue;
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
        rc = -1;
    }
    sqlite3_close(db);
    return rc;
}

/*
 * Java HttpMediaPlaybackTicketService.create: a progressive capture reports the cached layout of
 * its whole resource (total, merged cached ranges, its own block as the initial range); a manifest
 * reports none of it because its player loads segments on demand.
 */
static int media_create_ticket(const char *path,
                               const st_media_capture_identity *identity,
                               const char *database_path,
                               long long id,
                               char *out, size_t out_len)
{
    if (!g_media_ready) return media_write_json_error(out, out_len, 503, "媒体采集服务不可用");
    sqlite3 *db = NULL;
    st_media_capture_row row;
    if (media_db_open(database_path, &db) != 0 || media_load_row(db, identity->tenant_id, id, &row) != 0
        || !media_identity_can_access(db, identity, &row)) {
        if (db != NULL) sqlite3_close(db);
        return media_write_json_error(out, out_len, 404, "媒体采集记录不存在");
    }
    if (strcmp(row.state, "COMPLETE") != 0) {
        sqlite3_close(db);
        return media_write_json_error(out, out_len, 409, "媒体采集尚未完成");
    }
    if (strcmp(row.media_kind, "MEDIA_SEGMENT") == 0 || row.initialization_segment) {
        sqlite3_close(db);
        return media_write_json_error(out, out_len, 409, "媒体分段不能独立创建播放会话");
    }
    int manifest = media_kind_is_manifest(row.media_kind);
    st_media_playback_parts parts;
    memset(&parts, 0, sizeof(parts));
    st_media_byte_range *ranges = NULL;
    size_t ranges_len = 0U;
    if (!manifest) {
        if (media_load_playback_parts(db, &row, &parts) != 0) {
            sqlite3_close(db);
            return media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
        }
        char reason[160];
        if (!media_parts_coverage(&parts, reason, sizeof(reason)) && row.captured_bytes <= 0) {
            free(parts.items);
            sqlite3_close(db);
            return media_write_json_error(out, out_len, 409, reason);
        }
        if (media_parts_merged_ranges(&parts, &ranges, &ranges_len) != 0) {
            free(parts.items);
            sqlite3_close(db);
            return media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
        }
    }
    sqlite3_close(db);
    long long total = parts.total;
    free(parts.items);
    unsigned char random[32];
    char token[65];
    st_media_ticket *ticket = NULL;
    if (RAND_bytes(random, sizeof(random)) != 1
        || media_base64url(random, sizeof(random), token, sizeof(token)) != 0
        || (ticket = (st_media_ticket *)calloc(1, sizeof(*ticket))) == NULL) {
        free(ranges);
        return media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
    }
    time_t now = time(NULL);
    long long ttl = media_env_i64("SPECUS_MEDIA_CAPTURE_PLAYBACK_TICKET_TTL_SECONDS", 900LL);
    if (ttl < 60LL) ttl = 60LL;
    media_copy(ticket->token, sizeof(ticket->token), token);
    media_copy(ticket->tenant_id, sizeof(ticket->tenant_id), row.tenant_id);
    ticket->capture_id = row.id;
    ticket->expires_at = now + ttl;
    ticket->backfill_missing = media_query_bool(path, "backfillMissing", 0);
    int backfill = ticket->backfill_missing;
    pthread_mutex_lock(&g_media_ticket_lock);
    media_ticket_cleanup_locked(now);
    ticket->next = g_media_tickets;
    g_media_tickets = ticket;
    pthread_mutex_unlock(&g_media_ticket_lock);
    char expires[64];
    media_iso_time(now + ttl, expires);
    st_media_builder body = {0};
    int ok = media_builder_appendf(&body, "{\"ticket\":\"%s\",\"mediaKind\":", token) == 0
        && media_builder_json_string(&body, row.media_kind) == 0
        && media_builder_appendf(&body,
            ",\"playUrl\":\"/api/public/media-playback/%s/play\","
            "\"manifestUrl\":\"/api/public/media-playback/%s/manifest\",\"totalBytes\":%lld,",
            token, token, manifest ? 0LL : total) == 0;
    if (ok && !manifest && row.captured_bytes > 0 && total > 0) {
        long long start = row.has_range_start ? row.range_start : 0;
        long long end = row.has_range_end ? row.range_end : start + row.captured_bytes - 1LL;
        long long initial_start = start < total - 1LL ? start : total - 1LL;
        if (initial_start < 0) initial_start = 0;
        long long initial_end = end < total - 1LL ? end : total - 1LL;
        if (initial_end < initial_start) initial_end = initial_start;
        ok = media_builder_appendf(&body, "\"initialRangeStart\":%lld,\"initialRangeEnd\":%lld,",
                                   initial_start, initial_end) == 0;
    } else if (ok) {
        ok = media_builder_append(&body, "\"initialRangeStart\":null,\"initialRangeEnd\":null,") == 0;
    }
    if (ok) ok = media_builder_append(&body, "\"cachedRanges\":[") == 0;
    for (size_t i = 0; ok && i < ranges_len; ++i) {
        ok = media_builder_appendf(&body, "%s{\"start\":%lld,\"end\":%lld}",
                                   i == 0U ? "" : ",", ranges[i].start, ranges[i].end) == 0;
    }
    free(ranges);
    if (ok) ok = media_builder_appendf(&body, "],\"backfillMissing\":%s,\"expiresAt\":\"%s\"}",
                                       backfill ? "true" : "false", expires) == 0;
    int result = ok ? media_write_response(out, out_len, 200, "application/json", NULL,
                                            body.data, body.len, 1)
                    : media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
    free(body.data);
    return result;
}

static int media_resolve_ticket(const char *token, char tenant_id[64],
                                long long *capture_id, int *backfill)
{
    time_t now = time(NULL);
    int found = 0;
    pthread_mutex_lock(&g_media_ticket_lock);
    media_ticket_cleanup_locked(now);
    for (st_media_ticket *ticket = g_media_tickets; ticket != NULL; ticket = ticket->next) {
        if (strcmp(ticket->token, token) == 0) {
            media_copy(tenant_id, 64U, ticket->tenant_id);
            *capture_id = ticket->capture_id;
            *backfill = ticket->backfill_missing;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_media_ticket_lock);
    return found ? 0 : -1;
}

static int media_load_latest_source(sqlite3 *db, const st_media_capture_row *anchor,
                                    const char *source_url, int manifests_only,
                                    st_media_capture_row *row)
{
    char normalized[ST_MEDIA_SOURCE_MAX + 1U];
    media_normalize_source(source_url, normalized);
    char sql[2300];
    snprintf(sql, sizeof(sql), "SELECT %s FROM specus_http_media_capture m WHERE "
        "m.tenant_id=? AND m.client_id=? AND m.route=? AND m.source_url=? AND m.state='COMPLETE'%s "
        "ORDER BY m.id DESC LIMIT 1", media_row_columns(),
        manifests_only ? " AND m.media_kind IN ('HLS_MANIFEST','DASH_MANIFEST')" : "");
    sqlite3_stmt *stmt = NULL;
    int found = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, anchor->tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 2, anchor->client_id);
        sqlite3_bind_text(stmt, 3, anchor->route, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, normalized, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            media_scan_row(stmt, row);
            found = 1;
        }
    }
    sqlite3_finalize(stmt);
    return found ? 0 : -1;
}

/* ------------------------------------------------------------------------------------------------
 * Manifest support (Java HttpMediaManifestSupport)
 */

/* RFC 3986 section 5.2.4 on a path that starts with '/'; out has room for strlen(path) + 1. */
static void media_remove_dot_segments(const char *path, char *out)
{
    size_t used = 0U;
    const char *in = path;
    while (*in != '\0') {
        if (strncmp(in, "../", 3U) == 0) in += 3;
        else if (strncmp(in, "./", 2U) == 0) in += 2;
        else if (strncmp(in, "/./", 3U) == 0) in += 2;
        else if (strcmp(in, "/.") == 0) {
            out[used++] = '/';
            break;
        } else if (strncmp(in, "/../", 4U) == 0 || strcmp(in, "/..") == 0) {
            while (used > 0U && out[used - 1U] != '/') --used;
            if (used > 0U) --used;
            if (in[3] == '\0') {
                out[used++] = '/';
                break;
            }
            in += 3;
        } else if (strcmp(in, ".") == 0 || strcmp(in, "..") == 0) {
            break;
        } else {
            if (*in == '/') out[used++] = *in++;
            while (*in != '\0' && *in != '/') out[used++] = *in++;
        }
    }
    out[used] = '\0';
}

/*
 * Java resolveSourceUrl: the reference resolved against the manifest's own URL, kept as a path and
 * query; a blank or data: reference is returned as it is.
 */
static void media_resolve_source_url(const char *base, const char *reference,
                                     char out[ST_MEDIA_SOURCE_MAX + 1U])
{
    size_t used = 0U;
    out[0] = '\0';
    if (reference == NULL || !media_has_text(reference) || strncmp(reference, "data:", 5U) == 0) {
        media_source_append(out, &used, reference == NULL ? "" : reference,
                            reference == NULL ? 0U : strlen(reference));
        return;
    }
    const char *ref = reference;
    size_t ref_len = strlen(reference);
    media_trim_bounds(&ref, &ref_len);
    const char *fragment = memchr(ref, '#', ref_len);
    if (fragment != NULL) ref_len = (size_t)(fragment - ref);
    size_t scheme = media_scheme_authority_prefix(ref, ref_len);
    char resolved[ST_MEDIA_SOURCE_MAX + 1U];
    size_t resolved_len = 0U;
    resolved[0] = '\0';
    if (scheme > 0U) {
        media_source_after_authority(ref + scheme + 2U, ref + ref_len, resolved, &resolved_len);
    } else if (ref_len >= 2U && ref[0] == '/' && ref[1] == '/') {
        media_source_after_authority(ref + 2, ref + ref_len, resolved, &resolved_len);
    } else if (ref_len > 0U && ref[0] == '/') {
        media_source_append(resolved, &resolved_len, ref, ref_len);
    } else {
        /* A relative reference: merged with the base's directory, then dot segments removed. */
        const char *query = memchr(ref, '?', ref_len);
        size_t path_len = query == NULL ? ref_len : (size_t)(query - ref);
        char base_path[ST_MEDIA_SOURCE_MAX + 1U];
        media_normalize_source(base, base_path);
        char *base_query = strchr(base_path, '?');
        if (base_query != NULL) *base_query = '\0';
        char *base_fragment = strchr(base_path, '#');
        if (base_fragment != NULL) *base_fragment = '\0';
        char *slash = strrchr(base_path, '/');
        size_t directory_len = slash == NULL ? 0U : (size_t)(slash - base_path) + 1U;
        size_t merged_len = directory_len + path_len;
        char *merged = (char *)malloc(merged_len + 2U);
        char *clean = (char *)malloc(merged_len + 2U);
        if (merged != NULL && clean != NULL) {
            memcpy(merged, base_path, directory_len);
            memcpy(merged + directory_len, ref, path_len);
            merged[merged_len] = '\0';
            if (merged[0] != '/') {
                memmove(merged + 1, merged, merged_len + 1U);
                merged[0] = '/';
            }
            media_remove_dot_segments(merged, clean);
            media_source_append(resolved, &resolved_len, clean, strlen(clean));
            if (query != NULL) media_source_append(resolved, &resolved_len, query, ref_len - path_len);
        }
        free(merged);
        free(clean);
    }
    media_normalize_source(resolved, out);
}

/*
 * Java assetUrl: URLEncoder.encode with spaces as %20 and '$' kept, so DASH template tokens such as
 * $Number$ still reach the player and are substituted there.
 */
static char *media_asset_url(const char *base_path, const char *source_url)
{
    static const char digits[] = "0123456789ABCDEF";
    size_t source_len = strlen(source_url);
    size_t base_len = strlen(base_path);
    char *result = (char *)malloc(base_len + 5U + source_len * 3U + 1U);
    if (result == NULL) return NULL;
    memcpy(result, base_path, base_len);
    memcpy(result + base_len, "?url=", 5U);
    size_t offset = base_len + 5U;
    for (size_t i = 0; i < source_len; ++i) {
        unsigned char ch = (unsigned char)source_url[i];
        if (isalnum(ch) || ch == '.' || ch == '-' || ch == '*' || ch == '_' || ch == '$') {
            result[offset++] = (char)ch;
        } else {
            result[offset++] = '%';
            result[offset++] = digits[ch >> 4U];
            result[offset++] = digits[ch & 0x0fU];
        }
    }
    result[offset] = '\0';
    return result;
}

static char *media_reference_asset(const char *asset_base, const char *source_url,
                                   const char *reference, size_t reference_len)
{
    char *copy = (char *)malloc(reference_len + 1U);
    if (copy == NULL) return NULL;
    memcpy(copy, reference, reference_len);
    copy[reference_len] = '\0';
    char resolved[ST_MEDIA_SOURCE_MAX + 1U];
    media_resolve_source_url(source_url, copy, resolved);
    free(copy);
    return media_asset_url(asset_base, resolved);
}

/* Java xmlEscape for attribute values. */
static int media_builder_xml_escaped(st_media_builder *builder, const char *value)
{
    for (const char *p = value; *p != '\0'; ++p) {
        int rc = *p == '&' ? media_builder_append(builder, "&amp;")
            : *p == '"' ? media_builder_append(builder, "&quot;")
            : media_builder_append_len(builder, p, 1U);
        if (rc != 0) return -1;
    }
    return 0;
}

/* Splits like Java's "\\R" (CRLF, CR or LF); returns where the next line starts. */
static const char *media_manifest_line(const char *cursor, const char **line_end, int *has_break)
{
    const char *end = cursor;
    while (*end != '\0' && *end != '\r' && *end != '\n') ++end;
    *line_end = end;
    *has_break = *end != '\0';
    if (*end == '\r' && end[1] == '\n') return end + 2;
    return *end == '\0' ? end : end + 1;
}

/* Java HLS_URI_ATTRIBUTE, URI=("([^"]+)"|'([^']+)'), at p within the line. */
static int media_hls_uri_at(const char *p, const char *limit,
                            const char **value, size_t *value_len, const char **next)
{
    if (limit - p < 7 || strncmp(p, "URI=", 4U) != 0 || (p[4] != '"' && p[4] != '\'')) return 0;
    const char *start = p + 5;
    const char *close = memchr(start, p[4], (size_t)(limit - start));
    if (close == NULL || close == start) return 0;
    *value = start;
    *value_len = (size_t)(close - start);
    *next = close + 1;
    return 1;
}

/* Java DASH_URI_ATTRIBUTE, (media|initialization|sourceURL|href)\s*=\s*("..."|'...'), at p. */
static int media_dash_attribute_at(const char *p, size_t *name_len,
                                   const char **value, size_t *value_len, const char **next)
{
    static const char *names[] = {"media", "initialization", "sourceURL", "href"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t len = strlen(names[i]);
        if (strncasecmp(p, names[i], len) != 0) continue;
        const char *q = p + len;
        while (isspace((unsigned char)*q)) ++q;
        if (*q != '=') return 0;
        ++q;
        while (isspace((unsigned char)*q)) ++q;
        if (*q != '"' && *q != '\'') return 0;
        const char *start = q + 1;
        const char *close = strchr(start, *q);
        if (close == NULL || close == start) return 0;
        *name_len = len;
        *value = start;
        *value_len = (size_t)(close - start);
        *next = close + 1;
        return 1;
    }
    return 0;
}

/* Java DASH_BASE_URL, <BaseURL(\s[^>]*)?>([^<]+)</BaseURL> without regard to case, at p. */
static int media_dash_base_url_at(const char *p, const char **value, size_t *value_len,
                                  const char **next)
{
    if (strncasecmp(p, "<BaseURL", 8U) != 0) return 0;
    const char *q = p + 8;
    if (*q != '>') {
        if (!isspace((unsigned char)*q)) return 0;
        q = strchr(q, '>');
        if (q == NULL) return 0;
    }
    const char *start = ++q;
    while (*q != '\0' && *q != '<') ++q;
    if (q == start || strncasecmp(q, "</BaseURL>", 10U) != 0) return 0;
    *value = start;
    *value_len = (size_t)(q - start);
    *next = q + 10;
    return 1;
}

static const char *media_strcasestr_local(const char *value, const char *needle)
{
    size_t needle_len = strlen(needle);
    for (const char *p = value; *p != '\0'; ++p) {
        if (strncasecmp(p, needle, needle_len) == 0) return p;
    }
    return NULL;
}

static int media_word_char(unsigned char value)
{
    return isalnum(value) || value == '_';
}

/* Java's live test for DASH: <MPD\b[^>]*\btype\s*=\s*["']dynamic["'], without regard to case. */
static int media_dash_dynamic(const char *text)
{
    for (const char *mpd = media_strcasestr_local(text, "<MPD"); mpd != NULL;
         mpd = media_strcasestr_local(mpd + 4, "<MPD")) {
        if (media_word_char((unsigned char)mpd[4])) continue;
        const char *close = strchr(mpd + 4, '>');
        const char *limit = close == NULL ? mpd + strlen(mpd) : close;
        for (const char *q = mpd + 4; q < limit; ++q) {
            if (strncasecmp(q, "type", 4U) != 0 || media_word_char((unsigned char)q[-1])) continue;
            const char *r = q + 4;
            while (r < limit && isspace((unsigned char)*r)) ++r;
            if (r >= limit || *r != '=') continue;
            ++r;
            while (r < limit && isspace((unsigned char)*r)) ++r;
            if (limit - r < 9 || (*r != '"' && *r != '\'')
                || strncasecmp(r + 1, "dynamic", 7U) != 0 || (r[8] != '"' && r[8] != '\'')) continue;
            return 1;
        }
    }
    return 0;
}

static char *media_rewrite_hls(const char *source_url, const char *text, const char *asset_base)
{
    st_media_builder result = {0};
    const char *cursor = text;
    for (;;) {
        const char *line_end = NULL;
        int has_break = 0;
        const char *next_line = media_manifest_line(cursor, &line_end, &has_break);
        st_media_builder line = {0};
        const char *run = cursor;
        const char *p = cursor;
        int ok = 1;
        while (ok && p < line_end) {
            const char *value = NULL, *next = NULL;
            size_t value_len = 0U;
            if (!media_hls_uri_at(p, line_end, &value, &value_len, &next)) {
                ++p;
                continue;
            }
            char *asset = media_reference_asset(asset_base, source_url, value, value_len);
            ok = asset != NULL
                && media_builder_append_len(&line, run, (size_t)(p - run)) == 0
                && media_builder_append(&line, "URI=\"") == 0
                && media_builder_append(&line, asset) == 0
                && media_builder_append(&line, "\"") == 0;
            free(asset);
            p = run = next;
        }
        if (ok) ok = media_builder_append_len(&line, run, (size_t)(line_end - run)) == 0;
        const char *trimmed = line.data == NULL ? "" : line.data;
        size_t trimmed_len = line.len;
        media_trim_bounds(&trimmed, &trimmed_len);
        if (ok && trimmed_len > 0U && *trimmed != '#') {
            char *asset = media_reference_asset(asset_base, source_url, trimmed, trimmed_len);
            ok = asset != NULL && media_builder_append(&result, asset) == 0;
            free(asset);
        } else if (ok) {
            ok = media_builder_append_len(&result, line.data == NULL ? "" : line.data, line.len) == 0;
        }
        free(line.data);
        if (!ok || (has_break && media_builder_append(&result, "\n") != 0)) {
            free(result.data);
            return NULL;
        }
        if (!has_break) break;
        cursor = next_line;
    }
    if (result.data == NULL) result.data = strdup("");
    return result.data;
}

static char *media_rewrite_dash(const char *source_url, const char *text, const char *asset_base)
{
    st_media_builder attributes = {0};
    const char *run = text;
    const char *p = text;
    while (*p != '\0') {
        size_t name_len = 0U, value_len = 0U;
        const char *value = NULL, *next = NULL;
        if (!media_dash_attribute_at(p, &name_len, &value, &value_len, &next)) {
            ++p;
            continue;
        }
        char *asset = media_reference_asset(asset_base, source_url, value, value_len);
        int ok = asset != NULL
            && media_builder_append_len(&attributes, run, (size_t)(p - run)) == 0
            && media_builder_append_len(&attributes, p, name_len) == 0
            && media_builder_append(&attributes, "=\"") == 0
            && media_builder_xml_escaped(&attributes, asset) == 0
            && media_builder_append(&attributes, "\"") == 0;
        free(asset);
        if (!ok) {
            free(attributes.data);
            return NULL;
        }
        p = run = next;
    }
    if (media_builder_append_len(&attributes, run, (size_t)(p - run)) != 0) {
        free(attributes.data);
        return NULL;
    }
    st_media_builder result = {0};
    const char *first_pass = attributes.data == NULL ? "" : attributes.data;
    run = p = first_pass;
    while (*p != '\0') {
        size_t value_len = 0U;
        const char *value = NULL, *next = NULL;
        if (!media_dash_base_url_at(p, &value, &value_len, &next)) {
            ++p;
            continue;
        }
        const char *trimmed = value;
        media_trim_bounds(&trimmed, &value_len);
        char *asset = media_reference_asset(asset_base, source_url, trimmed, value_len);
        int ok = asset != NULL
            && media_builder_append_len(&result, run, (size_t)(value - run)) == 0
            && media_builder_xml_escaped(&result, asset) == 0
            && media_builder_append(&result, "</BaseURL>") == 0;
        free(asset);
        if (!ok) {
            free(attributes.data);
            free(result.data);
            return NULL;
        }
        p = run = next;
    }
    int ok = media_builder_append_len(&result, run, (size_t)(p - run)) == 0;
    free(attributes.data);
    if (!ok) {
        free(result.data);
        return NULL;
    }
    if (result.data == NULL) result.data = strdup("");
    return result.data;
}

typedef struct {
    const char *relation;
    int has_sequence;
    long long sequence;
    char *original;
    char *resolved;
} st_media_manifest_reference;

typedef struct {
    int live;
    st_media_manifest_reference *items;
    size_t len;
    size_t cap;
} st_media_parsed_manifest;

static void media_parsed_manifest_free(st_media_parsed_manifest *parsed)
{
    for (size_t i = 0; i < parsed->len; ++i) {
        free(parsed->items[i].original);
        free(parsed->items[i].resolved);
    }
    free(parsed->items);
    memset(parsed, 0, sizeof(*parsed));
}

static int media_parsed_manifest_add(st_media_parsed_manifest *parsed, const char *relation,
                                     int has_sequence, long long sequence,
                                     const char *original, size_t original_len,
                                     const char *source_url)
{
    if (parsed->len == parsed->cap) {
        size_t next = parsed->cap == 0U ? 16U : parsed->cap * 2U;
        st_media_manifest_reference *grown = (st_media_manifest_reference *)realloc(
            parsed->items, next * sizeof(*grown));
        if (grown == NULL) return -1;
        parsed->items = grown;
        parsed->cap = next;
    }
    st_media_manifest_reference *item = &parsed->items[parsed->len];
    memset(item, 0, sizeof(*item));
    item->original = (char *)malloc(original_len + 1U);
    if (item->original == NULL) return -1;
    memcpy(item->original, original, original_len);
    item->original[original_len] = '\0';
    char resolved[ST_MEDIA_SOURCE_MAX + 1U];
    media_resolve_source_url(source_url, item->original, resolved);
    item->resolved = strdup(resolved);
    if (item->resolved == NULL) {
        free(item->original);
        return -1;
    }
    item->relation = relation;
    item->has_sequence = has_sequence;
    item->sequence = sequence;
    ++parsed->len;
    return 0;
}

/* Java Long.parseLong: an optional sign and decimal digits, nothing else. */
static int media_java_parse_long(const char *value, size_t len, long long *out)
{
    size_t i = 0U;
    int negative = 0;
    if (len > 0U && (value[0] == '+' || value[0] == '-')) {
        negative = value[0] == '-';
        i = 1U;
    }
    if (i == len) return -1;
    const char *cursor = value + i;
    long long parsed = 0;
    if (media_parse_digits(&cursor, value + len, &parsed) != 0 || cursor != value + len) return -1;
    *out = negative ? -parsed : parsed;
    return 0;
}

/* Java parseHls: references in manifest order, segment sequence numbers and the live flag. */
static int media_parse_hls(const char *source_url, const char *text, st_media_parsed_manifest *parsed)
{
    static const char sequence_tag[] = "#EXT-X-MEDIA-SEQUENCE:";
    long long media_sequence = 0;
    int end_list = 0;
    int has_segment = 0;
    const char *cursor = text;
    for (;;) {
        const char *line_end = NULL;
        int has_break = 0;
        const char *next_line = media_manifest_line(cursor, &line_end, &has_break);
        const char *trimmed = cursor;
        size_t trimmed_len = (size_t)(line_end - cursor);
        media_trim_bounds(&trimmed, &trimmed_len);
        size_t tag_len = sizeof(sequence_tag) - 1U;
        if (trimmed_len >= tag_len && strncmp(trimmed, sequence_tag, tag_len) == 0) {
            const char *value = trimmed + tag_len;
            size_t value_len = trimmed_len - tag_len;
            media_trim_bounds(&value, &value_len);
            if (media_java_parse_long(value, value_len, &media_sequence) != 0) media_sequence = 0;
        } else if (trimmed_len == strlen("#EXT-X-ENDLIST")
                   && strncmp(trimmed, "#EXT-X-ENDLIST", trimmed_len) == 0) {
            end_list = 1;
        }
        const char *p = cursor;
        while (p < line_end) {
            const char *value = NULL, *next = NULL;
            size_t value_len = 0U;
            if (!media_hls_uri_at(p, line_end, &value, &value_len, &next)) {
                ++p;
                continue;
            }
            const char *relation = trimmed_len >= 10U && strncmp(trimmed, "#EXT-X-MAP", 10U) == 0
                ? "INITIALIZATION"
                : (trimmed_len >= 10U && strncmp(trimmed, "#EXT-X-KEY", 10U) == 0 ? "KEY" : "ASSET");
            if (media_parsed_manifest_add(parsed, relation, 0, 0, value, value_len, source_url) != 0)
                return -1;
            p = next;
        }
        if (trimmed_len > 0U && *trimmed != '#') {
            const char *query = memchr(trimmed, '?', trimmed_len);
            size_t path_len = query == NULL ? trimmed_len : (size_t)(query - trimmed);
            int playlist = path_len >= 5U && strncasecmp(trimmed + path_len - 5U, ".m3u8", 5U) == 0;
            int added = playlist
                ? media_parsed_manifest_add(parsed, "PLAYLIST", 0, 0, trimmed, trimmed_len, source_url)
                : media_parsed_manifest_add(parsed, "SEGMENT", 1, media_sequence, trimmed, trimmed_len,
                                            source_url);
            if (added != 0) return -1;
            if (!playlist) {
                has_segment = 1;
                if (media_sequence < LLONG_MAX) ++media_sequence;
            }
        }
        if (!has_break) break;
        cursor = next_line;
    }
    parsed->live = has_segment && !end_list;
    return 0;
}

/* Java parseDash: URI attributes, then BaseURL elements, and whether the MPD is dynamic. */
static int media_parse_dash(const char *source_url, const char *text, st_media_parsed_manifest *parsed)
{
    long long sequence = 0;
    const char *p = text;
    while (*p != '\0') {
        size_t name_len = 0U, value_len = 0U;
        const char *value = NULL, *next = NULL;
        if (!media_dash_attribute_at(p, &name_len, &value, &value_len, &next)) {
            ++p;
            continue;
        }
        int initialization = (name_len == strlen("initialization")
                              && strncasecmp(p, "initialization", name_len) == 0)
            || (name_len == strlen("sourceURL") && strncasecmp(p, "sourceURL", name_len) == 0);
        int added = initialization
            ? media_parsed_manifest_add(parsed, "INITIALIZATION", 0, 0, value, value_len, source_url)
            : media_parsed_manifest_add(parsed, "SEGMENT", 1, sequence++, value, value_len, source_url);
        if (added != 0) return -1;
        p = next;
    }
    p = text;
    while (*p != '\0') {
        size_t value_len = 0U;
        const char *value = NULL, *next = NULL;
        if (!media_dash_base_url_at(p, &value, &value_len, &next)) {
            ++p;
            continue;
        }
        media_trim_bounds(&value, &value_len);
        if (value_len > 0U
            && media_parsed_manifest_add(parsed, "BASE", 0, 0, value, value_len, source_url) != 0)
            return -1;
        p = next;
    }
    parsed->live = media_dash_dynamic(text);
    return 0;
}

/*
 * The manifest text as Java HttpBodyDataCodec.toDisplayText sees it: the Content-Encoding codings
 * are undone last to first. A coding C cannot undo (br) leaves the stored bytes as they are.
 */
static char *media_decode_manifest_text(const uint8_t *data, size_t len, const char *content_encoding)
{
    uint8_t *current = (uint8_t *)malloc(len + 1U);
    if (current == NULL) return NULL;
    memcpy(current, data, len);
    current[len] = '\0';
    size_t current_len = len;
    char encodings[129];
    media_copy(encodings, sizeof(encodings), content_encoding);
    char *tokens[16];
    size_t token_count = 0U;
    for (char *token = encodings; token != NULL && token_count < 16U;) {
        char *comma = strchr(token, ',');
        if (comma != NULL) *comma = '\0';
        tokens[token_count++] = token;
        token = comma == NULL ? NULL : comma + 1;
    }
    for (size_t i = token_count; i > 0U; --i) {
        const char *token = tokens[i - 1U];
        size_t token_len = strlen(token);
        media_trim_bounds(&token, &token_len);
        if (token_len == 0U || (token_len == 8U && strncasecmp(token, "identity", 8U) == 0)) continue;
        uint8_t *decoded = NULL;
        size_t decoded_len = 0U;
        st_decompression_result rc = ST_DECOMPRESSION_INVALID;
        if ((token_len == 4U && strncasecmp(token, "gzip", 4U) == 0)
            || (token_len == 6U && strncasecmp(token, "x-gzip", 6U) == 0)) {
            rc = st_decompress_bounded(current, current_len, ST_DECOMPRESSION_GZIP, &decoded, &decoded_len);
        } else if ((token_len == 7U && strncasecmp(token, "deflate", 7U) == 0)
                   || (token_len == 9U && strncasecmp(token, "x-deflate", 9U) == 0)) {
            rc = st_decompress_bounded(current, current_len, ST_DECOMPRESSION_ZLIB, &decoded, &decoded_len);
            if (rc != ST_DECOMPRESSION_OK)
                rc = st_decompress_bounded(current, current_len, ST_DECOMPRESSION_RAW_DEFLATE,
                                           &decoded, &decoded_len);
        } else if (token_len == 2U && strncasecmp(token, "br", 2U) == 0) {
            /* Decoded when the build has libbrotlidec (Java HttpBodyDataCodec); else kept as stored. */
            rc = st_decompress_bounded(current, current_len, ST_DECOMPRESSION_BROTLI, &decoded, &decoded_len);
        }
        if (rc != ST_DECOMPRESSION_OK) {
            free(decoded);
            if (i == token_count) return (char *)current;
            /* A later coding was already undone: start again from the stored bytes. */
            uint8_t *raw = (uint8_t *)realloc(current, len + 1U);
            if (raw == NULL) {
                free(current);
                return NULL;
            }
            memcpy(raw, data, len);
            raw[len] = '\0';
            return (char *)raw;
        }
        uint8_t *terminated = (uint8_t *)realloc(decoded, decoded_len + 1U);
        if (terminated == NULL) {
            free(decoded);
            free(current);
            return NULL;
        }
        terminated[decoded_len] = '\0';
        free(current);
        current = terminated;
        current_len = decoded_len;
    }
    return (char *)current;
}

/* Binds at most max_bytes of value, cut back to a UTF-8 character boundary (Java's cap). */
static void media_bind_capped_text(sqlite3_stmt *stmt, int index, const char *value, size_t max_bytes)
{
    size_t len = strlen(value);
    if (len > max_bytes) {
        len = max_bytes;
        while (len > 0U && ((unsigned char)value[len] & 0xc0U) == 0x80U) --len;
    }
    sqlite3_bind_text(stmt, index, value, (int)len, SQLITE_TRANSIENT);
}

static int media_exec_live_update(sqlite3 *db, const char *sql, const char *expires_at,
                                  const st_media_capture_session *session,
                                  const char *source_url, const char *cutoff)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, expires_at, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, session->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, session->client_id);
    sqlite3_bind_text(stmt, 4, session->route, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, source_url != NULL ? source_url : cutoff, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    return rc;
}

/*
 * Java markComplete for a complete manifest: the references are stored, and a live manifest (HLS
 * without #EXT-X-ENDLIST, dynamic DASH) moves itself, the segments it names and the route's recent
 * segments to the live window instead of the retention period (Java markLiveWindow).
 */
static void media_record_manifest(st_media_capture_session *session)
{
    char *text = media_decode_manifest_text(session->manifest_buffer, session->manifest_len,
                                            session->content_encoding);
    if (text == NULL) return;
    st_media_parsed_manifest parsed;
    memset(&parsed, 0, sizeof(parsed));
    int parsed_rc = strcmp(session->media_kind, "HLS_MANIFEST") == 0
        ? media_parse_hls(session->source_url, text, &parsed)
        : media_parse_dash(session->source_url, text, &parsed);
    free(text);
    sqlite3 *db = NULL;
    if (parsed_rc != 0 || media_db_open(session->database_path, &db) != 0) {
        media_parsed_manifest_free(&parsed);
        return;
    }
    time_t now = time(NULL);
    char created_at[64], live_expires[64], cutoff[64];
    media_iso_time(now, created_at);
    media_iso_time(now + session->cfg.live_window_seconds, live_expires);
    media_iso_time(now - session->cfg.live_window_seconds, cutoff);
    int ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_stmt *stmt = NULL;
    if (ok && parsed.live) {
        ok = sqlite3_prepare_v2(db,
            "UPDATE specus_http_media_capture SET live_stream=1,expires_at=? WHERE id=? AND tenant_id=?",
            -1, &stmt, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_text(stmt, 1, live_expires, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, session->id);
            sqlite3_bind_text(stmt, 3, session->tenant_id, -1, SQLITE_TRANSIENT);
            ok = sqlite3_step(stmt) == SQLITE_DONE;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        for (size_t i = 0; ok && i < parsed.len; ++i) {
            if (strcmp(parsed.items[i].relation, "SEGMENT") != 0
                && strcmp(parsed.items[i].relation, "INITIALIZATION") != 0) continue;
            ok = media_exec_live_update(db,
                "UPDATE specus_http_media_capture SET live_stream=1,expires_at=? "
                "WHERE tenant_id=? AND client_id=? AND route=? AND source_url=? AND state='COMPLETE'",
                live_expires, session, parsed.items[i].resolved, NULL) == 0;
        }
        /* DASH templates name no concrete URL, so the route's recent segments roll forward too. */
        if (ok) ok = media_exec_live_update(db,
            "UPDATE specus_http_media_capture SET live_stream=1,expires_at=? WHERE id IN ("
            "SELECT id FROM specus_http_media_capture WHERE tenant_id=? AND client_id=? AND route=? "
            "AND media_kind='MEDIA_SEGMENT' AND state='COMPLETE' ORDER BY id DESC LIMIT 1000) "
            "AND captured_at>?",
            live_expires, session, NULL, cutoff) == 0;
    }
    if (ok) {
        ok = sqlite3_prepare_v2(db,
            "DELETE FROM specus_http_media_reference WHERE tenant_id=? AND manifest_capture_id=?",
            -1, &stmt, NULL) == SQLITE_OK;
        if (ok) {
            sqlite3_bind_text(stmt, 1, session->tenant_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, session->id);
            ok = sqlite3_step(stmt) == SQLITE_DONE;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (ok && parsed.len > 0U) {
        ok = sqlite3_prepare_v2(db,
            "INSERT INTO specus_http_media_reference(tenant_id,manifest_capture_id,relation_type,"
            "sequence_index,original_uri,resolved_source_url,created_at) VALUES(?,?,?,?,?,?,?)",
            -1, &stmt, NULL) == SQLITE_OK;
        for (size_t i = 0; ok && i < parsed.len; ++i) {
            sqlite3_reset(stmt);
            sqlite3_clear_bindings(stmt);
            sqlite3_bind_text(stmt, 1, session->tenant_id, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, session->id);
            sqlite3_bind_text(stmt, 3, parsed.items[i].relation, -1, SQLITE_STATIC);
            if (parsed.items[i].has_sequence) sqlite3_bind_int64(stmt, 4, parsed.items[i].sequence);
            else sqlite3_bind_null(stmt, 4);
            media_bind_capped_text(stmt, 5, parsed.items[i].original, 2048U);
            media_bind_capped_text(stmt, 6, parsed.items[i].resolved, ST_MEDIA_SOURCE_MAX);
            sqlite3_bind_text(stmt, 7, created_at, -1, SQLITE_TRANSIENT);
            ok = sqlite3_step(stmt) == SQLITE_DONE;
        }
        sqlite3_finalize(stmt);
    }
    (void)sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL);
    sqlite3_close(db);
    media_parsed_manifest_free(&parsed);
}

/* ------------------------------------------------------------------------------------------------
 * Playback (Java HttpMediaPlaybackService and the two media resources)
 */

/* Java writeCacheMiss: a plain-text reason, and the total for a 416. */
static int media_write_cache_miss(char *out, size_t out_len, const char *method, int status,
                                  const char *message, long long total)
{
    char headers[160];
    int written = snprintf(headers, sizeof(headers), "Accept-Ranges: bytes\r\n");
    if (status == 416 && total > 0 && written > 0)
        snprintf(headers + written, sizeof(headers) - (size_t)written,
                 "Content-Range: bytes */%lld\r\n", total);
    const char *text = message == NULL ? "" : message;
    return media_write_response(out, out_len, status, "text/plain;charset=UTF-8", headers,
                                text, strlen(text), strcasecmp(method, "HEAD") != 0);
}

/* Spring UriUtils.encodePathSegment: pchar stays, everything else is percent-encoded. */
static int media_builder_path_segment(st_media_builder *builder, const char *value)
{
    static const char digits[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        int keep = media_is_unreserved(*p) || strchr("!$&'()*+,;=:@", *p) != NULL;
        char escaped[3] = {'%', digits[*p >> 4U], digits[*p & 0x0fU]};
        if ((keep ? media_builder_append_len(builder, (const char *)p, 1U)
                  : media_builder_append_len(builder, escaped, 3U)) != 0) return -1;
    }
    return 0;
}

/*
 * Java safeSourceUrl: line breaks dropped, trimmed, rooted, and every byte a URI cannot carry
 * percent-encoded, so the Location header holds exactly one ASCII URI.
 */
static int media_builder_safe_source(st_media_builder *builder, const char *source_url)
{
    static const char digits[] = "0123456789ABCDEF";
    const char *start = source_url == NULL ? "" : source_url;
    size_t len = strlen(start);
    media_trim_bounds(&start, &len);
    if (len == 0U || *start != '/') {
        if (media_builder_append(builder, "/") != 0) return -1;
    }
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)start[i];
        if (ch == '\r' || ch == '\n') continue;
        int keep = media_is_unreserved(ch) || strchr("!$&'()*+,;=:@/?#", ch) != NULL
            || (ch == '%' && i + 2U < len && isxdigit((unsigned char)start[i + 1U])
                && isxdigit((unsigned char)start[i + 2U]));
        char escaped[3] = {'%', digits[ch >> 4U], digits[ch & 0x0fU]};
        if ((keep && ch != '\0' ? media_builder_append_len(builder, (const char *)&start[i], 1U)
                                : media_builder_append_len(builder, escaped, 3U)) != 0) return -1;
    }
    return 0;
}

/* Java redirectToOrigin: 307 to the original /http/{client}/{route} URL, never cached. */
static int media_write_origin_redirect(char *out, size_t out_len,
                                       const st_media_capture_row *anchor,
                                       const char *source_url)
{
    st_media_builder headers = {0};
    int ok = media_builder_append(&headers, "Location: /http/") == 0
        && media_builder_path_segment(&headers, anchor->client_name) == 0
        && media_builder_append(&headers, "/") == 0
        && media_builder_path_segment(&headers, anchor->route) == 0
        && media_builder_safe_source(&headers, source_url) == 0
        && media_builder_append(&headers, "\r\n") == 0;
    int result = ok ? media_write_response(out, out_len, 307, "application/octet-stream",
                                           headers.data, "", 0U, 0)
                    : -1;
    free(headers.data);
    return result;
}

/* Java HttpMediaPlaybackService.parseRange, with its reasons for a refused Range. */
static int media_parse_playback_range(const char *header, long long total,
                                      long long *out_start, long long *out_end,
                                      char *message, size_t message_len)
{
    if (total <= 0) {
        media_copy(message, message_len, "媒体总长度未知");
        return -1;
    }
    if (!media_has_text(header)) {
        *out_start = 0;
        *out_end = total - 1LL;
        return 0;
    }
    const char *value = header;
    size_t len = strlen(header);
    media_trim_bounds(&value, &len);
    if (len < 6U || strncasecmp(value, "bytes=", 6U) != 0 || memchr(value, ',', len) != NULL) {
        media_copy(message, message_len, "仅支持单一 bytes Range");
        return -1;
    }
    value += 6;
    len -= 6U;
    media_trim_bounds(&value, &len);
    const char *dash = memchr(value, '-', len);
    if (dash == NULL) {
        media_copy(message, message_len, "Range 格式无效");
        return -1;
    }
    const char *start_text = value;
    size_t start_len = (size_t)(dash - value);
    const char *end_text = dash + 1;
    size_t end_len = len - start_len - 1U;
    media_trim_bounds(&start_text, &start_len);
    media_trim_bounds(&end_text, &end_len);
    long long start = 0, end = total - 1LL;
    if (start_len == 0U) {
        long long suffix = 0;
        if (media_java_parse_long(end_text, end_len, &suffix) != 0) {
            media_copy(message, message_len, "Range 格式无效");
            return -1;
        }
        if (suffix <= 0) {
            media_copy(message, message_len, "Range 后缀长度无效");
            return -1;
        }
        start = suffix >= total ? 0 : total - suffix;
    } else if (media_java_parse_long(start_text, start_len, &start) != 0
               || (end_len > 0U && media_java_parse_long(end_text, end_len, &end) != 0)) {
        media_copy(message, message_len, "Range 格式无效");
        return -1;
    }
    if (start < 0 || start >= total || end < start) {
        media_copy(message, message_len, "Range 超出媒体范围");
        return -1;
    }
    *out_start = start;
    *out_end = end < total - 1LL ? end : total - 1LL;
    return 0;
}

/*
 * Java initialSparseRange: a request without Range on a resource with gaps starts at the anchor's
 * own cached block, or else at the first cached block.
 */
static int media_initial_sparse_range(const st_media_capture_row *anchor,
                                      const st_media_playback_parts *parts,
                                      long long *out_start, long long *out_end,
                                      char *message, size_t message_len)
{
    long long total = parts->total;
    if (total <= 0) {
        media_copy(message, message_len, "媒体总长度未知");
        return -1;
    }
    long long anchor_start = anchor->has_range_start ? anchor->range_start : 0;
    long long anchor_end = anchor->has_range_end
        ? anchor->range_end : anchor_start + anchor->captured_bytes - 1LL;
    if (anchor_start >= 0 && anchor_start < total && anchor_end >= anchor_start
        && media_parts_furthest_end(parts, anchor_start) >= anchor_start) {
        *out_start = anchor_start;
        *out_end = anchor_end < total - 1LL ? anchor_end : total - 1LL;
        return 0;
    }
    st_media_byte_range *ranges = NULL;
    size_t ranges_len = 0U;
    if (media_parts_merged_ranges(parts, &ranges, &ranges_len) != 0 || ranges_len == 0U) {
        free(ranges);
        media_copy(message, message_len, "媒体采集没有可回放的数据");
        return -1;
    }
    *out_start = ranges[0].start;
    *out_end = ranges[0].end;
    free(ranges);
    return 0;
}

typedef struct {
    long long start;
    long long end;
    long long total;
    int partial;
} st_media_playback_plan;

/*
 * Java HttpMediaPlaybackService.plan: 0 with the plan; 1 when Java throws MediaRangeException
 * (message holds the reason); -1 when the resource has nothing to play.
 */
static int media_plan_playback(const st_media_capture_row *anchor,
                               const st_media_playback_parts *parts,
                               const char *range_header,
                               st_media_playback_plan *plan,
                               char *message, size_t message_len)
{
    memset(plan, 0, sizeof(*plan));
    plan->total = parts->total;
    if (parts->len == 0U) {
        media_copy(message, message_len, "媒体采集没有可回放的数据");
        return -1;
    }
    int range_requested = media_has_text(range_header);
    char reason[160];
    int playable = media_parts_coverage(parts, reason, sizeof(reason));
    long long start = 0, requested_end = 0;
    if (!range_requested && !playable) {
        if (media_initial_sparse_range(anchor, parts, &start, &requested_end, message, message_len) != 0)
            return 1;
    } else if (media_parse_playback_range(range_header, parts->total, &start, &requested_end,
                                          message, message_len) != 0) {
        return 1;
    }
    /* Java contiguousAvailableEnd: stop at the first byte no capture holds. */
    long long cursor = start;
    long long available_end = start - 1LL;
    while (cursor <= requested_end) {
        long long selected = media_parts_furthest_end(parts, cursor);
        if (selected < cursor) {
            if (available_end < start) {
                snprintf(message, message_len, "请求位置尚未缓存，缺少字节 %lld", cursor);
                return 1;
            }
            break;
        }
        available_end = selected < requested_end ? selected : requested_end;
        if (available_end == LLONG_MAX) break;
        cursor = available_end + 1LL;
    }
    plan->start = start;
    plan->end = available_end;
    plan->partial = range_requested || start > 0 || available_end < parts->total - 1LL;
    return 0;
}

static int media_header_safe(const char *value)
{
    if (value == NULL || *value == '\0') return 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (*cursor == '\r' || *cursor == '\n' || (*cursor < 0x20U && *cursor != '\t')) return 0;
    }
    return 1;
}

/*
 * Plays row's resource. A MediaRangeException answers 416 with its reason, or, when the ticket
 * allows backfill, a 307 to origin_source on the anchor's original route (Java writePlayback).
 */
static int media_playback_response(const char *method,
                                   sqlite3 *db,
                                   const st_media_capture_row *row,
                                   const char *range_header,
                                   int backfill,
                                   const st_media_capture_row *anchor,
                                   const char *origin_source,
                                   char *out,
                                   size_t out_len)
{
    st_media_playback_parts parts;
    if (media_load_playback_parts(db, row, &parts) != 0)
        return media_write_cache_miss(out, out_len, method, 500, "媒体采集读取失败", 0);
    st_media_playback_plan plan;
    char message[160];
    int planned = media_plan_playback(row, &parts, range_header, &plan, message, sizeof(message));
    if (planned != 0) {
        free(parts.items);
        if (planned < 0) return media_write_cache_miss(out, out_len, method, 409, message, 0);
        return backfill
            ? media_write_origin_redirect(out, out_len, anchor, origin_source)
            : media_write_cache_miss(out, out_len, method, 416, message, plan.total);
    }
    long long start = plan.start;
    long long end = plan.end;
    long long total = plan.total;
    size_t max_body = out_len > 4096U ? out_len - 4096U : 0U;
    unsigned long long planned_len = (unsigned long long)(end - start) + 1ULL;
    if (planned_len > max_body) {
        if (max_body == 0U) {
            free(parts.items);
            return -1;
        }
        end = start + (long long)max_body - 1LL;
    }
    st_media_builder body = {0};
    int include_body = strcasecmp(method, "HEAD") != 0;
    st_media_config cfg = media_load_config();
    long long cursor = start;
    while (include_body && cursor <= end) {
        size_t selected = SIZE_MAX;
        long long selected_end = -1;
        for (size_t i = 0; i < parts.len; ++i) {
            if (parts.items[i].start <= cursor && parts.items[i].end >= cursor
                && parts.items[i].end > selected_end) {
                selected = i;
                selected_end = parts.items[i].end;
            }
        }
        if (selected == SIZE_MAX) break;
        long long logical_end = selected_end < end ? selected_end : end;
        long long object_start = cursor - parts.items[selected].start;
        long long object_end = logical_end - parts.items[selected].start;
        char object_range[96];
        snprintf(object_range, sizeof(object_range), "%lld-%lld", object_start, object_end);
        st_media_http_response response = {0};
        if (media_s3_request(&cfg, "GET", parts.items[selected].object_key, "", NULL, NULL,
                             NULL, 0U, object_range, &response) != 0
            || !media_s3_success(&response)
            || response.data == NULL
            || response.len != (size_t)(logical_end - cursor + 1LL)
            || media_builder_append_len(&body, response.data,
                                        (size_t)(logical_end - cursor + 1LL)) != 0) {
            media_http_response_free(&response);
            free(parts.items);
            free(body.data);
            return media_write_json_error(out, out_len, 503, "媒体播放对象读取失败");
        }
        media_http_response_free(&response);
        cursor = logical_end + 1LL;
    }
    free(parts.items);
    if (include_body && cursor <= end) {
        free(body.data);
        return media_write_json_error(out, out_len, 503, "媒体播放对象不连续");
    }
    int partial = plan.partial || end < plan.end;
    st_media_builder headers = {0};
    int headers_ok = media_builder_append(&headers, "Accept-Ranges: bytes\r\n") == 0;
    if (headers_ok && partial)
        headers_ok = media_builder_appendf(&headers, "Content-Range: bytes %lld-%lld/%lld\r\n",
                                           start, end, total) == 0;
    if (headers_ok && media_header_safe(row->content_encoding))
        headers_ok = media_builder_appendf(&headers, "Content-Encoding: %s\r\n",
                                           row->content_encoding) == 0;
    const char *etag = media_header_safe(row->entity_tag) ? row->entity_tag
        : (media_header_safe(row->object_etag) ? row->object_etag : NULL);
    if (headers_ok && etag != NULL)
        headers_ok = media_builder_appendf(&headers, "ETag: %s\r\n", etag) == 0;
    const char *content_type = media_header_safe(row->content_type)
        ? row->content_type : "application/octet-stream";
    size_t body_len = (size_t)(end - start + 1LL);
    int result = headers_ok
        ? media_write_response(out, out_len, partial ? 206 : 200, content_type,
                               headers.data, body.data, body_len, include_body)
        : -1;
    free(headers.data);
    free(body.data);
    return result;
}

/*
 * Java writeManifest: the newest complete capture of the manifest's URL (a live playlist keeps
 * changing), decoded and with every reference pointing at asset_base.
 */
static int media_manifest_response(const char *method,
                                   sqlite3 *db,
                                   const st_media_capture_row *row,
                                   const char *asset_base,
                                   char *out, size_t out_len)
{
    st_media_capture_row latest;
    if (media_load_latest_source(db, row, row->source_url, 1, &latest) != 0) latest = *row;
    if (strcmp(latest.state, "COMPLETE") != 0 || !media_kind_is_manifest(latest.media_kind))
        return media_write_cache_miss(out, out_len, method, 409, "媒体清单尚未采集完成", 0);
    st_media_http_response response;
    st_media_config cfg = media_load_config();
    if (media_s3_request(&cfg, "GET", latest.object_key, "", NULL, NULL, NULL, 0U, NULL, &response) != 0
        || !media_s3_success(&response)) {
        media_http_response_free(&response);
        return media_write_cache_miss(out, out_len, method, 409, "媒体清单尚未采集完成", 0);
    }
    char *text = media_decode_manifest_text((const uint8_t *)(response.data == NULL ? "" : response.data),
                                            response.len, latest.content_encoding);
    media_http_response_free(&response);
    char *rewritten = text == NULL ? NULL
        : strcmp(latest.media_kind, "HLS_MANIFEST") == 0
            ? media_rewrite_hls(latest.source_url, text, asset_base)
            : media_rewrite_dash(latest.source_url, text, asset_base);
    free(text);
    if (rewritten == NULL) return media_write_json_error(out, out_len, 500, "媒体清单重写失败");
    const char *content_type = strcmp(row->media_kind, "HLS_MANIFEST") == 0
        ? "application/vnd.apple.mpegurl; charset=utf-8" : "application/dash+xml; charset=utf-8";
    size_t body_len = strlen(rewritten);
    int result = media_write_response(out, out_len, 200, content_type, NULL, rewritten, body_len,
                                      strcasecmp(method, "HEAD") != 0);
    free(rewritten);
    return result;
}

/* "/play", "/manifest" or "/asset" exactly, before any query. */
static int media_suffix_is(const char *suffix, const char *name)
{
    size_t len = strlen(name);
    return strncmp(suffix, name, len) == 0 && (suffix[len] == '\0' || suffix[len] == '?');
}

static int media_admin_resource_response(const char *method, const char *path,
                                         const char *range_header,
                                         const st_media_capture_identity *identity,
                                         const char *database_path,
                                         long long id, const char *suffix,
                                         char *out, size_t out_len)
{
    sqlite3 *db = NULL;
    st_media_capture_row anchor;
    if (!g_media_ready) return media_write_json_error(out, out_len, 503, "媒体采集服务不可用");
    if (media_db_open(database_path, &db) != 0 || media_load_row(db, identity->tenant_id, id, &anchor) != 0
        || !media_identity_can_access(db, identity, &anchor)) {
        if (db != NULL) sqlite3_close(db);
        return media_write_json_error(out, out_len, 404, "媒体采集记录不存在");
    }
    if (media_suffix_is(suffix, "/playback-ticket")) {
        sqlite3_close(db);
        return strcasecmp(method, "POST") == 0
            ? media_create_ticket(path, identity, database_path, id, out, out_len)
            : 0;
    }
    st_media_capture_row target = anchor;
    int asset = media_suffix_is(suffix, "/asset");
    if (asset) {
        char *url = media_query_value(path, "url");
        int found = url != NULL && media_load_latest_source(db, &anchor, url, 0, &target) == 0;
        free(url);
        if (!found) {
            sqlite3_close(db);
            return media_write_json_error(out, out_len, 404, "对应媒体分段尚未采集完成");
        }
    }
    int result = 0;
    if (media_suffix_is(suffix, "/manifest") || (asset && media_kind_is_manifest(target.media_kind))) {
        char base[256];
        snprintf(base, sizeof(base), "/api/admin/traffic/media-captures/%lld/asset", target.id);
        result = media_manifest_response(method, db, &target, base, out, out_len);
    } else if (media_suffix_is(suffix, "/play") || asset) {
        result = strcmp(target.state, "COMPLETE") != 0
            ? media_write_json_error(out, out_len, 409, "媒体采集尚未完成")
            : media_playback_response(method, db, &target, range_header, 0, &anchor, NULL,
                                      out, out_len);
    }
    sqlite3_close(db);
    return result;
}

/* Java PublicHttpMediaPlaybackResource: ticket-bound play, manifest and asset. */
static int media_public_resource_response(const char *method, const char *path,
                                          const char *range_header,
                                          const char *database_path,
                                          char *out, size_t out_len)
{
    const char *prefix = "/api/public/media-playback/";
    if (strncmp(path, prefix, strlen(prefix)) != 0) return 0;
    const char *token_start = path + strlen(prefix);
    const char *slash = strchr(token_start, '/');
    if (slash == NULL || slash == token_start || (size_t)(slash - token_start) > 64U) return 0;
    const char *suffix = slash;
    int play = media_suffix_is(suffix, "/play");
    int manifest = media_suffix_is(suffix, "/manifest");
    int asset = media_suffix_is(suffix, "/asset");
    if (!play && !manifest && !asset) return 0;
    char token[65];
    memcpy(token, token_start, (size_t)(slash - token_start));
    token[slash - token_start] = '\0';
    char tenant_id[64];
    long long capture_id = 0;
    int backfill = 0;
    if (media_resolve_ticket(token, tenant_id, &capture_id, &backfill) != 0)
        return media_write_cache_miss(out, out_len, method, 404, "媒体播放票据无效或已过期", 0);
    sqlite3 *db = NULL;
    st_media_capture_row anchor;
    if (media_db_open(database_path, &db) != 0 || media_load_row(db, tenant_id, capture_id, &anchor) != 0) {
        if (db != NULL) sqlite3_close(db);
        return media_write_cache_miss(out, out_len, method, 404, "媒体采集记录不存在", 0);
    }
    char asset_base[256];
    snprintf(asset_base, sizeof(asset_base), "/api/public/media-playback/%s/asset", token);
    int result = 0;
    if (manifest) {
        result = media_manifest_response(method, db, &anchor, asset_base, out, out_len);
    } else if (play) {
        result = strcmp(anchor.state, "COMPLETE") != 0
            ? media_write_cache_miss(out, out_len, method, 409, "媒体采集尚未完成", 0)
            : media_playback_response(method, db, &anchor, range_header, backfill, &anchor,
                                      anchor.source_url, out, out_len);
    } else {
        char *url = media_query_value(path, "url");
        st_media_capture_row target;
        if (url == NULL || media_load_latest_source(db, &anchor, url, 0, &target) != 0) {
            /* Java: an asset the capture never stored is a cache miss, or a backfill redirect. */
            result = backfill && url != NULL
                ? media_write_origin_redirect(out, out_len, &anchor, url)
                : media_write_cache_miss(out, out_len, method, 404, "媒体资源尚未缓存", 0);
        } else if (media_kind_is_manifest(target.media_kind)) {
            result = media_manifest_response(method, db, &target, asset_base, out, out_len);
        } else {
            result = media_playback_response(method, db, &target, range_header, backfill, &anchor,
                                             url, out, out_len);
        }
        free(url);
    }
    sqlite3_close(db);
    return result;
}

int st_media_capture_build_response_with_range(const char *method,
                                               const char *path,
                                               const char *range_header,
                                               const st_media_capture_identity *identity,
                                               const char *database_path,
                                               char *out,
                                               size_t out_len)
{
    if (method == NULL || path == NULL || database_path == NULL || out == NULL) return 0;
    if (strncmp(path, "/api/public/media-playback/", strlen("/api/public/media-playback/")) == 0)
        return media_public_resource_response(method, path, range_header,
                                              database_path, out, out_len);
    if (identity == NULL || !identity->authenticated) return 0;
    if (strcasecmp(method, "GET") == 0
        && (strcmp(path, "/api/admin/traffic/media-captures") == 0
            || strncmp(path, "/api/admin/traffic/media-captures?", strlen("/api/admin/traffic/media-captures?")) == 0))
        return media_list_response(path, identity, database_path, out, out_len);
    long long id = 0;
    const char *suffix = NULL;
    if (media_parse_capture_path(path, &id, &suffix) == 0)
        return media_admin_resource_response(method, path, range_header,
                                             identity, database_path,
                                             id, suffix, out, out_len);
    return 0;
}

int st_media_capture_build_response(const char *method,
                                    const char *path,
                                    const st_media_capture_identity *identity,
                                    const char *database_path,
                                    char *out,
                                    size_t out_len)
{
    return st_media_capture_build_response_with_range(method, path, NULL, identity,
                                                      database_path, out, out_len);
}
