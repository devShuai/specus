#define _POSIX_C_SOURCE 200809L

#include "object_storage.h"

#include "crypto.h"
#include "json.h"
#include "public_room.h"
#include "storage.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <utf8proc.h>

#define ST_OBJECT_MAX_BODY (64U * 1024U)
#define ST_OBJECT_MAX_KEY 1024U
#define ST_OBJECT_MAX_TTL (7LL * 24LL * 60LL * 60LL)
#define ST_OBJECT_DEFAULT_MAX_BYTES (512LL * 1024LL * 1024LL)
#define ST_OBJECT_DEFAULT_QUOTA_BYTES (1024LL * 1024LL * 1024LL)
#define ST_OBJECT_RATE_SOURCES 1024U

typedef struct {
    int enabled;
    char scheme[8];
    char endpoint_host[256];
    int endpoint_port;
    char region[80];
    char bucket[128];
    char access_key_id[256];
    char access_key_secret[512];
    char prefix[512];
    char callback_url[1024];
    long long upload_ttl;
    long long download_ttl;
    long long direct_download_ttl;
    long long retention_hours;
    long long max_attachment_bytes;
    long long storage_quota_bytes;
    long long download_quota_bytes;
    int presign_rate_limit;
    int presign_rate_window;
    int max_pending_per_room;
} st_object_config;

typedef struct {
    long long id;
    char tenant_id[81];
    char scope[41];
    char room_id[121];
    char room_token_hash[65];
    long long public_room_id;
    char owner_username[129];
    long long target_client_id;
    char object_key[ST_OBJECT_MAX_KEY + 1U];
    char file_name[256];
    char mime_type[121];
    long long size_bytes;
    char sha256[65];
    char status[25];
    char created_at[41];
    char updated_at[41];
    char upload_expires_at[41];
    char expires_at[41];
    char uploaded_at[41];
} st_attachment;

typedef struct st_object_rate_window {
    char address[128];
    time_t started_at;
    unsigned int count;
    struct st_object_rate_window *next;
} st_object_rate_window;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} st_object_buffer;

static pthread_mutex_t object_rate_lock = PTHREAD_MUTEX_INITIALIZER;
static st_object_rate_window *object_rate_windows = NULL;
static pthread_once_t object_curl_once = PTHREAD_ONCE_INIT;
static CURLcode object_curl_init_result = CURLE_FAILED_INIT;

static void object_curl_init(void)
{
    object_curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static const char *object_env_text(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value == NULL || *value == '\0' ? fallback : value;
}

static long long object_env_i64(const char *name, long long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(value, &end, 10);
    return errno == 0 && end != value && *end == '\0' ? parsed : fallback;
}

static int object_text_present(const char *value)
{
    if (value == NULL) return 0;
    while (*value != '\0') {
        if (!isspace((unsigned char)*value)) return 1;
        ++value;
    }
    return 0;
}

static int object_copy_trimmed(char *out, size_t out_len, const char *value)
{
    if (out == NULL || out_len == 0U) return -1;
    if (value == NULL) value = "";
    while (*value != '\0' && isspace((unsigned char)*value)) ++value;
    const char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    size_t len = (size_t)(end - value);
    if (len >= out_len) return -1;
    memcpy(out, value, len);
    out[len] = '\0';
    return 0;
}

static long long object_clamp_ttl(long long value, long long fallback)
{
    if (value <= 0) value = fallback;
    if (value > ST_OBJECT_MAX_TTL) value = ST_OBJECT_MAX_TTL;
    return value;
}

static int object_parse_endpoint(const char *input, st_object_config *config)
{
    char endpoint[512];
    if (object_copy_trimmed(endpoint, sizeof(endpoint), input) != 0 || endpoint[0] == '\0') return -1;
    const char *scheme_end = strstr(endpoint, "://");
    const char *authority = endpoint;
    if (scheme_end == NULL) {
        strcpy(config->scheme, "https");
    } else {
        size_t scheme_len = (size_t)(scheme_end - endpoint);
        if (scheme_len == 4U && strncasecmp(endpoint, "http", 4U) == 0) strcpy(config->scheme, "http");
        else if (scheme_len == 5U && strncasecmp(endpoint, "https", 5U) == 0) strcpy(config->scheme, "https");
        else return -1;
        authority = scheme_end + 3;
    }
    const char *authority_end = strchr(authority, '/');
    if (authority_end == NULL) authority_end = authority + strlen(authority);
    if (authority == authority_end || memchr(authority, '@', (size_t)(authority_end - authority)) != NULL) return -1;
    const char *colon = NULL;
    for (const char *cursor = authority; cursor < authority_end; ++cursor) {
        if (*cursor == ':') colon = cursor;
    }
    const char *host_end = colon == NULL ? authority_end : colon;
    size_t host_len = (size_t)(host_end - authority);
    if (host_len == 0U || host_len >= sizeof(config->endpoint_host)) return -1;
    memcpy(config->endpoint_host, authority, host_len);
    config->endpoint_host[host_len] = '\0';
    config->endpoint_port = -1;
    if (colon != NULL) {
        char port_text[8];
        size_t port_len = (size_t)(authority_end - colon - 1);
        if (port_len == 0U || port_len >= sizeof(port_text)) return -1;
        memcpy(port_text, colon + 1, port_len);
        port_text[port_len] = '\0';
        char *end = NULL;
        long port = strtol(port_text, &end, 10);
        if (end == port_text || *end != '\0' || port <= 0 || port > 65535) return -1;
        config->endpoint_port = (int)port;
    }
    return 0;
}

static int object_infer_region(st_object_config *config)
{
    if (config->region[0] != '\0') return 0;
    if (strncasecmp(config->endpoint_host, "oss-", 4U) != 0) return -1;
    const char *start = config->endpoint_host + 4;
    const char *dot = strchr(start, '.');
    size_t len = dot == NULL ? strlen(start) : (size_t)(dot - start);
    static const char internal[] = "-internal";
    if (len > sizeof(internal) - 1U
        && strncmp(start + len - (sizeof(internal) - 1U), internal, sizeof(internal) - 1U) == 0) {
        len -= sizeof(internal) - 1U;
    }
    if (len < 4U || len >= sizeof(config->region) || strncmp(start, "accelerate", len) == 0) return -1;
    memcpy(config->region, start, len);
    config->region[len] = '\0';
    return 0;
}

static void object_normalize_prefix(char *prefix)
{
    char *start = prefix;
    while (*start == '/') ++start;
    if (start != prefix) memmove(prefix, start, strlen(start) + 1U);
    size_t len = strlen(prefix);
    while (len > 0U && prefix[len - 1U] == '/') prefix[--len] = '\0';
}

static int object_load_config(st_object_config *config)
{
    memset(config, 0, sizeof(*config));
    const char *provider = object_env_text("SPECUS_OBJECT_STORAGE_PROVIDER", "disabled");
    if (strcasecmp(provider, "disabled") == 0) return 0;
    if (strcasecmp(provider, "aliyun-oss") != 0) return -1;
    if (object_parse_endpoint(getenv("SPECUS_OBJECT_STORAGE_ENDPOINT"), config) != 0
        || object_copy_trimmed(config->region, sizeof(config->region), getenv("SPECUS_OBJECT_STORAGE_REGION")) != 0
        || object_copy_trimmed(config->bucket, sizeof(config->bucket), getenv("SPECUS_OBJECT_STORAGE_BUCKET")) != 0
        || object_copy_trimmed(config->access_key_id, sizeof(config->access_key_id), getenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID")) != 0
        || object_copy_trimmed(config->access_key_secret, sizeof(config->access_key_secret), getenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET")) != 0
        || object_copy_trimmed(config->prefix, sizeof(config->prefix), object_env_text("SPECUS_OBJECT_STORAGE_PREFIX", "specus/attachments")) != 0
        || object_copy_trimmed(config->callback_url, sizeof(config->callback_url), getenv("SPECUS_OBJECT_STORAGE_UPLOAD_CALLBACK_URL")) != 0
        || config->bucket[0] == '\0' || config->access_key_id[0] == '\0'
        || config->access_key_secret[0] == '\0' || object_infer_region(config) != 0) return -1;
    object_normalize_prefix(config->prefix);
    config->upload_ttl = object_clamp_ttl(object_env_i64("SPECUS_OBJECT_STORAGE_UPLOAD_URL_TTL_SECONDS", 900), 900);
    config->download_ttl = object_clamp_ttl(object_env_i64("SPECUS_OBJECT_STORAGE_DOWNLOAD_URL_TTL_SECONDS", 600), 600);
    config->direct_download_ttl = object_clamp_ttl(object_env_i64("SPECUS_OBJECT_STORAGE_DOWNLOAD_OBJECT_URL_TTL_SECONDS", 30), 30);
    config->retention_hours = object_env_i64("SPECUS_OBJECT_STORAGE_RETENTION_HOURS", 72);
    if (config->retention_hours <= 0) config->retention_hours = 72;
    config->max_attachment_bytes = object_env_i64("SPECUS_OBJECT_STORAGE_MAX_ATTACHMENT_BYTES", ST_OBJECT_DEFAULT_MAX_BYTES);
    if (config->max_attachment_bytes <= 0) config->max_attachment_bytes = ST_OBJECT_DEFAULT_MAX_BYTES;
    config->storage_quota_bytes = object_env_i64("SPECUS_OBJECT_STORAGE_PER_USER_STORAGE_QUOTA_BYTES", ST_OBJECT_DEFAULT_QUOTA_BYTES);
    if (config->storage_quota_bytes <= 0) config->storage_quota_bytes = ST_OBJECT_DEFAULT_QUOTA_BYTES;
    config->download_quota_bytes = object_env_i64("SPECUS_OBJECT_STORAGE_PER_USER_MONTHLY_DOWNLOAD_QUOTA_BYTES", ST_OBJECT_DEFAULT_QUOTA_BYTES);
    if (config->download_quota_bytes <= 0) config->download_quota_bytes = ST_OBJECT_DEFAULT_QUOTA_BYTES;
    config->presign_rate_limit = (int)object_env_i64("SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_PER_IP", 30);
    if (config->presign_rate_limit <= 0) config->presign_rate_limit = 30;
    config->presign_rate_window = (int)object_env_i64("SPECUS_PUBLIC_TRANSFER_PRESIGN_RATE_LIMIT_WINDOW_SECONDS", 300);
    if (config->presign_rate_window <= 0) config->presign_rate_window = 300;
    config->max_pending_per_room = (int)object_env_i64("SPECUS_PUBLIC_TRANSFER_MAX_PENDING_UPLOADS_PER_ROOM", 50);
    if (config->max_pending_per_room <= 0) config->max_pending_per_room = 50;
    config->enabled = 1;
    return 0;
}

int st_object_storage_enabled_current(void)
{
    st_object_config config;
    return object_load_config(&config) == 0 && config.enabled;
}

int st_object_storage_validate_current(void)
{
    st_object_config config;
    int rc = object_load_config(&config);
    if (rc != 0) {
        fprintf(stderr, "object storage configuration is invalid; provider aliyun-oss requires endpoint, region, bucket and access keys\n");
        return -1;
    }
    return 0;
}

static int object_buffer_reserve(st_object_buffer *buffer, size_t extra)
{
    if (extra > SIZE_MAX - buffer->len - 1U) return -1;
    size_t needed = buffer->len + extra + 1U;
    if (needed <= buffer->cap) return 0;
    size_t next = buffer->cap == 0U ? 1024U : buffer->cap;
    while (next < needed) {
        if (next > SIZE_MAX / 2U) return -1;
        next *= 2U;
    }
    char *data = (char *)realloc(buffer->data, next);
    if (data == NULL) return -1;
    buffer->data = data;
    buffer->cap = next;
    return 0;
}

static int object_buffer_append_n(st_object_buffer *buffer, const char *value, size_t len)
{
    if (object_buffer_reserve(buffer, len) != 0) return -1;
    memcpy(buffer->data + buffer->len, value, len);
    buffer->len += len;
    buffer->data[buffer->len] = '\0';
    return 0;
}

static int object_buffer_append(st_object_buffer *buffer, const char *value)
{
    return object_buffer_append_n(buffer, value, strlen(value));
}

static char *object_uri_encode(const char *value, int encode_slash)
{
    static const char hex[] = "0123456789ABCDEF";
    st_object_buffer out = {0};
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        unsigned int ch = *cursor;
        int unreserved = isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~';
        if (unreserved || (!encode_slash && ch == '/')) {
            char one = (char)ch;
            if (object_buffer_append_n(&out, &one, 1U) != 0) goto error;
        } else {
            char encoded[3] = {'%', hex[ch >> 4U], hex[ch & 15U]};
            if (object_buffer_append_n(&out, encoded, sizeof(encoded)) != 0) goto error;
        }
    }
    if (out.data == NULL) out.data = strdup("");
    return out.data;
error:
    free(out.data);
    return NULL;
}

static void object_sha256_hex(const char *value, char out[65])
{
    uint8_t digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)value, strlen(value), digest);
    st_hex_encode(digest, sizeof(digest), out);
}

static char *object_base64(const uint8_t *value, size_t len)
{
    if (len > (size_t)INT_MAX) return NULL;
    size_t out_len = 4U * ((len + 2U) / 3U);
    char *out = (char *)malloc(out_len + 1U);
    if (out == NULL) return NULL;
    int written = EVP_EncodeBlock((unsigned char *)out, value, (int)len);
    if (written < 0 || (size_t)written != out_len) {
        free(out);
        return NULL;
    }
    out[out_len] = '\0';
    return out;
}

static int object_times(time_t now, char date[9], char timestamp[17], char iso[41])
{
    struct tm value;
    if (gmtime_r(&now, &value) == NULL) return -1;
    if (strftime(date, 9U, "%Y%m%d", &value) != 8U
        || strftime(timestamp, 17U, "%Y%m%dT%H%M%SZ", &value) != 16U
        || strftime(iso, 41U, "%Y-%m-%dT%H:%M:%SZ", &value) == 0U) return -1;
    return 0;
}

static int object_host(const st_object_config *config, char *out, size_t out_len)
{
    int written = config->endpoint_port > 0
        ? snprintf(out, out_len, "%s.%s:%d", config->bucket, config->endpoint_host, config->endpoint_port)
        : snprintf(out, out_len, "%s.%s", config->bucket, config->endpoint_host);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static char *object_callback_header(const st_object_config *config)
{
    if (config->callback_url[0] == '\0') return strdup("");
    const char *https_field = strncasecmp(config->callback_url, "https://", 8U) == 0
        ? ",\"callbackSNI\":true" : "";
    char *escaped = st_json_escape(config->callback_url);
    if (escaped == NULL) return NULL;
    st_object_buffer json = {0};
    int rc = object_buffer_append(&json, "{\"callbackUrl\":\"")
        || object_buffer_append(&json, escaped)
        || object_buffer_append(&json,
            "\",\"callbackBody\":\"{\\\"bucket\\\":${bucket},\\\"object\\\":${object},"
            "\\\"size\\\":${size},\\\"mimeType\\\":${mimeType},\\\"etag\\\":${etag}}\","
            "\"callbackBodyType\":\"application/json\"")
        || object_buffer_append(&json, https_field)
        || object_buffer_append(&json, "}");
    free(escaped);
    if (rc != 0) {
        free(json.data);
        return NULL;
    }
    char *encoded = object_base64((const uint8_t *)json.data, json.len);
    free(json.data);
    return encoded;
}

static char *object_presign(const st_object_config *config,
                            const char *method,
                            const char *object_key,
                            const char *content_type,
                            const char *grant_id,
                            long long ttl,
                            time_t now,
                            char expires_at[41],
                            char **callback_header_out)
{
    char date[9], timestamp[17], now_iso[41];
    if (object_times(now, date, timestamp, now_iso) != 0) return NULL;
    time_t expiry = now + (time_t)object_clamp_ttl(ttl, 1);
    char ignored_date[9], ignored_timestamp[17];
    if (object_times(expiry, ignored_date, ignored_timestamp, expires_at) != 0) return NULL;
    char host[512];
    if (object_host(config, host, sizeof(host)) != 0) return NULL;
    char scope[256];
    int scope_len = snprintf(scope, sizeof(scope), "%s/%s/oss/aliyun_v4_request", date, config->region);
    if (scope_len < 0 || (size_t)scope_len >= sizeof(scope)) return NULL;
    char credential[768];
    int credential_len = snprintf(credential, sizeof(credential), "%s/%s", config->access_key_id, scope);
    if (credential_len < 0 || (size_t)credential_len >= sizeof(credential)) return NULL;
    char *encoded_credential = object_uri_encode(credential, 1);
    char *encoded_grant = grant_id == NULL ? NULL : object_uri_encode(grant_id, 1);
    char *callback = strcasecmp(method, "PUT") == 0 ? object_callback_header(config) : strdup("");
    char *encoded_callback = callback != NULL && callback[0] != '\0' ? callback : NULL;
    if (encoded_credential == NULL || callback == NULL || (grant_id != NULL && encoded_grant == NULL)) goto error;

    st_object_buffer query = {0};
    char ttl_text[32];
    snprintf(ttl_text, sizeof(ttl_text), "%lld", object_clamp_ttl(ttl, 1));
    if (object_buffer_append(&query, "x-oss-additional-headers=host&x-oss-credential=") != 0
        || object_buffer_append(&query, encoded_credential) != 0
        || object_buffer_append(&query, "&x-oss-date=") != 0
        || object_buffer_append(&query, timestamp) != 0
        || object_buffer_append(&query, "&x-oss-expires=") != 0
        || object_buffer_append(&query, ttl_text) != 0
        || object_buffer_append(&query, "&x-oss-signature-version=OSS4-HMAC-SHA256") != 0
        || (encoded_grant != NULL && (object_buffer_append(&query, "&x-st-grant=") != 0
            || object_buffer_append(&query, encoded_grant) != 0))) goto error_query;

    char *resource_input = NULL;
    size_t resource_len = strlen(config->bucket) + strlen(object_key) + 3U;
    resource_input = (char *)malloc(resource_len);
    if (resource_input == NULL) goto error_query;
    snprintf(resource_input, resource_len, "/%s/%s", config->bucket, object_key);
    char *resource = object_uri_encode(resource_input, 0);
    free(resource_input);
    if (resource == NULL) goto error_query;

    st_object_buffer headers = {0};
    if (content_type != NULL && *content_type != '\0') {
        if (object_buffer_append(&headers, "content-type:") != 0
            || object_buffer_append(&headers, content_type) != 0
            || object_buffer_append(&headers, "\n") != 0) goto error_canonical;
    }
    if (object_buffer_append(&headers, "host:") != 0
        || object_buffer_append(&headers, host) != 0
        || object_buffer_append(&headers, "\n") != 0) goto error_canonical;
    if (encoded_callback != NULL) {
        if (object_buffer_append(&headers, "x-oss-callback:") != 0
            || object_buffer_append(&headers, encoded_callback) != 0
            || object_buffer_append(&headers, "\n") != 0) goto error_canonical;
    }
    st_object_buffer canonical = {0};
    if (object_buffer_append(&canonical, method) != 0
        || object_buffer_append(&canonical, "\n") != 0
        || object_buffer_append(&canonical, resource) != 0
        || object_buffer_append(&canonical, "\n") != 0
        || object_buffer_append(&canonical, query.data) != 0
        || object_buffer_append(&canonical, "\n") != 0
        || object_buffer_append(&canonical, headers.data) != 0
        || object_buffer_append(&canonical, "\nhost\nUNSIGNED-PAYLOAD") != 0) goto error_canonical_request;
    char canonical_hash[65];
    object_sha256_hex(canonical.data, canonical_hash);
    char string_to_sign[1024];
    int sts_len = snprintf(string_to_sign, sizeof(string_to_sign),
                           "OSS4-HMAC-SHA256\n%s\n%s\n%s", timestamp, scope, canonical_hash);
    if (sts_len < 0 || (size_t)sts_len >= sizeof(string_to_sign)) goto error_canonical_request;
    char initial_secret[544];
    int initial_len = snprintf(initial_secret, sizeof(initial_secret), "aliyun_v4%s", config->access_key_secret);
    if (initial_len < 0 || (size_t)initial_len >= sizeof(initial_secret)) goto error_canonical_request;
    uint8_t date_key[32], region_key[32], service_key[32], signing_key[32], signature[32];
    st_hmac_sha256((const uint8_t *)initial_secret, (size_t)initial_len,
                   (const uint8_t *)date, strlen(date), date_key);
    st_hmac_sha256(date_key, sizeof(date_key), (const uint8_t *)config->region, strlen(config->region), region_key);
    st_hmac_sha256(region_key, sizeof(region_key), (const uint8_t *)"oss", 3U, service_key);
    st_hmac_sha256(service_key, sizeof(service_key), (const uint8_t *)"aliyun_v4_request", 17U, signing_key);
    st_hmac_sha256(signing_key, sizeof(signing_key), (const uint8_t *)string_to_sign, (size_t)sts_len, signature);
    char signature_hex[65];
    st_hex_encode(signature, sizeof(signature), signature_hex);

    char *encoded_key = object_uri_encode(object_key, 0);
    if (encoded_key == NULL) goto error_canonical_request;
    st_object_buffer url = {0};
    if (object_buffer_append(&url, config->scheme) != 0
        || object_buffer_append(&url, "://") != 0
        || object_buffer_append(&url, host) != 0
        || object_buffer_append(&url, "/") != 0
        || object_buffer_append(&url, encoded_key) != 0
        || object_buffer_append(&url, "?x-oss-additional-headers=host&x-oss-credential=") != 0
        || object_buffer_append(&url, encoded_credential) != 0
        || object_buffer_append(&url, "&x-oss-date=") != 0
        || object_buffer_append(&url, timestamp) != 0
        || object_buffer_append(&url, "&x-oss-expires=") != 0
        || object_buffer_append(&url, ttl_text) != 0
        || object_buffer_append(&url, "&x-oss-signature=") != 0
        || object_buffer_append(&url, signature_hex) != 0
        || object_buffer_append(&url, "&x-oss-signature-version=OSS4-HMAC-SHA256") != 0
        || (encoded_grant != NULL && (object_buffer_append(&url, "&x-st-grant=") != 0
            || object_buffer_append(&url, encoded_grant) != 0))) {
        free(encoded_key);
        free(url.data);
        goto error_canonical_request;
    }
    free(encoded_key);
    free(canonical.data);
    free(headers.data);
    free(resource);
    free(query.data);
    free(encoded_credential);
    free(encoded_grant);
    if (callback_header_out != NULL) *callback_header_out = callback;
    else free(callback);
    return url.data;

error_canonical_request:
    free(canonical.data);
error_canonical:
    free(headers.data);
    free(resource);
error_query:
    free(query.data);
error:
    free(encoded_credential);
    free(encoded_grant);
    free(callback);
    return NULL;
}

static int object_write_response(char *out,
                                 size_t out_len,
                                 int status,
                                 const char *reason,
                                 const char *body)
{
    size_t body_len = body == NULL ? 0U : strlen(body);
    int written = snprintf(out, out_len,
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: application/json\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Content-Length: %zu\r\n\r\n%s",
                           status, reason, body_len, body == NULL ? "" : body);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static int object_error(char *out, size_t out_len, int status, const char *message)
{
    const char *reason = status == 400 ? "Bad Request"
        : status == 401 ? "Unauthorized"
        : status == 403 ? "Forbidden"
        : status == 404 ? "Not Found"
        : status == 409 ? "Conflict"
        : status == 410 ? "Gone"
        : status == 413 ? "Payload Too Large"
        : status == 429 ? "Too Many Requests"
        : status == 503 ? "Service Unavailable" : "Internal Server Error";
    char *escaped = st_json_escape(message == NULL ? "attachment operation failed" : message);
    if (escaped == NULL) return -1;
    st_object_buffer json = {0};
    int rc = object_buffer_append(&json, "{\"error\":\"")
        || object_buffer_append(&json, escaped)
        || object_buffer_append(&json, "\"}");
    free(escaped);
    if (rc != 0) {
        free(json.data);
        return -1;
    }
    int result = object_write_response(out, out_len, status, reason, json.data);
    free(json.data);
    return result;
}

static int object_disabled(char *out, size_t out_len)
{
    return object_write_response(out, out_len, 409, "Conflict",
        "{\"error\":\"object storage is not configured\","
        "\"code\":\"OBJECT_STORAGE_DISABLED\",\"enabled\":false}");
}

static int object_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t offset = 0U;
    while (offset < len) {
        ssize_t read_len = read(fd, out + offset, len - offset);
        if (read_len <= 0) {
            if (read_len < 0 && errno == EINTR) continue;
            close(fd);
            return -1;
        }
        offset += (size_t)read_len;
    }
    close(fd);
    return 0;
}

static long long object_new_id(void)
{
    uint8_t bytes[8];
    if (object_random(bytes, sizeof(bytes)) != 0) return -1;
    uint64_t value = 0U;
    for (size_t i = 0; i < sizeof(bytes); ++i) value = (value << 8U) | bytes[i];
    value &= UINT64_C(0x7fffffffffffffff);
    return value == 0U ? 1LL : (long long)value;
}

static int object_iso_time(time_t value, char out[41])
{
    char date[9], timestamp[17];
    return object_times(value, date, timestamp, out);
}

static int object_open(sqlite3 **db)
{
    const char *path = getenv("SPECUS_DATABASE_PATH");
    if (path == NULL || *path == '\0') return 1;
    if (sqlite3_open(path, db) != SQLITE_OK) {
        if (*db != NULL) sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    if (sqlite3_busy_timeout(*db, 5000) != SQLITE_OK) {
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS transfer_attachment ("
        "id INTEGER PRIMARY KEY,tenant_id TEXT,scope TEXT NOT NULL,room_id TEXT,"
        "room_token_hash TEXT,public_transfer_room_id INTEGER,owner_username TEXT,"
        "target_client_id INTEGER,object_key TEXT NOT NULL UNIQUE,file_name TEXT NOT NULL,"
        "mime_type TEXT NOT NULL,size_bytes INTEGER NOT NULL,sha256 TEXT,status TEXT NOT NULL,"
        "created_at TEXT NOT NULL,updated_at TEXT NOT NULL,upload_expires_at TEXT NOT NULL,"
        "expires_at TEXT NOT NULL,uploaded_at TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_transfer_attachment_tenant "
        "ON transfer_attachment(tenant_id,scope,id);"
        "CREATE INDEX IF NOT EXISTS idx_transfer_attachment_room "
        "ON transfer_attachment(scope,room_id,id);"
        "CREATE INDEX IF NOT EXISTS idx_transfer_attachment_public_room "
        "ON transfer_attachment(scope,public_transfer_room_id,id);"
        "CREATE INDEX IF NOT EXISTS idx_transfer_attachment_owner_status "
        "ON transfer_attachment(tenant_id,owner_username,status,expires_at);"
        "CREATE INDEX IF NOT EXISTS idx_transfer_attachment_expires "
        "ON transfer_attachment(expires_at,status);"
        "CREATE TABLE IF NOT EXISTS transfer_attachment_download_grant ("
        "id INTEGER PRIMARY KEY,token_hash TEXT NOT NULL UNIQUE,tenant_id TEXT NOT NULL,"
        "username TEXT NOT NULL,attachment_id INTEGER NOT NULL,created_at TEXT NOT NULL,"
        "expires_at TEXT NOT NULL,consumed_at TEXT,updated_at TEXT);"
        "CREATE INDEX IF NOT EXISTS idx_attachment_download_grant_attachment "
        "ON transfer_attachment_download_grant(attachment_id,created_at);"
        "CREATE INDEX IF NOT EXISTS idx_attachment_download_grant_expires "
        "ON transfer_attachment_download_grant(expires_at,consumed_at);"
        "CREATE TABLE IF NOT EXISTS transfer_attachment_download_usage ("
        "id INTEGER PRIMARY KEY,tenant_id TEXT NOT NULL,username TEXT NOT NULL,"
        "attachment_id INTEGER NOT NULL,size_bytes INTEGER NOT NULL,usage_month TEXT NOT NULL,"
        "created_at TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_attachment_download_usage_account_month "
        "ON transfer_attachment_download_usage(tenant_id,username,usage_month);"
        "CREATE INDEX IF NOT EXISTS idx_attachment_download_usage_attachment "
        "ON transfer_attachment_download_usage(attachment_id,created_at);";
    char *error = NULL;
    int rc = sqlite3_exec(*db, schema, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "object storage sqlite error: %s\n", error == NULL ? sqlite3_errmsg(*db) : error);
        sqlite3_free(error);
        sqlite3_close(*db);
        *db = NULL;
        return -1;
    }
    return 0;
}

static int object_bind_text(sqlite3_stmt *stmt, int index, const char *value)
{
    if (value == NULL || *value == '\0') return sqlite3_bind_null(stmt, index) == SQLITE_OK ? 0 : -1;
    return sqlite3_bind_text(stmt, index, value, -1, SQLITE_TRANSIENT) == SQLITE_OK ? 0 : -1;
}

static void object_column_text(sqlite3_stmt *stmt, int column, char *out, size_t out_len)
{
    const char *value = (const char *)sqlite3_column_text(stmt, column);
    snprintf(out, out_len, "%s", value == NULL ? "" : value);
}

static void object_read_attachment(sqlite3_stmt *stmt, st_attachment *attachment)
{
    memset(attachment, 0, sizeof(*attachment));
    attachment->id = sqlite3_column_int64(stmt, 0);
    object_column_text(stmt, 1, attachment->tenant_id, sizeof(attachment->tenant_id));
    object_column_text(stmt, 2, attachment->scope, sizeof(attachment->scope));
    object_column_text(stmt, 3, attachment->room_id, sizeof(attachment->room_id));
    object_column_text(stmt, 4, attachment->room_token_hash, sizeof(attachment->room_token_hash));
    attachment->public_room_id = sqlite3_column_type(stmt, 5) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 5);
    object_column_text(stmt, 6, attachment->owner_username, sizeof(attachment->owner_username));
    attachment->target_client_id = sqlite3_column_type(stmt, 7) == SQLITE_NULL ? 0 : sqlite3_column_int64(stmt, 7);
    object_column_text(stmt, 8, attachment->object_key, sizeof(attachment->object_key));
    object_column_text(stmt, 9, attachment->file_name, sizeof(attachment->file_name));
    object_column_text(stmt, 10, attachment->mime_type, sizeof(attachment->mime_type));
    attachment->size_bytes = sqlite3_column_int64(stmt, 11);
    object_column_text(stmt, 12, attachment->sha256, sizeof(attachment->sha256));
    object_column_text(stmt, 13, attachment->status, sizeof(attachment->status));
    object_column_text(stmt, 14, attachment->created_at, sizeof(attachment->created_at));
    object_column_text(stmt, 15, attachment->updated_at, sizeof(attachment->updated_at));
    object_column_text(stmt, 16, attachment->upload_expires_at, sizeof(attachment->upload_expires_at));
    object_column_text(stmt, 17, attachment->expires_at, sizeof(attachment->expires_at));
    object_column_text(stmt, 18, attachment->uploaded_at, sizeof(attachment->uploaded_at));
}

static const char object_attachment_columns[] =
    "id,tenant_id,scope,room_id,room_token_hash,public_transfer_room_id,owner_username,"
    "target_client_id,object_key,file_name,mime_type,size_bytes,sha256,status,created_at,"
    "updated_at,upload_expires_at,expires_at,uploaded_at";

static int object_find_attachment(sqlite3 *db, long long id, const char *scope, st_attachment *attachment)
{
    char sql[768];
    snprintf(sql, sizeof(sql), "SELECT %s FROM transfer_attachment WHERE id=? AND scope=?", object_attachment_columns);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK
        || object_bind_text(stmt, 2, scope) != 0) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) object_read_attachment(stmt, attachment);
    sqlite3_finalize(stmt);
    return step == SQLITE_ROW ? 0 : step == SQLITE_DONE ? 1 : -1;
}

static int object_find_attachment_by_key(sqlite3 *db, const char *key, st_attachment *attachment)
{
    char sql[768];
    snprintf(sql, sizeof(sql), "SELECT %s FROM transfer_attachment WHERE object_key=?", object_attachment_columns);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK || object_bind_text(stmt, 1, key) != 0) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) object_read_attachment(stmt, attachment);
    sqlite3_finalize(stmt);
    return step == SQLITE_ROW ? 0 : step == SQLITE_DONE ? 1 : -1;
}

static int object_insert_attachment(sqlite3 *db, const st_attachment *value)
{
    static const char sql[] =
        "INSERT INTO transfer_attachment (id,tenant_id,scope,room_id,room_token_hash,"
        "public_transfer_room_id,owner_username,target_client_id,object_key,file_name,mime_type,"
        "size_bytes,sha256,status,created_at,updated_at,upload_expires_at,expires_at,uploaded_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL)";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    int rc = sqlite3_bind_int64(stmt, 1, value->id) == SQLITE_OK
        && object_bind_text(stmt, 2, value->tenant_id) == 0
        && object_bind_text(stmt, 3, value->scope) == 0
        && object_bind_text(stmt, 4, value->room_id) == 0
        && object_bind_text(stmt, 5, value->room_token_hash) == 0
        && (value->public_room_id == 0 ? sqlite3_bind_null(stmt, 6) : sqlite3_bind_int64(stmt, 6, value->public_room_id)) == SQLITE_OK
        && object_bind_text(stmt, 7, value->owner_username) == 0
        && (value->target_client_id == 0 ? sqlite3_bind_null(stmt, 8) : sqlite3_bind_int64(stmt, 8, value->target_client_id)) == SQLITE_OK
        && object_bind_text(stmt, 9, value->object_key) == 0
        && object_bind_text(stmt, 10, value->file_name) == 0
        && object_bind_text(stmt, 11, value->mime_type) == 0
        && sqlite3_bind_int64(stmt, 12, value->size_bytes) == SQLITE_OK
        && object_bind_text(stmt, 13, value->sha256) == 0
        && object_bind_text(stmt, 14, value->status) == 0
        && object_bind_text(stmt, 15, value->created_at) == 0
        && object_bind_text(stmt, 16, value->updated_at) == 0
        && object_bind_text(stmt, 17, value->upload_expires_at) == 0
        && object_bind_text(stmt, 18, value->expires_at) == 0
        && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return rc ? 0 : -1;
}

static int object_active_storage_bytes(sqlite3 *db,
                                       const char *tenant,
                                       const char *username,
                                       long long excluded_id,
                                       long long *bytes)
{
    static const char sql[] =
        "SELECT COALESCE(SUM(size_bytes),0) FROM transfer_attachment "
        "WHERE tenant_id=? AND owner_username=? AND id<>? AND "
        "((status='PENDING' AND upload_expires_at>?) OR (status='UPLOADED' AND expires_at>?))";
    char now[41];
    if (object_iso_time(time(NULL), now) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK
        || object_bind_text(stmt, 1, tenant) != 0
        || object_bind_text(stmt, 2, username) != 0
        || sqlite3_bind_int64(stmt, 3, excluded_id) != SQLITE_OK
        || object_bind_text(stmt, 4, now) != 0
        || object_bind_text(stmt, 5, now) != 0
        || sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *bytes = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int object_quota_allows(long long used, long long requested, long long limit)
{
    return requested >= 0 && used >= 0 && used <= limit && requested <= limit - used;
}

static int object_pending_count(sqlite3 *db, long long room_id, long long *count)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM transfer_attachment WHERE scope='PUBLIC_TRANSFER' "
            "AND public_transfer_room_id=? AND status='PENDING'", -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 1, room_id) != SQLITE_OK
        || sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int object_rate_allow(const char *address, int limit, int window_seconds)
{
    if (address == NULL || *address == '\0') address = "unknown";
    time_t now = time(NULL);
    pthread_mutex_lock(&object_rate_lock);
    st_object_rate_window **cursor = &object_rate_windows;
    size_t entries = 0U;
    st_object_rate_window *found = NULL;
    while (*cursor != NULL) {
        st_object_rate_window *entry = *cursor;
        if (now - entry->started_at >= window_seconds) {
            *cursor = entry->next;
            free(entry);
            continue;
        }
        if (strcmp(entry->address, address) == 0) found = entry;
        ++entries;
        cursor = &entry->next;
    }
    if (found == NULL && entries < ST_OBJECT_RATE_SOURCES) {
        found = (st_object_rate_window *)calloc(1U, sizeof(*found));
        if (found != NULL) {
            snprintf(found->address, sizeof(found->address), "%s", address);
            found->started_at = now;
            found->next = object_rate_windows;
            object_rate_windows = found;
        }
    }
    int allowed = found != NULL && found->count < (unsigned int)limit;
    if (allowed) ++found->count;
    pthread_mutex_unlock(&object_rate_lock);
    return allowed;
}

static size_t object_curl_discard(char *data, size_t size, size_t nmemb, void *context)
{
    (void)data;
    (void)context;
    return size * nmemb;
}

static struct curl_slist *object_test_resolve(const st_object_config *config, CURL *curl)
{
    const char *address = getenv("SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS");
    if (!object_text_present(address)) return NULL;
    char host[512], entry[768];
    int host_written = snprintf(host, sizeof(host), "%s.%s", config->bucket, config->endpoint_host);
    if (host_written < 0 || (size_t)host_written >= sizeof(host)) return NULL;
    int port = config->endpoint_port > 0 ? config->endpoint_port
        : strcasecmp(config->scheme, "https") == 0 ? 443 : 80;
    int written = snprintf(entry, sizeof(entry), "%s:%d:%s", host, port, address);
    if (written < 0 || (size_t)written >= sizeof(entry)) return NULL;
    struct curl_slist *resolve = curl_slist_append(NULL, entry);
    if (resolve == NULL || curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve) != CURLE_OK) {
        curl_slist_free_all(resolve);
        return NULL;
    }
    return resolve;
}

static int object_stat(const st_object_config *config, const char *key, int *exists, long long *length)
{
    char expires[41];
    char *url = object_presign(config, "HEAD", key, NULL, NULL, 60, time(NULL), expires, NULL);
    if (url == NULL) return -1;
    (void)pthread_once(&object_curl_once, object_curl_init);
    CURL *curl = object_curl_init_result == CURLE_OK ? curl_easy_init() : NULL;
    if (curl == NULL) {
        free(url);
        return -1;
    }
    struct curl_slist *resolve = object_test_resolve(config, curl);
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "HEAD");
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, object_curl_discard);
    if (rc == CURLE_OK) rc = curl_easy_perform(curl);
    long status = 0;
    curl_off_t content_length = -1;
    if (rc == CURLE_OK) rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc == CURLE_OK && status >= 200 && status < 300)
        (void)curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &content_length);
    curl_easy_cleanup(curl);
    curl_slist_free_all(resolve);
    free(url);
    if (rc != CURLE_OK) return -1;
    if (status == 404) {
        *exists = 0;
        *length = -1;
        return 0;
    }
    if (status < 200 || status >= 300) return -1;
    *exists = 1;
    *length = content_length > LLONG_MAX ? -1 : (long long)content_length;
    return 0;
}

static int object_delete(const st_object_config *config, const char *key)
{
    char expires[41];
    char *url = object_presign(config, "DELETE", key, NULL, NULL, 60, time(NULL), expires, NULL);
    if (url == NULL) return -1;
    (void)pthread_once(&object_curl_once, object_curl_init);
    CURL *curl = object_curl_init_result == CURLE_OK ? curl_easy_init() : NULL;
    if (curl == NULL) {
        free(url);
        return -1;
    }
    struct curl_slist *resolve = object_test_resolve(config, curl);
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, object_curl_discard);
    if (rc == CURLE_OK) rc = curl_easy_perform(curl);
    long status = 0;
    if (rc == CURLE_OK) rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    curl_slist_free_all(resolve);
    free(url);
    return rc == CURLE_OK && ((status >= 200 && status < 300) || status == 404) ? 0 : -1;
}

int st_object_storage_cleanup_expired(void)
{
    st_object_config config;
    if (object_load_config(&config) != 0) return -1;
    sqlite3 *db = NULL;
    int open_rc = object_open(&db);
    if (open_rc != 0) return open_rc > 0 ? 0 : -1;
    char now[41];
    if (object_iso_time(time(NULL), now) != 0) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "DELETE FROM transfer_attachment_download_grant WHERE expires_at<?",
            -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(stmt) == SQLITE_DONE ? 0 : -1;
    sqlite3_finalize(stmt);
    while (rc == 0) {
        long long ids[100];
        char keys[100][1024];
        size_t count = 0U;
        if (sqlite3_prepare_v2(db,
                "SELECT id,object_key FROM transfer_attachment "
                "WHERE expires_at<? AND status<>'EXPIRED' ORDER BY expires_at ASC LIMIT 100",
                -1, &stmt, NULL) != SQLITE_OK) {
            rc = -1;
            break;
        }
        sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
        while (count < 100U && sqlite3_step(stmt) == SQLITE_ROW) {
            ids[count] = sqlite3_column_int64(stmt, 0);
            const char *key = (const char *)sqlite3_column_text(stmt, 1);
            snprintf(keys[count], sizeof(keys[count]), "%s", key == NULL ? "" : key);
            ++count;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (count == 0U) break;
        size_t updated = 0U;
        for (size_t i = 0U; i < count; ++i) {
            if (config.enabled && object_delete(&config, keys[i]) != 0) {
                rc = -1;
                continue;
            }
            if (sqlite3_prepare_v2(db,
                    "UPDATE transfer_attachment SET status='EXPIRED',updated_at=? "
                    "WHERE id=? AND expires_at<? AND status<>'EXPIRED'",
                    -1, &stmt, NULL) != SQLITE_OK) {
                rc = -1;
                continue;
            }
            sqlite3_bind_text(stmt, 1, now, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, ids[i]);
            sqlite3_bind_text(stmt, 3, now, -1, SQLITE_TRANSIENT);
            int update_ok = sqlite3_step(stmt) == SQLITE_DONE;
            if (update_ok && sqlite3_changes(db) > 0) ++updated;
            else rc = -1;
            sqlite3_finalize(stmt);
            stmt = NULL;
        }
        if (updated == 0U) break;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

static int object_valid_sha256(const char *value)
{
    if (value == NULL || strlen(value) != 64U) return 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor)
        if (!isxdigit(*cursor)) return 0;
    return 1;
}

static int object_normalize_filename(const char *input, char out[256])
{
    if (input == NULL || *input == '\0') return -1;
    const char *segment = input;
    for (const char *cursor = input; *cursor != '\0'; ++cursor)
        if (*cursor == '/' || *cursor == '\\') segment = cursor + 1;
    st_object_buffer normalized = {0};
    int previous_invalid = 0;
    int previous_dot = 0;
    const utf8proc_uint8_t *cursor = (const utf8proc_uint8_t *)segment;
    size_t remaining = strlen(segment);
    while (remaining > 0U) {
        utf8proc_int32_t codepoint = 0;
        utf8proc_ssize_t consumed = utf8proc_iterate(cursor, (utf8proc_ssize_t)remaining, &codepoint);
        if (consumed <= 0) {
            codepoint = -1;
            consumed = 1;
        }
        int allowed = (codepoint >= 'A' && codepoint <= 'Z')
            || (codepoint >= 'a' && codepoint <= 'z')
            || (codepoint >= '0' && codepoint <= '9')
            || codepoint == '.' || codepoint == '_' || codepoint == '-';
        if (!allowed) {
            if (!previous_invalid && object_buffer_append(&normalized, "_") != 0) goto error;
            previous_invalid = 1;
            previous_dot = 0;
        } else {
            previous_invalid = 0;
            char one = (char)codepoint;
            if (codepoint == '.') {
                if (!previous_dot && object_buffer_append_n(&normalized, &one, 1U) != 0) goto error;
                previous_dot = 1;
            } else {
                if (object_buffer_append_n(&normalized, &one, 1U) != 0) goto error;
                previous_dot = 0;
            }
        }
        cursor += consumed;
        remaining -= (size_t)consumed;
    }
    if (normalized.len == 0U || strcmp(normalized.data, ".") == 0) {
        free(normalized.data);
        strcpy(out, "attachment");
        return 0;
    }
    size_t keep = normalized.len > 180U ? 180U : normalized.len;
    if (normalized.len > 180U) {
        char *dot = strrchr(normalized.data, '.');
        if (dot != NULL && dot != normalized.data) {
            size_t extension_len = normalized.len - (size_t)(dot - normalized.data);
            if (extension_len < 180U) {
                size_t base_len = 180U - extension_len;
                memcpy(out, normalized.data, base_len);
                memcpy(out + base_len, dot, extension_len);
                out[180] = '\0';
                free(normalized.data);
                return 0;
            }
        }
    }
    memcpy(out, normalized.data, keep);
    out[keep] = '\0';
    free(normalized.data);
    return 0;
error:
    free(normalized.data);
    return -1;
}

static int object_normalize_mime(const char *input, char out[121])
{
    if (!object_text_present(input)) {
        strcpy(out, "application/octet-stream");
        return 0;
    }
    if (object_copy_trimmed(out, 121U, input) != 0 || strchr(out, '\r') != NULL || strchr(out, '\n') != NULL)
        return -1;
    return 0;
}

static int object_normalize_room(const char *input, char out[121])
{
    if (!object_text_present(input)) {
        strcpy(out, "default");
        return 0;
    }
    return object_copy_trimmed(out, 121U, input) == 0
        && strchr(out, '\r') == NULL && strchr(out, '\n') == NULL ? 0 : -1;
}

static int object_validate_key(const st_object_config *config, const char *key)
{
    if (key == NULL || *key == '\0' || key[0] == '/' || strlen(key) > ST_OBJECT_MAX_KEY
        || strchr(key, '\\') != NULL || strstr(key, "..") != NULL || strstr(key, "//") != NULL) return -1;
    for (const unsigned char *cursor = (const unsigned char *)key; *cursor != '\0'; ++cursor)
        if (*cursor < 32U) return -1;
    size_t prefix_len = strlen(config->prefix);
    return prefix_len == 0U || (strncmp(key, config->prefix, prefix_len) == 0 && key[prefix_len] == '/') ? 0 : -1;
}

static int object_build_key(const st_object_config *config,
                            const char *scope,
                            long long id,
                            const char *filename,
                            time_t now,
                            char out[ST_OBJECT_MAX_KEY + 1U])
{
    char date[9], timestamp[17], iso[41];
    if (object_times(now, date, timestamp, iso) != 0) return -1;
    const char *segment = strcmp(scope, "PUBLIC_TRANSFER") == 0
        ? "public-transfer" : "admin-client-message";
    int written = config->prefix[0] == '\0'
        ? snprintf(out, ST_OBJECT_MAX_KEY + 1U, "%s/%s/%lld/%s", segment, date, id, filename)
        : snprintf(out, ST_OBJECT_MAX_KEY + 1U, "%s/%s/%s/%lld/%s", config->prefix, segment, date, id, filename);
    return written < 0 || written > (int)ST_OBJECT_MAX_KEY || object_validate_key(config, out) != 0 ? -1 : 0;
}

static int object_parse_nested_id(const char *path,
                                  const char *prefix,
                                  const char *suffix,
                                  long long *id)
{
    size_t prefix_len = strlen(prefix), suffix_len = strlen(suffix);
    if (strncmp(path, prefix, prefix_len) != 0) return -1;
    const char *start = path + prefix_len;
    char *end = NULL;
    errno = 0;
    long long parsed = strtoll(start, &end, 10);
    if (errno != 0 || end == start || parsed <= 0 || strncmp(end, suffix, suffix_len) != 0) return -1;
    const char *tail = end + suffix_len;
    if (*tail != '\0' && *tail != '?') return -1;
    *id = parsed;
    return 0;
}

static int object_path_equals(const char *path, const char *expected)
{
    size_t len = strlen(expected);
    return strncmp(path, expected, len) == 0 && (path[len] == '\0' || path[len] == '?');
}

static int object_attachment_view(st_object_buffer *json, const st_attachment *attachment)
{
    char *file = st_json_escape(attachment->file_name);
    char *mime = st_json_escape(attachment->mime_type);
    char *status = st_json_escape(attachment->status);
    char *expires = st_json_escape(attachment->expires_at);
    char *sha = attachment->sha256[0] == '\0' ? NULL : st_json_escape(attachment->sha256);
    if (file == NULL || mime == NULL || status == NULL || expires == NULL
        || (attachment->sha256[0] != '\0' && sha == NULL)) {
        free(file); free(mime); free(status); free(expires); free(sha);
        return -1;
    }
    char prefix[256];
    int written = snprintf(prefix, sizeof(prefix),
        "{\"attachmentId\":%lld,\"objectId\":\"%lld\",\"fileName\":\"",
        attachment->id, attachment->id);
    int rc = written < 0 || (size_t)written >= sizeof(prefix)
        || object_buffer_append(json, prefix) != 0
        || object_buffer_append(json, file) != 0
        || object_buffer_append(json, "\",\"mimeType\":\"") != 0
        || object_buffer_append(json, mime) != 0;
    char fields[256];
    written = snprintf(fields, sizeof(fields), "\",\"sizeBytes\":%lld,\"sha256\":", attachment->size_bytes);
    if (!rc) rc = written < 0 || (size_t)written >= sizeof(fields) || object_buffer_append(json, fields) != 0;
    if (!rc) rc = sha == NULL ? object_buffer_append(json, "null") : object_buffer_append(json, "\"")
        || (sha != NULL && object_buffer_append(json, sha))
        || (sha != NULL && object_buffer_append(json, "\""));
    if (!rc) rc = object_buffer_append(json, ",\"status\":\"")
        || object_buffer_append(json, status)
        || object_buffer_append(json, "\",\"expiresAt\":\"")
        || object_buffer_append(json, expires)
        || object_buffer_append(json, "\"}");
    free(file); free(mime); free(status); free(expires); free(sha);
    return rc ? -1 : 0;
}

static int object_write_view(char *out, size_t out_len, const st_attachment *attachment)
{
    st_object_buffer json = {0};
    if (object_attachment_view(&json, attachment) != 0) {
        free(json.data);
        return -1;
    }
    int result = object_write_response(out, out_len, 200, "OK", json.data);
    free(json.data);
    return result;
}

static int object_identity_valid(const st_object_storage_identity *identity)
{
    return identity != NULL && identity->authenticated
        && object_text_present(identity->tenant_id) && object_text_present(identity->username);
}

static int object_admin_client_access(const st_object_storage_identity *identity, long long client_id)
{
    const char *database = getenv("SPECUS_DATABASE_PATH");
    if (!object_identity_valid(identity) || database == NULL || *database == '\0') return 0;
    st_storage_client client;
    return st_storage_get_client(database, client_id, &client) == 0
        && strcmp(client.tenant_id, identity->tenant_id) == 0
        && (identity->admin || strcmp(client.owner_username, identity->username) == 0);
}

static int object_public_room_access(const char *room_id,
                                     const char *room_token,
                                     const char *username,
                                     int require_edit,
                                     long long *public_room_id,
                                     char token_hash[65])
{
    if (!object_text_present(room_token)) return 2;
    st_public_room_access access;
    int rc = st_public_room_resolve(room_id, room_token, username, &access);
    if (rc != 0) return rc;
    if (require_edit && strcmp(access.role, "VIEWER") == 0) return 3;
    static const char prefix[] = "room:";
    if (strncmp(access.room_key, prefix, sizeof(prefix) - 1U) != 0) return -1;
    char *end = NULL;
    long long parsed = strtoll(access.room_key + sizeof(prefix) - 1U, &end, 10);
    if (end == access.room_key + sizeof(prefix) - 1U || *end != '\0' || parsed <= 0) return -1;
    *public_room_id = parsed;
    object_sha256_hex(room_token, token_hash);
    return 0;
}

static int object_attachment_access(const st_attachment *attachment,
                                    const st_object_storage_identity *identity,
                                    const char *room_token,
                                    int require_edit)
{
    if (!object_identity_valid(identity)) return 1;
    if (strcmp(attachment->scope, "ADMIN_CLIENT_MESSAGE") == 0) {
        if (strcmp(attachment->tenant_id, identity->tenant_id) != 0) return 2;
        return object_admin_client_access(identity, attachment->target_client_id) ? 0 : 2;
    }
    long long room_id = 0;
    char token_hash[65];
    int rc = object_public_room_access(attachment->room_id, room_token, identity->username,
                                       require_edit, &room_id, token_hash);
    return rc == 0 && room_id == attachment->public_room_id ? 0 : 2;
}

static int object_upload_response(char *out,
                                  size_t out_len,
                                  const st_attachment *attachment,
                                  const char *url,
                                  const char *callback)
{
    char *escaped_key = st_json_escape(attachment->object_key);
    char *escaped_url = st_json_escape(url);
    char *escaped_mime = st_json_escape(attachment->mime_type);
    char *escaped_expiry = st_json_escape(attachment->upload_expires_at);
    char *escaped_callback = callback != NULL && *callback != '\0' ? st_json_escape(callback) : NULL;
    if (escaped_key == NULL || escaped_url == NULL || escaped_mime == NULL || escaped_expiry == NULL
        || (callback != NULL && *callback != '\0' && escaped_callback == NULL)) {
        free(escaped_key); free(escaped_url); free(escaped_mime); free(escaped_expiry); free(escaped_callback);
        return -1;
    }
    st_object_buffer json = {0};
    char prefix[256];
    snprintf(prefix, sizeof(prefix),
             "{\"attachmentId\":%lld,\"objectId\":\"%lld\",\"objectKey\":\"",
             attachment->id, attachment->id);
    int rc = object_buffer_append(&json, prefix)
        || object_buffer_append(&json, escaped_key)
        || object_buffer_append(&json, "\",\"uploadUrl\":\"")
        || object_buffer_append(&json, escaped_url)
        || object_buffer_append(&json, "\",\"uploadHeaders\":{\"Content-Type\":\"")
        || object_buffer_append(&json, escaped_mime)
        || object_buffer_append(&json, "\"");
    if (!rc && escaped_callback != NULL) rc = object_buffer_append(&json, ",\"x-oss-callback\":\"")
        || object_buffer_append(&json, escaped_callback) || object_buffer_append(&json, "\"");
    if (!rc) rc = object_buffer_append(&json, "},\"expiresAt\":\"")
        || object_buffer_append(&json, escaped_expiry)
        || object_buffer_append(&json, "\",\"attachment\":")
        || object_attachment_view(&json, attachment)
        || object_buffer_append(&json, "}");
    free(escaped_key); free(escaped_url); free(escaped_mime); free(escaped_expiry); free(escaped_callback);
    if (rc) {
        free(json.data);
        return -1;
    }
    int result = object_write_response(out, out_len, 200, "OK", json.data);
    free(json.data);
    return result;
}

static int object_begin(sqlite3 *db)
{
    return sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static void object_rollback(sqlite3 *db)
{
    (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
}

static int object_commit(sqlite3 *db)
{
    return sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
}

static int object_create_upload(const st_object_config *config,
                                int public_scope,
                                const char *body,
                                const char *remote_address,
                                const st_object_storage_identity *identity,
                                char *out,
                                size_t out_len)
{
    if (!object_identity_valid(identity)) return object_error(out, out_len, 401, "missing or invalid bearer token");
    if (body == NULL || strlen(body) > ST_OBJECT_MAX_BODY || !st_json_is_valid_object(body))
        return object_error(out, out_len, 400, "invalid attachment request");
    char *raw_filename = st_json_get_top_level_string(body, "fileName");
    char *raw_mime = st_json_get_top_level_string(body, "mimeType");
    char *raw_sha = st_json_get_top_level_string(body, "sha256");
    char *raw_room = st_json_get_top_level_string(body, "roomId");
    char *room_token = st_json_get_top_level_string(body, "roomToken");
    long long size_bytes = 0, target_client_id = 0;
    int request_ok = object_normalize_filename(raw_filename, (char[256]){0}) == 0
        && st_json_get_i64(body, "sizeBytes", &size_bytes) == 0
        && size_bytes > 0 && size_bytes <= config->max_attachment_bytes;
    st_attachment attachment;
    memset(&attachment, 0, sizeof(attachment));
    if (request_ok) request_ok = object_normalize_filename(raw_filename, attachment.file_name) == 0
        && object_normalize_mime(raw_mime, attachment.mime_type) == 0;
    if (raw_sha != NULL && *raw_sha != '\0') {
        if (!object_valid_sha256(raw_sha)) request_ok = 0;
        else {
            for (size_t i = 0; i < 64U; ++i) attachment.sha256[i] = (char)tolower((unsigned char)raw_sha[i]);
            attachment.sha256[64] = '\0';
        }
    }
    long long public_room_id = 0;
    if (public_scope) {
        if (object_normalize_room(raw_room, attachment.room_id) != 0) request_ok = 0;
        if (request_ok) {
            int room_rc = object_public_room_access(attachment.room_id, room_token, identity->username,
                                                    1, &public_room_id, attachment.room_token_hash);
            if (room_rc == 3) request_ok = 0;
            else if (room_rc != 0) request_ok = 0;
        }
        attachment.public_room_id = public_room_id;
    } else {
        if (st_json_get_i64(body, "targetClientId", &target_client_id) != 0 || target_client_id <= 0
            || !object_admin_client_access(identity, target_client_id)) request_ok = 0;
        attachment.target_client_id = target_client_id;
    }
    free(raw_filename); free(raw_mime); free(raw_sha); free(raw_room);
    if (!request_ok) {
        free(room_token);
        return object_error(out, out_len, 400, public_scope
            ? "invalid attachment request or room credential" : "target client is not accessible or attachment request is invalid");
    }
    if (public_scope && !object_rate_allow(remote_address, config->presign_rate_limit, config->presign_rate_window)) {
        free(room_token);
        return object_error(out, out_len, 429, "presign upload rate limit exceeded");
    }
    free(room_token);
    sqlite3 *db = NULL;
    int opened = object_open(&db);
    if (opened != 0) return object_error(out, out_len, 503, "attachment persistence is unavailable");
    if (object_begin(db) != 0) {
        sqlite3_close(db);
        return object_error(out, out_len, 503, "attachment persistence is busy");
    }
    long long used = 0;
    if (object_active_storage_bytes(db, identity->tenant_id, identity->username, -1, &used) != 0
        || !object_quota_allows(used, size_bytes, config->storage_quota_bytes)) {
        object_rollback(db);
        sqlite3_close(db);
        return object_error(out, out_len, used >= 0 ? 429 : 500, "OSS storage quota is insufficient");
    }
    if (public_scope) {
        long long pending = 0;
        if (object_pending_count(db, public_room_id, &pending) != 0
            || pending >= config->max_pending_per_room) {
            object_rollback(db);
            sqlite3_close(db);
            return object_error(out, out_len, pending >= config->max_pending_per_room ? 429 : 500,
                                "too many pending uploads in this room");
        }
    }
    attachment.size_bytes = size_bytes;
    snprintf(attachment.tenant_id, sizeof(attachment.tenant_id), "%s", identity->tenant_id);
    snprintf(attachment.owner_username, sizeof(attachment.owner_username), "%s", identity->username);
    strcpy(attachment.scope, public_scope ? "PUBLIC_TRANSFER" : "ADMIN_CLIENT_MESSAGE");
    strcpy(attachment.status, "PENDING");
    time_t now = time(NULL);
    if (object_iso_time(now, attachment.created_at) != 0
        || object_iso_time(now + (time_t)(config->retention_hours * 3600LL), attachment.expires_at) != 0) {
        object_rollback(db); sqlite3_close(db);
        return object_error(out, out_len, 500, "failed to allocate attachment time");
    }
    strcpy(attachment.updated_at, attachment.created_at);
    char *upload_url = NULL, *callback = NULL;
    int inserted = 0;
    for (int attempt = 0; attempt < 8 && !inserted; ++attempt) {
        attachment.id = object_new_id();
        if (attachment.id <= 0
            || object_build_key(config, attachment.scope, attachment.id, attachment.file_name,
                                now, attachment.object_key) != 0) continue;
        free(upload_url); free(callback);
        upload_url = object_presign(config, "PUT", attachment.object_key, attachment.mime_type, NULL,
                                    config->upload_ttl, now, attachment.upload_expires_at, &callback);
        if (upload_url == NULL) continue;
        inserted = object_insert_attachment(db, &attachment) == 0;
    }
    if (!inserted || object_commit(db) != 0) {
        object_rollback(db); sqlite3_close(db); free(upload_url); free(callback);
        return object_error(out, out_len, 500, "failed to allocate attachment");
    }
    sqlite3_close(db);
    int result = object_upload_response(out, out_len, &attachment, upload_url, callback);
    free(upload_url); free(callback);
    return result;
}

static int object_complete(const st_object_config *config,
                           int public_scope,
                           long long attachment_id,
                           const char *body,
                           const st_object_storage_identity *identity,
                           char *out,
                           size_t out_len)
{
    if (!object_identity_valid(identity)) return object_error(out, out_len, 401, "missing or invalid bearer token");
    char *room_token = public_scope && body != NULL ? st_json_get_top_level_string(body, "roomToken") : NULL;
    sqlite3 *db = NULL;
    if (object_open(&db) != 0) {
        free(room_token);
        return object_error(out, out_len, 503, "attachment persistence is unavailable");
    }
    st_attachment attachment;
    int found = object_find_attachment(db, attachment_id,
        public_scope ? "PUBLIC_TRANSFER" : "ADMIN_CLIENT_MESSAGE", &attachment);
    if (found != 0) {
        sqlite3_close(db); free(room_token);
        return object_error(out, out_len, found == 1 ? 404 : 500, "attachment not found");
    }
    int access = object_attachment_access(&attachment, identity, room_token, 1);
    free(room_token);
    if (access != 0) {
        sqlite3_close(db);
        return object_error(out, out_len, access == 1 ? 401 : 403, "attachment access is forbidden");
    }
    if (strcmp(attachment.status, "UPLOADED") == 0) {
        sqlite3_close(db);
        return object_write_view(out, out_len, &attachment);
    }
    char now[41];
    if (object_iso_time(time(NULL), now) != 0 || strcmp(attachment.status, "PENDING") != 0
        || strcmp(attachment.upload_expires_at, now) < 0) {
        sqlite3_close(db);
        return object_error(out, out_len, 409, "attachment is not pending or upload URL is expired");
    }
    int exists = 0;
    long long actual_size = -1;
    if (object_stat(config, attachment.object_key, &exists, &actual_size) != 0) {
        sqlite3_close(db);
        return object_error(out, out_len, 503, "failed to verify uploaded object");
    }
    if (!exists) {
        sqlite3_close(db);
        return object_error(out, out_len, 409, "attachment object was not uploaded");
    }
    if (actual_size > config->max_attachment_bytes) {
        (void)object_delete(config, attachment.object_key);
        sqlite3_close(db);
        return object_error(out, out_len, 400, "attachment is too large");
    }
    if (actual_size >= 0) attachment.size_bytes = actual_size;
    if (object_begin(db) != 0) {
        sqlite3_close(db);
        return object_error(out, out_len, 503, "attachment persistence is busy");
    }
    long long used = 0;
    if (object_active_storage_bytes(db, attachment.tenant_id, attachment.owner_username,
                                    attachment.id, &used) != 0
        || !object_quota_allows(used, attachment.size_bytes, config->storage_quota_bytes)) {
        object_rollback(db); sqlite3_close(db); (void)object_delete(config, attachment.object_key);
        return object_error(out, out_len, 429, "OSS storage quota is insufficient");
    }
    sqlite3_stmt *stmt = NULL;
    int updated = sqlite3_prepare_v2(db,
        "UPDATE transfer_attachment SET status='UPLOADED',size_bytes=?,uploaded_at=?,updated_at=? "
        "WHERE id=? AND status='PENDING'", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 1, attachment.size_bytes) == SQLITE_OK
        && object_bind_text(stmt, 2, now) == 0 && object_bind_text(stmt, 3, now) == 0
        && sqlite3_bind_int64(stmt, 4, attachment.id) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(stmt);
    if (!updated || object_commit(db) != 0) {
        object_rollback(db); sqlite3_close(db);
        return object_error(out, out_len, 409, "attachment completion raced with another request");
    }
    strcpy(attachment.status, "UPLOADED");
    strcpy(attachment.uploaded_at, now);
    strcpy(attachment.updated_at, now);
    sqlite3_close(db);
    return object_write_view(out, out_len, &attachment);
}

static char *object_random_token(void)
{
    uint8_t bytes[32];
    if (object_random(bytes, sizeof(bytes)) != 0) return NULL;
    char *token = object_base64(bytes, sizeof(bytes));
    if (token == NULL) return NULL;
    for (char *cursor = token; *cursor != '\0'; ++cursor) {
        if (*cursor == '+') *cursor = '-';
        else if (*cursor == '/') *cursor = '_';
    }
    char *padding = strchr(token, '=');
    if (padding != NULL) *padding = '\0';
    return token;
}

static int object_download_usage(sqlite3 *db,
                                 const char *tenant,
                                 const char *username,
                                 const char *month,
                                 long long *bytes)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT COALESCE(SUM(size_bytes),0) FROM transfer_attachment_download_usage "
            "WHERE tenant_id=? AND username=? AND usage_month=?", -1, &stmt, NULL) != SQLITE_OK
        || object_bind_text(stmt, 1, tenant) != 0 || object_bind_text(stmt, 2, username) != 0
        || object_bind_text(stmt, 3, month) != 0 || sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1;
    }
    *bytes = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return 0;
}

static int object_month(char out[8])
{
    struct tm value;
    time_t now = time(NULL);
    return gmtime_r(&now, &value) != NULL && strftime(out, 8U, "%Y-%m", &value) == 7U ? 0 : -1;
}

static int object_create_download(const st_object_config *config,
                                  int public_scope,
                                  long long attachment_id,
                                  const char *body,
                                  const st_object_storage_identity *identity,
                                  char *out,
                                  size_t out_len)
{
    if (!object_identity_valid(identity)) return object_error(out, out_len, 401, "missing or invalid bearer token");
    char *room_token = public_scope && body != NULL ? st_json_get_top_level_string(body, "roomToken") : NULL;
    sqlite3 *db = NULL;
    if (object_open(&db) != 0) { free(room_token); return object_error(out, out_len, 503, "attachment persistence is unavailable"); }
    st_attachment attachment;
    int found = object_find_attachment(db, attachment_id,
        public_scope ? "PUBLIC_TRANSFER" : "ADMIN_CLIENT_MESSAGE", &attachment);
    if (found != 0) {
        sqlite3_close(db); free(room_token);
        return object_error(out, out_len, found == 1 ? 404 : 500, "attachment not found");
    }
    int access = object_attachment_access(&attachment, identity, room_token, 0);
    free(room_token);
    char now[41], month[8];
    if (access != 0 || object_iso_time(time(NULL), now) != 0 || object_month(month) != 0) {
        sqlite3_close(db);
        return object_error(out, out_len, access == 1 ? 401 : access == 2 ? 403 : 500, "attachment access is forbidden");
    }
    if (strcmp(attachment.status, "UPLOADED") != 0 || strcmp(attachment.expires_at, now) <= 0) {
        sqlite3_close(db);
        return object_error(out, out_len, 409, "attachment is not uploaded or is expired");
    }
    long long used = 0;
    if (object_download_usage(db, identity->tenant_id, identity->username, month, &used) != 0
        || !object_quota_allows(used, attachment.size_bytes, config->download_quota_bytes)) {
        sqlite3_close(db);
        return object_error(out, out_len, 429, "monthly OSS download quota is insufficient");
    }
    char *token = NULL;
    long long grant_id = 0;
    char token_hash[65], grant_expiry[41];
    if (object_iso_time(time(NULL) + (time_t)config->download_ttl, grant_expiry) != 0) {
        sqlite3_close(db); return object_error(out, out_len, 500, "failed to allocate download grant");
    }
    int inserted = 0;
    for (int attempt = 0; attempt < 8 && !inserted; ++attempt) {
        free(token);
        token = object_random_token();
        grant_id = object_new_id();
        if (token == NULL || grant_id <= 0) continue;
        object_sha256_hex(token, token_hash);
        sqlite3_stmt *stmt = NULL;
        inserted = sqlite3_prepare_v2(db,
            "INSERT INTO transfer_attachment_download_grant "
            "(id,token_hash,tenant_id,username,attachment_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
            -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_bind_int64(stmt, 1, grant_id) == SQLITE_OK
            && object_bind_text(stmt, 2, token_hash) == 0
            && object_bind_text(stmt, 3, identity->tenant_id) == 0
            && object_bind_text(stmt, 4, identity->username) == 0
            && sqlite3_bind_int64(stmt, 5, attachment.id) == SQLITE_OK
            && object_bind_text(stmt, 6, now) == 0
            && object_bind_text(stmt, 7, grant_expiry) == 0
            && sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    if (!inserted) { free(token); return object_error(out, out_len, 500, "failed to allocate download grant"); }
    char *escaped_token = st_json_escape(token);
    char *escaped_expiry = st_json_escape(grant_expiry);
    free(token);
    if (escaped_token == NULL || escaped_expiry == NULL) { free(escaped_token); free(escaped_expiry); return -1; }
    st_object_buffer json = {0};
    char prefix[256];
    snprintf(prefix, sizeof(prefix), "{\"attachmentId\":%lld,\"objectId\":\"%lld\",\"downloadUrl\":\"/api/public/transfer/downloads/",
             attachment.id, attachment.id);
    int rc = object_buffer_append(&json, prefix) || object_buffer_append(&json, escaped_token)
        || object_buffer_append(&json, "\",\"downloadHeaders\":{},\"expiresAt\":\"")
        || object_buffer_append(&json, escaped_expiry)
        || object_buffer_append(&json, "\",\"attachment\":")
        || object_attachment_view(&json, &attachment)
        || object_buffer_append(&json, "}");
    free(escaped_token); free(escaped_expiry);
    if (rc) { free(json.data); return -1; }
    int result = object_write_response(out, out_len, 200, "OK", json.data);
    free(json.data);
    return result;
}

static int object_find_attachment_any(sqlite3 *db, long long id, st_attachment *attachment)
{
    char sql[768];
    snprintf(sql, sizeof(sql), "SELECT %s FROM transfer_attachment WHERE id=?", object_attachment_columns);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return -1;
    }
    int step = sqlite3_step(stmt);
    if (step == SQLITE_ROW) object_read_attachment(stmt, attachment);
    sqlite3_finalize(stmt);
    return step == SQLITE_ROW ? 0 : step == SQLITE_DONE ? 1 : -1;
}

static int object_consume_download(const st_object_config *config,
                                   const char *method,
                                   const char *path,
                                   char *out,
                                   size_t out_len)
{
    static const char prefix[] = "/api/public/transfer/downloads/";
    const char *token_start = path + sizeof(prefix) - 1U;
    const char *token_end = strchr(token_start, '?');
    if (token_end == NULL) token_end = token_start + strlen(token_start);
    size_t token_len = (size_t)(token_end - token_start);
    if (strcmp(method, "GET") != 0) {
        const char *body = "{\"error\":\"method not allowed\"}";
        int written = snprintf(out, out_len,
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Type: application/json\r\n"
            "Cache-Control: no-store\r\nContent-Length: %zu\r\n\r\n%s", strlen(body), body);
        return written < 0 || (size_t)written >= out_len ? -1 : written;
    }
    if (token_len == 0U || token_len > 128U) return object_error(out, out_len, 410, "download link is expired or already used");
    char token[129];
    memcpy(token, token_start, token_len);
    token[token_len] = '\0';
    char token_hash[65];
    object_sha256_hex(token, token_hash);
    sqlite3 *db = NULL;
    if (object_open(&db) != 0) return object_error(out, out_len, 410, "download link is expired or already used");
    if (object_begin(db) != 0) { sqlite3_close(db); return object_error(out, out_len, 503, "attachment persistence is busy"); }
    sqlite3_stmt *stmt = NULL;
    long long grant_id = 0, attachment_id = 0;
    char tenant[81] = {0}, username[129] = {0}, expires[41] = {0}, consumed[41] = {0};
    int selected = sqlite3_prepare_v2(db,
        "SELECT id,tenant_id,username,attachment_id,expires_at,consumed_at "
        "FROM transfer_attachment_download_grant WHERE token_hash=?", -1, &stmt, NULL) == SQLITE_OK
        && object_bind_text(stmt, 1, token_hash) == 0 && sqlite3_step(stmt) == SQLITE_ROW;
    if (selected) {
        grant_id = sqlite3_column_int64(stmt, 0);
        object_column_text(stmt, 1, tenant, sizeof(tenant));
        object_column_text(stmt, 2, username, sizeof(username));
        attachment_id = sqlite3_column_int64(stmt, 3);
        object_column_text(stmt, 4, expires, sizeof(expires));
        object_column_text(stmt, 5, consumed, sizeof(consumed));
    }
    sqlite3_finalize(stmt);
    char now[41], month[8];
    st_attachment attachment;
    if (!selected || consumed[0] != '\0' || object_iso_time(time(NULL), now) != 0
        || object_month(month) != 0 || strcmp(expires, now) <= 0
        || object_find_attachment_any(db, attachment_id, &attachment) != 0
        || strcmp(attachment.status, "UPLOADED") != 0 || strcmp(attachment.expires_at, now) <= 0) {
        object_rollback(db); sqlite3_close(db);
        return object_error(out, out_len, 410, "download link is expired or already used");
    }
    long long used = 0;
    if (object_download_usage(db, tenant, username, month, &used) != 0
        || !object_quota_allows(used, attachment.size_bytes, config->download_quota_bytes)) {
        object_rollback(db); sqlite3_close(db);
        return object_error(out, out_len, 429, "monthly OSS download quota is insufficient");
    }
    char grant_text[32], direct_expiry[41];
    snprintf(grant_text, sizeof(grant_text), "%lld", grant_id);
    char *direct_url = object_presign(config, "GET", attachment.object_key, NULL, grant_text,
                                      config->direct_download_ttl, time(NULL), direct_expiry, NULL);
    if (direct_url == NULL) {
        object_rollback(db); sqlite3_close(db);
        return object_error(out, out_len, 500, "failed to sign object download");
    }
    stmt = NULL;
    int consumed_ok = sqlite3_prepare_v2(db,
        "UPDATE transfer_attachment_download_grant SET consumed_at=?,updated_at=? "
        "WHERE id=? AND token_hash=? AND consumed_at IS NULL AND expires_at>?", -1, &stmt, NULL) == SQLITE_OK
        && object_bind_text(stmt, 1, now) == 0 && object_bind_text(stmt, 2, now) == 0
        && sqlite3_bind_int64(stmt, 3, grant_id) == SQLITE_OK
        && object_bind_text(stmt, 4, token_hash) == 0 && object_bind_text(stmt, 5, now) == 0
        && sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(stmt);
    long long usage_id = object_new_id();
    stmt = NULL;
    int usage_ok = consumed_ok && usage_id > 0
        && sqlite3_prepare_v2(db,
            "INSERT INTO transfer_attachment_download_usage "
            "(id,tenant_id,username,attachment_id,size_bytes,usage_month,created_at) VALUES(?,?,?,?,?,?,?)",
            -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 1, usage_id) == SQLITE_OK
        && object_bind_text(stmt, 2, tenant) == 0 && object_bind_text(stmt, 3, username) == 0
        && sqlite3_bind_int64(stmt, 4, attachment.id) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 5, attachment.size_bytes) == SQLITE_OK
        && object_bind_text(stmt, 6, month) == 0 && object_bind_text(stmt, 7, now) == 0
        && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (!usage_ok || object_commit(db) != 0) {
        object_rollback(db); sqlite3_close(db); free(direct_url);
        return object_error(out, out_len, 410, "download link is expired or already used");
    }
    sqlite3_close(db);
    int written = snprintf(out, out_len,
        "HTTP/1.1 302 Found\r\nLocation: %s\r\nCache-Control: private, no-store\r\n"
        "Pragma: no-cache\r\nReferrer-Policy: no-referrer\r\nContent-Length: 0\r\n\r\n",
        direct_url);
    free(direct_url);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

typedef struct {
    uint8_t *data;
    size_t len;
    size_t cap;
} st_object_bytes;

static size_t object_curl_collect(char *data, size_t size, size_t nmemb, void *context)
{
    st_object_bytes *bytes = (st_object_bytes *)context;
    size_t count = size * nmemb;
    if (size != 0U && count / size != nmemb) return 0U;
    if (count > 64U * 1024U - bytes->len) return 0U;
    if (bytes->len + count + 1U > bytes->cap) {
        size_t next = bytes->cap == 0U ? 4096U : bytes->cap;
        while (next < bytes->len + count + 1U) next *= 2U;
        uint8_t *value = (uint8_t *)realloc(bytes->data, next);
        if (value == NULL) return 0U;
        bytes->data = value;
        bytes->cap = next;
    }
    memcpy(bytes->data + bytes->len, data, count);
    bytes->len += count;
    bytes->data[bytes->len] = '\0';
    return count;
}

static uint8_t *object_base64_decode(const char *value, size_t *out_len)
{
    size_t len = strlen(value);
    if (len == 0U || len > (size_t)INT_MAX || len % 4U != 0U) return NULL;
    uint8_t *out = (uint8_t *)malloc(3U * (len / 4U) + 1U);
    if (out == NULL) return NULL;
    int decoded = EVP_DecodeBlock(out, (const unsigned char *)value, (int)len);
    if (decoded < 0) { free(out); return NULL; }
    size_t actual = (size_t)decoded;
    if (len > 0U && value[len - 1U] == '=') --actual;
    if (len > 1U && value[len - 2U] == '=') --actual;
    out[actual] = '\0';
    *out_len = actual;
    return out;
}

static char *object_callback_key_url(const char *encoded)
{
    if (!object_text_present(encoded)) return NULL;
    size_t decoded_len = 0U;
    uint8_t *decoded = object_base64_decode(encoded, &decoded_len);
    if (decoded == NULL || memchr(decoded, '\0', decoded_len) != NULL) { free(decoded); return NULL; }
    const char *url = (const char *)decoded;
    const char *path = NULL;
    static const char http_prefix[] = "http://gosspublic.alicdn.com";
    static const char https_prefix[] = "https://gosspublic.alicdn.com";
    if (strncasecmp(url, http_prefix, sizeof(http_prefix) - 1U) == 0) path = url + sizeof(http_prefix) - 1U;
    else if (strncasecmp(url, https_prefix, sizeof(https_prefix) - 1U) == 0) path = url + sizeof(https_prefix) - 1U;
    if (path == NULL || strncmp(path, "/callback_pub_key", 17U) != 0
        || strchr(path, '?') != NULL || strchr(path, '#') != NULL) { free(decoded); return NULL; }
    size_t needed = strlen("https://gosspublic.alicdn.com") + strlen(path) + 1U;
    char *secure = (char *)malloc(needed);
    if (secure != NULL) snprintf(secure, needed, "https://gosspublic.alicdn.com%s", path);
    free(decoded);
    return secure;
}

static EVP_PKEY *object_load_callback_key(const char *encoded_url)
{
    char *url = object_callback_key_url(encoded_url);
    if (url == NULL) return NULL;
    (void)pthread_once(&object_curl_once, object_curl_init);
    CURL *curl = object_curl_init_result == CURLE_OK ? curl_easy_init() : NULL;
    st_object_bytes pem = {0};
    if (curl == NULL) { free(url); return NULL; }
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, object_curl_collect);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &pem);
    if (rc == CURLE_OK) rc = curl_easy_perform(curl);
    long status = 0;
    if (rc == CURLE_OK) rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(curl);
    free(url);
    if (rc != CURLE_OK || status != 200 || pem.data == NULL) { free(pem.data); return NULL; }
    BIO *bio = BIO_new_mem_buf(pem.data, (int)pem.len);
    EVP_PKEY *key = bio == NULL ? NULL : PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(pem.data);
    return key;
}

static char *object_url_decode_path(const char *target)
{
    const char *query = strchr(target, '?');
    size_t path_len = query == NULL ? strlen(target) : (size_t)(query - target);
    char *out = (char *)malloc(path_len + 1U);
    if (out == NULL) return NULL;
    size_t offset = 0U;
    for (size_t i = 0; i < path_len; ++i) {
        unsigned char ch = (unsigned char)target[i];
        if (ch == '+' ) out[offset++] = ' ';
        else if (ch == '%' && i + 2U < path_len && isxdigit((unsigned char)target[i + 1U])
                 && isxdigit((unsigned char)target[i + 2U])) {
            char hex[3] = {target[i + 1U], target[i + 2U], '\0'};
            out[offset++] = (char)strtol(hex, NULL, 16);
            i += 2U;
        } else out[offset++] = (char)ch;
    }
    out[offset] = '\0';
    return out;
}

static int object_verify_callback(const char *target,
                                  const char *body,
                                  const char *authorization,
                                  const char *public_key_url)
{
    if (!object_text_present(target) || body == NULL || strlen(body) > ST_OBJECT_MAX_BODY
        || !object_text_present(authorization) || !object_text_present(public_key_url)) return 0;
    EVP_PKEY *key = object_load_callback_key(public_key_url);
    if (key == NULL) return 0;
    while (isspace((unsigned char)*authorization)) ++authorization;
    if (strncasecmp(authorization, "OSS ", 4U) == 0) authorization += 4;
    while (isspace((unsigned char)*authorization)) ++authorization;
    size_t signature_len = 0U;
    uint8_t *signature = object_base64_decode(authorization, &signature_len);
    char *decoded_path = object_url_decode_path(target);
    const char *query = strchr(target, '?');
    st_object_buffer verify = {0};
    int built = signature != NULL && decoded_path != NULL
        && object_buffer_append(&verify, decoded_path) == 0
        && (query == NULL || object_buffer_append(&verify, query) == 0)
        && object_buffer_append(&verify, "\n") == 0
        && object_buffer_append(&verify, body) == 0;
    EVP_MD_CTX *context = built ? EVP_MD_CTX_new() : NULL;
    int valid = context != NULL
        && EVP_DigestVerifyInit(context, NULL, EVP_md5(), NULL, key) == 1
        && EVP_DigestVerifyUpdate(context, verify.data, verify.len) == 1
        && EVP_DigestVerifyFinal(context, signature, signature_len) == 1;
    EVP_MD_CTX_free(context);
    EVP_PKEY_free(key);
    free(signature); free(decoded_path); free(verify.data);
    return valid;
}

static int object_complete_callback(const st_object_config *config,
                                    const char *path,
                                    const char *body,
                                    const char *authorization,
                                    const char *public_key_url,
                                    char *out,
                                    size_t out_len)
{
    if (config->callback_url[0] == '\0'
        || !object_verify_callback(path, body, authorization, public_key_url))
        return object_error(out, out_len, 403, "invalid OSS upload callback signature");
    if (body == NULL || !st_json_is_valid_object(body)) return object_error(out, out_len, 400, "invalid OSS upload callback body");
    char *bucket = st_json_get_top_level_string(body, "bucket");
    char *key = st_json_get_top_level_string(body, "object");
    long long size = -1;
    int valid = bucket != NULL && strcmp(bucket, config->bucket) == 0 && key != NULL
        && object_validate_key(config, key) == 0 && st_json_get_i64(body, "size", &size) == 0 && size >= 0;
    free(bucket);
    if (!valid) {
        free(key);
        return object_error(out, out_len, 400, "invalid OSS upload callback body");
    }
    sqlite3 *db = NULL;
    if (object_open(&db) != 0) { free(key); return object_error(out, out_len, 503, "attachment persistence is unavailable"); }
    st_attachment attachment;
    int found = object_find_attachment_by_key(db, key, &attachment);
    if (found != 0) {
        sqlite3_close(db); free(key);
        return object_error(out, out_len, found == 1 ? 404 : 500, "attachment object was not allocated");
    }
    if (strcmp(attachment.status, "UPLOADED") == 0) {
        sqlite3_close(db); free(key);
        char value[160];
        snprintf(value, sizeof(value), "{\"Status\":\"OK\",\"attachmentId\":%lld,\"objectId\":\"%lld\"}",
                 attachment.id, attachment.id);
        return object_write_response(out, out_len, 200, "OK", value);
    }
    if (strcmp(attachment.status, "PENDING") != 0) {
        sqlite3_close(db); free(key);
        return object_error(out, out_len, 409, "attachment is not pending");
    }
    if (size > config->max_attachment_bytes) {
        sqlite3_close(db);
        (void)object_delete(config, key);
        free(key);
        return object_error(out, out_len, 400, "attachment is too large");
    }
    attachment.size_bytes = size;
    if (object_begin(db) != 0) { sqlite3_close(db); free(key); return object_error(out, out_len, 503, "attachment persistence is busy"); }
    long long used = 0;
    if (object_active_storage_bytes(db, attachment.tenant_id, attachment.owner_username,
                                    attachment.id, &used) != 0
        || !object_quota_allows(used, size, config->storage_quota_bytes)) {
        object_rollback(db); sqlite3_close(db); (void)object_delete(config, key); free(key);
        return object_error(out, out_len, 429, "OSS storage quota is insufficient");
    }
    char now[41];
    sqlite3_stmt *stmt = NULL;
    int updated = object_iso_time(time(NULL), now) == 0
        && sqlite3_prepare_v2(db,
            "UPDATE transfer_attachment SET status='UPLOADED',size_bytes=?,uploaded_at=?,updated_at=? "
            "WHERE id=? AND status='PENDING'", -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_int64(stmt, 1, size) == SQLITE_OK
        && object_bind_text(stmt, 2, now) == 0 && object_bind_text(stmt, 3, now) == 0
        && sqlite3_bind_int64(stmt, 4, attachment.id) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(stmt);
    if (!updated || object_commit(db) != 0) {
        object_rollback(db); sqlite3_close(db); free(key);
        return object_error(out, out_len, 409, "attachment completion raced with another request");
    }
    sqlite3_close(db); free(key);
    char response[160];
    snprintf(response, sizeof(response), "{\"Status\":\"OK\",\"attachmentId\":%lld,\"objectId\":\"%lld\"}",
             attachment.id, attachment.id);
    return object_write_response(out, out_len, 200, "OK", response);
}

int st_object_storage_build_response(const char *method,
                                     const char *path,
                                     const char *body,
                                     const char *remote_address,
                                     const char *callback_authorization,
                                     const char *callback_public_key_url,
                                     const st_object_storage_identity *identity,
                                     char *out,
                                     size_t out_len)
{
    if (method == NULL || path == NULL) return 0;
    static const char downloads[] = "/api/public/transfer/downloads/";
    int consume_download = strncmp(path, downloads, sizeof(downloads) - 1U) == 0;

    int public_upload = object_path_equals(path, "/api/public/transfer/attachments/presign-upload");
    int admin_upload = object_path_equals(path, "/api/admin/client-messages/attachments/presign-upload");
    int callback = object_path_equals(path, "/api/public/transfer/oss-callback");
    long long attachment_id = 0;
    int public_complete = object_parse_nested_id(path, "/api/public/transfer/attachments/", "/complete", &attachment_id) == 0;
    long long public_download_id = 0;
    int public_download = object_parse_nested_id(path, "/api/public/transfer/attachments/", "/presign-download", &public_download_id) == 0;
    long long admin_complete_id = 0;
    int admin_complete = object_parse_nested_id(path, "/api/admin/client-messages/attachments/", "/complete", &admin_complete_id) == 0;
    long long admin_download_id = 0;
    int admin_download = object_parse_nested_id(path, "/api/admin/client-messages/attachments/", "/presign-download", &admin_download_id) == 0;
    if (!consume_download && !public_upload && !admin_upload && !callback && !public_complete && !public_download
        && !admin_complete && !admin_download) return 0;
    if (!consume_download && strcmp(method, "POST") != 0)
        return object_error(out, out_len, 400, "method not allowed");
    st_object_config config;
    if (object_load_config(&config) != 0 || !config.enabled) {
        if (consume_download) return object_error(out, out_len, 410, "download link is expired or already used");
        return callback ? object_error(out, out_len, 403, "invalid OSS upload callback signature")
                        : object_disabled(out, out_len);
    }
    if (consume_download) return object_consume_download(&config, method, path, out, out_len);
    if (callback) return object_complete_callback(&config, path, body, callback_authorization,
                                                   callback_public_key_url, out, out_len);
    if (public_upload || admin_upload)
        return object_create_upload(&config, public_upload, body, remote_address, identity, out, out_len);
    if (public_complete || admin_complete)
        return object_complete(&config, public_complete, public_complete ? attachment_id : admin_complete_id,
                               body, identity, out, out_len);
    return object_create_download(&config, public_download, public_download ? public_download_id : admin_download_id,
                                  body, identity, out, out_len);
}

void st_object_storage_reset_for_tests(void)
{
    pthread_mutex_lock(&object_rate_lock);
    while (object_rate_windows != NULL) {
        st_object_rate_window *next = object_rate_windows->next;
        free(object_rate_windows);
        object_rate_windows = next;
    }
    pthread_mutex_unlock(&object_rate_lock);
}

char *st_object_storage_presign_for_tests(const char *method,
                                          const char *object_key,
                                          const char *content_type,
                                          const char *grant_id,
                                          long long ttl_seconds,
                                          long long epoch_seconds,
                                          char expires_at[41],
                                          char **callback_header_out)
{
    st_object_config config;
    if (object_load_config(&config) != 0 || !config.enabled || method == NULL || object_key == NULL
        || object_validate_key(&config, object_key) != 0) return NULL;
    return object_presign(&config, method, object_key, content_type, grant_id,
                          ttl_seconds, (time_t)epoch_seconds, expires_at, callback_header_out);
}
