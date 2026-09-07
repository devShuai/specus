#define _POSIX_C_SOURCE 200809L

#include "media_capture.h"

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

static void media_normalize_source(const char *source_url, char out[3073])
{
    const char *source = source_url == NULL || *source_url == '\0' ? "/" : source_url;
    while (isspace((unsigned char)*source)) ++source;
    if (*source == '/') media_copy(out, 3073U, source);
    else snprintf(out, 3073U, "/%s", source);
    size_t len = strlen(out);
    while (len > 0U && isspace((unsigned char)out[len - 1U])) out[--len] = '\0';
}

static int media_parse_content_range(const char *value,
                                     long long *start, long long *end, long long *total,
                                     int *has_total)
{
    if (value == NULL) return -1;
    char total_text[64];
    long long parsed_start = 0, parsed_end = 0;
    if (sscanf(value, "bytes %lld-%lld/%63s", &parsed_start, &parsed_end, total_text) != 3
        || parsed_start < 0 || parsed_end < parsed_start) return -1;
    *start = parsed_start;
    *end = parsed_end;
    *has_total = 0;
    if (strcmp(total_text, "*") != 0) {
        char *tail = NULL;
        long long parsed_total = strtoll(total_text, &tail, 10);
        if (tail == total_text || *tail != '\0' || parsed_total <= parsed_end) return -1;
        *total = parsed_total;
        *has_total = 1;
    }
    return 0;
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

static int media_db_reusable(sqlite3 *db, const char *tenant_id, const char *dedup_key,
                             time_t now)
{
    sqlite3_stmt *stmt = NULL;
    int result = 0;
    const char *sql = "SELECT state,expires_at FROM specus_http_media_capture "
        "WHERE tenant_id=? AND deduplication_key=? LIMIT 1";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, tenant_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, dedup_key, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *state = (const char *)sqlite3_column_text(stmt, 0);
            const char *expires = (const char *)sqlite3_column_text(stmt, 1);
            char now_text[64];
            media_iso_time(now, now_text);
            result = state != NULL && (strcmp(state, "STARTING") == 0 || strcmp(state, "CAPTURING") == 0
                || (strcmp(state, "COMPLETE") == 0 && expires != NULL && strcmp(expires, now_text) > 0));
        }
    }
    sqlite3_finalize(stmt);
    return result;
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
    char normalized_source[3073];
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
    char resource_input[8192];
    snprintf(resource_input, sizeof(resource_input), "%s\n%lld\n%s\n%s\n%s\n%s",
             client.tenant_id, client.id, route, normalized_source,
             entity_tag == NULL ? "" : entity_tag, last_modified == NULL ? "" : last_modified);
    char resource_key[65];
    media_sha256_hex(resource_input, strlen(resource_input), resource_key);
    char dedup_input[9000];
    snprintf(dedup_input, sizeof(dedup_input), "%s\n%s\n%s\n%lld\n%lld\n%lld\n%s",
             resource_key, method, kind,
             session->has_range_start ? session->range_start : -1LL,
             session->has_range_end ? session->range_end : -1LL,
             session->has_total_bytes ? session->total_bytes : -1LL,
             content_encoding == NULL ? "" : content_encoding);
    char dedup_key[65];
    media_sha256_hex(dedup_input, strlen(dedup_input), dedup_key);
    sqlite3 *db = NULL;
    if (media_db_open(database_path, &db) != 0) {
        free(session);
        session = NULL;
        goto cleanup;
    }
    time_t now = time(NULL);
    if (media_db_reusable(db, client.tenant_id, dedup_key, now)) {
        sqlite3_close(db);
        free(session);
        session = NULL;
        goto cleanup;
    }
    unsigned char random[16];
    if (RAND_bytes(random, sizeof(random)) != 1) {
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
    char *response_headers = media_join_headers(headers, headers_len);
    sqlite3_stmt *stmt = NULL;
    const char *sql = "INSERT INTO specus_http_media_capture(tenant_id,client_id,client_name,route,resource_id,"
        "source_url,resource_key,deduplication_key,method,status_code,content_type,content_encoding,media_kind,"
        "entity_tag,last_modified,content_range_start,content_range_end,total_bytes,captured_bytes,"
        "initialization_segment,live_stream,object_key,state,response_headers,captured_at,expires_at) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,0,0,?,'STARTING',?,?,?)";
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
        sqlite3_bind_text(stmt, index++, dedup_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, method, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, index++, status_code);
        if (content_type == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, content_type, -1, SQLITE_TRANSIENT);
        if (content_encoding == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, content_encoding, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, kind, -1, SQLITE_TRANSIENT);
        if (entity_tag == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, entity_tag, -1, SQLITE_TRANSIENT);
        if (last_modified == NULL) sqlite3_bind_null(stmt, index++); else sqlite3_bind_text(stmt, index++, last_modified, -1, SQLITE_TRANSIENT);
        if (session->has_range_start) sqlite3_bind_int64(stmt, index++, session->range_start); else sqlite3_bind_null(stmt, index++);
        if (session->has_range_end) sqlite3_bind_int64(stmt, index++, session->range_end); else sqlite3_bind_null(stmt, index++);
        if (session->has_total_bytes) sqlite3_bind_int64(stmt, index++, session->total_bytes); else sqlite3_bind_null(stmt, index++);
        sqlite3_bind_text(stmt, index++, session->object_key, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, response_headers, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, captured_at, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, index++, expires_at, -1, SQLITE_TRANSIENT);
        insert_ok = sqlite3_step(stmt) == SQLITE_DONE;
    }
    sqlite3_finalize(stmt);
    free(response_headers);
    if (!insert_ok) {
        sqlite3_close(db);
        free(session);
        session = NULL;
        goto cleanup;
    }
    session->id = sqlite3_last_insert_rowid(db);
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
    const char *sql = "UPDATE specus_http_media_capture SET state=?,deduplication_key=CASE WHEN ? THEN deduplication_key ELSE NULL END,failure_reason=?,"
        "captured_bytes=?,content_range_end=COALESCE(content_range_end,content_range_start+?-1),"
        "total_bytes=CASE WHEN total_bytes IS NULL AND content_range_start=0 AND ? THEN ? ELSE total_bytes END,"
        "upload_id=NULL,object_etag=?,completed_at=CURRENT_TIMESTAMP WHERE id=? AND tenant_id=?";
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
        sqlite3_bind_int64(stmt, 5, session->captured_bytes);
        sqlite3_bind_int(stmt, 6, complete ? 1 : 0);
        sqlite3_bind_int64(stmt, 7, session->captured_bytes);
        sqlite3_bind_text(stmt, 8, object_etag, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt, 9, session->id);
        sqlite3_bind_text(stmt, 10, session->tenant_id, -1, SQLITE_TRANSIENT);
        (void)sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
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

int st_media_capture_externalized(const st_media_capture_session *session)
{
    return session != NULL;
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

static void media_redact_source(const char *source, char out[3073])
{
    media_copy(out, 3073U, source);
    char *query = strchr(out, '?');
    if (query == NULL) return;
    char *cursor = query + 1;
    while (*cursor != '\0') {
        char *end = strchr(cursor, '&');
        if (end == NULL) end = cursor + strlen(cursor);
        char *equals = memchr(cursor, '=', (size_t)(end - cursor));
        if (equals != NULL) {
            char key[64];
            size_t key_len = (size_t)(equals - cursor);
            if (key_len >= sizeof(key)) key_len = sizeof(key) - 1U;
            memcpy(key, cursor, key_len);
            key[key_len] = '\0';
            for (char *p = key; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
            if (strcmp(key, "token") == 0 || strcmp(key, "access_token") == 0
                || strcmp(key, "auth_token") == 0 || strcmp(key, "api_key") == 0
                || strcmp(key, "apikey") == 0 || strcmp(key, "x-emby-token") == 0) {
                size_t tail = strlen(end);
                memmove(equals + strlen("=[REDACTED]"), end, tail + 1U);
                memcpy(equals, "=[REDACTED]", strlen("=[REDACTED]"));
                end = equals + strlen("=[REDACTED]");
            }
        }
        cursor = *end == '\0' ? end : end + 1;
    }
}

static int media_append_optional_i64(st_media_builder *body, int present, long long value)
{
    return present ? media_builder_appendf(body, "%lld", value) : media_builder_append(body, "null");
}

static int media_append_capture_view(st_media_builder *body, const st_media_capture_row *row)
{
    char source[3073];
    media_redact_source(row->source_url, source);
    int complete = strcmp(row->state, "COMPLETE") == 0;
    int segment = strcmp(row->media_kind, "MEDIA_SEGMENT") == 0 || row->initialization_segment;
    int playable = complete && !segment && row->captured_bytes > 0;
    int offline_ready = complete && (segment || (row->has_total_bytes && row->range_start == 0
        && row->captured_bytes >= row->total_bytes));
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
    if (rc == 0) {
        const char *message = !complete ? "媒体采集尚未完成"
            : segment ? "媒体分段由 HLS/DASH 清单播放器按需加载"
            : playable && !offline_ready ? "仅播放已缓存的媒体分段" : NULL;
        rc = media_builder_nullable_string(body, message);
    }
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
        sqlite3_bind_int(stmt, index++, page * size);
        int first = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            st_media_capture_row row;
            media_scan_row(stmt, &row);
            if ((!first && media_builder_append(&body, ",") != 0)
                || media_append_capture_view(&body, &row) != 0) {
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
    sqlite3_close(db);
    if (strcmp(row.state, "COMPLETE") != 0) return media_write_json_error(out, out_len, 409, "媒体采集尚未完成");
    if (strcmp(row.media_kind, "MEDIA_SEGMENT") == 0 || row.initialization_segment)
        return media_write_json_error(out, out_len, 409, "媒体分段不能独立创建播放会话");
    unsigned char random[32];
    if (RAND_bytes(random, sizeof(random)) != 1) return media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
    char token[65];
    if (media_base64url(random, sizeof(random), token, sizeof(token)) != 0)
        return media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
    time_t now = time(NULL);
    long long ttl = media_env_i64("SPECUS_MEDIA_CAPTURE_PLAYBACK_TICKET_TTL_SECONDS", 900LL);
    if (ttl < 60LL) ttl = 60LL;
    st_media_ticket *ticket = (st_media_ticket *)calloc(1, sizeof(*ticket));
    if (ticket == NULL) return media_write_json_error(out, out_len, 500, "媒体播放票据生成失败");
    media_copy(ticket->token, sizeof(ticket->token), token);
    media_copy(ticket->tenant_id, sizeof(ticket->tenant_id), row.tenant_id);
    ticket->capture_id = row.id;
    ticket->expires_at = now + ttl;
    ticket->backfill_missing = media_query_bool(path, "backfillMissing", 0);
    pthread_mutex_lock(&g_media_ticket_lock);
    media_ticket_cleanup_locked(now);
    ticket->next = g_media_tickets;
    g_media_tickets = ticket;
    pthread_mutex_unlock(&g_media_ticket_lock);
    char expires[64];
    media_iso_time(ticket->expires_at, expires);
    long long total = row.has_total_bytes ? row.total_bytes : row.captured_bytes;
    long long start = row.has_range_start ? row.range_start : 0;
    long long end = row.has_range_end ? row.range_end : start + row.captured_bytes - 1;
    st_media_builder body = {0};
    int ok = media_builder_appendf(&body,
        "{\"ticket\":\"%s\",\"mediaKind\":\"%s\","
        "\"playUrl\":\"/api/public/media-playback/%s/play\","
        "\"manifestUrl\":\"/api/public/media-playback/%s/manifest\","
        "\"totalBytes\":%lld,\"initialRangeStart\":%lld,\"initialRangeEnd\":%lld,"
        "\"cachedRanges\":[{\"start\":%lld,\"end\":%lld}],\"backfillMissing\":%s,\"expiresAt\":\"%s\"}",
        token, row.media_kind, token, token, total, start, end, start, end,
        ticket->backfill_missing ? "true" : "false", expires) == 0;
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
                                    const char *source_url, st_media_capture_row *row)
{
    char normalized[3073];
    media_normalize_source(source_url, normalized);
    char sql[2200];
    snprintf(sql, sizeof(sql), "SELECT %s FROM specus_http_media_capture m WHERE "
        "m.tenant_id=? AND m.client_id=? AND m.route=? AND m.source_url=? AND m.state='COMPLETE' "
        "ORDER BY m.id DESC LIMIT 1", media_row_columns());
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

static void media_resolve_source_url(const char *base, const char *reference, char out[3073])
{
    if (reference == NULL || *reference == '\0') {
        media_copy(out, 3073U, reference);
        return;
    }
    const char *absolute = strstr(reference, "://");
    if (absolute != NULL) {
        const char *path = strchr(absolute + 3, '/');
        media_normalize_source(path == NULL ? "/" : path, out);
        return;
    }
    if (*reference == '/') {
        media_normalize_source(reference, out);
        return;
    }
    char base_copy[3073];
    media_copy(base_copy, sizeof(base_copy), base);
    char *query = strchr(base_copy, '?');
    if (query != NULL) *query = '\0';
    char *slash = strrchr(base_copy, '/');
    if (slash == NULL) media_normalize_source(reference, out);
    else {
        slash[1] = '\0';
        snprintf(out, 3073U, "%s%s", base_copy, reference);
    }
}

static char *media_asset_url(const char *base_path, const char *source_url)
{
    char *encoded = media_uri_encode(source_url, 0);
    if (encoded == NULL) return NULL;
    size_t len = strlen(base_path) + strlen(encoded) + 6U;
    char *result = (char *)malloc(len);
    if (result != NULL) snprintf(result, len, "%s?url=%s", base_path, encoded);
    free(encoded);
    return result;
}

static char *media_rewrite_hls(const char *source_url, const char *text, const char *asset_base)
{
    st_media_builder result = {0};
    const char *cursor = text;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, '\n');
        if (end == NULL) end = cursor + strlen(cursor);
        size_t line_len = (size_t)(end - cursor);
        char *line = (char *)malloc(line_len + 1U);
        if (line == NULL) { free(result.data); return NULL; }
        memcpy(line, cursor, line_len);
        line[line_len] = '\0';
        char *trim = line;
        while (isspace((unsigned char)*trim)) ++trim;
        if (*trim != '\0' && *trim != '#') {
            char resolved[3073];
            media_resolve_source_url(source_url, trim, resolved);
            char *asset = media_asset_url(asset_base, resolved);
            if (asset == NULL || media_builder_append(&result, asset) != 0) {
                free(asset); free(line); free(result.data); return NULL;
            }
            free(asset);
        } else {
            char *uri = strstr(line, "URI=\"");
            if (uri != NULL) {
                char *value = uri + 5;
                char *close = strchr(value, '"');
                if (close != NULL) {
                    *close = '\0';
                    char resolved[3073];
                    media_resolve_source_url(source_url, value, resolved);
                    char *asset = media_asset_url(asset_base, resolved);
                    if (asset == NULL
                        || media_builder_append_len(&result, line, (size_t)(value - line)) != 0
                        || media_builder_append(&result, asset) != 0
                        || media_builder_append(&result, close + 1) != 0) {
                        free(asset); free(line); free(result.data); return NULL;
                    }
                    free(asset);
                } else if (media_builder_append(&result, line) != 0) {
                    free(line); free(result.data); return NULL;
                }
            } else if (media_builder_append(&result, line) != 0) {
                free(line); free(result.data); return NULL;
            }
        }
        free(line);
        if (*end == '\n') {
            if (media_builder_append(&result, "\n") != 0) { free(result.data); return NULL; }
            cursor = end + 1;
        } else cursor = end;
    }
    if (result.data == NULL) result.data = strdup("");
    return result.data;
}

static int media_ascii_prefix(const char *value, const char *prefix)
{
    return strncasecmp(value, prefix, strlen(prefix)) == 0;
}

static const char *media_strcasestr_local(const char *value, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (needle_len == 0U) return value;
    for (const char *p = value; *p != '\0'; ++p) {
        if (strncasecmp(p, needle, needle_len) == 0) return p;
    }
    return NULL;
}

static char *media_xml_escape_text(const char *value)
{
    st_media_builder out = {0};
    for (const char *p = value; *p != '\0'; ++p) {
        const char *replacement = *p == '&' ? "&amp;" : *p == '"' ? "&quot;"
            : *p == '<' ? "&lt;" : *p == '>' ? "&gt;" : NULL;
        if ((replacement != NULL && media_builder_append(&out, replacement) != 0)
            || (replacement == NULL && media_builder_append_len(&out, p, 1U) != 0)) {
            free(out.data);
            return NULL;
        }
    }
    if (out.data == NULL) out.data = strdup("");
    return out.data;
}

static int media_dash_attribute_name(const char *cursor, size_t *name_len)
{
    static const char *names[] = {"media", "initialization", "sourceURL", "href"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        size_t len = strlen(names[i]);
        if (strncasecmp(cursor, names[i], len) == 0
            && (cursor == NULL || !isalnum((unsigned char)cursor[len]))) {
            *name_len = len;
            return 1;
        }
    }
    return 0;
}

static char *media_rewrite_dash(const char *source_url, const char *text, const char *asset_base)
{
    st_media_builder out = {0};
    const char *cursor = text;
    while (*cursor != '\0') {
        if (media_ascii_prefix(cursor, "<BaseURL")) {
            const char *tag_end = strchr(cursor, '>');
            const char *close = tag_end == NULL ? NULL : media_strcasestr_local(tag_end + 1, "</BaseURL>");
            if (tag_end != NULL && close != NULL) {
                char reference[3073];
                size_t ref_len = (size_t)(close - tag_end - 1);
                if (ref_len >= sizeof(reference)) ref_len = sizeof(reference) - 1U;
                memcpy(reference, tag_end + 1, ref_len);
                reference[ref_len] = '\0';
                char *start = reference;
                while (isspace((unsigned char)*start)) ++start;
                char *tail = start + strlen(start);
                while (tail > start && isspace((unsigned char)tail[-1])) *--tail = '\0';
                char resolved[3073];
                media_resolve_source_url(source_url, start, resolved);
                char *asset = media_asset_url(asset_base, resolved);
                char *escaped = asset == NULL ? NULL : media_xml_escape_text(asset);
                free(asset);
                if (escaped == NULL
                    || media_builder_append_len(&out, cursor, (size_t)(tag_end + 1 - cursor)) != 0
                    || media_builder_append(&out, escaped) != 0
                    || media_builder_append(&out, "</BaseURL>") != 0) {
                    free(escaped); free(out.data); return NULL;
                }
                free(escaped);
                cursor = close + strlen("</BaseURL>");
                continue;
            }
        }
        size_t name_len = 0;
        if (media_dash_attribute_name(cursor, &name_len)) {
            const char *equals = cursor + name_len;
            while (isspace((unsigned char)*equals)) ++equals;
            if (*equals == '=') {
                const char *quote = equals + 1;
                while (isspace((unsigned char)*quote)) ++quote;
                if (*quote == '"' || *quote == '\'') {
                    char quote_char = *quote;
                    const char *close = strchr(quote + 1, quote_char);
                    if (close != NULL) {
                        char reference[3073];
                        size_t ref_len = (size_t)(close - quote - 1);
                        if (ref_len >= sizeof(reference)) ref_len = sizeof(reference) - 1U;
                        memcpy(reference, quote + 1, ref_len);
                        reference[ref_len] = '\0';
                        char resolved[3073];
                        media_resolve_source_url(source_url, reference, resolved);
                        char *asset = media_asset_url(asset_base, resolved);
                        char *escaped = asset == NULL ? NULL : media_xml_escape_text(asset);
                        free(asset);
                        if (escaped == NULL
                            || media_builder_append_len(&out, cursor, (size_t)(quote + 1 - cursor)) != 0
                            || media_builder_append(&out, escaped) != 0
                            || media_builder_append_len(&out, &quote_char, 1U) != 0) {
                            free(escaped); free(out.data); return NULL;
                        }
                        free(escaped);
                        cursor = close + 1;
                        continue;
                    }
                }
            }
        }
        if (media_builder_append_len(&out, cursor, 1U) != 0) {
            free(out.data);
            return NULL;
        }
        ++cursor;
    }
    if (out.data == NULL) out.data = strdup("");
    return out.data;
}

static int media_manifest_response(const char *method,
                                   const st_media_capture_row *row,
                                   const char *asset_base,
                                   char *out, size_t out_len)
{
    st_media_http_response response;
    st_media_config cfg = media_load_config();
    if (media_s3_request(&cfg, "GET", row->object_key, "", NULL, NULL, NULL, 0U, NULL, &response) != 0
        || !media_s3_success(&response)) {
        media_http_response_free(&response);
        return media_write_json_error(out, out_len, 409, "媒体清单尚未采集完成");
    }
    char *rewritten = strcmp(row->media_kind, "HLS_MANIFEST") == 0
        ? media_rewrite_hls(row->source_url, response.data == NULL ? "" : response.data, asset_base)
        : media_rewrite_dash(row->source_url, response.data == NULL ? "" : response.data, asset_base);
    media_http_response_free(&response);
    if (rewritten == NULL) return media_write_json_error(out, out_len, 500, "媒体清单重写失败");
    const char *content_type = strcmp(row->media_kind, "HLS_MANIFEST") == 0
        ? "application/vnd.apple.mpegurl; charset=utf-8" : "application/dash+xml; charset=utf-8";
    size_t body_len = strlen(rewritten);
    int result = media_write_response(out, out_len, 200, content_type, NULL, rewritten, body_len,
                                      strcasecmp(method, "HEAD") != 0);
    free(rewritten);
    return result;
}

static int media_header_safe(const char *value)
{
    if (value == NULL || *value == '\0') return 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (*cursor == '\r' || *cursor == '\n' || (*cursor < 0x20U && *cursor != '\t')) return 0;
    }
    return 1;
}

static int media_load_playback_parts(sqlite3 *db,
                                     const st_media_capture_row *anchor,
                                     st_media_playback_part **out_parts,
                                     size_t *out_len,
                                     long long *out_total)
{
    const char *sql =
        "SELECT object_key,content_range_start,content_range_end,total_bytes,captured_bytes "
        "FROM specus_http_media_capture WHERE tenant_id=? AND client_id=? AND resource_key=? "
        "AND state='COMPLETE' AND captured_bytes>0 "
        "AND (expires_at IS NULL OR expires_at>strftime('%Y-%m-%dT%H:%M:%SZ','now')) "
        "ORDER BY id DESC LIMIT ?";
    sqlite3_stmt *stmt = NULL;
    st_media_playback_part *parts = NULL;
    size_t len = 0U;
    long long total = 0;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, anchor->tenant_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 2, anchor->client_id);
    sqlite3_bind_text(stmt, 3, anchor->resource_key, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (int)ST_MEDIA_MAX_PLAYBACK_PARTS);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
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
            if (parts[len].has_total && parts[len].total > total) total = parts[len].total;
        }
        if (end < LLONG_MAX && end + 1LL > total) total = end + 1LL;
        ++len;
    }
    sqlite3_finalize(stmt);
    if (len == 0U || total <= 0) {
        free(parts);
        return -1;
    }
    *out_parts = parts;
    *out_len = len;
    *out_total = total;
    return 0;
}

static int media_parse_nonnegative(const char *value, size_t len, long long *out)
{
    if (value == NULL || len == 0U) return -1;
    long long parsed = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)value[i];
        if (!isdigit(ch)) return -1;
        int digit = ch - '0';
        if (parsed > (LLONG_MAX - digit) / 10LL) return -1;
        parsed = parsed * 10LL + digit;
    }
    *out = parsed;
    return 0;
}

static int media_parse_playback_range(const char *header,
                                      long long total,
                                      long long *out_start,
                                      long long *out_end)
{
    if (header == NULL || *header == '\0' || total <= 0) return -1;
    while (isspace((unsigned char)*header)) ++header;
    size_t len = strlen(header);
    while (len > 0U && isspace((unsigned char)header[len - 1U])) --len;
    if (len <= 6U || strncasecmp(header, "bytes=", 6U) != 0
        || memchr(header + 6, ',', len - 6U) != NULL) return -1;
    const char *value = header + 6;
    size_t value_len = len - 6U;
    const char *dash = memchr(value, '-', value_len);
    if (dash == NULL || memchr(dash + 1, '-', (size_t)(value + value_len - dash - 1)) != NULL) return -1;
    size_t left_len = (size_t)(dash - value);
    size_t right_len = value_len - left_len - 1U;
    long long start = 0;
    long long end = total - 1LL;
    if (left_len == 0U) {
        long long suffix = 0;
        if (media_parse_nonnegative(dash + 1, right_len, &suffix) != 0 || suffix <= 0) return -1;
        start = suffix >= total ? 0 : total - suffix;
    } else {
        if (media_parse_nonnegative(value, left_len, &start) != 0 || start >= total) return -1;
        if (right_len > 0U) {
            if (media_parse_nonnegative(dash + 1, right_len, &end) != 0 || end < start) return -1;
            if (end >= total) end = total - 1LL;
        }
    }
    *out_start = start;
    *out_end = end;
    return 0;
}

static long long media_playback_contiguous_end(const st_media_playback_part *parts,
                                               size_t parts_len,
                                               long long start,
                                               long long limit)
{
    long long cursor = start;
    while (cursor <= limit) {
        long long farthest = cursor - 1LL;
        for (size_t i = 0; i < parts_len; ++i) {
            if (parts[i].start <= cursor && parts[i].end >= cursor && parts[i].end > farthest)
                farthest = parts[i].end;
        }
        if (farthest < cursor) break;
        if (farthest >= limit) return limit;
        if (farthest == LLONG_MAX) return farthest;
        cursor = farthest + 1LL;
    }
    return cursor - 1LL;
}

static int media_write_range_error(char *out, size_t out_len, long long total)
{
    char headers[160];
    snprintf(headers, sizeof(headers),
             "Accept-Ranges: bytes\r\nContent-Range: bytes */%lld\r\n", total);
    return media_write_response(out, out_len, 416, "application/octet-stream",
                                headers, "", 0U, 0);
}

static int media_playback_response(const char *method,
                                   sqlite3 *db,
                                   const st_media_capture_row *row,
                                   const char *range_header,
                                   int *range_missing,
                                   char *out,
                                   size_t out_len)
{
    st_media_playback_part *parts = NULL;
    size_t parts_len = 0U;
    long long total = 0;
    if (range_missing != NULL) *range_missing = 0;
    if (media_load_playback_parts(db, row, &parts, &parts_len, &total) != 0)
        return media_write_json_error(out, out_len, 409, "媒体采集尚未形成可播放区间");
    int requested = range_header != NULL && *range_header != '\0';
    long long start = 0;
    long long requested_end = total - 1LL;
    if (requested) {
        if (media_parse_playback_range(range_header, total, &start, &requested_end) != 0) {
            if (range_missing != NULL) *range_missing = 1;
            free(parts);
            return media_write_range_error(out, out_len, total);
        }
    } else {
        start = parts[0].start;
        for (size_t i = 1; i < parts_len; ++i) {
            if (parts[i].start < start) start = parts[i].start;
        }
    }
    long long end = media_playback_contiguous_end(parts, parts_len, start, requested_end);
    if (end < start) {
        if (range_missing != NULL) *range_missing = 1;
        free(parts);
        return media_write_range_error(out, out_len, total);
    }
    size_t max_body = out_len > 4096U ? out_len - 4096U : 0U;
    unsigned long long planned = (unsigned long long)(end - start) + 1ULL;
    if (planned > max_body) {
        if (max_body == 0U) {
            free(parts);
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
        for (size_t i = 0; i < parts_len; ++i) {
            if (parts[i].start <= cursor && parts[i].end >= cursor && parts[i].end > selected_end) {
                selected = i;
                selected_end = parts[i].end;
            }
        }
        if (selected == SIZE_MAX) break;
        long long logical_end = selected_end < end ? selected_end : end;
        long long object_start = cursor - parts[selected].start;
        long long object_end = logical_end - parts[selected].start;
        char object_range[96];
        snprintf(object_range, sizeof(object_range), "%lld-%lld", object_start, object_end);
        st_media_http_response response = {0};
        if (media_s3_request(&cfg, "GET", parts[selected].object_key, "", NULL, NULL,
                             NULL, 0U, object_range, &response) != 0
            || !media_s3_success(&response)
            || response.data == NULL
            || response.len != (size_t)(logical_end - cursor + 1LL)
            || media_builder_append_len(&body, response.data,
                                        (size_t)(logical_end - cursor + 1LL)) != 0) {
            media_http_response_free(&response);
            free(parts);
            free(body.data);
            return media_write_json_error(out, out_len, 503, "媒体播放对象读取失败");
        }
        media_http_response_free(&response);
        cursor = logical_end + 1LL;
    }
    free(parts);
    if (include_body && cursor <= end) {
        free(body.data);
        return media_write_json_error(out, out_len, 503, "媒体播放对象不连续");
    }
    int partial = requested || start > 0 || end < total - 1LL;
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
    if (strncmp(suffix, "/playback-ticket", strlen("/playback-ticket")) == 0) {
        sqlite3_close(db);
        return strcasecmp(method, "POST") == 0
            ? media_create_ticket(path, identity, database_path, id, out, out_len)
            : 0;
    }
    st_media_capture_row target = anchor;
    if (strncmp(suffix, "/asset", strlen("/asset")) == 0) {
        char *url = media_query_value(path, "url");
        int found = url != NULL && media_load_latest_source(db, &anchor, url, &target) == 0;
        free(url);
        if (!found) {
            sqlite3_close(db);
            return media_write_json_error(out, out_len, 404, "对应媒体分段尚未采集完成");
        }
    }
    if (strcmp(target.state, "COMPLETE") != 0) {
        sqlite3_close(db);
        return media_write_json_error(out, out_len, 409, "媒体采集尚未完成");
    }
    if (strncmp(suffix, "/manifest", strlen("/manifest")) == 0
        || (strncmp(suffix, "/asset", strlen("/asset")) == 0
            && (strcmp(target.media_kind, "HLS_MANIFEST") == 0
                || strcmp(target.media_kind, "DASH_MANIFEST") == 0))) {
        char base[256];
        snprintf(base, sizeof(base), "/api/admin/traffic/media-captures/%lld/asset", target.id);
        int result = media_manifest_response(method, &target, base, out, out_len);
        sqlite3_close(db);
        return result;
    }
    if (strncmp(suffix, "/play", strlen("/play")) == 0
        || strncmp(suffix, "/asset", strlen("/asset")) == 0) {
        int result = media_playback_response(method, db, &target, range_header,
                                             NULL, out, out_len);
        sqlite3_close(db);
        return result;
    }
    sqlite3_close(db);
    return 0;
}

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
    char token[65];
    memcpy(token, token_start, (size_t)(slash - token_start));
    token[slash - token_start] = '\0';
    char tenant_id[64];
    long long capture_id = 0;
    int backfill = 0;
    if (media_resolve_ticket(token, tenant_id, &capture_id, &backfill) != 0)
        return media_write_json_error(out, out_len, 404, "媒体播放票据无效或已过期");
    sqlite3 *db = NULL;
    st_media_capture_row anchor;
    if (media_db_open(database_path, &db) != 0 || media_load_row(db, tenant_id, capture_id, &anchor) != 0) {
        if (db != NULL) sqlite3_close(db);
        return media_write_json_error(out, out_len, 404, "媒体采集记录不存在");
    }
    st_media_capture_row target = anchor;
    const char *suffix = slash;
    if (strncmp(suffix, "/asset", strlen("/asset")) == 0) {
        char *url = media_query_value(path, "url");
        int found = url != NULL && media_load_latest_source(db, &anchor, url, &target) == 0;
        if (!found && backfill && url != NULL) {
            char *encoded_client = media_uri_encode(anchor.client_name, 0);
            char *encoded_route = media_uri_encode(anchor.route, 0);
            char location[4096];
            snprintf(location, sizeof(location), "/http/%s/%s%s", encoded_client, encoded_route, url);
            char headers[4200];
            snprintf(headers, sizeof(headers), "Location: %s\r\n", location);
            free(encoded_client); free(encoded_route); free(url); sqlite3_close(db);
            return media_write_response(out, out_len, 307, "application/octet-stream", headers, "", 0U, 0);
        }
        free(url);
        if (!found) {
            sqlite3_close(db);
            return media_write_json_error(out, out_len, 404, "媒体资源尚未缓存");
        }
    }
    if (strcmp(target.state, "COMPLETE") != 0) {
        sqlite3_close(db);
        return media_write_json_error(out, out_len, 409, "媒体采集尚未完成");
    }
    if (strncmp(suffix, "/manifest", strlen("/manifest")) == 0
        || (strncmp(suffix, "/asset", strlen("/asset")) == 0
            && (strcmp(target.media_kind, "HLS_MANIFEST") == 0
                || strcmp(target.media_kind, "DASH_MANIFEST") == 0))) {
        char base[256];
        snprintf(base, sizeof(base), "/api/public/media-playback/%s/asset", token);
        int result = media_manifest_response(method, &target, base, out, out_len);
        sqlite3_close(db);
        return result;
    }
    if (strncmp(suffix, "/play", strlen("/play")) == 0
        || strncmp(suffix, "/asset", strlen("/asset")) == 0) {
        int range_missing = 0;
        int result = media_playback_response(method, db, &target, range_header,
                                             &range_missing, out, out_len);
        if (range_missing && backfill) {
            char *encoded_client = media_uri_encode(anchor.client_name, 0);
            char *encoded_route = media_uri_encode(anchor.route, 0);
            char location[4096];
            snprintf(location, sizeof(location), "/http/%s/%s%s",
                     encoded_client == NULL ? "" : encoded_client,
                     encoded_route == NULL ? "" : encoded_route,
                     target.source_url);
            char headers[4200];
            snprintf(headers, sizeof(headers), "Location: %s\r\n", location);
            free(encoded_client);
            free(encoded_route);
            result = media_write_response(out, out_len, 307, "application/octet-stream",
                                          headers, "", 0U, 0);
        }
        sqlite3_close(db);
        return result;
    }
    sqlite3_close(db);
    return 0;
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
