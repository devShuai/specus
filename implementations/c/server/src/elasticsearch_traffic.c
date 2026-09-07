#define _POSIX_C_SOURCE 200809L

#include "elasticsearch_traffic.h"

#include "json.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <limits.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <time.h>

#define ST_ES_PREVIEW_BYTES 1024U
#define ST_ES_MAX_RESPONSE (32U * 1024U * 1024U)

typedef struct {
    char endpoint[1024];
    char username[256];
    char password[512];
    char api_key[1024];
    char http_index[256];
    char tcp_index[256];
    long long http_max_bytes;
    long long tcp_max_bytes;
} st_es_config;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} st_es_buffer;

static pthread_once_t es_curl_once = PTHREAD_ONCE_INIT;
static CURLcode es_curl_init_result = CURLE_FAILED_INIT;
static pthread_mutex_t es_index_lock = PTHREAD_MUTEX_INITIALIZER;
static int es_http_ready = 0;
static int es_tcp_ready = 0;
static char es_ready_endpoint[1024];
static atomic_ullong es_id_sequence = 1U;
static atomic_llong es_http_last_trim_ms = 0;
static atomic_llong es_tcp_last_trim_ms = 0;

static int es_search(const st_es_config *config, const char *index, const char *request, char **response);
static int es_parse_total(const char *response, long long *total, char ***hits, size_t *hit_count);

static void es_curl_init(void)
{
    es_curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int es_buffer_reserve(st_es_buffer *buffer, size_t extra)
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

static int es_buffer_append_n(st_es_buffer *buffer, const char *value, size_t len)
{
    if (es_buffer_reserve(buffer, len) != 0) return -1;
    memcpy(buffer->data + buffer->len, value, len);
    buffer->len += len;
    buffer->data[buffer->len] = '\0';
    return 0;
}

static int es_buffer_append(st_es_buffer *buffer, const char *value)
{
    return es_buffer_append_n(buffer, value, strlen(value));
}

static int es_buffer_appendf(st_es_buffer *buffer, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0 || es_buffer_reserve(buffer, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    (void)vsnprintf(buffer->data + buffer->len, buffer->cap - buffer->len, format, args);
    va_end(args);
    buffer->len += (size_t)needed;
    return 0;
}

static int es_append_json_string(st_es_buffer *buffer, const char *value)
{
    char *escaped = st_json_escape(value == NULL ? "" : value);
    if (escaped == NULL) return -1;
    int rc = es_buffer_append(buffer, "\"") || es_buffer_append(buffer, escaped)
        || es_buffer_append(buffer, "\"");
    free(escaped);
    return rc ? -1 : 0;
}

static int es_copy_trimmed(char *out, size_t out_len, const char *value)
{
    if (out == NULL || out_len == 0U) return -1;
    if (value == NULL) value = "";
    while (isspace((unsigned char)*value)) ++value;
    const char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    size_t len = (size_t)(end - value);
    if (len >= out_len) return -1;
    memcpy(out, value, len);
    out[len] = '\0';
    return 0;
}

static int es_valid_index(const char *value)
{
    if (value == NULL || *value == '\0' || value[0] == '-' || value[0] == '_' || value[0] == '+') return 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor)
        if (!(islower(*cursor) || isdigit(*cursor) || *cursor == '-' || *cursor == '_')) return 0;
    return strstr(value, "..") == NULL;
}

static long long es_parse_size(const char *value, long long fallback)
{
    if (value == NULL || *value == '\0') return fallback;
    while (isspace((unsigned char)*value)) ++value;
    char *end = NULL;
    errno = 0;
    long long number = strtoll(value, &end, 10);
    if (errno != 0 || end == value || number <= 0) return fallback;
    while (isspace((unsigned char)*end)) ++end;
    long long multiplier = 1;
    if (*end != '\0') {
        if (strcasecmp(end, "KB") == 0) multiplier = 1024LL;
        else if (strcasecmp(end, "MB") == 0) multiplier = 1024LL * 1024LL;
        else if (strcasecmp(end, "GB") == 0) multiplier = 1024LL * 1024LL * 1024LL;
        else if (strcasecmp(end, "TB") == 0) multiplier = 1024LL * 1024LL * 1024LL * 1024LL;
        else return fallback;
    }
    return number > LLONG_MAX / multiplier ? fallback : number * multiplier;
}

static int es_load_config(st_es_config *config)
{
    memset(config, 0, sizeof(*config));
    const char *uris = getenv("SPECUS_ELASTICSEARCH_URIS");
    if (uris == NULL || *uris == '\0') return 1;
    const char *comma = strchr(uris, ',');
    size_t first_len = comma == NULL ? strlen(uris) : (size_t)(comma - uris);
    if (first_len >= sizeof(config->endpoint)) return -1;
    char first[1024];
    memcpy(first, uris, first_len);
    first[first_len] = '\0';
    if (es_copy_trimmed(config->endpoint, sizeof(config->endpoint), first) != 0) return -1;
    size_t endpoint_len = strlen(config->endpoint);
    while (endpoint_len > 0U && config->endpoint[endpoint_len - 1U] == '/')
        config->endpoint[--endpoint_len] = '\0';
    if (!(strncasecmp(config->endpoint, "http://", 7U) == 0
          || strncasecmp(config->endpoint, "https://", 8U) == 0)) return -1;
    if (es_copy_trimmed(config->username, sizeof(config->username), getenv("SPECUS_ELASTICSEARCH_USERNAME")) != 0
        || es_copy_trimmed(config->password, sizeof(config->password), getenv("SPECUS_ELASTICSEARCH_PASSWORD")) != 0
        || es_copy_trimmed(config->api_key, sizeof(config->api_key), getenv("SPECUS_ELASTICSEARCH_API_KEY")) != 0
        || es_copy_trimmed(config->http_index, sizeof(config->http_index),
                           getenv("SPECUS_ELASTICSEARCH_HTTP_INDEX")) != 0
        || es_copy_trimmed(config->tcp_index, sizeof(config->tcp_index),
                           getenv("SPECUS_ELASTICSEARCH_TCP_INDEX")) != 0) return -1;
    if (config->http_index[0] == '\0') strcpy(config->http_index, "specus-http-traffic");
    if (config->tcp_index[0] == '\0') strcpy(config->tcp_index, "specus-tcp-traffic");
    if (!es_valid_index(config->http_index) || !es_valid_index(config->tcp_index)) return -1;
    config->http_max_bytes = es_parse_size(getenv("SPECUS_ELASTICSEARCH_HTTP_MAX_STORE_SIZE"),
                                           100LL * 1024LL * 1024LL * 1024LL);
    config->tcp_max_bytes = es_parse_size(getenv("SPECUS_ELASTICSEARCH_TCP_MAX_STORE_SIZE"),
                                          10LL * 1024LL * 1024LL * 1024LL);
    return 0;
}

int st_elasticsearch_traffic_enabled_current(void)
{
    st_es_config config;
    return es_load_config(&config) == 0;
}

static size_t es_collect(char *data, size_t size, size_t nmemb, void *context)
{
    st_es_buffer *buffer = (st_es_buffer *)context;
    size_t count = size * nmemb;
    if (size != 0U && count / size != nmemb) return 0U;
    if (count > ST_ES_MAX_RESPONSE - buffer->len) return 0U;
    return es_buffer_append_n(buffer, data, count) == 0 ? count : 0U;
}

static int es_request(const st_es_config *config,
                      const char *method,
                      const char *path,
                      const char *body,
                      const char *content_type,
                      long *status,
                      char **response)
{
    *status = 0;
    *response = NULL;
    size_t url_len = strlen(config->endpoint) + strlen(path) + 1U;
    char *url = (char *)malloc(url_len);
    if (url == NULL) return -1;
    snprintf(url, url_len, "%s%s", config->endpoint, path);
    (void)pthread_once(&es_curl_once, es_curl_init);
    CURL *curl = es_curl_init_result == CURLE_OK ? curl_easy_init() : NULL;
    if (curl == NULL) { free(url); return -1; }
    st_es_buffer output = {0};
    struct curl_slist *headers = NULL;
    if (content_type != NULL) {
        char header[128];
        snprintf(header, sizeof(header), "Content-Type: %s", content_type);
        headers = curl_slist_append(headers, header);
    }
    if (config->api_key[0] != '\0') {
        size_t header_len = strlen(config->api_key) + 23U;
        char *header = (char *)malloc(header_len);
        if (header == NULL) { curl_slist_free_all(headers); curl_easy_cleanup(curl); free(url); return -1; }
        snprintf(header, header_len, "Authorization: ApiKey %s", config->api_key);
        headers = curl_slist_append(headers, header);
        free(header);
    }
    CURLcode rc = curl_easy_setopt(curl, CURLOPT_URL, url);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    if (rc == CURLE_OK && strcmp(method, "HEAD") == 0) rc = curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, es_collect);
    if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_WRITEDATA, &output);
    if (rc == CURLE_OK && headers != NULL) rc = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (rc == CURLE_OK && body != NULL) rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    if (rc == CURLE_OK && body != NULL) rc = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(body));
    if (rc == CURLE_OK && config->api_key[0] == '\0' && (config->username[0] != '\0' || config->password[0] != '\0')) {
        rc = curl_easy_setopt(curl, CURLOPT_USERNAME, config->username);
        if (rc == CURLE_OK) rc = curl_easy_setopt(curl, CURLOPT_PASSWORD, config->password);
    }
    if (rc == CURLE_OK) rc = curl_easy_perform(curl);
    if (rc == CURLE_OK) rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(url);
    if (rc != CURLE_OK) { free(output.data); return -1; }
    if (output.data == NULL) output.data = strdup("");
    *response = output.data;
    return output.data == NULL ? -1 : 0;
}

static const char es_http_mapping[] =
    "{\"mappings\":{\"properties\":{"
    "\"id\":{\"type\":\"long\"},\"tenantId\":{\"type\":\"keyword\"},"
    "\"clientId\":{\"type\":\"long\"},\"clientName\":{\"type\":\"keyword\"},"
    "\"route\":{\"type\":\"keyword\"},\"resourceId\":{\"type\":\"long\"},"
    "\"resourceName\":{\"type\":\"text\"},\"method\":{\"type\":\"keyword\"},"
    "\"relativePath\":{\"type\":\"text\"},\"rawQuery\":{\"type\":\"text\"},"
    "\"statusCode\":{\"type\":\"integer\"},\"success\":{\"type\":\"boolean\"},"
    "\"error\":{\"type\":\"text\"},\"remoteAddress\":{\"type\":\"keyword\"},"
    "\"requestBytes\":{\"type\":\"long\"},\"responseBytes\":{\"type\":\"long\"},"
    "\"elapsedMs\":{\"type\":\"long\"},\"requestContentType\":{\"type\":\"keyword\"},"
    "\"responseContentType\":{\"type\":\"keyword\"},\"responseBodyType\":{\"type\":\"keyword\"},"
    "\"requestHeaders\":{\"type\":\"text\"},\"responseHeaders\":{\"type\":\"text\"},"
    "\"requestPreviewHex\":{\"type\":\"text\"},\"requestPreviewText\":{\"type\":\"text\"},"
    "\"responsePreviewHex\":{\"type\":\"text\"},\"responsePreviewText\":{\"type\":\"text\"},"
    "\"requestTruncated\":{\"type\":\"boolean\"},\"responseTruncated\":{\"type\":\"boolean\"},"
    "\"capturedAt\":{\"type\":\"keyword\"}}}}";

static const char es_tcp_mapping[] =
    "{\"mappings\":{\"properties\":{"
    "\"id\":{\"type\":\"long\"},\"tenantId\":{\"type\":\"keyword\"},"
    "\"clientId\":{\"type\":\"long\"},\"clientName\":{\"type\":\"keyword\"},"
    "\"listenPort\":{\"type\":\"integer\"},\"resourceId\":{\"type\":\"long\"},"
    "\"resourceName\":{\"type\":\"text\"},\"channelId\":{\"type\":\"keyword\"},"
    "\"direction\":{\"type\":\"keyword\"},\"remoteAddress\":{\"type\":\"keyword\"},"
    "\"sourceAddress\":{\"type\":\"keyword\"},\"sourcePort\":{\"type\":\"integer\"},"
    "\"destinationAddress\":{\"type\":\"keyword\"},\"destinationPort\":{\"type\":\"integer\"},"
    "\"streamOffset\":{\"type\":\"long\"},\"streamEndOffset\":{\"type\":\"long\"},"
    "\"frameIndex\":{\"type\":\"long\"},\"payloadBytes\":{\"type\":\"long\"},"
    "\"payloadData\":{\"type\":\"binary\"},\"payloadPreviewHex\":{\"type\":\"text\"},"
    "\"payloadPreviewText\":{\"type\":\"text\"},\"truncated\":{\"type\":\"boolean\"},"
    "\"frameTime\":{\"type\":\"keyword\"}}}}";

static int es_ensure_index(const st_es_config *config, const char *index, const char *mapping, int *ready)
{
    pthread_mutex_lock(&es_index_lock);
    if (strcmp(es_ready_endpoint, config->endpoint) != 0) {
        es_http_ready = 0;
        es_tcp_ready = 0;
        snprintf(es_ready_endpoint, sizeof(es_ready_endpoint), "%s", config->endpoint);
    }
    if (*ready) { pthread_mutex_unlock(&es_index_lock); return 0; }
    char path[300];
    snprintf(path, sizeof(path), "/%s", index);
    long status = 0;
    char *response = NULL;
    int rc = es_request(config, "HEAD", path, NULL, NULL, &status, &response);
    free(response);
    if (rc == 0 && status == 404) {
        rc = es_request(config, "PUT", path, mapping, "application/json", &status, &response);
        free(response);
    }
    if (rc == 0 && status >= 200 && status < 300) *ready = 1;
    else rc = -1;
    pthread_mutex_unlock(&es_index_lock);
    return rc;
}

int st_elasticsearch_traffic_initialize_current(void)
{
    st_es_config config;
    int loaded = es_load_config(&config);
    if (loaded == 1) return 0;
    if (loaded != 0) {
        fprintf(stderr, "Elasticsearch configuration is invalid\n");
        return -1;
    }
    if (es_ensure_index(&config, config.http_index, es_http_mapping, &es_http_ready) != 0
        || es_ensure_index(&config, config.tcp_index, es_tcp_mapping, &es_tcp_ready) != 0) {
        fprintf(stderr, "failed to initialize Elasticsearch traffic detail indices\n");
        return -1;
    }
    return 0;
}

void st_elasticsearch_traffic_reset_for_tests(void)
{
    pthread_mutex_lock(&es_index_lock);
    es_http_ready = 0;
    es_tcp_ready = 0;
    es_ready_endpoint[0] = '\0';
    pthread_mutex_unlock(&es_index_lock);
    atomic_store(&es_http_last_trim_ms, 0);
    atomic_store(&es_tcp_last_trim_ms, 0);
}

static long long es_new_id(void)
{
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) return -1;
    unsigned long long sequence = atomic_fetch_add(&es_id_sequence, 1U) & 0xfffffU;
    unsigned long long millis = (unsigned long long)now.tv_sec * 1000ULL + (unsigned long long)now.tv_usec / 1000ULL;
    unsigned long long value = (millis << 20U) | sequence;
    return value > (unsigned long long)LLONG_MAX ? -1 : (long long)value;
}

static int es_store_bytes(const st_es_config *config, const char *index, long long *bytes)
{
    char path[320];
    snprintf(path, sizeof(path), "/%s/_stats/store", index);
    long status = 0;
    char *response = NULL;
    if (es_request(config, "GET", path, NULL, NULL, &status, &response) != 0
        || status < 200 || status >= 300 || response == NULL) { free(response); return -1; }
    char *indices = st_json_get_top_level_raw(response, "indices");
    char *entry = indices == NULL ? NULL : st_json_get_top_level_raw(indices, index);
    char *total = entry == NULL ? NULL : st_json_get_top_level_raw(entry, "total");
    char *store = total == NULL ? NULL : st_json_get_top_level_raw(total, "store");
    long long value = 0;
    int rc = store != NULL && st_json_get_i64(store, "total_data_set_size_in_bytes", &value) == 0
        && value > 0 ? 0 : store != NULL ? st_json_get_i64(store, "size_in_bytes", &value) : -1;
    free(store); free(total); free(entry); free(indices); free(response);
    if (rc == 0) *bytes = value;
    return rc;
}

static int es_oldest_ids(const st_es_config *config, const char *index, char ***ids, size_t *id_count)
{
    *ids = NULL;
    *id_count = 0U;
    static const char request[] =
        "{\"query\":{\"match_all\":{}},\"size\":500,"
        "\"sort\":[{\"id\":{\"order\":\"asc\"}}],\"_source\":false}";
    char *response = NULL;
    if (es_search(config, index, request, &response) != 0) { free(response); return -1; }
    char **hits = NULL;
    size_t hit_count = 0U;
    long long total = 0;
    int rc = es_parse_total(response, &total, &hits, &hit_count);
    free(response);
    if (rc != 0) { st_json_free_string_array(hits, hit_count); return -1; }
    char **values = hit_count == 0U ? NULL : (char **)calloc(hit_count, sizeof(*values));
    if (hit_count > 0U && values == NULL) { st_json_free_string_array(hits, hit_count); return -1; }
    for (size_t i = 0; i < hit_count; ++i) {
        values[i] = st_json_get_top_level_string(hits[i], "_id");
        if (values[i] == NULL) {
            st_json_free_string_array(values, i);
            st_json_free_string_array(hits, hit_count);
            return -1;
        }
    }
    st_json_free_string_array(hits, hit_count);
    *ids = values;
    *id_count = hit_count;
    return 0;
}

static int es_bulk_delete(const st_es_config *config, const char *index, char **ids, size_t count)
{
    st_es_buffer body = {0};
    for (size_t i = 0; i < count; ++i) {
        if (es_buffer_append(&body, "{\"delete\":{\"_index\":") != 0
            || es_append_json_string(&body, index) != 0
            || es_buffer_append(&body, ",\"_id\":") != 0
            || es_append_json_string(&body, ids[i]) != 0
            || es_buffer_append(&body, "}}\n") != 0) { free(body.data); return -1; }
    }
    long status = 0;
    char *response = NULL;
    int rc = es_request(config, "POST", "/_bulk", body.data, "application/x-ndjson", &status, &response);
    free(response); free(body.data);
    return rc == 0 && status >= 200 && status < 300 ? 0 : -1;
}

static void es_trim_if_needed(const st_es_config *config,
                              const char *index,
                              long long max_bytes,
                              atomic_llong *last_trim)
{
    if (max_bytes <= 0) return;
    struct timeval now;
    if (gettimeofday(&now, NULL) != 0) return;
    long long now_ms = (long long)now.tv_sec * 1000LL + now.tv_usec / 1000;
    long long last = atomic_load(last_trim);
    if (last != 0 && now_ms - last < 60000LL) return;
    if (!atomic_compare_exchange_strong(last_trim, &last, now_ms)) return;
    long long bytes = 0;
    if (es_store_bytes(config, index, &bytes) != 0) return;
    for (int batch = 0; bytes > max_bytes && batch < 20; ++batch) {
        char **ids = NULL;
        size_t count = 0U;
        if (es_oldest_ids(config, index, &ids, &count) != 0 || count == 0U) {
            st_json_free_string_array(ids, count);
            return;
        }
        int deleted = es_bulk_delete(config, index, ids, count);
        st_json_free_string_array(ids, count);
        if (deleted != 0 || es_store_bytes(config, index, &bytes) != 0) return;
    }
}

static void es_hex_preview(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char hex[] = "0123456789abcdef";
    size_t count = len < ST_ES_PREVIEW_BYTES ? len : ST_ES_PREVIEW_BYTES;
    size_t max = out_len > 0U ? (out_len - 1U) / 2U : 0U;
    if (count > max) count = max;
    for (size_t i = 0; i < count; ++i) {
        out[i * 2U] = hex[data[i] >> 4U];
        out[i * 2U + 1U] = hex[data[i] & 15U];
    }
    if (out_len > 0U) out[count * 2U] = '\0';
}

static void es_text_preview(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    size_t count = len < ST_ES_PREVIEW_BYTES ? len : ST_ES_PREVIEW_BYTES, offset = 0U;
    for (size_t i = 0; i < count && offset + 1U < out_len; ++i) {
        unsigned char ch = data[i];
        out[offset++] = ch == '\r' || ch == '\n' || ch == '\t' || (ch >= 32U && ch < 127U) ? (char)ch : '.';
    }
    if (out_len > 0U) out[offset] = '\0';
}

static const char *es_body_type(const char *explicit_type, const char *content_type, long long bytes)
{
    if (explicit_type != NULL && *explicit_type != '\0') return explicit_type;
    if (bytes == 0) return "empty";
    if (content_type == NULL) return "binary";
    if (strstr(content_type, "json") != NULL) return "json";
    if (strstr(content_type, "html") != NULL) return "html";
    if (strstr(content_type, "xml") != NULL) return "xml";
    if (strstr(content_type, "image/") != NULL) return "image";
    if (strstr(content_type, "video/") != NULL) return "video";
    if (strstr(content_type, "audio/") != NULL) return "audio";
    if (strstr(content_type, "form") != NULL) return "form";
    if (strstr(content_type, "javascript") != NULL || strstr(content_type, "ecmascript") != NULL) return "script";
    if (strstr(content_type, "text/") != NULL) return "text";
    return "binary";
}

static int es_json_key(st_es_buffer *json, const char *key, int *first)
{
    if (!*first && es_buffer_append(json, ",") != 0) return -1;
    *first = 0;
    return es_append_json_string(json, key) == 0 && es_buffer_append(json, ":") == 0 ? 0 : -1;
}

static int es_json_string_field(st_es_buffer *json, const char *key, const char *value, int *first)
{
    return es_json_key(json, key, first) == 0 && es_append_json_string(json, value) == 0 ? 0 : -1;
}

static int es_json_i64_field(st_es_buffer *json, const char *key, long long value, int *first)
{
    return es_json_key(json, key, first) == 0 && es_buffer_appendf(json, "%lld", value) == 0 ? 0 : -1;
}

static int es_json_bool_field(st_es_buffer *json, const char *key, int value, int *first)
{
    return es_json_key(json, key, first) == 0 && es_buffer_append(json, value ? "true" : "false") == 0 ? 0 : -1;
}

static int es_index_document(const st_es_config *config,
                             const char *index,
                             long long id,
                             const char *document)
{
    char path[384];
    int written = snprintf(path, sizeof(path), "/%s/_doc/%lld", index, id);
    if (written < 0 || (size_t)written >= sizeof(path)) return -1;
    long status = 0;
    char *response = NULL;
    int rc = es_request(config, "PUT", path, document, "application/json", &status, &response);
    free(response);
    return rc == 0 && status >= 200 && status < 300 ? 0 : -1;
}

int st_elasticsearch_record_http(const st_storage_http_exchange_record *record)
{
    if (record == NULL || record->client_id <= 0 || record->client_name == NULL || record->route == NULL) return -1;
    st_es_config config;
    if (es_load_config(&config) != 0
        || es_ensure_index(&config, config.http_index, es_http_mapping, &es_http_ready) != 0) return -1;
    long long id = es_new_id();
    if (id <= 0) return -1;
    char request_hex[4096], request_text[8192], response_hex[4096], response_text[8192];
    es_hex_preview(record->request_body, record->request_body_len, request_hex, sizeof(request_hex));
    es_text_preview(record->request_body, record->request_body_len, request_text, sizeof(request_text));
    es_hex_preview(record->response_body, record->response_body_len, response_hex, sizeof(response_hex));
    es_text_preview(record->response_body, record->response_body_len, response_text, sizeof(response_text));
    st_es_buffer json = {0};
    int first = 1;
    int rc = es_buffer_append(&json, "{")
        || es_json_i64_field(&json, "id", id, &first)
        || es_json_string_field(&json, "tenantId", record->tenant_id == NULL || *record->tenant_id == '\0' ? "default" : record->tenant_id, &first)
        || es_json_i64_field(&json, "clientId", record->client_id, &first)
        || es_json_string_field(&json, "clientName", record->client_name, &first)
        || es_json_string_field(&json, "route", record->route, &first)
        || es_json_i64_field(&json, "resourceId", record->resource_id, &first)
        || es_json_string_field(&json, "resourceName", record->resource_name == NULL ? record->route : record->resource_name, &first)
        || es_json_string_field(&json, "method", record->method, &first)
        || es_json_string_field(&json, "relativePath", record->relative_path == NULL ? "/" : record->relative_path, &first)
        || es_json_string_field(&json, "rawQuery", record->raw_query, &first)
        || es_json_i64_field(&json, "statusCode", record->status_code, &first)
        || es_json_bool_field(&json, "success", record->success, &first)
        || es_json_string_field(&json, "error", record->error, &first)
        || es_json_string_field(&json, "remoteAddress", record->remote_address, &first)
        || es_json_i64_field(&json, "requestBytes", record->request_bytes, &first)
        || es_json_i64_field(&json, "responseBytes", record->response_bytes, &first)
        || es_json_i64_field(&json, "elapsedMs", record->elapsed_ms, &first)
        || es_json_string_field(&json, "requestContentType", record->request_content_type, &first)
        || es_json_string_field(&json, "responseContentType", record->response_content_type, &first)
        || es_json_string_field(&json, "responseBodyType", es_body_type(record->response_body_type,
                                                                         record->response_content_type,
                                                                         record->response_bytes), &first)
        || es_json_string_field(&json, "requestHeaders", record->request_headers, &first)
        || es_json_string_field(&json, "responseHeaders", record->response_headers, &first)
        || es_json_string_field(&json, "requestPreviewHex", request_hex, &first)
        || es_json_string_field(&json, "requestPreviewText", request_text, &first)
        || es_json_string_field(&json, "responsePreviewHex", response_hex, &first)
        || es_json_string_field(&json, "responsePreviewText", response_text, &first)
        || es_json_bool_field(&json, "requestTruncated", record->request_body_len > ST_ES_PREVIEW_BYTES, &first)
        || es_json_bool_field(&json, "responseTruncated", record->response_body_len > ST_ES_PREVIEW_BYTES, &first)
        || es_json_string_field(&json, "capturedAt", record->captured_at, &first)
        || es_buffer_append(&json, "}");
    if (rc) { free(json.data); return -1; }
    rc = es_index_document(&config, config.http_index, id, json.data);
    free(json.data);
    if (rc == 0) es_trim_if_needed(&config, config.http_index, config.http_max_bytes,
                                   &es_http_last_trim_ms);
    return rc;
}

static char *es_base64(const uint8_t *data, size_t len)
{
    if (len == 0U) return strdup("");
    if (len > (size_t)INT_MAX) return NULL;
    size_t encoded_len = 4U * ((len + 2U) / 3U);
    char *encoded = (char *)malloc(encoded_len + 1U);
    if (encoded == NULL) return NULL;
    int written = EVP_EncodeBlock((unsigned char *)encoded, data, (int)len);
    if (written < 0 || (size_t)written != encoded_len) { free(encoded); return NULL; }
    encoded[encoded_len] = '\0';
    return encoded;
}

int st_elasticsearch_record_tcp(const st_storage_tcp_frame_record *record)
{
    if (record == NULL || record->client_id <= 0 || record->client_name == NULL
        || record->channel_id == NULL || record->direction == NULL) return -1;
    st_es_config config;
    if (es_load_config(&config) != 0
        || es_ensure_index(&config, config.tcp_index, es_tcp_mapping, &es_tcp_ready) != 0) return -1;
    long long id = es_new_id();
    char *payload = es_base64(record->payload_data, record->payload_data_len);
    if (id <= 0 || payload == NULL) { free(payload); return -1; }
    char preview_hex[4096], preview_text[4096];
    es_hex_preview(record->payload_data, record->payload_data_len, preview_hex, sizeof(preview_hex));
    es_text_preview(record->payload_data, record->payload_data_len, preview_text, sizeof(preview_text));
    st_es_buffer json = {0};
    int first = 1;
    long long end_offset = record->payload_data_len > (size_t)LLONG_MAX
        || record->stream_offset > LLONG_MAX - (long long)record->payload_data_len
        ? LLONG_MAX : record->stream_offset + (long long)record->payload_data_len;
    int rc = es_buffer_append(&json, "{")
        || es_json_i64_field(&json, "id", id, &first)
        || es_json_string_field(&json, "tenantId", record->tenant_id == NULL || *record->tenant_id == '\0' ? "default" : record->tenant_id, &first)
        || es_json_i64_field(&json, "clientId", record->client_id, &first)
        || es_json_string_field(&json, "clientName", record->client_name, &first)
        || es_json_i64_field(&json, "listenPort", record->listen_port, &first)
        || es_json_i64_field(&json, "resourceId", record->resource_id, &first)
        || es_json_string_field(&json, "resourceName", record->resource_name, &first)
        || es_json_string_field(&json, "channelId", record->channel_id, &first)
        || es_json_string_field(&json, "direction", record->direction, &first)
        || es_json_string_field(&json, "remoteAddress", record->remote_address, &first)
        || es_json_string_field(&json, "sourceAddress", record->source_address, &first)
        || es_json_i64_field(&json, "sourcePort", record->source_port, &first)
        || es_json_string_field(&json, "destinationAddress", record->destination_address, &first)
        || es_json_i64_field(&json, "destinationPort", record->destination_port, &first)
        || es_json_i64_field(&json, "streamOffset", record->stream_offset, &first)
        || es_json_i64_field(&json, "streamEndOffset", end_offset, &first)
        || es_json_i64_field(&json, "frameIndex", record->frame_index, &first)
        || es_json_i64_field(&json, "payloadBytes", (long long)record->payload_data_len, &first)
        || es_json_string_field(&json, "payloadData", payload, &first)
        || es_json_string_field(&json, "payloadPreviewHex", preview_hex, &first)
        || es_json_string_field(&json, "payloadPreviewText", preview_text, &first)
        || es_json_bool_field(&json, "truncated", 0, &first)
        || es_json_string_field(&json, "frameTime", record->frame_time, &first)
        || es_buffer_append(&json, "}");
    free(payload);
    if (rc) { free(json.data); return -1; }
    rc = es_index_document(&config, config.tcp_index, id, json.data);
    free(json.data);
    if (rc == 0) es_trim_if_needed(&config, config.tcp_index, config.tcp_max_bytes,
                                   &es_tcp_last_trim_ms);
    return rc;
}

static int es_visible_client_ids(const char *database_path,
                                 const char *tenant_id,
                                 const char *owner_username,
                                 int include_all_clients,
                                 long long **ids,
                                 size_t *id_count)
{
    *ids = NULL;
    *id_count = 0U;
    sqlite3 *db = NULL;
    if (database_path == NULL || sqlite3_open(database_path, &db) != SQLITE_OK) {
        if (db != NULL) sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *stmt = NULL;
    const char *sql = include_all_clients
        ? "SELECT rowid FROM client_account WHERE tenant_id=? ORDER BY rowid"
        : "SELECT rowid FROM client_account WHERE tenant_id=? AND owner_username=? ORDER BY rowid";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK
        || sqlite3_bind_text(stmt, 1, tenant_id == NULL || *tenant_id == '\0' ? "default" : tenant_id,
                             -1, SQLITE_TRANSIENT) != SQLITE_OK
        || (!include_all_clients && sqlite3_bind_text(stmt, 2, owner_username == NULL ? "" : owner_username,
                                                       -1, SQLITE_TRANSIENT) != SQLITE_OK)) {
        sqlite3_finalize(stmt); sqlite3_close(db); return -1;
    }
    size_t capacity = 0U;
    int step = SQLITE_DONE;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*id_count == capacity) {
            size_t next = capacity == 0U ? 16U : capacity * 2U;
            if (next < capacity || next > SIZE_MAX / sizeof(**ids)) {
                free(*ids); *ids = NULL; *id_count = 0U;
                sqlite3_finalize(stmt); sqlite3_close(db); return -1;
            }
            long long *grown = (long long *)realloc(*ids, next * sizeof(**ids));
            if (grown == NULL) {
                free(*ids); *ids = NULL; *id_count = 0U;
                sqlite3_finalize(stmt); sqlite3_close(db); return -1;
            }
            *ids = grown;
            capacity = next;
        }
        (*ids)[(*id_count)++] = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return step == SQLITE_DONE ? 0 : -1;
}

static int es_contains_id(const long long *ids, size_t count, long long id)
{
    for (size_t i = 0; i < count; ++i) if (ids[i] == id) return 1;
    return 0;
}

static int es_append_term_string(st_es_buffer *json, const char *field, const char *value)
{
    return es_buffer_append(json, "{\"term\":{")
        || es_append_json_string(json, field)
        || es_buffer_append(json, ":")
        || es_append_json_string(json, value)
        || es_buffer_append(json, "}}") ? -1 : 0;
}

static int es_append_term_i64(st_es_buffer *json, const char *field, long long value)
{
    return es_buffer_append(json, "{\"term\":{")
        || es_append_json_string(json, field)
        || es_buffer_appendf(json, ":%lld}}", value) ? -1 : 0;
}

static int es_append_client_filter(st_es_buffer *json,
                                   const long long *ids,
                                   size_t id_count,
                                   long long client_id)
{
    if (client_id > 0) return es_append_term_i64(json, "clientId", client_id);
    if (es_buffer_append(json, "{\"terms\":{\"clientId\":[") != 0) return -1;
    for (size_t i = 0; i < id_count; ++i) {
        if ((i > 0U && es_buffer_append(json, ",") != 0)
            || es_buffer_appendf(json, "%lld", ids[i]) != 0) return -1;
    }
    return es_buffer_append(json, "]}}") == 0 ? 0 : -1;
}

static const char *es_http_search_fields(const char *field)
{
    if (field == NULL || *field == '\0')
        return "[\"clientName\",\"route\",\"method\",\"resourceName\",\"relativePath\",\"rawQuery\",\"error\",\"remoteAddress\"]";
    char normalized[64];
    size_t offset = 0U;
    for (const unsigned char *cursor = (const unsigned char *)field; *cursor != '\0' && offset + 1U < sizeof(normalized); ++cursor)
        if (*cursor != '_' && *cursor != '-') normalized[offset++] = (char)tolower(*cursor);
    normalized[offset] = '\0';
    if (strcmp(normalized, "method") == 0) return "[\"method\"]";
    if (strcmp(normalized, "route") == 0) return "[\"route\"]";
    if (strcmp(normalized, "path") == 0 || strcmp(normalized, "relativepath") == 0)
        return "[\"relativePath\",\"rawQuery\"]";
    if (strcmp(normalized, "query") == 0 || strcmp(normalized, "rawquery") == 0) return "[\"rawQuery\"]";
    if (strncmp(normalized, "client", 6U) == 0) return "[\"clientName\"]";
    if (strncmp(normalized, "resource", 8U) == 0) return "[\"resourceName\"]";
    if (strncmp(normalized, "remote", 6U) == 0) return "[\"remoteAddress\"]";
    if (strcmp(normalized, "error") == 0) return "[\"error\"]";
    if (strcmp(normalized, "requestheaders") == 0) return "[\"requestHeaders\"]";
    if (strcmp(normalized, "responseheaders") == 0) return "[\"responseHeaders\"]";
    if (strcmp(normalized, "headers") == 0) return "[\"requestHeaders\",\"responseHeaders\"]";
    if (strcmp(normalized, "requestbody") == 0) return "[\"requestPreviewText\"]";
    if (strcmp(normalized, "responsebody") == 0) return "[\"responsePreviewText\"]";
    if (strcmp(normalized, "body") == 0) return "[\"requestPreviewText\",\"responsePreviewText\"]";
    return "[\"clientName\",\"route\",\"method\",\"resourceName\",\"relativePath\",\"rawQuery\",\"error\",\"remoteAddress\"]";
}

static int es_build_query(st_es_buffer *json,
                          const char *tenant_id,
                          const long long *visible_ids,
                          size_t visible_count,
                          long long client_id,
                          const char *route,
                          const char *body_type,
                          int listen_port,
                          const char *channel_id,
                          long long document_id,
                          const char *field,
                          const char *query,
                          int page,
                          int size,
                          int tcp,
                          int stream)
{
    int rc = es_buffer_append(json, "{\"query\":{\"bool\":{\"filter\":[")
        || es_append_term_string(json, "tenantId", tenant_id == NULL || *tenant_id == '\0' ? "default" : tenant_id)
        || es_buffer_append(json, ",")
        || es_append_client_filter(json, visible_ids, visible_count, client_id);
    if (!rc && route != NULL && *route != '\0') rc = es_buffer_append(json, ",") || es_append_term_string(json, "route", route);
    if (!rc && body_type != NULL && *body_type != '\0') rc = es_buffer_append(json, ",") || es_append_term_string(json, "responseBodyType", body_type);
    if (!rc && listen_port > 0) rc = es_buffer_append(json, ",") || es_append_term_i64(json, "listenPort", listen_port);
    if (!rc && channel_id != NULL && *channel_id != '\0') rc = es_buffer_append(json, ",") || es_append_term_string(json, "channelId", channel_id);
    if (!rc && document_id > 0) rc = es_buffer_append(json, ",") || es_append_term_i64(json, "id", document_id);
    if (!rc) rc = es_buffer_append(json, "]");
    if (!rc && query != NULL && *query != '\0') {
        rc = es_buffer_append(json, ",\"must\":[{\"simple_query_string\":{\"query\":")
            || es_append_json_string(json, query)
            || es_buffer_append(json, ",\"fields\":")
            || es_buffer_append(json, es_http_search_fields(field))
            || es_buffer_append(json, ",\"default_operator\":\"and\"}}]");
    }
    if (!rc) rc = es_buffer_append(json, "}},\"from\":")
        || es_buffer_appendf(json, "%d,\"size\":%d,\"sort\":[", page * size, size);
    if (!rc) {
        if (tcp && stream) rc = es_buffer_append(json,
            "{\"frameIndex\":{\"order\":\"asc\"}},{\"id\":{\"order\":\"asc\"}}]");
        else rc = es_buffer_append(json, "{\"id\":{\"order\":\"desc\"}}]");
    }
    if (!rc && !tcp) rc = es_buffer_append(json,
        ",\"_source\":{\"excludes\":[\"requestHeaders\",\"responseHeaders\","
        "\"requestPreviewHex\",\"requestPreviewText\",\"responsePreviewHex\",\"responsePreviewText\"]}");
    if (!rc) rc = es_buffer_append(json, "}");
    return rc ? -1 : 0;
}

static int es_search(const st_es_config *config, const char *index, const char *request, char **response)
{
    char path[320];
    snprintf(path, sizeof(path), "/%s/_search", index);
    long status = 0;
    int rc = es_request(config, "POST", path, request, "application/json", &status, response);
    return rc == 0 && status >= 200 && status < 300 && *response != NULL
        && st_json_is_valid_object(*response) ? 0 : -1;
}

static int es_copy_json_string(const char *json, const char *key, char *out, size_t out_len)
{
    char *value = st_json_get_top_level_string(json, key);
    if (value == NULL) {
        if (out_len > 0U) out[0] = '\0';
        return 0;
    }
    int rc = strlen(value) < out_len ? 0 : -1;
    if (rc == 0) strcpy(out, value);
    free(value);
    return rc;
}

static int es_parse_total(const char *response, long long *total, char ***hits, size_t *hit_count)
{
    *total = 0;
    *hits = NULL;
    *hit_count = 0U;
    char *hits_object = st_json_get_top_level_raw(response, "hits");
    if (hits_object == NULL) return -1;
    char *total_raw = st_json_get_top_level_raw(hits_object, "total");
    int rc = total_raw != NULL && total_raw[0] == '{'
        ? st_json_get_i64(total_raw, "value", total)
        : total_raw != NULL ? ((*total = strtoll(total_raw, NULL, 10)), 0) : -1;
    if (rc == 0) rc = st_json_get_raw_array(hits_object, "hits", hits, hit_count);
    free(total_raw);
    free(hits_object);
    return rc;
}

static int es_parse_http_source(const char *source, st_storage_http_exchange *item)
{
    memset(item, 0, sizeof(*item));
    return st_json_get_i64(source, "id", &item->id)
        || es_copy_json_string(source, "tenantId", item->tenant_id, sizeof(item->tenant_id))
        || st_json_get_i64(source, "clientId", &item->client_id)
        || es_copy_json_string(source, "clientName", item->client_name, sizeof(item->client_name))
        || es_copy_json_string(source, "route", item->route, sizeof(item->route))
        || (st_json_get_i64(source, "resourceId", &item->resource_id) != 0 ? (item->resource_id = 0, 0) : 0)
        || es_copy_json_string(source, "resourceName", item->resource_name, sizeof(item->resource_name))
        || es_copy_json_string(source, "method", item->method, sizeof(item->method))
        || es_copy_json_string(source, "relativePath", item->relative_path, sizeof(item->relative_path))
        || es_copy_json_string(source, "rawQuery", item->raw_query, sizeof(item->raw_query))
        || st_json_get_int(source, "statusCode", &item->status_code)
        || (st_json_get_bool(source, "success", &item->success) != 0 ? (item->success = 0, 0) : 0)
        || es_copy_json_string(source, "error", item->error, sizeof(item->error))
        || es_copy_json_string(source, "remoteAddress", item->remote_address, sizeof(item->remote_address))
        || st_json_get_i64(source, "requestBytes", &item->request_bytes)
        || st_json_get_i64(source, "responseBytes", &item->response_bytes)
        || st_json_get_i64(source, "elapsedMs", &item->elapsed_ms)
        || es_copy_json_string(source, "requestContentType", item->request_content_type, sizeof(item->request_content_type))
        || es_copy_json_string(source, "responseContentType", item->response_content_type, sizeof(item->response_content_type))
        || es_copy_json_string(source, "responseBodyType", item->response_body_type, sizeof(item->response_body_type))
        || es_copy_json_string(source, "requestHeaders", item->request_headers, sizeof(item->request_headers))
        || es_copy_json_string(source, "responseHeaders", item->response_headers, sizeof(item->response_headers))
        || es_copy_json_string(source, "requestPreviewHex", item->request_preview_hex, sizeof(item->request_preview_hex))
        || es_copy_json_string(source, "requestPreviewText", item->request_preview_text, sizeof(item->request_preview_text))
        || es_copy_json_string(source, "responsePreviewHex", item->response_preview_hex, sizeof(item->response_preview_hex))
        || es_copy_json_string(source, "responsePreviewText", item->response_preview_text, sizeof(item->response_preview_text))
        || (st_json_get_bool(source, "requestTruncated", &item->request_truncated) != 0 ? (item->request_truncated = 0, 0) : 0)
        || (st_json_get_bool(source, "responseTruncated", &item->response_truncated) != 0 ? (item->response_truncated = 0, 0) : 0)
        || es_copy_json_string(source, "capturedAt", item->captured_at, sizeof(item->captured_at)) ? -1 : 0;
}

static uint8_t *es_decode_base64(const char *value, size_t *out_len)
{
    *out_len = 0U;
    if (value == NULL || *value == '\0') return NULL;
    size_t len = strlen(value);
    if (len % 4U != 0U || len > (size_t)INT_MAX) return NULL;
    uint8_t *out = (uint8_t *)malloc(3U * (len / 4U) + 1U);
    if (out == NULL) return NULL;
    int decoded = EVP_DecodeBlock(out, (const unsigned char *)value, (int)len);
    if (decoded < 0) { free(out); return NULL; }
    size_t actual = (size_t)decoded;
    if (value[len - 1U] == '=') --actual;
    if (len > 1U && value[len - 2U] == '=') --actual;
    *out_len = actual;
    return out;
}

static int es_parse_tcp_source(const char *source, st_storage_tcp_frame *item, int include_payload)
{
    memset(item, 0, sizeof(*item));
    int rc = st_json_get_i64(source, "id", &item->id)
        || es_copy_json_string(source, "tenantId", item->tenant_id, sizeof(item->tenant_id))
        || st_json_get_i64(source, "clientId", &item->client_id)
        || es_copy_json_string(source, "clientName", item->client_name, sizeof(item->client_name))
        || st_json_get_int(source, "listenPort", &item->listen_port)
        || (st_json_get_i64(source, "resourceId", &item->resource_id) != 0 ? (item->resource_id = 0, 0) : 0)
        || es_copy_json_string(source, "resourceName", item->resource_name, sizeof(item->resource_name))
        || es_copy_json_string(source, "channelId", item->channel_id, sizeof(item->channel_id))
        || es_copy_json_string(source, "direction", item->direction, sizeof(item->direction))
        || es_copy_json_string(source, "remoteAddress", item->remote_address, sizeof(item->remote_address))
        || es_copy_json_string(source, "sourceAddress", item->source_address, sizeof(item->source_address))
        || (st_json_get_int(source, "sourcePort", &item->source_port) != 0 ? (item->source_port = 0, 0) : 0)
        || es_copy_json_string(source, "destinationAddress", item->destination_address, sizeof(item->destination_address))
        || (st_json_get_int(source, "destinationPort", &item->destination_port) != 0 ? (item->destination_port = 0, 0) : 0)
        || st_json_get_i64(source, "streamOffset", &item->stream_offset)
        || st_json_get_i64(source, "streamEndOffset", &item->stream_end_offset)
        || st_json_get_i64(source, "frameIndex", &item->frame_index)
        || st_json_get_i64(source, "payloadBytes", &item->payload_bytes)
        || es_copy_json_string(source, "payloadPreviewHex", item->payload_preview_hex, sizeof(item->payload_preview_hex))
        || es_copy_json_string(source, "payloadPreviewText", item->payload_preview_text, sizeof(item->payload_preview_text))
        || (st_json_get_bool(source, "truncated", &item->truncated) != 0 ? (item->truncated = 0, 0) : 0)
        || es_copy_json_string(source, "frameTime", item->frame_time, sizeof(item->frame_time));
    if (rc != 0) return -1;
    if (include_payload) {
        char *encoded = st_json_get_top_level_string(source, "payloadData");
        if (encoded != NULL && *encoded != '\0') {
            item->payload_data = es_decode_base64(encoded, &item->payload_data_len);
            if (item->payload_data == NULL) { free(encoded); return -1; }
        }
        free(encoded);
    }
    return 0;
}

static int es_parse_hit_source(const char *hit, char **source)
{
    *source = st_json_get_top_level_raw(hit, "_source");
    return *source != NULL && st_json_is_valid_object(*source) ? 0 : -1;
}

int st_elasticsearch_list_http(const char *database_path,
                               long long client_id,
                               const char *route,
                               const char *response_body_type,
                               const char *field,
                               const char *query,
                               const char *tenant_id,
                               const char *owner_username,
                               int include_all_clients,
                               int page,
                               int size,
                               st_storage_http_exchange *items,
                               size_t max_items,
                               size_t *item_count,
                               long long *total_count)
{
    *item_count = 0U;
    *total_count = 0;
    if (page < 0) page = 0;
    if (size <= 0) size = 50;
    if (size > 500) size = 500;
    if ((size_t)size > max_items) size = (int)max_items;
    long long *visible = NULL;
    size_t visible_count = 0U;
    if (es_visible_client_ids(database_path, tenant_id, owner_username, include_all_clients,
                              &visible, &visible_count) != 0) return -1;
    if (visible_count == 0U || (client_id > 0 && !es_contains_id(visible, visible_count, client_id))) {
        free(visible);
        return 0;
    }
    st_es_config config;
    if (es_load_config(&config) != 0
        || es_ensure_index(&config, config.http_index, es_http_mapping, &es_http_ready) != 0) {
        free(visible); return -1;
    }
    st_es_buffer request = {0};
    if (es_build_query(&request, tenant_id, visible, visible_count, client_id, route,
                       response_body_type, 0, NULL, 0, field, query, page, size, 0, 0) != 0) {
        free(visible); free(request.data); return -1;
    }
    free(visible);
    char *response = NULL;
    int rc = es_search(&config, config.http_index, request.data, &response);
    free(request.data);
    if (rc != 0) { free(response); return -1; }
    char **hits = NULL;
    size_t hit_count = 0U;
    rc = es_parse_total(response, total_count, &hits, &hit_count);
    free(response);
    if (rc != 0 || hit_count > max_items) { st_json_free_string_array(hits, hit_count); return -1; }
    for (size_t i = 0; i < hit_count; ++i) {
        char *source = NULL;
        if (es_parse_hit_source(hits[i], &source) != 0
            || es_parse_http_source(source, &items[*item_count]) != 0) {
            free(source); st_json_free_string_array(hits, hit_count); return -1;
        }
        free(source);
        ++*item_count;
    }
    st_json_free_string_array(hits, hit_count);
    return 0;
}

static int es_list_tcp_internal(const char *database_path,
                                long long client_id,
                                int listen_port,
                                const char *channel_id,
                                long long document_id,
                                const char *tenant_id,
                                const char *owner_username,
                                int include_all_clients,
                                int page,
                                int size,
                                int include_payload,
                                int stream,
                                st_storage_tcp_frame *items,
                                size_t max_items,
                                size_t *item_count,
                                long long *total_count)
{
    *item_count = 0U;
    if (total_count != NULL) *total_count = 0;
    if (page < 0) page = 0;
    if (size <= 0) size = 50;
    if (size > 1000) size = 1000;
    if ((size_t)size > max_items) size = (int)max_items;
    long long *visible = NULL;
    size_t visible_count = 0U;
    if (es_visible_client_ids(database_path, tenant_id, owner_username, include_all_clients,
                              &visible, &visible_count) != 0) return -1;
    if (visible_count == 0U || (client_id > 0 && !es_contains_id(visible, visible_count, client_id))) {
        free(visible);
        return document_id > 0 ? -1 : 0;
    }
    st_es_config config;
    if (es_load_config(&config) != 0
        || es_ensure_index(&config, config.tcp_index, es_tcp_mapping, &es_tcp_ready) != 0) {
        free(visible); return -1;
    }
    st_es_buffer request = {0};
    if (es_build_query(&request, tenant_id, visible, visible_count, client_id, NULL, NULL,
                       listen_port, channel_id, document_id, NULL, NULL, page, size, 1, stream) != 0) {
        free(visible); free(request.data); return -1;
    }
    free(visible);
    char *response = NULL;
    int rc = es_search(&config, config.tcp_index, request.data, &response);
    free(request.data);
    if (rc != 0) { free(response); return -1; }
    char **hits = NULL;
    size_t hit_count = 0U;
    long long total = 0;
    rc = es_parse_total(response, &total, &hits, &hit_count);
    free(response);
    if (total_count != NULL) *total_count = total;
    if (rc != 0 || hit_count > max_items) { st_json_free_string_array(hits, hit_count); return -1; }
    for (size_t i = 0; i < hit_count; ++i) {
        char *source = NULL;
        if (es_parse_hit_source(hits[i], &source) != 0
            || es_parse_tcp_source(source, &items[*item_count], include_payload) != 0) {
            free(source);
            for (size_t j = 0; j < *item_count; ++j) st_storage_tcp_frame_free(&items[j]);
            *item_count = 0U;
            st_json_free_string_array(hits, hit_count);
            return -1;
        }
        free(source);
        ++*item_count;
    }
    st_json_free_string_array(hits, hit_count);
    return 0;
}

int st_elasticsearch_list_tcp(const char *database_path,
                              long long client_id,
                              int listen_port,
                              const char *tenant_id,
                              const char *owner_username,
                              int include_all_clients,
                              int page,
                              int size,
                              st_storage_tcp_frame *items,
                              size_t max_items,
                              size_t *item_count,
                              long long *total_count)
{
    return es_list_tcp_internal(database_path, client_id, listen_port, NULL, 0,
                                tenant_id, owner_username, include_all_clients, page, size,
                                0, 0, items, max_items, item_count, total_count);
}

int st_elasticsearch_get_tcp(const char *database_path,
                             long long id,
                             const char *tenant_id,
                             const char *owner_username,
                             int include_all_clients,
                             st_storage_tcp_frame *frame)
{
    if (frame == NULL || id <= 0) return -1;
    size_t count = 0U;
    long long total = 0;
    int rc = es_list_tcp_internal(database_path, 0, 0, NULL, id,
                                  tenant_id, owner_username, include_all_clients, 0, 1,
                                  1, 0, frame, 1U, &count, &total);
    return rc == 0 && count == 1U ? 0 : -1;
}

int st_elasticsearch_list_tcp_stream(const char *database_path,
                                     const char *channel_id,
                                     const char *tenant_id,
                                     const char *owner_username,
                                     int include_all_clients,
                                     int limit,
                                     st_storage_tcp_frame *items,
                                     size_t max_items,
                                     size_t *item_count)
{
    if (channel_id == NULL || *channel_id == '\0') { *item_count = 0U; return 0; }
    if (limit <= 0 || limit > 1000) limit = 500;
    long long total = 0;
    return es_list_tcp_internal(database_path, 0, 0, channel_id, 0,
                                tenant_id, owner_username, include_all_clients, 0, limit,
                                1, 1, items, max_items, item_count, &total);
}
