#define _POSIX_C_SOURCE 200809L

#include "http_client.h"

#include <curl/curl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ST_HTTP_DEFAULT_TIMEOUT_MS 15000L
#define ST_HTTP_DEFAULT_MAX_RESPONSE_BYTES (64U * 1024U)

typedef struct {
    char *data;
    size_t len;
    size_t max_len;
    int failed;
} st_http_response_buffer;

static pthread_once_t curl_init_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_result = CURLE_FAILED_INIT;

static void initialize_curl(void)
{
    curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t append_response_body(char *data, size_t size, size_t count, void *context)
{
    st_http_response_buffer *buffer = (st_http_response_buffer *)context;
    if (size != 0U && count > SIZE_MAX / size) {
        buffer->failed = 1;
        return 0U;
    }
    size_t bytes = size * count;
    if (bytes > buffer->max_len - buffer->len) {
        buffer->failed = 1;
        return 0U;
    }
    char *next = (char *)realloc(buffer->data, buffer->len + bytes + 1U);
    if (next == NULL) {
        buffer->failed = 1;
        return 0U;
    }
    buffer->data = next;
    if (bytes > 0U) {
        memcpy(buffer->data + buffer->len, data, bytes);
    }
    buffer->len += bytes;
    buffer->data[buffer->len] = '\0';
    return bytes;
}

static int http_request_json(const char *endpoint,
                             const char *basic_authorization_base64,
                             const char *form,
                             int post,
                             const st_http_client_options *options,
                             long *status_code_out,
                             char **body_out)
{
    if (endpoint == NULL || (post && form == NULL) || status_code_out == NULL || body_out == NULL
        || (strncmp(endpoint, "http://", 7U) != 0 && strncmp(endpoint, "https://", 8U) != 0)) {
        return -1;
    }
    *status_code_out = 0L;
    *body_out = NULL;
    (void)pthread_once(&curl_init_once, initialize_curl);
    if (curl_init_result != CURLE_OK) {
        return -1;
    }

    long timeout_ms = options == NULL || options->timeout_ms <= 0L
        ? ST_HTTP_DEFAULT_TIMEOUT_MS
        : options->timeout_ms;
    size_t max_response_bytes = options == NULL || options->max_response_bytes == 0U
        ? ST_HTTP_DEFAULT_MAX_RESPONSE_BYTES
        : options->max_response_bytes;
    st_http_response_buffer response = {.max_len = max_response_bytes};
    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        return -1;
    }
    struct curl_slist *headers = NULL;
    if (post) headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    headers = curl_slist_append(headers, "Accept: application/json");
    if (!post) headers = curl_slist_append(headers, "X-GitHub-Api-Version: 2022-11-28");
    char *authorization_header = NULL;
    if (basic_authorization_base64 != NULL && *basic_authorization_base64 != '\0') {
        size_t needed = strlen(basic_authorization_base64) + sizeof("Authorization: Basic ");
        authorization_header = (char *)malloc(needed);
        if (authorization_header == NULL
            || snprintf(authorization_header, needed, "Authorization: Basic %s", basic_authorization_base64) < 0) {
            free(authorization_header);
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            return -1;
        }
        headers = curl_slist_append(headers, authorization_header);
    }
    if (headers == NULL) {
        free(authorization_header);
        curl_easy_cleanup(curl);
        return -1;
    }

    CURLcode rc = CURLE_OK;
#define ST_CURL_SETOPT(option, value) \
    do { \
        if (rc == CURLE_OK) rc = curl_easy_setopt(curl, (option), (value)); \
    } while (0)
    ST_CURL_SETOPT(CURLOPT_URL, endpoint);
    ST_CURL_SETOPT(CURLOPT_HTTPHEADER, headers);
    if (post) {
        ST_CURL_SETOPT(CURLOPT_POST, 1L);
        ST_CURL_SETOPT(CURLOPT_POSTFIELDS, form);
        ST_CURL_SETOPT(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(form));
    }
    ST_CURL_SETOPT(CURLOPT_CONNECTTIMEOUT_MS, timeout_ms < 10000L ? timeout_ms : 10000L);
    ST_CURL_SETOPT(CURLOPT_TIMEOUT_MS, timeout_ms);
    ST_CURL_SETOPT(CURLOPT_NOSIGNAL, 1L);
    ST_CURL_SETOPT(CURLOPT_FOLLOWLOCATION, 0L);
#if LIBCURL_VERSION_NUM >= 0x075500
    ST_CURL_SETOPT(CURLOPT_PROTOCOLS_STR, "http,https");
#else
    ST_CURL_SETOPT(CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    ST_CURL_SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    ST_CURL_SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    ST_CURL_SETOPT(CURLOPT_USERAGENT, "specus-c-server/1");
    ST_CURL_SETOPT(CURLOPT_WRITEFUNCTION, append_response_body);
    ST_CURL_SETOPT(CURLOPT_WRITEDATA, &response);
    if (options != NULL && options->ca_certificate_path != NULL
        && *options->ca_certificate_path != '\0') {
        ST_CURL_SETOPT(CURLOPT_CAINFO, options->ca_certificate_path);
    }
#undef ST_CURL_SETOPT
    if (rc == CURLE_OK) {
        rc = curl_easy_perform(curl);
    }
    long status_code = 0L;
    if (rc == CURLE_OK) {
        rc = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
    }
    curl_slist_free_all(headers);
    free(authorization_header);
    curl_easy_cleanup(curl);
    if (rc != CURLE_OK || response.failed || status_code <= 0L) {
        free(response.data);
        return -1;
    }
    if (response.data == NULL) {
        response.data = (char *)malloc(1U);
        if (response.data == NULL) {
            return -1;
        }
        response.data[0] = '\0';
    }
    *status_code_out = status_code;
    *body_out = response.data;
    return 0;
}

int st_http_post_form(const char *endpoint,
                      const char *basic_authorization_base64,
                      const char *form,
                      const st_http_client_options *options,
                      long *status_code_out,
                      char **body_out)
{
    return http_request_json(endpoint, basic_authorization_base64, form, 1,
                             options, status_code_out, body_out);
}

int st_http_get_json(const char *endpoint,
                     const st_http_client_options *options,
                     long *status_code_out,
                     char **body_out)
{
    return http_request_json(endpoint, NULL, NULL, 0, options, status_code_out, body_out);
}
