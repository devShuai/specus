#define _GNU_SOURCE

#include "registration.h"

#include "crypto.h"
#include "http_client.h"
#include "json.h"
#include "password_hash.h"
#include "security.h"

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

typedef struct {
    st_registration_turnstile_handler turnstile;
    st_registration_email_handler email;
    void *ctx;
} st_registration_handlers;

typedef struct {
    const char *data;
    size_t len;
    size_t offset;
} st_registration_mail_upload;

static pthread_mutex_t registration_handlers_lock = PTHREAD_MUTEX_INITIALIZER;
static st_registration_handlers registration_handlers;
static pthread_once_t registration_curl_once = PTHREAD_ONCE_INIT;
static CURLcode registration_curl_init = CURLE_FAILED_INIT;

static void registration_initialize_curl(void)
{
    registration_curl_init = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static int registration_env_bool(const char *name, int fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    return strcmp(value, "1") == 0 || strcasecmp(value, "true") == 0
        || strcasecmp(value, "yes") == 0;
}

static long long registration_env_i64(const char *name,
                                      long long fallback,
                                      long long minimum,
                                      long long maximum)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') return fallback;
    errno = 0;
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return errno == 0 && end != value && *end == '\0' && parsed >= minimum && parsed <= maximum
        ? parsed : fallback;
}

static int registration_text_present(const char *value)
{
    if (value == NULL) return 0;
    while (*value != '\0') if (!isspace((unsigned char)*value++)) return 1;
    return 0;
}

static int registration_no_newline(const char *value)
{
    return value != NULL && strchr(value, '\r') == NULL && strchr(value, '\n') == NULL;
}

static char *registration_trim(char *value)
{
    if (value == NULL) return NULL;
    while (isspace((unsigned char)*value)) ++value;
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    *end = '\0';
    return value;
}

static void registration_error(char *error, size_t error_len, const char *message)
{
    if (error != NULL && error_len > 0U) snprintf(error, error_len, "%s", message);
}

void st_registration_set_handlers(st_registration_turnstile_handler turnstile,
                                  st_registration_email_handler email,
                                  void *ctx)
{
    pthread_mutex_lock(&registration_handlers_lock);
    registration_handlers.turnstile = turnstile;
    registration_handlers.email = email;
    registration_handlers.ctx = ctx;
    pthread_mutex_unlock(&registration_handlers_lock);
}

static st_registration_handlers registration_get_handlers(void)
{
    pthread_mutex_lock(&registration_handlers_lock);
    st_registration_handlers copy = registration_handlers;
    pthread_mutex_unlock(&registration_handlers_lock);
    return copy;
}

static int registration_allowed_hostnames_configured(void)
{
    const char *allowed = getenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES");
    if (!registration_text_present(allowed)) return 0;
    char *copy = strdup(allowed);
    if (copy == NULL) return 0;
    int configured = 0;
    char *save = NULL;
    for (char *item = strtok_r(copy, ",", &save); item != NULL; item = strtok_r(NULL, ",", &save)) {
        if (*registration_trim(item) != '\0') {
            configured = 1;
            break;
        }
    }
    free(copy);
    return configured;
}

static int registration_email_format(const char *email)
{
    if (email == NULL || *email == '\0' || strlen(email) > 254U
        || strchr(email, ' ') != NULL || strchr(email, '\t') != NULL
        || strchr(email, '\r') != NULL || strchr(email, '\n') != NULL) return 0;
    const char *at = strrchr(email, '@');
    if (at == NULL || at == email || at[1] == '\0' || strchr(at + 1, '.') == NULL
        || at[strlen(at) - 1U] == '.') return 0;
    return strchr(email, '<') == NULL && strchr(email, '>') == NULL && strchr(email, ',') == NULL;
}

static int registration_smtp_configured(void)
{
    const char *host = getenv("SPECUS_AUTH_SMTP_HOST");
    const char *from = getenv("SPECUS_AUTH_EMAIL_FROM_ADDRESS");
    return registration_text_present(host) && registration_email_format(from)
        && registration_env_i64("SPECUS_AUTH_SMTP_PORT", 587, 1, 65535) > 0;
}

int st_registration_available(void)
{
    return registration_env_bool("SPECUS_AUTH_REGISTRATION_ENABLED", 1)
        && registration_env_bool("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", 1)
        && registration_text_present(getenv("SPECUS_AUTH_PASSWORD"))
        && registration_env_bool("SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED", 0)
        && registration_smtp_configured()
        && st_auth_turnstile_available();
}

int st_auth_turnstile_available(void)
{
    return registration_env_bool("SPECUS_AUTH_TURNSTILE_ENABLED", 0)
        && registration_text_present(getenv("SPECUS_AUTH_TURNSTILE_SITE_KEY"))
        && registration_text_present(getenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY"))
        && registration_text_present(getenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL"))
        && registration_allowed_hostnames_configured();
}

static char *registration_form_encode(const char *value)
{
    size_t len = strlen(value);
    char *out = malloc(len * 3U + 1U);
    if (out == NULL) return NULL;
    static const char hex[] = "0123456789ABCDEF";
    size_t w = 0U;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.' || *p == '~') out[w++] = (char)*p;
        else {
            out[w++] = '%';
            out[w++] = hex[*p >> 4U];
            out[w++] = hex[*p & 0x0fU];
        }
    }
    out[w] = '\0';
    return out;
}

static void registration_normalize_hostname(char *hostname)
{
    char *trimmed = registration_trim(hostname);
    if (trimmed != hostname) memmove(hostname, trimmed, strlen(trimmed) + 1U);
    for (char *p = hostname; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
    size_t len = strlen(hostname);
    if (len > 0U && hostname[len - 1U] == '.') hostname[len - 1U] = '\0';
}

static int registration_hostname_allowed(char *hostname)
{
    registration_normalize_hostname(hostname);
    const char *allowed = getenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES");
    char *copy = allowed == NULL ? NULL : strdup(allowed);
    if (copy == NULL) return 0;
    int matched = 0;
    char *save = NULL;
    for (char *item = strtok_r(copy, ",", &save); item != NULL; item = strtok_r(NULL, ",", &save)) {
        registration_normalize_hostname(item);
        if (*hostname != '\0' && strcmp(hostname, item) == 0) {
            matched = 1;
            break;
        }
    }
    free(copy);
    return matched;
}

static int registration_verify_turnstile(const char *token, const char *expected_action)
{
    st_registration_handlers handlers = registration_get_handlers();
    if (handlers.turnstile != NULL) return handlers.turnstile(handlers.ctx, token, expected_action);
    if (!registration_text_present(token)) return -1;
    char *secret = registration_form_encode(getenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY"));
    char *response = registration_form_encode(registration_trim((char *)token));
    if (secret == NULL || response == NULL) {
        free(secret); free(response);
        return -2;
    }
    size_t form_len = strlen(secret) + strlen(response) + 18U;
    char *form = malloc(form_len);
    if (form == NULL) {
        free(secret); free(response);
        return -2;
    }
    snprintf(form, form_len, "secret=%s&response=%s", secret, response);
    free(secret); free(response);
    st_http_client_options options = {.timeout_ms = 8000L, .max_response_bytes = 65536U};
    long status = 0L;
    char *response_body = NULL;
    int rc = st_http_post_form(getenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL"), NULL, form,
                               &options, &status, &response_body);
    free(form);
    if (rc != 0 || status / 100L != 2L || response_body == NULL) {
        free(response_body);
        return -2;
    }
    int success = 0;
    char *action = st_json_get_string(response_body, "action");
    char *hostname = st_json_get_string(response_body, "hostname");
    int accepted = st_json_get_bool(response_body, "success", &success) == 0 && success
        && action != NULL && strcmp(action, expected_action) == 0
        && hostname != NULL && registration_hostname_allowed(hostname);
    free(action); free(hostname); free(response_body);
    return accepted ? 0 : -1;
}

int st_auth_turnstile_verify(const char *response_token,
                             const char *expected_action,
                             int *http_status,
                             char *error,
                             size_t error_len)
{
    if (!registration_env_bool("SPECUS_AUTH_TURNSTILE_ENABLED", 0)) return 0;
    if (!st_auth_turnstile_available()) {
        if (http_status != NULL) *http_status = 503;
        registration_error(error, error_len, "Turnstile 未正确配置");
        return -1;
    }
    int rc = registration_verify_turnstile(response_token, expected_action);
    if (rc == 0) return 0;
    if (http_status != NULL) *http_status = rc == -1 ? 400 : 503;
    registration_error(error, error_len,
                       rc == -1 ? "人机验证失败，请重试" : "人机验证服务暂不可用");
    return -1;
}

static size_t registration_mail_read(char *buffer, size_t size, size_t count, void *ctx)
{
    st_registration_mail_upload *upload = ctx;
    if (size != 0U && count > SIZE_MAX / size) return CURL_READFUNC_ABORT;
    size_t capacity = size * count;
    size_t remaining = upload->len - upload->offset;
    size_t copied = remaining < capacity ? remaining : capacity;
    if (copied > 0U) memcpy(buffer, upload->data + upload->offset, copied);
    upload->offset += copied;
    return copied;
}

static int registration_send_smtp(const char *email,
                                  const char *username,
                                  const char *code,
                                  long long ttl_seconds)
{
    st_registration_handlers handlers = registration_get_handlers();
    if (handlers.email != NULL) return handlers.email(handlers.ctx, email, username, code, ttl_seconds);
    (void)pthread_once(&registration_curl_once, registration_initialize_curl);
    if (registration_curl_init != CURLE_OK) return -1;
    const char *host = getenv("SPECUS_AUTH_SMTP_HOST");
    long long port = registration_env_i64("SPECUS_AUTH_SMTP_PORT", 587, 1, 65535);
    int implicit_ssl = registration_env_bool("SPECUS_AUTH_SMTP_SSL", 0);
    char endpoint[512];
    int endpoint_len = snprintf(endpoint, sizeof(endpoint), "%s://%s:%lld",
                                implicit_ssl ? "smtps" : "smtp", host, port);
    if (endpoint_len <= 0 || (size_t)endpoint_len >= sizeof(endpoint)) return -1;
    const char *from = getenv("SPECUS_AUTH_EMAIL_FROM_ADDRESS");
    const char *from_name = getenv("SPECUS_AUTH_EMAIL_FROM_NAME");
    if (!registration_text_present(from_name)) from_name = "specus";
    const char *subject = getenv("SPECUS_AUTH_EMAIL_SUBJECT");
    if (!registration_text_present(subject)) subject = "specus registration verification code";
    if (!registration_no_newline(from_name) || !registration_no_newline(subject)) return -1;
    long long minutes = (ttl_seconds + 59LL) / 60LL;
    char message[4096];
    int message_len = snprintf(message, sizeof(message),
        "From: %s <%s>\r\nTo: <%s>\r\nSubject: %s\r\nMIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n"
        "Hello, %s.\r\n\r\nYour specus registration verification code is: %s\r\n\r\n"
        "The code is valid for %lld minute(s). Do not share it.\r\n",
        from_name, from, email, subject, username, code, minutes < 1 ? 1 : minutes);
    if (message_len <= 0 || (size_t)message_len >= sizeof(message)) return -1;
    CURL *curl = curl_easy_init();
    if (curl == NULL) return -1;
    struct curl_slist *recipients = NULL;
    recipients = curl_slist_append(recipients, email);
    st_registration_mail_upload upload = {.data = message, .len = (size_t)message_len};
    CURLcode rc = recipients == NULL ? CURLE_OUT_OF_MEMORY : CURLE_OK;
#define REGISTRATION_CURL_SET(option, value) \
    do { if (rc == CURLE_OK) rc = curl_easy_setopt(curl, (option), (value)); } while (0)
    REGISTRATION_CURL_SET(CURLOPT_URL, endpoint);
    REGISTRATION_CURL_SET(CURLOPT_MAIL_FROM, from);
    REGISTRATION_CURL_SET(CURLOPT_MAIL_RCPT, recipients);
    REGISTRATION_CURL_SET(CURLOPT_UPLOAD, 1L);
    REGISTRATION_CURL_SET(CURLOPT_READFUNCTION, registration_mail_read);
    REGISTRATION_CURL_SET(CURLOPT_READDATA, &upload);
    REGISTRATION_CURL_SET(CURLOPT_INFILESIZE_LARGE, (curl_off_t)upload.len);
    REGISTRATION_CURL_SET(CURLOPT_CONNECTTIMEOUT_MS, 8000L);
    REGISTRATION_CURL_SET(CURLOPT_TIMEOUT_MS, 15000L);
    REGISTRATION_CURL_SET(CURLOPT_NOSIGNAL, 1L);
    REGISTRATION_CURL_SET(CURLOPT_SSL_VERIFYPEER, 1L);
    REGISTRATION_CURL_SET(CURLOPT_SSL_VERIFYHOST, 2L);
    if (!implicit_ssl) {
        int starttls = registration_env_bool("SPECUS_AUTH_SMTP_STARTTLS", 1);
        int required = registration_env_bool("SPECUS_AUTH_SMTP_STARTTLS_REQUIRED", 1);
        REGISTRATION_CURL_SET(CURLOPT_USE_SSL,
            required ? (long)CURLUSESSL_ALL : (starttls ? (long)CURLUSESSL_TRY : (long)CURLUSESSL_NONE));
    }
    const char *smtp_username = getenv("SPECUS_AUTH_SMTP_USERNAME");
    if (registration_text_present(smtp_username)) {
        REGISTRATION_CURL_SET(CURLOPT_USERNAME, smtp_username);
        REGISTRATION_CURL_SET(CURLOPT_PASSWORD,
                              getenv("SPECUS_AUTH_SMTP_PASSWORD") == NULL ? "" : getenv("SPECUS_AUTH_SMTP_PASSWORD"));
    }
#undef REGISTRATION_CURL_SET
    if (rc == CURLE_OK) rc = curl_easy_perform(curl);
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK ? 0 : -1;
}

static int registration_random_id(char out[65])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint8_t random[24];
    if (RAND_bytes(random, sizeof(random)) != 1) return -1;
    size_t r = 0U, w = 0U;
    while (r < sizeof(random)) {
        uint32_t value = ((uint32_t)random[r] << 16U) | ((uint32_t)random[r + 1U] << 8U)
            | random[r + 2U];
        out[w++] = alphabet[(value >> 18U) & 0x3fU];
        out[w++] = alphabet[(value >> 12U) & 0x3fU];
        out[w++] = alphabet[(value >> 6U) & 0x3fU];
        out[w++] = alphabet[value & 0x3fU];
        r += 3U;
    }
    out[w] = '\0';
    return 0;
}

static int registration_random_code(char out[7])
{
    uint32_t value = 0U;
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % 1000000U);
    do {
        if (RAND_bytes((unsigned char *)&value, sizeof(value)) != 1) return -1;
    } while (value >= limit);
    snprintf(out, 7U, "%06u", value % 1000000U);
    return 0;
}

static int registration_format_time(time_t value, char out[64])
{
    struct tm utc;
    if (gmtime_r(&value, &utc) == NULL) return -1;
    return strftime(out, 64U, "%Y-%m-%dT%H:%M:%SZ", &utc) > 0U ? 0 : -1;
}

static time_t registration_parse_time(const char *value)
{
    struct tm utc;
    memset(&utc, 0, sizeof(utc));
    char *end = strptime(value, "%Y-%m-%dT%H:%M:%SZ", &utc);
    return end != NULL && *end == '\0' ? timegm(&utc) : (time_t)-1;
}

static int registration_normalize_username(char *username)
{
    char *trimmed = registration_trim(username);
    if (trimmed == NULL || *trimmed == '\0' || strlen(trimmed) > 80U) return -1;
    if (trimmed != username) memmove(username, trimmed, strlen(trimmed) + 1U);
    return 0;
}

static int registration_normalize_email(char *email)
{
    char *trimmed = registration_trim(email);
    if (trimmed == NULL || !registration_email_format(trimmed)) return -1;
    if (trimmed != email) memmove(email, trimmed, strlen(trimmed) + 1U);
    for (char *p = email; *p != '\0'; ++p) *p = (char)tolower((unsigned char)*p);
    return 0;
}

static int registration_code_valid(const char *code)
{
    if (code == NULL || strlen(code) != 6U) return 0;
    for (const unsigned char *p = (const unsigned char *)code; *p != '\0'; ++p) if (!isdigit(*p)) return 0;
    return 1;
}

int st_registration_request(const char *database_path,
                            const char *json_body,
                            st_registration_challenge_response *response,
                            int *http_status,
                            char *error,
                            size_t error_len)
{
    if (http_status != NULL) *http_status = 400;
    if (!st_registration_available()) {
        if (http_status != NULL) *http_status = 403;
        registration_error(error, error_len, "当前未开放注册");
        return -1;
    }
    if (json_body == NULL || !st_json_is_valid_object(json_body)) {
        registration_error(error, error_len, "请求体无效");
        return -1;
    }
    char *username = st_json_get_string(json_body, "username");
    char *email = st_json_get_string(json_body, "email");
    char *password = st_json_get_string(json_body, "password");
    char *turnstile = st_json_get_string(json_body, "turnstileToken");
    char *password_value = registration_trim(password);
    int rc = -1;
    if (registration_normalize_username(username) != 0) registration_error(error, error_len, "username cannot be blank");
    else if (strcasecmp(username, getenv("SPECUS_AUTH_USERNAME") == NULL ? "admin" : getenv("SPECUS_AUTH_USERNAME")) == 0)
        registration_error(error, error_len, "该用户名不可用");
    else if (registration_normalize_email(email) != 0) registration_error(error, error_len, "邮箱格式无效");
    else if (password_value == NULL || *password_value == '\0' || strlen(password_value) > 120U)
        registration_error(error, error_len, "password cannot be blank");
    else {
        int turnstile_result = registration_verify_turnstile(turnstile, "register");
        if (turnstile_result == -1) registration_error(error, error_len, "人机验证失败，请重试");
        else if (turnstile_result != 0) {
            if (http_status != NULL) *http_status = 503;
            registration_error(error, error_len, "人机验证服务暂不可用");
        } else rc = 0;
    }
    free(turnstile);
    if (rc != 0) {
        free(username); free(email); free(password);
        return -1;
    }
    if (database_path == NULL || st_storage_init(database_path, 0) != 0) {
        if (http_status != NULL) *http_status = 500;
        registration_error(error, error_len, "注册数据库不可用");
        free(username); free(email); free(password);
        return -1;
    }
    st_storage_management_user existing_user;
    int email_exists = st_storage_management_email_exists(database_path, email);
    if (st_storage_get_management_user(database_path, username, &existing_user) == 0) {
        registration_error(error, error_len, "用户名已存在");
        goto fail;
    }
    if (email_exists != 0) {
        if (email_exists < 0 && http_status != NULL) *http_status = 500;
        registration_error(error, error_len, email_exists > 0 ? "该邮箱已注册" : "注册数据库不可用");
        goto fail;
    }
    time_t now = time(NULL);
    char now_text[64];
    if (now == (time_t)-1 || registration_format_time(now, now_text) != 0
        || st_storage_delete_expired_registration_challenges(database_path, now_text) != 0) {
        if (http_status != NULL) *http_status = 500;
        registration_error(error, error_len, "注册验证创建失败");
        goto fail;
    }
    st_storage_registration_challenge existing;
    if (st_storage_find_registration_challenge(database_path, username, email, &existing) == 0) {
        if (strcasecmp(existing.username, username) != 0 || strcasecmp(existing.email, email) != 0) {
            registration_error(error, error_len, "用户名或邮箱正在等待验证");
            goto fail;
        }
        time_t resend_at = registration_parse_time(existing.resend_available_at);
        if (resend_at > now) {
            if (http_status != NULL) *http_status = 429;
            long long wait = (long long)(resend_at - now);
            char message[128];
            snprintf(message, sizeof(message), "请在 %lld 秒后重新发送验证码", wait < 1 ? 1 : wait);
            registration_error(error, error_len, message);
            goto fail;
        }
        if (st_storage_delete_registration_challenge(database_path, existing.registration_id) != 0) {
            if (http_status != NULL) *http_status = 500;
            registration_error(error, error_len, "注册验证创建失败");
            goto fail;
        }
    }
    long long ttl = registration_env_i64("SPECUS_AUTH_EMAIL_CODE_TTL_SECONDS", 600, 60, 86400);
    long long cooldown = registration_env_i64("SPECUS_AUTH_EMAIL_RESEND_COOLDOWN_SECONDS", 60, 1, 86400);
    st_storage_registration_challenge challenge;
    memset(&challenge, 0, sizeof(challenge));
    char code[7];
    if (registration_random_id(challenge.registration_id) != 0 || registration_random_code(code) != 0
        || st_password_hash(password_value, challenge.password_hash) != 0
        || st_security_registration_code_hash(challenge.registration_id, code, challenge.code_hash) != 0
        || registration_format_time(now, challenge.created_at) != 0
        || registration_format_time(now + (time_t)ttl, challenge.expires_at) != 0
        || registration_format_time(now + (time_t)cooldown, challenge.resend_available_at) != 0) {
        if (http_status != NULL) *http_status = 500;
        registration_error(error, error_len, "注册验证创建失败");
        goto fail;
    }
    snprintf(challenge.updated_at, sizeof(challenge.updated_at), "%s", challenge.created_at);
    snprintf(challenge.username, sizeof(challenge.username), "%s", username);
    snprintf(challenge.email, sizeof(challenge.email), "%s", email);
    challenge.attempts_remaining = (int)registration_env_i64("SPECUS_AUTH_EMAIL_MAX_ATTEMPTS", 5, 1, 100);
    if (st_storage_create_registration_challenge(database_path, &challenge) != 0) {
        registration_error(error, error_len, "用户名或邮箱正在等待验证");
        goto fail;
    }
    if (registration_send_smtp(email, username, code, ttl) != 0) {
        (void)st_storage_delete_registration_challenge(database_path, challenge.registration_id);
        if (http_status != NULL) *http_status = 503;
        registration_error(error, error_len, "验证码邮件发送失败，请稍后重试");
        goto fail;
    }
    memset(response, 0, sizeof(*response));
    snprintf(response->registration_id, sizeof(response->registration_id), "%s", challenge.registration_id);
    const char *at = strchr(email, '@');
    size_t visible = (size_t)(at - email) <= 2U ? 1U : 2U;
    snprintf(response->email_masked, sizeof(response->email_masked), "%.*s***%s",
             (int)visible, email, at);
    snprintf(response->expires_at, sizeof(response->expires_at), "%s", challenge.expires_at);
    response->resend_after_seconds = cooldown;
    if (http_status != NULL) *http_status = 202;
    free(username); free(email); free(password);
    return 0;
fail:
    free(username); free(email); free(password);
    return -1;
}

int st_registration_verify(const char *database_path,
                           const char *json_body,
                           st_storage_management_user *user,
                           int *http_status,
                           char *error,
                           size_t error_len)
{
    if (http_status != NULL) *http_status = 400;
    if (json_body == NULL || !st_json_is_valid_object(json_body)) {
        registration_error(error, error_len, "请求体无效");
        return -1;
    }
    if (!st_registration_available()) {
        if (http_status != NULL) *http_status = 403;
        registration_error(error, error_len, "当前未开放邮箱验证注册");
        return -1;
    }
    char *registration_id = st_json_get_string(json_body, "registrationId");
    char *code = st_json_get_string(json_body, "code");
    char *id_trimmed = registration_trim(registration_id);
    char *code_trimmed = registration_trim(code);
    if (id_trimmed == NULL || *id_trimmed == '\0' || strlen(id_trimmed) > 64U
        || !registration_code_valid(code_trimmed)) {
        registration_error(error, error_len, "验证码无效或已过期");
        free(registration_id); free(code);
        return -1;
    }
    st_storage_registration_challenge challenge;
    if (database_path == NULL
        || st_storage_get_registration_challenge(database_path, id_trimmed, &challenge) != 0) {
        registration_error(error, error_len, "验证码无效或已过期");
        free(registration_id); free(code);
        return -1;
    }
    time_t now = time(NULL);
    time_t expires = registration_parse_time(challenge.expires_at);
    char now_text[64];
    if (now == (time_t)-1 || registration_format_time(now, now_text) != 0
        || expires == (time_t)-1 || expires <= now || challenge.attempts_remaining <= 0) {
        (void)st_storage_delete_registration_challenge(database_path, challenge.registration_id);
        registration_error(error, error_len, "验证码无效或已过期");
        free(registration_id); free(code);
        return -1;
    }
    char actual_hash[65];
    if (st_security_registration_code_hash(challenge.registration_id, code_trimmed, actual_hash) != 0
        || !st_constant_time_eq((const uint8_t *)challenge.code_hash,
                                (const uint8_t *)actual_hash, 64U)) {
        --challenge.attempts_remaining;
        if (challenge.attempts_remaining <= 0)
            (void)st_storage_delete_registration_challenge(database_path, challenge.registration_id);
        else
            (void)st_storage_update_registration_attempts(database_path, challenge.registration_id,
                                                          challenge.attempts_remaining, now_text);
        registration_error(error, error_len, "验证码无效或已过期");
        free(registration_id); free(code);
        return -1;
    }
    st_storage_management_user existing;
    int email_exists = st_storage_management_email_exists(database_path, challenge.email);
    if (email_exists < 0) {
        if (http_status != NULL) *http_status = 500;
        registration_error(error, error_len, "注册数据库不可用");
        free(registration_id); free(code);
        return -1;
    }
    if (st_storage_get_management_user(database_path, challenge.username, &existing) == 0
        || email_exists > 0) {
        registration_error(error, error_len, email_exists > 0 ? "该邮箱已注册" : "用户名已存在");
        free(registration_id); free(code);
        return -1;
    }
    snprintf(challenge.updated_at, sizeof(challenge.updated_at), "%s", now_text);
    const char *tenant = getenv("SPECUS_AUTH_TENANT_ID");
    if (st_storage_complete_registration(database_path, &challenge,
                                         tenant == NULL ? "default" : tenant, user) != 0) {
        registration_error(error, error_len, "用户名或邮箱已被注册");
        free(registration_id); free(code);
        return -1;
    }
    if (http_status != NULL) *http_status = 200;
    free(registration_id); free(code);
    return 0;
}
