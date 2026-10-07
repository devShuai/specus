#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "client_auth_nonce.h"
#include "client_package.h"
#include "crypto.h"
#include "json.h"
#include "login_rate_limiter.h"
#include "public_discovery.h"
#include "public_room.h"
#include "registration.h"
#include "security.h"
#include "storage.h"

#include <arpa/inet.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <zlib.h>

static long long test_now_millis(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

static void sign_client_auth(const char *api_key,
                             const char *timestamp,
                             const char *nonce,
                             const char *machine_fingerprint,
                             const char *os_user,
                             const char *secret,
                             char signature_hex[ST_SHA256_HEX_LEN + 1])
{
    uint8_t key[ST_SHA256_LEN];
    uint8_t signature[ST_SHA256_LEN];
    char message[512];
    int message_len = snprintf(message,
                               sizeof(message),
                               "%s\n%s\n%s\n%s\n%s",
                               api_key,
                               timestamp,
                               nonce,
                               machine_fingerprint,
                               os_user);
    st_sha256((const uint8_t *)secret, strlen(secret), key);
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)message, (size_t)message_len, signature);
    st_hex_encode(signature, sizeof(signature), signature_hex);
}

static int contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

/* Logs a stored management user in and returns "Bearer <token>" in authorization. */
static int management_login(const char *username, const char *password, char *authorization, size_t len)
{
    static char response[65536];
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", username, password);
    int written = st_admin_build_response_with_body("POST", "/auth/login", body, response, sizeof(response));
    char *token = written > 0 && contains(response, "200 OK") ? st_json_get_string(response, "accessToken") : NULL;
    if (token == NULL) {
        fprintf(stderr, "management login for %s failed: %s\n", username, response);
        return -1;
    }
    snprintf(authorization, len, "Bearer %s", token);
    free(token);
    return 0;
}

static int expect_with_token(const char *what, const char *method, const char *path,
                             const char *authorization, const char *status, const char *needle)
{
    static char response[65536];
    int len = st_admin_build_response_with_auth(method, path, authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, status) || (needle != NULL && !contains(response, needle))) {
        fprintf(stderr, "%s: expected %s%s%s, got: %.300s\n", what, status,
                needle == NULL ? "" : " with ", needle == NULL ? "" : needle, response);
        return 1;
    }
    return 0;
}

static int update_management_user(const char *username, const char *body)
{
    static char response[65536];
    char path[128];
    snprintf(path, sizeof(path), "/api/admin/users/%s", username);
    int len = body == NULL
        ? st_admin_build_response("DELETE", path, response, sizeof(response))
        : st_admin_build_response_with_body("PUT", path, body, response, sizeof(response));
    if (len <= 0 || (!contains(response, "200 OK") && !contains(response, "204 No Content"))) {
        fprintf(stderr, "management user change for %s failed: %s\n", username, response);
        return 1;
    }
    return 0;
}

/*
 * A management token names an account; it does not freeze the account's rights. Like Java's
 * ManagementContextResolver every request and every refresh re-reads the user: a disabled or
 * deleted user is refused at once (403 on requests, 401 on refresh, with Java's bodies), and a
 * demoted admin loses the admin endpoints on its next request and is refreshed as USER.
 * Expects SPECUS_DATABASE_PATH to be set.
 */
static int test_management_token_follows_user_record(void)
{
    static char response[65536];
    const char *gone = "{\"error\":\"账号未绑定、已禁用或权限已撤销\"}";
    const char *refresh_gone = "{\"error\":\"账号已禁用、不存在或不再允许本地登录\"}";
    if (st_admin_build_response_with_body("POST", "/api/admin/users",
            "{\"username\":\"dora\",\"password\":\"dora-secret\",\"role\":\"ADMIN\",\"enabled\":true}",
            response, sizeof(response)) <= 0 || !contains(response, "201 Created")
        || st_admin_build_response_with_body("POST", "/api/admin/users",
            "{\"username\":\"evan\",\"password\":\"evan-secret\",\"role\":\"USER\",\"enabled\":true}",
            response, sizeof(response)) <= 0 || !contains(response, "201 Created")) {
        fprintf(stderr, "management token test users could not be created: %s\n", response);
        return 1;
    }
    char dora[2300];
    char evan[2300];
    if (management_login("dora", "dora-secret", dora, sizeof(dora)) != 0
        || management_login("evan", "evan-secret", evan, sizeof(evan)) != 0
        || expect_with_token("admin before demotion", "GET", "/api/admin/users", dora, "200 OK", NULL)
        || expect_with_token("user before disable", "GET", "/api/admin/me", evan, "200 OK", "\"admin\":false")) {
        return 1;
    }

    /* Demoted: the old ADMIN token loses the admin endpoints, and refresh issues a USER token. */
    if (update_management_user("dora", "{\"role\":\"USER\"}")
        || expect_with_token("demoted admin, admin endpoint", "GET", "/api/admin/users", dora,
                             "403 Forbidden", "需要 admin 权限")
        || expect_with_token("demoted admin, me", "GET", "/api/admin/me", dora, "200 OK", "\"admin\":false")) {
        return 1;
    }
    int len = st_admin_build_response_with_auth("POST", "/auth/refresh", dora, NULL, response, sizeof(response));
    char *refreshed = len > 0 && contains(response, "200 OK") ? st_json_get_string(response, "accessToken") : NULL;
    st_security_token_claims claims;
    int refreshed_as_user = refreshed != NULL
        && st_security_validate_local_token(refreshed, getenv("SPECUS_AUTH_JWT_SECRET"),
                                            "default", "admin-user", &claims) == 0
        && strcmp(claims.role, "USER") == 0;
    free(refreshed);
    if (!refreshed_as_user) {
        fprintf(stderr, "demoted admin was not refreshed as USER: %.300s\n", response);
        return 1;
    }

    /* Disabled: every request is refused, and so is refresh. */
    if (update_management_user("evan", "{\"enabled\":false}")
        || expect_with_token("disabled user, me", "GET", "/api/admin/me", evan, "403 Forbidden", gone)
        || expect_with_token("disabled user, clients", "GET", "/api/admin/clients", evan, "403 Forbidden", gone)
        || expect_with_token("disabled user, refresh", "POST", "/auth/refresh", evan, "401 Unauthorized",
                             refresh_gone)) {
        return 1;
    }
    /* Re-enabled, the same token works again: nothing about the account was frozen into it. */
    if (update_management_user("evan", "{\"enabled\":true}")
        || expect_with_token("re-enabled user", "GET", "/api/admin/me", evan, "200 OK", "\"username\":\"evan\"")) {
        return 1;
    }

    /* Deleted: refused, refresh included. */
    if (update_management_user("dora", NULL)
        || update_management_user("evan", NULL)
        || expect_with_token("deleted user, me", "GET", "/api/admin/me", dora, "403 Forbidden", gone)
        || expect_with_token("deleted user, refresh", "POST", "/auth/refresh", dora, "401 Unauthorized",
                             refresh_gone)
        || expect_with_token("deleted user, me", "GET", "/api/admin/me", evan, "403 Forbidden", gone)) {
        return 1;
    }

    /* A token that names a user the server never had, signed with the server's key. */
    char token[2048];
    char ghost[2300];
    if (st_security_issue_local_token("ghost", "tenant-admin", "ADMIN", getenv("SPECUS_AUTH_JWT_SECRET"),
                                      600, token, sizeof(token)) != 0) {
        return 1;
    }
    snprintf(ghost, sizeof(ghost), "Bearer %s", token);
    if (expect_with_token("unknown user with an ADMIN claim", "GET", "/api/admin/users", ghost,
                          "403 Forbidden", gone)) {
        return 1;
    }

    /* The built-in admin keeps its rights only while it may still sign in with its password. */
    char builtin[2300];
    if (st_security_issue_local_token("admin-user", "tenant-admin", "ADMIN", getenv("SPECUS_AUTH_JWT_SECRET"),
                                      600, token, sizeof(token)) != 0) {
        return 1;
    }
    snprintf(builtin, sizeof(builtin), "Bearer %s", token);
    char *saved_password = getenv("SPECUS_AUTH_PASSWORD") == NULL ? NULL : strdup(getenv("SPECUS_AUTH_PASSWORD"));
    setenv("SPECUS_AUTH_PASSWORD", "builtin-admin-password", 1);
    int failed = expect_with_token("built-in admin", "GET", "/api/admin/users", builtin, "200 OK", NULL);
    setenv("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", "false", 1);
    failed = failed
        || expect_with_token("built-in admin, password login off", "GET", "/api/admin/users", builtin,
                             "403 Forbidden", gone)
        || expect_with_token("built-in admin, password login off, refresh", "POST", "/auth/refresh", builtin,
                             "401 Unauthorized", refresh_gone);
    unsetenv("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED");
    if (saved_password == NULL) {
        unsetenv("SPECUS_AUTH_PASSWORD");
    } else {
        setenv("SPECUS_AUTH_PASSWORD", saved_password, 1);
        free(saved_password);
    }
    return failed;
}

/*
 * nettyTls in the login response follows the control listener's TLS settings the way Java and Go
 * derive it (protocol/spec/client-auth.md): any TLS mode, or TLS terminated by a trusted upstream.
 * Without it clients with controlTls.enabled unset connect in plaintext to a TLS listener.
 */
static int test_client_auth_netty_tls(void)
{
    static const struct {
        const char *mode;
        const char *terminated_upstream;
        const char *expected;
    } cases[] = {
        {NULL, NULL, "\"nettyTls\":false"},
        {"disabled", "false", "\"nettyTls\":false"},
        {"file", NULL, "\"nettyTls\":true"},
        {"self-signed", NULL, "\"nettyTls\":true"},
        {" SELF_SIGNED ", NULL, "\"nettyTls\":true"},
        {NULL, "true", "\"nettyTls\":true"},
    };
    static char response[65536];
    setenv("SPECUS_CLIENT_ACCESS_TOKEN", "tls-runtime-token", 1);
    int failed = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]) && !failed; ++i) {
        if (cases[i].mode == NULL) {
            unsetenv("SPECUS_TLS_MODE");
        } else {
            setenv("SPECUS_TLS_MODE", cases[i].mode, 1);
        }
        if (cases[i].terminated_upstream == NULL) {
            unsetenv("SPECUS_TLS_TERMINATED_UPSTREAM");
        } else {
            setenv("SPECUS_TLS_TERMINATED_UPSTREAM", cases[i].terminated_upstream, 1);
        }
        int len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
        if (len <= 0 || !contains(response, "200 OK") || !contains(response, cases[i].expected)
            || !contains(response, "\"nettyPort\":7010,\"nettyTls\":")) {
            fprintf(stderr, "client auth nettyTls mismatch for mode=%s terminatedUpstream=%s: %s\n",
                    cases[i].mode == NULL ? "(unset)" : cases[i].mode,
                    cases[i].terminated_upstream == NULL ? "(unset)" : cases[i].terminated_upstream,
                    response);
            failed = 1;
        }
    }
    unsetenv("SPECUS_TLS_MODE");
    unsetenv("SPECUS_TLS_TERMINATED_UPSTREAM");
    unsetenv("SPECUS_CLIENT_ACCESS_TOKEN");
    return failed;
}

static long long nat_control_expected_client_id = 0;
static int nat_control_push_calls = 0;
static long long runtime_status_expected_client_id = 0;
static char runtime_status_expected_client_name[256];
static int client_message_push_calls = 0;
static int peer_mesh_refresh_calls = 0;
static pthread_mutex_t client_message_block_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t client_message_block_cond = PTHREAD_COND_INITIALIZER;
static int client_message_block_started = 0;
static int client_message_block_release = 0;

typedef struct {
    int turnstile_calls;
    int email_calls;
    char email[255];
    char username[81];
    char code[7];
} test_registration_delivery;

static int test_registration_turnstile(void *ctx,
                                      const char *response_token,
                                      const char *expected_action)
{
    test_registration_delivery *delivery = ctx;
    ++delivery->turnstile_calls;
    if (response_token == NULL || expected_action == NULL) return -1;
    if (strcmp(expected_action, "register") == 0) {
        return strcmp(response_token, "turnstile-ok") == 0 ? 0 : -1;
    }
    if (strcmp(expected_action, "login") == 0) {
        return strcmp(response_token, "login-turnstile-ok") == 0 ? 0 : -1;
    }
    return -1;
}

static int test_registration_email(void *ctx,
                                  const char *email,
                                  const char *username,
                                  const char *code,
                                  long long ttl_seconds)
{
    test_registration_delivery *delivery = ctx;
    ++delivery->email_calls;
    snprintf(delivery->email, sizeof(delivery->email), "%s", email);
    snprintf(delivery->username, sizeof(delivery->username), "%s", username);
    snprintf(delivery->code, sizeof(delivery->code), "%s", code);
    return ttl_seconds >= 60 && strlen(code) == 6U ? 0 : -1;
}

static int test_nat_control_push(void *ctx, long long client_id, const char *client_name)
{
    (void)ctx;
    if (client_id != nat_control_expected_client_id
        || client_name == NULL
        || strcmp(client_name, "C managed") != 0) {
        return -2;
    }
    ++nat_control_push_calls;
    return 0;
}

static int test_peer_mesh_refresh(void *ctx, const char *tenant_id)
{
    (void)ctx;
    if (tenant_id == NULL || strcmp(tenant_id, "tenant-admin") != 0) return -1;
    ++peer_mesh_refresh_calls;
    return 0;
}

static int test_client_runtime_status(void *ctx,
                                      long long client_id,
                                      const char *client_name,
                                      st_admin_client_runtime_status *status)
{
    (void)ctx;
    if (status == NULL) {
        return -1;
    }
    memset(status, 0, sizeof(*status));
    if (client_id == runtime_status_expected_client_id
        && client_name != NULL
        && strcmp(client_name, runtime_status_expected_client_name) == 0) {
        status->online = 1;
        status->connected_since_ms = 1787875200123LL;
    }
    return 0;
}

static int test_client_message_push(void *ctx,
                                    long long client_id,
                                    const char *client_name,
                                    const char *from_admin_name,
                                    const char *message)
{
    (void)ctx;
    if (client_id != runtime_status_expected_client_id
        || client_name == NULL
        || strcmp(client_name, runtime_status_expected_client_name) != 0
        || from_admin_name == NULL
        || strcmp(from_admin_name, "admin:admin") != 0
        || message == NULL
        || (strcmp(message, "hello from admin") != 0
            && strcmp(message, "async block") != 0)) {
        return -2;
    }
    pthread_mutex_lock(&client_message_block_lock);
    if (strcmp(message, "async block") == 0) {
        client_message_block_started = 1;
        pthread_cond_broadcast(&client_message_block_cond);
        while (!client_message_block_release) {
            pthread_cond_wait(&client_message_block_cond, &client_message_block_lock);
        }
    }
    ++client_message_push_calls;
    pthread_mutex_unlock(&client_message_block_lock);
    return 0;
}

static int test_client_message_push_count(void)
{
    pthread_mutex_lock(&client_message_block_lock);
    int count = client_message_push_calls;
    pthread_mutex_unlock(&client_message_block_lock);
    return count;
}

static void test_base64url_no_padding(const uint8_t *data, size_t len, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t written = 0;
    for (size_t i = 0; i < len; i += 3U) {
        uint32_t value = (uint32_t)data[i] << 16;
        size_t remaining = len - i;
        if (remaining > 1U) value |= (uint32_t)data[i + 1U] << 8;
        if (remaining > 2U) value |= data[i + 2U];
        out[written++] = alphabet[(value >> 18) & 63U];
        out[written++] = alphabet[(value >> 12) & 63U];
        if (remaining > 1U) out[written++] = alphabet[(value >> 6) & 63U];
        if (remaining > 2U) out[written++] = alphabet[value & 63U];
    }
    out[written] = '\0';
}

static char *test_dup_string(const char *value)
{
    size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, len + 1U);
    return copy;
}

static uint8_t *test_dup_body(const char *value, size_t *len)
{
    *len = strlen(value);
    uint8_t *copy = (uint8_t *)malloc(*len == 0 ? 1U : *len);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, *len);
    return copy;
}

static uint8_t *test_gzip_body(const uint8_t *value, size_t len, size_t *out_len)
{
    if (value == NULL || out_len == NULL || len > UINT_MAX) {
        return NULL;
    }
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (deflateInit2(&stream,
                     Z_BEST_COMPRESSION,
                     Z_DEFLATED,
                     16 + MAX_WBITS,
                     8,
                     Z_DEFAULT_STRATEGY) != Z_OK) {
        return NULL;
    }
    uLong bound = deflateBound(&stream, (uLong)len);
    uint8_t *out = (uint8_t *)malloc((size_t)bound);
    if (out == NULL) {
        deflateEnd(&stream);
        return NULL;
    }
    stream.next_in = (Bytef *)value;
    stream.avail_in = (uInt)len;
    stream.next_out = out;
    stream.avail_out = (uInt)bound;
    if (deflate(&stream, Z_FINISH) != Z_STREAM_END) {
        free(out);
        deflateEnd(&stream);
        return NULL;
    }
    *out_len = (size_t)stream.total_out;
    deflateEnd(&stream);
    return out;
}

static int test_exec_sql(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite test setup failed: %s\n", error == NULL ? sqlite3_errmsg(db) : error);
        sqlite3_free(error);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;
}

typedef struct {
    pthread_mutex_t lock;
    int http_calls;
    int ws_calls;
    int authorization_headers;
    int normalized_accept_encoding_headers;
    char http_raw_query[256];
    char ws_raw_query[256];
    char http_relative_path[256];
    char ws_relative_path[256];
    char http_body[256];
    /* The Origin, Referer and Sec-Fetch-Site lines the device received, joined with '|'. */
    char http_browser_headers[512];
    char ws_browser_headers[512];
} route_auth_test_context;

#define ROUTE_RESET_REASON \
    "dial http://10.20.30.40:8080/admin/internal?token=s3cret&user=root failed: " \
    "connection refused\r\nX-Forged: yes"

/* Redirects stderr into a temporary file so a test can read what the server logged. */
static int stderr_capture_begin(FILE **capture, int *saved_fd)
{
    fflush(stderr);
    *capture = tmpfile();
    if (*capture == NULL) {
        return -1;
    }
    *saved_fd = dup(STDERR_FILENO);
    if (*saved_fd < 0 || dup2(fileno(*capture), STDERR_FILENO) < 0) {
        if (*saved_fd >= 0) {
            close(*saved_fd);
        }
        fclose(*capture);
        return -1;
    }
    return 0;
}

static void stderr_capture_end(FILE *capture, int saved_fd, char *out, size_t out_len)
{
    fflush(stderr);
    (void)dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);
    rewind(capture);
    size_t read_len = fread(out, 1U, out_len - 1U, capture);
    out[read_len] = '\0';
    fclose(capture);
}

static void route_auth_test_context_reset(route_auth_test_context *context)
{
    pthread_mutex_lock(&context->lock);
    context->http_calls = 0;
    context->ws_calls = 0;
    context->authorization_headers = 0;
    context->normalized_accept_encoding_headers = 0;
    context->http_raw_query[0] = '\0';
    context->ws_raw_query[0] = '\0';
    context->http_relative_path[0] = '\0';
    context->ws_relative_path[0] = '\0';
    context->http_body[0] = '\0';
    context->http_browser_headers[0] = '\0';
    context->ws_browser_headers[0] = '\0';
    pthread_mutex_unlock(&context->lock);
}

static void route_auth_test_capture_browser_headers(char *const *headers,
                                                    size_t headers_len,
                                                    char *out,
                                                    size_t out_len)
{
    size_t used = 0U;
    out[0] = '\0';
    for (size_t i = 0; i < headers_len; ++i) {
        if (headers[i] == NULL
            || (strncasecmp(headers[i], "Origin:", 7U) != 0 && strncasecmp(headers[i], "Referer:", 8U) != 0
                && strncasecmp(headers[i], "Sec-Fetch-Site:", 15U) != 0)) {
            continue;
        }
        int written = snprintf(out + used, out_len - used, "%s%s", used == 0U ? "" : "|", headers[i]);
        if (written < 0 || (size_t)written >= out_len - used) {
            return;
        }
        used += (size_t)written;
    }
}

static int route_auth_test_context_matches(route_auth_test_context *context,
                                           int http_calls,
                                           int ws_calls,
                                           int authorization_headers)
{
    pthread_mutex_lock(&context->lock);
    int matches = context->http_calls == http_calls
        && context->ws_calls == ws_calls
        && context->authorization_headers == authorization_headers;
    pthread_mutex_unlock(&context->lock);
    return matches;
}

static int route_auth_test_has_authorization(char *const *headers, size_t headers_len)
{
    for (size_t i = 0; i < headers_len; ++i) {
        if (headers[i] != NULL && strncmp(headers[i], "Authorization:", 14U) == 0) {
            return 1;
        }
    }
    return 0;
}

static int route_auth_test_has_normalized_accept_encoding(char *const *headers, size_t headers_len)
{
    for (size_t i = 0; i < headers_len; ++i) {
        if (headers[i] != NULL && strcmp(headers[i], "Accept-Encoding:identity") == 0) {
            return 1;
        }
    }
    return 0;
}

static int route_auth_test_queries_match(route_auth_test_context *context,
                                         const char *http_query,
                                         const char *ws_query)
{
    pthread_mutex_lock(&context->lock);
    int matches = strcmp(context->http_raw_query, http_query) == 0
        && strcmp(context->ws_raw_query, ws_query) == 0;
    pthread_mutex_unlock(&context->lock);
    return matches;
}

static int route_auth_test_paths_match(route_auth_test_context *context,
                                       const char *http_path,
                                       const char *ws_path)
{
    pthread_mutex_lock(&context->lock);
    int matches = strcmp(context->http_relative_path, http_path) == 0
        && strcmp(context->ws_relative_path, ws_path) == 0;
    pthread_mutex_unlock(&context->lock);
    return matches;
}

static int route_auth_http_forwarder(void *ctx,
                                     const char *client_name,
                                     const st_direct_http_request *request,
                                     const st_admin_direct_http_sink *sink)
{
    (void)client_name;
    route_auth_test_context *context = (route_auth_test_context *)ctx;
    pthread_mutex_lock(&context->lock);
    ++context->http_calls;
    context->authorization_headers += route_auth_test_has_authorization(request->headers,
                                                                        request->headers_len);
    context->normalized_accept_encoding_headers +=
        route_auth_test_has_normalized_accept_encoding(request->headers, request->headers_len);
    snprintf(context->http_raw_query,
             sizeof(context->http_raw_query),
             "%s",
             request->raw_query == NULL ? "" : request->raw_query);
    snprintf(context->http_relative_path,
             sizeof(context->http_relative_path),
             "%s",
             request->relative_path == NULL ? "" : request->relative_path);
    snprintf(context->http_body,
             sizeof(context->http_body),
             "%.*s",
             request->body_len < sizeof(context->http_body) ? (int)request->body_len : 0,
             request->body == NULL ? "" : (const char *)request->body);
    route_auth_test_capture_browser_headers(request->headers, request->headers_len,
                                            context->http_browser_headers,
                                            sizeof(context->http_browser_headers));
    pthread_mutex_unlock(&context->lock);
    if (request->relative_path != NULL && strcmp(request->relative_path, "/upstream-reset") == 0) {
        /* Plays a client whose upstream is unreachable: RST before any response OPEN. */
        if (sink->on_reset != NULL) {
            sink->on_reset(sink->ctx, 1U, ROUTE_RESET_REASON);
        }
        return ST_ADMIN_DIRECT_HTTP_STREAM_RESET;
    }
    char *headers[] = {"Content-Type: text/plain; charset=UTF-8"};
    static const uint8_t response_body[] = "forwarded";
    return sink->on_headers(sink->ctx, 200, headers, 1U, NULL, 0U) == 0
        && sink->on_data(sink->ctx, response_body, sizeof(response_body) - 1U) == 0
        && sink->on_end(sink->ctx, NULL, 0U) == 0
        ? 0
        : -1;
}

static int route_auth_ws_open(void *ctx, const st_admin_direct_ws_request *request)
{
    route_auth_test_context *context = (route_auth_test_context *)ctx;
    pthread_mutex_lock(&context->lock);
    ++context->ws_calls;
    context->authorization_headers += route_auth_test_has_authorization(request->headers,
                                                                        request->headers_len);
    snprintf(context->ws_raw_query,
             sizeof(context->ws_raw_query),
             "%s",
             request->raw_query == NULL ? "" : request->raw_query);
    snprintf(context->ws_relative_path,
             sizeof(context->ws_relative_path),
             "%s",
             request->relative_path == NULL ? "" : request->relative_path);
    route_auth_test_capture_browser_headers(request->headers, request->headers_len,
                                            context->ws_browser_headers,
                                            sizeof(context->ws_browser_headers));
    pthread_mutex_unlock(&context->lock);
    return -3;
}

static int route_auth_ws_data(void *ctx,
                              const char *channel_id,
                              const uint8_t *payload,
                              size_t payload_len)
{
    (void)ctx;
    (void)channel_id;
    (void)payload;
    (void)payload_len;
    return 0;
}

static void route_auth_ws_close(void *ctx,
                                const char *channel_id,
                                uint32_t reset_code,
                                const char *reason)
{
    (void)ctx;
    (void)channel_id;
    (void)reset_code;
    (void)reason;
}

static int route_auth_http_roundtrip(int port,
                                     const char *request,
                                     char *response,
                                     size_t response_len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    size_t request_len = strlen(request);
    size_t sent = 0;
    while (sent < request_len) {
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
    return received > 0U ? 0 : -1;
}

static int route_auth_start_server(st_admin_server *server,
                                   route_auth_test_context *context,
                                   int *port)
{
    if (st_admin_server_start_with_handlers(server,
                                            0,
                                            "",
                                            route_auth_http_forwarder,
                                            context,
                                            route_auth_ws_open,
                                            route_auth_ws_data,
                                            route_auth_ws_close,
                                            context) != 0) {
        return -1;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(server->fd, (struct sockaddr *)&address, &address_len) != 0) {
        shutdown(server->fd, SHUT_RDWR);
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    *port = ntohs(address.sin_port);
    return 0;
}

static void route_auth_stop_server(st_admin_server *server)
{
    if (server->fd >= 0) {
        (void)shutdown(server->fd, SHUT_RDWR);
        close(server->fd);
        server->fd = -1;
    }
}

static int test_recv_all(int fd, uint8_t *data, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        ssize_t got = recv(fd, data + offset, len - offset, 0);
        if (got <= 0) {
            return -1;
        }
        offset += (size_t)got;
    }
    return 0;
}

static int test_websocket_read_text(int fd, char *out, size_t out_len)
{
    uint8_t header[2];
    if (out_len == 0U || test_recv_all(fd, header, sizeof(header)) != 0
        || (header[0] & 0x0fU) != 0x1U || (header[1] & 0x80U) != 0U) {
        return -1;
    }
    uint64_t payload_len = header[1] & 0x7fU;
    if (payload_len == 126U) {
        uint8_t extended[2];
        if (test_recv_all(fd, extended, sizeof(extended)) != 0) {
            return -1;
        }
        payload_len = ((uint64_t)extended[0] << 8U) | extended[1];
    } else if (payload_len == 127U) {
        return -1;
    }
    if (payload_len >= out_len || test_recv_all(fd, (uint8_t *)out, (size_t)payload_len) != 0) {
        return -1;
    }
    out[payload_len] = '\0';
    return 0;
}

static int test_websocket_send_masked_text(int fd, const char *text)
{
    static const uint8_t mask[4] = {0x19U, 0x83U, 0x42U, 0x71U};
    size_t len = strlen(text);
    if (len > 65535U) {
        return -1;
    }
    uint8_t header[8];
    size_t header_len = 0U;
    header[header_len++] = 0x81U;
    if (len <= 125U) {
        header[header_len++] = 0x80U | (uint8_t)len;
    } else {
        header[header_len++] = 0x80U | 126U;
        header[header_len++] = (uint8_t)(len >> 8U);
        header[header_len++] = (uint8_t)len;
    }
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);
    uint8_t *payload = (uint8_t *)malloc(len == 0U ? 1U : len);
    if (payload == NULL) {
        return -1;
    }
    for (size_t i = 0; i < len; ++i) {
        payload[i] = (uint8_t)text[i] ^ mask[i % 4U];
    }
    int rc = send(fd, header, header_len, 0) == (ssize_t)header_len
        && send(fd, payload, len, 0) == (ssize_t)len
        ? 0 : -1;
    free(payload);
    return rc;
}

static int test_websocket_read_frame(int fd,
                                     uint8_t *opcode,
                                     uint8_t *out,
                                     size_t out_len,
                                     size_t *payload_len_out)
{
    uint8_t header[2];
    if (opcode == NULL || out == NULL || payload_len_out == NULL
        || test_recv_all(fd, header, sizeof(header)) != 0 || (header[1] & 0x80U) != 0U) {
        return -1;
    }
    uint64_t payload_len = header[1] & 0x7fU;
    if (payload_len == 126U) {
        uint8_t extended[2];
        if (test_recv_all(fd, extended, sizeof(extended)) != 0) return -1;
        payload_len = ((uint64_t)extended[0] << 8U) | extended[1];
    } else if (payload_len == 127U) {
        uint8_t extended[8];
        if (test_recv_all(fd, extended, sizeof(extended)) != 0) return -1;
        payload_len = 0U;
        for (size_t i = 0U; i < sizeof(extended); ++i) payload_len = (payload_len << 8U) | extended[i];
    }
    if (payload_len > out_len || test_recv_all(fd, out, (size_t)payload_len) != 0) return -1;
    *opcode = header[0] & 0x0fU;
    *payload_len_out = (size_t)payload_len;
    return 0;
}

static int test_websocket_send_masked_frame(int fd,
                                            uint8_t opcode,
                                            const uint8_t *data,
                                            size_t len)
{
    static const uint8_t mask[4] = {0x31U, 0x27U, 0x55U, 0xa3U};
    if (len > 0U && data == NULL) return -1;
    uint8_t header[16];
    size_t header_len = 0U;
    header[header_len++] = (uint8_t)(0x80U | (opcode & 0x0fU));
    if (len <= 125U) {
        header[header_len++] = (uint8_t)(0x80U | len);
    } else if (len <= 65535U) {
        header[header_len++] = 0x80U | 126U;
        header[header_len++] = (uint8_t)(len >> 8U);
        header[header_len++] = (uint8_t)len;
    } else {
        header[header_len++] = 0x80U | 127U;
        for (int i = 7; i >= 0; --i) {
            header[header_len++] = (uint8_t)(((uint64_t)len >> ((unsigned int)i * 8U)) & 0xffU);
        }
    }
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);
    uint8_t *payload = (uint8_t *)malloc(len == 0U ? 1U : len);
    if (payload == NULL) return -1;
    for (size_t i = 0U; i < len; ++i) payload[i] = data[i] ^ mask[i % 4U];
    int result = send(fd, header, header_len, 0) == (ssize_t)header_len
        && (len == 0U || send(fd, payload, len, 0) == (ssize_t)len)
        ? 0 : -1;
    free(payload);
    return result;
}

static int test_public_ticket(int port,
                              const char *room_id,
                              const char *room_token,
                              const char *peer_id,
                              const char *display_name,
                              const char *public_ip,
                              char **ticket_out)
{
    char body[2048];
    char request[4096];
    char response[4096] = {0};
    int body_len = snprintf(body,
                            sizeof(body),
                            "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"%s\","
                            "\"displayName\":\"%s\"}",
                            room_id,
                            room_token,
                            peer_id,
                            display_name);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) return -1;
    int request_len = snprintf(request,
                               sizeof(request),
                               "POST /api/public/transfer/ws-tickets HTTP/1.1\r\nHost: localhost\r\n"
                               "X-Real-IP: %s\r\nContent-Type: application/json\r\n"
                               "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
                               public_ip,
                               body_len,
                               body);
    if (request_len < 0 || (size_t)request_len >= sizeof(request)
        || route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK") || !contains(response, "Cache-Control: no-store")) {
        return -1;
    }
    *ticket_out = st_json_get_string(response, "ticket");
    return *ticket_out == NULL ? -1 : 0;
}

static int test_public_websocket_open(int port,
                                      const char *ticket,
                                      const char *public_ip,
                                      char *response,
                                      size_t response_len)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    char request[2048];
    int request_len = snprintf(request,
                               sizeof(request),
                               "GET /ws/public-transfer/discovery?ticket=%s HTTP/1.1\r\nHost: localhost\r\n"
                               "X-Real-IP: %s\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                               "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                               ticket,
                               public_ip);
    if (request_len < 0 || (size_t)request_len >= sizeof(request)
        || send(fd, request, (size_t)request_len, 0) != request_len) {
        close(fd);
        return -1;
    }
    size_t received = 0U;
    while (received + 1U < response_len) {
        if (recv(fd, response + received, 1U, 0) != 1) break;
        ++received;
        response[received] = '\0';
        if (received >= 4U && strcmp(response + received - 4U, "\r\n\r\n") == 0) break;
    }
    return fd;
}

static void test_write_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

static void test_close_websocket(int fd)
{
    if (fd < 0) return;
    uint8_t close_frame[] = {0x88U, 0x80U, 1U, 2U, 3U, 4U};
    (void)send(fd, close_frame, sizeof(close_frame), 0);
    (void)shutdown(fd, SHUT_RDWR);
    close(fd);
}

typedef struct {
    char body[256];
    char remote_address[64];
    char response[4096];
    int response_len;
} public_pairing_redeem_thread;

static void *test_public_pairing_redeem_thread(void *argument)
{
    public_pairing_redeem_thread *request = (public_pairing_redeem_thread *)argument;
    request->response_len = st_admin_build_response_with_remote(
        "POST",
        "/api/public/transfer/rooms/pairing-codes/redeem",
        request->body,
        request->remote_address,
        request->response,
        sizeof(request->response));
    return NULL;
}

static int test_public_room_access_contract(void)
{
    char response[65536] = {0};
    char request[4096];
    const char *room_name = "c-persistent-room";
    const char *owner_token = "c-owner-secret";
    setenv("SPECUS_AUTH_JWT_SECRET", "c-room-test-jwt-secret-with-more-than-32-bytes", 1);
    st_public_room_reset_for_tests();

    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\","
             "\"role\":\"VIEWER\",\"label\":\"Read only\",\"expiresInSeconds\":300}",
             room_name,
             owner_token);
    int len = st_admin_build_response_with_body("POST",
                                                 "/api/public/transfer/rooms/access-tokens",
                                                 request,
                                                 response,
                                                 sizeof(response));
    char *invite_token = st_json_get_string(response, "token");
    int access_id = 0;
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "Cache-Control: no-store")
        || !contains(response, "\"role\":\"VIEWER\"")
        || invite_token == NULL || strncmp(invite_token, "st-viewer-", 10U) != 0
        || st_json_get_int(response, "id", &access_id) != 0 || access_id <= 0) {
        fprintf(stderr, "public room access token create mismatch: %s\n", response);
        free(invite_token);
        return 1;
    }

    st_public_room_access owner_access;
    st_public_room_access viewer_access;
    if (st_public_room_resolve(room_name, owner_token, "owner-peer", &owner_access) != 0
        || st_public_room_resolve(room_name, invite_token, "viewer-peer", &viewer_access) != 0
        || strcmp(owner_access.role, "OWNER") != 0
        || strcmp(viewer_access.role, "VIEWER") != 0
        || strcmp(owner_access.room_key, viewer_access.room_key) != 0
        || st_public_room_resolve("wrong-room", invite_token, "viewer-peer", &viewer_access) != 2
        || st_public_room_resolve(room_name, "st-editor-unknown", "viewer-peer", &viewer_access) != 2) {
        fprintf(stderr, "public room persistent credential resolution mismatch\n");
        free(invite_token);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\"}",
             room_name,
             owner_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/access-tokens/list",
                                             request,
                                             response,
                                             sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "Read only")
        || !contains(response, "\"revokedAt\":null")) {
        fprintf(stderr, "public room access list mismatch: %s\n", response);
        free(invite_token);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\","
             "\"role\":\"EDITOR\",\"label\":\"Pair editor\",\"maxUses\":2}",
             room_name,
             owner_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/pairing-codes",
                                             request,
                                             response,
                                             sizeof(response));
    char *pairing_code = st_json_get_string(response, "code");
    if (len <= 0 || !contains(response, "200 OK") || pairing_code == NULL
        || strlen(pairing_code) != 8U || strspn(pairing_code, "0123456789") != 8U
        || !contains(response, "\"maxUses\":2") || !contains(response, "\"usedCount\":0")) {
        fprintf(stderr, "public room pairing code create mismatch: %s\n", response);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    char *redeemed_token = NULL;
    for (int attempt = 0; attempt < 3; ++attempt) {
        snprintf(request,
                 sizeof(request),
                 "{\"code\":\"%s\",\"peerId\":\"paired-%d\"}",
                 pairing_code,
                 attempt);
        len = st_admin_build_response_with_remote("POST",
                                                   "/api/public/transfer/rooms/pairing-codes/redeem",
                                                   request,
                                                   "198.51.100.77",
                                                   response,
                                                   sizeof(response));
        if (attempt < 2) {
            char *current = st_json_get_string(response, "roomToken");
            if (len <= 0 || !contains(response, "200 OK") || current == NULL
                || strncmp(current, "st-editor-", 10U) != 0
                || !contains(response, "\"role\":\"EDITOR\"")) {
                fprintf(stderr, "public room pairing redemption mismatch: %s\n", response);
                free(current);
                free(redeemed_token);
                free(invite_token);
                free(pairing_code);
                return 1;
            }
            free(redeemed_token);
            redeemed_token = current;
        } else if (len <= 0 || !contains(response, "400 Bad Request")
                   || !contains(response, "配对码无效或已过期")) {
            fprintf(stderr, "public room exhausted pairing code was accepted: %s\n", response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }
    }
    if (redeemed_token == NULL
        || st_public_room_resolve(room_name, redeemed_token, "paired", &viewer_access) != 0
        || strcmp(viewer_access.role, "EDITOR") != 0
        || strcmp(viewer_access.room_key, owner_access.room_key) != 0) {
        fprintf(stderr, "public room redeemed credential resolution mismatch\n");
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\","
             "\"name\":\"Owner snapshot\",\"update\":\"AQIDBA==\"}",
             room_name,
             owner_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/diagram/versions",
                                             request,
                                             response,
                                             sizeof(response));
    int owner_version_id = 0;
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"sizeBytes\":4")
        || st_json_get_int(response, "id", &owner_version_id) != 0 || owner_version_id <= 0) {
        fprintf(stderr, "public room owner diagram version create mismatch: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }
    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"editor-peer\","
             "\"name\":\"Editor snapshot\",\"update\":\"aGVsbG8=\"}",
             room_name,
             redeemed_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/diagram/versions",
                                             request,
                                             response,
                                             sizeof(response));
    int editor_version_id = 0;
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"sizeBytes\":5")
        || st_json_get_int(response, "id", &editor_version_id) != 0 || editor_version_id <= 0) {
        fprintf(stderr, "public room editor diagram version create mismatch: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }
    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"viewer-peer\","
             "\"name\":\"Forbidden snapshot\",\"update\":\"AQ==\"}",
             room_name,
             invite_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/diagram/versions",
                                             request,
                                             response,
                                             sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")
        || !contains(response, "访客不能创建流程图版本")) {
        fprintf(stderr, "public room viewer diagram write was not rejected: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }
    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"viewer-peer\"}",
             room_name,
             invite_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/diagram/versions/list",
                                             request,
                                             response,
                                             sizeof(response));
    char version_path[256];
    snprintf(version_path,
             sizeof(version_path),
             "/api/public/transfer/rooms/diagram/versions/%d",
             editor_version_id);
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "Owner snapshot")
        || !contains(response, "Editor snapshot")
        || st_admin_build_response_with_body("POST", version_path, request, response, sizeof(response)) <= 0
        || !contains(response, "200 OK") || !contains(response, "\"update\":\"aGVsbG8=\"")) {
        fprintf(stderr, "public room viewer diagram read mismatch: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }
    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"editor-peer\"}",
             room_name,
             redeemed_token);
    snprintf(version_path,
             sizeof(version_path),
             "/api/public/transfer/rooms/diagram/versions/%d/delete",
             editor_version_id);
    len = st_admin_build_response_with_body("POST", version_path, request, response, sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden") || !contains(response, "需要房主权限")) {
        fprintf(stderr, "public room editor diagram delete was not rejected: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }
    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\"}",
             room_name,
             owner_token);
    len = st_admin_build_response_with_body("POST", version_path, request, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "public room owner diagram delete mismatch: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    {
        const size_t encoded_len = 4U * 1024U * 1024U;
        const size_t request_capacity = encoded_len + 2048U;
        char *encoded = (char *)malloc(encoded_len + 5U);
        char *large_request = (char *)malloc(request_capacity);
        char *large_response = (char *)malloc(5U * 1024U * 1024U);
        if (encoded == NULL || large_request == NULL || large_response == NULL) {
            fprintf(stderr, "public room diagram boundary allocation failed\n");
            free(encoded);
            free(large_request);
            free(large_response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }
        memset(encoded, 'A', encoded_len + 4U);
        encoded[encoded_len] = '\0';
        int large_written = snprintf(large_request,
                                     request_capacity,
                                     "{\"roomId\":\"%s\",\"roomToken\":\"%s\","
                                     "\"peerId\":\"owner-peer\",\"name\":\"3 MiB snapshot\","
                                     "\"update\":\"%s\"}",
                                     room_name,
                                     owner_token,
                                     encoded);
        len = large_written < 0 || (size_t)large_written >= request_capacity ? -1
            : st_admin_build_response_with_body("POST",
                                                "/api/public/transfer/rooms/diagram/versions",
                                                large_request,
                                                response,
                                                sizeof(response));
        int large_version_id = 0;
        if (len <= 0 || !contains(response, "200 OK")
            || !contains(response, "\"sizeBytes\":3145728")
            || st_json_get_int(response, "id", &large_version_id) != 0
            || large_version_id <= 0) {
            fprintf(stderr, "public room exact 3 MiB diagram create mismatch: %s\n", response);
            free(encoded);
            free(large_request);
            free(large_response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }
        snprintf(request,
                 sizeof(request),
                 "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"viewer-peer\"}",
                 room_name,
                 invite_token);
        snprintf(version_path,
                 sizeof(version_path),
                 "/api/public/transfer/rooms/diagram/versions/%d",
                 large_version_id);
        len = st_admin_build_response_with_body("POST",
                                                 version_path,
                                                 request,
                                                 large_response,
                                                 5U * 1024U * 1024U);
        char *large_update = len > 0 ? strstr(large_response, "\"update\":\"") : NULL;
        if (large_update != NULL) large_update += strlen("\"update\":\"");
        if (len <= 0 || !contains(large_response, "200 OK") || large_update == NULL
            || strspn(large_update, "A") != encoded_len || large_update[encoded_len] != '"') {
            fprintf(stderr, "public room exact 3 MiB diagram read mismatch\n");
            free(encoded);
            free(large_request);
            free(large_response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }

        encoded[encoded_len] = 'A';
        encoded[encoded_len + 1U] = 'A';
        encoded[encoded_len + 2U] = 'A';
        encoded[encoded_len + 3U] = 'A';
        encoded[encoded_len + 4U] = '\0';
        large_written = snprintf(large_request,
                                 request_capacity,
                                 "{\"roomId\":\"%s\",\"roomToken\":\"%s\","
                                 "\"peerId\":\"owner-peer\",\"name\":\"Too large\","
                                 "\"update\":\"%s\"}",
                                 room_name,
                                 owner_token,
                                 encoded);
        len = large_written < 0 || (size_t)large_written >= request_capacity ? -1
            : st_admin_build_response_with_body("POST",
                                                "/api/public/transfer/rooms/diagram/versions",
                                                large_request,
                                                response,
                                                sizeof(response));
        if (len <= 0 || !contains(response, "400 Bad Request")
            || !contains(response, "超过 3 MB")) {
            fprintf(stderr, "public room oversized diagram was accepted: %s\n", response);
            free(encoded);
            free(large_request);
            free(large_response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }
        snprintf(request,
                 sizeof(request),
                 "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\"}",
                 room_name,
                 owner_token);
        snprintf(version_path,
                 sizeof(version_path),
                 "/api/public/transfer/rooms/diagram/versions/%d/delete",
                 large_version_id);
        len = st_admin_build_response_with_body("POST",
                                                 version_path,
                                                 request,
                                                 response,
                                                 sizeof(response));
        free(encoded);
        free(large_request);
        free(large_response);
        if (len <= 0 || !contains(response, "204 No Content")) {
            fprintf(stderr, "public room large diagram delete mismatch: %s\n", response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }
    }

    for (int version = 0; version < 51; ++version) {
        snprintf(request,
                 sizeof(request),
                 "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\","
                 "\"name\":\"Retention %d\",\"update\":\"AQ==\"}",
                 room_name,
                 owner_token,
                 version);
        len = st_admin_build_response_with_body("POST",
                                                 "/api/public/transfer/rooms/diagram/versions",
                                                 request,
                                                 response,
                                                 sizeof(response));
        if (len <= 0 || !contains(response, "200 OK")) {
            fprintf(stderr, "public room diagram retention create mismatch at %d: %s\n",
                    version,
                    response);
            free(redeemed_token);
            free(invite_token);
            free(pairing_code);
            return 1;
        }
    }

    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\"}",
             room_name,
             owner_token);
    char revoke_path[256];
    snprintf(revoke_path,
             sizeof(revoke_path),
             "/api/public/transfer/rooms/access-tokens/%d/revoke",
             access_id);
    len = st_admin_build_response_with_body("POST", revoke_path, request, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"revokedAt\":\"")
        || st_public_room_resolve(room_name, invite_token, "viewer-peer", &viewer_access) != 2) {
        fprintf(stderr, "public room access revoke mismatch: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    const char *database_path = getenv("SPECUS_DATABASE_PATH");
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int persisted_safely = database_path != NULL && sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
            "SELECT r.owner_token_hash,a.token_hash,c.code_hash FROM public_transfer_room r "
            "JOIN public_transfer_room_access a ON a.room_id=r.id "
            "JOIN public_transfer_room_pairing_code c ON c.room_id=r.id WHERE r.room_name=? LIMIT 1",
            -1,
            &stmt,
            NULL) == SQLITE_OK
        && sqlite3_bind_text(stmt, 1, room_name, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW
        && strcmp((const char *)sqlite3_column_text(stmt, 0), owner_token) != 0
        && strcmp((const char *)sqlite3_column_text(stmt, 1), invite_token) != 0
        && strcmp((const char *)sqlite3_column_text(stmt, 2), pairing_code) != 0;
    sqlite3_finalize(stmt);
    stmt = NULL;
    int retained_fifty_versions = db != NULL && sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM public_transfer_diagram_version v "
            "JOIN public_transfer_room r ON r.id=v.room_id WHERE r.room_name=?",
            -1,
            &stmt,
            NULL) == SQLITE_OK
        && sqlite3_bind_text(stmt, 1, room_name, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW
        && sqlite3_column_int(stmt, 0) == 50;
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    if (!persisted_safely || !retained_fifty_versions) {
        fprintf(stderr,
                "public room persistence mismatch (credentials=%d, versions=%d)\n",
                persisted_safely,
                retained_fifty_versions);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\","
             "\"role\":\"VIEWER\",\"label\":\"Atomic pair\",\"maxUses\":1}",
             room_name,
             owner_token);
    len = st_admin_build_response_with_body("POST",
                                             "/api/public/transfer/rooms/pairing-codes",
                                             request,
                                             response,
                                             sizeof(response));
    char *atomic_code = st_json_get_string(response, "code");
    if (len <= 0 || !contains(response, "200 OK") || atomic_code == NULL) {
        fprintf(stderr, "public room atomic pairing code create mismatch: %s\n", response);
        free(atomic_code);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }
    public_pairing_redeem_thread concurrent[2];
    pthread_t redeem_threads[2];
    memset(concurrent, 0, sizeof(concurrent));
    int threads_started = 0;
    for (int i = 0; i < 2; ++i) {
        snprintf(concurrent[i].body,
                 sizeof(concurrent[i].body),
                 "{\"code\":\"%s\",\"peerId\":\"atomic-%d\"}",
                 atomic_code,
                 i);
        snprintf(concurrent[i].remote_address,
                 sizeof(concurrent[i].remote_address),
                 "192.0.2.%d",
                 100 + i);
        if (pthread_create(&redeem_threads[i], NULL, test_public_pairing_redeem_thread, &concurrent[i]) != 0) {
            break;
        }
        ++threads_started;
    }
    for (int i = 0; i < threads_started; ++i) pthread_join(redeem_threads[i], NULL);
    int successful_redeems = 0;
    int rejected_redeems = 0;
    for (int i = 0; i < threads_started; ++i) {
        successful_redeems += concurrent[i].response_len > 0
            && contains(concurrent[i].response, "200 OK");
        rejected_redeems += concurrent[i].response_len > 0
            && contains(concurrent[i].response, "400 Bad Request");
    }
    free(atomic_code);
    if (threads_started != 2 || successful_redeems != 1 || rejected_redeems != 1) {
        fprintf(stderr,
                "public room concurrent one-use pairing mismatch: %s / %s\n",
                concurrent[0].response,
                concurrent[1].response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    int capacity_ok = 1;
    for (int i = 0; i < 17; ++i) {
        snprintf(request,
                 sizeof(request),
                 "{\"roomId\":\"%s\",\"roomToken\":\"%s\",\"peerId\":\"owner-peer\","
                 "\"role\":\"VIEWER\",\"label\":\"Capacity %d\"}",
                 room_name,
                 owner_token,
                 i);
        len = st_admin_build_response_with_body("POST",
                                                 "/api/public/transfer/rooms/access-tokens",
                                                 request,
                                                 response,
                                                 sizeof(response));
        if (len <= 0 || !contains(response, "200 OK")) {
            capacity_ok = 0;
            break;
        }
    }
    if (capacity_ok) {
        len = st_admin_build_response_with_body("POST",
                                                 "/api/public/transfer/rooms/access-tokens",
                                                 request,
                                                 response,
                                                 sizeof(response));
        capacity_ok = len > 0 && contains(response, "409 Conflict")
            && contains(response, "20 个上限");
    }
    if (!capacity_ok) {
        fprintf(stderr, "public room active invitation capacity mismatch: %s\n", response);
        free(redeemed_token);
        free(invite_token);
        free(pairing_code);
        return 1;
    }

    setenv("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP", "1", 1);
    st_public_room_reset_for_tests();
    len = st_admin_build_response_with_remote("POST",
                                               "/api/public/transfer/rooms/pairing-codes/redeem",
                                               "{\"code\":\"00000000\",\"peerId\":\"x\"}",
                                               "203.0.113.90",
                                               response,
                                               sizeof(response));
    int limited = len > 0 && contains(response, "400 Bad Request");
    len = st_admin_build_response_with_remote("POST",
                                               "/api/public/transfer/rooms/pairing-codes/redeem",
                                               "{\"code\":\"00000000\",\"peerId\":\"x\"}",
                                               "203.0.113.90",
                                               response,
                                               sizeof(response));
    limited = limited && len > 0 && contains(response, "429 Too Many Requests");
    unsetenv("SPECUS_PUBLIC_TRANSFER_PAIRING_CODE_REDEEM_RATE_LIMIT_PER_IP");
    st_public_room_reset_for_tests();
    free(redeemed_token);
    free(invite_token);
    free(pairing_code);
    if (!limited) {
        fprintf(stderr, "public room pairing redemption rate limit mismatch: %s\n", response);
        return 1;
    }
    return 0;
}

static int test_public_discovery_websocket(void)
{
    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    int peers[5] = {-1, -1, -1, -1, -1};
    int net_peer = -1;
    int result = 1;
    char *ticket_a = NULL;
    char *ticket_b = NULL;
    char *ticket_extra = NULL;
    char *invite_token = NULL;
    setenv("SPECUS_TRUSTED_PROXIES", "127.0.0.1/32", 1);
    st_public_discovery_reset_for_tests();
    if (st_admin_server_start(&server, 0, "") != 0) {
        fprintf(stderr, "public discovery server start failed\n");
        goto cleanup;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0) {
        fprintf(stderr, "public discovery port lookup failed\n");
        goto cleanup;
    }
    int port = ntohs(address.sin_port);
    char response[4096] = {0};
    char invite_body[1024];
    snprintf(invite_body,
             sizeof(invite_body),
             "{\"roomId\":\"shared\",\"roomToken\":\"shared-secret\",\"peerId\":\"peer-a\","
             "\"role\":\"VIEWER\",\"label\":\"Discovery viewer\"}");
    int invite_len = st_admin_build_response_with_body("POST",
                                                        "/api/public/transfer/rooms/access-tokens",
                                                        invite_body,
                                                        response,
                                                        sizeof(response));
    invite_token = st_json_get_string(response, "token");
    if (invite_len <= 0 || !contains(response, "200 OK") || invite_token == NULL) {
        fprintf(stderr, "public discovery persistent invitation create failed: %s\n", response);
        goto cleanup;
    }
    if (test_public_ticket(port, "shared", "shared-secret", "peer-a", "Device A", "198.51.100.1", &ticket_a) != 0
        || test_public_ticket(port, "shared", invite_token, "peer-b", "Device B", "203.0.113.2", &ticket_b) != 0) {
        fprintf(stderr, "public discovery ticket issue failed\n");
        goto cleanup;
    }
    char payload[8192] = {0};
    peers[0] = test_public_websocket_open(port, ticket_a, "198.51.100.1", response, sizeof(response));
    if (peers[0] < 0 || !contains(response, "101 Switching Protocols")
        || test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"hello\"")
        || !contains(payload, "\"peerId\":\"peer-a\"")
        || !contains(payload, "\"publicAddress\":\"198.51.100.1\"")
        || !contains(payload, "\"sharedRoom\":true")
        || !contains(payload, "\"roomRole\":\"OWNER\"")
        || test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"roster\"")
        || !contains(payload, "\"peerId\":\"peer-a\"")) {
        fprintf(stderr, "public discovery first peer handshake mismatch: %s\n", payload);
        goto cleanup;
    }
    memset(response, 0, sizeof(response));
    peers[1] = test_public_websocket_open(port, ticket_b, "203.0.113.2", response, sizeof(response));
    if (peers[1] < 0 || !contains(response, "101 Switching Protocols")
        || test_websocket_read_text(peers[1], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"hello\"")
        || !contains(payload, "\"peerId\":\"peer-b\"")
        || !contains(payload, "\"roomRole\":\"VIEWER\"")
        || test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"peer-a\"")
        || !contains(payload, "\"peerId\":\"peer-b\"")
        || test_websocket_read_text(peers[1], payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"peer-a\"")
        || !contains(payload, "\"peerId\":\"peer-b\"")) {
        fprintf(stderr, "public discovery shared-token roster mismatch: %s\n", payload);
        goto cleanup;
    }

    const char signal[] = "{\"type\":\"offer\",\"targetPeerId\":\"peer-b\","
                          "\"sourcePeerId\":\"forged\",\"payload\":{\"sdp\":\"test\"}}";
    if (test_websocket_send_masked_text(peers[0], signal) != 0
        || test_websocket_read_text(peers[1], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"offer\"")
        || !contains(payload, "\"sourcePeerId\":\"peer-a\"")
        || contains(payload, "forged")
        || !contains(payload, "\"targetPeerId\":\"peer-b\"")
        || !contains(payload, "\"payload\":{\"sdp\":\"test\"}")) {
        fprintf(stderr, "public discovery targeted signal mismatch: %s\n", payload);
        goto cleanup;
    }
    if (test_websocket_send_masked_text(peers[0], "{\"type\":\"ping\"}") != 0
        || test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"pong\"") || !contains(payload, "\"ts\":")) {
        fprintf(stderr, "public discovery ping mismatch: %s\n", payload);
        goto cleanup;
    }
    int availability_len = st_admin_build_response(
        "GET",
        "/api/public/transfer/clients/name-availability?clientName=Device+A",
        response,
        sizeof(response));
    if (availability_len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Device A\"")
        || !contains(response, "\"available\":false")) {
        fprintf(stderr, "public discovery occupied name availability mismatch: %s\n", response);
        goto cleanup;
    }
    availability_len = st_admin_build_response(
        "GET",
        "/api/public/transfer/clients/name-availability?clientName=Device+A&excludePeerId=peer-a",
        response,
        sizeof(response));
    if (availability_len <= 0 || !contains(response, "\"available\":true")) {
        fprintf(stderr, "public discovery excluded name availability mismatch: %s\n", response);
        goto cleanup;
    }
    char unicode_path[1024] = "/api/public/transfer/clients/name-availability?clientName=";
    size_t unicode_len = strlen(unicode_path);
    for (size_t i = 0U; i < 60U; ++i) {
        memcpy(unicode_path + unicode_len, "\xf0\x9f\x98\x80", 4U);
        unicode_len += 4U;
    }
    unicode_path[unicode_len] = '\0';
    availability_len = st_admin_build_response("GET", unicode_path, response, sizeof(response));
    if (availability_len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "public discovery 120 UTF-16-unit name was rejected\n");
        goto cleanup;
    }
    memcpy(unicode_path + unicode_len, "\xf0\x9f\x98\x80", 4U);
    unicode_len += 4U;
    unicode_path[unicode_len] = '\0';
    availability_len = st_admin_build_response("GET", unicode_path, response, sizeof(response));
    if (availability_len <= 0 || !contains(response, "400 Bad Request")) {
        fprintf(stderr, "public discovery 122 UTF-16-unit name was accepted\n");
        goto cleanup;
    }

    if (test_public_ticket(port,
                           "other-room",
                           "other-secret",
                           "peer-net",
                           "Same Net",
                           "198.51.100.1",
                           &ticket_extra) != 0) {
        fprintf(stderr, "public discovery merged-net ticket failed\n");
        goto cleanup;
    }
    memset(response, 0, sizeof(response));
    net_peer = test_public_websocket_open(port, ticket_extra, "198.51.100.1", response, sizeof(response));
    free(ticket_extra);
    ticket_extra = NULL;
    if (net_peer < 0 || test_websocket_read_text(net_peer, payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"peer-net\"")
        || test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"peer-a\"")
        || !contains(payload, "\"peerId\":\"peer-b\"")
        || !contains(payload, "\"peerId\":\"peer-net\"")
        || !contains(payload, "\"sameRoom\":false")
        || test_websocket_read_text(net_peer, payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"peer-a\"")
        || !contains(payload, "\"peerId\":\"peer-net\"")) {
        fprintf(stderr, "public discovery merged-net roster mismatch: %s\n", payload);
        goto cleanup;
    }
    if (test_websocket_send_masked_text(
            net_peer,
            "{\"type\":\"answer\",\"targetPeerId\":\"peer-a\",\"payload\":true}") != 0
        || test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || !contains(payload, "\"sourcePeerId\":\"peer-net\"")
        || !contains(payload, "\"targetPeerId\":\"peer-a\"")
        || !contains(payload, "\"payload\":true")) {
        fprintf(stderr, "public discovery merged-net targeted route mismatch: %s\n", payload);
        goto cleanup;
    }
    test_close_websocket(net_peer);
    net_peer = -1;
    if (test_websocket_read_text(peers[0], payload, sizeof(payload)) != 0
        || contains(payload, "peer-net")) {
        fprintf(stderr, "public discovery merged-net departure roster mismatch: %s\n", payload);
        goto cleanup;
    }

    uint8_t relay[14U + 6U + 72U];
    memset(relay, 0, sizeof(relay));
    memcpy(relay, "STWR", 4U);
    relay[4] = 2U;
    relay[6] = 0U;
    relay[7] = 6U;
    test_write_u32_be(relay + 10U, 72U);
    memcpy(relay + 14U, "peer-b", 6U);
    uint8_t *app = relay + 20U;
    memcpy(app, "STAP", 4U);
    app[4] = 2U;
    app[5] = 1U;
    test_write_u32_be(app + 28U, 1U);
    uint8_t binary[512];
    uint8_t opcode = 0U;
    size_t binary_len = 0U;
    if (test_websocket_send_masked_frame(peers[0], 0x2U, relay, sizeof(relay)) != 0
        || test_websocket_read_frame(peers[1], &opcode, binary, sizeof(binary), &binary_len) != 0
        || opcode != 0x2U || binary_len != sizeof(relay) + 6U
        || memcmp(binary, "STWR", 4U) != 0
        || binary[8] != 0U || binary[9] != 6U
        || memcmp(binary + 14U, "peer-b", 6U) != 0
        || memcmp(binary + 20U, "peer-a", 6U) != 0
        || memcmp(binary + 26U, "STAP", 4U) != 0) {
        fprintf(stderr, "public discovery STWR2 relay mismatch\n");
        goto cleanup;
    }
    memcpy(relay + 14U, "peer-a", 6U);
    app[5] = 1U;
    if (test_websocket_send_masked_frame(peers[1], 0x2U, relay, sizeof(relay)) != 0
        || test_websocket_read_text(peers[1], payload, sizeof(payload)) != 0
        || !contains(payload, "viewer is read-only")) {
        fprintf(stderr, "public discovery viewer write was not rejected: %s\n", payload);
        goto cleanup;
    }
    app[5] = 127U;
    if (test_websocket_send_masked_frame(peers[1], 0x2U, relay, sizeof(relay)) != 0
        || test_websocket_read_frame(peers[0], &opcode, binary, sizeof(binary), &binary_len) != 0
        || opcode != 0x2U || binary_len != sizeof(relay) + 6U
        || memcmp(binary + 14U, "peer-a", 6U) != 0
        || memcmp(binary + 20U, "peer-b", 6U) != 0
        || binary[31U] != 127U) {
        fprintf(stderr, "public discovery viewer ACK relay mismatch\n");
        goto cleanup;
    }

    memset(response, 0, sizeof(response));
    int reused = test_public_websocket_open(port, ticket_b, "203.0.113.2", response, sizeof(response));
    if (reused < 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "public discovery ticket reuse was not rejected: %s\n", response);
        if (reused >= 0) close(reused);
        goto cleanup;
    }
    close(reused);

    if (test_public_ticket(port, "shared", "shared-secret", "peer-a", "Duplicate peer", "192.0.2.10", &ticket_extra) != 0) {
        fprintf(stderr, "public discovery duplicate ticket failed\n");
        goto cleanup;
    }
    memset(response, 0, sizeof(response));
    int rejected = test_public_websocket_open(port, ticket_extra, "192.0.2.10", response, sizeof(response));
    free(ticket_extra);
    ticket_extra = NULL;
    if (rejected < 0 || !contains(response, "101 Switching Protocols")
        || test_websocket_read_text(rejected, payload, sizeof(payload)) != 0
        || !contains(payload, "peer id is already connected")) {
        fprintf(stderr, "public discovery duplicate peer was not rejected: %s\n", payload);
        if (rejected >= 0) close(rejected);
        goto cleanup;
    }
    close(rejected);

    setenv("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM", "2", 1);
    if (test_public_ticket(port, "shared", "shared-secret", "peer-c", "Device C", "192.0.2.11", &ticket_extra) != 0) {
        fprintf(stderr, "public discovery capacity ticket failed\n");
        goto cleanup;
    }
    memset(response, 0, sizeof(response));
    rejected = test_public_websocket_open(port, ticket_extra, "192.0.2.11", response, sizeof(response));
    free(ticket_extra);
    ticket_extra = NULL;
    unsetenv("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM");
    if (rejected < 0 || test_websocket_read_text(rejected, payload, sizeof(payload)) != 0
        || !contains(payload, "room is full")) {
        fprintf(stderr, "public discovery room capacity was not enforced: %s\n", payload);
        if (rejected >= 0) close(rejected);
        goto cleanup;
    }
    close(rejected);

    char *near_ticket_a = NULL;
    char *near_ticket_b = NULL;
    char *isolated_ticket = NULL;
    if (test_public_ticket(port, "nearby", "", "near-a", "Nearby A", "198.51.100.8", &near_ticket_a) != 0
        || test_public_ticket(port, "nearby", "", "near-b", "Nearby B", "198.51.100.8", &near_ticket_b) != 0
        || test_public_ticket(port, "nearby", "", "isolated", "Isolated", "198.51.100.9", &isolated_ticket) != 0) {
        free(near_ticket_a); free(near_ticket_b); free(isolated_ticket);
        fprintf(stderr, "public discovery nearby tickets failed\n");
        goto cleanup;
    }
    peers[2] = test_public_websocket_open(port, near_ticket_a, "198.51.100.8", response, sizeof(response));
    free(near_ticket_a);
    if (peers[2] < 0 || test_websocket_read_text(peers[2], payload, sizeof(payload)) != 0
        || test_websocket_read_text(peers[2], payload, sizeof(payload)) != 0) {
        free(near_ticket_b); free(isolated_ticket);
        fprintf(stderr, "public discovery nearby first peer failed\n");
        goto cleanup;
    }
    peers[3] = test_public_websocket_open(port, near_ticket_b, "198.51.100.8", response, sizeof(response));
    free(near_ticket_b);
    if (peers[3] < 0 || test_websocket_read_text(peers[3], payload, sizeof(payload)) != 0
        || test_websocket_read_text(peers[2], payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"near-a\"")
        || !contains(payload, "\"peerId\":\"near-b\"")
        || test_websocket_read_text(peers[3], payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"near-a\"")
        || !contains(payload, "\"peerId\":\"near-b\"")) {
        free(isolated_ticket);
        fprintf(stderr, "public discovery same-address grouping mismatch: %s\n", payload);
        goto cleanup;
    }
    peers[4] = test_public_websocket_open(port, isolated_ticket, "198.51.100.9", response, sizeof(response));
    free(isolated_ticket);
    if (peers[4] < 0 || test_websocket_read_text(peers[4], payload, sizeof(payload)) != 0
        || test_websocket_read_text(peers[4], payload, sizeof(payload)) != 0
        || !contains(payload, "\"peerId\":\"isolated\"")
        || contains(payload, "near-a") || contains(payload, "near-b")) {
        fprintf(stderr, "public discovery different-address isolation mismatch: %s\n", payload);
        goto cleanup;
    }
    setenv("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION", "1", 1);
    setenv("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS", "60", 1);
    if (test_websocket_send_masked_text(peers[4], "{\"type\":\"ping\"}") != 0
        || test_websocket_read_text(peers[4], payload, sizeof(payload)) != 0
        || !contains(payload, "\"type\":\"pong\"")
        || test_websocket_send_masked_text(peers[4], "{\"type\":\"ping\"}") != 0
        || test_websocket_read_text(peers[4], payload, sizeof(payload)) != 0
        || !contains(payload, "\"error\":\"rate limited\"")) {
        fprintf(stderr, "public discovery per-connection rate limit mismatch: %s\n", payload);
        goto cleanup;
    }
    test_close_websocket(peers[4]);
    peers[4] = -1;
    unsetenv("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION");
    unsetenv("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS");
    result = 0;

cleanup:
    free(ticket_a);
    free(ticket_b);
    free(ticket_extra);
    free(invite_token);
    unsetenv("SPECUS_PUBLIC_TRANSFER_MAX_DISCOVERY_PEERS_PER_ROOM");
    unsetenv("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_PER_CONNECTION");
    unsetenv("SPECUS_PUBLIC_TRANSFER_DISCOVERY_MESSAGE_RATE_LIMIT_WINDOW_SECONDS");
    test_close_websocket(net_peer);
    for (size_t i = 0U; i < sizeof(peers) / sizeof(peers[0]); ++i) test_close_websocket(peers[i]);
    route_auth_stop_server(&server);
    unsetenv("SPECUS_TRUSTED_PROXIES");
    return result;
}

static int test_client_messages_websocket(void)
{
    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    int socket_fd = -1;
    int result = 1;
    if (st_admin_server_start(&server, 0, "") != 0) {
        fprintf(stderr, "client messages websocket server start failed\n");
        return 1;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    memset(&address, 0, sizeof(address));
    if (getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0) {
        fprintf(stderr, "client messages websocket port lookup failed\n");
        goto cleanup;
    }
    int port = ntohs(address.sin_port);
    char response[8192] = {0};
    const char login_body[] = "{\"username\":\"admin\",\"password\":\"admin\"}";
    char request[8192];
    snprintf(request,
             sizeof(request),
             "POST /auth/login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             sizeof(login_body) - 1U,
             login_body);
    st_login_rate_limiter_reset();
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")) {
        fprintf(stderr, "client messages websocket login failed: %s\n", response);
        goto cleanup;
    }
    char *access_token = st_json_get_string(response, "accessToken");
    if (access_token == NULL) {
        fprintf(stderr, "client messages websocket login token missing\n");
        goto cleanup;
    }
    const char ticket_body[] = "{\"endpoint\":\"client-messages\"}";
    snprintf(request,
             sizeof(request),
             "POST /api/admin/ws-tickets HTTP/1.1\r\nHost: localhost\r\n"
             "Authorization: Bearer %s\r\nContent-Type: application/json\r\n"
             "Content-Length: %zu\r\nConnection: close\r\n\r\n%s",
             access_token,
             sizeof(ticket_body) - 1U,
             ticket_body);
    free(access_token);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")) {
        fprintf(stderr, "client messages websocket ticket request failed: %s\n", response);
        goto cleanup;
    }
    char *ticket = st_json_get_string(response, "ticket");
    if (ticket == NULL) {
        fprintf(stderr, "client messages websocket ticket missing\n");
        goto cleanup;
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    if (socket_fd < 0
        || setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0
        || setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0) {
        free(ticket);
        fprintf(stderr, "client messages websocket socket setup failed\n");
        goto cleanup;
    }
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        free(ticket);
        fprintf(stderr, "client messages websocket connect failed\n");
        goto cleanup;
    }
    snprintf(request,
             sizeof(request),
             "GET /ws/client-messages?ticket=%s HTTP/1.1\r\nHost: localhost\r\n"
             "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
             ticket);
    free(ticket);
    size_t request_len = strlen(request);
    if (send(socket_fd, request, request_len, 0) != (ssize_t)request_len) {
        fprintf(stderr, "client messages websocket handshake write failed\n");
        goto cleanup;
    }
    size_t response_len = 0U;
    while (response_len + 1U < sizeof(response)) {
        if (recv(socket_fd, response + response_len, 1U, 0) != 1) {
            break;
        }
        ++response_len;
        response[response_len] = '\0';
        if (response_len >= 4U && strcmp(response + response_len - 4U, "\r\n\r\n") == 0) {
            break;
        }
    }
    if (!contains(response, "101 Switching Protocols")) {
        fprintf(stderr, "client messages websocket handshake failed: %s\n", response);
        goto cleanup;
    }
    char websocket_payload[2048] = {0};
    if (test_websocket_read_text(socket_fd, websocket_payload, sizeof(websocket_payload)) != 0
        || !contains(websocket_payload, "\"type\":\"hello\"")
        || !contains(websocket_payload, "\"channel\":\"client-messages\"")
        || !contains(websocket_payload, "\"tenantId\":\"tenant-db\"")) {
        fprintf(stderr, "client messages websocket hello mismatch: %s\n", websocket_payload);
        goto cleanup;
    }

    pthread_mutex_lock(&client_message_block_lock);
    client_message_push_calls = 0;
    pthread_mutex_unlock(&client_message_block_lock);
    st_admin_set_client_runtime_status_handler(test_client_runtime_status, NULL);
    st_admin_set_client_message_handler(test_client_message_push, NULL);
    char command[1024];
    snprintf(command,
             sizeof(command),
             "{\"type\":\"message\",\"messageId\":\"m-1\",\"toClientName\":\"%s\","
             "\"message\":\" hello from admin \"}",
             runtime_status_expected_client_name);
    if (test_websocket_send_masked_text(socket_fd, command) != 0
        || test_websocket_read_text(socket_fd, websocket_payload, sizeof(websocket_payload)) != 0
        || !contains(websocket_payload, "\"type\":\"written\"")
        || !contains(websocket_payload, "\"messageId\":\"m-1\"")
        || !contains(websocket_payload, "\"message\":\"hello from admin\"")
        || test_client_message_push_count() != 1) {
        fprintf(stderr, "admin to client websocket delivery mismatch: %s\n", websocket_payload);
        goto cleanup;
    }
    if (st_admin_deliver_client_message_to_admin("tenant-db",
                                                  runtime_status_expected_client_name,
                                                  " ADMIN: admin ",
                                                  "reply from client") != 0
        || test_websocket_read_text(socket_fd, websocket_payload, sizeof(websocket_payload)) != 0
        || !contains(websocket_payload, "\"direction\":\"in\"")
        || !contains(websocket_payload, "\"toClientName\":\"admin:admin\"")
        || !contains(websocket_payload, "\"message\":\"reply from client\"")) {
        fprintf(stderr, "client to admin websocket delivery mismatch: %s\n", websocket_payload);
        goto cleanup;
    }
    pthread_mutex_lock(&client_message_block_lock);
    client_message_block_started = 0;
    client_message_block_release = 0;
    pthread_mutex_unlock(&client_message_block_lock);
    snprintf(command,
             sizeof(command),
             "{\"type\":\"message\",\"messageId\":\"m-async\",\"toClientName\":\"%s\","
             "\"message\":\"async block\"}",
             runtime_status_expected_client_name);
    if (test_websocket_send_masked_text(socket_fd, command) != 0
        || test_websocket_send_masked_text(socket_fd,
                                           "{\"type\":\"unsupported\",\"messageId\":\"m-after\"}") != 0
        || test_websocket_read_text(socket_fd, websocket_payload, sizeof(websocket_payload)) != 0
        || !contains(websocket_payload, "\"type\":\"error\"")
        || !contains(websocket_payload, "\"messageId\":\"m-after\"")
        || !contains(websocket_payload, "\"error\":\"unsupported-type\"")) {
        fprintf(stderr, "client message async non-blocking response mismatch: %s\n", websocket_payload);
        goto cleanup;
    }
    pthread_mutex_lock(&client_message_block_lock);
    client_message_block_release = 1;
    pthread_cond_broadcast(&client_message_block_cond);
    pthread_mutex_unlock(&client_message_block_lock);
    if (test_websocket_read_text(socket_fd, websocket_payload, sizeof(websocket_payload)) != 0
        || !contains(websocket_payload, "\"type\":\"written\"")
        || !contains(websocket_payload, "\"messageId\":\"m-async\"")
        || test_client_message_push_count() != 2) {
        fprintf(stderr, "client message async completion mismatch: %s\n", websocket_payload);
        goto cleanup;
    }
    static const char boundary_prefix[] =
        "{\"type\":\"unsupported\",\"messageId\":\"m-limit\",\"padding\":\"";
    static const char boundary_suffix[] = "\"}";
    size_t boundary_len = 65536U;
    char *boundary = (char *)malloc(boundary_len + 2U);
    if (boundary == NULL) goto cleanup;
    size_t prefix_len = sizeof(boundary_prefix) - 1U;
    size_t suffix_len = sizeof(boundary_suffix) - 1U;
    memcpy(boundary, boundary_prefix, prefix_len);
    memset(boundary + prefix_len, 'a', boundary_len - prefix_len - suffix_len);
    memcpy(boundary + boundary_len - suffix_len, boundary_suffix, suffix_len);
    boundary[boundary_len] = '\0';
    if (test_websocket_send_masked_frame(socket_fd,
                                         0x1U,
                                         (const uint8_t *)boundary,
                                         boundary_len) != 0
        || test_websocket_read_text(socket_fd, websocket_payload, sizeof(websocket_payload)) != 0
        || !contains(websocket_payload, "\"type\":\"error\"")
        || !contains(websocket_payload, "\"messageId\":\"m-limit\"")) {
        fprintf(stderr, "client message 65536 UTF-16-unit boundary mismatch: %s\n", websocket_payload);
        free(boundary);
        goto cleanup;
    }
    memmove(boundary + boundary_len - suffix_len + 1U,
            boundary + boundary_len - suffix_len,
            suffix_len + 1U);
    boundary[boundary_len - suffix_len] = 'b';
    ++boundary_len;
    uint8_t close_payload[16];
    uint8_t close_opcode = 0U;
    size_t close_len = 0U;
    int over_result = test_websocket_send_masked_frame(socket_fd,
                                                        0x1U,
                                                        (const uint8_t *)boundary,
                                                        boundary_len);
    free(boundary);
    if (over_result != 0
        || test_websocket_read_frame(socket_fd,
                                     &close_opcode,
                                     close_payload,
                                     sizeof(close_payload),
                                     &close_len) != 0
        || close_opcode != 0x8U || close_len < 2U
        || close_payload[0] != 0x03U || close_payload[1] != 0xf1U) {
        fprintf(stderr, "client message 65537 UTF-16-unit boundary was not closed with 1009\n");
        goto cleanup;
    }
    result = 0;

cleanup:
    pthread_mutex_lock(&client_message_block_lock);
    client_message_block_release = 1;
    pthread_cond_broadcast(&client_message_block_cond);
    pthread_mutex_unlock(&client_message_block_lock);
    st_admin_set_client_runtime_status_handler(NULL, NULL);
    st_admin_set_client_message_handler(NULL, NULL);
    if (socket_fd >= 0) {
        uint8_t close_frame[] = {0x88U, 0x80U, 1U, 2U, 3U, 4U};
        (void)send(socket_fd, close_frame, sizeof(close_frame), 0);
        (void)shutdown(socket_fd, SHUT_RDWR);
        close(socket_fd);
    }
    route_auth_stop_server(&server);
    return result;
}

/*
 * /ws/connections over real sockets, with the semantics of Java ConnectionEventsWebSocketHandler:
 * a created or updated event reaches every session of its tenant that may see the connection, i.e.
 * administrators, and other users only for connections of a client they own.
 */
static int connection_events_bearer(const char *username, const char *tenant, const char *role,
                                    char *out, size_t out_len)
{
    char token[2048];
    if (st_security_issue_local_token(username, tenant, role, getenv("SPECUS_AUTH_JWT_SECRET"), 600,
                                      token, sizeof(token)) != 0) {
        return -1;
    }
    int written = snprintf(out, out_len, "Bearer %s", token);
    return written < 0 || (size_t)written >= out_len ? -1 : 0;
}

static char *connection_events_ticket(int port, const char *authorization, const char *endpoint)
{
    char body[96];
    char request[4096];
    char response[4096] = {0};
    int body_len = snprintf(body, sizeof(body), "{\"endpoint\":\"%s\"}", endpoint);
    snprintf(request, sizeof(request),
             "POST /api/admin/ws-tickets HTTP/1.1\r\nHost: localhost\r\nAuthorization: %s\r\n"
             "Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
             authorization, body_len, body);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")) {
        fprintf(stderr, "connection events ticket request failed: %s\n", response);
        return NULL;
    }
    return st_json_get_string(response, "ticket");
}

/* Opens /ws/connections with the ticket; *status gets the handshake status code. */
static int connection_events_connect(int port, const char *ticket, int *status)
{
    *status = -1;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval timeout = {.tv_sec = 5, .tv_usec = 0};
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (fd < 0 || setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0
        || connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char request[2048];
    int request_len = snprintf(request, sizeof(request),
                               "GET /ws/connections%s%s HTTP/1.1\r\nHost: localhost\r\n"
                               "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                               "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
                               ticket == NULL ? "" : "?ticket=", ticket == NULL ? "" : ticket);
    char response[2048] = {0};
    size_t received = 0U;
    if (request_len > 0 && send(fd, request, (size_t)request_len, 0) == request_len) {
        while (received + 1U < sizeof(response) && recv(fd, response + received, 1U, 0) == 1) {
            ++received;
            if (received >= 4U && strcmp(response + received - 4U, "\r\n\r\n") == 0) break;
        }
    }
    if (strncmp(response, "HTTP/1.1 ", 9U) == 0) *status = atoi(response + 9);
    if (*status != 101) {
        close(fd);
        return -1;
    }
    /* The server registers the session before it reads frames, so a pong proves registration. */
    uint8_t opcode = 0U;
    uint8_t pong[16];
    size_t pong_len = 0U;
    if (test_websocket_send_masked_frame(fd, 0x9U, (const uint8_t *)"sync", 4U) != 0
        || test_websocket_read_frame(fd, &opcode, pong, sizeof(pong), &pong_len) != 0
        || opcode != 0xAU || pong_len != 4U || memcmp(pong, "sync", 4U) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int connection_events_open(int port, const char *username, const char *tenant, const char *role)
{
    char authorization[2300];
    int status = -1;
    char *ticket = connection_events_bearer(username, tenant, role, authorization, sizeof(authorization)) == 0
        ? connection_events_ticket(port, authorization, "connections") : NULL;
    int fd = ticket == NULL ? -1 : connection_events_connect(port, ticket, &status);
    if (fd < 0) fprintf(stderr, "connection events socket for %s/%s failed (%d)\n", tenant, username, status);
    free(ticket);
    return fd;
}

static void connection_events_broadcast(const char *tenant, const char *type, long long id, long long client_id,
                                        const char *disconnected_at)
{
    st_storage_connection connection;
    memset(&connection, 0, sizeof(connection));
    connection.id = id;
    connection.client_id = client_id;
    connection.success = 1;
    snprintf(connection.tenant_id, sizeof(connection.tenant_id), "%s", tenant);
    snprintf(connection.client_name, sizeof(connection.client_name), "events-client-%lld", id);
    snprintf(connection.channel_id, sizeof(connection.channel_id), "channel-%lld", id);
    snprintf(connection.remote_address, sizeof(connection.remote_address), "203.0.113.10");
    snprintf(connection.connected_at, sizeof(connection.connected_at), "2026-07-22T00:00:00Z");
    snprintf(connection.disconnected_at, sizeof(connection.disconnected_at), "%s",
             disconnected_at == NULL ? "" : disconnected_at);
    st_admin_broadcast_connection_event(tenant, type, &connection);
}

/* Reads the next event and checks tenant, type, connection id and the Java DTO field set. */
static int connection_events_expect(int fd, const char *tenant, const char *type, long long id, const char *label)
{
    char payload[4096] = {0};
    char expected_tenant[96];
    char expected_type[48];
    char expected_id[48];
    snprintf(expected_tenant, sizeof(expected_tenant), "{\"tenantId\":\"%s\",", tenant);
    snprintf(expected_type, sizeof(expected_type), "\"type\":\"%s\"", type);
    snprintf(expected_id, sizeof(expected_id), "\"connection\":{\"id\":%lld,", id);
    static const char *const fields[] = {
        "\"clientId\":", "\"clientName\":", "\"channelId\":", "\"remoteAddress\":", "\"connectedAt\":",
        "\"disconnectedAt\":", "\"success\":true", "\"failureReason\":", "\"disconnectReason\":",
        "\"disconnectReasonText\":"
    };
    int ok = test_websocket_read_text(fd, payload, sizeof(payload)) == 0
        && strncmp(payload, expected_tenant, strlen(expected_tenant)) == 0
        && contains(payload, expected_type) && contains(payload, expected_id);
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); ++i) ok = contains(payload, fields[i]);
    if (!ok) fprintf(stderr, "%s: expected %s %s #%lld, got %s\n", label, tenant, type, id, payload);
    return ok ? 0 : -1;
}

static int connection_events_silent(int fd, const char *label)
{
    struct timeval quick = {.tv_sec = 0, .tv_usec = 300000};
    struct timeval normal = {.tv_sec = 5, .tv_usec = 0};
    uint8_t byte = 0U;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &quick, sizeof(quick));
    ssize_t received = recv(fd, &byte, 1U, MSG_PEEK);
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &normal, sizeof(normal));
    if (received < 0) return 0;
    fprintf(stderr, "%s: an event leaked to this session\n", label);
    return -1;
}

/*
 * Management tokens are re-resolved against the user table on every request, so the users these
 * sessions sign as have to exist, enabled, in the tenant their token names.
 */
static int connection_events_ensure_user(const char *username, const char *tenant, const char *role)
{
    const char *db_path = getenv("SPECUS_DATABASE_PATH");
    st_storage_management_user user;
    if (db_path == NULL || db_path[0] == '\0') {
        fprintf(stderr, "connection events need SPECUS_DATABASE_PATH\n");
        return -1;
    }
    if (st_storage_get_management_user(db_path, username, &user) == 0) {
        return 0;
    }
    if (st_storage_create_management_user(db_path, username, tenant, "unused-password-hash", role, 1, &user) != 0) {
        fprintf(stderr, "connection events user %s/%s setup failed\n", tenant, username);
        return -1;
    }
    return 0;
}

static int test_connection_events_websocket(long long owned_client_id)
{
    if (connection_events_ensure_user("owner-db", "tenant-db", "USER") != 0
        || connection_events_ensure_user("someone-else", "tenant-db", "USER") != 0
        || connection_events_ensure_user("events-admin-other", "tenant-other", "ADMIN") != 0) {
        return 1;
    }

    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    if (st_admin_server_start(&server, 0, "") != 0) {
        fprintf(stderr, "connection events server start failed\n");
        return 1;
    }
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    int port = getsockname(server.fd, (struct sockaddr *)&address, &address_len) == 0 ? ntohs(address.sin_port) : -1;
    int admin = -1, owner = -1, stranger = -1, other_tenant = -1;
    int result = 1;
    char response[4096];
    char authorization[2300];
    int status = -1;
    if (port <= 0) goto cleanup;

    /* Plain HTTP is told to upgrade; missing, cross-endpoint and reused tickets are refused. */
    int len = st_admin_build_response("GET", "/ws/connections", response, sizeof(response));
    if (len <= 0 || !contains(response, "426 Upgrade Required")) {
        fprintf(stderr, "plain GET /ws/connections must be 426\n");
        goto cleanup;
    }
    if (connection_events_connect(port, NULL, &status) >= 0 || status != 403) {
        fprintf(stderr, "/ws/connections without a ticket must be 403, got %d\n", status);
        goto cleanup;
    }
    char *ticket = connection_events_bearer("admin", "tenant-db", "ADMIN", authorization, sizeof(authorization)) == 0
        ? connection_events_ticket(port, authorization, "client-messages") : NULL;
    int issued = ticket != NULL;
    int refused = issued ? connection_events_connect(port, ticket, &status) : -1;
    free(ticket);
    if (!issued || refused >= 0 || status != 403) {
        fprintf(stderr, "a client-messages ticket must not open /ws/connections (%d)\n", status);
        if (refused >= 0) close(refused);
        goto cleanup;
    }
    ticket = connection_events_ticket(port, authorization, "connections");
    admin = ticket == NULL ? -1 : connection_events_connect(port, ticket, &status);
    int reused = ticket == NULL || admin < 0 ? -1 : connection_events_connect(port, ticket, &status);
    free(ticket);
    if (admin < 0 || reused >= 0 || status != 403) {
        fprintf(stderr, "a connections ticket must open exactly one session (%d)\n", status);
        if (reused >= 0) close(reused);
        goto cleanup;
    }
    owner = connection_events_open(port, "owner-db", "tenant-db", "USER");
    stranger = connection_events_open(port, "someone-else", "tenant-db", "USER");
    other_tenant = connection_events_open(port, "events-admin-other", "tenant-other", "ADMIN");
    if (owner < 0 || stranger < 0 || other_tenant < 0) goto cleanup;

    /* Another tenant's event, then a created/updated pair of the owner's client, then a
     * connection of no owned client. Each session sees exactly its share, in order. */
    connection_events_broadcast("tenant-other", "created", 501, 0, NULL);
    connection_events_broadcast("tenant-db", "created", 502, owned_client_id, NULL);
    connection_events_broadcast("tenant-db", "updated", 502, owned_client_id, "2026-07-22T00:05:00Z");
    connection_events_broadcast("tenant-db", "created", 503, 0, NULL);
    connection_events_broadcast("tenant-other", "updated", 504, 0, "2026-07-22T00:06:00Z");
    if (connection_events_expect(admin, "tenant-db", "created", 502, "administrator, first event") != 0
        || connection_events_expect(admin, "tenant-db", "updated", 502, "administrator, second event") != 0
        || connection_events_expect(admin, "tenant-db", "created", 503, "administrator, third event") != 0
        || connection_events_silent(admin, "administrator after its tenant's events") != 0
        || connection_events_expect(owner, "tenant-db", "created", 502, "owner, first event") != 0
        || connection_events_expect(owner, "tenant-db", "updated", 502, "owner, second event") != 0
        || connection_events_silent(owner, "owner after its client's events") != 0
        || connection_events_silent(stranger, "user without clients") != 0
        || connection_events_expect(other_tenant, "tenant-other", "created", 501, "other tenant, first event") != 0
        || connection_events_expect(other_tenant, "tenant-other", "updated", 504, "other tenant, second event") != 0
        || connection_events_silent(other_tenant, "other tenant after its events") != 0) {
        goto cleanup;
    }
    /* A closed session is dropped: later events still reach the others. */
    test_close_websocket(owner);
    owner = -1;
    connection_events_broadcast("tenant-db", "updated", 503, 0, "2026-07-22T00:07:00Z");
    if (connection_events_expect(admin, "tenant-db", "updated", 503, "administrator after a session closed") != 0) {
        goto cleanup;
    }
    result = 0;

cleanup:
    test_close_websocket(admin);
    test_close_websocket(owner);
    test_close_websocket(stranger);
    test_close_websocket(other_tenant);
    route_auth_stop_server(&server);
    return result;
}

/*
 * Status codes, authentication and response shape of force-refresh-port-mapping,
 * traffic/inspection-status, traffic/http-exchanges/{id} and peer-mesh/egress/activity, against
 * the Java ClientResource, TrafficResource and PeerEgressResource DTOs.
 */
static long long endpoint_push_client_id = 0;
static int endpoint_push_calls = 0;

static int endpoint_nat_push(void *ctx, long long client_id, const char *client_name)
{
    (void)ctx;
    (void)client_name;
    if (client_id != endpoint_push_client_id) return -1;
    ++endpoint_push_calls;
    return 0;
}

static long long endpoint_runtime_client_id = 0;

static int endpoint_runtime_status(void *ctx, long long client_id, const char *client_name,
                                   st_admin_client_runtime_status *status)
{
    (void)ctx;
    (void)client_name;
    memset(status, 0, sizeof(*status));
    status->online = client_id == endpoint_runtime_client_id;
    return 0;
}

/* username NULL sends no credentials at all. */
static int endpoint_call(const char *method, const char *path, const char *username, const char *tenant,
                         const char *role, char *out, size_t out_len)
{
    char authorization[2300];
    if (username != NULL
        && connection_events_bearer(username, tenant, role, authorization, sizeof(authorization)) != 0) {
        return -1;
    }
    return st_admin_build_response_with_auth(method, path, username == NULL ? NULL : authorization, NULL,
                                             out, out_len);
}

static int endpoint_expect(int len, const char *response, const char *status, const char *needle, const char *label)
{
    int ok = len > 0 && strncmp(response, status, strlen(status)) == 0 && (needle == NULL || contains(response, needle));
    if (!ok) fprintf(stderr, "%s: expected %s%s%s, got %s\n", label, status, needle == NULL ? "" : " with ",
                     needle == NULL ? "" : needle, len > 0 ? response : "(none)");
    return ok ? 0 : -1;
}

static int endpoint_body_equals(int len, const char *response, const char *body, const char *label)
{
    const char *actual = len > 0 ? strstr(response, "\r\n\r\n") : NULL;
    int ok = actual != NULL && strncmp(response, "HTTP/1.1 200 OK", 15U) == 0 && strcmp(actual + 4, body) == 0;
    if (!ok) fprintf(stderr, "%s: expected 200 %s, got %s\n", label, body, len > 0 ? response : "(none)");
    return ok ? 0 : -1;
}

static long long endpoint_exchange_id(const char *database_path, const char *client_name)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long id = -1;
    if (sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT id FROM specus_http_traffic_exchange WHERE client_name=?",
                              -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_bind_text(stmt, 1, client_name, -1, SQLITE_TRANSIENT) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        id = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (db != NULL) sqlite3_close(db);
    return id;
}

static int endpoint_seed_exchange(const char *database_path, const char *tenant, const st_storage_client *client)
{
    st_storage_http_exchange_record record;
    memset(&record, 0, sizeof(record));
    record.tenant_id = tenant;
    record.client_id = client->id;
    record.client_name = client->client_name;
    record.route = "api";
    record.method = "GET";
    record.relative_path = "/status";
    record.raw_query = "verbose=1";
    record.status_code = 200;
    record.success = 1;
    record.remote_address = "203.0.113.10";
    record.request_bytes = 12;
    record.response_bytes = 34;
    record.elapsed_ms = 5;
    record.response_content_type = "application/json";
    record.response_body_type = "json";
    record.request_headers = "Accept: application/json";
    record.response_headers = "Content-Type: application/json";
    record.response_body = (const uint8_t *)"{\"ok\":true}";
    record.response_body_len = 11U;
    record.captured_at = "2026-07-22T00:00:00Z";
    return st_storage_record_http_exchange(database_path, &record);
}

static int endpoint_seed_activity(const char *database_path, const char *tenant, const st_storage_client *client,
                                  long long active_flows, const char *rejected_flows)
{
    st_storage_peer_mesh_egress_activity row;
    memset(&row, 0, sizeof(row));
    snprintf(row.tenant_id, sizeof(row.tenant_id), "%s", tenant);
    row.egress_client_id = client->id;
    snprintf(row.egress_client_name, sizeof(row.egress_client_name), "%s", client->client_name);
    row.session_id = 1;
    row.revision = 3;
    row.active_flows = active_flows;
    row.total_flows = active_flows + 10;
    snprintf(row.rejected_flows, sizeof(row.rejected_flows), "%s", rejected_flows);
    row.bytes_in = 1000;
    row.bytes_out = 2000;
    snprintf(row.reported_at, sizeof(row.reported_at), "2026-07-22T00:00:00Z");
    return st_storage_upsert_peer_mesh_egress_activity(database_path, &row);
}

static int test_admin_endpoint_contracts(void)
{
    char db_path[256];
    char path[160];
    char response[32768];
    snprintf(db_path, sizeof(db_path), "/tmp/specus-c-admin-endpoints-%ld.db", (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "c-admin-endpoint-test-secret", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    unsetenv("SPECUS_AUTH_TENANT_ID");
    unsetenv("SPECUS_AUTH_USERNAME");
    unsetenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");
    st_storage_client alpha, bravo, charlie;
    st_storage_mapping mapping;
    st_storage_http_route route;
    int failed = st_storage_init(db_path, 0) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-a", "endpoint-alpha", "alice", 1, 60, &alpha) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-a", "endpoint-bravo", "bob", 1, 60, &bravo) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-b", "endpoint-charlie", "alice", 1, 60, &charlie) != 0
        || st_storage_create_mapping_for_client(db_path, alpha.id, 18080, "127.0.0.1", 8080, 1, 0, &mapping) != 0
        || st_storage_create_mapping_for_client(db_path, alpha.id, 18081, "127.0.0.1", 8081, 0, 0, &mapping) != 0
        /* Tokens are re-resolved against the user table, so the callers below have to exist. */
        || connection_events_ensure_user("alice", "tenant-a", "USER") != 0
        || connection_events_ensure_user("bob", "tenant-a", "USER") != 0
        || connection_events_ensure_user("root", "tenant-a", "ADMIN") != 0
        || connection_events_ensure_user("root-b", "tenant-b", "ADMIN") != 0;
    if (failed) fprintf(stderr, "admin endpoint fixture setup failed\n");
    int len = 0;

    /* POST /api/admin/clients/{id}/force-refresh-port-mapping: {specusMappings, httpRoutes}. */
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/force-refresh-port-mapping", alpha.id);
    if (!failed) {
        len = endpoint_call("POST", path, NULL, NULL, NULL, response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 401 ", NULL, "force refresh without token") != 0;
    }
    if (!failed) {
        len = endpoint_call("POST", path, "alice", "tenant-a", "USER", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 409 ", "客户端不在线", "force refresh of an offline client") != 0;
    }
    endpoint_push_client_id = alpha.id;
    endpoint_push_calls = 0;
    st_admin_set_nat_control_handler(endpoint_nat_push, NULL);
    /* Only enabled mappings count; httpRoutes is -1 until a route was ever created. */
    if (!failed) {
        len = endpoint_call("POST", path, "alice", "tenant-a", "USER", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"specusMappings\":1", "force refresh") != 0
            || !contains(response, "\"httpRoutes\":-1") || endpoint_push_calls != 1;
    }
    if (!failed) {
        failed = st_storage_create_http_route_for_client(db_path, alpha.id, "disabled-route", "http://127.0.0.1:8080",
                                                         0, 0, 0, 0, 0, 0, NULL, NULL, &route) != 0;
        len = failed ? -1 : endpoint_call("POST", path, "root", "tenant-a", "ADMIN", response, sizeof(response));
        failed = failed || endpoint_expect(len, response, "HTTP/1.1 200 ", "\"httpRoutes\":0",
                                           "force refresh by the tenant administrator") != 0
            || endpoint_push_calls != 2;
    }
    if (!failed) {
        len = endpoint_call("POST", path, "bob", "tenant-a", "USER", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, "force refresh of another owner's client") != 0;
    }
    if (!failed) {
        len = endpoint_call("POST", path, "root-b", "tenant-b", "ADMIN", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, "force refresh from another tenant") != 0
            || endpoint_push_calls != 2;
    }
    st_admin_set_nat_control_handler(NULL, NULL);

    /* GET /api/admin/traffic/inspection-status: TrafficInspectionService.Snapshot. */
    if (!failed) {
        len = endpoint_call("GET", "/api/admin/traffic/inspection-status", NULL, NULL, NULL, response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 401 ", NULL, "inspection status without token") != 0;
    }
    if (!failed) {
        len = endpoint_call("GET", "/api/admin/traffic/inspection-status", "alice", "tenant-a", "USER",
                            response, sizeof(response));
        failed = endpoint_body_equals(len, response,
            "{\"enabled\":false,\"pendingHttp\":0,\"pendingTcp\":0,\"droppedHttp\":0,\"droppedTcp\":0,"
            "\"lastFlushedAt\":null}", "inspection status") != 0;
    }
    setenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", "true", 1);
    if (!failed) {
        len = endpoint_call("GET", "/api/admin/traffic/inspection-status", "alice", "tenant-a", "USER",
                            response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "{\"enabled\":true,", "enabled inspection status") != 0;
    }
    unsetenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");

    /* GET /api/admin/traffic/http-exchanges/{id}: HttpTrafficExchangeView or 404. */
    failed = failed || endpoint_seed_exchange(db_path, "tenant-a", &alpha) != 0
        || endpoint_seed_exchange(db_path, "tenant-a", &bravo) != 0
        || endpoint_seed_exchange(db_path, "tenant-b", &charlie) != 0;
    long long alpha_exchange = endpoint_exchange_id(db_path, alpha.client_name);
    long long charlie_exchange = endpoint_exchange_id(db_path, charlie.client_name);
    failed = failed || alpha_exchange <= 0 || charlie_exchange <= 0;
    snprintf(path, sizeof(path), "/api/admin/traffic/http-exchanges/%lld", alpha_exchange);
    if (!failed) {
        len = endpoint_call("GET", path, NULL, NULL, NULL, response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 401 ", NULL, "exchange detail without token") != 0;
    }
    if (!failed) {
        char expected_id[64];
        snprintf(expected_id, sizeof(expected_id), "{\"id\":\"%lld\",\"clientId\":%lld,", alpha_exchange, alpha.id);
        static const char *const fields[] = {
            "\"clientName\":\"endpoint-alpha\"", "\"route\":\"api\"", "\"resourceId\":", "\"resourceName\":",
            "\"method\":\"GET\"", "\"relativePath\":\"/status\"", "\"rawQuery\":\"verbose=1\"", "\"statusCode\":200",
            "\"success\":true", "\"error\":", "\"remoteAddress\":\"203.0.113.10\"", "\"requestBytes\":12",
            "\"responseBytes\":34", "\"elapsedMs\":5", "\"requestContentType\":", "\"responseContentType\":",
            "\"responseBodyType\":\"json\"", "\"requestHeaders\":", "\"responseHeaders\":", "\"requestPreviewHex\":",
            "\"requestPreviewText\":", "\"responsePreviewHex\":", "\"responsePreviewText\":",
            "\"requestTruncated\":false", "\"responseTruncated\":false", "\"capturedAt\":\"2026-07-22T00:00:00Z\""
        };
        len = endpoint_call("GET", path, "alice", "tenant-a", "USER", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", expected_id, "exchange detail for its owner") != 0;
        for (size_t i = 0; !failed && i < sizeof(fields) / sizeof(fields[0]); ++i) {
            if (!contains(response, fields[i])) {
                fprintf(stderr, "exchange detail is missing %s: %s\n", fields[i], response);
                failed = 1;
            }
        }
    }
    if (!failed) {
        len = endpoint_call("GET", path, "root", "tenant-a", "ADMIN", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"clientName\":\"endpoint-alpha\"",
                                 "exchange detail for the tenant administrator") != 0;
    }
    if (!failed) {
        len = endpoint_call("GET", path, "bob", "tenant-a", "USER", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", "HTTP exchange not found",
                                 "exchange detail for another owner") != 0;
    }
    if (!failed) {
        len = endpoint_call("GET", path, "root-b", "tenant-b", "ADMIN", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, "exchange detail from another tenant") != 0;
    }
    if (!failed) {
        snprintf(path, sizeof(path), "/api/admin/traffic/http-exchanges/%lld", charlie_exchange + 1000);
        len = endpoint_call("GET", path, "root", "tenant-a", "ADMIN", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, "unknown exchange detail") != 0;
    }

    /* GET /api/admin/peer-mesh/egress/activity: PeerMeshEgressActivityView[] of the tenant. */
    if (!failed) {
        len = endpoint_call("GET", "/api/admin/peer-mesh/egress/activity", NULL, NULL, NULL, response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 401 ", NULL, "egress activity without token") != 0;
    }
    if (!failed) {
        len = endpoint_call("GET", "/api/admin/peer-mesh/egress/activity", "alice", "tenant-a", "USER",
                            response, sizeof(response));
        failed = endpoint_body_equals(len, response, "[]", "egress activity before any report") != 0;
    }
    failed = failed || endpoint_seed_activity(db_path, "tenant-a", &bravo, 1, "{}") != 0
        || endpoint_seed_activity(db_path, "tenant-a", &alpha, 2, "{\"EGRESS_POLICY_DENIED\":4}") != 0
        || endpoint_seed_activity(db_path, "tenant-b", &charlie, 3, "{}") != 0;
    endpoint_runtime_client_id = alpha.id;
    st_admin_set_client_runtime_status_handler(endpoint_runtime_status, NULL);
    if (!failed) {
        char expected[1024];
        snprintf(expected, sizeof(expected),
            "[{\"egressClientId\":%lld,\"egressClientName\":\"endpoint-alpha\",\"online\":true,\"revision\":3,"
            "\"activeFlows\":2,\"totalFlows\":12,\"rejectedFlows\":{\"EGRESS_POLICY_DENIED\":4},\"bytesIn\":1000,"
            "\"bytesOut\":2000,\"reportedAt\":\"2026-07-22T00:00:00Z\"},"
            "{\"egressClientId\":%lld,\"egressClientName\":\"endpoint-bravo\",\"online\":false,\"revision\":3,"
            "\"activeFlows\":1,\"totalFlows\":11,\"rejectedFlows\":{},\"bytesIn\":1000,"
            "\"bytesOut\":2000,\"reportedAt\":\"2026-07-22T00:00:00Z\"}]", alpha.id, bravo.id);
        /* Every account of the tenant sees the tenant's devices, ordered by name, like Java. */
        len = endpoint_call("GET", "/api/admin/peer-mesh/egress/activity", "bob", "tenant-a", "USER",
                            response, sizeof(response));
        failed = endpoint_body_equals(len, response, expected, "egress activity of the tenant") != 0;
    }
    if (!failed) {
        len = endpoint_call("GET", "/api/admin/peer-mesh/egress/activity", "root-b", "tenant-b", "ADMIN",
                            response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"egressClientName\":\"endpoint-charlie\"",
                                 "egress activity of another tenant") != 0
            || contains(response, "endpoint-alpha") || contains(response, "endpoint-bravo");
        if (failed) fprintf(stderr, "egress activity leaked across tenants: %s\n", response);
    }
    st_admin_set_client_runtime_status_handler(NULL, NULL);
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(db_path);
    return failed ? 1 : 0;
}

/* Like endpoint_call, with a request body. */
static int tenant_scope_call(const char *method, const char *path, const char *username, const char *tenant,
                             const char *role, const char *body, char *out, size_t out_len)
{
    char authorization[2300];
    if (connection_events_bearer(username, tenant, role, authorization, sizeof(authorization)) != 0) {
        return -1;
    }
    return st_admin_build_response_with_auth(method, path, authorization, body, out, out_len);
}

/* The fixture users are stored by connection_events_ensure_user and must still look exactly like that. */
static int tenant_scope_user_unchanged(const char *database_path, const char *username, const char *tenant,
                                       const char *role, const char *label)
{
    st_storage_management_user user;
    int ok = st_storage_get_management_user(database_path, username, &user) == 0
        && strcmp(user.tenant_id, tenant) == 0
        && strcmp(user.role, role) == 0
        && user.enabled
        && strcmp(user.password_hash, "unused-password-hash") == 0;
    if (!ok) fprintf(stderr, "%s: %s/%s was changed or removed\n", label, tenant, username);
    return ok ? 0 : -1;
}

/*
 * An administrator manages the users of its own tenant only. Like Java's
 * ManagementUserService.requireMutableUserInTenant, the target is looked up inside the caller's
 * tenant, so another tenant's user answers exactly like one that does not exist (404) and its row
 * is left as it was; the built-in administrator belongs to its configured tenant and is scoped the
 * same way. Credentials, TCP mappings, HTTP routes and peer services are resolved through their
 * owning client or tenant and must answer another tenant's administrator the same way.
 */
static int test_tenant_scoped_admin_mutations(void)
{
    char db_path[256];
    char path[160];
    char response[32768];
    char missing[32768];
    snprintf(db_path, sizeof(db_path), "/tmp/specus-c-tenant-scope-%ld.db", (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "c-tenant-scope-test-secret", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    unsetenv("SPECUS_AUTH_TENANT_ID");
    unsetenv("SPECUS_AUTH_USERNAME");
    const char *not_found = "{\"error\":\"user not found\"}";
    const char *takeover = "{\"password\":\"taken-over\",\"role\":\"ADMIN\",\"enabled\":false}";
    int failed = st_storage_init(db_path, 0) != 0
        || connection_events_ensure_user("root-a", "tenant-a", "ADMIN") != 0
        || connection_events_ensure_user("carol", "tenant-a", "USER") != 0
        || connection_events_ensure_user("root-b", "tenant-b", "ADMIN") != 0
        || connection_events_ensure_user("dave", "tenant-b", "USER") != 0;
    if (failed) fprintf(stderr, "tenant scope fixture setup failed\n");
    int len = 0;

    /* Another tenant's user cannot be re-passworded, promoted, disabled or deleted, in any spelling. */
    if (!failed) {
        len = tenant_scope_call("PUT", "/api/admin/users/dave", "root-a", "tenant-a", "ADMIN", takeover,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found, "PUT of another tenant's user") != 0
            || tenant_scope_user_unchanged(db_path, "dave", "tenant-b", "USER", "PUT of another tenant's user") != 0;
    }
    if (!failed) {
        len = tenant_scope_call("PUT", "/api/admin/users/%20DAVE%20", "root-a", "tenant-a", "ADMIN", takeover,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found,
                                 "PUT of another tenant's user, other spelling") != 0
            || tenant_scope_user_unchanged(db_path, "dave", "tenant-b", "USER",
                                           "PUT of another tenant's user, other spelling") != 0;
    }
    if (!failed) {
        len = tenant_scope_call("PUT", "/api/admin/users/root-b", "root-a", "tenant-a", "ADMIN",
                                "{\"role\":\"USER\",\"enabled\":false}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found,
                                 "PUT of another tenant's administrator") != 0
            || tenant_scope_user_unchanged(db_path, "root-b", "tenant-b", "ADMIN",
                                           "PUT of another tenant's administrator") != 0;
    }
    if (!failed) {
        len = tenant_scope_call("DELETE", "/api/admin/users/dave", "root-a", "tenant-a", "ADMIN", NULL,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found, "DELETE of another tenant's user") != 0
            || tenant_scope_user_unchanged(db_path, "dave", "tenant-b", "USER", "DELETE of another tenant's user") != 0;
    }
    /* Another tenant's user and a user nobody has are indistinguishable, byte for byte. */
    if (!failed) {
        int missing_len = tenant_scope_call("DELETE", "/api/admin/users/ghost", "root-a", "tenant-a", "ADMIN",
                                            NULL, missing, sizeof(missing));
        len = tenant_scope_call("DELETE", "/api/admin/users/dave", "root-a", "tenant-a", "ADMIN", NULL,
                                response, sizeof(response));
        failed = missing_len <= 0 || len != missing_len || strcmp(response, missing) != 0;
        if (failed) fprintf(stderr, "another tenant's user answered unlike a missing one: %s / %s\n",
                            len > 0 ? response : "(none)", missing_len > 0 ? missing : "(none)");
        missing_len = failed ? -1 : tenant_scope_call("PUT", "/api/admin/users/ghost", "root-a", "tenant-a",
                                                      "ADMIN", takeover, missing, sizeof(missing));
        len = failed ? -1 : tenant_scope_call("PUT", "/api/admin/users/dave", "root-a", "tenant-a", "ADMIN",
                                              takeover, response, sizeof(response));
        if (!failed && (missing_len <= 0 || len != missing_len || strcmp(response, missing) != 0)) {
            fprintf(stderr, "another tenant's user was updated unlike a missing one: %s / %s\n",
                    len > 0 ? response : "(none)", missing_len > 0 ? missing : "(none)");
            failed = 1;
        }
    }
    /* Reads: there is no single-user endpoint, and the list holds the caller's tenant only. */
    if (!failed) {
        len = tenant_scope_call("GET", "/api/admin/users/dave", "root-a", "tenant-a", "ADMIN", NULL,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, "GET of another tenant's user") != 0
            || contains(response, "tenant-b");
        if (failed && len > 0) fprintf(stderr, "GET of another tenant's user leaked it: %s\n", response);
    }
    if (!failed) {
        len = tenant_scope_call("GET", "/api/admin/users", "root-a", "tenant-a", "ADMIN", NULL,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"username\":\"carol\"", "tenant user list") != 0
            || contains(response, "\"username\":\"dave\"") || contains(response, "\"username\":\"root-b\"")
            || contains(response, "tenant-b");
        if (failed && len > 0) fprintf(stderr, "tenant user list leaked another tenant: %s\n", response);
    }
    /* The built-in administrator's tenant is the default one; tenant-b is not its to manage. */
    if (!failed) {
        len = st_admin_build_response_with_body("PUT", "/api/admin/users/dave", takeover, response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found,
                                 "built-in admin PUT of another tenant's user") != 0
            || tenant_scope_user_unchanged(db_path, "dave", "tenant-b", "USER",
                                           "built-in admin PUT of another tenant's user") != 0;
    }
    if (!failed) {
        len = st_admin_build_response("DELETE", "/api/admin/users/dave", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found,
                                 "built-in admin DELETE of another tenant's user") != 0
            || tenant_scope_user_unchanged(db_path, "dave", "tenant-b", "USER",
                                           "built-in admin DELETE of another tenant's user") != 0;
    }
    /* An ordinary user manages no one, not even inside its tenant. */
    if (!failed) {
        len = tenant_scope_call("PUT", "/api/admin/users/carol", "carol", "tenant-a", "USER",
                                "{\"role\":\"ADMIN\"}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 403 ", NULL, "ordinary user PUT") != 0
            || tenant_scope_user_unchanged(db_path, "carol", "tenant-a", "USER", "ordinary user PUT") != 0;
    }
    /* Inside their own tenants both administrators still manage their users. */
    if (!failed) {
        len = tenant_scope_call("PUT", "/api/admin/users/carol", "root-a", "tenant-a", "ADMIN",
                                "{\"role\":\"ADMIN\"}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"tenantId\":\"tenant-a\"", "own tenant PUT") != 0
            || !contains(response, "\"role\":\"ADMIN\"");
    }
    if (!failed) {
        st_storage_management_user gone;
        len = tenant_scope_call("DELETE", "/api/admin/users/carol", "root-a", "tenant-a", "ADMIN", NULL,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 204 ", NULL, "own tenant DELETE") != 0
            || st_storage_get_management_user(db_path, "carol", &gone) == 0;
    }
    if (!failed) {
        len = tenant_scope_call("PUT", "/api/admin/users/dave", "root-b", "tenant-b", "ADMIN",
                                "{\"enabled\":false}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"enabled\":false", "tenant-b PUT") != 0;
        len = failed ? -1 : tenant_scope_call("DELETE", "/api/admin/users/dave", "root-b", "tenant-b", "ADMIN",
                                              NULL, response, sizeof(response));
        failed = failed || endpoint_expect(len, response, "HTTP/1.1 204 ", NULL, "tenant-b DELETE") != 0;
    }

    /* Tenant-b's credential, mapping, route and peer service, as tenant-a's administrator sees them. */
    st_storage_client bravo;
    st_storage_client_credential credential;
    st_storage_mapping mapping;
    st_storage_http_route route;
    st_storage_peer_mesh_service definition;
    st_storage_peer_mesh_service service;
    memset(&bravo, 0, sizeof(bravo));
    memset(&credential, 0, sizeof(credential));
    memset(&mapping, 0, sizeof(mapping));
    memset(&route, 0, sizeof(route));
    memset(&definition, 0, sizeof(definition));
    memset(&service, 0, sizeof(service));
    if (!failed) {
        failed = st_storage_upsert_client(db_path, 0, "tenant-b", "scope-bravo", "root-b", 1, 60, &bravo) != 0
            || st_storage_upsert_client_credential(db_path, 0, "tenant-b", "root-b", "ck-scope-bravo",
                   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 1, 3, &credential) != 0
            || st_storage_create_mapping_for_client(db_path, bravo.id, 18090, "127.0.0.1", 8090, 1, 0, &mapping) != 0
            || st_storage_create_http_route_for_client(db_path, bravo.id, "scope-api", "http://127.0.0.1:8090",
                                                       1, 0, 0, 0, 0, 0, NULL, NULL, &route) != 0;
        if (!failed) {
            snprintf(definition.tenant_id, sizeof(definition.tenant_id), "tenant-b");
            definition.client_id = bravo.id;
            snprintf(definition.client_name, sizeof(definition.client_name), "%s", bravo.client_name);
            snprintf(definition.service_id, sizeof(definition.service_id), "svc-scope-bravo");
            snprintf(definition.name, sizeof(definition.name), "bravo-ssh");
            snprintf(definition.transport, sizeof(definition.transport), "tcp");
            snprintf(definition.application, sizeof(definition.application), "ssh");
            snprintf(definition.target_host, sizeof(definition.target_host), "127.0.0.1");
            definition.target_port = 22;
            definition.published_port = 2222;
            definition.enabled = 1;
            snprintf(definition.visibility, sizeof(definition.visibility), "OWNER");
            failed = st_storage_upsert_peer_mesh_service(db_path, &definition, &service) != 0;
        }
        if (failed) fprintf(stderr, "tenant scope resource fixture setup failed\n");
    }
    struct {
        const char *prefix;
        long long id;
        const char *body;
        const char *label;
    } resources[] = {
        {"/api/admin/client-credentials/", 0, "{\"enabled\":false,\"secret\":\"taken-over\"}", "credential"},
        {"/api/admin/specus-mappings/", 0, "{\"targetPort\":9999}", "TCP mapping"},
        {"/api/admin/http-routes/", 0, "{\"targetBaseUrl\":\"http://203.0.113.9\"}", "HTTP route"},
        {"/api/admin/peer-mesh/services/", 0, "{\"name\":\"taken-over\",\"enabled\":false}", "peer service"},
    };
    resources[0].id = credential.id;
    resources[1].id = mapping.id;
    resources[2].id = route.id;
    resources[3].id = service.id;
    for (size_t i = 0; !failed && i < sizeof(resources) / sizeof(resources[0]); ++i) {
        char label[96];
        snprintf(path, sizeof(path), "%s%lld", resources[i].prefix, resources[i].id);
        snprintf(label, sizeof(label), "PUT of another tenant's %s", resources[i].label);
        len = tenant_scope_call("PUT", path, "root-a", "tenant-a", "ADMIN", resources[i].body,
                                response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, label) != 0;
        snprintf(label, sizeof(label), "DELETE of another tenant's %s", resources[i].label);
        len = failed ? -1 : tenant_scope_call("DELETE", path, "root-a", "tenant-a", "ADMIN", NULL,
                                              response, sizeof(response));
        failed = failed || endpoint_expect(len, response, "HTTP/1.1 404 ", NULL, label) != 0;
    }
    if (!failed) {
        st_storage_client_credential stored_credential;
        st_storage_mapping stored_mapping;
        st_storage_http_route stored_route;
        st_storage_peer_mesh_service stored_service;
        failed = st_storage_get_client_credential(db_path, credential.id, &stored_credential) != 0
            || !stored_credential.enabled
            || strcmp(stored_credential.secret_hash, credential.secret_hash) != 0
            || st_storage_get_mapping(db_path, mapping.id, &stored_mapping) != 0
            || stored_mapping.target_port != 8090
            || st_storage_get_http_route(db_path, route.id, &stored_route) != 0
            || strcmp(stored_route.target_base_url, "http://127.0.0.1:8090") != 0
            || st_storage_get_peer_mesh_service_visible(db_path, service.id, "tenant-b", "", 1,
                                                        &stored_service) != 0
            || strcmp(stored_service.name, "bravo-ssh") != 0
            || !stored_service.enabled;
        if (failed) fprintf(stderr, "another tenant's administrator changed tenant-b resources\n");
    }
    /* The fixture is real: tenant-b's own administrator reaches every one of them. */
    for (size_t i = 0; !failed && i < sizeof(resources) / sizeof(resources[0]); ++i) {
        char label[96];
        snprintf(path, sizeof(path), "%s%lld", resources[i].prefix, resources[i].id);
        snprintf(label, sizeof(label), "own tenant DELETE of the %s", resources[i].label);
        len = tenant_scope_call("DELETE", path, "root-b", "tenant-b", "ADMIN", NULL, response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 204 ", NULL, label) != 0;
    }
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(db_path);
    return failed ? 1 : 0;
}

/* "name|reason" of each client the management API asked to close in the last call. */
static char client_close_calls[4][160];
static size_t client_close_call_count = 0U;

static int record_client_close(void *ctx, const char *client_name, const char *reason)
{
    (void)ctx;
    if (client_close_call_count < sizeof(client_close_calls) / sizeof(client_close_calls[0])) {
        snprintf(client_close_calls[client_close_call_count], sizeof(client_close_calls[0]), "%s|%s",
                 client_name, reason);
    }
    ++client_close_call_count;
    return 0;
}

/* One client mutation by tenant-a's administrator: its status and the one close it asks for, or none. */
static int client_mutation_closes(const char *method, const char *path, const char *body, const char *status,
                                  const char *expected_close, const char *label)
{
    char response[16384];
    client_close_call_count = 0U;
    int len = tenant_scope_call(method, path, "root-a", "tenant-a", "ADMIN", body, response, sizeof(response));
    if (endpoint_expect(len, response, status, NULL, label) != 0) {
        return -1;
    }
    int ok = expected_close == NULL
        ? client_close_call_count == 0U
        : client_close_call_count == 1U && strcmp(client_close_calls[0], expected_close) == 0;
    if (!ok) {
        fprintf(stderr, "%s: %zu close(s), the first %s; expected %s\n", label, client_close_call_count,
                client_close_call_count > 0U ? client_close_calls[0] : "(none)",
                expected_close == NULL ? "none" : expected_close);
    }
    return ok ? 0 : -1;
}

/*
 * Disabling, renaming or deleting a client closes its online connections on the transitions Go's
 * management API kicks on, with Go's reasons: disabled from enabled, or renamed while disabled
 * (ADMIN_DISABLED), renamed (ADMIN_RENAMED), deleted (ADMIN_DELETED). The connections are named
 * by the client's name before the change. Other updates and refused mutations close nothing.
 */
static int test_client_mutations_close_connections(void)
{
    char db_path[256];
    char path[160];
    snprintf(db_path, sizeof(db_path), "/tmp/specus-c-client-close-%ld.db", (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "c-client-close-test-secret", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    unsetenv("SPECUS_AUTH_TENANT_ID");
    unsetenv("SPECUS_AUTH_USERNAME");
    st_storage_client alpha;
    st_storage_client foreign;
    int failed = st_storage_init(db_path, 0) != 0
        || connection_events_ensure_user("root-a", "tenant-a", "ADMIN") != 0
        || connection_events_ensure_user("root-b", "tenant-b", "ADMIN") != 0
        || st_storage_upsert_client(db_path, 0, "tenant-a", "close-alpha", "root-a", 1, 30, &alpha) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-b", "close-foreign", "root-b", 1, 30, &foreign) != 0;
    if (failed) fprintf(stderr, "client close fixture setup failed\n");
    st_admin_set_client_disconnect_handler(record_client_close, NULL);
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", alpha.id);
    failed = failed
        || client_mutation_closes("PUT", path, "{\"connectionRateLimitPerMinute\":40}", "HTTP/1.1 200 ", NULL,
                                  "rate limit change") != 0
        || client_mutation_closes("PUT", path, "{\"enabled\":false}", "HTTP/1.1 200 ",
                                  "close-alpha|ADMIN_DISABLED", "disable") != 0
        || client_mutation_closes("PUT", path, "{\"enabled\":false}", "HTTP/1.1 200 ", NULL,
                                  "disable an already disabled client") != 0
        || client_mutation_closes("PUT", path, "{\"enabled\":true}", "HTTP/1.1 200 ", NULL, "enable") != 0
        || client_mutation_closes("PUT", path, "{\"clientName\":\"close-alpha-2\"}", "HTTP/1.1 200 ",
                                  "close-alpha|ADMIN_RENAMED", "rename") != 0
        || client_mutation_closes("PUT", path, "{\"clientName\":\"close-alpha-3\",\"enabled\":false}",
                                  "HTTP/1.1 200 ", "close-alpha-2|ADMIN_DISABLED", "rename and disable") != 0
        || client_mutation_closes("PUT", path, "{\"clientName\":\"close-alpha-4\"}", "HTTP/1.1 200 ",
                                  "close-alpha-3|ADMIN_DISABLED", "rename while disabled") != 0;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", foreign.id);
    failed = failed
        || client_mutation_closes("PUT", path, "{\"enabled\":false}", "HTTP/1.1 404 ", NULL,
                                  "disable another tenant's client") != 0
        || client_mutation_closes("DELETE", path, NULL, "HTTP/1.1 404 ", NULL, "delete another tenant's client") != 0;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", alpha.id);
    failed = failed
        || client_mutation_closes("DELETE", path, NULL, "HTTP/1.1 204 ", "close-alpha-4|ADMIN_DELETED", "delete") != 0
        || client_mutation_closes("DELETE", path, NULL, "HTTP/1.1 404 ", NULL, "delete a deleted client") != 0;
    st_admin_set_client_disconnect_handler(NULL, NULL);
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(db_path);
    return failed ? 1 : 0;
}

/* The connectivity check device for the endpoint test: online and refused by its target, or offline. */
static int connectivity_test_online;

static void connectivity_test_presence(void *ctx, const char *client_name, int *control_online, int *data_online)
{
    (void)ctx;
    (void)client_name;
    *control_online = connectivity_test_online;
    *data_online = connectivity_test_online;
}

static void connectivity_test_probe(void *ctx, const char *client_name, const char *metadata_json,
                                    long long timeout_ms, st_connectivity_probe_answer *answer)
{
    (void)ctx;
    (void)client_name;
    (void)metadata_json;
    (void)timeout_ms;
    memset(answer, 0, sizeof(*answer));
    answer->kind = ST_CONNECTIVITY_PROBE_RESET;
    answer->capability = 1;
    snprintf(answer->failure, sizeof(answer->failure), "connect-refused");
}

static void connectivity_test_log(void *ctx, const char *line)
{
    (void)ctx;
    (void)line;
}

static int connectivity_call(const char *path, const char *username, const char *tenant, const char *role,
                             const char *body, char *out, size_t out_len)
{
    char authorization[2300];
    if (username != NULL
        && connection_events_bearer(username, tenant, role, authorization, sizeof(authorization)) != 0) {
        return -1;
    }
    return st_admin_build_response_with_auth("POST", path, username == NULL ? NULL : authorization, body,
                                             out, out_len);
}

/*
 * POST /api/admin/http-routes/{id}/connectivity-check: unknown, foreign and not-owned routes all
 * answer the same 404, the body is checked first, every answer is private and uncacheable, and a
 * result never names the target.
 */
static int test_connectivity_check_endpoint(void)
{
    char db_path[256];
    char path[160];
    char response[32768];
    snprintf(db_path, sizeof(db_path), "/tmp/specus-c-connectivity-%ld.db", (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "c-admin-endpoint-test-secret", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    st_storage_client alpha, bravo, charlie;
    st_storage_http_route offline_route, refused_route;
    int failed = st_storage_init(db_path, 0) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-a", "check-alpha", "alice", 1, 60, &alpha) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-a", "check-bravo", "bob", 1, 60, &bravo) != 0
        || st_storage_upsert_client(db_path, 0, "tenant-b", "check-charlie", "alice", 1, 60, &charlie) != 0
        || st_storage_create_http_route_for_client(db_path, alpha.id, "offline", "http://10.20.30.40:8080/base",
                                                   1, 0, 0, 0, 0, 0, "", "", &offline_route) != 0
        || st_storage_create_http_route_for_client(db_path, alpha.id, "refused", "http://10.20.30.40:9/",
                                                   1, 0, 0, 0, 0, 0, "", "", &refused_route) != 0
        /* Tokens are re-resolved against the user table, so the callers below have to exist. */
        || connection_events_ensure_user("alice", "tenant-a", "USER") != 0
        || connection_events_ensure_user("bob", "tenant-a", "USER") != 0
        || connection_events_ensure_user("root", "tenant-a", "ADMIN") != 0
        || connection_events_ensure_user("root-b", "tenant-b", "ADMIN") != 0;
    if (failed) fprintf(stderr, "connectivity fixture setup failed\n");
    st_connectivity_device device = {connectivity_test_presence, connectivity_test_probe, NULL,
                                     connectivity_test_log, NULL};
    st_admin_set_connectivity_device(&device);
    connectivity_test_online = 0;
    int len = 0;
    const char *not_found = "{\"code\":\"CHECK_TARGET_NOT_FOUND\"}";

    snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/connectivity-check", offline_route.id);
    if (!failed) {
        len = connectivity_call(path, NULL, NULL, NULL, "{}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 401 ", "Cache-Control: private, no-store",
                                 "connectivity check without token") != 0;
    }
    if (!failed) {
        len = connectivity_call(path, "alice", "tenant-a", "USER", "{\"path\":\"/../etc\"}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 400 ", "{\"code\":\"CHECK_REQUEST_INVALID\"}",
                                 "connectivity check invalid path") != 0;
    }
    if (!failed) {
        len = connectivity_call(path, "alice", "tenant-a", "USER", "{\"tenantId\":\"tenant-b\"}", response,
                                sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 400 ", NULL, "connectivity check unknown field") != 0;
    }
    /* Not the owner, another tenant's admin, an unknown id and a malformed id: one answer. */
    if (!failed) {
        len = connectivity_call(path, "bob", "tenant-a", "USER", "", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found, "connectivity check not owner") != 0;
    }
    if (!failed) {
        len = connectivity_call(path, "root-b", "tenant-b", "ADMIN", "", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found, "connectivity check other tenant") != 0;
    }
    if (!failed) {
        len = connectivity_call("/api/admin/http-routes/987654321/connectivity-check", "alice", "tenant-a", "USER",
                                "", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found, "connectivity check unknown route") != 0;
    }
    if (!failed) {
        len = connectivity_call("/api/admin/http-routes/abc/connectivity-check", "alice", "tenant-a", "USER",
                                "", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 404 ", not_found, "connectivity check malformed id") != 0;
    }
    /* The owner's check of an offline device runs and stops at the device stage. */
    if (!failed) {
        len = connectivity_call(path, "alice", "tenant-a", "USER", "{\"path\":\"/healthz\"}", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"code\":\"DEVICE_OFFLINE\"", "connectivity check offline") != 0
            || endpoint_expect(len, response, "HTTP/1.1 200 ", "Cache-Control: private, no-store", "connectivity cache") != 0
            || endpoint_expect(len, response, "HTTP/1.1 200 ", "\"stoppedAt\":\"device-online\"", "connectivity stage") != 0
            || contains(response, "10.20.30.40") || contains(response, "healthz");
    }
    /* The route key is shared by every caller: an admin of the tenant waits as well. */
    if (!failed) {
        len = connectivity_call(path, "root", "tenant-a", "ADMIN", "", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 429 ", "Retry-After: 10\r\n", "connectivity rate limit") != 0
            || endpoint_expect(len, response, "HTTP/1.1 429 ", "{\"code\":\"CHECK_RATE_LIMITED\"}", "connectivity rate code") != 0;
    }
    /* A capable device's classified reset decides the target stage; nothing of its reason leaks. */
    if (!failed) {
        connectivity_test_online = 1;
        snprintf(path, sizeof(path), "/api/admin/http-routes/%lld/connectivity-check", refused_route.id);
        len = connectivity_call(path, "alice", "tenant-a", "USER", "", response, sizeof(response));
        failed = endpoint_expect(len, response, "HTTP/1.1 200 ", "\"code\":\"TARGET_CONNECT_REFUSED\"",
                                 "connectivity check refused target") != 0
            || endpoint_expect(len, response, "HTTP/1.1 200 ", "\"requests\":[\"HEAD\"]", "connectivity requests") != 0;
    }
    st_admin_set_connectivity_device(NULL);
    unsetenv("SPECUS_DB_SEED_DEMO_CLIENT");
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(db_path);
    (void)bravo;
    (void)charlie;
    return failed ? 1 : 0;
}

static long long route_auth_exchange_count(const char *database_path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    long long count = -1;
    if (sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM specus_http_traffic_exchange WHERE route = 'api'", -1,
                              &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        count = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return count;
}

static int route_auth_detail_is_sanitized(const char *database_path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int result = -1;
    if (sqlite3_open(database_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db,
                              "SELECT request_headers FROM specus_http_traffic_exchange "
                              "WHERE route = 'api' ORDER BY id DESC LIMIT 1",
                              -1,
                              &stmt,
                              NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *headers = (const char *)sqlite3_column_text(stmt, 0);
        result = headers == NULL || strstr(headers, "Authorization:") == NULL ? 0 : -1;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return result;
}

static int test_log_safe_reason(void)
{
    char safe[2048];
    /* CR/LF/TAB/backslash, C0 NUL-free control, DEL, C1 (U+0085), U+2028, invalid UTF-8. */
    st_admin_log_safe_reason("a\r\nb\tc\x01" "d\x7f" "e\xc2\x85" "f\xe2\x80\xa8" "g\\h\xff" "\xe7\x95\x8c",
                             safe,
                             sizeof(safe));
    if (strcmp(safe, "a\\r\\nb\\tc\\u0001d\\u007fe\\u0085f\\u2028g\\\\h\\xff\xe7\x95\x8c") != 0) {
        fprintf(stderr, "log-safe reason escaping mismatch: %s\n", safe);
        return 1;
    }
    char long_reason[400];
    memset(long_reason, 'x', sizeof(long_reason) - 1U);
    long_reason[sizeof(long_reason) - 1U] = '\0';
    size_t written = st_admin_log_safe_reason(long_reason, safe, sizeof(safe));
    if (written != ST_ADMIN_LOG_REASON_MAX_CODE_POINTS + strlen("...(truncated)")
        || strncmp(safe + ST_ADMIN_LOG_REASON_MAX_CODE_POINTS, "...(truncated)", 15U) != 0) {
        fprintf(stderr, "log-safe reason truncation mismatch: %s\n", safe);
        return 1;
    }
    char tiny[8];
    if (st_admin_log_safe_reason("abc\r\ndefgh", tiny, sizeof(tiny)) >= sizeof(tiny)
        || strcmp(tiny, "abc\\r\\n") != 0
        || st_admin_log_safe_reason(NULL, tiny, sizeof(tiny)) != 0U || tiny[0] != '\0') {
        fprintf(stderr, "log-safe reason bounds mismatch: %s\n", tiny);
        return 1;
    }
    return 0;
}

/* Sends one request and checks its status and how many HTTP/WS dispatches it caused. */
static int route_auth_expect(int port,
                             route_auth_test_context *context,
                             const char *label,
                             const char *request,
                             const char *status,
                             int http_calls,
                             int ws_calls,
                             int authorization_headers)
{
    char response[8192];
    route_auth_test_context_reset(context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, status)
        || !route_auth_test_context_matches(context, http_calls, ws_calls, authorization_headers)) {
        fprintf(stderr, "%s: want %s and %d/%d dispatches, got %.160s\n",
                label, status, http_calls, ws_calls, response);
        return -1;
    }
    return 0;
}

/*
 * The fake dispatcher forwards every route it is handed, the way a client still holding a stale
 * route list would, so only the server's own records may decide what gets through. Leaves
 * SPECUS_HTTP_ROUTES set and may leave SPECUS_DATABASE_PATH unset; the caller restores both.
 */
static int test_direct_http_route_fails_closed(const char *database_path,
                                               int port,
                                               route_auth_test_context *context,
                                               const st_storage_http_route *protected_route)
{
    static const char doomed_get[] =
        "GET /http/C%20managed%202/doomed/secret HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char doomed_ws[] =
        "GET /http/C%20managed%202/doomed/socket HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
        "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    static const char never_created[] =
        "GET /http/C%20managed%202/never-created/ HTTP/1.1\r\nHost: localhost\r\n\r\n";
    static const char protected_with_credentials[] =
        "GET /http/C%20managed%202/api/items HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n";

    st_storage_client managed;
    st_storage_client changed;
    st_storage_http_route doomed;
    if (st_storage_get_client_by_name(database_path, "C managed 2", &managed) != 0
        || st_storage_create_http_route_for_client(database_path, managed.id, "doomed",
                                                   "http://127.0.0.1:8080", 1, 0, 0, 0, 0, 1,
                                                   protected_route->auth_username,
                                                   protected_route->auth_password_hash,
                                                   &doomed) != 0) {
        fprintf(stderr, "fail-closed route fixture failed\n");
        return -1;
    }
    /* A protected route deleted while the client still forwards it is refused, never anonymous. */
    if (route_auth_expect(port, context, "protected route before delete", doomed_get,
                          "401 Unauthorized", 0, 0, 0) != 0
        || st_storage_delete_http_route_by_id(database_path, doomed.id) != 0
        || route_auth_expect(port, context, "deleted protected route", doomed_get,
                             "404 Not Found", 0, 0, 0) != 0
        || route_auth_expect(port, context, "deleted protected websocket route", doomed_ws,
                             "404 Not Found", 0, 0, 0) != 0
        || route_auth_expect(port, context, "route never created", never_created,
                             "404 Not Found", 0, 0, 0) != 0
        || route_auth_expect(port, context, "path without a route",
                             "GET /http/C%20managed%202 HTTP/1.1\r\nHost: localhost\r\n\r\n",
                             "404 Not Found", 0, 0, 0) != 0) {
        return -1;
    }

    /* Every route of a disabled client is refused, valid credentials or not. */
    int disabled = st_storage_upsert_client(database_path, managed.id, managed.tenant_id, managed.client_name,
                                            managed.owner_username, 0, managed.connection_rate_limit_per_minute,
                                            &changed) == 0
        && route_auth_expect(port, context, "protected route of a disabled client", protected_with_credentials,
                             "404 Not Found", 0, 0, 0) == 0;
    int restored = st_storage_upsert_client(database_path, managed.id, managed.tenant_id, managed.client_name,
                                            managed.owner_username, 1, managed.connection_rate_limit_per_minute,
                                            &changed) == 0;
    if (!disabled || !restored
        || route_auth_expect(port, context, "protected route of a re-enabled client", protected_with_credentials,
                             "200 OK", 1, 0, 0) != 0) {
        return -1;
    }

    /* SPECUS_HTTP_ROUTES entries are server-defined and public, for an enabled account with a
     * database and for anyone without one; any other route stays refused. */
    setenv("SPECUS_HTTP_ROUTES", "envapi=http://127.0.0.1:8080", 1);
    static const char env_route[] =
        "GET /http/C%20managed%202/envapi/items HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n";
    static const char env_route_unknown_client[] =
        "GET /http/Env/envapi/items HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n";
    static const char not_env_route[] =
        "GET /http/Env/api/items HTTP/1.1\r\nHost: localhost\r\n\r\n";
    if (route_auth_expect(port, context, "environment route with a database", env_route,
                          "200 OK", 1, 0, 1) != 0
        || route_auth_expect(port, context, "environment route of a client without an account",
                             env_route_unknown_client, "404 Not Found", 0, 0, 0) != 0) {
        return -1;
    }
    unsetenv("SPECUS_DATABASE_PATH");
    if (route_auth_expect(port, context, "database-free environment route", env_route_unknown_client,
                          "200 OK", 1, 0, 1) != 0
        || route_auth_expect(port, context, "database-free route outside the environment list", not_env_route,
                             "404 Not Found", 0, 0, 0) != 0) {
        return -1;
    }
    return 0;
}

static int test_direct_http_route_authentication(const char *database_path)
{
    route_auth_test_context context;
    memset(&context, 0, sizeof(context));
    if (pthread_mutex_init(&context.lock, NULL) != 0) {
        return 1;
    }
    static st_admin_server server;
    int port = 0;
    if (route_auth_start_server(&server, &context, &port) != 0) {
        fprintf(stderr, "route auth test server start failed\n");
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    char response[8192];
    const char *protected_path = "/http/C%20managed%202/api/items";
    char request[2048];
    snprintf(request,
             sizeof(request),
             "POST %s HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000000\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "401 Unauthorized")
        || !contains(response,
                     "WWW-Authenticate: Basic realm=\"Specus HTTP Route\", charset=\"UTF-8\"")
        || !route_auth_test_context_matches(&context, 0, 0, 0)) {
        fprintf(stderr, "protected route missing basic credentials mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "GET %s HTTP/1.1\r\nHost: localhost\r\n"
             "Authorization: Basic dmlzaXRvcjp3cm9uZw==\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "401 Unauthorized")
        || !route_auth_test_context_matches(&context, 0, 0, 0)) {
        fprintf(stderr, "protected route invalid basic credentials mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    /* TrafficInspectionServiceTests: the route's detailCaptureEnabled is on, but without
     * SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED (Java's capture-detail-enabled, default false) nothing
     * is captured. */
    long long captured_before = route_auth_exchange_count(database_path);
    unsetenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");
    snprintf(request,
             sizeof(request),
             "GET %s HTTP/1.1\r\nHost: localhost\r\nAuthorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    int uncaptured = route_auth_http_roundtrip(port, request, response, sizeof(response));
    setenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", "true", 1);
    if (uncaptured != 0 || !contains(response, "200 OK") || captured_before < 0
        || route_auth_exchange_count(database_path) != captured_before) {
        fprintf(stderr, "HTTP detail captured with SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED unset\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "GET %s HTTP/1.1\r\nHost: localhost\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n"
             "Accept-Encoding:   identity \t\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")
        || !contains(response, "forwarded")
        || !route_auth_test_context_matches(&context, 1, 0, 0)
        || context.normalized_accept_encoding_headers != 1
        || route_auth_exchange_count(database_path) != captured_before + 1
        || route_auth_detail_is_sanitized(database_path) != 0) {
        fprintf(stderr, "protected route successful auth or authorization stripping mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    /* The path after the route keeps its percent-encoding: "+" is not a space and "%2F" is not
     * a separator there, so decoding it would send the app a different path. */
    snprintf(request,
             sizeof(request),
             "GET %s/a+b/c%%20d/%%E4%%BD%%A0/x%%2Fy?template={0}&encoded=%%7B1%%7D HTTP/1.1\r\n"
             "Host: localhost\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")
        || !route_auth_test_context_matches(&context, 1, 0, 0)
        || !route_auth_test_queries_match(&context, "template=%7B0%7D&encoded=%7B1%7D", "")
        || !route_auth_test_paths_match(&context, "/items/a+b/c%20d/%E4%BD%A0/x%2Fy", "")) {
        fprintf(stderr, "direct HTTP raw path or query brace encoding mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    /* Java UpstreamBrowserHeaders: the device sees the browser's Origin and Referer moved onto the
     * route target's origin (https://example.com here) and cross-site fetch metadata as
     * same-origin, so the target's own CSRF fences accept the request. */
    static const char browser_headers[] =
        "Origin: https://specus.example\r\n"
        "Referer: https://specus.example/http/C%20managed%202/api/page?x=1\r\n"
        "Sec-Fetch-Site: cross-site\r\n";
    static const char rewritten_browser_headers[] =
        "Origin:https://example.com|Referer:https://example.com/http/C%20managed%202/api/page?x=1"
        "|Sec-Fetch-Site:same-origin";
    snprintf(request,
             sizeof(request),
             "GET %s HTTP/1.1\r\nHost: localhost\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n%s\r\n",
             protected_path,
             browser_headers);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")
        || !route_auth_test_context_matches(&context, 1, 0, 0)
        || strcmp(context.http_browser_headers, rewritten_browser_headers) != 0) {
        fprintf(stderr, "direct HTTP browser headers were not moved onto the route target: %s\n",
                context.http_browser_headers);
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    /* A chunked body reaches the target decoded (extensions and trailers dropped); a chunked
     * body that also declares a length, or that ends early, never reaches it. */
    static const char *const chunked_requests[][2] = {
        {"Transfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n7\r\n, world\r\n0\r\nX-Sum: 1\r\n\r\n",
         "200 OK"},
        {"Transfer-Encoding: chunked\r\nContent-Length: 10\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
         "400 Bad Request"},
        {"Transfer-Encoding: chunked\r\n\r\n5\r\nhel", "400 Bad Request"},
        {"Transfer-Encoding: gzip\r\n\r\nxx", "501 Not Implemented"},
    };
    for (size_t i = 0; i < sizeof(chunked_requests) / sizeof(chunked_requests[0]); ++i) {
        /* PUT, because the traffic detail test later counts the POST exchanges in this database. */
        snprintf(request,
                 sizeof(request),
                 "PUT %s HTTP/1.1\r\nHost: localhost\r\n"
                 "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n%s",
                 protected_path,
                 chunked_requests[i][0]);
        route_auth_test_context_reset(&context);
        int forwarded = i == 0;
        if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
            || !contains(response, chunked_requests[i][1])
            || !route_auth_test_context_matches(&context, forwarded, 0, 0)
            || (forwarded && strcmp(context.http_body, "hello, world") != 0)) {
            fprintf(stderr, "direct HTTP chunked request %zu mismatch: %s\n", i, response);
            route_auth_stop_server(&server);
            pthread_mutex_destroy(&context.lock);
            return 1;
        }
    }

    snprintf(request,
             sizeof(request),
             "GET /http/C%%20managed%%202/api/upstream-reset?token=s3cret&user=root HTTP/1.1\r\n"
             "Host: localhost\r\nAuthorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n");
    route_auth_test_context_reset(&context);
    FILE *log_capture = NULL;
    int saved_stderr = -1;
    char logged[4096];
    if (stderr_capture_begin(&log_capture, &saved_stderr) != 0) {
        fprintf(stderr, "direct HTTP reset log capture setup failed\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    int reset_roundtrip = route_auth_http_roundtrip(port, request, response, sizeof(response));
    stderr_capture_end(log_capture, saved_stderr, logged, sizeof(logged));
    if (reset_roundtrip != 0
        || !contains(response, "502 Bad Gateway")
        || !contains(response, "{\"error\":\"" ST_ADMIN_DIRECT_HTTP_RESET_BODY "\"}")
        || contains(response, "offline")
        || contains(response, "10.20.30.40")
        || contains(response, "s3cret")
        || contains(response, "http://")
        || contains(response, "X-Forged")
        || !route_auth_test_context_matches(&context, 1, 0, 0)) {
        fprintf(stderr, "direct HTTP client reset leaked its reason or lost the 502: %s\n", response);
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    if (!contains(logged, "stream reset")
        || !contains(logged, "http://10.20.30.40:8080/admin/internal?token=s3cret&user=root")
        || !contains(logged, "refused\\r\\nX-Forged: yes")
        || contains(logged, "\r")) {
        fprintf(stderr, "direct HTTP client reset reason was not logged escaped: %s\n", logged);
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "GET %s?channel={0} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
             "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "401 Unauthorized")
        || !route_auth_test_context_matches(&context, 0, 0, 0)) {
        fprintf(stderr, "protected websocket missing basic credentials mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "GET %s/a+b/%%E4%%BD%%A0?channel={0} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
             "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n%s\r\n",
             protected_path,
             browser_headers);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "404 Not Found")
        || !route_auth_test_context_matches(&context, 0, 1, 0)
        || !route_auth_test_queries_match(&context, "", "channel=%7B0%7D")
        || !route_auth_test_paths_match(&context, "", "/items/a+b/%E4%BD%A0")
        || strcmp(context.ws_browser_headers, rewritten_browser_headers) != 0) {
        fprintf(stderr, "protected websocket successful auth or authorization stripping mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    st_storage_http_route route;
    st_storage_http_route changed;
    if (st_storage_get_http_route_by_client_route(database_path, "C managed 2", "api", &route) != 0
        || st_storage_update_http_route_by_id(database_path,
                                              route.id,
                                              route.route,
                                              route.target_base_url,
                                              0,
                                              route.detail_capture_enabled,
                                              route.media_capture_enabled,
                                              route.path_rewrite_enabled,
                                              route.insecure_skip_verify,
                                              route.auth_enabled,
                                              route.auth_username,
                                              route.auth_password_hash,
                                              &changed) != 0) {
        fprintf(stderr, "protected route disable fixture failed\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "404 Not Found")
        || !route_auth_test_context_matches(&context, 0, 0, 0)) {
        fprintf(stderr, "disabled database route should fail before websocket dispatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    if (st_storage_update_http_route_by_id(database_path,
                                           route.id,
                                           route.route,
                                           route.target_base_url,
                                           route.enabled,
                                           route.detail_capture_enabled,
                                           route.media_capture_enabled,
                                           route.path_rewrite_enabled,
                                           route.insecure_skip_verify,
                                           route.auth_enabled,
                                           route.auth_username,
                                           route.auth_password_hash,
                                           &changed) != 0
        || st_storage_update_http_route_by_id(database_path,
                                              route.id,
                                              route.route,
                                              route.target_base_url,
                                              route.enabled,
                                              route.detail_capture_enabled,
                                              route.media_capture_enabled,
                                              route.path_rewrite_enabled,
                                              route.insecure_skip_verify,
                                              1,
                                              route.auth_username,
                                              "",
                                              &changed) != 0) {
        fprintf(stderr, "protected route malformed policy fixture failed\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "503 Service Unavailable")
        || !contains(response, "Cache-Control: no-store")
        || !route_auth_test_context_matches(&context, 0, 0, 0)) {
        fprintf(stderr, "malformed protected route policy should fail closed\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    if (st_storage_update_http_route_by_id(database_path,
                                           route.id,
                                           route.route,
                                           route.target_base_url,
                                           route.enabled,
                                           route.detail_capture_enabled,
                                           route.media_capture_enabled,
                                           route.path_rewrite_enabled,
                                           route.insecure_skip_verify,
                                           route.auth_enabled,
                                           route.auth_username,
                                           route.auth_password_hash,
                                           &changed) != 0) {
        fprintf(stderr, "protected route policy restore failed\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    setenv("SPECUS_DATABASE_PATH", "/tmp", 1);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "503 Service Unavailable")
        || !contains(response, "Cache-Control: no-store")
        || !route_auth_test_context_matches(&context, 0, 0, 0)) {
        fprintf(stderr, "route auth database failure should fail closed\n");
        setenv("SPECUS_DATABASE_PATH", database_path, 1);
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    setenv("SPECUS_DATABASE_PATH", database_path, 1);
    int closed_ok = test_direct_http_route_fails_closed(database_path, port, &context, &route);
    unsetenv("SPECUS_HTTP_ROUTES");
    setenv("SPECUS_DATABASE_PATH", database_path, 1);
    route_auth_stop_server(&server);
    pthread_mutex_destroy(&context.lock);
    return closed_ok == 0 ? 0 : 1;
}

/*
 * The egress policy endpoint end to end. The rule-by-rule semantics are replayed from the shared
 * vector in peer_egress_tests; what is checked here is that a refused list refuses the whole
 * request, so neither the rules nor any other field of it is saved.
 */
static int test_peer_mesh_egress_policy_validation(int egress_client_id)
{
    static const char *const path = "/api/admin/peer-mesh/egress/policies";
    static const char *const stored =
        "\"destinationRules\":[{\"cidr\":\"10.0.0.0/8\",\"protocols\":[\"tcp\",\"udp\"],"
        "\"portRanges\":[[80,80],[8000,8100]]},"
        "{\"cidr\":\"198.51.100.0/24\",\"protocols\":[],\"portRanges\":[]}]";
    char response[16384];
    char body[1024];
    snprintf(body, sizeof(body),
             "{\"egressClientId\":%d,\"maxConcurrentFlows\":10,\"destinationRules\":["
             "{\"cidr\":\" 10.0.0.0/8 \",\"protocols\":[\" TCP \",\"udp\",\"tcp\"],"
             "\"portRanges\":[[80,80],[8000,8100]]},{\"cidr\":\"198.51.100.0/24\"}]}",
             egress_client_id);
    int len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
    int policy_id = 0;
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, stored)
        || !contains(response, "\"maxConcurrentFlows\":10")
        || !contains(response, "\"domainRules\":[]")
        || st_json_get_int(response, "id", &policy_id) != 0 || policy_id <= 0) {
        fprintf(stderr, "egress policy save did not store the normalised rules: %s\n", response);
        return 1;
    }

    static const char *const refused_rules[] = {
        "[{\"cidr\":\"203.0.113.07\"}]",
        "[{\"cidr\":\"10.0.0.0/8\",\"protocols\":[\"icmp\"]}]",
        "[{\"cidr\":\"10.0.0.0/8\",\"portRanges\":[[443,80]]}]",
        "[{\"protocols\":[\"tcp\"]}]",
    };
    for (size_t i = 0; i < sizeof(refused_rules) / sizeof(refused_rules[0]); ++i) {
        snprintf(body, sizeof(body),
                 "{\"egressClientId\":%d,\"maxConcurrentFlows\":20,\"destinationRules\":%s}",
                 egress_client_id, refused_rules[i]);
        len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
        if (len <= 0 || !contains(response, "400 Bad Request")
            || !contains(response, "invalid destinationRules")) {
            fprintf(stderr, "egress policy accepted %s: %s\n", refused_rules[i], response);
            return 1;
        }
    }
    len = st_admin_build_response("GET", path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, stored)
        || !contains(response, "\"maxConcurrentFlows\":10")) {
        fprintf(stderr, "a refused egress policy request changed what was stored: %s\n", response);
        return 1;
    }

    /* null reads as absent: the other fields apply and the rules stay as stored. */
    snprintf(body, sizeof(body),
             "{\"egressClientId\":%d,\"maxConcurrentFlows\":30,\"destinationRules\":null}",
             egress_client_id);
    len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, stored)
        || !contains(response, "\"maxConcurrentFlows\":30")) {
        fprintf(stderr, "null destinationRules did not keep the stored rules: %s\n", response);
        return 1;
    }

    /*
     * Domain rules: stored normalised next to the destination rules, which an update without them
     * keeps; a refused rule refuses the whole request; null and an absent field keep them.
     */
    static const char *const stored_names =
        "\"domainRules\":[{\"match\":\"*.cdn.example\",\"protocols\":[\"udp\"],\"portRanges\":[[443,443]]}]";
    snprintf(body, sizeof(body),
             "{\"egressClientId\":%d,\"domainRules\":[{\"match\":\" *.CDN.Example. \","
             "\"protocols\":[\" UDP \"],\"portRanges\":[[443,443]]}]}",
             egress_client_id);
    len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, stored_names)
        || !contains(response, stored) || !contains(response, "\"maxConcurrentFlows\":30")) {
        fprintf(stderr, "egress policy save did not store the normalised domain rules: %s\n", response);
        return 1;
    }
    static const char *const refused_names[] = {
        "[{\"match\":\"203.0.113.5\"}]",
        "[{\"match\":\"*.com\"}]",
        "[{\"match\":\"localhost\"}]",
        "[{\"match\":\"example.com\",\"protocols\":[\"icmp\"]}]",
        "{\"match\":\"example.com\"}",
    };
    for (size_t i = 0; i < sizeof(refused_names) / sizeof(refused_names[0]); ++i) {
        snprintf(body, sizeof(body),
                 "{\"egressClientId\":%d,\"maxConcurrentFlows\":50,\"domainRules\":%s}",
                 egress_client_id, refused_names[i]);
        len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
        if (len <= 0 || !contains(response, "400 Bad Request")
            || !contains(response, "invalid domainRules")) {
            fprintf(stderr, "egress policy accepted domain rules %s: %s\n", refused_names[i], response);
            return 1;
        }
    }
    snprintf(body, sizeof(body),
             "{\"egressClientId\":%d,\"maxConcurrentFlows\":31,\"domainRules\":null}", egress_client_id);
    len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, stored_names)
        || !contains(response, "\"maxConcurrentFlows\":31")) {
        fprintf(stderr, "null domainRules did not keep the stored rules: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, stored_names)
        || !contains(response, stored) || !contains(response, "\"maxConcurrentFlows\":31")) {
        fprintf(stderr, "the policy list lost the domain rules: %s\n", response);
        return 1;
    }

    /* Truncated: the field readers could still pick egressClientId out of it. */
    snprintf(body, sizeof(body), "{\"egressClientId\":%d,\"maxConcurrentFlows\":40,\"destinationRules\":[",
             egress_client_id);
    len = st_admin_build_response_with_body("POST", path, body, response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request") || !contains(response, "invalid request body")) {
        fprintf(stderr, "egress policy accepted an unparsable body: %s\n", response);
        return 1;
    }
    len = st_admin_build_response_with_body("POST", path,
                                            "{\"egressClientId\":987654321,\"destinationRules\":[]}",
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "egress policy for an unknown client was not 404: %s\n", response);
        return 1;
    }
    len = st_admin_build_response_with_body("PUT", "/api/admin/peer-mesh/egress/switch",
                                            "{\"enabled\":false", response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request") || !contains(response, "invalid request body")) {
        fprintf(stderr, "egress switch accepted an unparsable body: %s\n", response);
        return 1;
    }

    char delete_path[128];
    snprintf(delete_path, sizeof(delete_path), "%s/%d", path, policy_id);
    len = st_admin_build_response("DELETE", delete_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "egress policy delete failed: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("DELETE", delete_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "deleting a missing egress policy was not 404: %s\n", response);
        return 1;
    }
    return 0;
}

/* The body of a response, after its header. */
static const char *response_body(const char *response)
{
    const char *body = strstr(response, "\r\n\r\n");
    return body == NULL ? "" : body + 4;
}

/*
 * PeerEgressResourceTests mutationsByANonAdminAreForbidden, enablingWhilePeerMeshIsOffIsABadRequest,
 * anUnknownEgressClientIsNotFound and deletingAnUnknownPolicyIsNotFound: a tenant USER may read
 * but not change egress, Peer Mesh being off forbids switching egress on, and the 404s name the id.
 * Nothing refused is stored or pushed to the peers.
 */
static int test_peer_mesh_egress_admin_only(int egress_client_id)
{
    static const char *const switch_path = "/api/admin/peer-mesh/egress/switch";
    static const char *const policies_path = "/api/admin/peer-mesh/egress/policies";
    char response[16384];
    char before_switch[4096];
    char before_policies[8192];
    char body[256];
    char path[128];
    const char *tenant = getenv("SPECUS_AUTH_TENANT_ID");
    if (tenant == NULL || connection_events_ensure_user("egress-member", tenant, "USER") != 0) {
        fprintf(stderr, "egress member fixture setup failed\n");
        return 1;
    }
    snprintf(body, sizeof(body), "{\"egressClientId\":%d,\"enabled\":false}", egress_client_id);
    int len = st_admin_build_response_with_body("POST", policies_path, body, response, sizeof(response));
    int policy_id = 0;
    if (len <= 0 || !contains(response, "200 OK") || st_json_get_int(response, "id", &policy_id) != 0) {
        fprintf(stderr, "egress policy fixture create failed: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", switch_path, response, sizeof(response));
    snprintf(before_switch, sizeof(before_switch), "%s", response_body(response));
    len = st_admin_build_response("GET", policies_path, response, sizeof(response));
    snprintf(before_policies, sizeof(before_policies), "%s", response_body(response));
    int refreshes = peer_mesh_refresh_calls;

    snprintf(path, sizeof(path), "%s/%d", policies_path, policy_id);
    snprintf(body, sizeof(body), "{\"egressClientId\":%d,\"enabled\":true}", egress_client_id);
    struct {
        const char *method;
        const char *path;
        const char *body;
    } mutations[] = {
        {"PUT", switch_path, "{\"enabled\":false}"},
        {"POST", policies_path, body},
        {"DELETE", path, NULL},
    };
    for (size_t i = 0U; i < sizeof(mutations) / sizeof(mutations[0]); ++i) {
        len = tenant_scope_call(mutations[i].method, mutations[i].path, "egress-member", tenant, "USER",
                                mutations[i].body, response, sizeof(response));
        char *error = len > 0 ? st_json_get_string(response, "error") : NULL;
        int refused = len > 0 && contains(response, "403 Forbidden") && error != NULL && *error != '\0';
        free(error);
        if (!refused) {
            fprintf(stderr, "a USER's %s %s was not 403: %s\n", mutations[i].method, mutations[i].path, response);
            return 1;
        }
    }
    /* Reading stays open to the member. */
    len = tenant_scope_call("GET", policies_path, "egress-member", tenant, "USER", NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "a USER could not read the egress policies: %s\n", response);
        return 1;
    }

    /* Peer Mesh is off in this deployment: switching egress on is a bad request, off is allowed. */
    const char *peer_mesh = getenv("SPECUS_PEER_MESH_ENABLED");
    char saved_peer_mesh[16] = "";
    if (peer_mesh != NULL) snprintf(saved_peer_mesh, sizeof(saved_peer_mesh), "%s", peer_mesh);
    unsetenv("SPECUS_PEER_MESH_ENABLED");
    len = st_admin_build_response_with_body("PUT", switch_path, "{\"enabled\":true}", response, sizeof(response));
    char *error = len > 0 ? st_json_get_string(response, "error") : NULL;
    int refused = len > 0 && contains(response, "400 Bad Request") && error != NULL && *error != '\0';
    free(error);
    if (!refused) {
        fprintf(stderr, "enabling egress with Peer Mesh off was not 400: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", switch_path, response, sizeof(response));
    if (len <= 0 || strcmp(response_body(response), before_switch) != 0) {
        fprintf(stderr, "a refused switch request changed the switch: %s, was %s\n", response_body(response),
                before_switch);
        return 1;
    }
    len = st_admin_build_response("GET", policies_path, response, sizeof(response));
    if (len <= 0 || strcmp(response_body(response), before_policies) != 0 || peer_mesh_refresh_calls != refreshes) {
        fprintf(stderr, "a refused egress request changed the policies or pushed a refresh\n");
        return 1;
    }
    len = st_admin_build_response_with_body("PUT", switch_path, "{\"enabled\":false}", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"configuredEnabled\":false")) {
        fprintf(stderr, "switching egress off with Peer Mesh off was refused: %s\n", response);
        return 1;
    }
    if (saved_peer_mesh[0] != '\0') setenv("SPECUS_PEER_MESH_ENABLED", saved_peer_mesh, 1);

    len = st_admin_build_response_with_body("POST", policies_path,
                                            "{\"egressClientId\":987654321,\"enabled\":true}",
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")
        || !contains(response, "{\"error\":\"client not found: 987654321\"}")) {
        fprintf(stderr, "an unknown egress client was not named in the 404: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("DELETE", path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "egress policy fixture delete failed: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("DELETE", path, response, sizeof(response));
    char expected[96];
    snprintf(expected, sizeof(expected), "{\"error\":\"egress policy not found: %d\"}", policy_id);
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, expected)) {
        fprintf(stderr, "a missing egress policy was not named in the 404: %s\n", response);
        return 1;
    }
    return 0;
}

/*
 * PeerServiceDiscoveryServiceTests rejectsPublicTargetAndUnsafePath and
 * rejectsUdpApplicationWithTcpTransport over the management API: the refused definitions are 400
 * and nothing of them is stored; a local target in another spelling is stored normalised.
 */
static int test_peer_service_definition_validation(int client_id)
{
    static const char *const services_path = "/api/admin/peer-mesh/services";
    static const char *const refused[] = {
        "\"name\":\"evil\",\"application\":\"http\",\"targetHost\":\"evil.example\",\"targetPort\":80,"
        "\"publishedPort\":28080",
        "\"name\":\"public\",\"application\":\"http\",\"targetHost\":\"198.51.100.9\",\"targetPort\":80,"
        "\"publishedPort\":28081",
        "\"name\":\"url\",\"application\":\"http\",\"targetHost\":\"http://127.0.0.1\",\"targetPort\":80,"
        "\"publishedPort\":28082",
        "\"name\":\"wildcard\",\"application\":\"tcp\",\"targetHost\":\"0.0.0.0\",\"targetPort\":80,"
        "\"publishedPort\":28083",
        "\"name\":\"script\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":80,"
        "\"publishedPort\":28084,\"path\":\"javascript:alert(1)\"",
        "\"name\":\"traversal\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":80,"
        "\"publishedPort\":28085,\"path\":\"/a/../b\"",
        "\"name\":\"spaces\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":80,"
        "\"publishedPort\":28086,\"path\":\"/a b\"",
        "\"name\":\"dns\",\"transport\":\"tcp\",\"application\":\"udp\",\"targetHost\":\"127.0.0.1\","
        "\"targetPort\":53,\"publishedPort\":28087",
        "\"name\":\"web-over-udp\",\"transport\":\"udp\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\","
        "\"targetPort\":80,\"publishedPort\":28088",
        "\"name\":\"open\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":80,"
        "\"publishedPort\":28089,\"visibility\":\"public\"",
    };
    char body[512];
    char response[32768];
    for (size_t i = 0U; i < sizeof(refused) / sizeof(refused[0]); ++i) {
        snprintf(body, sizeof(body), "{\"clientId\":%d,%s}", client_id, refused[i]);
        int len = st_admin_build_response_with_body("POST", services_path, body, response, sizeof(response));
        if (len <= 0 || !contains(response, "400 Bad Request")) {
            fprintf(stderr, "peer service definition was not refused: %s -> %s\n", refused[i], response);
            return 1;
        }
    }
    int len = st_admin_build_response("GET", services_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || contains(response, "evil.example")
        || contains(response, "198.51.100.9") || contains(response, "javascript") || contains(response, "2808")) {
        fprintf(stderr, "a refused peer service definition was stored: %s\n", response);
        return 1;
    }
    /* Accepted spellings are stored normalised, and a new service starts disabled. */
    snprintf(body, sizeof(body),
             "{\"clientId\":%d,\"serviceId\":\"svc-normal01\",\"name\":\" Local DNS \",\"application\":\"UDP\","
             "\"targetHost\":\" LOCALHOST \",\"targetPort\":53,\"publishedPort\":28053,\"visibility\":\"acl\"}",
             client_id);
    len = st_admin_build_response_with_body("POST", services_path, body, response, sizeof(response));
    int service_id = 0;
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"name\":\"Local DNS\"")
        || !contains(response, "\"application\":\"udp\"") || !contains(response, "\"transport\":\"udp\"")
        || !contains(response, "\"targetHost\":\"127.0.0.1\"") || !contains(response, "\"visibility\":\"ACL\"")
        || !contains(response, "\"enabled\":false") || !contains(response, "\"path\":\"\"")
        || st_json_get_int(response, "id", &service_id) != 0 || service_id <= 0) {
        fprintf(stderr, "a valid peer service definition was not stored normalised: %s\n", response);
        return 1;
    }
    /* An update is checked the same way. */
    char path[128];
    snprintf(path, sizeof(path), "%s/%d", services_path, service_id);
    len = st_admin_build_response_with_body("PUT", path, "{\"targetHost\":\"8.8.8.8\"}", response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")) {
        fprintf(stderr, "an update to a public target was accepted: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("DELETE", path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "peer service fixture delete failed: %s\n", response);
        return 1;
    }
    return 0;
}

/*
 * serviceReportRateAndStateTablesAreBounded (its audit half): however many audit events a tenant
 * collects, the management API lists the latest 50.
 */
static int test_peer_service_audit_bounded(void)
{
    const char *database_path = getenv("SPECUS_DATABASE_PATH");
    const char *tenant = getenv("SPECUS_AUTH_TENANT_ID");
    for (int i = 0; i < 120; ++i) {
        if (database_path == NULL || tenant == NULL
            || st_storage_record_peer_mesh_service_audit(database_path, "service-report", tenant, 1, 7001 + i,
                                                         NULL, "rate-limited") != 0) {
            fprintf(stderr, "peer service audit fixture failed\n");
            return 1;
        }
    }
    char response[65536];
    int len = st_admin_build_response("GET", "/api/admin/peer-mesh/service-audit", response, sizeof(response));
    size_t events = 0U;
    for (const char *cursor = strstr(response, "\"action\":"); cursor != NULL;
         cursor = strstr(cursor + 1, "\"action\":")) {
        ++events;
    }
    if (len <= 0 || !contains(response, "200 OK") || events != 50U || !contains(response, "\"sessionId\":7120")) {
        fprintf(stderr, "peer service audit listed %zu events: %s\n", events, response);
        return 1;
    }
    return 0;
}

/*
 * PublicPeerMeshResourceTests: stun-config prefers a standalone STUN server, publishes it while
 * Peer Mesh is off, and falls back to the embedded endpoint when the standalone setting is
 * incomplete; nat-probe-config offers RFC 5780 only with a full second address and port.
 */
static int test_public_stun_config_endpoints(void)
{
    static const char *const settings[] = {
        "SPECUS_PEER_MESH_ENABLED", "SPECUS_PEER_MESH_PUBLIC_ADDRESS", "SPECUS_PEER_MESH_STUN_TURN_PORT",
        "SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS", "SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS",
        "SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS",
        "SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT", "SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS",
        "SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT",
    };
    for (size_t i = 0U; i < sizeof(settings) / sizeof(settings[0]); ++i) unsetenv(settings[i]);
    char response[16384];
    int failed = 0;

    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    setenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS", "turn.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "5349", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS", "stun-backup.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT", "5350", 1);
    static const char *const preferred =
        "{\"peerMeshEnabled\":true,\"selfHostedStunServer\":\"stun:stun.example.com:5349\","
        "\"stunServers\":[\"stun:stun.example.com:5349\",\"stun:stun-backup.example.com:5349\"],"
        "\"stunTurnPort\":3478}";
    int len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || strcmp(response_body(response), preferred) != 0) {
        fprintf(stderr, "stun-config did not prefer the standalone endpoint: %s\n", response_body(response));
        failed = 1;
    }
    /* The alternate is listed on the primary port whether or not a second port is set. */
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT");
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (!failed && (len <= 0 || strcmp(response_body(response), preferred) != 0)) {
        fprintf(stderr, "stun-config dropped the alternate without a second port: %s\n", response_body(response));
        failed = 1;
    }

    unsetenv("SPECUS_PEER_MESH_ENABLED");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS");
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (!failed && (len <= 0 || !contains(response, "\"peerMeshEnabled\":false")
                    || !contains(response, "\"selfHostedStunServer\":\"stun:stun.example.com:3478\""))) {
        fprintf(stderr, "stun-config did not publish standalone STUN with Peer Mesh off: %s\n",
                response_body(response));
        failed = 1;
    }

    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    setenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS", "relay.example.com", 1);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", "4444", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "0", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (!failed && (len <= 0 || !contains(response, "\"selfHostedStunServer\":\"stun:relay.example.com:4444\"")
                    || !contains(response, "\"stunTurnPort\":4444") || contains(response, "stun.example.com"))) {
        fprintf(stderr, "an incomplete standalone STUN did not fall back: %s\n", response_body(response));
        failed = 1;
    }

    for (size_t i = 0U; i < sizeof(settings) / sizeof(settings[0]); ++i) unsetenv(settings[i]);
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun-a.example.com", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "34780", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS", "203.0.113.20", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT", "34781", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/nat-probe-config", response, sizeof(response));
    if (!failed && (len <= 0 || !contains(response, "\"available\":true,\"protocol\":\"RFC8489\","
                                                     "\"discoveryMethod\":\"RFC5780\"")
                    || !contains(response, "{\"id\":\"A1P1\",\"url\":\"stun:stun-a.example.com:34780\"")
                    || !contains(response, "{\"id\":\"A1P2\",\"url\":\"stun:stun-a.example.com:34781\"")
                    || !contains(response, "{\"id\":\"A2P1\",\"url\":\"stun:203.0.113.20:34780\"")
                    || !contains(response, "{\"id\":\"A2P2\",\"url\":\"stun:203.0.113.20:34781\"")
                    || !contains(response, "\"changeRequest\":true")
                    || !contains(response, "\"padding\":true,\"browserMappingObservation\":true,"
                                           "\"browserFilteringObservation\":false"))) {
        fprintf(stderr, "standalone RFC 5780 nat-probe-config mismatch: %s\n", response_body(response));
        failed = 1;
    }
    /* Without the second port the NAT probe alternate port stands in, as in Java. */
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT");
    len = st_admin_build_response("GET", "/api/public/peer-mesh/nat-probe-config", response, sizeof(response));
    if (!failed && (len <= 0 || !contains(response, "{\"id\":\"A2P2\",\"url\":\"stun:203.0.113.20:3479\""))) {
        fprintf(stderr, "nat-probe-config ignored the NAT probe alternate port: %s\n", response_body(response));
        failed = 1;
    }
    unsetenv("SPECUS_PEER_MESH_ENABLED");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS");
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun.example.com", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/nat-probe-config", response, sizeof(response));
    if (!failed && (len <= 0 || !contains(response, "\"discoveryMethod\":\"BASIC_STUN\","
                                                     "\"endpoints\":[{\"id\":\"A1P1\","
                                                     "\"url\":\"stun:stun.example.com:34780\"")
                    || contains(response, "A1P2") || !contains(response, "\"changeRequest\":false"))) {
        fprintf(stderr, "basic STUN nat-probe-config mismatch: %s\n", response_body(response));
        failed = 1;
    }
    for (size_t i = 0U; i < sizeof(settings) / sizeof(settings[0]); ++i) unsetenv(settings[i]);
    return failed;
}

int main(void)
{
    /* The suite deliberately exercises demo credentials and seeding; production disables both. */
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED", "false", 1);
    char response[32768];
    char request_path[128];
    int len = st_admin_build_response("GET", "/health", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "{\"status\":\"ok\"}")) {
        fprintf(stderr, "health response mismatch\n");
        return 1;
    }

    unsetenv("SPECUS_AUTH_PASSWORD");
    unsetenv("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED");
    st_login_rate_limiter_reset();
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"admin\",\"password\":\"admin\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "built-in default admin password was still enabled\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/oidc-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "\"passwordLoginEnabled\":false")) {
        fprintf(stderr, "blank built-in password did not disable passwordLoginEnabled\n");
        return 1;
    }

    setenv("SPECUS_AUTH_PASSWORD", "admin", 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "c-admin-test-secret", 1);
    st_login_rate_limiter_reset();
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"admin\",\"password\":\"admin\"}",
                                            response,
                                            sizeof(response));
    char *admin_token = st_json_get_string(response, "accessToken");
    if (len <= 0 || !contains(response, "200 OK") || admin_token == NULL || !contains(admin_token, ".")) {
        fprintf(stderr, "login response mismatch\n");
        free(admin_token);
        return 1;
    }
    len = st_admin_build_response_with_body("POST", "/auth/register",
        "{\"username\":\"visitor\",\"email\":\"visitor@example.com\","
        "\"password\":\"password-1\",\"turnstileToken\":\"unused\"}",
        response, sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden") || !contains(response, "当前未开放注册")) {
        fprintf(stderr, "disabled registration response mismatch\n");
        return 1;
    }

    unsetenv("SPECUS_PEER_MESH_ENABLED");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS");
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"peerMeshEnabled\":false")
        || !contains(response, "\"selfHostedStunServer\":\"\"")
        || !contains(response, "\"stunServers\":[]")
        || !contains(response, "\"stunTurnPort\":3478")) {
        fprintf(stderr, "disabled public stun config mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/public/peer-mesh/nat-probe-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"available\":false")
        || !contains(response, "\"discoveryMethod\":\"BASIC_STUN\"")
        || !contains(response, "\"endpoints\":[]")) {
        fprintf(stderr, "disabled public NAT probe config mismatch\n");
        return 1;
    }
    setenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS", "STUN://fallback.example.test", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "\"peerMeshEnabled\":false")
        || !contains(response, "\"selfHostedStunServer\":\"\"")
        || !contains(response, "\"stun:fallback.example.test:3478\"")) {
        fprintf(stderr, "disabled public fallback stun config mismatch\n");
        return 1;
    }
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    setenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS", "ice.example.test", 1);
    setenv("SPECUS_PEER_MESH_STUN_TURN_PORT", "5349", 1);
    setenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS", "stun://stun.example.test, stun:stun.example.test:3478", 1);
    setenv("SPECUS_PEER_MESH_TURN_AUTH_REQUIRED", "true", 1);
    setenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET", "turn-test-secret", 1);
    setenv("SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS", "3600", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"peerMeshEnabled\":true")
        || !contains(response, "\"selfHostedStunServer\":\"stun:ice.example.test:5349\"")
        || !contains(response, "\"stun:stun.example.test:3478\"")) {
        fprintf(stderr, "enabled public stun config mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/public/transfer/ice-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"urls\":\"turn:ice.example.test:5349?transport=udp\"")
        || !contains(response, ":public-transfer:")
        || !contains(response, "\"credential\":\"")
        || !contains(response, "\"turnAuthRequired\":true")) {
        fprintf(stderr, "public ice config mismatch\n");
        return 1;
    }
    const char *turn_entry = strstr(response, "\"urls\":\"turn:");
    char *turn_username = turn_entry == NULL ? NULL : st_json_get_string(turn_entry, "username");
    char *turn_credential = turn_entry == NULL ? NULL : st_json_get_string(turn_entry, "credential");
    uint8_t expected_turn_mac[ST_SHA1_LEN];
    char expected_turn_credential[32];
    if (turn_username != NULL) {
        st_hmac_sha1((const uint8_t *)"turn-test-secret",
                     strlen("turn-test-secret"),
                     (const uint8_t *)turn_username,
                     strlen(turn_username),
                     expected_turn_mac);
        test_base64url_no_padding(expected_turn_mac, sizeof(expected_turn_mac), expected_turn_credential);
    }
    char *turn_subject = turn_username == NULL ? NULL : strstr(turn_username, ":public-transfer:");
    if (turn_username == NULL || turn_credential == NULL || turn_subject == NULL
        || strlen(turn_subject + strlen(":public-transfer:")) != 8U
        || strcmp(turn_credential, expected_turn_credential) != 0) {
        fprintf(stderr, "temporary turn credential mismatch\n");
        free(turn_username);
        free(turn_credential);
        return 1;
    }
    free(turn_username);
    free(turn_credential);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS", "stun-a.example.test", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", "3478", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS", "stun-b.example.test", 1);
    setenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT", "3479", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/nat-probe-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"available\":true")
        || !contains(response, "\"discoveryMethod\":\"RFC5780\"")
        || !contains(response, "\"id\":\"A1P1\"")
        || !contains(response, "\"id\":\"A1P2\"")
        || !contains(response, "\"id\":\"A2P1\"")
        || !contains(response, "\"id\":\"A2P2\"")
        || !contains(response, "\"url\":\"stun:stun-b.example.test:3479\"")
        || !contains(response, "\"changeRequest\":true")) {
        fprintf(stderr, "RFC5780 public NAT probe config mismatch\n");
        return 1;
    }
    len = st_admin_build_response("POST", "/api/public/transfer/attachments/presign-upload", response, sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")
        || !contains(response, "\"error\":\"object storage is not configured\"")
        || !contains(response, "\"code\":\"OBJECT_STORAGE_DISABLED\"")
        || !contains(response, "\"enabled\":false")) {
        fprintf(stderr, "disabled public attachment response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("POST",
                                  "/api/public/transfer/attachments/not-a-java-route",
                                  response,
                                  sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "unknown attachment path should remain not found\n");
        return 1;
    }
    unsetenv("SPECUS_PEER_MESH_ENABLED");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("SPECUS_PEER_MESH_STUN_TURN_PORT");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS");
    unsetenv("SPECUS_PEER_MESH_TURN_AUTH_REQUIRED");
    unsetenv("SPECUS_PEER_MESH_TURN_SHARED_SECRET");
    unsetenv("SPECUS_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_PORT");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT");
    if (test_public_stun_config_endpoints() != 0) {
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/overview", NULL, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "unauthenticated admin api response mismatch\n");
        free(admin_token);
        return 1;
    }
    char authorization[2300];
    snprintf(authorization, sizeof(authorization), "Bearer %s", admin_token);
    len = st_admin_build_response_with_auth("GET", "/api/admin/overview", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"server\":\"c\"")) {
        fprintf(stderr, "authenticated admin api response mismatch\n");
        free(admin_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/client-messages/attachments/presign-upload",
                                            authorization,
                                            "{}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")
        || !contains(response, "\"error\":\"object storage is not configured\"")
        || !contains(response, "\"code\":\"OBJECT_STORAGE_DISABLED\"")) {
        fprintf(stderr, "disabled admin attachment response mismatch\n");
        free(admin_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST", "/auth/refresh", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"tokenType\":\"Bearer\"")) {
        fprintf(stderr, "refresh response mismatch\n");
        free(admin_token);
        return 1;
    }
    free(admin_token);
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"admin\",\"password\":\"wrong\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "invalid login response mismatch\n");
        return 1;
    }

    setenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_IP", "2", 1);
    setenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT", "100", 1);
    setenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300", 1);
    st_login_rate_limiter_reset();
    const char *missing_logins[] = {"missing-one", "missing-two", "missing-three"};
    for (size_t i = 0; i < sizeof(missing_logins) / sizeof(missing_logins[0]); ++i) {
        char login_body[160];
        snprintf(login_body,
                 sizeof(login_body),
                 "{\"username\":\"%s\",\"password\":\"wrong\"}",
                 missing_logins[i]);
        len = st_admin_build_response_with_remote("POST",
                                                  "/auth/login",
                                                  login_body,
                                                  "192.0.2.10",
                                                  response,
                                                  sizeof(response));
        if (len <= 0
            || (i < 2U && !contains(response, "401 Unauthorized"))
            || (i == 2U && (!contains(response, "429 Too Many Requests")
                            || !contains(response, "Retry-After:")
                            || !contains(response, "登录尝试过于频繁,请稍后再试")))) {
            fprintf(stderr, "per-IP login rate limit response mismatch\n");
            return 1;
        }
    }

    setenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_IP", "100", 1);
    setenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT", "1", 1);
    st_login_rate_limiter_reset();
    len = st_admin_build_response_with_remote("POST",
                                              "/auth/login",
                                              "{\"username\":\"missing-account\",\"password\":\"wrong\"}",
                                              "192.0.2.11",
                                              response,
                                              sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "per-account login rate limit first response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_remote("POST",
                                              "/auth/login",
                                              "{\"username\":\"MISSING-ACCOUNT\",\"password\":\"wrong\"}",
                                              "192.0.2.12",
                                              response,
                                              sizeof(response));
    if (len <= 0 || !contains(response, "429 Too Many Requests")
        || !contains(response, "Retry-After:")) {
        fprintf(stderr, "per-account login rate limit response mismatch\n");
        return 1;
    }

    st_login_rate_limiter_reset();
    for (int i = 0; i < 2; ++i) {
        len = st_admin_build_response_with_remote("POST",
                                                  "/auth/login",
                                                  "{\"username\":\"admin\",\"password\":\"admin\"}",
                                                  i == 0 ? "192.0.2.20" : "192.0.2.21",
                                                  response,
                                                  sizeof(response));
        if (len <= 0 || !contains(response, "200 OK")) {
            fprintf(stderr, "successful login did not clear account rate-limit budget\n");
            return 1;
        }
    }
    unsetenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_ENABLED");
    unsetenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_IP");
    unsetenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT");
    unsetenv("SPECUS_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS");
    st_login_rate_limiter_reset();

    unsetenv("SPECUS_DATABASE_PATH");
    setenv("SPECUS_CLIENT_ACCESS_TOKEN", "dev-runtime-token", 1);
    setenv("SPECUS_CLIENT_TENANT_ID", "tenant-c", 1);
    setenv("SPECUS_CLIENT_ID", "42", 1);
    setenv("SPECUS_CLIENT_SESSION_ID", "99", 1);
    setenv("SPECUS_CLIENT_TOKEN_TTL_SECONDS", "120", 1);
    setenv("SPECUS_CLIENT_MAX_ONLINE_INSTANCES", "7", 1);
    setenv("SPECUS_CLIENT_POLICY_ENABLED", "false", 1);
    setenv("SPECUS_CLIENT_BILLING_STATUS", "SUSPENDED", 1);
    setenv("SPECUS_CLIENT_RETRY_AFTER_SECONDS", "60", 1);
    setenv("SPECUS_TCP_MAPPINGS", "18080=127.0.0.1:8080,10022=192.168.1.243:22", 1);
    setenv("SPECUS_HTTP_ROUTES", "api=http://127.0.0.1:8080/base", 1);
    len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tenantId\":\"tenant-c\"")
        || !contains(response, "\"clientId\":42")
        || !contains(response, "\"clientSessionId\":99")
        || !contains(response, "\"tokenTtlSeconds\":120")
        || !contains(response, "\"maxOnlineInstances\":7")
        || !contains(response, "\"policy\":{\"enabled\":false,\"billingStatus\":\"SUSPENDED\",\"retryAfterSeconds\":60}")
        || !contains(response, "\"peerMesh\":{\"enabled\":false,\"clientId\":42")
        || !contains(response, "\"specusConfigList\":[")
        || !contains(response, "\"port\":18080")
        || !contains(response, "\"specusAddress\":\"127.0.0.1\"")
        || !contains(response, "\"specusPort\":8080")
        || !contains(response, "\"port\":10022")
        || !contains(response, "\"specusAddress\":\"192.168.1.243\"")
        || !contains(response, "\"specusPort\":22")
        || !contains(response, "\"httpSpecusConfigList\":[")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"http://127.0.0.1:8080/base\"")
        || !contains(response, "\"insecureSkipVerify\":false")) {
        fprintf(stderr, "client auth tcp mappings response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_CLIENT_ACCESS_TOKEN");
    unsetenv("SPECUS_CLIENT_TENANT_ID");
    unsetenv("SPECUS_CLIENT_ID");
    unsetenv("SPECUS_CLIENT_SESSION_ID");
    unsetenv("SPECUS_CLIENT_TOKEN_TTL_SECONDS");
    unsetenv("SPECUS_CLIENT_MAX_ONLINE_INSTANCES");
    unsetenv("SPECUS_CLIENT_POLICY_ENABLED");
    unsetenv("SPECUS_CLIENT_BILLING_STATUS");
    unsetenv("SPECUS_CLIENT_RETRY_AFTER_SECONDS");
    unsetenv("SPECUS_TCP_MAPPINGS");
    unsetenv("SPECUS_HTTP_ROUTES");

    setenv("SPECUS_CLIENT_ACCESS_TOKEN", "dev-runtime-token", 1);
    setenv("SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS", "180", 1);
    setenv("SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES", "9", 1);
    len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tokenTtlSeconds\":180")
        || !contains(response, "\"maxOnlineInstances\":9")) {
        fprintf(stderr, "client auth java alias env response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_CLIENT_ACCESS_TOKEN");
    unsetenv("SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS");
    unsetenv("SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES");
    if (test_client_auth_netty_tls() != 0) {
        return 1;
    }

    setenv("SPECUS_CLIENT_ACCESS_TOKEN", "dev-runtime-token", 1);
    setenv("SPECUS_CLIENT_API_KEY", "demo-api", 1);
    setenv("SPECUS_CLIENT_SECRET", "test1234", 1);
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%lld", test_now_millis());
    char signature[ST_SHA256_HEX_LEN + 1];
    sign_client_auth("demo-api", timestamp, "nonce-1", "m_test", "tester", "test1234", signature);
    char body[1024];
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"demo-api\",\"timestamp\":\"%s\",\"nonce\":\"nonce-1\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"m_test\",\"osUser\":\"tester\"}}",
             timestamp,
             signature);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"accessToken\":\"dev-runtime-token\"")) {
        fprintf(stderr, "client auth signed login response mismatch\n");
        return 1;
    }
    /* The same signed request again is a replay: refused as Java refuses it, with no token. */
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")
        || !contains(response, "{\"error\":\"客户端签名 nonce 已使用\"}")
        || contains(response, "accessToken")) {
        fprintf(stderr, "client auth replayed environment login was not rejected: %s\n", response);
        return 1;
    }
    /* A request whose signature fails consumes nothing: its nonce still works once signed. */
    snprintf(timestamp, sizeof(timestamp), "%lld", test_now_millis());
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"demo-api\",\"timestamp\":\"%s\",\"nonce\":\"nonce-2\","
             "\"signature\":\"0000000000000000000000000000000000000000000000000000000000000000\","
             "\"environment\":{\"machineFingerprint\":\"m_test\",\"osUser\":\"tester\"}}",
             timestamp);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "client auth bad signature with a fresh nonce was not rejected\n");
        return 1;
    }
    sign_client_auth("demo-api", timestamp, "nonce-2", "m_test", "tester", "test1234", signature);
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"demo-api\",\"timestamp\":\"%s\",\"nonce\":\"nonce-2\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"m_test\",\"osUser\":\"tester\"}}",
             timestamp,
             signature);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "client auth nonce was consumed by a request whose signature failed\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/client/auth/login",
                                            "{\"apiKey\":\"demo-api\",\"timestamp\":\"1\",\"nonce\":\"nonce-1\","
                                            "\"signature\":\"0000000000000000000000000000000000000000000000000000000000000000\","
                                            "\"environment\":{\"machineFingerprint\":\"m_test\",\"osUser\":\"tester\"}}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized") || !contains(response, "signature invalid")) {
        fprintf(stderr, "client auth invalid signature was not rejected\n");
        return 1;
    }
    unsetenv("SPECUS_CLIENT_ACCESS_TOKEN");
    unsetenv("SPECUS_CLIENT_API_KEY");
    unsetenv("SPECUS_CLIENT_SECRET");

    char auth_db_path[256];
    snprintf(auth_db_path, sizeof(auth_db_path), "/tmp/specus-c-client-auth-%ld.db", (long)getpid());
    unlink(auth_db_path);
    if (st_storage_init(auth_db_path, 0) != 0) {
        fprintf(stderr, "client auth db init failed\n");
        return 1;
    }
    uint8_t db_secret_hash[ST_SHA256_LEN];
    char db_secret_hash_hex[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"db-secret", strlen("db-secret"), db_secret_hash);
    st_hex_encode(db_secret_hash, sizeof(db_secret_hash), db_secret_hash_hex);
    st_storage_client_credential db_credential;
    if (st_storage_upsert_client_credential(auth_db_path,
                                            0,
                                            "tenant-db",
                                            "owner-db",
                                            "db-api",
                                            db_secret_hash_hex,
                                            1,
                                            4,
                                            &db_credential) != 0) {
        fprintf(stderr, "client auth db credential seed failed\n");
        return 1;
    }
    setenv("SPECUS_DATABASE_PATH", auth_db_path, 1);
    snprintf(timestamp, sizeof(timestamp), "%lld", test_now_millis());
    sign_client_auth("db-api", timestamp, "nonce-db", "machine-db", "db-user", "db-secret", signature);
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"db-api\",\"timestamp\":\"%s\",\"nonce\":\"nonce-db\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"machine-db\",\"osUser\":\"db-user\",\"hostname\":\"DB Host\","
             "\"clientVersion\":\"2.1.0-test\","
             "\"clientMessageCapabilities\":{\"sendMessages\":true,\"receiveMessages\":true,"
             "\"attachments\":true,\"mediaPreview\":true,"
             "\"maxAttachmentBytes\":16777216},"
             "\"clientEgressCapabilities\":{\"version\":1,\"egressCapable\":true,"
             "\"consumerCapable\":true,\"domainTargetCapable\":true,\"ipv6TargetCapable\":false},"
             "\"clientPeerServiceCapabilities\":{\"version\":2,"
             "\"applications\":[\"http\",\"tcp\",\"http\"]}}}",
             timestamp,
             signature);
    /* The control listener runs TLS here, which the database login advertises too. */
    setenv("SPECUS_TLS_MODE", "file", 1);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    unsetenv("SPECUS_TLS_MODE");
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tenantId\":\"tenant-db\"")
        || !contains(response, "\"accessToken\":\"cs_")
        || !contains(response, "\"nettyTls\":true")
        || !contains(response, "\"maxOnlineInstances\":4")
        || !contains(response, "db-host-db-user-")) {
        fprintf(stderr, "client auth database login response mismatch\n");
        return 1;
    }
    {
        /* Replaying the database login must not mint a second session. */
        static char replay[65536];
        int replay_len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body,
                                                           replay, sizeof(replay));
        if (replay_len <= 0 || !contains(replay, "400 Bad Request")
            || !contains(replay, "{\"error\":\"客户端签名 nonce 已使用\"}")
            || contains(replay, "accessToken")) {
            fprintf(stderr, "client auth replayed database login was not rejected: %s\n", replay);
            return 1;
        }
    }
    int runtime_client_id = 0;
    int runtime_client_session_id = 0;
    char *runtime_client_name = st_json_get_string(response, "clientName");
    if (st_json_get_int(response, "clientId", &runtime_client_id) != 0
        || st_json_get_int(response, "clientSessionId", &runtime_client_session_id) != 0
        || runtime_client_id <= 0
        || runtime_client_session_id <= 0
        || runtime_client_name == NULL
        || *runtime_client_name == '\0') {
        fprintf(stderr, "client auth runtime identity response mismatch\n");
        free(runtime_client_name);
        return 1;
    }
    runtime_status_expected_client_id = runtime_client_id;
    snprintf(runtime_status_expected_client_name,
             sizeof(runtime_status_expected_client_name),
             "%s",
             runtime_client_name);
    free(runtime_client_name);
    st_storage_client_session negotiated_session;
    char *negotiated_token = st_json_get_string(response, "accessToken");
    uint8_t negotiated_digest[ST_SHA256_LEN];
    char negotiated_hash[ST_SHA256_HEX_LEN + 1U];
    if (negotiated_token == NULL) return 1;
    st_sha256((const uint8_t *)negotiated_token, strlen(negotiated_token), negotiated_digest);
    st_hex_encode(negotiated_digest, sizeof(negotiated_digest), negotiated_hash);
    free(negotiated_token);
    if (st_storage_get_client_session_for_login(auth_db_path, runtime_client_session_id,
                                                 negotiated_hash, &negotiated_session) != 0
        || negotiated_session.peer_service_discovery_version != 2
        || strcmp(negotiated_session.peer_service_applications, "http,tcp") != 0) {
        fprintf(stderr, "client peer service capability negotiation mismatch\n");
        return 1;
    }
    /* The egress-catalog reads domainTargetCapable from this session, so it must be stored here. */
    if (negotiated_session.client_egress_version != 1
        || !negotiated_session.client_egress_domain_targets) {
        fprintf(stderr, "client egress capability negotiation mismatch\n");
        return 1;
    }
    if (st_storage_mark_client_session_online(auth_db_path,
                                              runtime_client_session_id,
                                              "test-channel",
                                              "127.0.0.1",
                                              "2026-08-28T00:00:00Z") != 0) {
        fprintf(stderr, "client runtime session online seed failed\n");
        return 1;
    }
    if (st_storage_record_traffic_usage(auth_db_path,
                                        runtime_client_id,
                                        runtime_status_expected_client_name,
                                        "2026-08-28",
                                        321,
                                        654) != 0) {
        fprintf(stderr, "client runtime traffic seed failed\n");
        return 1;
    }
    setenv("SPECUS_AUTH_TENANT_ID", "tenant-db", 1);
    st_admin_set_client_runtime_status_handler(test_client_runtime_status, NULL);
    len = st_admin_build_response("GET", "/api/admin/clients", response, sizeof(response));
    st_admin_set_client_runtime_status_handler(NULL, NULL);
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"online\":true")
        || !contains(response, "\"connectedSinceMs\":1787875200123")
        || !contains(response, "\"clientVersion\":\"2.1.0-test\"")
        || !contains(response, "\"messageSendCapable\":true")
        || !contains(response, "\"messageReceiveCapable\":true")
        || !contains(response, "\"messageAttachmentsCapable\":true")
        || !contains(response, "\"messageMediaPreviewCapable\":true")
        || !contains(response, "\"messageMaxAttachmentBytes\":16777216")
        || !contains(response, "\"uploadBytes\":321")
        || !contains(response, "\"downloadBytes\":654")) {
        fprintf(stderr, "client message capability management response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"messageAttachmentsCapable\":false")
        || !contains(response, "\"messageMaxAttachmentBytes\":0")
        || !contains(response, "\"cidr\":\"100.96.0.0/11\"")
        || !contains(response, "\"virtualDeviceMode\":\"AUTO\"")) {
        fprintf(stderr, "peer mesh capability management response mismatch\n");
        return 1;
    }
    if (test_client_messages_websocket() != 0) {
        return 1;
    }
    if (test_connection_events_websocket(runtime_client_id) != 0) {
        return 1;
    }
    if (test_public_room_access_contract() != 0) {
        return 1;
    }
    if (test_public_discovery_websocket() != 0) {
        return 1;
    }
    unsetenv("SPECUS_AUTH_TENANT_ID");
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"db-api\",\"timestamp\":\"1\",\"nonce\":\"nonce-db\","
             "\"signature\":\"0000000000000000000000000000000000000000000000000000000000000000\","
             "\"environment\":{\"machineFingerprint\":\"machine-db\",\"osUser\":\"db-user\",\"hostname\":\"DB Host\"}}");
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized") || !contains(response, "signature invalid")) {
        fprintf(stderr, "client auth database invalid signature was not rejected\n");
        return 1;
    }
    unsetenv("SPECUS_DATABASE_PATH");
    unlink(auth_db_path);

    len = st_admin_build_response("GET", "/api/admin/overview", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"server\":\"c\"")
        || !contains(response, "\"tcpMappings\":0")) {
        fprintf(stderr, "overview response mismatch\n");
        return 1;
    }

    setenv("SPECUS_TCP_MAPPINGS", "18080=127.0.0.1:8080,10022=192.168.1.243:22", 1);
    len = st_admin_build_response("GET", "/api/admin/overview", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"tcpMappings\":2")) {
        fprintf(stderr, "overview tcp mapping count mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/api/admin/metrics", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"metricsWired\":false")
        || !contains(response, "\"listeners\":2")) {
        fprintf(stderr, "metrics response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_TCP_MAPPINGS");

    char db_path[256];
    snprintf(db_path, sizeof(db_path), "/tmp/specus-c-admin-%ld.db", (long)getpid());
    unlink(db_path);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_TENANT_ID", "tenant-admin", 1);
    setenv("SPECUS_AUTH_USERNAME", "admin-user", 1);
    len = st_admin_build_response("POST", "/api/admin/database/initialize", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"initialized\":true")
        || !contains(response, "\"tenantId\":\"tenant-admin\"")
        || !contains(response, "\"orm\":\"sqlite3\"")
        || !contains(response, "\"dialect\":\"sqlite\"")
        || !contains(response, "\"clients\":0")) {
        fprintf(stderr, "database initialize response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/me", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"username\":\"admin-user\"")
        || !contains(response, "\"tenantId\":\"tenant-admin\"")
        || !contains(response, "\"builtIn\":true")) {
        fprintf(stderr, "management me response mismatch\n");
        return 1;
    }
    test_registration_delivery registration_delivery = {0};
    setenv("SPECUS_AUTH_REGISTRATION_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_EMAIL_FROM_ADDRESS", "noreply@example.com", 1);
    setenv("SPECUS_AUTH_SMTP_HOST", "smtp.example.com", 1);
    setenv("SPECUS_AUTH_TURNSTILE_ENABLED", "true", 1);
    setenv("SPECUS_AUTH_TURNSTILE_SITE_KEY", "site-key", 1);
    setenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY", "secret-key", 1);
    setenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL", "https://verify.example.com", 1);
    setenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES", "specus.example.com", 1);
    st_registration_set_handlers(test_registration_turnstile, test_registration_email,
                                 &registration_delivery);
    len = st_admin_build_response_with_body("POST", "/auth/register",
        "{\"username\":\"registered-user\",\"email\":\"User@Example.com\","
        "\"password\":\"password-1\",\"turnstileToken\":\"turnstile-ok\"}",
        response, sizeof(response));
    char *registration_id = st_json_get_string(response, "registrationId");
    if (len <= 0 || !contains(response, "202 Accepted")
        || !contains(response, "\"emailMasked\":\"us***@example.com\"")
        || registration_id == NULL || strlen(registration_id) != 32U
        || registration_delivery.turnstile_calls != 1 || registration_delivery.email_calls != 1
        || strcmp(registration_delivery.email, "user@example.com") != 0
        || strcmp(registration_delivery.username, "registered-user") != 0) {
        fprintf(stderr, "registration request lifecycle mismatch: %s\n", response);
        free(registration_id);
        return 1;
    }
    st_storage_management_user premature_user;
    if (st_storage_get_management_user(db_path, "registered-user", &premature_user) == 0) {
        fprintf(stderr, "registration created user before email verification\n");
        free(registration_id);
        return 1;
    }
    char verification_body[256];
    snprintf(verification_body, sizeof(verification_body),
             "{\"registrationId\":\"%s\",\"code\":\"%s\"}",
             registration_id, registration_delivery.code);
    len = st_admin_build_response_with_body("POST", "/auth/register/verify",
                                            verification_body, response, sizeof(response));
    free(registration_id);
    st_storage_management_user registered_user;
    st_password_verification registered_password;
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"accessToken\"")
        || st_storage_get_management_user(db_path, "registered-user", &registered_user) != 0
        || strcmp(registered_user.role, "USER") != 0 || !registered_user.enabled
        || st_password_verify("password-1", registered_user.password_hash, &registered_password) != 0
        || !registered_password.matches
        || st_storage_management_email_exists(db_path, "USER@example.com") != 1) {
        fprintf(stderr, "registration verification lifecycle mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response_with_body("POST", "/auth/login",
        "{\"username\":\"registered-user\",\"password\":\"password-1\"}",
        response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request") || !contains(response, "人机验证失败")) {
        fprintf(stderr, "turnstile-protected login accepted a missing token\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST", "/auth/login",
        "{\"username\":\"registered-user\",\"password\":\"password-1\","
        "\"turnstileToken\":\"login-turnstile-ok\"}", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"accessToken\"")) {
        fprintf(stderr, "turnstile-protected login response mismatch: %s\n", response);
        return 1;
    }
    st_registration_set_handlers(NULL, NULL, NULL);
    unsetenv("SPECUS_AUTH_REGISTRATION_ENABLED");
    unsetenv("SPECUS_AUTH_EMAIL_VERIFICATION_ENABLED");
    unsetenv("SPECUS_AUTH_EMAIL_FROM_ADDRESS");
    unsetenv("SPECUS_AUTH_SMTP_HOST");
    unsetenv("SPECUS_AUTH_TURNSTILE_ENABLED");
    unsetenv("SPECUS_AUTH_TURNSTILE_SITE_KEY");
    unsetenv("SPECUS_AUTH_TURNSTILE_SECRET_KEY");
    unsetenv("SPECUS_AUTH_TURNSTILE_VERIFY_URL");
    unsetenv("SPECUS_AUTH_TURNSTILE_ALLOWED_HOSTNAMES");
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/users",
                                            "{\"username\":\"alice\",\"password\":\"secret\","
                                            "\"role\":\"USER\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"username\":\"alice\"")
        || !contains(response, "\"tenantId\":\"tenant-admin\"")
        || !contains(response, "\"role\":\"USER\"")
        || !contains(response, "\"admin\":false")
        || !contains(response, "\"builtIn\":false")) {
        fprintf(stderr, "management user create response mismatch\n");
        return 1;
    }
    st_storage_management_user stored_alice;
    if (st_storage_get_management_user(db_path, "alice", &stored_alice) != 0
        || strncmp(stored_alice.password_hash,
                   "$pbkdf2-sha256$v=1$i=210000$",
                   strlen("$pbkdf2-sha256$v=1$i=210000$")) != 0) {
        fprintf(stderr, "management user password was not stored with PBKDF2\n");
        return 1;
    }
    uint8_t legacy_password_digest[ST_SHA256_LEN];
    char legacy_password_hash[ST_SHA256_HEX_LEN + 1U];
    st_sha256((const uint8_t *)"legacy-secret", strlen("legacy-secret"), legacy_password_digest);
    st_hex_encode(legacy_password_digest, sizeof(legacy_password_digest), legacy_password_hash);
    st_storage_management_user legacy_user;
    if (st_storage_create_management_user(db_path,
                                          "legacy-user",
                                          "tenant-admin",
                                          legacy_password_hash,
                                          "USER",
                                          1,
                                          &legacy_user) != 0) {
        fprintf(stderr, "legacy management user setup failed\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"legacy-user\",\"password\":\"legacy-secret\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || st_storage_get_management_user(db_path, "legacy-user", &legacy_user) != 0
        || strcmp(legacy_user.password_hash, legacy_password_hash) == 0
        || strncmp(legacy_user.password_hash,
                   "$pbkdf2-sha256$v=1$i=210000$",
                   strlen("$pbkdf2-sha256$v=1$i=210000$")) != 0) {
        fprintf(stderr, "legacy management user hash was not upgraded on login\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/users", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"username\":\"admin-user\"")
        || !contains(response, "\"username\":\"alice\"")) {
        fprintf(stderr, "management user list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/client-credentials",
                                            "{\"apiKey\":\"ck-c-test\",\"secret\":\"secret-c\","
                                            "\"enabled\":true,\"maxOnlineInstances\":5}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"credential\":")
        || !contains(response, "\"apiKey\":\"ck-c-test\"")
        || !contains(response, "\"secret\":\"secret-c\"")
        || !contains(response, "\"maxOnlineInstances\":5")) {
        fprintf(stderr, "credential create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/client-credentials", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"apiKey\":\"ck-c-test\"")
        || contains(response, "\"secret\":\"secret-c\"")) {
        fprintf(stderr, "credential list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("PUT",
                                            "/api/admin/client-credentials/1",
                                            "{\"secret\":\"secret-c2\",\"enabled\":false,"
                                            "\"maxOnlineInstances\":6}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"secret\":\"secret-c2\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"maxOnlineInstances\":6")) {
        fprintf(stderr, "credential update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/client-credentials/1", response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "credential delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/client-downloads",
                                            "{\"implementation\":\"java\",\"platform\":\"any\",\"arch\":\"any\","
                                            "\"displayName\":\"Java exec jar\","
                                            "\"downloadUrl\":\"https://example.com/specus.jar\","
                                            "\"description\":\"cross platform\","
                                            "\"displayOrder\":20,\"enabled\":false}",
                                            response,
                                            sizeof(response));
    int disabled_download_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"displayName\":\"Java exec jar\"")
        || !contains(response, "\"enabled\":false")
        || st_json_get_int(response, "id", &disabled_download_id) != 0
        || disabled_download_id <= 0) {
        fprintf(stderr, "client download disabled create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/client-downloads",
                                            "{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\","
                                            "\"displayName\":\"Linux x64\","
                                            "\"downloadUrl\":\"https://example.com/specus-linux-amd64\","
                                            "\"version\":\"2.0.0\","
                                            "\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
                                            "\"fileSize\":123,\"minSupportedVersion\":\"1.5.0\","
                                            "\"changelogUrl\":\"https://example.com/changelog\",\"displayOrder\":10}",
                                            response,
                                            sizeof(response));
    int enabled_download_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"implementation\":\"go\"")
        || !contains(response, "\"platform\":\"linux\"")
        || !contains(response, "\"arch\":\"x64\"")
        || !contains(response, "\"enabled\":true")
        || !contains(response, "\"version\":\"2.0.0\"")
        || st_json_get_int(response, "id", &enabled_download_id) != 0
        || enabled_download_id <= 0) {
        fprintf(stderr, "client download enabled create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/public/client-downloads", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || contains(response, "\"displayName\":\"Linux x64\"")
        || contains(response, "\"displayName\":\"Java exec jar\"")) {
        fprintf(stderr, "unpublished client download leaked into public list\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/client-downloads/%d", enabled_download_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"implementation\":\"csharp\",\"platform\":\"windows\",\"arch\":\"x64\","
                                            "\"displayName\":\"Windows x64\","
                                            "\"downloadUrl\":\"https://example.com/specus-win-x64.zip\","
                                            "\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"implementation\":\"csharp\"")
        || !contains(response, "\"displayName\":\"Windows x64\"")
        || !contains(response, "\"displayOrder\":10")) {
        fprintf(stderr, "client download update response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/client-downloads/%d/latest", enabled_download_id);
    len = st_admin_build_response("POST", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"isLatest\":true")) {
        fprintf(stderr, "client download latest response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/public/client-downloads", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"displayName\":\"Windows x64\"")
        || contains(response, "\"displayName\":\"Java exec jar\"")) {
        fprintf(stderr, "published client download public list mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET",
        "/api/public/client-version-check?implementation=csharp&platform=windows&arch=x64&current=1.0.0",
        response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"updateAvailable\":true")
        || !contains(response, "\"mandatory\":true")
        || !contains(response, "\"latestVersion\":\"2.0.0\"")
        || !contains(response, "\"fileSize\":123")) {
        fprintf(stderr, "client version check response mismatch: %s\n", response);
        return 1;
    }
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP", "2", 1);
    setenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_WINDOW_SECONDS", "60", 1);
    st_client_package_rate_limit_reset();
    len = st_admin_build_response_with_remote("GET", "/api/public/client-downloads", NULL,
                                              "198.51.100.41", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "client package shared rate limit first request mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_remote("GET",
        "/api/public/client-version-check?implementation=csharp&platform=windows&arch=x64&current=1.0.0",
        NULL, "198.51.100.41", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")) {
        fprintf(stderr, "client package shared rate limit second request mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_remote("GET", "/api/public/client-downloads", NULL,
                                              "198.51.100.41", response, sizeof(response));
    if (len <= 0 || !contains(response, "429 Too Many Requests")
        || !contains(response, "Retry-After:")) {
        fprintf(stderr, "client package shared rate limit rejection mismatch: %s\n", response);
        return 1;
    }
    unsetenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_PER_IP");
    unsetenv("SPECUS_CLIENT_PACKAGE_PUBLIC_RATE_LIMIT_WINDOW_SECONDS");
    st_client_package_rate_limit_reset();
    len = st_admin_build_response("GET", "/api/admin/client-downloads", response, sizeof(response));
    const char *windows_pos = strstr(response, "\"displayName\":\"Windows x64\"");
    const char *java_pos = strstr(response, "\"displayName\":\"Java exec jar\"");
    if (len <= 0 || !contains(response, "200 OK") || windows_pos == NULL || java_pos == NULL
        || windows_pos > java_pos) {
        fprintf(stderr, "client download admin list order mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/client-downloads/%d", disabled_download_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "client download delete response mismatch\n");
        return 1;
    }
    char package_data_dir[256];
    snprintf(package_data_dir, sizeof(package_data_dir), "/tmp/specus-c-packages-%ld", (long)getpid());
    setenv("SPECUS_CLIENT_PACKAGE_DATA_DIRECTORY", package_data_dir, 1);
    static const char multipart_template[] =
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"implementation\"\r\n\r\n"
        "android\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"platform\"\r\n\r\n"
        "android\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"arch\"\r\n\r\n"
        "any\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"version\"\r\n\r\n"
        "3.0.0\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"displayName\"\r\n\r\n"
        "Specus Android\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"minSupportedVersion\"\r\n\r\n"
        "2.0.0\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"isLatest\"\r\n\r\n"
        "true\r\n"
        "--specus-package-test\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"untrusted.apk\"\r\n"
        "Content-Type: application/vnd.android.package-archive\r\n\r\n"
        "hosted-package-bytes\r\n"
        "--specus-package-test--\r\n";
    len = st_admin_build_response_with_content("POST", "/api/admin/client-packages", NULL,
        "multipart/form-data; boundary=specus-package-test",
        (const uint8_t *)multipart_template, sizeof(multipart_template) - 1U,
        response, sizeof(response));
    int hosted_package_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"hosted\":true")
        || !contains(response, "\"isLatest\":true")
        || !contains(response, "\"version\":\"3.0.0\"")
        || !contains(response, "\"fileSize\":20")
        || st_json_get_int(response, "id", &hosted_package_id) != 0 || hosted_package_id <= 0) {
        fprintf(stderr, "hosted client package upload mismatch: %s\n", response);
        return 1;
    }
    st_storage_client_download_link hosted_package;
    if (st_storage_get_client_download_link(db_path, hosted_package_id, &hosted_package) != 0
        || !st_client_package_is_readable(&hosted_package)
        || strcmp(hosted_package.package_file_name, "Specus Android.apk") != 0
        || !contains(hosted_package.download_url, "/api/public/client-packages/")) {
        fprintf(stderr, "hosted client package catalogue/file mismatch\n");
        return 1;
    }
    int package_sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, package_sockets) != 0) {
        fprintf(stderr, "hosted package socketpair failed\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/public/client-packages/%d/download", hosted_package_id);
    int download_handled = st_client_package_send_download(
        package_sockets[0], "GET", request_path, db_path, "198.51.100.40");
    shutdown(package_sockets[0], SHUT_WR);
    char package_response[4096];
    ssize_t package_response_len = recv(package_sockets[1], package_response,
                                        sizeof(package_response) - 1U, 0);
    close(package_sockets[0]);
    close(package_sockets[1]);
    if (package_response_len <= 0) package_response_len = 0;
    package_response[package_response_len] = '\0';
    if (download_handled != 1 || !contains(package_response, "200 OK")
        || !contains(package_response, "Content-Type: application/octet-stream")
        || !contains(package_response, "X-Checksum-SHA256:")
        || !contains(package_response, "hosted-package-bytes")) {
        fprintf(stderr, "hosted client package download mismatch: %s\n", package_response);
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/client-downloads/%d", hosted_package_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")
        || st_client_package_is_readable(&hosted_package)) {
        fprintf(stderr, "hosted client package delete mismatch\n");
        return 1;
    }
    char package_directory[320];
    snprintf(package_directory, sizeof(package_directory), "%s/packages", package_data_dir);
    rmdir(package_directory);
    rmdir(package_data_dir);
    unsetenv("SPECUS_CLIENT_PACKAGE_DATA_DIRECTORY");
    len = st_admin_build_response_with_body("POST", "/api/admin/diagrams",
                                            "{\"name\":\"Flow A\",\"update\":\"YWJj\"}",
                                            response, sizeof(response));
    int diagram_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"name\":\"Flow A\"")
        || !contains(response, "\"sizeBytes\":3")
        || !contains(response, "\"revision\":0")
        || st_json_get_int(response, "id", &diagram_id) != 0 || diagram_id <= 0) {
        fprintf(stderr, "diagram create response mismatch: %s\n", response);
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/diagrams/%d", diagram_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"update\":\"YWJj\"")) {
        fprintf(stderr, "diagram detail response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response_with_body("PUT", request_path,
                                            "{\"name\":\"Flow B\",\"update\":\"YWJjZA==\",\"revision\":0}",
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"revision\":1")
        || !contains(response, "\"sizeBytes\":4")) {
        fprintf(stderr, "diagram update response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response_with_body("PUT", request_path,
                                            "{\"name\":\"stale\",\"update\":\"YWJj\",\"revision\":0}",
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")) {
        fprintf(stderr, "diagram optimistic-lock response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/diagrams", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"name\":\"Flow B\"")) {
        fprintf(stderr, "diagram list response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "diagram delete response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"alice\",\"password\":\"secret\"}",
                                            response,
                                            sizeof(response));
    char *alice_token = st_json_get_string(response, "accessToken");
    if (len <= 0 || !contains(response, "200 OK") || alice_token == NULL) {
        fprintf(stderr, "database user login response mismatch\n");
        free(alice_token);
        return 1;
    }
    snprintf(authorization, sizeof(authorization), "Bearer %s", alice_token);
    len = st_admin_build_response_with_auth("GET", "/api/admin/me", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"username\":\"alice\"")
        || !contains(response, "\"admin\":false")) {
        fprintf(stderr, "database user me response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/users", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "database user admin-only response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/database/initialize",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "database user initialize admin-only response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/client-downloads",
                                            authorization,
                                            "{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"arm64\","
                                            "\"displayName\":\"Forbidden\","
                                            "\"downloadUrl\":\"https://example.com/forbidden\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "database user client download admin-only response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/clients", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || contains(response, "\"clientName\":\"Demo client\"")) {
        fprintf(stderr, "database user client visibility response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/clients/1/specus-mappings",
                                            authorization,
                                            "{\"listenPort\":19001,\"targetAddress\":\"127.0.0.1\",\"targetPort\":9001}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "database user foreign specus create response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/clients",
                                            authorization,
                                            "{\"clientName\":\"Alice managed\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    int alice_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"ownerUsername\":\"alice\"")
        || st_json_get_int(response, "id", &alice_client_id) != 0
        || alice_client_id <= 0) {
        fprintf(stderr, "database user client create response mismatch\n");
        free(alice_token);
        return 1;
    }
    st_storage_client alice_client;
    st_storage_client owner_case_client;
    st_storage_client tenant_case_client;
    if (st_storage_get_client(db_path, alice_client_id, &alice_client) != 0
        || st_storage_upsert_client(db_path,
                                    0,
                                    "tenant-admin",
                                    "Owner case client",
                                    "Alice",
                                    1,
                                    30,
                                    &owner_case_client) != 0
        || st_storage_upsert_client(db_path,
                                    0,
                                    "TENANT-ADMIN",
                                    "Tenant case client",
                                    "alice",
                                    1,
                                    30,
                                    &tenant_case_client) != 0) {
        fprintf(stderr, "peer mesh case-sensitive client setup failed\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/clients", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || contains(response, "Owner case client")
        || contains(response, "Tenant case client")) {
        fprintf(stderr, "client tenant/owner visibility must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    char case_acl_body[256];
    snprintf(case_acl_body,
             sizeof(case_acl_body),
             "{\"sourceClientId\":%lld,\"targetClientId\":%d}",
             owner_case_client.id,
             alice_client_id);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            case_acl_body,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "source client not found")) {
        fprintf(stderr, "peer mesh acl source-owner authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(case_acl_body,
             sizeof(case_acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%lld}",
             alice_client_id,
             owner_case_client.id);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            case_acl_body,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request") || !contains(response, "cross-user peer ACL")) {
        fprintf(stderr, "peer mesh acl target-owner authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(case_acl_body,
             sizeof(case_acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%lld}",
             alice_client_id,
             tenant_case_client.id);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            case_acl_body,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "target client not found")) {
        fprintf(stderr, "peer mesh acl tenant authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    st_storage_peer_mesh_acl hidden_case_acl;
    if (st_storage_upsert_peer_mesh_acl(db_path,
                                        "tenant-admin",
                                        "Alice",
                                        &alice_client,
                                        &owner_case_client,
                                        1,
                                        "OUTBOUND",
                                        &hidden_case_acl) != 0) {
        fprintf(stderr, "peer mesh case-sensitive acl setup failed\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || contains(response, "Owner case client")) {
        fprintf(stderr, "peer mesh acl owner visibility must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/acls/%lld", hidden_case_acl.id);
    len = st_admin_build_response_with_auth("DELETE", request_path, authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "peer mesh acl delete authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d", alice_client_id);
    len = st_admin_build_response_with_auth("DELETE", request_path, authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "database user client delete response mismatch\n");
        free(alice_token);
        return 1;
    }
    free(alice_token);
    if (test_management_token_follows_user_record() != 0) {
        return 1;
    }
    len = st_admin_build_response_with_body("PUT",
                                            "/api/admin/users/alice",
                                            "{\"role\":\"ADMIN\",\"enabled\":false}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"role\":\"ADMIN\"")
        || !contains(response, "\"admin\":true")
        || !contains(response, "\"enabled\":false")) {
        fprintf(stderr, "management user update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"alice\",\"password\":\"secret\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "disabled database user login response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/users/alice", response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "management user delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/clients", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || contains(response, "\"clientName\":\"Demo client\"")) {
        fprintf(stderr, "clients list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/clients",
                                            "{\"clientName\":\"C managed\",\"enabled\":true,"
                                            "\"connectionRateLimitPerMinute\":55}",
                                            response,
                                            sizeof(response));
    int created_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"ownerUsername\":\"admin-user\"")
        || !contains(response, "\"connectionRateLimitPerMinute\":55")
        || st_json_get_int(response, "id", &created_client_id) != 0
        || created_client_id <= 0) {
        fprintf(stderr, "client create response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d/nat-control", created_client_id);
    len = st_admin_build_response("POST", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")
        || !contains(response, "客户端不在线")) {
        fprintf(stderr, "offline nat-control response mismatch\n");
        return 1;
    }
    nat_control_expected_client_id = created_client_id;
    nat_control_push_calls = 0;
    st_admin_set_nat_control_handler(test_nat_control_push, NULL);
    len = st_admin_build_response("POST", request_path, response, sizeof(response));
    st_admin_set_nat_control_handler(NULL, NULL);
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"pushed\":0")
        || !contains(response, "\"specusMappings\":0")
        || !contains(response, "\"httpRoutes\":-1")
        || nat_control_push_calls != 1) {
        fprintf(stderr, "online nat-control response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/clients",
                                            "{\"clientName\":\"C peer target\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    int target_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"clientName\":\"C peer target\"")
        || st_json_get_int(response, "id", &target_client_id) != 0
        || target_client_id <= 0) {
        fprintf(stderr, "peer target client create response mismatch\n");
        return 1;
    }
    char acl_body[256];
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"allowed\":true,\"direction\":\"both\"}",
             created_client_id,
             target_client_id);
    peer_mesh_refresh_calls = 0;
    st_admin_set_peer_mesh_refresh_handler(test_peer_mesh_refresh, NULL);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    int created_acl_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"sourceClientName\":\"C managed\"")
        || !contains(response, "\"targetClientName\":\"C peer target\"")
        || !contains(response, "\"allowed\":true")
        || !contains(response, "\"direction\":\"BOTH\"")
        || st_json_get_int(response, "id", &created_acl_id) != 0
        || created_acl_id <= 0) {
        fprintf(stderr, "peer mesh acl create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/acls", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"sourceClientName\":\"C managed\"")
        || !contains(response, "\"targetClientName\":\"C peer target\"")
        || !contains(response, "\"direction\":\"BOTH\"")) {
        fprintf(stderr, "peer mesh acl list response mismatch\n");
        return 1;
    }
    if (test_peer_mesh_egress_policy_validation(target_client_id) != 0
        || test_peer_mesh_egress_admin_only(target_client_id) != 0) {
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"allowed\":true}",
             created_client_id,
             target_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"direction\":\"BOTH\"")) {
        fprintf(stderr, "peer mesh acl omitted direction should preserve existing value\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"allowed\":true}",
             target_client_id,
             created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    int default_direction_acl_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"direction\":\"OUTBOUND\"")
        || st_json_get_int(response, "id", &default_direction_acl_id) != 0
        || default_direction_acl_id <= 0) {
        fprintf(stderr, "peer mesh acl default direction response mismatch\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"direction\":\"inbound\"}",
             target_client_id,
             created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"direction\":\"INBOUND\"")) {
        fprintf(stderr, "peer mesh acl inbound direction response mismatch\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d}",
             target_client_id,
             created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"direction\":\"INBOUND\"")) {
        fprintf(stderr, "peer mesh acl omitted direction should preserve inbound value\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"direction\":\"SIDEWAYS\"}",
             created_client_id,
             target_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")
        || !contains(response, "invalid direction: SIDEWAYS")) {
        fprintf(stderr, "peer mesh acl direction validation mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/acls/%d", default_direction_acl_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "default direction peer mesh acl delete response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/acls/%d", created_acl_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "peer mesh acl delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"online\":false")
        || !contains(response, "\"virtualDeviceStatus\":\"DOWN\"")) {
        fprintf(stderr, "peer mesh devices from clients response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/devices/%d", created_client_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"enabled\":true")
        || !contains(response, "\"virtualDeviceStatus\":\"DOWN\"")) {
        fprintf(stderr, "peer mesh device update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"enabled\":true")) {
        fprintf(stderr, "peer mesh devices updated list response mismatch\n");
        return 1;
    }
    char peer_session_sql[2048];
    snprintf(peer_session_sql,
             sizeof(peer_session_sql),
             "INSERT INTO peer_mesh_session("
             "id, tenant_id, source_client_id, source_client_name, target_client_id, target_client_name, "
             "path_type, status, token_hash, started_at, updated_at, expires_at, rtt_millis, "
             "local_endpoint, remote_endpoint, direct_bytes, relay_bytes, last_traffic_at) VALUES "
             "(99001, 'tenant-admin', %d, 'C managed', %d, 'C peer target', 'DIRECT', 'ACTIVE', 'hash-a', "
             "'2026-06-25T01:00:00Z', '2026-06-25T01:01:00Z', '2026-06-25T02:00:00Z', 12, "
             "'10.0.0.1:10000', '10.0.0.2:10001', 128, 0, '2026-06-25T01:01:00Z'),"
             "(99002, 'tenant-admin', %d, 'C managed', %d, 'C peer target', 'RELAY', 'NEGOTIATING', 'hash-b', "
             "'2026-06-25T01:02:00Z', '2026-06-25T01:03:00Z', '2026-06-25T02:03:00Z', NULL, "
             "NULL, 'relay.example:3478', 0, 64, NULL)",
             created_client_id,
             target_client_id,
             created_client_id,
             target_client_id);
    if (test_exec_sql(db_path, peer_session_sql) != 0) {
        fprintf(stderr, "peer mesh session seed failed\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/sessions?limit=10", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"id\":99001")
        || !contains(response, "\"pathType\":\"DIRECT\"")
        || !contains(response, "\"rttMillis\":12")
        || !contains(response, "\"directBytes\":128")
        || !contains(response, "\"id\":99002")
        || !contains(response, "\"pathType\":\"RELAY\"")) {
        fprintf(stderr, "peer mesh session list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions/99001", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"id\":99001")
        || !contains(response, "\"status\":\"CLOSED\"")
        || !contains(response, "\"closedAt\":")) {
        fprintf(stderr, "peer mesh session close response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"id\":99002")
        || !contains(response, "\"status\":\"CLOSED\"")
        || contains(response, "\"id\":99001")) {
        fprintf(stderr, "peer mesh open session close response mismatch\n");
        return 1;
    }
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/stats", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"totalSessions\":2")
        || !contains(response, "\"pathTypes\":")) {
        fprintf(stderr, "peer mesh stats response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/service-sharing", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"deploymentEnabled\":true")
        || !contains(response, "\"peerServiceDiscoveryVersion\":2")) {
        fprintf(stderr, "peer service sharing status mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("PUT", "/api/admin/peer-mesh/service-sharing",
                                            "{\"enabled\":true,\"mdnsImportEnabled\":true}",
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"configuredEnabled\":true")
        || !contains(response, "\"effectiveEnabled\":true")
        || !contains(response, "\"mdnsImportEnabled\":true")) {
        fprintf(stderr, "peer service sharing update mismatch\n");
        return 1;
    }
    snprintf(body, sizeof(body),
             "{\"clientId\":%d,\"serviceId\":\"service-test\",\"name\":\"Local API\","
             "\"description\":\"test service\",\"transport\":\"tcp\",\"application\":\"http\","
             "\"targetHost\":\"127.0.0.1\",\"targetPort\":8080,\"publishedPort\":18080,"
             "\"path\":\"/api\",\"enabled\":true,\"visibility\":\"ACL\","
             "\"allowedClientIds\":[%d]}", created_client_id, target_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/services", body,
                                            response, sizeof(response));
    int created_service_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"serviceId\":\"service-test\"")
        || !contains(response, "\"publishedPort\":18080")
        || st_json_get_int(response, "id", &created_service_id) != 0 || created_service_id <= 0) {
        fprintf(stderr, "peer service create mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/services", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"targetHost\":\"127.0.0.1\"")
        || !contains(response, "\"allowedClientIds\":[")) {
        fprintf(stderr, "peer service list mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/services/%d", created_service_id);
    len = st_admin_build_response_with_body("PUT", request_path,
                                            "{\"name\":\"Local API v2\",\"publishedPort\":18081}",
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"name\":\"Local API v2\"")
        || !contains(response, "\"publishedPort\":18081")) {
        fprintf(stderr, "peer service update mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "peer service delete mismatch\n");
        return 1;
    }
    if (test_peer_service_definition_validation(created_client_id) != 0) {
        return 1;
    }
    st_admin_set_peer_mesh_refresh_handler(NULL, NULL);
    if (peer_mesh_refresh_calls < 5) {
        fprintf(stderr, "peer mesh admin mutations did not trigger runtime refresh\n");
        return 1;
    }
    unsetenv("SPECUS_PEER_MESH_ENABLED");
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d", created_client_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"clientName\":\"C managed 2\",\"enabled\":false,"
                                            "\"connectionRateLimitPerMinute\":12}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"connectionRateLimitPerMinute\":12")) {
        fprintf(stderr, "client update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"enabled\":true")) {
        fprintf(stderr, "client re-enable response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d/specus-mappings", created_client_id);
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            "{\"listenPort\":19090,\"targetAddress\":\"127.0.0.1\","
                                            "\"targetPort\":9090,\"enabled\":true,\"detailCaptureEnabled\":true}",
                                            response,
                                            sizeof(response));
    int created_specus_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"listenPort\":19090")
        || !contains(response, "\"targetAddress\":\"127.0.0.1\"")
        || !contains(response, "\"targetPort\":9090")
        || !contains(response, "\"detailCaptureEnabled\":true")
        || st_json_get_int(response, "id", &created_specus_id) != 0
        || created_specus_id <= 0) {
        fprintf(stderr, "specus create response mismatch\n");
        return 1;
    }
    snprintf(body, sizeof(body), "{\"clientId\":%d}", created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/services/import", body,
                                            response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"created\":1")
        || !contains(response, "\"serviceId\":\"import-tcp-")
        || !contains(response, "\"publishedPort\":19090")) {
        fprintf(stderr, "peer TCP service import mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/service-audit", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"action\":\"service-import\"")
        || !contains(response, "\"reason\":\"created=1,skipped=0\"")) {
        fprintf(stderr, "peer service audit mismatch: %s\n", response);
        return 1;
    }
    if (test_peer_service_audit_bounded() != 0) {
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/specus-mappings?clientId=%d", created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientId\":")
        || !contains(response, "\"listenPort\":19090")) {
        fprintf(stderr, "specus filtered list response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/specus-mappings/%d", created_specus_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"listenPort\":19091,\"targetAddress\":\"192.168.1.12\","
                                            "\"targetPort\":9091,\"enabled\":false,"
                                            "\"detailCaptureEnabled\":false}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"listenPort\":19091")
        || !contains(response, "\"targetAddress\":\"192.168.1.12\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"detailCaptureEnabled\":false")) {
        fprintf(stderr, "specus update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "specus delete response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d/http-routes", created_client_id);
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            "{\"route\":\"missing-auth\",\"targetBaseUrl\":\"http://127.0.0.1:8080\","
                                            "\"authEnabled\":true,\"authUsername\":\"visitor\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")) {
        fprintf(stderr, "http route missing authentication password was not rejected\n");
        return 1;
    }
    memset(body, 'u', 121U);
    body[121] = '\0';
    char invalid_route_auth[1024];
    snprintf(invalid_route_auth,
             sizeof(invalid_route_auth),
             "{\"route\":\"long-user\",\"targetBaseUrl\":\"http://127.0.0.1:8080\","
             "\"authEnabled\":true,\"authUsername\":\"%.121s\",\"authPassword\":\"secret\"}",
             body);
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            invalid_route_auth,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")) {
        fprintf(stderr, "http route authentication username length was not enforced\n");
        return 1;
    }
    memset(body, 'p', 257U);
    body[257] = '\0';
    snprintf(invalid_route_auth,
             sizeof(invalid_route_auth),
             "{\"route\":\"long-password\",\"targetBaseUrl\":\"http://127.0.0.1:8080\","
             "\"authEnabled\":true,\"authUsername\":\"visitor\",\"authPassword\":\"%.257s\"}",
             body);
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            invalid_route_auth,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")) {
        fprintf(stderr, "http route authentication password length was not enforced\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            "{\"route\":\"media\",\"targetBaseUrl\":\"https://example.com/media\","
                                            "\"mediaCaptureEnabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"mediaCaptureEnabled\":true")) {
        fprintf(stderr, "HTTP media capture route create mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            "{\"route\":\"api\",\"targetBaseUrl\":\"https://example.com/base\","
                                            "\"enabled\":true,\"detailCaptureEnabled\":true,"
                                            "\"pathRewriteEnabled\":true,\"insecureSkipVerify\":true,\"authEnabled\":true,"
                                            "\"authUsername\":\"visitor\",\"authPassword\":\"secret\"}",
                                            response,
                                            sizeof(response));
    int created_route_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"https://example.com/base\"")
        || !contains(response, "\"detailCaptureEnabled\":true")
        || !contains(response, "\"mediaCaptureEnabled\":false")
        || !contains(response, "\"pathRewriteEnabled\":true")
        || !contains(response, "\"insecureSkipVerify\":true")
        || !contains(response, "\"authEnabled\":true")
        || !contains(response, "\"authUsername\":\"visitor\"")
        || !contains(response, "\"authPasswordConfigured\":true")
        || contains(response, "\"authPasswordHash\"")
        || contains(response, "\"authPassword\":")
        || contains(response, "secret")
        || st_json_get_int(response, "id", &created_route_id) != 0
        || created_route_id <= 0) {
        fprintf(stderr, "http route create response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/http-routes?clientId=%d", created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"https://example.com/base\"")
        || !contains(response, "\"mediaCaptureEnabled\":false")
        || !contains(response, "\"insecureSkipVerify\":true")
        || !contains(response, "\"authEnabled\":true")
        || !contains(response, "\"authUsername\":\"visitor\"")
        || !contains(response, "\"authPasswordConfigured\":true")
        || contains(response, "\"authPasswordHash\"")
        || contains(response, "\"authPassword\":")
        || contains(response, "secret")) {
        fprintf(stderr, "http route filtered list response mismatch\n");
        return 1;
    }
    uint8_t expected_route_password_digest[ST_SHA256_LEN];
    char expected_route_password_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"secret", strlen("secret"), expected_route_password_digest);
    st_hex_encode(expected_route_password_digest,
                  sizeof(expected_route_password_digest),
                  expected_route_password_hash);
    st_storage_http_route stored_auth_route;
    if (st_storage_get_http_route_by_client_route(db_path,
                                                  "C managed 2",
                                                  "api",
                                                  &stored_auth_route) != 0
        || stored_auth_route.auth_enabled != 1
        || stored_auth_route.insecure_skip_verify != 1
        || strcmp(stored_auth_route.auth_username, "visitor") != 0
        || strcmp(stored_auth_route.auth_password_hash, expected_route_password_hash) != 0
        || strcmp(stored_auth_route.auth_password_hash, "secret") == 0) {
        fprintf(stderr, "http route authentication storage mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/http-routes/%d", created_route_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"mediaCaptureEnabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"mediaCaptureEnabled\":true")) {
        fprintf(stderr, "HTTP media capture route update mismatch\n");
        return 1;
    }
    int route_authentication_failed = test_log_safe_reason() != 0
        || test_direct_http_route_authentication(db_path) != 0;
    unsetenv("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED");
    if (route_authentication_failed) {
        return 1;
    }
    st_direct_http_response rewrite_response;
    memset(&rewrite_response, 0, sizeof(rewrite_response));
    rewrite_response.status_code = 200;
    rewrite_response.headers_len = 2;
    rewrite_response.headers = (char **)calloc(rewrite_response.headers_len, sizeof(*rewrite_response.headers));
    const char *rewrite_html = "<html><head><title>x</title></head><body>"
        "<a href=\"/login\"><img src='/img/logo.png' srcset=\"/a.png 1x, /b.png 2x\"></body></html>";
    if (rewrite_response.headers == NULL
        || (rewrite_response.headers[0] = test_dup_string("Content-Type: text/html; charset=UTF-8")) == NULL
        || (rewrite_response.headers[1] = test_dup_string("ETag: \"old\"")) == NULL
        || (rewrite_response.body = test_dup_body(rewrite_html, &rewrite_response.body_len)) == NULL) {
        fprintf(stderr, "direct http rewrite fixture allocation failed\n");
        st_direct_http_response_free(&rewrite_response);
        return 1;
    }
    if (st_admin_rewrite_direct_http_response("C managed 2", "api", &rewrite_response) != 1
        || !contains((const char *)rewrite_response.body, "href=\"/http/C managed 2/api/login\"")
        || !contains((const char *)rewrite_response.body, "src='/http/C managed 2/api/img/logo.png'")
        || !contains((const char *)rewrite_response.body, "/http/C managed 2/api/a.png 1x")
        || !contains((const char *)rewrite_response.body,
                     "<script src=\"/specus-http-route-runtime.js?v=4\" "
                     "data-specus-prefix=\"/http/C managed 2/api\"></script>")
        || contains((const char *)rewrite_response.body, "<script>")
        || rewrite_response.headers[1] != NULL) {
        fprintf(stderr, "direct http html rewrite response mismatch\n");
        st_direct_http_response_free(&rewrite_response);
        return 1;
    }
    st_direct_http_response_free(&rewrite_response);

    memset(&rewrite_response, 0, sizeof(rewrite_response));
    rewrite_response.status_code = 200;
    rewrite_response.headers_len = 2;
    rewrite_response.headers = (char **)calloc(rewrite_response.headers_len, sizeof(*rewrite_response.headers));
    rewrite_response.body = test_gzip_body((const uint8_t *)rewrite_html,
                                           strlen(rewrite_html),
                                           &rewrite_response.body_len);
    if (rewrite_response.headers == NULL
        || (rewrite_response.headers[0] = test_dup_string("Content-Type: text/html")) == NULL
        || (rewrite_response.headers[1] = test_dup_string("Content-Encoding: gzip")) == NULL
        || rewrite_response.body == NULL
        || st_admin_rewrite_direct_http_response("C managed 2", "api", &rewrite_response) != 1
        || !contains((const char *)rewrite_response.body, "href=\"/http/C managed 2/api/login\"")
        || rewrite_response.headers[1] != NULL) {
        fprintf(stderr, "bounded gzip response rewrite mismatch\n");
        st_direct_http_response_free(&rewrite_response);
        return 1;
    }
    st_direct_http_response_free(&rewrite_response);

    size_t bomb_plain_len = 1024U * 1024U;
    uint8_t *bomb_plain = (uint8_t *)calloc(bomb_plain_len, 1U);
    memset(&rewrite_response, 0, sizeof(rewrite_response));
    rewrite_response.status_code = 200;
    rewrite_response.headers_len = 2;
    rewrite_response.headers = (char **)calloc(rewrite_response.headers_len, sizeof(*rewrite_response.headers));
    rewrite_response.body = bomb_plain == NULL
        ? NULL
        : test_gzip_body(bomb_plain, bomb_plain_len, &rewrite_response.body_len);
    free(bomb_plain);
    uint8_t *original_bomb_body = rewrite_response.body;
    size_t original_bomb_len = rewrite_response.body_len;
    if (rewrite_response.headers == NULL
        || (rewrite_response.headers[0] = test_dup_string("Content-Type: text/html")) == NULL
        || (rewrite_response.headers[1] = test_dup_string("Content-Encoding: gzip")) == NULL
        || rewrite_response.body == NULL
        || st_admin_rewrite_direct_http_response("C managed 2", "api", &rewrite_response) != 0
        || rewrite_response.body != original_bomb_body
        || rewrite_response.body_len != original_bomb_len
        || rewrite_response.headers[1] == NULL) {
        fprintf(stderr, "gzip decompression bomb was not safely passed through without rewrite\n");
        st_direct_http_response_free(&rewrite_response);
        return 1;
    }
    st_direct_http_response_free(&rewrite_response);

    setenv("SPECUS_CLIENT_ACCESS_TOKEN", "db-route-token", 1);
    setenv("SPECUS_CLIENT_NAME", "C managed 2", 1);
    len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"httpSpecusConfigList\":[")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"https://example.com/base\"")
        || !contains(response, "\"insecureSkipVerify\":true")) {
        fprintf(stderr, "client auth database http route response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_CLIENT_ACCESS_TOKEN");
    unsetenv("SPECUS_CLIENT_NAME");
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"route\":\"web\",\"targetBaseUrl\":\"http://127.0.0.1:8088\","
                                            "\"enabled\":false,\"detailCaptureEnabled\":false,"
                                            "\"pathRewriteEnabled\":false,\"insecureSkipVerify\":false,\"authEnabled\":false,"
                                            "\"authUsername\":\"visitor\",\"authPassword\":\"   \"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"route\":\"web\"")
        || !contains(response, "\"targetBaseUrl\":\"http://127.0.0.1:8088\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"pathRewriteEnabled\":false")
        || !contains(response, "\"insecureSkipVerify\":false")
        || !contains(response, "\"authEnabled\":false")
        || !contains(response, "\"authUsername\":\"visitor\"")
        || !contains(response, "\"authPasswordConfigured\":true")
        || contains(response, "\"authPasswordHash\"")
        || contains(response, "\"authPassword\":")) {
        fprintf(stderr, "http route update response mismatch\n");
        return 1;
    }
    if (st_storage_get_http_route_by_client_route(db_path,
                                                  "C managed 2",
                                                  "web",
                                                  &stored_auth_route) != 0
        || strcmp(stored_auth_route.auth_password_hash, expected_route_password_hash) != 0) {
        fprintf(stderr, "blank http route auth password should retain the configured digest\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "http route delete response mismatch\n");
        return 1;
    }
    if (getenv("SPECUS_C_ADMIN_HTTP_AUTH_TEST_ONLY") != NULL) {
        unsetenv("SPECUS_DATABASE_PATH");
        unsetenv("SPECUS_AUTH_TENANT_ID");
        unsetenv("SPECUS_AUTH_USERNAME");
        unlink(db_path);
        return 0;
    }
    if (st_storage_record_connection_detail_with_tenant_and_id(db_path,
                                                               "tenant-admin",
                                                               created_client_id,
                                                               "C managed 2",
                                                               "admin-chan",
                                                               "127.0.0.1:62100",
                                                               1,
                                                               NULL,
                                                               "CLIENT_CLOSED",
                                                               "2026-06-20T02:00:00Z",
                                                               "2026-06-20T02:05:00Z",
                                                               NULL) != 0) {
        fprintf(stderr, "connection seed failed\n");
        return 1;
    }
    snprintf(request_path,
             sizeof(request_path),
             "/api/admin/connections?clientId=%d&success=true"
             "&from=2026-06-20T02%%3A00%%3A00Z"
             "&to=2026-06-20T03%%3A00%%3A00Z&page=0&size=10",
             created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"items\":[")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"page\":0")
        || !contains(response, "\"size\":10")
        || !contains(response, "\"totalPages\":1")
        || !contains(response, "\"clientId\":")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"channelId\":\"admin-chan\"")
        || !contains(response, "\"remoteAddress\":\"127.0.0.1:62100\"")
        || !contains(response, "\"success\":true")
        || !contains(response, "\"disconnectReason\":\"CLIENT_CLOSED\"")
        || !contains(response, "\"disconnectReasonText\":\"客户端正常断开\"")) {
        fprintf(stderr, "connection list response mismatch\n");
        return 1;
    }
    if (st_storage_archive_connections(db_path, "2026-06-21T00:00:00Z") != 0) {
        fprintf(stderr, "connection archive failed\n");
        return 1;
    }
    len = st_admin_build_response("GET",
                                  "/api/admin/connection-stats?clientName=C+managed+2&limit=10",
                                  response,
                                  sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"month\":\"2026-06-20\"")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"success\":1")
        || !contains(response, "\"failure\":0")
        || !contains(response, "\"updatedAt\":")) {
        fprintf(stderr, "connection stats response mismatch\n");
        return 1;
    }
    if (st_storage_record_traffic_usage(db_path,
                                        created_client_id,
                                        "C managed 2",
                                        "2026-06-20",
                                        1024,
                                        2048) != 0
        || st_storage_record_resource_traffic_usage(db_path,
                                                    created_client_id,
                                                    "C managed 2",
                                                    "HTTP_ROUTE",
                                                    "http:api",
                                                    created_route_id,
                                                    "api -> https://example.com/base",
                                                    "2026-06-20",
                                                    512,
                                                    4096) != 0) {
        fprintf(stderr, "traffic seed failed\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/traffic?clientId=%d&limit=10", created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"usageDate\":\"2026-06-20\"")
        || !contains(response, "\"uploadBytes\":1024")
        || !contains(response, "\"downloadBytes\":2048")
        || !contains(response, "\"updatedAt\":")) {
        fprintf(stderr, "traffic response mismatch\n");
        return 1;
    }
    snprintf(request_path,
             sizeof(request_path),
             "/api/admin/traffic/resources?clientId=%d&type=HTTP_ROUTE&limit=10",
             created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"resourceType\":\"HTTP_ROUTE\"")
        || !contains(response, "\"resourceKey\":\"http:api\"")
        || !contains(response, "\"resourceId\":")
        || !contains(response, "\"resourceName\":\"api -> https://example.com/base\"")
        || !contains(response, "\"uploadBytes\":512")
        || !contains(response, "\"downloadBytes\":4096")) {
        fprintf(stderr, "resource traffic response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/users",
                                            "{\"username\":\"bob\",\"password\":\"secret\","
                                            "\"role\":\"USER\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")) {
        fprintf(stderr, "tenant scoped user create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"bob\",\"password\":\"secret\"}",
                                            response,
                                            sizeof(response));
    char *bob_token = st_json_get_string(response, "accessToken");
    if (len <= 0 || !contains(response, "200 OK") || bob_token == NULL) {
        fprintf(stderr, "tenant scoped user login response mismatch\n");
        free(bob_token);
        return 1;
    }
    snprintf(authorization, sizeof(authorization), "Bearer %s", bob_token);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/clients",
                                            authorization,
                                            "{\"clientName\":\"Bob managed\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    int bob_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"ownerUsername\":\"bob\"")
        || st_json_get_int(response, "id", &bob_client_id) != 0
        || bob_client_id <= 0) {
        fprintf(stderr, "tenant scoped client create response mismatch\n");
        free(bob_token);
        return 1;
    }
    if (st_storage_record_connection_detail_with_tenant_and_id(db_path,
                                                               "tenant-admin",
                                                               created_client_id,
                                                               "C managed 2",
                                                               "admin-private-chan",
                                                               "127.0.0.1:62200",
                                                               1,
                                                               NULL,
                                                               "CLIENT_CLOSED",
                                                               "2026-06-22T02:00:00Z",
                                                               "2026-06-22T02:01:00Z",
                                                               NULL) != 0
        || st_storage_record_connection_detail_with_tenant_and_id(db_path,
                                                                  "tenant-admin",
                                                                  bob_client_id,
                                                                  "Bob managed",
                                                                  "bob-chan",
                                                                  "127.0.0.1:62300",
                                                                  1,
                                                                  NULL,
                                                                  "CLIENT_CLOSED",
                                                                  "2026-06-22T02:00:00Z",
                                                                  "2026-06-22T02:01:00Z",
                                                                  NULL) != 0
        || st_storage_record_traffic_usage(db_path,
                                           bob_client_id,
                                           "Bob managed",
                                           "2026-06-22",
                                           9,
                                           10) != 0
        || st_storage_record_resource_traffic_usage(db_path,
                                                    bob_client_id,
                                                    "Bob managed",
                                                    "HTTP_ROUTE",
                                                    "http:bob",
                                                    0,
                                                    "bob -> http://127.0.0.1:9000",
                                                    "2026-06-22",
                                                    11,
                                                    12) != 0) {
        fprintf(stderr, "tenant scoped seed failed\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/connections?page=0&size=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Bob managed\"")
        || !contains(response, "\"channelId\":\"bob-chan\"")
        || contains(response, "admin-private-chan")
        || contains(response, "\"clientName\":\"C managed 2\"")) {
        fprintf(stderr, "tenant scoped connection visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    if (st_storage_archive_connections(db_path, "2026-06-23T00:00:00Z") != 0) {
        fprintf(stderr, "tenant scoped connection archive failed\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/connection-stats?limit=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Bob managed\"")
        || contains(response, "\"clientName\":\"C managed 2\"")) {
        fprintf(stderr, "tenant scoped connection stats visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/traffic?limit=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Bob managed\"")
        || contains(response, "\"clientName\":\"C managed 2\"")) {
        fprintf(stderr, "tenant scoped traffic visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/traffic/resources?type=HTTP_ROUTE&limit=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"resourceKey\":\"http:bob\"")
        || contains(response, "\"resourceKey\":\"http:api\"")) {
        fprintf(stderr, "tenant scoped resource traffic visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    free(bob_token);
    const uint8_t http_request_body[] = "{\"hello\":true}";
    const uint8_t http_response_body[] = "{\"ok\":true}";
    st_storage_http_exchange_record http_record = {
        .tenant_id = "tenant-admin",
        .client_id = created_client_id,
        .client_name = "C managed 2",
        .route = "api",
        .resource_id = created_route_id,
        .resource_name = "api -> https://example.com/base",
        .method = "POST",
        .relative_path = "/items",
        .raw_query = "page=1",
        .status_code = 201,
        .success = 1,
        .remote_address = "127.0.0.1:62000",
        .request_bytes = (long long)(sizeof(http_request_body) - 1U),
        .response_bytes = (long long)(sizeof(http_response_body) - 1U),
        .elapsed_ms = 12,
        .request_content_type = "application/json",
        .response_content_type = "application/json",
        .request_headers = "Content-Type: application/json",
        .response_headers = "Content-Type: application/json",
        .request_body = http_request_body,
        .request_body_len = sizeof(http_request_body) - 1U,
        .response_body = http_response_body,
        .response_body_len = sizeof(http_response_body) - 1U,
        .captured_at = "2026-06-20T02:00:01Z"
    };
    st_storage_http_exchange_record http_record_get = {
        .tenant_id = "tenant-admin",
        .client_id = created_client_id,
        .client_name = "C managed 2",
        .route = "assets",
        .resource_id = created_route_id,
        .resource_name = "assets -> https://example.com/static",
        .method = "GET",
        .relative_path = "/vendor.js",
        .status_code = 200,
        .success = 1,
        .remote_address = "127.0.0.1:62001",
        .request_bytes = 0,
        .response_bytes = 1024,
        .elapsed_ms = 6,
        .response_content_type = "text/javascript",
        .request_headers = "X-Debug-Method: POST",
        .response_headers = "Content-Type: text/javascript",
        .response_body = (const uint8_t *)"console.log('ready')",
        .response_body_len = strlen("console.log('ready')"),
        .captured_at = "2026-06-20T02:00:02Z"
    };
    const uint8_t tcp_payload_a[] = "GET / HTTP/1.1\r\n\r\n";
    const uint8_t tcp_payload_b[] = "HTTP/1.1 200 OK\r\n\r\n";
    st_storage_tcp_frame_record tcp_record_a = {
        .tenant_id = "tenant-admin",
        .client_id = created_client_id,
        .client_name = "C managed 2",
        .listen_port = 19090,
        .resource_id = created_specus_id,
        .resource_name = "19090 -> 127.0.0.1:9090",
        .channel_id = "tcp-chan-1",
        .direction = "PUBLIC_TO_CLIENT",
        .remote_address = "127.0.0.1:62100",
        .source_address = "127.0.0.1",
        .source_port = 62100,
        .destination_address = "127.0.0.1",
        .destination_port = 9090,
        .stream_offset = 0,
        .frame_index = 0,
        .payload_data = tcp_payload_a,
        .payload_data_len = sizeof(tcp_payload_a) - 1U,
        .frame_time = "2026-06-20T02:00:02Z"
    };
    st_storage_tcp_frame_record tcp_record_b = tcp_record_a;
    tcp_record_b.direction = "CLIENT_TO_PUBLIC";
    tcp_record_b.stream_offset = 0;
    tcp_record_b.frame_index = 0;
    tcp_record_b.payload_data = tcp_payload_b;
    tcp_record_b.payload_data_len = sizeof(tcp_payload_b) - 1U;
    tcp_record_b.frame_time = "2026-06-20T02:00:03Z";
    if (st_storage_record_http_exchange(db_path, &http_record) != 0
        || st_storage_record_http_exchange(db_path, &http_record_get) != 0
        || st_storage_record_tcp_frame(db_path, &tcp_record_a) != 0
        || st_storage_record_tcp_frame(db_path, &tcp_record_b) != 0) {
        fprintf(stderr, "traffic detail seed failed\n");
        return 1;
    }
    /* HttpTrafficExchangeStoreTests: a page of summaries carries no headers and no previews. */
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"method\":\"POST\"")
        || !contains(response, "\"statusCode\":201")
        || !contains(response, "\"responseBodyType\":\"json\"")
        || !contains(response, "\"requestHeaders\":null,\"responseHeaders\":null,\"requestPreviewHex\":null,"
                               "\"requestPreviewText\":null,\"responsePreviewHex\":null,\"responsePreviewText\":null")
        || contains(response, "\"requestHeaders\":\"") || contains(response, "\"responseHeaders\":\"")
        || contains(response, "\"requestPreviewHex\":\"") || contains(response, "\"requestPreviewText\":\"")
        || contains(response, "\"responsePreviewHex\":\"") || contains(response, "\"responsePreviewText\":\"")
        || !contains(response, "\"size\":20")
        || !contains(response, "\"totalPages\":1")) {
        fprintf(stderr, "http exchange page response mismatch: %.2000s\n", response);
        return 1;
    }
    /* The detail of one exchange carries them, with Java's uppercase spaced hex. */
    long long post_exchange_id = 0;
    {
        sqlite3 *db = NULL;
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_open(db_path, &db) == SQLITE_OK
            && sqlite3_prepare_v2(db, "SELECT id FROM specus_http_traffic_exchange WHERE method='POST'", -1, &stmt,
                                  NULL) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_ROW) {
            post_exchange_id = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/traffic/http-exchanges/%lld", post_exchange_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"requestHeaders\":\"Content-Type: application/json\"")
        || !contains(response, "\"requestPreviewHex\":\"7B 22 68 65 6C 6C 6F 22 3A 74 72 75 65 7D\"")
        || !contains(response, "\"requestPreviewText\":\"{\\\"hello\\\":true}\"")
        || !contains(response, "\"responsePreviewText\":\"{\\\"ok\\\":true}\"")
        || !contains(response, "\"responseTruncated\":false")) {
        fprintf(stderr, "http exchange detail response mismatch: %s\n", response);
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?field=method&q=POST&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"method\":\"POST\"")) {
        fprintf(stderr, "http exchange field search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?q=POST%20api&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"method\":\"POST\"")) {
        fprintf(stderr, "http exchange tokenized search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?field=status&q=201&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"statusCode\":201")) {
        fprintf(stderr, "http exchange status search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?field=responseDataType&q=json&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"responseBodyType\":\"json\"")) {
        fprintf(stderr, "http exchange response data type search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/tcp-frames?limit=25", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"direction\":\"CLIENT_TO_PUBLIC\"")
        || !contains(response, "\"direction\":\"PUBLIC_TO_CLIENT\"")
        || !contains(response, "\"size\":25")
        || !contains(response, "\"total\":2")) {
        fprintf(stderr, "tcp frame page response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/tcp-streams?channelId=tcp-chan-1&limit=5", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"channelId\":\"tcp-chan-1\"")
        || !contains(response, "\"payloadBase64\":")
        || !contains(response, "\"limit\":5")
        || !contains(response, "\"truncated\":false")) {
        fprintf(stderr, "tcp stream response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/tcp-frames/1", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"payloadBase64\":")
        || !contains(response, "\"payloadPreviewText\":\"GET / HTTP/1.1")) {
        fprintf(stderr, "tcp frame detail response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d", created_client_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "client delete response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_DATABASE_PATH");
    unsetenv("SPECUS_AUTH_TENANT_ID");
    unsetenv("SPECUS_AUTH_USERNAME");
    unlink(db_path);

    len = st_admin_build_response("GET", "/api/admin/peer-mesh/status", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"enabled\":false")
        || contains(response, "\"dataPlane\"") || contains(response, "\"controlPlane\"")) {
        fprintf(stderr, "peer mesh status response mismatch\n");
        return 1;
    }
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/status", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"enabled\":true")) {
        fprintf(stderr, "peer mesh enabled status response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_PEER_MESH_ENABLED");

    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "[]")) {
        fprintf(stderr, "peer mesh devices response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "[]")) {
        fprintf(stderr, "peer mesh clear sessions response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions/123", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "peer mesh session not found")) {
        fprintf(stderr, "peer mesh close missing session response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("PUT", "/api/admin/peer-mesh/devices/42", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "peer mesh device not found")) {
        fprintf(stderr, "peer mesh update missing device response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/acls/42", response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "peer mesh delete missing acl response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("POST", "/api/admin/peer-mesh/relay-allocations", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")
        || !contains(response, "\"error\":\"not found\"")) {
        fprintf(stderr, "peer mesh unknown operation response mismatch: %s\n", response);
        return 1;
    }

    len = st_admin_build_response("GET", "/http/Demo%20client/api/v1/items", response, sizeof(response));
    if (len <= 0 || !contains(response, "501 Not Implemented")
        || !contains(response, "direct http dispatch")) {
        fprintf(stderr, "direct http skeleton response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/ws/connections", response, sizeof(response));
    if (len <= 0 || !contains(response, "426 Upgrade Required")
        || !contains(response, "websocket upgrade required")) {
        fprintf(stderr, "websocket skeleton response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/ws/client-messages", response, sizeof(response));
    if (len <= 0 || !contains(response, "426 Upgrade Required")
        || !contains(response, "websocket upgrade required")) {
        fprintf(stderr, "client messages websocket skeleton response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/ws-tickets",
                                            NULL,
                                            "{\"endpoint\":\"connections\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "websocket ticket endpoint allowed anonymous access\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/ws-tickets",
                                            "{\"endpoint\":\"connections\"}",
                                            response,
                                            sizeof(response));
    char *connection_ticket = st_json_get_string(response, "ticket");
    if (len <= 0 || !contains(response, "200 OK")
        || connection_ticket == NULL || strlen(connection_ticket) != 43U
        || !contains(response, "\"expiresAt\":")) {
        free(connection_ticket);
        fprintf(stderr, "websocket ticket response mismatch\n");
        return 1;
    }
    free(connection_ticket);
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/ws-tickets",
                                            "{\"endpoint\":\"client-messages\"}",
                                            response,
                                            sizeof(response));
    char *message_ticket = st_json_get_string(response, "ticket");
    if (len <= 0 || !contains(response, "200 OK")
        || message_ticket == NULL || strlen(message_ticket) != 43U) {
        free(message_ticket);
        fprintf(stderr, "client messages websocket ticket response mismatch\n");
        return 1;
    }
    free(message_ticket);
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/ws-tickets",
                                            "{\"endpoint\":\"unsupported\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")
        || !contains(response, "endpoint must be connections or client-messages")) {
        fprintf(stderr, "unsupported websocket ticket endpoint was not rejected\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/oidc-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"configured\":false")
        || !contains(response, "\"passwordLoginEnabled\":true")) {
        fprintf(stderr, "oidc config response mismatch\n");
        return 1;
    }
    setenv("SPECUS_OIDC_CLIENT_ID", "admin-spa", 1);
    setenv("SPECUS_OIDC_AUTHORIZATION_ENDPOINT", "https://issuer.example/authorize", 1);
    setenv("SPECUS_OIDC_TOKEN_ENDPOINT", "https://issuer.example/token", 1);
    setenv("SPECUS_OIDC_END_SESSION_ENDPOINT", "https://issuer.example/logout", 1);
    setenv("SPECUS_OIDC_REDIRECT_URI", "http://127.0.0.1:8088/callback", 1);
    setenv("SPECUS_OIDC_SCOPE", "openid profile email", 1);
    setenv("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", "false", 1);
    len = st_admin_build_response("GET", "/oidc-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"configured\":true")
        || !contains(response, "\"authorizationEndpoint\":\"https://issuer.example/authorize\"")
        || !contains(response, "\"registrationEndpoint\":\"https://certus.devshuai.com/register\"")
        || !contains(response, "\"endSessionEndpoint\":\"https://issuer.example/logout\"")
        || !contains(response, "\"clientId\":\"admin-spa\"")
        || !contains(response, "\"redirectUri\":\"http://127.0.0.1:8088/callback\"")
        || !contains(response, "\"scope\":\"openid profile email\"")
        || !contains(response, "\"passwordLoginEnabled\":false")
        || !contains(response, "\"registrationEnabled\":false")
        || !contains(response, "\"emailVerificationRequired\":false")
        || !contains(response, "\"turnstileEnabled\":false")
        || !contains(response, "\"turnstileSiteKey\":\"\"")
        || contains(response, "\"tokenEndpoint\"")
        || contains(response, "\"issuer\"")) {
        fprintf(stderr, "oidc configured response mismatch\n");
        return 1;
    }
    /* The full exchange runs against a fake identity provider in oidc_tests.c. Here: a callback
     * without the browser's nonce is refused before the token endpoint is contacted. */
    len = st_admin_build_response_with_body("POST",
                                            "/oidc/token",
                                            "{\"code\":\"abc\",\"codeVerifier\":\"verifier value\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")
        || !contains(response, "缺少 code、code_verifier 或 nonce")
        || contains(response, "accessToken")) {
        fprintf(stderr, "oidc token exchange without nonce response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_OIDC_CLIENT_ID");
    unsetenv("SPECUS_OIDC_AUTHORIZATION_ENDPOINT");
    unsetenv("SPECUS_OIDC_TOKEN_ENDPOINT");
    unsetenv("SPECUS_OIDC_END_SESSION_ENDPOINT");
    unsetenv("SPECUS_OIDC_REDIRECT_URI");
    unsetenv("SPECUS_OIDC_SCOPE");
    unsetenv("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED");
    len = st_admin_build_response("POST", "/oidc/token", response, sizeof(response));
    if (len <= 0 || !contains(response, "503 Service Unavailable")
        || !contains(response, "OIDC")) {
        fprintf(stderr, "oidc unconfigured token response mismatch\n");
        return 1;
    }
    unsetenv("SPECUS_AUTH_PASSWORD");
    st_login_rate_limiter_reset();

    len = st_admin_build_response("GET", "/missing", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "404 response mismatch\n");
        return 1;
    }

    char path[512];
    const char *content_type = NULL;
    if (st_admin_resolve_static_path("../../java/server/src/main/resources/static",
                                     "/",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "index.html")
        || strcmp(content_type, "text/html; charset=utf-8") != 0) {
        fprintf(stderr, "static index path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../java/server/src/main/resources/static",
                                     "/app.js?cache=1",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "app.js")
        || strcmp(content_type, "application/javascript; charset=utf-8") != 0) {
        fprintf(stderr, "static js path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../../../apps/admin-web/public",
                                     "/specus-http-route-runtime.js?v=4",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "specus-http-route-runtime.js")
        || strcmp(content_type, "application/javascript; charset=utf-8") != 0) {
        fprintf(stderr, "route runtime static asset path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../java/server/src/main/resources/static",
                                     "/../application.yml",
                                     path,
                                     sizeof(path),
                                     &content_type) == 0) {
        fprintf(stderr, "static traversal was allowed\n");
        return 1;
    }
    if (test_admin_endpoint_contracts() != 0) {
        return 1;
    }
    if (test_connectivity_check_endpoint() != 0) {
        return 1;
    }
    if (test_tenant_scoped_admin_mutations() != 0) {
        return 1;
    }
    if (test_client_mutations_close_connections() != 0) {
        return 1;
    }
    unsetenv("SPECUS_ENV");
    unsetenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED");
    return 0;
}
