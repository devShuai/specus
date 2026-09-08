#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"

#include "client_address.h"
#include "client_package.h"
#include "crypto.h"
#include "decompression_limits.h"
#include "github_release.h"
#include "http_client.h"
#include "json.h"
#include "peer_egress.h"
#include "login_rate_limiter.h"
#include "media_capture.h"
#include "object_storage.h"
#include "password_hash.h"
#include "peer_mesh.h"
#include "public_discovery.h"
#include "public_room.h"
#include "registration.h"
#include "security.h"
#include "security_baseline.h"
#include "storage.h"
#include "turn_auth.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#define ST_ADMIN_MAX_TCP_MAPPINGS 64U
#define ST_ADMIN_MAX_CLIENTS 128U
#define ST_ADMIN_MAX_CLIENT_DOWNLOADS 128U
#define ST_ADMIN_MAX_CONNECTIONS_PAGE 500U
#define ST_ADMIN_MAX_TRAFFIC_ITEMS 1000U
#define ST_ADMIN_MAX_PEER_ACLS 256U
#define ST_ADMIN_MAX_PEER_SESSIONS 200U
#define ST_ADMIN_MAX_HTTP_HEADERS 96U
#define ST_ADMIN_MAX_DIRECT_HTTP_BODY (16U * 1024U * 1024U)
#define ST_ADMIN_DEFAULT_REWRITE_BODY_BYTES (10U * 1024U * 1024U)
#define ST_ADMIN_SWS2_HEADER_BYTES 12U
#define ST_ADMIN_SWS2_MAX_PAYLOAD ((64U * 1024U) - ST_ADMIN_SWS2_HEADER_BYTES)
#define ST_ADMIN_STREAM_INITIAL_WINDOW (1024U * 1024U)
#define ST_ADMIN_STREAM_MAX_WINDOW (16U * 1024U * 1024U)
#define ST_ADMIN_WS_TICKET_BYTES 32U
#define ST_ADMIN_WS_TICKET_TTL_SECONDS 45
#define ST_ADMIN_MAX_WS_TICKETS 1024U
#define ST_ADMIN_CLIENT_MESSAGE_MAX_CHARS (64U * 1024U)
#define ST_ADMIN_CLIENT_MESSAGE_MAX_UTF8_BYTES (3U * ST_ADMIN_CLIENT_MESSAGE_MAX_CHARS)
#define ST_ADMIN_MAX_PENDING_CLIENT_MESSAGE_WRITES 1024U
#define ST_ADMIN_MAX_PENDING_CLIENT_MESSAGE_WRITES_PER_SOCKET 64U

static int admin_base64_decode_alloc(const char *encoded, uint8_t **out, size_t *out_len);
static const char *admin_reason_phrase(int status);
static int write_registration_error_response(int status,
                                             const char *error,
                                             char *out,
                                             size_t out_len);

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} st_admin_string_builder;

typedef struct {
    int port;
    char specus_address[256];
    int specus_port;
} st_admin_tcp_mapping;

typedef struct {
    char route[128];
    char target_base_url[512];
    int insecure_skip_verify;
} st_admin_http_route;

typedef struct {
    st_admin_server *server;
    int fd;
} st_admin_client_args;

typedef struct {
    char username[ST_SECURITY_TOKEN_USERNAME_LEN + 1];
    char tenant_id[ST_SECURITY_TOKEN_TENANT_LEN + 1];
    char role[ST_SECURITY_TOKEN_ROLE_LEN + 1];
    int admin;
    int authenticated;
} st_admin_context;

typedef struct st_admin_ws_client {
    int fd;
    char endpoint[32];
    char username[ST_SECURITY_TOKEN_USERNAME_LEN + 1];
    char tenant_id[ST_SECURITY_TOKEN_TENANT_LEN + 1];
    int admin;
    int closing;
    size_t pending_message_writes;
    pthread_mutex_t send_lock;
    pthread_cond_t pending_cond;
    struct st_admin_ws_client *next;
} st_admin_ws_client;

typedef struct st_admin_ws_ticket {
    uint8_t token_hash[ST_SHA256_LEN];
    uint8_t remote_address_hash[ST_SHA256_LEN];
    char username[ST_SECURITY_TOKEN_USERNAME_LEN + 1];
    char tenant_id[ST_SECURITY_TOKEN_TENANT_LEN + 1];
    char endpoint[32];
    int admin;
    time_t expires_at;
    struct st_admin_ws_ticket *next;
} st_admin_ws_ticket;

struct st_admin_direct_ws_stream {
    int fd;
    pthread_mutex_t send_lock;
    pthread_mutex_t flow_lock;
    pthread_cond_t flow_cond;
    uint64_t send_credit;
    uint8_t outbound_fragment_opcode;
    size_t outbound_fragment_bytes;
    int close_sent;
    int flow_closed;
    int closed;
};

static pthread_mutex_t admin_ws_lock = PTHREAD_MUTEX_INITIALIZER;
static st_admin_ws_client *admin_ws_clients = NULL;
static pthread_mutex_t admin_ws_ticket_lock = PTHREAD_MUTEX_INITIALIZER;
static st_admin_ws_ticket *admin_ws_tickets = NULL;
static pthread_mutex_t admin_nat_control_lock = PTHREAD_MUTEX_INITIALIZER;
static st_admin_nat_control_handler admin_nat_control_handler = NULL;
static void *admin_nat_control_ctx = NULL;
static pthread_mutex_t admin_client_runtime_status_lock = PTHREAD_MUTEX_INITIALIZER;
static st_admin_client_runtime_status_handler admin_client_runtime_status_handler = NULL;
static void *admin_client_runtime_status_ctx = NULL;
static pthread_mutex_t admin_client_message_lock = PTHREAD_MUTEX_INITIALIZER;
static st_admin_client_message_handler admin_client_message_handler = NULL;
static void *admin_client_message_ctx = NULL;
static size_t admin_pending_client_message_writes = 0U;
static pthread_mutex_t admin_peer_mesh_refresh_lock = PTHREAD_MUTEX_INITIALIZER;
static st_admin_peer_mesh_refresh_handler admin_peer_mesh_refresh_handler = NULL;
static void *admin_peer_mesh_refresh_ctx = NULL;

static char *admin_url_decode(const char *value, size_t len);
static const char *admin_database_path(void);
static int admin_can_access_client(const st_admin_context *context, const st_storage_client *client);
static char *admin_join_headers(char **headers, size_t headers_len);
static char *admin_header_array_value(char **headers, size_t headers_len, const char *name);
static int password_hash_hex(const char *password, char out[ST_SHA256_HEX_LEN + 1]);
static int password_hash_matches(const char *password, const char *expected_hash);

void st_admin_set_nat_control_handler(st_admin_nat_control_handler handler, void *ctx)
{
    pthread_mutex_lock(&admin_nat_control_lock);
    admin_nat_control_handler = handler;
    admin_nat_control_ctx = ctx;
    pthread_mutex_unlock(&admin_nat_control_lock);
}

void st_admin_set_client_runtime_status_handler(st_admin_client_runtime_status_handler handler,
                                                void *ctx)
{
    pthread_mutex_lock(&admin_client_runtime_status_lock);
    admin_client_runtime_status_handler = handler;
    admin_client_runtime_status_ctx = ctx;
    pthread_mutex_unlock(&admin_client_runtime_status_lock);
}

void st_admin_set_client_message_handler(st_admin_client_message_handler handler, void *ctx)
{
    pthread_mutex_lock(&admin_client_message_lock);
    admin_client_message_handler = handler;
    admin_client_message_ctx = ctx;
    pthread_mutex_unlock(&admin_client_message_lock);
}

void st_admin_set_peer_mesh_refresh_handler(st_admin_peer_mesh_refresh_handler handler, void *ctx)
{
    pthread_mutex_lock(&admin_peer_mesh_refresh_lock);
    admin_peer_mesh_refresh_handler = handler;
    admin_peer_mesh_refresh_ctx = ctx;
    pthread_mutex_unlock(&admin_peer_mesh_refresh_lock);
}

static void admin_notify_peer_mesh_refresh(const char *tenant_id)
{
    pthread_mutex_lock(&admin_peer_mesh_refresh_lock);
    st_admin_peer_mesh_refresh_handler handler = admin_peer_mesh_refresh_handler;
    void *ctx = admin_peer_mesh_refresh_ctx;
    pthread_mutex_unlock(&admin_peer_mesh_refresh_lock);
    if (handler != NULL && tenant_id != NULL && *tenant_id != '\0') {
        (void)handler(ctx, tenant_id);
    }
}

static int admin_send_client_message(long long client_id,
                                     const char *client_name,
                                     const char *from_admin_name,
                                     const char *message)
{
    pthread_mutex_lock(&admin_client_message_lock);
    st_admin_client_message_handler handler = admin_client_message_handler;
    void *ctx = admin_client_message_ctx;
    pthread_mutex_unlock(&admin_client_message_lock);
    return handler == NULL
        ? -1
        : handler(ctx, client_id, client_name, from_admin_name, message);
}

static void admin_get_client_runtime_status(long long client_id,
                                            const char *client_name,
                                            st_admin_client_runtime_status *status)
{
    memset(status, 0, sizeof(*status));
    pthread_mutex_lock(&admin_client_runtime_status_lock);
    st_admin_client_runtime_status_handler handler = admin_client_runtime_status_handler;
    void *ctx = admin_client_runtime_status_ctx;
    pthread_mutex_unlock(&admin_client_runtime_status_lock);
    if (handler != NULL && handler(ctx, client_id, client_name, status) != 0) {
        memset(status, 0, sizeof(*status));
    }
}

static int admin_push_nat_control(long long client_id, const char *client_name)
{
    pthread_mutex_lock(&admin_nat_control_lock);
    st_admin_nat_control_handler handler = admin_nat_control_handler;
    void *ctx = admin_nat_control_ctx;
    pthread_mutex_unlock(&admin_nat_control_lock);
    return handler == NULL ? -1 : handler(ctx, client_id, client_name);
}

static void admin_notify_nat_control(const st_storage_client *client)
{
    if (client != NULL) {
        (void)admin_push_nat_control(client->id, client->client_name);
    }
}

static int write_response(char *out, size_t out_len, int status, const char *reason, const char *body)
{
    if (body == NULL) {
        body = "";
    }
    int written = snprintf(out,
                           out_len,
                           "HTTP/1.1 %d %s\r\n"
                           "Content-Type: application/json\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Content-Length: %zu\r\n"
                           "\r\n"
                           "%s",
                           status,
                           reason,
                           strlen(body),
                           body);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static int write_login_rate_limited_response(char *out, size_t out_len, int64_t retry_after_seconds)
{
    const char *body = "{\"error\":\"登录尝试过于频繁,请稍后再试\"}";
    if (retry_after_seconds < 1) {
        retry_after_seconds = 1;
    }
    int written = snprintf(out,
                           out_len,
                           "HTTP/1.1 429 Too Many Requests\r\n"
                           "Content-Type: application/json\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Retry-After: %lld\r\n"
                           "Content-Length: %zu\r\n"
                           "\r\n"
                           "%s",
                           (long long)retry_after_seconds,
                           strlen(body),
                           body);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static int write_client_package_rate_limited_response(char *out,
                                                      size_t out_len,
                                                      long long retry_after_seconds)
{
    const char *body = "{\"error\":\"请求过于频繁,请稍后再试\"}";
    if (retry_after_seconds < 1) retry_after_seconds = 1;
    int written = snprintf(out,
                           out_len,
                           "HTTP/1.1 429 Too Many Requests\r\n"
                           "Content-Type: application/json\r\n"
                           "Cache-Control: no-store\r\n"
                           "X-Content-Type-Options: nosniff\r\n"
                           "Retry-After: %lld\r\n"
                           "Content-Length: %zu\r\n"
                           "\r\n"
                           "%s",
                           retry_after_seconds,
                           strlen(body),
                           body);
    return written < 0 || (size_t)written >= out_len ? -1 : written;
}

static const char *env_text(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    return value != NULL && *value != '\0' ? value : fallback;
}

static long long env_i64(const char *name, long long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' && parsed > 0 ? parsed : fallback;
}

static long long env_i64_alias(const char *primary, const char *legacy, long long fallback)
{
    const char *value = getenv(primary);
    if (value != NULL && *value != '\0') {
        char *end = NULL;
        long long parsed = strtoll(value, &end, 10);
        if (end != value && *end == '\0' && parsed > 0) {
            return parsed;
        }
    }
    return env_i64(legacy, fallback);
}

static long long current_time_millis(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

static int env_int(const char *name, int fallback)
{
    long long parsed = env_i64(name, fallback);
    return parsed > 0 && parsed <= 65535 ? (int)parsed : fallback;
}

static int env_int_alias(const char *primary, const char *legacy, int fallback)
{
    long long parsed = env_i64_alias(primary, legacy, fallback);
    return parsed > 0 && parsed <= 65535 ? (int)parsed : fallback;
}

static int client_auth_default_max_online_instances(void)
{
    int value = env_int_alias("SPECUS_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES",
                              "SPECUS_CLIENT_MAX_ONLINE_INSTANCES",
                              2);
    return value > 0 && value <= 10000 ? value : 2;
}

static int env_bool(const char *name, int fallback)
{
    if (strcmp(name, "SPECUS_DB_SEED_DEMO_CLIENT") == 0
        && !st_deployment_environment_allows_demo_data(getenv("SPECUS_ENV"))) {
        return 0;
    }
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    return strcmp(value, "1") == 0 || strcmp(value, "true") == 0 || strcmp(value, "TRUE") == 0
        || strcmp(value, "yes") == 0 || strcmp(value, "YES") == 0;
}

static int admin_text_present(const char *value)
{
    if (value == NULL) {
        return 0;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (!isspace(*cursor)) {
            return 1;
        }
    }
    return 0;
}

static int management_password_login_enabled(void)
{
    return env_bool("SPECUS_AUTH_PASSWORD_LOGIN_ENABLED", 1)
        && admin_text_present(getenv("SPECUS_AUTH_PASSWORD"));
}

static st_login_rate_limit_config management_login_rate_limit_config(void)
{
    long long per_ip = env_i64("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_IP", 20);
    long long per_account = env_i64("SPECUS_AUTH_LOGIN_RATE_LIMIT_PER_ACCOUNT", 10);
    long long window_seconds = env_i64("SPECUS_AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS", 300);
    st_login_rate_limit_config config = {
        .enabled = env_bool("SPECUS_AUTH_LOGIN_RATE_LIMIT_ENABLED", 1),
        .per_ip = per_ip > UINT_MAX ? UINT_MAX : (unsigned int)per_ip,
        .per_account = per_account > UINT_MAX ? UINT_MAX : (unsigned int)per_account,
        .window_seconds = window_seconds
    };
    return config;
}

static size_t admin_path_len_no_query(const char *path)
{
    const char *query = strchr(path, '?');
    return query == NULL ? strlen(path) : (size_t)(query - path);
}

static int admin_path_equals(const char *path, const char *expected)
{
    size_t len = admin_path_len_no_query(path);
    return len == strlen(expected) && memcmp(path, expected, len) == 0;
}

static int admin_parse_path_id(const char *path, const char *prefix, long long *id)
{
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) {
        return -1;
    }
    const char *cursor = path + prefix_len;
    char *end = NULL;
    long long parsed = strtoll(cursor, &end, 10);
    if (end == cursor || parsed <= 0 || (*end != '\0' && *end != '?')) {
        return -1;
    }
    *id = parsed;
    return 0;
}

static int admin_parse_nested_path_id(const char *path, const char *prefix, const char *suffix, long long *id)
{
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) {
        return -1;
    }
    const char *cursor = path + prefix_len;
    char *end = NULL;
    long long parsed = strtoll(cursor, &end, 10);
    if (end == cursor || parsed <= 0 || strncmp(end, suffix, strlen(suffix)) != 0) {
        return -1;
    }
    const char *tail = end + strlen(suffix);
    if (*tail != '\0' && *tail != '?') {
        return -1;
    }
    *id = parsed;
    return 0;
}

static int admin_query_i64(const char *path, const char *key, long long *out)
{
    const char *query = strchr(path, '?');
    if (query == NULL) {
        return -1;
    }
    ++query;
    size_t key_len = strlen(key);
    while (*query != '\0') {
        const char *next = strchr(query, '&');
        size_t part_len = next == NULL ? strlen(query) : (size_t)(next - query);
        if (part_len > key_len + 1U && memcmp(query, key, key_len) == 0 && query[key_len] == '=') {
            char *end = NULL;
            long long parsed = strtoll(query + key_len + 1U, &end, 10);
            if (end != query + key_len + 1U && parsed > 0
                && (end == query + part_len || *end == '&' || *end == '\0')) {
                *out = parsed;
                return 0;
            }
        }
        if (next == NULL) {
            break;
        }
        query = next + 1;
    }
    return -1;
}

static char *admin_query_string(const char *path, const char *key)
{
    const char *query = strchr(path, '?');
    if (query == NULL) {
        return NULL;
    }
    ++query;
    size_t key_len = strlen(key);
    while (*query != '\0') {
        const char *next = strchr(query, '&');
        size_t part_len = next == NULL ? strlen(query) : (size_t)(next - query);
        if (part_len >= key_len + 1U && memcmp(query, key, key_len) == 0 && query[key_len] == '=') {
            size_t value_len = part_len - key_len - 1U;
            char *copy = (char *)malloc(value_len + 1U);
            if (copy == NULL) {
                return NULL;
            }
            const char *value = query + key_len + 1U;
            size_t w = 0;
            for (size_t i = 0; i < value_len; ++i) {
                if (value[i] == '%' && i + 2U < value_len) {
                    int high = value[i + 1U] >= '0' && value[i + 1U] <= '9'
                        ? value[i + 1U] - '0'
                        : (value[i + 1U] >= 'a' && value[i + 1U] <= 'f'
                            ? value[i + 1U] - 'a' + 10
                            : (value[i + 1U] >= 'A' && value[i + 1U] <= 'F'
                                ? value[i + 1U] - 'A' + 10
                                : -1));
                    int low = value[i + 2U] >= '0' && value[i + 2U] <= '9'
                        ? value[i + 2U] - '0'
                        : (value[i + 2U] >= 'a' && value[i + 2U] <= 'f'
                            ? value[i + 2U] - 'a' + 10
                            : (value[i + 2U] >= 'A' && value[i + 2U] <= 'F'
                                ? value[i + 2U] - 'A' + 10
                                : -1));
                    if (high >= 0 && low >= 0) {
                        copy[w++] = (char)((high << 4) | low);
                        i += 2U;
                        continue;
                    }
                }
                copy[w++] = value[i] == '+' ? ' ' : value[i];
            }
            copy[w] = '\0';
            return copy;
        }
        if (next == NULL) {
            break;
        }
        query = next + 1;
    }
    return NULL;
}

static int admin_query_int_any(const char *path, const char *key, int *out)
{
    char *value = admin_query_string(path, key);
    if (value == NULL) {
        return -1;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    int ok = end != value && *end == '\0' && parsed >= -2147483647L && parsed <= 2147483647L;
    if (ok) {
        *out = (int)parsed;
    }
    free(value);
    return ok ? 0 : -1;
}

static int admin_query_bool(const char *path, const char *key, int *out)
{
    char *value = admin_query_string(path, key);
    if (value == NULL) {
        return -1;
    }
    if (strcmp(value, "true") == 0 || strcmp(value, "TRUE") == 0 || strcmp(value, "True") == 0
        || strcmp(value, "1") == 0) {
        *out = 1;
        free(value);
        return 0;
    }
    if (strcmp(value, "false") == 0 || strcmp(value, "FALSE") == 0 || strcmp(value, "False") == 0
        || strcmp(value, "0") == 0) {
        *out = 0;
        free(value);
        return 0;
    }
    free(value);
    return -1;
}

static int admin_parse_port_text(const char *text, int *out)
{
    if (text == NULL || *text == '\0') {
        return -1;
    }
    char *end = NULL;
    long parsed = strtol(text, &end, 10);
    if (end == text || *end != '\0' || parsed <= 0 || parsed > 65535) {
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

static char *admin_dup_string(const char *value)
{
    size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, len + 1U);
    return copy;
}

static char *admin_trim(char *value)
{
    while (*value != '\0' && isspace((unsigned char)*value)) {
        ++value;
    }
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)*(end - 1))) {
        --end;
    }
    *end = '\0';
    return value;
}

static int admin_ascii_lower(int ch)
{
    return ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch;
}

static int admin_ascii_casecmp(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        int a = admin_ascii_lower((unsigned char)*left++);
        int b = admin_ascii_lower((unsigned char)*right++);
        if (a != b) {
            return a - b;
        }
    }
    return admin_ascii_lower((unsigned char)*left) - admin_ascii_lower((unsigned char)*right);
}

static int admin_ascii_ncasecmp(const char *left, const char *right, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        int a = admin_ascii_lower((unsigned char)left[i]);
        int b = admin_ascii_lower((unsigned char)right[i]);
        if (a != b) {
            return a - b;
        }
        if (left[i] == '\0' || right[i] == '\0') {
            return 0;
        }
    }
    return 0;
}

static void admin_context_from_env(st_admin_context *context)
{
    memset(context, 0, sizeof(*context));
    snprintf(context->username, sizeof(context->username), "%s", env_text("SPECUS_AUTH_USERNAME", "admin"));
    snprintf(context->tenant_id, sizeof(context->tenant_id), "%s", env_text("SPECUS_AUTH_TENANT_ID", "default"));
    snprintf(context->role, sizeof(context->role), "%s", "ADMIN");
    context->admin = 1;
    context->authenticated = 1;
}

static int admin_context_from_authorization(const char *authorization, st_admin_context *context)
{
    memset(context, 0, sizeof(*context));
    if (authorization == NULL) {
        return -1;
    }
    while (*authorization != '\0' && isspace((unsigned char)*authorization)) {
        ++authorization;
    }
    const char *prefix = "Bearer ";
    if (admin_ascii_ncasecmp(authorization, prefix, strlen(prefix)) != 0) {
        return -1;
    }
    const char *token = authorization + strlen(prefix);
    while (*token != '\0' && isspace((unsigned char)*token)) {
        ++token;
    }
    st_security_token_claims claims;
    if (st_security_validate_local_token(token,
                                         getenv("SPECUS_AUTH_JWT_SECRET"),
                                         env_text("SPECUS_AUTH_TENANT_ID", "default"),
                                         env_text("SPECUS_AUTH_USERNAME", "admin"),
                                         &claims) != 0) {
        return -1;
    }
    snprintf(context->username, sizeof(context->username), "%s", claims.username);
    snprintf(context->tenant_id, sizeof(context->tenant_id), "%s", claims.tenant_id);
    snprintf(context->role, sizeof(context->role), "%s", claims.role);
    context->admin = admin_ascii_casecmp(claims.role, "ADMIN") == 0
        || admin_ascii_casecmp(claims.username, env_text("SPECUS_AUTH_USERNAME", "admin")) == 0;
    context->authenticated = 1;
    return 0;
}

static int admin_path_requires_auth(const char *method, const char *path)
{
    (void)method;
    return strncmp(path, "/api/admin/", strlen("/api/admin/")) == 0
        || strncmp(path,
                   "/api/public/transfer/attachments/",
                   strlen("/api/public/transfer/attachments/")) == 0
        || admin_path_equals(path, "/auth/refresh");
}

static int write_admin_unauthorized(char *out, size_t out_len)
{
    return write_response(out,
                          out_len,
                          401,
                          "Unauthorized",
                          "{\"error\":\"missing or invalid bearer token\"}");
}

static int write_admin_forbidden(char *out, size_t out_len)
{
    return write_response(out, out_len, 403, "Forbidden", "{\"error\":\"需要 admin 权限\"}");
}

static char *admin_next_csv_token(char **cursor)
{
    if (cursor == NULL || *cursor == NULL) {
        return NULL;
    }
    char *start = *cursor;
    char *comma = strchr(start, ',');
    if (comma == NULL) {
        *cursor = NULL;
    } else {
        *comma = '\0';
        *cursor = comma + 1;
    }
    return start;
}

static int admin_sb_reserve(st_admin_string_builder *builder, size_t extra)
{
    if (extra > (size_t)-1 - builder->len - 1U) {
        return -1;
    }
    size_t required = builder->len + extra + 1U;
    if (required <= builder->cap) {
        return 0;
    }
    size_t next_cap = builder->cap == 0 ? 1024U : builder->cap;
    while (next_cap < required) {
        if (next_cap > (size_t)-1 / 2U) {
            return -1;
        }
        next_cap *= 2U;
    }
    char *next = (char *)realloc(builder->data, next_cap);
    if (next == NULL) {
        return -1;
    }
    builder->data = next;
    builder->cap = next_cap;
    return 0;
}

static int admin_sb_append_len(st_admin_string_builder *builder, const char *text, size_t len)
{
    if (admin_sb_reserve(builder, len) != 0) {
        return -1;
    }
    memcpy(builder->data + builder->len, text, len);
    builder->len += len;
    builder->data[builder->len] = '\0';
    return 0;
}

static int admin_sb_append(st_admin_string_builder *builder, const char *text)
{
    return admin_sb_append_len(builder, text, strlen(text));
}

static int admin_sb_appendf(st_admin_string_builder *builder, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, format, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(args);
        return -1;
    }
    if (admin_sb_reserve(builder, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    int written = vsnprintf(builder->data + builder->len, builder->cap - builder->len, format, args);
    va_end(args);
    if (written != needed) {
        return -1;
    }
    builder->len += (size_t)written;
    return 0;
}

static int admin_sb_append_json_string(st_admin_string_builder *builder, const char *value)
{
    char *escaped = st_json_escape(value == NULL ? "" : value);
    if (escaped == NULL) {
        return -1;
    }
    int rc = admin_sb_appendf(builder, "\"%s\"", escaped);
    free(escaped);
    return rc;
}

static int admin_sb_append_nullable_json_string(st_admin_string_builder *builder, const char *value)
{
    if (value == NULL || *value == '\0') {
        return admin_sb_append(builder, "null");
    }
    return admin_sb_append_json_string(builder, value);
}

static int add_admin_tcp_mapping(st_admin_tcp_mapping *mappings,
                                 size_t *mapping_count,
                                 int port,
                                 const char *target_address,
                                 int target_port)
{
    if (*mapping_count >= ST_ADMIN_MAX_TCP_MAPPINGS || target_address == NULL || *target_address == '\0'
        || strlen(target_address) >= sizeof(mappings[0].specus_address)) {
        return -1;
    }
    st_admin_tcp_mapping *mapping = &mappings[*mapping_count];
    mapping->port = port;
    strcpy(mapping->specus_address, target_address);
    mapping->specus_port = target_port;
    ++(*mapping_count);
    return 0;
}

static int load_env_tcp_mappings(st_admin_tcp_mapping *mappings, size_t *mapping_count)
{
    const char *raw = getenv("SPECUS_TCP_MAPPINGS");
    if (raw == NULL || *raw == '\0') {
        return 0;
    }
    char *copy = admin_dup_string(raw);
    if (copy == NULL) {
        return -1;
    }
    char *cursor = copy;
    char *token = admin_next_csv_token(&cursor);
    while (token != NULL) {
        char *entry = admin_trim(token);
        char *equals = strchr(entry, '=');
        if (equals == NULL) {
            free(copy);
            return -1;
        }
        *equals = '\0';
        char *target = admin_trim(equals + 1);
        char *colon = strrchr(target, ':');
        if (colon == NULL) {
            free(copy);
            return -1;
        }
        *colon = '\0';
        char *public_port_text = admin_trim(entry);
        char *target_host = admin_trim(target);
        char *target_port_text = admin_trim(colon + 1);
        int public_port = 0;
        int target_port = 0;
        if (admin_parse_port_text(public_port_text, &public_port) != 0
            || admin_parse_port_text(target_port_text, &target_port) != 0
            || add_admin_tcp_mapping(mappings, mapping_count, public_port, target_host, target_port) != 0) {
            free(copy);
            return -1;
        }
        token = admin_next_csv_token(&cursor);
    }
    free(copy);
    return 0;
}

static int load_database_tcp_mappings(const char *client_name,
                                      st_admin_tcp_mapping *mappings,
                                      size_t *mapping_count)
{
    const char *database_path = getenv("SPECUS_DATABASE_PATH");
    if (database_path == NULL || *database_path == '\0') {
        return 0;
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0
        || st_storage_client_enabled(database_path, client_name) != 0) {
        return -1;
    }
    st_storage_mapping stored[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t stored_count = 0;
    if (st_storage_load_mappings(database_path,
                                 client_name,
                                 stored,
                                 ST_ADMIN_MAX_TCP_MAPPINGS,
                                 &stored_count) != 0) {
        return -1;
    }
    for (size_t i = 0; i < stored_count; ++i) {
        if (add_admin_tcp_mapping(mappings,
                                  mapping_count,
                                  stored[i].listen_port,
                                  stored[i].target_address,
                                  stored[i].target_port)
            != 0) {
            return -1;
        }
    }
    return 0;
}

static int load_current_tcp_mappings(const char *client_name,
                                     st_admin_tcp_mapping *mappings,
                                     size_t *mapping_count)
{
    *mapping_count = 0;
    return load_database_tcp_mappings(client_name, mappings, mapping_count) != 0
            || load_env_tcp_mappings(mappings, mapping_count) != 0
        ? -1
        : 0;
}

static int load_env_http_routes(st_admin_http_route *routes, size_t *route_count)
{
    const char *raw = getenv("SPECUS_HTTP_ROUTES");
    if (raw == NULL || *raw == '\0') {
        return 0;
    }
    char *copy = admin_dup_string(raw);
    if (copy == NULL) {
        return -1;
    }
    char *cursor = copy;
    char *token = admin_next_csv_token(&cursor);
    while (token != NULL) {
        if (*route_count >= ST_ADMIN_MAX_TCP_MAPPINGS) {
            free(copy);
            return -1;
        }
        char *entry = admin_trim(token);
        char *equals = strchr(entry, '=');
        if (equals == NULL) {
            free(copy);
            return -1;
        }
        *equals = '\0';
        char *route = admin_trim(entry);
        char *target = admin_trim(equals + 1);
        if (*route == '\0' || *target == '\0'
            || strlen(route) >= sizeof(routes[0].route)
            || strlen(target) >= sizeof(routes[0].target_base_url)) {
            free(copy);
            return -1;
        }
        st_admin_http_route *item = &routes[*route_count];
        strcpy(item->route, route);
        strcpy(item->target_base_url, target);
        item->insecure_skip_verify = 0;
        ++(*route_count);
        token = admin_next_csv_token(&cursor);
    }
    free(copy);
    return 0;
}

static int load_database_http_routes(const char *client_name, st_admin_http_route *routes, size_t *route_count)
{
    const char *database_path = getenv("SPECUS_DATABASE_PATH");
    if (database_path == NULL || *database_path == '\0') {
        return 0;
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0
        || st_storage_client_enabled(database_path, client_name) != 0) {
        return -1;
    }
    st_storage_http_route stored[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t stored_count = 0;
    if (st_storage_load_http_routes(database_path,
                                    client_name,
                                    stored,
                                    ST_ADMIN_MAX_TCP_MAPPINGS,
                                    &stored_count) != 0) {
        return -1;
    }
    for (size_t i = 0; i < stored_count; ++i) {
        if (*route_count >= ST_ADMIN_MAX_TCP_MAPPINGS
            || strlen(stored[i].route) >= sizeof(routes[0].route)
            || strlen(stored[i].target_base_url) >= sizeof(routes[0].target_base_url)) {
            return -1;
        }
        st_admin_http_route *item = &routes[*route_count];
        strcpy(item->route, stored[i].route);
        strcpy(item->target_base_url, stored[i].target_base_url);
        item->insecure_skip_verify = stored[i].insecure_skip_verify;
        ++(*route_count);
    }
    return 0;
}

static int load_current_http_routes(const char *client_name, st_admin_http_route *routes, size_t *route_count)
{
    *route_count = 0;
    return load_database_http_routes(client_name, routes, route_count) != 0
            || load_env_http_routes(routes, route_count) != 0
        ? -1
        : 0;
}

static int append_specus_config_list(st_admin_string_builder *builder,
                                     const st_admin_tcp_mapping *mappings,
                                     size_t mapping_count)
{
    for (size_t i = 0; i < mapping_count; ++i) {
        char *target = st_json_escape(mappings[i].specus_address);
        if (target == NULL) {
            return -1;
        }
        int rc = admin_sb_appendf(builder,
                                  "%s{\"port\":%d,\"specusAddress\":\"%s\",\"specusPort\":%d}",
                                  i == 0 ? "" : ",",
                                  mappings[i].port,
                                  target,
                                  mappings[i].specus_port);
        free(target);
        if (rc != 0) {
            return -1;
        }
    }
    return 0;
}

static int append_http_route_config_list(st_admin_string_builder *builder,
                                         const st_admin_http_route *routes,
                                         size_t route_count)
{
    for (size_t i = 0; i < route_count; ++i) {
        char *route = st_json_escape(routes[i].route);
        char *target = st_json_escape(routes[i].target_base_url);
        if (route == NULL || target == NULL) {
            free(route);
            free(target);
            return -1;
        }
        int rc = admin_sb_appendf(builder,
                                  "%s{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"insecureSkipVerify\":%s}",
                                  i == 0 ? "" : ",",
                                  route,
                                  target,
                                  routes[i].insecure_skip_verify ? "true" : "false");
        free(route);
        free(target);
        if (rc != 0) {
            return -1;
        }
    }
    return 0;
}

static int client_api_auth_required(void)
{
    const char *api_key = getenv("SPECUS_CLIENT_API_KEY");
    const char *secret = getenv("SPECUS_CLIENT_SECRET");
    const char *secret_hash = getenv("SPECUS_CLIENT_SECRET_HASH");
    return (api_key != NULL && *api_key != '\0') || (secret != NULL && *secret != '\0')
        || (secret_hash != NULL && *secret_hash != '\0');
}

static int load_client_api_key(uint8_t key[ST_SHA256_LEN])
{
    const char *secret_hash = getenv("SPECUS_CLIENT_SECRET_HASH");
    if (secret_hash != NULL && *secret_hash != '\0') {
        return st_hex_decode_32(secret_hash, key);
    }
    const char *secret = getenv("SPECUS_CLIENT_SECRET");
    if (secret == NULL || *secret == '\0') {
        return -1;
    }
    st_sha256((const uint8_t *)secret, strlen(secret), key);
    return 0;
}

static int validate_client_api_login(const char *body, char *out, size_t out_len)
{
    if (body == NULL || *body == '\0') {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client auth request body is required\"}");
    }

    const char *expected_api_key = getenv("SPECUS_CLIENT_API_KEY");
    if (expected_api_key == NULL || *expected_api_key == '\0') {
        return write_response(out,
                              out_len,
                              503,
                              "Service Unavailable",
                              "{\"error\":\"SPECUS_CLIENT_API_KEY is required when client API auth is enabled\"}");
    }

    char *api_key = st_json_get_string(body, "apiKey");
    char *timestamp = st_json_get_string(body, "timestamp");
    char *nonce = st_json_get_string(body, "nonce");
    char *signature = st_json_get_string(body, "signature");
    char *machine_fingerprint = st_json_get_string(body, "machineFingerprint");
    char *os_user = st_json_get_string(body, "osUser");

    if (api_key == NULL || timestamp == NULL || nonce == NULL || signature == NULL
        || machine_fingerprint == NULL || *machine_fingerprint == '\0'
        || os_user == NULL || *os_user == '\0') {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client auth request is incomplete\"}");
    }

    char *end = NULL;
    long long timestamp_ms = strtoll(timestamp, &end, 10);
    long long now_ms = current_time_millis();
    int invalid = expected_api_key == NULL || strcmp(api_key, expected_api_key) != 0
        || end == timestamp || *end != '\0' || timestamp_ms <= 0
        || now_ms <= 0 || llabs(now_ms - timestamp_ms) > 60000LL;

    uint8_t key[ST_SHA256_LEN] = {0};
    uint8_t actual_signature[ST_SHA256_LEN] = {0};
    uint8_t expected_signature[ST_SHA256_LEN] = {0};
    if (!invalid && load_client_api_key(key) != 0) {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        return write_response(out,
                              out_len,
                              503,
                              "Service Unavailable",
                              "{\"error\":\"SPECUS_CLIENT_SECRET or a 64-char SPECUS_CLIENT_SECRET_HASH is required\"}");
    }
    if (!invalid && st_hex_decode_32(signature, actual_signature) != 0) {
        invalid = 1;
    }

    if (!invalid) {
        st_admin_string_builder canonical = {0};
        if (admin_sb_appendf(&canonical,
                             "%s\n%s\n%s\n%s\n%s",
                             api_key,
                             timestamp,
                             nonce,
                             machine_fingerprint,
                             os_user) != 0) {
            free(canonical.data);
            free(api_key);
            free(timestamp);
            free(nonce);
            free(signature);
            free(machine_fingerprint);
            free(os_user);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"auth canonical build failed\"}");
        }
        st_hmac_sha256(key,
                       sizeof(key),
                       (const uint8_t *)canonical.data,
                       canonical.len,
                       expected_signature);
        free(canonical.data);
        invalid = !st_constant_time_eq(actual_signature, expected_signature, sizeof(expected_signature));
    }

    memset(key, 0, sizeof(key));
    memset(actual_signature, 0, sizeof(actual_signature));
    memset(expected_signature, 0, sizeof(expected_signature));
    free(api_key);
    free(timestamp);
    free(nonce);
    free(signature);
    free(machine_fingerprint);
    free(os_user);

    if (invalid) {
        return write_response(out, out_len, 401, "Unauthorized", "{\"error\":\"client signature invalid or expired\"}");
    }
    return 0;
}

static int build_client_auth_login_success_response(char *out, size_t out_len)
{
    const char *access_token = getenv("SPECUS_CLIENT_ACCESS_TOKEN");
    if (access_token == NULL || *access_token == '\0') {
        return write_response(out,
                              out_len,
                              503,
                              "Service Unavailable",
                              "{\"error\":\"SPECUS_CLIENT_ACCESS_TOKEN is required for the C environment-token compatibility mode\"}");
    }

    const char *client_name_raw = env_text("SPECUS_CLIENT_NAME", "Demo client");
    st_admin_tcp_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t mapping_count = 0;
    if (load_current_tcp_mappings(client_name_raw, mappings, &mapping_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp mapping response build failed\"}");
    }
    st_admin_http_route http_routes[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t http_route_count = 0;
    if (load_current_http_routes(client_name_raw, http_routes, &http_route_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route response build failed\"}");
    }

    const char *tenant_raw = getenv("SPECUS_CLIENT_TENANT_ID");
    if (tenant_raw == NULL || *tenant_raw == '\0') {
        tenant_raw = env_text("SPECUS_AUTH_TENANT_ID", "default");
    }
    long long client_id = env_i64("SPECUS_CLIENT_ID", 1);
    long long client_session_id = env_i64("SPECUS_CLIENT_SESSION_ID", 1);
    long long token_ttl_seconds = env_i64_alias("SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS",
                                                "SPECUS_CLIENT_TOKEN_TTL_SECONDS",
                                                28800);
    int max_online_instances = client_auth_default_max_online_instances();
    int policy_enabled = env_bool("SPECUS_CLIENT_POLICY_ENABLED", 1);
    long long retry_after_seconds = env_i64("SPECUS_CLIENT_RETRY_AFTER_SECONDS", 0);

    char *billing_status = st_json_escape(env_text("SPECUS_CLIENT_BILLING_STATUS", "ACTIVE"));
    char *tenant_id = st_json_escape(tenant_raw);
    char *client_name = st_json_escape(client_name_raw);
    char *netty_host = st_json_escape(env_text("SPECUS_PUBLIC_ADDRESS", "127.0.0.1"));
    char *token = st_json_escape(access_token);
    if (billing_status == NULL || tenant_id == NULL || client_name == NULL || netty_host == NULL || token == NULL) {
        free(billing_status);
        free(tenant_id);
        free(client_name);
        free(netty_host);
        free(token);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"auth response build failed\"}");
    }

    st_admin_string_builder builder = {0};
    int build_rc = admin_sb_appendf(&builder,
                                    "{\"tenantId\":\"%s\",\"clientId\":%lld,\"clientName\":\"%s\","
                                    "\"clientSessionId\":%lld,\"accessToken\":\"%s\",\"tokenTtlSeconds\":%lld,"
                                    "\"nettyHost\":\"%s\",\"nettyPort\":%d,\"maxOnlineInstances\":%d,"
                                    "\"policy\":{\"enabled\":%s,\"billingStatus\":\"%s\",\"retryAfterSeconds\":%lld},"
                                    "\"peerMesh\":{\"enabled\":false,\"clientId\":%lld,\"clientName\":\"%s\","
                                    "\"virtualIp\":\"\",\"cidr\":\"\",\"stunHost\":\"\",\"stunPort\":0,"
                                    "\"turnHost\":\"\",\"turnPort\":0,\"iceUsername\":\"\",\"iceCredential\":\"\","
                                    "\"serverPublicKey\":\"\",\"clientPublicKey\":\"\",\"sessionTtlSeconds\":0},"
                                    "\"specusConfigList\":[",
                                    tenant_id,
                                    client_id,
                                    client_name,
                                    client_session_id,
                                    token,
                                    token_ttl_seconds,
                                    netty_host,
                                    env_int("SPECUS_NETTY_PORT", 7010),
                                    max_online_instances,
                                    policy_enabled ? "true" : "false",
                                    billing_status,
                                    retry_after_seconds,
                                    client_id,
                                    client_name);
    if (build_rc == 0) {
        build_rc = append_specus_config_list(&builder, mappings, mapping_count);
    }
    if (build_rc == 0) {
        build_rc = admin_sb_append(&builder, "],\"httpSpecusConfigList\":[");
    }
    if (build_rc == 0) {
        build_rc = append_http_route_config_list(&builder, http_routes, http_route_count);
    }
    if (build_rc == 0) {
        build_rc = admin_sb_append(&builder, "]}");
    }
    free(billing_status);
    free(tenant_id);
    free(client_name);
    free(netty_host);
    free(token);
    if (build_rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"auth response too large\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static void admin_iso_time(long long epoch_seconds, char out[64])
{
    time_t value = (time_t)epoch_seconds;
    struct tm tm_value;
    gmtime_r(&value, &tm_value);
    strftime(out, 64, "%Y-%m-%dT%H:%M:%SZ", &tm_value);
}

static void build_prefixed_token(const char *prefix, char *out, size_t out_len)
{
    static unsigned long counter = 0;
    static pthread_mutex_t token_lock = PTHREAD_MUTEX_INITIALIZER;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pthread_mutex_lock(&token_lock);
    unsigned long local_counter = ++counter;
    pthread_mutex_unlock(&token_lock);
    char seed[256];
    snprintf(seed,
             sizeof(seed),
             "%s:%lld:%ld:%lu:%p",
             prefix == NULL ? "token" : prefix,
             (long long)tv.tv_sec * 1000000LL + (long long)tv.tv_usec,
             (long)getpid(),
             local_counter,
             (void *)&token_lock);
    uint8_t digest1[ST_SHA256_LEN];
    uint8_t digest2[ST_SHA256_LEN];
    char hex1[ST_SHA256_HEX_LEN + 1];
    char hex2[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)seed, strlen(seed), digest1);
    st_sha256(digest1, sizeof(digest1), digest2);
    st_hex_encode(digest1, sizeof(digest1), hex1);
    st_hex_encode(digest2, sizeof(digest2), hex2);
    snprintf(out, out_len, "%s%s%s", prefix == NULL ? "" : prefix, hex1, hex2);
}

static void base64url_no_padding(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t written = 0;
    for (size_t i = 0; i < len && written + 1U < out_len; i += 3U) {
        uint32_t value = (uint32_t)data[i] << 16;
        size_t remaining = len - i;
        if (remaining > 1U) value |= (uint32_t)data[i + 1U] << 8;
        if (remaining > 2U) value |= data[i + 2U];
        if (written + 1U < out_len) out[written++] = alphabet[(value >> 18) & 63U];
        if (written + 1U < out_len) out[written++] = alphabet[(value >> 12) & 63U];
        if (remaining > 1U && written + 1U < out_len) out[written++] = alphabet[(value >> 6) & 63U];
        if (remaining > 2U && written + 1U < out_len) out[written++] = alphabet[value & 63U];
    }
    out[written] = '\0';
}

static int admin_secure_random(uint8_t *out, size_t len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    size_t offset = 0;
    while (offset < len) {
        ssize_t read_len = read(fd, out + offset, len - offset);
        if (read_len < 0 && errno == EINTR) {
            continue;
        }
        if (read_len <= 0) {
            close(fd);
            return -1;
        }
        offset += (size_t)read_len;
    }
    close(fd);
    return 0;
}

static void admin_hash_text(const char *value, uint8_t out[ST_SHA256_LEN])
{
    const char *normalized = value == NULL ? "" : value;
    st_sha256((const uint8_t *)normalized, strlen(normalized), out);
}

static size_t admin_prune_websocket_tickets_locked(time_t now)
{
    size_t count = 0;
    st_admin_ws_ticket **cursor = &admin_ws_tickets;
    while (*cursor != NULL) {
        st_admin_ws_ticket *ticket = *cursor;
        if (ticket->expires_at <= now) {
            *cursor = ticket->next;
            free(ticket);
            continue;
        }
        ++count;
        cursor = &ticket->next;
    }
    return count;
}

static int admin_issue_websocket_ticket(const st_admin_context *context,
                                        const char *endpoint,
                                        const char *remote_address,
                                        char out[64],
                                        time_t *expires_at)
{
    if (context == NULL || !context->authenticated || endpoint == NULL
        || out == NULL || expires_at == NULL) {
        return -1;
    }
    uint8_t random_bytes[ST_ADMIN_WS_TICKET_BYTES];
    uint8_t token_hash[ST_SHA256_LEN];
    uint8_t remote_address_hash[ST_SHA256_LEN];
    if (admin_secure_random(random_bytes, sizeof(random_bytes)) != 0) {
        return -1;
    }
    base64url_no_padding(random_bytes, sizeof(random_bytes), out, 64U);
    admin_hash_text(out, token_hash);
    admin_hash_text(remote_address, remote_address_hash);

    st_admin_ws_ticket *ticket = (st_admin_ws_ticket *)calloc(1, sizeof(*ticket));
    if (ticket == NULL) {
        return -1;
    }
    memcpy(ticket->token_hash, token_hash, sizeof(token_hash));
    memcpy(ticket->remote_address_hash, remote_address_hash, sizeof(remote_address_hash));
    snprintf(ticket->username, sizeof(ticket->username), "%s", context->username);
    snprintf(ticket->tenant_id, sizeof(ticket->tenant_id), "%s", context->tenant_id);
    snprintf(ticket->endpoint, sizeof(ticket->endpoint), "%s", endpoint);
    ticket->admin = context->admin;
    ticket->expires_at = time(NULL) + ST_ADMIN_WS_TICKET_TTL_SECONDS;

    pthread_mutex_lock(&admin_ws_ticket_lock);
    size_t active_tickets = admin_prune_websocket_tickets_locked(time(NULL));
    if (active_tickets >= ST_ADMIN_MAX_WS_TICKETS) {
        pthread_mutex_unlock(&admin_ws_ticket_lock);
        free(ticket);
        return -2;
    }
    for (st_admin_ws_ticket *existing = admin_ws_tickets; existing != NULL; existing = existing->next) {
        if (st_constant_time_eq(existing->token_hash, token_hash, sizeof(token_hash))) {
            pthread_mutex_unlock(&admin_ws_ticket_lock);
            free(ticket);
            return -1;
        }
    }
    ticket->next = admin_ws_tickets;
    admin_ws_tickets = ticket;
    *expires_at = ticket->expires_at;
    pthread_mutex_unlock(&admin_ws_ticket_lock);
    return 0;
}

static int admin_consume_websocket_ticket(const char *token,
                                          const char *endpoint,
                                          const char *remote_address,
                                          st_admin_context *context)
{
    if (token == NULL || endpoint == NULL
        || strlen(token) < 32U || strlen(token) > 128U || context == NULL) {
        return -1;
    }
    uint8_t token_hash[ST_SHA256_LEN];
    uint8_t remote_address_hash[ST_SHA256_LEN];
    admin_hash_text(token, token_hash);
    admin_hash_text(remote_address, remote_address_hash);

    pthread_mutex_lock(&admin_ws_ticket_lock);
    admin_prune_websocket_tickets_locked(time(NULL));
    st_admin_ws_ticket **cursor = &admin_ws_tickets;
    while (*cursor != NULL) {
        st_admin_ws_ticket *ticket = *cursor;
        if (!st_constant_time_eq(ticket->token_hash, token_hash, sizeof(token_hash))) {
            cursor = &ticket->next;
            continue;
        }
        if (strcmp(ticket->endpoint, endpoint) != 0
            || !st_constant_time_eq(ticket->remote_address_hash,
                                 remote_address_hash,
                                 sizeof(remote_address_hash))) {
            pthread_mutex_unlock(&admin_ws_ticket_lock);
            return -1;
        }
        *cursor = ticket->next;
        memset(context, 0, sizeof(*context));
        snprintf(context->username, sizeof(context->username), "%s", ticket->username);
        snprintf(context->tenant_id, sizeof(context->tenant_id), "%s", ticket->tenant_id);
        snprintf(context->role, sizeof(context->role), "%s", ticket->admin ? "ADMIN" : "USER");
        context->admin = ticket->admin;
        context->authenticated = 1;
        free(ticket);
        pthread_mutex_unlock(&admin_ws_ticket_lock);
        return 0;
    }
    pthread_mutex_unlock(&admin_ws_ticket_lock);
    return -1;
}

static int handle_admin_websocket_ticket(const st_admin_context *context,
                                         const char *body,
                                         const char *remote_address,
                                         char *out,
                                         size_t out_len)
{
    char *endpoint = st_json_get_top_level_string(body, "endpoint");
    if (endpoint == NULL
        || (strcmp(endpoint, "connections") != 0
            && strcmp(endpoint, "client-messages") != 0)) {
        free(endpoint);
        return write_response(out,
                              out_len,
                              400,
                              "Bad Request",
                              "{\"error\":\"endpoint must be connections or client-messages\"}");
    }

    char token[64];
    time_t expires_at = 0;
    int issue_rc = admin_issue_websocket_ticket(context, endpoint, remote_address, token, &expires_at);
    free(endpoint);
    if (issue_rc == -2) {
        return write_response(out,
                              out_len,
                              429,
                              "Too Many Requests",
                              "{\"error\":\"too many active websocket tickets\"}");
    }
    if (issue_rc != 0) {
        return write_response(out,
                              out_len,
                              500,
                              "Internal Server Error",
                              "{\"error\":\"websocket ticket generation failed\"}");
    }

    char expires_text[64];
    admin_iso_time((long long)expires_at, expires_text);
    char response_body[256];
    int written = snprintf(response_body,
                           sizeof(response_body),
                           "{\"ticket\":\"%s\",\"expiresAt\":\"%s\"}",
                           token,
                           expires_text);
    if (written < 0 || (size_t)written >= sizeof(response_body)) {
        return write_response(out,
                              out_len,
                              500,
                              "Internal Server Error",
                              "{\"error\":\"websocket ticket response failed\"}");
    }
    return write_response(out, out_len, 200, "OK", response_body);
}

static int build_public_ice_url(const char *scheme,
                                const char *host,
                                int port,
                                const char *suffix,
                                char *out,
                                size_t out_len)
{
    if (host == NULL || *host == '\0') {
        return -1;
    }
    while (isspace((unsigned char)*host)) ++host;
    if (strncmp(host, "http://", 7) == 0) host += 7;
    else if (strncmp(host, "https://", 8) == 0) host += 8;
    const char *end = host + strlen(host);
    while (end > host && isspace((unsigned char)end[-1])) --end;
    const char *slash = memchr(host, '/', (size_t)(end - host));
    if (slash != NULL) end = slash;
    if (end <= host) return -1;

    char normalized[384];
    size_t host_len = (size_t)(end - host);
    if (host_len >= sizeof(normalized)) return -1;
    memcpy(normalized, host, host_len);
    normalized[host_len] = '\0';
    int colon_count = 0;
    for (size_t i = 0; i < host_len; ++i) {
        if (normalized[i] == ':') ++colon_count;
    }
    int written;
    if (normalized[0] == '[' || colon_count <= 1) {
        char *last_colon = strrchr(normalized, ':');
        if (normalized[0] == '[') {
            char *bracket = strchr(normalized, ']');
            if (bracket != NULL) bracket[1] = '\0';
        } else if (last_colon != NULL) {
            *last_colon = '\0';
        }
        written = snprintf(out, out_len, "%s:%s:%d%s", scheme, normalized, port, suffix == NULL ? "" : suffix);
    } else {
        written = snprintf(out, out_len, "%s:[%s]:%d%s", scheme, normalized, port, suffix == NULL ? "" : suffix);
    }
    return written > 0 && (size_t)written < out_len ? 0 : -1;
}

static int normalize_public_host(const char *value, char *out, size_t out_len)
{
    if (value == NULL || out == NULL || out_len == 0U) return -1;
    while (isspace((unsigned char)*value)) ++value;
    if (strncasecmp(value, "http://", 7U) == 0) value += 7;
    else if (strncasecmp(value, "https://", 8U) == 0) value += 8;
    const char *end = value + strlen(value);
    const char *comma = strchr(value, ',');
    const char *slash = strchr(value, '/');
    if (comma != NULL && comma < end) end = comma;
    if (slash != NULL && slash < end) end = slash;
    while (end > value && isspace((unsigned char)end[-1])) --end;
    if (end <= value) return -1;
    if (*value == '[') {
        const char *close = memchr(value + 1, ']', (size_t)(end - value - 1));
        if (close == NULL) return -1;
        ++value;
        end = close;
    } else {
        int colons = 0;
        const char *last_colon = NULL;
        for (const char *cursor = value; cursor < end; ++cursor) {
            if (*cursor == ':') {
                ++colons;
                last_colon = cursor;
            }
            if ((unsigned char)*cursor < 0x20U) return -1;
        }
        if (colons == 1 && last_colon != NULL) end = last_colon;
    }
    size_t len = (size_t)(end - value);
    if (len == 0U || len >= out_len) return -1;
    memcpy(out, value, len);
    out[len] = '\0';
    return 0;
}

static int public_primary_stun(const char *host_hint,
                               char host[384],
                               int *port,
                               int *standalone)
{
    const char *configured = getenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS");
    int configured_port = env_int("SPECUS_PEER_MESH_STANDALONE_STUN_PORT", 3478);
    *standalone = configured != NULL && *configured != '\0' && configured_port > 0;
    if (*standalone) {
        *port = configured_port;
        return normalize_public_host(configured, host, 384U);
    }
    configured = getenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    if (configured == NULL || *configured == '\0') configured = host_hint;
    *port = env_int("SPECUS_PEER_MESH_STUN_TURN_PORT", 3478);
    return *port > 0 ? normalize_public_host(configured, host, 384U) : -1;
}

static int public_alternate_stun(char host[384], int *port)
{
    const char *configured = getenv("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_ADDRESS");
    int configured_port = env_int("SPECUS_PEER_MESH_STANDALONE_STUN_ALTERNATE_PORT", 0);
    if (configured == NULL || *configured == '\0') {
        configured = getenv("SPECUS_PEER_MESH_STUN_ALTERNATE_PUBLIC_ADDRESS");
        configured_port = env_int("SPECUS_PEER_MESH_NAT_PROBE_ALTERNATE_PORT", 3479);
    }
    *port = configured_port;
    return configured_port > 0 ? normalize_public_host(configured, host, 384U) : -1;
}

static int normalize_public_stun_url(const char *value, char *out, size_t out_len)
{
    while (isspace((unsigned char)*value)) ++value;
    size_t value_len = strlen(value);
    if (value_len >= 7U
        && tolower((unsigned char)value[0]) == 's'
        && tolower((unsigned char)value[1]) == 't'
        && tolower((unsigned char)value[2]) == 'u'
        && tolower((unsigned char)value[3]) == 'n'
        && value[4] == ':' && value[5] == '/' && value[6] == '/') {
        value += 7;
    } else if (value_len >= 5U
               && tolower((unsigned char)value[0]) == 's'
               && tolower((unsigned char)value[1]) == 't'
               && tolower((unsigned char)value[2]) == 'u'
               && tolower((unsigned char)value[3]) == 'n'
               && value[4] == ':') {
        value += 5;
    }
    const char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    if (end <= value || (size_t)(end - value) >= 384U) return -1;
    char host[384];
    memcpy(host, value, (size_t)(end - value));
    host[end - value] = '\0';
    int port = 3478;
    char *last_colon = strrchr(host, ':');
    if (host[0] == '[') {
        char *bracket = strchr(host, ']');
        if (bracket != NULL && bracket[1] == ':') {
            int parsed = atoi(bracket + 2);
            if (parsed > 0 && parsed <= 65535) port = parsed;
        }
    } else if (last_colon != NULL && strchr(host, ':') == last_colon) {
        int parsed = atoi(last_colon + 1);
        if (parsed > 0 && parsed <= 65535) port = parsed;
    }
    return build_public_ice_url("stun", host, port, "", out, out_len);
}

static size_t collect_public_stun_urls(char urls[][512], size_t max_urls,
                                       int peer_mesh_enabled, const char *host_hint)
{
    size_t count = 0;
    char primary_host[384];
    int primary_port = 0;
    int standalone = 0;
    if (count < max_urls
        && public_primary_stun(host_hint, primary_host, &primary_port, &standalone) == 0
        && (peer_mesh_enabled || standalone)
        && build_public_ice_url("stun", primary_host, primary_port, "",
                                urls[count], sizeof(urls[count])) == 0) {
        ++count;
    }
    char alternate_host[384];
    int alternate_port = 0;
    if (count < max_urls && standalone
        && public_alternate_stun(alternate_host, &alternate_port) == 0) {
        (void)alternate_port;
        char normalized[512];
        if (build_public_ice_url("stun", alternate_host, primary_port, "",
                                 normalized, sizeof(normalized)) == 0
            && (count == 0U || strcmp(urls[0], normalized) != 0))
            snprintf(urls[count++], sizeof(urls[0]), "%s", normalized);
    }
    const char *configured = getenv("SPECUS_PEER_MESH_PUBLIC_STUN_SERVERS");
    if (configured == NULL || *configured == '\0') return count;
    char *copy = strdup(configured);
    if (copy == NULL) return count;
    char *save = NULL;
    for (char *item = strtok_r(copy, ",", &save); item != NULL && count < max_urls; item = strtok_r(NULL, ",", &save)) {
        char normalized[512];
        if (normalize_public_stun_url(item, normalized, sizeof(normalized)) != 0) continue;
        int duplicate = 0;
        for (size_t i = 0; i < count; ++i) {
            if (strcmp(urls[i], normalized) == 0) duplicate = 1;
        }
        if (!duplicate) snprintf(urls[count++], sizeof(urls[0]), "%s", normalized);
    }
    free(copy);
    return count;
}

static int build_public_stun_config_response(const char *host_hint, char *out, size_t out_len)
{
    int enabled = env_bool("SPECUS_PEER_MESH_ENABLED", 0);
    int port = 0;
    int standalone = 0;
    char primary_host[384];
    int has_primary = public_primary_stun(host_hint, primary_host, &port, &standalone) == 0;
    char urls[16][512];
    size_t count = collect_public_stun_urls(urls, 16U, enabled, host_hint);
    char self_url[512] = "";
    if (has_primary && (enabled || standalone)) {
        (void)build_public_ice_url("stun", primary_host, port, "", self_url, sizeof(self_url));
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_appendf(&builder,
                              "{\"peerMeshEnabled\":%s,\"selfHostedStunServer\":",
                              enabled ? "true" : "false");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, self_url);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"stunServers\":[");
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, urls[i]);
    }
    if (rc == 0) rc = admin_sb_appendf(&builder, "],\"stunTurnPort\":%d}", port);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"stun config response failed\"}");
    }
    int result = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return result;
}

static int build_public_ice_config_response(const char *host_hint, char *out, size_t out_len)
{
    int enabled = env_bool("SPECUS_PEER_MESH_ENABLED", 0);
    int auth_required = env_bool("SPECUS_PEER_MESH_TURN_AUTH_REQUIRED", 1);
    int port = env_int("SPECUS_PEER_MESH_STUN_TURN_PORT", 3478);
    char urls[16][512];
    size_t count = collect_public_stun_urls(urls, 16U, enabled, host_hint);
    st_admin_string_builder builder = {0};
    int rc = admin_sb_appendf(&builder, "{\"peerMeshEnabled\":%s,\"iceServers\":[", enabled ? "true" : "false");
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = admin_sb_append(&builder, "{\"urls\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, urls[i]);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"username\":\"\",\"credential\":\"\"}");
    }
    const char *public_address = getenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    if (public_address == NULL || *public_address == '\0') public_address = host_hint;
    int turn_publishable = enabled && public_address != NULL && *public_address != '\0';
    if (rc == 0 && turn_publishable) {
        char username[192];
        char credential[64];
        char turn_url[512];
        if (st_turn_auth_issue("public-transfer", username, sizeof(username),
                               credential, sizeof(credential)) == 0
            && build_public_ice_url("turn", public_address, port, "?transport=udp",
                                    turn_url, sizeof(turn_url)) == 0) {
            if (count > 0) rc = admin_sb_append(&builder, ",");
            if (rc == 0) rc = admin_sb_append(&builder, "{\"urls\":");
            if (rc == 0) rc = admin_sb_append_json_string(&builder, turn_url);
            if (rc == 0) rc = admin_sb_append(&builder, ",\"username\":");
            if (rc == 0) rc = admin_sb_append_json_string(&builder, username);
            if (rc == 0) rc = admin_sb_append(&builder, ",\"credential\":");
            if (rc == 0) rc = admin_sb_append_json_string(&builder, credential);
            if (rc == 0) rc = admin_sb_append(&builder, "}");
        }
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
                              "],\"turnAuthRequired\":%s,\"stunTurnPort\":%d}",
                              auth_required ? "true" : "false",
                              port);
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"ice config response failed\"}");
    }
    int result = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return result;
}

static int build_public_nat_probe_config_response(const char *host_hint,
                                                  char *out,
                                                  size_t out_len)
{
    char primary_host[384];
    char alternate_host[384];
    int primary_port = 0;
    int alternate_port = 0;
    int standalone = 0;
    int has_primary = public_primary_stun(host_hint, primary_host, &primary_port, &standalone) == 0;
    int has_alternate = public_alternate_stun(alternate_host, &alternate_port) == 0;
    int rfc5780 = has_primary && has_alternate && primary_port > 0 && alternate_port > 0
        && primary_port != alternate_port && strcasecmp(primary_host, alternate_host) != 0;
    (void)standalone;
    const char *ids[] = {"A1P1", "A1P2", "A2P1", "A2P2"};
    const char *address_slots[] = {"PRIMARY", "PRIMARY", "ALTERNATE", "ALTERNATE"};
    const char *port_slots[] = {"PRIMARY", "ALTERNATE", "PRIMARY", "ALTERNATE"};
    st_admin_string_builder builder = {0};
    int rc = admin_sb_appendf(&builder,
        "{\"available\":%s,\"protocol\":\"RFC8489\",\"discoveryMethod\":\"%s\",\"endpoints\":[",
        has_primary ? "true" : "false", rfc5780 ? "RFC5780" : "BASIC_STUN");
    size_t endpoint_count = has_primary ? (rfc5780 ? 4U : 1U) : 0U;
    for (size_t i = 0; rc == 0 && i < endpoint_count; ++i) {
        const char *host = i < 2U ? primary_host : alternate_host;
        int port = i == 0U || i == 2U ? primary_port : alternate_port;
        char url[512];
        if (build_public_ice_url("stun", host, port, "", url, sizeof(url)) != 0) {
            rc = -1;
            break;
        }
        if (i > 0U) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = admin_sb_append(&builder, "{\"id\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, ids[i]);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"url\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, url);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"host\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, host);
        if (rc == 0) rc = admin_sb_appendf(&builder, ",\"port\":%d,\"addressSlot\":", port);
        if (rc == 0) rc = admin_sb_append_json_string(&builder, address_slots[i]);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"portSlot\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, port_slots[i]);
        if (rc == 0) rc = admin_sb_append(&builder, "}");
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
            "],\"capabilities\":{\"binding\":true,\"changeRequest\":%s,"
            "\"responseOrigin\":%s,\"otherAddress\":%s,\"responsePort\":%s,"
            "\"padding\":%s,\"browserMappingObservation\":true,"
            "\"browserFilteringObservation\":false}}",
            rfc5780 ? "true" : "false", rfc5780 ? "true" : "false",
            rfc5780 ? "true" : "false", rfc5780 ? "true" : "false",
            rfc5780 ? "true" : "false");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"nat probe config response failed\"}");
    }
    int result = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return result;
}

static void build_client_access_token(char out[160])
{
    build_prefixed_token("cs_", out, 160);
}

static int append_db_client_auth_response(char *out,
                                          size_t out_len,
                                          const st_storage_client_credential *credential,
                                          const st_storage_client_identity *identity,
                                          const st_storage_client_session *session,
                                          const char *access_token)
{
    st_admin_tcp_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t mapping_count = 0;
    if (load_current_tcp_mappings(identity->client_name, mappings, &mapping_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp mapping response build failed\"}");
    }
    st_admin_http_route http_routes[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t http_route_count = 0;
    if (load_current_http_routes(identity->client_name, http_routes, &http_route_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route response build failed\"}");
    }

    char *tenant_id = st_json_escape(credential->tenant_id);
    char *client_name = st_json_escape(identity->client_name);
    char *netty_host = st_json_escape(env_text("SPECUS_PUBLIC_ADDRESS", "127.0.0.1"));
    char *token = st_json_escape(access_token);
    if (tenant_id == NULL || client_name == NULL || netty_host == NULL || token == NULL) {
        free(tenant_id);
        free(client_name);
        free(netty_host);
        free(token);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"auth response build failed\"}");
    }

    long long token_ttl_seconds = env_i64_alias("SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS",
                                                "SPECUS_CLIENT_TOKEN_TTL_SECONDS",
                                                28800);
    char *peer_mesh_config = st_peer_mesh_build_login_config(admin_database_path(), identity->client_name,
                                                              session->peer_service_discovery_version);
    if (peer_mesh_config == NULL) {
        peer_mesh_config = strdup("{\"enabled\":false,\"clientId\":0,\"clientName\":\"\","
                                  "\"virtualIp\":\"\",\"cidr\":\"100.96.0.0/11\","
                                  "\"stunHost\":\"\",\"stunPort\":0,\"turnHost\":\"\",\"turnPort\":0,"
                                  "\"publicStunServers\":[],\"iceUsername\":\"\",\"iceCredential\":\"\","
                                  "\"iceRealm\":\"specus\",\"iceNonce\":\"\",\"serverPublicKey\":\"\","
                                  "\"clientPublicKey\":\"\",\"sessionTtlSeconds\":3600,"
                                  "\"peerServiceDiscoveryVersion\":2,\"serviceSharing\":{"
                                  "\"deploymentEnabled\":false,\"configuredEnabled\":false,"
                                  "\"effectiveEnabled\":false,\"mdnsImportEnabled\":false},\"localServices\":[]}");
    }
    if (peer_mesh_config == NULL) {
        free(tenant_id); free(client_name); free(netty_host); free(token);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh response build failed\"}");
    }
    st_admin_string_builder builder = {0};
    int build_rc = admin_sb_appendf(&builder,
                                    "{\"tenantId\":\"%s\",\"clientId\":%lld,\"clientName\":\"%s\","
                                    "\"clientSessionId\":%lld,\"accessToken\":\"%s\",\"tokenTtlSeconds\":%lld,"
                                    "\"nettyHost\":\"%s\",\"nettyPort\":%d,\"maxOnlineInstances\":%d,"
                                    "\"policy\":{\"enabled\":true,\"billingStatus\":\"ACTIVE\",\"retryAfterSeconds\":0},"
                                    "\"peerMesh\":",
                                    tenant_id,
                                    identity->client_id,
                                    client_name,
                                    session->id,
                                    token,
                                    token_ttl_seconds,
                                    netty_host,
                                    env_int("SPECUS_NETTY_PORT", 7010),
                                    credential->max_online_instances <= 0
                                        ? client_auth_default_max_online_instances()
                                        : credential->max_online_instances);
    if (build_rc == 0) build_rc = admin_sb_append(&builder, peer_mesh_config);
    if (build_rc == 0) build_rc = admin_sb_append(&builder, ",\"specusConfigList\":[");
    if (build_rc == 0) {
        build_rc = append_specus_config_list(&builder, mappings, mapping_count);
    }
    if (build_rc == 0) {
        build_rc = admin_sb_append(&builder, "],\"httpSpecusConfigList\":[");
    }
    if (build_rc == 0) {
        build_rc = append_http_route_config_list(&builder, http_routes, http_route_count);
    }
    if (build_rc == 0) {
        build_rc = admin_sb_append(&builder, "]}");
    }
    free(tenant_id);
    free(client_name);
    free(netty_host);
    free(token);
    free(peer_mesh_config);
    if (build_rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"auth response too large\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_database_client_auth_login_response(const char *database_path,
                                                     const char *body,
                                                     char *out,
                                                     size_t out_len)
{
    if (body == NULL) {
        return 0;
    }
    char *api_key = st_json_get_string(body, "apiKey");
    if (api_key == NULL || *api_key == '\0') {
        free(api_key);
        return 0;
    }
    st_storage_client_credential credential;
    if (st_storage_get_client_credential_by_api_key(database_path, api_key, &credential) != 0) {
        free(api_key);
        return 0;
    }

    char *timestamp = st_json_get_string(body, "timestamp");
    char *nonce = st_json_get_string(body, "nonce");
    char *signature = st_json_get_string(body, "signature");
    char *machine_fingerprint = st_json_get_string(body, "machineFingerprint");
    char *os_user = st_json_get_string(body, "osUser");
    char *hostname = st_json_get_string(body, "hostname");
    char *os_name = st_json_get_string(body, "osName");
    char *os_version = st_json_get_string(body, "osVersion");
    char *os_arch = st_json_get_string(body, "osArch");
    char *client_version = st_json_get_string(body, "clientVersion");
    char *java_version = st_json_get_string(body, "javaVersion");
    int message_send_capable = 0;
    int message_receive_capable = 0;
    int message_attachments_capable = 0;
    int message_media_preview_capable = 0;
    long long message_max_attachment_bytes = 0;
    int peer_service_discovery_version = 0;
    char peer_service_applications[128] = "";
    /* ClientEnvironmentInfo uses the wire-level capability names below.  The
     * management projection deliberately keeps its message*Capable names, but
     * accepting those projection names here would silently discard the real
     * Java/Go/.NET/Android login payload. */
    (void)st_json_get_bool(body, "sendMessages", &message_send_capable);
    (void)st_json_get_bool(body, "receiveMessages", &message_receive_capable);
    (void)st_json_get_bool(body, "attachments", &message_attachments_capable);
    (void)st_json_get_bool(body, "mediaPreview", &message_media_preview_capable);
    (void)st_json_get_i64(body, "maxAttachmentBytes", &message_max_attachment_bytes);
    int client_egress_version = 0;
    /*
     * Scope the capability lookups to their own objects. clientPeerServiceCapabilities and
     * clientEgressCapabilities both carry a "version" field, so a depth-first search of the whole
     * body would return whichever the client happened to serialise first. Older payloads that put
     * the peer capabilities somewhere else still fall back to the previous search.
     */
    char *environment_raw = st_json_get_top_level_raw(body, "environment");
    char *peer_caps_raw = environment_raw == NULL
        ? NULL : st_json_get_top_level_raw(environment_raw, "clientPeerServiceCapabilities");
    char *egress_caps_raw = environment_raw == NULL
        ? NULL : st_json_get_top_level_raw(environment_raw, "clientEgressCapabilities");
    const char *peer_caps = peer_caps_raw == NULL ? body : peer_caps_raw;
    if (egress_caps_raw != NULL) {
        (void)st_json_get_int(egress_caps_raw, "version", &client_egress_version);
    }
    client_egress_version = st_egress_normalize_version(client_egress_version);
    (void)st_json_get_int(peer_caps, "version", &peer_service_discovery_version);
    if (peer_service_discovery_version < 1) peer_service_discovery_version = 0;
    else if (peer_service_discovery_version > 2) peer_service_discovery_version = 2;
    char **peer_apps = NULL;
    size_t peer_app_count = 0U;
    if (peer_service_discovery_version > 0
        && st_json_get_string_array(peer_caps, "applications", &peer_apps, &peer_app_count) == 0) {
        size_t offset = 0U;
        for (size_t i = 0; i < peer_app_count; ++i) {
            const char *app = peer_apps[i];
            int allowed = strcmp(app, "http") == 0 || strcmp(app, "https") == 0
                || strcmp(app, "ssh") == 0 || strcmp(app, "tcp") == 0 || strcmp(app, "udp") == 0;
            int duplicate = 0;
            if (allowed && peer_service_applications[0] != '\0') {
                char copy[sizeof(peer_service_applications)];
                snprintf(copy, sizeof(copy), "%s", peer_service_applications);
                char *save = NULL;
                for (char *part = strtok_r(copy, ",", &save); part != NULL; part = strtok_r(NULL, ",", &save)) {
                    if (strcmp(part, app) == 0) duplicate = 1;
                }
            }
            if (!allowed || duplicate) continue;
            int written = snprintf(peer_service_applications + offset,
                                   sizeof(peer_service_applications) - offset,
                                   "%s%s", offset == 0U ? "" : ",", app);
            if (written < 0 || (size_t)written >= sizeof(peer_service_applications) - offset) break;
            offset += (size_t)written;
        }
    }
    st_json_free_string_array(peer_apps, peer_app_count);
    free(environment_raw);
    free(peer_caps_raw);
    free(egress_caps_raw);
    if (message_max_attachment_bytes < 0) {
        message_max_attachment_bytes = 0;
    }
    if (timestamp == NULL || nonce == NULL || signature == NULL
        || machine_fingerprint == NULL || *machine_fingerprint == '\0'
        || os_user == NULL || *os_user == '\0') {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        free(hostname);
        free(os_name);
        free(os_version);
        free(os_arch);
        free(client_version);
        free(java_version);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"client auth request is incomplete\"}");
    }
    if (!credential.enabled) {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        free(hostname);
        free(os_name);
        free(os_version);
        free(os_arch);
        free(client_version);
        free(java_version);
        return write_response(out, out_len, 403, "Forbidden", "{\"error\":\"客户端凭证已停用\"}");
    }

    char *end = NULL;
    long long timestamp_ms = strtoll(timestamp, &end, 10);
    long long now_ms = current_time_millis();
    int invalid = end == timestamp || *end != '\0' || timestamp_ms <= 0
        || now_ms <= 0 || llabs(now_ms - timestamp_ms) > 60000LL;
    uint8_t key[ST_SHA256_LEN] = {0};
    uint8_t actual_signature[ST_SHA256_LEN] = {0};
    uint8_t expected_signature[ST_SHA256_LEN] = {0};
    if (!invalid && st_hex_decode_32(credential.secret_hash, key) != 0) {
        invalid = 1;
    }
    if (!invalid && st_hex_decode_32(signature, actual_signature) != 0) {
        invalid = 1;
    }
    if (!invalid) {
        st_admin_string_builder canonical = {0};
        if (admin_sb_appendf(&canonical,
                             "%s\n%s\n%s\n%s\n%s",
                             api_key,
                             timestamp,
                             nonce,
                             machine_fingerprint,
                             os_user) != 0) {
            free(canonical.data);
            invalid = 1;
        } else {
            st_hmac_sha256(key,
                           sizeof(key),
                           (const uint8_t *)canonical.data,
                           canonical.len,
                           expected_signature);
            free(canonical.data);
            invalid = !st_constant_time_eq(actual_signature, expected_signature, sizeof(expected_signature));
        }
    }
    memset(key, 0, sizeof(key));
    memset(actual_signature, 0, sizeof(actual_signature));
    memset(expected_signature, 0, sizeof(expected_signature));
    if (invalid) {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        free(hostname);
        free(os_name);
        free(os_version);
        free(os_arch);
        free(client_version);
        free(java_version);
        return write_response(out, out_len, 401, "Unauthorized", "{\"error\":\"client signature invalid or expired\"}");
    }

    st_storage_client_identity identity;
    int rc = st_storage_find_or_create_client_identity(database_path,
                                                       &credential,
                                                       machine_fingerprint,
                                                       os_user,
                                                       hostname == NULL ? "unknown-host" : hostname,
                                                       &identity);
    if (rc != 0) {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        free(hostname);
        free(os_name);
        free(os_version);
        free(os_arch);
        free(client_version);
        free(java_version);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client identity build failed\"}");
    }

    char *peer_public_key = st_json_get_string(body, "peerPublicKey");
    if (peer_public_key != NULL && *peer_public_key != '\0'
        && strlen(peer_public_key) <= 256U && env_bool("SPECUS_PEER_MESH_ENABLED", 0)) {
        st_storage_client peer_client;
        if (st_storage_get_client(database_path, identity.client_id, &peer_client) == 0) {
            (void)st_storage_update_peer_mesh_device_report(database_path,
                                                            &peer_client,
                                                            peer_public_key,
                                                            NULL, NULL, NULL, NULL, NULL,
                                                            NULL, NULL, NULL, NULL, NULL);
        }
    }
    free(peer_public_key);

    char access_token[160];
    char token_hash[ST_SHA256_HEX_LEN + 1];
    uint8_t token_digest[ST_SHA256_LEN];
    build_client_access_token(access_token);
    st_sha256((const uint8_t *)access_token, strlen(access_token), token_digest);
    st_hex_encode(token_digest, sizeof(token_digest), token_hash);

    long long now_seconds = current_time_millis() / 1000LL;
    long long ttl = env_i64_alias("SPECUS_CLIENT_AUTH_TOKEN_TTL_SECONDS",
                                  "SPECUS_CLIENT_TOKEN_TTL_SECONDS",
                                  28800);
    char now_text[64];
    char expires_text[64];
    admin_iso_time(now_seconds, now_text);
    admin_iso_time(now_seconds + ttl, expires_text);
    (void)st_storage_close_http_authenticated_sessions(database_path,
                                                       credential.id,
                                                       machine_fingerprint,
                                                       os_user,
                                                       now_text);
    st_storage_client_session session;
    memset(&session, 0, sizeof(session));
    snprintf(session.tenant_id, sizeof(session.tenant_id), "%s", credential.tenant_id);
    session.credential_id = credential.id;
    session.identity_id = identity.id;
    session.client_id = identity.client_id;
    snprintf(session.client_name, sizeof(session.client_name), "%s", identity.client_name);
    snprintf(session.token_hash, sizeof(session.token_hash), "%s", token_hash);
    snprintf(session.status, sizeof(session.status), "%s", "HTTP_AUTHENTICATED");
    snprintf(session.machine_fingerprint, sizeof(session.machine_fingerprint), "%s", machine_fingerprint);
    snprintf(session.os_user, sizeof(session.os_user), "%s", os_user);
    snprintf(session.hostname, sizeof(session.hostname), "%s", hostname == NULL ? "" : hostname);
    snprintf(session.os_name, sizeof(session.os_name), "%s", os_name == NULL ? "" : os_name);
    snprintf(session.os_version, sizeof(session.os_version), "%s", os_version == NULL ? "" : os_version);
    snprintf(session.os_arch, sizeof(session.os_arch), "%s", os_arch == NULL ? "" : os_arch);
    snprintf(session.client_version, sizeof(session.client_version), "%s", client_version == NULL ? "" : client_version);
    snprintf(session.java_version, sizeof(session.java_version), "%s", java_version == NULL ? "" : java_version);
    session.message_send_capable = message_send_capable;
    session.message_receive_capable = message_receive_capable;
    session.message_attachments_capable = message_attachments_capable;
    session.message_media_preview_capable = message_media_preview_capable;
    session.message_max_attachment_bytes = message_max_attachment_bytes;
    session.peer_service_discovery_version = peer_service_discovery_version;
    session.client_egress_version = client_egress_version;
    snprintf(session.peer_service_applications, sizeof(session.peer_service_applications),
             "%s", peer_service_applications);
    snprintf(session.http_login_at, sizeof(session.http_login_at), "%s", now_text);
    snprintf(session.expires_at, sizeof(session.expires_at), "%s", expires_text);
    if (st_storage_create_client_session(database_path, &session, &session) != 0) {
        free(api_key);
        free(timestamp);
        free(nonce);
        free(signature);
        free(machine_fingerprint);
        free(os_user);
        free(hostname);
        free(os_name);
        free(os_version);
        free(os_arch);
        free(client_version);
        free(java_version);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client session build failed\"}");
    }

    int response_len = append_db_client_auth_response(out, out_len, &credential, &identity, &session, access_token);
    free(api_key);
    free(timestamp);
    free(nonce);
    free(signature);
    free(machine_fingerprint);
    free(os_user);
    free(hostname);
    free(os_name);
    free(os_version);
    free(os_arch);
    free(client_version);
    free(java_version);
    return response_len;
}

static int build_client_auth_login_response(const char *body, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path != NULL
        && st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) == 0) {
        int db_response = build_database_client_auth_login_response(database_path, body, out, out_len);
        if (db_response != 0) {
            return db_response;
        }
    }
    if (client_api_auth_required()) {
        int auth_rc = validate_client_api_login(body, out, out_len);
        if (auth_rc != 0) {
            return auth_rc;
        }
    }
    return build_client_auth_login_success_response(out, out_len);
}

static int load_visible_tcp_mapping_count(const st_admin_context *context, size_t *mapping_count)
{
    *mapping_count = 0;
    const char *database_path = admin_database_path();
    if (database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            return -1;
        }
        st_storage_client clients[ST_ADMIN_MAX_CLIENTS];
        size_t client_count = 0;
        if (st_storage_list_clients(database_path, clients, ST_ADMIN_MAX_CLIENTS, &client_count) != 0) {
            return -1;
        }
        for (size_t i = 0; i < client_count; ++i) {
            if (!admin_can_access_client(context, &clients[i])) {
                continue;
            }
            st_storage_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
            size_t client_mapping_count = 0;
            if (st_storage_list_mappings(database_path,
                                         clients[i].id,
                                         mappings,
                                         ST_ADMIN_MAX_TCP_MAPPINGS,
                                         &client_mapping_count) != 0) {
                return -1;
            }
            *mapping_count += client_mapping_count;
        }
        return 0;
    }

    st_storage_client client = {0};
    client.id = env_i64("SPECUS_CLIENT_ID", 1);
    snprintf(client.tenant_id, sizeof(client.tenant_id), "%s", env_text("SPECUS_AUTH_TENANT_ID", "default"));
    snprintf(client.client_name, sizeof(client.client_name), "%s", env_text("SPECUS_CLIENT_NAME", "Demo client"));
    snprintf(client.owner_username, sizeof(client.owner_username), "%s", env_text("SPECUS_AUTH_USERNAME", "admin"));
    client.enabled = 1;
    if (!admin_can_access_client(context, &client)) {
        return 0;
    }
    st_admin_tcp_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
    return load_current_tcp_mappings(client.client_name, mappings, mapping_count);
}

static int build_overview_response(const st_admin_context *context, char *out, size_t out_len)
{
    size_t mapping_count = 0;
    if (load_visible_tcp_mapping_count(context, &mapping_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"overview response failed\"}");
    }
    char body[256];
    int written = snprintf(body,
                           sizeof(body),
                           "{\"server\":\"c\",\"status\":\"ok\",\"onlineClients\":0,\"tcpMappings\":%zu}",
                           mapping_count);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"overview response too large\"}");
    }
    return write_response(out, out_len, 200, "OK", body);
}

static int build_metrics_response(const st_admin_context *context, char *out, size_t out_len)
{
    size_t mapping_count = 0;
    if (load_visible_tcp_mapping_count(context, &mapping_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"metrics response failed\"}");
    }
    char body[256];
    int written = snprintf(body,
                           sizeof(body),
                           "{\"server\":\"c\",\"metricsWired\":false,"
                           "\"onlineClients\":0,\"listeners\":%zu,\"externalConnections\":0}",
                           mapping_count);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"metrics response too large\"}");
    }
    return write_response(out, out_len, 200, "OK", body);
}

static const char *admin_database_path(void)
{
    const char *path = getenv("SPECUS_DATABASE_PATH");
    return path != NULL && *path != '\0' ? path : NULL;
}

static int admin_current_utc_date(char out[11])
{
    time_t now = time(NULL);
    struct tm utc;
    if (gmtime_r(&now, &utc) == NULL) {
        return -1;
    }
    return strftime(out, 11U, "%Y-%m-%d", &utc) == 10U ? 0 : -1;
}

static int admin_current_utc_timestamp(char out[64])
{
    time_t now = time(NULL);
    struct tm utc;
    if (gmtime_r(&now, &utc) == NULL) {
        return -1;
    }
    return strftime(out, 64U, "%Y-%m-%dT%H:%M:%SZ", &utc) > 0 ? 0 : -1;
}

static long long admin_now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

static void record_direct_http_traffic(const char *client_name,
                                       const char *route,
                                       long long upload_bytes,
                                       long long download_bytes)
{
    if (client_name == NULL
        || route == NULL
        || (upload_bytes <= 0 && download_bytes <= 0)) {
        return;
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return;
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return;
    }
    st_storage_client client;
    if (st_storage_get_client_by_name(database_path, client_name, &client) != 0 || !client.enabled) {
        return;
    }
    char usage_date[11];
    if (admin_current_utc_date(usage_date) != 0) {
        return;
    }
    st_storage_record_traffic_usage(database_path,
                                    client.id,
                                    client.client_name,
                                    usage_date,
                                    upload_bytes,
                                    download_bytes);

    st_storage_http_route http_route;
    long long resource_id = 0;
    char resource_name[512];
    if (st_storage_get_http_route_by_client_route(database_path, client_name, route, &http_route) == 0) {
        resource_id = http_route.id;
        snprintf(resource_name,
                 sizeof(resource_name),
                 "%.127s -> %.380s",
                 http_route.route,
                 http_route.target_base_url);
    } else {
        snprintf(resource_name, sizeof(resource_name), "%s", route);
    }
    char resource_key[192];
    snprintf(resource_key, sizeof(resource_key), "http:%s", route);
    st_storage_record_resource_traffic_usage(database_path,
                                             client.id,
                                             client.client_name,
                                             "HTTP_ROUTE",
                                             resource_key,
                                             resource_id,
                                             resource_name,
                                             usage_date,
                                             upload_bytes,
                                             download_bytes);
}

static void record_direct_http_exchange(const char *client_name,
                                        const char *route,
                                        const st_direct_http_request *request,
                                        const st_direct_http_response *response,
                                        size_t response_bytes,
                                        const char *remote_address,
                                        long long elapsed_ms)
{
    if (client_name == NULL || route == NULL || request == NULL || response == NULL) {
        return;
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return;
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return;
    }
    st_storage_client client;
    st_storage_http_route http_route;
    if (st_storage_get_client_by_name(database_path, client_name, &client) != 0
        || !client.enabled
        || st_storage_get_http_route_by_client_route(database_path, client_name, route, &http_route) != 0
        || !http_route.detail_capture_enabled) {
        return;
    }
    char captured_at[64];
    if (admin_current_utc_timestamp(captured_at) != 0) {
        return;
    }
    char resource_name[512];
    snprintf(resource_name,
             sizeof(resource_name),
             "%.127s -> %.380s",
             http_route.route,
             http_route.target_base_url);
    char *request_headers = admin_join_headers(request->headers, request->headers_len);
    char *response_headers = admin_join_headers(response->headers, response->headers_len);
    char *request_content_type = admin_header_array_value(request->headers, request->headers_len, "Content-Type");
    char *response_content_type = admin_header_array_value(response->headers, response->headers_len, "Content-Type");
    if (request_headers == NULL || response_headers == NULL) {
        free(request_headers);
        free(response_headers);
        free(request_content_type);
        free(response_content_type);
        return;
    }
    st_storage_http_exchange_record record = {
        .tenant_id = client.tenant_id,
        .client_id = client.id,
        .client_name = client.client_name,
        .route = route,
        .resource_id = http_route.id,
        .resource_name = resource_name,
        .method = request->request_method,
        .relative_path = request->relative_path,
        .raw_query = request->raw_query,
        .status_code = response->status_code,
        .success = response->error == NULL || *response->error == '\0',
        .error = response->error,
        .remote_address = remote_address,
        .request_bytes = (long long)request->body_len,
        .response_bytes = (long long)response_bytes,
        .elapsed_ms = elapsed_ms,
        .request_content_type = request_content_type,
        .response_content_type = response_content_type,
        .response_body_type = NULL,
        .request_headers = request_headers,
        .response_headers = response_headers,
        .request_body = request->body,
        .request_body_len = request->body_len,
        .response_body = response->body,
        .response_body_len = response->body_len,
        .captured_at = captured_at
    };
    (void)st_storage_record_http_exchange(database_path, &record);
    free(request_headers);
    free(response_headers);
    free(request_content_type);
    free(response_content_type);
}

static int ensure_admin_database(const char **path, char *out, size_t out_len)
{
    *path = admin_database_path();
    if (*path == NULL) {
        return write_response(out,
                              out_len,
                              503,
                              "Service Unavailable",
                              "{\"error\":\"SPECUS_DATABASE_PATH is required for C management mutations\"}");
    }
    if (st_storage_init(*path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"database init failed\"}");
    }
    return 0;
}

static int handle_database_initialize(const st_admin_context *context, char *out, size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    long long clients = 0;
    if (st_storage_count_clients_by_tenant(database_path, context->tenant_id, &clients) != 0) {
        return write_response(out,
                              out_len,
                              500,
                              "Internal Server Error",
                              "{\"error\":\"database initialize failed\"}");
    }
    st_admin_string_builder builder = {0};
    int ok = admin_sb_append(&builder, "{\"initialized\":true,\"tenantId\":") == 0
        && admin_sb_append_json_string(&builder, context->tenant_id) == 0
        && admin_sb_appendf(&builder,
                            ",\"orm\":\"sqlite3\",\"dialect\":\"sqlite\",\"clients\":%lld}",
                            clients) == 0;
    if (!ok) {
        free(builder.data);
        return write_response(out,
                              out_len,
                              500,
                              "Internal Server Error",
                              "{\"error\":\"database initialize response failed\"}");
    }
    int response = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response;
}

static int append_client_view(st_admin_string_builder *builder, const st_storage_client *client)
{
    char *client_name = st_json_escape(client->client_name);
    char *owner = st_json_escape(client->owner_username);
    char *created = st_json_escape(client->created_at);
    char *updated = st_json_escape(client->updated_at);
    if (client_name == NULL || owner == NULL || created == NULL || updated == NULL) {
        free(client_name);
        free(owner);
        free(created);
        free(updated);
        return -1;
    }
    st_admin_client_runtime_status status;
    admin_get_client_runtime_status(client->id, client->client_name, &status);
    int online = status.online != 0;
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"clientName\":\"%s\",\"ownerUsername\":\"%s\","
                              "\"enabled\":%s,\"connectionRateLimitPerMinute\":%d,"
                              "\"online\":%s,\"connectedSinceMs\":",
                              client->id,
                              client_name,
                              owner,
                              client->enabled ? "true" : "false",
                              client->connection_rate_limit_per_minute,
                              online ? "true" : "false");
    if (rc == 0) {
        rc = online
            ? admin_sb_appendf(builder, "%lld", status.connected_since_ms)
            : admin_sb_append(builder, "null");
    }
    if (rc == 0) rc = admin_sb_append(builder, ",\"clientVersion\":");
    if (rc == 0) {
        rc = online
            ? admin_sb_append_nullable_json_string(builder, client->client_version)
            : admin_sb_append(builder, "null");
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"messageSendCapable\":%s,\"messageReceiveCapable\":%s,"
                              "\"messageAttachmentsCapable\":%s,\"messageMediaPreviewCapable\":%s,"
                              "\"messageMaxAttachmentBytes\":%lld,"
                              "\"uploadBytes\":%lld,\"downloadBytes\":%lld,"
                              "\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}",
                              online && client->message_send_capable ? "true" : "false",
                              online && client->message_receive_capable ? "true" : "false",
                              online && client->message_attachments_capable ? "true" : "false",
                              online && client->message_media_preview_capable ? "true" : "false",
                              online ? client->message_max_attachment_bytes : 0LL,
                              client->upload_bytes,
                              client->download_bytes,
                              created,
                              updated);
    }
    free(client_name);
    free(owner);
    free(created);
    free(updated);
    return rc;
}

static int append_peer_mesh_device_view(st_admin_string_builder *builder, const st_storage_peer_mesh_device *device)
{
    st_admin_client_runtime_status runtime_status;
    admin_get_client_runtime_status(device->client_id, device->client_name, &runtime_status);
    const char *nat_type = device->nat_type[0] == '\0' ? "UNKNOWN" : device->nat_type;
    const char *device_mode = device->virtual_device_mode[0] == '\0' ? "AUTO" : device->virtual_device_mode;
    const char *device_status = device->virtual_device_status[0] == '\0'
                                    ? "DOWN"
                                    : device->virtual_device_status;
    int rc = admin_sb_appendf(builder, "{\"id\":%lld,\"clientId\":%lld,\"clientName\":", device->id, device->client_id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, device->client_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"ownerUsername\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, device->owner_username);
    if (rc == 0) rc = admin_sb_appendf(builder, ",\"enabled\":%s,\"online\":%s,\"virtualIp\":",
                                       device->enabled ? "true" : "false",
                                       runtime_status.online ? "true" : "false");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->virtual_ip);
    if (rc == 0) rc = admin_sb_append(builder, ",\"cidr\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, device->cidr);
    if (rc == 0) rc = admin_sb_append(builder, ",\"publicKey\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->public_key);
    if (rc == 0) rc = admin_sb_append(builder, ",\"natType\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, nat_type);
    if (rc == 0) rc = admin_sb_append(builder, ",\"natMappingBehavior\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->nat_mapping_behavior);
    if (rc == 0) rc = admin_sb_append(builder, ",\"natFilteringBehavior\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->nat_filtering_behavior);
    if (rc == 0) rc = admin_sb_append(builder, ",\"natBehaviorDiscovery\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->nat_behavior_discovery);
    if (rc == 0) rc = admin_sb_append(builder, ",\"lastEndpoint\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->last_endpoint);
    if (rc == 0) rc = admin_sb_append(builder, ",\"virtualDeviceMode\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, device_mode);
    if (rc == 0) rc = admin_sb_append(builder, ",\"virtualDeviceName\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->virtual_device_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"virtualDeviceStatus\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, device_status);
    if (rc == 0) rc = admin_sb_append(builder, ",\"virtualDeviceError\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->virtual_device_error);
    if (rc == 0) rc = admin_sb_append(builder, ",\"virtualDeviceUpdatedAt\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->virtual_device_updated_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"lastSeenAt\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, device->last_seen_at);
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"messageSendCapable\":%s,\"messageReceiveCapable\":%s,"
                              "\"messageAttachmentsCapable\":%s,\"messageMediaPreviewCapable\":%s,"
                              "\"messageMaxAttachmentBytes\":%lld",
                              runtime_status.online && device->message_send_capable ? "true" : "false",
                              runtime_status.online && device->message_receive_capable ? "true" : "false",
                              runtime_status.online && device->message_attachments_capable ? "true" : "false",
                              runtime_status.online && device->message_media_preview_capable ? "true" : "false",
                              runtime_status.online ? device->message_max_attachment_bytes : 0LL);
    }
    if (rc == 0) rc = admin_sb_append(builder, ",\"updatedAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, device->updated_at);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    return rc;
}

static int append_peer_mesh_acl_view(st_admin_string_builder *builder, const st_storage_peer_mesh_acl *acl)
{
    char *source = st_json_escape(acl->source_client_name);
    char *target = st_json_escape(acl->target_client_name);
    char *created = st_json_escape(acl->created_at);
    char *updated = st_json_escape(acl->updated_at);
    char *direction = st_json_escape(acl->direction);
    if (source == NULL || target == NULL || created == NULL || updated == NULL || direction == NULL) {
        free(source);
        free(target);
        free(created);
        free(updated);
        free(direction);
        return -1;
    }
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"sourceClientId\":%lld,\"sourceClientName\":\"%s\","
                              "\"targetClientId\":%lld,\"targetClientName\":\"%s\","
                              "\"allowed\":%s,\"direction\":\"%s\",\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}",
                              acl->id,
                              acl->source_client_id,
                              source,
                              acl->target_client_id,
                              target,
                              acl->allowed ? "true" : "false",
                              direction,
                              created,
                              updated);
    free(source);
    free(target);
    free(created);
    free(updated);
    free(direction);
    return rc;
}

static int append_peer_mesh_session_view(st_admin_string_builder *builder, const st_storage_peer_mesh_session *session)
{
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"sourceClientId\":%lld,\"sourceClientName\":",
                              session->id,
                              session->source_client_id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->source_client_name);
    if (rc == 0) {
        rc = admin_sb_appendf(builder, ",\"targetClientId\":%lld,\"targetClientName\":", session->target_client_id);
    }
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->target_client_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"pathType\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->path_type);
    if (rc == 0) rc = admin_sb_append(builder, ",\"status\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->status);
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"rttMillis\":");
    }
    if (rc == 0) {
        rc = session->rtt_millis >= 0 ? admin_sb_appendf(builder, "%lld", session->rtt_millis)
                                      : admin_sb_append(builder, "null");
    }
    if (rc == 0) rc = admin_sb_append(builder, ",\"localEndpoint\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, session->local_endpoint);
    if (rc == 0) rc = admin_sb_append(builder, ",\"remoteEndpoint\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, session->remote_endpoint);
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"directBytes\":%lld,\"relayBytes\":%lld,\"lastTrafficAt\":",
                              session->direct_bytes,
                              session->relay_bytes);
    }
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, session->last_traffic_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"startedAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->started_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"updatedAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->updated_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"expiresAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, session->expires_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"closedAt\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, session->closed_at);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    return rc;
}

static int append_credential_view(st_admin_string_builder *builder, const st_storage_client_credential *credential)
{
    char *api_key = st_json_escape(credential->api_key);
    char *owner = st_json_escape(credential->owner_username);
    char *created = st_json_escape(credential->created_at);
    char *updated = st_json_escape(credential->updated_at);
    if (api_key == NULL || owner == NULL || created == NULL || updated == NULL) {
        free(api_key);
        free(owner);
        free(created);
        free(updated);
        return -1;
    }
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"apiKey\":\"%s\",\"ownerUsername\":\"%s\","
                              "\"enabled\":%s,\"maxOnlineInstances\":%d,"
                              "\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}",
                              credential->id,
                              api_key,
                              owner,
                              credential->enabled ? "true" : "false",
                              credential->max_online_instances <= 0
                                  ? client_auth_default_max_online_instances()
                                  : credential->max_online_instances,
                              created,
                              updated);
    free(api_key);
    free(owner);
    free(created);
    free(updated);
    return rc;
}

static int append_client_download_link_view(st_admin_string_builder *builder,
                                            const st_storage_client_download_link *link)
{
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"implementation\":",
                              link->id);
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->implementation);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"platform\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->platform);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"arch\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->arch);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"displayName\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->display_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"downloadUrl\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->download_url);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"description\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, link->description);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"displayOrder\":%d,\"enabled\":%s,\"version\":",
                              link->display_order,
                              link->enabled ? "true" : "false");
    }
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, link->version);
    if (rc == 0) rc = admin_sb_append(builder, ",\"sha256\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, link->sha256);
    if (rc == 0) rc = admin_sb_appendf(builder,
        ",\"fileSize\":%lld,\"isLatest\":%s,\"changelogUrl\":",
        link->file_size, link->is_latest ? "true" : "false");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, link->changelog_url);
    if (rc == 0) rc = admin_sb_append(builder, ",\"minSupportedVersion\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, link->min_supported_version);
    if (rc == 0) rc = admin_sb_appendf(builder,
        ",\"hosted\":%s,\"packageId\":", link->hosted ? "true" : "false");
    if (rc == 0) rc = link->hosted
        ? admin_sb_appendf(builder, "%lld", link->id) : admin_sb_append(builder, "null");
    if (rc == 0) rc = admin_sb_append(builder, ",\"createdAt\":");
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->created_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"updatedAt\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, link->updated_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, "}");
    }
    return rc;
}

static int append_mapping_view(st_admin_string_builder *builder, const st_storage_mapping *mapping)
{
    char *client_name = st_json_escape(mapping->client_name);
    char *target = st_json_escape(mapping->target_address);
    char *created = st_json_escape(mapping->created_at);
    char *updated = st_json_escape(mapping->updated_at);
    if (client_name == NULL || target == NULL || created == NULL || updated == NULL) {
        free(client_name);
        free(target);
        free(created);
        free(updated);
        return -1;
    }
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"clientId\":%lld,\"clientName\":\"%s\","
                              "\"listenPort\":%d,\"targetAddress\":\"%s\",\"targetPort\":%d,"
                              "\"enabled\":%s,\"detailCaptureEnabled\":%s,"
                              "\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}",
                              mapping->id,
                              mapping->client_id,
                              client_name,
                              mapping->listen_port,
                              target,
                              mapping->target_port,
                              mapping->enabled ? "true" : "false",
                              mapping->detail_capture_enabled ? "true" : "false",
                              created,
                              updated);
    free(client_name);
    free(target);
    free(created);
    free(updated);
    return rc;
}

static int append_http_route_view(st_admin_string_builder *builder, const st_storage_http_route *route)
{
    char *client_name = st_json_escape(route->client_name);
    char *route_name = st_json_escape(route->route);
    char *target = st_json_escape(route->target_base_url);
    char *auth_username = st_json_escape(route->auth_username);
    char *created = st_json_escape(route->created_at);
    char *updated = st_json_escape(route->updated_at);
    if (client_name == NULL || route_name == NULL || target == NULL || auth_username == NULL
        || created == NULL || updated == NULL) {
        free(client_name);
        free(route_name);
        free(target);
        free(auth_username);
        free(created);
        free(updated);
        return -1;
    }
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"clientId\":%lld,\"clientName\":\"%s\","
                              "\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"enabled\":%s,"
                              "\"detailCaptureEnabled\":%s,\"mediaCaptureEnabled\":%s,"
                              "\"pathRewriteEnabled\":%s,\"insecureSkipVerify\":%s,"
                              "\"authEnabled\":%s,\"authUsername\":\"%s\",\"authPasswordConfigured\":%s,"
                              "\"createdAt\":\"%s\",\"updatedAt\":\"%s\"}",
                              route->id,
                              route->client_id,
                              client_name,
                              route_name,
                              target,
                              route->enabled ? "true" : "false",
                              route->detail_capture_enabled ? "true" : "false",
                              route->media_capture_enabled ? "true" : "false",
                              route->path_rewrite_enabled ? "true" : "false",
                              route->insecure_skip_verify ? "true" : "false",
                              route->auth_enabled ? "true" : "false",
                              auth_username,
                              route->auth_password_hash[0] != '\0' ? "true" : "false",
                              created,
                              updated);
    free(client_name);
    free(route_name);
    free(target);
    free(auth_username);
    free(created);
    free(updated);
    return rc;
}

static const char *admin_disconnect_reason_text(const char *reason)
{
    if (reason == NULL || *reason == '\0') {
        return NULL;
    }
    if (strcmp(reason, "LOGIN_FAILURE") == 0) {
        return "登录失败";
    }
    if (strcmp(reason, "CLIENT_CLOSED") == 0) {
        return "客户端正常断开";
    }
    if (strcmp(reason, "IO_ERROR") == 0) {
        return "传输异常";
    }
    if (strcmp(reason, "IDLE_TIMEOUT") == 0) {
        return "读空闲超时(60s)";
    }
    if (strcmp(reason, "HEARTBEAT_WRITE_FAILED") == 0) {
        return "心跳发送失败";
    }
    if (strcmp(reason, "PROTOCOL_VIOLATION") == 0) {
        return "协议违规";
    }
    if (strcmp(reason, "REGISTER_FAILED") == 0) {
        return "注册失败";
    }
    if (strcmp(reason, "REPLACED_BY_NEW_LOGIN") == 0) {
        return "被新登录替换";
    }
    if (strcmp(reason, "ADMIN_DISABLED") == 0) {
        return "管理员停用账号";
    }
    if (strcmp(reason, "ADMIN_RENAMED") == 0) {
        return "管理员修改账号名";
    }
    if (strcmp(reason, "ADMIN_DELETED") == 0) {
        return "管理员删除账号";
    }
    if (strcmp(reason, "SERVER_BUSY") == 0) {
        return "服务端繁忙拒绝";
    }
    if (strcmp(reason, "SERVER_SHUTDOWN") == 0) {
        return "服务端优雅停机";
    }
    if (strcmp(reason, "SERVER_RESTARTED") == 0) {
        return "服务端重启时清理";
    }
    return "未知";
}

static int append_connection_view(st_admin_string_builder *builder, const st_storage_connection *connection)
{
    const char *reason_code = connection->disconnect_reason[0] == '\0' ? NULL : connection->disconnect_reason;
    const char *reason_text = admin_disconnect_reason_text(reason_code);
    int rc = admin_sb_append(builder, "{");
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              "\"id\":%lld,\"clientId\":",
                              connection->id);
    }
    if (rc == 0) {
        if (connection->client_id > 0) {
            rc = admin_sb_appendf(builder, "%lld", connection->client_id);
        } else {
            rc = admin_sb_append(builder, "null");
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"clientName\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, connection->client_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"channelId\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, connection->channel_id);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"remoteAddress\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, connection->remote_address);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"connectedAt\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, connection->connected_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"disconnectedAt\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, connection->disconnected_at);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"success\":%s,\"failureReason\":",
                              connection->success ? "true" : "false");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, connection->failure_reason);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"disconnectReason\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, reason_code);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"disconnectReasonText\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, reason_text);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, "}");
    }
    return rc;
}

static int append_connection_stat_view(st_admin_string_builder *builder, const st_storage_connection_stat *stat)
{
    int rc = admin_sb_appendf(builder, "{\"id\":%lld,\"clientId\":", stat->id);
    if (rc == 0) {
        if (stat->client_id > 0) {
            rc = admin_sb_appendf(builder, "%lld", stat->client_id);
        } else {
            rc = admin_sb_append(builder, "null");
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"clientName\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, stat->client_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"month\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, stat->month);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"total\":%lld,\"success\":%lld,\"failure\":%lld,\"updatedAt\":",
                              stat->total,
                              stat->success,
                              stat->failure);
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, stat->updated_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, "}");
    }
    return rc;
}

static int append_traffic_usage_view(st_admin_string_builder *builder, const st_storage_traffic_usage *usage)
{
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"clientId\":%lld,\"clientName\":",
                              usage->id,
                              usage->client_id);
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->client_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"usageDate\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->usage_date);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"uploadBytes\":%lld,\"downloadBytes\":%lld,\"updatedAt\":",
                              usage->upload_bytes,
                              usage->download_bytes);
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, usage->updated_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, "}");
    }
    return rc;
}

static int append_resource_traffic_usage_view(st_admin_string_builder *builder,
                                              const st_storage_resource_traffic_usage *usage)
{
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"clientId\":%lld,\"clientName\":",
                              usage->id,
                              usage->client_id);
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->client_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"resourceType\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->resource_type);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"resourceKey\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->resource_key);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"resourceId\":");
    }
    if (rc == 0) {
        rc = usage->resource_id > 0 ? admin_sb_appendf(builder, "%lld", usage->resource_id)
                                    : admin_sb_append(builder, "null");
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"resourceName\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->resource_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"usageDate\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, usage->usage_date);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"uploadBytes\":%lld,\"downloadBytes\":%lld,\"updatedAt\":",
                              usage->upload_bytes,
                              usage->download_bytes);
    }
    if (rc == 0) {
        rc = admin_sb_append_nullable_json_string(builder, usage->updated_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, "}");
    }
    return rc;
}

static char *admin_base64_encode(const uint8_t *data, size_t len)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((len + 2U) / 3U) * 4U;
    char *out = (char *)malloc(out_len + 1U);
    if (out == NULL) {
        return NULL;
    }
    size_t w = 0;
    for (size_t i = 0; i < len; i += 3U) {
        uint32_t value = (uint32_t)data[i] << 16U;
        int remain = (int)(len - i);
        if (remain > 1) {
            value |= (uint32_t)data[i + 1U] << 8U;
        }
        if (remain > 2) {
            value |= (uint32_t)data[i + 2U];
        }
        out[w++] = table[(value >> 18U) & 0x3fU];
        out[w++] = table[(value >> 12U) & 0x3fU];
        out[w++] = remain > 1 ? table[(value >> 6U) & 0x3fU] : '=';
        out[w++] = remain > 2 ? table[value & 0x3fU] : '=';
    }
    out[w] = '\0';
    return out;
}

static int admin_form_append_pair(st_admin_string_builder *builder, const char *key, const char *value)
{
    static const char hex[] = "0123456789ABCDEF";
    if (key == NULL || value == NULL) {
        return -1;
    }
    if (builder->len > 0 && admin_sb_append(builder, "&") != 0) {
        return -1;
    }
    const char *parts[2] = {key, value};
    for (int part = 0; part < 2; ++part) {
        if (part == 1 && admin_sb_append(builder, "=") != 0) {
            return -1;
        }
        const unsigned char *cursor = (const unsigned char *)parts[part];
        while (*cursor != '\0') {
            unsigned char ch = *cursor++;
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')
                || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.' || ch == '~') {
                char plain[2] = {(char)ch, '\0'};
                if (admin_sb_append(builder, plain) != 0) {
                    return -1;
                }
            } else if (ch == ' ') {
                if (admin_sb_append(builder, "+") != 0) {
                    return -1;
                }
            } else {
                char encoded[4] = {'%', hex[(ch >> 4U) & 0x0fU], hex[ch & 0x0fU], '\0'};
                if (admin_sb_append(builder, encoded) != 0) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int build_oidc_token_proxy_response(const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "{}";
    }
    const char *client_id = getenv("SPECUS_OIDC_CLIENT_ID");
    const char *token_endpoint = getenv("SPECUS_OIDC_TOKEN_ENDPOINT");
    const char *redirect_uri = getenv("SPECUS_OIDC_REDIRECT_URI");
    const char *client_secret = getenv("SPECUS_OIDC_CLIENT_SECRET");
    if (client_id == NULL || *client_id == '\0' || token_endpoint == NULL || *token_endpoint == '\0') {
        return write_response(out,
                              out_len,
                              503,
                              "Service Unavailable",
                              "{\"error\":\"OIDC is not configured: client-id or token-endpoint is missing\"}");
    }
    char *code = st_json_get_string(body, "code");
    char *code_verifier = st_json_get_string(body, "codeVerifier");
    if (code_verifier == NULL) {
        code_verifier = st_json_get_string(body, "code_verifier");
    }
    if (code == NULL || *code == '\0' || code_verifier == NULL || *code_verifier == '\0') {
        free(code);
        free(code_verifier);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"code or code_verifier is required\"}");
    }
    st_admin_string_builder form = {0};
    int rc = admin_form_append_pair(&form, "grant_type", "authorization_code");
    if (rc == 0) rc = admin_form_append_pair(&form, "code", code);
    if (rc == 0) rc = admin_form_append_pair(&form, "redirect_uri", redirect_uri == NULL ? "" : redirect_uri);
    if (rc == 0) rc = admin_form_append_pair(&form, "code_verifier", code_verifier);
    if (rc == 0 && (client_secret == NULL || *client_secret == '\0')) {
        rc = admin_form_append_pair(&form, "client_id", client_id);
    }
    free(code);
    free(code_verifier);
    if (rc != 0 || form.data == NULL) {
        free(form.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"OIDC token request build failed\"}");
    }
    char *authorization = NULL;
    if (client_secret != NULL && *client_secret != '\0') {
        st_admin_string_builder basic = {0};
        if (admin_sb_appendf(&basic, "%s:%s", client_id, client_secret) == 0 && basic.data != NULL) {
            authorization = admin_base64_encode((const uint8_t *)basic.data, basic.len);
        }
        free(basic.data);
        if (authorization == NULL) {
            free(form.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"OIDC authorization build failed\"}");
        }
    }
    long status_code = 0L;
    char *token_body = NULL;
    const char *ca_certificate_path = getenv("SPECUS_OIDC_CA_CERTIFICATE_PATH");
    st_http_client_options http_options = {
        .timeout_ms = 15000L,
        .max_response_bytes = 65536U,
        .ca_certificate_path = ca_certificate_path
    };
    if (st_http_post_form(token_endpoint,
                          authorization,
                          form.data,
                          &http_options,
                          &status_code,
                          &token_body) != 0) {
        free(authorization);
        free(form.data);
        return write_response(out, out_len, 502, "Bad Gateway", "{\"error\":\"cannot connect to OIDC token endpoint\"}");
    }
    free(authorization);
    free(form.data);
    if (status_code / 100 != 2) {
        char *error = st_json_get_string(token_body, "error");
        char *description = st_json_get_string(token_body, "error_description");
        st_admin_string_builder builder = {0};
        rc = admin_sb_append(&builder, "{\"error\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, error == NULL || *error == '\0' ? "token_exchange_failed" : error);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"error_description\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, description == NULL ? "" : description);
        if (rc == 0) rc = admin_sb_append(&builder, "}");
        free(error);
        free(description);
        free(token_body);
        if (rc != 0 || builder.data == NULL) {
            free(builder.data);
            return write_response(out, out_len, 502, "Bad Gateway", "{\"error\":\"token_exchange_failed\",\"error_description\":\"\"}");
        }
        int response_len = write_response(out, out_len, 502, "Bad Gateway", builder.data);
        free(builder.data);
        return response_len;
    }
    char *access_token = st_json_get_string(token_body, "access_token");
    char *id_token = st_json_get_string(token_body, "id_token");
    char *token_type = st_json_get_string(token_body, "token_type");
    int expires_in = 0;
    (void)st_json_get_int(token_body, "expires_in", &expires_in);
    free(token_body);
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "{\"accessToken\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(&builder, access_token);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"idToken\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(&builder, id_token);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"tokenType\":");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, token_type == NULL || *token_type == '\0' ? "Bearer" : token_type);
    if (rc == 0) rc = admin_sb_appendf(&builder, ",\"expiresIn\":%d}", expires_in);
    free(access_token);
    free(id_token);
    free(token_type);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"OIDC token response build failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int append_http_exchange_view(st_admin_string_builder *builder, const st_storage_http_exchange *item)
{
    int rc = admin_sb_appendf(builder,
                              "{\"id\":%lld,\"clientId\":%lld,\"clientName\":",
                              item->id,
                              item->client_id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, item->client_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"route\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, item->route);
    if (rc == 0) rc = admin_sb_append(builder, ",\"resourceId\":");
    if (rc == 0) rc = item->resource_id > 0 ? admin_sb_appendf(builder, "%lld", item->resource_id) : admin_sb_append(builder, "null");
    if (rc == 0) rc = admin_sb_append(builder, ",\"resourceName\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, item->resource_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"method\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, item->method);
    if (rc == 0) rc = admin_sb_append(builder, ",\"relativePath\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, item->relative_path);
    if (rc == 0) rc = admin_sb_append(builder, ",\"rawQuery\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->raw_query);
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"statusCode\":%d,\"success\":%s,\"error\":",
                              item->status_code,
                              item->success ? "true" : "false");
    }
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->error);
    if (rc == 0) rc = admin_sb_append(builder, ",\"remoteAddress\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->remote_address);
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"requestBytes\":%lld,\"responseBytes\":%lld,\"elapsedMs\":%lld,"
                              "\"requestContentType\":",
                              item->request_bytes,
                              item->response_bytes,
                              item->elapsed_ms);
    }
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->request_content_type);
    if (rc == 0) rc = admin_sb_append(builder, ",\"responseContentType\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->response_content_type);
    if (rc == 0) rc = admin_sb_append(builder, ",\"responseBodyType\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->response_body_type);
    if (rc == 0) rc = admin_sb_append(builder, ",\"requestHeaders\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->request_headers);
    if (rc == 0) rc = admin_sb_append(builder, ",\"responseHeaders\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->response_headers);
    if (rc == 0) rc = admin_sb_append(builder, ",\"requestPreviewHex\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->request_preview_hex);
    if (rc == 0) rc = admin_sb_append(builder, ",\"requestPreviewText\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->request_preview_text);
    if (rc == 0) rc = admin_sb_append(builder, ",\"responsePreviewHex\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->response_preview_hex);
    if (rc == 0) rc = admin_sb_append(builder, ",\"responsePreviewText\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, item->response_preview_text);
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"requestTruncated\":%s,\"responseTruncated\":%s,\"capturedAt\":",
                              item->request_truncated ? "true" : "false",
                              item->response_truncated ? "true" : "false");
    }
    if (rc == 0) rc = admin_sb_append_json_string(builder, item->captured_at);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    return rc;
}

static int append_tcp_frame_view(st_admin_string_builder *builder,
                                 const st_storage_tcp_frame *frame,
                                 int include_payload)
{
    char *payload_base64 = NULL;
    if (include_payload && frame->payload_data != NULL && frame->payload_data_len > 0) {
        payload_base64 = admin_base64_encode(frame->payload_data, frame->payload_data_len);
        if (payload_base64 == NULL) {
            return -1;
        }
    }
    int rc = admin_sb_append(builder, "{\"id\":");
    if (rc == 0) {
        char id_text[32];
        snprintf(id_text, sizeof(id_text), "%lld", frame->id);
        rc = admin_sb_append_json_string(builder, id_text);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"clientId\":%lld,\"clientName\":",
                              frame->client_id);
    }
    if (rc == 0) rc = admin_sb_append_json_string(builder, frame->client_name);
    if (rc == 0) {
        rc = admin_sb_appendf(builder, ",\"listenPort\":%d,\"resourceId\":", frame->listen_port);
    }
    if (rc == 0) rc = frame->resource_id > 0 ? admin_sb_appendf(builder, "%lld", frame->resource_id) : admin_sb_append(builder, "null");
    if (rc == 0) rc = admin_sb_append(builder, ",\"resourceName\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, frame->resource_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"channelId\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, frame->channel_id);
    if (rc == 0) rc = admin_sb_append(builder, ",\"direction\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, frame->direction);
    if (rc == 0) rc = admin_sb_append(builder, ",\"remoteAddress\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, frame->remote_address);
    if (rc == 0) rc = admin_sb_append(builder, ",\"sourceAddress\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, frame->source_address);
    if (rc == 0) rc = admin_sb_append(builder, ",\"sourcePort\":");
    if (rc == 0) rc = frame->source_port > 0 ? admin_sb_appendf(builder, "%d", frame->source_port) : admin_sb_append(builder, "null");
    if (rc == 0) rc = admin_sb_append(builder, ",\"destinationAddress\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, frame->destination_address);
    if (rc == 0) rc = admin_sb_append(builder, ",\"destinationPort\":");
    if (rc == 0) rc = frame->destination_port > 0 ? admin_sb_appendf(builder, "%d", frame->destination_port) : admin_sb_append(builder, "null");
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"streamOffset\":%lld,\"streamEndOffset\":%lld,\"frameIndex\":%lld,"
                              "\"payloadBytes\":%lld,\"payloadBase64\":",
                              frame->stream_offset,
                              frame->stream_end_offset,
                              frame->frame_index,
                              frame->payload_bytes);
    }
    if (rc == 0) {
        rc = payload_base64 != NULL ? admin_sb_append_json_string(builder, payload_base64) : admin_sb_append(builder, "null");
    }
    if (rc == 0) rc = admin_sb_append(builder, ",\"payloadPreviewHex\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, frame->payload_preview_hex);
    if (rc == 0) rc = admin_sb_append(builder, ",\"payloadPreviewText\":");
    if (rc == 0) rc = admin_sb_append_nullable_json_string(builder, frame->payload_preview_text);
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"truncated\":%s,\"frameTime\":",
                              frame->truncated ? "true" : "false");
    }
    if (rc == 0) rc = admin_sb_append_json_string(builder, frame->frame_time);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    free(payload_base64);
    return rc;
}

static int admin_can_access_client(const st_admin_context *context, const st_storage_client *client)
{
    if (context == NULL || client == NULL) {
        return 0;
    }
    if (strcmp(client->tenant_id, context->tenant_id) != 0) {
        return 0;
    }
    return context->admin || strcmp(client->owner_username, context->username) == 0;
}

static int admin_can_access_credential(const st_admin_context *context, const st_storage_client_credential *credential)
{
    if (context == NULL || credential == NULL) {
        return 0;
    }
    if (strcmp(credential->tenant_id, context->tenant_id) != 0) {
        return 0;
    }
    return context->admin || strcmp(credential->owner_username, context->username) == 0;
}

static int admin_load_accessible_client(const char *database_path,
                                        const st_admin_context *context,
                                        long long client_id,
                                        st_storage_client *client)
{
    return st_storage_get_client(database_path, client_id, client) == 0
        && admin_can_access_client(context, client);
}

static int admin_load_tenant_client(const char *database_path,
                                    const st_admin_context *context,
                                    long long client_id,
                                    st_storage_client *client)
{
    return st_storage_get_client(database_path, client_id, client) == 0
        && context != NULL
        && strcmp(client->tenant_id, context->tenant_id) == 0;
}

static int build_clients_response(const st_admin_context *context, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client list failed\"}");
        }
        st_storage_client clients[ST_ADMIN_MAX_CLIENTS];
        size_t client_count = 0;
        if (st_storage_list_clients(database_path, clients, ST_ADMIN_MAX_CLIENTS, &client_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client list failed\"}");
        }
        size_t visible_count = 0;
        for (size_t i = 0; rc == 0 && i < client_count; ++i) {
            if (!admin_can_access_client(context, &clients[i])) {
                continue;
            }
            rc = admin_sb_append(&builder, visible_count == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_client_view(&builder, &clients[i]);
            }
            ++visible_count;
        }
    } else if (rc == 0) {
        st_storage_client client = {0};
        client.id = env_i64("SPECUS_CLIENT_ID", 1);
        snprintf(client.tenant_id, sizeof(client.tenant_id), "%s", env_text("SPECUS_AUTH_TENANT_ID", "default"));
        snprintf(client.client_name, sizeof(client.client_name), "%s", env_text("SPECUS_CLIENT_NAME", "Demo client"));
        snprintf(client.owner_username, sizeof(client.owner_username), "%s", env_text("SPECUS_AUTH_USERNAME", "admin"));
        client.enabled = 1;
        client.connection_rate_limit_per_minute = env_int("SPECUS_CLIENT_CONNECTION_LIMIT_PER_MINUTE", 30);
        if (admin_can_access_client(context, &client)) {
            rc = append_client_view(&builder, &client);
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_client_name_availability_response(const st_admin_context *context,
                                                   const char *path,
                                                   char *out,
                                                   size_t out_len)
{
    char *client_name = admin_query_string(path, "clientName");
    if (!admin_text_present(client_name)) {
        free(client_name);
        return write_response(out, out_len, 400, "Bad Request",
                              "{\"error\":\"clientName is required\"}");
    }
    long long exclude_id = 0;
    (void)admin_query_i64(path, "excludeClientId", &exclude_id);
    const char *database_path = admin_database_path();
    st_storage_client excluded;
    if (exclude_id > 0 && (database_path == NULL
        || !admin_load_accessible_client(database_path, context, exclude_id, &excluded))) {
        free(client_name);
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    st_storage_client existing;
    int available = database_path == NULL
        || st_storage_get_client_by_name(database_path, client_name, &existing) != 0
        || (exclude_id > 0 && existing.id == exclude_id);
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"clientName\":") == 0
        && admin_sb_append_json_string(&builder, client_name) == 0
        && admin_sb_appendf(&builder, ",\"available\":%s}", available ? "true" : "false") == 0
        ? 0 : -1;
    free(client_name);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"client availability failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int build_client_detail_response(const st_admin_context *context,
                                        long long client_id,
                                        char *out,
                                        size_t out_len)
{
    const char *database_path = admin_database_path();
    st_storage_client client;
    if (database_path == NULL
        || !admin_load_accessible_client(database_path, context, client_id, &client)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    st_storage_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
    st_storage_http_route routes[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t mapping_count = 0U;
    size_t route_count = 0U;
    if (st_storage_list_mappings(database_path, client_id, mappings,
                                 ST_ADMIN_MAX_TCP_MAPPINGS, &mapping_count) != 0
        || st_storage_list_http_routes(database_path, client_id, routes,
                                       ST_ADMIN_MAX_TCP_MAPPINGS, &route_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"client detail failed\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"client\":");
    if (rc == 0) rc = append_client_view(&builder, &client);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"specusMappings\":[");
    for (size_t i = 0; rc == 0 && i < mapping_count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = append_mapping_view(&builder, &mappings[i]);
    }
    if (rc == 0) rc = admin_sb_append(&builder, "],\"httpRoutes\":[");
    for (size_t i = 0; rc == 0 && i < route_count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = append_http_route_view(&builder, &routes[i]);
    }
    if (rc == 0) rc = admin_sb_append(&builder, "]}");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"client detail failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int build_peer_mesh_devices_response(const st_admin_context *context, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh device list failed\"}");
        }
        st_storage_client clients[ST_ADMIN_MAX_CLIENTS];
        size_t client_count = 0;
        if (st_storage_list_clients(database_path, clients, ST_ADMIN_MAX_CLIENTS, &client_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh device list failed\"}");
        }
        size_t visible_count = 0;
        for (size_t i = 0; rc == 0 && i < client_count; ++i) {
            if (!admin_can_access_client(context, &clients[i])) {
                continue;
            }
            st_storage_peer_mesh_device device;
            if (st_storage_ensure_peer_mesh_device(database_path, &clients[i], &device) != 0) {
                free(builder.data);
                return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh device list failed\"}");
            }
            rc = admin_sb_append(&builder, visible_count == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_peer_mesh_device_view(&builder, &device);
            }
            ++visible_count;
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh device response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_peer_mesh_device_result_response(const st_storage_peer_mesh_device *device,
                                                  int status,
                                                  const char *reason,
                                                  char *out,
                                                  size_t out_len)
{
    st_admin_string_builder builder = {0};
    if (append_peer_mesh_device_view(&builder, device) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh device response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int handle_peer_mesh_device_update(const st_admin_context *context,
                                          long long client_id,
                                          const char *body,
                                          char *out,
                                          size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL || st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"peer mesh device not found\"}");
    }
    st_storage_client client;
    if (!admin_load_accessible_client(database_path, context, client_id, &client)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"peer mesh device not found\"}");
    }
    st_storage_peer_mesh_device existing;
    int enabled = 0;
    if (st_storage_ensure_peer_mesh_device(database_path, &client, &existing) == 0) {
        enabled = existing.enabled;
    }
    (void)st_json_get_bool(body, "enabled", &enabled);
    st_storage_peer_mesh_device updated;
    if (st_storage_update_peer_mesh_device_enabled(database_path, &client, enabled, &updated) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh device update failed\"}");
    }
    admin_notify_peer_mesh_refresh(client.tenant_id);
    return build_peer_mesh_device_result_response(&updated, 200, "OK", out, out_len);
}

static int build_peer_mesh_acls_response(const st_admin_context *context, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh acl list failed\"}");
        }
        st_storage_peer_mesh_acl acls[ST_ADMIN_MAX_PEER_ACLS];
        size_t acl_count = 0;
        if (st_storage_list_peer_mesh_acls_visible(database_path,
                                                   context->tenant_id,
                                                   context->username,
                                                   context->admin,
                                                   acls,
                                                   ST_ADMIN_MAX_PEER_ACLS,
                                                   &acl_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh acl list failed\"}");
        }
        for (size_t i = 0; rc == 0 && i < acl_count; ++i) {
            rc = admin_sb_append(&builder, i == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_peer_mesh_acl_view(&builder, &acls[i]);
            }
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh acl response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_peer_mesh_sessions_array_response(const st_storage_peer_mesh_session *sessions,
                                                   size_t session_count,
                                                   int status,
                                                   const char *reason,
                                                   char *out,
                                                   size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < session_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_peer_mesh_session_view(&builder, &sessions[i]);
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh session response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int build_peer_mesh_sessions_response(const st_admin_context *context,
                                             const char *path,
                                             char *out,
                                             size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 200, "OK", "[]");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh session list failed\"}");
    }
    int limit = 100;
    (void)admin_query_int_any(path, "limit", &limit);
    st_storage_peer_mesh_session sessions[ST_ADMIN_MAX_PEER_SESSIONS];
    size_t session_count = 0;
    if (st_storage_list_peer_mesh_sessions_visible(database_path,
                                                   context->tenant_id,
                                                   context->username,
                                                   context->admin,
                                                   1,
                                                   limit,
                                                   sessions,
                                                   ST_ADMIN_MAX_PEER_SESSIONS,
                                                   &session_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh session list failed\"}");
    }
    return build_peer_mesh_sessions_array_response(sessions, session_count, 200, "OK", out, out_len);
}

static int build_peer_mesh_session_response(const st_storage_peer_mesh_session *session,
                                            int status,
                                            const char *reason,
                                            char *out,
                                            size_t out_len)
{
    st_admin_string_builder builder = {0};
    if (append_peer_mesh_session_view(&builder, session) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh session response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int handle_peer_mesh_session_close(const st_admin_context *context,
                                          long long id,
                                          char *out,
                                          size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL || st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"peer mesh session not found\"}");
    }
    st_storage_peer_mesh_session session;
    if (st_storage_close_peer_mesh_session_visible(database_path,
                                                   id,
                                                   context->tenant_id,
                                                   context->username,
                                                   context->admin,
                                                   &session) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"peer mesh session not found\"}");
    }
    return build_peer_mesh_session_response(&session, 200, "OK", out, out_len);
}

static int handle_peer_mesh_sessions_close_open(const st_admin_context *context, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 200, "OK", "[]");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh session close failed\"}");
    }
    st_storage_peer_mesh_session sessions[ST_ADMIN_MAX_PEER_SESSIONS];
    size_t session_count = 0;
    if (st_storage_close_open_peer_mesh_sessions_visible(database_path,
                                                         context->tenant_id,
                                                         context->username,
                                                         context->admin,
                                                         sessions,
                                                         ST_ADMIN_MAX_PEER_SESSIONS,
                                                         &session_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh session close failed\"}");
    }
    return build_peer_mesh_sessions_array_response(sessions, session_count, 200, "OK", out, out_len);
}

static int build_peer_mesh_stats_response(const st_admin_context *context, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    st_storage_peer_mesh_session sessions[ST_ADMIN_MAX_PEER_SESSIONS];
    size_t count = 0U;
    if (database_path != NULL
        && st_storage_list_peer_mesh_sessions_visible(database_path, context->tenant_id,
            context->username, context->admin, 1, ST_ADMIN_MAX_PEER_SESSIONS,
            sessions, ST_ADMIN_MAX_PEER_SESSIONS, &count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh stats failed\"}");
    }
    long long reported = 0, active = 0, direct = 0, relay = 0;
    long long direct_bytes = 0, relay_bytes = 0;
    for (size_t i = 0; i < count; ++i) {
        int is_reported = sessions[i].rtt_millis >= 0 || sessions[i].local_endpoint[0] != '\0'
            || sessions[i].remote_endpoint[0] != '\0' || sessions[i].last_traffic_at[0] != '\0';
        if (is_reported) ++reported;
        if (strcmp(sessions[i].status, "ACTIVE") == 0) {
            ++active;
            if (strcmp(sessions[i].path_type, "RELAY") == 0) ++relay;
            else if (strcmp(sessions[i].path_type, "DIRECT") == 0) ++direct;
        }
        direct_bytes += sessions[i].direct_bytes;
        relay_bytes += sessions[i].relay_bytes;
    }
    char body[4096];
    int written = snprintf(body, sizeof(body),
        "{\"totalSessions\":%zu,\"reportedSessions\":%lld,\"activeSessions\":%lld,"
        "\"activeDirectSessions\":%lld,\"activeRelaySessions\":%lld,\"activeDirectRatio\":%s,"
        "\"pathTypes\":[{\"pathType\":\"DIRECT\",\"status\":\"ACTIVE\",\"sessions\":%lld,"
        "\"reportedSessions\":%lld,\"avgRttMillis\":null,\"directBytes\":%lld,\"relayBytes\":0},"
        "{\"pathType\":\"RELAY\",\"status\":\"ACTIVE\",\"sessions\":%lld,"
        "\"reportedSessions\":%lld,\"avgRttMillis\":null,\"directBytes\":0,\"relayBytes\":%lld}],"
        "\"addressFamilies\":[],\"natTypes\":[],\"natBehaviorDevices\":0,"
        "\"natBehaviorClassifiedDevices\":0,\"natBehaviorSuccessRatio\":null,"
        "\"natMappingBehaviors\":[],\"natFilteringBehaviors\":[],\"natBehaviorDiscoveries\":[]}",
        count, reported, active, direct, relay, active > 0 ? "0" : "null",
        direct, direct, direct_bytes, relay, relay, relay_bytes);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh stats failed\"}");
    }
    if (active > 0) {
        char ratio[32];
        snprintf(ratio, sizeof(ratio), "%.6f", (double)direct / (double)active);
        char *placeholder = strstr(body, "\"activeDirectRatio\":0,");
        if (placeholder != NULL) {
            size_t prefix = (size_t)(placeholder - body) + strlen("\"activeDirectRatio\":");
            char rebuilt[4096];
            snprintf(rebuilt, sizeof(rebuilt), "%.*s%s%s", (int)prefix, body, ratio,
                     placeholder + strlen("\"activeDirectRatio\":0"));
            snprintf(body, sizeof(body), "%s", rebuilt);
        }
    }
    return write_response(out, out_len, 200, "OK", body);
}

static int append_peer_mesh_service_view(st_admin_string_builder *builder,
                                         const st_storage_peer_mesh_service *service,
                                         int include_target)
{
    int rc = admin_sb_appendf(builder, "{\"id\":%lld,\"serviceId\":", service->id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->service_id);
    if (rc == 0) rc = admin_sb_appendf(builder, ",\"clientId\":%lld,\"clientName\":", service->client_id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->client_name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"name\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->name);
    if (rc == 0) rc = admin_sb_append(builder, ",\"description\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->description);
    if (rc == 0) rc = admin_sb_append(builder, ",\"transport\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->transport);
    if (rc == 0) rc = admin_sb_append(builder, ",\"application\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->application);
    if (rc == 0) rc = admin_sb_append(builder, ",\"targetHost\":");
    if (rc == 0) rc = include_target
        ? admin_sb_append_json_string(builder, service->target_host) : admin_sb_append(builder, "null");
    if (rc == 0) rc = admin_sb_appendf(builder,
        ",\"targetPort\":%d,\"publishedPort\":%d,\"path\":",
        include_target ? service->target_port : 0, service->published_port);
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->path);
    if (rc == 0) rc = admin_sb_appendf(builder, ",\"enabled\":%s,\"visibility\":",
                                       service->enabled ? "true" : "false");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->visibility);
    if (rc == 0) rc = admin_sb_append(builder, ",\"allowedClientIds\":[");
    if (rc == 0 && service->allowed_client_ids[0] != '\0') {
        char copy[sizeof(service->allowed_client_ids)];
        snprintf(copy, sizeof(copy), "%s", service->allowed_client_ids);
        char *save = NULL;
        int first = 1;
        for (char *part = strtok_r(copy, ",", &save); part != NULL; part = strtok_r(NULL, ",", &save)) {
            char *end = NULL;
            long long id = strtoll(part, &end, 10);
            if (end != part && *end == '\0' && id > 0) {
                if (admin_sb_appendf(builder, "%s%lld", first ? "" : ",", id) != 0) { rc = -1; break; }
                first = 0;
            }
        }
    }
    if (rc == 0) rc = admin_sb_append(builder, "],\"publishedAddress\":");
    st_storage_peer_mesh_device device;
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL
        && st_storage_get_peer_mesh_device_by_client(database_path, service->tenant_id,
                                                     service->client_id, &device) == 0
        && device.virtual_ip[0] != '\0') {
        char published_address[320];
        snprintf(published_address, sizeof(published_address), "%s:%d",
                 device.virtual_ip, service->published_port);
        rc = admin_sb_append_json_string(builder, published_address);
    } else if (rc == 0) {
        rc = admin_sb_append(builder, "null");
    }
    if (rc == 0) rc = admin_sb_append(builder, ",\"instances\":[");
    st_peer_mesh_service_instance instances[64];
    size_t instance_count = 0U;
    if (rc == 0 && st_peer_mesh_list_service_instances(service->tenant_id, service->client_id,
            service->service_id, instances, 64U, &instance_count) != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < instance_count; ++i) {
        st_peer_mesh_service_instance *instance = &instances[i];
        if (i > 0) rc = admin_sb_append(builder, ",");
        if (rc == 0) rc = admin_sb_appendf(builder,
            "{\"publisherSessionId\":%lld,\"instanceId\":", instance->publisher_session_id);
        if (rc == 0) rc = admin_sb_append_json_string(builder, instance->instance_id);
        if (rc == 0) rc = admin_sb_appendf(builder,
            ",\"online\":%s,\"advertised\":%s,\"revision\":%lld,\"lastReportedAt\":",
            instance->online ? "true" : "false", instance->advertised ? "true" : "false",
            instance->revision);
        if (rc == 0) rc = admin_sb_append_json_string(builder, instance->last_reported_at);
        if (rc == 0) rc = admin_sb_append(builder, ",\"expiresAt\":");
        if (rc == 0) rc = admin_sb_append_json_string(builder, instance->expires_at);
        if (rc == 0) rc = admin_sb_append(builder, ",\"service\":");
        if (rc == 0 && instance->advertised) {
            rc = admin_sb_append(builder, "{\"serviceId\":");
            if (rc == 0) rc = admin_sb_append_json_string(builder, service->service_id);
            if (rc == 0) rc = admin_sb_append(builder, ",\"name\":");
            if (rc == 0) rc = admin_sb_append_json_string(builder, service->name);
            if (rc == 0) rc = admin_sb_append(builder, ",\"description\":");
            if (rc == 0) rc = admin_sb_append_json_string(builder, service->description);
            if (rc == 0) rc = admin_sb_append(builder, ",\"transport\":");
            if (rc == 0) rc = admin_sb_append_json_string(builder, service->transport);
            if (rc == 0) rc = admin_sb_append(builder, ",\"application\":");
            if (rc == 0) rc = admin_sb_append_json_string(builder, service->application);
            if (rc == 0) rc = admin_sb_appendf(builder, ",\"publishedPort\":%d,\"path\":",
                                               service->published_port);
            if (rc == 0) rc = admin_sb_append_json_string(builder, service->path);
            if (rc == 0) rc = admin_sb_append(builder, "}");
        } else if (rc == 0) {
            rc = admin_sb_append(builder, "null");
        }
        if (rc == 0) rc = admin_sb_appendf(builder,
            ",\"bytesIn\":%lld,\"bytesOut\":%lld,\"activeConnections\":%d,"
            "\"totalConnections\":%lld}", instance->bytes_in, instance->bytes_out,
            instance->active_connections, instance->total_connections);
    }
    if (rc == 0) rc = admin_sb_append(builder, "],\"createdAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->created_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"updatedAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, service->updated_at);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    return rc;
}

static int admin_egress_id_listed(const char *csv, long long client_id)
{
    if (csv == NULL || *csv == '\0') return 0;
    char copy[512];
    snprintf(copy, sizeof(copy), "%s", csv);
    char *save = NULL;
    for (char *part = strtok_r(copy, ",", &save); part != NULL; part = strtok_r(NULL, ",", &save)) {
        char *end = NULL;
        long long value = strtoll(part, &end, 10);
        if (end != part && *end == '\0' && value == client_id) return 1;
    }
    return 0;
}

/*
 * Egress authorization management.
 *
 * effectiveConsumerClientIds is the configured allowlist already intersected with the base Peer
 * ACL, so an operator sees which devices the policy actually grants rather than which ones it
 * names.
 */
static int append_peer_mesh_egress_policy_view(st_admin_string_builder *builder,
                                               const char *database_path,
                                               const st_storage_peer_mesh_egress_policy *policy)
{
    st_storage_client clients[512];
    size_t client_count = 0U;
    (void)st_storage_list_clients(database_path, clients, 512U, &client_count);

    int rc = admin_sb_appendf(builder,
        "{\"id\":%lld,\"egressClientId\":%lld,\"egressClientName\":",
        policy->id, policy->egress_client_id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, policy->egress_client_name);
    if (rc == 0) rc = admin_sb_appendf(builder, ",\"enabled\":%s,\"scope\":",
                                       policy->enabled ? "true" : "false");
    if (rc == 0) rc = admin_sb_append_json_string(builder, policy->scope);
    if (rc == 0) rc = admin_sb_append(builder, ",\"allowedConsumerClientIds\":[");
    if (rc == 0 && policy->allowed_consumer_client_ids[0] != '\0') {
        char copy[sizeof(policy->allowed_consumer_client_ids)];
        snprintf(copy, sizeof(copy), "%s", policy->allowed_consumer_client_ids);
        char *save = NULL;
        int first = 1;
        for (char *part = strtok_r(copy, ",", &save); rc == 0 && part != NULL;
             part = strtok_r(NULL, ",", &save)) {
            char *end = NULL;
            long long value = strtoll(part, &end, 10);
            if (end == part || *end != '\0' || value <= 0) continue;
            rc = admin_sb_appendf(builder, "%s%lld", first ? "" : ",", value);
            first = 0;
        }
    }
    if (rc == 0) rc = admin_sb_append(builder, "],\"effectiveConsumerClientIds\":[");
    if (rc == 0) {
        const st_storage_client *egress = NULL;
        for (size_t i = 0; i < client_count; ++i) {
            if (clients[i].id == policy->egress_client_id) { egress = &clients[i]; break; }
        }
        int first = 1;
        for (size_t i = 0; rc == 0 && egress != NULL && i < client_count; ++i) {
            int allowed = 0;
            if (clients[i].id == egress->id
                || strcmp(clients[i].tenant_id, egress->tenant_id) != 0
                || !policy->enabled
                || !admin_egress_id_listed(policy->allowed_consumer_client_ids, clients[i].id)
                || st_storage_can_peer(database_path, &clients[i], egress, &allowed) != 0
                || !allowed) continue;
            rc = admin_sb_appendf(builder, "%s%lld", first ? "" : ",", clients[i].id);
            first = 0;
        }
    }
    if (rc == 0) rc = admin_sb_append(builder, "],\"destinationRules\":");
    if (rc == 0) {
        const char *stored = policy->destination_rules[0] == '\0' ? "[]" : policy->destination_rules;
        rc = admin_sb_append(builder, stored);
    }
    if (rc == 0) rc = admin_sb_appendf(builder,
        ",\"maxConcurrentFlows\":%d,\"maxFlowsPerConsumer\":%d,\"idleTimeoutSeconds\":%d,\"createdAt\":",
        policy->max_concurrent_flows, policy->max_flows_per_consumer, policy->idle_timeout_seconds);
    if (rc == 0) rc = admin_sb_append_json_string(builder, policy->created_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"updatedAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, policy->updated_at);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    return rc;
}

static int build_peer_mesh_egress_policies_response(const st_admin_context *context,
                                                    char *out,
                                                    size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) return write_response(out, out_len, 200, "OK", "[]");
    st_storage_peer_mesh_egress_policy policies[128];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_egress_policies(database_path, context->tenant_id, 0,
                                                  policies, 128U, &count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"egress policy list failed\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = append_peer_mesh_egress_policy_view(&builder, database_path, &policies[i]);
    }
    if (rc == 0) rc = admin_sb_append(&builder, "]");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"egress policy response failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

/* Serialises the destination allowlist for storage, rejecting anything the column cannot hold. */
static int admin_encode_egress_destination_rules(const char *raw, char *out, size_t out_len)
{
    st_egress_destination_rule rules[ST_EGRESS_MAX_DESTINATION_RULES];
    size_t rules_len = 0U;
    if (raw == NULL || *raw == '\0') {
        snprintf(out, out_len, "[]");
        return 0;
    }
    if (st_egress_parse_destination_rules(raw, rules, ST_EGRESS_MAX_DESTINATION_RULES, &rules_len) != 0) {
        return 1;
    }
    char *encoded = st_egress_encode_destination_rules(rules, rules_len);
    if (encoded == NULL) return 1;
    int rc = strlen(encoded) < out_len ? 0 : 1;
    if (rc == 0) snprintf(out, out_len, "%s", encoded);
    free(encoded);
    return rc;
}

static int handle_peer_mesh_egress_policy_mutation(const st_admin_context *context,
                                                   const char *body,
                                                   char *out,
                                                   size_t out_len)
{
    if (!context->admin) {
        return write_response(out, out_len, 403, "Forbidden",
                              "{\"error\":\"只有租户 ADMIN 可以管理出口授权\"}");
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 409, "Conflict",
                              "{\"error\":\"database-backed egress policies are unavailable\"}");
    }
    long long egress_client_id = 0;
    if (st_json_get_i64(body, "egressClientId", &egress_client_id) != 0 || egress_client_id <= 0) {
        return write_response(out, out_len, 400, "Bad Request",
                              "{\"error\":\"egressClientId is required\"}");
    }
    st_storage_client egress;
    if (st_storage_get_client(database_path, egress_client_id, &egress) != 0
        || strcmp(egress.tenant_id, context->tenant_id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }

    st_storage_peer_mesh_egress_policy policy;
    memset(&policy, 0, sizeof(policy));
    int found = st_storage_find_peer_mesh_egress_policy_by_client(database_path, context->tenant_id,
                                                                   egress_client_id, &policy);
    if (found < 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"egress policy lookup failed\"}");
    }
    if (found != 0) {
        memset(&policy, 0, sizeof(policy));
        snprintf(policy.scope, sizeof(policy.scope), "%s", ST_EGRESS_SCOPE_PUBLIC);
        snprintf(policy.destination_rules, sizeof(policy.destination_rules), "[]");
        policy.max_concurrent_flows = 256;
        policy.max_flows_per_consumer = 64;
        policy.idle_timeout_seconds = 60;
    }
    snprintf(policy.tenant_id, sizeof(policy.tenant_id), "%s", context->tenant_id);
    snprintf(policy.owner_username, sizeof(policy.owner_username), "%s", context->username);
    policy.egress_client_id = egress.id;
    snprintf(policy.egress_client_name, sizeof(policy.egress_client_name), "%s", egress.client_name);

    int enabled = 0;
    if (st_json_get_bool(body, "enabled", &enabled) == 0) policy.enabled = enabled;

    char *scope = st_json_get_string(body, "scope");
    if (scope != NULL) {
        for (char *p = scope; *p != '\0'; ++p) *p = (char)toupper((unsigned char)*p);
        if (strcmp(scope, ST_EGRESS_SCOPE_PUBLIC) != 0 && strcmp(scope, ST_EGRESS_SCOPE_LAN) != 0) {
            free(scope);
            return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid scope\"}");
        }
        snprintf(policy.scope, sizeof(policy.scope), "%s", scope);
        free(scope);
    }

    char **consumers = NULL;
    size_t consumer_count = 0U;
    if (st_json_get_raw_array(body, "allowedConsumerClientIds", &consumers, &consumer_count) == 0) {
        if (consumer_count > ST_EGRESS_MAX_CONSUMERS) {
            st_json_free_string_array(consumers, consumer_count);
            return write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"at most 32 allowedConsumerClientIds\"}");
        }
        size_t offset = 0U;
        policy.allowed_consumer_client_ids[0] = '\0';
        for (size_t i = 0; i < consumer_count; ++i) {
            char *end = NULL;
            long long value = strtoll(consumers[i], &end, 10);
            if (end == consumers[i] || *end != '\0' || value <= 0) continue;
            int written = snprintf(policy.allowed_consumer_client_ids + offset,
                                   sizeof(policy.allowed_consumer_client_ids) - offset,
                                   "%s%lld", offset == 0U ? "" : ",", value);
            if (written < 0
                || (size_t)written >= sizeof(policy.allowed_consumer_client_ids) - offset) break;
            offset += (size_t)written;
        }
        st_json_free_string_array(consumers, consumer_count);
    }

    char *rules_raw = st_json_get_top_level_raw(body, "destinationRules");
    if (rules_raw != NULL) {
        int rc = admin_encode_egress_destination_rules(rules_raw, policy.destination_rules,
                                                       sizeof(policy.destination_rules));
        free(rules_raw);
        if (rc != 0) {
            return write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"destinationRules exceed the storage limit\"}");
        }
    }

    int value = 0;
    if (st_json_get_int(body, "maxConcurrentFlows", &value) == 0) {
        if (value <= 0) return write_response(out, out_len, 400, "Bad Request",
                                              "{\"error\":\"maxConcurrentFlows must be positive\"}");
        policy.max_concurrent_flows = value;
    }
    if (st_json_get_int(body, "maxFlowsPerConsumer", &value) == 0) {
        if (value <= 0) return write_response(out, out_len, 400, "Bad Request",
                                              "{\"error\":\"maxFlowsPerConsumer must be positive\"}");
        policy.max_flows_per_consumer = value;
    }
    if (st_json_get_int(body, "idleTimeoutSeconds", &value) == 0) {
        if (value <= 0) return write_response(out, out_len, 400, "Bad Request",
                                              "{\"error\":\"idleTimeoutSeconds must be positive\"}");
        policy.idle_timeout_seconds = value;
    }

    st_storage_peer_mesh_egress_policy saved;
    if (st_storage_upsert_peer_mesh_egress_policy(database_path, &policy, &saved) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"egress policy save failed\"}");
    }
    /* Revoking or narrowing a grant has to take effect now, not at the next login. */
    admin_notify_peer_mesh_refresh(saved.tenant_id);

    st_admin_string_builder builder = {0};
    int rc = append_peer_mesh_egress_policy_view(&builder, database_path, &saved);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"egress policy response failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int handle_peer_mesh_egress_policy_delete(const st_admin_context *context,
                                                 long long id,
                                                 char *out,
                                                 size_t out_len)
{
    if (!context->admin) {
        return write_response(out, out_len, 403, "Forbidden",
                              "{\"error\":\"只有租户 ADMIN 可以管理出口授权\"}");
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 409, "Conflict",
                              "{\"error\":\"database-backed egress policies are unavailable\"}");
    }
    st_storage_peer_mesh_egress_policy policy;
    int found = st_storage_get_peer_mesh_egress_policy(database_path, id, context->tenant_id, &policy);
    if (found != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"egress policy not found\"}");
    }
    if (st_storage_delete_peer_mesh_egress_policy(database_path, id, context->tenant_id) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"egress policy delete failed\"}");
    }
    admin_notify_peer_mesh_refresh(policy.tenant_id);
    return write_response(out, out_len, 200, "OK", "{}");
}

static int build_peer_mesh_services_response(const st_admin_context *context, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) return write_response(out, out_len, 200, "OK", "[]");
    st_storage_peer_mesh_service services[256];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_services_visible(database_path, context->tenant_id,
            context->username, context->admin, services, 256, &count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service list failed\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = append_peer_mesh_service_view(&builder, &services[i], context->admin);
    }
    if (rc == 0) rc = admin_sb_append(&builder, "]");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service response failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int build_peer_mesh_sharing_response(const st_admin_context *context, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    st_storage_peer_mesh_service_sharing sharing = {0};
    int found = database_path == NULL ? 1
        : st_storage_get_peer_mesh_service_sharing(database_path, context->tenant_id, &sharing);
    if (found < 0) return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer sharing status failed\"}");
    st_storage_peer_mesh_service services[256];
    size_t count = 0U;
    long long enabled_count = 0;
    if (database_path != NULL
        && st_storage_list_peer_mesh_services_visible(database_path, context->tenant_id,
            context->username, 1, services, 256, &count) == 0) {
        for (size_t i = 0; i < count; ++i) if (services[i].enabled) ++enabled_count;
    }
    int deployment = env_bool("SPECUS_PEER_MESH_ENABLED", 0);
    st_admin_string_builder builder = {0};
    int rc = admin_sb_appendf(&builder,
        "{\"deploymentEnabled\":%s,\"configuredEnabled\":%s,\"effectiveEnabled\":%s,"
        "\"peerServiceDiscoveryVersion\":2,\"supportedApplications\":[\"http\",\"https\",\"ssh\",\"tcp\",\"udp\"],"
        "\"enabledServiceCount\":%lld,\"updatedAt\":",
        deployment ? "true" : "false", sharing.enabled ? "true" : "false",
        deployment && sharing.enabled ? "true" : "false", enabled_count);
    if (rc == 0) rc = found == 0 ? admin_sb_append_json_string(&builder, sharing.updated_at) : admin_sb_append(&builder, "null");
    if (rc == 0) rc = admin_sb_append(&builder, ",\"updatedBy\":");
    if (rc == 0) rc = found == 0 && sharing.updated_by[0] != '\0'
        ? admin_sb_append_json_string(&builder, sharing.updated_by) : admin_sb_append(&builder, "null");
    if (rc == 0) rc = admin_sb_appendf(&builder, ",\"mdnsImportEnabled\":%s}",
                                       sharing.mdns_import_enabled ? "true" : "false");
    if (rc != 0 || builder.data == NULL) { free(builder.data); return -1; }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int handle_peer_mesh_sharing_update(const st_admin_context *context,
                                           const char *body,
                                           char *out,
                                           size_t out_len)
{
    if (!context->admin) return write_response(out, out_len, 403, "Forbidden", "{\"error\":\"只有管理员可以修改 Peer 服务共享\"}");
    int enabled = 0, mdns = 0;
    int has_enabled = st_json_get_bool(body, "enabled", &enabled) == 0;
    int has_mdns = st_json_get_bool(body, "mdnsImportEnabled", &mdns) == 0;
    if (!has_enabled && !has_mdns) return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"enabled or mdnsImportEnabled is required\"}");
    if (has_enabled && enabled && !env_bool("SPECUS_PEER_MESH_ENABLED", 0)) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"部署端未启用 Peer Mesh，不能开启服务共享\"}");
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"database-backed peer sharing is unavailable\"}");
    }
    st_storage_peer_mesh_service_sharing current = {0};
    (void)st_storage_get_peer_mesh_service_sharing(database_path, context->tenant_id, &current);
    if (st_storage_upsert_peer_mesh_service_sharing(database_path, context->tenant_id,
            has_enabled ? enabled : current.enabled, has_mdns ? mdns : current.mdns_import_enabled,
            context->username, NULL) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer sharing update failed\"}");
    }
    (void)st_storage_record_peer_mesh_service_audit(database_path, "sharing-toggle",
        context->tenant_id, 0, 0, NULL,
        has_enabled && enabled ? "enabled" : "updated");
    admin_notify_peer_mesh_refresh(context->tenant_id);
    return build_peer_mesh_sharing_response(context, out, out_len);
}

static int peer_service_string_valid(const char *value, size_t min_len, size_t max_len)
{
    size_t len = value == NULL ? 0U : strlen(value);
    return len >= min_len && len <= max_len;
}

static int peer_service_id_valid(const char *value)
{
    if (!peer_service_string_valid(value, 8U, 64U)) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isalnum(*p) && *p != '.' && *p != '_' && *p != '-') return 0;
    }
    return 1;
}

static int peer_service_allowed_ids(const char *body, char out[512], int preserve_missing)
{
    char **items = NULL;
    size_t count = 0U;
    if (st_json_get_raw_array(body, "allowedClientIds", &items, &count) != 0) {
        return preserve_missing ? 1 : 0;
    }
    if (count > 32U) { st_json_free_string_array(items, count); return -1; }
    out[0] = '\0';
    size_t offset = 0U;
    long long unique_ids[32];
    size_t unique_count = 0U;
    for (size_t i = 0; i < count; ++i) {
        char *end = NULL;
        long long id = strtoll(items[i], &end, 10);
        if (end == items[i] || *end != '\0' || id <= 0) continue;
        int duplicate = 0;
        for (size_t j = 0; j < unique_count; ++j) if (unique_ids[j] == id) duplicate = 1;
        if (duplicate) continue;
        unique_ids[unique_count++] = id;
        int written = snprintf(out + offset, 512U - offset, "%s%lld", offset == 0U ? "" : ",", id);
        if (written < 0 || (size_t)written >= 512U - offset) { st_json_free_string_array(items, count); return -1; }
        offset += (size_t)written;
    }
    st_json_free_string_array(items, count);
    return 0;
}

static int handle_peer_mesh_service_mutation(const st_admin_context *context,
                                             long long id,
                                             const char *body,
                                             char *out,
                                             size_t out_len)
{
    if (!context->admin) return write_response(out, out_len, 403, "Forbidden", "{\"error\":\"只有管理员可以修改 Peer 服务共享\"}");
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"database-backed peer services are unavailable\"}");
    }
    int creating = id <= 0;
    st_storage_peer_mesh_service service;
    memset(&service, 0, sizeof(service));
    if (!creating) {
        int found = st_storage_get_peer_mesh_service_visible(database_path, id, context->tenant_id,
                                                              context->username, 1, &service);
        if (found != 0) return write_response(out, out_len, 404, "Not Found", "{\"error\":\"service not found\"}");
    } else {
        long long client_id = 0;
        if (st_json_get_i64(body, "clientId", &client_id) != 0 || client_id <= 0) {
            return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"clientId is required\"}");
        }
        st_storage_client client;
        if (st_storage_get_client(database_path, client_id, &client) != 0
            || strcmp(client.tenant_id, context->tenant_id) != 0) {
            return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
        }
        service.client_id = client.id;
        snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", client.tenant_id);
        snprintf(service.client_name, sizeof(service.client_name), "%s", client.client_name);
        snprintf(service.visibility, sizeof(service.visibility), "OWNER");
    }
    char *service_id = st_json_get_string(body, "serviceId");
    char *name = st_json_get_string(body, "name");
    char *description = st_json_get_string(body, "description");
    char *transport = st_json_get_string(body, "transport");
    char *application = st_json_get_string(body, "application");
    char *target_host = st_json_get_string(body, "targetHost");
    char *path = st_json_get_string(body, "path");
    char *visibility = st_json_get_string(body, "visibility");
    if (creating) {
        if (service_id == NULL) snprintf(service.service_id, sizeof(service.service_id),
                                         "svc-%lld-%lld", service.client_id, current_time_millis());
        else snprintf(service.service_id, sizeof(service.service_id), "%s", service_id);
    }
    if (name != NULL) snprintf(service.name, sizeof(service.name), "%s", name);
    if (description != NULL) snprintf(service.description, sizeof(service.description), "%s", description);
    if (application != NULL) snprintf(service.application, sizeof(service.application), "%s", application);
    if (transport != NULL) snprintf(service.transport, sizeof(service.transport), "%s", transport);
    if (target_host != NULL) snprintf(service.target_host, sizeof(service.target_host), "%s",
                                      strcmp(target_host, "localhost") == 0 ? "127.0.0.1" : target_host);
    if (path != NULL) snprintf(service.path, sizeof(service.path), "%s", path);
    if (visibility != NULL) snprintf(service.visibility, sizeof(service.visibility), "%s",
                                     strcmp(visibility, "ACL") == 0 ? "ACL" : "OWNER");
    if (creating && service.path[0] == '\0'
        && (strcmp(service.application, "http") == 0 || strcmp(service.application, "https") == 0)) snprintf(service.path, sizeof(service.path), "/");
    if (creating && service.transport[0] == '\0') snprintf(service.transport, sizeof(service.transport),
                                                            "%s", strcmp(service.application, "udp") == 0 ? "udp" : "tcp");
    int target_port = 0, published_port = 0, enabled = 0;
    if (st_json_get_int(body, "targetPort", &target_port) == 0) service.target_port = target_port;
    if (st_json_get_int(body, "publishedPort", &published_port) == 0) service.published_port = published_port;
    if (st_json_get_bool(body, "enabled", &enabled) == 0) service.enabled = enabled;
    int ids_rc = peer_service_allowed_ids(body, service.allowed_client_ids, !creating);
    int app_ok = strcmp(service.application, "http") == 0 || strcmp(service.application, "https") == 0
        || strcmp(service.application, "ssh") == 0 || strcmp(service.application, "tcp") == 0
        || strcmp(service.application, "udp") == 0;
    int transport_ok = strcmp(service.transport, "tcp") == 0 || strcmp(service.transport, "udp") == 0;
    if (!peer_service_id_valid(service.service_id) || !peer_service_string_valid(service.name, 1U, 80U)
        || strlen(service.description) > 200U || !app_ok || !transport_ok
        || (strcmp(service.application, "udp") == 0) != (strcmp(service.transport, "udp") == 0)
        || !peer_service_string_valid(service.target_host, 1U, 127U)
        || service.target_port < 1 || service.target_port > 65535
        || service.published_port < 1 || service.published_port > 65535
        || strstr(service.path, "..") != NULL || ids_rc < 0) {
        free(service_id); free(name); free(description); free(transport); free(application);
        free(target_host); free(path); free(visibility);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid peer service definition\"}");
    }
    service.id = id;
    if (service.enabled) {
        st_storage_peer_mesh_service services[256];
        size_t count = 0U;
        if (st_storage_list_peer_mesh_services_visible(database_path, service.tenant_id, "", 1,
                                                        services, 256U, &count) != 0) {
            free(service_id); free(name); free(description); free(transport); free(application);
            free(target_host); free(path); free(visibility);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service conflict check failed\"}");
        }
        for (size_t i = 0; i < count; ++i) {
            if (services[i].id != service.id && services[i].client_id == service.client_id
                && services[i].enabled && services[i].published_port == service.published_port) {
                free(service_id); free(name); free(description); free(transport); free(application);
                free(target_host); free(path); free(visibility);
                return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"publishedPort already used by another enabled service\"}");
            }
        }
    }
    st_storage_peer_mesh_service saved;
    int save_rc = st_storage_upsert_peer_mesh_service(database_path, &service, &saved);
    free(service_id); free(name); free(description); free(transport); free(application);
    free(target_host); free(path); free(visibility);
    if (save_rc != 0) return write_response(out, out_len, 409, "Conflict", "{\"error\":\"peer service conflict\"}");
    (void)st_storage_record_peer_mesh_service_audit(database_path,
        creating ? "service-create" : "service-update", context->tenant_id,
        saved.client_id, 0, saved.service_id,
        creating ? "created" : (saved.enabled ? "enabled" : "updated"));
    admin_notify_peer_mesh_refresh(saved.tenant_id);
    st_admin_string_builder builder = {0};
    if (append_peer_mesh_service_view(&builder, &saved, 1) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service response failed\"}");
    }
    int len = write_response(out, out_len, creating ? 201 : 200, creating ? "Created" : "OK", builder.data);
    free(builder.data);
    return len;
}

static int handle_peer_mesh_service_delete(const st_admin_context *context,
                                           long long id,
                                           char *out,
                                           size_t out_len)
{
    if (!context->admin) return write_response(out, out_len, 403, "Forbidden", "{\"error\":\"只有管理员可以修改 Peer 服务共享\"}");
    const char *database_path = admin_database_path();
    st_storage_peer_mesh_service service;
    if (database_path == NULL
        || st_storage_get_peer_mesh_service_visible(database_path, id, context->tenant_id,
                                                     context->username, 1, &service) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"service not found\"}");
    }
    int rc = st_storage_delete_peer_mesh_service(database_path, id, context->tenant_id);
    if (rc != 0) return write_response(out, out_len, 404, "Not Found", "{\"error\":\"service not found\"}");
    (void)st_storage_record_peer_mesh_service_audit(database_path, "service-delete",
        context->tenant_id, service.client_id, 0, service.service_id, "deleted");
    admin_notify_peer_mesh_refresh(service.tenant_id);
    return write_response(out, out_len, 204, "No Content", "");
}

static int peer_service_target_used(const st_storage_peer_mesh_service *services,
                                    size_t count,
                                    const char *host,
                                    int port)
{
    for (size_t i = 0; i < count; ++i) {
        if (services[i].target_port == port && strcmp(services[i].target_host, host) == 0) return 1;
    }
    return 0;
}

static int parse_peer_http_target(const char *url,
                                  char host[128],
                                  int *port,
                                  char application[16],
                                  char path[256])
{
    if (url == NULL || host == NULL || port == NULL || application == NULL || path == NULL) return -1;
    const char *authority = NULL;
    if (strncasecmp(url, "https://", 8U) == 0) {
        snprintf(application, 16U, "https");
        *port = 443;
        authority = url + 8U;
    } else if (strncasecmp(url, "http://", 7U) == 0) {
        snprintf(application, 16U, "http");
        *port = 80;
        authority = url + 7U;
    } else return -1;
    const char *path_start = strchr(authority, '/');
    const char *authority_end = path_start == NULL ? authority + strlen(authority) : path_start;
    if (authority_end == authority || (size_t)(authority_end - authority) >= 160U) return -1;
    const char *host_start = authority;
    const char *host_end = authority_end;
    const char *port_start = NULL;
    if (*host_start == '[') {
        const char *close = memchr(host_start, ']', (size_t)(authority_end - host_start));
        if (close == NULL) return -1;
        host_start++;
        host_end = close;
        if (close + 1 < authority_end && close[1] == ':') port_start = close + 2;
        else if (close + 1 != authority_end) return -1;
    } else {
        const char *colon = memchr(authority, ':', (size_t)(authority_end - authority));
        if (colon != NULL) {
            host_end = colon;
            port_start = colon + 1;
        }
    }
    if (host_end == host_start || (size_t)(host_end - host_start) >= 128U) return -1;
    memcpy(host, host_start, (size_t)(host_end - host_start));
    host[host_end - host_start] = '\0';
    if (strcmp(host, "localhost") == 0) snprintf(host, 128U, "127.0.0.1");
    if (port_start != NULL) {
        char port_text[16];
        size_t port_len = (size_t)(authority_end - port_start);
        if (port_len == 0U || port_len >= sizeof(port_text)) return -1;
        memcpy(port_text, port_start, port_len);
        port_text[port_len] = '\0';
        char *end = NULL;
        long parsed = strtol(port_text, &end, 10);
        if (end == port_text || *end != '\0' || parsed < 1 || parsed > 65535) return -1;
        *port = (int)parsed;
    }
    snprintf(path, 256U, "%s", path_start == NULL || *path_start == '\0' ? "/" : path_start);
    return strstr(path, "..") == NULL ? 0 : -1;
}

static int append_imported_peer_service(st_admin_string_builder *builder,
                                        const char *database_path,
                                        const st_storage_client *client,
                                        const char *service_id,
                                        const char *name,
                                        const char *transport,
                                        const char *application,
                                        const char *target_host,
                                        int target_port,
                                        int published_port,
                                        const char *path,
                                        st_storage_peer_mesh_service *existing,
                                        size_t *existing_count,
                                        int *first)
{
    if (peer_service_target_used(existing, *existing_count, target_host, target_port)) return 1;
    st_storage_peer_mesh_service service;
    memset(&service, 0, sizeof(service));
    snprintf(service.tenant_id, sizeof(service.tenant_id), "%s", client->tenant_id);
    service.client_id = client->id;
    snprintf(service.client_name, sizeof(service.client_name), "%s", client->client_name);
    snprintf(service.service_id, sizeof(service.service_id), "%s", service_id);
    snprintf(service.name, sizeof(service.name), "%.80s", name);
    snprintf(service.description, sizeof(service.description), "imported candidate");
    snprintf(service.transport, sizeof(service.transport), "%s", transport);
    snprintf(service.application, sizeof(service.application), "%s", application);
    snprintf(service.target_host, sizeof(service.target_host), "%s", target_host);
    service.target_port = target_port;
    service.published_port = published_port;
    snprintf(service.path, sizeof(service.path), "%s", path == NULL ? "" : path);
    service.enabled = 0;
    snprintf(service.visibility, sizeof(service.visibility), "OWNER");
    st_storage_peer_mesh_service saved;
    if (st_storage_upsert_peer_mesh_service(database_path, &service, &saved) != 0) return 1;
    if (*existing_count < 256U) existing[(*existing_count)++] = saved;
    if ((!*first && admin_sb_append(builder, ",") != 0)
        || append_peer_mesh_service_view(builder, &saved, 1) != 0) return -1;
    *first = 0;
    (void)st_storage_record_peer_mesh_service_audit(database_path, "service-create",
        client->tenant_id, client->id, 0, saved.service_id, "created");
    return 0;
}

static int handle_peer_mesh_service_import(const st_admin_context *context,
                                           const char *body,
                                           char *out,
                                           size_t out_len)
{
    if (!context->admin) return write_response(out, out_len, 403, "Forbidden", "{\"error\":\"只有管理员可以修改 Peer 服务共享\"}");
    long long client_id = 0;
    if (st_json_get_i64(body, "clientId", &client_id) != 0 || client_id <= 0) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"clientId is required\"}");
    }
    char *source = st_json_get_top_level_string(body, "source");
    int import_mdns = source != NULL && strcasecmp(source, "mdns") == 0;
    free(source);
    const char *database_path = admin_database_path();
    st_storage_client client;
    if (database_path == NULL || st_storage_get_client(database_path, client_id, &client) != 0
        || strcmp(client.tenant_id, context->tenant_id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    st_storage_peer_mesh_service existing[256];
    size_t existing_count = 0U;
    if (st_storage_list_peer_mesh_services_visible(database_path, client.tenant_id, "", 1,
                                                    existing, 256U, &existing_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service import failed\"}");
    }
    if (import_mdns) {
        st_storage_peer_mesh_service_sharing sharing = {0};
        if (st_storage_get_peer_mesh_service_sharing(database_path, client.tenant_id, &sharing) != 0
            || !sharing.mdns_import_enabled) {
            return write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"mDNS candidate import is disabled\"}");
        }
        st_peer_mesh_mdns_candidate candidates[256];
        size_t candidate_count = 0U;
        if (st_peer_mesh_list_mdns_candidates(client.tenant_id, client.id, candidates,
                                              256U, &candidate_count) != 0) {
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"peer service import failed\"}");
        }
        st_admin_string_builder imported_services = {0};
        int import_rc = admin_sb_append(&imported_services, "[");
        int import_first = 1;
        int imported_created = 0;
        int imported_skipped = 0;
        for (size_t i = 0; import_rc == 0 && i < candidate_count; ++i) {
            char service_id[65];
            const char *path = strcmp(candidates[i].application, "http") == 0
                || strcmp(candidates[i].application, "https") == 0 ? "/" : "";
            snprintf(service_id, sizeof(service_id), "import-mdns-%lld-%zu", client.id, i + 1U);
            int imported = append_imported_peer_service(&imported_services, database_path, &client,
                service_id, candidates[i].name, candidates[i].transport, candidates[i].application,
                candidates[i].target_host, candidates[i].target_port, candidates[i].target_port,
                path, existing, &existing_count, &import_first);
            if (imported == 0) ++imported_created;
            else if (imported == 1) ++imported_skipped;
            else import_rc = -1;
        }
        if (import_rc == 0) import_rc = admin_sb_append(&imported_services, "]");
        st_admin_string_builder imported_response = {0};
        if (import_rc == 0) import_rc = admin_sb_appendf(&imported_response,
            "{\"created\":%d,\"skipped\":%d,\"services\":",
            imported_created, imported_skipped);
        if (import_rc == 0) import_rc = admin_sb_append(&imported_response, imported_services.data);
        if (import_rc == 0) import_rc = admin_sb_append(&imported_response, "}");
        free(imported_services.data);
        if (import_rc != 0 || imported_response.data == NULL) {
            free(imported_response.data);
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"peer service import failed\"}");
        }
        char imported_reason[64];
        snprintf(imported_reason, sizeof(imported_reason), "created=%d,skipped=%d",
                 imported_created, imported_skipped);
        (void)st_storage_record_peer_mesh_service_audit(database_path, "service-import-mdns",
            client.tenant_id, client.id, 0, NULL, imported_reason);
        if (imported_created > 0) admin_notify_peer_mesh_refresh(client.tenant_id);
        int imported_len = write_response(out, out_len, 200, "OK", imported_response.data);
        free(imported_response.data);
        return imported_len;
    }
    st_admin_string_builder services = {0};
    int rc = admin_sb_append(&services, "[");
    int first = 1;
    int created = 0;
    int skipped = 0;
    st_storage_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t mapping_count = 0U;
    if (rc == 0 && st_storage_list_mappings(database_path, client.id, mappings,
                                             ST_ADMIN_MAX_TCP_MAPPINGS, &mapping_count) != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < mapping_count; ++i) {
        char service_id[65];
        char name[81];
        const char *host = strcmp(mappings[i].target_address, "localhost") == 0
            ? "127.0.0.1" : mappings[i].target_address;
        snprintf(service_id, sizeof(service_id), "import-tcp-%lld", mappings[i].id);
        snprintf(name, sizeof(name), "tcp-%d", mappings[i].listen_port);
        int imported = append_imported_peer_service(&services, database_path, &client,
            service_id, name, "tcp", "tcp", host, mappings[i].target_port,
            mappings[i].listen_port, "", existing, &existing_count, &first);
        if (imported == 0) ++created; else if (imported == 1) ++skipped; else rc = -1;
    }
    st_storage_http_route routes[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t route_count = 0U;
    if (rc == 0 && st_storage_list_http_routes(database_path, client.id, routes,
                                                ST_ADMIN_MAX_TCP_MAPPINGS, &route_count) != 0) rc = -1;
    for (size_t i = 0; rc == 0 && i < route_count; ++i) {
        char host[128], application[16], target_path[256], service_id[65];
        int target_port = 0;
        if (parse_peer_http_target(routes[i].target_base_url, host, &target_port,
                                   application, target_path) != 0) {
            ++skipped;
            continue;
        }
        snprintf(service_id, sizeof(service_id), "import-http-%lld", routes[i].id);
        int imported = append_imported_peer_service(&services, database_path, &client,
            service_id, routes[i].route, "tcp", application, host, target_port,
            target_port, target_path, existing, &existing_count, &first);
        if (imported == 0) ++created; else if (imported == 1) ++skipped; else rc = -1;
    }
    if (rc == 0) rc = admin_sb_append(&services, "]");
    st_admin_string_builder response = {0};
    if (rc == 0) rc = admin_sb_appendf(&response, "{\"created\":%d,\"skipped\":%d,\"services\":", created, skipped);
    if (rc == 0) rc = admin_sb_append(&response, services.data);
    if (rc == 0) rc = admin_sb_append(&response, "}");
    free(services.data);
    if (rc != 0 || response.data == NULL) {
        free(response.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service import failed\"}");
    }
    char reason[64];
    snprintf(reason, sizeof(reason), "created=%d,skipped=%d", created, skipped);
    (void)st_storage_record_peer_mesh_service_audit(database_path, "service-import",
        client.tenant_id, client.id, 0, NULL, reason);
    if (created > 0) admin_notify_peer_mesh_refresh(client.tenant_id);
    int len = write_response(out, out_len, 200, "OK", response.data);
    free(response.data);
    return len;
}

static int build_peer_mesh_service_audit_response(const st_admin_context *context,
                                                  char *out,
                                                  size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) return write_response(out, out_len, 200, "OK", "[]");
    st_storage_peer_mesh_service_audit events[50];
    size_t count = 0U;
    if (st_storage_list_peer_mesh_service_audits(database_path, context->tenant_id,
                                                 events, 50U, &count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer service audit failed\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        st_storage_peer_mesh_service_audit *event = &events[i];
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = admin_sb_append(&builder, "{\"at\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, event->at);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"action\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, event->action);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"tenantId\":");
        if (rc == 0) rc = admin_sb_append_json_string(&builder, event->tenant_id);
        if (rc == 0) rc = event->client_id > 0
            ? admin_sb_appendf(&builder, ",\"clientId\":%lld", event->client_id)
            : admin_sb_append(&builder, ",\"clientId\":null");
        if (rc == 0) rc = event->session_id > 0
            ? admin_sb_appendf(&builder, ",\"sessionId\":%lld", event->session_id)
            : admin_sb_append(&builder, ",\"sessionId\":null");
        if (rc == 0) rc = admin_sb_append(&builder, ",\"serviceId\":");
        if (rc == 0) rc = event->service_id[0] == '\0'
            ? admin_sb_append(&builder, "null") : admin_sb_append_json_string(&builder, event->service_id);
        if (rc == 0) rc = admin_sb_append(&builder, ",\"reason\":");
        if (rc == 0) rc = event->reason[0] == '\0'
            ? admin_sb_append(&builder, "null") : admin_sb_append_json_string(&builder, event->reason);
        if (rc == 0) rc = admin_sb_append(&builder, "}");
    }
    if (rc == 0) rc = admin_sb_append(&builder, "]");
    if (rc != 0 || builder.data == NULL) { free(builder.data); return -1; }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int build_client_result_response(const st_storage_client *client, int status, const char *reason, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"client\":");
    if (rc == 0) {
        rc = append_client_view(&builder, client);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "}");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int build_specusMappings_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    long long filter_client_id = 0;
    (void)admin_query_i64(path, "clientId", &filter_client_id);
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"specus list failed\"}");
        }
        if (filter_client_id > 0) {
            st_storage_client filter_client;
            if (!admin_load_accessible_client(database_path, context, filter_client_id, &filter_client)) {
                rc = admin_sb_append(&builder, "]");
                if (rc != 0 || builder.data == NULL) {
                    free(builder.data);
                    return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"specus response failed\"}");
                }
                int response_len = write_response(out, out_len, 200, "OK", builder.data);
                free(builder.data);
                return response_len;
            }
        }
        st_storage_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
        size_t mapping_count = 0;
        if (st_storage_list_mappings(database_path, filter_client_id, mappings, ST_ADMIN_MAX_TCP_MAPPINGS, &mapping_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"specus list failed\"}");
        }
        size_t visible_count = 0;
        for (size_t i = 0; rc == 0 && i < mapping_count; ++i) {
            st_storage_client owner;
            if (!admin_load_accessible_client(database_path, context, mappings[i].client_id, &owner)) {
                continue;
            }
            rc = admin_sb_append(&builder, visible_count == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_mapping_view(&builder, &mappings[i]);
            }
            ++visible_count;
        }
    } else if (rc == 0) {
        st_admin_tcp_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
        size_t mapping_count = 0;
        const char *client_name = env_text("SPECUS_CLIENT_NAME", "Demo client");
        if (load_current_tcp_mappings(client_name, mappings, &mapping_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"specus list failed\"}");
        }
        long long client_id = env_i64("SPECUS_CLIENT_ID", 1);
        for (size_t i = 0; rc == 0 && i < mapping_count; ++i) {
            st_storage_mapping mapping = {0};
            mapping.id = (long long)i + 1;
            mapping.client_id = client_id;
            snprintf(mapping.client_name, sizeof(mapping.client_name), "%s", client_name);
            mapping.listen_port = mappings[i].port;
            snprintf(mapping.target_address, sizeof(mapping.target_address), "%s", mappings[i].specus_address);
            mapping.target_port = mappings[i].specus_port;
            mapping.enabled = 1;
            rc = admin_sb_append(&builder, i == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_mapping_view(&builder, &mapping);
            }
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"specus response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_mapping_response(const st_storage_mapping *mapping, int status, const char *reason, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    if (append_mapping_view(&builder, mapping) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"specus response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int build_http_routes_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    long long filter_client_id = 0;
    (void)admin_query_i64(path, "clientId", &filter_client_id);
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route list failed\"}");
        }
        if (filter_client_id > 0) {
            st_storage_client filter_client;
            if (!admin_load_accessible_client(database_path, context, filter_client_id, &filter_client)) {
                rc = admin_sb_append(&builder, "]");
                if (rc != 0 || builder.data == NULL) {
                    free(builder.data);
                    return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route response failed\"}");
                }
                int response_len = write_response(out, out_len, 200, "OK", builder.data);
                free(builder.data);
                return response_len;
            }
        }
        st_storage_http_route routes[ST_ADMIN_MAX_TCP_MAPPINGS];
        size_t route_count = 0;
        if (st_storage_list_http_routes(database_path, filter_client_id, routes, ST_ADMIN_MAX_TCP_MAPPINGS, &route_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route list failed\"}");
        }
        size_t visible_count = 0;
        for (size_t i = 0; rc == 0 && i < route_count; ++i) {
            st_storage_client owner;
            if (!admin_load_accessible_client(database_path, context, routes[i].client_id, &owner)) {
                continue;
            }
            rc = admin_sb_append(&builder, visible_count == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_http_route_view(&builder, &routes[i]);
            }
            ++visible_count;
        }
    } else if (rc == 0) {
        st_admin_http_route routes[ST_ADMIN_MAX_TCP_MAPPINGS];
        size_t route_count = 0;
        const char *client_name = env_text("SPECUS_CLIENT_NAME", "Demo client");
        if (load_current_http_routes(client_name, routes, &route_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route list failed\"}");
        }
        long long client_id = env_i64("SPECUS_CLIENT_ID", 1);
        for (size_t i = 0; rc == 0 && i < route_count; ++i) {
            st_storage_http_route route = {0};
            route.id = (long long)i + 1;
            route.client_id = client_id;
            snprintf(route.client_name, sizeof(route.client_name), "%s", client_name);
            snprintf(route.route, sizeof(route.route), "%.127s", routes[i].route);
            snprintf(route.target_base_url, sizeof(route.target_base_url), "%s", routes[i].target_base_url);
            route.enabled = 1;
            rc = admin_sb_append(&builder, i == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_http_route_view(&builder, &route);
            }
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_http_route_response(const st_storage_http_route *route, int status, const char *reason, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    if (append_http_route_view(&builder, route) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http route response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int build_empty_connections_response(int page, int size, char *out, size_t out_len)
{
    char body[128];
    int written = snprintf(body,
                           sizeof(body),
                           "{\"items\":[],\"total\":0,\"page\":%d,\"size\":%d,\"totalPages\":0}",
                           page,
                           size);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection response failed\"}");
    }
    return write_response(out, out_len, 200, "OK", body);
}

static int build_connections_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    long long filter_client_id = 0;
    int success_filter = -1;
    int page = 0;
    int size = 100;
    (void)admin_query_i64(path, "clientId", &filter_client_id);
    (void)admin_query_bool(path, "success", &success_filter);
    (void)admin_query_int_any(path, "page", &page);
    (void)admin_query_int_any(path, "size", &size);
    if (page < 0) {
        page = 0;
    }
    if (size < 1) {
        size = 1;
    } else if (size > (int)ST_ADMIN_MAX_CONNECTIONS_PAGE) {
        size = (int)ST_ADMIN_MAX_CONNECTIONS_PAGE;
    }
    char *from = admin_query_string(path, "from");
    char *to = admin_query_string(path, "to");
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        free(from);
        free(to);
        return build_empty_connections_response(page, size, out, out_len);
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        free(from);
        free(to);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection list failed\"}");
    }

    st_storage_connection connections[ST_ADMIN_MAX_CONNECTIONS_PAGE];
    size_t connection_count = 0;
    long long total_count = 0;
    int rc = st_storage_list_connections_visible(database_path,
                                                 filter_client_id,
                                                 success_filter,
                                                 from,
                                                 to,
                                                 context->tenant_id,
                                                 context->username,
                                                 context->admin,
                                                 page,
                                                 size,
                                                 connections,
                                                 ST_ADMIN_MAX_CONNECTIONS_PAGE,
                                                 &connection_count,
                                                 &total_count);
    free(from);
    free(to);
    if (rc != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection list failed\"}");
    }
    long long total_pages = total_count <= 0 ? 0 : (total_count + size - 1) / size;
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "{\"items\":[");
    for (size_t i = 0; rc == 0 && i < connection_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_connection_view(&builder, &connections[i]);
        }
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
                              "],\"total\":%lld,\"page\":%d,\"size\":%d,\"totalPages\":%lld}",
                              total_count,
                              page,
                              size,
                              total_pages);
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_connection_stats_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    int limit = 100;
    (void)admin_query_int_any(path, "limit", &limit);
    if (limit < 1) {
        limit = 1;
    } else if (limit > 500) {
        limit = 500;
    }
    char *client_name = admin_query_string(path, "clientName");
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        free(client_name);
        return write_response(out, out_len, 200, "OK", "[]");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        free(client_name);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection stat list failed\"}");
    }
    st_storage_connection_stat stats[ST_ADMIN_MAX_CONNECTIONS_PAGE];
    size_t stat_count = 0;
    int rc = st_storage_list_connection_stats_visible(database_path,
                                                      client_name,
                                                      context->tenant_id,
                                                      context->username,
                                                      context->admin,
                                                      limit,
                                                      stats,
                                                      ST_ADMIN_MAX_CONNECTIONS_PAGE,
                                                      &stat_count);
    free(client_name);
    if (rc != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection stat list failed\"}");
    }
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < stat_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_connection_stat_view(&builder, &stats[i]);
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"connection stat response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_empty_page_response(const char *path, char *out, size_t out_len)
{
    int page = 0;
    int size = 50;
    int limit = 0;
    (void)admin_query_int_any(path, "page", &page);
    if (admin_query_int_any(path, "size", &size) != 0 && admin_query_int_any(path, "limit", &limit) == 0) {
        size = limit;
    }
    if (page < 0) {
        page = 0;
    }
    if (size < 1) {
        size = 1;
    } else if (size > 500) {
        size = 500;
    }
    char body[128];
    int written = snprintf(body,
                           sizeof(body),
                           "{\"items\":[],\"total\":0,\"page\":%d,\"size\":%d,\"totalPages\":0}",
                           page,
                           size);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"page response failed\"}");
    }
    return write_response(out, out_len, 200, "OK", body);
}

static int build_traffic_usage_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    long long filter_client_id = 0;
    int limit = 100;
    (void)admin_query_i64(path, "clientId", &filter_client_id);
    (void)admin_query_int_any(path, "limit", &limit);
    if (limit < 1) {
        limit = 1;
    } else if (limit > (int)ST_ADMIN_MAX_TRAFFIC_ITEMS) {
        limit = 100;
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 200, "OK", "[]");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"traffic list failed\"}");
    }
    st_storage_traffic_usage items[ST_ADMIN_MAX_TRAFFIC_ITEMS];
    size_t item_count = 0;
    int rc = st_storage_list_traffic_usage_visible(database_path,
                                                   filter_client_id,
                                                   context->tenant_id,
                                                   context->username,
                                                   context->admin,
                                                   limit,
                                                   items,
                                                   ST_ADMIN_MAX_TRAFFIC_ITEMS,
                                                   &item_count);
    if (rc != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"traffic list failed\"}");
    }
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < item_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_traffic_usage_view(&builder, &items[i]);
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"traffic response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_resource_traffic_usage_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    long long filter_client_id = 0;
    int limit = 200;
    (void)admin_query_i64(path, "clientId", &filter_client_id);
    (void)admin_query_int_any(path, "limit", &limit);
    if (limit < 1) {
        limit = 1;
    } else if (limit > (int)ST_ADMIN_MAX_TRAFFIC_ITEMS) {
        limit = 200;
    }
    char *type = admin_query_string(path, "type");
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        free(type);
        return write_response(out, out_len, 200, "OK", "[]");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        free(type);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"resource traffic list failed\"}");
    }
    st_storage_resource_traffic_usage items[ST_ADMIN_MAX_TRAFFIC_ITEMS];
    size_t item_count = 0;
    int rc = st_storage_list_resource_traffic_usage_visible(database_path,
                                                           type,
                                                           filter_client_id,
                                                           context->tenant_id,
                                                           context->username,
                                                           context->admin,
                                                           limit,
                                                           items,
                                                           ST_ADMIN_MAX_TRAFFIC_ITEMS,
                                                           &item_count);
    free(type);
    if (rc != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"resource traffic list failed\"}");
    }
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < item_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_resource_traffic_usage_view(&builder, &items[i]);
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"resource traffic response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_http_exchanges_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    int page = 0;
    int size = 50;
    long long client_id = 0;
    (void)admin_query_int_any(path, "page", &page);
    (void)admin_query_int_any(path, "size", &size);
    (void)admin_query_i64(path, "clientId", &client_id);
    if (page < 0) page = 0;
    if (size < 1) size = 1;
    if (size > 500) size = 500;
    char *route = admin_query_string(path, "route");
    char *response_body_type = admin_query_string(path, "responseBodyType");
    if (response_body_type == NULL || *response_body_type == '\0') {
        free(response_body_type);
        response_body_type = admin_query_string(path, "responseDataType");
    }
    char *field = admin_query_string(path, "field");
    char *query = admin_query_string(path, "q");
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        free(route);
        free(response_body_type);
        free(field);
        free(query);
        return build_empty_page_response(path, out, out_len);
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        free(route);
        free(response_body_type);
        free(field);
        free(query);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http exchange list failed\"}");
    }
    st_storage_http_exchange *items =
        (st_storage_http_exchange *)calloc(ST_ADMIN_MAX_CONNECTIONS_PAGE, sizeof(*items));
    if (items == NULL) {
        free(route);
        free(response_body_type);
        free(field);
        free(query);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http exchange list failed\"}");
    }
    size_t item_count = 0;
    long long total_count = 0;
    int rc = st_storage_list_http_exchanges_visible(database_path,
                                                    client_id,
                                                    route,
                                                    response_body_type,
                                                    field,
                                                    query,
                                                    context->tenant_id,
                                                    context->username,
                                                    context->admin,
                                                    page,
                                                    size,
                                                    items,
                                                    ST_ADMIN_MAX_CONNECTIONS_PAGE,
                                                    &item_count,
                                                    &total_count);
    free(route);
    free(response_body_type);
    free(field);
    free(query);
    if (rc != 0) {
        free(items);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http exchange list failed\"}");
    }
    long long total_pages = total_count <= 0 ? 0 : (total_count + size - 1) / size;
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "{\"items\":[");
    for (size_t i = 0; rc == 0 && i < item_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_http_exchange_view(&builder, &items[i]);
        }
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
                              "],\"total\":%lld,\"page\":%d,\"size\":%d,\"totalPages\":%lld}",
                              total_count,
                              page,
                              size,
                              total_pages);
    }
    if (rc != 0 || builder.data == NULL) {
        free(items);
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"http exchange response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(items);
    free(builder.data);
    return response_len;
}

static int build_http_exchange_detail_response(const st_admin_context *context,
                                               long long exchange_id,
                                               char *out,
                                               size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL || exchange_id <= 0) {
        return write_response(out, out_len, 404, "Not Found",
                              "{\"error\":\"HTTP exchange not found\"}");
    }
    const int page_size = 100;
    st_storage_http_exchange *items = (st_storage_http_exchange *)calloc(
        (size_t)page_size, sizeof(*items));
    if (items == NULL) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"http exchange lookup failed\"}");
    }
    long long total = 0;
    int found = 0;
    st_storage_http_exchange match;
    for (int page = 0; !found; ++page) {
        size_t count = 0U;
        if (st_storage_list_http_exchanges_visible(database_path, 0, NULL, NULL, NULL, NULL,
                context->tenant_id, context->username, context->admin, page, page_size,
                items, (size_t)page_size, &count, &total) != 0) {
            free(items);
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"http exchange lookup failed\"}");
        }
        for (size_t i = 0; i < count; ++i) {
            if (items[i].id == exchange_id) {
                match = items[i];
                found = 1;
                break;
            }
        }
        if (found || count == 0U || (long long)(page + 1) * page_size >= total) break;
    }
    free(items);
    if (!found) {
        return write_response(out, out_len, 404, "Not Found",
                              "{\"error\":\"HTTP exchange not found\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = append_http_exchange_view(&builder, &match);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"http exchange response failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int build_traffic_inspection_status_response(char *out, size_t out_len)
{
    int enabled = env_bool("SPECUS_TRAFFIC_CAPTURE_DETAIL_ENABLED", 0);
    return write_response(out, out_len, 200, "OK",
        enabled
            ? "{\"enabled\":true,\"pendingHttp\":0,\"pendingTcp\":0,\"droppedHttp\":0,\"droppedTcp\":0,\"lastFlushedAt\":null}"
            : "{\"enabled\":false,\"pendingHttp\":0,\"pendingTcp\":0,\"droppedHttp\":0,\"droppedTcp\":0,\"lastFlushedAt\":null}");
}

static int build_tcp_frames_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    int page = 0;
    int size = 50;
    int limit = 0;
    int listen_port = 0;
    long long client_id = 0;
    (void)admin_query_int_any(path, "page", &page);
    if (admin_query_int_any(path, "size", &size) != 0 && admin_query_int_any(path, "limit", &limit) == 0) {
        size = limit;
    }
    (void)admin_query_i64(path, "clientId", &client_id);
    (void)admin_query_int_any(path, "listenPort", &listen_port);
    if (page < 0) page = 0;
    if (size < 1) size = 1;
    if (size > 500) size = 500;
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return build_empty_page_response(path, out, out_len);
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp frame list failed\"}");
    }
    st_storage_tcp_frame items[ST_ADMIN_MAX_CONNECTIONS_PAGE];
    memset(items, 0, sizeof(items));
    size_t item_count = 0;
    long long total_count = 0;
    int rc = st_storage_list_tcp_frames_visible(database_path,
                                                client_id,
                                                listen_port,
                                                context->tenant_id,
                                                context->username,
                                                context->admin,
                                                page,
                                                size,
                                                items,
                                                ST_ADMIN_MAX_CONNECTIONS_PAGE,
                                                &item_count,
                                                &total_count);
    if (rc != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp frame list failed\"}");
    }
    long long total_pages = total_count <= 0 ? 0 : (total_count + size - 1) / size;
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "{\"items\":[");
    for (size_t i = 0; rc == 0 && i < item_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_tcp_frame_view(&builder, &items[i], 0);
        }
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
                              "],\"total\":%lld,\"page\":%d,\"size\":%d,\"totalPages\":%lld}",
                              total_count,
                              page,
                              size,
                              total_pages);
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp frame response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_tcp_frame_detail_response(const st_admin_context *context, long long id, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"TCP frame not found\"}");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp frame lookup failed\"}");
    }
    st_storage_tcp_frame frame;
    memset(&frame, 0, sizeof(frame));
    if (st_storage_get_tcp_frame_visible(database_path,
                                         id,
                                         context->tenant_id,
                                         context->username,
                                         context->admin,
                                         &frame) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"TCP frame not found\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = append_tcp_frame_view(&builder, &frame, 1);
    st_storage_tcp_frame_free(&frame);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp frame response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_empty_tcp_stream_response(const char *path, char *out, size_t out_len)
{
    char *channel_id = admin_query_string(path, "channelId");
    if (channel_id == NULL || *channel_id == '\0') {
        free(channel_id);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"channelId is required\"}");
    }
    int limit = 500;
    (void)admin_query_int_any(path, "limit", &limit);
    if (limit < 1) {
        limit = 1;
    } else if (limit > 1000) {
        limit = 1000;
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"channelId\":");
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, channel_id);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
                              ",\"items\":[],\"total\":0,\"limit\":%d,\"truncated\":false}",
                              limit);
    }
    free(channel_id);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp stream response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_tcp_stream_response(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    char *channel_id = admin_query_string(path, "channelId");
    if (channel_id == NULL || *channel_id == '\0') {
        free(channel_id);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"channelId is required\"}");
    }
    int limit = 500;
    (void)admin_query_int_any(path, "limit", &limit);
    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        int response_len = build_empty_tcp_stream_response(path, out, out_len);
        free(channel_id);
        return response_len;
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        free(channel_id);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp stream lookup failed\"}");
    }
    st_storage_tcp_frame items[ST_ADMIN_MAX_CONNECTIONS_PAGE];
    memset(items, 0, sizeof(items));
    size_t item_count = 0;
    int rc = st_storage_list_tcp_stream_visible(database_path,
                                                channel_id,
                                                context->tenant_id,
                                                context->username,
                                                context->admin,
                                                limit,
                                                items,
                                                ST_ADMIN_MAX_CONNECTIONS_PAGE,
                                                &item_count);
    if (rc != 0) {
        free(channel_id);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp stream lookup failed\"}");
    }
    st_admin_string_builder builder = {0};
    rc = admin_sb_append(&builder, "{\"channelId\":");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, channel_id);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"items\":[");
    for (size_t i = 0; rc == 0 && i < item_count; ++i) {
        rc = admin_sb_append(&builder, i == 0 ? "" : ",");
        if (rc == 0) {
            rc = append_tcp_frame_view(&builder, &items[i], 1);
        }
        st_storage_tcp_frame_free(&items[i]);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(&builder,
                              "],\"total\":%zu,\"limit\":%d,\"truncated\":%s}",
                              item_count,
                              limit,
                              item_count >= (size_t)limit ? "true" : "false");
    }
    free(channel_id);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"tcp stream response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int handle_client_create(const st_admin_context *context, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    char *client_name = st_json_get_string(body, "clientName");
    if (client_name == NULL || *client_name == '\0') {
        free(client_name);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"clientName is required\"}");
    }
    int enabled = 1;
    (void)st_json_get_bool(body, "enabled", &enabled);
    int rate_limit = 30;
    (void)st_json_get_int(body, "connectionRateLimitPerMinute", &rate_limit);
    st_storage_client client;
    int rc = st_storage_upsert_client(database_path,
                                      0,
                                      context->tenant_id,
                                      client_name,
                                      context->username,
                                      enabled,
                                      rate_limit,
                                      &client);
    free(client_name);
    if (rc != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"client create failed\"}");
    }
    admin_notify_peer_mesh_refresh(client.tenant_id);
    return build_client_result_response(&client, 201, "Created", out, out_len);
}

static int handle_client_update(const st_admin_context *context, long long id, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client existing;
    if (st_storage_get_client(database_path, id, &existing) != 0 || !admin_can_access_client(context, &existing)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    char *client_name = st_json_get_string(body, "clientName");
    const char *next_client_name = client_name != NULL && *client_name != '\0' ? client_name : existing.client_name;
    int enabled = existing.enabled;
    (void)st_json_get_bool(body, "enabled", &enabled);
    int rate_limit = existing.connection_rate_limit_per_minute;
    (void)st_json_get_int(body, "connectionRateLimitPerMinute", &rate_limit);
    st_storage_client updated;
    int rc = st_storage_upsert_client(database_path,
                                      id,
                                      existing.tenant_id,
                                      next_client_name,
                                      existing.owner_username,
                                      enabled,
                                      rate_limit,
                                      &updated);
    free(client_name);
    if (rc != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"client update failed\"}");
    }
    admin_notify_peer_mesh_refresh(updated.tenant_id);
    return build_client_result_response(&updated, 200, "OK", out, out_len);
}

static int handle_client_delete(const st_admin_context *context, long long id, char *out, size_t out_len)
{
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client existing;
    if (st_storage_get_client(database_path, id, &existing) != 0 || !admin_can_access_client(context, &existing)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    if (st_storage_delete_client(database_path, id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    admin_notify_peer_mesh_refresh(existing.tenant_id);
    return write_response(out, out_len, 204, "No Content", "");
}

static int build_peer_mesh_acl_result_response(const st_storage_peer_mesh_acl *acl, int status, const char *reason, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    if (append_peer_mesh_acl_view(&builder, acl) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh acl response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int handle_peer_mesh_acl_create(const st_admin_context *context, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    long long source_client_id = 0;
    long long target_client_id = 0;
    if (st_json_get_i64(body, "sourceClientId", &source_client_id) != 0
        || st_json_get_i64(body, "targetClientId", &target_client_id) != 0
        || source_client_id <= 0
        || target_client_id <= 0) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"sourceClientId and targetClientId are required\"}");
    }
    if (source_client_id == target_client_id) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"source and target cannot be the same client\"}");
    }
    st_storage_client source;
    st_storage_client target;
    if (!admin_load_accessible_client(database_path, context, source_client_id, &source)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"source client not found\"}");
    }
    if (!admin_load_tenant_client(database_path, context, target_client_id, &target)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"target client not found\"}");
    }
    if (!context->admin && strcmp(target.owner_username, context->username) != 0) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"ordinary users cannot create cross-user peer ACL\"}");
    }
    int allowed = 1;
    (void)st_json_get_bool(body, "allowed", &allowed);
    char *direction_value = st_json_get_string(body, "direction");
    const char *direction = NULL;
    if (direction_value != NULL && admin_ascii_casecmp(direction_value, "OUTBOUND") == 0) {
        direction = "OUTBOUND";
    } else if (direction_value != NULL && admin_ascii_casecmp(direction_value, "INBOUND") == 0) {
        direction = "INBOUND";
    } else if (direction_value != NULL && admin_ascii_casecmp(direction_value, "BOTH") == 0) {
        direction = "BOTH";
    } else if (direction_value != NULL) {
        char *escaped_direction = st_json_escape(direction_value);
        st_admin_string_builder error = {0};
        int error_rc = escaped_direction == NULL
            ? -1
            : admin_sb_appendf(&error, "{\"error\":\"invalid direction: %s\"}", escaped_direction);
        free(escaped_direction);
        free(direction_value);
        if (error_rc != 0 || error.data == NULL) {
            free(error.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh acl validation failed\"}");
        }
        int response_len = write_response(out, out_len, 400, "Bad Request", error.data);
        free(error.data);
        return response_len;
    }
    st_storage_peer_mesh_acl acl;
    if (st_storage_upsert_peer_mesh_acl(database_path,
                                        context->tenant_id,
                                        context->username,
                                        &source,
                                        &target,
                                        allowed,
                                        direction,
                                        &acl) != 0) {
        free(direction_value);
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"peer mesh acl create failed\"}");
    }
    free(direction_value);
    admin_notify_peer_mesh_refresh(context->tenant_id);
    return build_peer_mesh_acl_result_response(&acl, 201, "Created", out, out_len);
}

static int handle_peer_mesh_acl_delete(const st_admin_context *context, long long id, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        return write_response(out, out_len, 204, "No Content", "");
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh acl delete failed\"}");
    }
    if (st_storage_delete_peer_mesh_acl_visible(database_path,
                                                id,
                                                context->tenant_id,
                                                context->username,
                                                context->admin) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"peer mesh acl not found\"}");
    }
    admin_notify_peer_mesh_refresh(context->tenant_id);
    return write_response(out, out_len, 204, "No Content", "");
}

static int handle_specus_create(const st_admin_context *context, long long client_id, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client owner;
    if (!admin_load_accessible_client(database_path, context, client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    int listen_port = 0;
    int target_port = 0;
    char *target_address = st_json_get_string(body, "targetAddress");
    if (st_json_get_int(body, "listenPort", &listen_port) != 0
        || st_json_get_int(body, "targetPort", &target_port) != 0
        || target_address == NULL || *target_address == '\0') {
        free(target_address);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"listenPort, targetAddress and targetPort are required\"}");
    }
    int enabled = 1;
    (void)st_json_get_bool(body, "enabled", &enabled);
    int detail_capture_enabled = 0;
    (void)st_json_get_bool(body, "detailCaptureEnabled", &detail_capture_enabled);
    st_storage_mapping mapping;
    int rc = st_storage_create_mapping_for_client(database_path,
                                                  client_id,
                                                  listen_port,
                                                  target_address,
                                                  target_port,
                                                  enabled,
                                                  detail_capture_enabled,
                                                  &mapping);
    free(target_address);
    if (rc != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found or specus create failed\"}");
    }
    admin_notify_nat_control(&owner);
    return build_mapping_response(&mapping, 201, "Created", out, out_len);
}

static int handle_nat_control_push(const st_admin_context *context, long long client_id, char *out, size_t out_len)
{
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client owner;
    if (!admin_load_accessible_client(database_path, context, client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    st_storage_mapping mappings[ST_ADMIN_MAX_TCP_MAPPINGS];
    st_storage_http_route routes[ST_ADMIN_MAX_TCP_MAPPINGS];
    size_t mapping_count = 0U;
    size_t route_count = 0U;
    if (st_storage_list_mappings(database_path, client_id, mappings,
                                 ST_ADMIN_MAX_TCP_MAPPINGS, &mapping_count) != 0
        || st_storage_list_http_routes(database_path, client_id, routes,
                                       ST_ADMIN_MAX_TCP_MAPPINGS, &route_count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"映射下发失败\"}");
    }
    int enabled_mappings = 0;
    int enabled_routes = 0;
    for (size_t i = 0; i < mapping_count; ++i) if (mappings[i].enabled) ++enabled_mappings;
    for (size_t i = 0; i < route_count; ++i) if (routes[i].enabled) ++enabled_routes;
    int push_result = admin_push_nat_control(owner.id, owner.client_name);
    if (push_result == 0) {
        char response[160];
        snprintf(response, sizeof(response),
                 "{\"pushed\":%d,\"specusMappings\":%d,\"httpRoutes\":%d}",
                 enabled_mappings, enabled_mappings, route_count == 0U ? -1 : enabled_routes);
        return write_response(out, out_len, 200, "OK", response);
    }
    return push_result == -1
        ? write_response(out,
                         out_len,
                         409,
                         "Conflict",
                         "{\"error\":\"客户端不在线，无法下发映射\"}")
        : write_response(out,
                         out_len,
                         500,
                         "Internal Server Error",
                         "{\"error\":\"映射下发失败\"}");
}

static int handle_specus_update(const st_admin_context *context, long long id, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_mapping existing;
    st_storage_client owner;
    if (st_storage_get_mapping(database_path, id, &existing) != 0
        || !admin_load_accessible_client(database_path, context, existing.client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"specus not found\"}");
    }
    int listen_port = existing.listen_port;
    (void)st_json_get_int(body, "listenPort", &listen_port);
    int target_port = existing.target_port;
    (void)st_json_get_int(body, "targetPort", &target_port);
    char *target_address = st_json_get_string(body, "targetAddress");
    const char *next_target_address = target_address != NULL && *target_address != '\0'
        ? target_address
        : existing.target_address;
    int enabled = existing.enabled;
    (void)st_json_get_bool(body, "enabled", &enabled);
    int detail_capture_enabled = existing.detail_capture_enabled;
    (void)st_json_get_bool(body, "detailCaptureEnabled", &detail_capture_enabled);
    st_storage_mapping mapping;
    int rc = st_storage_update_mapping_by_id(database_path,
                                             id,
                                             listen_port,
                                             next_target_address,
                                             target_port,
                                             enabled,
                                             detail_capture_enabled,
                                             &mapping);
    free(target_address);
    if (rc != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"specus update failed\"}");
    }
    admin_notify_nat_control(&owner);
    return build_mapping_response(&mapping, 200, "OK", out, out_len);
}

static int handle_specus_delete(const st_admin_context *context, long long id, char *out, size_t out_len)
{
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_mapping existing;
    st_storage_client owner;
    if (st_storage_get_mapping(database_path, id, &existing) != 0
        || !admin_load_accessible_client(database_path, context, existing.client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"specus not found\"}");
    }
    if (st_storage_delete_mapping_by_id(database_path, id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"specus not found\"}");
    }
    admin_notify_nat_control(&owner);
    return write_response(out, out_len, 204, "No Content", "");
}

static int http_route_auth_text_present(const char *value)
{
    if (value == NULL) {
        return 0;
    }
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (!isspace(*cursor)) {
            return 1;
        }
    }
    return 0;
}

static int normalize_http_route_auth_username(char *username)
{
    if (username == NULL) {
        return 0;
    }
    char *trimmed = admin_trim(username);
    size_t len = strlen(trimmed);
    if (len > 120U || strchr(trimmed, ':') != NULL
        || strchr(trimmed, '\r') != NULL || strchr(trimmed, '\n') != NULL) {
        return -1;
    }
    if (trimmed != username) {
        memmove(username, trimmed, len + 1U);
    }
    return 0;
}

static int http_route_auth_password_hash(const char *password,
                                         const char *existing_hash,
                                         char out[ST_SHA256_HEX_LEN + 1])
{
    snprintf(out, ST_SHA256_HEX_LEN + 1U, "%s", existing_hash == NULL ? "" : existing_hash);
    if (!http_route_auth_text_present(password)) {
        return 0;
    }
    if (strlen(password) > 256U) {
        return -1;
    }
    return password_hash_hex(password, out);
}

static int handle_http_route_create(const st_admin_context *context, long long client_id, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client owner;
    if (!admin_load_accessible_client(database_path, context, client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found\"}");
    }
    char *route_name = st_json_get_string(body, "route");
    char *target_base_url = st_json_get_string(body, "targetBaseUrl");
    if (route_name == NULL || *route_name == '\0' || target_base_url == NULL || *target_base_url == '\0') {
        free(route_name);
        free(target_base_url);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"route and targetBaseUrl are required\"}");
    }
    int enabled = 1;
    (void)st_json_get_bool(body, "enabled", &enabled);
    int detail_capture_enabled = 0;
    (void)st_json_get_bool(body, "detailCaptureEnabled", &detail_capture_enabled);
    int media_capture_enabled = 0;
    (void)st_json_get_bool(body, "mediaCaptureEnabled", &media_capture_enabled);
    int path_rewrite_enabled = 0;
    (void)st_json_get_bool(body, "pathRewriteEnabled", &path_rewrite_enabled);
    int insecure_skip_verify = 0;
    (void)st_json_get_bool(body, "insecureSkipVerify", &insecure_skip_verify);
    int auth_enabled = 0;
    (void)st_json_get_bool(body, "authEnabled", &auth_enabled);
    char *auth_username = st_json_get_string(body, "authUsername");
    char *auth_password = st_json_get_string(body, "authPassword");
    char auth_password_hash[ST_SHA256_HEX_LEN + 1] = {0};
    if (normalize_http_route_auth_username(auth_username) != 0
        || http_route_auth_password_hash(auth_password, NULL, auth_password_hash) != 0) {
        free(route_name);
        free(target_base_url);
        free(auth_username);
        free(auth_password);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid HTTP route authentication credentials\"}");
    }
    if (auth_enabled && (auth_username == NULL || *auth_username == '\0' || auth_password_hash[0] == '\0')) {
        free(route_name);
        free(target_base_url);
        free(auth_username);
        free(auth_password);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"authUsername and authPassword are required when authentication is enabled\"}");
    }
    st_storage_http_route route;
    int rc = st_storage_create_http_route_for_client(database_path,
                                                     client_id,
                                                     route_name,
                                                     target_base_url,
                                                     enabled,
                                                     detail_capture_enabled,
                                                     media_capture_enabled,
                                                     path_rewrite_enabled,
                                                     insecure_skip_verify,
                                                     auth_enabled,
                                                     auth_username,
                                                     auth_password_hash,
                                                     &route);
    free(route_name);
    free(target_base_url);
    free(auth_username);
    free(auth_password);
    if (rc != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client not found or http route create failed\"}");
    }
    admin_notify_nat_control(&owner);
    return build_http_route_response(&route, 201, "Created", out, out_len);
}

static int handle_http_route_update(const st_admin_context *context, long long id, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_http_route existing;
    st_storage_client owner;
    if (st_storage_get_http_route(database_path, id, &existing) != 0
        || !admin_load_accessible_client(database_path, context, existing.client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"http route not found\"}");
    }
    char *route_name = st_json_get_string(body, "route");
    const char *next_route = route_name != NULL && *route_name != '\0' ? route_name : existing.route;
    char *target_base_url = st_json_get_string(body, "targetBaseUrl");
    const char *next_target = target_base_url != NULL && *target_base_url != '\0'
        ? target_base_url
        : existing.target_base_url;
    int enabled = existing.enabled;
    (void)st_json_get_bool(body, "enabled", &enabled);
    int detail_capture_enabled = existing.detail_capture_enabled;
    (void)st_json_get_bool(body, "detailCaptureEnabled", &detail_capture_enabled);
    int media_capture_enabled = existing.media_capture_enabled;
    (void)st_json_get_bool(body, "mediaCaptureEnabled", &media_capture_enabled);
    int path_rewrite_enabled = existing.path_rewrite_enabled;
    (void)st_json_get_bool(body, "pathRewriteEnabled", &path_rewrite_enabled);
    int insecure_skip_verify = existing.insecure_skip_verify;
    (void)st_json_get_bool(body, "insecureSkipVerify", &insecure_skip_verify);
    int auth_enabled = existing.auth_enabled;
    (void)st_json_get_bool(body, "authEnabled", &auth_enabled);
    char *auth_username = st_json_get_string(body, "authUsername");
    const char *next_auth_username = auth_username == NULL ? existing.auth_username : auth_username;
    char *auth_password = st_json_get_string(body, "authPassword");
    char auth_password_hash[ST_SHA256_HEX_LEN + 1];
    if (normalize_http_route_auth_username(auth_username) != 0
        || http_route_auth_password_hash(auth_password, existing.auth_password_hash, auth_password_hash) != 0) {
        free(route_name);
        free(target_base_url);
        free(auth_username);
        free(auth_password);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"invalid HTTP route authentication credentials\"}");
    }
    if (auth_enabled && (*next_auth_username == '\0' || auth_password_hash[0] == '\0')) {
        free(route_name);
        free(target_base_url);
        free(auth_username);
        free(auth_password);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"authUsername and a configured authPassword are required when authentication is enabled\"}");
    }
    st_storage_http_route route;
    int rc = st_storage_update_http_route_by_id(database_path,
                                                id,
                                                next_route,
                                                next_target,
                                                enabled,
                                                detail_capture_enabled,
                                                media_capture_enabled,
                                                path_rewrite_enabled,
                                                insecure_skip_verify,
                                                auth_enabled,
                                                next_auth_username,
                                                auth_password_hash,
                                                &route);
    free(route_name);
    free(target_base_url);
    free(auth_username);
    free(auth_password);
    if (rc != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"http route update failed\"}");
    }
    admin_notify_nat_control(&owner);
    return build_http_route_response(&route, 200, "OK", out, out_len);
}

static int handle_http_route_delete(const st_admin_context *context, long long id, char *out, size_t out_len)
{
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_http_route existing;
    st_storage_client owner;
    if (st_storage_get_http_route(database_path, id, &existing) != 0
        || !admin_load_accessible_client(database_path, context, existing.client_id, &owner)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"http route not found\"}");
    }
    if (st_storage_delete_http_route_by_id(database_path, id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"http route not found\"}");
    }
    admin_notify_nat_control(&owner);
    return write_response(out, out_len, 204, "No Content", "");
}

static const char *normalize_management_role(const char *role)
{
    if (role == NULL) {
        return "USER";
    }
    while (*role != '\0' && isspace((unsigned char)*role)) {
        ++role;
    }
    size_t len = strlen(role);
    while (len > 0 && isspace((unsigned char)role[len - 1U])) {
        --len;
    }
    return len == 5U && admin_ascii_ncasecmp(role, "ADMIN", len) == 0 ? "ADMIN" : "USER";
}

static int password_hash_hex(const char *password, char out[ST_SHA256_HEX_LEN + 1])
{
    if (password == NULL || *password == '\0') {
        return -1;
    }
    uint8_t digest[ST_SHA256_LEN];
    st_sha256((const uint8_t *)password, strlen(password), digest);
    st_hex_encode(digest, sizeof(digest), out);
    return 0;
}

static int password_hash_matches(const char *password, const char *expected_hash)
{
    char actual_hex[ST_SHA256_HEX_LEN + 1];
    uint8_t actual[ST_SHA256_LEN];
    uint8_t expected[ST_SHA256_LEN];
    if (password_hash_hex(password, actual_hex) != 0
        || st_hex_decode_32(actual_hex, actual) != 0
        || st_hex_decode_32(expected_hash, expected) != 0) {
        return 0;
    }
    return st_constant_time_eq(actual, expected, sizeof(actual));
}

static int normalize_api_key_in_place(char *api_key)
{
    if (api_key == NULL) {
        return -1;
    }
    char *trimmed = admin_trim(api_key);
    size_t len = strlen(trimmed);
    if (len < 3U || len > 120U) {
        return -1;
    }
    if (trimmed != api_key) {
        memmove(api_key, trimmed, len + 1U);
    }
    return 0;
}

static int build_credential_result_response(const st_storage_client_credential *credential,
                                            const char *secret,
                                            int status,
                                            const char *reason,
                                            char *out,
                                            size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"credential\":");
    if (rc == 0) {
        rc = append_credential_view(&builder, credential);
    }
    if (rc == 0 && secret != NULL && *secret != '\0') {
        rc = admin_sb_append(&builder, ",\"secret\":");
        if (rc == 0) {
            rc = admin_sb_append_json_string(&builder, secret);
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "}");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"credential response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int build_credentials_response(const st_admin_context *context, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"credential list failed\"}");
        }
        st_storage_client_credential credentials[ST_ADMIN_MAX_CLIENTS];
        size_t credential_count = 0;
        if (st_storage_list_client_credentials(database_path,
                                               context->tenant_id,
                                               credentials,
                                               ST_ADMIN_MAX_CLIENTS,
                                               &credential_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"credential list failed\"}");
        }
        size_t visible_count = 0;
        for (size_t i = 0; rc == 0 && i < credential_count; ++i) {
            if (!admin_can_access_credential(context, &credentials[i])) {
                continue;
            }
            rc = admin_sb_append(&builder, visible_count == 0 ? "" : ",");
            if (rc == 0) {
                rc = append_credential_view(&builder, &credentials[i]);
            }
            ++visible_count;
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"credential response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int handle_credential_create(const st_admin_context *context, const char *body, char *out, size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    char generated_api_key[140];
    char generated_secret[140];
    char *api_key = st_json_get_string(body, "apiKey");
    char *secret = st_json_get_string(body, "secret");
    if (api_key == NULL || *admin_trim(api_key) == '\0') {
        build_prefixed_token("ck_", generated_api_key, sizeof(generated_api_key));
        generated_api_key[120] = '\0';
        free(api_key);
        api_key = admin_dup_string(generated_api_key);
    }
    if (secret == NULL || *admin_trim(secret) == '\0') {
        build_prefixed_token("sk_", generated_secret, sizeof(generated_secret));
        free(secret);
        secret = admin_dup_string(generated_secret);
    }
    if (normalize_api_key_in_place(api_key) != 0 || secret == NULL || *admin_trim(secret) == '\0') {
        free(api_key);
        free(secret);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"apiKey length must be between 3 and 120\"}");
    }
    st_storage_client_credential existing;
    if (st_storage_get_client_credential_by_api_key(database_path, api_key, &existing) == 0) {
        free(api_key);
        free(secret);
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"apiKey already exists\"}");
    }
    int enabled = 1;
    int max_online_instances = client_auth_default_max_online_instances();
    (void)st_json_get_bool(body, "enabled", &enabled);
    (void)st_json_get_int(body, "maxOnlineInstances", &max_online_instances);
    if (max_online_instances <= 0) {
        max_online_instances = client_auth_default_max_online_instances();
    }
    char secret_hash[ST_SHA256_HEX_LEN + 1];
    if (password_hash_hex(admin_trim(secret), secret_hash) != 0) {
        free(api_key);
        free(secret);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"secret cannot be blank\"}");
    }
    st_storage_client_credential credential;
    int rc = st_storage_upsert_client_credential(database_path,
                                                 0,
                                                 context->tenant_id,
                                                 context->username,
                                                 api_key,
                                                 secret_hash,
                                                 enabled,
                                                 max_online_instances,
                                                 &credential);
    free(api_key);
    if (rc != 0) {
        free(secret);
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"credential create failed\"}");
    }
    int response_len = build_credential_result_response(&credential, admin_trim(secret), 201, "Created", out, out_len);
    free(secret);
    return response_len;
}

static int handle_credential_update(const st_admin_context *context,
                                    long long id,
                                    const char *body,
                                    char *out,
                                    size_t out_len)
{
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client_credential existing;
    if (st_storage_get_client_credential(database_path, id, &existing) != 0
        || !admin_can_access_credential(context, &existing)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"credential not found\"}");
    }
    char *api_key = st_json_get_string(body, "apiKey");
    char *secret = st_json_get_string(body, "secret");
    const char *next_api_key = existing.api_key;
    if (api_key != NULL && *admin_trim(api_key) != '\0') {
        if (normalize_api_key_in_place(api_key) != 0) {
            free(api_key);
            free(secret);
            return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"apiKey length must be between 3 and 120\"}");
        }
        if (strcmp(api_key, existing.api_key) != 0) {
            st_storage_client_credential duplicate;
            if (st_storage_get_client_credential_by_api_key(database_path, api_key, &duplicate) == 0) {
                free(api_key);
                free(secret);
                return write_response(out, out_len, 409, "Conflict", "{\"error\":\"apiKey already exists\"}");
            }
        }
        next_api_key = api_key;
    }
    char secret_hash[ST_SHA256_HEX_LEN + 1];
    const char *secret_hash_ptr = existing.secret_hash;
    const char *revealed_secret = NULL;
    if (secret != NULL && *admin_trim(secret) != '\0') {
        if (password_hash_hex(admin_trim(secret), secret_hash) != 0) {
            free(api_key);
            free(secret);
            return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"secret cannot be blank\"}");
        }
        secret_hash_ptr = secret_hash;
        revealed_secret = admin_trim(secret);
    }
    int enabled = existing.enabled;
    int max_online_instances = existing.max_online_instances <= 0
        ? client_auth_default_max_online_instances()
        : existing.max_online_instances;
    (void)st_json_get_bool(body, "enabled", &enabled);
    (void)st_json_get_int(body, "maxOnlineInstances", &max_online_instances);
    if (max_online_instances <= 0) {
        max_online_instances = client_auth_default_max_online_instances();
    }
    st_storage_client_credential credential;
    int rc = st_storage_upsert_client_credential(database_path,
                                                 existing.id,
                                                 existing.tenant_id,
                                                 existing.owner_username,
                                                 next_api_key,
                                                 secret_hash_ptr,
                                                 enabled,
                                                 max_online_instances,
                                                 &credential);
    int response_len;
    if (rc != 0) {
        response_len = write_response(out, out_len, 409, "Conflict", "{\"error\":\"credential update failed\"}");
    } else {
        response_len = build_credential_result_response(&credential, revealed_secret, 200, "OK", out, out_len);
    }
    free(api_key);
    free(secret);
    return response_len;
}

static int handle_credential_delete(const st_admin_context *context, long long id, char *out, size_t out_len)
{
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client_credential existing;
    if (st_storage_get_client_credential(database_path, id, &existing) != 0
        || !admin_can_access_credential(context, &existing)) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"credential not found\"}");
    }
    if (st_storage_delete_client_credential(database_path, id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"credential not found\"}");
    }
    return write_response(out, out_len, 204, "No Content", "");
}

typedef struct {
    char implementation[33];
    char platform[33];
    char arch[33];
    char display_name[121];
    char download_url[1025];
    char description[513];
    int display_order;
    int enabled;
    char version[81];
    char sha256[65];
    long long file_size;
    int is_latest;
    char changelog_url[1025];
    char min_supported_version[81];
} st_admin_client_download_mutation;

static int client_download_enum_allowed(const char *value, const char *const *allowed, size_t allowed_count)
{
    for (size_t i = 0; i < allowed_count; ++i) {
        if (strcmp(value, allowed[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int normalize_client_download_enum(char *value,
                                          char *out,
                                          size_t out_len,
                                          const char *const *allowed,
                                          size_t allowed_count)
{
    if (value == NULL || out_len == 0) {
        return -1;
    }
    char *trimmed = admin_trim(value);
    size_t len = strlen(trimmed);
    if (len == 0 || len >= out_len) {
        return -1;
    }
    for (size_t i = 0; i < len; ++i) {
        out[i] = (char)admin_ascii_lower((unsigned char)trimmed[i]);
    }
    out[len] = '\0';
    return client_download_enum_allowed(out, allowed, allowed_count) ? 0 : -1;
}

static int copy_trimmed_required(char *value, char *out, size_t out_len)
{
    if (value == NULL || out_len == 0) {
        return -1;
    }
    char *trimmed = admin_trim(value);
    size_t len = strlen(trimmed);
    if (len == 0 || len >= out_len) {
        return -1;
    }
    memcpy(out, trimmed, len + 1U);
    return 0;
}

static void copy_trimmed_optional_truncated(char *value, char *out, size_t out_len)
{
    if (out_len == 0) {
        return;
    }
    out[0] = '\0';
    if (value == NULL) {
        return;
    }
    char *trimmed = admin_trim(value);
    size_t len = strlen(trimmed);
    if (len >= out_len) {
        len = out_len - 1U;
    }
    memcpy(out, trimmed, len);
    out[len] = '\0';
}

static int valid_client_download_url(const char *url)
{
    const char *authority = NULL;
    if (admin_ascii_ncasecmp(url, "http://", 7U) == 0) {
        authority = url + 7U;
    } else if (admin_ascii_ncasecmp(url, "https://", 8U) == 0) {
        authority = url + 8U;
    } else {
        return 0;
    }
    if (*authority == '\0' || *authority == '/') {
        return 0;
    }
    const char *cursor = authority;
    while (*cursor != '\0' && *cursor != '/') {
        if (isspace((unsigned char)*cursor)) {
            return 0;
        }
        ++cursor;
    }
    return cursor > authority;
}

static int valid_sha256_text(const char *value)
{
    if (value == NULL || strlen(value) != 64U) return 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (!isxdigit(*cursor)) return 0;
    }
    return 1;
}

typedef struct {
    char major[33];
    char minor[33];
    char patch[33];
    char prerelease[33];
} st_admin_semver;

static int semver_numeric_part(const char *value)
{
    if (value == NULL || *value == '\0' || (value[0] == '0' && value[1] != '\0')) return 0;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        if (!isdigit(*p)) return 0;
    }
    return 1;
}

static int parse_admin_semver(const char *value, st_admin_semver *out)
{
    if (value == NULL || out == NULL) return -1;
    while (isspace((unsigned char)*value)) ++value;
    if (*value == 'v') ++value;
    const char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) --end;
    size_t len = (size_t)(end - value);
    if (len == 0U || len > 32U) return -1;
    char copy[33];
    memcpy(copy, value, len);
    copy[len] = '\0';
    char *build = strchr(copy, '+');
    if (build != NULL) {
        if (build[1] == '\0') return -1;
        for (char *p = build + 1; *p != '\0'; ++p) {
            if (!isalnum((unsigned char)*p) && *p != '-' && *p != '.') return -1;
        }
        *build = '\0';
    }
    char *prerelease = strchr(copy, '-');
    memset(out, 0, sizeof(*out));
    if (prerelease != NULL) {
        *prerelease++ = '\0';
        if (*prerelease == '\0' || strlen(prerelease) >= sizeof(out->prerelease)) return -1;
        char validation[33];
        snprintf(validation, sizeof(validation), "%s", prerelease);
        char *save = NULL;
        for (char *part = strtok_r(validation, ".", &save); part != NULL;
             part = strtok_r(NULL, ".", &save)) {
            int all_numeric = *part != '\0';
            for (char *p = part; *p != '\0'; ++p) if (!isdigit((unsigned char)*p)) all_numeric = 0;
            if (*part == '\0' || (all_numeric && semver_numeric_part(part) == 0)) return -1;
            for (char *p = part; *p != '\0'; ++p) {
                if (!isalnum((unsigned char)*p) && *p != '-') return -1;
            }
        }
        snprintf(out->prerelease, sizeof(out->prerelease), "%s", prerelease);
    }
    char *save = NULL;
    char *major = strtok_r(copy, ".", &save);
    char *minor = strtok_r(NULL, ".", &save);
    char *patch = strtok_r(NULL, ".", &save);
    if (!semver_numeric_part(major) || !semver_numeric_part(minor)
        || !semver_numeric_part(patch) || strtok_r(NULL, ".", &save) != NULL) return -1;
    snprintf(out->major, sizeof(out->major), "%s", major);
    snprintf(out->minor, sizeof(out->minor), "%s", minor);
    snprintf(out->patch, sizeof(out->patch), "%s", patch);
    return 0;
}

static int compare_semver_numeric(const char *left, const char *right)
{
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    if (left_len != right_len) return left_len < right_len ? -1 : 1;
    int compared = strcmp(left, right);
    return compared < 0 ? -1 : (compared > 0 ? 1 : 0);
}

static int compare_admin_semver(const st_admin_semver *left, const st_admin_semver *right)
{
    int compared = compare_semver_numeric(left->major, right->major);
    if (compared == 0) compared = compare_semver_numeric(left->minor, right->minor);
    if (compared == 0) compared = compare_semver_numeric(left->patch, right->patch);
    if (compared != 0) return compared;
    if (left->prerelease[0] == '\0' || right->prerelease[0] == '\0') {
        return left->prerelease[0] == right->prerelease[0]
            ? 0 : (left->prerelease[0] == '\0' ? 1 : -1);
    }
    char left_copy[33], right_copy[33];
    snprintf(left_copy, sizeof(left_copy), "%s", left->prerelease);
    snprintf(right_copy, sizeof(right_copy), "%s", right->prerelease);
    char *left_save = NULL, *right_save = NULL;
    char *left_part = strtok_r(left_copy, ".", &left_save);
    char *right_part = strtok_r(right_copy, ".", &right_save);
    while (left_part != NULL && right_part != NULL) {
        int left_numeric = semver_numeric_part(left_part);
        int right_numeric = semver_numeric_part(right_part);
        if (left_numeric && right_numeric) compared = compare_semver_numeric(left_part, right_part);
        else if (left_numeric != right_numeric) compared = left_numeric ? -1 : 1;
        else {
            compared = strcmp(left_part, right_part);
            compared = compared < 0 ? -1 : (compared > 0 ? 1 : 0);
        }
        if (compared != 0) return compared;
        left_part = strtok_r(NULL, ".", &left_save);
        right_part = strtok_r(NULL, ".", &right_save);
    }
    return left_part == right_part ? 0 : (left_part == NULL ? -1 : 1);
}

static int read_client_download_mutation(const char *body,
                                         const st_storage_client_download_link *existing,
                                         st_admin_client_download_mutation *mutation,
                                         char *out,
                                         size_t out_len)
{
    static const char *const implementations[] = {"java", "go", "csharp", "android"};
    static const char *const platforms[] = {"windows", "linux", "macos", "android", "any"};
    static const char *const archs[] = {"x64", "arm64", "any"};
    char *implementation = st_json_get_string(body, "implementation");
    char *platform = st_json_get_string(body, "platform");
    char *arch = st_json_get_string(body, "arch");
    char *display_name = st_json_get_string(body, "displayName");
    char *download_url = st_json_get_string(body, "downloadUrl");
    char *description = st_json_get_string(body, "description");
    char *version = st_json_get_string(body, "version");
    char *sha256 = st_json_get_string(body, "sha256");
    char *changelog_url = st_json_get_string(body, "changelogUrl");
    char *min_supported_version = st_json_get_string(body, "minSupportedVersion");
    int response = 0;
    memset(mutation, 0, sizeof(*mutation));
    mutation->display_order = existing == NULL ? 0 : existing->display_order;
    mutation->enabled = existing == NULL ? 1 : existing->enabled;
    mutation->file_size = existing == NULL ? 0 : existing->file_size;
    mutation->is_latest = existing == NULL ? 0 : existing->is_latest;
    if (normalize_client_download_enum(implementation != NULL ? implementation
                                                              : (char *)(existing == NULL ? NULL : existing->implementation),
                                       mutation->implementation,
                                       sizeof(mutation->implementation),
                                       implementations,
                                       sizeof(implementations) / sizeof(implementations[0])) != 0) {
        response = write_response(out,
                                  out_len,
                                  400,
                                  "Bad Request",
                                  "{\"error\":\"implementation must be one of [java go csharp android]\"}");
        goto done;
    }
    if (normalize_client_download_enum(platform != NULL ? platform
                                                        : (char *)(existing == NULL ? NULL : existing->platform),
                                       mutation->platform,
                                       sizeof(mutation->platform),
                                       platforms,
                                       sizeof(platforms) / sizeof(platforms[0])) != 0) {
        response = write_response(out,
                                  out_len,
                                  400,
                                  "Bad Request",
                                  "{\"error\":\"platform must be one of [windows linux macos android any]\"}");
        goto done;
    }
    if (normalize_client_download_enum(arch != NULL ? arch
                                                    : (char *)(existing == NULL ? NULL : existing->arch),
                                       mutation->arch,
                                       sizeof(mutation->arch),
                                       archs,
                                       sizeof(archs) / sizeof(archs[0])) != 0) {
        response = write_response(out,
                                  out_len,
                                  400,
                                  "Bad Request",
                                  "{\"error\":\"arch must be one of [x64 arm64 any]\"}");
        goto done;
    }
    if (copy_trimmed_required(display_name != NULL ? display_name
                                                   : (char *)(existing == NULL ? NULL : existing->display_name),
                              mutation->display_name, sizeof(mutation->display_name)) != 0) {
        response = write_response(out,
                                  out_len,
                                  400,
                                  "Bad Request",
                                  "{\"error\":\"displayName cannot be blank or longer than 120\"}");
        goto done;
    }
    if (copy_trimmed_required(download_url != NULL ? download_url
                                                   : (char *)(existing == NULL ? NULL : existing->download_url),
                              mutation->download_url, sizeof(mutation->download_url)) != 0
        || (!valid_client_download_url(mutation->download_url)
            && !(existing != NULL && existing->hosted
                 && strncmp(mutation->download_url, "/api/public/client-packages/", 28U) == 0))) {
        response = write_response(out,
                                  out_len,
                                  400,
                                  "Bad Request",
                                  "{\"error\":\"downloadUrl must be an absolute http(s) URL\"}");
        goto done;
    }
    copy_trimmed_optional_truncated(description != NULL ? description
        : (char *)(existing == NULL ? NULL : existing->description),
        mutation->description, sizeof(mutation->description));
    copy_trimmed_optional_truncated(version != NULL ? version
        : (char *)(existing == NULL ? NULL : existing->version),
        mutation->version, sizeof(mutation->version));
    copy_trimmed_optional_truncated(sha256 != NULL ? sha256
        : (char *)(existing == NULL ? NULL : existing->sha256),
        mutation->sha256, sizeof(mutation->sha256));
    for (char *cursor = mutation->sha256; *cursor != '\0'; ++cursor) {
        *cursor = (char)tolower((unsigned char)*cursor);
    }
    copy_trimmed_optional_truncated(changelog_url != NULL ? changelog_url
        : (char *)(existing == NULL ? NULL : existing->changelog_url),
        mutation->changelog_url, sizeof(mutation->changelog_url));
    copy_trimmed_optional_truncated(min_supported_version != NULL ? min_supported_version
        : (char *)(existing == NULL ? NULL : existing->min_supported_version),
        mutation->min_supported_version, sizeof(mutation->min_supported_version));
    if (mutation->version[0] == 'v') memmove(mutation->version, mutation->version + 1,
                                             strlen(mutation->version));
    if (mutation->min_supported_version[0] == 'v') {
        memmove(mutation->min_supported_version, mutation->min_supported_version + 1,
                strlen(mutation->min_supported_version));
    }
    (void)st_json_get_int(body, "displayOrder", &mutation->display_order);
    (void)st_json_get_bool(body, "enabled", &mutation->enabled);
    (void)st_json_get_i64(body, "fileSize", &mutation->file_size);
    (void)st_json_get_bool(body, "isLatest", &mutation->is_latest);
    if ((strcmp(mutation->implementation, "android") == 0
         && (strcmp(mutation->platform, "android") != 0 || strcmp(mutation->arch, "any") != 0))
        || (strcmp(mutation->platform, "android") == 0
            && (strcmp(mutation->implementation, "android") != 0
                || strcmp(mutation->arch, "any") != 0))) {
        response = write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"android packages require android/any\"}");
        goto done;
    }
    st_admin_semver release_version;
    st_admin_semver minimum_version;
    if ((mutation->version[0] != '\0' && parse_admin_semver(mutation->version, &release_version) != 0)
        || (mutation->min_supported_version[0] != '\0'
            && parse_admin_semver(mutation->min_supported_version, &minimum_version) != 0)
        || (mutation->min_supported_version[0] != '\0' && mutation->version[0] == '\0')
        || (mutation->min_supported_version[0] != '\0'
            && compare_admin_semver(&minimum_version, &release_version) > 0)) {
        response = write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"invalid version or minSupportedVersion\"}");
        goto done;
    }
    if (mutation->file_size < 0 || (mutation->sha256[0] != '\0' && !valid_sha256_text(mutation->sha256))) {
        response = write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"invalid fileSize or sha256\"}");
        goto done;
    }
    if (mutation->is_latest && (!mutation->enabled || mutation->version[0] == '\0')) {
        response = write_response(out, out_len, 400, "Bad Request",
                                  "{\"error\":\"an enabled version is required for latest\"}");
        goto done;
    }
    if (mutation->is_latest && (existing == NULL || !existing->hosted)
        && (admin_ascii_ncasecmp(mutation->download_url, "https://", 8U) != 0
            || !valid_sha256_text(mutation->sha256) || mutation->file_size <= 0)) {
        response = write_response(out, out_len, 400, "Bad Request",
            "{\"error\":\"an external latest download requires HTTPS, sha256 and a positive fileSize\"}");
        goto done;
    }
done:
    free(implementation);
    free(platform);
    free(arch);
    free(display_name);
    free(download_url);
    free(description);
    free(version);
    free(sha256);
    free(changelog_url);
    free(min_supported_version);
    return response;
}

static int client_download_same_target(const st_storage_client_download_link *left,
                                       const st_storage_client_download_link *right)
{
    return strcmp(left->implementation, right->implementation) == 0
        && strcmp(left->platform, right->platform) == 0
        && strcmp(left->arch, right->arch) == 0;
}

static int compare_client_download_order(const void *left_raw, const void *right_raw)
{
    const st_storage_client_download_link *left = left_raw;
    const st_storage_client_download_link *right = right_raw;
    if (left->display_order != right->display_order) {
        return left->display_order < right->display_order ? -1 : 1;
    }
    return left->id < right->id ? -1 : (left->id > right->id ? 1 : 0);
}

static int build_client_downloads_response(const st_admin_context *context,
                                           int enabled_only,
                                           char *out,
                                           size_t out_len)
{
    if (!enabled_only && !context->admin) return write_admin_forbidden(out, out_len);
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"client download list failed\"}");
        }
        st_storage_client_download_link catalogue[ST_ADMIN_MAX_CLIENT_DOWNLOADS];
        size_t catalogue_count = 0U;
        if (st_storage_list_client_download_links(database_path, 0, catalogue,
                ST_ADMIN_MAX_CLIENT_DOWNLOADS, &catalogue_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"client download list failed\"}");
        }
        st_storage_client_download_link links[
            ST_ADMIN_MAX_CLIENT_DOWNLOADS + ST_GITHUB_RELEASE_MAX_PACKAGES];
        size_t link_count = 0U;
        if (!enabled_only) {
            memcpy(links, catalogue, catalogue_count * sizeof(*links));
            link_count = catalogue_count;
        } else {
            for (size_t i = 0U; i < catalogue_count; ++i) {
                if (!catalogue[i].enabled) continue;
                int versioned_target = 0;
                for (size_t j = 0U; j < catalogue_count; ++j) {
                    if (client_download_same_target(&catalogue[i], &catalogue[j])
                        && catalogue[j].version[0] != '\0') {
                        versioned_target = 1;
                        break;
                    }
                }
                if ((versioned_target && catalogue[i].is_latest)
                    || (!versioned_target && catalogue[i].version[0] == '\0')) {
                    links[link_count++] = catalogue[i];
                }
            }
            st_storage_client_download_link fallback[ST_GITHUB_RELEASE_MAX_PACKAGES];
            size_t fallback_count = 0U;
            if (st_github_release_latest(fallback, ST_GITHUB_RELEASE_MAX_PACKAGES,
                                         &fallback_count) == 0) {
                for (size_t i = 0U; i < fallback_count; ++i) {
                    int configured = 0;
                    for (size_t j = 0U; j < catalogue_count; ++j) {
                        if (client_download_same_target(&fallback[i], &catalogue[j])) {
                            configured = 1;
                            break;
                        }
                    }
                    if (!configured && link_count < sizeof(links) / sizeof(links[0])) {
                        links[link_count++] = fallback[i];
                    }
                }
            }
            qsort(links, link_count, sizeof(*links), compare_client_download_order);
        }
        for (size_t i = 0U; rc == 0 && i < link_count; ++i) {
            rc = admin_sb_append(&builder, i == 0U ? "" : ",");
            if (rc == 0) rc = append_client_download_link_view(&builder, &links[i]);
        }
    }
    if (rc == 0) rc = admin_sb_append(&builder, "]");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"client download response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_client_download_result_response(const st_storage_client_download_link *link,
                                                 int status,
                                                 const char *reason,
                                                 char *out,
                                                 size_t out_len)
{
    st_admin_string_builder builder = {0};
    if (append_client_download_link_view(&builder, link) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"client download response failed\"}");
    }
    int response_len = write_response(out, out_len, status, reason, builder.data);
    free(builder.data);
    return response_len;
}

static int handle_client_download_create(const st_admin_context *context,
                                         const char *body,
                                         char *out,
                                         size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_admin_client_download_mutation mutation;
    int validation_response = read_client_download_mutation(body, NULL, &mutation, out, out_len);
    if (validation_response != 0) {
        return validation_response;
    }
    st_storage_client_download_link link;
    if (st_storage_upsert_client_download_link_extended(database_path, 0,
            mutation.implementation, mutation.platform, mutation.arch, mutation.display_name,
            mutation.download_url, mutation.description, mutation.display_order, mutation.enabled,
            mutation.version, mutation.sha256, mutation.file_size, mutation.is_latest,
            mutation.changelog_url, mutation.min_supported_version, 0, NULL, NULL, &link) != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"client download create failed\"}");
    }
    return build_client_download_result_response(&link, 201, "Created", out, out_len);
}

static int handle_client_package_upload(const st_admin_context *context,
                                        const char *content_type,
                                        const uint8_t *body,
                                        size_t body_len,
                                        char *out,
                                        size_t out_len)
{
    if (!context->admin) return write_admin_forbidden(out, out_len);
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) return init_response;
    st_storage_client_download_link link;
    int status = 400;
    char error[256];
    if (st_client_package_upload(database_path, content_type, body, body_len,
                                 &link, &status, error, sizeof(error)) != 0) {
        char *escaped = st_json_escape(error);
        if (escaped == NULL) {
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"client package upload failed\"}");
        }
        char response_body[512];
        int written = snprintf(response_body, sizeof(response_body), "{\"error\":\"%s\"}", escaped);
        free(escaped);
        if (written <= 0 || (size_t)written >= sizeof(response_body)) {
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"client package upload failed\"}");
        }
        return write_response(out, out_len, status, admin_reason_phrase(status), response_body);
    }
    return build_client_download_result_response(&link, 201, "Created", out, out_len);
}

static int handle_client_download_update(const st_admin_context *context,
                                         long long id,
                                         const char *body,
                                         char *out,
                                         size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    if (body == NULL) {
        body = "";
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    st_storage_client_download_link existing;
    if (st_storage_get_client_download_link(database_path, id, &existing) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client download not found\"}");
    }
    st_admin_client_download_mutation mutation;
    int validation_response = read_client_download_mutation(body, &existing, &mutation, out, out_len);
    if (validation_response != 0) {
        return validation_response;
    }
    st_storage_client_download_link link;
    if (st_storage_upsert_client_download_link_extended(database_path, id,
            mutation.implementation, mutation.platform, mutation.arch, mutation.display_name,
            mutation.download_url, mutation.description, mutation.display_order, mutation.enabled,
            mutation.version, mutation.sha256, mutation.file_size, mutation.is_latest,
            mutation.changelog_url, mutation.min_supported_version, existing.hosted,
            existing.package_path, existing.package_file_name, &link) != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"client download update failed\"}");
    }
    return build_client_download_result_response(&link, 200, "OK", out, out_len);
}

static int handle_client_download_mark_latest(const st_admin_context *context,
                                              long long id,
                                              char *out,
                                              size_t out_len)
{
    if (!context->admin) return write_admin_forbidden(out, out_len);
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) return init_response;
    st_storage_client_download_link existing;
    if (st_storage_get_client_download_link(database_path, id, &existing) != 0) {
        return write_response(out, out_len, 404, "Not Found",
                              "{\"error\":\"client download not found\"}");
    }
    st_admin_semver parsed;
    if (!existing.enabled || parse_admin_semver(existing.version, &parsed) != 0
        || (existing.hosted && !st_client_package_is_readable(&existing))
        || (!existing.hosted && (admin_ascii_ncasecmp(existing.download_url, "https://", 8U) != 0
            || !valid_sha256_text(existing.sha256) || existing.file_size <= 0))) {
        return write_response(out, out_len, 400, "Bad Request",
                              "{\"error\":\"download is not publishable as latest\"}");
    }
    st_storage_client_download_link updated;
    if (st_storage_mark_client_download_latest(database_path, id, &updated) != 0) {
        return write_response(out, out_len, 409, "Conflict",
                              "{\"error\":\"client download latest update failed\"}");
    }
    return build_client_download_result_response(&updated, 200, "OK", out, out_len);
}

static int build_client_version_check_response(const char *path, char *out, size_t out_len)
{
    char *implementation = admin_query_string(path, "implementation");
    char *platform = admin_query_string(path, "platform");
    char *arch = admin_query_string(path, "arch");
    char *current_text = admin_query_string(path, "current");
    char normalized_implementation[33];
    char normalized_platform[33];
    char normalized_arch[33];
    static const char *const implementations[] = {"java", "go", "csharp", "android"};
    static const char *const platforms[] = {"windows", "linux", "macos", "android", "any"};
    static const char *const archs[] = {"x64", "arm64", "any"};
    st_admin_semver current;
    int valid = normalize_client_download_enum(implementation, normalized_implementation,
            sizeof(normalized_implementation), implementations, 4U) == 0
        && normalize_client_download_enum(platform, normalized_platform,
            sizeof(normalized_platform), platforms, 5U) == 0
        && normalize_client_download_enum(arch, normalized_arch,
            sizeof(normalized_arch), archs, 3U) == 0
        && parse_admin_semver(current_text, &current) == 0;
    free(implementation); free(platform); free(arch); free(current_text);
    if (!valid) {
        return write_response(out, out_len, 400, "Bad Request",
                              "{\"error\":\"invalid client version target\"}");
    }
    const char *database_path = admin_database_path();
    st_storage_client_download_link links[ST_ADMIN_MAX_CLIENT_DOWNLOADS];
    size_t count = 0U;
    if (database_path == NULL || st_storage_list_client_download_links(database_path, 0, links,
            ST_ADMIN_MAX_CLIENT_DOWNLOADS, &count) != 0) {
        return write_response(out, out_len, 200, "OK",
            "{\"updateAvailable\":false,\"mandatory\":false,\"latestVersion\":null,"
            "\"downloadUrl\":null,\"sha256\":null,\"fileSize\":0,"
            "\"changelogUrl\":null,\"packageId\":null}");
    }
    st_storage_client_download_link *best = NULL;
    st_admin_semver best_version;
    int best_specificity = -1;
    for (size_t i = 0; i < count; ++i) {
        st_storage_client_download_link *candidate = &links[i];
        st_admin_semver candidate_version;
        if (!candidate->enabled || !candidate->is_latest
            || strcmp(candidate->implementation, normalized_implementation) != 0
            || (strcmp(candidate->platform, normalized_platform) != 0
                && strcmp(candidate->platform, "any") != 0)
            || (strcmp(candidate->arch, normalized_arch) != 0 && strcmp(candidate->arch, "any") != 0)
            || candidate->file_size <= 0 || !valid_sha256_text(candidate->sha256)
            || parse_admin_semver(candidate->version, &candidate_version) != 0
            || (!candidate->hosted
                && admin_ascii_ncasecmp(candidate->download_url, "https://", 8U) != 0)) continue;
        int specificity = (strcmp(candidate->platform, normalized_platform) == 0 ? 2 : 0)
            + (strcmp(candidate->arch, normalized_arch) == 0 ? 1 : 0);
        if (best == NULL || specificity > best_specificity
            || (specificity == best_specificity
                && compare_admin_semver(&candidate_version, &best_version) > 0)) {
            best = candidate;
            best_version = candidate_version;
            best_specificity = specificity;
        }
    }
    if (best == NULL) {
        int configured_target = 0;
        for (size_t i = 0U; i < count; ++i) {
            if (strcmp(links[i].implementation, normalized_implementation) == 0
                && (strcmp(links[i].platform, normalized_platform) == 0
                    || strcmp(links[i].platform, "any") == 0)
                && (strcmp(links[i].arch, normalized_arch) == 0
                    || strcmp(links[i].arch, "any") == 0)) {
                configured_target = 1;
                break;
            }
        }
        if (!configured_target) {
            st_storage_client_download_link fallback[ST_GITHUB_RELEASE_MAX_PACKAGES];
            size_t fallback_count = 0U;
            if (st_github_release_latest(fallback, ST_GITHUB_RELEASE_MAX_PACKAGES,
                                         &fallback_count) == 0) {
                for (size_t i = 0U; i < fallback_count; ++i) {
                    st_admin_semver candidate_version;
                    if (strcmp(fallback[i].implementation, normalized_implementation) != 0
                        || (strcmp(fallback[i].platform, normalized_platform) != 0
                            && strcmp(fallback[i].platform, "any") != 0)
                        || (strcmp(fallback[i].arch, normalized_arch) != 0
                            && strcmp(fallback[i].arch, "any") != 0)
                        || parse_admin_semver(fallback[i].version, &candidate_version) != 0) continue;
                    int specificity = (strcmp(fallback[i].platform, normalized_platform) == 0 ? 2 : 0)
                        + (strcmp(fallback[i].arch, normalized_arch) == 0 ? 1 : 0);
                    if (best == NULL || specificity > best_specificity
                        || (specificity == best_specificity
                            && compare_admin_semver(&candidate_version, &best_version) > 0)) {
                        links[0] = fallback[i];
                        best = &links[0];
                        best_version = candidate_version;
                        best_specificity = specificity;
                    }
                }
            }
        }
        if (best == NULL) {
            return write_response(out, out_len, 200, "OK",
                "{\"updateAvailable\":false,\"mandatory\":false,\"latestVersion\":null,"
                "\"downloadUrl\":null,\"sha256\":null,\"fileSize\":0,"
                "\"changelogUrl\":null,\"packageId\":null}");
        }
    }
    int update_available = compare_admin_semver(&best_version, &current) > 0;
    int mandatory = 0;
    st_admin_semver minimum;
    if (update_available && parse_admin_semver(best->min_supported_version, &minimum) == 0) {
        mandatory = compare_admin_semver(&current, &minimum) < 0;
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_appendf(&builder, "{\"updateAvailable\":%s,\"mandatory\":%s,\"latestVersion\":",
                              update_available ? "true" : "false", mandatory ? "true" : "false");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, best->version);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"downloadUrl\":");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, best->download_url);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"sha256\":");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, best->sha256);
    if (rc == 0) rc = admin_sb_appendf(&builder, ",\"fileSize\":%lld,\"changelogUrl\":", best->file_size);
    if (rc == 0) rc = admin_sb_append_nullable_json_string(&builder, best->changelog_url);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"packageId\":");
    if (rc == 0) rc = best->hosted
        ? admin_sb_appendf(&builder, "%lld", best->id) : admin_sb_append(&builder, "null");
    if (rc == 0) rc = admin_sb_append(&builder, "}");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"version check failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int handle_client_download_delete(const st_admin_context *context,
                                         long long id,
                                         char *out,
                                         size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    if (st_client_package_delete(database_path, id) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"client download not found\"}");
    }
    return write_response(out, out_len, 204, "No Content", "");
}

static int append_user_diagram_view(st_admin_string_builder *builder,
                                    const st_storage_user_diagram *diagram)
{
    int rc = admin_sb_appendf(builder, "{\"id\":%lld,\"name\":", diagram->id);
    if (rc == 0) rc = admin_sb_append_json_string(builder, diagram->name);
    if (rc == 0) rc = admin_sb_appendf(builder,
        ",\"sizeBytes\":%lld,\"revision\":%lld,\"createdAt\":",
        diagram->size_bytes, diagram->revision);
    if (rc == 0) rc = admin_sb_append_json_string(builder, diagram->created_at);
    if (rc == 0) rc = admin_sb_append(builder, ",\"updatedAt\":");
    if (rc == 0) rc = admin_sb_append_json_string(builder, diagram->updated_at);
    if (rc == 0) rc = admin_sb_append(builder, "}");
    return rc;
}

static int build_user_diagrams_response(const st_admin_context *context,
                                        char *out,
                                        size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL) return write_response(out, out_len, 200, "OK", "[]");
    st_storage_user_diagram diagrams[100];
    size_t count = 0U;
    if (st_storage_list_user_diagrams(database_path, context->tenant_id, context->username,
                                      diagrams, 100U, &count) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"diagram list failed\"}");
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "[");
    for (size_t i = 0; rc == 0 && i < count; ++i) {
        if (i > 0) rc = admin_sb_append(&builder, ",");
        if (rc == 0) rc = append_user_diagram_view(&builder, &diagrams[i]);
    }
    if (rc == 0) rc = admin_sb_append(&builder, "]");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"diagram response failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int build_user_diagram_detail_response(const st_admin_context *context,
                                              long long id,
                                              char *out,
                                              size_t out_len)
{
    const char *database_path = admin_database_path();
    st_storage_user_diagram diagram;
    if (database_path == NULL || st_storage_get_user_diagram(database_path, id,
            context->tenant_id, context->username, &diagram) != 0) {
        return write_response(out, out_len, 404, "Not Found",
                              "{\"error\":\"diagram not found\"}");
    }
    char *encoded = admin_base64_encode(diagram.snapshot_data, diagram.snapshot_len);
    st_admin_string_builder builder = {0};
    int rc = encoded == NULL ? -1 : admin_sb_append(&builder, "{\"document\":");
    if (rc == 0) rc = append_user_diagram_view(&builder, &diagram);
    if (rc == 0) rc = admin_sb_append(&builder, ",\"update\":");
    if (rc == 0) rc = admin_sb_append_json_string(&builder, encoded);
    if (rc == 0) rc = admin_sb_append(&builder, "}");
    free(encoded);
    st_storage_user_diagram_free(&diagram);
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"diagram response failed\"}");
    }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int read_user_diagram_mutation(const char *body,
                                      char name[121],
                                      uint8_t **snapshot,
                                      size_t *snapshot_len,
                                      char *out,
                                      size_t out_len)
{
    char *raw_name = st_json_get_top_level_string(body, "name");
    char *encoded = st_json_get_top_level_string(body, "update");
    char *trimmed = raw_name == NULL ? NULL : admin_trim(raw_name);
    if (!admin_text_present(trimmed) || strlen(trimmed) > 120U
        || strchr(trimmed, '\r') != NULL || strchr(trimmed, '\n') != NULL) {
        free(raw_name); free(encoded);
        return write_response(out, out_len, 400, "Bad Request",
                              "{\"error\":\"invalid diagram name\"}");
    }
    snprintf(name, 121U, "%s", trimmed);
    int decoded = admin_base64_decode_alloc(encoded, snapshot, snapshot_len);
    free(raw_name); free(encoded);
    return decoded == 0 ? 0 : write_response(out, out_len, 400, "Bad Request",
                                              "{\"error\":\"invalid diagram snapshot\"}");
}

static int handle_user_diagram_create(const st_admin_context *context,
                                      const char *body,
                                      char *out,
                                      size_t out_len)
{
    char name[121];
    uint8_t *snapshot = NULL;
    size_t snapshot_len = 0U;
    int validation = read_user_diagram_mutation(body, name, &snapshot, &snapshot_len, out, out_len);
    if (validation != 0) return validation;
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) { free(snapshot); return init_response; }
    st_storage_user_diagram diagram;
    int rc = st_storage_create_user_diagram(database_path, context->tenant_id, context->username,
                                            name, snapshot, snapshot_len, &diagram);
    free(snapshot);
    if (rc == 1) return write_response(out, out_len, 409, "Conflict",
                                       "{\"error\":\"diagram limit reached\"}");
    if (rc != 0) return write_response(out, out_len, 500, "Internal Server Error",
                                       "{\"error\":\"diagram create failed\"}");
    st_admin_string_builder builder = {0};
    rc = append_user_diagram_view(&builder, &diagram);
    st_storage_user_diagram_free(&diagram);
    if (rc != 0 || builder.data == NULL) { free(builder.data); return -1; }
    int len = write_response(out, out_len, 201, "Created", builder.data);
    free(builder.data);
    return len;
}

static int handle_user_diagram_update(const st_admin_context *context,
                                      long long id,
                                      const char *body,
                                      char *out,
                                      size_t out_len)
{
    long long revision = -1;
    if (st_json_get_i64(body, "revision", &revision) != 0 || revision < 0) {
        return write_response(out, out_len, 409, "Conflict",
                              "{\"error\":\"diagram revision conflict\"}");
    }
    char name[121];
    uint8_t *snapshot = NULL;
    size_t snapshot_len = 0U;
    int validation = read_user_diagram_mutation(body, name, &snapshot, &snapshot_len, out, out_len);
    if (validation != 0) return validation;
    const char *database_path = admin_database_path();
    st_storage_user_diagram existing;
    if (database_path == NULL || st_storage_get_user_diagram(database_path, id,
            context->tenant_id, context->username, &existing) != 0) {
        free(snapshot);
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"diagram not found\"}");
    }
    st_storage_user_diagram_free(&existing);
    st_storage_user_diagram updated;
    int rc = st_storage_update_user_diagram(database_path, id, context->tenant_id, context->username,
                                            revision, name, snapshot, snapshot_len, &updated);
    free(snapshot);
    if (rc == 1) return write_response(out, out_len, 409, "Conflict",
                                       "{\"error\":\"diagram revision conflict\"}");
    if (rc != 0) return write_response(out, out_len, 500, "Internal Server Error",
                                       "{\"error\":\"diagram update failed\"}");
    st_admin_string_builder builder = {0};
    rc = append_user_diagram_view(&builder, &updated);
    st_storage_user_diagram_free(&updated);
    if (rc != 0 || builder.data == NULL) { free(builder.data); return -1; }
    int len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return len;
}

static int handle_user_diagram_delete(const st_admin_context *context,
                                      long long id,
                                      char *out,
                                      size_t out_len)
{
    const char *database_path = admin_database_path();
    if (database_path == NULL || st_storage_delete_user_diagram(database_path, id,
            context->tenant_id, context->username) != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"diagram not found\"}");
    }
    return write_response(out, out_len, 204, "No Content", "");
}

static int append_management_user_view(st_admin_string_builder *builder,
                                       const char *username,
                                       const char *tenant_id,
                                       const char *role,
                                       int built_in,
                                       int enabled,
                                       const char *created_at,
                                       const char *updated_at)
{
    const char *normalized_role = normalize_management_role(role);
    int admin = strcmp(normalized_role, "ADMIN") == 0;
    int rc = admin_sb_append(builder, "{\"username\":");
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, username);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"tenantId\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, tenant_id == NULL || *tenant_id == '\0' ? "default" : tenant_id);
    }
    if (rc == 0) {
        rc = admin_sb_appendf(builder,
                              ",\"role\":\"%s\",\"admin\":%s,\"builtIn\":%s,\"enabled\":%s,"
                              "\"createdAt\":",
                              normalized_role,
                              admin ? "true" : "false",
                              built_in ? "true" : "false",
                              enabled ? "true" : "false");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, created_at == NULL ? "" : created_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, ",\"updatedAt\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(builder, updated_at == NULL ? "" : updated_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(builder, "}");
    }
    return rc;
}

static int append_stored_management_user_view(st_admin_string_builder *builder,
                                              const st_storage_management_user *user)
{
    return append_management_user_view(builder,
                                       user->username,
                                       user->tenant_id,
                                       user->role,
                                       0,
                                       user->enabled,
                                       user->created_at,
                                       user->updated_at);
}

static int build_management_me_response(const st_admin_context *context, char *out, size_t out_len)
{
    st_admin_string_builder builder = {0};
    int rc = append_management_user_view(&builder,
                                         context->username,
                                         context->tenant_id,
                                         context->role,
                                         admin_ascii_casecmp(context->username, env_text("SPECUS_AUTH_USERNAME", "admin")) == 0,
                                         1,
                                         "",
                                         "");
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"user response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int build_management_users_response(const st_admin_context *context, char *out, size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    st_admin_string_builder builder = {0};
    const char *tenant_id = context->tenant_id;
    int rc = admin_sb_append(&builder, "[");
    if (rc == 0) {
        rc = append_management_user_view(&builder,
                                         env_text("SPECUS_AUTH_USERNAME", "admin"),
                                         tenant_id,
                                         "ADMIN",
                                         1,
                                         1,
                                         "",
                                         "");
    }
    const char *database_path = admin_database_path();
    if (rc == 0 && database_path != NULL) {
        if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"user list failed\"}");
        }
        st_storage_management_user users[ST_ADMIN_MAX_CLIENTS];
        size_t user_count = 0;
        if (st_storage_list_management_users(database_path, tenant_id, users, ST_ADMIN_MAX_CLIENTS, &user_count) != 0) {
            free(builder.data);
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"user list failed\"}");
        }
        for (size_t i = 0; rc == 0 && i < user_count; ++i) {
            rc = admin_sb_append(&builder, ",");
            if (rc == 0) {
                rc = append_stored_management_user_view(&builder, &users[i]);
            }
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "]");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"user response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int normalize_username_in_place(char *username)
{
    if (username == NULL) {
        return -1;
    }
    char *trimmed = admin_trim(username);
    if (*trimmed == '\0' || strlen(trimmed) > 80U) {
        return -1;
    }
    if (trimmed != username) {
        memmove(username, trimmed, strlen(trimmed) + 1U);
    }
    return 0;
}

static int handle_management_user_create(const st_admin_context *context, const char *body, char *out, size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    if (body == NULL) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"request body is required\"}");
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    char *username = st_json_get_string(body, "username");
    char *password = st_json_get_string(body, "password");
    char *role = st_json_get_string(body, "role");
    int enabled = 1;
    (void)st_json_get_bool(body, "enabled", &enabled);
    if (normalize_username_in_place(username) != 0 || password == NULL || *admin_trim(password) == '\0') {
        free(username);
        free(password);
        free(role);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"username and password are required\"}");
    }
    st_storage_management_user existing_user;
    if (admin_ascii_casecmp(username, env_text("SPECUS_AUTH_USERNAME", "admin")) == 0
        || st_storage_get_management_user(database_path, username, &existing_user) == 0) {
        free(username);
        free(password);
        free(role);
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"username already exists\"}");
    }
    char hash[ST_PASSWORD_HASH_MAX_LEN + 1U];
    if (st_password_hash(admin_trim(password), hash) != 0) {
        free(username);
        free(password);
        free(role);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"password cannot be blank\"}");
    }
    st_storage_management_user user;
    int rc = st_storage_create_management_user(database_path,
                                               username,
                                               context->tenant_id,
                                               hash,
                                               normalize_management_role(role),
                                               enabled,
                                               &user);
    free(username);
    free(password);
    free(role);
    if (rc != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"user create failed\"}");
    }
    st_admin_string_builder builder = {0};
    if (append_stored_management_user_view(&builder, &user) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"user response failed\"}");
    }
    int response_len = write_response(out, out_len, 201, "Created", builder.data);
    free(builder.data);
    return response_len;
}

static char *admin_parse_user_path_username(const char *path)
{
    const char *prefix = "/api/admin/users/";
    size_t prefix_len = strlen(prefix);
    if (strncmp(path, prefix, prefix_len) != 0) {
        return NULL;
    }
    const char *cursor = path + prefix_len;
    const char *end = strchr(cursor, '?');
    size_t len = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
    if (len == 0) {
        return NULL;
    }
    return admin_url_decode(cursor, len);
}

static int handle_management_user_update(const st_admin_context *context,
                                         const char *path,
                                         const char *body,
                                         char *out,
                                         size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    if (body == NULL) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"request body is required\"}");
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    char *username = admin_parse_user_path_username(path);
    if (normalize_username_in_place(username) != 0) {
        free(username);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"username is required\"}");
    }
    if (admin_ascii_casecmp(username, env_text("SPECUS_AUTH_USERNAME", "admin")) == 0) {
        free(username);
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"built-in admin cannot be updated\"}");
    }
    st_storage_management_user existing;
    if (st_storage_get_management_user(database_path, username, &existing) != 0) {
        free(username);
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"user not found\"}");
    }
    char *password = st_json_get_string(body, "password");
    char *role = st_json_get_string(body, "role");
    int enabled = existing.enabled;
    (void)st_json_get_bool(body, "enabled", &enabled);
    char hash[ST_PASSWORD_HASH_MAX_LEN + 1U];
    const char *hash_ptr = NULL;
    if (password != NULL && *admin_trim(password) != '\0') {
        if (st_password_hash(admin_trim(password), hash) != 0) {
            free(username);
            free(password);
            free(role);
            return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"password cannot be blank\"}");
        }
        hash_ptr = hash;
    }
    st_storage_management_user user;
    int rc = st_storage_update_management_user(database_path,
                                               username,
                                               hash_ptr,
                                               role == NULL ? NULL : normalize_management_role(role),
                                               enabled,
                                               &user);
    free(username);
    free(password);
    free(role);
    if (rc != 0) {
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"user update failed\"}");
    }
    st_admin_string_builder builder = {0};
    if (append_stored_management_user_view(&builder, &user) != 0 || builder.data == NULL) {
        free(builder.data);
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"user response failed\"}");
    }
    int response_len = write_response(out, out_len, 200, "OK", builder.data);
    free(builder.data);
    return response_len;
}

static int handle_management_user_delete(const st_admin_context *context, const char *path, char *out, size_t out_len)
{
    if (!context->admin) {
        return write_admin_forbidden(out, out_len);
    }
    const char *database_path = NULL;
    int init_response = ensure_admin_database(&database_path, out, out_len);
    if (init_response != 0) {
        return init_response;
    }
    char *username = admin_parse_user_path_username(path);
    if (normalize_username_in_place(username) != 0) {
        free(username);
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"username is required\"}");
    }
    if (admin_ascii_casecmp(username, env_text("SPECUS_AUTH_USERNAME", "admin")) == 0) {
        free(username);
        return write_response(out, out_len, 409, "Conflict", "{\"error\":\"built-in admin cannot be deleted\"}");
    }
    int rc = st_storage_delete_management_user(database_path, username);
    free(username);
    if (rc != 0) {
        return write_response(out, out_len, 404, "Not Found", "{\"error\":\"user not found\"}");
    }
    return write_response(out, out_len, 204, "No Content", "");
}

static int write_management_token_response(const char *username,
                                           const char *tenant_id,
                                           const char *role,
                                           char *out,
                                           size_t out_len)
{
    long long ttl = st_security_token_ttl_seconds(getenv("SPECUS_AUTH_TOKEN_TTL_SECONDS"));
    char token[2048];
    if (st_security_issue_local_token(username,
                                      tenant_id,
                                      role,
                                      getenv("SPECUS_AUTH_JWT_SECRET"),
                                      ttl,
                                      token,
                                      sizeof(token)) != 0) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"token issue failed\"}");
    }
    char *escaped_token = st_json_escape(token);
    if (escaped_token == NULL) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"token response failed\"}");
    }
    char body[2300];
    int written = snprintf(body,
                           sizeof(body),
                           "{\"accessToken\":\"%s\",\"tokenType\":\"Bearer\",\"expiresIn\":%lld}",
                           escaped_token,
                           ttl);
    free(escaped_token);
    if (written < 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"token response failed\"}");
    }
    return write_response(out, out_len, 200, "OK", body);
}

static int handle_management_auth_login(const char *body,
                                        const char *remote_address,
                                        char *out,
                                        size_t out_len)
{
    if (body == NULL) {
        return write_response(out, out_len, 401, "Unauthorized", "{\"error\":\"用户名或密码错误\"}");
    }
    char *username = st_json_get_string(body, "username");
    char *password = st_json_get_string(body, "password");
    char *turnstile_token = st_json_get_string(body, "turnstileToken");
    st_login_rate_limit_config rate_limit = management_login_rate_limit_config();
    int64_t retry_after_seconds = 0;
    time_t now = time(NULL);
    if (st_login_rate_limiter_check(remote_address,
                                    username,
                                    &rate_limit,
                                    now < 0 ? 0 : (int64_t)now,
                                    &retry_after_seconds) != 0) {
        free(username);
        free(password);
        free(turnstile_token);
        return write_login_rate_limited_response(out, out_len, retry_after_seconds);
    }
    int turnstile_status = 400;
    char turnstile_error[256];
    if (st_auth_turnstile_verify(turnstile_token, "login", &turnstile_status,
                                 turnstile_error, sizeof(turnstile_error)) != 0) {
        free(username);
        free(password);
        free(turnstile_token);
        return write_registration_error_response(turnstile_status, turnstile_error, out, out_len);
    }
    free(turnstile_token);
    if (normalize_username_in_place(username) != 0 || password == NULL) {
        free(username);
        free(password);
        return write_response(out, out_len, 401, "Unauthorized", "{\"error\":\"用户名或密码错误\"}");
    }
    int ok = 0;
    char token_username[ST_SECURITY_TOKEN_USERNAME_LEN + 1];
    char token_tenant[ST_SECURITY_TOKEN_TENANT_LEN + 1];
    char token_role[ST_SECURITY_TOKEN_ROLE_LEN + 1];
    snprintf(token_username, sizeof(token_username), "%s", username);
    snprintf(token_tenant, sizeof(token_tenant), "%s", env_text("SPECUS_AUTH_TENANT_ID", "default"));
    snprintf(token_role, sizeof(token_role), "%s", "USER");
    if (admin_ascii_casecmp(username, env_text("SPECUS_AUTH_USERNAME", "admin")) == 0) {
        const char *admin_password = getenv("SPECUS_AUTH_PASSWORD");
        if (admin_password == NULL) {
            admin_password = "";
        }
        uint8_t expected[ST_SHA256_LEN];
        uint8_t actual[ST_SHA256_LEN];
        st_sha256((const uint8_t *)admin_password, strlen(admin_password), expected);
        st_sha256((const uint8_t *)password, strlen(password), actual);
        ok = management_password_login_enabled()
            && st_constant_time_eq(expected, actual, sizeof(expected));
        if (ok) {
            snprintf(token_username, sizeof(token_username), "%s", env_text("SPECUS_AUTH_USERNAME", "admin"));
            snprintf(token_tenant, sizeof(token_tenant), "%s", env_text("SPECUS_AUTH_TENANT_ID", "default"));
            snprintf(token_role, sizeof(token_role), "%s", "ADMIN");
        }
    } else {
        const char *database_path = admin_database_path();
        if (database_path != NULL
            && st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) == 0) {
            st_storage_management_user user;
            st_password_verification verification;
            ok = st_storage_get_management_user(database_path, username, &user) == 0
                && user.enabled
                && st_password_verify(password, user.password_hash, &verification) == 0
                && verification.matches;
            if (ok) {
                if (verification.needs_upgrade) {
                    (void)st_storage_update_management_user(database_path,
                                                            user.username,
                                                            verification.upgraded_hash,
                                                            NULL,
                                                            user.enabled,
                                                            NULL);
                }
                snprintf(token_username, sizeof(token_username), "%s", user.username);
                snprintf(token_tenant, sizeof(token_tenant), "%s", user.tenant_id);
                snprintf(token_role, sizeof(token_role), "%s", normalize_management_role(user.role));
            }
        }
    }
    if (ok) {
        st_login_rate_limiter_record_success(username);
    }
    free(username);
    free(password);
    if (!ok) {
        return write_response(out, out_len, 401, "Unauthorized", "{\"error\":\"用户名或密码错误\"}");
    }
    return write_management_token_response(token_username, token_tenant, token_role, out, out_len);
}

static int handle_management_auth_refresh(const st_admin_context *context, char *out, size_t out_len)
{
    if (context == NULL || !context->authenticated) {
        return write_admin_unauthorized(out, out_len);
    }
    return write_management_token_response(context->username, context->tenant_id, context->role, out, out_len);
}

static int write_registration_error_response(int status,
                                             const char *error,
                                             char *out,
                                             size_t out_len)
{
    char *escaped = st_json_escape(error == NULL ? "注册请求失败" : error);
    if (escaped == NULL) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"registration response failed\"}");
    }
    char body[512];
    int written = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    free(escaped);
    if (written <= 0 || (size_t)written >= sizeof(body)) {
        return write_response(out, out_len, 500, "Internal Server Error",
                              "{\"error\":\"registration response failed\"}");
    }
    return write_response(out, out_len, status, admin_reason_phrase(status), body);
}

static int handle_management_registration_request(const char *body, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    st_registration_challenge_response challenge;
    int status = 400;
    char error[256];
    if (st_registration_request(database_path, body, &challenge,
                                &status, error, sizeof(error)) != 0) {
        return write_registration_error_response(status, error, out, out_len);
    }
    char *registration_id = st_json_escape(challenge.registration_id);
    char *email_masked = st_json_escape(challenge.email_masked);
    char *expires_at = st_json_escape(challenge.expires_at);
    if (registration_id == NULL || email_masked == NULL || expires_at == NULL) {
        free(registration_id); free(email_masked); free(expires_at);
        return write_registration_error_response(500, "registration response failed", out, out_len);
    }
    char response_body[1024];
    int written = snprintf(response_body, sizeof(response_body),
        "{\"registrationId\":\"%s\",\"emailMasked\":\"%s\","
        "\"expiresAt\":\"%s\",\"resendAfterSeconds\":%lld}",
        registration_id, email_masked, expires_at, challenge.resend_after_seconds);
    free(registration_id); free(email_masked); free(expires_at);
    if (written <= 0 || (size_t)written >= sizeof(response_body)) {
        return write_registration_error_response(500, "registration response failed", out, out_len);
    }
    return write_response(out, out_len, 202, "Accepted", response_body);
}

static int handle_management_registration_verify(const char *body, char *out, size_t out_len)
{
    const char *database_path = admin_database_path();
    st_storage_management_user user;
    int status = 400;
    char error[256];
    if (st_registration_verify(database_path, body, &user, &status, error, sizeof(error)) != 0) {
        return write_registration_error_response(status, error, out, out_len);
    }
    return write_management_token_response(user.username, user.tenant_id, user.role, out, out_len);
}

static int st_admin_build_response_internal(const char *method,
                                            const char *path,
                                            const char *authorization,
                                            const char *oss_public_key_url,
                                            const char *range_header,
                                            const char *host_header,
                                            const char *content_type,
                                            const char *body,
                                            size_t body_len,
                                            const char *remote_address,
                                            int allow_default_admin,
                                            char *out,
                                            size_t out_len)
{
    if (method == NULL || path == NULL) {
        return write_response(out, out_len, 400, "Bad Request", "{\"error\":\"bad request\"}");
    }
    st_admin_context context;
    admin_context_from_env(&context);
    if (admin_path_requires_auth(method, path)) {
        if (authorization != NULL) {
            if (admin_context_from_authorization(authorization, &context) != 0) {
                return write_admin_unauthorized(out, out_len);
            }
        } else if (!allow_default_admin) {
            return write_admin_unauthorized(out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/health")) {
        return write_response(out, out_len, 200, "OK", "{\"status\":\"ok\"}");
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/public/peer-mesh/stun-config")) {
        return build_public_stun_config_response(host_header, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/public/transfer/ice-config")) {
        return build_public_ice_config_response(host_header, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/public/peer-mesh/nat-probe-config")) {
        return build_public_nat_probe_config_response(host_header, out, out_len);
    }
    if (strcmp(method, "POST") == 0
        && admin_path_equals(path, "/api/public/transfer/ws-tickets")) {
        return st_public_discovery_issue_ticket_response(body, remote_address, out, out_len);
    }
    if (strcmp(method, "GET") == 0
        && admin_path_equals(path, "/api/public/transfer/clients/name-availability")) {
        return st_public_discovery_name_availability_response(path, out, out_len);
    }
    st_object_storage_identity attachment_identity = {
        .tenant_id = context.tenant_id,
        .username = context.username,
        .admin = context.admin,
        .authenticated = context.authenticated
    };
    int attachment_response = st_object_storage_build_response(method,
                                                                path,
                                                                body,
                                                                remote_address,
                                                                authorization,
                                                                oss_public_key_url,
                                                                &attachment_identity,
                                                                out,
                                                                out_len);
    if (attachment_response != 0) {
        return attachment_response;
    }
    if (strncmp(path, "/api/admin/traffic/media-captures",
                strlen("/api/admin/traffic/media-captures")) == 0
        || strncmp(path, "/api/public/media-playback/",
                   strlen("/api/public/media-playback/")) == 0) {
        const char *media_database_path = admin_database_path();
        if (media_database_path == NULL
            || st_storage_init(media_database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
            return write_response(out, out_len, 500, "Internal Server Error",
                                  "{\"error\":\"media capture database unavailable\"}");
        }
        st_media_capture_identity media_identity = {
            .tenant_id = context.tenant_id,
            .username = context.username,
            .admin = context.admin,
            .authenticated = context.authenticated
        };
        int media_response = st_media_capture_build_response_with_range(method,
                                                                        path,
                                                                        range_header,
                                                                        &media_identity,
                                                                        media_database_path,
                                                                        out,
                                                                        out_len);
        if (media_response != 0) {
            return media_response;
        }
    }
    int public_room_response = st_public_room_build_response(method,
                                                             path,
                                                             body,
                                                             remote_address,
                                                             out,
                                                             out_len);
    if (public_room_response != 0) {
        return public_room_response;
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/ws-tickets")) {
        return handle_admin_websocket_ticket(&context, body, remote_address, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/overview")) {
        return build_overview_response(&context, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/metrics")) {
        return build_metrics_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/database/initialize")) {
        return handle_database_initialize(&context, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/public/client-downloads")) {
        long long retry_after = 1;
        if (st_client_package_rate_limit(remote_address, &retry_after) != 0) {
            return write_client_package_rate_limited_response(out, out_len, retry_after);
        }
        return build_client_downloads_response(&context, 1, out, out_len);
    }
    if (strcmp(method, "GET") == 0
        && admin_path_equals(path, "/api/public/client-version-check")) {
        long long retry_after = 1;
        if (st_client_package_rate_limit(remote_address, &retry_after) != 0) {
            return write_client_package_rate_limited_response(out, out_len, retry_after);
        }
        return build_client_version_check_response(path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/client-downloads")) {
        return build_client_downloads_response(&context, 0, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/client-downloads")) {
        return handle_client_download_create(&context, body, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/client-packages")) {
        return handle_client_package_upload(&context, content_type, (const uint8_t *)body,
                                            body_len, out, out_len);
    }
    long long path_id = 0;
    if (strcmp(method, "POST") == 0
        && admin_parse_nested_path_id(path, "/api/admin/client-downloads/", "/latest", &path_id) == 0) {
        return handle_client_download_mark_latest(&context, path_id, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/client-downloads/", &path_id) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_client_download_update(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_client_download_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/client-credentials")) {
        return build_credentials_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/client-credentials")) {
        return handle_credential_create(&context, body, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/client-credentials/", &path_id) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_credential_update(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_credential_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/clients")) {
        return build_clients_response(&context, out, out_len);
    }
    if (strcmp(method, "GET") == 0
        && admin_path_equals(path, "/api/admin/clients/name-availability")) {
        return build_client_name_availability_response(&context, path, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/clients")) {
        return handle_client_create(&context, body, out, out_len);
    }
    if (strcmp(method, "POST") == 0
        && admin_parse_nested_path_id(path, "/api/admin/clients/",
                                      "/force-refresh-port-mapping", &path_id) == 0) {
        return handle_nat_control_push(&context, path_id, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/clients/", &path_id) == 0) {
        if (strcmp(method, "GET") == 0) {
            return build_client_detail_response(&context, path_id, out, out_len);
        }
        if (strcmp(method, "PUT") == 0) {
            return handle_client_update(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_client_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/specus-mappings")) {
        return build_specusMappings_response(&context, path, out, out_len);
    }
    if (strcmp(method, "POST") == 0
        && admin_parse_nested_path_id(path, "/api/admin/clients/", "/specus-mappings", &path_id) == 0) {
        return handle_specus_create(&context, path_id, body, out, out_len);
    }
    if (strcmp(method, "POST") == 0
        && admin_parse_nested_path_id(path, "/api/admin/clients/", "/nat-control", &path_id) == 0) {
        return handle_nat_control_push(&context, path_id, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/specus-mappings/", &path_id) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_specus_update(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_specus_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/http-routes")) {
        return build_http_routes_response(&context, path, out, out_len);
    }
    if (strcmp(method, "POST") == 0
        && admin_parse_nested_path_id(path, "/api/admin/clients/", "/http-routes", &path_id) == 0) {
        return handle_http_route_create(&context, path_id, body, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/http-routes/", &path_id) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_http_route_update(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_http_route_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/connections")) {
        return build_connections_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/connection-stats")) {
        return build_connection_stats_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/traffic")) {
        return build_traffic_usage_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/traffic/resources")) {
        return build_resource_traffic_usage_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/traffic/http-exchanges")) {
        return build_http_exchanges_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0
        && admin_parse_path_id(path, "/api/admin/traffic/http-exchanges/", &path_id) == 0) {
        return build_http_exchange_detail_response(&context, path_id, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/traffic/tcp-frames")) {
        return build_tcp_frames_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/traffic/tcp-streams")) {
        return build_tcp_stream_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0
        && admin_path_equals(path, "/api/admin/traffic/inspection-status")) {
        return build_traffic_inspection_status_response(out, out_len);
    }
    if (strcmp(method, "GET") == 0
        && admin_parse_path_id(path, "/api/admin/traffic/tcp-frames/", &path_id) == 0) {
        return build_tcp_frame_detail_response(&context, path_id, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/status")) {
        char status_body[32];
        int written = snprintf(status_body,
                               sizeof(status_body),
                               "{\"enabled\":%s}",
                               env_bool("SPECUS_PEER_MESH_ENABLED", 0) ? "true" : "false");
        if (written < 0 || (size_t)written >= sizeof(status_body)) {
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"peer mesh status failed\"}");
        }
        return write_response(out, out_len, 200, "OK", status_body);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/devices")) {
        return build_peer_mesh_devices_response(&context, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/acls")) {
        return build_peer_mesh_acls_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/acls")) {
        return handle_peer_mesh_acl_create(&context, body, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/sessions")) {
        return build_peer_mesh_sessions_response(&context, path, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/stats")) {
        return build_peer_mesh_stats_response(&context, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/service-sharing")) {
        return build_peer_mesh_sharing_response(&context, out, out_len);
    }
    if (strcmp(method, "PUT") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/service-sharing")) {
        return handle_peer_mesh_sharing_update(&context, body, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/services")) {
        return build_peer_mesh_services_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/services")) {
        return handle_peer_mesh_service_mutation(&context, 0, body, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/services/import")) {
        return handle_peer_mesh_service_import(&context, body, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/egress/policies")) {
        return build_peer_mesh_egress_policies_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/egress/policies")) {
        return handle_peer_mesh_egress_policy_mutation(&context, body, out, out_len);
    }
    if (strcmp(method, "DELETE")== 0
        && admin_parse_path_id(path, "/api/admin/peer-mesh/egress/policies/", &path_id) == 0) {
        return handle_peer_mesh_egress_policy_delete(&context, path_id, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/service-audit")) {
        return build_peer_mesh_service_audit_response(&context, out, out_len);
    }
    if (strcmp(method, "DELETE") == 0 && admin_path_equals(path, "/api/admin/peer-mesh/sessions")) {
        return handle_peer_mesh_sessions_close_open(&context, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/peer-mesh/sessions/", &path_id) == 0) {
        if (strcmp(method, "DELETE") == 0) {
            return handle_peer_mesh_session_close(&context, path_id, out, out_len);
        }
    }
    if (admin_parse_path_id(path, "/api/admin/peer-mesh/devices/", &path_id) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_peer_mesh_device_update(&context, path_id, body, out, out_len);
        }
    }
    if (admin_parse_path_id(path, "/api/admin/peer-mesh/acls/", &path_id) == 0) {
        if (strcmp(method, "DELETE") == 0) {
            return handle_peer_mesh_acl_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/diagrams")) {
        return build_user_diagrams_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/diagrams")) {
        return handle_user_diagram_create(&context, body, out, out_len);
    }
    if (admin_parse_path_id(path, "/api/admin/diagrams/", &path_id) == 0) {
        if (strcmp(method, "GET") == 0) {
            return build_user_diagram_detail_response(&context, path_id, out, out_len);
        }
        if (strcmp(method, "PUT") == 0) {
            return handle_user_diagram_update(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_user_diagram_delete(&context, path_id, out, out_len);
        }
    }
    if (admin_parse_path_id(path, "/api/admin/peer-mesh/services/", &path_id) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_peer_mesh_service_mutation(&context, path_id, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_peer_mesh_service_delete(&context, path_id, out, out_len);
        }
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/me")) {
        return build_management_me_response(&context, out, out_len);
    }
    if (strcmp(method, "GET") == 0 && admin_path_equals(path, "/api/admin/users")) {
        return build_management_users_response(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/admin/users")) {
        return handle_management_user_create(&context, body, out, out_len);
    }
    if (strncmp(path, "/api/admin/users/", strlen("/api/admin/users/")) == 0) {
        if (strcmp(method, "PUT") == 0) {
            return handle_management_user_update(&context, path, body, out, out_len);
        }
        if (strcmp(method, "DELETE") == 0) {
            return handle_management_user_delete(&context, path, out, out_len);
        }
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/auth/login")) {
        return handle_management_auth_login(body, remote_address, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/auth/register")) {
        return handle_management_registration_request(body, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/auth/register/verify")) {
        return handle_management_registration_verify(body, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/auth/refresh")) {
        return handle_management_auth_refresh(&context, out, out_len);
    }
    if (strcmp(method, "POST") == 0 && admin_path_equals(path, "/api/client/auth/login")) {
        return build_client_auth_login_response(body, out, out_len);
    }
    if (strncmp(path, "/http/", 6) == 0) {
        return write_response(out,
                              out_len,
                              501,
                              "Not Implemented",
                              "{\"error\":\"direct http dispatch is not wired yet\"}");
    }
    if (admin_path_equals(path, "/ws/connections")
        || admin_path_equals(path, "/ws/client-messages")
        || admin_path_equals(path, "/ws/public-transfer/discovery")) {
        return write_response(out,
                              out_len,
                              426,
                              "Upgrade Required",
                              "{\"error\":\"websocket upgrade required\"}");
    }
    if (strcmp(method, "GET") == 0 && strcmp(path, "/oidc-config") == 0) {
        char body[1024];
        int turnstile_available = st_auth_turnstile_available();
        if (st_security_build_oidc_config_extended(getenv("SPECUS_OIDC_CLIENT_ID"),
                                                   env_text("SPECUS_OIDC_AUTHORIZATION_ENDPOINT",
                                                            "https://certus.devshuai.com/oauth2/authorize"),
                                                   env_text("SPECUS_OIDC_REGISTRATION_ENDPOINT",
                                                            "https://certus.devshuai.com/register"),
                                                   env_text("SPECUS_OIDC_END_SESSION_ENDPOINT",
                                                            "https://certus.devshuai.com/oauth2/logout"),
                                                   env_text("SPECUS_OIDC_REDIRECT_URI",
                                                            "http://127.0.0.1:8088/"),
                                                   env_text("SPECUS_OIDC_SCOPE", "openid profile email"),
                                                   management_password_login_enabled(),
                                                   st_registration_available(),
                                                   turnstile_available,
                                                   turnstile_available
                                                       ? getenv("SPECUS_AUTH_TURNSTILE_SITE_KEY") : "",
                                                   body,
                                                   sizeof(body)) < 0) {
            return write_response(out, out_len, 500, "Internal Server Error", "{\"error\":\"oidc config failed\"}");
        }
        return write_response(out, out_len, 200, "OK", body);
    }
    if (strcmp(method, "POST") == 0 && strcmp(path, "/oidc/token") == 0) {
        return build_oidc_token_proxy_response(body, out, out_len);
    }
    return write_response(out, out_len, 404, "Not Found", "{\"error\":\"not found\"}");
}

int st_admin_build_response_with_auth(const char *method,
                                      const char *path,
                                      const char *authorization,
                                      const char *body,
                                      char *out,
                                      size_t out_len)
{
    return st_admin_build_response_internal(method, path, authorization, NULL, NULL, NULL,
                                            NULL, body, body == NULL ? 0U : strlen(body),
                                            "", 0, out, out_len);
}

int st_admin_build_response_with_content(const char *method,
                                         const char *path,
                                         const char *authorization,
                                         const char *content_type,
                                         const uint8_t *body,
                                         size_t body_len,
                                         char *out,
                                         size_t out_len)
{
    return st_admin_build_response_internal(method, path, authorization, NULL, NULL, NULL,
                                            content_type, (const char *)body, body_len,
                                            "", authorization == NULL, out, out_len);
}

int st_admin_build_response_with_body(const char *method,
                                      const char *path,
                                      const char *body,
                                      char *out,
                                      size_t out_len)
{
    return st_admin_build_response_internal(method, path, NULL, NULL, NULL, NULL,
                                            NULL, body, body == NULL ? 0U : strlen(body),
                                            "", 1, out, out_len);
}

int st_admin_build_response_with_remote(const char *method,
                                        const char *path,
                                        const char *body,
                                        const char *remote_address,
                                        char *out,
                                        size_t out_len)
{
    return st_admin_build_response_internal(method,
                                            path,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            NULL,
                                            body,
                                            body == NULL ? 0U : strlen(body),
                                            remote_address == NULL ? "" : remote_address,
                                            1,
                                            out,
                                            out_len);
}

int st_admin_build_response(const char *method, const char *path, char *out, size_t out_len)
{
    return st_admin_build_response_with_body(method, path, NULL, out, out_len);
}

int st_admin_resolve_static_path(const char *static_root,
                                 const char *request_path,
                                 char *file_path,
                                 size_t file_path_len,
                                 const char **content_type)
{
    if (static_root == NULL || *static_root == '\0'
        || request_path == NULL || request_path[0] != '/'
        || strstr(request_path, "..") != NULL) {
        return -1;
    }
    const char *relative = request_path[1] == '\0' ? "index.html" : request_path + 1;
    const char *query = strchr(relative, '?');
    size_t relative_len = query == NULL ? strlen(relative) : (size_t)(query - relative);
    if (relative_len == 0) {
        relative = "index.html";
        relative_len = strlen(relative);
    }
    int written = snprintf(file_path, file_path_len, "%s/%.*s", static_root, (int)relative_len, relative);
    if (written < 0 || (size_t)written >= file_path_len) {
        return -1;
    }
    const char *dot = strrchr(file_path, '.');
    if (dot != NULL && strcmp(dot, ".html") == 0) {
        *content_type = "text/html; charset=utf-8";
    } else if (dot != NULL && strcmp(dot, ".js") == 0) {
        *content_type = "application/javascript; charset=utf-8";
    } else if (dot != NULL && strcmp(dot, ".css") == 0) {
        *content_type = "text/css; charset=utf-8";
    } else {
        *content_type = "application/octet-stream";
    }
    return 0;
}

static int send_all(int fd, const char *buffer, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t sent = send(fd, buffer + offset, len - offset, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        offset += (size_t)sent;
    }
    return 0;
}

static int hex_nibble(char value)
{
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

static char *admin_url_decode(const char *value, size_t len)
{
    char *out = (char *)malloc(len + 1U);
    if (out == NULL) {
        return NULL;
    }
    size_t w = 0;
    for (size_t i = 0; i < len; ++i) {
        if (value[i] == '%' && i + 2U < len) {
            int high = hex_nibble(value[i + 1U]);
            int low = hex_nibble(value[i + 2U]);
            if (high >= 0 && low >= 0) {
                out[w++] = (char)((high << 4) | low);
                i += 2U;
                continue;
            }
        }
        out[w++] = value[i] == '+' ? ' ' : value[i];
    }
    out[w] = '\0';
    return out;
}

static int admin_snapshot_base64_value(unsigned char value)
{
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

static int admin_base64_decode_alloc(const char *encoded, uint8_t **out, size_t *out_len)
{
    size_t len = encoded == NULL ? 0U : strlen(encoded);
    *out = NULL;
    *out_len = 0U;
    if (len == 0U || len > 4U * 1024U * 1024U + 16U || len % 4U != 0U) return -1;
    size_t capacity = (len / 4U) * 3U;
    uint8_t *decoded = (uint8_t *)malloc(capacity == 0U ? 1U : capacity);
    if (decoded == NULL) return -1;
    for (size_t i = 0U; i < len; i += 4U) {
        int a = admin_snapshot_base64_value((unsigned char)encoded[i]);
        int b = admin_snapshot_base64_value((unsigned char)encoded[i + 1U]);
        int c = encoded[i + 2U] == '=' ? -2
            : admin_snapshot_base64_value((unsigned char)encoded[i + 2U]);
        int d = encoded[i + 3U] == '=' ? -2
            : admin_snapshot_base64_value((unsigned char)encoded[i + 3U]);
        if (a < 0 || b < 0 || c == -1 || d == -1 || (c == -2 && d != -2)
            || ((c == -2 || d == -2) && i + 4U != len)) {
            free(decoded);
            return -1;
        }
        uint32_t value = (uint32_t)a << 18U | (uint32_t)b << 12U;
        if (c >= 0) value |= (uint32_t)c << 6U;
        if (d >= 0) value |= (uint32_t)d;
        decoded[(*out_len)++] = (uint8_t)(value >> 16U);
        if (c >= 0) decoded[(*out_len)++] = (uint8_t)(value >> 8U);
        if (d >= 0) decoded[(*out_len)++] = (uint8_t)value;
    }
    if (*out_len == 0U || *out_len > 3U * 1024U * 1024U) {
        free(decoded);
        *out_len = 0U;
        return -1;
    }
    *out = decoded;
    return 0;
}

/* The public listener deliberately accepts raw query braces used by some legacy web apps.
 * Encode only those relaxed characters before they leave the server so every client can build a
 * standards-compliant upstream URI without changing any other byte in the original query. */
static char *admin_encode_raw_query_for_forwarding(const char *value)
{
    if (value == NULL) {
        return admin_dup_string("");
    }
    size_t len = strlen(value);
    if (len > (SIZE_MAX - 1U) / 3U) {
        return NULL;
    }
    char *encoded = (char *)malloc(len * 3U + 1U);
    if (encoded == NULL) {
        return NULL;
    }
    size_t written = 0U;
    for (size_t i = 0; i < len; ++i) {
        if (value[i] == '{' || value[i] == '}') {
            const char *escape = value[i] == '{' ? "%7B" : "%7D";
            memcpy(encoded + written, escape, 3U);
            written += 3U;
        } else {
            encoded[written++] = value[i];
        }
    }
    encoded[written] = '\0';
    return encoded;
}

static int admin_parse_content_length(const char *request,
                                      size_t max_content_length,
                                      size_t *content_length)
{
    *content_length = 0;
    const char *line = strstr(request, "\r\n");
    if (line == NULL) {
        return 0;
    }
    line += 2;
    while (*line != '\0' && !(line[0] == '\r' && line[1] == '\n')) {
        const char *next = strstr(line, "\r\n");
        if (next == NULL) {
            break;
        }
        const char *colon = memchr(line, ':', (size_t)(next - line));
        if (colon != NULL && (size_t)(colon - line) == strlen("Content-Length")
            && admin_ascii_ncasecmp(line, "Content-Length", strlen("Content-Length")) == 0) {
            char *end = NULL;
            unsigned long long parsed = strtoull(colon + 1, &end, 10);
            if (end == colon + 1) {
                return -1;
            }
            if (parsed > max_content_length || parsed > (unsigned long long)SIZE_MAX) {
                return -2;
            }
            *content_length = (size_t)parsed;
            return 0;
        }
        line = next + 2;
    }
    return 0;
}

static char *admin_extract_header_value(const char *request, const char *name)
{
    const char *line = strstr(request, "\r\n");
    if (line == NULL) {
        return NULL;
    }
    line += 2;
    size_t name_len = strlen(name);
    while (*line != '\0' && !(line[0] == '\r' && line[1] == '\n')) {
        const char *next = strstr(line, "\r\n");
        if (next == NULL) {
            break;
        }
        const char *colon = memchr(line, ':', (size_t)(next - line));
        if (colon != NULL && (size_t)(colon - line) == name_len
            && admin_ascii_ncasecmp(line, name, name_len) == 0) {
            const char *value = colon + 1;
            while (value < next && isspace((unsigned char)*value)) {
                ++value;
            }
            while (next > value && isspace((unsigned char)*(next - 1))) {
                --next;
            }
            size_t len = (size_t)(next - value);
            char *copy = (char *)malloc(len + 1U);
            if (copy == NULL) {
                return NULL;
            }
            memcpy(copy, value, len);
            copy[len] = '\0';
            return copy;
        }
        line = next + 2;
    }
    return NULL;
}

static int admin_header_name_equals(const char *line, const char *name)
{
    const char *colon = strchr(line, ':');
    if (colon == NULL) {
        return 0;
    }
    size_t len = (size_t)(colon - line);
    return len == strlen(name) && admin_ascii_ncasecmp(line, name, len) == 0;
}

static int admin_skip_response_header(const char *line)
{
    return admin_header_name_equals(line, "Content-Length")
        || admin_header_name_equals(line, "Transfer-Encoding")
        || admin_header_name_equals(line, "Connection")
        || admin_header_name_equals(line, "Keep-Alive")
        || admin_header_name_equals(line, "Proxy-Authenticate")
        || admin_header_name_equals(line, "Proxy-Authorization")
        || admin_header_name_equals(line, "TE")
        || admin_header_name_equals(line, "Trailer")
        || admin_header_name_equals(line, "Upgrade");
}

static int admin_skip_direct_request_header(const char *line)
{
    return admin_header_name_equals(line, "Connection")
        || admin_header_name_equals(line, "Content-Length")
        || admin_header_name_equals(line, "Host")
        || admin_header_name_equals(line, "Keep-Alive")
        || admin_header_name_equals(line, "Proxy-Authenticate")
        || admin_header_name_equals(line, "Proxy-Authorization")
        || admin_header_name_equals(line, "TE")
        || admin_header_name_equals(line, "Trailer")
        || admin_header_name_equals(line, "Transfer-Encoding")
        || admin_header_name_equals(line, "Upgrade")
        || admin_header_name_equals(line, "Sec-WebSocket-Key")
        || admin_header_name_equals(line, "Sec-WebSocket-Version")
        || admin_header_name_equals(line, "Sec-WebSocket-Extensions")
        || admin_header_name_equals(line, "Sec-WebSocket-Protocol")
        || admin_header_name_equals(line, "Sec-WebSocket-Accept");
}

static void admin_generate_request_id(char out[37])
{
    static unsigned long counter = 0;
    static pthread_mutex_t counter_lock = PTHREAD_MUTEX_INITIALIZER;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    pthread_mutex_lock(&counter_lock);
    unsigned long local_counter = ++counter;
    pthread_mutex_unlock(&counter_lock);
    snprintf(out,
             37,
             "%08lx-%04lx-%04lx-%04lx-%012lx",
             (unsigned long)tv.tv_sec & 0xffffffffUL,
             (unsigned long)(tv.tv_usec & 0xffffUL),
             local_counter & 0xffffUL,
             (local_counter >> 16U) & 0xffffUL,
             ((unsigned long)tv.tv_usec << 20U) ^ local_counter);
}

static int admin_collect_headers(const char *request,
                                 int strip_authorization,
                                 char ***headers,
                                 size_t *headers_len)
{
    *headers = NULL;
    *headers_len = 0;
    const char *line = strstr(request, "\r\n");
    if (line == NULL) {
        return 0;
    }
    line += 2;
    char **items = (char **)calloc(ST_ADMIN_MAX_HTTP_HEADERS, sizeof(*items));
    if (items == NULL) {
        return -1;
    }
    size_t count = 0;
    while (*line != '\0' && !(line[0] == '\r' && line[1] == '\n')) {
        const char *next = strstr(line, "\r\n");
        if (next == NULL) {
            break;
        }
        size_t len = (size_t)(next - line);
        if (len > 0 && count < ST_ADMIN_MAX_HTTP_HEADERS
            && !admin_skip_direct_request_header(line)
            && !(strip_authorization && admin_header_name_equals(line, "Authorization"))) {
            const char *colon = memchr(line, ':', len);
            if (colon == NULL || colon == line) {
                line = next + 2;
                continue;
            }
            const char *value = colon + 1;
            while (value < next && (*value == ' ' || *value == '\t')) {
                ++value;
            }
            const char *value_end = next;
            while (value_end > value && (value_end[-1] == ' ' || value_end[-1] == '\t')) {
                --value_end;
            }
            size_t name_len = (size_t)(colon - line);
            size_t value_len = (size_t)(value_end - value);
            size_t normalized_len = name_len + 1U + value_len;
            items[count] = (char *)malloc(normalized_len + 1U);
            if (items[count] == NULL) {
                for (size_t i = 0; i < count; ++i) {
                    free(items[i]);
                }
                free(items);
                return -1;
            }
            memcpy(items[count], line, name_len);
            items[count][name_len] = ':';
            memcpy(items[count] + name_len + 1U, value, value_len);
            items[count][normalized_len] = '\0';
            ++count;
        }
        line = next + 2;
    }
    *headers = items;
    *headers_len = count;
    return 0;
}

static char *admin_join_headers(char **headers, size_t headers_len)
{
    size_t total = 1;
    for (size_t i = 0; i < headers_len; ++i) {
        if (headers[i] != NULL) {
            total += strlen(headers[i]) + 1U;
        }
    }
    char *joined = (char *)malloc(total);
    if (joined == NULL) {
        return NULL;
    }
    joined[0] = '\0';
    for (size_t i = 0; i < headers_len; ++i) {
        if (headers[i] == NULL) {
            continue;
        }
        if (joined[0] != '\0') {
            strcat(joined, "\n");
        }
        strcat(joined, headers[i]);
    }
    return joined;
}

static char *admin_header_array_value(char **headers, size_t headers_len, const char *name)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i < headers_len; ++i) {
        char *line = headers[i];
        if (line == NULL) {
            continue;
        }
        char *colon = strchr(line, ':');
        if (colon == NULL || (size_t)(colon - line) != name_len
            || admin_ascii_ncasecmp(line, name, name_len) != 0) {
            continue;
        }
        char *value = colon + 1;
        while (*value != '\0' && isspace((unsigned char)*value)) {
            ++value;
        }
        return admin_dup_string(value);
    }
    return NULL;
}

#define ST_ADMIN_REWRITE_HTML 1
#define ST_ADMIN_REWRITE_CSS 2

static long long admin_env_nonnegative_i64(const char *name, long long fallback)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    return end != value && *end == '\0' && parsed >= 0 ? parsed : fallback;
}

static int admin_response_rewrite_kind(char **headers, size_t headers_len)
{
    char *content_type = admin_header_array_value(headers, headers_len, "Content-Type");
    if (content_type == NULL) {
        return 0;
    }
    char *trimmed = admin_trim(content_type);
    char *semicolon = strchr(trimmed, ';');
    if (semicolon != NULL) {
        *semicolon = '\0';
    }
    trimmed = admin_trim(trimmed);
    for (char *cursor = trimmed; *cursor != '\0'; ++cursor) {
        *cursor = (char)admin_ascii_lower((unsigned char)*cursor);
    }
    int kind = 0;
    if (strcmp(trimmed, "text/html") == 0) {
        kind = ST_ADMIN_REWRITE_HTML;
    } else if (strcmp(trimmed, "text/css") == 0) {
        kind = ST_ADMIN_REWRITE_CSS;
    } else if (strcmp(trimmed, "text/javascript") == 0
        || strcmp(trimmed, "application/javascript") == 0
        || strcmp(trimmed, "application/x-javascript") == 0
        || strcmp(trimmed, "application/ecmascript") == 0
        || strcmp(trimmed, "text/ecmascript") == 0) {
        kind = 0;
    }
    free(content_type);
    return kind;
}

static int admin_should_rewrite_path(const char *path, size_t len, const char *prefix)
{
    if (path == NULL || len == 0 || path[0] != '/' || (len > 1U && path[1] == '/')) {
        return 0;
    }
    size_t prefix_len = strlen(prefix);
    if (len == prefix_len && memcmp(path, prefix, prefix_len) == 0) {
        return 0;
    }
    return !(len > prefix_len
        && memcmp(path, prefix, prefix_len) == 0
        && path[prefix_len] == '/');
}

static int admin_is_attr_name_char(int ch)
{
    return isalnum((unsigned char)ch) || ch == '-' || ch == ':' || ch == '_';
}

static int admin_attr_name_equals(const char *name, size_t len, const char *expected)
{
    return len == strlen(expected) && admin_ascii_ncasecmp(name, expected, len) == 0;
}

static int admin_is_html_url_attr(const char *name, size_t len)
{
    return admin_attr_name_equals(name, len, "href")
        || admin_attr_name_equals(name, len, "src")
        || admin_attr_name_equals(name, len, "action")
        || admin_attr_name_equals(name, len, "data-href")
        || admin_attr_name_equals(name, len, "data-src")
        || admin_attr_name_equals(name, len, "poster")
        || admin_attr_name_equals(name, len, "background")
        || admin_attr_name_equals(name, len, "formaction")
        || admin_attr_name_equals(name, len, "cite")
        || admin_attr_name_equals(name, len, "longdesc")
        || admin_attr_name_equals(name, len, "usemap");
}

static int admin_rewrite_srcset_value(const char *value,
                                      size_t len,
                                      const char *prefix,
                                      char **out,
                                      size_t *out_len)
{
    st_admin_string_builder builder = {0};
    int changed = 0;
    size_t segment_start = 0;
    while (segment_start <= len) {
        size_t segment_end = segment_start;
        while (segment_end < len && value[segment_end] != ',') {
            ++segment_end;
        }
        size_t token_start = segment_start;
        while (token_start < segment_end && isspace((unsigned char)value[token_start])) {
            ++token_start;
        }
        size_t token_end = token_start;
        while (token_end < segment_end && !isspace((unsigned char)value[token_end])) {
            ++token_end;
        }
        if (token_start > segment_start
            && admin_sb_append_len(&builder, value + segment_start, token_start - segment_start) != 0) {
            free(builder.data);
            return -1;
        }
        if (token_end > token_start
            && admin_should_rewrite_path(value + token_start, token_end - token_start, prefix)) {
            if (admin_sb_append(&builder, prefix) != 0) {
                free(builder.data);
                return -1;
            }
            changed = 1;
        }
        if (admin_sb_append_len(&builder, value + token_start, segment_end - token_start) != 0) {
            free(builder.data);
            return -1;
        }
        if (segment_end < len) {
            if (admin_sb_append_len(&builder, value + segment_end, 1U) != 0) {
                free(builder.data);
                return -1;
            }
            segment_start = segment_end + 1U;
            continue;
        }
        break;
    }
    if (!changed) {
        free(builder.data);
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    *out = builder.data;
    *out_len = builder.len;
    return 0;
}

static int admin_rewrite_html_attrs(const char *input,
                                    size_t len,
                                    const char *prefix,
                                    char **out,
                                    size_t *out_len)
{
    st_admin_string_builder builder = {0};
    size_t last = 0;
    int changed = 0;
    for (size_t i = 0; i < len;) {
        if (!admin_is_attr_name_char((unsigned char)input[i])) {
            ++i;
            continue;
        }
        size_t name_start = i;
        while (i < len && admin_is_attr_name_char((unsigned char)input[i])) {
            ++i;
        }
        size_t name_len = i - name_start;
        size_t cursor = i;
        while (cursor < len && isspace((unsigned char)input[cursor])) {
            ++cursor;
        }
        if (cursor >= len || input[cursor] != '=') {
            continue;
        }
        ++cursor;
        while (cursor < len && isspace((unsigned char)input[cursor])) {
            ++cursor;
        }
        if (cursor >= len || (input[cursor] != '"' && input[cursor] != '\'')) {
            continue;
        }
        char quote = input[cursor++];
        size_t value_start = cursor;
        while (cursor < len && input[cursor] != quote) {
            ++cursor;
        }
        if (cursor >= len) {
            break;
        }
        size_t value_end = cursor;
        if (admin_is_html_url_attr(input + name_start, name_len)
            && admin_should_rewrite_path(input + value_start, value_end - value_start, prefix)) {
            if (admin_sb_append_len(&builder, input + last, value_start - last) != 0
                || admin_sb_append(&builder, prefix) != 0) {
                free(builder.data);
                return -1;
            }
            last = value_start;
            changed = 1;
        } else if (admin_attr_name_equals(input + name_start, name_len, "srcset")) {
            char *rewritten_srcset = NULL;
            size_t rewritten_srcset_len = 0;
            if (admin_rewrite_srcset_value(input + value_start,
                                           value_end - value_start,
                                           prefix,
                                           &rewritten_srcset,
                                           &rewritten_srcset_len) != 0) {
                free(builder.data);
                return -1;
            }
            if (rewritten_srcset != NULL) {
                if (admin_sb_append_len(&builder, input + last, value_start - last) != 0
                    || admin_sb_append_len(&builder, rewritten_srcset, rewritten_srcset_len) != 0) {
                    free(rewritten_srcset);
                    free(builder.data);
                    return -1;
                }
                free(rewritten_srcset);
                last = value_end;
                changed = 1;
            }
        }
        i = value_end + 1U;
    }
    if (!changed) {
        free(builder.data);
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    if (admin_sb_append_len(&builder, input + last, len - last) != 0) {
        free(builder.data);
        return -1;
    }
    *out = builder.data;
    *out_len = builder.len;
    return 0;
}

static char *admin_escape_html_attribute(const char *value)
{
    st_admin_string_builder builder = {0};
    for (const char *cursor = value; *cursor != '\0'; ++cursor) {
        const char *replacement = NULL;
        switch (*cursor) {
            case '&': replacement = "&amp;"; break;
            case '<': replacement = "&lt;"; break;
            case '>': replacement = "&gt;"; break;
            case '"': replacement = "&quot;"; break;
            case '\'': replacement = "&#39;"; break;
            default: break;
        }
        if ((replacement == NULL && admin_sb_append_len(&builder, cursor, 1U) != 0)
            || (replacement != NULL && admin_sb_append(&builder, replacement) != 0)) {
            free(builder.data);
            return NULL;
        }
    }
    if (builder.data == NULL && admin_sb_append(&builder, "") != 0) {
        return NULL;
    }
    return builder.data;
}

static char *admin_build_polyfill_script(const char *prefix)
{
    char *escaped = admin_escape_html_attribute(prefix);
    if (escaped == NULL) {
        return NULL;
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_appendf(
        &builder,
        "<script src=\"/specus-http-route-runtime.js?v=4\" data-specus-prefix=\"%s\"></script>",
        escaped);
    free(escaped);
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return builder.data;
}

static int admin_tag_name_boundary(int ch)
{
    return ch == '>' || ch == '/' || isspace((unsigned char)ch);
}

static int admin_find_tag_end_ci(const char *text, size_t len, const char *tag, size_t *end)
{
    size_t tag_len = strlen(tag);
    for (size_t i = 0; i + tag_len + 1U < len; ++i) {
        if (text[i] != '<' || (i + 1U < len && text[i + 1U] == '/')) {
            continue;
        }
        if (admin_ascii_ncasecmp(text + i + 1U, tag, tag_len) != 0
            || !admin_tag_name_boundary((unsigned char)text[i + 1U + tag_len])) {
            continue;
        }
        for (size_t j = i + 1U + tag_len; j < len; ++j) {
            if (text[j] == '>') {
                *end = j + 1U;
                return 1;
            }
        }
        return 0;
    }
    return 0;
}

static int admin_inject_runtime_polyfill(const char *input,
                                         size_t len,
                                         const char *prefix,
                                         char **out,
                                         size_t *out_len)
{
    char *script = admin_build_polyfill_script(prefix);
    if (script == NULL) {
        return -1;
    }
    size_t insert_at = 0;
    if (!admin_find_tag_end_ci(input, len, "head", &insert_at)) {
        (void)admin_find_tag_end_ci(input, len, "html", &insert_at);
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append_len(&builder, input, insert_at)
        || admin_sb_append(&builder, script)
        || admin_sb_append_len(&builder, input + insert_at, len - insert_at);
    free(script);
    if (rc != 0) {
        free(builder.data);
        return -1;
    }
    *out = builder.data;
    *out_len = builder.len;
    return 0;
}

static int admin_rewrite_html_body(const char *input,
                                   size_t len,
                                   const char *prefix,
                                   char **out,
                                   size_t *out_len)
{
    char *rewritten_attrs = NULL;
    size_t rewritten_attrs_len = 0;
    if (admin_rewrite_html_attrs(input, len, prefix, &rewritten_attrs, &rewritten_attrs_len) != 0) {
        return -1;
    }
    const char *source = rewritten_attrs == NULL ? input : rewritten_attrs;
    size_t source_len = rewritten_attrs == NULL ? len : rewritten_attrs_len;
    int rc = admin_inject_runtime_polyfill(source, source_len, prefix, out, out_len);
    free(rewritten_attrs);
    return rc;
}

static int admin_ci_match_at(const char *input, size_t len, size_t offset, const char *needle)
{
    size_t needle_len = strlen(needle);
    return offset <= len && len - offset >= needle_len
        && admin_ascii_ncasecmp(input + offset, needle, needle_len) == 0;
}

static int admin_rewrite_css_urls(const char *input,
                                  size_t len,
                                  const char *prefix,
                                  char **out,
                                  size_t *out_len)
{
    st_admin_string_builder builder = {0};
    size_t last = 0;
    int changed = 0;
    for (size_t i = 0; i + 4U <= len; ++i) {
        if (!admin_ci_match_at(input, len, i, "url(")) {
            continue;
        }
        size_t cursor = i + 4U;
        while (cursor < len && isspace((unsigned char)input[cursor])) {
            ++cursor;
        }
        char quote = 0;
        if (cursor < len && (input[cursor] == '"' || input[cursor] == '\'')) {
            quote = input[cursor++];
        }
        size_t path_start = cursor;
        if (quote != 0) {
            while (cursor < len && input[cursor] != quote) {
                ++cursor;
            }
        } else {
            while (cursor < len && input[cursor] != ')' && !isspace((unsigned char)input[cursor])) {
                ++cursor;
            }
        }
        size_t path_end = cursor;
        if (path_end > path_start && admin_should_rewrite_path(input + path_start, path_end - path_start, prefix)) {
            if (admin_sb_append_len(&builder, input + last, path_start - last) != 0
                || admin_sb_append(&builder, prefix) != 0) {
                free(builder.data);
                return -1;
            }
            last = path_start;
            changed = 1;
        }
        i = path_end;
    }
    if (!changed) {
        free(builder.data);
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    if (admin_sb_append_len(&builder, input + last, len - last) != 0) {
        free(builder.data);
        return -1;
    }
    *out = builder.data;
    *out_len = builder.len;
    return 0;
}

static int admin_rewrite_css_imports(const char *input,
                                     size_t len,
                                     const char *prefix,
                                     char **out,
                                     size_t *out_len)
{
    st_admin_string_builder builder = {0};
    size_t last = 0;
    int changed = 0;
    for (size_t i = 0; i + 7U <= len; ++i) {
        if (!admin_ci_match_at(input, len, i, "@import")) {
            continue;
        }
        size_t cursor = i + 7U;
        while (cursor < len && isspace((unsigned char)input[cursor])) {
            ++cursor;
        }
        if (cursor >= len || (input[cursor] != '"' && input[cursor] != '\'')) {
            continue;
        }
        char quote = input[cursor++];
        size_t path_start = cursor;
        while (cursor < len && input[cursor] != quote) {
            ++cursor;
        }
        size_t path_end = cursor;
        if (path_end > path_start && admin_should_rewrite_path(input + path_start, path_end - path_start, prefix)) {
            if (admin_sb_append_len(&builder, input + last, path_start - last) != 0
                || admin_sb_append(&builder, prefix) != 0) {
                free(builder.data);
                return -1;
            }
            last = path_start;
            changed = 1;
        }
        i = path_end;
    }
    if (!changed) {
        free(builder.data);
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    if (admin_sb_append_len(&builder, input + last, len - last) != 0) {
        free(builder.data);
        return -1;
    }
    *out = builder.data;
    *out_len = builder.len;
    return 0;
}

static int admin_rewrite_css_body(const char *input,
                                  size_t len,
                                  const char *prefix,
                                  char **out,
                                  size_t *out_len)
{
    char *url_rewritten = NULL;
    size_t url_rewritten_len = 0;
    if (admin_rewrite_css_urls(input, len, prefix, &url_rewritten, &url_rewritten_len) != 0) {
        return -1;
    }
    const char *source = url_rewritten == NULL ? input : url_rewritten;
    size_t source_len = url_rewritten == NULL ? len : url_rewritten_len;
    char *import_rewritten = NULL;
    size_t import_rewritten_len = 0;
    if (admin_rewrite_css_imports(source, source_len, prefix, &import_rewritten, &import_rewritten_len) != 0) {
        free(url_rewritten);
        return -1;
    }
    if (import_rewritten != NULL) {
        free(url_rewritten);
        *out = import_rewritten;
        *out_len = import_rewritten_len;
        return 0;
    }
    if (url_rewritten != NULL) {
        *out = url_rewritten;
        *out_len = url_rewritten_len;
        return 0;
    }
    *out = NULL;
    *out_len = 0;
    return 0;
}

static int admin_plain_response_body(const st_direct_http_response *response,
                                     uint8_t **out,
                                     size_t *out_len,
                                     int *decompressed)
{
    char *encoding_raw = admin_header_array_value(response->headers, response->headers_len, "Content-Encoding");
    char *encoding = encoding_raw == NULL ? NULL : admin_trim(encoding_raw);
    if (encoding != NULL) {
        for (char *cursor = encoding; *cursor != '\0'; ++cursor) {
            *cursor = (char)admin_ascii_lower((unsigned char)*cursor);
        }
    }
    int rc = -1;
    if (encoding == NULL || *encoding == '\0' || strcmp(encoding, "identity") == 0) {
        uint8_t *copy = (uint8_t *)malloc(response->body_len + 1U);
        if (copy != NULL) {
            if (response->body_len > 0) {
                memcpy(copy, response->body, response->body_len);
            }
            copy[response->body_len] = '\0';
            *out = copy;
            *out_len = response->body_len;
            *decompressed = 0;
            rc = 0;
        }
    } else if (strcmp(encoding, "gzip") == 0 || strcmp(encoding, "x-gzip") == 0) {
        rc = st_decompress_bounded(response->body,
                                   response->body_len,
                                   ST_DECOMPRESSION_GZIP,
                                   out,
                                   out_len);
        *decompressed = rc == 0;
    } else if (strcmp(encoding, "deflate") == 0) {
        rc = st_decompress_bounded(response->body,
                                   response->body_len,
                                   ST_DECOMPRESSION_ZLIB,
                                   out,
                                   out_len);
        if (rc == ST_DECOMPRESSION_INVALID) {
            rc = st_decompress_bounded(response->body,
                                       response->body_len,
                                       ST_DECOMPRESSION_RAW_DEFLATE,
                                       out,
                                       out_len);
        }
        *decompressed = rc == 0;
    }
    free(encoding_raw);
    return rc;
}

static void admin_remove_response_header(st_direct_http_response *response, const char *name)
{
    for (size_t i = 0; i < response->headers_len; ++i) {
        if (response->headers[i] != NULL && admin_header_name_equals(response->headers[i], name)) {
            free(response->headers[i]);
            response->headers[i] = NULL;
        }
    }
}

int st_admin_rewrite_direct_http_response(const char *client_name,
                                          const char *route,
                                          st_direct_http_response *response)
{
    if (client_name == NULL || route == NULL || response == NULL || response->body == NULL || response->body_len == 0
        || (response->error != NULL && *response->error != '\0')) {
        return 0;
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL
        || st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return 0;
    }
    st_storage_http_route http_route;
    if (st_storage_get_http_route_by_client_route(database_path, client_name, route, &http_route) != 0
        || !http_route.enabled
        || !http_route.path_rewrite_enabled) {
        return 0;
    }
    int rewrite_kind = admin_response_rewrite_kind(response->headers, response->headers_len);
    if (rewrite_kind == 0) {
        return 0;
    }
    long long max_body = admin_env_nonnegative_i64("SPECUS_HTTP_REWRITE_MAX_BODY_BYTES",
                                                  ST_ADMIN_DEFAULT_REWRITE_BODY_BYTES);
    if (max_body <= 0 || response->body_len > (size_t)max_body) {
        return 0;
    }
    char prefix[512];
    int prefix_len = snprintf(prefix, sizeof(prefix), "/http/%s/%s", client_name, route);
    if (prefix_len <= 0 || (size_t)prefix_len >= sizeof(prefix)) {
        return 0;
    }
    uint8_t *plain = NULL;
    size_t plain_len = 0;
    int decompressed = 0;
    if (admin_plain_response_body(response, &plain, &plain_len, &decompressed) != 0) {
        return 0;
    }
    char *rewritten = NULL;
    size_t rewritten_len = 0;
    int rc = rewrite_kind == ST_ADMIN_REWRITE_HTML
        ? admin_rewrite_html_body((const char *)plain, plain_len, prefix, &rewritten, &rewritten_len)
        : admin_rewrite_css_body((const char *)plain, plain_len, prefix, &rewritten, &rewritten_len);
    free(plain);
    if (rc != 0 || rewritten == NULL) {
        free(rewritten);
        return 0;
    }
    free(response->body);
    response->body = (uint8_t *)rewritten;
    response->body_len = rewritten_len;
    if (decompressed) {
        admin_remove_response_header(response, "Content-Encoding");
    }
    admin_remove_response_header(response, "ETag");
    admin_remove_response_header(response, "Content-MD5");
    return 1;
}

static const char *admin_reason_phrase(int status)
{
    switch (status) {
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 413: return "Payload Too Large";
        case 426: return "Upgrade Required";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default: return "OK";
    }
}

static int send_direct_http_response(int fd, const st_direct_http_response *response, int include_body)
{
    if (response->error != NULL && *response->error != '\0') {
        char *escaped = st_json_escape(response->error);
        if (escaped == NULL) {
            return -1;
        }
        char body[1024];
        int body_len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
        free(escaped);
        if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
            return -1;
        }
        char header[256];
        int header_len = snprintf(header,
                                  sizeof(header),
                                  "HTTP/1.1 502 Bad Gateway\r\n"
                                  "Content-Type: application/json\r\n"
                                  "Cache-Control: no-store\r\n"
                                  "Content-Length: %d\r\n"
                                  "\r\n",
                                  body_len);
        return header_len > 0 && (size_t)header_len < sizeof(header)
            && send_all(fd, header, (size_t)header_len) == 0
            && (!include_body || send_all(fd, body, (size_t)body_len) == 0);
    }

    int status = response->status_code <= 0 ? 502 : response->status_code;
    st_admin_string_builder builder = {0};
    if (admin_sb_appendf(&builder,
                         "HTTP/1.1 %d %s\r\n"
                         "Content-Length: %zu\r\n"
                         "Connection: close\r\n",
                         status,
                         admin_reason_phrase(status),
                         response->body_len) != 0) {
        free(builder.data);
        return -1;
    }
    for (size_t i = 0; i < response->headers_len; ++i) {
        if (response->headers[i] != NULL && strchr(response->headers[i], '\n') == NULL
            && !admin_skip_response_header(response->headers[i])) {
            if (admin_sb_appendf(&builder, "%s\r\n", response->headers[i]) != 0) {
                free(builder.data);
                return -1;
            }
        }
    }
    if (admin_sb_append(&builder, "\r\n") != 0) {
        free(builder.data);
        return -1;
    }
    int ok = send_all(fd, builder.data, builder.len) == 0
        && (!include_body || response->body_len == 0
            || send_all(fd, (const char *)response->body, response->body_len) == 0);
    free(builder.data);
    return ok ? 1 : -1;
}

static int send_text_http_error(int fd, int status, const char *message)
{
    char *escaped = st_json_escape(message);
    if (escaped == NULL) {
        return -1;
    }
    char body[1024];
    int body_len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", escaped);
    free(escaped);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        return -1;
    }
    char header[256];
    int header_len = snprintf(header,
                              sizeof(header),
                              "HTTP/1.1 %d %s\r\n"
                              "Content-Type: application/json\r\n"
                              "Cache-Control: no-store\r\n"
                              "Content-Length: %d\r\n"
                              "\r\n",
                              status,
                              admin_reason_phrase(status),
                              body_len);
    return header_len > 0 && (size_t)header_len < sizeof(header)
        && send_all(fd, header, (size_t)header_len) == 0
        && send_all(fd, body, (size_t)body_len) == 0;
}

static int send_http_route_auth_challenge(int fd)
{
    static const char body[] = "{\"error\":\"HTTP route authentication required\"}";
    char header[384];
    int header_len = snprintf(header,
                              sizeof(header),
                              "HTTP/1.1 401 Unauthorized\r\n"
                              "WWW-Authenticate: Basic realm=\"Specus HTTP Route\", charset=\"UTF-8\"\r\n"
                              "Content-Type: application/json\r\n"
                              "Cache-Control: no-store\r\n"
                              "X-Content-Type-Options: nosniff\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              sizeof(body) - 1U);
    return header_len > 0 && (size_t)header_len < sizeof(header)
        && send_all(fd, header, (size_t)header_len) == 0
        && send_all(fd, body, sizeof(body) - 1U) == 0
        ? 0
        : -1;
}

static int send_http_route_policy_unavailable(int fd)
{
    static const char body[] = "{\"error\":\"HTTP route authentication is temporarily unavailable\"}";
    char header[384];
    int header_len = snprintf(header,
                              sizeof(header),
                              "HTTP/1.1 503 Service Unavailable\r\n"
                              "Content-Type: application/json\r\n"
                              "Cache-Control: no-store\r\n"
                              "X-Content-Type-Options: nosniff\r\n"
                              "Content-Length: %zu\r\n"
                              "Connection: close\r\n"
                              "\r\n",
                              sizeof(body) - 1U);
    return header_len > 0 && (size_t)header_len < sizeof(header)
        && send_all(fd, header, (size_t)header_len) == 0
        && send_all(fd, body, sizeof(body) - 1U) == 0
        ? 0
        : -1;
}

static int admin_basic_base64_value(unsigned char value)
{
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '+') return 62;
    if (value == '/') return 63;
    return -1;
}

static int admin_decode_basic_credentials(const char *encoded,
                                          uint8_t *out,
                                          size_t out_cap,
                                          size_t *out_len)
{
    size_t len = encoded == NULL ? 0U : strlen(encoded);
    *out_len = 0U;
    if (len == 0U || len > 1024U || len % 4U != 0U) {
        return -1;
    }
    for (size_t i = 0; i < len; i += 4U) {
        int a = admin_basic_base64_value((unsigned char)encoded[i]);
        int b = admin_basic_base64_value((unsigned char)encoded[i + 1U]);
        int c = encoded[i + 2U] == '=' ? -2 : admin_basic_base64_value((unsigned char)encoded[i + 2U]);
        int d = encoded[i + 3U] == '=' ? -2 : admin_basic_base64_value((unsigned char)encoded[i + 3U]);
        if (a < 0 || b < 0 || c == -1 || d == -1
            || (c == -2 && d != -2) || ((c == -2 || d == -2) && i + 4U != len)) {
            return -1;
        }
        uint32_t value = (uint32_t)a << 18U | (uint32_t)b << 12U;
        if (c >= 0) value |= (uint32_t)c << 6U;
        if (d >= 0) value |= (uint32_t)d;
        size_t bytes = c == -2 ? 1U : d == -2 ? 2U : 3U;
        if (*out_len + bytes >= out_cap) {
            return -1;
        }
        out[(*out_len)++] = (uint8_t)(value >> 16U);
        if (bytes > 1U) out[(*out_len)++] = (uint8_t)(value >> 8U);
        if (bytes > 2U) out[(*out_len)++] = (uint8_t)value;
    }
    out[*out_len] = '\0';
    return 0;
}

static int admin_parse_direct_route_identity(const char *path, char **client_name, char **route)
{
    *client_name = NULL;
    *route = NULL;
    if (path == NULL || strncmp(path, "/http/", 6) != 0) {
        return -1;
    }
    const char *query = strchr(path, '?');
    size_t path_len = query == NULL ? strlen(path) : (size_t)(query - path);
    const char *cursor = path + 6;
    const char *client_end = path_len > 6U ? memchr(cursor, '/', path_len - 6U) : NULL;
    if (client_end == NULL || client_end == cursor) {
        return -1;
    }
    const char *route_start = client_end + 1;
    const char *route_end = memchr(route_start, '/', path + path_len - route_start);
    if (route_end == NULL) {
        route_end = path + path_len;
    }
    if (route_end == route_start) {
        return -1;
    }
    *client_name = admin_url_decode(cursor, (size_t)(client_end - cursor));
    *route = admin_url_decode(route_start, (size_t)(route_end - route_start));
    if (*client_name == NULL || *route == NULL) {
        free(*client_name);
        free(*route);
        *client_name = NULL;
        *route = NULL;
        return -1;
    }
    return 0;
}

static int admin_constant_time_text_equals(const char *left, const char *right)
{
    uint8_t left_hash[ST_SHA256_LEN];
    uint8_t right_hash[ST_SHA256_LEN];
    st_sha256((const uint8_t *)(left == NULL ? "" : left),
              strlen(left == NULL ? "" : left),
              left_hash);
    st_sha256((const uint8_t *)(right == NULL ? "" : right),
              strlen(right == NULL ? "" : right),
              right_hash);
    return st_constant_time_eq(left_hash, right_hash, sizeof(left_hash));
}

/* Returns 1 when Basic credentials were consumed, 0 for a public/env-only route, and -1 after an error response. */
static int authorize_direct_http_route(int fd, const char *path, const char *raw_request)
{
    char *client_name = NULL;
    char *route_name = NULL;
    if (admin_parse_direct_route_identity(path, &client_name, &route_name) != 0) {
        return 0;
    }
    const char *database_path = admin_database_path();
    if (database_path == NULL) {
        free(client_name);
        free(route_name);
        return 0;
    }
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        free(client_name);
        free(route_name);
        send_http_route_policy_unavailable(fd);
        return -1;
    }
    st_storage_http_route route;
    int found = 0;
    int lookup_rc = st_storage_find_http_route_by_client_route(database_path,
                                                               client_name,
                                                               route_name,
                                                               &route,
                                                               &found);
    free(client_name);
    free(route_name);
    if (lookup_rc != 0) {
        send_http_route_policy_unavailable(fd);
        return -1;
    }
    if (!found) {
        return 0;
    }
    if (!route.enabled) {
        send_text_http_error(fd, 404, "HTTP route is not configured or disabled");
        return -1;
    }
    if (!route.auth_enabled) {
        return 0;
    }
    if (route.auth_username[0] == '\0' || route.auth_password_hash[0] == '\0') {
        send_http_route_policy_unavailable(fd);
        return -1;
    }

    char *authorization = admin_extract_header_value(raw_request, "Authorization");
    const char *encoded = authorization;
    while (encoded != NULL && isspace((unsigned char)*encoded)) ++encoded;
    int scheme_ok = encoded != NULL
        && admin_ascii_ncasecmp(encoded, "Basic", 5U) == 0
        && isspace((unsigned char)encoded[5]);
    if (scheme_ok) {
        encoded += 5;
        while (isspace((unsigned char)*encoded)) ++encoded;
    }
    uint8_t decoded[512];
    size_t decoded_len = 0;
    int valid = scheme_ok
        && admin_decode_basic_credentials(encoded, decoded, sizeof(decoded), &decoded_len) == 0
        && memchr(decoded, '\0', decoded_len) == NULL;
    uint8_t *colon = valid ? memchr(decoded, ':', decoded_len) : NULL;
    if (colon == NULL) {
        valid = 0;
    } else {
        *colon = '\0';
        const char *password = (const char *)(colon + 1);
        int username_matches = admin_constant_time_text_equals((const char *)decoded,
                                                               route.auth_username);
        int password_matches = strlen(password) <= 256U
            && password_hash_matches(password, route.auth_password_hash);
        valid = username_matches & password_matches;
    }
    memset(decoded, 0, sizeof(decoded));
    free(authorization);
    if (!valid) {
        send_http_route_auth_challenge(fd);
        return -1;
    }
    return 1;
}

typedef struct {
    int fd;
    int include_body;
    int started;
    int ended;
    int buffer_for_rewrite;
    size_t rewrite_limit;
    size_t response_bytes;
    const char *client_name;
    const char *route;
    const char *method;
    const char *source_url;
    st_media_capture_session *media_capture;
    st_direct_http_response response;
    char **trailer_names;
    size_t trailer_names_len;
} admin_direct_http_sink_state;

static void direct_free_strings(char **values, size_t values_len)
{
    if (values == NULL) {
        return;
    }
    for (size_t i = 0; i < values_len; ++i) {
        free(values[i]);
    }
    free(values);
}

static int direct_copy_strings(char *const *values, size_t values_len,
                               char ***out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    if (values_len == 0U) {
        return 0;
    }
    char **copy = (char **)calloc(values_len, sizeof(*copy));
    if (copy == NULL) {
        return -1;
    }
    for (size_t i = 0; i < values_len; ++i) {
        copy[i] = admin_dup_string(values[i] == NULL ? "" : values[i]);
        if (copy[i] == NULL) {
            direct_free_strings(copy, values_len);
            return -1;
        }
    }
    *out = copy;
    *out_len = values_len;
    return 0;
}

void st_direct_http_response_free(st_direct_http_response *response)
{
    if (response == NULL) {
        return;
    }
    direct_free_strings(response->headers, response->headers_len);
    free(response->body);
    free(response->error);
    memset(response, 0, sizeof(*response));
}

static int direct_valid_trailer_name(const char *name)
{
    if (name == NULL || *name == '\0') {
        return 0;
    }
    for (const unsigned char *p = (const unsigned char *)name; *p != '\0'; ++p) {
        if (!isalnum(*p) && strchr("!#$%&'*+-.^_`|~", *p) == NULL) {
            return 0;
        }
    }
    return 1;
}

static int direct_should_buffer_rewrite(const char *client_name,
                                        const char *route,
                                        char **headers,
                                        size_t headers_len,
                                        size_t *limit)
{
    const char *database_path = admin_database_path();
    st_storage_http_route http_route;
    long long max_body = admin_env_nonnegative_i64("SPECUS_HTTP_REWRITE_MAX_BODY_BYTES",
                                                   ST_ADMIN_DEFAULT_REWRITE_BODY_BYTES);
    if (database_path == NULL || max_body <= 0
        || st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0
        || st_storage_get_http_route_by_client_route(database_path, client_name, route, &http_route) != 0
        || !http_route.enabled || !http_route.path_rewrite_enabled
        || admin_response_rewrite_kind(headers, headers_len) == 0) {
        return 0;
    }
    *limit = (size_t)max_body;
    return 1;
}

static int direct_sink_start_chunked(admin_direct_http_sink_state *state)
{
    if (state->started) {
        return 0;
    }
    st_admin_string_builder builder = {0};
    int status = state->response.status_code <= 0 ? 502 : state->response.status_code;
    int rc = admin_sb_appendf(&builder,
                              "HTTP/1.1 %d %s\r\n"
                              "Transfer-Encoding: chunked\r\n"
                              "Connection: close\r\n",
                              status, admin_reason_phrase(status));
    for (size_t i = 0; rc == 0 && i < state->response.headers_len; ++i) {
        const char *header = state->response.headers[i];
        if (header != NULL && strchr(header, '\r') == NULL && strchr(header, '\n') == NULL
            && !admin_skip_response_header(header)) {
            rc = admin_sb_appendf(&builder, "%s\r\n", header);
        }
    }
    if (rc == 0 && state->trailer_names_len > 0U) {
        rc = admin_sb_append(&builder, "Trailer: ");
        int written = 0;
        for (size_t i = 0; rc == 0 && i < state->trailer_names_len; ++i) {
            if (direct_valid_trailer_name(state->trailer_names[i])) {
                rc = admin_sb_appendf(&builder, "%s%s", written ? ", " : "",
                                      state->trailer_names[i]);
                written = 1;
            }
        }
        if (rc == 0) {
            rc = admin_sb_append(&builder, "\r\n");
        }
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "\r\n");
    }
    if (rc == 0) {
        rc = send_all(state->fd, builder.data, builder.len);
    }
    free(builder.data);
    if (rc == 0) {
        state->started = 1;
    }
    return rc;
}

static int direct_sink_send_chunk(admin_direct_http_sink_state *state,
                                  const uint8_t *data, size_t data_len)
{
    if (data_len == 0U || !state->include_body) {
        return 0;
    }
    char prefix[32];
    int prefix_len = snprintf(prefix, sizeof(prefix), "%zx\r\n", data_len);
    return prefix_len > 0 && (size_t)prefix_len < sizeof(prefix)
        && send_all(state->fd, prefix, (size_t)prefix_len) == 0
        && send_all(state->fd, (const char *)data, data_len) == 0
        && send_all(state->fd, "\r\n", 2U) == 0 ? 0 : -1;
}

static int direct_sink_append_body(st_direct_http_response *response,
                                   const uint8_t *data, size_t data_len,
                                   size_t limit)
{
    if (data_len == 0U || response->body_len >= limit) {
        return 0;
    }
    size_t append = data_len;
    if (append > limit - response->body_len) {
        append = limit - response->body_len;
    }
    uint8_t *grown = (uint8_t *)realloc(response->body, response->body_len + append);
    if (grown == NULL) {
        return -1;
    }
    response->body = grown;
    memcpy(response->body + response->body_len, data, append);
    response->body_len += append;
    return 0;
}

static int direct_sink_on_headers(void *ctx,
                                  int status_code,
                                  char *const *headers,
                                  size_t headers_len,
                                  char *const *trailer_names,
                                  size_t trailer_names_len)
{
    admin_direct_http_sink_state *state = (admin_direct_http_sink_state *)ctx;
    if (state->started || state->response.status_code != 0 || status_code < 100 || status_code > 599
        || direct_copy_strings(headers, headers_len,
                               &state->response.headers, &state->response.headers_len) != 0
        || direct_copy_strings(trailer_names, trailer_names_len,
                               &state->trailer_names, &state->trailer_names_len) != 0) {
        return -1;
    }
    state->response.status_code = status_code;
    state->media_capture = st_media_capture_open(admin_database_path(),
                                                state->client_name,
                                                state->route,
                                                state->method,
                                                state->source_url,
                                                status_code,
                                                state->response.headers,
                                                state->response.headers_len);
    state->buffer_for_rewrite = trailer_names_len == 0U
        && direct_should_buffer_rewrite(
            state->client_name, state->route, state->response.headers,
            state->response.headers_len, &state->rewrite_limit);
    return state->buffer_for_rewrite ? 0 : direct_sink_start_chunked(state);
}

static int direct_sink_on_data(void *ctx, const uint8_t *data, size_t data_len)
{
    admin_direct_http_sink_state *state = (admin_direct_http_sink_state *)ctx;
    if (state->ended || state->response.status_code == 0
        || data_len > SIZE_MAX - state->response_bytes) {
        return -1;
    }
    state->response_bytes += data_len;
    if (state->media_capture != NULL
        && st_media_capture_append(state->media_capture, data, data_len) != 0) {
        st_media_capture_fail(state->media_capture, "RustFS media part upload failed");
    }
    if (state->buffer_for_rewrite) {
        if (state->response.body_len <= state->rewrite_limit
            && data_len <= state->rewrite_limit - state->response.body_len) {
            return direct_sink_append_body(&state->response, data, data_len, state->rewrite_limit);
        }
        if (direct_sink_start_chunked(state) != 0
            || direct_sink_send_chunk(state, state->response.body, state->response.body_len) != 0) {
            return -1;
        }
        if (state->response.body_len > 64U * 1024U) {
            state->response.body_len = 64U * 1024U;
        }
        state->buffer_for_rewrite = 0;
    }
    if (direct_sink_append_body(&state->response, data, data_len, 64U * 1024U) != 0) {
        return -1;
    }
    return direct_sink_start_chunked(state) == 0
        ? direct_sink_send_chunk(state, data, data_len) : -1;
}

static int direct_sink_on_end(void *ctx, char *const *trailers, size_t trailers_len)
{
    admin_direct_http_sink_state *state = (admin_direct_http_sink_state *)ctx;
    if (state->ended || state->response.status_code == 0) {
        return -1;
    }
    if (state->buffer_for_rewrite) {
        (void)st_admin_rewrite_direct_http_response(state->client_name, state->route, &state->response);
        if (send_direct_http_response(state->fd, &state->response, state->include_body) < 0) {
            return -1;
        }
        state->started = 1;
        state->ended = 1;
        st_media_capture_complete(state->media_capture);
        return 0;
    }
    if (direct_sink_start_chunked(state) != 0 || send_all(state->fd, "0\r\n", 3U) != 0) {
        return -1;
    }
    for (size_t i = 0; i < trailers_len; ++i) {
        const char *trailer = trailers[i];
        const char *colon = trailer == NULL ? NULL : strchr(trailer, ':');
        if (colon != NULL && colon != trailer && strchr(trailer, '\r') == NULL
            && strchr(trailer, '\n') == NULL
            && send_all(state->fd, trailer, strlen(trailer)) != 0) {
            return -1;
        }
        if (colon != NULL && colon != trailer && send_all(state->fd, "\r\n", 2U) != 0) {
            return -1;
        }
    }
    if (send_all(state->fd, "\r\n", 2U) != 0) {
        return -1;
    }
    state->ended = 1;
    st_media_capture_complete(state->media_capture);
    return 0;
}

static void admin_fd_remote_text(int fd, char out[128])
{
    struct sockaddr_storage remote;
    socklen_t remote_len = sizeof(remote);
    if (getpeername(fd, (struct sockaddr *)&remote, &remote_len) != 0) {
        snprintf(out, 128U, "unknown");
        return;
    }
    if (remote.ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)&remote;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        snprintf(out, 128U, "%s:%d", ip, ntohs(addr->sin_port));
        return;
    }
    if (remote.ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&remote;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
        snprintf(out, 128U, "[%s]:%d", ip, ntohs(addr->sin6_port));
        return;
    }
    snprintf(out, 128U, "unknown");
}

static int admin_header_value_equals_ci(const char *request, const char *name, const char *expected)
{
    char *value = admin_extract_header_value(request, name);
    if (value == NULL) {
        return 0;
    }
    int matched = strlen(value) == strlen(expected)
        && admin_ascii_ncasecmp(value, expected, strlen(expected)) == 0;
    free(value);
    return matched;
}

static int admin_header_value_contains_token_ci(const char *request, const char *name, const char *expected)
{
    char *value = admin_extract_header_value(request, name);
    if (value == NULL) {
        return 0;
    }
    int matched = 0;
    const char *cursor = value;
    size_t expected_len = strlen(expected);
    while (*cursor != '\0') {
        while (*cursor == ',' || isspace((unsigned char)*cursor)) {
            ++cursor;
        }
        const char *end = cursor;
        while (*end != '\0' && *end != ',') {
            ++end;
        }
        const char *trimmed_end = end;
        while (trimmed_end > cursor && isspace((unsigned char)*(trimmed_end - 1))) {
            --trimmed_end;
        }
        size_t len = (size_t)(trimmed_end - cursor);
        if (len == expected_len && admin_ascii_ncasecmp(cursor, expected, expected_len) == 0) {
            matched = 1;
            break;
        }
        cursor = end;
    }
    free(value);
    return matched;
}

static int admin_recv_all(int fd, uint8_t *buffer, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t read_len = recv(fd, buffer + offset, len - offset, 0);
        if (read_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (read_len == 0) {
            return -1;
        }
        offset += (size_t)read_len;
    }
    return 0;
}

static void admin_socket_peer_address(int fd, char out[INET6_ADDRSTRLEN])
{
    out[0] = '\0';
    struct sockaddr_storage address;
    socklen_t address_len = sizeof(address);
    if (getpeername(fd, (struct sockaddr *)&address, &address_len) != 0) {
        return;
    }
    const void *source = NULL;
    if (address.ss_family == AF_INET) {
        source = &((const struct sockaddr_in *)&address)->sin_addr;
    } else if (address.ss_family == AF_INET6) {
        source = &((const struct sockaddr_in6 *)&address)->sin6_addr;
    }
    if (source != NULL) {
        (void)inet_ntop(address.ss_family, source, out, INET6_ADDRSTRLEN);
    }
}

static char *admin_websocket_accept_key(const char *client_key)
{
    static const char guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    size_t key_len = strlen(client_key);
    size_t guid_len = strlen(guid);
    char *joined = (char *)malloc(key_len + guid_len + 1U);
    if (joined == NULL) {
        return NULL;
    }
    memcpy(joined, client_key, key_len);
    memcpy(joined + key_len, guid, guid_len);
    joined[key_len + guid_len] = '\0';

    uint8_t digest[ST_SHA1_LEN];
    st_sha1((const uint8_t *)joined, key_len + guid_len, digest);
    free(joined);
    return admin_base64_encode(digest, sizeof(digest));
}

static int admin_send_websocket_frame_ex(int fd,
                                         int fin,
                                         uint8_t rsv,
                                         uint8_t opcode,
                                         const uint8_t *payload,
                                         size_t payload_len)
{
    uint8_t header[10];
    size_t header_len = 2U;
    header[0] = (uint8_t)((fin ? 0x80U : 0U) | ((rsv & 0x07U) << 4U) | (opcode & 0x0fU));
    if (payload_len <= 125U) {
        header[1] = (uint8_t)payload_len;
    } else if (payload_len <= 0xffffU) {
        header[1] = 126U;
        header[2] = (uint8_t)(payload_len >> 8U);
        header[3] = (uint8_t)payload_len;
        header_len = 4U;
    } else {
        header[1] = 127U;
        for (int i = 7; i >= 0; --i) {
            header[2U + (size_t)(7 - i)] = (uint8_t)(((uint64_t)payload_len >> ((unsigned int)i * 8U)) & 0xffU);
        }
        header_len = 10U;
    }
    if (send_all(fd, (const char *)header, header_len) != 0) {
        return -1;
    }
    if (payload_len > 0 && payload != NULL && send_all(fd, (const char *)payload, payload_len) != 0) {
        return -1;
    }
    return 0;
}

static int admin_send_websocket_frame(int fd, uint8_t opcode, const uint8_t *payload, size_t payload_len)
{
    return admin_send_websocket_frame_ex(fd, 1, 0U, opcode, payload, payload_len);
}

static uint16_t admin_read_u16_be(const uint8_t *value)
{
    return (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
}

static uint32_t admin_read_u32_be(const uint8_t *value)
{
    return ((uint32_t)value[0] << 24U) | ((uint32_t)value[1] << 16U)
        | ((uint32_t)value[2] << 8U) | (uint32_t)value[3];
}

static void admin_write_u16_be(uint8_t *value, uint16_t number)
{
    value[0] = (uint8_t)(number >> 8U);
    value[1] = (uint8_t)number;
}

static void admin_write_u32_be(uint8_t *value, uint32_t number)
{
    value[0] = (uint8_t)(number >> 24U);
    value[1] = (uint8_t)(number >> 16U);
    value[2] = (uint8_t)(number >> 8U);
    value[3] = (uint8_t)number;
}

static void admin_request_client_address(int fd,
                                         const char *request,
                                         char out[ST_CLIENT_ADDRESS_MAX_LEN])
{
    char peer[INET6_ADDRSTRLEN];
    admin_socket_peer_address(fd, peer);
    char *forwarded_for = admin_extract_header_value(request, "X-Forwarded-For");
    char *real_ip = admin_extract_header_value(request, "X-Real-IP");
    if (st_client_address_resolve(peer,
                                  forwarded_for,
                                  real_ip,
                                  getenv("SPECUS_TRUSTED_PROXIES"),
                                  out,
                                  ST_CLIENT_ADDRESS_MAX_LEN) != 0) {
        snprintf(out, ST_CLIENT_ADDRESS_MAX_LEN, "%s", "unknown");
    }
    free(forwarded_for);
    free(real_ip);
}

static int admin_sws2_close_code_valid(uint16_t close_code)
{
    return close_code >= 1000U && close_code < 5000U
        && close_code != 1004U
        && close_code != 1005U
        && close_code != 1006U
        && close_code != 1015U;
}

static int admin_sws2_validate(uint8_t opcode,
                               int fin,
                               uint8_t rsv,
                               uint16_t close_code,
                               size_t payload_len)
{
    if (opcode != 0x0U && opcode != 0x1U && opcode != 0x2U
        && opcode != 0x8U && opcode != 0x9U && opcode != 0xAU) {
        return -1;
    }
    if (rsv > 7U || payload_len > ST_ADMIN_SWS2_MAX_PAYLOAD) {
        return -1;
    }
    if (opcode >= 0x8U && (!fin || rsv != 0U || payload_len > 125U)) {
        return -1;
    }
    if (opcode == 0x8U) {
        if (payload_len > 123U || (close_code != 0U && !admin_sws2_close_code_valid(close_code))
            || (close_code == 0U && payload_len != 0U)) {
            return -1;
        }
    } else if (close_code != 0U) {
        return -1;
    }
    return 0;
}

static uint8_t *admin_sws2_encode(uint8_t opcode,
                                  int fin,
                                  uint8_t rsv,
                                  uint16_t close_code,
                                  const uint8_t *payload,
                                  size_t payload_len,
                                  size_t *encoded_len)
{
    if (encoded_len == NULL
        || admin_sws2_validate(opcode, fin, rsv, close_code, payload_len) != 0) {
        return NULL;
    }
    uint8_t *encoded = (uint8_t *)malloc(ST_ADMIN_SWS2_HEADER_BYTES + payload_len);
    if (encoded == NULL) {
        return NULL;
    }
    memcpy(encoded, "SWS2", 4U);
    encoded[4] = opcode;
    encoded[5] = (uint8_t)((fin ? 1U : 0U) | ((rsv & 7U) << 1U));
    admin_write_u16_be(encoded + 6U, close_code);
    admin_write_u32_be(encoded + 8U, (uint32_t)payload_len);
    if (payload_len > 0U && payload != NULL) {
        memcpy(encoded + ST_ADMIN_SWS2_HEADER_BYTES, payload, payload_len);
    }
    *encoded_len = ST_ADMIN_SWS2_HEADER_BYTES + payload_len;
    return encoded;
}

int st_admin_validate_sws2_payload(const uint8_t *payload, size_t payload_len)
{
    if (payload == NULL || payload_len < ST_ADMIN_SWS2_HEADER_BYTES
        || memcmp(payload, "SWS2", 4U) != 0) {
        return -1;
    }
    uint8_t flags = payload[5];
    if ((flags & 0xf0U) != 0U) {
        return -1;
    }
    uint32_t data_len = admin_read_u32_be(payload + 8U);
    return data_len <= ST_ADMIN_SWS2_MAX_PAYLOAD
            && (size_t)data_len == payload_len - ST_ADMIN_SWS2_HEADER_BYTES
            && admin_sws2_validate(payload[4],
                                   (flags & 1U) != 0U,
                                   (uint8_t)((flags >> 1U) & 7U),
                                   admin_read_u16_be(payload + 6U),
                                   data_len) == 0
        ? 0
        : -1;
}

static int admin_direct_ws_consume_send_credit(st_admin_direct_ws_stream *stream, size_t bytes)
{
    if (stream == NULL || bytes == 0U || bytes > ST_ADMIN_STREAM_MAX_WINDOW) {
        return -1;
    }
    pthread_mutex_lock(&stream->flow_lock);
    while (!stream->flow_closed && stream->send_credit < bytes) {
        pthread_cond_wait(&stream->flow_cond, &stream->flow_lock);
    }
    if (stream->flow_closed) {
        pthread_mutex_unlock(&stream->flow_lock);
        return -1;
    }
    stream->send_credit -= bytes;
    pthread_mutex_unlock(&stream->flow_lock);
    return 0;
}

int st_admin_direct_ws_send_framed_payload(st_admin_direct_ws_stream *stream,
                                           const uint8_t *payload,
                                           size_t payload_len)
{
    if (stream == NULL || st_admin_validate_sws2_payload(payload, payload_len) != 0) {
        return -1;
    }
    uint8_t opcode = payload[4];
    uint8_t flags = payload[5];
    int fin = (flags & 1U) != 0U;
    uint8_t rsv = (uint8_t)((flags >> 1U) & 7U);
    uint16_t close_code = admin_read_u16_be(payload + 6U);
    uint32_t data_len = admin_read_u32_be(payload + 8U);
    const uint8_t *data = payload + ST_ADMIN_SWS2_HEADER_BYTES;
    uint8_t close_payload[125];
    if (opcode == 0x8U && close_code != 0U) {
        admin_write_u16_be(close_payload, close_code);
        if (data_len > 0U) {
            memcpy(close_payload + 2U, data, data_len);
        }
        data = close_payload;
        data_len += 2U;
    }
    pthread_mutex_lock(&stream->send_lock);
    int invalid_sequence = 0;
    size_t next_fragment_bytes = stream->outbound_fragment_bytes;
    if (stream->close_sent) {
        invalid_sequence = 1;
    } else if (opcode == 0x0U) {
        invalid_sequence = stream->outbound_fragment_opcode == 0U;
        if (!invalid_sequence) {
            if (next_fragment_bytes > ST_ADMIN_MAX_DIRECT_HTTP_BODY - data_len) {
                invalid_sequence = 1;
            } else {
                next_fragment_bytes += data_len;
            }
        }
        if (!invalid_sequence && fin) {
            next_fragment_bytes = 0U;
        }
    } else if (opcode == 0x1U || opcode == 0x2U) {
        invalid_sequence = stream->outbound_fragment_opcode != 0U;
        if (!invalid_sequence && !fin) {
            next_fragment_bytes = data_len;
        }
    }
    int rc = stream->closed || invalid_sequence
        ? -1
        : admin_send_websocket_frame_ex(stream->fd, fin, rsv, opcode, data, data_len);
    if (rc == 0) {
        if (opcode == 0x8U) {
            stream->close_sent = 1;
            stream->outbound_fragment_opcode = 0U;
            stream->outbound_fragment_bytes = 0U;
        } else if (opcode == 0x0U) {
            stream->outbound_fragment_bytes = next_fragment_bytes;
            if (fin) {
                stream->outbound_fragment_opcode = 0U;
            }
        } else if ((opcode == 0x1U || opcode == 0x2U) && !fin) {
            stream->outbound_fragment_opcode = opcode;
            stream->outbound_fragment_bytes = next_fragment_bytes;
        }
    }
    pthread_mutex_unlock(&stream->send_lock);
    return rc;
}

int st_admin_direct_ws_add_send_credit(st_admin_direct_ws_stream *stream, uint32_t credit)
{
    if (stream == NULL || credit == 0U) {
        return -1;
    }
    pthread_mutex_lock(&stream->flow_lock);
    if (stream->flow_closed || stream->send_credit > ST_ADMIN_STREAM_MAX_WINDOW - credit) {
        pthread_mutex_unlock(&stream->flow_lock);
        return -1;
    }
    stream->send_credit += credit;
    pthread_cond_broadcast(&stream->flow_cond);
    pthread_mutex_unlock(&stream->flow_lock);
    return 0;
}

void st_admin_direct_ws_close(st_admin_direct_ws_stream *stream)
{
    if (stream == NULL) {
        return;
    }
    pthread_mutex_lock(&stream->send_lock);
    if (!stream->closed) {
        stream->closed = 1;
        shutdown(stream->fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&stream->send_lock);
    pthread_mutex_lock(&stream->flow_lock);
    stream->flow_closed = 1;
    pthread_cond_broadcast(&stream->flow_cond);
    pthread_mutex_unlock(&stream->flow_lock);
}

static st_admin_ws_client *admin_ws_add(int fd,
                                        const st_admin_context *context,
                                        const char *endpoint)
{
    st_admin_ws_client *client = (st_admin_ws_client *)calloc(1, sizeof(*client));
    if (client == NULL || context == NULL || !context->authenticated || endpoint == NULL) {
        free(client);
        return NULL;
    }
    client->fd = fd;
    snprintf(client->endpoint, sizeof(client->endpoint), "%s", endpoint);
    snprintf(client->username, sizeof(client->username), "%s", context->username);
    snprintf(client->tenant_id, sizeof(client->tenant_id), "%s", context->tenant_id);
    client->admin = context->admin;
    pthread_mutex_init(&client->send_lock, NULL);
    pthread_cond_init(&client->pending_cond, NULL);
    pthread_mutex_lock(&admin_ws_lock);
    client->next = admin_ws_clients;
    admin_ws_clients = client;
    pthread_mutex_unlock(&admin_ws_lock);
    return client;
}

static void admin_ws_remove(st_admin_ws_client *client)
{
    if (client == NULL) {
        return;
    }
    pthread_mutex_lock(&admin_ws_lock);
    client->closing = 1;
    st_admin_ws_client **cursor = &admin_ws_clients;
    while (*cursor != NULL) {
        if (*cursor == client) {
            *cursor = client->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    while (client->pending_message_writes > 0U) {
        pthread_cond_wait(&client->pending_cond, &admin_ws_lock);
    }
    pthread_mutex_unlock(&admin_ws_lock);
    pthread_cond_destroy(&client->pending_cond);
    pthread_mutex_destroy(&client->send_lock);
    free(client);
}

static int admin_ws_send_frame(st_admin_ws_client *client,
                               uint8_t opcode,
                               const uint8_t *payload,
                               size_t payload_len)
{
    pthread_mutex_lock(&client->send_lock);
    int rc = admin_send_websocket_frame(client->fd, opcode, payload, payload_len);
    pthread_mutex_unlock(&client->send_lock);
    return rc;
}

static int admin_ws_reserve_client_message_write(st_admin_ws_client *client)
{
    pthread_mutex_lock(&admin_ws_lock);
    int rejected = client->closing
        || client->pending_message_writes >= ST_ADMIN_MAX_PENDING_CLIENT_MESSAGE_WRITES_PER_SOCKET
        || admin_pending_client_message_writes >= ST_ADMIN_MAX_PENDING_CLIENT_MESSAGE_WRITES;
    if (!rejected) {
        ++client->pending_message_writes;
        ++admin_pending_client_message_writes;
    }
    pthread_mutex_unlock(&admin_ws_lock);
    return rejected ? -1 : 0;
}

static int admin_ws_client_is_open(st_admin_ws_client *client)
{
    pthread_mutex_lock(&admin_ws_lock);
    int open = !client->closing;
    pthread_mutex_unlock(&admin_ws_lock);
    return open;
}

static void admin_ws_release_client_message_write(st_admin_ws_client *client)
{
    pthread_mutex_lock(&admin_ws_lock);
    if (client->pending_message_writes > 0U) {
        --client->pending_message_writes;
    }
    if (admin_pending_client_message_writes > 0U) {
        --admin_pending_client_message_writes;
    }
    pthread_cond_broadcast(&client->pending_cond);
    pthread_mutex_unlock(&admin_ws_lock);
}

static void admin_drain_websocket(st_admin_ws_client *client)
{
    for (;;) {
        uint8_t header[2];
        if (admin_recv_all(client->fd, header, sizeof(header)) != 0) {
            return;
        }
        uint8_t opcode = header[0] & 0x0fU;
        int masked = (header[1] & 0x80U) != 0;
        uint64_t payload_len = header[1] & 0x7fU;
        if (payload_len == 126U) {
            uint8_t extended[2];
            if (admin_recv_all(client->fd, extended, sizeof(extended)) != 0) {
                return;
            }
            payload_len = ((uint64_t)extended[0] << 8U) | (uint64_t)extended[1];
        } else if (payload_len == 127U) {
            uint8_t extended[8];
            if (admin_recv_all(client->fd, extended, sizeof(extended)) != 0) {
                return;
            }
            payload_len = 0;
            for (size_t i = 0; i < sizeof(extended); ++i) {
                payload_len = (payload_len << 8U) | (uint64_t)extended[i];
            }
        }
        uint8_t mask[4] = {0};
        if (masked && admin_recv_all(client->fd, mask, sizeof(mask)) != 0) {
            return;
        }
        if (payload_len > (1024U * 1024U)) {
            uint8_t close_payload[2] = {0x03U, 0xf1U};
            admin_ws_send_frame(client, 0x8U, close_payload, sizeof(close_payload));
            return;
        }
        uint8_t *payload = NULL;
        if (payload_len > 0) {
            payload = (uint8_t *)malloc((size_t)payload_len);
            if (payload == NULL) {
                return;
            }
            if (admin_recv_all(client->fd, payload, (size_t)payload_len) != 0) {
                free(payload);
                return;
            }
            if (masked) {
                for (size_t i = 0; i < (size_t)payload_len; ++i) {
                    payload[i] ^= mask[i % 4U];
                }
            }
        }
        if (opcode == 0x8U) {
            admin_ws_send_frame(client, 0x8U, payload, payload_len <= 125U ? (size_t)payload_len : 0U);
            free(payload);
            return;
        }
        if (opcode == 0x9U) {
            admin_ws_send_frame(client, 0xAU, payload, payload_len <= 125U ? (size_t)payload_len : 0U);
        }
        free(payload);
    }
}

static int admin_ws_send_message_status(st_admin_ws_client *client,
                                        const char *type,
                                        const char *message_id,
                                        const char *to_client_name,
                                        const char *message,
                                        const char *error)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"type\":")
        || admin_sb_append_json_string(&builder, type);
    if (rc == 0 && message_id != NULL) {
        rc = admin_sb_append(&builder, ",\"messageId\":")
            || admin_sb_append_json_string(&builder, message_id);
    }
    if (rc == 0 && to_client_name != NULL) {
        rc = admin_sb_append(&builder, ",\"toClientName\":")
            || admin_sb_append_json_string(&builder, to_client_name);
    }
    if (rc == 0 && message != NULL) {
        rc = admin_sb_append(&builder, ",\"message\":")
            || admin_sb_append_json_string(&builder, message);
    }
    if (rc == 0 && error != NULL) {
        rc = admin_sb_append(&builder, ",\"error\":")
            || admin_sb_append_json_string(&builder, error);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "}");
    }
    if (rc == 0) {
        rc = admin_ws_send_frame(client, 0x1U, (const uint8_t *)builder.data, builder.len);
    }
    free(builder.data);
    return rc;
}

typedef struct {
    st_admin_ws_client *client;
    long long client_id;
    char client_name[256];
    char from_admin_name[ST_SECURITY_TOKEN_USERNAME_LEN + 8U];
    char *message_id;
    char *message;
} st_admin_client_message_write;

static void admin_client_message_write_free(st_admin_client_message_write *write)
{
    if (write == NULL) {
        return;
    }
    free(write->message_id);
    free(write->message);
    free(write);
}

static void *admin_client_message_write_thread(void *arg)
{
    st_admin_client_message_write *write = (st_admin_client_message_write *)arg;
    int send_rc = admin_send_client_message(write->client_id,
                                            write->client_name,
                                            write->from_admin_name,
                                            write->message);
    if (admin_ws_client_is_open(write->client)) {
        if (send_rc == 0) {
            (void)admin_ws_send_message_status(write->client,
                                               "written",
                                               write->message_id,
                                               write->client_name,
                                               write->message,
                                               NULL);
        } else {
            (void)admin_ws_send_message_status(write->client,
                                               send_rc == -1 ? "error" : "failed",
                                               write->message_id,
                                               NULL,
                                               NULL,
                                               send_rc == -1
                                                   ? "target-offline"
                                                   : "target-write-failed");
        }
    }
    admin_ws_release_client_message_write(write->client);
    admin_client_message_write_free(write);
    return NULL;
}

static void admin_handle_client_message_command(st_admin_ws_client *client, const char *json)
{
    if (!st_json_is_valid_object(json)) {
        (void)admin_ws_send_message_status(client, "error", NULL, NULL, NULL, "invalid-json");
        return;
    }
    char *type = st_json_get_top_level_string(json, "type");
    char *message_id = st_json_get_top_level_string(json, "messageId");
    char *to_client_name = st_json_get_top_level_string(json, "toClientName");
    char *message = st_json_get_top_level_string(json, "message");
    if (type == NULL || strcmp(type, "message") != 0) {
        (void)admin_ws_send_message_status(client,
                                           "error",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "unsupported-type");
        goto done;
    }
    char *target = to_client_name == NULL ? NULL : admin_trim(to_client_name);
    char *body = message == NULL ? NULL : admin_trim(message);
    if (target == NULL || *target == '\0' || body == NULL || *body == '\0') {
        (void)admin_ws_send_message_status(client,
                                           "error",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "target-and-message-required");
        goto done;
    }
    st_storage_client target_client;
    const char *database_path = admin_database_path();
    st_admin_context context;
    memset(&context, 0, sizeof(context));
    snprintf(context.username, sizeof(context.username), "%s", client->username);
    snprintf(context.tenant_id, sizeof(context.tenant_id), "%s", client->tenant_id);
    context.admin = client->admin;
    context.authenticated = 1;
    if (database_path == NULL
        || st_storage_get_client_by_name(database_path, target, &target_client) != 0
        || !target_client.enabled
        || !admin_can_access_client(&context, &target_client)) {
        (void)admin_ws_send_message_status(client,
                                           "error",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "target-not-found");
        goto done;
    }
    int can_receive_message = 0;
    if (st_storage_client_has_online_receive_capability(database_path,
                                                        target_client.id,
                                                        &can_receive_message) != 0
        || !can_receive_message) {
        (void)admin_ws_send_message_status(client,
                                           "error",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "target-cannot-receive-message");
        goto done;
    }
    st_admin_client_runtime_status runtime_status;
    admin_get_client_runtime_status(target_client.id, target_client.client_name, &runtime_status);
    if (!runtime_status.online) {
        (void)admin_ws_send_message_status(client,
                                           "error",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "target-offline");
        goto done;
    }
    char from_admin_name[ST_SECURITY_TOKEN_USERNAME_LEN + 8U];
    snprintf(from_admin_name, sizeof(from_admin_name), "admin:%s", client->username);
    st_admin_client_message_write *write = (st_admin_client_message_write *)calloc(1, sizeof(*write));
    if (write != NULL) {
        write->client = client;
        write->client_id = target_client.id;
        snprintf(write->client_name, sizeof(write->client_name), "%s", target_client.client_name);
        snprintf(write->from_admin_name, sizeof(write->from_admin_name), "%s", from_admin_name);
        write->message_id = strdup(message_id == NULL ? "" : message_id);
        write->message = strdup(body);
    }
    if (write == NULL || write->message_id == NULL || write->message == NULL
        || admin_ws_reserve_client_message_write(client) != 0) {
        admin_client_message_write_free(write);
        (void)admin_ws_send_message_status(client,
                                           "failed",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "target-write-failed");
        goto done;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, admin_client_message_write_thread, write) != 0) {
        admin_ws_release_client_message_write(client);
        admin_client_message_write_free(write);
        (void)admin_ws_send_message_status(client,
                                           "failed",
                                           message_id == NULL ? "" : message_id,
                                           NULL,
                                           NULL,
                                           "target-write-failed");
    } else {
        pthread_detach(thread);
    }

done:
    free(type);
    free(message_id);
    free(to_client_name);
    free(message);
}

static int admin_utf8_utf16_units(const uint8_t *data, size_t len, size_t *units)
{
    size_t offset = 0U;
    size_t count = 0U;
    while (offset < len) {
        uint32_t codepoint;
        uint8_t first = data[offset++];
        size_t continuation;
        if (first <= 0x7fU) {
            codepoint = first;
            continuation = 0U;
        } else if (first >= 0xc2U && first <= 0xdfU) {
            codepoint = first & 0x1fU;
            continuation = 1U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            codepoint = first & 0x0fU;
            continuation = 2U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            codepoint = first & 0x07U;
            continuation = 3U;
        } else {
            return -1;
        }
        if (continuation > len - offset) {
            return -1;
        }
        for (size_t i = 0U; i < continuation; ++i) {
            uint8_t next = data[offset++];
            if ((next & 0xc0U) != 0x80U) {
                return -1;
            }
            codepoint = (codepoint << 6U) | (next & 0x3fU);
        }
        if ((continuation == 2U && codepoint < 0x800U)
            || (continuation == 3U && codepoint < 0x10000U)
            || (codepoint >= 0xd800U && codepoint <= 0xdfffU)
            || codepoint > 0x10ffffU) {
            return -1;
        }
        size_t increment = codepoint > 0xffffU ? 2U : 1U;
        if (count > ST_ADMIN_CLIENT_MESSAGE_MAX_CHARS - increment) {
            return -2;
        }
        count += increment;
    }
    if (units != NULL) {
        *units = count;
    }
    return 0;
}

static void admin_drain_client_messages_websocket(st_admin_ws_client *client)
{
    st_admin_string_builder fragmented = {0};
    int fragment_active = 0;
    for (;;) {
        uint8_t header[2];
        if (admin_recv_all(client->fd, header, sizeof(header)) != 0) {
            break;
        }
        int fin = (header[0] & 0x80U) != 0U;
        uint8_t rsv = (uint8_t)((header[0] >> 4U) & 7U);
        uint8_t opcode = header[0] & 0x0fU;
        int masked = (header[1] & 0x80U) != 0;
        uint64_t payload_len = header[1] & 0x7fU;
        if (payload_len == 126U) {
            uint8_t extended[2];
            if (admin_recv_all(client->fd, extended, sizeof(extended)) != 0) break;
            payload_len = ((uint64_t)extended[0] << 8U) | extended[1];
        } else if (payload_len == 127U) {
            uint8_t extended[8];
            if (admin_recv_all(client->fd, extended, sizeof(extended)) != 0) break;
            payload_len = 0U;
            for (size_t i = 0; i < sizeof(extended); ++i) {
                payload_len = (payload_len << 8U) | extended[i];
            }
        }
        int control_frame = opcode >= 0x8U;
        int too_large = !control_frame
            && (payload_len > ST_ADMIN_CLIENT_MESSAGE_MAX_UTF8_BYTES
                || (fragment_active
                    && payload_len > ST_ADMIN_CLIENT_MESSAGE_MAX_UTF8_BYTES - fragmented.len));
        int protocol_error = !masked || rsv != 0U
            || (control_frame && (!fin || payload_len > 125U));
        if (protocol_error || too_large) {
            uint8_t close_payload[2] = {0x03U, too_large ? 0xf1U : 0xeaU};
            (void)admin_ws_send_frame(client, 0x8U, close_payload, sizeof(close_payload));
            break;
        }
        uint8_t mask[4];
        if (admin_recv_all(client->fd, mask, sizeof(mask)) != 0) break;
        uint8_t *payload = (uint8_t *)malloc(payload_len == 0U ? 1U : (size_t)payload_len);
        if (payload == NULL) break;
        if (payload_len > 0U && admin_recv_all(client->fd, payload, (size_t)payload_len) != 0) {
            free(payload);
            break;
        }
        for (size_t i = 0; i < (size_t)payload_len; ++i) {
            payload[i] ^= mask[i % 4U];
        }
        if (opcode == 0x8U) {
            if (payload_len == 1U) {
                uint8_t close_payload[2] = {0x03U, 0xeaU};
                (void)admin_ws_send_frame(client, 0x8U, close_payload, sizeof(close_payload));
                free(payload);
                break;
            }
            (void)admin_ws_send_frame(client, 0x8U, payload, payload_len <= 125U ? (size_t)payload_len : 0U);
            free(payload);
            break;
        }
        if (opcode == 0x9U) {
            (void)admin_ws_send_frame(client, 0xAU, payload, payload_len <= 125U ? (size_t)payload_len : 0U);
            free(payload);
            continue;
        }
        if (opcode == 0xAU) {
            free(payload);
            continue;
        }
        if (opcode == 0x2U) {
            uint8_t close_payload[2] = {0x03U, 0xebU};
            (void)admin_ws_send_frame(client, 0x8U, close_payload, sizeof(close_payload));
            free(payload);
            break;
        }
        if ((opcode == 0x1U && fragment_active) || (opcode == 0x0U && !fragment_active)
            || (opcode != 0x0U && opcode != 0x1U)) {
            uint8_t close_payload[2] = {0x03U, 0xeaU};
            (void)admin_ws_send_frame(client, 0x8U, close_payload, sizeof(close_payload));
            free(payload);
            break;
        }
        if (admin_sb_append_len(&fragmented, (const char *)payload, (size_t)payload_len) != 0) {
            free(payload);
            break;
        }
        free(payload);
        fragment_active = !fin;
        if (fin) {
            const uint8_t *text = (const uint8_t *)(fragmented.data == NULL ? "" : fragmented.data);
            int utf8_rc = admin_utf8_utf16_units(text, fragmented.len, NULL);
            if (utf8_rc != 0 || memchr(text, '\0', fragmented.len) != NULL) {
                uint8_t close_payload[2] = {0x03U, utf8_rc == -2 ? 0xf1U : 0xefU};
                (void)admin_ws_send_frame(client, 0x8U, close_payload, sizeof(close_payload));
                break;
            }
            admin_handle_client_message_command(client, (const char *)text);
            free(fragmented.data);
            memset(&fragmented, 0, sizeof(fragmented));
        }
    }
    free(fragmented.data);
}

static int handle_connection_websocket_request(int fd, const char *method, const char *path, const char *request)
{
    if (strcmp(method, "GET") != 0 || !admin_path_equals(path, "/ws/connections")) {
        return 0;
    }
    if (!admin_header_value_contains_token_ci(request, "Connection", "Upgrade")
        || !admin_header_value_equals_ci(request, "Upgrade", "websocket")) {
        send_text_http_error(fd, 426, "websocket upgrade required");
        return 1;
    }
    const char *query = strchr(path, '?');
    char *ticket = NULL;
    int single_ticket_query = 0;
    if (query != NULL && strncmp(query + 1, "ticket=", 7U) == 0 && strchr(query + 1, '&') == NULL) {
        single_ticket_query = 1;
        ticket = admin_query_string(path, "ticket");
    }
    char remote_address[ST_CLIENT_ADDRESS_MAX_LEN];
    admin_request_client_address(fd, request, remote_address);
    st_admin_context context;
    int ticket_valid = ticket != NULL
        && *ticket != '\0'
        && admin_consume_websocket_ticket(ticket, "connections", remote_address, &context) == 0;
    free(ticket);
    if (!ticket_valid) {
        char header[256];
        const char *reason = single_ticket_query
            ? "invalid or consumed ticket"
            : "single-use ticket required";
        char body[128];
        int body_len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", reason);
        int header_len = snprintf(header,
                                  sizeof(header),
                                  "HTTP/1.1 403 Forbidden\r\n"
                                  "Content-Type: application/json\r\n"
                                  "Cache-Control: no-store\r\n"
                                  "X-Auth-Reason: %s\r\n"
                                  "Content-Length: %zu\r\n"
                                  "\r\n",
                                  reason,
                                  body_len > 0 ? (size_t)body_len : 0U);
        if (body_len > 0 && (size_t)body_len < sizeof(body)
            && header_len > 0 && (size_t)header_len < sizeof(header)) {
            send_all(fd, header, (size_t)header_len);
            send_all(fd, body, (size_t)body_len);
        }
        return 1;
    }
    char *client_key = admin_extract_header_value(request, "Sec-WebSocket-Key");
    if (client_key == NULL || *client_key == '\0') {
        free(client_key);
        send_text_http_error(fd, 400, "Sec-WebSocket-Key is required");
        return 1;
    }
    char *accept_key = admin_websocket_accept_key(client_key);
    free(client_key);
    if (accept_key == NULL) {
        send_text_http_error(fd, 500, "websocket accept key build failed");
        return 1;
    }
    char response[512];
    int response_len = snprintf(response,
                                sizeof(response),
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n"
                                "\r\n",
                                accept_key);
    free(accept_key);
    if (response_len <= 0 || (size_t)response_len >= sizeof(response)
        || send_all(fd, response, (size_t)response_len) != 0) {
        return 1;
    }
    st_admin_ws_client *client = admin_ws_add(fd, &context, "connections");
    if (client == NULL) {
        uint8_t close_payload[2] = {0x03U, 0xf3U};
        admin_send_websocket_frame(fd, 0x8U, close_payload, sizeof(close_payload));
        return 1;
    }
    admin_drain_websocket(client);
    admin_ws_remove(client);
    return 1;
}

static int admin_ws_send_client_messages_hello(st_admin_ws_client *client)
{
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"type\":\"hello\",\"channel\":\"client-messages\",\"username\":");
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, client->username);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, ",\"tenantId\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, client->tenant_id);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "}");
    }
    if (rc == 0) {
        rc = admin_ws_send_frame(client, 0x1U, (const uint8_t *)builder.data, builder.len);
    }
    free(builder.data);
    return rc;
}

static int handle_client_messages_websocket_request(int fd,
                                                    const char *method,
                                                    const char *path,
                                                    const char *request)
{
    if (strcmp(method, "GET") != 0 || !admin_path_equals(path, "/ws/client-messages")) {
        return 0;
    }
    if (!admin_header_value_contains_token_ci(request, "Connection", "Upgrade")
        || !admin_header_value_equals_ci(request, "Upgrade", "websocket")) {
        send_text_http_error(fd, 426, "websocket upgrade required");
        return 1;
    }
    const char *query = strchr(path, '?');
    char *ticket = NULL;
    int single_ticket_query = 0;
    if (query != NULL && strncmp(query + 1, "ticket=", 7U) == 0 && strchr(query + 1, '&') == NULL) {
        single_ticket_query = 1;
        ticket = admin_query_string(path, "ticket");
    }
    char remote_address[ST_CLIENT_ADDRESS_MAX_LEN];
    admin_request_client_address(fd, request, remote_address);
    st_admin_context context;
    int ticket_valid = ticket != NULL
        && *ticket != '\0'
        && admin_consume_websocket_ticket(ticket, "client-messages", remote_address, &context) == 0;
    free(ticket);
    if (!ticket_valid) {
        char header[256];
        const char *reason = single_ticket_query
            ? "invalid or consumed ticket"
            : "single-use ticket required";
        char body[128];
        int body_len = snprintf(body, sizeof(body), "{\"error\":\"%s\"}", reason);
        int header_len = snprintf(header,
                                  sizeof(header),
                                  "HTTP/1.1 403 Forbidden\r\n"
                                  "Content-Type: application/json\r\n"
                                  "Cache-Control: no-store\r\n"
                                  "X-Auth-Reason: %s\r\n"
                                  "Content-Length: %zu\r\n"
                                  "\r\n",
                                  reason,
                                  body_len > 0 ? (size_t)body_len : 0U);
        if (body_len > 0 && (size_t)body_len < sizeof(body)
            && header_len > 0 && (size_t)header_len < sizeof(header)) {
            send_all(fd, header, (size_t)header_len);
            send_all(fd, body, (size_t)body_len);
        }
        return 1;
    }
    char *client_key = admin_extract_header_value(request, "Sec-WebSocket-Key");
    if (client_key == NULL || *client_key == '\0') {
        free(client_key);
        send_text_http_error(fd, 400, "Sec-WebSocket-Key is required");
        return 1;
    }
    char *accept_key = admin_websocket_accept_key(client_key);
    free(client_key);
    if (accept_key == NULL) {
        send_text_http_error(fd, 500, "websocket accept key build failed");
        return 1;
    }
    char response[512];
    int response_len = snprintf(response,
                                sizeof(response),
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n"
                                "\r\n",
                                accept_key);
    free(accept_key);
    if (response_len <= 0 || (size_t)response_len >= sizeof(response)
        || send_all(fd, response, (size_t)response_len) != 0) {
        return 1;
    }
    st_admin_ws_client *client = admin_ws_add(fd, &context, "client-messages");
    if (client == NULL) {
        uint8_t close_payload[2] = {0x03U, 0xf3U};
        admin_send_websocket_frame(fd, 0x8U, close_payload, sizeof(close_payload));
        return 1;
    }
    if (admin_ws_send_client_messages_hello(client) == 0) {
        admin_drain_client_messages_websocket(client);
    }
    admin_ws_remove(client);
    return 1;
}

static int admin_normalize_admin_message_target(const char *value,
                                                char username[ST_SECURITY_TOKEN_USERNAME_LEN + 1])
{
    static const char prefix[] = "admin:";
    username[0] = '\0';
    if (value == NULL) {
        return -1;
    }
    while (*value != '\0' && isspace((unsigned char)*value)) {
        ++value;
    }
    for (size_t i = 0; i < sizeof(prefix) - 1U; ++i) {
        if (value[i] == '\0'
            || tolower((unsigned char)value[i]) != (unsigned char)prefix[i]) {
            return -1;
        }
    }
    value += sizeof(prefix) - 1U;
    while (*value != '\0' && isspace((unsigned char)*value)) {
        ++value;
    }
    size_t len = strlen(value);
    while (len > 0U && isspace((unsigned char)value[len - 1U])) {
        --len;
    }
    if (len == 0U || len > ST_SECURITY_TOKEN_USERNAME_LEN) {
        return -1;
    }
    memcpy(username, value, len);
    username[len] = '\0';
    return 0;
}

static int admin_message_body_has_text(const char *message)
{
    if (message == NULL) {
        return 0;
    }
    for (; *message != '\0'; ++message) {
        if (!isspace((unsigned char)*message)) {
            return 1;
        }
    }
    return 0;
}

int st_admin_deliver_client_message_to_admin(const char *tenant_id,
                                             const char *from_client_name,
                                             const char *to_admin_name,
                                             const char *message)
{
    char username[ST_SECURITY_TOKEN_USERNAME_LEN + 1];
    if (tenant_id == NULL || from_client_name == NULL || *from_client_name == '\0'
        || admin_normalize_admin_message_target(to_admin_name, username) != 0
        || !admin_message_body_has_text(message)) {
        return -1;
    }
    char created_at[64];
    if (admin_current_utc_timestamp(created_at) != 0) {
        return -1;
    }

    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder,
                             "{\"type\":\"message\",\"direction\":\"in\",\"fromClientName\":");
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, from_client_name);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, ",\"toClientName\":");
    }
    if (rc == 0) {
        char target[ST_SECURITY_TOKEN_USERNAME_LEN + 8U];
        snprintf(target, sizeof(target), "admin:%s", username);
        rc = admin_sb_append_json_string(&builder, target);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, ",\"message\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, message);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, ",\"createdAt\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, created_at);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "}");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return -1;
    }

    int delivered = 0;
    pthread_mutex_lock(&admin_ws_lock);
    for (st_admin_ws_client *client = admin_ws_clients; client != NULL; client = client->next) {
        if (strcmp(client->endpoint, "client-messages") != 0
            || strcmp(client->tenant_id, tenant_id) != 0
            || strcmp(client->username, username) != 0) {
            continue;
        }
        if (admin_ws_send_frame(client, 0x1U, (const uint8_t *)builder.data, builder.len) == 0) {
            delivered = 1;
        } else {
            shutdown(client->fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&admin_ws_lock);
    free(builder.data);
    return delivered ? 0 : -1;
}

void st_admin_broadcast_connection_event(const char *tenant_id,
                                         const char *type,
                                         const st_storage_connection *connection)
{
    if (type == NULL || connection == NULL) {
        return;
    }
    st_admin_string_builder builder = {0};
    int rc = admin_sb_append(&builder, "{\"tenantId\":");
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, tenant_id == NULL ? "" : tenant_id);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, ",\"type\":");
    }
    if (rc == 0) {
        rc = admin_sb_append_json_string(&builder, type);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, ",\"connection\":");
    }
    if (rc == 0) {
        rc = append_connection_view(&builder, connection);
    }
    if (rc == 0) {
        rc = admin_sb_append(&builder, "}");
    }
    if (rc != 0 || builder.data == NULL) {
        free(builder.data);
        return;
    }
    st_storage_client owner;
    int owner_loaded = 0;
    const char *event_tenant = tenant_id == NULL ? "" : tenant_id;
    const char *database_path = admin_database_path();
    if (connection->client_id > 0
        && database_path != NULL
        && st_storage_get_client(database_path, connection->client_id, &owner) == 0
        && strcmp(owner.tenant_id, event_tenant) == 0) {
        owner_loaded = 1;
    }
    pthread_mutex_lock(&admin_ws_lock);
    for (st_admin_ws_client *client = admin_ws_clients; client != NULL; client = client->next) {
        if (strcmp(client->endpoint, "connections") != 0
            || strcmp(client->tenant_id, event_tenant) != 0) {
            continue;
        }
        if (!client->admin
            && (!owner_loaded || strcmp(client->username, owner.owner_username) != 0)) {
            continue;
        }
        if (admin_ws_send_frame(client, 0x1U, (const uint8_t *)builder.data, builder.len) != 0) {
            shutdown(client->fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&admin_ws_lock);
    free(builder.data);
}

static void free_header_array(char **headers, size_t headers_len)
{
    if (headers == NULL) {
        return;
    }
    for (size_t i = 0; i < headers_len; ++i) {
        free(headers[i]);
    }
    free(headers);
}

static int admin_direct_ws_send_frame(st_admin_direct_ws_stream *stream,
                                      uint8_t opcode,
                                      const uint8_t *payload,
                                      size_t payload_len)
{
    pthread_mutex_lock(&stream->send_lock);
    int rc;
    if (stream->closed) {
        rc = -1;
    } else if (opcode == 0x8U && stream->close_sent) {
        rc = 0;
    } else {
        rc = admin_send_websocket_frame(stream->fd, opcode, payload, payload_len);
        if (rc == 0 && opcode == 0x8U) {
            stream->close_sent = 1;
            stream->outbound_fragment_opcode = 0U;
            stream->outbound_fragment_bytes = 0U;
        }
    }
    pthread_mutex_unlock(&stream->send_lock);
    return rc;
}

static int admin_direct_ws_mark_closed(st_admin_direct_ws_stream *stream)
{
    int notify = 0;
    pthread_mutex_lock(&stream->send_lock);
    if (!stream->closed) {
        stream->closed = 1;
        notify = 1;
    }
    pthread_mutex_unlock(&stream->send_lock);
    return notify;
}

static void admin_direct_ws_destroy(st_admin_direct_ws_stream *stream)
{
    if (stream == NULL) {
        return;
    }
    pthread_cond_destroy(&stream->flow_cond);
    pthread_mutex_destroy(&stream->flow_lock);
    pthread_mutex_destroy(&stream->send_lock);
    free(stream);
}

static void admin_drain_direct_websocket(st_admin_server *server,
                                         st_admin_direct_ws_stream *stream,
                                         const char *channel_id)
{
    uint8_t incoming_fragment_opcode = 0U;
    size_t incoming_fragment_bytes = 0U;
    for (;;) {
        uint8_t header[2];
        if (admin_recv_all(stream->fd, header, sizeof(header)) != 0) {
            return;
        }
        int fin = (header[0] & 0x80U) != 0U;
        uint8_t rsv = (uint8_t)((header[0] >> 4U) & 0x07U);
        uint8_t opcode = header[0] & 0x0fU;
        int masked = (header[1] & 0x80U) != 0;
        if (!masked) {
            uint8_t close_payload[2] = {0x03U, 0xeaU};
            admin_direct_ws_send_frame(stream, 0x8U, close_payload, sizeof(close_payload));
            return;
        }
        uint64_t payload_len = header[1] & 0x7fU;
        if (payload_len == 126U) {
            uint8_t extended[2];
            if (admin_recv_all(stream->fd, extended, sizeof(extended)) != 0) {
                return;
            }
            payload_len = ((uint64_t)extended[0] << 8U) | (uint64_t)extended[1];
        } else if (payload_len == 127U) {
            uint8_t extended[8];
            if (admin_recv_all(stream->fd, extended, sizeof(extended)) != 0) {
                return;
            }
            payload_len = 0;
            for (size_t i = 0; i < sizeof(extended); ++i) {
                payload_len = (payload_len << 8U) | (uint64_t)extended[i];
            }
        }
        uint8_t mask[4] = {0};
        if (masked && admin_recv_all(stream->fd, mask, sizeof(mask)) != 0) {
            return;
        }
        if (payload_len > ST_ADMIN_MAX_DIRECT_HTTP_BODY) {
            uint8_t close_payload[2] = {0x03U, 0xf1U};
            admin_direct_ws_send_frame(stream, 0x8U, close_payload, sizeof(close_payload));
            return;
        }
        uint8_t *payload = NULL;
        if (payload_len > 0) {
            payload = (uint8_t *)malloc((size_t)payload_len);
            if (payload == NULL) {
                return;
            }
            if (admin_recv_all(stream->fd, payload, (size_t)payload_len) != 0) {
                free(payload);
                return;
            }
            if (masked) {
                for (size_t i = 0; i < (size_t)payload_len; ++i) {
                    payload[i] ^= mask[i % 4U];
                }
            }
        }

        if (opcode != 0x0U && opcode != 0x1U && opcode != 0x2U
            && opcode != 0x8U && opcode != 0x9U && opcode != 0xAU) {
            free(payload);
            return;
        }
        if (opcode >= 0x8U && (!fin || rsv != 0U || payload_len > 125U)) {
            free(payload);
            return;
        }
        if (opcode == 0x0U) {
            if (incoming_fragment_opcode == 0U) {
                free(payload);
                return;
            }
            if (incoming_fragment_bytes > ST_ADMIN_MAX_DIRECT_HTTP_BODY - (size_t)payload_len) {
                uint8_t close_payload[2] = {0x03U, 0xf1U};
                admin_direct_ws_send_frame(stream, 0x8U, close_payload, sizeof(close_payload));
                free(payload);
                return;
            }
            incoming_fragment_bytes += (size_t)payload_len;
            if (fin) {
                incoming_fragment_opcode = 0U;
                incoming_fragment_bytes = 0U;
            }
        } else if (opcode == 0x1U || opcode == 0x2U) {
            if (incoming_fragment_opcode != 0U) {
                free(payload);
                return;
            }
            if (!fin) {
                incoming_fragment_opcode = opcode;
                incoming_fragment_bytes = (size_t)payload_len;
            }
        }

        if (opcode == 0x9U) {
            admin_direct_ws_send_frame(stream, 0xAU, payload, (size_t)payload_len);
            free(payload);
            continue;
        }

        uint16_t close_code = 0U;
        const uint8_t *frame_payload = payload;
        size_t frame_payload_len = (size_t)payload_len;
        if (opcode == 0x8U) {
            if (payload_len == 1U) {
                free(payload);
                return;
            }
            if (payload_len >= 2U) {
                close_code = admin_read_u16_be(payload);
                frame_payload = payload + 2U;
                frame_payload_len -= 2U;
            }
        }

        size_t offset = 0U;
        int first = 1;
        do {
            size_t chunk_len = frame_payload_len - offset;
            if (chunk_len > ST_ADMIN_SWS2_MAX_PAYLOAD) {
                chunk_len = ST_ADMIN_SWS2_MAX_PAYLOAD;
            }
            int last = offset + chunk_len == frame_payload_len;
            size_t framed_len = 0U;
            uint8_t *framed = admin_sws2_encode(
                first ? opcode : 0x0U,
                fin && last,
                first ? rsv : 0U,
                first ? close_code : 0U,
                chunk_len == 0U ? NULL : frame_payload + offset,
                chunk_len,
                &framed_len);
            if (framed == NULL
                || admin_direct_ws_consume_send_credit(stream, framed_len) != 0
                || server->direct_ws_data == NULL
                || server->direct_ws_data(server->direct_ws_ctx, channel_id, framed, framed_len) != 0) {
                free(framed);
                free(payload);
                return;
            }
            free(framed);
            offset += chunk_len;
            first = 0;
        } while (offset < frame_payload_len);

        if (opcode == 0x8U) {
            admin_direct_ws_send_frame(stream, 0x8U, payload, (size_t)payload_len);
            free(payload);
            return;
        }
        free(payload);
    }
}

static int handle_direct_http_websocket_request(st_admin_server *server,
                                                 int fd,
                                                 const char *method,
                                                 const char *path,
                                                 const char *raw_request,
                                                 int strip_authorization)
{
    if (strncmp(path, "/http/", 6) != 0
        || !admin_header_value_contains_token_ci(raw_request, "Connection", "Upgrade")
        || !admin_header_value_equals_ci(raw_request, "Upgrade", "websocket")) {
        return 0;
    }
    if (strcmp(method, "GET") != 0) {
        send_text_http_error(fd, 400, "websocket upgrade only supports GET");
        return 1;
    }
    if (server->direct_ws_open == NULL || server->direct_ws_data == NULL || server->direct_ws_close == NULL) {
        send_text_http_error(fd, 501, "direct websocket dispatch is not wired yet");
        return 1;
    }

    char *client_key = admin_extract_header_value(raw_request, "Sec-WebSocket-Key");
    if (client_key == NULL || *client_key == '\0') {
        free(client_key);
        send_text_http_error(fd, 400, "Sec-WebSocket-Key is required");
        return 1;
    }
    char *accept_key = admin_websocket_accept_key(client_key);
    free(client_key);
    if (accept_key == NULL) {
        send_text_http_error(fd, 500, "websocket accept key build failed");
        return 1;
    }

    const char *query = strchr(path, '?');
    size_t path_len = query == NULL ? strlen(path) : (size_t)(query - path);
    const char *cursor = path + 6;
    const char *client_end = memchr(cursor, '/', path_len - 6U);
    if (client_end == NULL || client_end == cursor) {
        free(accept_key);
        send_text_http_error(fd, 400, "direct websocket path must include client and route");
        return 1;
    }
    const char *route_start = client_end + 1;
    const char *route_end = memchr(route_start, '/', path + path_len - route_start);
    if (route_end == NULL) {
        route_end = path + path_len;
    }
    if (route_end == route_start) {
        free(accept_key);
        send_text_http_error(fd, 400, "direct websocket path must include route");
        return 1;
    }

    char *client_name = admin_url_decode(cursor, (size_t)(client_end - cursor));
    char *route = admin_url_decode(route_start, (size_t)(route_end - route_start));
    char *relative_path = route_end < path + path_len
        ? admin_url_decode(route_end, (size_t)(path + path_len - route_end))
        : admin_dup_string("/");
    char *raw_query = admin_encode_raw_query_for_forwarding(query == NULL ? "" : query + 1);
    if (client_name == NULL || route == NULL || relative_path == NULL || raw_query == NULL) {
        free(accept_key);
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        send_text_http_error(fd, 500, "direct websocket request build failed");
        return 1;
    }

    char **headers = NULL;
    size_t headers_len = 0;
    if (admin_collect_headers(raw_request, strip_authorization, &headers, &headers_len) != 0) {
        free(accept_key);
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        send_text_http_error(fd, 500, "direct websocket header capture failed");
        return 1;
    }

    st_admin_direct_ws_stream *stream = (st_admin_direct_ws_stream *)calloc(1, sizeof(*stream));
    if (stream == NULL) {
        free(accept_key);
        free_header_array(headers, headers_len);
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        send_text_http_error(fd, 500, "direct websocket stream build failed");
        return 1;
    }
    stream->fd = fd;
    stream->send_credit = ST_ADMIN_STREAM_INITIAL_WINDOW;
    pthread_mutex_init(&stream->send_lock, NULL);
    pthread_mutex_init(&stream->flow_lock, NULL);
    pthread_cond_init(&stream->flow_cond, NULL);

    char channel_id[37];
    admin_generate_request_id(channel_id);
    static const uint8_t empty_body[] = {0};
    st_admin_direct_ws_request direct = {
        .channel_id = channel_id,
        .client_name = client_name,
        .route = route,
        .relative_path = relative_path,
        .raw_query = raw_query,
        .headers = headers,
        .headers_len = headers_len,
        .body = empty_body,
        .body_len = 0,
        .stream = stream
    };
    int open_rc = server->direct_ws_open(server->direct_ws_ctx, &direct);
    if (open_rc != 0) {
        admin_direct_ws_destroy(stream);
        free(accept_key);
        free_header_array(headers, headers_len);
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        if (open_rc == -3) {
            send_text_http_error(fd, 404, "direct websocket route is not configured");
        } else if (open_rc == -1) {
            send_text_http_error(fd, 502, "direct websocket target client is offline");
        } else {
            send_text_http_error(fd, 500, "direct websocket open failed");
        }
        return 1;
    }

    char response[512];
    int response_len = snprintf(response,
                                sizeof(response),
                                "HTTP/1.1 101 Switching Protocols\r\n"
                                "Upgrade: websocket\r\n"
                                "Connection: Upgrade\r\n"
                                "Sec-WebSocket-Accept: %s\r\n"
                                "\r\n",
                                accept_key);
    free(accept_key);
    if (response_len <= 0 || (size_t)response_len >= sizeof(response)
        || send_all(fd, response, (size_t)response_len) != 0) {
        if (admin_direct_ws_mark_closed(stream)) {
            server->direct_ws_close(server->direct_ws_ctx, channel_id);
        }
        admin_direct_ws_destroy(stream);
        free_header_array(headers, headers_len);
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        return 1;
    }

    admin_drain_direct_websocket(server, stream, channel_id);
    if (admin_direct_ws_mark_closed(stream)) {
        server->direct_ws_close(server->direct_ws_ctx, channel_id);
    }
    admin_direct_ws_destroy(stream);
    free_header_array(headers, headers_len);
    free(client_name);
    free(route);
    free(relative_path);
    free(raw_query);
    return 1;
}

static int handle_direct_http_request(st_admin_server *server,
                                      int fd,
                                      const char *method,
                                      const char *path,
                                      const char *raw_request,
                                      const uint8_t *body,
                                      size_t body_len,
                                      int strip_authorization)
{
    if (strncmp(path, "/http/", 6) != 0) {
        return 0;
    }
    if (server->direct_http_forward == NULL) {
        send_text_http_error(fd, 501, "direct http dispatch is not wired yet");
        return 1;
    }

    const char *query = strchr(path, '?');
    size_t path_len = query == NULL ? strlen(path) : (size_t)(query - path);
    const char *cursor = path + 6;
    const char *client_end = memchr(cursor, '/', path_len - 6U);
    if (client_end == NULL || client_end == cursor) {
        send_text_http_error(fd, 400, "direct http path must include client and route");
        return 1;
    }
    const char *route_start = client_end + 1;
    const char *route_end = memchr(route_start, '/', path + path_len - route_start);
    if (route_end == NULL) {
        route_end = path + path_len;
    }
    if (route_end == route_start) {
        send_text_http_error(fd, 400, "direct http path must include route");
        return 1;
    }

    char *client_name = admin_url_decode(cursor, (size_t)(client_end - cursor));
    char *route = admin_url_decode(route_start, (size_t)(route_end - route_start));
    char *relative_path = NULL;
    if (route_end < path + path_len) {
        relative_path = admin_url_decode(route_end, (size_t)(path + path_len - route_end));
    } else {
        relative_path = admin_dup_string("/");
    }
    char *raw_query = admin_encode_raw_query_for_forwarding(query == NULL ? "" : query + 1);
    if (client_name == NULL || route == NULL || relative_path == NULL || raw_query == NULL) {
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        send_text_http_error(fd, 500, "direct http request build failed");
        return 1;
    }

    char **headers = NULL;
    size_t headers_len = 0;
    if (admin_collect_headers(raw_request, strip_authorization, &headers, &headers_len) != 0) {
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        send_text_http_error(fd, 500, "direct http header capture failed");
        return 1;
    }
    st_direct_http_request direct = {
        .request_method = (char *)method,
        .route = route,
        .relative_path = relative_path,
        .raw_query = raw_query,
        .headers = headers,
        .headers_len = headers_len,
        .body = body,
        .body_len = body_len
    };
    size_t source_len = strlen(relative_path) + strlen(raw_query) + 2U;
    char *source_url = (char *)malloc(source_len);
    if (source_url == NULL) {
        free_header_array(headers, headers_len);
        free(client_name);
        free(route);
        free(relative_path);
        free(raw_query);
        send_text_http_error(fd, 500, "direct http media source build failed");
        return 1;
    }
    snprintf(source_url, source_len, "%s%s%s", relative_path,
             *raw_query == '\0' ? "" : "?", raw_query);
    admin_direct_http_sink_state sink_state = {
        .fd = fd,
        .include_body = admin_ascii_casecmp(method, "HEAD") != 0,
        .client_name = client_name,
        .route = route,
        .method = method,
        .source_url = source_url
    };
    st_admin_direct_http_sink sink = {
        .ctx = &sink_state,
        .on_headers = direct_sink_on_headers,
        .on_data = direct_sink_on_data,
        .on_end = direct_sink_on_end
    };
    char remote_address[128];
    admin_fd_remote_text(fd, remote_address);
    long long started_ms = admin_now_ms();
    int rc = server->direct_http_forward(server->direct_http_ctx, client_name, &direct, &sink);
    long long elapsed_ms = admin_now_ms() - started_ms;
    if (elapsed_ms < 0) {
        elapsed_ms = 0;
    }
    if (rc == 0) {
        record_direct_http_traffic(client_name, route, (long long)body_len,
                                   (long long)sink_state.response_bytes);
        record_direct_http_exchange(client_name, route, &direct, &sink_state.response,
                                    sink_state.response_bytes, remote_address, elapsed_ms);
    } else if (!sink_state.started && rc == -2) {
        send_text_http_error(fd, 504, "direct http response timeout");
    } else if (!sink_state.started && rc == -3) {
        send_text_http_error(fd, 404, "direct http route is not configured");
    } else if (!sink_state.started) {
        send_text_http_error(fd, 502, "direct http target client is offline");
    }

    if (rc != 0) {
        st_media_capture_fail(sink_state.media_capture, "媒体响应中断");
    }
    st_media_capture_free(sink_state.media_capture);

    st_direct_http_response_free(&sink_state.response);
    direct_free_strings(sink_state.trailer_names, sink_state.trailer_names_len);
    free_header_array(headers, headers_len);
    free(client_name);
    free(route);
    free(relative_path);
    free(raw_query);
    free(source_url);
    return 1;
}

static int send_static_file(int fd, const char *method, const char *path, const char *static_root)
{
    if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
        return 0;
    }
    char file_path[1024];
    const char *content_type = NULL;
    if (st_admin_resolve_static_path(static_root, path, file_path, sizeof(file_path), &content_type) != 0) {
        return 0;
    }
    struct stat st;
    if (stat(file_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;
    }
    FILE *file = fopen(file_path, "rb");
    if (file == NULL) {
        return 0;
    }
    char header[512];
    int header_len = snprintf(header,
                              sizeof(header),
                              "HTTP/1.1 200 OK\r\n"
                              "Content-Type: %s\r\n"
                              "Cache-Control: no-cache\r\n"
                              "X-Content-Type-Options: nosniff\r\n"
                              "Content-Length: %lld\r\n"
                              "\r\n",
                              content_type,
                              (long long)st.st_size);
    if (header_len <= 0 || (size_t)header_len >= sizeof(header)
        || send_all(fd, header, (size_t)header_len) != 0) {
        fclose(file);
        return 1;
    }
    if (strcmp(method, "HEAD") != 0) {
        char buffer[8192];
        size_t read_len;
        while ((read_len = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            if (send_all(fd, buffer, read_len) != 0) {
                break;
            }
        }
    }
    fclose(file);
    return 1;
}

static void handle_client(st_admin_server *server, int fd)
{
    char request[8192];
    ssize_t len = recv(fd, request, sizeof(request) - 1U, 0);
    if (len <= 0) {
        close(fd);
        return;
    }
    request[len] = '\0';
    while (strstr(request, "\r\n\r\n") == NULL) {
        if ((size_t)len >= sizeof(request) - 1U) {
            send_text_http_error(fd, 400, "HTTP request headers are too large");
            close(fd);
            return;
        }
        ssize_t more = recv(fd,
                            request + len,
                            sizeof(request) - 1U - (size_t)len,
                            0);
        if (more <= 0) {
            send_text_http_error(fd, 400, "HTTP request headers are incomplete");
            close(fd);
            return;
        }
        len += more;
        request[len] = '\0';
    }
    char method[16] = {0};
    char path[1024] = {0};
    if (sscanf(request, "%15s %1023s", method, path) != 2) {
        strcpy(method, "");
        strcpy(path, "");
    }
    int strip_direct_authorization = 0;
    if (strncmp(path, "/http/", 6) == 0) {
        int auth_result = authorize_direct_http_route(fd, path, request);
        if (auth_result < 0) {
            close(fd);
            return;
        }
        strip_direct_authorization = auth_result > 0;
    }
    const char *body = strstr(request, "\r\n\r\n");
    size_t available_body_len = 0;
    size_t content_length = 0;
    char *body_buffer = NULL;
    if (body != NULL) {
        body += 4;
        available_body_len = (size_t)(request + len - body);
        size_t max_content_length = admin_path_equals(path, "/api/admin/client-packages")
            ? st_client_package_max_request_bytes() : ST_ADMIN_MAX_DIRECT_HTTP_BODY;
        int length_rc = admin_parse_content_length(request, max_content_length, &content_length);
        if (length_rc == -2) {
            send_text_http_error(fd, 413, "HTTP 请求体超过限制");
            close(fd);
            return;
        }
        if (length_rc != 0) {
            send_text_http_error(fd, 400, "Content-Length 无效");
            close(fd);
            return;
        }
        if (content_length > available_body_len) {
            body_buffer = (char *)malloc(content_length + 1U);
            if (body_buffer == NULL) {
                send_text_http_error(fd, 500, "HTTP 请求体读取失败");
                close(fd);
                return;
            }
            memcpy(body_buffer, body, available_body_len);
            size_t offset = available_body_len;
            while (offset < content_length) {
                ssize_t read_len = recv(fd, body_buffer + offset, content_length - offset, 0);
                if (read_len <= 0) {
                    free(body_buffer);
                    send_text_http_error(fd, 400, "HTTP 请求体不完整");
                    close(fd);
                    return;
                }
                offset += (size_t)read_len;
            }
            body_buffer[content_length] = '\0';
            body = body_buffer;
            available_body_len = content_length;
        } else if (content_length > 0) {
            available_body_len = content_length;
        }
    }
    if (body == NULL) {
        body = "";
    }

    char request_remote_address[ST_CLIENT_ADDRESS_MAX_LEN];
    admin_request_client_address(fd, request, request_remote_address);

    if (st_public_discovery_handle_websocket(fd,
                                             method,
                                             path,
                                             request,
                                             request_remote_address)) {
        free(body_buffer);
        close(fd);
        return;
    }

    if (handle_connection_websocket_request(fd, method, path, request)) {
        free(body_buffer);
        close(fd);
        return;
    }
    if (handle_client_messages_websocket_request(fd, method, path, request)) {
        free(body_buffer);
        close(fd);
        return;
    }
    if (handle_direct_http_websocket_request(server,
                                             fd,
                                             method,
                                             path,
                                             request,
                                             strip_direct_authorization)) {
        free(body_buffer);
        close(fd);
        return;
    }
    if (handle_direct_http_request(server,
                                   fd,
                                   method,
                                   path,
                                   request,
                                   (const uint8_t *)body,
                                   available_body_len,
                                   strip_direct_authorization)) {
        free(body_buffer);
        close(fd);
        return;
    }
    const char *database_path = admin_database_path();
    int package_download_response = st_client_package_send_download(
        fd, method, path, database_path, request_remote_address);
    if (package_download_response != 0) {
        free(body_buffer);
        close(fd);
        return;
    }
    if (send_static_file(fd, method, path, server->static_root)) {
        free(body_buffer);
        close(fd);
        return;
    }
    char *authorization = admin_extract_header_value(request, "Authorization");
    char *oss_public_key_url = admin_extract_header_value(request, "x-oss-pub-key-url");
    char *range_header = admin_extract_header_value(request, "Range");
    char *content_type = admin_extract_header_value(request, "Content-Type");
    char *host_header = admin_extract_header_value(request, "X-Forwarded-Host");
    if (host_header == NULL || *host_header == '\0') {
        free(host_header);
        host_header = admin_extract_header_value(request, "Host");
    }
    char response_stack[32768];
    size_t response_capacity = sizeof(response_stack);
    char *response = response_stack;
    if (strncmp(path,
                "/api/public/transfer/rooms/diagram/versions",
                strlen("/api/public/transfer/rooms/diagram/versions")) == 0) {
        response_capacity = 5U * 1024U * 1024U;
        response = (char *)malloc(response_capacity);
        if (response == NULL) {
            free(authorization);
            free(oss_public_key_url);
            free(range_header);
            free(content_type);
            free(host_header);
            free(body_buffer);
            send_text_http_error(fd, 500, "HTTP 响应分配失败");
            close(fd);
            return;
        }
    }
    if (strncmp(path, "/api/admin/traffic/media-captures",
                strlen("/api/admin/traffic/media-captures")) == 0
        || strncmp(path, "/api/public/media-playback/",
                   strlen("/api/public/media-playback/")) == 0) {
        response_capacity = 20U * 1024U * 1024U;
        response = (char *)malloc(response_capacity);
        if (response == NULL) {
            free(authorization);
            free(oss_public_key_url);
            free(range_header);
            free(content_type);
            free(host_header);
            free(body_buffer);
            send_text_http_error(fd, 500, "HTTP media response allocation failed");
            close(fd);
            return;
        }
    }
    int response_len = st_admin_build_response_internal(method,
                                                        path,
                                                        authorization,
                                                        oss_public_key_url,
                                                        range_header,
                                                        host_header,
                                                        content_type,
                                                        body,
                                                        available_body_len,
                                                        request_remote_address,
                                                        0,
                                                        response,
                                                        response_capacity);
    if (response_len > 0) {
        send_all(fd, response, (size_t)response_len);
    }
    if (response != response_stack) {
        free(response);
    }
    free(authorization);
    free(oss_public_key_url);
    free(range_header);
    free(content_type);
    free(host_header);
    free(body_buffer);
    close(fd);
}

static void *admin_client_thread(void *arg)
{
    st_admin_client_args *client = (st_admin_client_args *)arg;
    st_admin_server *server = client->server;
    int fd = client->fd;
    free(client);
    handle_client(server, fd);
    return NULL;
}

static void *admin_thread(void *arg)
{
    st_admin_server *server = (st_admin_server *)arg;
    printf("[admin] listening on 0.0.0.0:%d\n", server->port);
    for (;;) {
        int fd = accept(server->fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        st_admin_client_args *client = (st_admin_client_args *)malloc(sizeof(*client));
        if (client == NULL) {
            close(fd);
            continue;
        }
        client->server = server;
        client->fd = fd;
        pthread_t worker;
        if (pthread_create(&worker, NULL, admin_client_thread, client) != 0) {
            perror("admin client pthread_create");
            close(fd);
            free(client);
            continue;
        }
        pthread_detach(worker);
    }
    return NULL;
}

int st_admin_server_start(st_admin_server *server, int port, const char *static_root)
{
    return st_admin_server_start_with_handlers(server, port, static_root, NULL, NULL, NULL, NULL, NULL, NULL);
}

int st_admin_server_start_with_forwarder(st_admin_server *server,
                                         int port,
                                         const char *static_root,
                                         st_admin_direct_http_forwarder forwarder,
                                         void *forwarder_ctx)
{
    return st_admin_server_start_with_handlers(server,
                                               port,
                                               static_root,
                                               forwarder,
                                               forwarder_ctx,
                                               NULL,
                                               NULL,
                                               NULL,
                                               NULL);
}

int st_admin_server_start_with_handlers(st_admin_server *server,
                                        int port,
                                        const char *static_root,
                                        st_admin_direct_http_forwarder http_forwarder,
                                        void *http_ctx,
                                        st_admin_direct_ws_open_handler ws_open,
                                        st_admin_direct_ws_data_handler ws_data,
                                        st_admin_direct_ws_close_handler ws_close,
                                        void *ws_ctx)
{
    memset(server, 0, sizeof(*server));
    server->port = port;
    snprintf(server->static_root, sizeof(server->static_root), "%s", static_root == NULL ? "" : static_root);
    server->direct_http_forward = http_forwarder;
    server->direct_http_ctx = http_ctx;
    server->direct_ws_open = ws_open;
    server->direct_ws_data = ws_data;
    server->direct_ws_close = ws_close;
    server->direct_ws_ctx = ws_ctx;
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        perror("admin socket");
        return -1;
    }
    int yes = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("admin bind");
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    if (listen(server->fd, 64) != 0) {
        perror("admin listen");
        close(server->fd);
        server->fd = -1;
        return -1;
    }

    pthread_t thread;
    if (pthread_create(&thread, NULL, admin_thread, server) != 0) {
        perror("admin pthread_create");
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    pthread_detach(thread);
    server->started = 1;
    return 0;
}
