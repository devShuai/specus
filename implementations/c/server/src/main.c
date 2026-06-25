#include "admin_http.h"
#include "crypto.h"
#include "json.h"
#include "protocol.h"
#include "storage.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define ST_MAX_TCP_MAPPINGS 64U
#define ST_CHANNEL_ID_SIZE 64U
#define ST_IO_BUFFER_SIZE 16384U

typedef struct {
    long long id;
    int port;
    char tunnel_address[256];
    int tunnel_port;
    int detail_capture_enabled;
} tcp_mapping;

typedef struct {
    long long id;
    char route[128];
    char target_base_url[512];
    int detail_capture_enabled;
    int path_rewrite_enabled;
} http_route_mapping;

typedef struct {
    long long client_id;
    char tenant_id[64];
    char client_name[128];
    int64_t client_session_id;
    uint8_t access_token_hash[ST_SHA256_LEN];
    int port;
    char public_address[256];
    int control_read_idle_seconds;
    int max_global_external_connections;
    int max_client_external_connections;
    int max_port_external_connections;
    int admin_port;
    char static_root[512];
    char database_path[512];
    tcp_mapping mappings[ST_MAX_TCP_MAPPINGS];
    size_t mapping_count;
    http_route_mapping http_routes[ST_MAX_TCP_MAPPINGS];
    size_t http_route_count;
    char *nat_control_json;
    int owns_nat_control_json;
    int client_session_db_backed;
} server_config;

typedef struct tunnel_session tunnel_session;

typedef struct external_conn {
    int fd;
    int port;
    char channel_id[ST_CHANNEL_ID_SIZE];
    char remote_address[128];
    char remote_ip[128];
    int remote_port;
    long long public_to_client_offset;
    long long client_to_public_offset;
    long long public_to_client_frame_index;
    long long client_to_public_frame_index;
    pthread_t thread;
    int thread_started;
    int done;
    int counted;
    tunnel_session *session;
    struct external_conn *next;
} external_conn;

typedef struct tunnel_listener {
    int fd;
    int port;
    pthread_t thread;
    int thread_started;
    int done;
    tunnel_session *session;
    struct tunnel_listener *next;
} tunnel_listener;

typedef struct direct_http_pending {
    char request_id[64];
    int done;
    st_direct_http_response response;
    pthread_cond_t cond;
    struct direct_http_pending *next;
} direct_http_pending;

typedef struct ws_conn {
    char channel_id[ST_CHANNEL_ID_SIZE];
    st_admin_direct_ws_stream *stream;
    struct ws_conn *next;
} ws_conn;

struct tunnel_session {
    int control_fd;
    server_config config;
    pthread_mutex_t send_lock;
    pthread_mutex_t map_lock;
    pthread_mutex_t direct_lock;
    external_conn *conns;
    ws_conn *ws_conns;
    tunnel_listener *listeners;
    direct_http_pending *direct_pending;
    int active;
    uint64_t next_channel_id;
    char remote[128];
    long long connection_record_id;
    char connected_at[64];
    struct tunnel_session *active_next;
};

typedef struct {
    int fd;
    struct sockaddr_storage remote;
    socklen_t remote_len;
    server_config config;
} client_args;

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} string_builder;

static pthread_mutex_t global_external_lock = PTHREAD_MUTEX_INITIALIZER;
static int global_external_connections = 0;
static pthread_mutex_t active_session_lock = PTHREAD_MUTEX_INITIALIZER;
static tunnel_session *active_sessions = NULL;

static int send_ws_connected(tunnel_session *session, const st_admin_direct_ws_request *request);
static int send_ws_disconnected(tunnel_session *session, const char *channel_id);
static int send_ws_data(tunnel_session *session, const char *channel_id, const uint8_t *data, size_t data_len);
static ws_conn *find_ws_conn_locked(tunnel_session *session, const char *channel_id);
static ws_conn *remove_ws_conn_locked(tunnel_session *session, const char *channel_id);
static int current_utc_timestamp(char out[64]);

static char *dup_string(const char *value)
{
    size_t len = strlen(value);
    char *out = (char *)malloc(len + 1U);
    if (out == NULL) {
        return NULL;
    }
    memcpy(out, value, len + 1U);
    return out;
}

static int sb_reserve(string_builder *builder, size_t more)
{
    if (builder->len + more + 1U <= builder->cap) {
        return 0;
    }
    size_t next = builder->cap == 0 ? 128U : builder->cap;
    while (next < builder->len + more + 1U) {
        if (next > SIZE_MAX / 2U) {
            return -1;
        }
        next *= 2U;
    }
    char *grown = (char *)realloc(builder->data, next);
    if (grown == NULL) {
        return -1;
    }
    builder->data = grown;
    builder->cap = next;
    return 0;
}

static int sb_append(string_builder *builder, const char *value)
{
    size_t len = strlen(value);
    if (sb_reserve(builder, len) != 0) {
        return -1;
    }
    memcpy(builder->data + builder->len, value, len);
    builder->len += len;
    builder->data[builder->len] = '\0';
    return 0;
}

static int sb_appendf(string_builder *builder, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    va_list copy;
    va_copy(copy, args);
    int needed = vsnprintf(NULL, 0, fmt, copy);
    va_end(copy);
    if (needed < 0) {
        va_end(args);
        return -1;
    }
    if (sb_reserve(builder, (size_t)needed) != 0) {
        va_end(args);
        return -1;
    }
    vsnprintf(builder->data + builder->len, builder->cap - builder->len, fmt, args);
    va_end(args);
    builder->len += (size_t)needed;
    return 0;
}

static char *sb_finish(string_builder *builder)
{
    if (builder->data == NULL) {
        return dup_string("");
    }
    char *out = builder->data;
    builder->data = NULL;
    builder->len = 0;
    builder->cap = 0;
    return out;
}

static int env_int_range(const char *name, int default_value, int min_value, int max_value, int *out)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        *out = default_value;
        return 0;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < min_value || parsed > max_value) {
        fprintf(stderr, "invalid %s; expected integer in [%d,%d]\n", name, min_value, max_value);
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

static int env_i64_range(const char *name, int64_t default_value, int64_t min_value, int64_t max_value, int64_t *out)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        *out = default_value;
        return 0;
    }
    char *end = NULL;
    long long parsed = strtoll(value, &end, 10);
    if (end == value || *end != '\0' || parsed < min_value || parsed > max_value) {
        fprintf(stderr, "invalid %s; expected integer in [%lld,%lld]\n",
                name, (long long)min_value, (long long)max_value);
        return -1;
    }
    *out = (int64_t)parsed;
    return 0;
}

static int copy_config_string(char *dest, size_t dest_len, const char *name, const char *value)
{
    if (value == NULL || *value == '\0') {
        fprintf(stderr, "%s cannot be empty\n", name);
        return -1;
    }
    size_t len = strlen(value);
    if (len >= dest_len) {
        fprintf(stderr, "%s is too long; max %zu bytes\n", name, dest_len - 1U);
        return -1;
    }
    memcpy(dest, value, len + 1U);
    return 0;
}

static int env_bool(const char *name, int default_value)
{
    const char *value = getenv(name);
    if (value == NULL || *value == '\0') {
        return default_value;
    }
    return strcmp(value, "0") != 0
        && strcmp(value, "false") != 0
        && strcmp(value, "FALSE") != 0
        && strcmp(value, "no") != 0
        && strcmp(value, "NO") != 0;
}

static char *trim(char *value)
{
    while (*value != '\0' && isspace((unsigned char)*value)) {
        ++value;
    }
    char *end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return value;
}

static char *next_csv_token(char **cursor)
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

static int parse_port_text(const char *value, int *out)
{
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed <= 0 || parsed > 65535) {
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

static int parse_tcp_mappings(server_config *config)
{
    const char *raw = getenv("TUNNEL_TCP_MAPPINGS");
    if (raw == NULL || *raw == '\0') {
        return 0;
    }
    char *copy = dup_string(raw);
    if (copy == NULL) {
        return -1;
    }

    char *cursor = copy;
    char *token = next_csv_token(&cursor);
    while (token != NULL) {
        if (config->mapping_count >= ST_MAX_TCP_MAPPINGS) {
            fprintf(stderr, "too many TUNNEL_TCP_MAPPINGS entries; max is %u\n", (unsigned)ST_MAX_TCP_MAPPINGS);
            free(copy);
            return -1;
        }
        char *entry = trim(token);
        char *equals = strchr(entry, '=');
        if (equals == NULL) {
            fprintf(stderr, "invalid mapping \"%s\"; expected publicPort=targetHost:targetPort\n", entry);
            free(copy);
            return -1;
        }
        *equals = '\0';
        char *target = trim(equals + 1);
        char *colon = strrchr(target, ':');
        if (colon == NULL) {
            fprintf(stderr, "invalid mapping target \"%s\"; expected targetHost:targetPort\n", target);
            free(copy);
            return -1;
        }
        *colon = '\0';
        char *public_port_text = trim(entry);
        char *target_host = trim(target);
        char *target_port_text = trim(colon + 1);
        if (*target_host == '\0') {
            fprintf(stderr, "invalid mapping target host\n");
            free(copy);
            return -1;
        }
        if (strlen(target_host) >= sizeof(config->mappings[0].tunnel_address)) {
            fprintf(stderr, "mapping target host is too long\n");
            free(copy);
            return -1;
        }

        tcp_mapping *mapping = &config->mappings[config->mapping_count];
        if (parse_port_text(public_port_text, &mapping->port) != 0
            || parse_port_text(target_port_text, &mapping->tunnel_port) != 0) {
            fprintf(stderr, "invalid mapping port in \"%s=%s:%s\"\n",
                    public_port_text, target_host, target_port_text);
            free(copy);
            return -1;
        }
        strcpy(mapping->tunnel_address, target_host);
        ++config->mapping_count;
        token = next_csv_token(&cursor);
    }
    free(copy);
    return 0;
}

static int parse_http_routes(server_config *config)
{
    const char *raw = getenv("TUNNEL_HTTP_ROUTES");
    if (raw == NULL || *raw == '\0') {
        return 0;
    }
    char *copy = dup_string(raw);
    if (copy == NULL) {
        return -1;
    }

    char *cursor = copy;
    char *token = next_csv_token(&cursor);
    while (token != NULL) {
        if (config->http_route_count >= ST_MAX_TCP_MAPPINGS) {
            fprintf(stderr, "too many TUNNEL_HTTP_ROUTES entries; max is %u\n", (unsigned)ST_MAX_TCP_MAPPINGS);
            free(copy);
            return -1;
        }
        char *entry = trim(token);
        char *equals = strchr(entry, '=');
        if (equals == NULL) {
            fprintf(stderr, "invalid HTTP route \"%s\"; expected route=targetBaseUrl\n", entry);
            free(copy);
            return -1;
        }
        *equals = '\0';
        char *route = trim(entry);
        char *target = trim(equals + 1);
        if (*route == '\0' || *target == '\0') {
            fprintf(stderr, "invalid HTTP route; route and targetBaseUrl are required\n");
            free(copy);
            return -1;
        }
        if (strlen(route) >= sizeof(config->http_routes[0].route)
            || strlen(target) >= sizeof(config->http_routes[0].target_base_url)) {
            fprintf(stderr, "HTTP route entry is too long\n");
            free(copy);
            return -1;
        }
        http_route_mapping *mapping = &config->http_routes[config->http_route_count++];
        strcpy(mapping->route, route);
        strcpy(mapping->target_base_url, target);
        token = next_csv_token(&cursor);
    }
    free(copy);
    return 0;
}

static int load_database_config(server_config *config, const char *database_path)
{
    if (st_storage_init(database_path, env_bool("TUNNEL_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return -1;
    }
    st_storage_client client;
    if (st_storage_get_client_by_name(database_path, config->client_name, &client) != 0 || !client.enabled) {
        fprintf(stderr, "client not found or disabled in database: %s\n", config->client_name);
        return -1;
    }
    config->client_id = client.id;
    if (copy_config_string(config->tenant_id,
                           sizeof(config->tenant_id),
                           "client_account.tenant_id",
                           client.tenant_id[0] == '\0' ? "default" : client.tenant_id) != 0) {
        return -1;
    }

    st_storage_mapping mappings[ST_MAX_TCP_MAPPINGS];
    size_t mapping_count = 0;
    if (st_storage_load_mappings(database_path,
                                 config->client_name,
                                 mappings,
                                 ST_MAX_TCP_MAPPINGS,
                                 &mapping_count) != 0) {
        fprintf(stderr, "failed to load tunnel mappings from database\n");
        return -1;
    }
    for (size_t i = 0; i < mapping_count; ++i) {
        tcp_mapping *mapping = &config->mappings[config->mapping_count++];
        mapping->id = mappings[i].id;
        mapping->port = mappings[i].listen_port;
        strcpy(mapping->tunnel_address, mappings[i].target_address);
        mapping->tunnel_port = mappings[i].target_port;
        mapping->detail_capture_enabled = mappings[i].detail_capture_enabled;
    }
    st_storage_http_route routes[ST_MAX_TCP_MAPPINGS];
    size_t route_count = 0;
    if (st_storage_load_http_routes(database_path,
                                    config->client_name,
                                    routes,
                                    ST_MAX_TCP_MAPPINGS,
                                    &route_count) != 0) {
        fprintf(stderr, "failed to load HTTP routes from database\n");
        return -1;
    }
    for (size_t i = 0; i < route_count; ++i) {
        if (config->http_route_count >= ST_MAX_TCP_MAPPINGS) {
            fprintf(stderr, "too many database HTTP route entries; max is %u\n", (unsigned)ST_MAX_TCP_MAPPINGS);
            return -1;
        }
        http_route_mapping *route = &config->http_routes[config->http_route_count++];
        route->id = routes[i].id;
        strcpy(route->route, routes[i].route);
        strcpy(route->target_base_url, routes[i].target_base_url);
        route->detail_capture_enabled = routes[i].detail_capture_enabled;
        route->path_rewrite_enabled = routes[i].path_rewrite_enabled;
    }
    return 0;
}

static int build_nat_control_json(server_config *config)
{
    char *client_name = st_json_escape(config->client_name);
    char *public_address = st_json_escape(config->public_address);
    if (client_name == NULL || public_address == NULL) {
        free(client_name);
        free(public_address);
        return -1;
    }

    string_builder builder = {0};
    if (sb_appendf(&builder,
                   "{\"clientName\":\"%s\",\"remoteAddress\":\"%s\",\"remotePort\":%d,\"tunnelConfigList\":[",
                   client_name,
                   public_address,
                   config->port) != 0) {
        free(client_name);
        free(public_address);
        free(builder.data);
        return -1;
    }
    free(client_name);
    free(public_address);

    for (size_t i = 0; i < config->mapping_count; ++i) {
        char *target = st_json_escape(config->mappings[i].tunnel_address);
        if (target == NULL) {
            free(builder.data);
            return -1;
        }
        int rc = sb_appendf(&builder,
                            "%s{\"port\":%d,\"tunnelAddress\":\"%s\",\"tunnelPort\":%d}",
                            i == 0 ? "" : ",",
                            config->mappings[i].port,
                            target,
                            config->mappings[i].tunnel_port);
        free(target);
        if (rc != 0) {
            free(builder.data);
            return -1;
        }
    }
    if (sb_append(&builder, "],\"httpTunnelConfigList\":[") != 0) {
        free(builder.data);
        return -1;
    }
    for (size_t i = 0; i < config->http_route_count; ++i) {
        char *route = st_json_escape(config->http_routes[i].route);
        char *target = st_json_escape(config->http_routes[i].target_base_url);
        if (route == NULL || target == NULL) {
            free(route);
            free(target);
            free(builder.data);
            return -1;
        }
        int rc = sb_appendf(&builder,
                            "%s{\"route\":\"%s\",\"targetBaseUrl\":\"%s\"}",
                            i == 0 ? "" : ",",
                            route,
                            target);
        free(route);
        free(target);
        if (rc != 0) {
            free(builder.data);
            return -1;
        }
    }
    if (sb_append(&builder, "]}") != 0) {
        free(builder.data);
        return -1;
    }
    config->nat_control_json = sb_finish(&builder);
    return config->nat_control_json == NULL ? -1 : 0;
}

static int load_config(server_config *config)
{
    const char *name = getenv("TUNNEL_CLIENT_NAME");
    const char *access_token = getenv("TUNNEL_CLIENT_ACCESS_TOKEN");
    const char *access_token_hash = getenv("TUNNEL_CLIENT_ACCESS_TOKEN_HASH");
    const char *public_address = getenv("TUNNEL_PUBLIC_ADDRESS");
    const char *database_path = getenv("TUNNEL_DATABASE_PATH");
    const char *static_root = getenv("TUNNEL_STATIC_ROOT");
    const char *tenant_id = getenv("TUNNEL_CLIENT_TENANT_ID");
    if (tenant_id == NULL || *tenant_id == '\0') {
        tenant_id = getenv("TUNNEL_AUTH_TENANT_ID");
    }

    memset(config, 0, sizeof(*config));
    if (copy_config_string(config->client_name, sizeof(config->client_name),
                           "TUNNEL_CLIENT_NAME",
                           (name != NULL && *name != '\0') ? name : "Demo client") != 0
        || copy_config_string(config->tenant_id, sizeof(config->tenant_id),
                              "TUNNEL_CLIENT_TENANT_ID",
                              (tenant_id != NULL && *tenant_id != '\0') ? tenant_id : "default") != 0
        || copy_config_string(config->public_address, sizeof(config->public_address),
                              "TUNNEL_PUBLIC_ADDRESS",
                              (public_address != NULL && *public_address != '\0') ? public_address : "127.0.0.1") != 0
        || env_int_range("TUNNEL_NETTY_PORT", 7010, 1, 65535, &config->port) != 0
        || env_i64_range("TUNNEL_CLIENT_ID", 0, 0, INT64_MAX, &config->client_id) != 0
        || env_i64_range("TUNNEL_CLIENT_SESSION_ID", 1, 1, INT64_MAX, &config->client_session_id) != 0
        || env_int_range("TUNNEL_CONTROL_READ_IDLE_SECONDS", 60, 5, 3600,
                         &config->control_read_idle_seconds) != 0
        || env_int_range("TUNNEL_MAX_GLOBAL_EXTERNAL_CONNECTIONS", 4096, 1, 1000000,
                         &config->max_global_external_connections) != 0
        || env_int_range("TUNNEL_MAX_CLIENT_EXTERNAL_CONNECTIONS", 1024, 1, 1000000,
                         &config->max_client_external_connections) != 0
        || env_int_range("TUNNEL_MAX_PORT_EXTERNAL_CONNECTIONS", 512, 1, 1000000,
                         &config->max_port_external_connections) != 0
        || env_int_range("TUNNEL_ADMIN_PORT", 0, 0, 65535, &config->admin_port) != 0) {
        return -1;
    }
    if (copy_config_string(config->static_root, sizeof(config->static_root),
                           "TUNNEL_STATIC_ROOT",
                           (static_root != NULL && *static_root != '\0')
                               ? static_root
                               : "implementations/java/server/src/main/resources/static") != 0) {
        return -1;
    }

    if (database_path != NULL && *database_path != '\0') {
        if (copy_config_string(config->database_path, sizeof(config->database_path),
                               "TUNNEL_DATABASE_PATH", database_path) != 0) {
            return -1;
        }
        if (load_database_config(config, database_path) != 0) {
            return -1;
        }
        char startup_time[64];
        if (current_utc_timestamp(startup_time) == 0) {
            (void)st_storage_close_client_sessions_by_status(database_path, "NETTY_ONLINE", startup_time);
        }
    }
    if (access_token_hash != NULL && *access_token_hash != '\0') {
        if (st_hex_decode_32(access_token_hash, config->access_token_hash) != 0) {
            fprintf(stderr, "invalid TUNNEL_CLIENT_ACCESS_TOKEN_HASH; expected 64 hex chars\n");
            return -1;
        }
    } else if (access_token != NULL && *access_token != '\0') {
        st_sha256((const uint8_t *)access_token, strlen(access_token), config->access_token_hash);
    } else if (config->database_path[0] == '\0') {
        if (access_token == NULL || *access_token == '\0') {
            fprintf(stderr, "TUNNEL_CLIENT_ACCESS_TOKEN is required when TUNNEL_CLIENT_ACCESS_TOKEN_HASH is unset\n");
            return -1;
        }
    }

    if (parse_tcp_mappings(config) != 0) {
        return -1;
    }
    if (parse_http_routes(config) != 0) {
        return -1;
    }
    if (build_nat_control_json(config) != 0) {
        fprintf(stderr, "failed to build NAT_CONTROL JSON\n");
        return -1;
    }
    config->owns_nat_control_json = 1;
    return 0;
}

static int64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000LL + (int64_t)tv.tv_usec / 1000LL;
}

static int current_utc_date(char out[11])
{
    time_t now = time(NULL);
    struct tm utc;
    if (gmtime_r(&now, &utc) == NULL) {
        return -1;
    }
    return strftime(out, 11U, "%Y-%m-%d", &utc) == 10U ? 0 : -1;
}

static int current_utc_timestamp(char out[64])
{
    time_t now = time(NULL);
    struct tm utc;
    if (gmtime_r(&now, &utc) == NULL) {
        return -1;
    }
    return strftime(out, 64U, "%Y-%m-%dT%H:%M:%SZ", &utc) > 0 ? 0 : -1;
}

static const char *nonempty_text(const char *value)
{
    return value == NULL || *value == '\0' ? NULL : value;
}

static void fill_connection_event(st_storage_connection *connection,
                                  const server_config *config,
                                  long long id,
                                  const char *client_name,
                                  const char *remote_address,
                                  int success,
                                  const char *failure_reason,
                                  const char *disconnect_reason,
                                  const char *connected_at,
                                  const char *disconnected_at)
{
    memset(connection, 0, sizeof(*connection));
    connection->id = id;
    snprintf(connection->tenant_id,
             sizeof(connection->tenant_id),
             "%s",
             config->tenant_id[0] == '\0' ? "default" : config->tenant_id);
    connection->client_id = config->client_id;
    snprintf(connection->client_name,
             sizeof(connection->client_name),
             "%s",
             client_name != NULL && *client_name != '\0' ? client_name : config->client_name);
    snprintf(connection->remote_address,
             sizeof(connection->remote_address),
             "%s",
             remote_address == NULL ? "" : remote_address);
    snprintf(connection->connected_at,
             sizeof(connection->connected_at),
             "%s",
             connected_at == NULL ? "" : connected_at);
    snprintf(connection->disconnected_at,
             sizeof(connection->disconnected_at),
             "%s",
             disconnected_at == NULL ? "" : disconnected_at);
    snprintf(connection->failure_reason,
             sizeof(connection->failure_reason),
             "%s",
             failure_reason == NULL ? "" : failure_reason);
    snprintf(connection->disconnect_reason,
             sizeof(connection->disconnect_reason),
             "%s",
             disconnect_reason == NULL ? "" : disconnect_reason);
    connection->success = success;
}

static void record_login_failure_event(const server_config *config,
                                       const char *client_name,
                                       const char *remote_address,
                                       const char *reason)
{
    if (config->database_path[0] == '\0') {
        return;
    }
    char timestamp[64];
    if (current_utc_timestamp(timestamp) != 0) {
        return;
    }
    const char *effective_name = client_name != NULL && *client_name != '\0'
        ? client_name
        : config->client_name;
    long long client_id = strcmp(effective_name, config->client_name) == 0 ? config->client_id : 0;
    long long record_id = 0;
    if (st_storage_record_connection_detail_with_tenant_and_id(config->database_path,
                                                               config->tenant_id,
                                                               client_id,
                                                               effective_name,
                                                               NULL,
                                                               remote_address,
                                                               0,
                                                               reason,
                                                               "LOGIN_FAILURE",
                                                               timestamp,
                                                               timestamp,
                                                               &record_id) != 0) {
        return;
    }
    st_storage_connection connection;
    fill_connection_event(&connection,
                          config,
                          record_id,
                          effective_name,
                          remote_address,
                          0,
                          reason,
                          "LOGIN_FAILURE",
                          timestamp,
                          timestamp);
    connection.client_id = client_id;
    st_admin_broadcast_connection_event(config->tenant_id, "created", &connection);
}

static void record_login_success_event(tunnel_session *session)
{
    if (session->config.database_path[0] == '\0') {
        return;
    }
    if (current_utc_timestamp(session->connected_at) != 0) {
        return;
    }
    long long record_id = 0;
    if (st_storage_record_connection_detail_with_tenant_and_id(session->config.database_path,
                                                               session->config.tenant_id,
                                                               session->config.client_id,
                                                               session->config.client_name,
                                                               NULL,
                                                               session->remote,
                                                               1,
                                                               NULL,
                                                               NULL,
                                                               session->connected_at,
                                                               NULL,
                                                               &record_id) != 0) {
        session->connected_at[0] = '\0';
        return;
    }
    session->connection_record_id = record_id;
    st_storage_connection connection;
    fill_connection_event(&connection,
                          &session->config,
                          record_id,
                          session->config.client_name,
                          session->remote,
                          1,
                          NULL,
                          NULL,
                          session->connected_at,
                          NULL);
    st_admin_broadcast_connection_event(session->config.tenant_id, "created", &connection);
}

static void record_session_disconnected_event(tunnel_session *session, const char *reason)
{
    if (session->config.database_path[0] == '\0'
        || session->connection_record_id <= 0
        || session->connected_at[0] == '\0') {
        return;
    }
    char disconnected_at[64];
    if (current_utc_timestamp(disconnected_at) != 0) {
        return;
    }
    const char *disconnect_reason = nonempty_text(reason);
    if (st_storage_mark_connection_disconnected(session->config.database_path,
                                                session->connection_record_id,
                                                disconnect_reason,
                                                disconnected_at) != 0) {
        return;
    }
    st_storage_connection connection;
    fill_connection_event(&connection,
                          &session->config,
                          session->connection_record_id,
                          session->config.client_name,
                          session->remote,
                          1,
                          NULL,
                          disconnect_reason,
                          session->connected_at,
                          disconnected_at);
    st_admin_broadcast_connection_event(session->config.tenant_id, "updated", &connection);
}

static const tcp_mapping *find_tcp_mapping_by_port(const server_config *config, int port)
{
    for (size_t i = 0; i < config->mapping_count; ++i) {
        if (config->mappings[i].port == port) {
            return &config->mappings[i];
        }
    }
    return NULL;
}

static void build_tcp_resource_name(const tcp_mapping *mapping, int port, char out[512])
{
    if (mapping == NULL) {
        snprintf(out, 512U, "端口 %d", port);
    } else {
        snprintf(out,
                 512U,
                 "%d -> %s:%d",
                 mapping->port,
                 mapping->tunnel_address,
                 mapping->tunnel_port);
    }
}

static void record_tcp_traffic(tunnel_session *session, int port, long long upload_bytes, long long download_bytes)
{
    if (session == NULL
        || session->config.database_path[0] == '\0'
        || (upload_bytes <= 0 && download_bytes <= 0)) {
        return;
    }
    char usage_date[11];
    if (current_utc_date(usage_date) != 0) {
        return;
    }
    const char *database_path = session->config.database_path;
    const char *client_name = session->config.client_name;
    long long client_id = session->config.client_id;
    st_storage_record_traffic_usage(database_path, client_id, client_name, usage_date, upload_bytes, download_bytes);

    const tcp_mapping *mapping = find_tcp_mapping_by_port(&session->config, port);
    char resource_key[64];
    char resource_name[512];
    snprintf(resource_key, sizeof(resource_key), "tcp:%d", port);
    long long resource_id = mapping == NULL ? 0 : mapping->id;
    build_tcp_resource_name(mapping, port, resource_name);
    st_storage_record_resource_traffic_usage(database_path,
                                             client_id,
                                             client_name,
                                             "TCP_TUNNEL",
                                             resource_key,
                                             resource_id,
                                             resource_name,
                                             usage_date,
                                             upload_bytes,
                                             download_bytes);
}

static void record_tcp_frame(tunnel_session *session,
                             external_conn *conn,
                             const char *direction,
                             const uint8_t *data,
                             size_t data_len)
{
    if (session == NULL || conn == NULL || data == NULL || data_len == 0
        || session->config.database_path[0] == '\0') {
        return;
    }
    const tcp_mapping *mapping = find_tcp_mapping_by_port(&session->config, conn->port);
    if (mapping == NULL || !mapping->detail_capture_enabled) {
        return;
    }
    char frame_time[64];
    if (current_utc_timestamp(frame_time) != 0) {
        return;
    }
    char resource_name[512];
    build_tcp_resource_name(mapping, conn->port, resource_name);
    long long offset;
    long long frame_index;
    if (strcmp(direction, "PUBLIC_TO_CLIENT") == 0) {
        offset = conn->public_to_client_offset;
        frame_index = conn->public_to_client_frame_index++;
        conn->public_to_client_offset += (long long)data_len;
    } else {
        offset = conn->client_to_public_offset;
        frame_index = conn->client_to_public_frame_index++;
        conn->client_to_public_offset += (long long)data_len;
    }
    const char *source_address = strcmp(direction, "PUBLIC_TO_CLIENT") == 0
        ? conn->remote_ip
        : mapping->tunnel_address;
    int source_port = strcmp(direction, "PUBLIC_TO_CLIENT") == 0 ? conn->remote_port : mapping->tunnel_port;
    const char *destination_address = strcmp(direction, "PUBLIC_TO_CLIENT") == 0
        ? mapping->tunnel_address
        : conn->remote_ip;
    int destination_port = strcmp(direction, "PUBLIC_TO_CLIENT") == 0 ? mapping->tunnel_port : conn->remote_port;
    st_storage_tcp_frame_record record = {
        .tenant_id = session->config.tenant_id,
        .client_id = session->config.client_id,
        .client_name = session->config.client_name,
        .listen_port = conn->port,
        .resource_id = mapping->id,
        .resource_name = resource_name,
        .channel_id = conn->channel_id,
        .direction = direction,
        .remote_address = conn->remote_address,
        .source_address = source_address,
        .source_port = source_port,
        .destination_address = destination_address,
        .destination_port = destination_port,
        .stream_offset = offset,
        .frame_index = frame_index,
        .payload_data = data,
        .payload_data_len = data_len,
        .frame_time = frame_time
    };
    (void)st_storage_record_tcp_frame(session->config.database_path, &record);
}

static int recv_all(int fd, uint8_t *buffer, size_t len)
{
    size_t offset = 0;
    while (offset < len) {
        ssize_t read_len = recv(fd, buffer + offset, len - offset, 0);
        if (read_len == 0) {
            return 0;
        }
        if (read_len < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return -2;
            }
            return -1;
        }
        offset += (size_t)read_len;
    }
    return 1;
}

static int send_all(int fd, const uint8_t *buffer, size_t len)
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

static int session_send_packet(tunnel_session *session, st_buffer *packet)
{
    int rc = -1;
    if (packet->data != NULL) {
        pthread_mutex_lock(&session->send_lock);
        if (session->control_fd >= 0) {
            rc = send_all(session->control_fd, packet->data, packet->len);
        }
        pthread_mutex_unlock(&session->send_lock);
    }
    st_buffer_free(packet);
    return rc;
}

static void direct_pending_fail_all(tunnel_session *session, const char *message)
{
    pthread_mutex_lock(&session->direct_lock);
    for (direct_http_pending *pending = session->direct_pending; pending != NULL; pending = pending->next) {
        if (!pending->done) {
            pending->response.error = dup_string(message);
            pending->done = 1;
            pthread_cond_signal(&pending->cond);
        }
    }
    pthread_mutex_unlock(&session->direct_lock);
}

static void direct_pending_remove(tunnel_session *session, direct_http_pending *target)
{
    direct_http_pending **cursor = &session->direct_pending;
    while (*cursor != NULL) {
        if (*cursor == target) {
            *cursor = target->next;
            return;
        }
        cursor = &(*cursor)->next;
    }
}

static int process_direct_http_response(tunnel_session *session, st_direct_http_response *response)
{
    if (response->request_id == NULL) {
        return 0;
    }
    pthread_mutex_lock(&session->direct_lock);
    for (direct_http_pending *pending = session->direct_pending; pending != NULL; pending = pending->next) {
        if (strcmp(pending->request_id, response->request_id) == 0) {
            pending->response = *response;
            memset(response, 0, sizeof(*response));
            pending->done = 1;
            pthread_cond_signal(&pending->cond);
            pthread_mutex_unlock(&session->direct_lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&session->direct_lock);
    return 0;
}

static int config_has_http_route(const server_config *config, const char *route)
{
    if (config == NULL || route == NULL) {
        return 0;
    }
    for (size_t i = 0; i < config->http_route_count; ++i) {
        if (strcmp(config->http_routes[i].route, route) == 0) {
            return 1;
        }
    }
    return 0;
}

static void active_session_add_locked(tunnel_session *session)
{
    if (session == NULL) {
        return;
    }
    session->active_next = active_sessions;
    active_sessions = session;
}

static void active_session_remove_locked(tunnel_session *session)
{
    tunnel_session **cursor = &active_sessions;
    while (*cursor != NULL) {
        if (*cursor == session) {
            *cursor = session->active_next;
            session->active_next = NULL;
            return;
        }
        cursor = &(*cursor)->active_next;
    }
}

static tunnel_session *active_session_find_locked(const char *client_name)
{
    for (tunnel_session *session = active_sessions; session != NULL; session = session->active_next) {
        if (session->active && strcmp(client_name, session->config.client_name) == 0) {
            return session;
        }
    }
    return NULL;
}

static int direct_http_forward(void *ctx,
                               const char *client_name,
                               const st_direct_http_request *request,
                               st_direct_http_response *response)
{
    (void)ctx;

    pthread_mutex_lock(&active_session_lock);
    tunnel_session *session = active_session_find_locked(client_name);
    if (session == NULL) {
        pthread_mutex_unlock(&active_session_lock);
        return -1;
    }
    if (!config_has_http_route(&session->config, request->route)) {
        pthread_mutex_unlock(&active_session_lock);
        return -3;
    }

    direct_http_pending pending;
    memset(&pending, 0, sizeof(pending));
    snprintf(pending.request_id, sizeof(pending.request_id), "%s", request->request_id);
    pthread_cond_init(&pending.cond, NULL);

    pthread_mutex_lock(&session->direct_lock);
    pending.next = session->direct_pending;
    session->direct_pending = &pending;
    pthread_mutex_unlock(&session->direct_lock);

    st_buffer packet = st_protocol_encode_direct_http_request(request);
    if (packet.data == NULL || session_send_packet(session, &packet) != 0) {
        pthread_mutex_lock(&session->direct_lock);
        direct_pending_remove(session, &pending);
        pthread_mutex_unlock(&session->direct_lock);
        pthread_cond_destroy(&pending.cond);
        pthread_mutex_unlock(&active_session_lock);
        return -1;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    struct timespec deadline;
    deadline.tv_sec = now.tv_sec + 30;
    deadline.tv_nsec = now.tv_usec * 1000L;

    int timed_out = 0;
    pthread_mutex_lock(&session->direct_lock);
    while (!pending.done) {
        int rc = pthread_cond_timedwait(&pending.cond, &session->direct_lock, &deadline);
        if (rc == ETIMEDOUT) {
            timed_out = 1;
            break;
        }
    }
    direct_pending_remove(session, &pending);
    if (pending.done) {
        *response = pending.response;
        memset(&pending.response, 0, sizeof(pending.response));
    }
    pthread_mutex_unlock(&session->direct_lock);

    pthread_cond_destroy(&pending.cond);
    pthread_mutex_unlock(&active_session_lock);
    if (timed_out) {
        return -2;
    }
    return pending.done ? 0 : -1;
}

static int direct_ws_open(void *ctx, const st_admin_direct_ws_request *request)
{
    (void)ctx;

    pthread_mutex_lock(&active_session_lock);
    tunnel_session *session = active_session_find_locked(request->client_name);
    if (session == NULL) {
        pthread_mutex_unlock(&active_session_lock);
        return -1;
    }
    if (!config_has_http_route(&session->config, request->route)) {
        pthread_mutex_unlock(&active_session_lock);
        return -3;
    }

    ws_conn *conn = (ws_conn *)calloc(1, sizeof(*conn));
    if (conn == NULL) {
        pthread_mutex_unlock(&active_session_lock);
        return -2;
    }
    snprintf(conn->channel_id, sizeof(conn->channel_id), "%s", request->channel_id);
    conn->stream = request->stream;

    pthread_mutex_lock(&session->map_lock);
    conn->next = session->ws_conns;
    session->ws_conns = conn;
    pthread_mutex_unlock(&session->map_lock);

    if (send_ws_connected(session, request) != 0) {
        pthread_mutex_lock(&session->map_lock);
        ws_conn *removed = remove_ws_conn_locked(session, request->channel_id);
        pthread_mutex_unlock(&session->map_lock);
        free(removed);
        pthread_mutex_unlock(&active_session_lock);
        return -1;
    }

    printf("[ws-tunnel] open client=%s route=%s channel=%s\n",
           request->client_name, request->route, request->channel_id);
    pthread_mutex_unlock(&active_session_lock);
    return 0;
}

static int direct_ws_data(void *ctx, const char *channel_id, const uint8_t *payload, size_t payload_len)
{
    (void)ctx;
    int rc = -1;
    st_admin_direct_ws_stream *stream_to_close = NULL;
    ws_conn *removed = NULL;

    pthread_mutex_lock(&active_session_lock);
    for (tunnel_session *session = active_sessions; session != NULL; session = session->active_next) {
        pthread_mutex_lock(&session->map_lock);
        ws_conn *conn = find_ws_conn_locked(session, channel_id);
        if (conn != NULL) {
            rc = send_ws_data(session, channel_id, payload, payload_len);
            if (rc != 0) {
                removed = remove_ws_conn_locked(session, channel_id);
                if (removed != NULL) {
                    stream_to_close = removed->stream;
                }
            }
            pthread_mutex_unlock(&session->map_lock);
            break;
        }
        pthread_mutex_unlock(&session->map_lock);
    }
    pthread_mutex_unlock(&active_session_lock);

    if (stream_to_close != NULL) {
        st_admin_direct_ws_close(stream_to_close);
    }
    free(removed);
    return rc;
}

static void direct_ws_close(void *ctx, const char *channel_id)
{
    (void)ctx;
    pthread_mutex_lock(&active_session_lock);
    for (tunnel_session *session = active_sessions; session != NULL; session = session->active_next) {
        pthread_mutex_lock(&session->map_lock);
        ws_conn *removed = remove_ws_conn_locked(session, channel_id);
        pthread_mutex_unlock(&session->map_lock);
        if (removed != NULL) {
            send_ws_disconnected(session, channel_id);
            printf("[ws-tunnel] close client=%s channel=%s\n",
                   session->config.client_name, channel_id);
            free(removed);
            break;
        }
    }
    pthread_mutex_unlock(&active_session_lock);
}

static int read_frame(int fd, st_frame_header *header, uint8_t **body)
{
    uint8_t raw_header[ST_HEADER_SIZE];
    int rc = recv_all(fd, raw_header, sizeof(raw_header));
    if (rc <= 0) {
        return rc;
    }
    if (st_protocol_read_header(raw_header, header) != 0) {
        return -1;
    }
    if (header->command == ST_CMD_NAT_MESSAGE) {
        if (header->serializer != ST_SERIALIZER_FASTJSON) {
            return -1;
        }
    } else if (header->serializer != ST_SERIALIZER_COMPACT_BINARY) {
        return -1;
    }
    uint8_t *frame_body = (uint8_t *)malloc(header->length == 0 ? 1U : header->length);
    if (frame_body == NULL) {
        return -1;
    }
    rc = recv_all(fd, frame_body, header->length);
    if (rc <= 0) {
        free(frame_body);
        return rc;
    }
    *body = frame_body;
    return 1;
}

static int reload_config_for_client_session(server_config *config, const st_storage_client_session *client_session)
{
    if (config == NULL || client_session == NULL || config->database_path[0] == '\0') {
        return -1;
    }
    char database_path[sizeof(config->database_path)];
    snprintf(database_path, sizeof(database_path), "%s", config->database_path);
    if (config->owns_nat_control_json) {
        free(config->nat_control_json);
    }
    config->nat_control_json = NULL;
    config->owns_nat_control_json = 0;
    config->mapping_count = 0;
    config->http_route_count = 0;
    if (copy_config_string(config->client_name,
                           sizeof(config->client_name),
                           "client_session.client_name",
                           client_session->client_name) != 0
        || copy_config_string(config->tenant_id,
                              sizeof(config->tenant_id),
                              "client_session.tenant_id",
                              client_session->tenant_id[0] == '\0' ? "default" : client_session->tenant_id) != 0) {
        return -1;
    }
    config->client_id = client_session->client_id;
    config->client_session_id = client_session->id;
    config->client_session_db_backed = 1;
    if (load_database_config(config, database_path) != 0
        || parse_tcp_mappings(config) != 0
        || parse_http_routes(config) != 0
        || build_nat_control_json(config) != 0) {
        return -1;
    }
    config->owns_nat_control_json = 1;
    return 0;
}

static int verify_database_login(tunnel_session *session, const st_login_request *request, const char **reason)
{
    server_config *config = &session->config;
    if (config->database_path[0] == '\0') {
        return -1;
    }
    uint8_t actual_hash[ST_SHA256_LEN];
    char token_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)request->access_token, strlen(request->access_token), actual_hash);
    st_hex_encode(actual_hash, sizeof(actual_hash), token_hash);

    st_storage_client_session client_session;
    if (st_storage_get_client_session_for_login(config->database_path,
                                                request->client_session_id,
                                                token_hash,
                                                &client_session) != 0) {
        return -1;
    }
    if (strcmp(request->client_name, client_session.client_name) != 0) {
        *reason = "客户端访问令牌无效";
        return 0;
    }
    if (strcmp(client_session.status, "HTTP_AUTHENTICATED") != 0) {
        *reason = "同一台机器和用户已经有在线实例";
        return 0;
    }
    char now_text[64];
    if (current_utc_timestamp(now_text) != 0) {
        *reason = "服务器时间不可用";
        return 0;
    }
    if (client_session.expires_at[0] != '\0' && strcmp(client_session.expires_at, now_text) <= 0) {
        (void)st_storage_mark_client_session_disconnected(config->database_path, client_session.id, now_text);
        *reason = "客户端访问令牌已过期";
        return 0;
    }

    st_storage_client client;
    st_storage_client_credential credential;
    if (st_storage_get_client(config->database_path, client_session.client_id, &client) != 0
        || st_storage_get_client_credential(config->database_path, client_session.credential_id, &credential) != 0) {
        *reason = "客户端不存在";
        return 0;
    }
    if (!client.enabled || !credential.enabled) {
        *reason = "客户端已停用";
        return 0;
    }

    int online_count = 0;
    if (st_storage_count_online_sessions_by_machine(config->database_path,
                                                    client_session.credential_id,
                                                    client_session.machine_fingerprint,
                                                    client_session.os_user,
                                                    client_session.id,
                                                    &online_count) != 0) {
        *reason = "客户端在线状态不可用";
        return 0;
    }
    if (online_count >= 1) {
        *reason = "同一台机器和用户已经有在线实例";
        return 0;
    }
    if (st_storage_count_online_sessions_by_credential(config->database_path,
                                                       client_session.credential_id,
                                                       client_session.id,
                                                       &online_count) != 0) {
        *reason = "客户端在线状态不可用";
        return 0;
    }
    if (credential.max_online_instances > 0 && online_count >= credential.max_online_instances) {
        *reason = "在线实例数已达上限";
        return 0;
    }
    if (st_storage_mark_client_session_online(config->database_path,
                                              client_session.id,
                                              session->remote,
                                              session->remote,
                                              now_text) != 0) {
        *reason = "客户端会话状态更新失败";
        return 0;
    }
    if (reload_config_for_client_session(config, &client_session) != 0) {
        (void)st_storage_mark_client_session_disconnected(config->database_path, client_session.id, now_text);
        *reason = "客户端配置加载失败";
        return 0;
    }
    memcpy(config->access_token_hash, actual_hash, sizeof(config->access_token_hash));
    *reason = NULL;
    return 1;
}

static int verify_login(tunnel_session *session, const st_login_request *request, const char **reason)
{
    server_config *config = &session->config;
    if (request->client_name == NULL
        || request->client_session_id <= 0
        || request->access_token == NULL
        || request->access_token[0] == '\0') {
        *reason = "登录包缺少必要字段";
        return 0;
    }

    int database_login = verify_database_login(session, request, reason);
    if (database_login >= 0) {
        return database_login;
    }

    if (strcmp(request->client_name, config->client_name) != 0) {
        *reason = "客户端不存在或未启用";
        return 0;
    }
    if (request->client_session_id != config->client_session_id) {
        *reason = "客户端访问令牌无效";
        return 0;
    }
    uint8_t actual_hash[ST_SHA256_LEN];
    st_sha256((const uint8_t *)request->access_token, strlen(request->access_token), actual_hash);
    if (!st_constant_time_eq(actual_hash, config->access_token_hash, sizeof(actual_hash))) {
        *reason = "客户端访问令牌无效";
        return 0;
    }

    *reason = NULL;
    return 1;
}

static void remote_text(const struct sockaddr_storage *remote, socklen_t remote_len, char *out, size_t out_len)
{
    (void)remote_len;
    if (remote->ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)remote;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        snprintf(out, out_len, "%s:%d", ip, ntohs(addr->sin_port));
        return;
    }
    if (remote->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)remote;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr->sin6_addr, ip, sizeof(ip));
        snprintf(out, out_len, "[%s]:%d", ip, ntohs(addr->sin6_port));
        return;
    }
    snprintf(out, out_len, "unknown");
}

static void remote_endpoint(const struct sockaddr_storage *remote,
                            char *address,
                            size_t address_len,
                            int *port,
                            char *text,
                            size_t text_len)
{
    *port = 0;
    if (remote->ss_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)remote;
        inet_ntop(AF_INET, &addr->sin_addr, address, address_len);
        *port = ntohs(addr->sin_port);
        snprintf(text, text_len, "%s:%d", address, *port);
        return;
    }
    if (remote->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)remote;
        inet_ntop(AF_INET6, &addr->sin6_addr, address, address_len);
        *port = ntohs(addr->sin6_port);
        snprintf(text, text_len, "[%s]:%d", address, *port);
        return;
    }
    snprintf(address, address_len, "unknown");
    snprintf(text, text_len, "unknown");
}

static int create_listener(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 128) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static void configure_control_socket(int fd, const server_config *config)
{
    struct timeval timeout;
    timeout.tv_sec = config->control_read_idle_seconds;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
}

static int mapping_allowed(const server_config *config, int port, const char *address, int tunnel_port)
{
    for (size_t i = 0; i < config->mapping_count; ++i) {
        const tcp_mapping *mapping = &config->mappings[i];
        if (mapping->port == port
            && mapping->tunnel_port == tunnel_port
            && strcmp(mapping->tunnel_address, address) == 0) {
            return 1;
        }
    }
    return 0;
}

static char *json_register_result(int port, int success, const char *reason)
{
    char *escaped_reason = st_json_escape(reason == NULL ? "" : reason);
    if (escaped_reason == NULL) {
        return NULL;
    }
    string_builder builder = {0};
    int rc = success
        ? sb_appendf(&builder, "{\"port\":%d,\"success\":true}", port)
        : sb_appendf(&builder, "{\"port\":%d,\"success\":false,\"reason\":\"%s\"}", port, escaped_reason);
    free(escaped_reason);
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static char *json_connected(const char *channel_id, int port)
{
    char *escaped_id = st_json_escape(channel_id);
    if (escaped_id == NULL) {
        return NULL;
    }
    string_builder builder = {0};
    int rc = sb_appendf(&builder, "{\"channelId\":\"%s\",\"port\":%d}", escaped_id, port);
    free(escaped_id);
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static char *json_channel(const char *channel_id)
{
    char *escaped_id = st_json_escape(channel_id);
    if (escaped_id == NULL) {
        return NULL;
    }
    string_builder builder = {0};
    int rc = sb_appendf(&builder, "{\"channelId\":\"%s\"}", escaped_id);
    free(escaped_id);
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static char *json_ws_channel(const char *channel_id)
{
    char *escaped_id = st_json_escape(channel_id);
    if (escaped_id == NULL) {
        return NULL;
    }
    string_builder builder = {0};
    int rc = sb_appendf(&builder, "{\"channelId\":\"%s\",\"source\":\"ws\"}", escaped_id);
    free(escaped_id);
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static int append_json_property(string_builder *builder,
                                const char *name,
                                const char *value,
                                int *first)
{
    char *escaped = st_json_escape(value == NULL ? "" : value);
    if (escaped == NULL) {
        return -1;
    }
    int rc = sb_appendf(builder,
                        "%s\"%s\":\"%s\"",
                        *first ? "" : ",",
                        name,
                        escaped);
    free(escaped);
    *first = 0;
    return rc;
}

static char *json_ws_connected(const st_admin_direct_ws_request *request)
{
    string_builder builder = {0};
    int rc = sb_append(&builder, "{");
    int first = 1;
    if (rc == 0) {
        rc = append_json_property(&builder, "source", "ws", &first);
    }
    if (rc == 0) {
        rc = append_json_property(&builder, "channelId", request->channel_id, &first);
    }
    if (rc == 0) {
        rc = append_json_property(&builder, "clientName", request->client_name, &first);
    }
    if (rc == 0) {
        rc = append_json_property(&builder, "route", request->route, &first);
    }
    if (rc == 0) {
        rc = append_json_property(&builder, "relativePath", request->relative_path, &first);
    }
    if (rc == 0) {
        rc = append_json_property(&builder, "rawQuery", request->raw_query, &first);
    }
    if (rc == 0) {
        rc = sb_append(&builder, first ? "\"headers\":[" : ",\"headers\":[");
        first = 0;
    }
    for (size_t i = 0; rc == 0 && i < request->headers_len; ++i) {
        char *escaped = st_json_escape(request->headers[i] == NULL ? "" : request->headers[i]);
        if (escaped == NULL) {
            rc = -1;
            break;
        }
        rc = sb_appendf(&builder, "%s\"%s\"", i == 0 ? "" : ",", escaped);
        free(escaped);
    }
    if (rc == 0) {
        rc = sb_append(&builder, "],\"body\":\"\"}");
    }
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static int send_nat_with_json(tunnel_session *session, int type, char *json, const uint8_t *data, size_t data_len)
{
    if (json == NULL) {
        return -1;
    }
    st_buffer packet = st_protocol_encode_nat_message(type, json, data, data_len);
    free(json);
    return session_send_packet(session, &packet);
}

static int send_register_result(tunnel_session *session, int port, int success, const char *reason)
{
    return send_nat_with_json(session, ST_NAT_REGISTER_RESULT,
                              json_register_result(port, success, reason),
                              NULL, 0);
}

static int send_connected(tunnel_session *session, const char *channel_id, int port)
{
    return send_nat_with_json(session, ST_NAT_CONNECTED, json_connected(channel_id, port), NULL, 0);
}

static int send_disconnected(tunnel_session *session, const char *channel_id)
{
    return send_nat_with_json(session, ST_NAT_DISCONNECTED, json_channel(channel_id), NULL, 0);
}

static int send_data(tunnel_session *session, const char *channel_id, const uint8_t *data, size_t data_len)
{
    return send_nat_with_json(session, ST_NAT_DATA, json_channel(channel_id), data, data_len);
}

static int send_ws_connected(tunnel_session *session, const st_admin_direct_ws_request *request)
{
    return send_nat_with_json(session, ST_NAT_CONNECTED, json_ws_connected(request), NULL, 0);
}

static int send_ws_disconnected(tunnel_session *session, const char *channel_id)
{
    return send_nat_with_json(session, ST_NAT_DISCONNECTED, json_ws_channel(channel_id), NULL, 0);
}

static int send_ws_data(tunnel_session *session, const char *channel_id, const uint8_t *data, size_t data_len)
{
    return send_nat_with_json(session, ST_NAT_DATA, json_ws_channel(channel_id), data, data_len);
}

static external_conn *find_conn_locked(tunnel_session *session, const char *channel_id)
{
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (!conn->done && strcmp(conn->channel_id, channel_id) == 0) {
            return conn;
        }
    }
    return NULL;
}

static ws_conn *find_ws_conn_locked(tunnel_session *session, const char *channel_id)
{
    for (ws_conn *conn = session->ws_conns; conn != NULL; conn = conn->next) {
        if (strcmp(conn->channel_id, channel_id) == 0) {
            return conn;
        }
    }
    return NULL;
}

static ws_conn *remove_ws_conn_locked(tunnel_session *session, const char *channel_id)
{
    ws_conn **cursor = &session->ws_conns;
    while (*cursor != NULL) {
        if (strcmp((*cursor)->channel_id, channel_id) == 0) {
            ws_conn *removed = *cursor;
            *cursor = removed->next;
            removed->next = NULL;
            return removed;
        }
        cursor = &(*cursor)->next;
    }
    return NULL;
}

static void release_external_count(external_conn *conn)
{
    if (!conn->counted) {
        return;
    }
    pthread_mutex_lock(&global_external_lock);
    if (global_external_connections > 0) {
        --global_external_connections;
    }
    conn->counted = 0;
    pthread_mutex_unlock(&global_external_lock);
}

static void close_conn_locked(external_conn *conn)
{
    if (conn->fd >= 0) {
        shutdown(conn->fd, SHUT_RDWR);
        close(conn->fd);
        conn->fd = -1;
    }
    release_external_count(conn);
    conn->done = 1;
}

static int count_external_locked(tunnel_session *session, int port, int *client_count, int *port_count)
{
    int total = 0;
    int on_port = 0;
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (!conn->done) {
            ++total;
            if (conn->port == port) {
                ++on_port;
            }
        }
    }
    *client_count = total;
    *port_count = on_port;
    return 0;
}

static int try_count_external_connection(external_conn *conn)
{
    tunnel_session *session = conn->session;
    int client_count = 0;
    int port_count = 0;
    count_external_locked(session, conn->port, &client_count, &port_count);
    if (client_count >= session->config.max_client_external_connections
        || port_count >= session->config.max_port_external_connections) {
        return -1;
    }

    pthread_mutex_lock(&global_external_lock);
    if (global_external_connections >= session->config.max_global_external_connections) {
        pthread_mutex_unlock(&global_external_lock);
        return -1;
    }
    ++global_external_connections;
    conn->counted = 1;
    pthread_mutex_unlock(&global_external_lock);
    return 0;
}

static void mark_conn_done(external_conn *conn)
{
    tunnel_session *session = conn->session;
    pthread_mutex_lock(&session->map_lock);
    close_conn_locked(conn);
    pthread_mutex_unlock(&session->map_lock);
}

static void *external_conn_thread(void *arg)
{
    external_conn *conn = (external_conn *)arg;
    tunnel_session *session = conn->session;
    printf("[nat] external connected channel=%s port=%d client=%s\n",
           conn->channel_id, conn->port, session->config.client_name);

    if (send_connected(session, conn->channel_id, conn->port) != 0) {
        mark_conn_done(conn);
        return NULL;
    }

    uint8_t buffer[ST_IO_BUFFER_SIZE];
    for (;;) {
        int fd;
        pthread_mutex_lock(&session->map_lock);
        fd = conn->fd;
        pthread_mutex_unlock(&session->map_lock);
        if (fd < 0) {
            break;
        }
        ssize_t read_len = recv(fd, buffer, sizeof(buffer), 0);
        if (read_len > 0) {
            if (send_data(session, conn->channel_id, buffer, (size_t)read_len) != 0) {
                break;
            }
            record_tcp_traffic(session, conn->port, (long long)read_len, 0);
            record_tcp_frame(session, conn, "PUBLIC_TO_CLIENT", buffer, (size_t)read_len);
            continue;
        }
        if (read_len < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    send_disconnected(session, conn->channel_id);
    mark_conn_done(conn);
    printf("[nat] external closed channel=%s port=%d client=%s\n",
           conn->channel_id, conn->port, session->config.client_name);
    return NULL;
}

static int start_external_conn(tunnel_session *session,
                               int fd,
                               int port,
                               const struct sockaddr_storage *remote)
{
    external_conn *conn = (external_conn *)calloc(1, sizeof(*conn));
    if (conn == NULL) {
        close(fd);
        return -1;
    }
    conn->fd = fd;
    conn->port = port;
    conn->session = session;
    if (remote != NULL) {
        remote_endpoint(remote,
                        conn->remote_ip,
                        sizeof(conn->remote_ip),
                        &conn->remote_port,
                        conn->remote_address,
                        sizeof(conn->remote_address));
    }

    pthread_mutex_lock(&session->map_lock);
    if (try_count_external_connection(conn) != 0) {
        pthread_mutex_unlock(&session->map_lock);
        fprintf(stderr, "[nat] reject external connection on port=%d client=%s: limit reached\n",
                port, session->config.client_name);
        close(fd);
        free(conn);
        return -1;
    }
    snprintf(conn->channel_id, sizeof(conn->channel_id), "c-%llu",
             (unsigned long long)session->next_channel_id++);
    conn->next = session->conns;
    session->conns = conn;
    pthread_mutex_unlock(&session->map_lock);

    if (pthread_create(&conn->thread, NULL, external_conn_thread, conn) != 0) {
        perror("pthread_create");
        pthread_mutex_lock(&session->map_lock);
        close_conn_locked(conn);
        pthread_mutex_unlock(&session->map_lock);
        return -1;
    }
    conn->thread_started = 1;
    return 0;
}

static void *listener_thread(void *arg)
{
    tunnel_listener *listener = (tunnel_listener *)arg;
    tunnel_session *session = listener->session;
    printf("[nat] listening on 0.0.0.0:%d for client=%s\n",
           listener->port, session->config.client_name);

    for (;;) {
        struct sockaddr_storage remote;
        socklen_t remote_len = sizeof(remote);
        int fd = accept(listener->fd, (struct sockaddr *)&remote, &remote_len);
        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        start_external_conn(session, fd, listener->port, &remote);
    }

    pthread_mutex_lock(&session->map_lock);
    if (listener->fd >= 0) {
        close(listener->fd);
        listener->fd = -1;
    }
    listener->done = 1;
    pthread_mutex_unlock(&session->map_lock);
    printf("[nat] listener stopped port=%d client=%s\n",
           listener->port, session->config.client_name);
    return NULL;
}

static int listener_exists_locked(tunnel_session *session, int port)
{
    for (tunnel_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (!listener->done && listener->fd >= 0 && listener->port == port) {
            return 1;
        }
    }
    return 0;
}

static int start_tunnel_listener(tunnel_session *session, int port, char *reason, size_t reason_len)
{
    int fd = create_listener(port);
    if (fd < 0) {
        snprintf(reason, reason_len, "port %d bind failed", port);
        return -1;
    }

    tunnel_listener *listener = (tunnel_listener *)calloc(1, sizeof(*listener));
    if (listener == NULL) {
        close(fd);
        snprintf(reason, reason_len, "server out of memory");
        return -1;
    }
    listener->fd = fd;
    listener->port = port;
    listener->session = session;

    pthread_mutex_lock(&session->map_lock);
    if (listener_exists_locked(session, port)) {
        pthread_mutex_unlock(&session->map_lock);
        close(fd);
        free(listener);
        snprintf(reason, reason_len, "port %d already registered", port);
        return -1;
    }
    listener->next = session->listeners;
    session->listeners = listener;
    pthread_mutex_unlock(&session->map_lock);

    if (pthread_create(&listener->thread, NULL, listener_thread, listener) != 0) {
        perror("pthread_create");
        pthread_mutex_lock(&session->map_lock);
        close(listener->fd);
        listener->fd = -1;
        listener->done = 1;
        pthread_mutex_unlock(&session->map_lock);
        snprintf(reason, reason_len, "failed to start listener thread");
        return -1;
    }
    listener->thread_started = 1;
    return 0;
}

static void stop_tunnel_listener(tunnel_session *session, int port)
{
    pthread_mutex_lock(&session->map_lock);
    for (tunnel_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (!listener->done && listener->port == port) {
            if (listener->fd >= 0) {
                shutdown(listener->fd, SHUT_RDWR);
                close(listener->fd);
                listener->fd = -1;
            }
            listener->done = 1;
        }
    }
    pthread_mutex_unlock(&session->map_lock);
}

static void process_register(tunnel_session *session, const st_nat_message *message)
{
    int port;
    int tunnel_port;
    char *tunnel_address = st_json_get_string(message->meta_json, "tunnelAddress");
    char *client_name = st_json_get_string(message->meta_json, "clientName");
    if (st_json_get_int(message->meta_json, "port", &port) != 0
        || st_json_get_int(message->meta_json, "tunnelPort", &tunnel_port) != 0
        || tunnel_address == NULL
        || client_name == NULL) {
        send_register_result(session, 0, 0, "missing required metadata");
        free(tunnel_address);
        free(client_name);
        return;
    }

    if (strcmp(client_name, session->config.client_name) != 0) {
        send_register_result(session, port, 0, "clientName mismatch");
        free(tunnel_address);
        free(client_name);
        return;
    }
    if (!mapping_allowed(&session->config, port, tunnel_address, tunnel_port)) {
        send_register_result(session, port, 0, "port mapping not configured");
        free(tunnel_address);
        free(client_name);
        return;
    }

    char reason[128];
    if (start_tunnel_listener(session, port, reason, sizeof(reason)) != 0) {
        send_register_result(session, port, 0, reason);
        free(tunnel_address);
        free(client_name);
        return;
    }

    printf("[nat] register ok client=%s port=%d -> %s:%d\n",
           client_name, port, tunnel_address, tunnel_port);
    send_register_result(session, port, 1, NULL);
    free(tunnel_address);
    free(client_name);
}

static void process_control_data(tunnel_session *session, const st_nat_message *message)
{
    if (message->data == NULL || message->data_len == 0) {
        return;
    }
    char *channel_id = st_json_get_string(message->meta_json, "channelId");
    if (channel_id == NULL) {
        return;
    }

    pthread_mutex_lock(&session->map_lock);
    external_conn *conn = find_conn_locked(session, channel_id);
    ws_conn *ws = NULL;
    ws_conn *removed_ws = NULL;
    st_admin_direct_ws_stream *stream_to_close = NULL;
    int port = 0;
    int record_download = 0;
    if (conn != NULL && conn->fd >= 0) {
        port = conn->port;
        if (send_all(conn->fd, message->data, message->data_len) != 0) {
            close_conn_locked(conn);
        } else {
            record_download = 1;
            record_tcp_frame(session, conn, "CLIENT_TO_PUBLIC", message->data, message->data_len);
        }
    }
    if (conn == NULL) {
        ws = find_ws_conn_locked(session, channel_id);
        if (ws != NULL
            && st_admin_direct_ws_send_framed_payload(ws->stream, message->data, message->data_len) != 0) {
            removed_ws = remove_ws_conn_locked(session, channel_id);
            if (removed_ws != NULL) {
                stream_to_close = removed_ws->stream;
            }
        }
    }
    pthread_mutex_unlock(&session->map_lock);
    if (stream_to_close != NULL) {
        st_admin_direct_ws_close(stream_to_close);
    }
    free(removed_ws);
    if (record_download) {
        record_tcp_traffic(session, port, 0, (long long)message->data_len);
    }
    free(channel_id);
}

static void process_control_disconnected(tunnel_session *session, const st_nat_message *message)
{
    char *channel_id = st_json_get_string(message->meta_json, "channelId");
    if (channel_id == NULL) {
        return;
    }
    pthread_mutex_lock(&session->map_lock);
    external_conn *conn = find_conn_locked(session, channel_id);
    if (conn != NULL) {
        close_conn_locked(conn);
    }
    ws_conn *removed_ws = NULL;
    if (conn == NULL) {
        removed_ws = remove_ws_conn_locked(session, channel_id);
    }
    pthread_mutex_unlock(&session->map_lock);
    if (removed_ws != NULL) {
        st_admin_direct_ws_close(removed_ws->stream);
        free(removed_ws);
    }
    free(channel_id);
}

static void process_unregister(tunnel_session *session, const st_nat_message *message)
{
    int port;
    if (st_json_get_int(message->meta_json, "port", &port) == 0) {
        printf("[nat] unregister port=%d client=%s\n", port, session->config.client_name);
        stop_tunnel_listener(session, port);
    }
}

static void process_nat_message(tunnel_session *session, const st_nat_message *message)
{
    switch (message->type) {
        case ST_NAT_REGISTER:
            process_register(session, message);
            break;
        case ST_NAT_UNREGISTER:
            process_unregister(session, message);
            break;
        case ST_NAT_DATA:
            process_control_data(session, message);
            break;
        case ST_NAT_DISCONNECTED:
            process_control_disconnected(session, message);
            break;
        case ST_NAT_KEEPALIVE:
        case ST_NAT_HTTP_ROUTES_REPORT:
            break;
        default:
            printf("[nat] ignored type=%d client=%s\n", message->type, session->config.client_name);
            break;
    }
}

static void session_shutdown(tunnel_session *session)
{
    direct_pending_fail_all(session, "control connection closed");

    pthread_mutex_lock(&session->send_lock);
    if (session->control_fd >= 0) {
        shutdown(session->control_fd, SHUT_RDWR);
        close(session->control_fd);
        session->control_fd = -1;
    }
    pthread_mutex_unlock(&session->send_lock);

    pthread_mutex_lock(&session->map_lock);
    session->active = 0;
    for (tunnel_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (listener->fd >= 0) {
            shutdown(listener->fd, SHUT_RDWR);
            close(listener->fd);
            listener->fd = -1;
        }
    }
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (conn->fd >= 0) {
            shutdown(conn->fd, SHUT_RDWR);
            close(conn->fd);
            conn->fd = -1;
        }
    }
    for (ws_conn *conn = session->ws_conns; conn != NULL; conn = conn->next) {
        st_admin_direct_ws_close(conn->stream);
    }
    pthread_mutex_unlock(&session->map_lock);

    for (tunnel_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (listener->thread_started) {
            pthread_join(listener->thread, NULL);
        }
    }
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (conn->thread_started) {
            pthread_join(conn->thread, NULL);
        }
    }

    tunnel_listener *listener = session->listeners;
    while (listener != NULL) {
        tunnel_listener *next = listener->next;
        free(listener);
        listener = next;
    }
    external_conn *conn = session->conns;
    while (conn != NULL) {
        external_conn *next = conn->next;
        free(conn);
        conn = next;
    }
    ws_conn *ws = session->ws_conns;
    while (ws != NULL) {
        ws_conn *next = ws->next;
        free(ws);
        ws = next;
    }
    session->ws_conns = NULL;
    if (session->config.owns_nat_control_json) {
        free(session->config.nat_control_json);
        session->config.nat_control_json = NULL;
        session->config.owns_nat_control_json = 0;
    }
}

static void *client_thread(void *arg)
{
    client_args *args = (client_args *)arg;
    tunnel_session *session = (tunnel_session *)calloc(1, sizeof(*session));
    if (session == NULL) {
        close(args->fd);
        free(args);
        return NULL;
    }
    session->control_fd = args->fd;
    session->config = args->config;
    session->active = 1;
    session->next_channel_id = 1;
    pthread_mutex_init(&session->send_lock, NULL);
    pthread_mutex_init(&session->map_lock, NULL);
    pthread_mutex_init(&session->direct_lock, NULL);
    remote_text(&args->remote, args->remote_len, session->remote, sizeof(session->remote));
    free(args);

    printf("[control] accepted %s\n", session->remote);

    int logged_in = 0;
    const char *disconnect_reason = "CLIENT_CLOSED";
    for (;;) {
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(session->control_fd, &header, &body);
        if (rc == 0) {
            disconnect_reason = "CLIENT_CLOSED";
            printf("[control] closed %s\n", session->remote);
            break;
        }
        if (rc == -2) {
            disconnect_reason = "IDLE_TIMEOUT";
            fprintf(stderr, "[control] read idle timeout from %s\n", session->remote);
            break;
        }
        if (rc < 0) {
            disconnect_reason = "PROTOCOL_VIOLATION";
            fprintf(stderr, "[control] bad frame from %s\n", session->remote);
            break;
        }

        if (!logged_in) {
            if (header.command != ST_CMD_LOGIN_REQUEST) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[control] non-login packet before auth from %s\n", session->remote);
                free(body);
                break;
            }
            st_login_request request;
            if (st_protocol_decode_login_request(body, header.length, &request) != 0) {
                free(body);
                st_buffer response = st_protocol_encode_login_response("", 0, "登录包无法解析");
                session_send_packet(session, &response);
                disconnect_reason = "PROTOCOL_VIOLATION";
                break;
            }
            free(body);

            const char *reason = NULL;
            logged_in = verify_login(session, &request, &reason);
            st_buffer response = st_protocol_encode_login_response(
                request.client_name == NULL ? "" : request.client_name,
                logged_in,
                reason);
            if (session_send_packet(session, &response) != 0) {
                st_login_request_free(&request);
                break;
            }
            if (!logged_in) {
                printf("[control] login rejected client=%s remote=%s reason=%s\n",
                       request.client_name == NULL ? "" : request.client_name,
                       session->remote,
                       reason == NULL ? "" : reason);
                record_login_failure_event(&session->config,
                                           request.client_name,
                                           session->remote,
                                           reason == NULL ? "登录失败" : reason);
                st_login_request_free(&request);
                break;
            }
            printf("[control] login ok client=%s remote=%s\n", request.client_name, session->remote);
            pthread_mutex_lock(&active_session_lock);
            active_session_add_locked(session);
            pthread_mutex_unlock(&active_session_lock);
            record_login_success_event(session);
            st_buffer nat_control = st_protocol_encode_nat_control(session->config.client_name,
                                                                   session->config.nat_control_json);
            if (session_send_packet(session, &nat_control) != 0) {
                disconnect_reason = "IO_ERROR";
                st_login_request_free(&request);
                break;
            }
            printf("[nat-control] pushed %zu tcp route(s) to %s\n",
                   session->config.mapping_count, session->config.client_name);
            st_login_request_free(&request);
            continue;
        }

        if (header.command == ST_CMD_HEARTBEAT_REQUEST) {
            free(body);
            st_buffer response = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
            if (session_send_packet(session, &response) != 0) {
                disconnect_reason = "HEARTBEAT_WRITE_FAILED";
                break;
            }
            continue;
        }

        if (header.command == ST_CMD_LOGOUT_REQUEST) {
            free(body);
            st_buffer response = st_protocol_encode_empty_packet(ST_CMD_LOGOUT_RESPONSE);
            session_send_packet(session, &response);
            disconnect_reason = "CLIENT_CLOSED";
            break;
        }

        if (header.command == ST_CMD_NAT_MESSAGE) {
            st_nat_message message;
            if (st_protocol_decode_nat_message(body, header.length, &message) != 0) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[nat] bad NAT frame from %s\n", session->remote);
                free(body);
                break;
            }
            free(body);
            process_nat_message(session, &message);
            st_nat_message_free(&message);
            continue;
        }

        if (header.command == ST_CMD_DIRECT_HTTP_RESPONSE) {
            st_direct_http_response response;
            if (st_protocol_decode_direct_http_response(body, header.length, &response) != 0) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[direct-http] bad response from %s\n", session->remote);
                free(body);
                break;
            }
            free(body);
            if (!process_direct_http_response(session, &response)) {
                printf("[direct-http] unmatched response requestId=%s client=%s\n",
                       response.request_id == NULL ? "" : response.request_id,
                       session->config.client_name);
                st_direct_http_response_free(&response);
            }
            continue;
        }

        printf("[control] unsupported command=%d from %s; keeping connection open\n",
               (int)header.command, session->remote);
        free(body);
    }

    direct_pending_fail_all(session, "control connection closed");

    pthread_mutex_lock(&active_session_lock);
    active_session_remove_locked(session);
    pthread_mutex_unlock(&active_session_lock);
    if (logged_in) {
        if (session->config.database_path[0] != '\0'
            && session->config.client_session_db_backed
            && session->config.client_session_id > 0) {
            char disconnected_at[64];
            if (current_utc_timestamp(disconnected_at) == 0) {
                (void)st_storage_mark_client_session_disconnected(session->config.database_path,
                                                                  session->config.client_session_id,
                                                                  disconnected_at);
            }
        }
        record_session_disconnected_event(session, disconnect_reason);
    }
    session_shutdown(session);
    pthread_mutex_destroy(&session->send_lock);
    pthread_mutex_destroy(&session->map_lock);
    pthread_mutex_destroy(&session->direct_lock);
    free(session);
    return NULL;
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);

    server_config config;
    if (load_config(&config) != 0) {
        return 1;
    }

    int listener = create_listener(config.port);
    if (listener < 0) {
        free(config.nat_control_json);
        return 1;
    }
    printf("shuai-tunnel-server-c listening on 0.0.0.0:%d for client \"%s\" (%zu tcp route(s))\n",
           config.port, config.client_name, config.mapping_count);

    st_admin_server admin_server;
    if (config.admin_port > 0
        && st_admin_server_start_with_handlers(&admin_server,
                                               config.admin_port,
                                               config.static_root,
                                               direct_http_forward,
                                               &config,
                                               direct_ws_open,
                                               direct_ws_data,
                                               direct_ws_close,
                                               &config)
            != 0) {
        close(listener);
        free(config.nat_control_json);
        return 1;
    }

    for (;;) {
        client_args *args = (client_args *)calloc(1, sizeof(*args));
        if (args == NULL) {
            fprintf(stderr, "out of memory\n");
            break;
        }
        args->remote_len = sizeof(args->remote);
        args->fd = accept(listener, (struct sockaddr *)&args->remote, &args->remote_len);
        if (args->fd < 0) {
            free(args);
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            break;
        }
        args->config = config;
        args->config.owns_nat_control_json = 0;
        int one = 1;
        setsockopt(args->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        configure_control_socket(args->fd, &config);

        pthread_t thread;
        if (pthread_create(&thread, NULL, client_thread, args) != 0) {
            perror("pthread_create");
            close(args->fd);
            free(args);
            continue;
        }
        pthread_detach(thread);
    }

    close(listener);
    free(config.nat_control_json);
    return 0;
}
