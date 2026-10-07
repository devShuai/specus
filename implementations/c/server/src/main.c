#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "crypto.h"
#include "elasticsearch_traffic.h"
#include "http_share.h"
#include "json.h"
#include "media_capture.h"
#include "object_storage.h"
#include "peer_mesh.h"
#include "product_metrics.h"
#include "protocol.h"
#include "public_discovery.h"
#include "security_baseline.h"
#include "storage.h"
#include "stream_tombstones.h"
#include "stun_turn.h"
#include "tls_transport.h"
#include "workbench.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
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
#define ST_STREAM_INITIAL_WINDOW (1024U * 1024U)
#define ST_MAX_DATA_FRAME_BYTES (64U * 1024U)
#define ST_STREAM_MAX_PENDING_BYTES (4U * 1024U * 1024U)
#define ST_STREAM_MAX_WINDOW (16U * 1024U * 1024U)
#define ST_MAX_PENDING_DIRECT_STREAMS 1024U
#define ST_MAX_QUEUED_DATA_EVENTS 4096U
#define ST_HTTP_MAX_REQUEST_BODY (16U * 1024U * 1024U)
#define ST_HTTP_MAX_RESPONSE_BODY (64U * 1024U * 1024U)
/* How long a graceful shutdown waits for closed channels to finish their bookkeeping. */
#define ST_SHUTDOWN_DRAIN_SECONDS 10
/* Upper bound on NETTY_ONLINE rows one control login inspects for stale-session cleanup. */
#define ST_MAX_STALE_SESSION_SCAN 256U
/* A displaced client has at most one control and one data connection; slack covers a race. */
#define ST_MAX_DISPLACED_SESSIONS 8U

typedef struct {
    long long id;
    int port;
    char specus_address[256];
    int specus_port;
    int detail_capture_enabled;
} tcp_mapping;

typedef struct {
    long long id;
    char route[128];
    char target_base_url[512];
    int detail_capture_enabled;
    int path_rewrite_enabled;
    int insecure_skip_verify;
} http_route_mapping;

typedef struct {
    int64_t client_id;
    char tenant_id[64];
    char client_name[128];
    int64_t client_session_id;
    int peer_service_discovery_version;
    /* clientHttpRouteCapabilities.version of the login session; RST failure is trusted from 1. */
    int client_http_route_version;
    uint8_t access_token_hash[ST_SHA256_LEN];
    int port;
    char bind_address[128];
    char public_address[256];
    int control_read_idle_seconds;
    int control_write_timeout_seconds;
    int per_machine_user_max_instances;
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
    st_tls_server_context *tls_context;
} server_config;

typedef struct specus_session specus_session;

typedef struct external_write_chunk {
    uint8_t *data;
    size_t len;
    struct external_write_chunk *next;
} external_write_chunk;

typedef struct external_conn {
    int fd;
    int port;
    uint32_t stream_id;
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
    pthread_t writer_thread;
    int writer_thread_started;
    int done;
    int counted;
    pthread_mutex_t flow_lock;
    pthread_cond_t flow_cond;
    uint64_t send_credit;
    int flow_closed;
    int public_finished;
    int client_finished;
    int client_write_drained;
    pthread_mutex_t write_lock;
    pthread_cond_t write_cond;
    external_write_chunk *write_head;
    external_write_chunk *write_tail;
    size_t queued_write_bytes;
    int write_closed;
    specus_session *session;
    struct external_conn *next;
} external_conn;

typedef struct specus_listener {
    int fd;
    int port;
    pthread_t thread;
    int thread_started;
    int done;
    specus_session *session;
    struct specus_listener *next;
} specus_listener;

typedef struct direct_http_event {
    int type;
    char *meta_json;
    uint8_t *data;
    size_t data_len;
    struct direct_http_event *next;
} direct_http_event;

typedef struct direct_http_pending {
    uint32_t stream_id;
    int done;
    int response_started;
    /* Either side reset the stream; frames the client sent before it saw an RST are dropped. */
    int reset;
    /* Set when error holds the client's RST reason rather than a server-side failure. */
    int client_reset;
    /* The temporary HTTP share the request came through ended: reset the stream and stop. */
    int cancelled;
    uint32_t reset_code;
    /* metadata.failure of the client's RST, for the connectivity check; "" when absent. */
    char failure[32];
    char *error;
    direct_http_event *events_head;
    direct_http_event *events_tail;
    size_t event_count;
    uint64_t send_credit;
    uint64_t receive_credit;
    uint64_t receive_outstanding;
    uint64_t response_bytes;
    pthread_cond_t cond;
    struct direct_http_pending *next;
} direct_http_pending;

typedef struct ws_conn {
    char channel_id[ST_CHANNEL_ID_SIZE];
    uint32_t stream_id;
    st_admin_direct_ws_stream *stream;
    struct ws_conn *next;
} ws_conn;

struct specus_session {
    int control_fd;
    st_tls_connection *tls_connection;
    int is_data_connection;
    server_config config;
    pthread_mutex_t send_lock;
    pthread_mutex_t map_lock;
    pthread_mutex_t direct_lock;
    pthread_cond_t reference_cond;
    external_conn *conns;
    ws_conn *ws_conns;
    specus_listener *listeners;
    direct_http_pending *direct_pending;
    int active;
    /* Set, under active_session_lock, when a newer login of the same client took this role over. */
    int replaced;
    size_t references;
    uint32_t next_stream_id;
    /* Recently closed NAT streams of this data connection, guarded by map_lock. */
    st_stream_tombstones closed_streams;
    char remote[128];
    long long connection_record_id;
    long long connected_since_ms;
    char connected_at[64];
    struct specus_session *active_next;
    struct specus_session *live_next;
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
static specus_session *active_sessions = NULL;
/*
 * Serialises control-login admission (stale-session cleanup, the online-instance counts and the
 * NETTY_ONLINE write) with the DISCONNECTED write of a control connection that is going away.
 * Without it a re-login of the same session could be marked online and then overwritten by the
 * departing connection, leaving a live control whose session the database reports as offline.
 */
static pthread_mutex_t control_admission_lock = PTHREAD_MUTEX_INITIALIZER;
/*
 * Every accepted connection, logged in or not, so a graceful shutdown can close each of them and
 * wait for its bookkeeping. A session's socket is closed only while holding this lock, which lets
 * the shutdown path shut sockets down without racing a close.
 */
static pthread_mutex_t connection_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t connection_registry_cond = PTHREAD_COND_INITIALIZER;
static specus_session *live_connections = NULL;
static size_t live_connection_count = 0U;
static int server_stopping = 0;

static char *json_http_request(const st_direct_http_request *request);
static int send_reset(specus_session *session, uint32_t stream_id,
                      uint32_t code, const char *reason);
static int send_window_update(specus_session *session, uint32_t stream_id, size_t credit);

static int send_ws_open(specus_session *session, uint32_t stream_id,
                        const st_admin_direct_ws_request *request);
static int send_ws_fin(specus_session *session, uint32_t stream_id);
static int send_ws_data(specus_session *session, uint32_t stream_id,
                        const uint8_t *data, size_t data_len);
static ws_conn *find_ws_conn_locked(specus_session *session, const char *channel_id);
static ws_conn *remove_ws_conn_locked(specus_session *session, const char *channel_id);
static void free_ws_conn(ws_conn *conn);
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
    if (strcmp(name, "SPECUS_DB_SEED_DEMO_CLIENT") == 0
        && !st_deployment_environment_allows_demo_data(getenv("SPECUS_ENV"))) {
        return 0;
    }
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
    const char *raw = getenv("SPECUS_TCP_MAPPINGS");
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
            fprintf(stderr, "too many SPECUS_TCP_MAPPINGS entries; max is %u\n", (unsigned)ST_MAX_TCP_MAPPINGS);
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
        if (strlen(target_host) >= sizeof(config->mappings[0].specus_address)) {
            fprintf(stderr, "mapping target host is too long\n");
            free(copy);
            return -1;
        }

        tcp_mapping *mapping = &config->mappings[config->mapping_count];
        if (parse_port_text(public_port_text, &mapping->port) != 0
            || parse_port_text(target_port_text, &mapping->specus_port) != 0) {
            fprintf(stderr, "invalid mapping port in \"%s=%s:%s\"\n",
                    public_port_text, target_host, target_port_text);
            free(copy);
            return -1;
        }
        strcpy(mapping->specus_address, target_host);
        ++config->mapping_count;
        token = next_csv_token(&cursor);
    }
    free(copy);
    return 0;
}

static int parse_http_routes(server_config *config)
{
    const char *raw = getenv("SPECUS_HTTP_ROUTES");
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
            fprintf(stderr, "too many SPECUS_HTTP_ROUTES entries; max is %u\n", (unsigned)ST_MAX_TCP_MAPPINGS);
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
    if (st_storage_init(database_path, env_bool("SPECUS_DB_SEED_DEMO_CLIENT", 1)) != 0) {
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
        fprintf(stderr, "failed to load specus mappings from database\n");
        return -1;
    }
    for (size_t i = 0; i < mapping_count; ++i) {
        tcp_mapping *mapping = &config->mappings[config->mapping_count++];
        mapping->id = mappings[i].id;
        mapping->port = mappings[i].listen_port;
        strcpy(mapping->specus_address, mappings[i].target_address);
        mapping->specus_port = mappings[i].target_port;
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
        route->insecure_skip_verify = routes[i].insecure_skip_verify;
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
                   "{\"clientName\":\"%s\",\"remoteAddress\":\"%s\",\"remotePort\":%d,\"specusConfigList\":[",
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
        char *target = st_json_escape(config->mappings[i].specus_address);
        if (target == NULL) {
            free(builder.data);
            return -1;
        }
        int rc = sb_appendf(&builder,
                            "%s{\"port\":%d,\"specusAddress\":\"%s\",\"specusPort\":%d}",
                            i == 0 ? "" : ",",
                            config->mappings[i].port,
                            target,
                            config->mappings[i].specus_port);
        free(target);
        if (rc != 0) {
            free(builder.data);
            return -1;
        }
    }
    if (sb_append(&builder, "],\"httpSpecusConfigList\":[") != 0) {
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
                            "%s{\"route\":\"%s\",\"targetBaseUrl\":\"%s\",\"insecureSkipVerify\":%s}",
                            i == 0 ? "" : ",",
                            route,
                            target,
                            config->http_routes[i].insecure_skip_verify ? "true" : "false");
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
    const char *name = getenv("SPECUS_CLIENT_NAME");
    const char *access_token = getenv("SPECUS_CLIENT_ACCESS_TOKEN");
    const char *access_token_hash = getenv("SPECUS_CLIENT_ACCESS_TOKEN_HASH");
    const char *public_address = getenv("SPECUS_PUBLIC_ADDRESS");
    const char *bind_address = getenv("SPECUS_NETTY_BIND_ADDRESS");
    const char *database_path = getenv("SPECUS_DATABASE_PATH");
    const char *static_root = getenv("SPECUS_STATIC_ROOT");
    const char *tenant_id = getenv("SPECUS_CLIENT_TENANT_ID");
    if (tenant_id == NULL || *tenant_id == '\0') {
        tenant_id = getenv("SPECUS_AUTH_TENANT_ID");
    }

    memset(config, 0, sizeof(*config));
    if (copy_config_string(config->client_name, sizeof(config->client_name),
                           "SPECUS_CLIENT_NAME",
                           (name != NULL && *name != '\0') ? name : "Demo client") != 0
        || copy_config_string(config->tenant_id, sizeof(config->tenant_id),
                              "SPECUS_CLIENT_TENANT_ID",
                              (tenant_id != NULL && *tenant_id != '\0') ? tenant_id : "default") != 0
        || copy_config_string(config->public_address, sizeof(config->public_address),
                              "SPECUS_PUBLIC_ADDRESS",
                              (public_address != NULL && *public_address != '\0') ? public_address : "127.0.0.1") != 0
        || copy_config_string(config->bind_address, sizeof(config->bind_address),
                              "SPECUS_NETTY_BIND_ADDRESS",
                              (bind_address != NULL && *bind_address != '\0') ? bind_address : "0.0.0.0") != 0
        || env_int_range("SPECUS_NETTY_PORT", 7010, 1, 65535, &config->port) != 0
        || env_i64_range("SPECUS_CLIENT_ID", 0, 0, INT64_MAX, &config->client_id) != 0
        || env_i64_range("SPECUS_CLIENT_SESSION_ID", 1, 1, INT64_MAX, &config->client_session_id) != 0
        || env_int_range("SPECUS_CONTROL_READ_IDLE_SECONDS", 60, 5, 3600,
                         &config->control_read_idle_seconds) != 0
        || env_int_range("SPECUS_CONTROL_WRITE_TIMEOUT_SECONDS", 30, 1, 300,
                         &config->control_write_timeout_seconds) != 0
        || env_int_range("SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES", 1, 1, 1000000,
                         &config->per_machine_user_max_instances) != 0
        || env_int_range("SPECUS_MAX_GLOBAL_EXTERNAL_CONNECTIONS", 4096, 1, 1000000,
                         &config->max_global_external_connections) != 0
        || env_int_range("SPECUS_MAX_CLIENT_EXTERNAL_CONNECTIONS", 1024, 1, 1000000,
                         &config->max_client_external_connections) != 0
        || env_int_range("SPECUS_MAX_PORT_EXTERNAL_CONNECTIONS", 512, 1, 1000000,
                         &config->max_port_external_connections) != 0
        || env_int_range("SPECUS_ADMIN_PORT", 0, 0, 65535, &config->admin_port) != 0) {
        return -1;
    }
    if (copy_config_string(config->static_root, sizeof(config->static_root),
                           "SPECUS_STATIC_ROOT",
                           (static_root != NULL && *static_root != '\0')
                               ? static_root
                               : "implementations/java/server/src/main/resources/static") != 0) {
        return -1;
    }

    if (database_path != NULL && *database_path != '\0') {
        if (copy_config_string(config->database_path, sizeof(config->database_path),
                               "SPECUS_DATABASE_PATH", database_path) != 0) {
            return -1;
        }
        if (load_database_config(config, database_path) != 0) {
            return -1;
        }
        char startup_time[64];
        if (current_utc_timestamp(startup_time) == 0) {
            /* Nothing is connected yet, so every online session and open connection record was
             * left behind by a previous process that never ran its disconnect handlers. */
            (void)st_storage_close_client_sessions_by_status(database_path, "NETTY_ONLINE", startup_time);
            (void)st_storage_close_open_connections(database_path, "SERVER_RESTARTED", startup_time, NULL);
        }
    }
    if (access_token_hash != NULL && *access_token_hash != '\0') {
        if (st_hex_decode_32(access_token_hash, config->access_token_hash) != 0) {
            fprintf(stderr, "invalid SPECUS_CLIENT_ACCESS_TOKEN_HASH; expected 64 hex chars\n");
            return -1;
        }
    } else if (access_token != NULL && *access_token != '\0') {
        st_sha256((const uint8_t *)access_token, strlen(access_token), config->access_token_hash);
    } else if (config->database_path[0] == '\0') {
        if (access_token == NULL || *access_token == '\0') {
            fprintf(stderr, "SPECUS_CLIENT_ACCESS_TOKEN is required when SPECUS_CLIENT_ACCESS_TOKEN_HASH is unset\n");
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

/*
 * The client_online onboarding milestone of opt-in product metrics (product-metrics.md section 4.1)
 * after a successful control login: it belongs to the owner of the client account. It never
 * affects the login; the hook ignores tenants that are off and logs its own storage errors.
 */
static void record_client_online_milestone(const specus_session *session)
{
    if (session->config.database_path[0] == '\0') {
        return;
    }
    st_storage_client client;
    if (st_storage_get_client(session->config.database_path, session->config.client_id, &client) == 0) {
        (void)st_product_metrics_milestone(session->config.database_path, client.tenant_id,
                                           client.owner_username, ST_PRODUCT_METRICS_STEP_CLIENT_ONLINE);
    }
}

static void record_login_success_event(specus_session *session)
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

static void record_session_disconnected_event(specus_session *session, const char *reason)
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
                 mapping->specus_address,
                 mapping->specus_port);
    }
}

static void record_tcp_traffic(specus_session *session, int port, long long upload_bytes, long long download_bytes)
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

    tcp_mapping mapping_copy;
    const tcp_mapping *mapping = NULL;
    pthread_mutex_lock(&session->map_lock);
    const tcp_mapping *configured = find_tcp_mapping_by_port(&session->config, port);
    if (configured != NULL) {
        mapping_copy = *configured;
        mapping = &mapping_copy;
    }
    pthread_mutex_unlock(&session->map_lock);
    char resource_key[64];
    char resource_name[512];
    snprintf(resource_key, sizeof(resource_key), "tcp:%d", port);
    long long resource_id = mapping == NULL ? 0 : mapping->id;
    build_tcp_resource_name(mapping, port, resource_name);
    st_storage_record_resource_traffic_usage(database_path,
                                             client_id,
                                             client_name,
                                             "TCP_SPECUS",
                                             resource_key,
                                             resource_id,
                                             resource_name,
                                             usage_date,
                                             upload_bytes,
                                             download_bytes);
}

static void record_tcp_frame(specus_session *session,
                             external_conn *conn,
                             const char *direction,
                             const uint8_t *data,
                             size_t data_len)
{
    if (session == NULL || conn == NULL || data == NULL || data_len == 0
        || session->config.database_path[0] == '\0') {
        return;
    }
    tcp_mapping mapping_copy;
    const tcp_mapping *mapping = NULL;
    pthread_mutex_lock(&session->map_lock);
    const tcp_mapping *configured = find_tcp_mapping_by_port(&session->config, conn->port);
    if (configured != NULL) {
        mapping_copy = *configured;
        mapping = &mapping_copy;
    }
    pthread_mutex_unlock(&session->map_lock);
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
        : mapping->specus_address;
    int source_port = strcmp(direction, "PUBLIC_TO_CLIENT") == 0 ? conn->remote_port : mapping->specus_port;
    const char *destination_address = strcmp(direction, "PUBLIC_TO_CLIENT") == 0
        ? mapping->specus_address
        : conn->remote_ip;
    int destination_port = strcmp(direction, "PUBLIC_TO_CLIENT") == 0 ? mapping->specus_port : conn->remote_port;
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

static int session_send_packet(specus_session *session, st_buffer *packet)
{
    int rc = -1;
    if (packet->data != NULL) {
        pthread_mutex_lock(&session->send_lock);
        if (session->control_fd >= 0) {
            rc = session->tls_connection == NULL
                ? send_all(session->control_fd, packet->data, packet->len)
                : st_tls_connection_write_all(session->tls_connection, packet->data, packet->len);
        }
        pthread_mutex_unlock(&session->send_lock);
    }
    st_buffer_free(packet);
    return rc;
}

static void direct_pending_fail_all(specus_session *session, const char *message)
{
    pthread_mutex_lock(&session->direct_lock);
    for (direct_http_pending *pending = session->direct_pending; pending != NULL; pending = pending->next) {
        if (!pending->done) {
            free(pending->error);
            pending->error = dup_string(message);
            pending->done = 1;
            pthread_cond_broadcast(&pending->cond);
        }
    }
    pthread_mutex_unlock(&session->direct_lock);
}

static void direct_pending_remove(specus_session *session, direct_http_pending *target)
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

static void direct_event_free(direct_http_event *event)
{
    if (event == NULL) {
        return;
    }
    free(event->meta_json);
    free(event->data);
    free(event);
}

static void direct_pending_free_events(direct_http_pending *pending)
{
    direct_http_event *event = pending->events_head;
    while (event != NULL) {
        direct_http_event *next = event->next;
        direct_event_free(event);
        event = next;
    }
    pending->events_head = NULL;
    pending->events_tail = NULL;
    pending->event_count = 0;
}

static direct_http_pending *find_direct_pending_locked(specus_session *session, uint32_t stream_id)
{
    for (direct_http_pending *pending = session->direct_pending; pending != NULL; pending = pending->next) {
        if (pending->stream_id == stream_id) {
            return pending;
        }
    }
    return NULL;
}

static size_t direct_pending_count_locked(const specus_session *session)
{
    size_t count = 0U;
    for (const direct_http_pending *pending = session->direct_pending;
         pending != NULL;
         pending = pending->next) {
        ++count;
    }
    return count;
}

static int direct_pending_enqueue(direct_http_pending *pending,
                                  int type,
                                  const char *meta_json,
                                  const uint8_t *data,
                                  size_t data_len)
{
    if (pending->event_count >= ST_MAX_QUEUED_DATA_EVENTS + 2U) {
        return -1;
    }
    direct_http_event *event = (direct_http_event *)calloc(1, sizeof(*event));
    if (event == NULL) {
        return -1;
    }
    event->type = type;
    if (meta_json != NULL) {
        event->meta_json = dup_string(meta_json);
        if (event->meta_json == NULL) {
            direct_event_free(event);
            return -1;
        }
    }
    if (data_len > 0U) {
        event->data = (uint8_t *)malloc(data_len);
        if (event->data == NULL) {
            direct_event_free(event);
            return -1;
        }
        memcpy(event->data, data, data_len);
        event->data_len = data_len;
    }
    if (pending->events_tail == NULL) {
        pending->events_head = event;
    } else {
        pending->events_tail->next = event;
    }
    pending->events_tail = event;
    ++pending->event_count;
    pthread_cond_broadcast(&pending->cond);
    return 0;
}

static int session_recv_all(specus_session *session, uint8_t *buffer, size_t len)
{
    if (session->tls_connection == NULL) {
        return recv_all(session->control_fd, buffer, len);
    }
    size_t offset = 0U;
    while (offset < len) {
        ssize_t read_len = st_tls_connection_read(session->tls_connection,
                                                  buffer + offset,
                                                  len - offset);
        if (read_len == 0) {
            return 0;
        }
        if (read_len == -2) {
            return -2;
        }
        if (read_len < 0) {
            return -1;
        }
        offset += (size_t)read_len;
    }
    return 1;
}

static direct_http_event *direct_pending_pop(direct_http_pending *pending)
{
    direct_http_event *event = pending->events_head;
    if (event == NULL) {
        return NULL;
    }
    pending->events_head = event->next;
    if (pending->events_head == NULL) {
        pending->events_tail = NULL;
    }
    event->next = NULL;
    --pending->event_count;
    return event;
}

/*
 * A frame for a pending Direct HTTP stream. Returns 0 when the stream id is not one, 1 when the
 * frame was handled and -1 for a data-connection protocol violation.
 *
 * As in Java NatServerHandler and Go clientSession, a frame the stream state refuses (a second
 * response head, DATA before the head or after the end, DATA beyond the receive window, a second
 * FIN) resets only this stream with RST 8, and a response beyond 64 MiB with RST 4 as Go does; the
 * other streams of the data connection carry on. Only a WINDOW_UPDATE that overflows the send
 * window closes the data connection, which is what Java StreamFlowController and Go do.
 * DATA|END_STREAM is that DATA followed by a FIN (protocol/spec/control-protocol.md).
 */
static int process_direct_http_message(specus_session *session, const st_nat_message *message)
{
    pthread_mutex_lock(&session->direct_lock);
    direct_http_pending *pending = find_direct_pending_locked(session, message->stream_id);
    if (pending == NULL) {
        pthread_mutex_unlock(&session->direct_lock);
        return 0;
    }

    int violation = 0;
    uint32_t reset_code = 0U;
    const char *reset_reason = NULL;
    const char *metadata = message->meta_json == NULL ? "{}" : message->meta_json;
    if (message->type == ST_NAT_RST) {
        /* A client RST after the server's own reset keeps the server's failure. */
        if (!pending->reset) {
            char *reason = st_json_get_string(metadata, "reason");
            free(pending->error);
            pending->error = reason == NULL ? dup_string("HTTP stream reset by client") : reason;
            pending->client_reset = 1;
            pending->reset_code = message->value;
            /* Only the connectivity check reads it, and only from a session that announced it. */
            char *failure = st_json_get_top_level_string(metadata, "failure");
            snprintf(pending->failure, sizeof(pending->failure), "%s",
                     failure == NULL ? "" : strlen(failure) < sizeof(pending->failure) ? failure : "?");
            free(failure);
        }
        pending->done = 1;
        pending->reset = 1;
        pthread_cond_broadcast(&pending->cond);
    } else if (message->type == ST_NAT_WINDOW_UPDATE) {
        violation = message->value > ST_STREAM_MAX_WINDOW
            || pending->send_credit > ST_STREAM_MAX_WINDOW - message->value;
        if (!violation) {
            pending->send_credit += message->value;
            pthread_cond_broadcast(&pending->cond);
        }
    } else if (pending->reset) {
        /* Already reset by the server: in flight before the client saw the RST, dropped. */
    } else if (message->type == ST_NAT_OPEN) {
        char *source = st_json_get_string(metadata, "source");
        char *phase = st_json_get_string(metadata, "phase");
        int status = 0;
        int invalid = pending->response_started
            || source == NULL || strcmp(source, "http") != 0
            || phase == NULL || strcmp(phase, "response") != 0
            || st_json_get_int(metadata, "statusCode", &status) != 0
            || status < 100 || status > 599
            || direct_pending_enqueue(pending, ST_NAT_OPEN, message->meta_json, NULL, 0U) != 0;
        free(source);
        free(phase);
        if (invalid) {
            reset_code = 8U;
            reset_reason = "invalid HTTP response headers";
        } else {
            pending->response_started = 1;
        }
    } else if (message->type == ST_NAT_DATA) {
        if (!pending->response_started || pending->done
            || message->data_len == 0U
            || message->data_len > ST_MAX_DATA_FRAME_BYTES
            || message->data_len > pending->receive_credit) {
            reset_code = 8U;
            reset_reason = "HTTP DATA is invalid for the stream state";
        } else if (pending->response_bytes > ST_HTTP_MAX_RESPONSE_BODY - message->data_len) {
            reset_code = 4U;
            reset_reason = "HTTP response body exceeds limit";
        } else if (direct_pending_enqueue(pending, ST_NAT_DATA, NULL,
                                          message->data, message->data_len) != 0) {
            reset_code = 8U;
            reset_reason = "HTTP response queue exceeded";
        } else {
            pending->receive_credit -= message->data_len;
            pending->receive_outstanding += message->data_len;
            pending->response_bytes += message->data_len;
            if ((message->flags & ST_NAT_FLAG_END_STREAM) != 0U) {
                if (direct_pending_enqueue(pending, ST_NAT_FIN, NULL, NULL, 0U) != 0) {
                    reset_code = 8U;
                    reset_reason = "HTTP response queue exceeded";
                } else {
                    pending->done = 1;
                }
            }
        }
    } else if (message->type == ST_NAT_FIN) {
        if (!pending->response_started || pending->done
            || direct_pending_enqueue(pending, ST_NAT_FIN, message->meta_json, NULL, 0U) != 0) {
            reset_code = 8U;
            reset_reason = pending->done ? "duplicate HTTP FIN" : "invalid HTTP terminal frame";
        } else {
            pending->done = 1;
        }
    } else {
        violation = 1;
    }
    if (reset_code != 0U) {
        free(pending->error);
        pending->error = dup_string(reset_reason);
        pending->done = 1;
        pending->reset = 1;
        pthread_cond_broadcast(&pending->cond);
    }
    pthread_mutex_unlock(&session->direct_lock);

    if (reset_code != 0U) {
        fprintf(stderr, "[nat] HTTP stream reset stream=%u client=%s code=%u reason=%s\n",
                message->stream_id, session->config.client_name, (unsigned)reset_code, reset_reason);
        (void)send_reset(session, message->stream_id, reset_code, reset_reason);
    }
    return violation ? -1 : 1;
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

static void active_session_add_locked(specus_session *session)
{
    if (session == NULL) {
        return;
    }
    session->active_next = active_sessions;
    active_sessions = session;
}

static void active_session_remove_locked(specus_session *session)
{
    specus_session **cursor = &active_sessions;
    while (*cursor != NULL) {
        if (*cursor == session) {
            *cursor = session->active_next;
            session->active_next = NULL;
            return;
        }
        cursor = &(*cursor)->active_next;
    }
}

static specus_session *active_session_find_role_locked(const char *client_name, int data_connection)
{
    for (specus_session *session = active_sessions; session != NULL; session = session->active_next) {
        if (session->active
            && session->is_data_connection == data_connection
            && strcmp(client_name, session->config.client_name) == 0) {
            return session;
        }
    }
    return NULL;
}

static specus_session *active_data_session_find_locked(const char *client_name)
{
    return active_session_find_role_locked(client_name, 1);
}

static specus_session *active_data_session_acquire_locked(const char *client_name)
{
    specus_session *session = active_data_session_find_locked(client_name);
    if (session != NULL) {
        ++session->references;
    }
    return session;
}

static int get_client_runtime_status(void *ctx,
                                     long long client_id,
                                     const char *client_name,
                                     st_admin_client_runtime_status *status)
{
    (void)ctx;
    if (client_name == NULL || status == NULL) {
        return -1;
    }
    memset(status, 0, sizeof(*status));
    pthread_mutex_lock(&active_session_lock);
    specus_session *control = active_session_find_role_locked(client_name, 0);
    if (control != NULL
        && (client_id <= 0 || control->config.client_id <= 0 || control->config.client_id == client_id)) {
        status->online = 1;
        status->connected_since_ms = control->connected_since_ms;
    }
    pthread_mutex_unlock(&active_session_lock);
    return 0;
}

static void session_reference_release(specus_session *session)
{
    if (session == NULL) {
        return;
    }
    pthread_mutex_lock(&active_session_lock);
    if (session->references > 1U) {
        --session->references;
    }
    pthread_cond_broadcast(&session->reference_cond);
    pthread_mutex_unlock(&active_session_lock);
}

/*
 * A control connection going away takes its data connection with it (protocol/spec/control-
 * protocol.md). Only the data connection of the same runtime session qualifies: one that belongs to
 * a newer session of the same client is that client's current pair and must survive. A data
 * connection already marked inactive by a protocol violation is still in the list and is closed
 * too, so it cannot linger holding its listeners. The reverse is deliberately not done, as in Java
 * and Go: a data connection that goes away leaves its control alone, the client rebuilds the pair,
 * and the control's record keeps its own disconnect reason.
 */
static void active_session_close_data_locked(specus_session *control)
{
    if (control == NULL || control->is_data_connection) {
        return;
    }
    for (specus_session *data = active_sessions; data != NULL; data = data->active_next) {
        if (data->is_data_connection
            && data->config.client_session_id == control->config.client_session_id
            && strcmp(data->config.client_name, control->config.client_name) == 0) {
            shutdown(data->control_fd, SHUT_RDWR);
        }
    }
}

/* Hands a client RST reason to the sink for server-side logging; it never reaches the caller. */
static int direct_report_client_reset(const st_admin_direct_http_sink *sink,
                                      uint32_t code,
                                      const char *reason)
{
    if (sink->on_reset != NULL) {
        sink->on_reset(sink->ctx, code, reason);
    }
    return ST_ADMIN_DIRECT_HTTP_STREAM_RESET;
}

/* Whether a bound control connection still carries this runtime session. */
static int control_session_live_locked(long long client_session_id)
{
    for (specus_session *session = active_sessions; session != NULL; session = session->active_next) {
        if (session->active
            && !session->is_data_connection
            && session->config.client_session_id == client_session_id) {
            return 1;
        }
    }
    return 0;
}

static int control_session_live(long long client_session_id)
{
    pthread_mutex_lock(&active_session_lock);
    int live = control_session_live_locked(client_session_id);
    pthread_mutex_unlock(&active_session_lock);
    return live;
}

/*
 * Retires a connection a newer login has taken over: it leaves the routing list at once, so no
 * request is routed to it again, and its socket is shut down so its own thread unwinds and frees
 * its NAT streams, pending Direct HTTP requests and listeners. The caller keeps a reference until
 * it is done with the session.
 */
static void displace_session_locked(specus_session *session)
{
    session->replaced = 1;
    ++session->references;
    shutdown(session->control_fd, SHUT_RDWR);
    active_session_remove_locked(session);
}

/*
 * Releases the public TCP ports of a displaced data connection before the replacing login is
 * answered. Its own thread would close them too, but only after it notices the shutdown; the
 * client's next REGISTER for the same port would otherwise race that and fail to bind. Shutting a
 * listening socket down takes it out of LISTEN, which with SO_REUSEADDR already frees the port;
 * the descriptor itself is left to the listener thread, which closes it once accept() fails, so
 * no descriptor is closed under a thread still blocked on it.
 */
static void release_session_listeners(specus_session *session)
{
    pthread_mutex_lock(&session->map_lock);
    for (specus_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (listener->fd >= 0) {
            shutdown(listener->fd, SHUT_RDWR);
        }
    }
    pthread_mutex_unlock(&session->map_lock);
}

/*
 * Binds a freshly authenticated connection as its client's current connection of that role.
 *
 * The protocol keeps one control and one data connection per client and lets a newer login
 * replace the older one instead of refusing it. That is what lets a client whose previous socket
 * died without a FIN reconnect at once rather than wait out the read-idle timeout. A control login
 * also retires the client's data connection, which belongs to the pair it just superseded. A data
 * login re-checks its control under the same lock that publishes it, so a control replaced while
 * the data login was being verified cannot leave a data connection bound to a session that is gone.
 */
static int activate_session(specus_session *session, const char **reason)
{
    specus_session *displaced[ST_MAX_DISPLACED_SESSIONS];
    size_t displaced_count = 0U;
    pthread_mutex_lock(&active_session_lock);
    if (session->is_data_connection) {
        specus_session *control = active_session_find_role_locked(session->config.client_name, 0);
        if (control == NULL || control->config.client_session_id != session->config.client_session_id) {
            pthread_mutex_unlock(&active_session_lock);
            *reason = "数据连接未找到匹配的控制连接";
            return -1;
        }
    }
    specus_session *cursor = active_sessions;
    while (cursor != NULL) {
        specus_session *next = cursor->active_next;
        int same_client = strcmp(cursor->config.client_name, session->config.client_name) == 0;
        int same_role = cursor->is_data_connection == session->is_data_connection;
        if (cursor != session && same_client && (same_role || !session->is_data_connection)) {
            displace_session_locked(cursor);
            if (displaced_count < ST_MAX_DISPLACED_SESSIONS) {
                displaced[displaced_count++] = cursor;
            } else {
                --cursor->references;
            }
        }
        cursor = next;
    }
    active_session_add_locked(session);
    pthread_mutex_unlock(&active_session_lock);

    for (size_t i = 0; i < displaced_count; ++i) {
        printf("[%s] replaced by new login client=%s remote=%s\n",
               displaced[i]->is_data_connection ? "data" : "control",
               displaced[i]->config.client_name,
               displaced[i]->remote);
        if (displaced[i]->is_data_connection) {
            release_session_listeners(displaced[i]);
        }
        session_reference_release(displaced[i]);
    }
    *reason = NULL;
    return 0;
}

/* Returns -1 once shutdown has begun, so a connection accepted during the drain is refused. */
static int connection_register(specus_session *session)
{
    pthread_mutex_lock(&connection_registry_lock);
    if (server_stopping) {
        pthread_mutex_unlock(&connection_registry_lock);
        return -1;
    }
    session->live_next = live_connections;
    live_connections = session;
    ++live_connection_count;
    pthread_mutex_unlock(&connection_registry_lock);
    return 0;
}

static void connection_unregister(specus_session *session)
{
    pthread_mutex_lock(&connection_registry_lock);
    for (specus_session **cursor = &live_connections; *cursor != NULL; cursor = &(*cursor)->live_next) {
        if (*cursor == session) {
            *cursor = session->live_next;
            session->live_next = NULL;
            --live_connection_count;
            break;
        }
    }
    pthread_cond_broadcast(&connection_registry_cond);
    pthread_mutex_unlock(&connection_registry_lock);
}

static int connection_registry_stopping(void)
{
    pthread_mutex_lock(&connection_registry_lock);
    int stopping = server_stopping;
    pthread_mutex_unlock(&connection_registry_lock);
    return stopping;
}

/*
 * Closes every control and data connection and waits, up to the drain timeout, for their threads
 * to finish: each one marks its runtime session DISCONNECTED and stamps its connection record
 * before it exits. This is the C counterpart of Go closing every connection with SERVER_SHUTDOWN
 * and awaiting the handlers before the store is closed. Returns the connections still running.
 */
static size_t close_live_connections_and_wait(int timeout_seconds)
{
    pthread_mutex_lock(&connection_registry_lock);
    server_stopping = 1;
    for (specus_session *session = live_connections; session != NULL; session = session->live_next) {
        if (session->control_fd >= 0) {
            shutdown(session->control_fd, SHUT_RDWR);
        }
    }
    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_seconds;
    while (live_connection_count > 0U) {
        if (pthread_cond_timedwait(&connection_registry_cond, &connection_registry_lock, &deadline) == ETIMEDOUT) {
            break;
        }
    }
    size_t remaining = live_connection_count;
    pthread_mutex_unlock(&connection_registry_lock);
    return remaining;
}

/*
 * An optional string-array field: absent reads as empty, as Java HttpStreamExchange reads the
 * response head's trailerNames ("trailerNames?" in protocol/spec/control-protocol.md).
 */
static int optional_string_array(const char *json, const char *key, char ***out, size_t *out_len)
{
    *out = NULL;
    *out_len = 0U;
    char *raw = st_json_get_top_level_raw(json, key);
    if (raw == NULL) {
        return 0;
    }
    free(raw);
    return st_json_get_string_array(json, key, out, out_len);
}

/*
 * Takes a finished Direct HTTP stream off the pending list; its error and condition stay for the
 * caller. It is tombstoned before it leaves the list, so a late client RST always finds one of
 * the two and is never mistaken for a never-opened stream.
 */
typedef struct {
    specus_session *session;
    direct_http_pending *pending;
} direct_cancel_ctx;

/* A temporary HTTP share ended under the stream: wakes the forwarder, which resets the stream. */
static void direct_pending_cancel(void *ctx)
{
    direct_cancel_ctx *cancel = (direct_cancel_ctx *)ctx;
    pthread_mutex_lock(&cancel->session->direct_lock);
    cancel->pending->cancelled = 1;
    pthread_cond_broadcast(&cancel->pending->cond);
    pthread_mutex_unlock(&cancel->session->direct_lock);
}

static void direct_pending_retire(specus_session *session, direct_http_pending *pending)
{
    pthread_mutex_lock(&session->map_lock);
    st_stream_tombstones_add(&session->closed_streams, pending->stream_id);
    pthread_mutex_unlock(&session->map_lock);
    pthread_mutex_lock(&session->direct_lock);
    direct_pending_remove(session, pending);
    direct_pending_free_events(pending);
    pthread_mutex_unlock(&session->direct_lock);
}

static int direct_http_forward(void *ctx,
                               const char *client_name,
                               const st_direct_http_request *request,
                               const st_admin_direct_http_sink *sink)
{
    (void)ctx;

    if (request == NULL || request->body_len > ST_HTTP_MAX_REQUEST_BODY
        || sink == NULL || sink->on_headers == NULL
        || sink->on_data == NULL || sink->on_end == NULL) {
        return -1;
    }

    pthread_mutex_lock(&active_session_lock);
    specus_session *session = active_data_session_acquire_locked(client_name);
    pthread_mutex_unlock(&active_session_lock);
    if (session == NULL) {
        return -1;
    }
    pthread_mutex_lock(&session->map_lock);
    int route_configured = config_has_http_route(&session->config, request->route);
    pthread_mutex_unlock(&session->map_lock);
    if (!route_configured) {
        session_reference_release(session);
        return -3;
    }

    direct_http_pending pending;
    memset(&pending, 0, sizeof(pending));
    pending.send_credit = ST_STREAM_INITIAL_WINDOW;
    pending.receive_credit = ST_STREAM_INITIAL_WINDOW;
    pthread_cond_init(&pending.cond, NULL);

    pthread_mutex_lock(&session->map_lock);
    pending.stream_id = session->next_stream_id++;
    if (session->next_stream_id == 0U) {
        session->next_stream_id = 1U;
    }
    st_stream_tombstones_remove(&session->closed_streams, pending.stream_id);
    pthread_mutex_unlock(&session->map_lock);

    pthread_mutex_lock(&session->direct_lock);
    if (direct_pending_count_locked(session) >= ST_MAX_PENDING_DIRECT_STREAMS) {
        pthread_mutex_unlock(&session->direct_lock);
        pthread_cond_destroy(&pending.cond);
        session_reference_release(session);
        return ST_ADMIN_DIRECT_HTTP_STREAM_LIMIT;
    }
    pending.next = session->direct_pending;
    session->direct_pending = &pending;
    pthread_mutex_unlock(&session->direct_lock);
    /* A request through a temporary HTTP share can be cut from another thread once it ends. */
    direct_cancel_ctx cancel = {session, &pending};
    int opened = 0;
    if (sink->bind_cancel != NULL) {
        sink->bind_cancel(sink->ctx, direct_pending_cancel, &cancel);
    }

    char *request_json = json_http_request(request);
    if (request_json == NULL) {
        goto failed;
    }
    st_buffer packet = st_protocol_encode_nat_message(ST_NAT_OPEN, 0U,
                                                       pending.stream_id, 0U,
                                                       request_json, NULL, 0U);
    free(request_json);
    if (packet.data == NULL || session_send_packet(session, &packet) != 0) {
        goto failed;
    }
    opened = 1;

    for (size_t offset = 0; offset < request->body_len;) {
        size_t chunk_len = request->body_len - offset;
        if (chunk_len > 64U * 1024U) {
            chunk_len = 64U * 1024U;
        }
        pthread_mutex_lock(&session->direct_lock);
        while (pending.error == NULL && !pending.done && !pending.cancelled && pending.send_credit < chunk_len) {
            pthread_cond_wait(&pending.cond, &session->direct_lock);
        }
        if (pending.error != NULL || pending.done || pending.cancelled) {
            pthread_mutex_unlock(&session->direct_lock);
            goto failed;
        }
        pending.send_credit -= chunk_len;
        pthread_mutex_unlock(&session->direct_lock);
        packet = st_protocol_encode_nat_message(ST_NAT_DATA, 0U,
                                                pending.stream_id, 0U,
                                                NULL, request->body + offset, chunk_len);
        if (packet.data == NULL || session_send_packet(session, &packet) != 0) {
            goto failed;
        }
        offset += chunk_len;
    }
    packet = st_protocol_encode_nat_message(ST_NAT_FIN, 0U,
                                            pending.stream_id, 0U,
                                            NULL, NULL, 0U);
    if (packet.data == NULL || session_send_packet(session, &packet) != 0) {
        goto failed;
    }

    struct timeval now;
    gettimeofday(&now, NULL);
    struct timespec deadline;
    deadline.tv_sec = now.tv_sec + 30;
    deadline.tv_nsec = now.tv_usec * 1000L;

    int result = 0;
    int delivered_head = 0;
    for (;;) {
        pthread_mutex_lock(&session->direct_lock);
        while (pending.events_head == NULL && pending.error == NULL && !pending.cancelled
               && !(pending.done && pending.response_started)) {
            int rc = delivered_head
                ? pthread_cond_wait(&pending.cond, &session->direct_lock)
                : pthread_cond_timedwait(&pending.cond, &session->direct_lock, &deadline);
            if (!delivered_head && rc == ETIMEDOUT) {
                result = -2;
                break;
            }
        }
        int cancelled = pending.cancelled;
        int already_reset = pending.reset;
        direct_http_event *event = result == 0 && !cancelled ? direct_pending_pop(&pending) : NULL;
        char *pending_error = !cancelled && event == NULL && pending.error != NULL
            ? dup_string(pending.error) : NULL;
        int client_reset = pending.client_reset;
        uint32_t reset_code = pending.reset_code;
        pthread_mutex_unlock(&session->direct_lock);

        if (cancelled) {
            if (!already_reset) {
                send_reset(session, pending.stream_id, ST_ADMIN_HTTP_SHARE_RESET_CODE,
                           ST_ADMIN_HTTP_SHARE_RESET_REASON);
            }
            result = ST_ADMIN_DIRECT_HTTP_STREAM_CANCELLED;
            break;
        }
        if (result != 0) {
            send_reset(session, pending.stream_id, 30U, "HTTP response header timeout");
            break;
        }
        if (pending_error != NULL) {
            result = client_reset
                ? direct_report_client_reset(sink, reset_code, pending_error) : -1;
            free(pending_error);
            break;
        }
        if (event == NULL) {
            result = -1;
            break;
        }

        if (event->type == ST_NAT_OPEN) {
            int status_code = 0;
            char **headers = NULL;
            size_t headers_len = 0;
            char **trailer_names = NULL;
            size_t trailer_names_len = 0;
            int valid = st_json_get_int(event->meta_json, "statusCode", &status_code) == 0
                && st_json_get_string_array(event->meta_json, "headers",
                                            &headers, &headers_len) == 0
                && optional_string_array(event->meta_json, "trailerNames",
                                         &trailer_names, &trailer_names_len) == 0;
            if (!valid || sink->on_headers(sink->ctx, status_code,
                                            headers, headers_len,
                                            trailer_names, trailer_names_len) != 0) {
                result = -4;
            } else {
                delivered_head = 1;
            }
            st_json_free_string_array(headers, headers_len);
            st_json_free_string_array(trailer_names, trailer_names_len);
        } else if (event->type == ST_NAT_DATA) {
            if (!delivered_head || sink->on_data(sink->ctx, event->data, event->data_len) != 0) {
                result = -4;
            } else {
                pthread_mutex_lock(&session->direct_lock);
                if (event->data_len > pending.receive_outstanding
                    || pending.receive_credit > ST_STREAM_MAX_WINDOW - event->data_len) {
                    result = -1;
                } else {
                    pending.receive_outstanding -= event->data_len;
                    pending.receive_credit += event->data_len;
                }
                pthread_mutex_unlock(&session->direct_lock);
                if (result == 0
                    && send_window_update(session, pending.stream_id, event->data_len) != 0) {
                    result = -1;
                }
            }
        } else if (event->type == ST_NAT_FIN) {
            char **trailers = NULL;
            size_t trailers_len = 0;
            if (event->meta_json != NULL
                && st_json_get_string_array(event->meta_json, "trailers",
                                            &trailers, &trailers_len) != 0) {
                trailers = NULL;
                trailers_len = 0;
            }
            result = delivered_head && sink->on_end(sink->ctx, trailers, trailers_len) == 0
                ? 0 : -4;
            st_json_free_string_array(trailers, trailers_len);
            direct_event_free(event);
            break;
        }
        direct_event_free(event);
        if (result != 0) {
            send_reset(session, pending.stream_id, 31U, "HTTP downstream closed");
            break;
        }
    }

    /* After the unbind no canceller can reach this stack frame any more. */
    if (sink->bind_cancel != NULL) {
        sink->bind_cancel(sink->ctx, NULL, NULL);
    }
    direct_pending_retire(session, &pending);
    free(pending.error);
    pthread_cond_destroy(&pending.cond);
    session_reference_release(session);
    return result;

failed:
    if (sink->bind_cancel != NULL) {
        sink->bind_cancel(sink->ctx, NULL, NULL);
    }
    pthread_mutex_lock(&session->direct_lock);
    int failed_cancelled = pending.cancelled;
    int failed_reset = pending.reset;
    pthread_mutex_unlock(&session->direct_lock);
    if (failed_cancelled && opened && !failed_reset) {
        send_reset(session, pending.stream_id, ST_ADMIN_HTTP_SHARE_RESET_CODE, ST_ADMIN_HTTP_SHARE_RESET_REASON);
    }
    direct_pending_retire(session, &pending);
    /* A client RST while the request body was still uploading is reported like one after it. */
    int failed_result = failed_cancelled ? ST_ADMIN_DIRECT_HTTP_STREAM_CANCELLED
        : pending.client_reset && pending.error != NULL
        ? direct_report_client_reset(sink, pending.reset_code, pending.error) : -1;
    free(pending.error);
    pthread_cond_destroy(&pending.cond);
    session_reference_release(session);
    return failed_result;
}

/* Connectivity check presence: a bound control connection and data connection, no grace wait. */
static void connectivity_presence(void *ctx, const char *client_name, int *control_online, int *data_online)
{
    (void)ctx;
    pthread_mutex_lock(&active_session_lock);
    *control_online = active_session_find_role_locked(client_name, 0) != NULL;
    *data_online = active_session_find_role_locked(client_name, 1) != NULL;
    pthread_mutex_unlock(&active_session_lock);
}

static long long connectivity_now_ms(void *ctx)
{
    (void)ctx;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

/*
 * One connectivity check probe (protocol/spec/service-connectivity-check.md section 5): the same
 * HTTP stream as a public request, minus the public entry -- no route Basic auth, no server-side
 * route lookup (the device answers for its own configuration), no traffic accounting or detail.
 * OPEN with the fixed metadata and the request FIN go out at once; the first answer within
 * timeout_ms decides. A response head ends the exchange: the stream is reset unless it already
 * ended both ways, and its body is dropped without WINDOW_UPDATE.
 */
static void connectivity_probe(void *ctx,
                               const char *client_name,
                               const char *metadata_json,
                               long long timeout_ms,
                               st_connectivity_probe_answer *answer)
{
    (void)ctx;
    memset(answer, 0, sizeof(*answer));
    pthread_mutex_lock(&active_session_lock);
    specus_session *session = active_data_session_acquire_locked(client_name);
    pthread_mutex_unlock(&active_session_lock);
    if (session == NULL) {
        /* The data connection went away between the presence check and the open. */
        answer->kind = ST_CONNECTIVITY_PROBE_WRITE_FAILED;
        return;
    }
    answer->capability = session->config.client_http_route_version;

    direct_http_pending pending;
    memset(&pending, 0, sizeof(pending));
    pending.send_credit = ST_STREAM_INITIAL_WINDOW;
    pending.receive_credit = ST_STREAM_INITIAL_WINDOW;
    pthread_cond_init(&pending.cond, NULL);
    pthread_mutex_lock(&session->map_lock);
    pending.stream_id = session->next_stream_id++;
    if (session->next_stream_id == 0U) {
        session->next_stream_id = 1U;
    }
    st_stream_tombstones_remove(&session->closed_streams, pending.stream_id);
    pthread_mutex_unlock(&session->map_lock);

    pthread_mutex_lock(&session->direct_lock);
    if (direct_pending_count_locked(session) >= ST_MAX_PENDING_DIRECT_STREAMS) {
        pthread_mutex_unlock(&session->direct_lock);
        pthread_cond_destroy(&pending.cond);
        session_reference_release(session);
        answer->kind = ST_CONNECTIVITY_PROBE_STREAM_LIMIT;
        return;
    }
    pending.next = session->direct_pending;
    session->direct_pending = &pending;
    pthread_mutex_unlock(&session->direct_lock);

    st_buffer packet = st_protocol_encode_nat_message(ST_NAT_OPEN, 0U, pending.stream_id, 0U,
                                                       metadata_json, NULL, 0U);
    int written = packet.data != NULL && session_send_packet(session, &packet) == 0;
    if (written) {
        packet = st_protocol_encode_nat_message(ST_NAT_FIN, 0U, pending.stream_id, 0U, NULL, NULL, 0U);
        written = packet.data != NULL && session_send_packet(session, &packet) == 0;
    }
    if (!written) {
        answer->kind = ST_CONNECTIVITY_PROBE_WRITE_FAILED;
    } else {
        struct timespec deadline;
        clock_gettime(CLOCK_REALTIME, &deadline);
        long long wait_ms = timeout_ms < 0 ? 0 : timeout_ms;
        deadline.tv_sec += (time_t)(wait_ms / 1000LL);
        deadline.tv_nsec += (long)(wait_ms % 1000LL) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        pthread_mutex_lock(&session->direct_lock);
        while (pending.events_head == NULL && pending.error == NULL) {
            if (pthread_cond_timedwait(&pending.cond, &session->direct_lock, &deadline) == ETIMEDOUT) {
                break;
            }
        }
        if (pending.events_head != NULL && pending.events_head->type == ST_NAT_OPEN) {
            int status = 0;
            (void)st_json_get_int(pending.events_head->meta_json, "statusCode", &status);
            answer->kind = ST_CONNECTIVITY_PROBE_RESPONSE;
            answer->status_code = status;
        } else if (pending.error != NULL && pending.client_reset) {
            answer->kind = ST_CONNECTIVITY_PROBE_RESET;
            snprintf(answer->failure, sizeof(answer->failure), "%s", pending.failure);
        } else if (pending.error != NULL) {
            /* The data connection closed or was replaced, which fails every pending stream. */
            answer->kind = ST_CONNECTIVITY_PROBE_LINK_LOST;
        } else {
            answer->kind = ST_CONNECTIVITY_PROBE_TIMEOUT;
        }
        int ended = pending.done;
        pthread_mutex_unlock(&session->direct_lock);
        if (!ended) {
            (void)send_reset(session, pending.stream_id, ST_CONNECTIVITY_PROBE_RESET_CODE,
                             "connectivity check finished");
        }
    }

    /*
     * Tombstoned like a public stream: the device's own RST may cross the one sent above, or follow
     * it when the device fails the request it was told to drop. Either is a stale frame then, not an
     * RST for a never-opened stream that would close the whole data connection.
     */
    direct_pending_retire(session, &pending);
    free(pending.error);
    pthread_cond_destroy(&pending.cond);
    session_reference_release(session);
}

static int direct_ws_open(void *ctx, const st_admin_direct_ws_request *request)
{
    (void)ctx;

    pthread_mutex_lock(&active_session_lock);
    specus_session *session = active_data_session_acquire_locked(request->client_name);
    pthread_mutex_unlock(&active_session_lock);
    if (session == NULL) {
        return -1;
    }
    pthread_mutex_lock(&session->map_lock);
    int route_configured = config_has_http_route(&session->config, request->route);
    pthread_mutex_unlock(&session->map_lock);
    if (!route_configured) {
        session_reference_release(session);
        return -3;
    }

    ws_conn *conn = (ws_conn *)calloc(1, sizeof(*conn));
    if (conn == NULL) {
        session_reference_release(session);
        return -2;
    }
    snprintf(conn->channel_id, sizeof(conn->channel_id), "%s", request->channel_id);
    /* The map's own reference: the stream outlives the browser thread while it is mapped here. */
    conn->stream = request->stream;
    st_admin_direct_ws_retain(conn->stream);

    pthread_mutex_lock(&session->map_lock);
    conn->stream_id = session->next_stream_id++;
    if (session->next_stream_id == 0U) {
        session->next_stream_id = 1U;
    }
    st_stream_tombstones_remove(&session->closed_streams, conn->stream_id);
    conn->next = session->ws_conns;
    session->ws_conns = conn;
    pthread_mutex_unlock(&session->map_lock);

    if (send_ws_open(session, conn->stream_id, request) != 0) {
        pthread_mutex_lock(&session->map_lock);
        ws_conn *removed = remove_ws_conn_locked(session, request->channel_id);
        pthread_mutex_unlock(&session->map_lock);
        free_ws_conn(removed);
        session_reference_release(session);
        return -1;
    }

    printf("[ws-specus] open client=%s route=%s channel=%s\n",
           request->client_name, request->route, request->channel_id);
    session_reference_release(session);
    return 0;
}

static int direct_ws_data(void *ctx, const char *channel_id, const uint8_t *payload, size_t payload_len)
{
    (void)ctx;
    int rc = -1;
    st_admin_direct_ws_stream *stream_to_close = NULL;
    ws_conn *removed = NULL;
    specus_session *target_session = NULL;
    uint32_t stream_id = 0U;

    pthread_mutex_lock(&active_session_lock);
    for (specus_session *session = active_sessions; session != NULL; session = session->active_next) {
        pthread_mutex_lock(&session->map_lock);
        ws_conn *conn = find_ws_conn_locked(session, channel_id);
        if (conn != NULL) {
            ++session->references;
            target_session = session;
            stream_id = conn->stream_id;
            pthread_mutex_unlock(&session->map_lock);
            break;
        }
        pthread_mutex_unlock(&session->map_lock);
    }
    pthread_mutex_unlock(&active_session_lock);

    if (target_session != NULL) {
        rc = send_ws_data(target_session, stream_id, payload, payload_len);
        if (rc != 0) {
            pthread_mutex_lock(&target_session->map_lock);
            removed = remove_ws_conn_locked(target_session, channel_id);
            if (removed != NULL) {
                stream_to_close = removed->stream;
            }
            pthread_mutex_unlock(&target_session->map_lock);
        }
        session_reference_release(target_session);
    }

    if (stream_to_close != NULL) {
        st_admin_direct_ws_close(stream_to_close);
    }
    free_ws_conn(removed);
    return rc;
}

static void direct_ws_close(void *ctx, const char *channel_id, uint32_t reset_code, const char *reason)
{
    (void)ctx;
    specus_session *target_session = NULL;
    ws_conn *removed = NULL;
    pthread_mutex_lock(&active_session_lock);
    for (specus_session *session = active_sessions; session != NULL; session = session->active_next) {
        pthread_mutex_lock(&session->map_lock);
        removed = remove_ws_conn_locked(session, channel_id);
        pthread_mutex_unlock(&session->map_lock);
        if (removed != NULL) {
            ++session->references;
            target_session = session;
            break;
        }
    }
    pthread_mutex_unlock(&active_session_lock);
    /* Not mapped any more means the client side already ended the stream (RST, violation). */
    if (target_session != NULL) {
        if (reset_code == 0U) {
            send_ws_fin(target_session, removed->stream_id);
        } else {
            send_reset(target_session, removed->stream_id, reset_code, reason);
        }
        printf("[ws-specus] close client=%s channel=%s reset=%u\n",
               target_session->config.client_name, channel_id, (unsigned)reset_code);
        free_ws_conn(removed);
        session_reference_release(target_session);
    }
}

static int read_frame(specus_session *session,
                      size_t max_frame_size,
                      st_frame_header *header,
                      uint8_t **body)
{
    if (max_frame_size < ST_HEADER_SIZE || max_frame_size > ST_MAX_FRAME_SIZE) {
        return -1;
    }
    uint8_t raw_header[ST_HEADER_SIZE];
    int rc = session_recv_all(session, raw_header, sizeof(raw_header));
    if (rc <= 0) {
        return rc;
    }
    if (st_protocol_read_header(raw_header, header) != 0) {
        return -1;
    }
    if (header->length > max_frame_size - ST_HEADER_SIZE) {
        return -1;
    }
    uint8_t *frame_body = (uint8_t *)malloc(header->length == 0 ? 1U : header->length);
    if (frame_body == NULL) {
        return -1;
    }
    rc = session_recv_all(session, frame_body, header->length);
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
    config->peer_service_discovery_version = client_session->peer_service_discovery_version;
    config->client_http_route_version = client_session->client_http_route_version;
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

static int prepare_runtime_route_config(const server_config *current, server_config *refreshed)
{
    if (current == NULL || refreshed == NULL || current->database_path[0] == '\0') {
        return -1;
    }
    *refreshed = *current;
    memset(refreshed->mappings, 0, sizeof(refreshed->mappings));
    memset(refreshed->http_routes, 0, sizeof(refreshed->http_routes));
    refreshed->mapping_count = 0U;
    refreshed->http_route_count = 0U;
    refreshed->nat_control_json = NULL;
    refreshed->owns_nat_control_json = 0;
    if (load_database_config(refreshed, refreshed->database_path) != 0
        || parse_tcp_mappings(refreshed) != 0
        || parse_http_routes(refreshed) != 0
        || build_nat_control_json(refreshed) != 0) {
        free(refreshed->nat_control_json);
        refreshed->nat_control_json = NULL;
        return -1;
    }
    refreshed->owns_nat_control_json = 1;
    return 0;
}

static void apply_runtime_route_config(specus_session *session, server_config *refreshed)
{
    char *old_json = NULL;
    pthread_mutex_lock(&session->map_lock);
    if (session->config.owns_nat_control_json) {
        old_json = session->config.nat_control_json;
    }
    session->config.client_id = refreshed->client_id;
    snprintf(session->config.tenant_id,
             sizeof(session->config.tenant_id),
             "%s",
             refreshed->tenant_id);
    memcpy(session->config.mappings, refreshed->mappings, sizeof(refreshed->mappings));
    session->config.mapping_count = refreshed->mapping_count;
    memcpy(session->config.http_routes, refreshed->http_routes, sizeof(refreshed->http_routes));
    session->config.http_route_count = refreshed->http_route_count;
    session->config.nat_control_json = refreshed->nat_control_json;
    session->config.owns_nat_control_json = 1;
    refreshed->nat_control_json = NULL;
    refreshed->owns_nat_control_json = 0;
    pthread_mutex_unlock(&session->map_lock);
    free(old_json);
}

static pthread_mutex_t runtime_nat_control_lock = PTHREAD_MUTEX_INITIALIZER;

static int push_runtime_nat_control(void *ctx, long long client_id, const char *client_name)
{
    (void)ctx;
    if (client_name == NULL || *client_name == '\0') {
        return -2;
    }

    pthread_mutex_lock(&runtime_nat_control_lock);
    pthread_mutex_lock(&active_session_lock);
    specus_session *control = active_session_find_role_locked(client_name, 0);
    specus_session *data = active_session_find_role_locked(client_name, 1);
    if (control == NULL || control->config.client_id != client_id) {
        pthread_mutex_unlock(&active_session_lock);
        pthread_mutex_unlock(&runtime_nat_control_lock);
        return -1;
    }
    ++control->references;
    if (data != NULL && data->config.client_id == client_id) {
        ++data->references;
    } else {
        data = NULL;
    }
    pthread_mutex_unlock(&active_session_lock);

    server_config control_current;
    server_config data_current;
    server_config refreshed_control;
    server_config refreshed_data;
    memset(&refreshed_control, 0, sizeof(refreshed_control));
    memset(&refreshed_data, 0, sizeof(refreshed_data));
    pthread_mutex_lock(&control->map_lock);
    control_current = control->config;
    pthread_mutex_unlock(&control->map_lock);
    if (data != NULL) {
        pthread_mutex_lock(&data->map_lock);
        data_current = data->config;
        pthread_mutex_unlock(&data->map_lock);
    }

    int result = prepare_runtime_route_config(&control_current, &refreshed_control) == 0
        && (data == NULL || prepare_runtime_route_config(&data_current, &refreshed_data) == 0)
        ? 0 : -2;
    st_buffer packet = {0};
    if (result == 0) {
        packet = st_protocol_encode_nat_control(client_name, refreshed_control.nat_control_json);
        if (packet.data == NULL) {
            result = -2;
        }
    }
    if (result == 0) {
        apply_runtime_route_config(control, &refreshed_control);
        if (data != NULL) {
            apply_runtime_route_config(data, &refreshed_data);
        }
        if (session_send_packet(control, &packet) != 0) {
            result = -2;
        } else {
            printf("[nat-control] runtime push client=%s tcp=%zu http=%zu\n",
                   client_name,
                   control->config.mapping_count,
                   control->config.http_route_count);
        }
    } else {
        st_buffer_free(&packet);
        free(refreshed_control.nat_control_json);
        if (data != NULL) {
            free(refreshed_data.nat_control_json);
        }
    }

    session_reference_release(data);
    session_reference_release(control);
    pthread_mutex_unlock(&runtime_nat_control_lock);
    return result;
}

static int push_runtime_client_message(void *ctx,
                                       long long client_id,
                                       const char *client_name,
                                       const char *from_admin_name,
                                       const char *message)
{
    (void)ctx;
    if (client_name == NULL || *client_name == '\0'
        || from_admin_name == NULL || *from_admin_name == '\0'
        || message == NULL || *message == '\0') {
        return -2;
    }
    pthread_mutex_lock(&active_session_lock);
    specus_session *control = active_session_find_role_locked(client_name, 0);
    if (control == NULL
        || (client_id > 0 && control->config.client_id > 0
            && control->config.client_id != client_id)) {
        pthread_mutex_unlock(&active_session_lock);
        return -1;
    }
    ++control->references;
    pthread_mutex_unlock(&active_session_lock);

    st_buffer packet = st_protocol_encode_message_response(from_admin_name,
                                                           client_name,
                                                           ST_MESSAGE_TYPE_CLIENT_TO_CLIENT,
                                                           message);
    int result = packet.data != NULL && session_send_packet(control, &packet) == 0 ? 0 : -2;
    session_reference_release(control);
    return result;
}

static int message_target_is_admin(const char *value)
{
    static const char prefix[] = "admin:";
    if (value == NULL) {
        return 0;
    }
    while (*value != '\0' && isspace((unsigned char)*value)) {
        ++value;
    }
    for (size_t i = 0; i < sizeof(prefix) - 1U; ++i) {
        if (value[i] == '\0'
            || tolower((unsigned char)value[i]) != (unsigned char)prefix[i]) {
            return 0;
        }
    }
    return 1;
}

static int message_body_has_text(const char *value)
{
    if (value == NULL) {
        return 0;
    }
    for (; *value != '\0'; ++value) {
        if (!isspace((unsigned char)*value)) {
            return 1;
        }
    }
    return 0;
}

static int forward_runtime_client_message(specus_session *source_session,
                                          const st_message_response *request)
{
    if (source_session == NULL || request == NULL
        || request->to_client_name == NULL || request->message == NULL
        || !message_body_has_text(request->to_client_name)
        || !message_body_has_text(request->message)
        || source_session->config.database_path[0] == '\0') {
        return -1;
    }
    size_t target_len = strlen(request->to_client_name);
    if (target_len >= sizeof(((st_storage_client *)0)->client_name)) {
        return -1;
    }
    char target_name[sizeof(((st_storage_client *)0)->client_name)];
    memcpy(target_name, request->to_client_name, target_len + 1U);
    char *canonical_input = trim(target_name);
    if (*canonical_input == '\0') {
        return -1;
    }

    st_storage_client source;
    st_storage_client target;
    if (st_storage_get_client_by_name(source_session->config.database_path,
                                      source_session->config.client_name,
                                      &source) != 0
        || st_storage_get_client_by_name(source_session->config.database_path,
                                         canonical_input,
                                         &target) != 0
        || !source.enabled || !target.enabled
        || strcmp(source.tenant_id, source_session->config.tenant_id) != 0) {
        return -1;
    }
    int allowed = 0;
    if (st_storage_can_peer(source_session->config.database_path, &source, &target, &allowed) != 0
        || !allowed) {
        return -1;
    }

    pthread_mutex_lock(&active_session_lock);
    specus_session *target_control = active_session_find_role_locked(target.client_name, 0);
    if (target_control == NULL
        || strcmp(target_control->config.tenant_id, source.tenant_id) != 0
        || (target.id > 0 && target_control->config.client_id > 0
            && target_control->config.client_id != target.id)) {
        pthread_mutex_unlock(&active_session_lock);
        return -1;
    }
    ++target_control->references;
    pthread_mutex_unlock(&active_session_lock);

    st_buffer packet = st_protocol_encode_message_response(source.client_name,
                                                           target.client_name,
                                                           ST_MESSAGE_TYPE_CLIENT_TO_CLIENT,
                                                           request->message);
    int result = packet.data != NULL && session_send_packet(target_control, &packet) == 0 ? 0 : -2;
    session_reference_release(target_control);
    return result;
}

static int peer_mesh_runtime_online(void *ctx,
                                    long long client_id,
                                    const char *client_name)
{
    (void)ctx;
    int online = 0;
    pthread_mutex_lock(&active_session_lock);
    specus_session *control = active_session_find_role_locked(client_name, 0);
    if (control != NULL
        && (client_id <= 0 || control->config.client_id <= 0
            || control->config.client_id == client_id)) online = 1;
    pthread_mutex_unlock(&active_session_lock);
    return online;
}

static int peer_mesh_runtime_send(void *ctx,
                                  const char *target_client_name,
                                  const char *source_client_name,
                                  const char *message)
{
    (void)ctx;
    if (!message_body_has_text(target_client_name)
        || !message_body_has_text(source_client_name)
        || !message_body_has_text(message)) return -1;
    pthread_mutex_lock(&active_session_lock);
    specus_session *target = active_session_find_role_locked(target_client_name, 0);
    if (target != NULL) ++target->references;
    pthread_mutex_unlock(&active_session_lock);
    if (target == NULL) return -1;
    st_buffer packet = st_protocol_encode_message_response(source_client_name,
                                                           target_client_name,
                                                           ST_MESSAGE_TYPE_PEER_CONTROL,
                                                           message);
    int rc = packet.data != NULL && session_send_packet(target, &packet) == 0 ? 0 : -1;
    session_reference_release(target);
    return rc;
}

static st_peer_mesh_runtime peer_mesh_runtime_for_session(specus_session *session)
{
    st_peer_mesh_runtime runtime;
    runtime.database_path = session->config.database_path;
    runtime.send = peer_mesh_runtime_send;
    runtime.online = peer_mesh_runtime_online;
    runtime.ctx = session;
    runtime.publisher_session_id = session->config.client_session_id;
    runtime.peer_service_discovery_version = session->config.peer_service_discovery_version;
    return runtime;
}

static int push_runtime_peer_mesh_refresh(void *ctx, const char *tenant_id)
{
    const server_config *config = (const server_config *)ctx;
    if (config == NULL || config->database_path[0] == '\0'
        || tenant_id == NULL || *tenant_id == '\0') return -1;
    st_peer_mesh_runtime runtime = {
        config->database_path,
        peer_mesh_runtime_send,
        peer_mesh_runtime_online,
        NULL,
        0,
        2
    };
    return st_peer_mesh_refresh_tenant(&runtime, tenant_id);
}

typedef struct {
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int started;
    int stop;
    char database_path[512];
    time_t next_registration_cleanup;
    time_t next_object_cleanup;
    time_t next_media_cleanup;
    time_t next_workbench_sweep;
    time_t next_product_metrics_sweep;
    time_t next_catalog_expiry;
    time_t next_share_sweep;
} peer_mesh_maintenance_state;

/* The workbench retention sweep runs at the first maintenance tick, then hourly. */
#define WORKBENCH_SWEEP_INTERVAL_SECONDS 3600

static peer_mesh_maintenance_state peer_mesh_maintenance = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .condition = PTHREAD_COND_INITIALIZER
};

static time_t maintenance_interval_seconds(const char *name, long long fallback_ms)
{
    int64_t parsed = fallback_ms;
    if (env_i64_range(name, fallback_ms, 1LL, INT64_MAX, &parsed) != 0) parsed = fallback_ms;
    long long milliseconds = parsed < 1000LL ? 1000LL : (long long)parsed;
    long long seconds = (milliseconds + 999LL) / 1000LL;
    return seconds > (long long)INT_MAX ? (time_t)INT_MAX : (time_t)seconds;
}

static void *peer_mesh_maintenance_thread(void *unused)
{
    (void)unused;
    pthread_mutex_lock(&peer_mesh_maintenance.lock);
    while (!peer_mesh_maintenance.stop) {
        struct timespec deadline;
        if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) break;
        /*
         * One second: temporary HTTP share streams are cut within a second of their expiry and
         * re-read every two (protocol/spec/temporary-http-share.md 6.6); the other jobs keep their
         * own next_* times.
         */
        deadline.tv_sec += 1;
        int wait_rc = pthread_cond_timedwait(&peer_mesh_maintenance.condition,
                                             &peer_mesh_maintenance.lock,
                                             &deadline);
        if (peer_mesh_maintenance.stop) break;
        if (wait_rc != ETIMEDOUT) continue;
        st_peer_mesh_runtime runtime = {
            peer_mesh_maintenance.database_path,
            peer_mesh_runtime_send,
            peer_mesh_runtime_online,
            NULL,
            0,
            2
        };
        pthread_mutex_unlock(&peer_mesh_maintenance.lock);
        st_admin_http_share_tick();
        time_t now = time(NULL);
        if (now >= peer_mesh_maintenance.next_catalog_expiry) {
            if (st_peer_mesh_expire_catalogs(&runtime) != 0) {
                fprintf(stderr, "[peer-mesh] stale catalog cleanup failed\n");
            }
            peer_mesh_maintenance.next_catalog_expiry = now + 30;
        }
        if (now >= peer_mesh_maintenance.next_share_sweep) {
            if (st_admin_http_share_sweep() != 0) {
                fprintf(stderr, "[http-share] sweep failed\n");
            }
            peer_mesh_maintenance.next_share_sweep = now + ST_HTTP_SHARE_SWEEP_INTERVAL_SECONDS;
        }
        if (now >= peer_mesh_maintenance.next_registration_cleanup) {
            char now_text[64];
            if (current_utc_timestamp(now_text) != 0
                || st_storage_delete_expired_registration_challenges(
                    peer_mesh_maintenance.database_path, now_text) != 0) {
                fprintf(stderr, "[registration] expired challenge cleanup failed\n");
            }
            peer_mesh_maintenance.next_registration_cleanup = now
                + maintenance_interval_seconds("SPECUS_AUTH_EMAIL_CLEANUP_INTERVAL_MS", 3600000LL);
        }
        if (now >= peer_mesh_maintenance.next_object_cleanup) {
            if (st_object_storage_cleanup_expired() != 0) {
                fprintf(stderr, "[object-storage] expiration cleanup failed\n");
            }
            peer_mesh_maintenance.next_object_cleanup = now
                + maintenance_interval_seconds("SPECUS_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS", 3600000LL);
        }
        if (now >= peer_mesh_maintenance.next_media_cleanup) {
            if (st_media_capture_cleanup_expired(peer_mesh_maintenance.database_path) != 0) {
                fprintf(stderr, "[media-capture] retention cleanup failed\n");
            }
            peer_mesh_maintenance.next_media_cleanup = now
                + maintenance_interval_seconds("SPECUS_MEDIA_CAPTURE_CLEANUP_INTERVAL_MS", 60000LL);
        }
        if (now >= peer_mesh_maintenance.next_workbench_sweep) {
            /* Recent opens older than 30 days, of every identity; idempotent. */
            if (st_workbench_sweep(peer_mesh_maintenance.database_path) != 0) {
                fprintf(stderr, "[workbench] retention sweep failed\n");
            }
            peer_mesh_maintenance.next_workbench_sweep = now + WORKBENCH_SWEEP_INTERVAL_SECONDS;
        }
        if (now >= peer_mesh_maintenance.next_product_metrics_sweep) {
            /* Product metrics retention (product-metrics.md section 9); idempotent, logs its own failure. */
            (void)st_product_metrics_sweep(peer_mesh_maintenance.database_path);
            peer_mesh_maintenance.next_product_metrics_sweep = now + ST_PRODUCT_METRICS_SWEEP_INTERVAL_SECONDS;
        }
        pthread_mutex_lock(&peer_mesh_maintenance.lock);
    }
    pthread_mutex_unlock(&peer_mesh_maintenance.lock);
    return NULL;
}

static int peer_mesh_maintenance_start(const char *database_path)
{
    if (database_path == NULL || database_path[0] == '\0') return 0;
    pthread_mutex_lock(&peer_mesh_maintenance.lock);
    peer_mesh_maintenance.stop = 0;
    time_t now = time(NULL);
    peer_mesh_maintenance.next_registration_cleanup = now
        + maintenance_interval_seconds("SPECUS_AUTH_EMAIL_CLEANUP_INTERVAL_MS", 3600000LL);
    peer_mesh_maintenance.next_object_cleanup = now
        + maintenance_interval_seconds("SPECUS_OBJECT_STORAGE_EXPIRATION_SCAN_INTERVAL_MS", 3600000LL);
    peer_mesh_maintenance.next_media_cleanup = now
        + maintenance_interval_seconds("SPECUS_MEDIA_CAPTURE_CLEANUP_INTERVAL_MS", 60000LL);
    peer_mesh_maintenance.next_workbench_sweep = now;
    /* The first sweep comes at the first maintenance tick a minute after start, then hourly. */
    peer_mesh_maintenance.next_product_metrics_sweep = now + ST_PRODUCT_METRICS_SWEEP_FIRST_DELAY_SECONDS;
    peer_mesh_maintenance.next_catalog_expiry = now + 30;
    /* The first share sweep runs right after start, then every 30 seconds. */
    peer_mesh_maintenance.next_share_sweep = now + 1;
    snprintf(peer_mesh_maintenance.database_path,
             sizeof(peer_mesh_maintenance.database_path), "%s", database_path);
    if (pthread_create(&peer_mesh_maintenance.thread, NULL,
                       peer_mesh_maintenance_thread, NULL) != 0) {
        pthread_mutex_unlock(&peer_mesh_maintenance.lock);
        return -1;
    }
    peer_mesh_maintenance.started = 1;
    pthread_mutex_unlock(&peer_mesh_maintenance.lock);
    return 0;
}

static void peer_mesh_maintenance_stop(void)
{
    pthread_mutex_lock(&peer_mesh_maintenance.lock);
    int started = peer_mesh_maintenance.started;
    peer_mesh_maintenance.stop = 1;
    pthread_cond_broadcast(&peer_mesh_maintenance.condition);
    pthread_mutex_unlock(&peer_mesh_maintenance.lock);
    if (started) pthread_join(peer_mesh_maintenance.thread, NULL);
    pthread_mutex_lock(&peer_mesh_maintenance.lock);
    peer_mesh_maintenance.started = 0;
    peer_mesh_maintenance.database_path[0] = '\0';
    peer_mesh_maintenance.next_registration_cleanup = 0;
    peer_mesh_maintenance.next_object_cleanup = 0;
    peer_mesh_maintenance.next_media_cleanup = 0;
    peer_mesh_maintenance.next_workbench_sweep = 0;
    peer_mesh_maintenance.next_product_metrics_sweep = 0;
    peer_mesh_maintenance.next_catalog_expiry = 0;
    peer_mesh_maintenance.next_share_sweep = 0;
    pthread_mutex_unlock(&peer_mesh_maintenance.lock);
}

/*
 * Java ClientAuthService.closeStaleOnlineSessions: before the online-instance limits are counted,
 * a NETTY_ONLINE row of this credential whose session no bound control connection carries is
 * marked DISCONNECTED. Such a row is left by a disconnect whose DISCONNECTED write failed, and
 * would otherwise lock the machine user out until the next restart. Runs under
 * control_admission_lock, so a control that is still being admitted cannot be mistaken for stale.
 */
static void close_stale_online_sessions(const char *database_path,
                                        long long credential_id,
                                        long long current_session_id,
                                        const char *now_text)
{
    long long ids[ST_MAX_STALE_SESSION_SCAN];
    size_t id_count = 0U;
    if (st_storage_list_online_session_ids_by_credential(database_path,
                                                         credential_id,
                                                         ids,
                                                         ST_MAX_STALE_SESSION_SCAN,
                                                         &id_count) != 0) {
        return;
    }
    for (size_t i = 0; i < id_count; ++i) {
        if (ids[i] == current_session_id || control_session_live(ids[i])) {
            continue;
        }
        if (st_storage_mark_client_session_disconnected(database_path, ids[i], now_text) == 0) {
            printf("[control] closed stale online session=%lld credential=%lld\n", ids[i], credential_id);
        }
    }
}

static int verify_database_login(specus_session *session, const st_login_request *request, const char **reason)
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
    int session_lookup = st_storage_get_client_session_for_login(config->database_path,
                                                                 request->client_session_id,
                                                                 token_hash,
                                                                 &client_session);
    if (session_lookup > 0) {
        return -1;
    }
    if (session_lookup < 0) {
        *reason = "客户端认证存储暂不可用";
        return 0;
    }
    if (strcmp(request->client_name, client_session.client_name) != 0) {
        *reason = "客户端访问令牌无效";
        return 0;
    }
    if (session->is_data_connection) {
        if (strcmp(client_session.status, "NETTY_ONLINE") != 0) {
            *reason = "数据连接要求控制连接先登录";
            return 0;
        }
        pthread_mutex_lock(&active_session_lock);
        specus_session *control = active_session_find_role_locked(request->client_name, 0);
        int matching_control = control != NULL
            && control->config.client_session_id == client_session.id;
        pthread_mutex_unlock(&active_session_lock);
        if (!matching_control) {
            *reason = "数据连接未找到匹配的控制连接";
            return 0;
        }
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
    /*
     * The runtime token is reusable until it expires: an ordinary reconnect presents the same
     * clientSessionId + accessToken again, whatever status the previous connection left behind
     * (protocol/spec/client-auth.md). What may not come back is a session a later HTTP login of
     * the same machine user replaced: the client has moved on to the newer token, so the old one
     * is answered as invalid, which makes a real client refresh instead of giving up.
     */
    if (!session->is_data_connection) {
        int superseded = 0;
        if (st_storage_client_session_superseded(config->database_path,
                                                 client_session.credential_id,
                                                 client_session.machine_fingerprint,
                                                 client_session.os_user,
                                                 client_session.id,
                                                 &superseded) != 0) {
            *reason = "客户端在线状态不可用";
            return 0;
        }
        if (superseded) {
            *reason = "客户端访问令牌无效";
            return 0;
        }
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
    if (!session->is_data_connection) {
        close_stale_online_sessions(config->database_path, client_session.credential_id, client_session.id, now_text);
    }
    /* Both counts leave this session out: a re-login of the same session is the same instance
     * coming back, not "another" one, and activate_session() replaces its old connections. */
    if (!session->is_data_connection
        && st_storage_count_online_sessions_by_machine(config->database_path,
                                                    client_session.credential_id,
                                                    client_session.machine_fingerprint,
                                                    client_session.os_user,
                                                    client_session.id,
                                                    &online_count) != 0) {
        *reason = "客户端在线状态不可用";
        return 0;
    }
    if (!session->is_data_connection && online_count >= config->per_machine_user_max_instances) {
        *reason = "同一台机器和用户已经有在线实例";
        return 0;
    }
    if (!session->is_data_connection
        && st_storage_count_online_sessions_by_credential(config->database_path,
                                                       client_session.credential_id,
                                                       client_session.id,
                                                       &online_count) != 0) {
        *reason = "客户端在线状态不可用";
        return 0;
    }
    if (!session->is_data_connection
        && credential.max_online_instances > 0
        && online_count >= credential.max_online_instances) {
        *reason = "在线实例数已达上限";
        return 0;
    }
    if (!session->is_data_connection
        && st_storage_mark_client_session_online(config->database_path,
                                              client_session.id,
                                              session->remote,
                                              session->remote,
                                              now_text) != 0) {
        *reason = "客户端会话状态更新失败";
        return 0;
    }
    if (reload_config_for_client_session(config, &client_session) != 0) {
        /* A failed re-login must not take a session offline that an older control still carries. */
        if (!session->is_data_connection && !control_session_live(client_session.id)) {
            (void)st_storage_mark_client_session_disconnected(config->database_path, client_session.id, now_text);
        }
        *reason = "客户端配置加载失败";
        return 0;
    }
    memcpy(config->access_token_hash, actual_hash, sizeof(config->access_token_hash));
    *reason = NULL;
    return 1;
}

static int verify_login(specus_session *session, const st_login_request *request, const char **reason)
{
    server_config *config = &session->config;
    if (request->client_name == NULL
        || request->client_session_id <= 0
        || request->access_token == NULL
        || request->access_token[0] == '\0'
        || request->connection_role == NULL
        || (strcmp(request->connection_role, ST_CONNECTION_ROLE_CONTROL) != 0
            && strcmp(request->connection_role, ST_CONNECTION_ROLE_DATA) != 0)) {
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

    if (session->is_data_connection) {
        pthread_mutex_lock(&active_session_lock);
        specus_session *control = active_session_find_role_locked(request->client_name, 0);
        int matching_control = control != NULL
            && control->config.client_session_id == request->client_session_id;
        pthread_mutex_unlock(&active_session_lock);
        if (!matching_control) {
            *reason = "数据连接未找到匹配的控制连接";
            return 0;
        }
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
        snprintf(text, text_len, "%.45s:%d", address, *port);
        return;
    }
    if (remote->ss_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)remote;
        inet_ntop(AF_INET6, &addr->sin6_addr, address, address_len);
        *port = ntohs(addr->sin6_port);
        snprintf(text, text_len, "[%.45s]:%d", address, *port);
        return;
    }
    snprintf(address, address_len, "unknown");
    snprintf(text, text_len, "unknown");
}

static int create_listener_on(const char *bind_address, int port)
{
    char port_text[16];
    snprintf(port_text, sizeof(port_text), "%d", port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *addresses = NULL;
    int gai = getaddrinfo(bind_address, port_text, &hints, &addresses);
    if (gai != 0) {
        fprintf(stderr, "invalid listener bind address %s: %s\n", bind_address, gai_strerror(gai));
        return -1;
    }
    int fd = -1;
    for (const struct addrinfo *address = addresses; address != NULL; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd < 0) {
            continue;
        }
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (address->ai_family == AF_INET6) {
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &yes, sizeof(yes));
        }
        if (bind(fd, address->ai_addr, address->ai_addrlen) == 0 && listen(fd, 128) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) {
        perror("bind/listen");
    }
    return fd;
}

static int create_listener(int port)
{
    return create_listener_on("0.0.0.0", port);
}

static void configure_control_socket(int fd, const server_config *config)
{
    struct timeval timeout;
    timeout.tv_sec = config->control_read_idle_seconds;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    timeout.tv_sec = config->control_write_timeout_seconds;
    timeout.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

static int mapping_allowed(const server_config *config, int port, const char *address, int specus_port)
{
    for (size_t i = 0; i < config->mapping_count; ++i) {
        const tcp_mapping *mapping = &config->mappings[i];
        if (mapping->port == port
            && mapping->specus_port == specus_port
            && strcmp(mapping->specus_address, address) == 0) {
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

static int append_json_string_array(string_builder *builder,
                                    const char *name,
                                    char *const *values,
                                    size_t values_len,
                                    int *first)
{
    if (sb_appendf(builder, "%s\"%s\":[", *first ? "" : ",", name) != 0) {
        return -1;
    }
    *first = 0;
    for (size_t i = 0; i < values_len; ++i) {
        char *escaped = st_json_escape(values[i] == NULL ? "" : values[i]);
        if (escaped == NULL) {
            return -1;
        }
        int rc = sb_appendf(builder, "%s\"%s\"", i == 0 ? "" : ",", escaped);
        free(escaped);
        if (rc != 0) {
            return -1;
        }
    }
    return sb_append(builder, "]");
}

static char *json_http_request(const st_direct_http_request *request)
{
    string_builder builder = {0};
    int first = 1;
    int rc = sb_append(&builder, "{");
    if (rc == 0) rc = append_json_property(&builder, "source", "http", &first);
    if (rc == 0) rc = append_json_property(&builder, "phase", "request", &first);
    if (rc == 0) rc = append_json_property(&builder, "method", request->request_method, &first);
    if (rc == 0) rc = append_json_property(&builder, "route", request->route, &first);
    if (rc == 0) rc = append_json_property(&builder, "relativePath", request->relative_path, &first);
    if (rc == 0) rc = append_json_property(&builder, "rawQuery", request->raw_query, &first);
    if (rc == 0) {
        rc = append_json_string_array(&builder, "headers", request->headers,
                                      request->headers_len, &first);
    }
    if (rc == 0) {
        rc = sb_appendf(&builder, ",\"contentLength\":%zu,\"trailerNames\":[]}",
                        request->body_len);
    }
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static char *json_reset_reason(const char *reason)
{
    char *escaped = st_json_escape(reason == NULL ? "HTTP stream reset" : reason);
    if (escaped == NULL) {
        return NULL;
    }
    string_builder builder = {0};
    int rc = sb_appendf(&builder, "{\"reason\":\"%s\"}", escaped);
    free(escaped);
    if (rc != 0) {
        free(builder.data);
        return NULL;
    }
    return sb_finish(&builder);
}

static int send_nat_with_json(specus_session *session, int type, uint32_t stream_id, uint32_t value,
                              char *json, const uint8_t *data, size_t data_len)
{
    st_buffer packet = st_protocol_encode_nat_message(type, 0U, stream_id, value, json, data, data_len);
    free(json);
    return session_send_packet(session, &packet);
}

static int send_register_result(specus_session *session, int port, int success, const char *reason)
{
    return send_nat_with_json(session, ST_NAT_REGISTER_RESULT, 0U, 0U,
                              json_register_result(port, success, reason),
                              NULL, 0);
}

static int send_open(specus_session *session, uint32_t stream_id, const char *channel_id, int port)
{
    return send_nat_with_json(session, ST_NAT_OPEN, stream_id, 0U,
                              json_connected(channel_id, port), NULL, 0);
}

static int send_fin(specus_session *session, uint32_t stream_id)
{
    return send_nat_with_json(session, ST_NAT_FIN, stream_id, 0U, NULL, NULL, 0);
}

static int send_reset(specus_session *session, uint32_t stream_id,
                      uint32_t code, const char *reason)
{
    return send_nat_with_json(session, ST_NAT_RST, stream_id, code,
                              json_reset_reason(reason), NULL, 0);
}

static int send_data(specus_session *session, uint32_t stream_id, const uint8_t *data, size_t data_len)
{
    return send_nat_with_json(session, ST_NAT_DATA, stream_id, 0U, NULL, data, data_len);
}

static int send_window_update(specus_session *session, uint32_t stream_id, size_t credit)
{
    if (credit == 0U || credit > UINT32_MAX) {
        return -1;
    }
    return send_nat_with_json(session, ST_NAT_WINDOW_UPDATE, stream_id,
                              (uint32_t)credit, NULL, NULL, 0);
}

static int send_ws_open(specus_session *session, uint32_t stream_id,
                        const st_admin_direct_ws_request *request)
{
    return send_nat_with_json(session, ST_NAT_OPEN, stream_id, 0U,
                              json_ws_connected(request), NULL, 0);
}

static int send_ws_fin(specus_session *session, uint32_t stream_id)
{
    return send_nat_with_json(session, ST_NAT_FIN, stream_id, 0U, NULL, NULL, 0);
}

static int send_ws_data(specus_session *session, uint32_t stream_id, const uint8_t *data, size_t data_len)
{
    return send_nat_with_json(session, ST_NAT_DATA, stream_id, 0U, NULL, data, data_len);
}

static external_conn *find_conn_locked(specus_session *session, uint32_t stream_id)
{
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (!conn->done && conn->stream_id == stream_id) {
            return conn;
        }
    }
    return NULL;
}

static ws_conn *find_ws_conn_locked(specus_session *session, const char *channel_id)
{
    for (ws_conn *conn = session->ws_conns; conn != NULL; conn = conn->next) {
        if (strcmp(conn->channel_id, channel_id) == 0) {
            return conn;
        }
    }
    return NULL;
}

static ws_conn *find_ws_stream_locked(specus_session *session, uint32_t stream_id)
{
    for (ws_conn *conn = session->ws_conns; conn != NULL; conn = conn->next) {
        if (conn->stream_id == stream_id) {
            return conn;
        }
    }
    return NULL;
}

/* Unmapping a WebSocket stream tombstones it in the same map_lock section. */
static ws_conn *remove_ws_conn_locked(specus_session *session, const char *channel_id)
{
    ws_conn **cursor = &session->ws_conns;
    while (*cursor != NULL) {
        if (strcmp((*cursor)->channel_id, channel_id) == 0) {
            ws_conn *removed = *cursor;
            *cursor = removed->next;
            removed->next = NULL;
            st_stream_tombstones_add(&session->closed_streams, removed->stream_id);
            return removed;
        }
        cursor = &(*cursor)->next;
    }
    return NULL;
}

static ws_conn *remove_ws_stream_locked(specus_session *session, uint32_t stream_id)
{
    ws_conn **cursor = &session->ws_conns;
    while (*cursor != NULL) {
        if ((*cursor)->stream_id == stream_id) {
            ws_conn *removed = *cursor;
            *cursor = removed->next;
            removed->next = NULL;
            st_stream_tombstones_add(&session->closed_streams, removed->stream_id);
            return removed;
        }
        cursor = &(*cursor)->next;
    }
    return NULL;
}

/* Gives back the map's reference to the browser stream along with the unmapped entry. */
static void free_ws_conn(ws_conn *conn)
{
    if (conn == NULL) {
        return;
    }
    st_admin_direct_ws_release(conn->stream);
    free(conn);
}

/*
 * Looks a WebSocket stream up and takes a temporary reference, so the browser socket can be
 * written (which may block, or wait for the 101 response) without holding map_lock.
 */
static st_admin_direct_ws_stream *acquire_ws_stream(specus_session *session, uint32_t stream_id)
{
    pthread_mutex_lock(&session->map_lock);
    ws_conn *ws = find_ws_stream_locked(session, stream_id);
    st_admin_direct_ws_stream *stream = ws == NULL ? NULL : ws->stream;
    st_admin_direct_ws_retain(stream);
    pthread_mutex_unlock(&session->map_lock);
    return stream;
}

/*
 * The browser side refused what the client sent on the stream and has already closed the browser
 * socket; unmap the stream and reset it. If it is no longer mapped, the browser thread unmapped it
 * first and sent the same RST.
 */
static void reset_ws_stream(specus_session *session, uint32_t stream_id, int result)
{
    pthread_mutex_lock(&session->map_lock);
    ws_conn *removed = remove_ws_stream_locked(session, stream_id);
    pthread_mutex_unlock(&session->map_lock);
    if (removed == NULL) {
        return;
    }
    const char *reason = NULL;
    uint32_t code = st_admin_direct_ws_reset_code(result, &reason);
    fprintf(stderr, "[ws-specus] reset stream=%u client=%s code=%u reason=%s\n",
            stream_id, session->config.client_name, (unsigned)code, reason);
    (void)send_reset(session, stream_id, code, reason);
    free_ws_conn(removed);
}

/* DATA or DATA|END_STREAM for a WebSocket stream; returns 0 when the stream id is not one. */
static int process_ws_data(specus_session *session, const st_nat_message *message)
{
    st_admin_direct_ws_stream *stream = acquire_ws_stream(session, message->stream_id);
    if (stream == NULL) {
        return 0;
    }
    int end_stream = (message->flags & ST_NAT_FLAG_END_STREAM) != 0U;
    int result = ST_ADMIN_DIRECT_WS_ACCEPTED;
    /* An empty DATA carries no SWS2 envelope; it is only meaningful as a bare END_STREAM. */
    if (message->data_len > 0U || !end_stream) {
        result = st_admin_direct_ws_send_framed_payload(stream, message->data, message->data_len);
        if (result == ST_ADMIN_DIRECT_WS_ACCEPTED) {
            (void)send_window_update(session, message->stream_id, message->data_len);
        }
    }
    if (result == ST_ADMIN_DIRECT_WS_ACCEPTED && end_stream) {
        result = st_admin_direct_ws_peer_finished(stream);
    }
    st_admin_direct_ws_release(stream);
    if (result != ST_ADMIN_DIRECT_WS_ACCEPTED) {
        reset_ws_stream(session, message->stream_id, result);
    }
    return 1;
}

/* FIN or RST for a WebSocket stream; returns 0 when the stream id is not one. */
static int process_ws_closed(specus_session *session, const st_nat_message *message)
{
    if (message->type == ST_NAT_RST) {
        pthread_mutex_lock(&session->map_lock);
        ws_conn *removed = remove_ws_stream_locked(session, message->stream_id);
        pthread_mutex_unlock(&session->map_lock);
        if (removed == NULL) {
            return 0;
        }
        st_admin_direct_ws_peer_reset(removed->stream);
        free_ws_conn(removed);
        return 1;
    }
    st_admin_direct_ws_stream *stream = acquire_ws_stream(session, message->stream_id);
    if (stream == NULL) {
        return 0;
    }
    /* The stream stays mapped: the browser's CLOSE reply still goes back as SWS2 CLOSE + FIN. */
    int result = st_admin_direct_ws_peer_finished(stream);
    st_admin_direct_ws_release(stream);
    if (result != ST_ADMIN_DIRECT_WS_ACCEPTED) {
        reset_ws_stream(session, message->stream_id, result);
    }
    return 1;
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

/* Closes a TCP stream and, the first time, tombstones it in the same map_lock section. */
static void close_conn_locked(external_conn *conn)
{
    if (!conn->done) {
        st_stream_tombstones_add(&conn->session->closed_streams, conn->stream_id);
    }
    pthread_mutex_lock(&conn->flow_lock);
    conn->flow_closed = 1;
    pthread_cond_broadcast(&conn->flow_cond);
    pthread_mutex_unlock(&conn->flow_lock);
    pthread_mutex_lock(&conn->write_lock);
    conn->write_closed = 1;
    pthread_cond_broadcast(&conn->write_cond);
    pthread_mutex_unlock(&conn->write_lock);
    if (conn->fd >= 0) {
        shutdown(conn->fd, SHUT_RDWR);
        close(conn->fd);
        conn->fd = -1;
    }
    release_external_count(conn);
    conn->done = 1;
}

static void free_external_write_queue(external_conn *conn)
{
    external_write_chunk *chunk = conn->write_head;
    while (chunk != NULL) {
        external_write_chunk *next = chunk->next;
        free(chunk->data);
        free(chunk);
        chunk = next;
    }
    conn->write_head = NULL;
    conn->write_tail = NULL;
    conn->queued_write_bytes = 0U;
}

/* Results of queueing client data for the public socket, each answered with its own RST code. */
#define ST_EXTERNAL_WRITE_AFTER_FIN (-1) /* the client's direction already ended: RST 7 */
#define ST_EXTERNAL_WRITE_REFUSED (-2)   /* frame too large, 4 MiB queue full or no memory: RST 6 */

static int enqueue_external_write(external_conn *conn,
                                  const uint8_t *data,
                                  size_t data_len,
                                  int end_stream)
{
    if (data == NULL || data_len == 0U || data_len > ST_MAX_DATA_FRAME_BYTES) {
        return ST_EXTERNAL_WRITE_REFUSED;
    }
    external_write_chunk *chunk = (external_write_chunk *)calloc(1, sizeof(*chunk));
    if (chunk == NULL) {
        return ST_EXTERNAL_WRITE_REFUSED;
    }
    chunk->data = (uint8_t *)malloc(data_len);
    if (chunk->data == NULL) {
        free(chunk);
        return ST_EXTERNAL_WRITE_REFUSED;
    }
    memcpy(chunk->data, data, data_len);
    chunk->len = data_len;

    pthread_mutex_lock(&conn->write_lock);
    int refused = 0;
    if (conn->write_closed || conn->client_finished) {
        refused = ST_EXTERNAL_WRITE_AFTER_FIN;
    } else if (conn->queued_write_bytes > ST_STREAM_MAX_PENDING_BYTES - data_len) {
        refused = ST_EXTERNAL_WRITE_REFUSED;
    }
    if (refused != 0) {
        pthread_mutex_unlock(&conn->write_lock);
        free(chunk->data);
        free(chunk);
        return refused;
    }
    if (conn->write_tail == NULL) {
        conn->write_head = chunk;
    } else {
        conn->write_tail->next = chunk;
    }
    conn->write_tail = chunk;
    conn->queued_write_bytes += data_len;
    if (end_stream) {
        conn->client_finished = 1;
    }
    pthread_cond_broadcast(&conn->write_cond);
    pthread_mutex_unlock(&conn->write_lock);
    return 0;
}

static int finish_external_write(external_conn *conn)
{
    pthread_mutex_lock(&conn->write_lock);
    if (conn->write_closed || conn->client_finished) {
        pthread_mutex_unlock(&conn->write_lock);
        return ST_EXTERNAL_WRITE_AFTER_FIN;
    }
    conn->client_finished = 1;
    pthread_cond_broadcast(&conn->write_cond);
    pthread_mutex_unlock(&conn->write_lock);
    return 0;
}

static int consume_send_credit(external_conn *conn, size_t bytes)
{
    if (bytes == 0U || bytes > ST_STREAM_MAX_WINDOW) {
        return -1;
    }
    pthread_mutex_lock(&conn->flow_lock);
    while (!conn->flow_closed && conn->send_credit < bytes) {
        pthread_cond_wait(&conn->flow_cond, &conn->flow_lock);
    }
    if (conn->flow_closed) {
        pthread_mutex_unlock(&conn->flow_lock);
        return -1;
    }
    conn->send_credit -= bytes;
    pthread_mutex_unlock(&conn->flow_lock);
    return 0;
}

static int add_send_credit(external_conn *conn, uint32_t credit)
{
    if (credit == 0U || credit > ST_STREAM_MAX_WINDOW) {
        return -1;
    }
    pthread_mutex_lock(&conn->flow_lock);
    if (conn->flow_closed || conn->send_credit > ST_STREAM_MAX_WINDOW - credit) {
        pthread_mutex_unlock(&conn->flow_lock);
        return -1;
    }
    conn->send_credit += credit;
    pthread_cond_broadcast(&conn->flow_cond);
    pthread_mutex_unlock(&conn->flow_lock);
    return 0;
}

static int count_external_locked(specus_session *session, int port, int *client_count, int *port_count)
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
    specus_session *session = conn->session;
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
    specus_session *session = conn->session;
    pthread_mutex_lock(&session->map_lock);
    close_conn_locked(conn);
    pthread_mutex_unlock(&session->map_lock);
}

static void *external_writer_thread(void *arg)
{
    external_conn *conn = (external_conn *)arg;
    specus_session *session = conn->session;
    for (;;) {
        pthread_mutex_lock(&conn->write_lock);
        while (!conn->write_closed && conn->write_head == NULL && !conn->client_finished) {
            pthread_cond_wait(&conn->write_cond, &conn->write_lock);
        }
        if (conn->write_closed) {
            pthread_mutex_unlock(&conn->write_lock);
            break;
        }
        external_write_chunk *chunk = conn->write_head;
        if (chunk != NULL) {
            conn->write_head = chunk->next;
            if (conn->write_head == NULL) {
                conn->write_tail = NULL;
            }
            conn->queued_write_bytes -= chunk->len;
            pthread_mutex_unlock(&conn->write_lock);

            int fd;
            pthread_mutex_lock(&session->map_lock);
            fd = conn->fd;
            pthread_mutex_unlock(&session->map_lock);
            if (fd < 0 || send_all(fd, chunk->data, chunk->len) != 0) {
                fprintf(stderr,
                        "[nat] external write failed stream=%u client=%s bytes=%zu errno=%d\n",
                        conn->stream_id,
                        session->config.client_name,
                        chunk->len,
                        errno);
                free(chunk->data);
                free(chunk);
                /* A stream the server closed on its own is reset, as Java and Go do (RST 9). */
                pthread_mutex_lock(&session->map_lock);
                int already_closed = conn->done;
                close_conn_locked(conn);
                pthread_mutex_unlock(&session->map_lock);
                if (!already_closed) {
                    (void)send_reset(session, conn->stream_id, 9U, "write to external TCP stream failed");
                }
                break;
            }
            record_tcp_traffic(session, conn->port, 0, (long long)chunk->len);
            record_tcp_frame(session, conn, "CLIENT_TO_PUBLIC", chunk->data, chunk->len);
            if (send_window_update(session, conn->stream_id, chunk->len) != 0) {
                free(chunk->data);
                free(chunk);
                mark_conn_done(conn);
                break;
            }
            free(chunk->data);
            free(chunk);
            continue;
        }
        pthread_mutex_unlock(&conn->write_lock);

        pthread_mutex_lock(&session->map_lock);
        if (conn->fd >= 0) {
            (void)shutdown(conn->fd, SHUT_WR);
        }
        conn->client_write_drained = 1;
        if (conn->public_finished) {
            close_conn_locked(conn);
        }
        pthread_mutex_unlock(&session->map_lock);
        break;
    }
    return NULL;
}

static void *external_conn_thread(void *arg)
{
    external_conn *conn = (external_conn *)arg;
    specus_session *session = conn->session;
    printf("[nat] external connected channel=%s port=%d client=%s\n",
           conn->channel_id, conn->port, session->config.client_name);

    if (send_open(session, conn->stream_id, conn->channel_id, conn->port) != 0) {
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
            if (consume_send_credit(conn, (size_t)read_len) != 0) {
                break;
            }
            if (send_data(session, conn->stream_id, buffer, (size_t)read_len) != 0) {
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

    /* A stream already closed (reset by either side, or its connection shutting down) is over;
     * a FIN after its RST would name a stream the client has already dropped. */
    pthread_mutex_lock(&session->map_lock);
    int closed = conn->done;
    pthread_mutex_unlock(&session->map_lock);
    if (!closed) {
        send_fin(session, conn->stream_id);
    }
    pthread_mutex_lock(&session->map_lock);
    conn->public_finished = 1;
    if (conn->client_write_drained) {
        close_conn_locked(conn);
    }
    pthread_mutex_unlock(&session->map_lock);
    printf("[nat] external read side closed channel=%s port=%d client=%s\n",
           conn->channel_id, conn->port, session->config.client_name);
    return NULL;
}

static int start_external_conn(specus_session *session,
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
    conn->send_credit = ST_STREAM_INITIAL_WINDOW;
    pthread_mutex_init(&conn->flow_lock, NULL);
    pthread_cond_init(&conn->flow_cond, NULL);
    pthread_mutex_init(&conn->write_lock, NULL);
    pthread_cond_init(&conn->write_cond, NULL);
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
        pthread_cond_destroy(&conn->flow_cond);
        pthread_mutex_destroy(&conn->flow_lock);
        pthread_cond_destroy(&conn->write_cond);
        pthread_mutex_destroy(&conn->write_lock);
        free(conn);
        return -1;
    }
    conn->stream_id = session->next_stream_id++;
    if (session->next_stream_id == 0U) {
        session->next_stream_id = 1U;
    }
    st_stream_tombstones_remove(&session->closed_streams, conn->stream_id);
    snprintf(conn->channel_id, sizeof(conn->channel_id), "c-%u", conn->stream_id);
    conn->next = session->conns;
    session->conns = conn;
    pthread_mutex_unlock(&session->map_lock);

    if (pthread_create(&conn->writer_thread, NULL, external_writer_thread, conn) != 0) {
        perror("pthread_create");
        pthread_mutex_lock(&session->map_lock);
        close_conn_locked(conn);
        pthread_mutex_unlock(&session->map_lock);
        return -1;
    }
    conn->writer_thread_started = 1;
    if (pthread_create(&conn->thread, NULL, external_conn_thread, conn) != 0) {
        perror("pthread_create");
        pthread_mutex_lock(&session->map_lock);
        close_conn_locked(conn);
        pthread_mutex_unlock(&session->map_lock);
        pthread_join(conn->writer_thread, NULL);
        conn->writer_thread_started = 0;
        return -1;
    }
    conn->thread_started = 1;
    return 0;
}

static void *listener_thread(void *arg)
{
    specus_listener *listener = (specus_listener *)arg;
    specus_session *session = listener->session;
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

static int listener_exists_locked(specus_session *session, int port)
{
    for (specus_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (!listener->done && listener->fd >= 0 && listener->port == port) {
            return 1;
        }
    }
    return 0;
}

static int start_specus_listener(specus_session *session, int port, char *reason, size_t reason_len)
{
    int fd = create_listener(port);
    if (fd < 0) {
        snprintf(reason, reason_len, "port %d bind failed", port);
        return -1;
    }

    specus_listener *listener = (specus_listener *)calloc(1, sizeof(*listener));
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

static void stop_specus_listener(specus_session *session, int port)
{
    pthread_mutex_lock(&session->map_lock);
    for (specus_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
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

static void process_register(specus_session *session, const st_nat_message *message)
{
    int port;
    int specus_port;
    char *specus_address = st_json_get_string(message->meta_json, "specusAddress");
    char *client_name = st_json_get_string(message->meta_json, "clientName");
    if (st_json_get_int(message->meta_json, "port", &port) != 0
        || st_json_get_int(message->meta_json, "specusPort", &specus_port) != 0
        || specus_address == NULL
        || client_name == NULL) {
        send_register_result(session, 0, 0, "missing required metadata");
        free(specus_address);
        free(client_name);
        return;
    }

    if (strcmp(client_name, session->config.client_name) != 0) {
        send_register_result(session, port, 0, "clientName mismatch");
        free(specus_address);
        free(client_name);
        return;
    }
    pthread_mutex_lock(&session->map_lock);
    int allowed = mapping_allowed(&session->config, port, specus_address, specus_port);
    pthread_mutex_unlock(&session->map_lock);
    if (!allowed) {
        send_register_result(session, port, 0, "port mapping not configured");
        free(specus_address);
        free(client_name);
        return;
    }

    char reason[128];
    if (start_specus_listener(session, port, reason, sizeof(reason)) != 0) {
        send_register_result(session, port, 0, reason);
        free(specus_address);
        free(client_name);
        return;
    }

    printf("[nat] register ok client=%s port=%d -> %s:%d\n",
           client_name, port, specus_address, specus_port);
    send_register_result(session, port, 1, NULL);
    free(specus_address);
    free(client_name);
}

/*
 * A server-side RST for a stream the client named but that is not (or no longer) open here. As
 * Java resetTcpStream and Go resetTCPStream do, the id is tombstoned so the client's own RST for
 * it, should one cross this one, is taken as late rather than as a never-opened stream.
 */
static void reset_unknown_stream(specus_session *session, uint32_t stream_id,
                                 uint32_t code, const char *reason)
{
    pthread_mutex_lock(&session->map_lock);
    st_stream_tombstones_add(&session->closed_streams, stream_id);
    pthread_mutex_unlock(&session->map_lock);
    fprintf(stderr, "[nat] stream reset stream=%u client=%s code=%u reason=%s\n",
            stream_id, session->config.client_name, (unsigned)code, reason);
    (void)send_reset(session, stream_id, code, reason);
}

/*
 * DATA or DATA|END_STREAM for an ordinary TCP stream; an empty DATA|END_STREAM is a bare FIN. A
 * frame the stream cannot take resets only this stream (protocol/spec/control-protocol.md): DATA
 * for an unknown stream or after the client's FIN with RST 7 as in Java and Go, a frame the 4 MiB
 * client-to-public queue cannot hold with RST 6 like Java StreamFlowController's queue overflow.
 */
static void process_control_data(specus_session *session, const st_nat_message *message)
{
    if (process_ws_data(session, message)) {
        return;
    }
    int end_stream = (message->flags & ST_NAT_FLAG_END_STREAM) != 0U;
    uint32_t reset_code = 0U;
    const char *reset_reason = NULL;
    pthread_mutex_lock(&session->map_lock);
    external_conn *conn = find_conn_locked(session, message->stream_id);
    int unknown = conn == NULL || conn->fd < 0;
    if (!unknown) {
        int rc = 0;
        if (message->data_len > 0U) {
            rc = enqueue_external_write(conn, message->data, message->data_len, end_stream);
        } else if (end_stream) {
            rc = finish_external_write(conn);
        }
        if (rc == ST_EXTERNAL_WRITE_AFTER_FIN) {
            reset_code = 7U;
            reset_reason = "client TCP DATA after FIN";
        } else if (rc != 0) {
            reset_code = 6U;
            reset_reason = "stream send queue exceeded";
        }
        if (reset_code != 0U) {
            close_conn_locked(conn);
        }
    }
    pthread_mutex_unlock(&session->map_lock);
    if (unknown) {
        reset_unknown_stream(session, message->stream_id, 7U, "DATA for unknown TCP stream");
    } else if (reset_code != 0U) {
        fprintf(stderr, "[nat] TCP stream reset stream=%u client=%s code=%u reason=%s bytes=%zu\n",
                message->stream_id, session->config.client_name, (unsigned)reset_code,
                reset_reason, message->data_len);
        (void)send_reset(session, message->stream_id, reset_code, reset_reason);
    }
}

/*
 * FIN or RST for a WebSocket or ordinary TCP stream. Returns -1 for an RST naming a stream that
 * was never opened, which the spec makes a data-connection protocol violation; an RST for a
 * recently closed stream is late and ignored. A FIN for an unknown stream or a second FIN resets
 * only that stream with RST 7, as Java and Go do.
 */
static int process_control_closed(specus_session *session, const st_nat_message *message)
{
    if (process_ws_closed(session, message)) {
        return 0;
    }
    int unknown = 0;
    int never_opened = 0;
    int duplicate_fin = 0;
    pthread_mutex_lock(&session->map_lock);
    external_conn *conn = find_conn_locked(session, message->stream_id);
    if (conn == NULL || conn->fd < 0) {
        unknown = 1;
        never_opened = message->type == ST_NAT_RST
            && !st_stream_tombstones_contains(&session->closed_streams, message->stream_id);
    } else if (message->type == ST_NAT_RST) {
        close_conn_locked(conn);
    } else if (finish_external_write(conn) != 0) {
        close_conn_locked(conn);
        duplicate_fin = 1;
    }
    pthread_mutex_unlock(&session->map_lock);
    if (never_opened) {
        fprintf(stderr, "[nat] RST for never-opened stream=%u client=%s\n",
                message->stream_id, session->config.client_name);
        return -1;
    }
    if (unknown && message->type == ST_NAT_FIN) {
        reset_unknown_stream(session, message->stream_id, 7U, "FIN for unknown TCP stream");
    } else if (duplicate_fin) {
        fprintf(stderr, "[nat] TCP stream reset stream=%u client=%s code=7 reason=duplicate client TCP FIN\n",
                message->stream_id, session->config.client_name);
        (void)send_reset(session, message->stream_id, 7U, "duplicate client TCP FIN");
    }
    return 0;
}

/*
 * A client OPEN is only valid as the response head of a pending Direct HTTP stream. Any other one
 * resets just that stream with RST 8, as in Java and Go; a TCP or WebSocket stream with that id is
 * torn down with it, since the client drops a stream once it has seen its RST.
 */
static void process_unexpected_open(specus_session *session, const st_nat_message *message)
{
    pthread_mutex_lock(&session->map_lock);
    external_conn *conn = find_conn_locked(session, message->stream_id);
    if (conn != NULL) {
        close_conn_locked(conn);
    }
    ws_conn *ws = remove_ws_stream_locked(session, message->stream_id);
    pthread_mutex_unlock(&session->map_lock);
    if (ws != NULL) {
        st_admin_direct_ws_peer_reset(ws->stream);
        free_ws_conn(ws);
    }
    reset_unknown_stream(session, message->stream_id, 8U, "invalid HTTP response headers");
}

static void process_unregister(specus_session *session, const st_nat_message *message)
{
    int port;
    if (st_json_get_int(message->meta_json, "port", &port) == 0) {
        printf("[nat] unregister port=%d client=%s\n", port, session->config.client_name);
        stop_specus_listener(session, port);
    }
}

/*
 * Returns -1 for a data-connection protocol violation, after which the caller closes the data
 * connection: an RST for a never-opened stream, a WINDOW_UPDATE that overflows a stream's send
 * window (Java StreamFlowController.onWindowUpdate and Go handleWindowUpdate close the connection
 * too) and a NAT type a client never sends. Everything that concerns a single stream is answered
 * on that stream only.
 */
static int process_nat_message(specus_session *session, const st_nat_message *message)
{
    int direct_result = process_direct_http_message(session, message);
    if (direct_result != 0) {
        if (direct_result < 0) {
            fprintf(stderr, "[nat] protocol violation on HTTP stream=%u type=%d client=%s\n",
                    message->stream_id, message->type, session->config.client_name);
            return -1;
        }
        return 0;
    }
    switch (message->type) {
        case ST_NAT_REGISTER:
            process_register(session, message);
            return 0;
        case ST_NAT_UNREGISTER:
            process_unregister(session, message);
            return 0;
        case ST_NAT_OPEN:
            process_unexpected_open(session, message);
            return 0;
        case ST_NAT_DATA:
            process_control_data(session, message);
            return 0;
        case ST_NAT_FIN:
        case ST_NAT_RST:
            return process_control_closed(session, message);
        case ST_NAT_WINDOW_UPDATE: {
            /* Credit for a stream that is not open any more is late and ignored. */
            pthread_mutex_lock(&session->map_lock);
            external_conn *conn = find_conn_locked(session, message->stream_id);
            ws_conn *ws = conn == NULL ? find_ws_stream_locked(session, message->stream_id) : NULL;
            int overflow = conn != NULL
                ? add_send_credit(conn, message->value) != 0
                : ws != NULL && st_admin_direct_ws_add_send_credit(ws->stream, message->value) != 0;
            pthread_mutex_unlock(&session->map_lock);
            if (overflow) {
                fprintf(stderr, "[nat] WINDOW_UPDATE overflows the send window stream=%u client=%s\n",
                        message->stream_id, session->config.client_name);
                return -1;
            }
            return 0;
        }
        case ST_NAT_KEEPALIVE:
            return 0;
        default:
            fprintf(stderr, "[nat] protocol violation type=%d client=%s\n",
                    message->type, session->config.client_name);
            return -1;
    }
}

static void session_shutdown(specus_session *session)
{
    direct_pending_fail_all(session, "control connection closed");

    pthread_mutex_lock(&session->send_lock);
    if (session->control_fd >= 0) {
        st_tls_connection_free(session->tls_connection);
        session->tls_connection = NULL;
        /* The shutdown path shuts registered sockets down under this lock; closing under it too
         * keeps that path from ever touching a descriptor number that was already reused. */
        pthread_mutex_lock(&connection_registry_lock);
        shutdown(session->control_fd, SHUT_RDWR);
        close(session->control_fd);
        session->control_fd = -1;
        pthread_mutex_unlock(&connection_registry_lock);
    }
    pthread_mutex_unlock(&session->send_lock);

    pthread_mutex_lock(&session->map_lock);
    session->active = 0;
    for (specus_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (listener->fd >= 0) {
            shutdown(listener->fd, SHUT_RDWR);
            close(listener->fd);
            listener->fd = -1;
        }
    }
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        close_conn_locked(conn);
    }
    for (ws_conn *conn = session->ws_conns; conn != NULL; conn = conn->next) {
        st_admin_direct_ws_close(conn->stream);
    }
    pthread_mutex_unlock(&session->map_lock);

    for (specus_listener *listener = session->listeners; listener != NULL; listener = listener->next) {
        if (listener->thread_started) {
            pthread_join(listener->thread, NULL);
        }
    }
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (conn->thread_started) {
            pthread_join(conn->thread, NULL);
        }
        if (conn->writer_thread_started) {
            pthread_join(conn->writer_thread, NULL);
        }
    }

    specus_listener *listener = session->listeners;
    while (listener != NULL) {
        specus_listener *next = listener->next;
        free(listener);
        listener = next;
    }
    external_conn *conn = session->conns;
    while (conn != NULL) {
        external_conn *next = conn->next;
        free_external_write_queue(conn);
        pthread_cond_destroy(&conn->flow_cond);
        pthread_mutex_destroy(&conn->flow_lock);
        pthread_cond_destroy(&conn->write_cond);
        pthread_mutex_destroy(&conn->write_lock);
        free(conn);
        conn = next;
    }
    ws_conn *ws = session->ws_conns;
    while (ws != NULL) {
        ws_conn *next = ws->next;
        free_ws_conn(ws);
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
    specus_session *session = (specus_session *)calloc(1, sizeof(*session));
    if (session == NULL) {
        close(args->fd);
        free(args);
        return NULL;
    }
    session->control_fd = args->fd;
    session->config = args->config;
    session->active = 1;
    session->references = 1U;
    session->next_stream_id = 1U;
    pthread_mutex_init(&session->send_lock, NULL);
    pthread_mutex_init(&session->map_lock, NULL);
    pthread_mutex_init(&session->direct_lock, NULL);
    pthread_cond_init(&session->reference_cond, NULL);
    remote_text(&args->remote, args->remote_len, session->remote, sizeof(session->remote));
    free(args);

    if (connection_register(session) != 0) {
        /* Accepted just as the server began to stop: nothing was read, so nothing to record. */
        close(session->control_fd);
        pthread_mutex_destroy(&session->send_lock);
        pthread_mutex_destroy(&session->map_lock);
        pthread_mutex_destroy(&session->direct_lock);
        pthread_cond_destroy(&session->reference_cond);
        free(session);
        return NULL;
    }
    printf("[control] accepted %s\n", session->remote);

    if (st_tls_server_context_enabled(session->config.tls_context)) {
        char tls_error[512];
        if (st_tls_connection_accept(session->config.tls_context,
                                     session->control_fd,
                                     &session->tls_connection,
                                     tls_error,
                                     sizeof(tls_error)) != 0) {
            fprintf(stderr, "[tls] handshake rejected remote=%s: %s\n", session->remote, tls_error);
            session_shutdown(session);
            connection_unregister(session);
            pthread_mutex_destroy(&session->send_lock);
            pthread_mutex_destroy(&session->map_lock);
            pthread_mutex_destroy(&session->direct_lock);
            pthread_cond_destroy(&session->reference_cond);
            free(session);
            return NULL;
        }
        printf("[tls] handshake complete remote=%s\n", session->remote);
    }

    int logged_in = 0;
    const char *disconnect_reason = "CLIENT_CLOSED";
    int heartbeat_logged = 0;
    for (;;) {
        st_frame_header header;
        uint8_t *body = NULL;
        size_t frame_limit = logged_in ? ST_MAX_FRAME_SIZE : ST_PRE_AUTH_MAX_FRAME_SIZE;
        int rc = read_frame(session, frame_limit, &header, &body);
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

            session->is_data_connection = strcmp(
                request.connection_role, ST_CONNECTION_ROLE_DATA) == 0;
            /*
             * A login for a client that already has a connection of this role is not refused: the
             * spec keeps one control and one data per client and lets the newer connection replace
             * the older one. The session is published before the response is written, so once the
             * client sees success its next frame already finds this connection bound.
             */
            const char *reason = NULL;
            int control_login = !session->is_data_connection;
            if (control_login) {
                pthread_mutex_lock(&control_admission_lock);
            }
            logged_in = verify_login(session, &request, &reason);
            if (logged_in) {
                session->connected_since_ms = now_ms();
                if (activate_session(session, &reason) != 0) {
                    logged_in = 0;
                }
            }
            if (control_login) {
                pthread_mutex_unlock(&control_admission_lock);
            }
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
            printf("[%s] login ok client=%s remote=%s\n",
                   session->is_data_connection ? "data" : "control",
                   request.client_name, session->remote);
            if (!session->is_data_connection) {
                record_login_success_event(session);
                record_client_online_milestone(session);
                st_buffer nat_control = st_protocol_encode_nat_control(session->config.client_name,
                                                                       session->config.nat_control_json);
                if (session_send_packet(session, &nat_control) != 0) {
                    disconnect_reason = "IO_ERROR";
                    st_login_request_free(&request);
                    break;
                }
                printf("[nat-control] pushed %zu tcp route(s) to %s\n",
                       session->config.mapping_count, session->config.client_name);
                if (session->config.database_path[0] != '\0') {
                    st_peer_mesh_runtime peer_runtime = peer_mesh_runtime_for_session(session);
                    if (st_peer_mesh_push_on_login(&peer_runtime, session->config.client_name) != 0) {
                        fprintf(stderr, "[peer-mesh] login configuration push failed client=%s\n",
                                session->config.client_name);
                    }
                }
            }
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
            /* Only the first one per connection is logged: it shows the client's keepalive reaches
             * the server and is answered, without a line every few seconds for every channel. */
            if (!heartbeat_logged) {
                heartbeat_logged = 1;
                printf("[%s] first heartbeat answered client=%s remote=%s\n",
                       session->is_data_connection ? "data" : "control",
                       session->config.client_name, session->remote);
            }
            continue;
        }

        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) {
            /* Heartbeats are allowed on both roles (protocol/spec/control-protocol.md); a response
             * needs no answer and, as in Java ConnectionRoleHandler and Go, is simply accepted. */
            free(body);
            continue;
        }

        if (header.command == ST_CMD_LOGOUT_REQUEST) {
            free(body);
            st_buffer response = st_protocol_encode_empty_packet(ST_CMD_LOGOUT_RESPONSE);
            session_send_packet(session, &response);
            disconnect_reason = "CLIENT_CLOSED";
            break;
        }

        if (header.command == ST_CMD_MESSAGE_REQUEST) {
            if (session->is_data_connection) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[data] message request received on data connection from %s\n", session->remote);
                free(body);
                break;
            }
            st_message_response message_request;
            if (st_protocol_decode_message_response(body, header.length, &message_request) != 0) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[message] invalid request from %s\n", session->remote);
                free(body);
                break;
            }
            free(body);
            if (message_request.message_type == ST_MESSAGE_TYPE_CLIENT_TO_CLIENT
                && message_request.to_client_name != NULL
                && message_request.message != NULL) {
                int admin_target = message_target_is_admin(message_request.to_client_name);
                int delivery_rc = admin_target
                    ? st_admin_deliver_client_message_to_admin(session->config.tenant_id,
                                                               session->config.client_name,
                                                               message_request.to_client_name,
                                                               message_request.message)
                    : forward_runtime_client_message(session, &message_request);
                printf("[message] client->%s %s source=%s target=%s\n",
                       admin_target ? "admin" : "client",
                       delivery_rc == 0 ? "delivered" : "not-delivered",
                       session->config.client_name,
                       message_request.to_client_name);
            } else if (message_request.message_type == ST_MESSAGE_TYPE_CLIENT_TO_SERVER) {
                printf("[message] client->server source=%s bytes=%zu\n",
                       session->config.client_name,
                       message_request.message == NULL ? 0U : strlen(message_request.message));
            } else if (message_request.message_type == ST_MESSAGE_TYPE_PEER_CONTROL
                       && message_request.message != NULL
                       && session->config.database_path[0] != '\0') {
                st_peer_mesh_runtime peer_runtime = peer_mesh_runtime_for_session(session);
                int delivery_rc = st_peer_mesh_handle_control(&peer_runtime,
                                                              session->config.client_name,
                                                              message_request.to_client_name,
                                                              message_request.message);
                printf("[peer-mesh] signal %s source=%s target=%s\n",
                       delivery_rc == 0 ? "accepted" : "rejected",
                       session->config.client_name,
                       message_request.to_client_name == NULL ? "" : message_request.to_client_name);
            } else {
                fprintf(stderr,
                        "[message] unsupported type=%d source=%s target=%s\n",
                        message_request.message_type,
                        session->config.client_name,
                        message_request.to_client_name == NULL ? "" : message_request.to_client_name);
            }
            st_message_response_free(&message_request);
            continue;
        }

        if (header.command == ST_CMD_NAT_MESSAGE) {
            if (!session->is_data_connection) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[control] NAT frame received on control connection from %s\n", session->remote);
                free(body);
                break;
            }
            st_nat_message message;
            if (st_protocol_decode_nat_message(body, header.length, &message) != 0) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                fprintf(stderr, "[nat] bad NAT frame from %s\n", session->remote);
                free(body);
                break;
            }
            free(body);
            int nat_rc = process_nat_message(session, &message);
            st_nat_message_free(&message);
            if (nat_rc != 0) {
                disconnect_reason = "PROTOCOL_VIOLATION";
                break;
            }
            continue;
        }

        disconnect_reason = "PROTOCOL_VIOLATION";
        fprintf(stderr, "[%s] unsupported command=%d from %s\n",
               session->is_data_connection ? "data" : "control",
               (int)header.command, session->remote);
        free(body);
        break;
    }

    direct_pending_fail_all(session, "control connection closed");

    pthread_mutex_lock(&active_session_lock);
    int replaced = session->replaced;
    /* A replaced control's data connection was retired by the login that replaced it, and
     * whatever of this client is still bound belongs to the newer pair. A connection that never
     * logged in owns no pair: its config still names the default client, which it must not touch. */
    if (logged_in && !replaced) {
        active_session_close_data_locked(session);
    }
    active_session_remove_locked(session);
    while (session->references > 1U) {
        pthread_cond_wait(&session->reference_cond, &active_session_lock);
    }
    pthread_mutex_unlock(&active_session_lock);
    if (replaced) {
        disconnect_reason = "REPLACED_BY_NEW_LOGIN";
    } else if (connection_registry_stopping()) {
        disconnect_reason = "SERVER_SHUTDOWN";
    }
    if (logged_in && !session->is_data_connection) {
        /*
         * The runtime session goes offline only if no other control carries it: after a re-login
         * of the same session the newer control does, and writing DISCONNECTED here would leave
         * the live client looking offline and refuse its data connection. The decision and the
         * write happen under the admission lock so a concurrent re-login cannot slip between them.
         */
        int session_still_live;
        pthread_mutex_lock(&control_admission_lock);
        session_still_live = control_session_live(session->config.client_session_id);
        if (!session_still_live
            && session->config.database_path[0] != '\0'
            && session->config.client_session_db_backed
            && session->config.client_session_id > 0) {
            char disconnected_at[64];
            if (current_utc_timestamp(disconnected_at) == 0) {
                (void)st_storage_mark_client_session_disconnected(session->config.database_path,
                                                                  session->config.client_session_id,
                                                                  disconnected_at);
            }
        }
        pthread_mutex_unlock(&control_admission_lock);
        if (session->config.database_path[0] != '\0') {
            st_peer_mesh_runtime peer_runtime = peer_mesh_runtime_for_session(session);
            /* The catalog is keyed by runtime session; a newer control of the same session owns it now. */
            if (!session_still_live
                && st_peer_mesh_handle_disconnect(&peer_runtime,
                                                  session->config.client_name) != 0) {
                fprintf(stderr, "[peer-mesh] service catalog withdrawal failed client=%s\n",
                        session->config.client_name);
            }
            /* After active_session_remove_locked above, so the rosters count it as offline; a
             * client already back on a newer control is still online and is left alone. */
            if (st_peer_mesh_push_on_logout(&peer_runtime, session->config.client_name) != 0) {
                fprintf(stderr, "[peer-mesh] departure announcement failed client=%s\n",
                        session->config.client_name);
            }
        }
        record_session_disconnected_event(session, disconnect_reason);
    }
    session_shutdown(session);
    connection_unregister(session);
    pthread_mutex_destroy(&session->send_lock);
    pthread_mutex_destroy(&session->map_lock);
    pthread_mutex_destroy(&session->direct_lock);
    pthread_cond_destroy(&session->reference_cond);
    free(session);
    return NULL;
}

static pthread_mutex_t shutdown_signal_lock = PTHREAD_MUTEX_INITIALIZER;
static int shutdown_wake_fd = -1;
static sigset_t shutdown_signals;

/*
 * SIGTERM/SIGINT are blocked in every thread and taken here, so the accept loop can run the
 * graceful shutdown on its own thread instead of the process dying with channels still open,
 * sessions still NETTY_ONLINE and connection records never stamped.
 */
static void *shutdown_signal_thread(void *unused)
{
    (void)unused;
    int signal_number = 0;
    if (sigwait(&shutdown_signals, &signal_number) != 0) {
        return NULL;
    }
    printf("[server] signal %d received, shutting down\n", signal_number);
    fflush(stdout);
    /* Written under the lock main closes the pipe under, so the byte never lands in a reused fd. */
    pthread_mutex_lock(&shutdown_signal_lock);
    int wake_fd = shutdown_wake_fd;
    if (wake_fd >= 0) {
        char byte = 1;
        while (write(wake_fd, &byte, 1) < 0 && errno == EINTR) {
        }
    }
    pthread_mutex_unlock(&shutdown_signal_lock);
    if (wake_fd < 0) {
        /* Still starting up: nothing is connected yet, so stop as the default action would. */
        fprintf(stderr, "[server] signal %d outside the serving loop, exiting\n", signal_number);
        _exit(128 + signal_number);
    }
    return NULL;
}

static int start_shutdown_signal_thread(void)
{
    sigemptyset(&shutdown_signals);
    sigaddset(&shutdown_signals, SIGTERM);
    sigaddset(&shutdown_signals, SIGINT);
    /* Before any other thread exists, so every thread inherits the blocked mask. */
    if (pthread_sigmask(SIG_BLOCK, &shutdown_signals, NULL) != 0) {
        return -1;
    }
    pthread_t thread;
    if (pthread_create(&thread, NULL, shutdown_signal_thread, NULL) != 0) {
        return -1;
    }
    pthread_detach(thread);
    return 0;
}

/*
 * Opens the pipe that carries a SIGTERM/SIGINT to the serving loop. main does this before the
 * control listener opens: once a port accepts connections a readiness probe may call the server
 * up, and a signal from then on has to reach the graceful shutdown (the loop finds the byte on its
 * first poll) instead of the "outside the serving loop" exit, even while startup is still opening
 * the admin port.
 */
static int shutdown_wake_open(int shutdown_pipe[2])
{
    if (pipe(shutdown_pipe) != 0) {
        shutdown_pipe[0] = -1;
        shutdown_pipe[1] = -1;
        return -1;
    }
    pthread_mutex_lock(&shutdown_signal_lock);
    shutdown_wake_fd = shutdown_pipe[1];
    pthread_mutex_unlock(&shutdown_signal_lock);
    return 0;
}

static void shutdown_wake_close(int shutdown_pipe[2])
{
    pthread_mutex_lock(&shutdown_signal_lock);
    shutdown_wake_fd = -1;
    close(shutdown_pipe[1]);
    pthread_mutex_unlock(&shutdown_signal_lock);
    close(shutdown_pipe[0]);
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    if (start_shutdown_signal_thread() != 0) {
        fprintf(stderr, "shutdown signal handling failed to start\n");
        return 1;
    }

    if (st_security_baseline_validate_current() != 0) {
        return 1;
    }
    if (st_elasticsearch_traffic_initialize_current() != 0) {
        return 1;
    }
    if (st_media_capture_validate_current() != 0) {
        return 1;
    }
    if (st_public_discovery_initialize() != 0) {
        fprintf(stderr, "public transfer discovery initialization failed\n");
        return 1;
    }

    server_config config;
    if (load_config(&config) != 0) {
        st_public_discovery_shutdown();
        return 1;
    }
    st_stun_turn_server *stun_turn_server = NULL;
    if (env_bool("SPECUS_PEER_MESH_ENABLED", 0)) {
        if (st_stun_turn_server_start(&stun_turn_server) != 0) {
            fprintf(stderr, "Peer Mesh STUN/TURN listener failed to start\n");
            free(config.nat_control_json);
            st_public_discovery_shutdown();
            return 1;
        }
        printf("[peer-mesh] STUN/TURN UDP listener active on port %d\n",
               st_stun_turn_server_port(stun_turn_server));
    }

    st_tls_config tls_config;
    st_tls_config_from_env(&tls_config);
    char tls_error[512];
    if (st_tls_validate_deployment(&tls_config,
                                   getenv("SPECUS_ENV"),
                                   config.bind_address,
                                   tls_error,
                                   sizeof(tls_error)) != 0
        || st_tls_server_context_create(&tls_config,
                                        &config.tls_context,
                                        tls_error,
                                        sizeof(tls_error)) != 0) {
        fprintf(stderr, "TLS configuration rejected: %s\n", tls_error);
        st_stun_turn_server_stop(stun_turn_server);
        free(config.nat_control_json);
        st_public_discovery_shutdown();
        return 1;
    }

    int shutdown_pipe[2] = {-1, -1};
    if (shutdown_wake_open(shutdown_pipe) != 0) {
        perror("shutdown pipe");
        st_stun_turn_server_stop(stun_turn_server);
        st_tls_server_context_free(config.tls_context);
        free(config.nat_control_json);
        st_public_discovery_shutdown();
        return 1;
    }
    int listener = create_listener_on(config.bind_address, config.port);
    if (listener < 0) {
        shutdown_wake_close(shutdown_pipe);
        st_stun_turn_server_stop(stun_turn_server);
        st_tls_server_context_free(config.tls_context);
        free(config.nat_control_json);
        st_public_discovery_shutdown();
        return 1;
    }
    printf("specus-server-c listening on %s:%d tls=%s for client \"%s\" (%zu tcp route(s))\n",
           config.bind_address,
           config.port,
           st_tls_mode_name(tls_config.mode),
           config.client_name,
           config.mapping_count);

    st_admin_server admin_server;
    st_admin_set_nat_control_handler(push_runtime_nat_control, NULL);
    st_admin_set_client_runtime_status_handler(get_client_runtime_status, NULL);
    st_admin_set_client_message_handler(push_runtime_client_message, NULL);
    st_admin_set_peer_mesh_refresh_handler(push_runtime_peer_mesh_refresh, &config);
    const st_connectivity_device connectivity_device = {
        .presence = connectivity_presence,
        .probe = connectivity_probe,
        .now_ms = connectivity_now_ms,
        .log = NULL,
        .ctx = NULL,
    };
    st_admin_set_connectivity_device(&connectivity_device);
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
        st_admin_set_nat_control_handler(NULL, NULL);
        st_admin_set_client_runtime_status_handler(NULL, NULL);
        st_admin_set_client_message_handler(NULL, NULL);
        st_admin_set_peer_mesh_refresh_handler(NULL, NULL);
        close(listener);
        shutdown_wake_close(shutdown_pipe);
        st_stun_turn_server_stop(stun_turn_server);
        st_tls_server_context_free(config.tls_context);
        free(config.nat_control_json);
        st_public_discovery_shutdown();
        return 1;
    }
    if (peer_mesh_maintenance_start(config.database_path) != 0) {
        fprintf(stderr, "Peer Mesh catalog maintenance failed to start\n");
        st_admin_set_nat_control_handler(NULL, NULL);
        st_admin_set_client_runtime_status_handler(NULL, NULL);
        st_admin_set_client_message_handler(NULL, NULL);
        st_admin_set_peer_mesh_refresh_handler(NULL, NULL);
        close(listener);
        shutdown_wake_close(shutdown_pipe);
        st_stun_turn_server_stop(stun_turn_server);
        st_tls_server_context_free(config.tls_context);
        free(config.nat_control_json);
        st_public_discovery_shutdown();
        return 1;
    }

    int listener_flags = fcntl(listener, F_GETFL, 0);
    /* Nonblocking, so a connection that vanishes between poll() and accept() cannot park the loop
     * where it would no longer notice a shutdown request. */
    if (listener_flags < 0 || fcntl(listener, F_SETFL, listener_flags | O_NONBLOCK) != 0) {
        perror("control listener");
        shutdown_wake_close(shutdown_pipe);
        peer_mesh_maintenance_stop();
        st_admin_set_nat_control_handler(NULL, NULL);
        st_admin_set_client_runtime_status_handler(NULL, NULL);
        st_admin_set_client_message_handler(NULL, NULL);
        st_admin_set_peer_mesh_refresh_handler(NULL, NULL);
        close(listener);
        st_stun_turn_server_stop(stun_turn_server);
        st_tls_server_context_free(config.tls_context);
        free(config.nat_control_json);
        st_public_discovery_shutdown();
        return 1;
    }

    for (;;) {
        struct pollfd ready[2];
        ready[0].fd = listener;
        ready[0].events = POLLIN;
        ready[0].revents = 0;
        ready[1].fd = shutdown_pipe[0];
        ready[1].events = POLLIN;
        ready[1].revents = 0;
        if (poll(ready, 2, -1) < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("poll");
            break;
        }
        if (ready[1].revents != 0) {
            break;
        }
        if ((ready[0].revents & POLLIN) == 0) {
            if ((ready[0].revents & (POLLERR | POLLNVAL)) != 0) {
                fprintf(stderr, "control listener failed\n");
                break;
            }
            continue;
        }
        client_args *args = (client_args *)calloc(1, sizeof(*args));
        if (args == NULL) {
            fprintf(stderr, "out of memory\n");
            break;
        }
        args->remote_len = sizeof(args->remote);
        args->fd = accept(listener, (struct sockaddr *)&args->remote, &args->remote_len);
        if (args->fd < 0) {
            free(args);
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED) {
                continue;
            }
            perror("accept");
            break;
        }
        /* Linux does not pass O_NONBLOCK on to accepted sockets, but other systems do. */
        int accepted_flags = fcntl(args->fd, F_GETFL, 0);
        if (accepted_flags >= 0 && (accepted_flags & O_NONBLOCK) != 0) {
            (void)fcntl(args->fd, F_SETFL, accepted_flags & ~O_NONBLOCK);
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

    /*
     * Graceful shutdown, in the order Java and Go use: stop accepting, close every control/data
     * channel and let each one write its own disconnect (session DISCONNECTED, connection record
     * stamped) while storage is still in use, sweep whatever did not finish in time, and only then
     * stop the background writers. C opens SQLite per call, so there is no store handle to close;
     * what matters is that no channel bookkeeping is still pending when the process exits.
     */
    printf("[server] stopping: closing control/data connections\n");
    fflush(stdout);
    close(listener);
    size_t unfinished = close_live_connections_and_wait(ST_SHUTDOWN_DRAIN_SECONDS);
    if (unfinished > 0U) {
        fprintf(stderr, "[server] %zu connection(s) did not finish within %d s\n",
                unfinished, ST_SHUTDOWN_DRAIN_SECONDS);
    }
    if (config.database_path[0] != '\0') {
        char stopped_at[64];
        if (current_utc_timestamp(stopped_at) == 0) {
            int swept = 0;
            (void)st_storage_close_open_connections(config.database_path, "SERVER_SHUTDOWN", stopped_at, &swept);
            if (unfinished > 0U) {
                (void)st_storage_close_client_sessions_by_status(config.database_path, "NETTY_ONLINE", stopped_at);
            }
            printf("[server] stopped: %zu connection(s) unfinished, %d open connection record(s) swept\n",
                   unfinished, swept);
        }
    }
    shutdown_wake_close(shutdown_pipe);
    peer_mesh_maintenance_stop();
    st_admin_set_nat_control_handler(NULL, NULL);
    st_admin_set_client_runtime_status_handler(NULL, NULL);
    st_admin_set_client_message_handler(NULL, NULL);
    st_admin_set_peer_mesh_refresh_handler(NULL, NULL);
    st_stun_turn_server_stop(stun_turn_server);
    st_tls_server_context_free(config.tls_context);
    free(config.nat_control_json);
    st_public_discovery_shutdown();
    return 0;
}
