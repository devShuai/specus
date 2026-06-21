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
#include <unistd.h>

#define ST_MAX_TCP_MAPPINGS 64U
#define ST_CHANNEL_ID_SIZE 64U
#define ST_IO_BUFFER_SIZE 16384U

typedef struct {
    int port;
    char tunnel_address[256];
    int tunnel_port;
} tcp_mapping;

typedef struct {
    char client_name[128];
    uint8_t password_hash[ST_SHA256_LEN];
    int port;
    char public_address[256];
    int login_time_window_ms;
    int control_read_idle_seconds;
    int max_global_external_connections;
    int max_client_external_connections;
    int max_port_external_connections;
    int admin_port;
    char static_root[512];
    tcp_mapping mappings[ST_MAX_TCP_MAPPINGS];
    size_t mapping_count;
    char *nat_control_json;
} server_config;

typedef struct tunnel_session tunnel_session;

typedef struct external_conn {
    int fd;
    int port;
    char channel_id[ST_CHANNEL_ID_SIZE];
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

struct tunnel_session {
    int control_fd;
    server_config config;
    pthread_mutex_t send_lock;
    pthread_mutex_t map_lock;
    external_conn *conns;
    tunnel_listener *listeners;
    int active;
    uint64_t next_channel_id;
    char remote[128];
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

    char *token = strtok(copy, ",");
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
        token = strtok(NULL, ",");
    }
    free(copy);
    return 0;
}

static int load_database_config(server_config *config, const char *database_path)
{
    if (st_storage_init(database_path, env_bool("TUNNEL_DB_SEED_DEMO_CLIENT", 1)) != 0) {
        return -1;
    }
    if (st_storage_load_client_hash(database_path, config->client_name, config->password_hash) != 0) {
        fprintf(stderr, "client not found or disabled in database: %s\n", config->client_name);
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
        mapping->port = mappings[i].listen_port;
        strcpy(mapping->tunnel_address, mappings[i].target_address);
        mapping->tunnel_port = mappings[i].target_port;
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
    const char *password = getenv("TUNNEL_CLIENT_PASSWORD");
    const char *password_hash = getenv("TUNNEL_CLIENT_PASSWORD_HASH");
    const char *public_address = getenv("TUNNEL_PUBLIC_ADDRESS");
    const char *database_path = getenv("TUNNEL_DATABASE_PATH");
    const char *static_root = getenv("TUNNEL_STATIC_ROOT");

    memset(config, 0, sizeof(*config));
    if (copy_config_string(config->client_name, sizeof(config->client_name),
                           "TUNNEL_CLIENT_NAME",
                           (name != NULL && *name != '\0') ? name : "Demo client") != 0
        || copy_config_string(config->public_address, sizeof(config->public_address),
                              "TUNNEL_PUBLIC_ADDRESS",
                              (public_address != NULL && *public_address != '\0') ? public_address : "127.0.0.1") != 0
        || env_int_range("TUNNEL_NETTY_PORT", 7010, 1, 65535, &config->port) != 0
        || env_int_range("TUNNEL_LOGIN_TIME_WINDOW_MS", 30000, 1000, 300000,
                         &config->login_time_window_ms) != 0
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
                               : "tunnel-server/src/main/resources/static") != 0) {
        return -1;
    }

    if (database_path != NULL && *database_path != '\0') {
        if (load_database_config(config, database_path) != 0) {
            return -1;
        }
    } else if (password_hash != NULL && *password_hash != '\0') {
        if (st_hex_decode_32(password_hash, config->password_hash) != 0) {
            fprintf(stderr, "invalid TUNNEL_CLIENT_PASSWORD_HASH; expected 64 hex chars\n");
            return -1;
        }
    } else {
        if (password == NULL || *password == '\0') {
            password = "test1234";
        }
        st_sha256((const uint8_t *)password, strlen(password), config->password_hash);
    }

    if (parse_tcp_mappings(config) != 0) {
        return -1;
    }
    if (build_nat_control_json(config) != 0) {
        fprintf(stderr, "failed to build NAT_CONTROL JSON\n");
        return -1;
    }
    return 0;
}

static int64_t now_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (int64_t)tv.tv_sec * 1000LL + (int64_t)tv.tv_usec / 1000LL;
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

static int verify_login(const server_config *config, const st_login_request *request, const char **reason)
{
    if (request->client_name == NULL
        || request->timestamp == NULL
        || request->nonce == NULL
        || request->check_sign == NULL
        || request->check_sign_len != ST_SHA256_LEN) {
        *reason = "登录包缺少必要字段";
        return 0;
    }

    if (strcmp(request->client_name, config->client_name) != 0) {
        *reason = "客户端不存在或未启用";
        return 0;
    }

    char *end = NULL;
    long long timestamp = strtoll(request->timestamp, &end, 10);
    if (end == request->timestamp || *end != '\0') {
        *reason = "时间戳无效";
        return 0;
    }
    int64_t delta = now_ms() - (int64_t)timestamp;
    int64_t window = (int64_t)config->login_time_window_ms;
    if (delta < -window || delta > window) {
        *reason = "签名无效或已过期";
        return 0;
    }

    size_t message_len = strlen(request->client_name)
        + 1U + strlen(request->timestamp)
        + 1U + strlen(request->nonce);
    char *message = (char *)malloc(message_len + 1U);
    if (message == NULL) {
        *reason = "服务器忙";
        return 0;
    }
    snprintf(message, message_len + 1U, "%s\n%s\n%s",
             request->client_name, request->timestamp, request->nonce);

    uint8_t expected[ST_SHA256_LEN];
    st_hmac_sha256(config->password_hash, ST_SHA256_LEN,
                   (const uint8_t *)message, message_len,
                   expected);
    free(message);

    if (!st_constant_time_eq(expected, request->check_sign, ST_SHA256_LEN)) {
        *reason = "签名无效或已过期";
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

static external_conn *find_conn_locked(tunnel_session *session, const char *channel_id)
{
    for (external_conn *conn = session->conns; conn != NULL; conn = conn->next) {
        if (!conn->done && strcmp(conn->channel_id, channel_id) == 0) {
            return conn;
        }
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

static int start_external_conn(tunnel_session *session, int fd, int port)
{
    external_conn *conn = (external_conn *)calloc(1, sizeof(*conn));
    if (conn == NULL) {
        close(fd);
        return -1;
    }
    conn->fd = fd;
    conn->port = port;
    conn->session = session;

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
        start_external_conn(session, fd, listener->port);
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
    if (conn != NULL && conn->fd >= 0) {
        if (send_all(conn->fd, message->data, message->data_len) != 0) {
            close_conn_locked(conn);
        }
    }
    pthread_mutex_unlock(&session->map_lock);
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
    pthread_mutex_unlock(&session->map_lock);
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
    remote_text(&args->remote, args->remote_len, session->remote, sizeof(session->remote));
    free(args);

    printf("[control] accepted %s\n", session->remote);

    int logged_in = 0;
    for (;;) {
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(session->control_fd, &header, &body);
        if (rc == 0) {
            printf("[control] closed %s\n", session->remote);
            break;
        }
        if (rc == -2) {
            fprintf(stderr, "[control] read idle timeout from %s\n", session->remote);
            break;
        }
        if (rc < 0) {
            fprintf(stderr, "[control] bad frame from %s\n", session->remote);
            break;
        }

        if (!logged_in) {
            if (header.command != ST_CMD_LOGIN_REQUEST) {
                fprintf(stderr, "[control] non-login packet before auth from %s\n", session->remote);
                free(body);
                break;
            }
            st_login_request request;
            if (st_protocol_decode_login_request(body, header.length, &request) != 0) {
                free(body);
                st_buffer response = st_protocol_encode_login_response("", 0, "登录包无法解析");
                session_send_packet(session, &response);
                break;
            }
            free(body);

            const char *reason = NULL;
            logged_in = verify_login(&session->config, &request, &reason);
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
                st_login_request_free(&request);
                break;
            }
            printf("[control] login ok client=%s remote=%s\n", request.client_name, session->remote);
            st_buffer nat_control = st_protocol_encode_nat_control(session->config.client_name,
                                                                   session->config.nat_control_json);
            if (session_send_packet(session, &nat_control) != 0) {
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
                break;
            }
            continue;
        }

        if (header.command == ST_CMD_LOGOUT_REQUEST) {
            free(body);
            st_buffer response = st_protocol_encode_empty_packet(ST_CMD_LOGOUT_RESPONSE);
            session_send_packet(session, &response);
            break;
        }

        if (header.command == ST_CMD_NAT_MESSAGE) {
            st_nat_message message;
            if (st_protocol_decode_nat_message(body, header.length, &message) != 0) {
                fprintf(stderr, "[nat] bad NAT frame from %s\n", session->remote);
                free(body);
                break;
            }
            free(body);
            process_nat_message(session, &message);
            st_nat_message_free(&message);
            continue;
        }

        printf("[control] unsupported command=%d from %s; keeping connection open\n",
               (int)header.command, session->remote);
        free(body);
    }

    session_shutdown(session);
    pthread_mutex_destroy(&session->send_lock);
    pthread_mutex_destroy(&session->map_lock);
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
        && st_admin_server_start(&admin_server, config.admin_port, config.static_root) != 0) {
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
