/*
 * Session lifecycle tests against a real specus-server-c process.
 *
 * Every scenario starts the server binary with its own SQLite database, logs a client in through
 * the real HTTP endpoint and drives the v2 control/data protocol over real sockets: re-login
 * replacing the previous pair and its NAT streams, a superseded session being refused, a dead
 * channel being cleaned up by the read-idle timeout, stale online rows, and SIGTERM closing every
 * channel and recording it before the process exits.
 *
 * Usage: specus_c_session_lifecycle_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "crypto.h"
#include "json.h"
#include "protocol.h"
#include "storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define ADMIN_USERNAME "lifecycle-admin"
#define ADMIN_PASSWORD "lifecycle-e2e-password-2026"
#define ADMIN_JWT_SECRET "lifecycle-e2e-jwt-secret-that-is-long-and-random-2026"
#define IO_TIMEOUT_MS 5000
#define MAX_EXTRA_ENV 4

typedef struct {
    pid_t pid;
    int control_port;
    int admin_port;
    char dir[256];
    char db_path[320];
    char log_path[320];
    const char *extra_env[MAX_EXTRA_ENV];
} test_server;

typedef struct {
    char client_name[256];
    long long client_id;
    long long session_id;
    char access_token[256];
} runtime_session;

static const char *server_binary = NULL;

#define CHECK(condition, ...)                                   \
    do {                                                        \
        if (!(condition)) {                                     \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                       \
            fprintf(stderr, "\n");                              \
            return 1;                                           \
        }                                                       \
    } while (0)

static long long monotonic_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

static long long wall_clock_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

static void sleep_ms(int ms)
{
    struct timespec delay;
    delay.tv_sec = ms / 1000;
    delay.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

/* ------------------------------------------------------------------------------------------- */
/* Sockets                                                                                       */

static int pick_free_port(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    address.sin_port = 0;
    socklen_t length = sizeof(address);
    int port = -1;
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0
        && getsockname(fd, (struct sockaddr *)&address, &length) == 0) {
        port = ntohs(address.sin_port);
    }
    close(fd);
    return port;
}

static int connect_local(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons((uint16_t)port);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const uint8_t *data, size_t len)
{
    size_t offset = 0U;
    while (offset < len) {
        ssize_t sent = send(fd, data + offset, len - offset, 0);
        if (sent < 0 && errno == EINTR) {
            continue;
        }
        if (sent <= 0) {
            return -1;
        }
        offset += (size_t)sent;
    }
    return 0;
}

/* 1 = filled, 0 = orderly EOF or reset, -1 = error, -2 = timed out. */
static int recv_exact(int fd, uint8_t *buffer, size_t len, long long deadline)
{
    size_t offset = 0U;
    while (offset < len) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -2;
        }
        struct pollfd ready;
        ready.fd = fd;
        ready.events = POLLIN;
        ready.revents = 0;
        int polled = poll(&ready, 1, (int)remaining);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled < 0) {
            return -1;
        }
        if (polled == 0) {
            return -2;
        }
        ssize_t received = recv(fd, buffer + offset, len - offset, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received == 0 || (received < 0 && (errno == ECONNRESET || errno == EPIPE))) {
            return 0;
        }
        if (received < 0) {
            return -1;
        }
        offset += (size_t)received;
    }
    return 1;
}

static int send_buffer(int fd, st_buffer *buffer)
{
    int rc = buffer->data == NULL ? -1 : send_all(fd, buffer->data, buffer->len);
    st_buffer_free(buffer);
    return rc;
}

/* Same return convention as recv_exact; on 1 the caller frees *body. */
static int read_frame(int fd, int timeout_ms, st_frame_header *header, uint8_t **body)
{
    long long deadline = monotonic_ms() + timeout_ms;
    uint8_t raw[ST_HEADER_SIZE];
    int rc = recv_exact(fd, raw, sizeof(raw), deadline);
    if (rc != 1) {
        return rc;
    }
    if (st_protocol_read_header(raw, header) != 0) {
        return -1;
    }
    *body = (uint8_t *)malloc(header->length == 0U ? 1U : header->length);
    if (*body == NULL) {
        return -1;
    }
    rc = recv_exact(fd, *body, header->length, deadline);
    if (rc != 1) {
        free(*body);
        *body = NULL;
    }
    return rc;
}

/* The server reads LOGIN_REQUEST but never writes one, so the test encodes it itself. */
static void put_varint(uint8_t *out, size_t *len, uint64_t value)
{
    while ((value & ~(uint64_t)0x7fU) != 0U) {
        out[(*len)++] = (uint8_t)((value & 0x7fU) | 0x80U);
        value >>= 7;
    }
    out[(*len)++] = (uint8_t)value;
}

static void put_string(uint8_t *out, size_t *len, const char *value)
{
    size_t value_len = strlen(value);
    put_varint(out, len, (uint64_t)value_len + 1U);
    memcpy(out + *len, value, value_len);
    *len += value_len;
}

static int send_login_request(int fd, const runtime_session *runtime, const char *role)
{
    uint8_t frame[2048];
    size_t len = ST_HEADER_SIZE;
    put_string(frame, &len, runtime->client_name);
    frame[len++] = 1U;
    int64_t session_id = runtime->session_id;
    put_varint(frame, &len, ((uint64_t)session_id << 1) ^ (uint64_t)(session_id >> 63));
    put_string(frame, &len, runtime->access_token);
    put_string(frame, &len, role);
    uint32_t body_len = (uint32_t)(len - ST_HEADER_SIZE);
    const uint8_t header[ST_HEADER_SIZE] = {
        0x14, 0x35, 0x35, 0x65, ST_VERSION, ST_SERIALIZER_COMPACT_BINARY, (uint8_t)ST_CMD_LOGIN_REQUEST,
        (uint8_t)(body_len >> 24), (uint8_t)(body_len >> 16), (uint8_t)(body_len >> 8), (uint8_t)body_len
    };
    memcpy(frame, header, sizeof(header));
    return send_all(fd, frame, len);
}

static int read_string_field(const uint8_t *body, size_t body_len, size_t *pos, char *out, size_t out_len)
{
    uint64_t marker = 0U;
    for (int shift = 0; shift < 35; shift += 7) {
        if (*pos >= body_len) {
            return -1;
        }
        uint8_t byte = body[(*pos)++];
        marker |= (uint64_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0U) {
            break;
        }
    }
    out[0] = '\0';
    if (marker == 0U) {
        return 0;
    }
    size_t value_len = (size_t)(marker - 1U);
    if (value_len > body_len - *pos) {
        return -1;
    }
    size_t copy = value_len < out_len - 1U ? value_len : out_len - 1U;
    memcpy(out, body + *pos, copy);
    out[copy] = '\0';
    *pos += value_len;
    return 0;
}

/*
 * Logs a connection in with the given role. Returns 1 and keeps the socket in *fd_out when the
 * server accepts, 0 with the server's reason when it refuses (the socket is closed), -1 on I/O
 * failure.
 */
static int channel_login(int port, const runtime_session *runtime, const char *role,
                         int *fd_out, char *reason, size_t reason_len)
{
    *fd_out = -1;
    reason[0] = '\0';
    int fd = connect_local(port);
    if (fd < 0 || send_login_request(fd, runtime, role) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        snprintf(reason, reason_len, "connect/send failed");
        return -1;
    }
    st_frame_header header;
    uint8_t *body = NULL;
    int rc = read_frame(fd, IO_TIMEOUT_MS, &header, &body);
    if (rc != 1 || header.command != ST_CMD_LOGIN_RESPONSE) {
        if (rc == 1) {
            free(body);
        }
        close(fd);
        snprintf(reason, reason_len, "no login response (rc=%d)", rc);
        return -1;
    }
    char client_name[256];
    size_t pos = 0U;
    int success = 0;
    if (read_string_field(body, header.length, &pos, client_name, sizeof(client_name)) != 0
        || pos >= header.length) {
        free(body);
        close(fd);
        snprintf(reason, reason_len, "malformed login response");
        return -1;
    }
    success = body[pos++] == 1U;
    if (read_string_field(body, header.length, &pos, reason, reason_len) != 0) {
        free(body);
        close(fd);
        snprintf(reason, reason_len, "malformed login response reason");
        return -1;
    }
    free(body);
    if (!success) {
        close(fd);
        return 0;
    }
    *fd_out = fd;
    return 1;
}

/* Reads and discards frames until the server closes the connection. */
static int expect_channel_closed(int fd, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(fd, (int)remaining, &header, &body);
        if (rc == 1) {
            free(body);
            continue;
        }
        return rc == 0 ? 0 : -1;
    }
}

/* A heartbeat answered proves the channel is still bound and served. */
static int expect_channel_alive(int fd)
{
    st_buffer heartbeat = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_REQUEST);
    if (send_buffer(fd, &heartbeat) != 0) {
        return -1;
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        if (read_frame(fd, (int)remaining, &header, &body) != 1) {
            return -1;
        }
        free(body);
        if (header.command == ST_CMD_HEARTBEAT_RESPONSE) {
            return 0;
        }
    }
}

/* Waits for the next NAT frame of the given type on a data connection, skipping everything else. */
static int expect_nat_frame(int fd, int type, st_nat_message *message)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return -1;
        }
        st_frame_header header;
        uint8_t *body = NULL;
        if (read_frame(fd, (int)remaining, &header, &body) != 1) {
            return -1;
        }
        if (header.command != ST_CMD_NAT_MESSAGE) {
            free(body);
            continue;
        }
        int decoded = st_protocol_decode_nat_message(body, header.length, message);
        free(body);
        if (decoded != 0) {
            return -1;
        }
        if (message->type == type) {
            return 0;
        }
        st_nat_message_free(message);
    }
}

static int nat_register(int data_fd, const char *client_name, int public_port, int target_port)
{
    char meta[512];
    snprintf(meta, sizeof(meta),
             "{\"port\":%d,\"specusAddress\":\"127.0.0.1\",\"specusPort\":%d,\"clientName\":\"%s\"}",
             public_port, target_port, client_name);
    st_buffer frame = st_protocol_encode_nat_message(ST_NAT_REGISTER, 0U, 0U, 0U, meta, NULL, 0U);
    if (send_buffer(data_fd, &frame) != 0) {
        return -1;
    }
    st_nat_message result;
    if (expect_nat_frame(data_fd, ST_NAT_REGISTER_RESULT, &result) != 0) {
        return -1;
    }
    int success = 0;
    int rc = st_json_get_bool(result.meta_json, "success", &success) == 0 && success ? 0 : -1;
    if (rc != 0) {
        fprintf(stderr, "REGISTER rejected: %s\n", result.meta_json == NULL ? "" : result.meta_json);
    }
    st_nat_message_free(&result);
    return rc;
}

/* Opens a public TCP connection through a registered port and waits for the stream's OPEN. */
static int open_public_stream(int data_fd, int public_port, int *public_fd)
{
    *public_fd = connect_local(public_port);
    if (*public_fd < 0) {
        return -1;
    }
    st_nat_message open;
    if (expect_nat_frame(data_fd, ST_NAT_OPEN, &open) != 0) {
        return -1;
    }
    int rc = open.stream_id != 0U ? 0 : -1;
    st_nat_message_free(&open);
    return rc;
}

static int expect_socket_eof(int fd, int timeout_ms)
{
    uint8_t byte;
    int rc = recv_exact(fd, &byte, 1U, monotonic_ms() + timeout_ms);
    return rc == 0 ? 0 : -1;
}

static void close_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/* ------------------------------------------------------------------------------------------- */
/* HTTP                                                                                          */

static int http_request(int port, const char *method, const char *path, const char *body,
                        const char *bearer, int *status, char **response_body)
{
    *status = 0;
    *response_body = NULL;
    int fd = connect_local(port);
    if (fd < 0) {
        return -1;
    }
    char head[1024];
    char authorization[600] = "";
    if (bearer != NULL) {
        snprintf(authorization, sizeof(authorization), "Authorization: Bearer %s\r\n", bearer);
    }
    size_t body_len = body == NULL ? 0U : strlen(body);
    int head_len = snprintf(head, sizeof(head),
                            "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nContent-Type: application/json\r\n"
                            "%sContent-Length: %zu\r\nConnection: close\r\n\r\n",
                            method, path, port, authorization, body_len);
    if (head_len < 0 || (size_t)head_len >= sizeof(head)
        || send_all(fd, (const uint8_t *)head, (size_t)head_len) != 0
        || (body_len > 0U && send_all(fd, (const uint8_t *)body, body_len) != 0)) {
        close(fd);
        return -1;
    }
    size_t capacity = 65536U;
    size_t used = 0U;
    char *response = (char *)malloc(capacity + 1U);
    if (response == NULL) {
        close(fd);
        return -1;
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    char *body_start = NULL;
    long long content_length = -1;
    for (;;) {
        if (body_start != NULL && content_length >= 0
            && (long long)(used - (size_t)(body_start - response)) >= content_length) {
            break;
        }
        if (used == capacity) {
            size_t offset = body_start == NULL ? 0U : (size_t)(body_start - response);
            char *grown = (char *)realloc(response, capacity * 2U + 1U);
            if (grown == NULL) {
                break;
            }
            response = grown;
            capacity *= 2U;
            if (body_start != NULL) {
                body_start = response + offset;
            }
        }
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready;
        ready.fd = fd;
        ready.events = POLLIN;
        ready.revents = 0;
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) {
            break;
        }
        ssize_t received = recv(fd, response + used, capacity - used, 0);
        if (received <= 0) {
            break;
        }
        used += (size_t)received;
        response[used] = '\0';
        if (body_start == NULL) {
            char *separator = strstr(response, "\r\n\r\n");
            if (separator != NULL) {
                body_start = separator + 4;
                const char *length_header = strstr(response, "Content-Length:");
                if (length_header != NULL && length_header < separator) {
                    content_length = strtoll(length_header + strlen("Content-Length:"), NULL, 10);
                }
            }
        }
    }
    close(fd);
    response[used] = '\0';
    if (body_start == NULL || sscanf(response, "HTTP/1.1 %d", status) != 1) {
        free(response);
        return -1;
    }
    *response_body = strdup(body_start);
    free(response);
    return *response_body == NULL ? -1 : 0;
}

static void random_hex(char *out, size_t bytes)
{
    uint8_t buffer[32];
    if (bytes > sizeof(buffer)) {
        bytes = sizeof(buffer);
    }
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, buffer, bytes) != (ssize_t)bytes) {
        for (size_t i = 0; i < bytes; ++i) {
            buffer[i] = (uint8_t)(rand() & 0xff);
        }
    }
    if (fd >= 0) {
        close(fd);
    }
    st_hex_encode(buffer, bytes, out);
}

/* A POST /api/client/auth/login body, signed exactly as protocol/spec/client-auth.md describes. */
static void signed_login_body(const char *api_key, const char *secret, const char *fingerprint,
                              const char *os_user, char *body, size_t body_len)
{
    char timestamp[32];
    char nonce[33];
    snprintf(timestamp, sizeof(timestamp), "%lld", wall_clock_ms());
    random_hex(nonce, 16U);
    uint8_t key[ST_SHA256_LEN];
    st_sha256((const uint8_t *)secret, strlen(secret), key);
    char canonical[1024];
    snprintf(canonical, sizeof(canonical), "%s\n%s\n%s\n%s\n%s", api_key, timestamp, nonce, fingerprint, os_user);
    uint8_t mac[ST_SHA256_LEN];
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)canonical, strlen(canonical), mac);
    char signature[ST_SHA256_HEX_LEN + 1];
    st_hex_encode(mac, sizeof(mac), signature);
    snprintf(body, body_len,
             "{\"apiKey\":\"%s\",\"timestamp\":\"%s\",\"nonce\":\"%s\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"%s\",\"hostname\":\"lifecycle-host\","
             "\"osUser\":\"%s\",\"osName\":\"Linux\",\"osVersion\":\"test\",\"osArch\":\"amd64\","
             "\"clientVersion\":\"session-lifecycle-test\"}}",
             api_key, timestamp, nonce, signature, fingerprint, os_user);
}

/* The real POST /api/client/auth/login with a freshly signed body. */
static int http_client_login(const test_server *server, const char *api_key, const char *secret,
                             const char *fingerprint, const char *os_user, runtime_session *out)
{
    memset(out, 0, sizeof(*out));
    char body[2048];
    signed_login_body(api_key, secret, fingerprint, os_user, body, sizeof(body));
    int status = 0;
    char *response = NULL;
    if (http_request(server->admin_port, "POST", "/api/client/auth/login", body, NULL, &status, &response) != 0) {
        return -1;
    }
    char *client_name = st_json_get_top_level_string(response, "clientName");
    char *token = st_json_get_top_level_string(response, "accessToken");
    int rc = status == 200 && client_name != NULL && token != NULL
        && st_json_get_i64(response, "clientSessionId", &out->session_id) == 0
        && st_json_get_i64(response, "clientId", &out->client_id) == 0
        && out->session_id > 0 && out->client_id > 0
        ? 0 : -1;
    if (rc == 0) {
        snprintf(out->client_name, sizeof(out->client_name), "%s", client_name);
        snprintf(out->access_token, sizeof(out->access_token), "%s", token);
    } else {
        fprintf(stderr, "client auth login failed: status=%d body=%s\n", status, response);
    }
    free(client_name);
    free(token);
    free(response);
    return rc;
}

/* Reads the management projection's "online" flag for one client: 1, 0, or -1 on error. */
static int admin_client_online(const test_server *server, const char *client_name)
{
    int status = 0;
    char *response = NULL;
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) {
        return -1;
    }
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    if (token == NULL) {
        return -1;
    }
    response = NULL;
    int rc = http_request(server->admin_port, "GET", "/api/admin/clients", NULL, token, &status, &response);
    free(token);
    if (rc != 0 || status != 200) {
        free(response);
        return -1;
    }
    char needle[320];
    snprintf(needle, sizeof(needle), "\"clientName\":\"%s\"", client_name);
    const char *view = strstr(response, needle);
    const char *online = view == NULL ? NULL : strstr(view, "\"online\":");
    int result = -1;
    if (online != NULL) {
        online += strlen("\"online\":");
        result = strncmp(online, "true", 4) == 0 ? 1 : (strncmp(online, "false", 5) == 0 ? 0 : -1);
    }
    free(response);
    return result;
}

/* ------------------------------------------------------------------------------------------- */
/* Database                                                                                      */

static int create_credential(const char *db_path, const char *api_key, const char *secret, int max_online)
{
    uint8_t digest[ST_SHA256_LEN];
    char secret_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)secret, strlen(secret), digest);
    st_hex_encode(digest, sizeof(digest), secret_hash);
    st_storage_client_credential credential;
    return st_storage_upsert_client_credential(db_path, 0, "default", ADMIN_USERNAME, api_key,
                                               secret_hash, 1, max_online, &credential);
}

static int create_mapping(const char *db_path, long long client_id, int public_port)
{
    st_storage_mapping mapping;
    return st_storage_create_mapping_for_client(db_path, client_id, public_port, "127.0.0.1", 9, 1, 0, &mapping);
}

/* Runs a query whose first column of the first row is text or integer; copies it as text. */
static int db_scalar(const char *db_path, const char *sql, const char *text_arg, long long int_arg,
                     char *out, size_t out_len)
{
    out[0] = '\0';
    sqlite3 *db = NULL;
    if (sqlite3_open(db_path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_busy_timeout(db, 5000);
    sqlite3_stmt *stmt = NULL;
    int rc = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        int index = 1;
        if (text_arg != NULL) {
            sqlite3_bind_text(stmt, index++, text_arg, -1, SQLITE_TRANSIENT);
        }
        if (sqlite3_bind_parameter_count(stmt) >= index) {
            sqlite3_bind_int64(stmt, index, int_arg);
        }
        int step = sqlite3_step(stmt);
        if (step == SQLITE_ROW) {
            const unsigned char *value = sqlite3_column_text(stmt, 0);
            snprintf(out, out_len, "%s", value == NULL ? "" : (const char *)value);
            rc = 0;
        } else if (step == SQLITE_DONE) {
            rc = 1;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}

static int session_status(const char *db_path, long long session_id, char *out, size_t out_len)
{
    return db_scalar(db_path, "SELECT status FROM specus_client_session WHERE id = ?", NULL, session_id,
                     out, out_len);
}

static int wait_session_status(const char *db_path, long long session_id, const char *expected, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    char status[64] = "";
    for (;;) {
        if (session_status(db_path, session_id, status, sizeof(status)) == 0 && strcmp(status, expected) == 0) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "session %lld status %s, expected %s\n", session_id, status, expected);
            return -1;
        }
        sleep_ms(50);
    }
}

/* Waits until a closed connection record of the client carries the given disconnect reason. */
static int wait_connection_reason(const char *db_path, const char *client_name, const char *reason, int timeout_ms)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM connection_record WHERE client_name = ? AND success = 1 "
             "AND disconnect_reason = '%s' AND disconnected_at IS NOT NULL AND disconnected_at <> ''",
             reason);
    long long deadline = monotonic_ms() + timeout_ms;
    char count[32] = "";
    for (;;) {
        if (db_scalar(db_path, sql, client_name, 0, count, sizeof(count)) == 0 && atoi(count) > 0) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "no %s connection record for %s\n", reason, client_name);
            return -1;
        }
        sleep_ms(50);
    }
}

/* ------------------------------------------------------------------------------------------- */
/* Server process                                                                                */

static void dump_server_log(const test_server *server)
{
    FILE *log = fopen(server->log_path, "r");
    if (log == NULL) {
        return;
    }
    fprintf(stderr, "---- server log (%s) ----\n", server->log_path);
    char line[1024];
    while (fgets(line, sizeof(line), log) != NULL) {
        fputs(line, stderr);
    }
    fprintf(stderr, "---- end of server log ----\n");
    fclose(log);
}

static int server_prepare(test_server *server)
{
    memset(server, 0, sizeof(*server));
    server->pid = -1;
    const char *tmp = getenv("TMPDIR");
    snprintf(server->dir, sizeof(server->dir), "%s/specus-c-session-XXXXXX",
             tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    if (mkdtemp(server->dir) == NULL) {
        return -1;
    }
    snprintf(server->db_path, sizeof(server->db_path), "%s/specus.db", server->dir);
    snprintf(server->log_path, sizeof(server->log_path), "%s/server.log", server->dir);
    return st_storage_init(server->db_path, 1);
}

static int server_start(test_server *server)
{
    server->control_port = pick_free_port();
    server->admin_port = pick_free_port();
    if (server->control_port <= 0 || server->admin_port <= 0 || server->control_port == server->admin_port) {
        return -1;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        return -1;
    }
    if (pid == 0) {
        char control_port[16];
        char admin_port[16];
        snprintf(control_port, sizeof(control_port), "%d", server->control_port);
        snprintf(admin_port, sizeof(admin_port), "%d", server->admin_port);
        setenv("SPECUS_ENV", "dev", 1);
        setenv("SPECUS_DATABASE_PATH", server->db_path, 1);
        /* The server binds its environment-token client, "Demo client", at startup. */
        setenv("SPECUS_DB_SEED_DEMO_CLIENT", "1", 1);
        setenv("SPECUS_NETTY_PORT", control_port, 1);
        setenv("SPECUS_NETTY_BIND_ADDRESS", "127.0.0.1", 1);
        setenv("SPECUS_ADMIN_PORT", admin_port, 1);
        setenv("SPECUS_AUTH_USERNAME", ADMIN_USERNAME, 1);
        setenv("SPECUS_AUTH_PASSWORD", ADMIN_PASSWORD, 1);
        setenv("SPECUS_AUTH_JWT_SECRET", ADMIN_JWT_SECRET, 1);
        for (size_t i = 0; i < MAX_EXTRA_ENV && server->extra_env[i] != NULL; ++i) {
            char assignment[256];
            snprintf(assignment, sizeof(assignment), "%s", server->extra_env[i]);
            char *equals = strchr(assignment, '=');
            if (equals != NULL) {
                *equals = '\0';
                setenv(assignment, equals + 1, 1);
            }
        }
        int log = open(server->log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (log >= 0) {
            dup2(log, STDOUT_FILENO);
            dup2(log, STDERR_FILENO);
            close(log);
        }
        execl(server_binary, server_binary, (char *)NULL);
        _exit(127);
    }
    server->pid = pid;
    long long deadline = monotonic_ms() + 20000;
    while (monotonic_ms() < deadline) {
        int status = 0;
        if (waitpid(pid, &status, WNOHANG) == pid) {
            server->pid = -1;
            fprintf(stderr, "server exited during startup (status %d)\n", status);
            return -1;
        }
        int admin = connect_local(server->admin_port);
        int control = admin < 0 ? -1 : connect_local(server->control_port);
        close_fd(&admin);
        if (control >= 0) {
            close_fd(&control);
            return 0;
        }
        sleep_ms(50);
    }
    fprintf(stderr, "server did not become ready\n");
    return -1;
}

/* Sends SIGTERM and waits for the exit; returns the exit status, or -1 if it had to be killed. */
static int server_stop(test_server *server, int timeout_ms)
{
    if (server->pid <= 0) {
        return -1;
    }
    kill(server->pid, SIGTERM);
    long long deadline = monotonic_ms() + timeout_ms;
    while (monotonic_ms() < deadline) {
        int status = 0;
        if (waitpid(server->pid, &status, WNOHANG) == server->pid) {
            server->pid = -1;
            return WIFEXITED(status) ? WEXITSTATUS(status) : 1000 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
        }
        sleep_ms(20);
    }
    kill(server->pid, SIGKILL);
    waitpid(server->pid, NULL, 0);
    server->pid = -1;
    return -1;
}

static void server_cleanup(test_server *server, int failed)
{
    if (server->pid > 0) {
        kill(server->pid, SIGKILL);
        waitpid(server->pid, NULL, 0);
        server->pid = -1;
    }
    if (failed) {
        dump_server_log(server);
    }
    const char *suffixes[] = {"/specus.db", "/specus.db-journal", "/specus.db-wal", "/specus.db-shm", "/server.log"};
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        char path[400];
        snprintf(path, sizeof(path), "%s%s", server->dir, suffixes[i]);
        unlink(path);
    }
    rmdir(server->dir);
}

/* ------------------------------------------------------------------------------------------- */
/* Scenarios                                                                                     */

/*
 * The same runtime session logging in again while its previous pair is still bound (a client whose
 * old sockets died without a FIN looks exactly like this to the server) replaces that pair: the old
 * control and data connections and the NAT stream on the old data connection are closed, the
 * public port is free for the new data connection at once, and the session stays NETTY_ONLINE.
 */
static int test_same_session_relogin_replaces_old_pair(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control1 = -1, data1 = -1, control2 = -1, data2 = -1, public_fd = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_relogin", "relogin-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_relogin", "relogin-secret", "machine-relogin", "alice", &runtime) == 0,
          "http login");
    CHECK(create_mapping(server->db_path, runtime.client_id, public_port) == 0, "mapping");

    CHECK(channel_login(server->control_port, &runtime, "control", &control1, reason, sizeof(reason)) == 1,
          "first control login: %s", reason);
    CHECK(channel_login(server->control_port, &runtime, "data", &data1, reason, sizeof(reason)) == 1,
          "first data login: %s", reason);
    CHECK(nat_register(data1, runtime.client_name, public_port, 9) == 0, "first REGISTER");
    CHECK(open_public_stream(data1, public_port, &public_fd) == 0, "public stream OPEN on first data");
    CHECK(admin_client_online(server, runtime.client_name) == 1, "client online before re-login");

    CHECK(channel_login(server->control_port, &runtime, "control", &control2, reason, sizeof(reason)) == 1,
          "re-login of the same session must replace the old control: %s", reason);
    CHECK(expect_channel_closed(control1, IO_TIMEOUT_MS) == 0, "old control was not closed");
    CHECK(expect_channel_closed(data1, IO_TIMEOUT_MS) == 0, "old data was not closed");
    CHECK(expect_socket_eof(public_fd, IO_TIMEOUT_MS) == 0, "NAT stream of the old data was not closed");

    CHECK(channel_login(server->control_port, &runtime, "data", &data2, reason, sizeof(reason)) == 1,
          "data login for the replacing control: %s", reason);
    CHECK(nat_register(data2, runtime.client_name, public_port, 9) == 0,
          "the old data connection still holds the public port");
    CHECK(expect_channel_alive(control2) == 0 && expect_channel_alive(data2) == 0, "new pair not served");
    CHECK(wait_connection_reason(server->db_path, runtime.client_name, "REPLACED_BY_NEW_LOGIN", IO_TIMEOUT_MS) == 0,
          "old control record not stamped REPLACED_BY_NEW_LOGIN");
    char status[64];
    CHECK(session_status(server->db_path, runtime.session_id, status, sizeof(status)) == 0
              && strcmp(status, "NETTY_ONLINE") == 0,
          "the departing old control took the live session offline: %s", status);
    CHECK(admin_client_online(server, runtime.client_name) == 1, "client not online after re-login");

    close_fd(&control2);
    CHECK(expect_channel_closed(data2, IO_TIMEOUT_MS) == 0, "closing the control did not close its data");
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the client left");
    close_fd(&control1);
    close_fd(&data1);
    close_fd(&data2);
    close_fd(&public_fd);
    return 0;
}

/*
 * An ordinary reconnect reuses the runtime session (spec: the token is reusable until it expires),
 * but once a later HTTP login of the same machine user issued a newer session, the old one opens
 * nothing any more. Also covers the same-machine single-instance rule.
 */
static int test_session_reuse_and_supersession(test_server *server)
{
    char reason[256];
    runtime_session first, second, third, fourth;
    int control = -1, data = -1, refused = -1;
    CHECK(create_credential(server->db_path, "ck_reuse", "reuse-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &first) == 0, "login 1");

    for (int round = 0; round < 2; ++round) {
        CHECK(channel_login(server->control_port, &first, "control", &control, reason, sizeof(reason)) == 1,
              "control login round %d with the same session: %s", round, reason);
        CHECK(channel_login(server->control_port, &first, "data", &data, reason, sizeof(reason)) == 1,
              "data login round %d: %s", round, reason);
        close_fd(&data);
        /* As in Java and Go, a data connection going away leaves its control connection alone. */
        CHECK(expect_channel_alive(control) == 0, "round %d: closing the data closed the control", round);
        close_fd(&control);
        CHECK(wait_session_status(server->db_path, first.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
              "round %d: session not DISCONNECTED", round);
    }

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &second) == 0, "login 2");
    CHECK(channel_login(server->control_port, &first, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "superseded session must not open a control channel, got: %s", reason);
    CHECK(channel_login(server->control_port, &second, "control", &control, reason, sizeof(reason)) == 1,
          "control login with the newer session: %s", reason);
    CHECK(channel_login(server->control_port, &first, "data", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "数据连接") != NULL,
          "old session must not attach a data channel, got: %s", reason);
    CHECK(channel_login(server->control_port, &second, "data", &data, reason, sizeof(reason)) == 1,
          "data login with the newer session: %s", reason);

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &third) == 0, "login 3");
    CHECK(channel_login(server->control_port, &third, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "同一台机器和用户已经有在线实例") != NULL,
          "a second live instance of the machine user must be refused, got: %s", reason);
    CHECK(expect_channel_alive(control) == 0, "the refused login disturbed the live control");

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &fourth) == 0, "login 4");
    CHECK(channel_login(server->control_port, &third, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "a session retired before it ever connected must stay unusable, got: %s", reason);

    close_fd(&data);
    close_fd(&control);
    CHECK(wait_session_status(server->db_path, second.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "second session not DISCONNECTED");
    return 0;
}

/* Each TCP connection logs in once; a second LOGIN_REQUEST on it is a protocol violation. */
static int test_second_login_on_one_connection_closes_it(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control = -1;
    CHECK(create_credential(server->db_path, "ck_twice", "twice-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_twice", "twice-secret", "machine-twice", "hank", &runtime) == 0, "login");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(send_login_request(control, &runtime, "control") == 0, "second LOGIN_REQUEST");
    CHECK(expect_channel_closed(control, IO_TIMEOUT_MS) == 0, "a second login on one connection was tolerated");
    CHECK(wait_connection_reason(server->db_path, runtime.client_name, "PROTOCOL_VIOLATION", IO_TIMEOUT_MS) == 0,
          "violation not recorded");
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the violation");
    close_fd(&control);
    return 0;
}

static int test_credential_online_limit(test_server *server)
{
    char reason[256];
    runtime_session machine_a, machine_b;
    int control_a = -1, control_b = -1;
    CHECK(create_credential(server->db_path, "ck_limit", "limit-secret", 1) == 0, "credential");
    CHECK(http_client_login(server, "ck_limit", "limit-secret", "machine-limit-a", "carol", &machine_a) == 0, "login a");
    CHECK(http_client_login(server, "ck_limit", "limit-secret", "machine-limit-b", "carol", &machine_b) == 0, "login b");
    CHECK(channel_login(server->control_port, &machine_a, "control", &control_a, reason, sizeof(reason)) == 1,
          "machine a: %s", reason);
    CHECK(channel_login(server->control_port, &machine_b, "control", &control_b, reason, sizeof(reason)) == 0
              && strstr(reason, "在线实例数已达上限") != NULL,
          "maxOnlineInstances=1 must refuse a second machine, got: %s", reason);
    close_fd(&control_a);
    CHECK(wait_session_status(server->db_path, machine_a.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "machine a not DISCONNECTED");
    CHECK(channel_login(server->control_port, &machine_b, "control", &control_b, reason, sizeof(reason)) == 1,
          "machine b once a left: %s", reason);
    close_fd(&control_b);
    return 0;
}

/*
 * A NETTY_ONLINE row whose session no bound control carries (a disconnect whose DISCONNECTED write
 * was lost) must not lock the machine user out: the next control login closes it first.
 */
static int test_stale_online_row_is_closed(test_server *server)
{
    char reason[256];
    runtime_session stale, fresh;
    int control = -1;
    CHECK(create_credential(server->db_path, "ck_stale_row", "stale-row-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_stale_row", "stale-row-secret", "machine-stale", "dave", &stale) == 0,
          "login 1");
    CHECK(st_storage_mark_client_session_online(server->db_path, stale.session_id, "lost-channel",
                                                "127.0.0.1:1", "2026-01-01T00:00:00Z") == 0,
          "mark stale row online");
    CHECK(http_client_login(server, "ck_stale_row", "stale-row-secret", "machine-stale", "dave", &fresh) == 0,
          "login 2");
    CHECK(channel_login(server->control_port, &fresh, "control", &control, reason, sizeof(reason)) == 1,
          "a stale online row blocked the machine user: %s", reason);
    CHECK(wait_session_status(server->db_path, stale.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "stale row not closed");
    close_fd(&control);
    return 0;
}

/*
 * With more than one instance allowed per machine user, a control login of a newer session takes
 * the client over: the previous pair and its NAT stream close, and the previous session can neither
 * attach a data connection nor open a control channel again.
 */
static int test_new_session_replaces_previous_session(test_server *server)
{
    char reason[256];
    runtime_session old_session, new_session;
    int control1 = -1, data1 = -1, control2 = -1, data2 = -1, refused = -1, public_fd = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_replace", "replace-secret", 3) == 0, "credential");
    CHECK(http_client_login(server, "ck_replace", "replace-secret", "machine-replace", "erin", &old_session) == 0,
          "login 1");
    CHECK(create_mapping(server->db_path, old_session.client_id, public_port) == 0, "mapping");
    CHECK(channel_login(server->control_port, &old_session, "control", &control1, reason, sizeof(reason)) == 1,
          "old control: %s", reason);
    CHECK(channel_login(server->control_port, &old_session, "data", &data1, reason, sizeof(reason)) == 1,
          "old data: %s", reason);
    CHECK(nat_register(data1, old_session.client_name, public_port, 9) == 0, "old REGISTER");
    CHECK(open_public_stream(data1, public_port, &public_fd) == 0, "public stream OPEN");

    CHECK(http_client_login(server, "ck_replace", "replace-secret", "machine-replace", "erin", &new_session) == 0,
          "login 2");
    CHECK(strcmp(new_session.client_name, old_session.client_name) == 0, "same machine user, same client");
    CHECK(channel_login(server->control_port, &new_session, "control", &control2, reason, sizeof(reason)) == 1,
          "new session control: %s", reason);
    CHECK(expect_channel_closed(control1, IO_TIMEOUT_MS) == 0, "old control was not closed");
    CHECK(expect_channel_closed(data1, IO_TIMEOUT_MS) == 0, "old data was not closed");
    CHECK(expect_socket_eof(public_fd, IO_TIMEOUT_MS) == 0, "old NAT stream was not closed");

    CHECK(channel_login(server->control_port, &old_session, "data", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "数据连接") != NULL,
          "old session attached a data connection, got: %s", reason);
    CHECK(channel_login(server->control_port, &old_session, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "old session reopened a control channel, got: %s", reason);
    CHECK(wait_session_status(server->db_path, old_session.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "old session not DISCONNECTED");
    char status[64];
    CHECK(session_status(server->db_path, new_session.session_id, status, sizeof(status)) == 0
              && strcmp(status, "NETTY_ONLINE") == 0,
          "new session status %s", status);
    CHECK(wait_connection_reason(server->db_path, old_session.client_name, "REPLACED_BY_NEW_LOGIN",
                                 IO_TIMEOUT_MS) == 0,
          "replaced control not recorded");

    CHECK(channel_login(server->control_port, &new_session, "data", &data2, reason, sizeof(reason)) == 1,
          "new session data: %s", reason);
    CHECK(nat_register(data2, new_session.client_name, public_port, 9) == 0, "public port not released");
    CHECK(expect_channel_alive(control2) == 0 && expect_channel_alive(data2) == 0, "new pair not served");
    close_fd(&control2);
    close_fd(&data2);
    close_fd(&control1);
    close_fd(&data1);
    close_fd(&public_fd);
    return 0;
}

/*
 * A pair whose peer went silent without a FIN is torn down by the read-idle timeout and stops
 * counting as online: the management view shows it offline and a new session of the same machine
 * user is admitted.
 */
static int test_dead_channel_is_cleaned_up(test_server *server)
{
    char reason[256];
    runtime_session dead, fresh;
    int control = -1, data = -1;
    CHECK(create_credential(server->db_path, "ck_idle", "idle-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_idle", "idle-secret", "machine-idle", "frank", &dead) == 0, "login 1");
    CHECK(channel_login(server->control_port, &dead, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, &dead, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);
    CHECK(admin_client_online(server, dead.client_name) == 1, "client not online while connected");

    /* From here on the client sends nothing, exactly like a peer that vanished. */
    CHECK(expect_channel_closed(control, 15000) == 0, "silent control was not closed by the idle timeout");
    CHECK(expect_channel_closed(data, 15000) == 0, "silent data was not closed");
    CHECK(wait_session_status(server->db_path, dead.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "dead session still online");
    CHECK(wait_connection_reason(server->db_path, dead.client_name, "IDLE_TIMEOUT", IO_TIMEOUT_MS) == 0,
          "idle timeout not recorded");
    CHECK(admin_client_online(server, dead.client_name) == 0, "dead channel keeps the client online");

    close_fd(&control);
    close_fd(&data);
    CHECK(http_client_login(server, "ck_idle", "idle-secret", "machine-idle", "frank", &fresh) == 0, "login 2");
    CHECK(channel_login(server->control_port, &fresh, "control", &control, reason, sizeof(reason)) == 1,
          "the dead channel still blocks the machine user: %s", reason);
    close_fd(&control);
    return 0;
}

/*
 * SIGTERM closes every channel (logged in or not) and every NAT stream, each control records its
 * own disconnect as SERVER_SHUTDOWN and takes its session offline, and only then does the process
 * exit with status 0.
 */
static int test_sigterm_closes_channels_before_exit(test_server *server, runtime_session *runtime)
{
    char reason[256];
    int control = -1, data = -1, public_fd = -1, pre_auth = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_shutdown", "shutdown-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_shutdown", "shutdown-secret", "machine-shutdown", "gina", runtime) == 0,
          "http login");
    CHECK(create_mapping(server->db_path, runtime->client_id, public_port) == 0, "mapping");
    CHECK(channel_login(server->control_port, runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, runtime, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);
    CHECK(nat_register(data, runtime->client_name, public_port, 9) == 0, "REGISTER");
    CHECK(open_public_stream(data, public_port, &public_fd) == 0, "public stream OPEN");
    CHECK(expect_channel_alive(control) == 0, "control idle in its read loop");
    pre_auth = connect_local(server->control_port);
    CHECK(pre_auth >= 0, "pre-auth connection");

    CHECK(kill(server->pid, SIGTERM) == 0, "SIGTERM");
    CHECK(expect_channel_closed(control, 10000) == 0, "control not closed at shutdown");
    CHECK(expect_channel_closed(data, 10000) == 0, "data not closed at shutdown");
    CHECK(expect_socket_eof(public_fd, 10000) == 0, "NAT stream not closed at shutdown");
    CHECK(expect_socket_eof(pre_auth, 10000) == 0, "pre-auth connection not closed at shutdown");
    int exit_status = server_stop(server, 20000);
    CHECK(exit_status == 0, "server exit status %d", exit_status);

    char status[64];
    CHECK(session_status(server->db_path, runtime->session_id, status, sizeof(status)) == 0
              && strcmp(status, "DISCONNECTED") == 0,
          "session left %s by the shutdown", status);
    CHECK(wait_connection_reason(server->db_path, runtime->client_name, "SERVER_SHUTDOWN", 0) == 0,
          "control record not stamped SERVER_SHUTDOWN");
    char open_records[32];
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) FROM connection_record WHERE disconnected_at IS NULL OR disconnected_at = ''",
                    NULL, 0, open_records, sizeof(open_records)) == 0
              && strcmp(open_records, "0") == 0,
          "%s connection record(s) left open", open_records);
    FILE *log = fopen(server->log_path, "r");
    int drained = 0;
    if (log != NULL) {
        char line[1024];
        while (fgets(line, sizeof(line), log) != NULL) {
            if (strstr(line, "[server] stopped: 0 connection(s) unfinished") != NULL) {
                drained = 1;
            }
        }
        fclose(log);
    }
    CHECK(drained, "channels did not all finish their own bookkeeping before the process exited");
    close_fd(&control);
    close_fd(&data);
    close_fd(&public_fd);
    close_fd(&pre_auth);
    return 0;
}

/* A restart closes what a process that never shut down cleanly left online or open. */
static int test_restart_closes_leftover_state(test_server *server, const runtime_session *runtime)
{
    long long record_id = 0;
    CHECK(st_storage_mark_client_session_online(server->db_path, runtime->session_id, "killed-channel",
                                                "127.0.0.1:1", "2026-01-01T00:00:00Z") == 0,
          "leftover online session");
    CHECK(st_storage_record_connection_detail_with_tenant_and_id(server->db_path, "default", runtime->client_id,
                                                                 runtime->client_name, NULL, "127.0.0.1:1", 1,
                                                                 NULL, NULL, "2026-01-01T00:00:00Z", NULL,
                                                                 &record_id) == 0,
          "leftover open connection record");
    CHECK(server_start(server) == 0, "restart");
    char status[64];
    CHECK(session_status(server->db_path, runtime->session_id, status, sizeof(status)) == 0
              && strcmp(status, "DISCONNECTED") == 0,
          "leftover session still %s after restart", status);
    char reason[64];
    CHECK(db_scalar(server->db_path, "SELECT COALESCE(disconnect_reason, '') FROM connection_record WHERE id = ?",
                    NULL, record_id, reason, sizeof(reason)) == 0
              && strcmp(reason, "SERVER_RESTARTED") == 0,
          "leftover record reason '%s'", reason);
    CHECK(server_stop(server, 20000) == 0, "second shutdown");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */

typedef int (*server_scenario)(test_server *server);

static int run_on_fresh_server(const char *name, server_scenario scenario, const char *const *extra_env)
{
    test_server server;
    if (server_prepare(&server) != 0) {
        fprintf(stderr, "%s: cannot prepare server directory\n", name);
        return 1;
    }
    for (size_t i = 0; extra_env != NULL && extra_env[i] != NULL && i < MAX_EXTRA_ENV; ++i) {
        server.extra_env[i] = extra_env[i];
    }
    int failed = server_start(&server) != 0;
    if (!failed) {
        failed = scenario(&server) != 0;
    }
    if (!failed && server.pid > 0 && server_stop(&server, 20000) != 0) {
        fprintf(stderr, "%s: server did not stop cleanly\n", name);
        failed = 1;
    }
    server_cleanup(&server, failed);
    printf("%s %s\n", failed ? "FAIL" : "ok  ", name);
    return failed;
}

/*
 * client-auth.md: a verified login consumes its (apiKey, nonce) pair. The identical signed body
 * sent again, well inside its 60 s timestamp window, is refused with Java's answer and mints no
 * second session; a freshly signed login for the same machine still succeeds.
 */
static int test_replayed_login_is_rejected(test_server *server)
{
    CHECK(create_credential(server->db_path, "ck_replay", "replay-secret", 2) == 0, "credential");
    char body[2048];
    signed_login_body("ck_replay", "replay-secret", "machine-replay", "mallory", body, sizeof(body));
    int status = 0;
    char *response = NULL;
    CHECK(http_request(server->admin_port, "POST", "/api/client/auth/login", body, NULL, &status, &response) == 0
          && status == 200 && strstr(response, "\"accessToken\":\"cs_") != NULL,
          "first login: status %d", status);
    free(response);
    response = NULL;
    int replay_ok = http_request(server->admin_port, "POST", "/api/client/auth/login", body, NULL,
                                 &status, &response) == 0
        && status == 400
        && strstr(response, "{\"error\":\"客户端签名 nonce 已使用\"}") != NULL
        && strstr(response, "accessToken") == NULL;
    if (!replay_ok) {
        fprintf(stderr, "replayed login answered %d: %s\n", status, response == NULL ? "" : response);
    }
    free(response);
    CHECK(replay_ok, "replayed login was not rejected");
    char sessions[32] = "";
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) FROM specus_client_session WHERE machine_fingerprint = ?",
                    "machine-replay", 0, sessions, sizeof(sessions)) == 0
          && strcmp(sessions, "1") == 0,
          "replay minted a session: %s session(s)", sessions);
    runtime_session fresh;
    CHECK(http_client_login(server, "ck_replay", "replay-secret", "machine-replay", "mallory", &fresh) == 0,
          "a freshly signed login after the replay");
    return 0;
}

static int scenario_default_limits(test_server *server)
{
    return test_replayed_login_is_rejected(server)
        || test_same_session_relogin_replaces_old_pair(server)
        || test_session_reuse_and_supersession(server)
        || test_second_login_on_one_connection_closes_it(server)
        || test_credential_online_limit(server)
        || test_stale_online_row_is_closed(server);
}

static int scenario_shutdown_and_restart(test_server *server)
{
    runtime_session runtime;
    return test_sigterm_closes_channels_before_exit(server, &runtime)
        || test_restart_closes_leftover_state(server, &runtime);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    static const char *const two_per_machine[] = {"SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES=2", NULL};
    static const char *const short_idle[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=5", NULL};
    int failures = 0;
    failures += run_on_fresh_server("login replay, relogin, supersession, single login, online limits, stale rows",
                                    scenario_default_limits, NULL);
    failures += run_on_fresh_server("new session replaces previous session",
                                    test_new_session_replaces_previous_session, two_per_machine);
    failures += run_on_fresh_server("dead channel cleanup", test_dead_channel_is_cleaned_up, short_idle);
    failures += run_on_fresh_server("SIGTERM shutdown and restart cleanup", scenario_shutdown_and_restart, NULL);
    if (failures != 0) {
        fprintf(stderr, "%d session lifecycle scenario(s) failed\n", failures);
        return 1;
    }
    printf("session lifecycle tests passed\n");
    return 0;
}
