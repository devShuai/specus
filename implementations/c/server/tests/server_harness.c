#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "crypto.h"
#include "json.h"
#include "storage.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

const char *server_binary = NULL;

long long monotonic_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

long long wall_clock_ms(void)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

void sleep_ms(int ms)
{
    struct timespec delay;
    delay.tv_sec = ms / 1000;
    delay.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

/* ------------------------------------------------------------------------------------------- */
/* Sockets                                                                                       */

int pick_free_port(void)
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

int connect_local(int port)
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

int send_all(int fd, const uint8_t *data, size_t len)
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

int recv_exact(int fd, uint8_t *buffer, size_t len, long long deadline)
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

int send_buffer(int fd, st_buffer *buffer)
{
    int rc = buffer->data == NULL ? -1 : send_all(fd, buffer->data, buffer->len);
    st_buffer_free(buffer);
    return rc;
}

int read_frame(int fd, int timeout_ms, st_frame_header *header, uint8_t **body)
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

void close_fd(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
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

int send_login_request(int fd, const runtime_session *runtime, const char *role)
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

/* read_login_response that also copies the client name the response carries into name, unless NULL. */
static int read_named_login_response(int fd, int timeout_ms, int *command, int *success,
                                     char *name, size_t name_len, char *reason, size_t reason_len)
{
    *command = 0;
    *success = 0;
    reason[0] = '\0';
    st_frame_header header;
    uint8_t *body = NULL;
    int rc = read_frame(fd, timeout_ms, &header, &body);
    if (rc != 1) {
        snprintf(reason, reason_len, "no login response (rc=%d)", rc);
        return -1;
    }
    *command = header.command;
    if (header.command != ST_CMD_LOGIN_RESPONSE) {
        free(body);
        snprintf(reason, reason_len, "command %d came before the login response", header.command);
        return 0;
    }
    char client_name[256];
    size_t pos = 0U;
    if (read_string_field(body, header.length, &pos, client_name, sizeof(client_name)) != 0
        || pos >= header.length) {
        free(body);
        snprintf(reason, reason_len, "malformed login response");
        return -1;
    }
    *success = body[pos++] == 1U;
    if (name != NULL && name_len > 0U) {
        snprintf(name, name_len, "%s", client_name);
    }
    if (read_string_field(body, header.length, &pos, reason, reason_len) != 0) {
        free(body);
        snprintf(reason, reason_len, "malformed login response reason");
        return -1;
    }
    free(body);
    return 1;
}

int read_login_response(int fd, int timeout_ms, int *command, int *success, char *reason, size_t reason_len)
{
    return read_named_login_response(fd, timeout_ms, command, success, NULL, 0U, reason, reason_len);
}

int channel_login(int port, const runtime_session *runtime, const char *role,
                  int *fd_out, char *reason, size_t reason_len)
{
    return channel_login_answer(port, runtime, role, fd_out, NULL, 0U, reason, reason_len);
}

int channel_login_answer(int port, const runtime_session *runtime, const char *role, int *fd_out,
                         char *answered_name, size_t answered_name_len, char *reason, size_t reason_len)
{
    *fd_out = -1;
    reason[0] = '\0';
    if (answered_name != NULL && answered_name_len > 0U) {
        answered_name[0] = '\0';
    }
    int fd = connect_local(port);
    if (fd < 0 || send_login_request(fd, runtime, role) != 0) {
        if (fd >= 0) {
            close(fd);
        }
        snprintf(reason, reason_len, "connect/send failed");
        return -1;
    }
    int command = 0;
    int success = 0;
    if (read_named_login_response(fd, IO_TIMEOUT_MS, &command, &success, answered_name, answered_name_len,
                                  reason, reason_len) != 1) {
        close(fd);
        return -1;
    }
    if (!success) {
        close(fd);
        return 0;
    }
    *fd_out = fd;
    return 1;
}

int expect_channel_closed(int fd, int timeout_ms)
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

int expect_channel_alive(int fd)
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

int expect_nat_frame(int fd, int type, st_nat_message *message)
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

int nat_register(int data_fd, const char *client_name, int public_port, int target_port)
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

int open_public_stream_id(int data_fd, int public_port, int *public_fd, uint32_t *stream_id)
{
    *public_fd = connect_local(public_port);
    if (*public_fd < 0) {
        return -1;
    }
    st_nat_message open;
    if (expect_nat_frame(data_fd, ST_NAT_OPEN, &open) != 0) {
        return -1;
    }
    *stream_id = open.stream_id;
    int rc = open.stream_id != 0U ? 0 : -1;
    st_nat_message_free(&open);
    return rc;
}

int open_public_stream(int data_fd, int public_port, int *public_fd)
{
    uint32_t stream_id = 0U;
    return open_public_stream_id(data_fd, public_port, public_fd, &stream_id);
}

int expect_socket_eof(int fd, int timeout_ms)
{
    uint8_t byte;
    int rc = recv_exact(fd, &byte, 1U, monotonic_ms() + timeout_ms);
    return rc == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------------------------------- */
/* HTTP                                                                                          */

int http_request(int port, const char *method, const char *path, const char *body,
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

const char *harness_login_environment_extra = "";

void signed_login_body(const char *api_key, const char *secret, const char *fingerprint,
                       const char *os_user, char *body, size_t body_len)
{
    char nonce[33];
    random_hex(nonce, 16U);
    signed_login_body_with_nonce(api_key, secret, fingerprint, os_user, nonce, body, body_len);
}

void signed_login_body_with_nonce(const char *api_key, const char *secret, const char *fingerprint,
                                  const char *os_user, const char *nonce, char *body, size_t body_len)
{
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%lld", wall_clock_ms());
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
             "\"clientVersion\":\"session-lifecycle-test\"%s}}",
             api_key, timestamp, nonce, signature, fingerprint, os_user,
             harness_login_environment_extra == NULL ? "" : harness_login_environment_extra);
}

int http_client_login(const test_server *server, const char *api_key, const char *secret,
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

/* ------------------------------------------------------------------------------------------- */
/* Database                                                                                      */

int create_credential(const char *db_path, const char *api_key, const char *secret, int max_online)
{
    uint8_t digest[ST_SHA256_LEN];
    char secret_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)secret, strlen(secret), digest);
    st_hex_encode(digest, sizeof(digest), secret_hash);
    st_storage_client_credential credential;
    return st_storage_upsert_client_credential(db_path, 0, "default", ADMIN_USERNAME, api_key,
                                               secret_hash, 1, max_online, &credential);
}

int create_mapping(const char *db_path, long long client_id, int public_port)
{
    st_storage_mapping mapping;
    return st_storage_create_mapping_for_client(db_path, client_id, public_port, "127.0.0.1", 9, 1, 0, &mapping);
}

int db_scalar(const char *db_path, const char *sql, const char *text_arg, long long int_arg,
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

/* ------------------------------------------------------------------------------------------- */
/* Server process                                                                                */

void dump_server_log(const test_server *server)
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

int server_prepare(test_server *server)
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

int server_start(test_server *server)
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

int server_stop(test_server *server, int timeout_ms)
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

void server_cleanup(test_server *server, int failed)
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

int run_on_fresh_server(const char *name, server_scenario scenario, const char *const *extra_env)
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
