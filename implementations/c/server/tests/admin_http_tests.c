#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "client_package.h"
#include "crypto.h"
#include "json.h"
#include "login_rate_limiter.h"
#include "public_discovery.h"
#include "public_room.h"
#include "registration.h"
#include "storage.h"

#include <arpa/inet.h>
#include <limits.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <zlib.h>

#ifndef ST_APPLICATION_FIXTURE_FILE
#define ST_APPLICATION_FIXTURE_FILE "../../../protocol/test-vectors/application-protocol-v2.json"
#endif

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
} route_auth_test_context;

static void route_auth_test_context_reset(route_auth_test_context *context)
{
    pthread_mutex_lock(&context->lock);
    context->http_calls = 0;
    context->ws_calls = 0;
    context->authorization_headers = 0;
    context->normalized_accept_encoding_headers = 0;
    context->http_raw_query[0] = '\0';
    context->ws_raw_query[0] = '\0';
    pthread_mutex_unlock(&context->lock);
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
    pthread_mutex_unlock(&context->lock);
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

static void route_auth_ws_close(void *ctx, const char *channel_id)
{
    (void)ctx;
    (void)channel_id;
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
        || route_auth_detail_is_sanitized(database_path) != 0) {
        fprintf(stderr, "protected route successful auth or authorization stripping mismatch\n");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    snprintf(request,
             sizeof(request),
             "GET %s?template={0}&encoded=%%7B1%%7D HTTP/1.1\r\nHost: localhost\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")
        || !route_auth_test_context_matches(&context, 1, 0, 0)
        || !route_auth_test_queries_match(&context, "template=%7B0%7D&encoded=%7B1%7D", "")) {
        fprintf(stderr, "direct HTTP raw query brace encoding mismatch\n");
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
             "GET %s?channel={0} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\n"
             "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n",
             protected_path);
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "404 Not Found")
        || !route_auth_test_context_matches(&context, 0, 1, 0)
        || !route_auth_test_queries_match(&context, "", "channel=%7B0%7D")) {
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
    setenv("SPECUS_HTTP_ROUTES", "api=http://127.0.0.1:8080", 1);
    snprintf(request,
             sizeof(request),
             "GET /http/Env/api/items HTTP/1.1\r\nHost: localhost\r\n"
             "Authorization: Basic dmlzaXRvcjpzZWNyZXQ=\r\n\r\n");
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")
        || !route_auth_test_context_matches(&context, 1, 0, 1)) {
        fprintf(stderr, "database-unmanaged environment route compatibility mismatch\n");
        unsetenv("SPECUS_HTTP_ROUTES");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }

    unsetenv("SPECUS_DATABASE_PATH");
    route_auth_test_context_reset(&context);
    if (route_auth_http_roundtrip(port, request, response, sizeof(response)) != 0
        || !contains(response, "200 OK")
        || !route_auth_test_context_matches(&context, 1, 0, 1)) {
        fprintf(stderr, "database-free environment route compatibility mismatch\n");
        setenv("SPECUS_DATABASE_PATH", database_path, 1);
        unsetenv("SPECUS_HTTP_ROUTES");
        route_auth_stop_server(&server);
        pthread_mutex_destroy(&context.lock);
        return 1;
    }
    setenv("SPECUS_DATABASE_PATH", database_path, 1);
    unsetenv("SPECUS_HTTP_ROUTES");
    route_auth_stop_server(&server);
    pthread_mutex_destroy(&context.lock);
    return 0;
}

typedef struct {
    int fd;
    int port;
    char request[4096];
} oidc_test_server;

static void *oidc_test_server_thread(void *arg)
{
    oidc_test_server *server = (oidc_test_server *)arg;
    int client = accept(server->fd, NULL, NULL);
    if (client >= 0) {
        ssize_t got = recv(client, server->request, sizeof(server->request) - 1U, 0);
        if (got > 0) {
            server->request[got] = '\0';
        }
        const char body[] = "{\"access_token\":\"access-1\",\"id_token\":\"id-1\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        char response[512];
        int response_len = snprintf(response,
                                    sizeof(response),
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n"
                                    "\r\n"
                                    "%s",
                                    strlen(body),
                                    body);
        if (response_len > 0 && (size_t)response_len < sizeof(response)) {
            (void)send(client, response, (size_t)response_len, 0);
        }
        close(client);
    }
    return NULL;
}

static int oidc_test_server_start(oidc_test_server *server, pthread_t *thread)
{
    memset(server, 0, sizeof(*server));
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        return -1;
    }
    int reuse = 1;
    (void)setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    (void)setsockopt(server->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(server->fd, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(server->fd, 1) != 0) {
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    socklen_t address_len = sizeof(address);
    if (getsockname(server->fd, (struct sockaddr *)&address, &address_len) != 0) {
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    server->port = ntohs(address.sin_port);
    if (pthread_create(thread, NULL, oidc_test_server_thread, server) != 0) {
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    return 0;
}

static void oidc_test_server_stop(oidc_test_server *server, pthread_t thread)
{
    (void)pthread_join(thread, NULL);
    if (server->fd >= 0) {
        close(server->fd);
        server->fd = -1;
    }
}

static void test_write_u16_be(uint8_t *value, uint16_t number)
{
    value[0] = (uint8_t)(number >> 8U);
    value[1] = (uint8_t)number;
}

static char *test_read_text_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
        if (file != NULL) fclose(file);
        return NULL;
    }
    long size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return NULL;
    }
    char *text = (char *)malloc((size_t)size + 1U);
    if (text == NULL || fread(text, 1U, (size_t)size, file) != (size_t)size) {
        free(text);
        fclose(file);
        return NULL;
    }
    fclose(file);
    text[(size_t)size] = '\0';
    return text;
}

static int test_hex_nibble(char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static uint8_t *test_decode_hex(const char *hex, size_t *decoded_len)
{
    size_t len = hex == NULL ? 0U : strlen(hex);
    if (len == 0U || len % 2U != 0U) return NULL;
    uint8_t *decoded = (uint8_t *)malloc(len / 2U);
    if (decoded == NULL) return NULL;
    for (size_t i = 0; i < len; i += 2U) {
        int high = test_hex_nibble(hex[i]);
        int low = test_hex_nibble(hex[i + 1U]);
        if (high < 0 || low < 0) {
            free(decoded);
            return NULL;
        }
        decoded[i / 2U] = (uint8_t)((high << 4U) | low);
    }
    *decoded_len = len / 2U;
    return decoded;
}

static int test_sws2_central_vectors(void)
{
    char *json = test_read_text_file(ST_APPLICATION_FIXTURE_FILE);
    if (json == NULL) {
        fprintf(stderr, "application protocol fixture could not be read\n");
        return 1;
    }
    const char *fields[] = {"frameHex", "invalidMagicHex", "truncatedHex", "trailingHex"};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); ++i) {
        char *hex = st_json_get_string(json, fields[i]);
        size_t payload_len = 0U;
        uint8_t *payload = test_decode_hex(hex, &payload_len);
        int accepted = payload != NULL && st_admin_validate_sws2_payload(payload, payload_len) == 0;
        int missing = payload == NULL;
        free(hex);
        free(payload);
        if (missing || (i == 0U && !accepted) || (i != 0U && accepted)) {
            fprintf(stderr, "central SWS2 vector mismatch: %s\n", fields[i]);
            free(json);
            return 1;
        }
    }
    free(json);
    return 0;
}

static int test_sws2_validation(void)
{
    if (test_sws2_central_vectors() != 0) {
        return 1;
    }
    uint8_t close_frame[12] = {'S', 'W', 'S', '2', 0x8U, 0x1U, 0, 0, 0, 0, 0, 0};
    test_write_u16_be(close_frame + 6U, 1000U);
    if (st_admin_validate_sws2_payload(close_frame, sizeof(close_frame)) != 0) {
        fprintf(stderr, "valid SWS2 close frame was rejected\n");
        return 1;
    }
    const uint16_t forbidden[] = {1004U, 1005U, 1006U, 1015U};
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
        test_write_u16_be(close_frame + 6U, forbidden[i]);
        if (st_admin_validate_sws2_payload(close_frame, sizeof(close_frame)) == 0) {
            fprintf(stderr,
                    "forbidden SWS2 close code was accepted: %u\n",
                    (unsigned)forbidden[i]);
            return 1;
        }
    }
    test_write_u16_be(close_frame + 6U, 0U);
    if (st_admin_validate_sws2_payload(close_frame, sizeof(close_frame)) != 0) {
        fprintf(stderr, "empty SWS2 close frame was rejected\n");
        return 1;
    }
    close_frame[8] = 1U;
    if (st_admin_validate_sws2_payload(close_frame, sizeof(close_frame)) == 0) {
        fprintf(stderr, "truncated SWS2 payload was accepted\n");
        return 1;
    }
    close_frame[8] = 0U;
    close_frame[5] = 0x81U;
    if (st_admin_validate_sws2_payload(close_frame, sizeof(close_frame)) == 0) {
        fprintf(stderr, "reserved SWS2 flag bits were accepted\n");
        return 1;
    }
    close_frame[5] = 0x1U;
    close_frame[4] = 0x3U;
    if (st_admin_validate_sws2_payload(close_frame, sizeof(close_frame)) == 0) {
        fprintf(stderr, "unknown SWS2 opcode was accepted\n");
        return 1;
    }
    return 0;
}

int main(void)
{
    /* The suite deliberately exercises demo credentials and seeding; production disables both. */
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED", "false", 1);
    if (test_sws2_validation() != 0) {
        return 1;
    }
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
             "\"clientPeerServiceCapabilities\":{\"version\":2,"
             "\"applications\":[\"http\",\"tcp\",\"http\"]}}}",
             timestamp,
             signature);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tenantId\":\"tenant-db\"")
        || !contains(response, "\"accessToken\":\"cs_")
        || !contains(response, "\"maxOnlineInstances\":4")
        || !contains(response, "db-host-db-user-")) {
        fprintf(stderr, "client auth database login response mismatch\n");
        return 1;
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
    if (test_direct_http_route_authentication(db_path) != 0) {
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
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"method\":\"POST\"")
        || !contains(response, "\"statusCode\":201")
        || !contains(response, "\"responseBodyType\":\"json\"")
        || !contains(response, "\"responsePreviewText\":\"{\\\"ok\\\":true}\"")
        || !contains(response, "\"size\":20")
        || !contains(response, "\"totalPages\":1")) {
        fprintf(stderr, "http exchange page response mismatch\n");
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
    oidc_test_server oidc_server;
    pthread_t oidc_thread;
    if (oidc_test_server_start(&oidc_server, &oidc_thread) != 0) {
        fprintf(stderr, "oidc test server start failed\n");
        return 1;
    }
    char oidc_endpoint[128];
    snprintf(oidc_endpoint, sizeof(oidc_endpoint), "http://127.0.0.1:%d/token", oidc_server.port);
    setenv("SPECUS_OIDC_TOKEN_ENDPOINT", oidc_endpoint, 1);
    len = st_admin_build_response_with_body("POST",
                                            "/oidc/token",
                                            "{\"code\":\"abc\",\"codeVerifier\":\"verifier value\"}",
                                            response,
                                            sizeof(response));
    oidc_test_server_stop(&oidc_server, oidc_thread);
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"accessToken\":\"access-1\"")
        || !contains(response, "\"idToken\":\"id-1\"")
        || !contains(response, "\"tokenType\":\"Bearer\"")
        || !contains(response, "\"expiresIn\":3600")
        || !contains(oidc_server.request, "POST /token HTTP/1.1")
        || !contains(oidc_server.request, "grant_type=authorization_code")
        || !contains(oidc_server.request, "code=abc")
        || !contains(oidc_server.request, "code_verifier=verifier+value")
        || !contains(oidc_server.request, "client_id=admin-spa")) {
        fprintf(stderr, "oidc http token exchange response mismatch\n");
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
    unsetenv("SPECUS_ENV");
    unsetenv("SPECUS_CLIENT_PACKAGE_GITHUB_RELEASE_FALLBACK_ENABLED");
    return 0;
}
