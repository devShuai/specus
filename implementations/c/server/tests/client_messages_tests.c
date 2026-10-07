/*
 * The management message channel of protocol/spec/client-messages.md against Java's
 * ClientMessagesWebSocketHandler and MessageRequestHandler:
 *
 *   1. A real specus-server-c: an administrator's /ws/client-messages sessions (ticket, hello), a
 *      message to a logged-in client written as MessageResponsePacket on its control connection
 *      and acknowledged as written, a client's reply fanned out to every session of that
 *      administrator, and no delivery while the sending account is disabled.
 *   2. An in-process admin listener: a write to the target that fails after the online check is
 *      reported as failed / target-write-failed, as Java reports a failed channel write; and
 *      /ws/connections refuses binary (1003) and unmasked (1002) frames as Java's container does.
 *
 *   client_messages_tests <specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "crypto.h"
#include "json.h"
#include "protocol.h"
#include "security.h"
#include "server_harness.h"
#include "storage.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ------------------------------------------------------------------------------------------- */
/* WebSocket client                                                                              */

static int ws_send_text(int fd, const char *text)
{
    size_t len = strlen(text);
    uint8_t header[14];
    size_t header_len = 0U;
    header[header_len++] = 0x81U;
    if (len < 126U) {
        header[header_len++] = (uint8_t)(0x80U | len);
    } else if (len <= 0xffffU) {
        header[header_len++] = 0x80U | 126U;
        header[header_len++] = (uint8_t)(len >> 8);
        header[header_len++] = (uint8_t)len;
    } else {
        return -1;
    }
    static const uint8_t mask[4] = {0x12U, 0x34U, 0x56U, 0x78U};
    memcpy(header + header_len, mask, sizeof(mask));
    header_len += sizeof(mask);
    uint8_t *frame = (uint8_t *)malloc(header_len + len);
    if (frame == NULL) return -1;
    memcpy(frame, header, header_len);
    for (size_t i = 0; i < len; ++i) frame[header_len + i] = (uint8_t)text[i] ^ mask[i % 4U];
    int rc = send_all(fd, frame, header_len + len);
    free(frame);
    return rc;
}

/* 1 = a text message in out, 0 = nothing before the timeout, -1 = closed or not text. */
static int ws_read_text(int fd, char *out, size_t out_len, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    uint8_t header[2];
    int rc = recv_exact(fd, header, sizeof(header), deadline);
    if (rc == -2) return 0;
    if (rc != 1) return -1;
    uint64_t len = header[1] & 0x7fU;
    if (len == 126U) {
        uint8_t extended[2];
        if (recv_exact(fd, extended, sizeof(extended), deadline) != 1) return -1;
        len = ((uint64_t)extended[0] << 8) | extended[1];
    } else if (len == 127U) {
        return -1;
    }
    if ((header[0] & 0x0fU) != 0x1U || len + 1U > out_len) return -1;
    if (len > 0U && recv_exact(fd, (uint8_t *)out, (size_t)len, deadline) != 1) return -1;
    out[len] = '\0';
    return 1;
}

static char *ws_ticket(int port, const char *token, const char *endpoint)
{
    int status = 0;
    char *body = NULL;
    char request_body[64];
    snprintf(request_body, sizeof(request_body), "{\"endpoint\":\"%s\"}", endpoint);
    if (http_request(port, "POST", "/api/admin/ws-tickets", request_body, token, &status, &body) != 0
        || status != 200) {
        fprintf(stderr, "ws ticket: %d %s\n", status, body == NULL ? "" : body);
        free(body);
        return NULL;
    }
    char *ticket = st_json_get_string(body, "ticket");
    free(body);
    return ticket;
}

/* Opens /ws/<endpoint> and, when hello is given, reads the first message; the socket, or -1. */
static int ws_open_endpoint(int port, const char *token, const char *endpoint, char *hello, size_t hello_len)
{
    char *ticket = ws_ticket(port, token, endpoint);
    if (ticket == NULL) return -1;
    int fd = connect_local(port);
    char request[1024];
    snprintf(request, sizeof(request),
             "GET /ws/%s?ticket=%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\n"
             "Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
             endpoint, ticket);
    free(ticket);
    if (fd < 0 || send_all(fd, (const uint8_t *)request, strlen(request)) != 0) {
        if (fd >= 0) close(fd);
        return -1;
    }
    char response[1024] = {0};
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used + 1U < sizeof(response)) {
        if (recv_exact(fd, (uint8_t *)response + used, 1U, deadline) != 1) break;
        ++used;
        if (used >= 4U && memcmp(response + used - 4U, "\r\n\r\n", 4U) == 0) break;
    }
    if (strncmp(response, "HTTP/1.1 101", 12U) != 0
        || (hello != NULL && ws_read_text(fd, hello, hello_len, IO_TIMEOUT_MS) != 1)) {
        fprintf(stderr, "%s upgrade: %s\n", endpoint, response);
        close(fd);
        return -1;
    }
    return fd;
}

static int ws_open(int port, const char *token, char *hello, size_t hello_len)
{
    return ws_open_endpoint(port, token, "client-messages", hello, hello_len);
}

/* The close code of the next frame, which must be a CLOSE; -1 otherwise. */
static int ws_read_close_code(int fd)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    uint8_t header[2];
    uint8_t code[2];
    if (recv_exact(fd, header, sizeof(header), deadline) != 1 || (header[0] & 0x0fU) != 0x8U
        || (header[1] & 0x7fU) < 2U || recv_exact(fd, code, sizeof(code), deadline) != 1) {
        return -1;
    }
    return (code[0] << 8) | code[1];
}

static int contains(const char *haystack, const char *needle)
{
    return haystack != NULL && strstr(haystack, needle) != NULL;
}

/* ------------------------------------------------------------------------------------------- */
/* 1. A real server                                                                              */

/* The next CLIENT_TO_CLIENT MessageResponsePacket on the control connection. */
static int expect_client_message(int control, st_message_response *message)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (monotonic_ms() < deadline) {
        st_frame_header header;
        uint8_t *body = NULL;
        int rc = read_frame(control, (int)(deadline - monotonic_ms()), &header, &body);
        if (rc != 1) return -1;
        if (header.command == ST_CMD_MESSAGE_RESPONSE) {
            int decoded = st_protocol_decode_message_response(body, header.length, message) == 0;
            free(body);
            if (decoded && message->message_type == ST_MESSAGE_TYPE_CLIENT_TO_CLIENT) return 0;
            if (decoded) st_message_response_free(message);
            continue;
        }
        free(body);
    }
    return -1;
}

static int send_client_message(int control, const char *client_name, const char *to, const char *text)
{
    st_buffer frame = st_protocol_encode_message_response(client_name, to, ST_MESSAGE_TYPE_CLIENT_TO_CLIENT, text);
    if (frame.data == NULL) return -1;
    frame.data[6] = (uint8_t)ST_CMD_MESSAGE_REQUEST;
    return send_buffer(control, &frame);
}

static int set_client_enabled(const char *path, long long client_id, int enabled)
{
    sqlite3 *db = NULL;
    char statement[128];
    snprintf(statement, sizeof(statement), "UPDATE client_account SET enabled = %d WHERE id = %lld", enabled, client_id);
    int rc = sqlite3_open(path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, statement, NULL, NULL, NULL) == SQLITE_OK ? 0 : -1;
    sqlite3_close(db);
    return rc;
}

static int scenario_message_channel(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control = -1;
    harness_login_environment_extra = ",\"receiveMessages\":true,\"sendMessages\":true";
    CHECK(create_credential(server->db_path, "ck_messages", "messages-secret", 2) == 0, "credential");
    int logged_in = http_client_login(server, "ck_messages", "messages-secret", "machine-messages", "mia", &runtime);
    harness_login_environment_extra = "";
    CHECK(logged_in == 0, "client login");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);

    int status = 0;
    char *body = NULL;
    char login[256];
    snprintf(login, sizeof(login), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    CHECK(http_request(server->admin_port, "POST", "/auth/login", login, NULL, &status, &body) == 0 && status == 200,
          "admin login %d", status);
    char *token = st_json_get_string(body, "accessToken");
    free(body);
    CHECK(token != NULL, "access token");

    /* Two sessions of one administrator; each starts with its hello. */
    char text[8192];
    int first = ws_open(server->admin_port, token, text, sizeof(text));
    char expected_hello[256];
    snprintf(expected_hello, sizeof(expected_hello),
             "{\"type\":\"hello\",\"channel\":\"client-messages\",\"username\":\"%s\",\"tenantId\":\"default\"}",
             ADMIN_USERNAME);
    int hello_ok = first >= 0 && strcmp(text, expected_hello) == 0;
    int second = ws_open(server->admin_port, token, text, sizeof(text));
    free(token);
    CHECK(hello_ok && second >= 0, "two client-messages sessions with their hello: %s", text);

    /* Administrator to client: trimmed, written as MessageResponsePacket, then acknowledged. */
    char command[512];
    snprintf(command, sizeof(command),
             "{\"type\":\"message\",\"messageId\":\"m-1\",\"toClientName\":\" %s \",\"message\":\"  hello client  \"}",
             runtime.client_name);
    CHECK(ws_send_text(first, command) == 0, "admin message");
    st_message_response delivered;
    memset(&delivered, 0, sizeof(delivered));
    CHECK(expect_client_message(control, &delivered) == 0, "the client must receive the admin's message");
    char admin_name[128];
    snprintf(admin_name, sizeof(admin_name), "admin:%s", ADMIN_USERNAME);
    int packet_ok = delivered.client_name != NULL && strcmp(delivered.client_name, admin_name) == 0
        && delivered.to_client_name != NULL && strcmp(delivered.to_client_name, runtime.client_name) == 0
        && delivered.message != NULL && strcmp(delivered.message, "hello client") == 0;
    st_message_response_free(&delivered);
    CHECK(packet_ok, "MessageResponsePacket from admin:<user> to the canonical client with the trimmed body");
    CHECK(ws_read_text(first, text, sizeof(text), IO_TIMEOUT_MS) == 1 && contains(text, "\"type\":\"written\"")
              && contains(text, "\"messageId\":\"m-1\"") && contains(text, "\"message\":\"hello client\""),
          "written: %s", text);

    /* Errors keep the session open and carry the messageId. */
    CHECK(ws_send_text(first, "{\"type\":\"message\",\"messageId\":\"m-2\",\"toClientName\":\"nobody-here\","
                              "\"message\":\"x\"}") == 0
              && ws_read_text(first, text, sizeof(text), IO_TIMEOUT_MS) == 1
              && contains(text, "\"error\":\"target-not-found\"") && contains(text, "\"messageId\":\"m-2\""),
          "target-not-found: %s", text);
    /* Java's default ObjectMapper: an unknown member or a non-scalar value is invalid-json, without
     * a messageId; a number where a string belongs is read as text. */
    static const char *const unmappable[] = {
        "{\"type\":\"message\",\"messageId\":\"m-3\",\"toClientName\":\"x\",\"message\":\"y\",\"extra\":1}",
        "{\"type\":\"message\",\"messageId\":\"m-4\",\"toClientName\":{\"name\":\"x\"},\"message\":\"y\"}",
        "[\"message\"]",
    };
    for (size_t i = 0; i < sizeof(unmappable) / sizeof(unmappable[0]); ++i) {
        CHECK(ws_send_text(first, unmappable[i]) == 0 && ws_read_text(first, text, sizeof(text), IO_TIMEOUT_MS) == 1
                  && strcmp(text, "{\"type\":\"error\",\"error\":\"invalid-json\"}") == 0,
              "unmappable command %zu: %s", i, text);
    }
    CHECK(ws_send_text(first, "{\"type\":\"message\",\"messageId\":5,\"toClientName\":\"\",\"message\":\"y\"}") == 0
              && ws_read_text(first, text, sizeof(text), IO_TIMEOUT_MS) == 1
              && contains(text, "\"error\":\"target-and-message-required\""),
          "a numeric messageId is not invalid-json: %s", text);

    /* Client to administrator: every open session of that administrator gets it. */
    char to_admin[128];
    snprintf(to_admin, sizeof(to_admin), " Admin: %s ", ADMIN_USERNAME);
    CHECK(send_client_message(control, runtime.client_name, to_admin, "reply one") == 0, "client reply");
    char expected_in[512];
    snprintf(expected_in, sizeof(expected_in),
             "{\"type\":\"message\",\"direction\":\"in\",\"fromClientName\":\"%s\",\"toClientName\":\"%s\","
             "\"message\":\"reply one\",\"createdAt\":\"",
             runtime.client_name, admin_name);
    CHECK(ws_read_text(first, text, sizeof(text), IO_TIMEOUT_MS) == 1 && strncmp(text, expected_in, strlen(expected_in)) == 0,
          "first session: %s", text);
    CHECK(ws_read_text(second, text, sizeof(text), IO_TIMEOUT_MS) == 1 && strncmp(text, expected_in, strlen(expected_in)) == 0,
          "second session: %s", text);

    /* A disabled account sends nothing to an administrator (Java checks the source account on
     * every message); the session is left open here, as an account changed outside the API. */
    CHECK(set_client_enabled(server->db_path, runtime.client_id, 0) == 0, "disable");
    CHECK(send_client_message(control, runtime.client_name, to_admin, "while disabled") == 0, "disabled reply");
    CHECK(expect_channel_alive(control) == 0, "the control connection must stay usable");
    CHECK(ws_read_text(first, text, sizeof(text), 500) == 0, "a disabled account's message reached the admin: %s", text);
    CHECK(set_client_enabled(server->db_path, runtime.client_id, 1) == 0, "enable");
    CHECK(send_client_message(control, runtime.client_name, to_admin, "enabled again") == 0, "enabled reply");
    CHECK(ws_read_text(first, text, sizeof(text), IO_TIMEOUT_MS) == 1 && contains(text, "\"message\":\"enabled again\""),
          "after re-enabling: %s", text);

    close(first);
    close(second);
    close_fd(&control);
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* 2. A write that fails after the checks                                                        */

static long long write_target_id = 0;

static int target_online(void *ctx, long long client_id, const char *client_name, st_admin_client_runtime_status *status)
{
    (void)ctx;
    (void)client_name;
    memset(status, 0, sizeof(*status));
    status->online = client_id == write_target_id;
    return 0;
}

/* The control connection is gone by the time of the write. */
static int target_vanished(void *ctx, long long client_id, const char *client_name, const char *from, const char *message)
{
    (void)ctx;
    (void)client_id;
    (void)client_name;
    (void)from;
    (void)message;
    return -1;
}

static int test_write_failure(void)
{
    char dir[] = "/tmp/specus-c-client-messages-XXXXXX";
    CHECK(mkdtemp(dir) != NULL, "temporary directory");
    char path[256];
    snprintf(path, sizeof(path), "%s/messages.db", dir);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1);
    setenv("SPECUS_DATABASE_PATH", path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", "client-messages-jwt-secret-long-enough-2026", 1);
    st_storage_management_user user;
    sqlite3 *db = NULL;
    int ready = st_storage_init(path, 0) == 0
        && st_storage_create_management_user(path, "msg-admin", "default", "unused-password-hash", "ADMIN", 1, &user) == 0
        && sqlite3_open(path, &db) == SQLITE_OK
        && sqlite3_exec(db,
                        "INSERT INTO client_account(tenant_id, client_name, owner_username) "
                        "VALUES ('default', 'msg-target', 'msg-admin');"
                        "INSERT INTO specus_client_session(tenant_id, credential_id, identity_id, client_id, client_name, "
                        "token_hash, status, machine_fingerprint, os_user, message_receive_capable, expires_at) "
                        "SELECT 'default', 1, 1, id, client_name, 'hash', 'NETTY_ONLINE', 'machine', 'user', 1, "
                        "'2999-01-01T00:00:00Z' FROM client_account WHERE client_name = 'msg-target';",
                        NULL, NULL, NULL) == SQLITE_OK;
    if (db != NULL) {
        sqlite3_stmt *stmt = NULL;
        if (sqlite3_prepare_v2(db, "SELECT id FROM client_account WHERE client_name = 'msg-target'", -1, &stmt, NULL) == SQLITE_OK
            && sqlite3_step(stmt) == SQLITE_ROW) {
            write_target_id = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    CHECK(ready && write_target_id > 0, "fixture");
    char token[1024];
    CHECK(st_security_issue_local_token("msg-admin", "default", "ADMIN", "client-messages-jwt-secret-long-enough-2026",
                                        600, token, sizeof(token)) == 0,
          "token");

    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    CHECK(st_admin_server_start(&server, 0, "") == 0
              && getsockname(server.fd, (struct sockaddr *)&address, &address_len) == 0,
          "listener");
    st_admin_set_client_runtime_status_handler(target_online, NULL);
    st_admin_set_client_message_handler(target_vanished, NULL);
    char text[4096];
    int fd = ws_open(ntohs(address.sin_port), token, text, sizeof(text));
    int ok = fd >= 0
        && ws_send_text(fd, "{\"type\":\"message\",\"messageId\":\"m-gone\",\"toClientName\":\"msg-target\","
                            "\"message\":\"hello\"}") == 0
        && ws_read_text(fd, text, sizeof(text), IO_TIMEOUT_MS) == 1
        && strcmp(text, "{\"type\":\"failed\",\"messageId\":\"m-gone\",\"error\":\"target-write-failed\"}") == 0;
    if (!ok) fprintf(stderr, "write failure answer: %s\n", text);
    if (fd >= 0) close(fd);
    st_admin_set_client_runtime_status_handler(NULL, NULL);
    st_admin_set_client_message_handler(NULL, NULL);
    CHECK(ok, "a failed write after the checks must answer failed / target-write-failed");

    /* /ws/connections as Java's TextWebSocketHandler: binary closes 1003, an unmasked frame 1002. */
    int port = ntohs(address.sin_port);
    fd = ws_open_endpoint(port, token, "connections", NULL, 0U);
    static const uint8_t binary[] = {0x82U, 0x82U, 1U, 2U, 3U, 4U, 'h' ^ 1U, 'i' ^ 2U};
    int binary_code = fd >= 0 && send_all(fd, binary, sizeof(binary)) == 0 ? ws_read_close_code(fd) : -1;
    if (fd >= 0) close(fd);
    fd = ws_open_endpoint(port, token, "connections", NULL, 0U);
    static const uint8_t unmasked[] = {0x81U, 0x02U, 'h', 'i'};
    int unmasked_code = fd >= 0 && send_all(fd, unmasked, sizeof(unmasked)) == 0 ? ws_read_close_code(fd) : -1;
    if (fd >= 0) close(fd);
    unlink(path);
    rmdir(dir);
    CHECK(binary_code == 1003, "a binary frame on /ws/connections must close 1003, got %d", binary_code);
    CHECK(unmasked_code == 1002, "an unmasked frame on /ws/connections must close 1002, got %d", unmasked_code);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    int failed = run_on_fresh_server("client message channel on a real server", scenario_message_channel, NULL);
    if (!failed) {
        failed = test_write_failure();
        printf("%s a failed write after the checks\n", failed ? "FAIL" : "ok  ");
    }
    if (failed) return 1;
    printf("client messages tests passed\n");
    return 0;
}
