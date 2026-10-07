/*
 * Java HttpWebSocketRoutingTests against a real specus-server-c process. The public entry
 * /http/{client}/{route}/... splits by the request, not by the path:
 *
 *   - an Upgrade: websocket request goes to the WebSocket tunnel handler, which completes the
 *     handshake (101) and, the client being offline, closes with 1011 "客户端不在线";
 *   - a plain GET of the same route reaches the HTTP tunnel and gets 502 "客户端不在线";
 *   - raw braces in the query reach the tunnel too (502), and so does a raw '|': Tomcat answers
 *     the latter with 400 before Spring sees it, C has no such container rule;
 *   - the route runtime polyfill is a public JavaScript asset.
 *
 * Usage: specus_c_http_websocket_routing_tests <path-to-specus-server-c>
 */
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "storage.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef ST_ADMIN_WEB_PUBLIC_DIR
#define ST_ADMIN_WEB_PUBLIC_DIR "../../../apps/admin-web/public"
#endif

#define OFFLINE_CLIENT "offline-client"
#define ROUTE "route"

typedef struct {
    int status;
    char text[65536];
    size_t len;
} raw_answer;

/* Sends one raw request and reads the whole answer until the server ends the connection. */
static int raw_request(const test_server *server, const char *request, raw_answer *answer)
{
    memset(answer, 0, sizeof(*answer));
    int fd = connect_local(server->admin_port);
    if (fd < 0 || send_all(fd, (const uint8_t *)request, strlen(request)) != 0) {
        close_fd(&fd);
        return -1;
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) {
            break;
        }
        ssize_t received = recv(fd, answer->text + answer->len, sizeof(answer->text) - 1U - answer->len, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            break;
        }
        answer->len += (size_t)received;
        if (answer->len == sizeof(answer->text) - 1U) {
            break;
        }
    }
    close_fd(&fd);
    answer->text[answer->len] = '\0';
    if (sscanf(answer->text, "HTTP/1.1 %d", &answer->status) != 1) {
        answer->status = 0;
    }
    return 0;
}

static const char *answer_body(const raw_answer *answer, size_t *body_len)
{
    const char *end = strstr(answer->text, "\r\n\r\n");
    if (end == NULL) {
        *body_len = 0U;
        return answer->text + answer->len;
    }
    *body_len = answer->len - (size_t)(end + 4 - answer->text);
    return end + 4;
}

static int seed_offline_route(const test_server *server)
{
    st_storage_client client;
    st_storage_http_route route;
    return st_storage_upsert_client(server->db_path, 0, "default", OFFLINE_CLIENT, ADMIN_USERNAME, 1, 60,
                                    &client) == 0
        && st_storage_create_http_route_for_client(server->db_path, client.id, ROUTE, "http://127.0.0.1:8080",
                                                   1, 0, 0, 0, 0, 0, "", "", &route) == 0
        ? 0 : -1;
}

/* websocketUpgradeUsesTunnelHandlerInsteadOfHttpController */
static int check_websocket_upgrade(test_server *server)
{
    char request[512];
    snprintf(request, sizeof(request),
             "GET /http/" OFFLINE_CLIENT "/" ROUTE "/socket HTTP/1.1\r\nHost: localhost:%d\r\n"
             "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
             "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nOrigin: http://localhost:%d\r\n\r\n",
             server->admin_port, server->admin_port);
    raw_answer answer;
    CHECK(raw_request(server, request, &answer) == 0, "upgrade request");
    CHECK(answer.status == 101 && strstr(answer.text, "\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n")
              != NULL,
          "the upgrade must be answered by the tunnel handler with 101:\n%s", answer.text);
    size_t frame_len = 0U;
    const uint8_t *frame = (const uint8_t *)answer_body(&answer, &frame_len);
    static const char reason[] = "客户端不在线";
    size_t reason_len = sizeof(reason) - 1U;
    /* One unmasked CLOSE frame: 1011 and the reason, then the end of the connection. */
    CHECK(frame_len == 4U + reason_len && frame[0] == 0x88U && frame[1] == (uint8_t)(2U + reason_len)
              && frame[2] == 0x03U && frame[3] == 0xf3U && memcmp(frame + 4, reason, reason_len) == 0,
          "an offline client must close the upgraded socket with 1011 %s (%zu bytes after the head)", reason,
          frame_len);
    return 0;
}

/* plainHttpGetIsNotCapturedByWebSocketHandshake */
static int check_plain_get(test_server *server)
{
    raw_answer answer;
    CHECK(raw_request(server, "GET /http/" OFFLINE_CLIENT "/" ROUTE "/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Connection: close\r\n\r\n", &answer) == 0, "plain GET");
    CHECK(answer.status == 502 && strstr(answer.text, "客户端不在线") != NULL,
          "a plain GET must reach the HTTP tunnel, not the handshake:\n%s", answer.text);
    return 0;
}

/* rawQueryBracesReachTunnelControllerInsteadOfTomcat400, unrelatedRawQueryCharactersRemainRejectedByTomcat */
static int check_raw_queries(test_server *server)
{
    raw_answer answer;
    CHECK(raw_request(server, "GET /http/" OFFLINE_CLIENT "/" ROUTE "/webapi/entry.cgi?path=icon_{0}.png HTTP/1.1\r\n"
                              "Host: 127.0.0.1\r\nConnection: close\r\n\r\n", &answer) == 0, "braces");
    CHECK(answer.status == 502, "raw braces in the query must reach the tunnel:\n%s", answer.text);
    /* Tomcat's request-line check answers 400 here; C forwards the query as it came. */
    CHECK(raw_request(server, "GET /http/" OFFLINE_CLIENT "/" ROUTE "/items?invalid=| HTTP/1.1\r\n"
                              "Host: 127.0.0.1\r\nConnection: close\r\n\r\n", &answer) == 0, "pipe");
    CHECK(answer.status == 502, "a raw '|' in the query reaches the tunnel in C:\n%s", answer.text);
    return 0;
}

/* runtimePolyfillAssetIsPublicJavaScript */
static int check_runtime_asset(test_server *server)
{
    raw_answer answer;
    CHECK(raw_request(server, "GET /specus-http-route-runtime.js?v=2 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Connection: close\r\n\r\n", &answer) == 0, "runtime asset");
    size_t body_len = 0U;
    const char *body = answer_body(&answer, &body_len);
    CHECK(answer.status == 200 && strstr(answer.text, "\r\nContent-Type: application/javascript") != NULL,
          "the route runtime must be public JavaScript: %.300s", answer.text);
    CHECK(body_len > 0U && strstr(body, "data-specus-prefix") != NULL && strstr(body, "normalizePath") != NULL,
          "the route runtime body is not the polyfill (%zu bytes)", body_len);
    return 0;
}

static int scenario_routing(test_server *server)
{
    CHECK(seed_offline_route(server) == 0, "offline client route");
    return check_websocket_upgrade(server)
        || check_plain_get(server)
        || check_raw_queries(server)
        || check_runtime_asset(server);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    /* The admin web's public directory holds the polyfill the server hands out. */
    char public_dir[PATH_MAX];
    if (realpath(ST_ADMIN_WEB_PUBLIC_DIR, public_dir) == NULL) {
        fprintf(stderr, "cannot resolve %s\n", ST_ADMIN_WEB_PUBLIC_DIR);
        return 1;
    }
    static char static_root_env[PATH_MAX + 32];
    snprintf(static_root_env, sizeof(static_root_env), "SPECUS_STATIC_ROOT=%s", public_dir);
    const char *const environment[] = {static_root_env, NULL};
    if (strlen(static_root_env) >= 256U) {
        fprintf(stderr, "static root path too long for the harness: %s\n", public_dir);
        return 1;
    }

    int failures = run_on_fresh_server("HTTP entry WebSocket routing", scenario_routing, environment);
    if (failures != 0) {
        fprintf(stderr, "%d HTTP entry routing scenario(s) failed\n", failures);
        return 1;
    }
    printf("http websocket routing tests passed\n");
    return 0;
}
