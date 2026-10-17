#define _GNU_SOURCE
#include "server_harness.h"
#include "admin_http.h"
#include "storage.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *barrier_library;
static const char head[] = "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,\"headers\":[\"Content-Type: text/plain\"]}";

static int file_marker(const test_server *server, const char *name, const char *value)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    FILE *file = fopen(path, "w"); if (!file) return -1;
    int result = fputs(value, file) < 0 ? -1 : 0;
    if (fclose(file)) result = -1;
    return result;
}

static int wait_marker(const test_server *server, const char *name)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(path, F_OK)) { if (monotonic_ms() >= deadline) return -1; sleep_ms(1); }
    return 0;
}

static int packet(int fd, int type, uint32_t id, const char *meta, const void *body, size_t size)
{
    st_buffer frame = st_protocol_encode_nat_message(type, 0, id, 0, meta, body, size);
    return send_buffer(fd, &frame);
}

static int open_browser(const test_server *server, const runtime_session *runtime, int websocket)
{
    char request[1500];
    int length = snprintf(request, sizeof(request),
        "GET /http/%s/retire/probe HTTP/1.1\r\nHost: localhost\r\n%s\r\n", runtime->client_name,
        websocket ? "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" : "Connection: close\r\n");
    int fd = connect_local(server->admin_port);
    if (fd >= 0 && (length <= 0 || (size_t)length >= sizeof(request)
        || send_all(fd, (const uint8_t *)request, (size_t)length))) close_fd(&fd);
    return fd;
}

static int browser_headers(int fd, int status)
{
    char response[4096]; size_t used = 0;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used + 1 < sizeof(response)) {
        if (recv_exact(fd, (uint8_t *)response + used, 1, deadline) != 1) return -1;
        response[++used] = 0;
        if (used >= 4 && !memcmp(response + used - 4, "\r\n\r\n", 4)) break;
    }
    int received = 0;
    return sscanf(response, "HTTP/1.1 %d", &received) == 1 && received == status ? 0 : -1;
}

static int ws_text(int data, uint32_t id, const char *value)
{
    uint8_t *payload = NULL; size_t size = 0;
    st_admin_sws2_frame frame = {.opcode = 0x1U, .fin = 1, .rsv = 0, .close_code = 0,
                                .payload = (const uint8_t *)value, .payload_len = strlen(value)};
    payload = st_admin_sws2_encode(&frame, &size);
    if (payload == NULL) return -1;
    int result = packet(data, ST_NAT_DATA, id, NULL, payload, size);
    free(payload); return result;
}

static int ws_receive(int fd, uint8_t opcode, const char *value)
{
    uint8_t prefix[2], body[256]; size_t length = strlen(value);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    if (length >= 126 || recv_exact(fd, prefix, 2, deadline) != 1 || prefix[0] != (0x80U | opcode)
        || prefix[1] != length || recv_exact(fd, body, length, deadline) != 1) return -1;
    return memcmp(body, value, length) ? -1 : 0;
}

static int response_end(int fd, const char *contains)
{
    char buffer[8192]; size_t used = 0;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        int rc = recv_exact(fd, (uint8_t *)buffer + used, 1, deadline);
        if (rc == 0) break;
        if (rc != 1 || ++used + 1 >= sizeof(buffer)) return -1;
    }
    buffer[used] = 0;
    return strstr(buffer, contains) && strstr(buffer, "0\r\n\r\n") ? 0 : -1;
}

/* Actual signed auth, SQLite routes, CONTROL/DATA and browser sockets. mode 0 blocks an unfinished
 * HTTP sink, mode 1 a complete pre-detach response, mode 2 a WS sender holding send_lock,
 * mode 3 an uncontended WS that should still get graceful 1001. No fake production callback. */
static int scenario(int mode)
{
    test_server server; if (server_prepare(&server)) return 1;
    int failed = 1, started = 0, control = -1, old_data = -1, successor = -1, browser = -1, fresh = -1;
    uint32_t id = 0, fresh_id = 0;
    runtime_session runtime = {0}; st_storage_http_route route;
    char preload[2048], gate_env[600], arm[80], reason[512] = "";
    void *asan = dlsym(RTLD_DEFAULT, "__asan_init"); Dl_info sanitizer = {0};
    if (asan && dladdr(asan, &sanitizer) && sanitizer.dli_fname)
        snprintf(preload, sizeof(preload), "LD_PRELOAD=%s:%s", sanitizer.dli_fname, barrier_library);
    else snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", barrier_library);
    snprintf(gate_env, sizeof(gate_env), "SPECUS_TEST_NAT_LIFECYCLE_DIR=%s", server.dir);
    server.extra_env[0] = preload; server.extra_env[1] = gate_env;
#define REQUIRE(test, label) do { if (!(test)) { fprintf(stderr, "FAIL stream retirement mode=%d %s (%s)\n", mode, label, reason); goto done; } } while (0)
    REQUIRE(server_start(&server) == 0, "server start"); started = 1;
    REQUIRE(create_credential(server.db_path, "stream-key", "stream-secret", 3) == 0, "credential");
    REQUIRE(http_client_login(&server, "stream-key", "stream-secret", "stream-machine", "stream-user", &runtime) == 0, "signed HTTP login");
    REQUIRE(st_storage_create_http_route_for_client(server.db_path, runtime.client_id, "retire", "http://127.0.0.1:9",
        1, 0, 0, 0, 0, 0, NULL, NULL, &route) == 0, "route");
    REQUIRE(channel_login(server.control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1, "CONTROL");
    REQUIRE(channel_login(server.control_port, &runtime, "data", &old_data, reason, sizeof(reason)) == 1, "old DATA");
    browser = open_browser(&server, &runtime, mode >= 2); REQUIRE(browser >= 0, "browser");
    st_nat_message open;
    REQUIRE(expect_nat_frame(old_data, ST_NAT_OPEN, &open) == 0, "actual request OPEN");
    id = open.stream_id; st_nat_message_free(&open);
    if (mode >= 2) REQUIRE(browser_headers(browser, 101) == 0, "actual WS upgrade");
    if (mode != 3) {
        snprintf(arm, sizeof(arm), "send %d", server.admin_port);
        REQUIRE(file_marker(&server, "arm", arm) == 0, "arm after actual send");
        if (mode < 2) {
            REQUIRE(packet(old_data, ST_NAT_OPEN, id, head, NULL, 0) == 0, "response head");
            REQUIRE(packet(old_data, ST_NAT_DATA, id, NULL, "nat-retire-hold", 15) == 0, "HTTP sink send");
        } else REQUIRE(ws_text(old_data, id, "nat-retire-hold") == 0, "WS sender");
        REQUIRE(wait_marker(&server, "ready") == 0, "real browser send paused");
        if (mode == 0) {
            const char admitted[] = "f\r\nnat-retire-hold";
            char received[sizeof(admitted) - 1];
            REQUIRE(browser_headers(browser, 200) == 0
                && recv_exact(browser, (uint8_t *)received, sizeof(received), monotonic_ms() + IO_TIMEOUT_MS) == 1
                && !memcmp(received, admitted, sizeof(received)), "already-admitted HTTP head/chunk prefix before retirement");
        }
        if (mode < 2) {
            REQUIRE(packet(old_data, ST_NAT_DATA, id, NULL, "queued-before-cut", 17) == 0, "queued HTTP response body");
            if (mode == 1) REQUIRE(packet(old_data, ST_NAT_FIN, id, NULL, NULL, 0) == 0, "complete response before detach");
            REQUIRE(expect_channel_alive(old_data) == 0, "reader consumed all queued DATA/FIN");
        } else REQUIRE(ws_receive(browser, 1, "nat-retire-hold") == 0, "already-admitted WS frame");
    }
    REQUIRE(channel_login(server.control_port, &runtime, "data", &successor, reason, sizeof(reason)) == 1,
        "successor must publish before old callback resumes");
    if (mode == 0 || mode == 2) REQUIRE(expect_socket_eof(browser, IO_TIMEOUT_MS) == 0, "old browser aborted while callback still held");
    if (mode == 3) {
        const uint8_t close[] = {0x88, 2, 3, 0xe9}; uint8_t received[4];
        REQUIRE(recv_exact(browser, received, sizeof(received), monotonic_ms() + IO_TIMEOUT_MS) == 1
            && !memcmp(close, received, sizeof(close)) && expect_socket_eof(browser, IO_TIMEOUT_MS) == 0, "uncontended retirement preserves CLOSE 1001");
    }
    REQUIRE(expect_channel_alive(control) == 0, "CONTROL heartbeat independent of blocked browser writer");
    fresh = open_browser(&server, &runtime, mode >= 2); REQUIRE(fresh >= 0, "successor browser");
    REQUIRE(expect_nat_frame(successor, ST_NAT_OPEN, &open) == 0, "successor OPEN");
    fresh_id = open.stream_id; st_nat_message_free(&open);
    if (mode >= 2) REQUIRE(browser_headers(fresh, 101) == 0, "successor WS upgrades before old release");
    REQUIRE(file_marker(&server, "resume", "continue") == 0, "resume old callback");
    if (mode == 1) REQUIRE(browser_headers(browser, 200) == 0 && response_end(browser, "queued-before-cut") == 0,
        "fully received pre-detach response must finish, not be truncated");
    if (mode != 3) REQUIRE(wait_marker(&server, "closed") == 0, "old browser owner actually closes, not merely shutdown");
    if (mode >= 2) REQUIRE(ws_text(successor, fresh_id, "successor survives") == 0 && ws_receive(fresh, 1, "successor survives") == 0,
        "old callback cannot close successor WS");
    else {
        REQUIRE(packet(successor, ST_NAT_OPEN, fresh_id, head, NULL, 0) == 0
            && packet(successor, ST_NAT_DATA, fresh_id, NULL, "successor survives", 18) == 0
            && packet(successor, ST_NAT_FIN, fresh_id, NULL, NULL, 0) == 0, "successor HTTP response");
        REQUIRE(browser_headers(fresh, 200) == 0 && response_end(fresh, "successor survives") == 0, "old callback cannot close successor HTTP");
    }
    REQUIRE(expect_channel_alive(successor) == 0, "successor remains current");
    failed = 0;
done:
    file_marker(&server, "resume", "cleanup");
    close_fd(&browser); close_fd(&fresh); close_fd(&old_data); close_fd(&successor); close_fd(&control);
    if (started && server_stop(&server, 10000)) failed = 1;
    if (failed) dump_server_log(&server);
    const char *files[] = {"arm", "ready", "resume", "closed", "finished", "late-listen", "late-worker"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) { char path[512]; snprintf(path, sizeof(path), "%s/%s", server.dir, files[i]); unlink(path); }
    server_cleanup(&server, failed);
    printf("%s HTTP/WS retirement mode=%d\n", failed ? "FAIL" : "PASS", mode);
    return failed;
#undef REQUIRE
}

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s server-binary test-barrier-library\n", argv[0]); return 2; }
    signal(SIGPIPE, SIG_IGN); server_binary = argv[1]; barrier_library = argv[2];
    int failures = 0; for (int mode = 0; mode < 4; ++mode) failures += scenario(mode);
    return failures ? 1 : 0;
}
