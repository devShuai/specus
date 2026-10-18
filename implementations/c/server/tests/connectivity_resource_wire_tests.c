#define _POSIX_C_SOURCE 200809L

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server_harness.h"
#include "connectivity_http_test_support.h"

/* Supplement the builder-level corpus with the real executable's presence/session adapter.
 * No device connects; neither the server nor this executable links the fixed test time symbol. */
static const char *caller_name;

static int roundtrip(int port, const char *authorization, char *out, size_t capacity)
{
    char request[4096];
    int length = snprintf(request, sizeof(request),
        "POST /api/admin/http-routes/7/connectivity-check HTTP/1.1\r\nHost: localhost\r\n"
        "Authorization: %s\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        authorization);
    int fd = connect_local(port);
    if (fd < 0) return 1;
    int failed = length < 0 || (size_t)length >= sizeof(request)
        || send_all(fd, (const uint8_t *)request, (size_t)length) != 0;
    size_t used = 0;
    long long until = monotonic_ms() + IO_TIMEOUT_MS;
    while (!failed && used + 1U < capacity) {
        long long left = until - monotonic_ms();
        struct pollfd ready = {fd, POLLIN, 0};
        if (left <= 0 || poll(&ready, 1, (int)left) <= 0) { failed = 1; break; }
        ssize_t received = recv(fd, out + used, capacity - used - 1U, 0);
        if (received == 0) break;
        if (received < 0) { failed = 1; break; }
        used += (size_t)received;
    }
    out[used] = '\0';
    if (used + 1U >= capacity) failed = 1;
    close(fd);
    return failed;
}

static int offline_real_session_table(test_server *server)
{
    char authorization[2300], response[8192] = {0};
    setenv("SPECUS_AUTH_JWT_SECRET", ADMIN_JWT_SECRET, 1);
    CHECK(create_bearer(server->db_path, caller_name, strcmp(caller_name, "alice") == 0 ? "USER" : "ADMIN",
                        authorization, sizeof(authorization)) == 0, "wire caller setup");
    CHECK(create_route(server->db_path, 7, "alice", 1, 1, 1) == 0, "wire offline route setup");
    CHECK(roundtrip(server->admin_port, authorization, response, sizeof(response)) == 0, "wire response I/O");
    CHECK(strncmp(response, "HTTP/1.1 200 ", 13) == 0, "wire offline status: %s", response);
    const char *body = strstr(response, "\r\n\r\n");
    CHECK(body != NULL, "wire response framing");
    body += 4;
    char *checked = st_json_get_top_level_string(body, "checkedAt");
    int valid_time = checked != NULL && strlen(checked) == 20U;
    for (size_t i = 0; valid_time && i < 20U; ++i) {
        char separator = i == 4U || i == 7U ? '-' : i == 10U ? 'T' : i == 13U || i == 16U ? ':' : i == 19U ? 'Z' : '\0';
        if (separator ? checked[i] != separator : checked[i] < '0' || checked[i] > '9') valid_time = 0;
    }
    char expected[2048];
    snprintf(expected, sizeof(expected), "{\"schemaVersion\":1,\"kind\":\"http-route\",\"routeId\":7,"
        "\"checkedAt\":\"%s\",\"outcome\":\"failed\",\"stoppedAt\":\"device-online\","
        "\"code\":\"DEVICE_OFFLINE\",\"totalMs\":0,\"requests\":[],\"stages\":["
        "{\"stage\":\"configured\",\"result\":\"passed\",\"code\":\"CONFIGURED\",\"atMs\":0},"
        "{\"stage\":\"device-online\",\"result\":\"failed\",\"code\":\"DEVICE_OFFLINE\",\"atMs\":0},"
        "{\"stage\":\"target-reachable\",\"result\":\"skipped\"},"
        "{\"stage\":\"access-succeeded\",\"result\":\"skipped\"}]}", checked ? checked : "");
    int failed = !valid_time || strcmp(body, expected) != 0
        || assert_header(response, "Cache-Control", "private, no-store")
        || assert_header(response, "Retry-After", NULL) || strstr(body, "/base") != NULL
        || strstr(body, "127.0.0.1") != NULL;
    free(checked);
    CHECK(!failed, "real-session offline body/headers differ: %s", response);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    server_binary = argv[1];
    caller_name = "alice";
    if (run_on_fresh_server("connectivity wire owner: real session table offline/full body", offline_real_session_table, NULL)) return 1;
    caller_name = "root";
    if (run_on_fresh_server("connectivity wire tenant admin: real session table offline/full body", offline_real_session_table, NULL)) return 1;
    puts("connectivity resource wire:2 real-process/socket offline scenarios passed");
    return 0;
}
