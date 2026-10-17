#define _GNU_SOURCE
#include "server_harness.h"
#include "json.h"
#include <dlfcn.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *barrier_library;

static int marker_file(const test_server *server, const char *name, const char *contents)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    FILE *file = fopen(path, "w");
    if (!file) return -1;
    int result = fputs(contents, file) < 0 ? -1 : 0;
    if (fclose(file)) result = -1;
    return result;
}

static int wait_marker(const test_server *server, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(path, F_OK)) {
        if (monotonic_ms() >= deadline) return -1;
        sleep_ms(1);
    }
    return 0;
}

static int server_fd_count(const test_server *server)
{
    char path[80]; snprintf(path, sizeof(path), "/proc/%ld/fd", (long)server->pid);
    DIR *directory = opendir(path);
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) ++count;
    }
    closedir(directory);
    return count;
}

static int send_register_only(int fd, const char *client, int port)
{
    char meta[512];
    snprintf(meta, sizeof(meta), "{\"port\":%d,\"specusAddress\":\"127.0.0.1\",\"specusPort\":9,\"clientName\":\"%s\"}", port, client);
    st_buffer frame = st_protocol_encode_nat_message(ST_NAT_REGISTER, 0, 0, 0, meta, NULL, 0);
    return send_buffer(fd, &frame);
}

static int reset_stream(int fd, uint32_t id)
{
    st_buffer reset = st_protocol_encode_nat_message(ST_NAT_RST, 0, id, 0, "{\"reason\":\"test done\"}", NULL, 0);
    return send_buffer(fd, &reset);
}

/* A real stream remains usable after the old binder/acceptor/reader and its finally finish. */
static int exchange(int data, int public_fd, uint32_t id)
{
    const uint8_t payload[] = "successor still owns its stream";
    uint8_t received[sizeof(payload)];
    st_buffer frame = st_protocol_encode_nat_message(ST_NAT_DATA, 0, id, 0, NULL, payload, sizeof(payload));
    if (send_buffer(data, &frame) || recv_exact(public_fd, received, sizeof(received), monotonic_ms() + IO_TIMEOUT_MS) != 1
        || memcmp(payload, received, sizeof(payload))) return -1;
    if (send_all(public_fd, payload, sizeof(payload))) return -1;
    size_t offset = 0;
    while (offset < sizeof(payload)) {
        st_nat_message message;
        if (expect_nat_frame(data, ST_NAT_DATA, &message)) return -1;
        int valid = message.stream_id == id && message.data_len > 0
            && message.data_len <= sizeof(payload) - offset
            && !memcmp(message.data, payload + offset, message.data_len);
        if (valid) offset += message.data_len;
        st_nat_message_free(&message);
        if (!valid) return -1;
    }
    return 0;
}

static int scenario(const char *mode)
{
    test_server server;
    if (server_prepare(&server)) return 1;
    int failed = 1, started = 0, control = -1, old_data = -1, new_data = -1;
    int old_public = -1, new_public = -1, refused = -1, recovered = -1;
    int port = 0;
    int bind_case = !strncmp(mode, "bind", 4), accept_case = !strncmp(mode, "accept", 6);
    int idle = strstr(mode, "idle") != NULL;
    const char *operation = bind_case ? "bind" : accept_case ? "accept" : "recv";
    uint32_t old_id = 0, new_id = 0, recovered_id = 0;
    runtime_session runtime = {0};
    char reason[512] = "", arm[64], preload[2048], gate_env[600];
    void *asan = dlsym(RTLD_DEFAULT, "__asan_init");
    Dl_info sanitizer = {0};
    if (asan && dladdr(asan, &sanitizer) && sanitizer.dli_fname)
        snprintf(preload, sizeof(preload), "LD_PRELOAD=%s:%s", sanitizer.dli_fname, barrier_library);
    else snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", barrier_library);
    snprintf(gate_env, sizeof(gate_env), "SPECUS_TEST_NAT_LIFECYCLE_DIR=%s", server.dir);
    server.extra_env[0] = preload;
    server.extra_env[1] = gate_env;
    server.extra_env[2] = "SPECUS_MAX_GLOBAL_EXTERNAL_CONNECTIONS=1";
    if (server_start(&server)) goto done;
    started = 1;
#define REQUIRE(condition, label) do { if (!(condition)) { fprintf(stderr, "FAIL NAT %s: %s (%s)\n", mode, label, reason); goto done; } } while (0)
    /* The server's control/admin ports are already occupied: this selection cannot reuse either. */
    port = pick_free_port();
    REQUIRE(port > 0, "distinct public port");
    REQUIRE(create_credential(server.db_path, "nat-retire-key", "nat-retire-secret", 3) == 0, "credential");
    REQUIRE(http_client_login(&server, "nat-retire-key", "nat-retire-secret", "nat-machine", "nat-user", &runtime) == 0, "HTTP auth");
    REQUIRE(create_mapping(server.db_path, runtime.client_id, port) == 0, "mapping");
    REQUIRE(channel_login(server.control_port, &runtime, ST_CONNECTION_ROLE_CONTROL, &control, reason, sizeof(reason)) == 1, "CONTROL");
    REQUIRE(channel_login(server.control_port, &runtime, ST_CONNECTION_ROLE_DATA, &old_data, reason, sizeof(reason)) == 1, "old DATA");
    if (!bind_case) REQUIRE(nat_register(old_data, runtime.client_name, port, 9) == 0, "old REGISTER");
    if (!strcmp(operation, "recv")) REQUIRE(open_public_stream_id(old_data, port, &old_public, &old_id) == 0, "old quota=1");
    snprintf(arm, sizeof(arm), "%s %d", operation, port);
    REQUIRE(marker_file(&server, "arm", arm) == 0, "arm real syscall gate");
    if (bind_case) REQUIRE(send_register_only(old_data, runtime.client_name, port) == 0, "pending bind");
    else if (accept_case) { old_public = connect_local(port); REQUIRE(old_public >= 0, "pending accept"); }
    else {
        st_buffer hold = st_protocol_encode_nat_message(ST_NAT_KEEPALIVE, 0, 0, 0, "{\"hold\":\"nat-retire-hold\"}", NULL, 0);
        REQUIRE(send_buffer(old_data, &hold) == 0, "pending old reader");
    }
    REQUIRE(wait_marker(&server, "ready") == 0, "actual syscall paused (not a simulated result)");
    if (!strcmp(mode, "control-recv")) {
        int successor_control = -1;
        REQUIRE(channel_login(server.control_port, &runtime, ST_CONNECTION_ROLE_CONTROL, &successor_control, reason, sizeof(reason)) == 1, "new CONTROL must retire old DATA before old reader resumes");
        close_fd(&control); control = successor_control;
    }
    REQUIRE(channel_login(server.control_port, &runtime, ST_CONNECTION_ROLE_DATA, &new_data, reason, sizeof(reason)) == 1, "new DATA must not wait for old worker");
    if (!idle) {
        REQUIRE(nat_register(new_data, runtime.client_name, port, 9) == 0, "new REGISTER before old worker resumes");
        REQUIRE(open_public_stream_id(new_data, port, &new_public, &new_id) == 0, "quota must be available before old finally");
    }
    if (!strcmp(operation, "recv")) REQUIRE(expect_socket_eof(old_public, IO_TIMEOUT_MS) == 0, "old stream closes before old reader resumes");
    REQUIRE(marker_file(&server, "resume", "continue") == 0, "release syscall");
    REQUIRE(expect_channel_closed(old_data, IO_TIMEOUT_MS) == 0, "old DATA closed");
    if (!strcmp(operation, "recv"))
        REQUIRE(wait_marker(&server, "finished") == 0, "actual old DATA teardown passed stream closure and joins, not just socket EOF");
    if (bind_case || accept_case) {
        REQUIRE(wait_marker(&server, "closed") == 0, "real delayed descriptor has closed");
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", server.dir, bind_case ? "late-listen" : "late-worker");
        FILE *late = fopen(path, "r");
        if (late) {
            int actual = -999; fscanf(late, "%d", &actual); fclose(late);
            fprintf(stderr, "observed real late %s result=%d\n", bind_case ? "listen" : "pthread_create", actual);
            REQUIRE(0, "retired namespace must not attempt LISTEN or admit a new external worker");
        }
    }
    if (old_public >= 0) REQUIRE(expect_socket_eof(old_public, IO_TIMEOUT_MS) == 0, "late accepted socket cannot survive retirement");
    if (idle) {
        REQUIRE(nat_register(new_data, runtime.client_name, port, 9) == 0, "new REGISTER after old callback");
        REQUIRE(open_public_stream_id(new_data, port, &new_public, &new_id) == 0, "new TCP after old callback");
    }
    REQUIRE(exchange(new_data, new_public, new_id) == 0, "old late completion cannot close successor stream");
    refused = connect_local(port);
    REQUIRE(refused >= 0 && expect_socket_eof(refused, IO_TIMEOUT_MS) == 0, "old finally cannot release successor quota (limit still 1)");
    REQUIRE(reset_stream(new_data, new_id) == 0 && expect_channel_alive(new_data) == 0, "new stream reset processed");
    REQUIRE(open_public_stream_id(new_data, port, &recovered, &recovered_id) == 0, "new stream releases exactly its own quota");
    REQUIRE(exchange(new_data, recovered, recovered_id) == 0, "real bidirectional bytes after recovery");
    REQUIRE(reset_stream(new_data, recovered_id) == 0 && expect_channel_alive(new_data) == 0, "last stream reset");
    close_fd(&recovered);
    int before = server_fd_count(&server);
    REQUIRE(before >= 0, "read actual owned process fd count");
    for (int i = 0; i < 24; ++i) {
        REQUIRE(open_public_stream_id(new_data, port, &recovered, &recovered_id) == 0, "repeated stream admission");
        REQUIRE(reset_stream(new_data, recovered_id) == 0 && expect_socket_eof(recovered, IO_TIMEOUT_MS) == 0
            && expect_channel_alive(new_data) == 0, "repeated stream retires");
        close_fd(&recovered);
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    int after;
    do {
        after = server_fd_count(&server);
        if (after >= 0 && after <= before + 4) break;
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    REQUIRE(after >= 0 && after <= before + 4, "closed stream descriptors released while DATA stays alive, not only at session teardown");
    failed = 0;
done:
    marker_file(&server, "resume", "cleanup");
    close_fd(&old_public); close_fd(&new_public); close_fd(&refused); close_fd(&recovered);
    close_fd(&old_data); close_fd(&new_data); close_fd(&control);
    if (started && server_stop(&server, 10000)) failed = 1;
    if (failed) dump_server_log(&server);
    const char *files[] = {"arm", "ready", "resume", "closed", "finished", "late-listen", "late-worker"};
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        char path[512]; snprintf(path, sizeof(path), "%s/%s", server.dir, files[i]); unlink(path);
    }
    server_cleanup(&server, failed);
    printf("%s NAT namespace late %s\n", failed ? "FAIL" : "PASS", mode);
    return failed;
#undef REQUIRE
}

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: %s server-binary test-barrier-library\n", argv[0]); return 2; }
    signal(SIGPIPE, SIG_IGN);
    server_binary = argv[1]; barrier_library = argv[2];
    int failures = scenario("bind") + scenario("bind-idle") + scenario("accept")
        + scenario("accept-idle") + scenario("recv") + scenario("control-recv");
    return failures ? 1 : 0;
}
