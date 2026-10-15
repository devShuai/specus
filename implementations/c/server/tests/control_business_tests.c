#define _GNU_SOURCE
#include "server_harness.h"
#include "json.h"
#include <dlfcn.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

static void preload_assignment(char *out, size_t length, const char *library)
{
    void *asan = dlsym(RTLD_DEFAULT, "__asan_init");
    Dl_info sanitizer = {0};
    if (asan && dladdr(asan, &sanitizer) && sanitizer.dli_fname)
        snprintf(out, length, "LD_PRELOAD=%s:%s", sanitizer.dli_fname, library);
    else snprintf(out, length, "LD_PRELOAD=%s", library);
}

static int marker(const test_server *server, const char *name)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    FILE *file = fopen(path, "w"); if (!file) return -1;
    return fclose(file);
}
static int wait_marker(const test_server *server, const char *name)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(path, F_OK)) { if (monotonic_ms() >= deadline) return -1; sleep_ms(1); }
    return 0;
}
static int wait_revision(const test_server *server, long long cid, const char *want)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    do {
        char value[64];
        if (db_scalar(server->db_path, "SELECT revision FROM peer_mesh_egress_activity WHERE egress_client_id=?",
                      NULL, cid, value, sizeof(value)) == 0 && strcmp(value, want) == 0) return 0;
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    return -1;
}
static int peer_config(int fd)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (monotonic_ms() < deadline) {
        st_frame_header header; uint8_t *body = NULL;
        if (read_frame(fd, (int)(deadline - monotonic_ms()), &header, &body) != 1) return -1;
        st_message_response message = {0};
        int found = header.command == ST_CMD_MESSAGE_RESPONSE
            && st_protocol_decode_message_response(body, header.length, &message) == 0
            && message.message && strstr(message.message, "\"type\":\"peer-config\"");
        st_message_response_free(&message); free(body);
        if (found) return 0;
    }
    return -1;
}
static int report(int fd, const runtime_session *runtime, int revision)
{
    char json[128]; snprintf(json, sizeof(json), "{\"type\":\"egress-report\",\"revision\":%d,\"activeFlows\":3}", revision);
    st_buffer packet = st_protocol_encode_message_response(runtime->client_name, NULL, ST_MESSAGE_TYPE_PEER_CONTROL, json);
    if (!packet.data) return -1;
    packet.data[6] = ST_CMD_MESSAGE_REQUEST;
    return send_buffer(fd, &packet);
}
static int blocking_business(const char *library)
{
    test_server server; int prepared = 0, started = 0, failed = 1;
    int first = -1, replacement = -1, other = -1;
    runtime_session a, b; char reason[512], preload[512], barrier[512];
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL CONTROL business: %s\n", label); goto done; } } while (0)
    REQUIRE(server_prepare(&server) == 0, "prepare"); prepared = 1;
    preload_assignment(preload, sizeof(preload), library);
    snprintf(barrier, sizeof(barrier), "SPECUS_TEST_CONTROL_BARRIER_DIR=%s", server.dir);
    server.extra_env[0] = preload; server.extra_env[1] = barrier;
    server.extra_env[2] = "SPECUS_PEER_MESH_ENABLED=true";
    server.extra_env[3] = "SPECUS_PEER_MESH_STUN_TURN_PORT=0";
    REQUIRE(server_start(&server) == 0, "start"); started = 1;
    REQUIRE(create_credential(server.db_path, "ck_control", "control-secret", 4) == 0, "credential");
    harness_login_environment_extra = ",\"clientEgressCapabilities\":{\"version\":1,\"egressCapable\":true,\"consumerCapable\":true}";
    REQUIRE(http_client_login(&server, "ck_control", "control-secret", "control-a", "user", &a) == 0, "HTTP A");
    REQUIRE(http_client_login(&server, "ck_control", "control-secret", "control-b", "user", &b) == 0, "HTTP B");
    REQUIRE(channel_login(server.control_port, &a, ST_CONNECTION_ROLE_CONTROL, &first, reason, sizeof(reason)) == 1, "CONTROL A");
    REQUIRE(peer_config(first) == 0 && report(first, &a, 1) == 0 && wait_revision(&server, a.client_id, "1") == 0, "initial worker completes native report");
    REQUIRE(marker(&server, "arm") == 0 && report(first, &a, 2) == 0 && wait_marker(&server, "ready") == 0,
            "business pauses after actual SQLite handle closed");
    REQUIRE(expect_channel_alive(first) == 0, "heartbeat remains responsive while native business is paused");
    replacement = connect_local(server.control_port);
    REQUIRE(replacement >= 0 && send_login_request(replacement, &a, ST_CONNECTION_ROLE_CONTROL) == 0, "same-CID replacement submitted");
    REQUIRE(channel_login(server.control_port, &b, ST_CONNECTION_ROLE_CONTROL, &other, reason, sizeof(reason)) == 1
        && expect_channel_alive(other) == 0, "unrelated CID authenticates and heartbeats while A holds lifecycle");
    /* B's initial business is waiting for the global Peer dispatcher, not its heartbeat reader.
     * Queue an old B packet, retire B, and require cancellation to let B reconnect while A is held. */
    REQUIRE(report(other, &b, 99) == 0 && expect_channel_alive(other) == 0, "old B report queued behind blocked business");
    close_fd(&other);
    REQUIRE(channel_login(server.control_port, &b, ST_CONNECTION_ROLE_CONTROL, &other, reason, sizeof(reason)) == 1
        && expect_channel_alive(other) == 0, "retired dispatch waiter cancels without waiting for unrelated A");
    struct pollfd pending = {.fd = replacement, .events = POLLIN};
    REQUIRE(poll(&pending, 1, 100) == 0, "replacement cannot publish through unfinished original-source work");
    REQUIRE(marker(&server, "resume") == 0, "release real business");
    int command, success;
    REQUIRE(read_login_response(replacement, IO_TIMEOUT_MS, &command, &success, reason, sizeof(reason)) == 1 && success,
            "same-CID replacement finishes after prior business");
    REQUIRE(wait_revision(&server, a.client_id, "2") == 0 && expect_channel_alive(replacement) == 0
        && expect_channel_closed(first, IO_TIMEOUT_MS) == 0, "native commit precedes replacement; old source retired");
    REQUIRE(peer_config(other) == 0, "replacement B business now completes");
    char stale[64];
    REQUIRE(db_scalar(server.db_path, "SELECT revision FROM peer_mesh_egress_activity WHERE egress_client_id=?",
                       NULL, b.client_id, stale, sizeof(stale)) == 1, "retired B queued packet never writes native activity");
    failed = 0;
done:
    harness_login_environment_extra = "";
    if (prepared) marker(&server, "resume");
    close_fd(&first); close_fd(&replacement); close_fd(&other);
    if (started && server_stop(&server, 20000) != 0) failed = 1;
    if (!failed) {
        char audit[128] = "";
        if (db_scalar(server.db_path,
            "SELECT COUNT(DISTINCT channel_id)||':'||COUNT(*)||':'||SUM(disconnected_at IS NOT NULL) "
            "FROM connection_record WHERE client_id=? AND success=1", NULL, b.client_id, audit, sizeof(audit)) != 0
            || strcmp(audit, "2:2:2") != 0) {
            fprintf(stderr, "FAIL accepted B login audit/channel/drain counts: %s\n", audit); failed = 1;
        } else printf("OBSERVATION B native distinct-physical/accepted/disconnected audits=%s\n", audit);
    }
    if (prepared) {
        const char *names[] = {"arm", "ready", "resume"};
        for (size_t i = 0; i < 3; ++i) { char path[512]; snprintf(path, sizeof(path), "%s/%s", server.dir, names[i]); unlink(path); }
        server_cleanup(&server, failed);
    }
    printf("%s CONTROL business heartbeat, exact-CID admission and replacement ordering\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}

static int cross_process_cleanup(void)
{
    test_server first, second; int prepared1 = 0, prepared2 = 0, started1 = 0, started2 = 0, failed = 1;
    int old = -1, current = -1, data = -1; char db_env[512], reason[512], before[128], after[128]; runtime_session runtime;
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL cross-process CONTROL: %s\n", label); goto done; } } while (0)
    REQUIRE(server_prepare(&first) == 0, "prepare first"); prepared1 = 1;
    REQUIRE(server_start(&first) == 0, "start first"); started1 = 1;
    REQUIRE(server_prepare(&second) == 0, "prepare second"); prepared2 = 1;
    snprintf(db_env, sizeof(db_env), "SPECUS_DATABASE_PATH=%s", first.db_path); second.extra_env[0] = db_env;
    REQUIRE(server_start(&second) == 0, "start second against shared native SQLite before login"); started2 = 1;
    REQUIRE(create_credential(first.db_path, "ck_shared", "shared-secret", 2) == 0
        && http_client_login(&first, "ck_shared", "shared-secret", "shared-machine", "user", &runtime) == 0, "signed HTTP session");
    REQUIRE(channel_login(first.control_port, &runtime, ST_CONNECTION_ROLE_CONTROL, &old, reason, sizeof(reason)) == 1,
            "original physical source in process one");
    REQUIRE(db_scalar(first.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL,
                       runtime.session_id, before, sizeof(before)) == 0, "first native channel");
    REQUIRE(channel_login(second.control_port, &runtime, ST_CONNECTION_ROLE_CONTROL, &current, reason, sizeof(reason)) == 1,
            "same SID new physical source in independent process");
    REQUIRE(db_scalar(first.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL,
                       runtime.session_id, after, sizeof(after)) == 0 && strcmp(before, after) != 0, "native physical epoch changes");
    printf("OBSERVATION old-native-channel=%s new-native-channel=%s\n", before, after);
    close_fd(&old);
    REQUIRE(server_stop(&first, 20000) == 0, "first process fully drains old cleanup"); started1 = 0;
    REQUIRE(db_scalar(first.db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
                       runtime.session_id, after, sizeof(after)) == 0 && strcmp(after, "NETTY_ONLINE") == 0,
            "old cleanup cannot mark newer native physical source offline");
    printf("OBSERVATION native status-after-old-process-exit=%s\n", after);
    REQUIRE(channel_login(second.control_port, &runtime, ST_CONNECTION_ROLE_DATA, &data, reason, sizeof(reason)) == 1
        && expect_channel_alive(current) == 0 && expect_channel_alive(data) == 0, "new CONTROL and DATA still actually usable");
    failed = 0;
done:
    close_fd(&old); close_fd(&current); close_fd(&data);
    if (started1 && server_stop(&first, 20000) != 0) failed = 1;
    if (started2 && server_stop(&second, 20000) != 0) failed = 1;
    if (prepared2) server_cleanup(&second, failed);
    if (prepared1) server_cleanup(&first, failed);
    printf("%s cross-process native physical-channel conditional cleanup\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}
static int startup_crypto_drain(const char *library)
{
    test_server server; int prepared = 0, started = 0, failed = 1, client = -1;
    char preload[512], barrier[512], path[512];
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL startup crypto drain: %s\n", label); goto done; } } while (0)
    REQUIRE(server_prepare(&server) == 0, "prepare"); prepared = 1;
    preload_assignment(preload, sizeof(preload), library);
    snprintf(barrier, sizeof(barrier), "SPECUS_TEST_CONTROL_BARRIER_DIR=%s", server.dir);
    server.extra_env[0] = preload; server.extra_env[1] = barrier; server.extra_env[2] = "SPECUS_TEST_CONTROL_STARTUP=1";
    REQUIRE(server_start_without_control_probe(&server) == 0, "start without a hidden CONTROL readiness probe"); started = 1;
    REQUIRE(marker(&server, "arm") == 0, "arm");
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    do { client = connect_local(server.control_port); if (client >= 0) break; sleep_ms(1); } while (monotonic_ms() < deadline);
    REQUIRE(client >= 0 && wait_marker(&server, "ready") == 0, "actual reader paused at real RAND_bytes entry");
    REQUIRE(kill(server.pid, SIGTERM) == 0, "SIGTERM while crypto reader is paused");
    snprintf(path, sizeof(path), "%s/drain-wait", server.dir);
    deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(path, F_OK)) {
        int status;
        if (waitpid(server.pid, &status, WNOHANG) == server.pid) {
            printf("OBSERVATION process exited before registered crypto drain raw_status=%d\n", status);
            server.pid = -1; started = 0;
            REQUIRE(0, "process-global cleanup overtook the unfinished accepted reader");
        }
        REQUIRE(monotonic_ms() < deadline, "main reaches real registry condition wait, not an arbitrary sleep");
        sleep_ms(1);
    }
    REQUIRE(marker(&server, "resume") == 0, "release real crypto only after actual registry drain wait");
    REQUIRE(server_stop(&server, 10000) == 0, "registered crypto finishes before process exits"); started = 0;
    failed = 0;
done:
    if (prepared) marker(&server, "resume");
    close_fd(&client);
    if (started && server_stop(&server, 10000) != 0) failed = 1;
    if (prepared) {
        const char *names[] = {"arm", "ready", "resume", "drain-wait"};
        for (size_t i = 0; i < 4; ++i) { snprintf(path, sizeof(path), "%s/%s", server.dir, names[i]); unlink(path); }
        server_cleanup(&server, failed);
    }
    printf("%s accepted pre-login crypto reader participates in actual shutdown drain\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    signal(SIGPIPE, SIG_IGN); server_binary = argv[1];
    return blocking_business(argv[2]) + cross_process_cleanup() + startup_crypto_drain(argv[2]) ? 1 : 0;
}
