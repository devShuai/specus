#define _GNU_SOURCE
#include "server_harness.h"
#include "storage.h"
#include <dlfcn.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define WATCH_TEST_NATIVE_BATCH 64U

typedef struct {
    test_server a, b;
    int prepared_a, prepared_b, started_a, started_b;
    runtime_session runtime, witness;
    int control, receiver, data, public_fd, replacement, new_data, new_public;
    int port;
    char shared[512], preload[512], gate[512];
} fixture;
static int enable_peer(fixture *f, long long id)
{
    st_storage_client client;
    return st_storage_get_client(f->a.db_path, id, &client) == 0
        && st_storage_update_peer_mesh_device_enabled(f->a.db_path, &client, 1, NULL) == 0 ? 0 : -1;
}
static int business_fence(fixture *f)
{
    st_buffer packet = st_protocol_encode_message_response(f->runtime.client_name, f->witness.client_name,
        ST_MESSAGE_TYPE_CLIENT_TO_CLIENT, "source-watch-idle-after-this");
    if (!packet.data) return -1;
    packet.data[6] = ST_CMD_MESSAGE_REQUEST;
    if (send_buffer(f->control, &packet)) return -1;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (monotonic_ms() < deadline) {
        st_frame_header header; uint8_t *body = NULL;
        if (read_frame(f->receiver, (int)(deadline - monotonic_ms()), &header, &body) != 1) return -1;
        st_message_response message = {0};
        int done = header.command == ST_CMD_MESSAGE_RESPONSE
            && st_protocol_decode_message_response(body, header.length, &message) == 0
            && message.message_type == ST_MESSAGE_TYPE_CLIENT_TO_CLIENT && message.message
            && !strcmp(message.message, "source-watch-idle-after-this");
        st_message_response_free(&message); free(body); if (done) return 0;
    }
    return -1;
}
static int prepare(fixture *f, const char *library, int second)
{
    memset(f, 0, sizeof(*f)); f->control = f->receiver = f->data = f->public_fd = -1;
    f->replacement = f->new_data = f->new_public = -1;
    if (server_prepare(&f->a)) return -1;
    f->prepared_a = 1;
    Dl_info asan = {0}; void *symbol = dlsym(RTLD_DEFAULT, "__asan_init");
    if (symbol && dladdr(symbol, &asan) && asan.dli_fname)
        snprintf(f->preload, sizeof(f->preload), "LD_PRELOAD=%s:%s", asan.dli_fname, library);
    else snprintf(f->preload, sizeof(f->preload), "LD_PRELOAD=%s", library);
    snprintf(f->gate, sizeof(f->gate), "SPECUS_TEST_SOURCE_WATCH_DIR=%s", f->a.dir);
    f->a.extra_env[0] = f->preload; f->a.extra_env[1] = f->gate; f->a.extra_env[2] = "SPECUS_PEER_MESH_ENABLED=false";
    if (server_start(&f->a)) return -1;
    f->started_a = 1;
    if (second) {
        if (server_prepare(&f->b)) return -1;
        f->prepared_b = 1;
        snprintf(f->shared, sizeof(f->shared), "SPECUS_DATABASE_PATH=%s", f->a.db_path);
        f->b.extra_env[0] = f->shared; f->b.extra_env[1] = "SPECUS_PEER_MESH_ENABLED=false";
        if (server_start(&f->b)) return -1;
        f->started_b = 1;
    }
    if (create_credential(f->a.db_path, "ck_watch", "watch-secret", 5)) return -1;
    harness_login_environment_extra = ",\"sendMessages\":true,\"receiveMessages\":true";
    int rc = http_client_login(&f->a, "ck_watch", "watch-secret", "watch-source", "user", &f->runtime)
        || http_client_login(&f->a, "ck_watch", "watch-secret", "watch-witness", "user", &f->witness);
    harness_login_environment_extra = ""; if (rc) return -1;
    /* Client-to-client delivery requires enabled Peer devices even when discovery itself is off.
     * This is explicit test setup, not an authentication/policy bypass in the server. */
    if (enable_peer(f, f->runtime.client_id) || enable_peer(f, f->witness.client_id)) return -1;
    char reason[512];
    if (channel_login(f->a.control_port, &f->runtime, ST_CONNECTION_ROLE_CONTROL, &f->control, reason, sizeof(reason)) != 1
        || channel_login(f->a.control_port, &f->witness, ST_CONNECTION_ROLE_CONTROL, &f->receiver, reason, sizeof(reason)) != 1
        || business_fence(f)) return -1;
    /* The fence is a real outgoing message after the source's queued login job. No more business
     * is sent by this source. Heartbeats cannot invoke the worker's current-source check. */
    f->port = pick_free_port();
    if (f->port <= 0 || create_mapping(f->a.db_path, f->runtime.client_id, f->port)
        || channel_login(f->a.control_port, &f->runtime, ST_CONNECTION_ROLE_DATA, &f->data, reason, sizeof(reason)) != 1
        || nat_register(f->data, f->runtime.client_name, f->port, 9)
        || open_public_stream(f->data, f->port, &f->public_fd)) return -1;
    return expect_channel_alive(f->control) || expect_channel_alive(f->data) ? -1 : 0;
}
static int cleanup(fixture *f, int failed)
{
    close_fd(&f->control); close_fd(&f->receiver); close_fd(&f->data); close_fd(&f->public_fd);
    close_fd(&f->replacement); close_fd(&f->new_data); close_fd(&f->new_public);
    if (f->started_a && server_stop(&f->a, 10000)) failed = 1;
    if (f->started_b && server_stop(&f->b, 10000)) failed = 1;
    if (f->prepared_b) server_cleanup(&f->b, failed);
    if (f->prepared_a) {
        const char *names[] = {"arm", "watch-busy", "watch-account-disabled", "watch-credential-disabled"};
        for (size_t i = 0; i < 4; ++i) { char path[512]; snprintf(path, sizeof(path), "%s/%s", f->a.dir, names[i]); unlink(path); }
        server_cleanup(&f->a, failed);
    }
    return failed;
}
static int execute(fixture *f, const char *sql)
{
    sqlite3 *db = NULL; int rc = sqlite3_open(f->a.db_path, &db);
    if (rc == SQLITE_OK) { sqlite3_busy_timeout(db, 5000); rc = sqlite3_exec(db, sql, NULL, NULL, NULL); }
    sqlite3_close(db); return rc == SQLITE_OK ? 0 : -1;
}
static int wait_marker(fixture *f, const char *name)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", f->a.dir, name);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(path, F_OK)) { if (monotonic_ms() >= deadline) return -1; sleep_ms(1); }
    return 0;
}
static int same_sid(const char *library)
{
    fixture f; int failed = 1; char reason[512], before[128], after[128];
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL idle cross-process source: %s\n", label); goto done; } } while (0)
    REQUIRE(prepare(&f, library, 1) == 0, "real signed HTTP + completed-business fence + original DATA/public stream, Peer disabled");
    REQUIRE(db_scalar(f.a.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL,
        f.runtime.session_id, before, sizeof(before)) == 0, "old native epoch");
    REQUIRE(channel_login(f.b.control_port, &f.runtime, ST_CONNECTION_ROLE_CONTROL, &f.replacement, reason, sizeof(reason)) == 1,
        "independent process replaces same native SID");
    REQUIRE(db_scalar(f.a.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL,
        f.runtime.session_id, after, sizeof(after)) == 0 && strcmp(before, after), "new physical epoch really committed");
    REQUIRE(expect_channel_closed(f.control, IO_TIMEOUT_MS) == 0, "idle old CONTROL must close WITHOUT any business packet");
    REQUIRE(expect_channel_closed(f.data, IO_TIMEOUT_MS) == 0 && expect_socket_eof(f.public_fd, IO_TIMEOUT_MS) == 0,
        "original DATA/public TCP retired with idle CONTROL");
    REQUIRE(expect_channel_alive(f.receiver) == 0 && expect_channel_alive(f.replacement) == 0, "unrelated and new CONTROL survive");
    REQUIRE(db_scalar(f.a.db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
        f.runtime.session_id, after, sizeof(after)) == 0 && !strcmp(after, "NETTY_ONLINE"), "old cleanup preserves winner ONLINE");
    REQUIRE(channel_login(f.b.control_port, &f.runtime, ST_CONNECTION_ROLE_DATA, &f.new_data, reason, sizeof(reason)) == 1
        && nat_register(f.new_data, f.runtime.client_name, f.port, 9) == 0, "replacement DATA binds released public port");
    uint32_t id;
    REQUIRE(open_public_stream_id(f.new_data, f.port, &f.new_public, &id) == 0, "replacement real TCP stream");
    const uint8_t payload[] = "idle old source is gone"; uint8_t received[sizeof(payload)];
    st_buffer packet = st_protocol_encode_nat_message(ST_NAT_DATA, 0, id, 0, NULL, payload, sizeof(payload));
    REQUIRE(send_buffer(f.new_data, &packet) == 0 && recv_exact(f.new_public, received, sizeof(received), monotonic_ms() + IO_TIMEOUT_MS) == 1
        && !memcmp(payload, received, sizeof(payload)), "replacement actual DATA-to-public bytes");
    failed = 0;
done:
    failed = cleanup(&f, failed);
    printf("%s idle cross-process same-SID retirement WITHOUT business; DATA/public TCP and winner remain usable\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}
static int policy_and_busy(const char *library)
{
    fixture f; int failed = 1; sqlite3 *writer = NULL; char path[512];
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL source watch policy/busy: %s\n", label); goto done; } } while (0)
    REQUIRE(prepare(&f, library, 0) == 0, "prepare completed idle source");
    snprintf(path, sizeof(path), "%s/arm", f.a.dir); FILE *arm = fopen(path, "w"); REQUIRE(arm, "arm actual native read probe"); fclose(arm);
    char sql[256]; snprintf(sql, sizeof(sql), "UPDATE client_account SET enabled=0 WHERE rowid=%lld", f.runtime.client_id);
    REQUIRE(execute(&f, sql) == 0 && wait_marker(&f, "watch-account-disabled") == 0, "background READ transaction actually observed disabled account");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.data) == 0, "disabled account is not permanent physical loss");
    REQUIRE(execute(&f, "UPDATE client_account SET enabled=1; UPDATE specus_client_credential SET enabled=0") == 0
        && wait_marker(&f, "watch-credential-disabled") == 0, "background native READ actually observed disabled credential");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.receiver) == 0, "temporary credential switch does not retire either physical source");
    REQUIRE(execute(&f, "UPDATE specus_client_credential SET enabled=1") == 0, "restore policy");
    REQUIRE(sqlite3_open(f.a.db_path, &writer) == SQLITE_OK && sqlite3_busy_timeout(writer, 5000) == SQLITE_OK
        && sqlite3_exec(writer, "BEGIN EXCLUSIVE", NULL, NULL, NULL) == SQLITE_OK, "real independent SQLite exclusive writer");
    REQUIRE(wait_marker(&f, "watch-busy") == 0, "background native query really hit BUSY under its bounded timeout");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.data) == 0,
        "CONTROL/DATA heartbeat still answers while actual database is unavailable");
    REQUIRE(sqlite3_exec(writer, "ROLLBACK", NULL, NULL, NULL) == SQLITE_OK, "release real DB"); sqlite3_close(writer); writer = NULL;
    REQUIRE(business_fence(&f) == 0, "restored original CONTROL resumes actual message delivery");
    failed = 0;
done:
    if (writer) { sqlite3_exec(writer, "ROLLBACK", NULL, NULL, NULL); sqlite3_close(writer); }
    failed = cleanup(&f, failed); printf("%s actual background disabled-policy/BUSY observation, independent heartbeat and original-source recovery\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}
static int expiry(const char *library)
{
    fixture f; int failed = 1; char sql[256];
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL idle source expiry: %s\n", label); goto done; } } while (0)
    REQUIRE(prepare(&f, library, 0) == 0, "prepare completed idle source");
    snprintf(sql, sizeof(sql), "UPDATE specus_client_session SET expires_at='2000-01-01T00:00:00Z' WHERE id=%lld", f.runtime.session_id);
    REQUIRE(execute(&f, sql) == 0, "actual native expiry");
    REQUIRE(expect_channel_closed(f.control, IO_TIMEOUT_MS) == 0 && expect_channel_closed(f.data, IO_TIMEOUT_MS) == 0
        && expect_socket_eof(f.public_fd, IO_TIMEOUT_MS) == 0, "expired CONTROL/DATA/public close WITHOUT business");
    REQUIRE(expect_channel_alive(f.receiver) == 0, "unexpired unrelated physical source survives");
    failed = 0;
done:
    failed = cleanup(&f, failed); printf("%s native idle expiry closes exact physical family without business\n", failed ? "FAIL" : "PASS"); return failed;
#undef REQUIRE
}
static int beyond_batch(const char *library)
{
    fixture f; int failed = 1, controls[WATCH_TEST_NATIVE_BATCH];
    runtime_session runtimes[WATCH_TEST_NATIVE_BATCH];
    for (size_t i = 0; i < WATCH_TEST_NATIVE_BATCH; ++i) controls[i] = -1;
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL idle source batch fairness: %s\n", label); goto done; } } while (0)
    REQUIRE(prepare(&f, library, 0) == 0, "original completed idle source and witness");
    REQUIRE(execute(&f, "UPDATE specus_client_credential SET max_online_instances=100") == 0, "explicit test credential capacity");
    harness_login_environment_extra = ",\"sendMessages\":true,\"receiveMessages\":true";
    for (size_t i = 0; i < WATCH_TEST_NATIVE_BATCH; ++i) {
        char fingerprint[64], reason[256]; snprintf(fingerprint, sizeof(fingerprint), "watch-batch-%zu", i);
        REQUIRE(http_client_login(&f.a, "ck_watch", "watch-secret", fingerprint, "user", &runtimes[i]) == 0
            && enable_peer(&f, runtimes[i].client_id) == 0, "additional real native source");
        REQUIRE(channel_login(f.a.control_port, &runtimes[i], ST_CONNECTION_ROLE_CONTROL,
            &controls[i], reason, sizeof(reason)) == 1, "additional physical CONTROL");
        fixture source = f; source.runtime = runtimes[i]; source.control = controls[i];
        REQUIRE(business_fence(&source) == 0, "every source finishes actual prior business before native invalidation");
    }
    harness_login_environment_extra = "";
    char sql[256]; snprintf(sql, sizeof(sql), "UPDATE specus_client_session SET expires_at='2000-01-01T00:00:00Z' WHERE client_id<>%lld", f.witness.client_id);
    REQUIRE(execute(&f, sql) == 0, "65 idle sources invalidated, more than one 64-element scan");
    REQUIRE(expect_channel_closed(f.control, IO_TIMEOUT_MS) == 0, "original source retires");
    for (size_t i = 0; i < WATCH_TEST_NATIVE_BATCH; ++i)
        REQUIRE(expect_channel_closed(controls[i], IO_TIMEOUT_MS) == 0, "every beyond-first-batch source eventually retires WITHOUT business");
    REQUIRE(expect_channel_closed(f.data, IO_TIMEOUT_MS) == 0 && expect_socket_eof(f.public_fd, IO_TIMEOUT_MS) == 0
        && expect_channel_alive(f.receiver) == 0, "exact invalidated family closes; valid witness survives multiple scans");
    failed = 0;
done:
    harness_login_environment_extra = "";
    for (size_t i = 0; i < WATCH_TEST_NATIVE_BATCH; ++i) close_fd(&controls[i]);
    failed = cleanup(&f, failed); printf("%s 65 real idle sources beyond native scan batch, with completed-business fences and surviving valid witness\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}
static int wait_open_audits(fixture *f, long long cid, int expected)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS; char value[64], want[32];
    snprintf(want, sizeof(want), "%d", expected);
    do {
        if (db_scalar(f->a.db_path, "SELECT COUNT(*) FROM connection_record WHERE client_id=? AND success=1 AND disconnected_at IS NULL",
            NULL, cid, value, sizeof(value)) == 0 && !strcmp(value, want)) return 0;
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    fprintf(stderr, "OBSERVATION native open audits cid=%lld actual=%s expected=%s\n", cid, value, want);
    return -1;
}
static int process_lifecycle(const char *library)
{
    fixture f; int failed = 1; runtime_session other; char reason[512], value[128], dead_channel[128];
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL shared-db process lifecycle: %s\n", label); goto done; } } while (0)
    REQUIRE(prepare(&f, library, 0) == 0, "first process owns actual idle CONTROL/DATA/TCP and witness");
    REQUIRE(wait_open_audits(&f, f.runtime.client_id, 1) == 0 && wait_open_audits(&f, f.witness.client_id, 1) == 0,
        "both first-instance accepted audits actually persisted before second startup");
    REQUIRE(execute(&f, "UPDATE specus_client_credential SET max_online_instances=3") == 0, "three-instance credential limit");
    REQUIRE(server_prepare(&f.b) == 0, "prepare second AFTER first is online"); f.prepared_b = 1;
    snprintf(f.shared, sizeof(f.shared), "SPECUS_DATABASE_PATH=%s", f.a.db_path);
    f.b.extra_env[0] = f.shared; f.b.extra_env[1] = "SPECUS_PEER_MESH_ENABLED=false";
    REQUIRE(server_start(&f.b) == 0, "second starts on an already-live shared SQLite"); f.started_b = 1;
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.receiver) == 0
        && expect_channel_alive(f.data) == 0 && wait_open_audits(&f, f.runtime.client_id, 1) == 0,
        "second startup must not retire or stamp another instance's live physical sources");
    REQUIRE(http_client_login(&f.b, "ck_watch", "watch-secret", "watch-other-process", "user", &other) == 0
        && channel_login(f.b.control_port, &other, ST_CONNECTION_ROLE_CONTROL, &f.replacement, reason, sizeof(reason)) == 1
        && wait_open_audits(&f, other.client_id, 1) == 0, "second owns third native CONTROL, audit committed");
    REQUIRE(server_stop(&f.b, 10000) == 0, "normal second-instance shutdown drains only its own source"); f.started_b = 0;
    REQUIRE(expect_channel_closed(f.replacement, IO_TIMEOUT_MS) == 0, "second own socket really closes"); close_fd(&f.replacement);
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.receiver) == 0
        && wait_open_audits(&f, f.runtime.client_id, 1) == 0 && wait_open_audits(&f, f.witness.client_id, 1) == 0,
        "second shutdown cannot close first-instance audits or native sources");
    REQUIRE(server_start(&f.b) == 0, "second restarts while first remains live"); f.started_b = 1;
    REQUIRE(http_client_login(&f.b, "ck_watch", "watch-secret", "watch-other-process", "user", &other) == 0
        && channel_login(f.b.control_port, &other, ST_CONNECTION_ROLE_CONTROL, &f.replacement, reason, sizeof(reason)) == 1
        && wait_open_audits(&f, other.client_id, 1) == 0, "new second physical owner actually accepted");
    REQUIRE(db_scalar(f.a.db_path, "SELECT channel_id FROM specus_client_session WHERE id=?", NULL, other.session_id,
        dead_channel, sizeof(dead_channel)) == 0, "capture actual killed physical source");
    REQUIRE(kill(f.b.pid, SIGKILL) == 0, "real SIGKILL, no graceful cleanup");
    int status; REQUIRE(waitpid(f.b.pid, &status, 0) == f.b.pid && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
        "actual process death observed"); f.b.pid = -1; f.started_b = 0; close_fd(&f.replacement);
    REQUIRE(db_scalar(f.a.db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL, other.session_id,
        value, sizeof(value)) == 0 && !strcmp(value, "NETTY_ONLINE") && wait_open_audits(&f, other.client_id, 1) == 0,
        "crash leaves real ONLINE native row and unclosed accepted audit");
    REQUIRE(server_start(&f.b) == 0, "recovery startup against live first instance and dead second owner"); f.started_b = 1;
    REQUIRE(db_scalar(f.a.db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL, other.session_id,
        value, sizeof(value)) == 0 && !strcmp(value, "DISCONNECTED"), "recovery closes exact dead source before accepting");
    REQUIRE(db_scalar(f.a.db_path, "SELECT disconnect_reason FROM connection_record WHERE channel_id=?", dead_channel, 0,
        value, sizeof(value)) == 0 && !strcmp(value, "SERVER_RESTARTED"), "dead audit is recovered, not another instance's audit");
    REQUIRE(expect_channel_alive(f.control) == 0 && expect_channel_alive(f.receiver) == 0
        && wait_open_audits(&f, f.runtime.client_id, 1) == 0 && wait_open_audits(&f, f.witness.client_id, 1) == 0,
        "crash recovery preserves first instance's real channels and open audits");
    REQUIRE(http_client_login(&f.b, "ck_watch", "watch-secret", "watch-other-process", "user", &other) == 0
        && channel_login(f.b.control_port, &other, ST_CONNECTION_ROLE_CONTROL, &f.replacement, reason, sizeof(reason)) == 1
        && expect_channel_alive(f.replacement) == 0, "dead row no longer consumes the three-instance/machine quota");
    failed = 0;
done:
    failed = cleanup(&f, failed); printf("%s real shared-DB late startup/normal shutdown/SIGKILL recovery preserve foreign physical owners and quota\n", failed ? "FAIL" : "PASS"); return failed;
#undef REQUIRE
}
int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) return 2;
    signal(SIGPIPE, SIG_IGN); server_binary = argv[1];
    if (argc == 4) {
        if (!strcmp(argv[3], "same-sid")) return same_sid(argv[2]);
        if (!strcmp(argv[3], "process-lifecycle")) return process_lifecycle(argv[2]);
        return 2;
    }
    return same_sid(argv[2]) + policy_and_busy(argv[2]) + expiry(argv[2]) + beyond_batch(argv[2]) + process_lifecycle(argv[2]) ? 1 : 0;
}
