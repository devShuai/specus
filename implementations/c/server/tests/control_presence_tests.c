#define _POSIX_C_SOURCE 200809L
#include "control_presence.h"
#include "storage.h"
/* The interleaving hook calls the actual kernel probe, then commits a real replacement
 * before the production reaper begins its writer transaction. No production test hooks. */
static int observed_probe(const char *, const char *);
#define st_control_presence_probe observed_probe
#include "../src/storage.c"
#undef st_control_presence_probe
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL presence line %d: %s\n", __LINE__, #c); return 1; } } while (0)
static const char *channels[] = {
    "c-11111111111111111111111111111111", "c-22222222222222222222222222222222",
    "c-33333333333333333333333333333333", "c-44444444444444444444444444444444",
    "c-55555555555555555555555555555555", "c-66666666666666666666666666666666",
    "c-77777777777777777777777777777777", "c-88888888888888888888888888888888"
};
static struct {
    int armed, fired, failed;
    long long sid, cid, audit;
    char name[256];
} replacement;
static int observed_probe(const char *path, const char *channel)
{
    int rc = st_control_presence_probe(path, channel);
    if (replacement.armed && rc == ST_CONTROL_PRESENCE_DEAD && !strcmp(channel, channels[0])) {
        replacement.armed = 0; replacement.fired = 1;
        if (st_storage_mark_client_session_online(path, replacement.sid, channels[2], "127.0.0.1:10", "2026-10-16T00:00:01Z") != 0
            || st_storage_record_connection_detail_with_tenant_and_id(path, "presence", replacement.cid,
                replacement.name, channels[2], "127.0.0.1:10", 1, NULL, NULL, "2026-10-16T00:00:01Z", NULL, &replacement.audit) != 0)
            replacement.failed = 1;
    }
    return rc;
}
static int test_sql(const char *path, const char *format, ...)
{
    va_list args; va_start(args, format); char *query = sqlite3_vmprintf(format, args); va_end(args);
    sqlite3 *db = NULL; int rc = sqlite3_open(path, &db);
    if (rc == SQLITE_OK) rc = sqlite3_exec(db, query, NULL, NULL, NULL);
    sqlite3_free(query); sqlite3_close(db); return rc == SQLITE_OK ? 0 : -1;
}
static long long test_scalar(const char *path, const char *format, ...)
{
    va_list args; va_start(args, format); char *query = sqlite3_vmprintf(format, args); va_end(args);
    sqlite3 *db = NULL; sqlite3_stmt *stmt = NULL; long long value = -1;
    if (sqlite3_open(path, &db) == SQLITE_OK && sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK
        && sqlite3_step(stmt) == SQLITE_ROW) value = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt); sqlite3_close(db); sqlite3_free(query); return value;
}
static int add_native(const char *path, long long credential, const char *name, const char *channel,
                       st_storage_client_session *session, long long *audit)
{
    st_storage_client client;
    CHECK(st_storage_upsert_client(path, 0, "presence", name, "alice", 1, 60, &client) == 0);
    memset(session, 0, sizeof(*session));
    session->client_id = client.id; session->identity_id = client.id; session->credential_id = credential;
    snprintf(session->tenant_id, sizeof(session->tenant_id), "presence");
    snprintf(session->client_name, sizeof(session->client_name), "%s", name);
    snprintf(session->machine_fingerprint, sizeof(session->machine_fingerprint), "%s", name);
    uint8_t digest[ST_SHA256_LEN]; st_sha256((const uint8_t *)name, strlen(name), digest);
    st_hex_encode(digest, sizeof(digest), session->token_hash);
    snprintf(session->status, sizeof(session->status), "HTTP_AUTHENTICATED");
    snprintf(session->expires_at, sizeof(session->expires_at), "2999-01-01T00:00:00Z");
    CHECK(st_storage_create_client_session(path, session, session) == 0);
    CHECK(st_storage_mark_client_session_online(path, session->id, channel, "127.0.0.1:9", "2026-10-16T00:00:00Z") == 0);
    CHECK(st_storage_record_connection_detail_with_tenant_and_id(path, "presence", client.id, name, channel,
        "127.0.0.1:9", 1, NULL, NULL, "2026-10-16T00:00:00Z", NULL, audit) == 0);
    return 0;
}
static int kernel_lifecycle(const char *self, const char *path)
{
    st_control_presence *holder = NULL, *duplicate = NULL;
    CHECK(st_control_presence_acquire(path, channels[6], &holder) == 0);
    CHECK(st_control_presence_probe(path, channels[6]) == ST_CONTROL_PRESENCE_LIVE);
    CHECK(st_control_presence_acquire(path, channels[6], &duplicate) == -1 && !duplicate);
    int start[2], answer[2]; CHECK(pipe(start) == 0 && pipe(answer) == 0);
    pid_t child = fork(); CHECK(child >= 0);
    if (child == 0) {
        close(start[1]); close(answer[0]); char read_fd[24], write_fd[24];
        snprintf(read_fd, sizeof(read_fd), "%d", start[0]); snprintf(write_fd, sizeof(write_fd), "%d", answer[1]);
        execl(self, self, "--exec-probe", path, channels[6], read_fd, write_fd, (char *)NULL); _exit(99);
    }
    close(start[0]); close(answer[1]); st_control_presence_release(holder, 0); holder = NULL;
    char byte = 'P'; CHECK(write(start[1], &byte, 1) == 1); close(start[1]);
    int received = (int)read(answer[0], &byte, 1); close(answer[0]); int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(received == 1 && byte == 'D' && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(st_control_presence_probe(path, channels[6]) == ST_CONTROL_PRESENCE_DEAD);
    /* A successful probe cannot report success when its reply pipe is invalid. */
    CHECK(pipe(start) == 0); child = fork(); CHECK(child >= 0);
    if (child == 0) {
        close(start[1]); char read_fd[24];
        snprintf(read_fd, sizeof(read_fd), "%d", start[0]);
        execl(self, self, "--exec-probe", path, channels[6], read_fd, "-1", (char *)NULL); _exit(99);
    }
    close(start[0]); byte = 'P'; CHECK(write(start[1], &byte, 1) == 1); close(start[1]);
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1);
    st_control_presence_forget_dead(path, channels[6]);
    int ready[2]; CHECK(pipe(ready) == 0); child = fork(); CHECK(child >= 0);
    if (child == 0) {
        close(ready[0]); st_control_presence *owned = NULL;
        char ready_byte = st_control_presence_acquire(path, channels[4], &owned) == 0 ? 'R' : 'X';
        ssize_t written = write(ready[1], &ready_byte, 1); close(ready[1]);
        if (written != 1 || ready_byte != 'R') _exit(98);
        for (;;) pause();
    }
    close(ready[1]); received = (int)read(ready[0], &byte, 1); close(ready[0]);
    int was_live = st_control_presence_probe(path, channels[4]);
    (void)kill(child, SIGKILL); CHECK(waitpid(child, &status, 0) == child);
    CHECK(received == 1 && byte == 'R' && was_live == ST_CONTROL_PRESENCE_LIVE
        && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    CHECK(st_control_presence_probe(path, channels[4]) == ST_CONTROL_PRESENCE_DEAD);
    st_control_presence_forget_dead(path, channels[4]);
    puts("PASS actual cross-process kernel presence, duplicate ownership rejection, exec FD isolation and SIGKILL releases liveness");
    return 0;
}
static int native_recovery(const char *path, const char *dir)
{
    st_storage_client_credential credential;
    CHECK(st_storage_insert_client_credential(path, "presence", "alice", "presence-key", "presence-secret", 1, 100, &credential) == 0);
    st_control_presence *old = NULL, *peer = NULL, *winner = NULL, *rollback = NULL;
    CHECK(st_control_presence_acquire(path, channels[0], &old) == 0
        && st_control_presence_acquire(path, channels[1], &peer) == 0
        && st_control_presence_acquire(path, channels[2], &winner) == 0);
    st_storage_client_session one, two, unknown, failed, legacy;
    long long audit_one, audit_two, audit_unknown, audit_failed, audit_legacy;
    CHECK(add_native(path, credential.id, "one", channels[0], &one, &audit_one) == 0);
    CHECK(add_native(path, credential.id, "two", channels[1], &two, &audit_two) == 0);
    CHECK(add_native(path, credential.id, "unknown", channels[3], &unknown, &audit_unknown) == 0);
    int closed = -1;
    CHECK(st_storage_reap_dead_control_channels(path, 0, 0, "2026-10-16T00:00:02Z", "RESTART", &closed) == 0 && closed == 0);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE status='NETTY_ONLINE'") == 3);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM connection_record WHERE disconnected_at IS NULL") == 3);
    CHECK(st_control_presence_probe(path, channels[3]) == ST_CONTROL_PRESENCE_UNKNOWN);
    char alias[512]; snprintf(alias, sizeof(alias), "%s/database-alias", dir); CHECK(symlink(path, alias) == 0);
    CHECK(st_control_presence_probe(alias, channels[0]) == ST_CONTROL_PRESENCE_LIVE); unlink(alias);
    st_control_presence *invalid = NULL;
    CHECK(st_control_presence_acquire(dir, channels[6], &invalid) == -1 && !invalid);
    CHECK(st_control_presence_acquire(path, "../outside", &invalid) == -1 && !invalid);
    st_control_presence_release(old, 0); old = NULL;
    replacement.armed = 1; replacement.sid = one.id; replacement.cid = one.client_id;
    snprintf(replacement.name, sizeof(replacement.name), "%s", one.client_name);
    CHECK(st_storage_reap_dead_control_channels(path, 0, 0, "2026-10-16T00:00:03Z", "RECOVERED", &closed) == 0);
    CHECK(replacement.fired && !replacement.failed && replacement.audit > 0);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE id=%lld AND channel_id='%q' AND status='NETTY_ONLINE'", one.id, channels[2]) == 1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM connection_record WHERE id=%lld AND disconnected_at IS NOT NULL", audit_one) == 1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM connection_record WHERE id=%lld AND disconnected_at IS NULL", replacement.audit) == 1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE id=%lld AND status='NETTY_ONLINE'", two.id) == 1);
    CHECK(st_control_presence_acquire(path, channels[5], &rollback) == 0);
    CHECK(add_native(path, credential.id, "rollback", channels[5], &failed, &audit_failed) == 0);
    st_control_presence_release(rollback, 0); rollback = NULL;
    CHECK(test_sql(path, "CREATE TRIGGER audit_failure BEFORE UPDATE ON connection_record WHEN OLD.id=%lld BEGIN SELECT RAISE(ABORT,'audit failed'); END", audit_failed) == 0);
    CHECK(st_storage_reap_dead_control_channels(path, 0, 0, "2026-10-16T00:00:04Z", "RECOVERED", &closed) == -1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE id=%lld AND status='NETTY_ONLINE'", failed.id) == 1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM connection_record WHERE id=%lld AND disconnected_at IS NULL", audit_failed) == 1);
    CHECK(st_control_presence_probe(path, channels[5]) == ST_CONTROL_PRESENCE_DEAD);
    CHECK(test_sql(path, "DROP TRIGGER audit_failure") == 0);
    CHECK(st_storage_reap_dead_control_channels(path, 0, 0, "2026-10-16T00:00:05Z", "RECOVERED", &closed) == 0);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE id=%lld AND status='DISCONNECTED'", failed.id) == 1);
    CHECK(st_control_presence_probe(path, channels[5]) == ST_CONTROL_PRESENCE_UNKNOWN);
    CHECK(add_native(path, credential.id, "legacy", "killed-legacy-channel", &legacy, &audit_legacy) == 0);
    CHECK(st_storage_reap_dead_control_channels(path, 0, 0, "2026-10-16T00:00:06Z", "RESTART", &closed) == 0 && closed == 1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE id=%lld AND status='DISCONNECTED'", legacy.id) == 1);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE id=%lld AND status='NETTY_ONLINE'", unknown.id) == 1);
    CHECK(test_sql(path, "UPDATE specus_client_session SET status='DISCONNECTED' WHERE id=%lld; UPDATE connection_record SET disconnected_at='terminal' WHERE id=%lld", unknown.id, audit_unknown) == 0);
    st_control_presence_release(peer, 0); st_control_presence_release(winner, 0);
    CHECK(st_storage_reap_dead_control_channels(path, 0, 0, "2026-10-16T00:00:07Z", "RESTART", &closed) == 0 && closed == 2);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM specus_client_session WHERE status='NETTY_ONLINE'") == 0);
    CHECK(test_scalar(path, "SELECT COUNT(*) FROM connection_record WHERE disconnected_at IS NULL") == 0);
    puts("PASS native live/unknown preservation, real post-probe same-SID replacement CAS, audit rollback/retry, legacy recovery and dead-sidecar reclamation");
    return 0;
}
int main(int argc, char **argv)
{
    if (argc == 6 && !strcmp(argv[1], "--exec-probe")) {
        int input = atoi(argv[4]), output = atoi(argv[5]); char byte;
        int ok = read(input, &byte, 1) == 1 && st_control_presence_probe(argv[2], argv[3]) == ST_CONTROL_PRESENCE_DEAD;
        byte = ok ? 'D' : 'X';
        if (write(output, &byte, 1) != 1) ok = 0;
        close(input); close(output); return ok ? 0 : 1;
    }
    char dir[] = "/tmp/specus-presence-XXXXXX", path[512]; CHECK(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/specus.db", dir); CHECK(st_storage_init(path, 0) == 0);
    CHECK(kernel_lifecycle(argv[0], path) == 0 && native_recovery(path, dir) == 0);
    unlink(path); CHECK(rmdir(dir) == 0); return 0;
}
