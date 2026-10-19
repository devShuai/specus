#define _POSIX_C_SOURCE 200809L
#include "server_harness.h"
#include "instant.h"
#include "storage.h"
#include <signal.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

static int execute(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    int ok = sqlite3_open(path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
    if (!ok && db != NULL) fprintf(stderr, "rate fixture SQL: %s\n", sqlite3_errmsg(db));
    sqlite3_close(db);
    return ok ? 0 : -1;
}

static int set_limit(const test_server *server, long long id, int limit)
{
    char sql[192];
    snprintf(sql, sizeof(sql), "UPDATE client_account SET connection_limit_per_minute=%d WHERE rowid=%lld", limit, id);
    return execute(server->db_path, sql);
}

static long long rows(const test_server *server, long long client_id)
{
    char count[32];
    return db_scalar(server->db_path,
        "SELECT count(*) FROM connection_record WHERE tenant_id='default' AND client_id=?",
        NULL, client_id, count, sizeof(count)) == 0 ? strtoll(count, NULL, 10) : -1;
}

static int wait_rows(const test_server *server, long long id, long long expected)
{
    long long end = monotonic_ms() + IO_TIMEOUT_MS;
    do {
        if (rows(server, id) == expected) return 0;
        sleep_ms(10);
    } while (monotonic_ms() < end);
    return -1;
}

static int setup(test_server *server, runtime_session *runtime, int limit)
{
    CHECK(create_credential(server->db_path, "rate-key", "rate-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "rate-key", "rate-secret", "rate-machine", "rate-user", runtime) == 0, "HTTP login");
    CHECK(set_limit(server, runtime->client_id, limit) == 0, "limit");
    return 0;
}

static int seed(const test_server *server, const runtime_session *runtime, const char *tenant,
                long long id, int success, const char *when)
{
    return st_storage_record_connection_detail_with_tenant_and_id(server->db_path, tenant, id,
        runtime->client_name, NULL, "127.0.0.1", success, success ? NULL : "seed refusal",
        "CLIENT_CLOSED", when, when, NULL);
}

/* EOF proves the refusal path finished its record write before the database is inspected. */
static int refused(const test_server *server, const runtime_session *runtime, const char *role, const char *expected)
{
    int fd = connect_local(server->control_port), command = 0, success = 1;
    char reason[256] = "";
    int ok = fd >= 0 && send_login_request(fd, runtime, role) == 0
        && read_login_response(fd, IO_TIMEOUT_MS, &command, &success, reason, sizeof(reason)) == 1
        && !success && strcmp(reason, expected) == 0 && expect_channel_closed(fd, IO_TIMEOUT_MS) == 0;
    close_fd(&fd);
    CHECK(ok, "expected refusal %s, got success=%d reason=%s", expected, success, reason);
    return 0;
}

static int admission(test_server *server)
{
    runtime_session runtime;
    CHECK(setup(server, &runtime, 3) == 0, "setup");
    CHECK(refused(server, &runtime, "data", "数据连接要求控制连接先登录") == 0, "data before control");
    char all_rows[32];
    CHECK(db_scalar(server->db_path, "SELECT count(*) FROM connection_record WHERE ?=1", NULL, 1,
        all_rows, sizeof(all_rows)) == 0 && strcmp(all_rows, "0") == 0,
        "a refused data connection created a control record");
    char now[ST_INSTANT_CAPACITY], old[ST_INSTANT_CAPACITY], recent[ST_INSTANT_CAPACITY];
    CHECK(st_instant_now(now) == 0 && st_instant_add_seconds(now, -90, old) == 0
        && st_instant_add_seconds(now, -30, recent) == 0, "time fixture");
    for (int i = 0; i < 3; ++i) {
        CHECK(seed(server, &runtime, "default", runtime.client_id, 1, old) == 0, "expired row");
        CHECK(seed(server, &runtime, "foreign", runtime.client_id, 1, now) == 0, "foreign tenant");
        CHECK(seed(server, &runtime, "default", runtime.client_id + 1000, 1, now) == 0, "other client");
    }
    int control = -1, data = -1;
    char reason[256], before[ST_INSTANT_CAPACITY], after[ST_INSTANT_CAPACITY], recorded[64] = "";
    CHECK(st_instant_now(before) == 0, "before login");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
        "old/foreign records blocked control: %s", reason);
    CHECK(wait_rows(server, runtime.client_id, 4) == 0 && st_instant_now(after) == 0, "accepted control record");
    CHECK(db_scalar(server->db_path,
        "SELECT connected_at FROM connection_record WHERE tenant_id='default' AND client_id=? ORDER BY id DESC LIMIT 1",
        NULL, runtime.client_id, recorded, sizeof(recorded)) == 0
        && strlen(recorded) == 28U && strcmp(recorded, before) >= 0 && strcmp(recorded, after) <= 0,
        "runtime connection timestamp lost request precision: %s", recorded);
    for (int i = 0; i < 2; ++i) CHECK(seed(server, &runtime, "default", runtime.client_id, 0, recent) == 0, "failed attempt");
    runtime_session renamed_request = runtime;
    snprintf(renamed_request.client_name, sizeof(renamed_request.client_name), "untrusted-old-name");
    CHECK(refused(server, &renamed_request, "control", "连接频率超过限制") == 0, "control rate");
    CHECK(rows(server, runtime.client_id) == 7, "refusal was not counted under the authenticated client");
    char identity[256] = "";
    CHECK(db_scalar(server->db_path,
        "SELECT client_name FROM connection_record WHERE tenant_id='default' AND client_id=? AND success=0 AND reason='连接频率超过限制' ORDER BY id DESC LIMIT 1",
        NULL, runtime.client_id, identity, sizeof(identity)) == 0 && strcmp(identity, runtime.client_name) == 0,
        "refusal identity came from the request: %s", identity);
    CHECK(expect_channel_alive(control) == 0, "a refused replacement displaced the online control");
    CHECK(channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) == 1,
        "quota blocked data: %s", reason);
    CHECK(expect_channel_alive(data) == 0 && rows(server, runtime.client_id) == 7, "data consumed quota");
    close_fd(&data); close_fd(&control);
    return 0;
}

static int at_limit(test_server *server)
{
    runtime_session runtime;
    CHECK(setup(server, &runtime, 1) == 0, "setup");
    char now[ST_INSTANT_CAPACITY]; CHECK(st_instant_now(now) == 0, "now");
    CHECK(seed(server, &runtime, "default", runtime.client_id, 0, now) == 0, "failed attempt");
    CHECK(refused(server, &runtime, "control", "连接频率超过限制") == 0, "limit must apply before activation");
    CHECK(rows(server, runtime.client_id) == 2, "refusal not counted");
    return 0;
}

static int tenant_refusal(test_server *server)
{
    runtime_session runtime;
    CHECK(setup(server, &runtime, 1) == 0, "setup");
    char sql[512], now[ST_INSTANT_CAPACITY];
    snprintf(sql, sizeof(sql),
        "UPDATE client_account SET tenant_id='rate-tenant' WHERE rowid=%lld;"
        "UPDATE specus_client_credential SET tenant_id='rate-tenant' WHERE id=(SELECT credential_id FROM specus_client_session WHERE id=%lld);"
        "UPDATE specus_client_session SET tenant_id='rate-tenant' WHERE id=%lld;",
        runtime.client_id, runtime.session_id, runtime.session_id);
    CHECK(execute(server->db_path, sql) == 0 && st_instant_now(now) == 0, "tenant fixture");
    CHECK(seed(server, &runtime, "rate-tenant", runtime.client_id, 0, now) == 0, "tenant limit");
    runtime_session spoofed = runtime;
    snprintf(spoofed.client_name, sizeof(spoofed.client_name), "spoofed-name");
    CHECK(refused(server, &spoofed, "control", "连接频率超过限制") == 0, "tenant control");
    char name[256] = "";
    CHECK(db_scalar(server->db_path,
        "SELECT client_name FROM connection_record WHERE tenant_id='rate-tenant' AND client_id=? AND reason='连接频率超过限制'",
        NULL, runtime.client_id, name, sizeof(name)) == 0 && strcmp(name, runtime.client_name) == 0
        && rows(server, runtime.client_id) == 0, "failure escaped its authenticated tenant: %s", name);
    return 0;
}

static int disabled(test_server *server)
{
    runtime_session runtime;
    CHECK(setup(server, &runtime, 0) == 0, "setup");
    char now[ST_INSTANT_CAPACITY]; CHECK(st_instant_now(now) == 0, "now");
    for (int i = 0; i < 35; ++i) CHECK(seed(server, &runtime, "default", runtime.client_id, 0, now) == 0, "seed");
    for (int limit = 0; limit >= -1; --limit) {
        int control = -1; char reason[256];
        CHECK(set_limit(server, runtime.client_id, limit) == 0, "disable limit");
        CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
            "nonpositive limit=%d rejected: %s", limit, reason);
        CHECK(expect_channel_alive(control) == 0, "control");
        close_fd(&control);
    }
    return 0;
}

static int unavailable(test_server *server)
{
    runtime_session runtime;
    CHECK(setup(server, &runtime, 3) == 0, "setup");
    CHECK(execute(server->db_path, "ALTER TABLE connection_record RENAME TO unavailable_connection_record") == 0, "hide table");
    int result = refused(server, &runtime, "control", "客户端连接频率状态不可用");
    if (result != 0) return 1;
    CHECK(execute(server->db_path, "ALTER TABLE unavailable_connection_record RENAME TO connection_record") == 0, "restore table");
    char status[64] = "";
    CHECK(db_scalar(server->db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
        runtime.session_id, status, sizeof(status)) == 0 && strcmp(status, "HTTP_AUTHENTICATED") == 0,
        "failed count activated the session: %s", status);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) return 2;
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IOLBF, 0);
    int mode = argc > 2 ? atoi(argv[2]) : -1, failed = 0;
    if (mode < 0 || mode == 0) failed += run_on_fresh_server("control rate scope, failures, data exemption and precise records", admission, NULL);
    if (mode < 0 || mode == 1) failed += run_on_fresh_server("nonpositive control rate disables the gate", disabled, NULL);
    if (mode < 0 || mode == 2) failed += run_on_fresh_server("control rate storage errors refuse admission", unavailable, NULL);
    if (mode < 0 || mode == 3) failed += run_on_fresh_server("control at its rate limit is refused before activation", at_limit, NULL);
    if (mode < 0 || mode == 4) failed += run_on_fresh_server("control refusal retains authenticated tenant and current name", tenant_refusal, NULL);
    return failed ? 1 : 0;
}
