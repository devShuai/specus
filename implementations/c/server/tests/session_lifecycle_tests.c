/*
 * Session lifecycle tests against a real specus-server-c process.
 *
 * Every scenario starts the server binary with its own SQLite database, logs a client in through
 * the real HTTP endpoint and drives the v2 control/data protocol over real sockets: re-login
 * replacing the previous pair and its NAT streams, a superseded session being refused, a dead
 * channel being cleaned up by the read-idle timeout, stale online rows, and SIGTERM closing every
 * channel and recording it before the process exits. The process and protocol helpers live in
 * server_harness.c.
 *
 * Usage: specus_c_session_lifecycle_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "json.h"
#include "protocol.h"
#include "storage.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Reads the management projection's "online" flag for one client: 1, 0, or -1 on error. */
static int admin_client_online(const test_server *server, const char *client_name)
{
    int status = 0;
    char *response = NULL;
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) {
        return -1;
    }
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    if (token == NULL) {
        return -1;
    }
    response = NULL;
    int rc = http_request(server->admin_port, "GET", "/api/admin/clients", NULL, token, &status, &response);
    free(token);
    if (rc != 0 || status != 200) {
        free(response);
        return -1;
    }
    char needle[320];
    snprintf(needle, sizeof(needle), "\"clientName\":\"%s\"", client_name);
    const char *view = strstr(response, needle);
    const char *online = view == NULL ? NULL : strstr(view, "\"online\":");
    int result = -1;
    if (online != NULL) {
        online += strlen("\"online\":");
        result = strncmp(online, "true", 4) == 0 ? 1 : (strncmp(online, "false", 5) == 0 ? 0 : -1);
    }
    free(response);
    return result;
}

static int session_status(const char *db_path, long long session_id, char *out, size_t out_len)
{
    return db_scalar(db_path, "SELECT status FROM specus_client_session WHERE id = ?", NULL, session_id,
                     out, out_len);
}

static int wait_session_status(const char *db_path, long long session_id, const char *expected, int timeout_ms)
{
    long long deadline = monotonic_ms() + timeout_ms;
    char status[64] = "";
    for (;;) {
        if (session_status(db_path, session_id, status, sizeof(status)) == 0 && strcmp(status, expected) == 0) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "session %lld status %s, expected %s\n", session_id, status, expected);
            return -1;
        }
        sleep_ms(50);
    }
}

/* Waits until a closed connection record of the client carries the given disconnect reason. */
static int wait_connection_reason(const char *db_path, const char *client_name, const char *reason, int timeout_ms)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM connection_record WHERE client_name = ? AND success = 1 "
             "AND disconnect_reason = '%s' AND disconnected_at IS NOT NULL AND disconnected_at <> ''",
             reason);
    long long deadline = monotonic_ms() + timeout_ms;
    char count[32] = "";
    for (;;) {
        if (db_scalar(db_path, sql, client_name, 0, count, sizeof(count)) == 0 && atoi(count) > 0) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "no %s connection record for %s\n", reason, client_name);
            return -1;
        }
        sleep_ms(50);
    }
}

/* ------------------------------------------------------------------------------------------- */
/* Scenarios                                                                                     */

/*
 * The same runtime session logging in again while its previous pair is still bound (a client whose
 * old sockets died without a FIN looks exactly like this to the server) replaces that pair: the old
 * control and data connections and the NAT stream on the old data connection are closed, the
 * public port is free for the new data connection at once, and the session stays NETTY_ONLINE.
 */
static int test_same_session_relogin_replaces_old_pair(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control1 = -1, data1 = -1, control2 = -1, data2 = -1, public_fd = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_relogin", "relogin-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_relogin", "relogin-secret", "machine-relogin", "alice", &runtime) == 0,
          "http login");
    CHECK(create_mapping(server->db_path, runtime.client_id, public_port) == 0, "mapping");

    CHECK(channel_login(server->control_port, &runtime, "control", &control1, reason, sizeof(reason)) == 1,
          "first control login: %s", reason);
    CHECK(channel_login(server->control_port, &runtime, "data", &data1, reason, sizeof(reason)) == 1,
          "first data login: %s", reason);
    CHECK(nat_register(data1, runtime.client_name, public_port, 9) == 0, "first REGISTER");
    CHECK(open_public_stream(data1, public_port, &public_fd) == 0, "public stream OPEN on first data");
    CHECK(admin_client_online(server, runtime.client_name) == 1, "client online before re-login");

    CHECK(channel_login(server->control_port, &runtime, "control", &control2, reason, sizeof(reason)) == 1,
          "re-login of the same session must replace the old control: %s", reason);
    CHECK(expect_channel_closed(control1, IO_TIMEOUT_MS) == 0, "old control was not closed");
    CHECK(expect_channel_closed(data1, IO_TIMEOUT_MS) == 0, "old data was not closed");
    CHECK(expect_socket_eof(public_fd, IO_TIMEOUT_MS) == 0, "NAT stream of the old data was not closed");

    CHECK(channel_login(server->control_port, &runtime, "data", &data2, reason, sizeof(reason)) == 1,
          "data login for the replacing control: %s", reason);
    CHECK(nat_register(data2, runtime.client_name, public_port, 9) == 0,
          "the old data connection still holds the public port");
    CHECK(expect_channel_alive(control2) == 0 && expect_channel_alive(data2) == 0, "new pair not served");
    CHECK(wait_connection_reason(server->db_path, runtime.client_name, "REPLACED_BY_NEW_LOGIN", IO_TIMEOUT_MS) == 0,
          "old control record not stamped REPLACED_BY_NEW_LOGIN");
    char status[64];
    CHECK(session_status(server->db_path, runtime.session_id, status, sizeof(status)) == 0
              && strcmp(status, "NETTY_ONLINE") == 0,
          "the departing old control took the live session offline: %s", status);
    CHECK(admin_client_online(server, runtime.client_name) == 1, "client not online after re-login");

    close_fd(&control2);
    CHECK(expect_channel_closed(data2, IO_TIMEOUT_MS) == 0, "closing the control did not close its data");
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the client left");
    close_fd(&control1);
    close_fd(&data1);
    close_fd(&data2);
    close_fd(&public_fd);
    return 0;
}

/*
 * An ordinary reconnect reuses the runtime session (spec: the token is reusable until it expires),
 * but once a later HTTP login of the same machine user issued a newer session, the old one opens
 * nothing any more. Also covers the same-machine single-instance rule.
 */
static int test_session_reuse_and_supersession(test_server *server)
{
    char reason[256];
    runtime_session first, second, third, fourth;
    int control = -1, data = -1, refused = -1;
    CHECK(create_credential(server->db_path, "ck_reuse", "reuse-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &first) == 0, "login 1");

    for (int round = 0; round < 2; ++round) {
        CHECK(channel_login(server->control_port, &first, "control", &control, reason, sizeof(reason)) == 1,
              "control login round %d with the same session: %s", round, reason);
        CHECK(channel_login(server->control_port, &first, "data", &data, reason, sizeof(reason)) == 1,
              "data login round %d: %s", round, reason);
        close_fd(&data);
        /* As in Java and Go, a data connection going away leaves its control connection alone. */
        CHECK(expect_channel_alive(control) == 0, "round %d: closing the data closed the control", round);
        close_fd(&control);
        CHECK(wait_session_status(server->db_path, first.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
              "round %d: session not DISCONNECTED", round);
    }

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &second) == 0, "login 2");
    CHECK(channel_login(server->control_port, &first, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "superseded session must not open a control channel, got: %s", reason);
    CHECK(channel_login(server->control_port, &second, "control", &control, reason, sizeof(reason)) == 1,
          "control login with the newer session: %s", reason);
    CHECK(channel_login(server->control_port, &first, "data", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "数据连接") != NULL,
          "old session must not attach a data channel, got: %s", reason);
    CHECK(channel_login(server->control_port, &second, "data", &data, reason, sizeof(reason)) == 1,
          "data login with the newer session: %s", reason);

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &third) == 0, "login 3");
    CHECK(channel_login(server->control_port, &third, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "同一台机器和用户已经有在线实例") != NULL,
          "a second live instance of the machine user must be refused, got: %s", reason);
    CHECK(expect_channel_alive(control) == 0, "the refused login disturbed the live control");

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &fourth) == 0, "login 4");
    CHECK(channel_login(server->control_port, &third, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "a session retired before it ever connected must stay unusable, got: %s", reason);

    close_fd(&data);
    close_fd(&control);
    CHECK(wait_session_status(server->db_path, second.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "second session not DISCONNECTED");
    return 0;
}

/* Each TCP connection logs in once; a second LOGIN_REQUEST on it is a protocol violation. */
static int test_second_login_on_one_connection_closes_it(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control = -1;
    CHECK(create_credential(server->db_path, "ck_twice", "twice-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_twice", "twice-secret", "machine-twice", "hank", &runtime) == 0, "login");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(send_login_request(control, &runtime, "control") == 0, "second LOGIN_REQUEST");
    CHECK(expect_channel_closed(control, IO_TIMEOUT_MS) == 0, "a second login on one connection was tolerated");
    CHECK(wait_connection_reason(server->db_path, runtime.client_name, "PROTOCOL_VIOLATION", IO_TIMEOUT_MS) == 0,
          "violation not recorded");
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the violation");
    close_fd(&control);
    return 0;
}

static int test_credential_online_limit(test_server *server)
{
    char reason[256];
    runtime_session machine_a, machine_b;
    int control_a = -1, control_b = -1;
    CHECK(create_credential(server->db_path, "ck_limit", "limit-secret", 1) == 0, "credential");
    CHECK(http_client_login(server, "ck_limit", "limit-secret", "machine-limit-a", "carol", &machine_a) == 0, "login a");
    CHECK(http_client_login(server, "ck_limit", "limit-secret", "machine-limit-b", "carol", &machine_b) == 0, "login b");
    CHECK(channel_login(server->control_port, &machine_a, "control", &control_a, reason, sizeof(reason)) == 1,
          "machine a: %s", reason);
    CHECK(channel_login(server->control_port, &machine_b, "control", &control_b, reason, sizeof(reason)) == 0
              && strstr(reason, "在线实例数已达上限") != NULL,
          "maxOnlineInstances=1 must refuse a second machine, got: %s", reason);
    close_fd(&control_a);
    CHECK(wait_session_status(server->db_path, machine_a.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "machine a not DISCONNECTED");
    CHECK(channel_login(server->control_port, &machine_b, "control", &control_b, reason, sizeof(reason)) == 1,
          "machine b once a left: %s", reason);
    close_fd(&control_b);
    return 0;
}

/*
 * A NETTY_ONLINE row whose session no bound control carries (a disconnect whose DISCONNECTED write
 * was lost) must not lock the machine user out: the next control login closes it first.
 */
static int test_stale_online_row_is_closed(test_server *server)
{
    char reason[256];
    runtime_session stale, fresh;
    int control = -1;
    CHECK(create_credential(server->db_path, "ck_stale_row", "stale-row-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_stale_row", "stale-row-secret", "machine-stale", "dave", &stale) == 0,
          "login 1");
    CHECK(st_storage_mark_client_session_online(server->db_path, stale.session_id, "lost-channel",
                                                "127.0.0.1:1", "2026-01-01T00:00:00Z") == 0,
          "mark stale row online");
    CHECK(http_client_login(server, "ck_stale_row", "stale-row-secret", "machine-stale", "dave", &fresh) == 0,
          "login 2");
    CHECK(channel_login(server->control_port, &fresh, "control", &control, reason, sizeof(reason)) == 1,
          "a stale online row blocked the machine user: %s", reason);
    CHECK(wait_session_status(server->db_path, stale.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "stale row not closed");
    close_fd(&control);
    return 0;
}

/*
 * With more than one instance allowed per machine user, a control login of a newer session takes
 * the client over: the previous pair and its NAT stream close, and the previous session can neither
 * attach a data connection nor open a control channel again.
 */
static int test_new_session_replaces_previous_session(test_server *server)
{
    char reason[256];
    runtime_session old_session, new_session;
    int control1 = -1, data1 = -1, control2 = -1, data2 = -1, refused = -1, public_fd = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_replace", "replace-secret", 3) == 0, "credential");
    CHECK(http_client_login(server, "ck_replace", "replace-secret", "machine-replace", "erin", &old_session) == 0,
          "login 1");
    CHECK(create_mapping(server->db_path, old_session.client_id, public_port) == 0, "mapping");
    CHECK(channel_login(server->control_port, &old_session, "control", &control1, reason, sizeof(reason)) == 1,
          "old control: %s", reason);
    CHECK(channel_login(server->control_port, &old_session, "data", &data1, reason, sizeof(reason)) == 1,
          "old data: %s", reason);
    CHECK(nat_register(data1, old_session.client_name, public_port, 9) == 0, "old REGISTER");
    CHECK(open_public_stream(data1, public_port, &public_fd) == 0, "public stream OPEN");

    CHECK(http_client_login(server, "ck_replace", "replace-secret", "machine-replace", "erin", &new_session) == 0,
          "login 2");
    CHECK(strcmp(new_session.client_name, old_session.client_name) == 0, "same machine user, same client");
    CHECK(channel_login(server->control_port, &new_session, "control", &control2, reason, sizeof(reason)) == 1,
          "new session control: %s", reason);
    CHECK(expect_channel_closed(control1, IO_TIMEOUT_MS) == 0, "old control was not closed");
    CHECK(expect_channel_closed(data1, IO_TIMEOUT_MS) == 0, "old data was not closed");
    CHECK(expect_socket_eof(public_fd, IO_TIMEOUT_MS) == 0, "old NAT stream was not closed");

    CHECK(channel_login(server->control_port, &old_session, "data", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "数据连接") != NULL,
          "old session attached a data connection, got: %s", reason);
    CHECK(channel_login(server->control_port, &old_session, "control", &refused, reason, sizeof(reason)) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "old session reopened a control channel, got: %s", reason);
    CHECK(wait_session_status(server->db_path, old_session.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "old session not DISCONNECTED");
    char status[64];
    CHECK(session_status(server->db_path, new_session.session_id, status, sizeof(status)) == 0
              && strcmp(status, "NETTY_ONLINE") == 0,
          "new session status %s", status);
    CHECK(wait_connection_reason(server->db_path, old_session.client_name, "REPLACED_BY_NEW_LOGIN",
                                 IO_TIMEOUT_MS) == 0,
          "replaced control not recorded");

    CHECK(channel_login(server->control_port, &new_session, "data", &data2, reason, sizeof(reason)) == 1,
          "new session data: %s", reason);
    CHECK(nat_register(data2, new_session.client_name, public_port, 9) == 0, "public port not released");
    CHECK(expect_channel_alive(control2) == 0 && expect_channel_alive(data2) == 0, "new pair not served");
    close_fd(&control2);
    close_fd(&data2);
    close_fd(&control1);
    close_fd(&data1);
    close_fd(&public_fd);
    return 0;
}

/*
 * A pair whose peer went silent without a FIN is torn down by the read-idle timeout and stops
 * counting as online: the management view shows it offline and a new session of the same machine
 * user is admitted.
 */
static int test_dead_channel_is_cleaned_up(test_server *server)
{
    char reason[256];
    runtime_session dead, fresh;
    int control = -1, data = -1;
    CHECK(create_credential(server->db_path, "ck_idle", "idle-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_idle", "idle-secret", "machine-idle", "frank", &dead) == 0, "login 1");
    CHECK(channel_login(server->control_port, &dead, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, &dead, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);
    CHECK(admin_client_online(server, dead.client_name) == 1, "client not online while connected");

    /* From here on the client sends nothing, exactly like a peer that vanished. */
    CHECK(expect_channel_closed(control, 15000) == 0, "silent control was not closed by the idle timeout");
    CHECK(expect_channel_closed(data, 15000) == 0, "silent data was not closed");
    CHECK(wait_session_status(server->db_path, dead.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "dead session still online");
    CHECK(wait_connection_reason(server->db_path, dead.client_name, "IDLE_TIMEOUT", IO_TIMEOUT_MS) == 0,
          "idle timeout not recorded");
    CHECK(admin_client_online(server, dead.client_name) == 0, "dead channel keeps the client online");

    close_fd(&control);
    close_fd(&data);
    CHECK(http_client_login(server, "ck_idle", "idle-secret", "machine-idle", "frank", &fresh) == 0, "login 2");
    CHECK(channel_login(server->control_port, &fresh, "control", &control, reason, sizeof(reason)) == 1,
          "the dead channel still blocks the machine user: %s", reason);
    close_fd(&control);
    return 0;
}

/*
 * SIGTERM closes every channel (logged in or not) and every NAT stream, each control records its
 * own disconnect as SERVER_SHUTDOWN and takes its session offline, and only then does the process
 * exit with status 0.
 */
static int test_sigterm_closes_channels_before_exit(test_server *server, runtime_session *runtime)
{
    char reason[256];
    int control = -1, data = -1, public_fd = -1, pre_auth = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_shutdown", "shutdown-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_shutdown", "shutdown-secret", "machine-shutdown", "gina", runtime) == 0,
          "http login");
    CHECK(create_mapping(server->db_path, runtime->client_id, public_port) == 0, "mapping");
    CHECK(channel_login(server->control_port, runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, runtime, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);
    CHECK(nat_register(data, runtime->client_name, public_port, 9) == 0, "REGISTER");
    CHECK(open_public_stream(data, public_port, &public_fd) == 0, "public stream OPEN");
    CHECK(expect_channel_alive(control) == 0, "control idle in its read loop");
    pre_auth = connect_local(server->control_port);
    CHECK(pre_auth >= 0, "pre-auth connection");

    CHECK(kill(server->pid, SIGTERM) == 0, "SIGTERM");
    CHECK(expect_channel_closed(control, 10000) == 0, "control not closed at shutdown");
    CHECK(expect_channel_closed(data, 10000) == 0, "data not closed at shutdown");
    CHECK(expect_socket_eof(public_fd, 10000) == 0, "NAT stream not closed at shutdown");
    CHECK(expect_socket_eof(pre_auth, 10000) == 0, "pre-auth connection not closed at shutdown");
    int exit_status = server_stop(server, 20000);
    CHECK(exit_status == 0, "server exit status %d", exit_status);

    char status[64];
    CHECK(session_status(server->db_path, runtime->session_id, status, sizeof(status)) == 0
              && strcmp(status, "DISCONNECTED") == 0,
          "session left %s by the shutdown", status);
    CHECK(wait_connection_reason(server->db_path, runtime->client_name, "SERVER_SHUTDOWN", 0) == 0,
          "control record not stamped SERVER_SHUTDOWN");
    char open_records[32];
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) FROM connection_record WHERE disconnected_at IS NULL OR disconnected_at = ''",
                    NULL, 0, open_records, sizeof(open_records)) == 0
              && strcmp(open_records, "0") == 0,
          "%s connection record(s) left open", open_records);
    FILE *log = fopen(server->log_path, "r");
    int drained = 0;
    if (log != NULL) {
        char line[1024];
        while (fgets(line, sizeof(line), log) != NULL) {
            if (strstr(line, "[server] stopped: 0 connection(s) unfinished") != NULL) {
                drained = 1;
            }
        }
        fclose(log);
    }
    CHECK(drained, "channels did not all finish their own bookkeeping before the process exited");
    close_fd(&control);
    close_fd(&data);
    close_fd(&public_fd);
    close_fd(&pre_auth);
    return 0;
}

/* A restart closes what a process that never shut down cleanly left online or open. */
static int test_restart_closes_leftover_state(test_server *server, const runtime_session *runtime)
{
    long long record_id = 0;
    CHECK(st_storage_mark_client_session_online(server->db_path, runtime->session_id, "killed-channel",
                                                "127.0.0.1:1", "2026-01-01T00:00:00Z") == 0,
          "leftover online session");
    CHECK(st_storage_record_connection_detail_with_tenant_and_id(server->db_path, "default", runtime->client_id,
                                                                 runtime->client_name, NULL, "127.0.0.1:1", 1,
                                                                 NULL, NULL, "2026-01-01T00:00:00Z", NULL,
                                                                 &record_id) == 0,
          "leftover open connection record");
    CHECK(server_start(server) == 0, "restart");
    char status[64];
    CHECK(session_status(server->db_path, runtime->session_id, status, sizeof(status)) == 0
              && strcmp(status, "DISCONNECTED") == 0,
          "leftover session still %s after restart", status);
    char reason[64];
    CHECK(db_scalar(server->db_path, "SELECT COALESCE(disconnect_reason, '') FROM connection_record WHERE id = ?",
                    NULL, record_id, reason, sizeof(reason)) == 0
              && strcmp(reason, "SERVER_RESTARTED") == 0,
          "leftover record reason '%s'", reason);
    CHECK(server_stop(server, 20000) == 0, "second shutdown");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */

static int scenario_default_limits(test_server *server)
{
    return test_same_session_relogin_replaces_old_pair(server)
        || test_session_reuse_and_supersession(server)
        || test_second_login_on_one_connection_closes_it(server)
        || test_credential_online_limit(server)
        || test_stale_online_row_is_closed(server);
}

static int scenario_shutdown_and_restart(test_server *server)
{
    runtime_session runtime;
    return test_sigterm_closes_channels_before_exit(server, &runtime)
        || test_restart_closes_leftover_state(server, &runtime);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    static const char *const two_per_machine[] = {"SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES=2", NULL};
    static const char *const short_idle[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=5", NULL};
    int failures = 0;
    failures += run_on_fresh_server("relogin, supersession, single login, online limits, stale rows",
                                    scenario_default_limits, NULL);
    failures += run_on_fresh_server("new session replaces previous session",
                                    test_new_session_replaces_previous_session, two_per_machine);
    failures += run_on_fresh_server("dead channel cleanup", test_dead_channel_is_cleaned_up, short_idle);
    failures += run_on_fresh_server("SIGTERM shutdown and restart cleanup", scenario_shutdown_and_restart, NULL);
    if (failures != 0) {
        fprintf(stderr, "%d session lifecycle scenario(s) failed\n", failures);
        return 1;
    }
    printf("session lifecycle tests passed\n");
    return 0;
}
