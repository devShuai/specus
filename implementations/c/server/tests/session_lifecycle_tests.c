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

/* An admin bearer token from the real /auth/login, or NULL; the caller frees it. */
static char *admin_access_token(const test_server *server)
{
    int status = 0;
    char *response = NULL;
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) {
        return NULL;
    }
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    return token;
}

/* Reads the management projection's "online" flag for one client: 1, 0, or -1 on error. */
static int admin_client_online(const test_server *server, const char *client_name)
{
    char *token = admin_access_token(server);
    if (token == NULL) {
        return -1;
    }
    int status = 0;
    char *response = NULL;
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
    long long started = monotonic_ms();
    long long deadline = started + timeout_ms;
    char status[64] = "";
    for (;;) {
        int rc = session_status(db_path, session_id, status, sizeof(status));
        if (rc == 0 && strcmp(status, expected) == 0) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "session %lld is %s after %lld ms, expected %s\n", session_id,
                    rc == 0 ? status : (rc == 1 ? "missing" : "unreadable"), monotonic_ms() - started, expected);
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
            char records[2048] = "";
            db_scalar(db_path,
                      "SELECT COALESCE(group_concat(id || '|' || success || '|' || COALESCE(disconnect_reason, 'NULL')"
                      " || '|' || COALESCE(disconnected_at, 'NULL'), ', '), 'none') FROM connection_record"
                      " WHERE client_name = ?",
                      client_name, 0, records, sizeof(records));
            fprintf(stderr, "no closed %s connection record for %s within %d ms; its records "
                    "(id|success|disconnect reason|disconnected at): %s\n",
                    reason, client_name, timeout_ms, records);
            return -1;
        }
        sleep_ms(50);
    }
}

/* ------------------------------------------------------------------------------------------- */
/* Scenarios                                                                                     */

/*
 * The scenarios report errno and one of them forks a server of its own (sigterm_at_first_accept),
 * so they include what that needs themselves instead of relying on the process helpers above.
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * The server gives its channels up to 10 s (ST_SHUTDOWN_DRAIN_SECONDS) to finish at shutdown. The
 * shutdown checks wait for the event itself (an EOF, the exit) and give up only well past that, so
 * a slow, loaded runner is not mistaken for a server that never closed or never exited.
 */
#define SHUTDOWN_TIMEOUT_MS 30000
#define SERVER_START_TIMEOUT_MS 30000

/*
 * TIMED(call) runs a helper that only answers pass or fail and keeps how long it took, so a failed
 * check can say whether its wait ran out or the helper failed early (see timed_outcome).
 */
static long long timed_started_ms;
static long long timed_ms;
static int timed_rc;
#define TIMED(call) \
    (timed_started_ms = monotonic_ms(), timed_rc = (call), timed_ms = monotonic_ms() - timed_started_ms, timed_rc)

/* Why the last TIMED call, bounded by bound_ms, failed. */
static const char *timed_outcome(int bound_ms)
{
    static char text[200];
    if (timed_ms >= bound_ms) {
        snprintf(text, sizeof(text), "nothing happened before the %d ms wait ran out", bound_ms);
    } else {
        snprintf(text, sizeof(text), "it failed after %lld ms of its %d ms bound (the socket closed or errored, "
                 "or the server answered something else)", timed_ms, bound_ms);
    }
    return text;
}

/* admin_client_online's answer, for a check message. */
static const char *online_text(int online)
{
    return online == 1 ? "true" : (online == 0 ? "false" : "unknown (the admin API request failed)");
}

/* How the last TIMED channel_login ended, for a check that expected a refusal. */
static const char *login_outcome(void)
{
    return timed_rc == 1 ? "an accepted login" : (timed_rc == 0 ? "a refusal" : "no login answer");
}

/* What server_stop's result says about how the server ended. */
static const char *describe_server_exit(int exit_status, char *out, size_t out_len)
{
    if (exit_status == -1) {
        snprintf(out, out_len, "still running when the wait ran out, so it was killed");
    } else if (exit_status > 1000) {
        snprintf(out, out_len, "killed by signal %d (%s)", exit_status - 1000, strsignal(exit_status - 1000));
    } else if (exit_status == 128 + SIGTERM) {
        snprintf(out, out_len, "exit status %d: SIGTERM took the \"outside the serving loop\" exit, "
                 "not the graceful shutdown", exit_status);
    } else {
        snprintf(out, out_len, "exit status %d", exit_status);
    }
    return out;
}

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
    CHECK(public_port > 0, "no free port for the public mapping");
    CHECK(create_credential(server->db_path, "ck_relogin", "relogin-secret", 2) == 0,
          "credential ck_relogin not stored");
    CHECK(http_client_login(server, "ck_relogin", "relogin-secret", "machine-relogin", "alice", &runtime) == 0,
          "http login (status and body above)");
    CHECK(create_mapping(server->db_path, runtime.client_id, public_port) == 0,
          "mapping of port %d not stored", public_port);

    CHECK(channel_login(server->control_port, &runtime, "control", &control1, reason, sizeof(reason)) == 1,
          "first control login: %s", reason);
    CHECK(channel_login(server->control_port, &runtime, "data", &data1, reason, sizeof(reason)) == 1,
          "first data login: %s", reason);
    CHECK(TIMED(nat_register(data1, runtime.client_name, public_port, 9)) == 0,
          "first REGISTER of port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(open_public_stream(data1, public_port, &public_fd)) == 0,
          "no OPEN on the first data for a connection to port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    int online = admin_client_online(server, runtime.client_name);
    CHECK(online == 1, "client not online before re-login: management view online=%s", online_text(online));

    CHECK(channel_login(server->control_port, &runtime, "control", &control2, reason, sizeof(reason)) == 1,
          "re-login of the same session must replace the old control: %s", reason);
    CHECK(TIMED(expect_channel_closed(control1, IO_TIMEOUT_MS)) == 0,
          "old control was not closed: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_closed(data1, IO_TIMEOUT_MS)) == 0,
          "old data was not closed: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_socket_eof(public_fd, IO_TIMEOUT_MS)) == 0,
          "NAT stream of the old data was not closed: %s", timed_outcome(IO_TIMEOUT_MS));

    CHECK(channel_login(server->control_port, &runtime, "data", &data2, reason, sizeof(reason)) == 1,
          "data login for the replacing control: %s", reason);
    CHECK(TIMED(nat_register(data2, runtime.client_name, public_port, 9)) == 0,
          "the old data connection still holds the public port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_alive(control2)) == 0, "new control not served: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_alive(data2)) == 0, "new data not served: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(wait_connection_reason(server->db_path, runtime.client_name, "REPLACED_BY_NEW_LOGIN", IO_TIMEOUT_MS) == 0,
          "old control record not stamped REPLACED_BY_NEW_LOGIN");
    char status[64];
    CHECK(session_status(server->db_path, runtime.session_id, status, sizeof(status)) == 0
              && strcmp(status, "NETTY_ONLINE") == 0,
          "the departing old control took the live session offline: session %lld is '%s', expected NETTY_ONLINE",
          runtime.session_id, status);
    online = admin_client_online(server, runtime.client_name);
    CHECK(online == 1, "client not online after re-login: management view online=%s", online_text(online));

    close_fd(&control2);
    CHECK(TIMED(expect_channel_closed(data2, IO_TIMEOUT_MS)) == 0,
          "closing the control did not close its data: %s", timed_outcome(IO_TIMEOUT_MS));
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
    CHECK(create_credential(server->db_path, "ck_reuse", "reuse-secret", 2) == 0, "credential ck_reuse not stored");
    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &first) == 0,
          "login 1 (status and body above)");

    for (int round = 0; round < 2; ++round) {
        CHECK(channel_login(server->control_port, &first, "control", &control, reason, sizeof(reason)) == 1,
              "control login round %d with the same session: %s", round, reason);
        CHECK(channel_login(server->control_port, &first, "data", &data, reason, sizeof(reason)) == 1,
              "data login round %d: %s", round, reason);
        close_fd(&data);
        /* As in Java and Go, a data connection going away leaves its control connection alone. */
        CHECK(TIMED(expect_channel_alive(control)) == 0, "round %d: closing the data closed the control: %s",
              round, timed_outcome(IO_TIMEOUT_MS));
        close_fd(&control);
        CHECK(wait_session_status(server->db_path, first.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
              "round %d: session not DISCONNECTED", round);
    }

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &second) == 0,
          "login 2 (status and body above)");
    CHECK(TIMED(channel_login(server->control_port, &first, "control", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "superseded session must not open a control channel; expected a 访问令牌无效 refusal, got %s: %s",
          login_outcome(), reason);
    CHECK(channel_login(server->control_port, &second, "control", &control, reason, sizeof(reason)) == 1,
          "control login with the newer session: %s", reason);
    CHECK(TIMED(channel_login(server->control_port, &first, "data", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "数据连接") != NULL,
          "old session must not attach a data channel; expected a 数据连接 refusal, got %s: %s",
          login_outcome(), reason);
    CHECK(channel_login(server->control_port, &second, "data", &data, reason, sizeof(reason)) == 1,
          "data login with the newer session: %s", reason);

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &third) == 0,
          "login 3 (status and body above)");
    CHECK(TIMED(channel_login(server->control_port, &third, "control", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "同一台机器和用户已经有在线实例") != NULL,
          "a second live instance of the machine user must be refused; expected a 同一台机器和用户已经有在线实例 "
          "refusal, got %s: %s", login_outcome(), reason);
    CHECK(TIMED(expect_channel_alive(control)) == 0, "the refused login disturbed the live control: %s",
          timed_outcome(IO_TIMEOUT_MS));

    CHECK(http_client_login(server, "ck_reuse", "reuse-secret", "machine-reuse", "bob", &fourth) == 0,
          "login 4 (status and body above)");
    CHECK(TIMED(channel_login(server->control_port, &third, "control", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "a session retired before it ever connected must stay unusable; expected a 访问令牌无效 refusal, got %s: %s",
          login_outcome(), reason);

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
    CHECK(create_credential(server->db_path, "ck_twice", "twice-secret", 2) == 0, "credential ck_twice not stored");
    CHECK(http_client_login(server, "ck_twice", "twice-secret", "machine-twice", "hank", &runtime) == 0,
          "login (status and body above)");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(send_login_request(control, &runtime, "control") == 0, "second LOGIN_REQUEST not sent: %s", strerror(errno));
    CHECK(TIMED(expect_channel_closed(control, IO_TIMEOUT_MS)) == 0,
          "a second login on one connection was tolerated: %s", timed_outcome(IO_TIMEOUT_MS));
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
    CHECK(create_credential(server->db_path, "ck_limit", "limit-secret", 1) == 0, "credential ck_limit not stored");
    CHECK(http_client_login(server, "ck_limit", "limit-secret", "machine-limit-a", "carol", &machine_a) == 0,
          "login a (status and body above)");
    CHECK(http_client_login(server, "ck_limit", "limit-secret", "machine-limit-b", "carol", &machine_b) == 0,
          "login b (status and body above)");
    CHECK(channel_login(server->control_port, &machine_a, "control", &control_a, reason, sizeof(reason)) == 1,
          "machine a: %s", reason);
    CHECK(TIMED(channel_login(server->control_port, &machine_b, "control", &control_b, reason, sizeof(reason))) == 0
              && strstr(reason, "在线实例数已达上限") != NULL,
          "maxOnlineInstances=1 must refuse a second machine; expected a 在线实例数已达上限 refusal, got %s: %s",
          login_outcome(), reason);
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
    CHECK(create_credential(server->db_path, "ck_stale_row", "stale-row-secret", 2) == 0,
          "credential ck_stale_row not stored");
    CHECK(http_client_login(server, "ck_stale_row", "stale-row-secret", "machine-stale", "dave", &stale) == 0,
          "login 1 (status and body above)");
    CHECK(st_storage_mark_client_session_online(server->db_path, stale.session_id, "lost-channel",
                                                "127.0.0.1:1", "2026-01-01T00:00:00Z") == 0,
          "could not mark session %lld online", stale.session_id);
    CHECK(http_client_login(server, "ck_stale_row", "stale-row-secret", "machine-stale", "dave", &fresh) == 0,
          "login 2 (status and body above)");
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
    CHECK(public_port > 0, "no free port for the public mapping");
    CHECK(create_credential(server->db_path, "ck_replace", "replace-secret", 3) == 0,
          "credential ck_replace not stored");
    CHECK(http_client_login(server, "ck_replace", "replace-secret", "machine-replace", "erin", &old_session) == 0,
          "login 1 (status and body above)");
    CHECK(create_mapping(server->db_path, old_session.client_id, public_port) == 0,
          "mapping of port %d not stored", public_port);
    CHECK(channel_login(server->control_port, &old_session, "control", &control1, reason, sizeof(reason)) == 1,
          "old control: %s", reason);
    CHECK(channel_login(server->control_port, &old_session, "data", &data1, reason, sizeof(reason)) == 1,
          "old data: %s", reason);
    CHECK(TIMED(nat_register(data1, old_session.client_name, public_port, 9)) == 0,
          "old REGISTER of port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(open_public_stream(data1, public_port, &public_fd)) == 0,
          "no OPEN for a connection to port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));

    CHECK(http_client_login(server, "ck_replace", "replace-secret", "machine-replace", "erin", &new_session) == 0,
          "login 2 (status and body above)");
    CHECK(strcmp(new_session.client_name, old_session.client_name) == 0,
          "same machine user, same client: got %s after %s", new_session.client_name, old_session.client_name);
    CHECK(channel_login(server->control_port, &new_session, "control", &control2, reason, sizeof(reason)) == 1,
          "new session control: %s", reason);
    CHECK(TIMED(expect_channel_closed(control1, IO_TIMEOUT_MS)) == 0,
          "old control was not closed: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_closed(data1, IO_TIMEOUT_MS)) == 0,
          "old data was not closed: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_socket_eof(public_fd, IO_TIMEOUT_MS)) == 0,
          "old NAT stream was not closed: %s", timed_outcome(IO_TIMEOUT_MS));

    CHECK(TIMED(channel_login(server->control_port, &old_session, "data", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "数据连接") != NULL,
          "old session attached a data connection; expected a 数据连接 refusal, got %s: %s", login_outcome(), reason);
    CHECK(TIMED(channel_login(server->control_port, &old_session, "control", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "访问令牌无效") != NULL,
          "old session reopened a control channel; expected a 访问令牌无效 refusal, got %s: %s",
          login_outcome(), reason);
    CHECK(wait_session_status(server->db_path, old_session.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "old session not DISCONNECTED");
    char status[64];
    CHECK(session_status(server->db_path, new_session.session_id, status, sizeof(status)) == 0
              && strcmp(status, "NETTY_ONLINE") == 0,
          "new session %lld is '%s', expected NETTY_ONLINE", new_session.session_id, status);
    CHECK(wait_connection_reason(server->db_path, old_session.client_name, "REPLACED_BY_NEW_LOGIN",
                                 IO_TIMEOUT_MS) == 0,
          "replaced control not recorded");

    CHECK(channel_login(server->control_port, &new_session, "data", &data2, reason, sizeof(reason)) == 1,
          "new session data: %s", reason);
    CHECK(TIMED(nat_register(data2, new_session.client_name, public_port, 9)) == 0,
          "public port %d not released: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_alive(control2)) == 0, "new control not served: %s", timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_alive(data2)) == 0, "new data not served: %s", timed_outcome(IO_TIMEOUT_MS));
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
    CHECK(create_credential(server->db_path, "ck_idle", "idle-secret", 2) == 0, "credential ck_idle not stored");
    CHECK(http_client_login(server, "ck_idle", "idle-secret", "machine-idle", "frank", &dead) == 0,
          "login 1 (status and body above)");
    CHECK(channel_login(server->control_port, &dead, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, &dead, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);
    int online = admin_client_online(server, dead.client_name);
    CHECK(online == 1, "client not online while connected: management view online=%s", online_text(online));

    /* From here on the client sends nothing, exactly like a peer that vanished. */
    CHECK(TIMED(expect_channel_closed(control, 15000)) == 0,
          "silent control was not closed by the 5 s idle timeout: %s", timed_outcome(15000));
    CHECK(TIMED(expect_channel_closed(data, 15000)) == 0, "silent data was not closed: %s", timed_outcome(15000));
    CHECK(wait_session_status(server->db_path, dead.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "dead session still online");
    CHECK(wait_connection_reason(server->db_path, dead.client_name, "IDLE_TIMEOUT", IO_TIMEOUT_MS) == 0,
          "idle timeout not recorded");
    online = admin_client_online(server, dead.client_name);
    CHECK(online == 0, "dead channel keeps the client online: management view online=%s", online_text(online));

    close_fd(&control);
    close_fd(&data);
    CHECK(http_client_login(server, "ck_idle", "idle-secret", "machine-idle", "frank", &fresh) == 0,
          "login 2 (status and body above)");
    CHECK(channel_login(server->control_port, &fresh, "control", &control, reason, sizeof(reason)) == 1,
          "the dead channel still blocks the machine user: %s", reason);
    close_fd(&control);
    return 0;
}

/* The last "[server] stopped: ..." line of the server log, or a note that there is none. */
static void server_stopped_line(const test_server *server, char *out, size_t out_len)
{
    snprintf(out, out_len, "no \"[server] stopped:\" line in %s", server->log_path);
    FILE *log = fopen(server->log_path, "r");
    if (log == NULL) {
        return;
    }
    char line[1024];
    while (fgets(line, sizeof(line), log) != NULL) {
        if (strncmp(line, "[server] stopped:", strlen("[server] stopped:")) == 0) {
            line[strcspn(line, "\n")] = '\0';
            snprintf(out, out_len, "%s", line);
        }
    }
    fclose(log);
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
    CHECK(public_port > 0, "no free port for the public mapping");
    CHECK(create_credential(server->db_path, "ck_shutdown", "shutdown-secret", 2) == 0,
          "credential ck_shutdown not stored");
    CHECK(http_client_login(server, "ck_shutdown", "shutdown-secret", "machine-shutdown", "gina", runtime) == 0,
          "http login (status and body above)");
    CHECK(create_mapping(server->db_path, runtime->client_id, public_port) == 0,
          "mapping of port %d not stored", public_port);
    CHECK(channel_login(server->control_port, runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, runtime, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);
    CHECK(TIMED(nat_register(data, runtime->client_name, public_port, 9)) == 0,
          "REGISTER of port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(open_public_stream(data, public_port, &public_fd)) == 0,
          "no OPEN for a connection to port %d: %s", public_port, timed_outcome(IO_TIMEOUT_MS));
    CHECK(TIMED(expect_channel_alive(control)) == 0, "control not idle in its read loop: %s",
          timed_outcome(IO_TIMEOUT_MS));
    pre_auth = connect_local(server->control_port);
    CHECK(pre_auth >= 0, "pre-auth connection to control port %d: %s", server->control_port, strerror(errno));

    /* Each wait below ends as soon as its event happens; only the bound is generous. */
    long long sigterm_at = monotonic_ms();
    CHECK(kill(server->pid, SIGTERM) == 0, "SIGTERM to pid %d: %s", (int)server->pid, strerror(errno));
    CHECK(TIMED(expect_channel_closed(control, SHUTDOWN_TIMEOUT_MS)) == 0,
          "control not closed at shutdown: %s (%lld ms after SIGTERM)", timed_outcome(SHUTDOWN_TIMEOUT_MS),
          monotonic_ms() - sigterm_at);
    CHECK(TIMED(expect_channel_closed(data, SHUTDOWN_TIMEOUT_MS)) == 0,
          "data not closed at shutdown: %s (%lld ms after SIGTERM)", timed_outcome(SHUTDOWN_TIMEOUT_MS),
          monotonic_ms() - sigterm_at);
    CHECK(TIMED(expect_socket_eof(public_fd, SHUTDOWN_TIMEOUT_MS)) == 0,
          "NAT stream not closed at shutdown: %s (%lld ms after SIGTERM)", timed_outcome(SHUTDOWN_TIMEOUT_MS),
          monotonic_ms() - sigterm_at);
    CHECK(TIMED(expect_socket_eof(pre_auth, SHUTDOWN_TIMEOUT_MS)) == 0,
          "pre-auth connection not closed at shutdown: %s (%lld ms after SIGTERM)",
          timed_outcome(SHUTDOWN_TIMEOUT_MS), monotonic_ms() - sigterm_at);
    /* Waits for the exit; the SIGTERM server_stop sends again stays blocked, the server takes one. */
    int exit_status = server_stop(server, SHUTDOWN_TIMEOUT_MS);
    char exit_text[160];
    CHECK(exit_status == 0, "server did not shut down cleanly: %s, %lld ms after SIGTERM",
          describe_server_exit(exit_status, exit_text, sizeof(exit_text)), monotonic_ms() - sigterm_at);

    /* The process is gone, so everything it was going to write is in the database. */
    char status[64] = "";
    int status_rc = session_status(server->db_path, runtime->session_id, status, sizeof(status));
    CHECK(status_rc == 0 && strcmp(status, "DISCONNECTED") == 0,
          "session %lld is %s after the shutdown, expected DISCONNECTED", runtime->session_id,
          status_rc == 0 ? status : (status_rc == 1 ? "missing" : "unreadable"));
    CHECK(wait_connection_reason(server->db_path, runtime->client_name, "SERVER_SHUTDOWN", 0) == 0,
          "control record not stamped SERVER_SHUTDOWN (the client's records are listed above)");
    char open_records[512] = "";
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) || ' (' || COALESCE(group_concat(id || ':' || client_name, ', '), 'none') || ')'"
                    " FROM connection_record WHERE disconnected_at IS NULL OR disconnected_at = ''",
                    NULL, 0, open_records, sizeof(open_records)) == 0
              && strcmp(open_records, "0 (none)") == 0,
          "connection records left open after the shutdown: %s, expected none", open_records);
    char stopped[1100];
    server_stopped_line(server, stopped, sizeof(stopped));
    CHECK(strncmp(stopped, "[server] stopped: 0 connection(s) unfinished",
                  strlen("[server] stopped: 0 connection(s) unfinished")) == 0,
          "channels did not all finish their own bookkeeping before the process exited: %s", stopped);
    close_fd(&control);
    close_fd(&data);
    close_fd(&public_fd);
    close_fd(&pre_auth);
    return 0;
}

/*
 * Starts the server as server_start does, but sends SIGTERM the instant its admin port accepts a
 * connection. The admin port opens after the control listener, so that is the earliest moment a
 * readiness probe can call the server up, and server_start's 50 ms probe can land there too on a
 * busy runner. Returns server_stop's result for the exit.
 */
static int sigterm_at_first_accept(test_server *server, long long *accepted_after_ms)
{
    *accepted_after_ms = -1;
    server->control_port = pick_free_port();
    server->admin_port = pick_free_port();
    if (server->control_port <= 0 || server->admin_port <= 0 || server->control_port == server->admin_port) {
        fprintf(stderr, "no two distinct free ports (control %d, admin %d)\n", server->control_port,
                server->admin_port);
        return -2;
    }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork: %s\n", strerror(errno));
        return -2;
    }
    if (pid == 0) {
        char control_port[16];
        char admin_port[16];
        snprintf(control_port, sizeof(control_port), "%d", server->control_port);
        snprintf(admin_port, sizeof(admin_port), "%d", server->admin_port);
        setenv("SPECUS_ENV", "dev", 1);
        setenv("SPECUS_DATABASE_PATH", server->db_path, 1);
        setenv("SPECUS_DB_SEED_DEMO_CLIENT", "1", 1);
        setenv("SPECUS_NETTY_PORT", control_port, 1);
        setenv("SPECUS_NETTY_BIND_ADDRESS", "127.0.0.1", 1);
        setenv("SPECUS_ADMIN_PORT", admin_port, 1);
        setenv("SPECUS_AUTH_USERNAME", ADMIN_USERNAME, 1);
        setenv("SPECUS_AUTH_PASSWORD", ADMIN_PASSWORD, 1);
        setenv("SPECUS_AUTH_JWT_SECRET", ADMIN_JWT_SECRET, 1);
        int log = open(server->log_path, O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (log >= 0) {
            dup2(log, STDOUT_FILENO);
            dup2(log, STDERR_FILENO);
            close(log);
        }
        execl(server_binary, server_binary, (char *)NULL);
        _exit(127);
    }
    server->pid = pid;
    long long started = monotonic_ms();
    /* No sleep between attempts: the point is to probe as early as anything could. */
    for (;;) {
        int wait_status = 0;
        if (waitpid(pid, &wait_status, WNOHANG) == pid) {
            server->pid = -1;
            fprintf(stderr, "server exited during startup (wait status %d) before its admin port accepted\n",
                    wait_status);
            return -2;
        }
        if (monotonic_ms() - started >= SERVER_START_TIMEOUT_MS) {
            fprintf(stderr, "admin port %d did not accept a connection within %d ms\n", server->admin_port,
                    SERVER_START_TIMEOUT_MS);
            return -2;
        }
        int admin = connect_local(server->admin_port);
        if (admin >= 0) {
            kill(pid, SIGTERM);
            *accepted_after_ms = monotonic_ms() - started;
            close_fd(&admin);
            return server_stop(server, SHUTDOWN_TIMEOUT_MS);
        }
    }
}

/*
 * A SIGTERM that arrives once the ports accept connections but before the accept loop runs still
 * takes the graceful shutdown and exit status 0, not the 128+15 exit meant for a signal that lands
 * before anything listens. Before the shutdown pipe was opened ahead of the listeners, this was the
 * window that made the restarted server's SIGTERM exit 143 now and then.
 */
static int test_sigterm_at_first_accept_is_graceful(test_server *server)
{
    for (int attempt = 1; attempt <= 3; ++attempt) {
        long long accepted_after_ms = -1;
        int exit_status = sigterm_at_first_accept(server, &accepted_after_ms);
        char exit_text[160];
        CHECK(exit_status != -2, "attempt %d: the server never accepted a connection (see above)", attempt);
        CHECK(exit_status == 0, "attempt %d: SIGTERM sent as the admin port first accepted (%lld ms after start) "
              "did not shut the server down cleanly: %s", attempt, accepted_after_ms,
              describe_server_exit(exit_status, exit_text, sizeof(exit_text)));
    }
    return 0;
}

/* A restart closes what a process that never shut down cleanly left online or open. */
static int test_restart_closes_leftover_state(test_server *server, const runtime_session *runtime)
{
    long long record_id = 0;
    CHECK(st_storage_mark_client_session_online(server->db_path, runtime->session_id, "killed-channel",
                                                "127.0.0.1:1", "2026-01-01T00:00:00Z") == 0,
          "could not mark session %lld online as a leftover", runtime->session_id);
    CHECK(st_storage_record_connection_detail_with_tenant_and_id(server->db_path, "default", runtime->client_id,
                                                                 runtime->client_name, NULL, "127.0.0.1:1", 1,
                                                                 NULL, NULL, "2026-01-01T00:00:00Z", NULL,
                                                                 &record_id) == 0,
          "could not store a leftover open connection record");
    CHECK(server_start(server) == 0, "restart: the server did not come up (its startup error, if any, is above)");
    /* Startup closes leftovers before it opens a port, so they are closed once server_start returns. */
    char status[64] = "";
    int status_rc = session_status(server->db_path, runtime->session_id, status, sizeof(status));
    CHECK(status_rc == 0 && strcmp(status, "DISCONNECTED") == 0,
          "leftover session %lld is %s after the restart, expected DISCONNECTED", runtime->session_id,
          status_rc == 0 ? status : (status_rc == 1 ? "missing" : "unreadable"));
    char reason[64] = "";
    CHECK(db_scalar(server->db_path, "SELECT COALESCE(disconnect_reason, '') FROM connection_record WHERE id = ?",
                    NULL, record_id, reason, sizeof(reason)) == 0
              && strcmp(reason, "SERVER_RESTARTED") == 0,
          "leftover connection record %lld has disconnect reason '%s' after the restart, expected SERVER_RESTARTED",
          record_id, reason);
    int exit_status = server_stop(server, SHUTDOWN_TIMEOUT_MS);
    char exit_text[160];
    CHECK(exit_status == 0, "SIGTERM to the restarted server: %s",
          describe_server_exit(exit_status, exit_text, sizeof(exit_text)));
    return 0;
}

/* ------------------------------------------------------------------------------------------- */

/*
 * client-auth.md: a verified login consumes its (apiKey, nonce) pair. The identical signed body
 * sent again, well inside its 60 s timestamp window, is refused with Java's answer and mints no
 * second session; a freshly signed login for the same machine still succeeds.
 */
static int test_replayed_login_is_rejected(test_server *server)
{
    CHECK(create_credential(server->db_path, "ck_replay", "replay-secret", 2) == 0, "credential ck_replay not stored");
    char body[2048];
    signed_login_body("ck_replay", "replay-secret", "machine-replay", "mallory", body, sizeof(body));
    int status = 0;
    char *response = NULL;
    CHECK(http_request(server->admin_port, "POST", "/api/client/auth/login", body, NULL, &status, &response) == 0
          && status == 200 && strstr(response, "\"accessToken\":\"cs_") != NULL,
          "first login answered %d, expected 200 with a cs_ access token: %s", status,
          response == NULL ? "(no response)" : response);
    free(response);
    response = NULL;
    int replay_ok = http_request(server->admin_port, "POST", "/api/client/auth/login", body, NULL,
                                 &status, &response) == 0
        && status == 400
        && strstr(response, "{\"error\":\"客户端签名 nonce 已使用\"}") != NULL
        && strstr(response, "accessToken") == NULL;
    if (!replay_ok) {
        fprintf(stderr, "replayed login answered %d: %s\n", status, response == NULL ? "" : response);
    }
    free(response);
    CHECK(replay_ok, "replayed login was not rejected with 400 客户端签名 nonce 已使用 (its answer is above)");
    char sessions[32] = "";
    CHECK(db_scalar(server->db_path,
                    "SELECT COUNT(*) FROM specus_client_session WHERE machine_fingerprint = ?",
                    "machine-replay", 0, sessions, sizeof(sessions)) == 0
          && strcmp(sessions, "1") == 0,
          "replay minted a session: %s session(s), expected 1", sessions);
    runtime_session fresh;
    CHECK(http_client_login(server, "ck_replay", "replay-secret", "machine-replay", "mallory", &fresh) == 0,
          "a freshly signed login after the replay (status and body above)");
    return 0;
}

/* ------------------------------------------------------------------------------------------- */
/* Login response order                                                                          */

/*
 * The order scenario's server runs with SPECUS_LOGIN_TEST_GATE_DIR=login_gate_dir: each successful
 * login stops between publishing its connection and writing its response until the test lets it
 * go, so the test can send on the connection inside that window every time.
 */
static char login_gate_dir[256];
static char login_gate_env[320];

/* How long a held login is watched for anything that must wait for its response. */
#define HELD_LOGIN_WATCH_MS 1000
#define ORDER_ROUTE "order"
#define ORDER_RESPONSE_HEAD                                                                        \
    "{\"source\":\"http\",\"phase\":\"response\",\"statusCode\":200,\"headers\":[\"Content-Type: text/plain\"]," \
    "\"trailerNames\":[]}"

static void login_gate_path(const char *role, const char *event, char *out, size_t out_len)
{
    snprintf(out, out_len, "%s/%s-%s", login_gate_dir, role, event);
}

/* Removes what a failed scenario may have left at the gate, so the next one starts clean. */
static void clear_login_gate(void)
{
    static const char *const files[][2] = {
        {"control", "published"}, {"control", "release"}, {"data", "published"}, {"data", "release"}
    };
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        char path[400];
        login_gate_path(files[i][0], files[i][1], path, sizeof(path));
        unlink(path);
    }
}

/* Sends a login and waits until the server holds it at the gate with its connection published. */
static int start_held_login(const test_server *server, const runtime_session *runtime, const char *role, int *fd)
{
    *fd = connect_local(server->control_port);
    if (*fd < 0 || send_login_request(*fd, runtime, role) != 0) {
        return -1;
    }
    char published[400];
    login_gate_path(role, "published", published, sizeof(published));
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(published, F_OK) != 0) {
        if (monotonic_ms() >= deadline) {
            return -1;
        }
        sleep_ms(5);
    }
    return 0;
}

/* Lets a held login go; 0 when the first frame on its connection is then a successful response. */
static int finish_held_login(const char *role, int fd, char *reason, size_t reason_len)
{
    char release[400];
    login_gate_path(role, "release", release, sizeof(release));
    int gate = open(release, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (gate < 0) {
        snprintf(reason, reason_len, "cannot release the %s login: %s", role, strerror(errno));
        return -1;
    }
    close(gate);
    int command = 0;
    int success = 0;
    return read_login_response(fd, IO_TIMEOUT_MS, &command, &success, reason, reason_len) == 1 && success
        ? 0 : -1;
}

/*
 * While a login is held after publishing, nothing may reach its connection and the request sent
 * at it must stay unanswered: an early answer means the request never got to the connection.
 * Returns 0 when both stay quiet for HELD_LOGIN_WATCH_MS, else -1 with what happened in what.
 */
static int expect_quiet_while_held(int channel, int request, char *what, size_t what_len)
{
    struct pollfd ready[2] = {{.fd = channel, .events = POLLIN}, {.fd = request, .events = POLLIN}};
    long long deadline = monotonic_ms() + HELD_LOGIN_WATCH_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        if (remaining <= 0) {
            return 0;
        }
        int polled = poll(ready, 2, (int)remaining);
        if (polled < 0 && errno == EINTR) {
            continue;
        }
        if (polled == 0) {
            return 0;
        }
        if (polled < 0) {
            snprintf(what, what_len, "poll failed: %s", strerror(errno));
        } else if (ready[0].revents != 0) {
            st_frame_header header;
            uint8_t *body = NULL;
            int rc = read_frame(channel, IO_TIMEOUT_MS, &header, &body);
            if (rc == 1) {
                free(body);
                snprintf(what, what_len, "command %d was written before the login response", header.command);
            } else {
                snprintf(what, what_len, "the connection ended before the login response (rc=%d)", rc);
            }
        } else {
            snprintf(what, what_len, "the request was answered without waiting for the login response");
        }
        return -1;
    }
}

/* Sends an HTTP request, with a JSON body unless body is NULL, without waiting for its answer;
 * returns the socket, or -1. */
static int http_request_start(int port, const char *method, const char *path, const char *body,
                              const char *bearer)
{
    char authorization[600] = "";
    if (bearer != NULL) {
        snprintf(authorization, sizeof(authorization), "Authorization: Bearer %s\r\n", bearer);
    }
    char head[1536];
    int len = snprintf(head, sizeof(head),
                       "%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n%s%sContent-Length: %zu\r\n"
                       "Connection: close\r\n\r\n%s",
                       method, path, port, authorization,
                       body == NULL ? "" : "Content-Type: application/json\r\n",
                       body == NULL ? 0U : strlen(body), body == NULL ? "" : body);
    int fd = connect_local(port);
    if (fd >= 0 && (len <= 0 || (size_t)len >= sizeof(head)
                    || send_all(fd, (const uint8_t *)head, (size_t)len) != 0)) {
        close_fd(&fd);
    }
    return fd;
}

/* The status code that starts the answer to a request sent with http_request_start, or -1. */
static int http_response_status(int fd)
{
    char line[128];
    size_t used = 0U;
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (used < sizeof(line) - 1U) {
        uint8_t byte = 0U;
        if (recv_exact(fd, &byte, 1U, deadline) != 1 || byte == '\n') {
            break;
        }
        line[used++] = (char)byte;
    }
    line[used] = '\0';
    int status = -1;
    return sscanf(line, "HTTP/1.1 %d", &status) == 1 ? status : -1;
}

/*
 * The JSON of the next NAT_CONTROL push on a control connection, skipping every other frame; NULL
 * when none arrives before deadline. The caller frees it.
 */
static char *next_nat_control(int fd, long long deadline)
{
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        st_frame_header header;
        uint8_t *body = NULL;
        if (remaining <= 0 || read_frame(fd, (int)remaining, &header, &body) != 1) {
            return NULL;
        }
        st_message_response message;
        char *json = NULL;
        int nat_control = 0;
        if (header.command == ST_CMD_MESSAGE_RESPONSE
            && st_protocol_decode_message_response(body, header.length, &message) == 0) {
            if (message.message_type == ST_MESSAGE_TYPE_NAT_CONTROL) {
                nat_control = 1;
                json = message.message;
                message.message = NULL;
            }
            st_message_response_free(&message);
        }
        free(body);
        if (nat_control) {
            return json;
        }
    }
}

/* Waits for count NAT_CONTROL pushes on a control connection, skipping every other frame. */
static int expect_nat_controls(int fd, int count)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (; count > 0; --count) {
        char *json = next_nat_control(fd, deadline);
        if (json == NULL) {
            return -1;
        }
        free(json);
    }
    return 0;
}

/* Whether a NAT_CONTROL's specusConfigList has a TCP mapping listening on port. */
static int nat_control_lists_port(const char *json, int port)
{
    char entry[32];
    snprintf(entry, sizeof(entry), "{\"port\":%d,", port);
    return strstr(json, entry) != NULL;
}

static void url_encode(const char *value, char *out, size_t out_len)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t used = 0U;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0' && used + 4U < out_len; ++cursor) {
        unsigned char c = *cursor;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
            || c == '-' || c == '_' || c == '.' || c == '~') {
            out[used++] = (char)c;
        } else {
            out[used++] = '%';
            out[used++] = hex[c >> 4U];
            out[used++] = hex[c & 0x0fU];
        }
    }
    out[used] = '\0';
}

/*
 * A runtime NAT_CONTROL push that finds a control connection as soon as it is published, before
 * its login is answered, goes out after the login response: clients take the first frame after
 * their login request to be its answer (the Go client's loginConnection fails the login on
 * anything else). The push waits for the response rather than being dropped.
 */
static int test_control_login_answered_before_push(test_server *server)
{
    char reason[256];
    char what[160];
    runtime_session runtime;
    int control = -1;
    CHECK(create_credential(server->db_path, "ck_order_control", "order-control-secret", 2) == 0,
          "credential ck_order_control not stored");
    CHECK(http_client_login(server, "ck_order_control", "order-control-secret", "machine-order-control", "olga",
                            &runtime) == 0,
          "http login (status and body above)");
    char *token = admin_access_token(server);
    CHECK(token != NULL, "admin login failed");

    CHECK(start_held_login(server, &runtime, "control", &control) == 0,
          "the control login was never published and held at the gate");
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/nat-control", runtime.client_id);
    int push = http_request_start(server->admin_port, "POST", path, NULL, token);
    free(token);
    CHECK(push >= 0, "NAT_CONTROL push request not sent");
    CHECK(expect_quiet_while_held(control, push, what, sizeof(what)) == 0,
          "control login held after publishing, NAT_CONTROL pushed at it: %s", what);
    CHECK(finish_held_login("control", control, reason, sizeof(reason)) == 0,
          "the first frame on the control connection must be a successful login response: %s", reason);
    int status = http_response_status(push);
    CHECK(status == 200, "the push that waited for the login response answered %d, expected 200", status);
    CHECK(expect_nat_controls(control, 2) == 0,
          "the login's own NAT_CONTROL and the pushed one did not both follow the response");
    CHECK(TIMED(expect_channel_alive(control)) == 0, "control not served after the login: %s",
          timed_outcome(IO_TIMEOUT_MS));

    close_fd(&push);
    close_fd(&control);
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the client left");
    return 0;
}

/*
 * A TCP mapping created while a control login is held after publishing reloads the routes of that
 * connection and pushes them at it. The login's own NAT_CONTROL and the push both follow the
 * response, the push last, so the client ends with the new mapping rather than the routes it
 * logged in with. Under ThreadSanitizer this is also the scenario where the push used to replace
 * the routes while the login thread read them without map_lock.
 */
static int test_route_change_while_held_reaches_client_last(test_server *server)
{
    char reason[256];
    char what[160];
    runtime_session runtime;
    int control = -1;
    CHECK(create_credential(server->db_path, "ck_order_routes", "order-routes-secret", 2) == 0,
          "credential ck_order_routes not stored");
    CHECK(http_client_login(server, "ck_order_routes", "order-routes-secret", "machine-order-routes", "rita",
                            &runtime) == 0,
          "http login (status and body above)");
    char *token = admin_access_token(server);
    CHECK(token != NULL, "admin login failed");

    CHECK(start_held_login(server, &runtime, "control", &control) == 0,
          "the control login was never published and held at the gate");
    int listen_port = pick_free_port();
    CHECK(listen_port > 0, "no free port for the new mapping");
    char path[160];
    char body[160];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/specus-mappings", runtime.client_id);
    snprintf(body, sizeof(body), "{\"listenPort\":%d,\"targetAddress\":\"127.0.0.1\",\"targetPort\":9}",
             listen_port);
    int change = http_request_start(server->admin_port, "POST", path, body, token);
    free(token);
    CHECK(change >= 0, "mapping create request not sent");
    CHECK(expect_quiet_while_held(control, change, what, sizeof(what)) == 0,
          "control login held after publishing, a mapping created for it: %s", what);
    CHECK(finish_held_login("control", control, reason, sizeof(reason)) == 0,
          "the first frame on the control connection must be a successful login response: %s", reason);
    int status = http_response_status(change);
    CHECK(status == 201, "the mapping create that waited for the login response answered %d, expected 201", status);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    char *login_routes = next_nat_control(control, deadline);
    char *pushed_routes = login_routes == NULL ? NULL : next_nat_control(control, deadline);
    int pushed_has_mapping = pushed_routes != NULL && nat_control_lists_port(pushed_routes, listen_port);
    if (!pushed_has_mapping) {
        fprintf(stderr, "NAT_CONTROL after the login response: %s\nthen: %s\n",
                login_routes == NULL ? "(none)" : login_routes, pushed_routes == NULL ? "(none)" : pushed_routes);
    }
    free(login_routes);
    free(pushed_routes);
    CHECK(pushed_has_mapping,
          "the last NAT_CONTROL after the login response must list the mapping on port %d", listen_port);
    CHECK(TIMED(expect_channel_alive(control)) == 0, "control not served after the login: %s",
          timed_outcome(IO_TIMEOUT_MS));

    close_fd(&change);
    close_fd(&control);
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the client left");
    return 0;
}

/*
 * The same on a data connection: a public HTTP request that finds it as soon as it is published
 * opens its stream after the login response, and is still served. A data login refused because
 * its control is missing is answered at once, gate or not.
 */
static int test_data_login_answered_before_stream_open(test_server *server)
{
    char reason[256];
    char what[160];
    runtime_session runtime;
    int control = -1, data = -1, refused = -1;
    CHECK(create_credential(server->db_path, "ck_order_data", "order-data-secret", 2) == 0,
          "credential ck_order_data not stored");
    CHECK(http_client_login(server, "ck_order_data", "order-data-secret", "machine-order-data", "dora", &runtime) == 0,
          "http login (status and body above)");
    st_storage_http_route route;
    CHECK(st_storage_create_http_route_for_client(server->db_path, runtime.client_id, ORDER_ROUTE,
                                                  "http://127.0.0.1:9", 1, 0, 0, 0, 0, 0, NULL, NULL,
                                                  &route) == 0,
          "HTTP route not stored");

    CHECK(TIMED(channel_login(server->control_port, &runtime, "data", &refused, reason, sizeof(reason))) == 0
              && strstr(reason, "数据连接") != NULL,
          "a data login without its control must be refused with an answer; expected a 数据连接 refusal, got %s: %s",
          login_outcome(), reason);
    CHECK(start_held_login(server, &runtime, "control", &control) == 0,
          "the control login was never published and held at the gate");
    CHECK(finish_held_login("control", control, reason, sizeof(reason)) == 0, "control login: %s", reason);

    CHECK(start_held_login(server, &runtime, "data", &data) == 0,
          "the data login was never published and held at the gate");
    char client[768];
    char path[1024];
    url_encode(runtime.client_name, client, sizeof(client));
    snprintf(path, sizeof(path), "/http/%s/%s/held", client, ORDER_ROUTE);
    int browser = http_request_start(server->admin_port, "GET", path, NULL, NULL);
    CHECK(browser >= 0, "browser request not sent");
    CHECK(expect_quiet_while_held(data, browser, what, sizeof(what)) == 0,
          "data login held after publishing, HTTP request routed to it: %s", what);
    CHECK(finish_held_login("data", data, reason, sizeof(reason)) == 0,
          "the first frame on the data connection must be a successful login response: %s", reason);
    st_nat_message open;
    CHECK(expect_nat_frame(data, ST_NAT_OPEN, &open) == 0,
          "the request that waited for the login response opened no stream after it");
    uint32_t stream_id = open.stream_id;
    st_nat_message_free(&open);
    st_buffer head = st_protocol_encode_nat_message(ST_NAT_OPEN, 0U, stream_id, 0U, ORDER_RESPONSE_HEAD, NULL, 0U);
    CHECK(send_buffer(data, &head) == 0, "response head not sent");
    st_buffer fin = st_protocol_encode_nat_message(ST_NAT_FIN, 0U, stream_id, 0U, NULL, NULL, 0U);
    CHECK(send_buffer(data, &fin) == 0, "response FIN not sent");
    int status = http_response_status(browser);
    CHECK(status == 200, "the request that waited for the login response answered %d, expected 200", status);

    close_fd(&browser);
    close_fd(&data);
    close_fd(&control);
    CHECK(wait_session_status(server->db_path, runtime.session_id, "DISCONNECTED", IO_TIMEOUT_MS) == 0,
          "session not DISCONNECTED after the client left");
    return 0;
}

/* Counts the client's closed connection records with the given disconnect reason, or -1. */
static int connection_reason_count(const char *db_path, const char *client_name, const char *reason)
{
    char sql[256];
    char count[32] = "";
    snprintf(sql, sizeof(sql),
             "SELECT COUNT(*) FROM connection_record WHERE client_name = ? AND disconnect_reason = '%s'", reason);
    return db_scalar(db_path, sql, client_name, 0, count, sizeof(count)) == 0 ? atoi(count) : -1;
}

/* Waits until the client has at least expected connection records closed for reason. */
static int wait_connection_reason_count(const char *db_path, const char *client_name, const char *reason,
                                        int expected)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        int count = connection_reason_count(db_path, client_name, reason);
        if (count >= expected) {
            return 0;
        }
        if (monotonic_ms() >= deadline) {
            fprintf(stderr, "%d %s record(s) for %s, expected %d\n", count, reason, client_name, expected);
            return -1;
        }
        sleep_ms(50);
    }
}

/* A MESSAGE_REQUEST frame: the compact message body under the client-to-server command. */
static st_buffer encode_message_request(const char *client_name)
{
    st_buffer frame = st_protocol_encode_message_response(client_name, NULL, ST_MESSAGE_TYPE_CLIENT_TO_SERVER,
                                                          "role test");
    if (frame.data != NULL) {
        frame.data[6] = (uint8_t)ST_CMD_MESSAGE_REQUEST;
    }
    return frame;
}

/* The server packets a client must never send: login, message and logout responses. */
static st_buffer encode_server_packet(int which, const char *client_name)
{
    if (which == 0) {
        return st_protocol_encode_login_response(client_name, 1, NULL);
    }
    if (which == 1) {
        return st_protocol_encode_message_response(client_name, NULL, ST_MESSAGE_TYPE_SERVER_TO_CLIENT, "x");
    }
    return st_protocol_encode_empty_packet(ST_CMD_LOGOUT_RESPONSE);
}

/* LOGOUT_REQUEST is answered with LOGOUT_RESPONSE before the server closes the connection. */
static int expect_logout_answered(int fd)
{
    st_buffer logout = st_protocol_encode_empty_packet(ST_CMD_LOGOUT_REQUEST);
    if (send_buffer(fd, &logout) != 0) {
        return -1;
    }
    for (;;) {
        st_frame_header header;
        uint8_t *body = NULL;
        if (read_frame(fd, IO_TIMEOUT_MS, &header, &body) != 1) {
            fprintf(stderr, "no LOGOUT_RESPONSE\n");
            return -1;
        }
        free(body);
        if (header.command == ST_CMD_LOGOUT_RESPONSE) {
            return expect_channel_closed(fd, IO_TIMEOUT_MS);
        }
    }
}

/*
 * Java ConnectionRoleHandlerTests on real connections: a control connection takes MESSAGE_REQUEST,
 * heartbeats both ways and LOGOUT_REQUEST, a data connection NAT frames, heartbeats and
 * LOGOUT_REQUEST. A frame of the other role (NAT on control, MESSAGE_REQUEST on data) or a server
 * response packet closes that connection, and only it, as a protocol violation.
 */
static int test_connection_roles(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control = -1;
    int data = -1;
    CHECK(create_credential(server->db_path, "ck_roles", "roles-secret", 2) == 0, "credential ck_roles not stored");
    CHECK(http_client_login(server, "ck_roles", "roles-secret", "machine-roles", "rita", &runtime) == 0,
          "login (status and body above)");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control: %s", reason);
    CHECK(channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) == 1,
          "data: %s", reason);

    /* Accepted: the frames of each role. */
    st_buffer frame = encode_message_request(runtime.client_name);
    CHECK(send_buffer(control, &frame) == 0, "control MESSAGE_REQUEST");
    frame = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    CHECK(send_buffer(control, &frame) == 0, "control HEARTBEAT_RESPONSE");
    CHECK(expect_channel_alive(control) == 0, "the control connection refused a control frame");
    frame = st_protocol_encode_nat_message(ST_NAT_KEEPALIVE, 0U, 0U, 0U, NULL, NULL, 0U);
    CHECK(send_buffer(data, &frame) == 0, "data NAT KEEPALIVE");
    frame = st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    CHECK(send_buffer(data, &frame) == 0, "data HEARTBEAT_RESPONSE");
    CHECK(expect_channel_alive(data) == 0, "the data connection refused a data frame");

    /* Refused on data: MESSAGE_REQUEST and every server packet close the data connection only. */
    for (int which = -1; which < 3; ++which) {
        frame = which < 0 ? encode_message_request(runtime.client_name) : encode_server_packet(which, runtime.client_name);
        CHECK(send_buffer(data, &frame) == 0, "refused frame %d on data", which);
        CHECK(TIMED(expect_channel_closed(data, IO_TIMEOUT_MS)) == 0,
              "the data connection tolerated %s: %s", which < 0 ? "MESSAGE_REQUEST" : "a server packet",
              timed_outcome(IO_TIMEOUT_MS));
        close_fd(&data);
        CHECK(expect_channel_alive(control) == 0, "a data connection's violation closed the control connection");
        CHECK(channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) == 1,
              "data re-login: %s", reason);
    }
    /* LOGOUT_REQUEST is a data frame as well: answered, then the data connection ends. */
    CHECK(expect_logout_answered(data) == 0, "LOGOUT_REQUEST on data");
    close_fd(&data);
    CHECK(expect_channel_alive(control) == 0, "the data logout closed the control connection");
    CHECK(expect_logout_answered(control) == 0, "LOGOUT_REQUEST on control");
    close_fd(&control);
    CHECK(wait_connection_reason(server->db_path, runtime.client_name, "CLIENT_CLOSED", IO_TIMEOUT_MS) == 0,
          "the control logout was not recorded as CLIENT_CLOSED");

    /* Refused on control: a NAT frame and every server packet, each recorded as a violation. */
    int violations = connection_reason_count(server->db_path, runtime.client_name, "PROTOCOL_VIOLATION");
    CHECK(violations >= 0, "violation count");
    for (int which = -1; which < 3; ++which) {
        CHECK(http_client_login(server, "ck_roles", "roles-secret", "machine-roles", "rita", &runtime) == 0,
              "login (status and body above)");
        CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
              "control: %s", reason);
        frame = which < 0 ? st_protocol_encode_nat_message(ST_NAT_KEEPALIVE, 0U, 0U, 0U, NULL, NULL, 0U)
                          : encode_server_packet(which, runtime.client_name);
        CHECK(send_buffer(control, &frame) == 0, "refused frame %d on control", which);
        CHECK(TIMED(expect_channel_closed(control, IO_TIMEOUT_MS)) == 0,
              "the control connection tolerated %s: %s", which < 0 ? "a NAT frame" : "a server packet",
              timed_outcome(IO_TIMEOUT_MS));
        close_fd(&control);
        CHECK(wait_connection_reason_count(server->db_path, runtime.client_name, "PROTOCOL_VIOLATION",
                                           ++violations) == 0,
              "the control connection's violation was not recorded");
    }
    return 0;
}

static int scenario_default_limits(test_server *server)
{
    return test_replayed_login_is_rejected(server)
        || test_same_session_relogin_replaces_old_pair(server)
        || test_session_reuse_and_supersession(server)
        || test_second_login_on_one_connection_closes_it(server)
        || test_credential_online_limit(server)
        || test_stale_online_row_is_closed(server);
}

static int scenario_shutdown_and_restart(test_server *server)
{
    runtime_session runtime;
    return test_sigterm_closes_channels_before_exit(server, &runtime)
        || test_restart_closes_leftover_state(server, &runtime)
        || test_sigterm_at_first_accept_is_graceful(server);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    /* Line by line, so in a CI log each scenario's verdict follows its own failure details. */
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());

    static const char *const two_per_machine[] = {"SPECUS_CLIENT_AUTH_PER_MACHINE_USER_MAX_INSTANCES=2", NULL};
    static const char *const short_idle[] = {"SPECUS_CONTROL_READ_IDLE_SECONDS=5", NULL};
    int failures = 0;
    failures += run_on_fresh_server("login replay, relogin, supersession, single login, online limits, stale rows",
                                    scenario_default_limits, NULL);
    failures += run_on_fresh_server("new session replaces previous session",
                                    test_new_session_replaces_previous_session, two_per_machine);
    failures += run_on_fresh_server("dead channel cleanup", test_dead_channel_is_cleaned_up, short_idle);
    failures += run_on_fresh_server("connection roles refuse the other role's frames", test_connection_roles, NULL);
    failures += run_on_fresh_server("SIGTERM shutdown and restart cleanup", scenario_shutdown_and_restart, NULL);

    const char *tmp = getenv("TMPDIR");
    snprintf(login_gate_dir, sizeof(login_gate_dir), "%s/specus-c-login-gate-XXXXXX",
             tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    if (mkdtemp(login_gate_dir) == NULL) {
        fprintf(stderr, "cannot create the login gate directory: %s\n", strerror(errno));
        return 1;
    }
    snprintf(login_gate_env, sizeof(login_gate_env), "SPECUS_LOGIN_TEST_GATE_DIR=%s", login_gate_dir);
    const char *const login_gate[] = {login_gate_env, NULL};
    failures += run_on_fresh_server("control login answered before a NAT_CONTROL push sent once it is published",
                                    test_control_login_answered_before_push, login_gate);
    clear_login_gate();
    failures += run_on_fresh_server("a route change pushed while a control login is held reaches the client last",
                                    test_route_change_while_held_reaches_client_last, login_gate);
    clear_login_gate();
    failures += run_on_fresh_server("data login answered before a stream OPEN sent once it is published",
                                    test_data_login_answered_before_stream_open, login_gate);
    clear_login_gate();
    rmdir(login_gate_dir);

    if (failures != 0) {
        fprintf(stderr, "%d session lifecycle scenario(s) failed\n", failures);
        return 1;
    }
    printf("session lifecycle tests passed\n");
    return 0;
}
