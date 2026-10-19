#define _POSIX_C_SOURCE 200809L
#include "server_harness.h"
#include "security.h"
#include "json.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define METRIC_OWNER "session-reference-owner"
#define METRIC_PASSWORD "session-reference-password-2026"
#define METRIC_TENANT "session-reference-tenant"

typedef struct {
    unsigned int total_logouts;
    unsigned int logouts;
    unsigned int online_logouts;
    unsigned int rosters;
    unsigned int metrics;
    unsigned int owner_metrics;
} observed_events;

static int events(const test_server *server, const char *client, observed_events *out)
{
    memset(out, 0, sizeof(*out));
    char path[512];
    snprintf(path, sizeof(path), "%s/observer.jsonl", server->dir);
    FILE *file = fopen(path, "rb");
    if (file == NULL) return errno == ENOENT ? 0 : -1;
    char line[4096];
    int failed = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        if (!st_json_is_valid_object(line)) { failed = 1; break; }
        char *kind = st_json_get_top_level_string(line, "kind");
        char *name = st_json_get_top_level_string(line, "client");
        if (kind != NULL && strcmp(kind, "logout") == 0) {
            int online = -1, rosters = -1, result = -1;
            if (name == NULL || st_json_get_int(line, "online", &online) != 0 || st_json_get_int(line, "rosters", &rosters) != 0
                || st_json_get_int(line, "result", &result) != 0 || result != 0 || rosters < 0
                || (online != 0 && online != 1)) failed = 1;
            ++out->total_logouts;
            if (name != NULL && strcmp(name, client) == 0) {
                ++out->logouts;
                out->online_logouts += online == 1;
                if (rosters >= 0) out->rosters += (unsigned int)rosters;
            }
        } else if (kind != NULL && strcmp(kind, "metric") == 0) {
            char *tenant = st_json_get_top_level_string(line, "tenant");
            char *owner = st_json_get_top_level_string(line, "owner");
            char *step = st_json_get_top_level_string(line, "step");
            ++out->metrics;
            if (tenant != NULL && strcmp(tenant, METRIC_TENANT) == 0 && owner != NULL
                && strcmp(owner, METRIC_OWNER) == 0 && step != NULL && strcmp(step, "client_online") == 0)
                ++out->owner_metrics;
            free(tenant); free(owner); free(step);
        } else if (kind == NULL || strcmp(kind, "logout") != 0) failed = 1;
        free(kind); free(name);
        if (failed) break;
    }
    if (ferror(file)) failed = 1;
    fclose(file);
    return failed ? -1 : 0;
}

static int marker(const test_server *server, const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return -1;
    close(fd);
    return 0;
}

static int local_port(int fd)
{
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    return getsockname(fd, (struct sockaddr *)&address, &length) == 0
        && address.sin_family == AF_INET ? ntohs(address.sin_port) : -1;
}

static int wait_gate(const test_server *server, int expected_port)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/gate-entered", server->dir);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (monotonic_ms() < deadline) {
        FILE *file = fopen(path, "rb");
        if (file != NULL) {
            unsigned int port = 0U;
            int read = fscanf(file, "%u", &port);
            fclose(file);
            if (read == 1) return port == (unsigned int)expected_port ? 0 : -1;
        }
        sleep_ms(1); /* Wait for a concrete marker, never infer cleanup from a fixed delay. */
    }
    return -1;
}

static int closed_record(const test_server *server, const runtime_session *runtime, int port, int wait)
{
    char sql[512], count[32];
    snprintf(sql, sizeof(sql),
        "SELECT COUNT(*) FROM connection_record WHERE client_name=? AND success=1 "
        "AND remote_address='127.0.0.1:%d' AND disconnect_reason='REPLACED_BY_NEW_LOGIN' "
        "AND disconnected_at IS NOT NULL AND disconnected_at<>''", port);
    long long deadline = monotonic_ms() + (wait ? IO_TIMEOUT_MS : 0);
    do {
        if (db_scalar(server->db_path, sql, runtime->client_name, 0, count, sizeof(count)) != 0) return -1;
        if (atoi(count) == 1) return 1;
        if (!wait) return atoi(count) == 0 ? 0 : -1;
        sleep_ms(1);
    } while (monotonic_ms() < deadline);
    return -1;
}

static int new_runtime(const test_server *server, const char *fingerprint, runtime_session *runtime)
{
    return http_client_login(server, "session-reference-key", "session-reference-secret", fingerprint,
                             "distinct-os-user", runtime);
}

static int heartbeat_pair(int control, int data)
{
    return expect_channel_alive(control) != 0 || expect_channel_alive(data) != 0;
}

static int pair_scenario(test_server *server, int mode)
{
    runtime_session runtime, peer;
    int control = -1, data = -1, peer_control = -1, current = -1, current_data = -1;
    char reason[256];
    int failed = 1;
    const char *stage = "initial target pair";
    if (create_credential(server->db_path, "session-reference-key", "session-reference-secret", 4) != 0
        || new_runtime(server, "reference-target", &runtime) != 0
        || channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) != 1
        || channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) != 1
        || heartbeat_pair(control, data)) goto cleanup;
    /* A real online bystander calibrates the logout's emission count, including the zero case. */
    if (new_runtime(server, "reference-peer", &peer) != 0
        || channel_login(server->control_port, &peer, "control", &peer_control, reason, sizeof(reason)) != 1
        || expect_channel_alive(peer_control) != 0) goto cleanup;
    observed_events observed;
    if (events(server, runtime.client_name, &observed) != 0 || observed.total_logouts != 0U) goto cleanup;
    if (mode == 0) {
        stage = "current control close must unbind pair and announce exactly once";
        if (shutdown(control, SHUT_WR) != 0 || expect_channel_closed(control, IO_TIMEOUT_MS) != 0
            || expect_channel_closed(data, IO_TIMEOUT_MS) != 0 || expect_channel_alive(peer_control) != 0
            || events(server, runtime.client_name, &observed) != 0 || observed.total_logouts != 1U || observed.logouts != 1U
            || observed.online_logouts != 0U || observed.rosters != 1U) goto cleanup;
        char state[32];
        if (db_scalar(server->db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
                runtime.session_id, state, sizeof(state)) != 0 || strcmp(state, "DISCONNECTED") != 0) goto cleanup;
        puts("session reference: current control closes data, both EOFs and disconnected state; exactly one logout after unbind and one real peer roster passed");
    } else if (mode == 1) {
        int old_port = local_port(control);
        stage = "arm selected old control";
        if (old_port <= 0 || marker(server, "gate-armed") != 0) goto cleanup;
        stage = "replacement control login";
        if (channel_login(server->control_port, &runtime, "control", &current, reason, sizeof(reason)) != 1) goto cleanup;
        stage = "actual old EOF must enter its identified gate";
        if (wait_gate(server, old_port) != 0) goto cleanup;
        stage = "old control close record must still be open";
        if (closed_record(server, &runtime, old_port, 0) != 0) goto cleanup;
        stage = "new data binding while old EOF held";
        if (channel_login(server->control_port, &runtime, "data", &current_data, reason, sizeof(reason)) != 1
            || heartbeat_pair(current, current_data)) goto cleanup;
        stage = "no old logout before gate release";
        if (events(server, runtime.client_name, &observed) != 0 || observed.total_logouts != 0U) goto cleanup;
        stage = "release old cleanup and preserve new pair";
        if (marker(server, "gate-release") != 0 || closed_record(server, &runtime, old_port, 1) != 1
            || heartbeat_pair(current, current_data) || expect_channel_alive(peer_control) != 0
            || events(server, runtime.client_name, &observed) != 0 || observed.total_logouts != 1U || observed.logouts != 1U
            || observed.online_logouts != 1U || observed.rosters != 0U) goto cleanup;
        char state[32];
        if (db_scalar(server->db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
                runtime.session_id, state, sizeof(state)) != 0 || strcmp(state, "NETTY_ONLINE") != 0) goto cleanup;
        stage = "closing the replacement must still announce its final departure exactly once";
        if (shutdown(current, SHUT_WR) != 0 || expect_channel_closed(current, IO_TIMEOUT_MS) != 0
            || expect_channel_closed(current_data, IO_TIMEOUT_MS) != 0 || expect_channel_alive(peer_control) != 0
            || events(server, runtime.client_name, &observed) != 0 || observed.total_logouts != 2U || observed.logouts != 2U
            || observed.online_logouts != 1U || observed.rosters != 1U
            || db_scalar(server->db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
                runtime.session_id, state, sizeof(state)) != 0 || strcmp(state, "DISCONNECTED") != 0) goto cleanup;
        puts("session reference: actual old EOF held across new pair binding; late cleanup preserves new channels and online state with zero departure roster; final current close announces exactly once passed");
    } else {
        stage = "data close must leave control live without any logout callback";
        if (shutdown(data, SHUT_WR) != 0 || expect_channel_closed(data, IO_TIMEOUT_MS) != 0
            || expect_channel_alive(control) != 0 || expect_channel_alive(peer_control) != 0
            || events(server, runtime.client_name, &observed) != 0 || observed.total_logouts != 0U
            || observed.rosters != 0U) goto cleanup;
        char state[32];
        if (db_scalar(server->db_path, "SELECT status FROM specus_client_session WHERE id=?", NULL,
                runtime.session_id, state, sizeof(state)) != 0 || strcmp(state, "NETTY_ONLINE") != 0) goto cleanup;
        puts("session reference: data EOF leaves actual control live and online; no logout callback or departure roster passed");
    }
    failed = 0;
cleanup:
    /* Always release a held worker before closing channels or stopping its process. */
    {
        char path[512];
        snprintf(path, sizeof(path), "%s/gate-release", server->dir);
        int fd = open(path, O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) close(fd);
    }
    close_fd(&control); close_fd(&data); close_fd(&peer_control);
    close_fd(&current); close_fd(&current_data);
    if (failed) fprintf(stderr, "FAIL session reference pair mode%d stage=%s\n", mode, stage);
    return failed;
}

static int request_ok(test_server *server, const char *method, const char *path, const char *body,
                       const char *bearer, int expected, char **out)
{
    int status = 0;
    char *response = NULL;
    int rc = http_request(server->admin_port, method, path, body, bearer, &status, &response);
    if (out != NULL) *out = response; else free(response);
    return rc != 0 || status != expected;
}

static int metrics_scenario(test_server *server)
{
    char admin[2048], reason[256];
    int control = -1, data = -1;
    char *response = NULL, *token = NULL;
    int failed = 1;
    const char *stage = "enable metrics and create ordinary owner";
    if (st_security_issue_local_token(ADMIN_USERNAME, METRIC_TENANT, "ADMIN", ADMIN_JWT_SECRET, 600,
                                      admin, sizeof(admin)) != 0
        || request_ok(server, "PUT", "/api/admin/product-metrics/settings",
            "{\"enabled\":true,\"disclosureVersion\":1}", admin, 200, NULL)
        || request_ok(server, "POST", "/api/admin/users",
            "{\"username\":\"" METRIC_OWNER "\",\"password\":\"" METRIC_PASSWORD "\",\"role\":\"USER\"}", admin, 201, NULL)
        || request_ok(server, "POST", "/auth/login",
            "{\"username\":\"" METRIC_OWNER "\",\"password\":\"" METRIC_PASSWORD "\",\"tenantId\":\"" METRIC_TENANT "\"}", NULL, 200, &response)) goto cleanup;
    token = st_json_get_top_level_string(response, "accessToken");
    free(response); response = NULL;
    stage = "owner credential creation";
    if (token == NULL || request_ok(server, "POST", "/api/admin/client-credentials",
            "{\"apiKey\":\"session-reference-key\",\"secret\":\"session-reference-secret\"}", token, 201, NULL)) goto cleanup;
    char value[64];
    observed_events observed;
    stage = "account_created must have started exactly one untouched owner progress row";
    if (db_scalar(server->db_path,
        "SELECT COUNT(*) FROM product_metrics_onboarding_progress WHERE tenant_id='" METRIC_TENANT "' AND username=? "
        "AND started_at IS NOT NULL AND client_online_at IS NULL",
        METRIC_OWNER, 0, value, sizeof(value)) != 0 || strcmp(value, "1") != 0
        || events(server, "", &observed) != 0 || observed.metrics != 0U) goto cleanup;
    runtime_session runtime;
    stage = "owner control login and callback barrier";
    if (new_runtime(server, "reference-metrics", &runtime) != 0
        || channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) != 1
        || expect_channel_alive(control) != 0) goto cleanup;
    stage = "exact owner callback and no additional data callback";
    if (events(server, runtime.client_name, &observed) != 0 || observed.metrics != 1U
        || observed.owner_metrics != 1U
        || channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) != 1
        || heartbeat_pair(control, data) || events(server, runtime.client_name, &observed) != 0
        || observed.metrics != 1U || observed.owner_metrics != 1U) goto cleanup;
    stage = "real owner progress row";
    if (db_scalar(server->db_path,
        "SELECT client_online_at FROM product_metrics_onboarding_progress WHERE tenant_id='" METRIC_TENANT "' AND username=?",
        METRIC_OWNER, 0, value, sizeof(value)) != 0 || value[0] == '\0') goto cleanup;
    stage = "OS identity must not own progress";
    if (db_scalar(server->db_path,
        "SELECT COUNT(*) FROM product_metrics_onboarding_progress WHERE tenant_id='" METRIC_TENANT "' AND username=?",
        "distinct-os-user", 0, value, sizeof(value)) != 0 || strcmp(value, "0") != 0) goto cleanup;
    stage = "default tenant must not receive this owner's progress";
    if (db_scalar(server->db_path,
        "SELECT COUNT(*) FROM product_metrics_onboarding_progress WHERE tenant_id='default' AND username=?",
        METRIC_OWNER, 0, value, sizeof(value)) != 0 || strcmp(value, "0") != 0) goto cleanup;
    puts("session reference: real control records client_online exactly once for actual non-default tenant and owner, not OS user; data emits no extra milestone and real storage updated passed");
    failed = 0;
cleanup:
    free(response); free(token);
    close_fd(&control); close_fd(&data);
    if (failed) fprintf(stderr, "FAIL session reference owner metrics stage=%s\n", stage);
    return failed;
}

static int run_case(int mode)
{
    test_server server;
    if (server_prepare(&server) != 0) return 1;
    char directory[256];
    int length = snprintf(directory, sizeof(directory), "SPECUS_SESSION_REFERENCE_DIR=%s", server.dir);
    if (length < 0 || (size_t)length >= sizeof(directory)) { server_cleanup(&server, 1); return 1; }
    server.extra_env[0] = directory;
    server.extra_env[1] = "SPECUS_CONTROL_READ_IDLE_SECONDS=900";
    server.extra_env[2] = "SPECUS_PEER_MESH_ENABLED=true";
    if (mode == 3) server.extra_env[3] = "SPECUS_AUTH_TENANT_ID=" METRIC_TENANT;
    int failed = server_start(&server) != 0;
    if (!failed) failed = mode == 3 ? metrics_scenario(&server) : pair_scenario(&server, mode);
    if (!failed && server_stop(&server, 20000) != 0) failed = 1;
    /* Stop before removing observer files; no process may append behind cleanup. */
    if (failed && server.pid > 0) (void)server_stop(&server, 20000);
    if (failed) {
        char path[512];
        snprintf(path, sizeof(path), "%s/observer.jsonl", server.dir);
        FILE *file = fopen(path, "rb");
        if (file != NULL) {
            char line[4096];
            /* The observer sink contains only bounded identities/counts, never login tokens. */
            while (fgets(line, sizeof(line), file) != NULL) fprintf(stderr, "observer: %s", line);
            fclose(file);
        }
    }
    const char *names[] = {"observer.jsonl", "gate-armed", "gate-entered", "gate-release"};
    for (size_t i = 0U; i < sizeof(names) / sizeof(names[0]); ++i) {
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", server.dir, names[i]);
        unlink(path);
    }
    server_cleanup(&server, failed);
    printf("%s session reference wire mode%d\n", failed ? "FAIL" : "ok  ", mode);
    return failed;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    server_binary = argv[1];
    signal(SIGPIPE, SIG_IGN);
    int failed = 0;
    for (int mode = 0; mode < 4; ++mode) failed |= run_case(mode);
    if (!failed) puts("session reference wire:4 isolated real server scenarios; session pair, logout ordering/absence, owner metrics passed");
    return failed;
}
