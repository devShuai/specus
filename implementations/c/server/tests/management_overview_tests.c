/*
 * GET /api/admin/overview on a real server process, against Java OverviewService: the tenant's
 * clients and how many are online, successful and failed logins, and the public connections that
 * are open and that a connection limit refused (RemotePortServerManager's per-tenant counters).
 *
 *   management_overview_tests <specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "json.h"
#include "protocol.h"
#include "server_harness.h"
#include "storage.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long long overview_number(const test_server *server, const char *token, const char *key)
{
    int status = 0;
    char *body = NULL;
    long long value = -1;
    if (http_request(server->admin_port, "GET", "/api/admin/overview", NULL, token, &status, &body) == 0
        && status == 200) {
        (void)st_json_get_i64(body, key, &value);
    }
    free(body);
    return value;
}

static int wait_overview(const test_server *server, const char *token, const char *key, long long expected)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (overview_number(server, token, key) != expected && monotonic_ms() < deadline) {
        sleep_ms(50);
    }
    long long seen = overview_number(server, token, key);
    if (seen != expected) fprintf(stderr, "overview %s is %lld, expected %lld\n", key, seen, expected);
    return seen == expected ? 0 : -1;
}

static int scenario_overview(test_server *server)
{
    char reason[256];
    runtime_session runtime;
    int control = -1;
    int data = -1;
    int public_port = pick_free_port();
    CHECK(create_credential(server->db_path, "ck_overview", "overview-secret", 2) == 0, "credential");
    CHECK(http_client_login(server, "ck_overview", "overview-secret", "machine-overview", "olga", &runtime) == 0,
          "client login");
    CHECK(create_mapping(server->db_path, runtime.client_id, public_port) == 0, "mapping");
    CHECK(channel_login(server->control_port, &runtime, "control", &control, reason, sizeof(reason)) == 1,
          "control login: %s", reason);
    CHECK(channel_login(server->control_port, &runtime, "data", &data, reason, sizeof(reason)) == 1,
          "data login: %s", reason);
    CHECK(nat_register(data, runtime.client_name, public_port, 9) == 0, "REGISTER");
    /* A login with a wrong token is recorded as a failed connection. */
    runtime_session forged = runtime;
    snprintf(forged.access_token, sizeof(forged.access_token), "forged-token");
    int refused_fd = -1;
    CHECK(channel_login(server->control_port, &forged, "control", &refused_fd, reason, sizeof(reason)) == 0,
          "a forged token must be refused");
    /* So is a login under a name no account has; Java lists it for the tenant's administrator. */
    snprintf(forged.client_name, sizeof(forged.client_name), "no-such-client");
    CHECK(channel_login(server->control_port, &forged, "control", &refused_fd, reason, sizeof(reason)) == 0,
          "an unknown client must be refused");

    int status = 0;
    char *body = NULL;
    char login[256];
    snprintf(login, sizeof(login), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    CHECK(http_request(server->admin_port, "POST", "/auth/login", login, NULL, &status, &body) == 0 && status == 200,
          "admin login %d", status);
    char *token = st_json_get_string(body, "accessToken");
    free(body);
    CHECK(token != NULL, "access token");
    char token_copy[1024];
    snprintf(token_copy, sizeof(token_copy), "%s", token);
    free(token);

    /* One public connection is open; the next one on that port is over its limit of 1. */
    int public_fd = -1;
    uint32_t stream_id = 0U;
    CHECK(open_public_stream_id(data, public_port, &public_fd, &stream_id) == 0, "public OPEN");
    CHECK(wait_overview(server, token_copy, "externalConnections", 1) == 0, "one open public connection");
    int second = connect_local(public_port);
    CHECK(second >= 0 && expect_socket_eof(second, IO_TIMEOUT_MS) == 0, "the second connection must be refused");
    close_fd(&second);
    CHECK(wait_overview(server, token_copy, "rejectedExternalConnections", 1) == 0, "one refused public connection");

    CHECK(http_request(server->admin_port, "GET", "/api/admin/overview", NULL, token_copy, &status, &body) == 0
              && status == 200,
          "overview");
    static const char *const keys[] = {
        "\"clients\":", "\"onlineClients\":", "\"successfulConnections\":", "\"failedConnections\":",
        "\"uploadBytes\":", "\"downloadBytes\":", "\"externalConnections\":", "\"rejectedExternalConnections\":"
    };
    int keys_ok = 1;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) keys_ok = keys_ok && strstr(body, keys[i]) != NULL;
    long long clients = -1, online = -1, successful = -1, failed = -1;
    (void)st_json_get_i64(body, "clients", &clients);
    (void)st_json_get_i64(body, "onlineClients", &online);
    (void)st_json_get_i64(body, "successfulConnections", &successful);
    (void)st_json_get_i64(body, "failedConnections", &failed);
    /* The seeded Demo client and this one; only the control connection's login is recorded, as
     * Java records no connection for a data connection; both refused logins count. */
    int counts_ok = clients == 2 && online == 1 && successful == 1 && failed == 2;
    if (!keys_ok || !counts_ok) fprintf(stderr, "overview: %s\n", body);
    free(body);
    CHECK(keys_ok, "Java's overview fields");
    CHECK(counts_ok, "clients, online clients and login counts");
    CHECK(http_request(server->admin_port, "GET", "/api/admin/connections?success=false", NULL, token_copy,
                       &status, &body) == 0 && status == 200,
          "failed connections");
    long long failed_total = -1;
    (void)st_json_get_i64(body, "total", &failed_total);
    int listed_ok = failed_total == 2 && strstr(body, "\"clientName\":\"no-such-client\"") != NULL;
    if (!listed_ok) fprintf(stderr, "connections: %s\n", body);
    free(body);
    CHECK(listed_ok, "the administrator must see the failed login of an unknown client");

    /* A connection closed on both sides is off the open count. */
    close_fd(&public_fd);
    st_buffer reset = st_protocol_encode_nat_message(ST_NAT_RST, 0U, stream_id, 0U, NULL, NULL, 0U);
    CHECK(send_buffer(data, &reset) == 0, "RST of the stream");
    CHECK(wait_overview(server, token_copy, "externalConnections", 0) == 0, "the closed connection must be released");
    close_fd(&data);
    close_fd(&control);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    static const char *const env[] = {"SPECUS_MAX_PORT_EXTERNAL_CONNECTIONS=1", NULL};
    if (run_on_fresh_server("management overview on a real server", scenario_overview, env)) return 1;
    printf("management overview tests passed\n");
    return 0;
}
