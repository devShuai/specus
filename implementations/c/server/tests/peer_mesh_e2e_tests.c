/*
 * Peer Mesh control messages against a real specus-server-c process.
 *
 * An egress logs in over the real HTTP endpoint announcing clientEgressCapabilities, opens its
 * control connection and sends egress-report as PEER_CONTROL message requests, the way a client
 * does; what the server kept is read back through the management API. This is the path
 * protocol/spec/peer-egress.md describes for egress-report: identity and session bound from the
 * authenticated connection, server-bound envelope fields refused, older snapshots ignored and at
 * most 20 reports per control session per minute. A second scenario starts the server with a
 * STUN/TURN listener that cannot start and checks that the server runs on without it.
 *
 * Usage: specus_c_peer_mesh_e2e_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "crypto.h"
#include "json.h"
#include "protocol.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static void random_nonce(char out[33])
{
    uint8_t bytes[16];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, bytes, sizeof(bytes)) != (ssize_t)sizeof(bytes)) {
        for (size_t i = 0; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(rand() & 0xff);
    }
    if (fd >= 0) close(fd);
    st_hex_encode(bytes, sizeof(bytes), out);
}

/*
 * The real POST /api/client/auth/login, announcing the given egress capability version and the
 * peer public key "pk-<fingerprint>". The response is kept in *login_response when asked for.
 */
static int egress_login(const test_server *server, const char *api_key, const char *secret,
                        const char *fingerprint, int egress_version, runtime_session *out,
                        char **login_response)
{
    char timestamp[32];
    char nonce[33];
    snprintf(timestamp, sizeof(timestamp), "%lld", wall_clock_ms());
    random_nonce(nonce);
    uint8_t key[ST_SHA256_LEN];
    st_sha256((const uint8_t *)secret, strlen(secret), key);
    char canonical[1024];
    snprintf(canonical, sizeof(canonical), "%s\n%s\n%s\n%s\n%s", api_key, timestamp, nonce, fingerprint, "egress");
    uint8_t mac[ST_SHA256_LEN];
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)canonical, strlen(canonical), mac);
    char signature[ST_SHA256_HEX_LEN + 1];
    st_hex_encode(mac, sizeof(mac), signature);
    char body[2048];
    snprintf(body, sizeof(body),
             "{\"apiKey\":\"%s\",\"timestamp\":\"%s\",\"nonce\":\"%s\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"%s\",\"hostname\":\"egress-host\","
             "\"osUser\":\"egress\",\"osName\":\"Linux\",\"osVersion\":\"test\",\"osArch\":\"amd64\","
             "\"clientVersion\":\"peer-mesh-e2e-test\",\"peerPublicKey\":\"pk-%s\","
             "\"clientEgressCapabilities\":{\"version\":%d,"
             "\"egressCapable\":%s,\"consumerCapable\":%s}}}",
             api_key, timestamp, nonce, signature, fingerprint, fingerprint, egress_version,
             egress_version >= 1 ? "true" : "false", egress_version >= 1 ? "true" : "false");
    memset(out, 0, sizeof(*out));
    int status = 0;
    char *response = NULL;
    if (http_request(server->admin_port, "POST", "/api/client/auth/login", body, NULL, &status, &response) != 0) {
        return -1;
    }
    char *client_name = st_json_get_top_level_string(response, "clientName");
    char *token = st_json_get_top_level_string(response, "accessToken");
    int rc = status == 200 && client_name != NULL && token != NULL
        && st_json_get_i64(response, "clientSessionId", &out->session_id) == 0
        && st_json_get_i64(response, "clientId", &out->client_id) == 0 ? 0 : -1;
    if (rc == 0) {
        snprintf(out->client_name, sizeof(out->client_name), "%s", client_name);
        snprintf(out->access_token, sizeof(out->access_token), "%s", token);
    } else {
        fprintf(stderr, "egress login failed: status=%d body=%s\n", status, response);
    }
    free(client_name);
    free(token);
    if (login_response != NULL && rc == 0) *login_response = response;
    else free(response);
    return rc;
}

/* A PEER_CONTROL message request on a control connection, as a client sends one. */
static int send_peer_control(int fd, const char *client_name, const char *to_client_name, const char *message)
{
    st_buffer frame = st_protocol_encode_message_response(client_name, to_client_name,
                                                          ST_MESSAGE_TYPE_PEER_CONTROL, message);
    if (frame.data == NULL || frame.len <= ST_HEADER_SIZE) {
        st_buffer_free(&frame);
        return -1;
    }
    /* Requests and responses share the body layout; only the command differs. */
    frame.data[6] = (uint8_t)ST_CMD_MESSAGE_REQUEST;
    return send_buffer(fd, &frame);
}

static char *admin_token(const test_server *server)
{
    char body[256];
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    int status = 0;
    char *response = NULL;
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0) return NULL;
    char *token = status == 200 ? st_json_get_top_level_string(response, "accessToken") : NULL;
    free(response);
    return token;
}

/*
 * The egress activity entry of one client, through GET /api/admin/peer-mesh/egress/activity:
 * 1 with its revision and activeFlows, 0 when there is none, -1 on error.
 */
static int egress_activity(const test_server *server, const char *token, const char *client_name,
                           long long *revision, long long *active_flows, int *online)
{
    int status = 0;
    char *response = NULL;
    if (http_request(server->admin_port, "GET", "/api/admin/peer-mesh/egress/activity", NULL, token,
                     &status, &response) != 0 || status != 200) {
        free(response);
        return -1;
    }
    char needle[320];
    snprintf(needle, sizeof(needle), "\"egressClientName\":\"%s\"", client_name);
    const char *entry = strstr(response, needle);
    int found = entry != NULL;
    if (found) {
        const char *end = strstr(entry, "\"reportedAt\":");
        size_t len = end == NULL ? strlen(entry) : (size_t)(end - entry);
        char *view = (char *)calloc(len + 3U, 1U);
        if (view == NULL) {
            free(response);
            return -1;
        }
        view[0] = '{';
        memcpy(view + 1, entry, len);
        /* The cut leaves a trailing comma; close the object over it. */
        if (len > 0U && view[len] == ',') view[len] = '}';
        else view[len + 1U] = '}';
        found = st_json_get_i64(view, "revision", revision) == 0
            && st_json_get_i64(view, "activeFlows", active_flows) == 0
            && st_json_get_bool(view, "online", online) == 0 ? 1 : -1;
        free(view);
    }
    free(response);
    return found;
}

static int expect_activity(const test_server *server, const char *token, const char *client_name,
                           long long want_revision, long long want_active, const char *label)
{
    long long revision = 0, active = 0;
    int online = 0;
    int found = egress_activity(server, token, client_name, &revision, &active, &online);
    if (found == 1 && revision == want_revision && active == want_active && online) return 0;
    fprintf(stderr, "%s: activity of %s is %s revision %lld activeFlows %lld online %d, want %lld/%lld\n",
            label, client_name, found == 1 ? "at" : (found == 0 ? "missing," : "unreadable,"),
            revision, active, online, want_revision, want_active);
    return -1;
}

static int report_and_sync(int fd, const char *client_name, const char *to, const char *message)
{
    /* The control connection handles its frames in order: once the heartbeat is answered, the
     * report before it has been handled. */
    return send_peer_control(fd, client_name, to, message) == 0 && expect_channel_alive(fd) == 0 ? 0 : -1;
}

static int scenario_egress_report(test_server *server)
{
    CHECK(create_credential(server->db_path, "ck_egress", "egress-secret", 2) == 0, "egress credential not stored");
    CHECK(create_credential(server->db_path, "ck_legacy", "legacy-secret", 2) == 0, "legacy credential not stored");
    runtime_session egress;
    runtime_session legacy;
    char *login = NULL;
    CHECK(egress_login(server, "ck_egress", "egress-secret", "machine-egress", 1, &egress, &login) == 0,
          "egress login");
    /*
     * loginConfigAllocatesVirtualIpButLeavesDeviceDisabledByDefault, over the real login: a new
     * device gets a virtual IP and the public key it announced, stays off, and is still told the
     * STUN/TURN endpoints and its TURN credential.
     */
    char ice_subject[64];
    snprintf(ice_subject, sizeof(ice_subject), ":pm-%lld:", egress.client_id);
    int login_ok = login != NULL && strstr(login, "\"peerMesh\":{\"enabled\":false,") != NULL
        && strstr(login, "\"virtualIp\":\"100.") != NULL
        && strstr(login, "\"clientPublicKey\":\"pk-machine-egress\"") != NULL
        && strstr(login, "\"stunHost\":\"127.0.0.1\"") != NULL && strstr(login, "\"turnHost\":\"127.0.0.1\"") != NULL
        && strstr(login, ice_subject) != NULL
        && strstr(login, "\"deploymentEnabled\":true,\"configuredEnabled\":false,\"effectiveEnabled\":false") != NULL;
    if (!login_ok) fprintf(stderr, "login peerMesh config mismatch: %s\n", login == NULL ? "(none)" : login);
    free(login);
    CHECK(login_ok, "login peerMesh config");
    CHECK(egress_login(server, "ck_legacy", "legacy-secret", "machine-legacy", 0, &legacy, NULL) == 0,
          "legacy login");
    int fd = -1;
    int legacy_fd = -1;
    char reason[256];
    CHECK(channel_login(server->control_port, &egress, "control", &fd, reason, sizeof(reason)) == 1,
          "egress control login refused: %s", reason);
    CHECK(channel_login(server->control_port, &legacy, "control", &legacy_fd, reason, sizeof(reason)) == 1,
          "legacy control login refused: %s", reason);
    char *token = admin_token(server);
    CHECK(token != NULL, "admin login failed");
    const char *name = egress.client_name;
    int failed = 0;

    /* Stored against the authenticated client and session, as sent. */
    if (report_and_sync(fd, name, NULL, "{\"type\":\"egress-report\",\"revision\":100,\"activeFlows\":3,"
                                         "\"totalFlows\":9,\"rejectedFlows\":{\"EGRESS_DEST_DENIED\":1}}") != 0
        || expect_activity(server, token, name, 100, 3, "first report") != 0) failed = 1;
    char session_text[32] = "";
    if (!failed && (db_scalar(server->db_path,
                              "SELECT session_id FROM peer_mesh_egress_activity WHERE egress_client_name = ?",
                              name, 0, session_text, sizeof(session_text)) != 0
                    || atoll(session_text) != egress.session_id)) {
        fprintf(stderr, "egress activity bound session %s, want the control session %lld\n", session_text,
                egress.session_id);
        failed = 1;
    }
    /* Server-bound fields, even null, and a report addressed to a peer are refused. */
    if (!failed && (report_and_sync(fd, name, NULL,
                                    "{\"type\":\"egress-report\",\"revision\":200,\"activeFlows\":7,"
                                    "\"sourceClientId\":null}") != 0
                    || report_and_sync(fd, name, legacy.client_name,
                                       "{\"type\":\"egress-report\",\"revision\":201,\"activeFlows\":7}") != 0
                    || expect_activity(server, token, name, 100, 3, "refused envelopes") != 0)) failed = 1;
    /* An older snapshot does not overwrite a newer one; a newer one replaces it. */
    if (!failed && (report_and_sync(fd, name, NULL, "{\"type\":\"egress-report\",\"revision\":50,\"activeFlows\":1}") != 0
                    || expect_activity(server, token, name, 100, 3, "older snapshot") != 0
                    || report_and_sync(fd, name, NULL, "{\"type\":\"egress-report\",\"revision\":101,\"activeFlows\":4}") != 0
                    || expect_activity(server, token, name, 101, 4, "newer snapshot") != 0)) failed = 1;
    /*
     * 20 per control session per minute: three were taken above (the refused envelopes are
     * refused before they count), so 17 more pass and the next is refused.
     */
    char message[160];
    for (int revision = 102; !failed && revision <= 118; ++revision) {
        snprintf(message, sizeof(message), "{\"type\":\"egress-report\",\"revision\":%d,\"activeFlows\":5}", revision);
        if (send_peer_control(fd, name, NULL, message) != 0) failed = 1;
    }
    if (!failed && (report_and_sync(fd, name, NULL, "{\"type\":\"egress-report\",\"revision\":119,\"activeFlows\":6}") != 0
                    || expect_activity(server, token, name, 118, 5, "rate limit") != 0)) failed = 1;
    /* A client that did not announce egress capability cannot report. */
    long long revision = 0, active = 0;
    int online = 0;
    if (!failed && (report_and_sync(legacy_fd, legacy.client_name, NULL,
                                    "{\"type\":\"egress-report\",\"revision\":5,\"activeFlows\":2}") != 0
                    || egress_activity(server, token, legacy.client_name, &revision, &active, &online) != 0)) {
        fprintf(stderr, "a client without egress capability had its report stored\n");
        failed = 1;
    }
    free(token);
    close_fd(&fd);
    close_fd(&legacy_fd);
    return failed;
}

static int stun_turn_port;

/*
 * A STUN/TURN listener that cannot start, here because the public address does not resolve, is no
 * reason to stop the server: Java StunTurnServer.run logs it and the server runs on without
 * STUN/TURN. The management API and client logins answer, nothing answers STUN on the configured
 * port, and the server still stops cleanly. C used to exit at startup.
 */
static int scenario_without_stun_turn(test_server *server)
{
    char *token = admin_token(server);
    CHECK(token != NULL, "admin login failed without STUN/TURN");
    int status = 0;
    char *response = NULL;
    int overview = http_request(server->admin_port, "GET", "/api/admin/overview", NULL, token, &status, &response);
    free(response);
    free(token);
    CHECK(overview == 0 && status == 200, "management overview without STUN/TURN: status %d", status);
    CHECK(create_credential(server->db_path, "ck_nostun", "nostun-secret", 2) == 0, "credential not stored");
    runtime_session client;
    CHECK(egress_login(server, "ck_nostun", "nostun-secret", "machine-nostun", 0, &client, NULL) == 0,
          "client login without STUN/TURN");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    CHECK(fd >= 0, "UDP socket");
    struct timeval timeout = {0, 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;
    target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    target.sin_port = htons((unsigned short)stun_turn_port);
    uint8_t binding[20] = {0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    uint8_t answer[512];
    int sent = sendto(fd, binding, sizeof(binding), 0, (struct sockaddr *)&target, sizeof(target)) == (ssize_t)sizeof(binding);
    ssize_t received = recvfrom(fd, answer, sizeof(answer), 0, NULL, NULL);
    close(fd);
    CHECK(sent && received < 0, "a STUN Binding was answered (%zd bytes) although STUN/TURN failed to start", received);
    char line[128];
    snprintf(line, sizeof(line), "[peer-mesh] standard STUN/TURN UDP server failed to start on %d", stun_turn_port);
    FILE *log = fopen(server->log_path, "r");
    char text[16384] = "";
    size_t text_len = log == NULL ? 0U : fread(text, 1, sizeof(text) - 1U, log);
    text[text_len] = '\0';
    if (log != NULL) fclose(log);
    CHECK(strstr(text, line) != NULL, "no log line \"%s\"", line);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <specus-server-c>\n", argv[0]);
        return 2;
    }
    server_binary = argv[1];
    setvbuf(stdout, NULL, _IOLBF, 0);
    signal(SIGPIPE, SIG_IGN);
    srand((unsigned int)wall_clock_ms());
    /* Peer Mesh on, its STUN/TURN listener on an ephemeral loopback port. */
    static const char *const peer_mesh[] = {
        "SPECUS_PEER_MESH_ENABLED=true", "SPECUS_PEER_MESH_STUN_TURN_PORT=0",
        "SPECUS_PEER_MESH_BIND_ADDRESS=127.0.0.1", NULL,
    };
    int failures = run_on_fresh_server("egress-report over a real control connection", scenario_egress_report,
                                       peer_mesh);
    /* RFC 2606 reserves .invalid: the public address never resolves. */
    static char port_setting[64];
    stun_turn_port = pick_free_port();
    snprintf(port_setting, sizeof(port_setting), "SPECUS_PEER_MESH_STUN_TURN_PORT=%d", stun_turn_port);
    const char *const unresolvable[] = {
        "SPECUS_PEER_MESH_ENABLED=true", port_setting, "SPECUS_PEER_MESH_BIND_ADDRESS=127.0.0.1",
        "SPECUS_PEER_MESH_PUBLIC_ADDRESS=no-such-host.invalid", NULL,
    };
    failures += run_on_fresh_server("the server runs on when STUN/TURN cannot start", scenario_without_stun_turn,
                                    unresolvable);
    if (failures != 0) {
        fprintf(stderr, "%d peer mesh scenario(s) failed\n", failures);
        return 1;
    }
    printf("peer mesh e2e tests passed\n");
    return 0;
}
