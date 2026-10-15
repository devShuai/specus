#define _GNU_SOURCE
#include "server_harness.h"
#include "json.h"
#include "storage.h"
#include <dlfcn.h>
#include <limits.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int marker(const test_server *server, const char *name)
{
    char path[512]; snprintf(path, sizeof(path), "%s/%s", server->dir, name);
    FILE *file = fopen(path, "w"); if (!file) return -1; return fclose(file);
}
static int wait_marker(const test_server *server)
{
    char path[512]; snprintf(path, sizeof(path), "%s/ready", server->dir);
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (access(path, F_OK)) { if (monotonic_ms() >= deadline) return -1; sleep_ms(1); }
    return 0;
}
static int send_peer(int fd, const runtime_session *runtime, const char *message)
{
    st_buffer packet = st_protocol_encode_message_response(runtime->client_name, NULL, ST_MESSAGE_TYPE_PEER_CONTROL, message);
    if (!packet.data) return -1;
    packet.data[6] = ST_CMD_MESSAGE_REQUEST;
    return send_buffer(fd, &packet);
}
static int wait_peer(int fd, const char *type, const runtime_session *publisher, int empty, long long *revision)
{
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    while (monotonic_ms() < deadline) {
        st_frame_header header; uint8_t *body = NULL; st_message_response message = {0};
        if (read_frame(fd, (int)(deadline - monotonic_ms()), &header, &body) != 1) return -1;
        int decoded = header.command == ST_CMD_MESSAGE_RESPONSE
            && st_protocol_decode_message_response(body, header.length, &message) == 0;
        free(body);
        char *actual = decoded && message.message ? st_json_get_top_level_string(message.message, "type") : NULL;
        int found = actual && strcmp(actual, type) == 0;
        free(actual);
        if (found && strcmp(type, "service-catalog") == 0) {
            long long cid = 0, session = 0;
            found = st_json_get_i64(message.message, "publisherClientId", &cid) == 0 && cid == publisher->client_id
                && st_json_get_i64(message.message, "publisherSessionId", &session) == 0 && session == publisher->session_id;
            if (found) {
                char *name = st_json_get_top_level_string(message.message, "publisherClientName");
                int ok = st_json_get_i64(message.message, "revision", revision) == 0
                    && name && strcmp(name, publisher->client_name) == 0
                    && (empty ? strstr(message.message, "\"services\":[]") != NULL
                              : strstr(message.message, "\"serviceId\":\"svc-reconnect\"") != NULL)
                    && strstr(message.message, "targetHost") == NULL && strstr(message.message, "untrusted-name") == NULL;
                free(name);
                if (!ok) fprintf(stderr, "unexpected actual catalog: %s\n", message.message);
                st_message_response_free(&message);
                return ok ? 0 : -1;
            }
        }
        st_message_response_free(&message);
        if (found) return 0;
    }
    return -1;
}
static char *admin_token(const test_server *server)
{
    char body[512]; snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    char *answer = NULL; int status = 0;
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &answer) != 0) return NULL;
    char *token = status == 200 ? st_json_get_top_level_string(answer, "accessToken") : NULL;
    free(answer); return token;
}
static int instances(const test_server *server, const char *token, int present, const char *instance)
{
    char *answer = NULL; int status = 0;
    int rc = http_request(server->admin_port, "GET", "/api/admin/peer-mesh/services", NULL, token, &status, &answer);
    int valid = rc == 0 && status == 200 && answer && strstr(answer, "\"serviceId\":\"svc-reconnect\"")
        && (present ? strstr(answer, "\"advertised\":true") != NULL && strstr(answer, instance) != NULL
                    : strstr(answer, "\"instances\":[]") != NULL);
    if (valid && present && strcmp(instance, "old-physical") != 0)
        valid = strstr(answer, "old-physical") == NULL && strstr(answer, "\"bytesIn\":987") == NULL
            && strstr(answer, "\"bytesIn\":0") != NULL;
    if (!valid) fprintf(stderr, "actual service instances status=%d: %s\n", status, answer ? answer : "(none)");
    free(answer); return valid ? 0 : -1;
}
static int sql(const test_server *server, const char *statement)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open(server->db_path, &db);
    if (rc == SQLITE_OK) { sqlite3_busy_timeout(db, 5000); rc = sqlite3_exec(db, statement, NULL, NULL, NULL); }
    if (rc != SQLITE_OK) fprintf(stderr, "native fixture SQL failed: %s\n", db ? sqlite3_errmsg(db) : "open");
    sqlite3_close(db); return rc == SQLITE_OK ? 0 : -1;
}
static int send_report(int fd, const runtime_session *publisher, long long revision, const char *instance, int old_stats)
{
    char report[2048];
    snprintf(report, sizeof(report),
        "{\"type\":\"service-report\",\"enabled\":true,\"revision\":%lld,\"instanceId\":\"%s\","
        "\"services\":[{\"serviceId\":\"svc-reconnect\",\"name\":\"untrusted-name\",\"transport\":\"tcp\","
        "\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}]%s}", revision, instance,
        old_stats ? ",\"stats\":[{\"serviceId\":\"svc-reconnect\",\"bytesIn\":987,\"totalConnections\":4}],"
            "\"mdnsCandidates\":[{\"name\":\"Old Local\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":8080}]" : "");
    return send_peer(fd, publisher, report);
}
static int scenario(const char *library)
{
    test_server server; int prepared = 0, started = 0, failed = 1;
    int old = -1, replacement = -1, recipient = -1, blocker = -1, rejected = -1;
    char *token = NULL; char reason[512], preload[512], barrier[512], trigger[512];
    runtime_session p, r, b; st_storage_client account; st_storage_peer_mesh_device device;
    long long first = 0, withdrawal = 0, fresh = 0, next = 0;
#define REQUIRE(c, label) do { if (!(c)) { fprintf(stderr, "FAIL real catalog reconnect: %s\n", label); goto done; } } while (0)
    REQUIRE(server_prepare(&server) == 0, "prepare"); prepared = 1;
    void *asan = dlsym(RTLD_DEFAULT, "__asan_init"); Dl_info sanitizer = {0};
    if (asan && dladdr(asan, &sanitizer) && sanitizer.dli_fname)
        snprintf(preload, sizeof(preload), "LD_PRELOAD=%s:%s", sanitizer.dli_fname, library);
    else snprintf(preload, sizeof(preload), "LD_PRELOAD=%s", library);
    snprintf(barrier, sizeof(barrier), "SPECUS_TEST_CONTROL_BARRIER_DIR=%s", server.dir);
    server.extra_env[0] = preload; server.extra_env[1] = barrier;
    server.extra_env[2] = "SPECUS_PEER_MESH_ENABLED=true"; server.extra_env[3] = "SPECUS_PEER_MESH_STUN_TURN_PORT=0";
    REQUIRE(server_start(&server) == 0, "start"); started = 1;
    REQUIRE(create_credential(server.db_path, "ck_catalog", "catalog-secret", 4) == 0, "credential");
    harness_login_environment_extra = ",\"clientPeerServiceCapabilities\":{\"version\":2,\"applications\":[\"http\"]},"
        "\"clientEgressCapabilities\":{\"version\":1,\"egressCapable\":true,\"consumerCapable\":true}";
    REQUIRE(http_client_login(&server, "ck_catalog", "catalog-secret", "catalog-p", "user", &p) == 0
        && http_client_login(&server, "ck_catalog", "catalog-secret", "catalog-r", "user", &r) == 0
        && http_client_login(&server, "ck_catalog", "catalog-secret", "catalog-b", "user", &b) == 0, "real signed HTTP v2 sessions");
    const runtime_session *clients[] = {&p, &r, &b};
    for (size_t i = 0; i < 3; ++i) {
        REQUIRE(st_storage_get_client(server.db_path, clients[i]->client_id, &account) == 0
            && st_storage_update_peer_mesh_device_enabled(server.db_path, &account, 1, &device) == 0, "enable native Peer device");
    }
    REQUIRE(st_storage_get_client(server.db_path, p.client_id, &account) == 0
        && st_storage_upsert_peer_mesh_service_sharing(server.db_path, account.tenant_id, 1, 1, ADMIN_USERNAME, NULL) == 0, "service sharing");
    st_storage_peer_mesh_service definition = {0};
    snprintf(definition.tenant_id, sizeof(definition.tenant_id), "%s", account.tenant_id);
    definition.client_id = p.client_id; snprintf(definition.client_name, sizeof(definition.client_name), "%s", p.client_name);
    snprintf(definition.service_id, sizeof(definition.service_id), "svc-reconnect");
    snprintf(definition.name, sizeof(definition.name), "Catalog Service");
    snprintf(definition.transport, sizeof(definition.transport), "tcp"); snprintf(definition.application, sizeof(definition.application), "http");
    snprintf(definition.target_host, sizeof(definition.target_host), "127.0.0.1"); snprintf(definition.path, sizeof(definition.path), "/");
    snprintf(definition.visibility, sizeof(definition.visibility), "OWNER"); definition.target_port = 8080;
    definition.published_port = 18080; definition.enabled = 1;
    REQUIRE(st_storage_upsert_peer_mesh_service(server.db_path, &definition, NULL) == 0, "native authoritative service");
    token = admin_token(&server); REQUIRE(token != NULL, "admin auth");
    REQUIRE(channel_login(server.control_port, &r, ST_CONNECTION_ROLE_CONTROL, &recipient, reason, sizeof(reason)) == 1
        && wait_peer(recipient, "peer-config", NULL, 0, NULL) == 0, "recipient physical CONTROL");
    REQUIRE(channel_login(server.control_port, &b, ST_CONNECTION_ROLE_CONTROL, &blocker, reason, sizeof(reason)) == 1
        && wait_peer(blocker, "peer-config", NULL, 0, NULL) == 0, "blocker physical CONTROL");
    REQUIRE(channel_login(server.control_port, &p, ST_CONNECTION_ROLE_CONTROL, &old, reason, sizeof(reason)) == 1
        && wait_peer(old, "peer-config", NULL, 0, NULL) == 0, "publisher original CONTROL");
    REQUIRE(send_report(old, &p, LLONG_MAX, "old-physical", 1) == 0
        && wait_peer(recipient, "service-catalog", &p, 0, &first) == 0
        && first > 0 && first < LLONG_MAX
        && instances(&server, token, 1, "old-physical") == 0, "raw MAX accepted with bounded output clock and original live instance");
    snprintf(trigger, sizeof(trigger), "CREATE TRIGGER reject_catalog_reconnect BEFORE UPDATE ON specus_client_session "
        "WHEN OLD.id=%lld AND NEW.status='NETTY_ONLINE' AND NEW.channel_id<>OLD.channel_id "
        "BEGIN SELECT RAISE(ABORT,'native admission fault'); END", p.session_id);
    REQUIRE(sql(&server, trigger) == 0, "real native ONLINE failure trigger");
    REQUIRE(channel_login(server.control_port, &p, ST_CONNECTION_ROLE_CONTROL, &rejected, reason, sizeof(reason)) == 0
        && strstr(reason, "服务器繁忙") != NULL && expect_channel_alive(old) == 0
        && instances(&server, token, 1, "old-physical") == 0, "failed native admission preserves original source, report and live directory");
    REQUIRE(sql(&server, "DROP TRIGGER reject_catalog_reconnect") == 0, "remove native fault");
    REQUIRE(marker(&server, "arm") == 0 && send_peer(blocker, &b, "{\"type\":\"egress-report\",\"revision\":1}") == 0
        && wait_marker(&server) == 0, "independent real business holds Peer dispatcher after its DB closes");
    REQUIRE(channel_login(server.control_port, &p, ST_CONNECTION_ROLE_CONTROL, &replacement, reason, sizeof(reason)) == 1
        && expect_channel_alive(replacement) == 0 && expect_channel_alive(recipient) == 0, "same SID physical reconnect and heartbeats do not await global publication");
    REQUIRE(instances(&server, token, 0, NULL) == 0, "old directory logically absent before blocked publisher can emit or accept a fresh report");
    REQUIRE(send_report(replacement, &p, 1, "new-physical", 0) == 0 && expect_channel_alive(replacement) == 0,
            "new physical raw1 queued behind its own ordered withdrawal");
    REQUIRE(marker(&server, "resume") == 0, "resume unrelated dispatcher");
    REQUIRE(wait_peer(recipient, "service-catalog", &p, 1, &withdrawal) == 0
        && withdrawal == first + 1, "empty withdrawal precedes fresh catalog; aborted admission used no wire revision");
    REQUIRE(wait_peer(recipient, "service-catalog", &p, 0, &fresh) == 0 && fresh == withdrawal + 1
        && instances(&server, token, 1, "new-physical") == 0 && expect_channel_closed(old, IO_TIMEOUT_MS) == 0,
            "raw1 accepted on same SID, old instance/stats removed, original physical source retired");
    REQUIRE(send_report(replacement, &p, 1, "duplicate-must-not-win", 0) == 0
        && send_report(replacement, &p, 2, "next-physical", 0) == 0
        && wait_peer(recipient, "service-catalog", &p, 0, &next) == 0 && next == fresh + 1
        && instances(&server, token, 1, "next-physical") == 0, "new generation raw high-water still ignores duplicates");
    printf("OBSERVATION actual sameSID=%lld catalog revisions old=%lld withdrawal=%lld raw1=%lld raw2=%lld\n",
           p.session_id, first, withdrawal, fresh, next);
    failed = 0;
done:
    harness_login_environment_extra = "";
    if (prepared) marker(&server, "resume");
    close_fd(&old); close_fd(&replacement); close_fd(&recipient); close_fd(&blocker); close_fd(&rejected);
    if (started && server_stop(&server, 20000) != 0) failed = 1;
    if (!failed) {
        char count[64];
        if (db_scalar(server.db_path, "SELECT COUNT(*) FROM peer_mesh_service_audit WHERE session_id=? AND reason='control-reconnected'",
                       NULL, p.session_id, count, sizeof(count)) != 0 || strcmp(count, "1") != 0) {
            fprintf(stderr, "FAIL native reconnect audit count=%s\n", count); failed = 1;
        }
    }
    free(token);
    if (prepared) {
        const char *names[] = {"arm", "ready", "resume"};
        for (size_t i = 0; i < 3; ++i) { char path[512]; snprintf(path, sizeof(path), "%s/%s", server.dir, names[i]); unlink(path); }
        server_cleanup(&server, failed);
    }
    printf("%s real signedHTTP/nativeSQLite/physicalCONTROL catalog reconnect rollback, cutover and monotonic wire order\n", failed ? "FAIL" : "PASS");
    return failed;
#undef REQUIRE
}
int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    signal(SIGPIPE, SIG_IGN); server_binary = argv[1]; return scenario(argv[2]);
}
