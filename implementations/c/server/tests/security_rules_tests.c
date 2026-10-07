/*
 * Java SecurityRulesTests against a real specus-server-c process, the rules the other suites leave
 * out:
 *
 *   - an unknown one-time download grant is gone (410) without a session, and the OSS upload
 *     callback is anonymous but refuses an invalid signature (403);
 *   - a foreign Bearer token on the public HTTP entry is not management authentication: the entry
 *     answers itself, 404 "HTTP 路由不存在或未启用" for a route without a server record;
 *   - the management page carries the portal Content-Security-Policy (frame-ancestors 'none',
 *     connect-src with https://api.github.com and, when configured, the aliyun-oss bucket), while
 *     /http/ answers carry none of the portal's headers;
 *   - the cloud diagram API needs a session, and an account manages its own diagram with it;
 *   - a protected route challenges without credentials and lets valid ones through to the offline
 *     client's 502 "客户端不在线".
 *
 * Usage: specus_c_security_rules_tests <path-to-specus-server-c>
 */
#define _POSIX_C_SOURCE 200809L

#include "server_harness.h"

#include "crypto.h"
#include "json.h"
#include "storage.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* One whole answer of the server, head and body, read to the end of the connection. */
typedef struct {
    int status;
    char text[16384];
    size_t len;
} raw_answer;

static int raw_request(const test_server *server, const char *request, raw_answer *answer)
{
    memset(answer, 0, sizeof(*answer));
    int fd = connect_local(server->admin_port);
    if (fd < 0 || send_all(fd, (const uint8_t *)request, strlen(request)) != 0) {
        close_fd(&fd);
        return -1;
    }
    long long deadline = monotonic_ms() + IO_TIMEOUT_MS;
    for (;;) {
        long long remaining = deadline - monotonic_ms();
        struct pollfd ready = {.fd = fd, .events = POLLIN, .revents = 0};
        if (remaining <= 0 || poll(&ready, 1, (int)remaining) <= 0) {
            break;
        }
        ssize_t received = recv(fd, answer->text + answer->len, sizeof(answer->text) - 1U - answer->len, 0);
        if (received < 0 && errno == EINTR) {
            continue;
        }
        if (received <= 0) {
            break;
        }
        answer->len += (size_t)received;
        if (answer->len == sizeof(answer->text) - 1U) {
            break;
        }
    }
    close_fd(&fd);
    answer->text[answer->len] = '\0';
    if (sscanf(answer->text, "HTTP/1.1 %d", &answer->status) != 1) {
        answer->status = 0;
    }
    return 0;
}

/* The answer's header block only, so a check of a header never matches the body. */
static void answer_head(const raw_answer *answer, char *out, size_t out_len)
{
    const char *end = strstr(answer->text, "\r\n\r\n");
    size_t len = end == NULL ? answer->len : (size_t)(end - answer->text) + 2U;
    if (len >= out_len) {
        len = out_len - 1U;
    }
    memcpy(out, answer->text, len);
    out[len] = '\0';
}

static int expect_status(const raw_answer *answer, int status, const char *needle, const char *what)
{
    if (answer->status != status || (needle != NULL && strstr(answer->text, needle) == NULL)) {
        fprintf(stderr, "%s: expected %d%s%s, got:\n%s\n", what, status, needle == NULL ? "" : " with ",
                needle == NULL ? "" : needle, answer->text);
        return -1;
    }
    return 0;
}

static int admin_token(const test_server *server, char *token, size_t token_len)
{
    char body[256];
    int status = 0;
    char *response = NULL;
    snprintf(body, sizeof(body), "{\"username\":\"%s\",\"password\":\"%s\"}", ADMIN_USERNAME, ADMIN_PASSWORD);
    if (http_request(server->admin_port, "POST", "/auth/login", body, NULL, &status, &response) != 0
        || status != 200) {
        free(response);
        return -1;
    }
    char *value = st_json_get_top_level_string(response, "accessToken");
    free(response);
    if (value == NULL || strlen(value) >= token_len) {
        free(value);
        return -1;
    }
    snprintf(token, token_len, "%s", value);
    free(value);
    return 0;
}

/* oneTimeDownloadGrantIsPublicButUnknownTokenIsGone, ossUploadCallbackIsAnonymousButRejectsInvalidSignature */
static int check_public_transfer_rules(test_server *server)
{
    raw_answer answer;
    CHECK(raw_request(server, "GET /api/public/transfer/downloads/not-a-real-token HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Connection: close\r\n\r\n", &answer) == 0, "grant request");
    CHECK(expect_status(&answer, 410, NULL, "an unknown one-time download grant") == 0, "unknown grant");
    CHECK(raw_request(server, "POST /api/public/transfer/oss-callback HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Content-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                      &answer) == 0, "callback request");
    CHECK(expect_status(&answer, 403, NULL, "an OSS callback without a valid signature") == 0, "OSS callback");
    return 0;
}

/* publicHttpProxyIgnoresForeignBearerToken, httpSpecusIngressDoesNotInheritManagementContentSecurityPolicy */
static int check_public_entry_rules(test_server *server)
{
    raw_answer answer;
    char head[4096];
    CHECK(raw_request(server, "GET /http/missing-client/nacos/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Authorization: Bearer nacos-owned-token\r\nConnection: close\r\n\r\n", &answer) == 0,
          "entry request with a foreign token");
    CHECK(expect_status(&answer, 404, "HTTP 路由不存在或未启用", "a foreign Bearer token on the public entry") == 0,
          "the entry itself must answer, not management authentication");

    CHECK(raw_request(server, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &answer) == 0,
          "portal request");
    CHECK(expect_status(&answer, 200, NULL, "the management page") == 0, "portal");
    answer_head(&answer, head, sizeof(head));
    CHECK(strstr(head, "\r\nContent-Security-Policy: ") != NULL && strstr(head, "frame-ancestors 'none'") != NULL
              && strstr(head, "connect-src 'self' ws: wss: https://api.github.com") != NULL
              && strstr(head, "\r\nX-Frame-Options: DENY\r\n") != NULL
              && strstr(head, "\r\nX-Content-Type-Options: nosniff\r\n") != NULL
              && strstr(head, "\r\nReferrer-Policy: strict-origin-when-cross-origin\r\n") != NULL,
          "the management page must carry the portal security headers:\n%s", head);

    CHECK(raw_request(server, "GET /http/missing-client/nacos/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Connection: close\r\n\r\n", &answer) == 0, "entry request");
    CHECK(expect_status(&answer, 404, "HTTP 路由不存在或未启用", "a route without a server record") == 0, "entry");
    answer_head(&answer, head, sizeof(head));
    CHECK(strstr(head, "Content-Security-Policy") == NULL && strstr(head, "X-Frame-Options") == NULL
              && strstr(head, "X-Content-Type-Options") == NULL,
          "the public entry must not inherit the portal headers:\n%s", head);
    return 0;
}

/* cloudDiagramApiRequiresAuthentication, authenticatedAccountCanManageItsCloudDiagram */
static int check_cloud_diagram_rules(test_server *server)
{
    raw_answer answer;
    CHECK(raw_request(server, "GET /api/admin/diagrams HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
                      &answer) == 0, "anonymous diagram request");
    CHECK(expect_status(&answer, 401, NULL, "the diagram API without a session") == 0, "anonymous diagrams");

    char token[1024];
    CHECK(admin_token(server, token, sizeof(token)) == 0, "management login");
    int status = 0;
    char *body = NULL;
    CHECK(http_request(server->admin_port, "POST", "/api/admin/diagrams",
                       "{\"name\":\"云端架构图\",\"update\":\"AQID\"}", token, &status, &body) == 0 && status == 201,
          "diagram create: %d %s", status, body == NULL ? "" : body);
    long long id = 0;
    long long revision = -1;
    int parsed = st_json_get_i64(body, "id", &id) == 0 && st_json_get_i64(body, "revision", &revision) == 0;
    free(body);
    CHECK(parsed, "diagram id and revision");

    char path[96];
    body = NULL;
    CHECK(http_request(server->admin_port, "GET", "/api/admin/diagrams", NULL, token, &status, &body) == 0
              && status == 200 && body != NULL && strstr(body, "云端架构图") != NULL,
          "diagram list: %d %s", status, body == NULL ? "" : body);
    free(body);
    snprintf(path, sizeof(path), "/api/admin/diagrams/%lld", id);
    body = NULL;
    CHECK(http_request(server->admin_port, "GET", path, NULL, token, &status, &body) == 0 && status == 200
              && body != NULL && strstr(body, "\"update\":\"AQID\"") != NULL,
          "diagram detail: %d %s", status, body == NULL ? "" : body);
    free(body);
    char update[160];
    snprintf(update, sizeof(update), "{\"name\":\"云端架构图 v2\",\"update\":\"BAUG\",\"revision\":%lld}", revision);
    body = NULL;
    long long updated_revision = -1;
    CHECK(http_request(server->admin_port, "PUT", path, update, token, &status, &body) == 0 && status == 200
              && st_json_get_i64(body, "revision", &updated_revision) == 0 && updated_revision > revision,
          "diagram update: %d %s", status, body == NULL ? "" : body);
    free(body);
    body = NULL;
    CHECK(http_request(server->admin_port, "DELETE", path, NULL, token, &status, &body) == 0 && status == 204,
          "diagram delete: %d", status);
    free(body);
    return 0;
}

/* clientDetailExposesRouteAuthenticationStateWithoutPasswordOrHash, the public entry half */
static int check_protected_route_entry(test_server *server)
{
    uint8_t digest[ST_SHA256_LEN];
    char password_hash[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"s3cret-value", strlen("s3cret-value"), digest);
    st_hex_encode(digest, sizeof(digest), password_hash);
    st_storage_client client;
    st_storage_http_route route;
    CHECK(st_storage_upsert_client(server->db_path, 0, "default", "route-auth-detail", ADMIN_USERNAME, 1, 60,
                                   &client) == 0
              && st_storage_create_http_route_for_client(server->db_path, client.id, "private", "http://127.0.0.1:8080",
                                                         1, 0, 0, 0, 0, 1, "viewer", password_hash, &route) == 0,
          "protected route");
    raw_answer answer;
    char head[4096];
    CHECK(raw_request(server, "GET /http/route-auth-detail/private/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Connection: close\r\n\r\n", &answer) == 0, "request without credentials");
    CHECK(expect_status(&answer, 401, NULL, "a protected route without credentials") == 0, "challenge");
    answer_head(&answer, head, sizeof(head));
    CHECK(strstr(head, "\r\nWWW-Authenticate: Basic realm=\"Specus HTTP Route\", charset=\"UTF-8\"\r\n") != NULL
              && strstr(head, "\r\nCache-Control: no-store\r\n") != NULL,
          "the challenge headers:\n%s", head);
    /* viewer:s3cret-value */
    CHECK(raw_request(server, "GET /http/route-auth-detail/private/ HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                              "Authorization: Basic dmlld2VyOnMzY3JldC12YWx1ZQ==\r\nConnection: close\r\n\r\n",
                      &answer) == 0, "request with credentials");
    CHECK(expect_status(&answer, 502, "客户端不在线", "valid credentials before the offline client") == 0,
          "valid credentials must pass the gate");
    return 0;
}

static int scenario_security_rules(test_server *server)
{
    return check_public_transfer_rules(server)
        || check_public_entry_rules(server)
        || check_cloud_diagram_rules(server)
        || check_protected_route_entry(server);
}

/* With aliyun-oss configured the portal policy lets the browser reach the bucket directly. */
static int scenario_oss_origin(test_server *server)
{
    raw_answer answer;
    char head[4096];
    CHECK(raw_request(server, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n", &answer) == 0,
          "portal request");
    CHECK(expect_status(&answer, 200, NULL, "the management page") == 0, "portal");
    answer_head(&answer, head, sizeof(head));
    CHECK(strstr(head, "connect-src 'self' ws: wss: https://api.github.com https://www.google-analytics.com "
                       "https://*.analytics.google.com https://*.googletagmanager.com "
                       "https://specus-files.oss-cn-hangzhou.aliyuncs.com; ") != NULL
              && strstr(head, "media-src 'self' blob: data: https://specus-files.oss-cn-hangzhou.aliyuncs.com; ") != NULL,
          "the bucket origin is missing from the portal policy:\n%s", head);
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

    /* A portal stand-in: the policy belongs to the page, whatever the page holds. */
    const char *tmp = getenv("TMPDIR");
    static char static_root[256];
    static char index_path[320];
    static char static_root_env[300];
    snprintf(static_root, sizeof(static_root), "%s/specus-c-portal-XXXXXX", tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    if (mkdtemp(static_root) == NULL) {
        fprintf(stderr, "cannot create the portal directory\n");
        return 1;
    }
    snprintf(index_path, sizeof(index_path), "%s/index.html", static_root);
    FILE *index = fopen(index_path, "w");
    if (index == NULL) {
        rmdir(static_root);
        return 1;
    }
    fputs("<!doctype html><title>Specus</title>\n", index);
    fclose(index);
    snprintf(static_root_env, sizeof(static_root_env), "SPECUS_STATIC_ROOT=%s", static_root);
    const char *const portal[] = {static_root_env, NULL};

    int failures = run_on_fresh_server("security rules", scenario_security_rules, portal);
    /* The server inherits these; the bucket only shapes the policy here. */
    setenv("SPECUS_OBJECT_STORAGE_PROVIDER", "aliyun-oss", 1);
    setenv("SPECUS_OBJECT_STORAGE_ENDPOINT", "https://oss-cn-hangzhou.aliyuncs.com/", 1);
    setenv("SPECUS_OBJECT_STORAGE_BUCKET", " specus-files ", 1);
    setenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID", "test-access-key-id", 1);
    setenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET", "test-access-key-secret", 1);
    failures += run_on_fresh_server("portal policy with the aliyun-oss bucket", scenario_oss_origin, portal);
    unlink(index_path);
    rmdir(static_root);
    if (failures != 0) {
        fprintf(stderr, "%d security rules scenario(s) failed\n", failures);
        return 1;
    }
    printf("security rules tests passed\n");
    return 0;
}
