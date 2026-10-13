/*
 * The Peer Mesh and Egress management endpoints against the Java controllers and services they
 * mirror (PeerMeshResource, PeerEgressResource, PeerMeshService, PeerSignalService,
 * PeerServiceDiscoveryService, PeerEgressService): Spring's 400 for a body or parameter that does not
 * bind, the services' checks in order with their messages, the status codes, the view fields and
 * their ISO-8601 times, and the close messages both ends of a session hear when the management API
 * closes it. Also the other management parameters Spring converts, the TCP mapping create's
 * public-port rule and the forwarded host of the public STUN configuration. Every request goes over
 * real HTTP to an in-process admin listener with real management tokens.
 *
 *   peer_mesh_api_tests
 */
#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "json.h"
#include "security.h"
#include "server_harness.h"
#include "storage.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define JWT_SECRET "peer-mesh-api-jwt-secret-long-enough-2026"
#define BUILT_IN "pm-root"
#define TENANT "t-peer"
#define OTHER_TENANT "t-peer-other"

static char db_path[320];
static int port = 0;
static char admin_token[1024]; /* pm-admin, ADMIN of t-peer */
static char user_token[1024];  /* pm-user, USER of t-peer */
static long long client_a = 0; /* pm-admin's, with a device */
static long long client_b = 0; /* pm-user's, with a device */
static long long client_c = 0; /* pm-user's, never logged in: no device */
static long long client_d = 0; /* another tenant's */

static int last_status = 0;
static char *last_body = NULL;

/* PEER_CONTROL messages the management API sent, with their target. */
static pthread_mutex_t sent_lock = PTHREAD_MUTEX_INITIALIZER;
static char sent[64][1024];
static size_t sent_count = 0U;

static int capture_peer_control(void *ctx, const char *target_client_name, const char *message)
{
    (void)ctx;
    pthread_mutex_lock(&sent_lock);
    if (sent_count < 64U) {
        snprintf(sent[sent_count++], sizeof(sent[0]), "%s|%s", target_client_name, message);
    }
    pthread_mutex_unlock(&sent_lock);
    return 0;
}

/* How many captured messages went to target and contain needle. */
static size_t sent_matching(const char *target, const char *needle)
{
    size_t count = 0U;
    char prefix[300];
    snprintf(prefix, sizeof(prefix), "%s|", target);
    pthread_mutex_lock(&sent_lock);
    for (size_t i = 0U; i < sent_count; ++i) {
        if (strncmp(sent[i], prefix, strlen(prefix)) == 0 && strstr(sent[i], needle) != NULL) ++count;
    }
    pthread_mutex_unlock(&sent_lock);
    return count;
}

static int call(const char *method, const char *path, const char *body, const char *token)
{
    free(last_body);
    last_body = NULL;
    last_status = 0;
    if (http_request(port, method, path, body, token, &last_status, &last_body) != 0) {
        last_status = -1;
    }
    return last_status;
}

/* method path answers status, and the body holds needle (NULL: anything). */
static int expect(const char *method, const char *path, const char *body, const char *token, int status,
                  const char *needle)
{
    int answered = call(method, path, body, token);
    if (answered == status && (needle == NULL || (last_body != NULL && strstr(last_body, needle) != NULL))) {
        return 0;
    }
    fprintf(stderr, "FAIL %s %s %s: expected %d%s%s, got %d %s\n", method, path, body == NULL ? "" : body, status,
            needle == NULL ? "" : " with ", needle == NULL ? "" : needle, answered,
            last_body == NULL ? "" : last_body);
    return -1;
}

/* Spring's own 400, for a body or parameter that does not bind. */
static int expect_spring_400(const char *method, const char *path, const char *body, const char *token)
{
    return expect(method, path, body, token, 400, "{\"error\":\"Bad Request\"}");
}

static int exec_sql(const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    int rc = sqlite3_open(db_path, &db) == SQLITE_OK && sqlite3_busy_timeout(db, 5000) == SQLITE_OK
        && sqlite3_exec(db, sql, NULL, NULL, &error) == SQLITE_OK ? 0 : -1;
    if (rc != 0) fprintf(stderr, "sql failed: %s: %s\n", sql, error == NULL ? "sqlite error" : error);
    sqlite3_free(error);
    sqlite3_close(db);
    return rc;
}

/* Java Instant.toString of a whole second: "YYYY-MM-DDTHH:MM:SSZ". */
static int is_instant(const char *text)
{
    static const char pattern[] = "dddd-dd-ddTdd:dd:ddZ";
    if (strlen(text) != sizeof(pattern) - 1U) return 0;
    for (size_t i = 0; i < sizeof(pattern) - 1U; ++i) {
        if (pattern[i] == 'd' ? !isdigit((unsigned char)text[i]) : text[i] != pattern[i]) return 0;
    }
    return 1;
}

/* The first string value of key in the last answer is an instant. */
static int last_has_instant(const char *key)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "\"%s\":\"", key);
    const char *at = last_body == NULL ? NULL : strstr(last_body, needle);
    if (at == NULL) return 0;
    char value[32];
    snprintf(value, sizeof(value), "%.20s", at + strlen(needle));
    return is_instant(value);
}

static int insert_open_session(long long id, long long source, const char *source_name, long long target,
                               const char *target_name)
{
    char sql[1024];
    snprintf(sql, sizeof(sql),
             "INSERT INTO peer_mesh_session(id, tenant_id, source_client_id, source_client_name, target_client_id, "
             "target_client_name, path_type, status, token_hash, started_at, updated_at, expires_at) VALUES "
             "(%lld, '" TENANT "', %lld, '%s', %lld, '%s', 'DIRECT', 'ACTIVE', 'hash', CURRENT_TIMESTAMP, "
             "CURRENT_TIMESTAMP, datetime('now', '+1 hour'))",
             id, source, source_name, target, target_name);
    return exec_sql(sql);
}

static int session_status_is(long long id, const char *status)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    int matches = 0;
    if (sqlite3_open(db_path, &db) == SQLITE_OK
        && sqlite3_prepare_v2(db, "SELECT status FROM peer_mesh_session WHERE id = ?", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, id);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *text = sqlite3_column_text(stmt, 0);
            matches = text != NULL && strcmp((const char *)text, status) == 0;
        }
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return matches;
}

/* ---- devices ------------------------------------------------------------------------------- */

/*
 * PeerMeshService.listDevices and updateDevice, and PeerSignalService.refreshDevice: only devices
 * that exist are listed (the tenant's, or a USER's own), the view is Java's 21 fields with nothing
 * reported as null, an update needs an existing device the caller may see, and disabling a device
 * closes its open sessions and tells both ends.
 */
static int test_devices(void)
{
    char path[160];
    char needle[160];
    int failed = expect("GET", "/api/admin/peer-mesh/devices", NULL, admin_token, 200, "\"clientName\":\"pm-a\"") != 0
        || strstr(last_body, "\"clientName\":\"pm-b\"") == NULL || strstr(last_body, "\"clientName\":\"pm-c\"") != NULL
        || strstr(last_body, "\"natType\":null") == NULL || strstr(last_body, "\"virtualDeviceMode\":null") == NULL
        || strstr(last_body, "\"lastSeenAt\":null") == NULL || strstr(last_body, "messageSendCapable") != NULL
        || !last_has_instant("updatedAt");
    failed = failed || expect("GET", "/api/admin/peer-mesh/devices", NULL, user_token, 200, "\"clientName\":\"pm-b\"") != 0
        || strstr(last_body, "\"clientName\":\"pm-a\"") != NULL;
    /* A client that never logged in has no device; a USER does not reach another owner's. */
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/devices/%lld", client_c);
    snprintf(needle, sizeof(needle), "{\"error\":\"peer device not found: %lld\"}", client_c);
    failed = failed || expect("PUT", path, "{\"enabled\":true}", admin_token, 400, needle) != 0;
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/devices/%lld", client_a);
    snprintf(needle, sizeof(needle), "{\"error\":\"peer device not found: %lld\"}", client_a);
    failed = failed || expect("PUT", path, "{\"enabled\":true}", user_token, 400, needle) != 0
        || expect("PUT", "/api/admin/peer-mesh/devices/0", "{}", admin_token, 400,
                  "{\"error\":\"peer device not found: 0\"}") != 0
        /* Spring: the path variable, the required body and the Boolean must bind. */
        || expect_spring_400("PUT", "/api/admin/peer-mesh/devices/abc", "{}", admin_token) != 0
        || expect_spring_400("PUT", path, NULL, admin_token) != 0
        || expect_spring_400("PUT", path, "{\"enabled\":\"maybe\"}", admin_token) != 0
        || expect_spring_400("PUT", path, "[true]", admin_token) != 0
        /* Jackson's Boolean takes "TRUE"; an absent flag leaves it as it is. */
        || expect("PUT", path, "{\"enabled\":\"TRUE\"}", admin_token, 200, "\"enabled\":true") != 0
        || expect("PUT", path, "{}", admin_token, 200, "\"enabled\":true") != 0;
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/devices/%lld", client_b);
    failed = failed || expect("PUT", path, "{\"enabled\":true}", user_token, 200, "\"enabled\":true") != 0;
    /* Disabling closes the device's open sessions; both ends hear the close. */
    failed = failed || insert_open_session(7001, client_a, "pm-a", client_b, "pm-b") != 0;
    sent_count = 0U;
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/devices/%lld", client_a);
    failed = failed || expect("PUT", path, "{\"enabled\":false}", admin_token, 200, "\"enabled\":false") != 0
        || !session_status_is(7001, "CLOSED")
        || sent_matching("pm-a", "\"sessionId\":7001") != 1U || sent_matching("pm-b", "admin-force-close") != 1U;
    failed = failed || expect("PUT", path, "{\"enabled\":true}", admin_token, 200, "\"enabled\":true") != 0;
    printf("%s devices as Java listDevices, updateDevice and refreshDevice\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- ACLs ---------------------------------------------------------------------------------- */

/*
 * PeerMeshService.createAcl (200, an upsert) with its checks in order, and deleteAcl (200 with no
 * body); PeerSignalService.refreshAuthorization closes the sessions an ACL change no longer allows.
 */
static int test_acls(void)
{
    char body[256];
    char needle[160];
    int failed = expect_spring_400("POST", "/api/admin/peer-mesh/acls", NULL, admin_token) != 0
        || expect_spring_400("POST", "/api/admin/peer-mesh/acls", "{\"sourceClientId\":\"x\"}", admin_token) != 0
        || expect_spring_400("POST", "/api/admin/peer-mesh/acls", "{\"sourceClientId\":1,\"allowed\":\"no way\"}",
                             admin_token) != 0
        || expect("POST", "/api/admin/peer-mesh/acls", "{}", admin_token, 400,
                  "{\"error\":\"sourceClientId is required\"}") != 0
        || expect("POST", "/api/admin/peer-mesh/acls", "{\"sourceClientId\":999999}", admin_token, 400,
                  "{\"error\":\"client not found: 999999\"}") != 0;
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":0}", client_a);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, admin_token, 400,
                              "{\"error\":\"targetClientId is required\"}") != 0;
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":%lld}", client_a, client_d);
    snprintf(needle, sizeof(needle), "{\"error\":\"client not found: %lld\"}", client_d);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, admin_token, 400, needle) != 0;
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":%lld}", client_a, client_a);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, admin_token, 400,
                              "{\"error\":\"source and target cannot be the same client\"}") != 0;
    /* A USER's source must be the user's own, and so must the target. */
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":%lld}", client_a, client_b);
    snprintf(needle, sizeof(needle), "{\"error\":\"client not found: %lld\"}", client_a);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, user_token, 400, needle) != 0;
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":%lld}", client_b, client_a);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, user_token, 400,
                              "{\"error\":\"普通用户不能创建跨用户 peer ACL\"}") != 0;
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":%lld,\"direction\":\"sideways\"}",
             client_a, client_b);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, admin_token, 400,
                              "{\"error\":\"invalid direction: sideways\"}") != 0;
    snprintf(body, sizeof(body), "{\"sourceClientId\":%lld,\"targetClientId\":%lld,\"direction\":\"both\"}",
             client_a, client_b);
    failed = failed || expect("POST", "/api/admin/peer-mesh/acls", body, admin_token, 200, "\"direction\":\"BOTH\"") != 0
        || !last_has_instant("createdAt") || !last_has_instant("updatedAt");
    long long acl_id = 0;
    failed = failed || last_body == NULL || st_json_get_i64(last_body, "id", &acl_id) != 0 || acl_id <= 0;
    failed = failed || expect("GET", "/api/admin/peer-mesh/acls", NULL, admin_token, 200, "\"direction\":\"BOTH\"") != 0
        || !last_has_instant("createdAt");
    /* Deleting the ACL closes the session it allowed between two owners' devices. */
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/devices/%lld", client_a);
    failed = failed || expect("PUT", path, "{\"enabled\":true}", admin_token, 200, NULL) != 0
        || insert_open_session(7002, client_a, "pm-a", client_b, "pm-b") != 0;
    sent_count = 0U;
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/acls/%lld", acl_id);
    failed = failed || expect("DELETE", path, NULL, admin_token, 200, NULL) != 0
        || (last_body != NULL && *last_body != '\0') || !session_status_is(7002, "CLOSED")
        || sent_matching("pm-a", "\"sessionId\":7002") != 1U || sent_matching("pm-b", "\"sessionId\":7002") != 1U;
    snprintf(needle, sizeof(needle), "{\"error\":\"peer ACL not found: %lld\"}", acl_id);
    failed = failed || expect("DELETE", path, NULL, admin_token, 400, needle) != 0
        || expect("DELETE", "/api/admin/peer-mesh/acls/-5", NULL, admin_token, 400,
                  "{\"error\":\"peer ACL not found: -5\"}") != 0
        || expect_spring_400("DELETE", "/api/admin/peer-mesh/acls/five", NULL, admin_token) != 0;
    printf("%s ACLs as Java createAcl, deleteAcl and refreshAuthorization\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- sessions ------------------------------------------------------------------------------ */

/*
 * The session list's Spring parameters, the view's lastKeepaliveAt (set by a path report, as Java's
 * reportPath does), and forceClose / forceCloseOpenSessions telling both ends.
 */
static int test_sessions(void)
{
    int failed = insert_open_session(7003, client_a, "pm-a", client_b, "pm-b") != 0
        || expect_spring_400("GET", "/api/admin/peer-mesh/sessions?limit=abc", NULL, admin_token) != 0
        || expect_spring_400("GET", "/api/admin/peer-mesh/sessions?openOnly=perhaps", NULL, admin_token) != 0
        || expect_spring_400("GET", "/api/admin/peer-mesh/sessions?page=1.5", NULL, admin_token) != 0
        || expect("GET", "/api/admin/peer-mesh/sessions?page=0&openOnly=yes", NULL, admin_token, 200,
                  "\"totalPages\":") != 0
        || strstr(last_body, "\"id\":7003") == NULL || strstr(last_body, "\"id\":7002") != NULL
        /* An empty page or size is null: the plain list. */
        || expect("GET", "/api/admin/peer-mesh/sessions?page=", NULL, admin_token, 200, "[{") != 0
        || strstr(last_body, "\"lastKeepaliveAt\":null") == NULL || !last_has_instant("startedAt")
        || !last_has_instant("expiresAt");
    st_storage_client reporter;
    failed = failed || st_storage_get_client(db_path, client_a, &reporter) != 0
        || st_storage_report_peer_mesh_session(db_path, &reporter, 7003, "DIRECT", "ACTIVE", 7, NULL, NULL, 0, 0, 0,
                                               NULL) != 0
        || expect("GET", "/api/admin/peer-mesh/sessions?limit=200", NULL, admin_token, 200, "\"id\":7003") != 0
        || !last_has_instant("lastKeepaliveAt");
    sent_count = 0U;
    failed = failed || expect("DELETE", "/api/admin/peer-mesh/sessions/999999", NULL, admin_token, 400,
                              "{\"error\":\"peer session not found: 999999\"}") != 0
        || expect_spring_400("DELETE", "/api/admin/peer-mesh/sessions/x1", NULL, admin_token) != 0
        || expect("DELETE", "/api/admin/peer-mesh/sessions/7003", NULL, admin_token, 200, "\"status\":\"CLOSED\"") != 0
        || !last_has_instant("closedAt")
        || sent_matching("pm-a", "\"sessionId\":7003") != 1U || sent_matching("pm-b", "\"sessionId\":7003") != 1U;
    failed = failed || insert_open_session(7004, client_b, "pm-b", client_a, "pm-a") != 0;
    sent_count = 0U;
    failed = failed || expect("DELETE", "/api/admin/peer-mesh/sessions", NULL, admin_token, 200, "\"id\":7004") != 0
        || sent_matching("pm-b", "\"sessionId\":7004") != 1U || sent_matching("pm-a", "\"sessionId\":7004") != 1U;
    printf("%s sessions as Java listSessions, forceClose and forceCloseOpenSessions\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- egress -------------------------------------------------------------------------------- */

static int test_egress(void)
{
    static const char *const switch_path = "/api/admin/peer-mesh/egress/switch";
    static const char *const policies = "/api/admin/peer-mesh/egress/policies";
    int failed = expect("GET", switch_path, NULL, admin_token, 200, "\"updatedAt\":null,\"updatedBy\":null") != 0
        /* Spring binds the body before the service checks ADMIN. */
        || expect_spring_400("PUT", switch_path, "[1]", user_token) != 0
        || expect("PUT", switch_path, "{\"enabled\":false}", user_token, 403,
                  "{\"error\":\"只有租户 ADMIN 可以管理出口授权\"}") != 0
        || expect_spring_400("PUT", switch_path, "{\"enabled\":\"nah\"}", admin_token) != 0
        || expect("PUT", switch_path, "{}", admin_token, 400, "{\"error\":\"enabled is required\"}") != 0
        || expect("PUT", switch_path, "{\"enabled\":false}", admin_token, 200, "\"updatedBy\":\"pm-admin\"") != 0
        || !last_has_instant("updatedAt");
    char body[2048];
    failed = failed || expect("POST", policies, "{\"egressClientId\":0}", admin_token, 404,
                              "{\"error\":\"client not found: 0\"}") != 0
        || expect("POST", policies, "{}", admin_token, 400, "{\"error\":\"egressClientId is required\"}") != 0
        || expect_spring_400("POST", policies, "{\"egressClientId\":\"one\"}", admin_token) != 0;
    snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"scope\":\" lan \"}", client_a);
    failed = failed || expect("POST", policies, body, admin_token, 200, "\"scope\":\"LAN\"") != 0
        || !last_has_instant("createdAt");
    long long policy_id = 0;
    failed = failed || last_body == NULL || st_json_get_i64(last_body, "id", &policy_id) != 0 || policy_id <= 0;
    snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"scope\":\"wan\"}", client_a);
    failed = failed || expect("POST", policies, body, admin_token, 400, "{\"error\":\"invalid scope: wan\"}") != 0;
    /* encodeClientIds: positive ids without repeats, at most 32. */
    int written = snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"allowedConsumerClientIds\":[", client_a);
    for (int i = 1; i <= 33; ++i) written += snprintf(body + written, sizeof(body) - (size_t)written, "%s%d", i == 1 ? "" : ",", i);
    snprintf(body + written, sizeof(body) - (size_t)written, "]}");
    failed = failed || expect("POST", policies, body, admin_token, 400, "{\"error\":\"at most 32 allowedClientIds\"}") != 0;
    written = snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"allowedConsumerClientIds\":[", client_a);
    for (int i = 1; i <= 34; ++i) written += snprintf(body + written, sizeof(body) - (size_t)written, "%s%d", i == 1 ? "" : ",", i > 32 ? 1 : i);
    snprintf(body + written, sizeof(body) - (size_t)written, ",null,0,-3]}");
    failed = failed || expect("POST", policies, body, admin_token, 200, "\"allowedConsumerClientIds\":[1,2,3") != 0;
    snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"allowedConsumerClientIds\":[\"x\"]}", client_a);
    failed = failed || expect_spring_400("POST", policies, body, admin_token) != 0;
    snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"maxConcurrentFlows\":\"many\"}", client_a);
    failed = failed || expect_spring_400("POST", policies, body, admin_token) != 0;
    snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"maxFlowsPerConsumer\":0}", client_a);
    failed = failed || expect("POST", policies, body, admin_token, 400,
                              "{\"error\":\"maxFlowsPerConsumer must be positive\"}") != 0;
    snprintf(body, sizeof(body), "{\"egressClientId\":%lld,\"domainRules\":[{\"match\":\"localhost\"}]}", client_a);
    failed = failed || expect("POST", policies, body, admin_token, 400,
                              "{\"error\":\"domainRules[0].match must be a name or *.name with at least two labels: localhost\"}") != 0;
    char path[160];
    char needle[160];
    snprintf(path, sizeof(path), "%s/%lld", policies, policy_id);
    snprintf(needle, sizeof(needle), "{\"error\":\"egress policy not found: %lld\"}", policy_id);
    failed = failed || expect("DELETE", path, NULL, admin_token, 200, NULL) != 0
        || (last_body != NULL && *last_body != '\0')
        || expect("DELETE", path, NULL, admin_token, 404, needle) != 0
        || expect_spring_400("DELETE", "/api/admin/peer-mesh/egress/policies/p1", NULL, admin_token) != 0;
    printf("%s egress switch and policies as Java PeerEgressService\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- services, sharing and import ---------------------------------------------------------- */

static int service_refused(const char *fields, const char *message)
{
    char body[1024];
    snprintf(body, sizeof(body), "{\"clientId\":%lld,%s}", client_a, fields);
    return expect("POST", "/api/admin/peer-mesh/services", body, admin_token, 400, message);
}

/*
 * PeerServiceDiscoveryService.createService, updateService and deleteService with
 * PeerServiceDiscovery's messages in applyDefinition's order; both mutations answer 200 and a
 * service created without a serviceId gets a random UUID.
 */
static int test_services(void)
{
    static const char *const valid =
        "\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":8080,\"publishedPort\":18080";
    char fields[512];
    char needle[160];
    int failed = expect_spring_400("POST", "/api/admin/peer-mesh/services", NULL, admin_token) != 0
        || expect_spring_400("POST", "/api/admin/peer-mesh/services", "{\"targetPort\":\"eighty\"}", admin_token) != 0
        || expect_spring_400("POST", "/api/admin/peer-mesh/services", "{\"name\":{\"x\":1}}", admin_token) != 0
        || expect("POST", "/api/admin/peer-mesh/services", "{}", user_token, 403,
                  "{\"error\":\"只有管理员可以修改 Peer 服务共享\"}") != 0
        || expect("POST", "/api/admin/peer-mesh/services", "{\"name\":\"x\"}", admin_token, 400,
                  "{\"error\":\"clientId is required\"}") != 0;
    snprintf(fields, sizeof(fields), "{\"clientId\":%lld,%s}", client_d, valid);
    snprintf(needle, sizeof(needle), "{\"error\":\"client not found: %lld\"}", client_d);
    failed = failed || expect("POST", "/api/admin/peer-mesh/services", fields, admin_token, 400, needle) != 0
        || service_refused("\"name\":\" \"", "{\"error\":\"name is required\"}") != 0
        || service_refused("\"name\":\"a\\u0001b\"", "{\"error\":\"name contains control characters\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"ftp\"", "{\"error\":\"unsupported application\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"transport\":\"sctp\"",
                           "{\"error\":\"transport must be tcp or udp\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"http://127.0.0.1\"",
                           "{\"error\":\"targetHost must be a local address, not a URL\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"router.lan\"",
                           "{\"error\":\"targetHost must be a numeric local address or localhost\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"127.1\"",
                           "{\"error\":\"targetHost must be a unicast IP or localhost\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"0.0.0.0\"",
                           "{\"error\":\"targetHost cannot be wildcard or multicast\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"8.8.8.8\"",
                           "{\"error\":\"targetHost must be loopback or a local interface address\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":0",
                           "{\"error\":\"targetPort must be 1..65535\"}") != 0
        || service_refused("\"name\":\"api\",\"application\":\"http\",\"targetHost\":\"127.0.0.1\",\"targetPort\":80",
                           "{\"error\":\"publishedPort must be 1..65535\"}") != 0;
    snprintf(fields, sizeof(fields), "%s,\"path\":\"api\"", valid);
    failed = failed || service_refused(fields, "{\"error\":\"path must start with /\"}") != 0;
    snprintf(fields, sizeof(fields), "%s,\"path\":\"/a?b\"", valid);
    failed = failed || service_refused(fields, "{\"error\":\"path contains unsupported characters\"}") != 0;
    snprintf(fields, sizeof(fields), "%s,\"visibility\":\"public\"", valid);
    failed = failed || service_refused(fields, "{\"error\":\"visibility must be OWNER or ACL\"}") != 0;
    snprintf(fields, sizeof(fields), "%s,\"serviceId\":\"bad id\"", valid);
    failed = failed || service_refused(fields, "{\"error\":\"invalid serviceId\"}") != 0;
    /* Created without a serviceId: a UUID, answered 200. */
    char body[1024];
    snprintf(body, sizeof(body), "{\"clientId\":%lld,%s}", client_a, valid);
    failed = failed || expect("POST", "/api/admin/peer-mesh/services", body, admin_token, 200, "\"name\":\"api\"") != 0
        || !last_has_instant("createdAt");
    char service_id[80] = "";
    long long id = 0;
    if (!failed) {
        char *value = st_json_get_string(last_body, "serviceId");
        snprintf(service_id, sizeof(service_id), "%s", value == NULL ? "" : value);
        free(value);
        failed = strlen(service_id) != 36U || service_id[8] != '-' || service_id[13] != '-' || service_id[14] != '4'
            || st_json_get_i64(last_body, "id", &id) != 0;
        if (failed) fprintf(stderr, "a created service did not get a UUID: %s\n", last_body);
    }
    snprintf(fields, sizeof(fields), "%s,\"serviceId\":\"%s\",\"publishedPort\":18081", valid, service_id);
    failed = failed || service_refused(fields, "{\"error\":\"serviceId already exists on this client\"}") != 0;
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/peer-mesh/services/%lld", id);
    failed = failed || expect("PUT", path, "{\"targetHost\":\"10.0.0.8\"}", admin_token, 200,
                              "\"targetHost\":\"10.0.0.8\"") != 0
        || expect("PUT", path, "{\"application\":\"udp\"}", admin_token, 400,
                  "{\"error\":\"udp application requires udp transport\"}") != 0
        || expect("PUT", "/api/admin/peer-mesh/services/999999", "{}", admin_token, 400,
                  "{\"error\":\"service not found: 999999\"}") != 0
        || expect_spring_400("PUT", "/api/admin/peer-mesh/services/import", "{}", admin_token) != 0
        || expect("DELETE", path, NULL, admin_token, 200, NULL) != 0 || (last_body != NULL && *last_body != '\0');
    snprintf(needle, sizeof(needle), "{\"error\":\"service not found: %lld\"}", id);
    failed = failed || expect("DELETE", path, NULL, admin_token, 400, needle) != 0;
    printf("%s services as Java createService, updateService and deleteService\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/*
 * updateServiceSharing reads only JSON booleans out of its Map; importServices only a numeric
 * clientId; importCandidates skips a target requireTargetHost refuses and names a service by UUID.
 */
static int test_sharing_and_import(void)
{
    static const char *const sharing = "/api/admin/peer-mesh/service-sharing";
    static const char *const import_path = "/api/admin/peer-mesh/services/import";
    int failed = expect_spring_400("PUT", sharing, NULL, admin_token) != 0
        || expect("PUT", sharing, "{\"enabled\":\"true\",\"mdnsImportEnabled\":1}", admin_token, 400,
                  "{\"error\":\"enabled or mdnsImportEnabled is required\"}") != 0
        || expect("PUT", sharing, "{\"mdnsImportEnabled\":false}", admin_token, 200, "\"updatedBy\":\"pm-admin\"") != 0
        || !last_has_instant("updatedAt")
        || expect("PUT", sharing, "{\"mdnsImportEnabled\":true}", admin_token, 200, "\"mdnsImportEnabled\":true") != 0
        || expect("GET", "/api/admin/peer-mesh/service-audit", NULL, admin_token, 200, "\"reason\":\"updated,mdns\"") != 0
        || !last_has_instant("at")
        || expect("PUT", sharing, "{\"mdnsImportEnabled\":false}", admin_token, 200, NULL) != 0;
    char body[256];
    snprintf(body, sizeof(body), "{\"clientId\":\"%lld\"}", client_a);
    failed = failed || expect_spring_400("POST", import_path, NULL, admin_token) != 0
        || expect("POST", import_path, body, admin_token, 400, "{\"error\":\"clientId is required\"}") != 0
        || expect("POST", import_path, "{\"clientId\":999999}", admin_token, 400,
                  "{\"error\":\"client not found: 999999\"}") != 0;
    snprintf(body, sizeof(body), "{\"clientId\":%lld,\"source\":\"MDNS\"}", client_a);
    failed = failed || expect("POST", import_path, body, admin_token, 400, "{\"error\":\"mDNS 候选导入未开启\"}") != 0;
    /* One local target is imported, a public one is skipped as requireTargetHost refuses it. */
    st_storage_mapping mapping;
    failed = failed || st_storage_create_mapping_for_client(db_path, client_a, 31001, "localhost", 8080, 1, 0, &mapping) != 0
        || st_storage_create_mapping_for_client(db_path, client_a, 31002, "8.8.8.8", 53, 1, 0, &mapping) != 0;
    snprintf(body, sizeof(body), "{\"clientId\":%lld}", client_a);
    failed = failed || expect("POST", import_path, body, admin_token, 200, "\"created\":1,\"skipped\":1") != 0
        || strstr(last_body, "\"name\":\"tcp-31001\"") == NULL || strstr(last_body, "\"targetHost\":\"127.0.0.1\"") == NULL
        || strstr(last_body, "\"serviceId\":\"import-") != NULL;
    printf("%s service sharing and import as Java\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* ---- the rest of item 54: mapping create, parameters, timestamps ---------------------------- */

/* NatControlService.createMapping: a public port any mapping holds is refused, never replaced. */
static int test_mapping_create(void)
{
    char path[160];
    char needle[160];
    static const char *const body = "{\"listenPort\":32001,\"targetAddress\":\"127.0.0.1\",\"targetPort\":9001}";
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/specus-mappings", client_a);
    int failed = expect("POST", path, body, admin_token, 201, "\"listenPort\":32001") != 0
        || !last_has_instant("createdAt")
        || expect("POST", path, "{\"listenPort\":32001,\"targetAddress\":\"127.0.0.2\",\"targetPort\":9002}",
                  admin_token, 400, "{\"error\":\"公网端口 32001 已被占用\"}") != 0
        || expect_spring_400("POST", path, "{\"listenPort\":32002,\"targetAddress\":\"x\",\"targetPort\":1,"
                                           "\"enabled\":\"perhaps\"}", admin_token) != 0
        || expect_spring_400("POST", path, NULL, admin_token) != 0;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/specus-mappings", client_b);
    failed = failed || expect("POST", path, body, admin_token, 400, "{\"error\":\"公网端口 32001 已被占用\"}") != 0;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/specus-mappings", client_d);
    snprintf(needle, sizeof(needle), "{\"error\":\"client not found: %lld\"}", client_d);
    failed = failed || expect("POST", path, body, admin_token, 400, needle) != 0;
    printf("%s TCP mapping create as Java createMapping\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* Request parameters Spring converts before the controller: a value that does not convert is 400. */
static int test_parameters(void)
{
    static const char *const refused[] = {
        "/api/admin/connections?page=abc",
        "/api/admin/connections?success=maybe",
        "/api/admin/connections?clientId=1x",
        "/api/admin/connection-stats?limit=1.5",
        "/api/admin/traffic?flush=sometimes",
        "/api/admin/traffic/resources?clientId=one",
        "/api/admin/traffic/http-exchanges?size=ten",
        "/api/admin/traffic/tcp-frames?listenPort=x",
        "/api/admin/traffic/tcp-streams",
        "/api/admin/traffic/tcp-streams?channelId=c&limit=all",
        "/api/admin/traffic/media-captures?page=first",
        "/api/admin/http-routes?clientId=abc",
    };
    int failed = 0;
    for (size_t i = 0U; !failed && i < sizeof(refused) / sizeof(refused[0]); ++i) {
        failed = expect_spring_400("GET", refused[i], NULL, admin_token) != 0;
    }
    /* Spring's boolean words, hexadecimal and whitespace in numbers, and empty values. */
    failed = failed || expect("GET", "/api/admin/connections?success=yes&page=%200x0&size=", NULL, admin_token, 200,
                              "\"items\":") != 0
        || expect("GET", "/api/admin/traffic?flush=on&limit=5", NULL, admin_token, 200, "[") != 0
        || expect("GET", "/api/admin/traffic/tcp-streams?channelId=c1", NULL, admin_token, 200, "\"channelId\":\"c1\"") != 0;
    /* Request bodies: a Boolean, Integer or Long member Jackson cannot convert, or no body at all. */
    char path[160];
    snprintf(path, sizeof(path), "/api/admin/clients/%lld", client_a);
    failed = failed || expect_spring_400("POST", "/api/admin/clients", "{\"clientName\":\"pm-new\",\"enabled\":\"1\"}",
                                         admin_token) != 0
        || expect_spring_400("POST", "/api/admin/clients", NULL, admin_token) != 0
        || expect_spring_400("PUT", path, "{\"connectionRateLimitPerMinute\":\"often\"}", admin_token) != 0
        || expect("PUT", path, "{\"connectionRateLimitPerMinute\":\"40\",\"enabled\":\"true\"}", admin_token, 200,
                  "\"connectionRateLimitPerMinute\":40") != 0;
    snprintf(path, sizeof(path), "/api/admin/clients/%lld/http-routes", client_a);
    failed = failed || expect_spring_400("POST", path, "{\"route\":\"r1\",\"targetBaseUrl\":\"http://127.0.0.1\","
                                                       "\"authEnabled\":[]}", admin_token) != 0
        || expect_spring_400("POST", "/api/admin/client-credentials", "{\"enabled\":\"no\"}", admin_token) != 0
        || expect_spring_400("POST", "/api/admin/client-downloads", "{\"displayOrder\":\"first\"}", admin_token) != 0;
    printf("%s Spring-converted request parameters and bodies\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* The client and route views show their stored times as Java's Instant.toString. */
static int test_timestamps(void)
{
    st_storage_http_route route;
    int failed = expect("GET", "/api/admin/clients", NULL, admin_token, 200, "\"clientName\":\"pm-a\"") != 0
        || !last_has_instant("createdAt") || !last_has_instant("updatedAt")
        || st_storage_create_http_route_for_client(db_path, client_a, "pm-route", "http://127.0.0.1:8080", 1, 0, 0, 0,
                                                   0, 0, "", "", &route) != 0
        || expect("GET", "/api/admin/http-routes", NULL, admin_token, 200, "\"route\":\"pm-route\"") != 0
        || !last_has_instant("createdAt") || !last_has_instant("updatedAt");
    printf("%s client and route times as ISO-8601\n", failed ? "FAIL" : "ok  ");
    return failed;
}

/* PublicPeerMeshResource.forwardedHost: the first host of X-Forwarded-Host, trimmed. */
static int test_forwarded_host(void)
{
    setenv("SPECUS_PEER_MESH_ENABLED", "true", 1);
    int fd = connect_local(port);
    char response[8192] = "";
    size_t used = 0U;
    static const char request[] =
        "GET /api/public/peer-mesh/stun-config HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        "X-Forwarded-Host: edge.example:8443 , inner.example\r\nConnection: close\r\n\r\n";
    if (fd >= 0 && send_all(fd, (const uint8_t *)request, strlen(request)) == 0) {
        for (;;) {
            ssize_t got = recv(fd, response + used, sizeof(response) - 1U - used, 0);
            if (got <= 0) break;
            used += (size_t)got;
        }
    }
    if (fd >= 0) close(fd);
    response[used] = '\0';
    unsetenv("SPECUS_PEER_MESH_ENABLED");
    int failed = strstr(response, "\"selfHostedStunServer\":\"stun:edge.example:3478\"") == NULL;
    if (failed) fprintf(stderr, "stun-config with a forwarded host list: %s\n", response);
    printf("%s public STUN configuration takes the first forwarded host\n", failed ? "FAIL" : "ok  ");
    return failed;
}

static int seed(void)
{
    st_storage_management_user user;
    st_storage_client client;
    st_storage_peer_mesh_device device;
    int failed = st_storage_create_management_user(db_path, "pm-admin", TENANT, "unused-hash", "ADMIN", 1, &user) != 0
        || st_storage_create_management_user(db_path, "pm-user", TENANT, "unused-hash", "USER", 1, &user) != 0;
    failed = failed || st_storage_upsert_client(db_path, 0, TENANT, "pm-a", "pm-admin", 1, 30, &client) != 0
        || st_storage_ensure_peer_mesh_device(db_path, &client, &device) != 0;
    client_a = client.id;
    failed = failed || st_storage_upsert_client(db_path, 0, TENANT, "pm-b", "pm-user", 1, 30, &client) != 0
        || st_storage_ensure_peer_mesh_device(db_path, &client, &device) != 0;
    client_b = client.id;
    failed = failed || st_storage_upsert_client(db_path, 0, TENANT, "pm-c", "pm-user", 1, 30, &client) != 0;
    client_c = client.id;
    failed = failed || st_storage_upsert_client(db_path, 0, OTHER_TENANT, "pm-d", "other-admin", 1, 30, &client) != 0;
    client_d = client.id;
    return failed
        || st_security_issue_local_token("pm-admin", TENANT, "ADMIN", JWT_SECRET, 600, admin_token,
                                         sizeof(admin_token)) != 0
        || st_security_issue_local_token("pm-user", TENANT, "USER", JWT_SECRET, 600, user_token,
                                         sizeof(user_token)) != 0 ? -1 : 0;
}

int main(void)
{
    const char *tmp = getenv("TMPDIR");
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/specus-c-peer-api-XXXXXX", tmp != NULL && *tmp != '\0' ? tmp : "/tmp");
    if (mkdtemp(dir) == NULL) {
        perror("mkdtemp");
        return 1;
    }
    snprintf(db_path, sizeof(db_path), "%s/peer-api.db", dir);
    setenv("SPECUS_ENV", "test", 1);
    setenv("SPECUS_DB_SEED_DEMO_CLIENT", "false", 1);
    setenv("SPECUS_DATABASE_PATH", db_path, 1);
    setenv("SPECUS_AUTH_JWT_SECRET", JWT_SECRET, 1);
    setenv("SPECUS_AUTH_USERNAME", BUILT_IN, 1);
    setenv("SPECUS_AUTH_PASSWORD", "pm-root-password-2026", 1);
    unsetenv("SPECUS_AUTH_TENANT_ID");
    unsetenv("SPECUS_PEER_MESH_ENABLED");
    unsetenv("SPECUS_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("SPECUS_PEER_MESH_STANDALONE_STUN_ADDRESS");

    int failed = st_storage_init(db_path, 0) != 0 || seed() != 0;
    if (failed) fprintf(stderr, "seeding failed\n");
    st_admin_set_peer_control_send_handler(capture_peer_control, NULL);
    st_admin_server server;
    memset(&server, 0, sizeof(server));
    server.fd = -1;
    struct sockaddr_in address;
    socklen_t address_len = sizeof(address);
    if (!failed && (st_admin_server_start(&server, 0, "") != 0
                    || getsockname(server.fd, (struct sockaddr *)&address, &address_len) != 0)) {
        fprintf(stderr, "listener start failed\n");
        failed = 1;
    }
    if (!failed) {
        port = ntohs(address.sin_port);
        failed = test_devices() != 0;
        failed = test_acls() != 0 || failed;
        failed = test_sessions() != 0 || failed;
        failed = test_egress() != 0 || failed;
        failed = test_services() != 0 || failed;
        failed = test_sharing_and_import() != 0 || failed;
        failed = test_mapping_create() != 0 || failed;
        failed = test_parameters() != 0 || failed;
        failed = test_timestamps() != 0 || failed;
        failed = test_forwarded_host() != 0 || failed;
    }
    st_admin_set_peer_control_send_handler(NULL, NULL);
    free(last_body);
    unlink(db_path);
    char journal[400];
    snprintf(journal, sizeof(journal), "%s-journal", db_path);
    unlink(journal);
    rmdir(dir);
    if (failed) return 1;
    printf("peer mesh API tests passed\n");
    return 0;
}
