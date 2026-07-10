#define _POSIX_C_SOURCE 200809L

#include "admin_http.h"
#include "crypto.h"
#include "json.h"
#include "storage.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static long long test_now_millis(void)
{
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0) {
        return 0;
    }
    return (long long)tv.tv_sec * 1000LL + (long long)tv.tv_usec / 1000LL;
}

static void sign_client_auth(const char *api_key,
                             const char *timestamp,
                             const char *nonce,
                             const char *machine_fingerprint,
                             const char *os_user,
                             const char *secret,
                             char signature_hex[ST_SHA256_HEX_LEN + 1])
{
    uint8_t key[ST_SHA256_LEN];
    uint8_t signature[ST_SHA256_LEN];
    char message[512];
    int message_len = snprintf(message,
                               sizeof(message),
                               "%s\n%s\n%s\n%s\n%s",
                               api_key,
                               timestamp,
                               nonce,
                               machine_fingerprint,
                               os_user);
    st_sha256((const uint8_t *)secret, strlen(secret), key);
    st_hmac_sha256(key, sizeof(key), (const uint8_t *)message, (size_t)message_len, signature);
    st_hex_encode(signature, sizeof(signature), signature_hex);
}

static int contains(const char *haystack, const char *needle)
{
    return strstr(haystack, needle) != NULL;
}

static void test_base64url_no_padding(const uint8_t *data, size_t len, char *out)
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t written = 0;
    for (size_t i = 0; i < len; i += 3U) {
        uint32_t value = (uint32_t)data[i] << 16;
        size_t remaining = len - i;
        if (remaining > 1U) value |= (uint32_t)data[i + 1U] << 8;
        if (remaining > 2U) value |= data[i + 2U];
        out[written++] = alphabet[(value >> 18) & 63U];
        out[written++] = alphabet[(value >> 12) & 63U];
        if (remaining > 1U) out[written++] = alphabet[(value >> 6) & 63U];
        if (remaining > 2U) out[written++] = alphabet[value & 63U];
    }
    out[written] = '\0';
}

static char *test_dup_string(const char *value)
{
    size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, len + 1U);
    return copy;
}

static uint8_t *test_dup_body(const char *value, size_t *len)
{
    *len = strlen(value);
    uint8_t *copy = (uint8_t *)malloc(*len == 0 ? 1U : *len);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, *len);
    return copy;
}

static int test_exec_sql(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    char *error = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "sqlite test setup failed: %s\n", error == NULL ? sqlite3_errmsg(db) : error);
        sqlite3_free(error);
        sqlite3_close(db);
        return -1;
    }
    sqlite3_close(db);
    return 0;
}

typedef struct {
    int fd;
    int port;
    char request[4096];
} oidc_test_server;

static void *oidc_test_server_thread(void *arg)
{
    oidc_test_server *server = (oidc_test_server *)arg;
    int client = accept(server->fd, NULL, NULL);
    if (client >= 0) {
        ssize_t got = recv(client, server->request, sizeof(server->request) - 1U, 0);
        if (got > 0) {
            server->request[got] = '\0';
        }
        const char body[] = "{\"access_token\":\"access-1\",\"id_token\":\"id-1\",\"token_type\":\"Bearer\",\"expires_in\":3600}";
        char response[512];
        int response_len = snprintf(response,
                                    sizeof(response),
                                    "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: application/json\r\n"
                                    "Content-Length: %zu\r\n"
                                    "Connection: close\r\n"
                                    "\r\n"
                                    "%s",
                                    strlen(body),
                                    body);
        if (response_len > 0 && (size_t)response_len < sizeof(response)) {
            (void)send(client, response, (size_t)response_len, 0);
        }
        close(client);
    }
    return NULL;
}

static int oidc_test_server_start(oidc_test_server *server, pthread_t *thread)
{
    memset(server, 0, sizeof(*server));
    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        return -1;
    }
    int reuse = 1;
    (void)setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    (void)setsockopt(server->fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(server->fd, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(server->fd, 1) != 0) {
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    socklen_t address_len = sizeof(address);
    if (getsockname(server->fd, (struct sockaddr *)&address, &address_len) != 0) {
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    server->port = ntohs(address.sin_port);
    if (pthread_create(thread, NULL, oidc_test_server_thread, server) != 0) {
        close(server->fd);
        server->fd = -1;
        return -1;
    }
    return 0;
}

static void oidc_test_server_stop(oidc_test_server *server, pthread_t thread)
{
    (void)pthread_join(thread, NULL);
    if (server->fd >= 0) {
        close(server->fd);
        server->fd = -1;
    }
}

int main(void)
{
    char response[32768];
    char request_path[128];
    int len = st_admin_build_response("GET", "/health", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "{\"status\":\"ok\"}")) {
        fprintf(stderr, "health response mismatch\n");
        return 1;
    }

    setenv("TUNNEL_AUTH_JWT_SECRET", "c-admin-test-secret", 1);
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"admin\",\"password\":\"admin\"}",
                                            response,
                                            sizeof(response));
    char *admin_token = st_json_get_string(response, "accessToken");
    if (len <= 0 || !contains(response, "200 OK") || admin_token == NULL || !contains(admin_token, ".")) {
        fprintf(stderr, "login response mismatch\n");
        free(admin_token);
        return 1;
    }

    unsetenv("TUNNEL_PEER_MESH_ENABLED");
    unsetenv("TUNNEL_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS");
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"peerMeshEnabled\":false")
        || !contains(response, "\"selfHostedStunServer\":\"\"")
        || !contains(response, "\"stunServers\":[]")
        || !contains(response, "\"stunTurnPort\":3478")) {
        fprintf(stderr, "disabled public stun config mismatch\n");
        return 1;
    }
    setenv("TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS", "STUN://fallback.example.test", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "\"peerMeshEnabled\":false")
        || !contains(response, "\"selfHostedStunServer\":\"\"")
        || !contains(response, "\"stun:fallback.example.test:3478\"")) {
        fprintf(stderr, "disabled public fallback stun config mismatch\n");
        return 1;
    }
    setenv("TUNNEL_PEER_MESH_ENABLED", "true", 1);
    setenv("TUNNEL_PEER_MESH_PUBLIC_ADDRESS", "ice.example.test", 1);
    setenv("TUNNEL_PEER_MESH_STUN_TURN_PORT", "5349", 1);
    setenv("TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS", "stun://stun.example.test, stun:stun.example.test:3478", 1);
    setenv("TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED", "true", 1);
    setenv("TUNNEL_PEER_MESH_TURN_SHARED_SECRET", "turn-test-secret", 1);
    setenv("TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS", "3600", 1);
    len = st_admin_build_response("GET", "/api/public/peer-mesh/stun-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"peerMeshEnabled\":true")
        || !contains(response, "\"selfHostedStunServer\":\"stun:ice.example.test:5349\"")
        || !contains(response, "\"stun:stun.example.test:3478\"")) {
        fprintf(stderr, "enabled public stun config mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/public/transfer/ice-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"urls\":\"turn:ice.example.test:5349?transport=udp\"")
        || !contains(response, ":public-transfer:")
        || !contains(response, "\"credential\":\"")
        || !contains(response, "\"turnAuthRequired\":true")) {
        fprintf(stderr, "public ice config mismatch\n");
        return 1;
    }
    const char *turn_entry = strstr(response, "\"urls\":\"turn:");
    char *turn_username = turn_entry == NULL ? NULL : st_json_get_string(turn_entry, "username");
    char *turn_credential = turn_entry == NULL ? NULL : st_json_get_string(turn_entry, "credential");
    uint8_t expected_turn_mac[ST_SHA1_LEN];
    char expected_turn_credential[32];
    if (turn_username != NULL) {
        st_hmac_sha1((const uint8_t *)"turn-test-secret",
                     strlen("turn-test-secret"),
                     (const uint8_t *)turn_username,
                     strlen(turn_username),
                     expected_turn_mac);
        test_base64url_no_padding(expected_turn_mac, sizeof(expected_turn_mac), expected_turn_credential);
    }
    char *turn_subject = turn_username == NULL ? NULL : strstr(turn_username, ":public-transfer:");
    if (turn_username == NULL || turn_credential == NULL || turn_subject == NULL
        || strlen(turn_subject + strlen(":public-transfer:")) != 8U
        || strcmp(turn_credential, expected_turn_credential) != 0) {
        fprintf(stderr, "temporary turn credential mismatch\n");
        free(turn_username);
        free(turn_credential);
        return 1;
    }
    free(turn_username);
    free(turn_credential);
    len = st_admin_build_response("POST", "/api/public/transfer/attachments/presign-upload", response, sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")
        || !contains(response, "\"error\":\"object storage is not configured\"")
        || !contains(response, "\"code\":\"OBJECT_STORAGE_DISABLED\"")
        || !contains(response, "\"enabled\":false")) {
        fprintf(stderr, "disabled public attachment response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("POST",
                                  "/api/public/transfer/attachments/not-a-java-route",
                                  response,
                                  sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "unknown attachment path should remain not found\n");
        return 1;
    }
    unsetenv("TUNNEL_PEER_MESH_ENABLED");
    unsetenv("TUNNEL_PEER_MESH_PUBLIC_ADDRESS");
    unsetenv("TUNNEL_PEER_MESH_STUN_TURN_PORT");
    unsetenv("TUNNEL_PEER_MESH_PUBLIC_STUN_SERVERS");
    unsetenv("TUNNEL_PEER_MESH_TURN_AUTH_REQUIRED");
    unsetenv("TUNNEL_PEER_MESH_TURN_SHARED_SECRET");
    unsetenv("TUNNEL_PEER_MESH_TURN_CREDENTIAL_TTL_SECONDS");
    len = st_admin_build_response_with_auth("GET", "/api/admin/overview", NULL, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "unauthenticated admin api response mismatch\n");
        free(admin_token);
        return 1;
    }
    char authorization[2300];
    snprintf(authorization, sizeof(authorization), "Bearer %s", admin_token);
    len = st_admin_build_response_with_auth("GET", "/api/admin/overview", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"server\":\"c\"")) {
        fprintf(stderr, "authenticated admin api response mismatch\n");
        free(admin_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/client-messages/attachments/presign-upload",
                                            authorization,
                                            "{}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")
        || !contains(response, "\"error\":\"object storage is not configured\"")
        || !contains(response, "\"code\":\"OBJECT_STORAGE_DISABLED\"")) {
        fprintf(stderr, "disabled admin attachment response mismatch\n");
        free(admin_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST", "/auth/refresh", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"tokenType\":\"Bearer\"")) {
        fprintf(stderr, "refresh response mismatch\n");
        free(admin_token);
        return 1;
    }
    free(admin_token);
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"admin\",\"password\":\"wrong\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "invalid login response mismatch\n");
        return 1;
    }

    unsetenv("TUNNEL_DATABASE_PATH");
    setenv("TUNNEL_CLIENT_ACCESS_TOKEN", "dev-runtime-token", 1);
    setenv("TUNNEL_CLIENT_TENANT_ID", "tenant-c", 1);
    setenv("TUNNEL_CLIENT_ID", "42", 1);
    setenv("TUNNEL_CLIENT_SESSION_ID", "99", 1);
    setenv("TUNNEL_CLIENT_TOKEN_TTL_SECONDS", "120", 1);
    setenv("TUNNEL_CLIENT_MAX_ONLINE_INSTANCES", "7", 1);
    setenv("TUNNEL_CLIENT_POLICY_ENABLED", "false", 1);
    setenv("TUNNEL_CLIENT_BILLING_STATUS", "SUSPENDED", 1);
    setenv("TUNNEL_CLIENT_RETRY_AFTER_SECONDS", "60", 1);
    setenv("TUNNEL_TCP_MAPPINGS", "18080=127.0.0.1:8080,10022=192.168.1.243:22", 1);
    setenv("TUNNEL_HTTP_ROUTES", "api=http://127.0.0.1:8080/base", 1);
    len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tenantId\":\"tenant-c\"")
        || !contains(response, "\"clientId\":42")
        || !contains(response, "\"clientSessionId\":99")
        || !contains(response, "\"tokenTtlSeconds\":120")
        || !contains(response, "\"maxOnlineInstances\":7")
        || !contains(response, "\"policy\":{\"enabled\":false,\"billingStatus\":\"SUSPENDED\",\"retryAfterSeconds\":60}")
        || !contains(response, "\"peerMesh\":{\"enabled\":false,\"clientId\":42")
        || !contains(response, "\"tunnelConfigList\":[")
        || !contains(response, "\"port\":18080")
        || !contains(response, "\"tunnelAddress\":\"127.0.0.1\"")
        || !contains(response, "\"tunnelPort\":8080")
        || !contains(response, "\"port\":10022")
        || !contains(response, "\"tunnelAddress\":\"192.168.1.243\"")
        || !contains(response, "\"tunnelPort\":22")
        || !contains(response, "\"httpTunnelConfigList\":[")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"http://127.0.0.1:8080/base\"")) {
        fprintf(stderr, "client auth tcp mappings response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_CLIENT_ACCESS_TOKEN");
    unsetenv("TUNNEL_CLIENT_TENANT_ID");
    unsetenv("TUNNEL_CLIENT_ID");
    unsetenv("TUNNEL_CLIENT_SESSION_ID");
    unsetenv("TUNNEL_CLIENT_TOKEN_TTL_SECONDS");
    unsetenv("TUNNEL_CLIENT_MAX_ONLINE_INSTANCES");
    unsetenv("TUNNEL_CLIENT_POLICY_ENABLED");
    unsetenv("TUNNEL_CLIENT_BILLING_STATUS");
    unsetenv("TUNNEL_CLIENT_RETRY_AFTER_SECONDS");
    unsetenv("TUNNEL_TCP_MAPPINGS");
    unsetenv("TUNNEL_HTTP_ROUTES");

    setenv("TUNNEL_CLIENT_ACCESS_TOKEN", "dev-runtime-token", 1);
    setenv("TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS", "180", 1);
    setenv("TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES", "9", 1);
    len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tokenTtlSeconds\":180")
        || !contains(response, "\"maxOnlineInstances\":9")) {
        fprintf(stderr, "client auth java alias env response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_CLIENT_ACCESS_TOKEN");
    unsetenv("TUNNEL_CLIENT_AUTH_TOKEN_TTL_SECONDS");
    unsetenv("TUNNEL_CLIENT_AUTH_DEFAULT_MAX_ONLINE_INSTANCES");

    setenv("TUNNEL_CLIENT_ACCESS_TOKEN", "dev-runtime-token", 1);
    setenv("TUNNEL_CLIENT_API_KEY", "demo-api", 1);
    setenv("TUNNEL_CLIENT_SECRET", "test1234", 1);
    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%lld", test_now_millis());
    char signature[ST_SHA256_HEX_LEN + 1];
    sign_client_auth("demo-api", timestamp, "nonce-1", "m_test", "tester", "test1234", signature);
    char body[1024];
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"demo-api\",\"timestamp\":\"%s\",\"nonce\":\"nonce-1\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"m_test\",\"osUser\":\"tester\"}}",
             timestamp,
             signature);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"accessToken\":\"dev-runtime-token\"")) {
        fprintf(stderr, "client auth signed login response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/client/auth/login",
                                            "{\"apiKey\":\"demo-api\",\"timestamp\":\"1\",\"nonce\":\"nonce-1\","
                                            "\"signature\":\"0000000000000000000000000000000000000000000000000000000000000000\","
                                            "\"environment\":{\"machineFingerprint\":\"m_test\",\"osUser\":\"tester\"}}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized") || !contains(response, "signature invalid")) {
        fprintf(stderr, "client auth invalid signature was not rejected\n");
        return 1;
    }
    unsetenv("TUNNEL_CLIENT_ACCESS_TOKEN");
    unsetenv("TUNNEL_CLIENT_API_KEY");
    unsetenv("TUNNEL_CLIENT_SECRET");

    char auth_db_path[256];
    snprintf(auth_db_path, sizeof(auth_db_path), "/tmp/shuai-tunnel-c-client-auth-%ld.db", (long)getpid());
    unlink(auth_db_path);
    if (st_storage_init(auth_db_path, 0) != 0) {
        fprintf(stderr, "client auth db init failed\n");
        return 1;
    }
    uint8_t db_secret_hash[ST_SHA256_LEN];
    char db_secret_hash_hex[ST_SHA256_HEX_LEN + 1];
    st_sha256((const uint8_t *)"db-secret", strlen("db-secret"), db_secret_hash);
    st_hex_encode(db_secret_hash, sizeof(db_secret_hash), db_secret_hash_hex);
    st_storage_client_credential db_credential;
    if (st_storage_upsert_client_credential(auth_db_path,
                                            0,
                                            "tenant-db",
                                            "owner-db",
                                            "db-api",
                                            db_secret_hash_hex,
                                            1,
                                            4,
                                            &db_credential) != 0) {
        fprintf(stderr, "client auth db credential seed failed\n");
        return 1;
    }
    setenv("TUNNEL_DATABASE_PATH", auth_db_path, 1);
    snprintf(timestamp, sizeof(timestamp), "%lld", test_now_millis());
    sign_client_auth("db-api", timestamp, "nonce-db", "machine-db", "db-user", "db-secret", signature);
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"db-api\",\"timestamp\":\"%s\",\"nonce\":\"nonce-db\",\"signature\":\"%s\","
             "\"environment\":{\"machineFingerprint\":\"machine-db\",\"osUser\":\"db-user\",\"hostname\":\"DB Host\","
             "\"clientMessageCapabilities\":{\"sendMessages\":true,\"receiveMessages\":true,"
             "\"attachments\":true,\"mediaPreview\":true,"
             "\"maxAttachmentBytes\":16777216}}}",
             timestamp,
             signature);
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"tenantId\":\"tenant-db\"")
        || !contains(response, "\"accessToken\":\"cs_")
        || !contains(response, "\"maxOnlineInstances\":4")
        || !contains(response, "db-host-db-user-")) {
        fprintf(stderr, "client auth database login response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/clients", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"messageSendCapable\":false")
        || !contains(response, "\"messageReceiveCapable\":false")
        || !contains(response, "\"messageAttachmentsCapable\":false")
        || !contains(response, "\"messageMediaPreviewCapable\":false")
        || !contains(response, "\"messageMaxAttachmentBytes\":0")) {
        fprintf(stderr, "client message capability management response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"messageAttachmentsCapable\":false")
        || !contains(response, "\"messageMaxAttachmentBytes\":0")
        || !contains(response, "C server does not implement Peer Mesh data plane")) {
        fprintf(stderr, "peer mesh capability management response mismatch\n");
        return 1;
    }
    snprintf(body,
             sizeof(body),
             "{\"apiKey\":\"db-api\",\"timestamp\":\"1\",\"nonce\":\"nonce-db\","
             "\"signature\":\"0000000000000000000000000000000000000000000000000000000000000000\","
             "\"environment\":{\"machineFingerprint\":\"machine-db\",\"osUser\":\"db-user\",\"hostname\":\"DB Host\"}}");
    len = st_admin_build_response_with_body("POST", "/api/client/auth/login", body, response, sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized") || !contains(response, "signature invalid")) {
        fprintf(stderr, "client auth database invalid signature was not rejected\n");
        return 1;
    }
    unsetenv("TUNNEL_DATABASE_PATH");
    unlink(auth_db_path);

    len = st_admin_build_response("GET", "/api/admin/overview", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"server\":\"c\"")
        || !contains(response, "\"tcpMappings\":0")) {
        fprintf(stderr, "overview response mismatch\n");
        return 1;
    }

    setenv("TUNNEL_TCP_MAPPINGS", "18080=127.0.0.1:8080,10022=192.168.1.243:22", 1);
    len = st_admin_build_response("GET", "/api/admin/overview", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"tcpMappings\":2")) {
        fprintf(stderr, "overview tcp mapping count mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/api/admin/metrics", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"metricsWired\":false")
        || !contains(response, "\"listeners\":2")) {
        fprintf(stderr, "metrics response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_TCP_MAPPINGS");

    char db_path[256];
    snprintf(db_path, sizeof(db_path), "/tmp/shuai-tunnel-c-admin-%ld.db", (long)getpid());
    unlink(db_path);
    setenv("TUNNEL_DATABASE_PATH", db_path, 1);
    setenv("TUNNEL_AUTH_TENANT_ID", "tenant-admin", 1);
    setenv("TUNNEL_AUTH_USERNAME", "admin-user", 1);
    len = st_admin_build_response("POST", "/api/admin/database/initialize", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"initialized\":true")
        || !contains(response, "\"tenantId\":\"tenant-admin\"")
        || !contains(response, "\"orm\":\"sqlite3\"")
        || !contains(response, "\"dialect\":\"sqlite\"")
        || !contains(response, "\"clients\":0")) {
        fprintf(stderr, "database initialize response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/me", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"username\":\"admin-user\"")
        || !contains(response, "\"tenantId\":\"tenant-admin\"")
        || !contains(response, "\"builtIn\":true")) {
        fprintf(stderr, "management me response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/users",
                                            "{\"username\":\"alice\",\"password\":\"secret\","
                                            "\"role\":\"USER\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"username\":\"alice\"")
        || !contains(response, "\"tenantId\":\"tenant-admin\"")
        || !contains(response, "\"role\":\"USER\"")
        || !contains(response, "\"admin\":false")
        || !contains(response, "\"builtIn\":false")) {
        fprintf(stderr, "management user create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/users", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"username\":\"admin-user\"")
        || !contains(response, "\"username\":\"alice\"")) {
        fprintf(stderr, "management user list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/client-credentials",
                                            "{\"apiKey\":\"ck-c-test\",\"secret\":\"secret-c\","
                                            "\"enabled\":true,\"maxOnlineInstances\":5}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"credential\":")
        || !contains(response, "\"apiKey\":\"ck-c-test\"")
        || !contains(response, "\"secret\":\"secret-c\"")
        || !contains(response, "\"maxOnlineInstances\":5")) {
        fprintf(stderr, "credential create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/client-credentials", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"apiKey\":\"ck-c-test\"")
        || contains(response, "\"secret\":\"secret-c\"")) {
        fprintf(stderr, "credential list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("PUT",
                                            "/api/admin/client-credentials/1",
                                            "{\"secret\":\"secret-c2\",\"enabled\":false,"
                                            "\"maxOnlineInstances\":6}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"secret\":\"secret-c2\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"maxOnlineInstances\":6")) {
        fprintf(stderr, "credential update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/client-credentials/1", response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "credential delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/client-downloads",
                                            "{\"implementation\":\"java\",\"platform\":\"any\",\"arch\":\"any\","
                                            "\"displayName\":\"Java exec jar\","
                                            "\"downloadUrl\":\"https://example.com/shuai-tunnel.jar\","
                                            "\"description\":\"cross platform\","
                                            "\"displayOrder\":20,\"enabled\":false}",
                                            response,
                                            sizeof(response));
    int disabled_download_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"displayName\":\"Java exec jar\"")
        || !contains(response, "\"enabled\":false")
        || st_json_get_int(response, "id", &disabled_download_id) != 0
        || disabled_download_id <= 0) {
        fprintf(stderr, "client download disabled create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/client-downloads",
                                            "{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"x64\","
                                            "\"displayName\":\"Linux x64\","
                                            "\"downloadUrl\":\"https://example.com/shuai-tunnel-linux-amd64\","
                                            "\"displayOrder\":10}",
                                            response,
                                            sizeof(response));
    int enabled_download_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"implementation\":\"go\"")
        || !contains(response, "\"platform\":\"linux\"")
        || !contains(response, "\"arch\":\"x64\"")
        || !contains(response, "\"enabled\":true")
        || st_json_get_int(response, "id", &enabled_download_id) != 0
        || enabled_download_id <= 0) {
        fprintf(stderr, "client download enabled create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/public/client-downloads", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"displayName\":\"Linux x64\"")
        || contains(response, "\"displayName\":\"Java exec jar\"")) {
        fprintf(stderr, "client download public list response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/client-downloads/%d", enabled_download_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"implementation\":\"csharp\",\"platform\":\"windows\",\"arch\":\"x64\","
                                            "\"displayName\":\"Windows x64\","
                                            "\"downloadUrl\":\"https://example.com/shuai-tunnel-win-x64.zip\","
                                            "\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"implementation\":\"csharp\"")
        || !contains(response, "\"displayName\":\"Windows x64\"")
        || !contains(response, "\"displayOrder\":10")) {
        fprintf(stderr, "client download update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/client-downloads", response, sizeof(response));
    const char *windows_pos = strstr(response, "\"displayName\":\"Windows x64\"");
    const char *java_pos = strstr(response, "\"displayName\":\"Java exec jar\"");
    if (len <= 0 || !contains(response, "200 OK") || windows_pos == NULL || java_pos == NULL
        || windows_pos > java_pos) {
        fprintf(stderr, "client download admin list order mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/client-downloads/%d", disabled_download_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "client download delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"alice\",\"password\":\"secret\"}",
                                            response,
                                            sizeof(response));
    char *alice_token = st_json_get_string(response, "accessToken");
    if (len <= 0 || !contains(response, "200 OK") || alice_token == NULL) {
        fprintf(stderr, "database user login response mismatch\n");
        free(alice_token);
        return 1;
    }
    snprintf(authorization, sizeof(authorization), "Bearer %s", alice_token);
    len = st_admin_build_response_with_auth("GET", "/api/admin/me", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"username\":\"alice\"")
        || !contains(response, "\"admin\":false")) {
        fprintf(stderr, "database user me response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/users", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "database user admin-only response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/database/initialize",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "database user initialize admin-only response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/client-downloads",
                                            authorization,
                                            "{\"implementation\":\"go\",\"platform\":\"linux\",\"arch\":\"arm64\","
                                            "\"displayName\":\"Forbidden\","
                                            "\"downloadUrl\":\"https://example.com/forbidden\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "403 Forbidden")) {
        fprintf(stderr, "database user client download admin-only response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/clients", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || contains(response, "\"clientName\":\"Demo client\"")) {
        fprintf(stderr, "database user client visibility response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/clients/1/tunnels",
                                            authorization,
                                            "{\"listenPort\":19001,\"targetAddress\":\"127.0.0.1\",\"targetPort\":9001}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "database user foreign tunnel create response mismatch\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/clients",
                                            authorization,
                                            "{\"clientName\":\"Alice managed\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    int alice_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"ownerUsername\":\"alice\"")
        || st_json_get_int(response, "id", &alice_client_id) != 0
        || alice_client_id <= 0) {
        fprintf(stderr, "database user client create response mismatch\n");
        free(alice_token);
        return 1;
    }
    st_storage_client alice_client;
    st_storage_client owner_case_client;
    st_storage_client tenant_case_client;
    if (st_storage_get_client(db_path, alice_client_id, &alice_client) != 0
        || st_storage_upsert_client(db_path,
                                    0,
                                    "tenant-admin",
                                    "Owner case client",
                                    "Alice",
                                    1,
                                    30,
                                    &owner_case_client) != 0
        || st_storage_upsert_client(db_path,
                                    0,
                                    "TENANT-ADMIN",
                                    "Tenant case client",
                                    "alice",
                                    1,
                                    30,
                                    &tenant_case_client) != 0) {
        fprintf(stderr, "peer mesh case-sensitive client setup failed\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET", "/api/admin/clients", authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || contains(response, "Owner case client")
        || contains(response, "Tenant case client")) {
        fprintf(stderr, "client tenant/owner visibility must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    char case_acl_body[256];
    snprintf(case_acl_body,
             sizeof(case_acl_body),
             "{\"sourceClientId\":%lld,\"targetClientId\":%d}",
             owner_case_client.id,
             alice_client_id);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            case_acl_body,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "source client not found")) {
        fprintf(stderr, "peer mesh acl source-owner authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(case_acl_body,
             sizeof(case_acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%lld}",
             alice_client_id,
             owner_case_client.id);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            case_acl_body,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request") || !contains(response, "cross-user peer ACL")) {
        fprintf(stderr, "peer mesh acl target-owner authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(case_acl_body,
             sizeof(case_acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%lld}",
             alice_client_id,
             tenant_case_client.id);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            case_acl_body,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "target client not found")) {
        fprintf(stderr, "peer mesh acl tenant authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    st_storage_peer_mesh_acl hidden_case_acl;
    if (st_storage_upsert_peer_mesh_acl(db_path,
                                        "tenant-admin",
                                        "Alice",
                                        &alice_client,
                                        &owner_case_client,
                                        1,
                                        "OUTBOUND",
                                        &hidden_case_acl) != 0) {
        fprintf(stderr, "peer mesh case-sensitive acl setup failed\n");
        free(alice_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/peer-mesh/acls",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || contains(response, "Owner case client")) {
        fprintf(stderr, "peer mesh acl owner visibility must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/acls/%lld", hidden_case_acl.id);
    len = st_admin_build_response_with_auth("DELETE", request_path, authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "peer mesh acl delete authorization must be case-sensitive\n");
        free(alice_token);
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d", alice_client_id);
    len = st_admin_build_response_with_auth("DELETE", request_path, authorization, NULL, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "database user client delete response mismatch\n");
        free(alice_token);
        return 1;
    }
    free(alice_token);
    len = st_admin_build_response_with_body("PUT",
                                            "/api/admin/users/alice",
                                            "{\"role\":\"ADMIN\",\"enabled\":false}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"role\":\"ADMIN\"")
        || !contains(response, "\"admin\":true")
        || !contains(response, "\"enabled\":false")) {
        fprintf(stderr, "management user update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"alice\",\"password\":\"secret\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "401 Unauthorized")) {
        fprintf(stderr, "disabled database user login response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/users/alice", response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "management user delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/clients", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || contains(response, "\"clientName\":\"Demo client\"")) {
        fprintf(stderr, "clients list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/clients",
                                            "{\"clientName\":\"C managed\",\"enabled\":true,"
                                            "\"connectionRateLimitPerMinute\":55}",
                                            response,
                                            sizeof(response));
    int created_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"ownerUsername\":\"admin-user\"")
        || !contains(response, "\"connectionRateLimitPerMinute\":55")
        || st_json_get_int(response, "id", &created_client_id) != 0
        || created_client_id <= 0) {
        fprintf(stderr, "client create response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d/nat-control", created_client_id);
    len = st_admin_build_response("POST", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "409 Conflict")
        || !contains(response, "客户端不在线")) {
        fprintf(stderr, "offline nat-control response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/clients",
                                            "{\"clientName\":\"C peer target\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    int target_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"clientName\":\"C peer target\"")
        || st_json_get_int(response, "id", &target_client_id) != 0
        || target_client_id <= 0) {
        fprintf(stderr, "peer target client create response mismatch\n");
        return 1;
    }
    char acl_body[256];
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"allowed\":true,\"direction\":\"both\"}",
             created_client_id,
             target_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    int created_acl_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"sourceClientName\":\"C managed\"")
        || !contains(response, "\"targetClientName\":\"C peer target\"")
        || !contains(response, "\"allowed\":true")
        || !contains(response, "\"direction\":\"BOTH\"")
        || st_json_get_int(response, "id", &created_acl_id) != 0
        || created_acl_id <= 0) {
        fprintf(stderr, "peer mesh acl create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/acls", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"sourceClientName\":\"C managed\"")
        || !contains(response, "\"targetClientName\":\"C peer target\"")
        || !contains(response, "\"direction\":\"BOTH\"")) {
        fprintf(stderr, "peer mesh acl list response mismatch\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"allowed\":true}",
             created_client_id,
             target_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"direction\":\"BOTH\"")) {
        fprintf(stderr, "peer mesh acl omitted direction should preserve existing value\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"allowed\":true}",
             target_client_id,
             created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    int default_direction_acl_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"direction\":\"OUTBOUND\"")
        || st_json_get_int(response, "id", &default_direction_acl_id) != 0
        || default_direction_acl_id <= 0) {
        fprintf(stderr, "peer mesh acl default direction response mismatch\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"direction\":\"inbound\"}",
             target_client_id,
             created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"direction\":\"INBOUND\"")) {
        fprintf(stderr, "peer mesh acl inbound direction response mismatch\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d}",
             target_client_id,
             created_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "201 Created") || !contains(response, "\"direction\":\"INBOUND\"")) {
        fprintf(stderr, "peer mesh acl omitted direction should preserve inbound value\n");
        return 1;
    }
    snprintf(acl_body,
             sizeof(acl_body),
             "{\"sourceClientId\":%d,\"targetClientId\":%d,\"direction\":\"SIDEWAYS\"}",
             created_client_id,
             target_client_id);
    len = st_admin_build_response_with_body("POST", "/api/admin/peer-mesh/acls", acl_body, response, sizeof(response));
    if (len <= 0 || !contains(response, "400 Bad Request")
        || !contains(response, "invalid direction: SIDEWAYS")) {
        fprintf(stderr, "peer mesh acl direction validation mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/acls/%d", default_direction_acl_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "default direction peer mesh acl delete response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/acls/%d", created_acl_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "peer mesh acl delete response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"online\":false")
        || !contains(response, "\"virtualDeviceStatus\":\"UNSUPPORTED\"")) {
        fprintf(stderr, "peer mesh devices from clients response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/peer-mesh/devices/%d", created_client_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"enabled\":true")
        || !contains(response, "\"virtualDeviceStatus\":\"UNSUPPORTED\"")) {
        fprintf(stderr, "peer mesh device update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed\"")
        || !contains(response, "\"enabled\":true")) {
        fprintf(stderr, "peer mesh devices updated list response mismatch\n");
        return 1;
    }
    char peer_session_sql[2048];
    snprintf(peer_session_sql,
             sizeof(peer_session_sql),
             "INSERT INTO peer_mesh_session("
             "id, tenant_id, source_client_id, source_client_name, target_client_id, target_client_name, "
             "path_type, status, token_hash, started_at, updated_at, expires_at, rtt_millis, "
             "local_endpoint, remote_endpoint, direct_bytes, relay_bytes, last_traffic_at) VALUES "
             "(99001, 'tenant-admin', %d, 'C managed', %d, 'C peer target', 'DIRECT', 'ACTIVE', 'hash-a', "
             "'2026-06-25T01:00:00Z', '2026-06-25T01:01:00Z', '2026-06-25T02:00:00Z', 12, "
             "'10.0.0.1:10000', '10.0.0.2:10001', 128, 0, '2026-06-25T01:01:00Z'),"
             "(99002, 'tenant-admin', %d, 'C managed', %d, 'C peer target', 'RELAY', 'NEGOTIATING', 'hash-b', "
             "'2026-06-25T01:02:00Z', '2026-06-25T01:03:00Z', '2026-06-25T02:03:00Z', NULL, "
             "NULL, 'relay.example:3478', 0, 64, NULL)",
             created_client_id,
             target_client_id,
             created_client_id,
             target_client_id);
    if (test_exec_sql(db_path, peer_session_sql) != 0) {
        fprintf(stderr, "peer mesh session seed failed\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/sessions?limit=10", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"id\":99001")
        || !contains(response, "\"pathType\":\"DIRECT\"")
        || !contains(response, "\"rttMillis\":12")
        || !contains(response, "\"directBytes\":128")
        || !contains(response, "\"id\":99002")
        || !contains(response, "\"pathType\":\"RELAY\"")) {
        fprintf(stderr, "peer mesh session list response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions/99001", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"id\":99001")
        || !contains(response, "\"status\":\"CLOSED\"")
        || !contains(response, "\"closedAt\":")) {
        fprintf(stderr, "peer mesh session close response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"id\":99002")
        || !contains(response, "\"status\":\"CLOSED\"")
        || contains(response, "\"id\":99001")) {
        fprintf(stderr, "peer mesh open session close response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d", created_client_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"clientName\":\"C managed 2\",\"enabled\":false,"
                                            "\"connectionRateLimitPerMinute\":12}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"connectionRateLimitPerMinute\":12")) {
        fprintf(stderr, "client update response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d/tunnels", created_client_id);
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            "{\"listenPort\":19090,\"targetAddress\":\"127.0.0.1\","
                                            "\"targetPort\":9090,\"enabled\":true,\"detailCaptureEnabled\":true}",
                                            response,
                                            sizeof(response));
    int created_tunnel_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"listenPort\":19090")
        || !contains(response, "\"targetAddress\":\"127.0.0.1\"")
        || !contains(response, "\"targetPort\":9090")
        || !contains(response, "\"detailCaptureEnabled\":true")
        || st_json_get_int(response, "id", &created_tunnel_id) != 0
        || created_tunnel_id <= 0) {
        fprintf(stderr, "tunnel create response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/tunnels?clientId=%d", created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientId\":")
        || !contains(response, "\"listenPort\":19090")) {
        fprintf(stderr, "tunnel filtered list response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/tunnels/%d", created_tunnel_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"listenPort\":19091,\"targetAddress\":\"192.168.1.12\","
                                            "\"targetPort\":9091,\"enabled\":false,"
                                            "\"detailCaptureEnabled\":false}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"listenPort\":19091")
        || !contains(response, "\"targetAddress\":\"192.168.1.12\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"detailCaptureEnabled\":false")) {
        fprintf(stderr, "tunnel update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "tunnel delete response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d/http-routes", created_client_id);
    len = st_admin_build_response_with_body("POST",
                                            request_path,
                                            "{\"route\":\"api\",\"targetBaseUrl\":\"https://example.com/base\","
                                            "\"enabled\":true,\"detailCaptureEnabled\":true,"
                                            "\"pathRewriteEnabled\":true}",
                                            response,
                                            sizeof(response));
    int created_route_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"https://example.com/base\"")
        || !contains(response, "\"detailCaptureEnabled\":true")
        || !contains(response, "\"pathRewriteEnabled\":true")
        || st_json_get_int(response, "id", &created_route_id) != 0
        || created_route_id <= 0) {
        fprintf(stderr, "http route create response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/http-routes?clientId=%d", created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"https://example.com/base\"")) {
        fprintf(stderr, "http route filtered list response mismatch\n");
        return 1;
    }
    st_direct_http_response rewrite_response;
    memset(&rewrite_response, 0, sizeof(rewrite_response));
    rewrite_response.status_code = 200;
    rewrite_response.headers_len = 2;
    rewrite_response.headers = (char **)calloc(rewrite_response.headers_len, sizeof(*rewrite_response.headers));
    const char *rewrite_html = "<html><head><title>x</title></head><body>"
        "<a href=\"/login\"><img src='/img/logo.png' srcset=\"/a.png 1x, /b.png 2x\"></body></html>";
    if (rewrite_response.headers == NULL
        || (rewrite_response.headers[0] = test_dup_string("Content-Type: text/html; charset=UTF-8")) == NULL
        || (rewrite_response.headers[1] = test_dup_string("ETag: \"old\"")) == NULL
        || (rewrite_response.body = test_dup_body(rewrite_html, &rewrite_response.body_len)) == NULL) {
        fprintf(stderr, "direct http rewrite fixture allocation failed\n");
        st_direct_http_response_free(&rewrite_response);
        return 1;
    }
    if (st_admin_rewrite_direct_http_response("C managed 2", "api", &rewrite_response) != 1
        || !contains((const char *)rewrite_response.body, "href=\"/http/C managed 2/api/login\"")
        || !contains((const char *)rewrite_response.body, "src='/http/C managed 2/api/img/logo.png'")
        || !contains((const char *)rewrite_response.body, "/http/C managed 2/api/a.png 1x")
        || !contains((const char *)rewrite_response.body, "var P='/http/C managed 2/api'")
        || rewrite_response.headers[1] != NULL) {
        fprintf(stderr, "direct http html rewrite response mismatch\n");
        st_direct_http_response_free(&rewrite_response);
        return 1;
    }
    st_direct_http_response_free(&rewrite_response);
    setenv("TUNNEL_CLIENT_ACCESS_TOKEN", "db-route-token", 1);
    setenv("TUNNEL_CLIENT_NAME", "C managed 2", 1);
    len = st_admin_build_response("POST", "/api/client/auth/login", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"httpTunnelConfigList\":[")
        || !contains(response, "\"route\":\"api\"")
        || !contains(response, "\"targetBaseUrl\":\"https://example.com/base\"")) {
        fprintf(stderr, "client auth database http route response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_CLIENT_ACCESS_TOKEN");
    unsetenv("TUNNEL_CLIENT_NAME");
    snprintf(request_path, sizeof(request_path), "/api/admin/http-routes/%d", created_route_id);
    len = st_admin_build_response_with_body("PUT",
                                            request_path,
                                            "{\"route\":\"web\",\"targetBaseUrl\":\"http://127.0.0.1:8088\","
                                            "\"enabled\":false,\"detailCaptureEnabled\":false,"
                                            "\"pathRewriteEnabled\":false}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"route\":\"web\"")
        || !contains(response, "\"targetBaseUrl\":\"http://127.0.0.1:8088\"")
        || !contains(response, "\"enabled\":false")
        || !contains(response, "\"pathRewriteEnabled\":false")) {
        fprintf(stderr, "http route update response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "http route delete response mismatch\n");
        return 1;
    }
    if (st_storage_record_connection_detail_with_tenant_and_id(db_path,
                                                               "tenant-admin",
                                                               created_client_id,
                                                               "C managed 2",
                                                               "admin-chan",
                                                               "127.0.0.1:62100",
                                                               1,
                                                               NULL,
                                                               "CLIENT_CLOSED",
                                                               "2026-06-20T02:00:00Z",
                                                               "2026-06-20T02:05:00Z",
                                                               NULL) != 0) {
        fprintf(stderr, "connection seed failed\n");
        return 1;
    }
    snprintf(request_path,
             sizeof(request_path),
             "/api/admin/connections?clientId=%d&success=true"
             "&from=2026-06-20T02%%3A00%%3A00Z"
             "&to=2026-06-20T03%%3A00%%3A00Z&page=0&size=10",
             created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"items\":[")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"page\":0")
        || !contains(response, "\"size\":10")
        || !contains(response, "\"totalPages\":1")
        || !contains(response, "\"clientId\":")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"channelId\":\"admin-chan\"")
        || !contains(response, "\"remoteAddress\":\"127.0.0.1:62100\"")
        || !contains(response, "\"success\":true")
        || !contains(response, "\"disconnectReason\":\"CLIENT_CLOSED\"")
        || !contains(response, "\"disconnectReasonText\":\"客户端正常断开\"")) {
        fprintf(stderr, "connection list response mismatch\n");
        return 1;
    }
    if (st_storage_archive_connections(db_path, "2026-06-21T00:00:00Z") != 0) {
        fprintf(stderr, "connection archive failed\n");
        return 1;
    }
    len = st_admin_build_response("GET",
                                  "/api/admin/connection-stats?clientName=C+managed+2&limit=10",
                                  response,
                                  sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"month\":\"2026-06-20\"")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"success\":1")
        || !contains(response, "\"failure\":0")
        || !contains(response, "\"updatedAt\":")) {
        fprintf(stderr, "connection stats response mismatch\n");
        return 1;
    }
    if (st_storage_record_traffic_usage(db_path,
                                        created_client_id,
                                        "C managed 2",
                                        "2026-06-20",
                                        1024,
                                        2048) != 0
        || st_storage_record_resource_traffic_usage(db_path,
                                                    created_client_id,
                                                    "C managed 2",
                                                    "HTTP_ROUTE",
                                                    "http:api",
                                                    created_route_id,
                                                    "api -> https://example.com/base",
                                                    "2026-06-20",
                                                    512,
                                                    4096) != 0) {
        fprintf(stderr, "traffic seed failed\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/traffic?clientId=%d&limit=10", created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"C managed 2\"")
        || !contains(response, "\"usageDate\":\"2026-06-20\"")
        || !contains(response, "\"uploadBytes\":1024")
        || !contains(response, "\"downloadBytes\":2048")
        || !contains(response, "\"updatedAt\":")) {
        fprintf(stderr, "traffic response mismatch\n");
        return 1;
    }
    snprintf(request_path,
             sizeof(request_path),
             "/api/admin/traffic/resources?clientId=%d&type=HTTP_ROUTE&limit=10",
             created_client_id);
    len = st_admin_build_response("GET", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"resourceType\":\"HTTP_ROUTE\"")
        || !contains(response, "\"resourceKey\":\"http:api\"")
        || !contains(response, "\"resourceId\":")
        || !contains(response, "\"resourceName\":\"api -> https://example.com/base\"")
        || !contains(response, "\"uploadBytes\":512")
        || !contains(response, "\"downloadBytes\":4096")) {
        fprintf(stderr, "resource traffic response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/api/admin/users",
                                            "{\"username\":\"bob\",\"password\":\"secret\","
                                            "\"role\":\"USER\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "201 Created")) {
        fprintf(stderr, "tenant scoped user create response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/auth/login",
                                            "{\"username\":\"bob\",\"password\":\"secret\"}",
                                            response,
                                            sizeof(response));
    char *bob_token = st_json_get_string(response, "accessToken");
    if (len <= 0 || !contains(response, "200 OK") || bob_token == NULL) {
        fprintf(stderr, "tenant scoped user login response mismatch\n");
        free(bob_token);
        return 1;
    }
    snprintf(authorization, sizeof(authorization), "Bearer %s", bob_token);
    len = st_admin_build_response_with_auth("POST",
                                            "/api/admin/clients",
                                            authorization,
                                            "{\"clientName\":\"Bob managed\",\"enabled\":true}",
                                            response,
                                            sizeof(response));
    int bob_client_id = 0;
    if (len <= 0 || !contains(response, "201 Created")
        || !contains(response, "\"ownerUsername\":\"bob\"")
        || st_json_get_int(response, "id", &bob_client_id) != 0
        || bob_client_id <= 0) {
        fprintf(stderr, "tenant scoped client create response mismatch\n");
        free(bob_token);
        return 1;
    }
    if (st_storage_record_connection_detail_with_tenant_and_id(db_path,
                                                               "tenant-admin",
                                                               created_client_id,
                                                               "C managed 2",
                                                               "admin-private-chan",
                                                               "127.0.0.1:62200",
                                                               1,
                                                               NULL,
                                                               "CLIENT_CLOSED",
                                                               "2026-06-22T02:00:00Z",
                                                               "2026-06-22T02:01:00Z",
                                                               NULL) != 0
        || st_storage_record_connection_detail_with_tenant_and_id(db_path,
                                                                  "tenant-admin",
                                                                  bob_client_id,
                                                                  "Bob managed",
                                                                  "bob-chan",
                                                                  "127.0.0.1:62300",
                                                                  1,
                                                                  NULL,
                                                                  "CLIENT_CLOSED",
                                                                  "2026-06-22T02:00:00Z",
                                                                  "2026-06-22T02:01:00Z",
                                                                  NULL) != 0
        || st_storage_record_traffic_usage(db_path,
                                           bob_client_id,
                                           "Bob managed",
                                           "2026-06-22",
                                           9,
                                           10) != 0
        || st_storage_record_resource_traffic_usage(db_path,
                                                    bob_client_id,
                                                    "Bob managed",
                                                    "HTTP_ROUTE",
                                                    "http:bob",
                                                    0,
                                                    "bob -> http://127.0.0.1:9000",
                                                    "2026-06-22",
                                                    11,
                                                    12) != 0) {
        fprintf(stderr, "tenant scoped seed failed\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/connections?page=0&size=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Bob managed\"")
        || !contains(response, "\"channelId\":\"bob-chan\"")
        || contains(response, "admin-private-chan")
        || contains(response, "\"clientName\":\"C managed 2\"")) {
        fprintf(stderr, "tenant scoped connection visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    if (st_storage_archive_connections(db_path, "2026-06-23T00:00:00Z") != 0) {
        fprintf(stderr, "tenant scoped connection archive failed\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/connection-stats?limit=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Bob managed\"")
        || contains(response, "\"clientName\":\"C managed 2\"")) {
        fprintf(stderr, "tenant scoped connection stats visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/traffic?limit=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"clientName\":\"Bob managed\"")
        || contains(response, "\"clientName\":\"C managed 2\"")) {
        fprintf(stderr, "tenant scoped traffic visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    len = st_admin_build_response_with_auth("GET",
                                            "/api/admin/traffic/resources?type=HTTP_ROUTE&limit=20",
                                            authorization,
                                            NULL,
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"resourceKey\":\"http:bob\"")
        || contains(response, "\"resourceKey\":\"http:api\"")) {
        fprintf(stderr, "tenant scoped resource traffic visibility mismatch\n");
        free(bob_token);
        return 1;
    }
    free(bob_token);
    const uint8_t http_request_body[] = "{\"hello\":true}";
    const uint8_t http_response_body[] = "{\"ok\":true}";
    st_storage_http_exchange_record http_record = {
        .tenant_id = "tenant-admin",
        .client_id = created_client_id,
        .client_name = "C managed 2",
        .route = "api",
        .resource_id = created_route_id,
        .resource_name = "api -> https://example.com/base",
        .method = "POST",
        .relative_path = "/items",
        .raw_query = "page=1",
        .status_code = 201,
        .success = 1,
        .remote_address = "127.0.0.1:62000",
        .request_bytes = (long long)(sizeof(http_request_body) - 1U),
        .response_bytes = (long long)(sizeof(http_response_body) - 1U),
        .elapsed_ms = 12,
        .request_content_type = "application/json",
        .response_content_type = "application/json",
        .request_headers = "Content-Type: application/json",
        .response_headers = "Content-Type: application/json",
        .request_body = http_request_body,
        .request_body_len = sizeof(http_request_body) - 1U,
        .response_body = http_response_body,
        .response_body_len = sizeof(http_response_body) - 1U,
        .captured_at = "2026-06-20T02:00:01Z"
    };
    st_storage_http_exchange_record http_record_get = {
        .tenant_id = "tenant-admin",
        .client_id = created_client_id,
        .client_name = "C managed 2",
        .route = "assets",
        .resource_id = created_route_id,
        .resource_name = "assets -> https://example.com/static",
        .method = "GET",
        .relative_path = "/vendor.js",
        .status_code = 200,
        .success = 1,
        .remote_address = "127.0.0.1:62001",
        .request_bytes = 0,
        .response_bytes = 1024,
        .elapsed_ms = 6,
        .response_content_type = "text/javascript",
        .request_headers = "X-Debug-Method: POST",
        .response_headers = "Content-Type: text/javascript",
        .response_body = (const uint8_t *)"console.log('ready')",
        .response_body_len = strlen("console.log('ready')"),
        .captured_at = "2026-06-20T02:00:02Z"
    };
    const uint8_t tcp_payload_a[] = "GET / HTTP/1.1\r\n\r\n";
    const uint8_t tcp_payload_b[] = "HTTP/1.1 200 OK\r\n\r\n";
    st_storage_tcp_frame_record tcp_record_a = {
        .tenant_id = "tenant-admin",
        .client_id = created_client_id,
        .client_name = "C managed 2",
        .listen_port = 19090,
        .resource_id = created_tunnel_id,
        .resource_name = "19090 -> 127.0.0.1:9090",
        .channel_id = "tcp-chan-1",
        .direction = "PUBLIC_TO_CLIENT",
        .remote_address = "127.0.0.1:62100",
        .source_address = "127.0.0.1",
        .source_port = 62100,
        .destination_address = "127.0.0.1",
        .destination_port = 9090,
        .stream_offset = 0,
        .frame_index = 0,
        .payload_data = tcp_payload_a,
        .payload_data_len = sizeof(tcp_payload_a) - 1U,
        .frame_time = "2026-06-20T02:00:02Z"
    };
    st_storage_tcp_frame_record tcp_record_b = tcp_record_a;
    tcp_record_b.direction = "CLIENT_TO_PUBLIC";
    tcp_record_b.stream_offset = 0;
    tcp_record_b.frame_index = 0;
    tcp_record_b.payload_data = tcp_payload_b;
    tcp_record_b.payload_data_len = sizeof(tcp_payload_b) - 1U;
    tcp_record_b.frame_time = "2026-06-20T02:00:03Z";
    if (st_storage_record_http_exchange(db_path, &http_record) != 0
        || st_storage_record_http_exchange(db_path, &http_record_get) != 0
        || st_storage_record_tcp_frame(db_path, &tcp_record_a) != 0
        || st_storage_record_tcp_frame(db_path, &tcp_record_b) != 0) {
        fprintf(stderr, "traffic detail seed failed\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"method\":\"POST\"")
        || !contains(response, "\"statusCode\":201")
        || !contains(response, "\"responseBodyType\":\"json\"")
        || !contains(response, "\"responsePreviewText\":\"{\\\"ok\\\":true}\"")
        || !contains(response, "\"size\":20")
        || !contains(response, "\"totalPages\":1")) {
        fprintf(stderr, "http exchange page response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?field=method&q=POST&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"method\":\"POST\"")) {
        fprintf(stderr, "http exchange field search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?q=POST%20api&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"method\":\"POST\"")) {
        fprintf(stderr, "http exchange tokenized search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?field=status&q=201&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"statusCode\":201")) {
        fprintf(stderr, "http exchange status search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/http-exchanges?field=responseDataType&q=json&page=0&size=20", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"total\":1")
        || !contains(response, "\"responseBodyType\":\"json\"")) {
        fprintf(stderr, "http exchange response data type search response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/tcp-frames?limit=25", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"direction\":\"CLIENT_TO_PUBLIC\"")
        || !contains(response, "\"direction\":\"PUBLIC_TO_CLIENT\"")
        || !contains(response, "\"size\":25")
        || !contains(response, "\"total\":2")) {
        fprintf(stderr, "tcp frame page response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/tcp-streams?channelId=tcp-chan-1&limit=5", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"channelId\":\"tcp-chan-1\"")
        || !contains(response, "\"payloadBase64\":")
        || !contains(response, "\"limit\":5")
        || !contains(response, "\"truncated\":false")) {
        fprintf(stderr, "tcp stream response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("GET", "/api/admin/traffic/tcp-frames/1", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"payloadBase64\":")
        || !contains(response, "\"payloadPreviewText\":\"GET / HTTP/1.1")) {
        fprintf(stderr, "tcp frame detail response mismatch\n");
        return 1;
    }
    snprintf(request_path, sizeof(request_path), "/api/admin/clients/%d", created_client_id);
    len = st_admin_build_response("DELETE", request_path, response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "client delete response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_DATABASE_PATH");
    unsetenv("TUNNEL_AUTH_TENANT_ID");
    unsetenv("TUNNEL_AUTH_USERNAME");
    unlink(db_path);

    len = st_admin_build_response("GET", "/api/admin/peer-mesh/status", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"enabled\":false")
        || contains(response, "\"dataPlane\"") || contains(response, "\"controlPlane\"")) {
        fprintf(stderr, "peer mesh status response mismatch\n");
        return 1;
    }
    setenv("TUNNEL_PEER_MESH_ENABLED", "true", 1);
    len = st_admin_build_response("GET", "/api/admin/peer-mesh/status", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"enabled\":true")) {
        fprintf(stderr, "peer mesh enabled status response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_PEER_MESH_ENABLED");

    len = st_admin_build_response("GET", "/api/admin/peer-mesh/devices", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "[]")) {
        fprintf(stderr, "peer mesh devices response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "[]")) {
        fprintf(stderr, "peer mesh clear sessions response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/sessions/123", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "peer mesh session not found")) {
        fprintf(stderr, "peer mesh close missing session response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("PUT", "/api/admin/peer-mesh/devices/42", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found") || !contains(response, "peer mesh device not found")) {
        fprintf(stderr, "peer mesh update missing device response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("DELETE", "/api/admin/peer-mesh/acls/42", response, sizeof(response));
    if (len <= 0 || !contains(response, "204 No Content")) {
        fprintf(stderr, "peer mesh delete missing acl response mismatch\n");
        return 1;
    }
    len = st_admin_build_response("POST", "/api/admin/peer-mesh/relay-allocations", response, sizeof(response));
    if (len <= 0 || !contains(response, "501 Not Implemented")
        || !contains(response, "C server does not implement this Peer Mesh operation")) {
        fprintf(stderr, "peer mesh unsupported operation response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/http/Demo%20client/api/v1/items", response, sizeof(response));
    if (len <= 0 || !contains(response, "501 Not Implemented")
        || !contains(response, "direct http dispatch")) {
        fprintf(stderr, "direct http skeleton response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/ws/connections", response, sizeof(response));
    if (len <= 0 || !contains(response, "426 Upgrade Required")
        || !contains(response, "websocket upgrade required")) {
        fprintf(stderr, "websocket skeleton response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/oidc-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK") || !contains(response, "\"configured\":false")
        || !contains(response, "\"passwordLoginEnabled\":true")) {
        fprintf(stderr, "oidc config response mismatch\n");
        return 1;
    }
    setenv("TUNNEL_OIDC_CLIENT_ID", "admin-spa", 1);
    setenv("TUNNEL_OIDC_AUTHORIZATION_ENDPOINT", "https://issuer.example/authorize", 1);
    setenv("TUNNEL_OIDC_TOKEN_ENDPOINT", "https://issuer.example/token", 1);
    setenv("TUNNEL_OIDC_END_SESSION_ENDPOINT", "https://issuer.example/logout", 1);
    setenv("TUNNEL_OIDC_REDIRECT_URI", "http://127.0.0.1:8088/callback", 1);
    setenv("TUNNEL_OIDC_SCOPE", "openid profile email", 1);
    setenv("TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED", "false", 1);
    len = st_admin_build_response("GET", "/oidc-config", response, sizeof(response));
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"configured\":true")
        || !contains(response, "\"authorizationEndpoint\":\"https://issuer.example/authorize\"")
        || !contains(response, "\"endSessionEndpoint\":\"https://issuer.example/logout\"")
        || !contains(response, "\"clientId\":\"admin-spa\"")
        || !contains(response, "\"redirectUri\":\"http://127.0.0.1:8088/callback\"")
        || !contains(response, "\"scope\":\"openid profile email\"")
        || !contains(response, "\"passwordLoginEnabled\":false")
        || contains(response, "\"tokenEndpoint\"")
        || contains(response, "\"issuer\"")) {
        fprintf(stderr, "oidc configured response mismatch\n");
        return 1;
    }
    len = st_admin_build_response_with_body("POST",
                                            "/oidc/token",
                                            "{\"code\":\"abc\",\"codeVerifier\":\"verifier\"}",
                                            response,
                                            sizeof(response));
    if (len <= 0 || !contains(response, "502 Bad Gateway")
        || !contains(response, "HTTPS token endpoint")) {
        fprintf(stderr, "oidc https token response mismatch\n");
        return 1;
    }
    oidc_test_server oidc_server;
    pthread_t oidc_thread;
    if (oidc_test_server_start(&oidc_server, &oidc_thread) != 0) {
        fprintf(stderr, "oidc test server start failed\n");
        return 1;
    }
    char oidc_endpoint[128];
    snprintf(oidc_endpoint, sizeof(oidc_endpoint), "http://127.0.0.1:%d/token", oidc_server.port);
    setenv("TUNNEL_OIDC_TOKEN_ENDPOINT", oidc_endpoint, 1);
    len = st_admin_build_response_with_body("POST",
                                            "/oidc/token",
                                            "{\"code\":\"abc\",\"codeVerifier\":\"verifier value\"}",
                                            response,
                                            sizeof(response));
    oidc_test_server_stop(&oidc_server, oidc_thread);
    if (len <= 0 || !contains(response, "200 OK")
        || !contains(response, "\"accessToken\":\"access-1\"")
        || !contains(response, "\"idToken\":\"id-1\"")
        || !contains(response, "\"tokenType\":\"Bearer\"")
        || !contains(response, "\"expiresIn\":3600")
        || !contains(oidc_server.request, "POST /token HTTP/1.1")
        || !contains(oidc_server.request, "grant_type=authorization_code")
        || !contains(oidc_server.request, "code=abc")
        || !contains(oidc_server.request, "code_verifier=verifier+value")
        || !contains(oidc_server.request, "client_id=admin-spa")) {
        fprintf(stderr, "oidc http token exchange response mismatch\n");
        return 1;
    }
    unsetenv("TUNNEL_OIDC_CLIENT_ID");
    unsetenv("TUNNEL_OIDC_AUTHORIZATION_ENDPOINT");
    unsetenv("TUNNEL_OIDC_TOKEN_ENDPOINT");
    unsetenv("TUNNEL_OIDC_END_SESSION_ENDPOINT");
    unsetenv("TUNNEL_OIDC_REDIRECT_URI");
    unsetenv("TUNNEL_OIDC_SCOPE");
    unsetenv("TUNNEL_AUTH_PASSWORD_LOGIN_ENABLED");
    len = st_admin_build_response("POST", "/oidc/token", response, sizeof(response));
    if (len <= 0 || !contains(response, "503 Service Unavailable")
        || !contains(response, "OIDC")) {
        fprintf(stderr, "oidc unconfigured token response mismatch\n");
        return 1;
    }

    len = st_admin_build_response("GET", "/missing", response, sizeof(response));
    if (len <= 0 || !contains(response, "404 Not Found")) {
        fprintf(stderr, "404 response mismatch\n");
        return 1;
    }

    char path[512];
    const char *content_type = NULL;
    if (st_admin_resolve_static_path("../../java/server/src/main/resources/static",
                                     "/",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "index.html")
        || strcmp(content_type, "text/html; charset=utf-8") != 0) {
        fprintf(stderr, "static index path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../java/server/src/main/resources/static",
                                     "/app.js?cache=1",
                                     path,
                                     sizeof(path),
                                     &content_type) != 0
        || !contains(path, "app.js")
        || strcmp(content_type, "application/javascript; charset=utf-8") != 0) {
        fprintf(stderr, "static js path mismatch\n");
        return 1;
    }
    if (st_admin_resolve_static_path("../../java/server/src/main/resources/static",
                                     "/../application.yml",
                                     path,
                                     sizeof(path),
                                     &content_type) == 0) {
        fprintf(stderr, "static traversal was allowed\n");
        return 1;
    }
    return 0;
}
