#define _POSIX_C_SOURCE 200809L
#include "admin_http.h"
#include "crypto.h"
#include "instant.h"
#include "json.h"
#include "security.h"
#include "storage.h"
#include "websocket_ticket.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "ticket request failed line%d: %s\n", __LINE__, #ok); exit(1); } } while (0)
static pthread_mutex_t clock_lock = PTHREAD_MUTEX_INITIALIZER;
static struct timespec fixed_clock;
static int port;
static char database[256], auth[2400];
static pid_t child_pid;
static const long long base_seconds = 1789473600LL;
extern int __real_clock_gettime(clockid_t id, struct timespec *out);
int __wrap_clock_gettime(clockid_t id, struct timespec *out)
{
    if (id != CLOCK_REALTIME) return __real_clock_gettime(id, out);
    pthread_mutex_lock(&clock_lock); *out = fixed_clock; pthread_mutex_unlock(&clock_lock); return 0;
}
static void set_clock(long long seconds, long nanos)
{
    while (nanos < 0) { --seconds; nanos += 1000000000L; }
    while (nanos >= 1000000000L) { ++seconds; nanos -= 1000000000L; }
    pthread_mutex_lock(&clock_lock); fixed_clock.tv_sec = (time_t)seconds; fixed_clock.tv_nsec = nanos; pthread_mutex_unlock(&clock_lock);
}
static void cleanup(void)
{
    if (child_pid > 0) { kill(child_pid, SIGKILL); waitpid(child_pid, NULL, 0); }
    if (*database != '\0') unlink(database);
}
static int connect_api(const char *source)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0); CHECK(fd >= 0);
    struct timeval timeout = {3,0};
    CHECK(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0 && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0);
    struct sockaddr_in address = {0}; address.sin_family = AF_INET;
    CHECK(inet_pton(AF_INET, source, &address.sin_addr) == 1 && bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK); address.sin_port = htons((uint16_t)port);
    CHECK(connect(fd, (struct sockaddr *)&address, sizeof(address)) == 0); return fd;
}
static void send_all(int fd, const char *bytes, size_t len)
{
    while (len > 0U) { ssize_t n = send(fd, bytes, len, MSG_NOSIGNAL); CHECK(n > 0); bytes += n; len -= (size_t)n; }
}
static int http(const char *method, const char *path, const char *source, const char *body, char response[8192])
{
    char request[8192]; size_t len = body == NULL ? 0U : strlen(body);
    int n = snprintf(request, sizeof(request), "%s %s HTTP/1.1\r\nHost: localhost\r\nAuthorization: %s\r\nContent-Type: application/json\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s", method, path, auth, len, body == NULL ? "" : body);
    CHECK(n > 0 && (size_t)n < sizeof(request)); int fd = connect_api(source); send_all(fd, request, (size_t)n);
    size_t at = 0U; ssize_t got;
    while ((got = recv(fd, response + at, 8191U - at, 0)) > 0) { at += (size_t)got; CHECK(at < 8191U); }
    CHECK(got == 0); response[at] = '\0'; close(fd); return atoi(response + 9);
}
static int websocket(const char *path, const char *source)
{
    int fd = connect_api(source); char request[4096], response[8192];
    int n = snprintf(request, sizeof(request), "GET %s HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", path);
    CHECK(n > 0 && (size_t)n < sizeof(request)); send_all(fd, request, (size_t)n);
    size_t at = 0U;
    do { CHECK(at + 1U < sizeof(response) && recv(fd, response + at, 1U, 0) == 1); response[++at] = '\0'; } while (strstr(response, "\r\n\r\n") == NULL);
    int status = atoi(response + 9);
    if (status == 101) {
        static const char close_frame[] = {(char)0x88,(char)0x82,1,2,3,4, (char)(3^1),(char)(0xe8^2)};
        send_all(fd, close_frame, sizeof(close_frame));
    }
    ssize_t got; do { got = recv(fd, response, sizeof(response), 0); } while (got > 0);
    CHECK(got == 0); close(fd); return status;
}
static void start_api(st_admin_server *server)
{
    CHECK(st_admin_server_start(server, 0, "") == 0);
    struct sockaddr_in address; socklen_t bytes = sizeof(address);
    CHECK(getsockname(server->fd, (struct sockaddr *)&address, &bytes) == 0); port = ntohs(address.sin_port);
}
static void issue(int scope, const char *source, char token[64], char expiry[40])
{
    const char *bodies[] = {"{\"endpoint\":\"connections\"}","{\"endpoint\":\"client-messages\"}","{\"roomId\":\"ttl-test\",\"peerId\":\"ttl-peer\",\"displayName\":\"TTL\"}"};
    char response[8192]; CHECK(http("POST", scope == 2 ? "/api/public/transfer/ws-tickets" : "/api/admin/ws-tickets", source, bodies[scope], response) == 200);
    const char *body = strstr(response, "\r\n\r\n"); CHECK(body != NULL);
    CHECK(st_websocket_ticket_json_string(body + 4, "ticket", token, 64U, 1) == 0 && strlen(token) == 43U);
    CHECK(st_websocket_ticket_json_string(body + 4, "expiresAt", expiry, 40U, 1) == 0);
}
static const char *ws_paths[] = {"/ws/connections", "/ws/client-messages", "/ws/public-transfer/discovery"};
static void restart_ticket(void)
{
    int ready[2], stop[2]; CHECK(pipe(ready) == 0 && pipe(stop) == 0);
    set_clock(base_seconds - 45LL, 123456700L);
    child_pid = fork(); CHECK(child_pid >= 0);
    if (child_pid == 0) {
        close(ready[0]); close(stop[1]);
#ifdef __linux__
        CHECK(prctl(PR_SET_PDEATHSIG, SIGKILL) == 0);
#endif
        st_admin_server server; start_api(&server);
        CHECK(write(ready[1], &port, sizeof(port)) == (ssize_t)sizeof(port)); close(ready[1]);
        char signal; CHECK(read(stop[0], &signal, 1) == 1); _exit(0);
    }
    close(ready[1]); close(stop[0]); CHECK(read(ready[0], &port, sizeof(port)) == (ssize_t)sizeof(port)); close(ready[0]);
    char token[64], expiry[40]; issue(0, "127.10.0.1", token, expiry);
    CHECK(strcmp(expiry, "2026-09-15T12:00:00.123456700Z") == 0);
    CHECK(write(stop[1], "x", 1) == 1); close(stop[1]);
    int status; CHECK(waitpid(child_pid, &status, 0) == child_pid && WIFEXITED(status) && WEXITSTATUS(status) == 0); child_pid = 0;
    static st_admin_server restarted; start_api(&restarted); set_clock(base_seconds, 123456700L);
    char path[256]; snprintf(path, sizeof(path), "/ws/connections?ticket=%s", token);
    CHECK(websocket(path, "127.10.0.1") == 101 && websocket(path, "127.10.0.1") == 403);
    puts("ticket request: actual HTTP issuer process exited; new API server process consumed stored ticket at exact100ns expiry once, replay403 passed; not main-CLI startup");
}
static void expiry_routes(void)
{
    static const long offsets[] = {-500000000L,-1000000L,-1000L,0,1000L,250000000L,500000000L};
    unsigned int identity = 1U;
    for (int stored = 0; stored < 2; ++stored) {
        if (stored) CHECK(setenv("SPECUS_DATABASE_PATH", database, 1) == 0); else CHECK(unsetenv("SPECUS_DATABASE_PATH") == 0);
        for (int scope = 0; scope < 3; ++scope) for (int fractional = 0; fractional < 2; ++fractional) {
            for (int i = 0; i < 7; ++i) {
                char source[32]; snprintf(source, sizeof(source), "127.11.0.%u", identity++);
                long nanos = fractional * 500000000L + offsets[i];
                set_clock(base_seconds - 45LL, nanos);
                char token[64], expiry[40], expected[40], path[512]; issue(scope, source, token, expiry);
                long long seconds = base_seconds; while (nanos < 0) { --seconds; nanos += 1000000000L; } while (nanos >= 1000000000L) { ++seconds; nanos -= 1000000000L; }
                CHECK(st_instant_format(seconds, nanos, expected) == 0 && st_instant_public(expected, expected, sizeof(expected)) == 0 && strcmp(expiry, expected) == 0);
                set_clock(base_seconds, fractional * 500000000L);
                if (i == 3) {
                    snprintf(path, sizeof(path), "%s?ticket=%s", ws_paths[(scope + 1) % 3], token); CHECK(websocket(path, source) == 403);
                    snprintf(path, sizeof(path), "%s?ticket=%s", ws_paths[scope], token); CHECK(websocket(path, "127.12.0.1") == 403);
                    snprintf(path, sizeof(path), "%s?ticket=%s%%00suffix", ws_paths[scope], token); CHECK(websocket(path, source) == 403);
                    snprintf(path, sizeof(path), "%s?ticket=%s&ticket=%s", ws_paths[scope], token, token); CHECK(websocket(path, source) == 403);
                }
                snprintf(path, sizeof(path), "%s?ticket=%s", ws_paths[scope], token);
                CHECK(websocket(path, source) == (i >= 3 ? 101 : 403));
                CHECK(websocket(path, source) == 403);
            }
            printf("ticket request: stored%d scope%d fractional%d actual HTTP/WS seven offsets45s TTL,wrong scope/address/NUL/duplicate query,no burn/replay passed\n", stored, scope, fractional);
        }
    }
    st_websocket_ticket_reset_memory_scope(NULL);
}
static long long count(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL; CHECK(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW);
    long long result = sqlite3_column_int64(stmt, 0); sqlite3_finalize(stmt); return result;
}
static void transaction_revoke(void)
{
    CHECK(setenv("SPECUS_DATABASE_PATH", database, 1) == 0);
    st_storage_management_user user; CHECK(st_storage_create_management_user(database, "MiXeD", "default", "unused", "USER", 1, &user) == 0);
    sqlite3 *db = NULL; CHECK(sqlite3_open(database, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "DELETE FROM specus_websocket_ticket", NULL, NULL, NULL) == SQLITE_OK);
    const char *json = "{\"tenantId\":\"default\",\"wsUser\":\"MiXeD\"}";
    CHECK(st_storage_issue_websocket_ticket(database, "target", "connections", json, NULL, "2026-09-15T11:00:00Z", "2026-09-15T13:00:00Z") == 0);
    CHECK(st_storage_issue_websocket_ticket(database, "case", "connections", "{\"tenantId\":\"default\",\"wsUser\":\"mixed\"}", NULL, "2026-09-15T11:00:00Z", "2026-09-15T13:00:00Z") == 0);
    CHECK(st_storage_issue_websocket_ticket(database, "tenant", "connections", "{\"tenantId\":\"Default\",\"wsUser\":\"MiXeD\"}", NULL, "2026-09-15T11:00:00Z", "2026-09-15T13:00:00Z") == 0);
    CHECK(st_storage_issue_websocket_ticket(database, "public", "public-transfer", json, NULL, "2026-09-15T11:00:00Z", "2026-09-15T13:00:00Z") == 0);
    CHECK(sqlite3_exec(db, "CREATE TRIGGER abort_revoke BEFORE DELETE ON specus_websocket_ticket BEGIN SELECT RAISE(ABORT,'controlled revoke failure');END", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(st_storage_update_management_user(database, "default", "MIXED", NULL, "ADMIN", 1, NULL) == -1);
    CHECK(count(db, "SELECT count(*) FROM specus_management_user WHERE role='USER' AND login_name='MiXeD'") == 1 && count(db, "SELECT count(*) FROM specus_websocket_ticket") == 4);
    /* Existing C controller maps update storage failures to409. This tests rollback,
     * not Java/Spring exception classification, and preserves that public convention. */
    char response[8192]; CHECK(http("PUT", "/api/admin/users/MIXED", "127.13.0.1", "{\"role\":\"ADMIN\",\"enabled\":true}", response) == 409);
    CHECK(count(db, "SELECT count(*) FROM specus_management_user WHERE role='USER' AND login_name='MiXeD'") == 1 && count(db, "SELECT count(*) FROM specus_websocket_ticket") == 4);
    CHECK(sqlite3_exec(db, "DROP TRIGGER abort_revoke", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(st_storage_update_management_user(database, "default", "MIXED", NULL, "ADMIN", 1, NULL) == 0);
    CHECK(count(db, "SELECT count(*) FROM specus_websocket_ticket WHERE token_hash='target'") == 0 && count(db, "SELECT count(*) FROM specus_websocket_ticket") == 3);
    CHECK(st_storage_update_management_user(database, "default", "mixed", NULL, "USER", 1, NULL) == 0);
    char *payload = NULL; CHECK(st_storage_consume_websocket_ticket(database, "target", "connections", NULL, "2026-09-15T12:00:00Z", &payload) == 1 && payload == NULL);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    puts("ticket request: nonaudited+actual audited HTTP role-change delete-abort rolls back account/tickets; success revokes exact identity only; role restore does not revive old ticket passed");
    puts("ticket request: existing C update-failure409 preserved; cross-language HTTP storage-error classification NOT accepted by this probe");
}
int main(void)
{
    CHECK(atexit(cleanup) == 0);
    CHECK(setenv("SPECUS_AUTH_USERNAME", "admin", 1) == 0 && setenv("SPECUS_AUTH_TENANT_ID", "default", 1) == 0
        && setenv("SPECUS_AUTH_PASSWORD", "ticket-test-admin-pass", 1) == 0 && setenv("SPECUS_AUTH_JWT_SECRET", "ticket-test-jwt-key", 1) == 0
        && setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0 && setenv("SPECUS_PUBLIC_TRANSFER_CLUSTER_ENABLED", "0", 1) == 0
        && setenv("SPECUS_TRUSTED_PROXIES", "", 1) == 0);
    snprintf(database, sizeof(database), "/tmp/specus-ticket-request-XXXXXX"); int fd = mkstemp(database); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(database, 0) == 0 && setenv("SPECUS_DATABASE_PATH", database, 1) == 0);
    char token[2200]; CHECK(st_security_issue_local_token("admin", "default", "ADMIN", "ticket-test-jwt-key", 600, token, sizeof(token)) == 0);
    CHECK(snprintf(auth, sizeof(auth), "Bearer %s", token) > 0);
    restart_ticket(); expiry_routes(); transaction_revoke();
    puts("ticket request: API TCP expiry84 cases,process-restart persistence and account rollback passed; quota, account lifecycle and main restart have separate suites");
    return 0;
}
