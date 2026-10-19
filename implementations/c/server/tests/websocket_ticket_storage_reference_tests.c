#define _POSIX_C_SOURCE 200809L
#include "storage.h"
#include "instant_reference_cases.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr, "persistent ticket failed line%d\n", __LINE__); exit(1); } } while (0)
static const char *scopes[] = {"connections", "client-messages", "public-transfer"};
static const char *created = "2026-09-15T11:00:00Z";
static const char *payload = "{\"tenantId\":\"tenant\",\"value\":\"完整内容😀\"}";
static long long scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL;
    CHECK(sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW);
    long long value = sqlite3_column_int64(stmt, 0);
    CHECK(sqlite3_step(stmt) == SQLITE_DONE); sqlite3_finalize(stmt); return value;
}
static void run(int family, int fractional, int legacy)
{
    char path[] = "/tmp/specus-ws-ticket-reference-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(path, 0) == 0);
    sqlite3 *db = NULL; CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    for (int i = 0; i < 7; ++i) for (int use = 0; use < 2; ++use) {
        char id[32]; snprintf(id, sizeof(id), "%c%d", use ? 'p' : 'c', i + 1);
        CHECK(st_storage_issue_websocket_ticket(path, id, scopes[family], payload, "remote", created, values[fractional][i]) == 0);
        CHECK(st_storage_issue_websocket_ticket(path, id, scopes[family], payload, "remote", created, values[fractional][i]) == -1);
        if (legacy) {
            sqlite3_stmt *stmt = NULL;
            CHECK(sqlite3_prepare_v2(db, "UPDATE specus_websocket_ticket SET expires_at=?1 WHERE token_hash=?2", -1, &stmt, NULL) == SQLITE_OK
                && sqlite3_bind_text(stmt, 1, values[fractional][i], -1, SQLITE_STATIC) == SQLITE_OK
                && sqlite3_bind_text(stmt, 2, id, -1, SQLITE_TRANSIENT) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE);
            sqlite3_finalize(stmt);
        }
    }
    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(st_storage_init(path, 0) == 0 && st_storage_init(path, 0) == 0);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK
        && scalar(db, "SELECT count(*) FROM specus_websocket_ticket WHERE length(expires_at)=28") == 14
        && scalar(db, "SELECT count(*) FROM specus_websocket_ticket WHERE created_at='2026-09-15T11:00:00Z'") == 14);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    for (int i = 1; i <= 7; ++i) {
        char id[32]; snprintf(id, sizeof(id), "c%d", i);
        char *json = (char *)1;
        CHECK(st_storage_consume_websocket_ticket(path, id, scopes[(family + 1) % 3], "remote", cutoffs[fractional], &json) == 1 && json == NULL);
        CHECK(st_storage_consume_websocket_ticket(path, id, scopes[family], "other-remote", cutoffs[fractional], &json) == 1 && json == NULL);
        int expected = i < 4 ? 1 : 0;
        CHECK(st_storage_consume_websocket_ticket(path, id, scopes[family], "remote", cutoffs[fractional], &json) == expected);
        if (expected == 0) { CHECK(json != NULL && strcmp(json, payload) == 0); free(json); }
        else CHECK(json == NULL);
        CHECK(st_storage_consume_websocket_ticket(path, id, scopes[family], "remote", cutoffs[fractional], &json) == 1 && json == NULL);
    }
    int deleted = -1;
    CHECK(st_storage_delete_expired_websocket_tickets(path, cutoffs[fractional], &deleted) == 0 && deleted == 6);
    CHECK(sqlite3_open(path, &db) == SQLITE_OK && scalar(db, "SELECT count(*) FROM specus_websocket_ticket") == 4
        && scalar(db, "SELECT count(*) FROM specus_websocket_ticket WHERE token_hash IN('p4','p5','p6','p7')") == 4);
    CHECK(sqlite3_close(db) == SQLITE_OK && unlink(path) == 0);
    printf("persistent ticket: scope=%s fractional%d legacy%d seven offsets inclusive consume/strict purge/restart/scope/address/replay passed\n", scopes[family], fractional, legacy);
}
static void process_race(void)
{
    char path[] = "/tmp/specus-ws-ticket-process-XXXXXX";
    int fd = mkstemp(path); CHECK(fd >= 0); close(fd);
    CHECK(st_storage_init(path, 0) == 0);
    pid_t issuer = fork(); CHECK(issuer >= 0);
    if (issuer == 0) _exit(st_storage_issue_websocket_ticket(path, "from-child", "connections", payload, NULL, created, "2026-09-15T12:00:01Z") == 0 ? 0 : 2);
    int status; CHECK(waitpid(issuer, &status, 0) == issuer && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    char *json = NULL;
    CHECK(st_storage_consume_websocket_ticket(path, "from-child", "connections", "anywhere", "2026-09-15T12:00:01Z", &json) == 0 && strcmp(json, payload) == 0);
    free(json);
    CHECK(st_storage_issue_websocket_ticket(path, "race", "connections", payload, "remote", created, "2026-09-15T12:00:01Z") == 0);
    int gate[2]; CHECK(pipe(gate) == 0);
    pid_t children[4];
    for (int i = 0; i < 4; ++i) {
        children[i] = fork(); CHECK(children[i] >= 0);
        if (children[i] == 0) {
            close(gate[1]); char signal;
            if (read(gate[0], &signal, 1) != 1) _exit(3);
            close(gate[0]); char *data = NULL;
            int rc = st_storage_consume_websocket_ticket(path, "race", "connections", "remote", "2026-09-15T12:00:01Z", &data);
            int ok = rc != 0 || (data != NULL && strcmp(data, payload) == 0);
            free(data); _exit(ok && (rc == 0 || rc == 1) ? rc : 2);
        }
    }
    close(gate[0]); CHECK(write(gate[1], "xxxx", 4) == 4); close(gate[1]);
    int wins = 0, misses = 0;
    for (int i = 0; i < 4; ++i) {
        CHECK(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status));
        int rc = WEXITSTATUS(status); CHECK(rc == 0 || rc == 1);
        wins += rc == 0; misses += rc == 1;
    }
    CHECK(wins == 1 && misses == 3);
    CHECK(st_storage_consume_websocket_ticket(path, "race", "connections", "remote", "2026-09-15T12:00:01Z", &json) == 1 && json == NULL);
    CHECK(st_storage_issue_websocket_ticket(path, "invalid", "connections", "{bad}", NULL, created, "2026-09-15T12:00:01Z") == -1);
    CHECK(st_storage_issue_websocket_ticket(path, "invalid", "connections", "{\"x\":1,\"x\":2}", NULL, created, "2026-09-15T12:00:01Z") == -1);
    CHECK(st_storage_issue_websocket_ticket(path, "invalid", "connections", payload, NULL, "invalid", "2026-09-15T12:00:01Z") == -1);
    CHECK(st_storage_issue_websocket_ticket(path, "rollback", "connections", payload, "remote", created, "2026-09-15T12:00:01Z") == 0);
    CHECK(st_storage_consume_websocket_ticket(path, "rollback", "connections", "remote", "2026-09-15T12:00:01Z", NULL) == -1);
    sqlite3 *db = NULL; CHECK(sqlite3_open(path, &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "CREATE TRIGGER fail_consume BEFORE DELETE ON specus_websocket_ticket BEGIN SELECT RAISE(ABORT,'controlled consume failure');END", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(st_storage_consume_websocket_ticket(path, "rollback", "connections", "remote", "2026-09-15T12:00:01Z", &json) == -1 && json == NULL);
    CHECK(scalar(db, "SELECT count(*) FROM specus_websocket_ticket WHERE token_hash='rollback'") == 1);
    CHECK(sqlite3_exec(db, "DROP TRIGGER fail_consume;UPDATE specus_websocket_ticket SET attributes_json='{bad}' WHERE token_hash='rollback'", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(st_storage_consume_websocket_ticket(path, "rollback", "connections", "remote", "2026-09-15T12:00:01Z", &json) == -1 && json == NULL);
    CHECK(scalar(db, "SELECT count(*) FROM specus_websocket_ticket WHERE token_hash='rollback'") == 1);
    CHECK(sqlite3_exec(db, "UPDATE specus_websocket_ticket SET attributes_json='{}' WHERE token_hash='rollback'", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(sqlite3_close(db) == SQLITE_OK);
    CHECK(st_storage_consume_websocket_ticket(path, "rollback", "connections", NULL, "2026-09-15T12:00:01Z", &json) == 1 && json == NULL);
    CHECK(st_storage_consume_websocket_ticket(path, "rollback", "connections", "remote", "2026-09-15T12:00:01Z", &json) == 0 && strcmp(json, "{}") == 0);
    free(json);
    CHECK(unlink(path) == 0);
    puts("persistent ticket: issued in separate process, unbound address, four real concurrent consumers exactly1 success/3 misses, replay refused passed");
    puts("persistent ticket: invalid attributes/time rejected; NULL output, delete-abort and corrupt-payload controls preserve ticket; repaired ticket consumed once passed");
}
int main(void)
{
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT", "0", 1) == 0);
    for (int family = 0; family < 3; ++family) for (int fractional = 0; fractional < 2; ++fractional)
        for (int legacy = 0; legacy < 2; ++legacy) run(family, fractional, legacy);
    process_race();
    puts("persistent ticket repository:12 actual SQLite expiry scenarios and cross-process atomicity passed; HTTP/WebSocket acceptance has separate request/quota/account/restart suites");
    return 0;
}
