#define _GNU_SOURCE
/* Test-only LD_PRELOAD probe. Normal interleavings pause AFTER the real lookup closes,
 * holding no read lock. The separate config-fence mode pauses IN a real sharing-row read
 * to verify an independent writer is refused. No fake result or production hook. */
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int (*real_step)(sqlite3_stmt *);
static int (*real_close)(sqlite3 *);
static pthread_once_t symbols_once = PTHREAD_ONCE_INIT;
static _Atomic int fired;
static _Atomic int ws_account_reads;
static _Thread_local sqlite3 *selected_db;

static void pause_once(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&fired, &expected, 1)) return;
    const char *ready = getenv("SPECUS_TEST_AUTH_BARRIER_READY"), *resume = getenv("SPECUS_TEST_AUTH_BARRIER_RESUME");
    if (ready == NULL || resume == NULL) _exit(92);
    int output = open(ready, O_WRONLY | O_CLOEXEC);
    if (output < 0 || write(output, "R", 1) != 1) _exit(93);
    close(output);
    int input = open(resume, O_RDONLY | O_CLOEXEC);
    char signal = 0;
    if (input < 0 || read(input, &signal, 1) != 1 || signal != 'C') _exit(94);
    close(input);
}

static void symbols(void)
{
    void *step = dlsym(RTLD_NEXT, "sqlite3_step"), *close = dlsym(RTLD_NEXT, "sqlite3_close");
    _Static_assert(sizeof(step) == sizeof(real_step), "POSIX function pointer size");
    _Static_assert(sizeof(close) == sizeof(real_close), "POSIX function pointer size");
    memcpy(&real_step, &step, sizeof(step)); memcpy(&real_close, &close, sizeof(close));
    if (real_step == NULL || real_close == NULL) { fputs("auth probe missing real SQLite symbol\n", stderr); _exit(91); }
}
int sqlite3_step(sqlite3_stmt *stmt)
{
    pthread_once(&symbols_once, symbols);
    int rc = real_step(stmt);
    const char *sql = sqlite3_sql(stmt), *key = getenv("SPECUS_TEST_AUTH_BARRIER_KEY");
    if (rc == SQLITE_ROW && key != NULL && sql != NULL
        && (strstr(sql, "FROM specus_client_credential WHERE api_key = ?") != NULL
            || strstr(sql, "FROM specus_client_credential WHERE id = ?") != NULL)) {
        const char *actual = (const char *)sqlite3_column_text(stmt, 3);
        if (actual != NULL && strcmp(actual, key) == 0) selected_db = sqlite3_db_handle(stmt);
    }
    const char *account = getenv("SPECUS_TEST_AUTH_BARRIER_ACCOUNT");
    const char *ws_account = getenv("SPECUS_TEST_AUTH_BARRIER_WS_ACCOUNT");
    if (rc == SQLITE_ROW && (account != NULL || ws_account != NULL) && sql != NULL
        && strstr(sql, "FROM specus_management_user ") != NULL && sqlite3_column_count(stmt) == 8) {
        const char *actual = (const char *)sqlite3_column_text(stmt, 7);
        if (actual != NULL && account != NULL && strcmp(actual, account) == 0) selected_db = sqlite3_db_handle(stmt);
        /* Ticket issuance resolves once; pause only the next, pre-upgrade identity read. */
        if (actual != NULL && ws_account != NULL && strcmp(actual, ws_account) == 0
            && atomic_fetch_add(&ws_account_reads, 1) == 1) selected_db = sqlite3_db_handle(stmt);
    }
    const char *client = getenv("SPECUS_TEST_AUTH_BARRIER_CLIENT_ID");
    if (rc == SQLITE_ROW && client != NULL && sql != NULL
        && (strstr(sql, "FROM client_account WHERE rowid = ?") != NULL
            || strstr(sql, "FROM client_account WHERE client_name = ?") != NULL)
        && sqlite3_column_int64(stmt, 0) == strtoll(client, NULL, 10)) selected_db = sqlite3_db_handle(stmt);
    /* Snapshot-fence test: pause in the real read while its transaction is held. */
    if (rc == SQLITE_ROW && getenv("SPECUS_TEST_AUTH_BARRIER_PEER_SESSION") != NULL && sql != NULL
        && strstr(sql, "SELECT COUNT(*) FROM peer_mesh_device ") != NULL) selected_db = sqlite3_db_handle(stmt);
    if (rc == SQLITE_ROW && getenv("SPECUS_TEST_AUTH_BARRIER_CONFIG_SNAPSHOT") != NULL && sql != NULL
        && strstr(sql, "SELECT enabled,mdns_import_enabled,updated_by,updated_at FROM peer_mesh_service_sharing") != NULL) pause_once();
    return rc;
}
int sqlite3_close(sqlite3 *db)
{
    pthread_once(&symbols_once, symbols);
    int selected = db != NULL && db == selected_db;
    if (selected) selected_db = NULL;
    int rc = real_close(db);
    if (selected && rc == SQLITE_OK) pause_once();
    return rc;
}
