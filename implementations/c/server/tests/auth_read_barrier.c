#define _GNU_SOURCE
/* Test-only LD_PRELOAD probe. Pauses AFTER the real API-key/by-id credential connection closes,
 * hence holds no SQLite read lock. The native HTTP thread really retains its old struct.
 * No production callback, fake SQLite result, timer race or application bypass is installed. */
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
static _Thread_local sqlite3 *selected_db;

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
    return rc;
}
int sqlite3_close(sqlite3 *db)
{
    pthread_once(&symbols_once, symbols);
    int selected = db != NULL && db == selected_db;
    if (selected) selected_db = NULL;
    int rc = real_close(db);
    int expected = 0;
    if (selected && rc == SQLITE_OK && atomic_compare_exchange_strong(&fired, &expected, 1)) {
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
    return rc;
}
