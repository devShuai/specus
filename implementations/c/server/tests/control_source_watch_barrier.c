#define _GNU_SOURCE
/* Observe actual background read transactions. No fake rows or production test hooks. */
#include <dlfcn.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int (*real_step)(sqlite3_stmt *);
static int (*real_prepare)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
static pthread_once_t once = PTHREAD_ONCE_INIT;
static void symbols(void)
{
    void *step = dlsym(RTLD_NEXT, "sqlite3_step"), *prepare = dlsym(RTLD_NEXT, "sqlite3_prepare_v2");
    _Static_assert(sizeof(step) == sizeof(real_step), "POSIX pointers");
    _Static_assert(sizeof(prepare) == sizeof(real_prepare), "POSIX pointers");
    memcpy(&real_step, &step, sizeof(step)); memcpy(&real_prepare, &prepare, sizeof(prepare));
    if (!real_step || !real_prepare) _exit(91);
}
static void marker(const char *name)
{
    const char *dir = getenv("SPECUS_TEST_SOURCE_WATCH_DIR"); if (!dir) return;
    char arm[512], path[512]; snprintf(arm, sizeof(arm), "%s/arm", dir);
    if (access(arm, F_OK)) return;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *file = fopen(path, "w"); if (!file) _exit(92); fputs("actual native background transaction", file); fclose(file);
}
static int source_read(sqlite3 *db, const char *sql)
{ return db && !sqlite3_get_autocommit(db) && sql && strstr(sql, "FROM specus_client_session s JOIN client_account c"); }
int sqlite3_prepare_v2(sqlite3 *db, const char *sql, int bytes, sqlite3_stmt **stmt, const char **tail)
{
    pthread_once(&once, symbols); int rc = real_prepare(db, sql, bytes, stmt, tail);
    if (source_read(db, sql) && (rc == SQLITE_BUSY || rc == SQLITE_LOCKED)) marker("watch-busy");
    return rc;
}
int sqlite3_step(sqlite3_stmt *stmt)
{
    pthread_once(&once, symbols); int rc = real_step(stmt);
    sqlite3 *db = sqlite3_db_handle(stmt);
    if (source_read(db, sqlite3_sql(stmt))) {
        if (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) marker("watch-busy");
        else if (rc == SQLITE_ROW && sqlite3_txn_state(db, "main") == SQLITE_TXN_READ) {
            if (sqlite3_column_int(stmt, 0) == 0) marker("watch-account-disabled");
            if (sqlite3_column_int(stmt, 1) == 0) marker("watch-credential-disabled");
        }
    }
    return rc;
}
