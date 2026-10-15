#define _GNU_SOURCE
/* Pause actual SQLite boundaries, with no fake rows or production hooks. */
#include <dlfcn.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int (*real_step)(sqlite3_stmt *);
static int (*real_close)(sqlite3 *);
static int (*real_exec)(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *, char **);
static pthread_once_t once = PTHREAD_ONCE_INIT;
static atomic_int fired;
static _Thread_local sqlite3 *selected;
static void symbols(void)
{
    void *step = dlsym(RTLD_NEXT, "sqlite3_step"), *close = dlsym(RTLD_NEXT, "sqlite3_close"), *exec = dlsym(RTLD_NEXT, "sqlite3_exec");
    _Static_assert(sizeof(step) == sizeof(real_step), "POSIX pointers");
    _Static_assert(sizeof(close) == sizeof(real_close), "POSIX pointers");
    _Static_assert(sizeof(exec) == sizeof(real_exec), "POSIX pointers");
    memcpy(&real_step, &step, sizeof(step)); memcpy(&real_close, &close, sizeof(close)); memcpy(&real_exec, &exec, sizeof(exec));
    if (!real_step || !real_close || !real_exec) _exit(91);
}
static int armed(void)
{
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    if (!dir) return 0;
    char path[512]; snprintf(path, sizeof(path), "%s/arm", dir); return access(path, F_OK) == 0;
}
static void mark(const char *name)
{
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    char path[512]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *file = fopen(path, "w"); if (!file) _exit(92); fputs("actual native boundary", file); fclose(file);
}
static void pause_once(void)
{
    int expected = 0;
    if (!atomic_compare_exchange_strong(&fired, &expected, 1)) return;
    mark("ready");
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    char path[512]; snprintf(path, sizeof(path), "%s/resume", dir);
    struct timespec start, now; clock_gettime(CLOCK_MONOTONIC, &start);
    while (access(path, F_OK)) {
        clock_gettime(CLOCK_MONOTONIC, &now); if (now.tv_sec - start.tv_sec > 30) _exit(93);
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
}
int sqlite3_step(sqlite3_stmt *stmt)
{
    pthread_once(&once, symbols);
    int rc = real_step(stmt);
    const char *mode = getenv("SPECUS_TEST_CATALOG_SOURCE_MODE"), *sql = sqlite3_sql(stmt);
    if (!mode || !sql || !armed()) return rc;
    sqlite3 *db = sqlite3_db_handle(stmt);
    if (!strcmp(mode, "pre") && (rc == SQLITE_ROW || rc == SQLITE_DONE)
        && strstr(sql, "FROM client_account ORDER BY client_name") && sqlite3_get_autocommit(db)) selected = db;
    if (!strcmp(mode, "writer") && rc == SQLITE_DONE && strstr(sql, "INSERT INTO peer_mesh_service_audit")
        && !sqlite3_get_autocommit(db) && sqlite3_txn_state(db, "main") == SQLITE_TXN_WRITE) pause_once();
    return rc;
}
int sqlite3_close(sqlite3 *db)
{
    pthread_once(&once, symbols); int chosen = db && db == selected;
    if (chosen) selected = NULL;
    int rc = real_close(db);
    if (chosen && rc == SQLITE_OK) pause_once(); /* No retained SQL handle/transaction. */
    return rc;
}
int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *context, char **error)
{
    pthread_once(&once, symbols);
    const char *mode = getenv("SPECUS_TEST_CATALOG_SOURCE_MODE");
    if (mode && !strcmp(mode, "observer") && armed() && sql && strstr(sql, "CREATE TABLE IF NOT EXISTS"))
        mark("native-write-attempt");
    return real_exec(db, sql, callback, context, error);
}
