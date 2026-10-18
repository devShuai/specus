#define _GNU_SOURCE
/* Real egress-activity lookup, paused AFTER sqlite3_close: no retained database lock or fake row. */
#include <dlfcn.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
static int (*real_step)(sqlite3_stmt *);
static int (*real_close)(sqlite3 *);
static int (*real_exec)(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *, char **);
static int (*real_random)(unsigned char *, int);
static int (*real_cond_timedwait)(pthread_cond_t *, pthread_mutex_t *, const struct timespec *);
static pthread_once_t once = PTHREAD_ONCE_INIT;
static atomic_int fired;
static _Thread_local sqlite3 *selected;
static _Thread_local int activity_read_closed;
static void symbols(void)
{
    void *step = dlsym(RTLD_NEXT, "sqlite3_step"), *close = dlsym(RTLD_NEXT, "sqlite3_close");
    _Static_assert(sizeof(step) == sizeof(real_step), "POSIX pointers");
    _Static_assert(sizeof(close) == sizeof(real_close), "POSIX pointers");
    memcpy(&real_step, &step, sizeof(step)); memcpy(&real_close, &close, sizeof(close));
    void *exec = dlsym(RTLD_NEXT, "sqlite3_exec");
    _Static_assert(sizeof(exec) == sizeof(real_exec), "POSIX pointers");
    memcpy(&real_exec, &exec, sizeof(exec));
    void *random = dlsym(RTLD_NEXT, "RAND_bytes"), *wait = dlsym(RTLD_NEXT, "pthread_cond_timedwait");
    _Static_assert(sizeof(random) == sizeof(real_random), "POSIX pointers");
    _Static_assert(sizeof(wait) == sizeof(real_cond_timedwait), "POSIX pointers");
    memcpy(&real_random, &random, sizeof(random)); memcpy(&real_cond_timedwait, &wait, sizeof(wait));
    if (!real_step || !real_close || !real_exec || !real_random || !real_cond_timedwait) _exit(91);
}
static void barrier_pause(void)
{
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    char path[512]; snprintf(path, sizeof(path), "%s/ready", dir);
    FILE *file = fopen(path, "w"); if (!file) _exit(92); fputs("real operation paused", file); fclose(file);
    snprintf(path, sizeof(path), "%s/resume", dir);
    struct timespec start, now; clock_gettime(CLOCK_MONOTONIC, &start);
    while (access(path, F_OK)) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec > 30) _exit(93);
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
}
int RAND_bytes(unsigned char *bytes, int count)
{
    pthread_once(&once, symbols);
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    if (count == 16 && dir && getenv("SPECUS_TEST_CONTROL_STARTUP")) {
        char path[512]; snprintf(path, sizeof(path), "%s/arm", dir);
        int expected = 0;
        if (access(path, F_OK) == 0 && atomic_compare_exchange_strong(&fired, &expected, 1)) barrier_pause();
    }
    return real_random(bytes, count);
}
int pthread_cond_timedwait(pthread_cond_t *condition, pthread_mutex_t *mutex, const struct timespec *deadline)
{
    pthread_once(&once, symbols);
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    if (dir && getenv("SPECUS_TEST_CONTROL_STARTUP") && atomic_load(&fired) && syscall(SYS_gettid) == getpid()) {
        char path[512]; snprintf(path, sizeof(path), "%s/drain-wait", dir);
        FILE *file = fopen(path, "w"); if (!file) _exit(94); fputs("main awaits registered reader", file); fclose(file);
    }
    return real_cond_timedwait(condition, mutex, deadline);
}
int sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *, int, char **, char **), void *context, char **error)
{
    pthread_once(&once, symbols);
    const char *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR"), *mode = getenv("SPECUS_TEST_CONTROL_SOURCE_MODE");
    /* Login's actual configuration reload reaches schema writes before native ONLINE. Do not
     * wait for a later ONLINE step while the earlier writer is correctly blocked. */
    if (dir && mode && !strcmp(mode, "observer") && sql && strstr(sql, "CREATE TABLE IF NOT EXISTS")) {
        char path[512]; snprintf(path, sizeof(path), "%s/arm", dir);
        if (access(path, F_OK) == 0) {
            snprintf(path, sizeof(path), "%s/native-write-attempt", dir);
            FILE *file = fopen(path, "w"); if (!file) _exit(95); fputs("actual configuration native writer entered", file); fclose(file);
        }
    }
    return real_exec(db, sql, callback, context, error);
}
int sqlite3_step(sqlite3_stmt *stmt)
{
    pthread_once(&once, symbols);
    const char *sql = sqlite3_sql(stmt), *dir = getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");
    const char *mode = getenv("SPECUS_TEST_CONTROL_SOURCE_MODE");
    int rc = real_step(stmt);
    if (rc == SQLITE_ROW && dir && mode && !strcmp(mode, "writer") && activity_read_closed && sql
        && strstr(sql, "FROM specus_client_session s JOIN client_account c")
        && !sqlite3_get_autocommit(sqlite3_db_handle(stmt))
        && sqlite3_txn_state(sqlite3_db_handle(stmt), "main") == SQLITE_TXN_WRITE) {
        int expected = 0;
        if (atomic_compare_exchange_strong(&fired, &expected, 1)) barrier_pause();
    }
    if ((rc == SQLITE_ROW || rc == SQLITE_DONE) && dir && (!mode || strcmp(mode, "observer")) && sql
        && strstr(sql, "FROM peer_mesh_egress_activity WHERE tenant_id=? AND egress_client_id=?")) {
        char path[512]; snprintf(path, sizeof(path), "%s/arm", dir);
        if (access(path, F_OK) == 0) selected = sqlite3_db_handle(stmt);
    }
    return rc;
}
int sqlite3_close(sqlite3 *db)
{
    pthread_once(&once, symbols);
    int chosen = db && db == selected;
    if (chosen) selected = NULL;
    int rc = real_close(db), expected = 0;
    if (chosen && rc == SQLITE_OK && atomic_compare_exchange_strong(&fired, &expected, 1)) {
        const char *mode = getenv("SPECUS_TEST_CONTROL_SOURCE_MODE");
        if (mode && !strcmp(mode, "writer")) { activity_read_closed = 1; atomic_store(&fired, 0); }
        else barrier_pause();
    }
    return rc;
}
