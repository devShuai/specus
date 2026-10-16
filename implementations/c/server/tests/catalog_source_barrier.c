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
#include <sys/socket.h>

static int (*real_step)(sqlite3_stmt *);
static int (*real_close)(sqlite3 *);
static int (*real_exec)(sqlite3 *, const char *, int (*)(void *, int, char **, char **), void *, char **);
static ssize_t (*real_send)(int,const void *,size_t,int);
static pthread_once_t once = PTHREAD_ONCE_INIT;
static atomic_int fired;
static atomic_int sends;
static _Thread_local sqlite3 *selected;
static void symbols(void)
{
    void *step = dlsym(RTLD_NEXT, "sqlite3_step"), *close = dlsym(RTLD_NEXT, "sqlite3_close"), *exec = dlsym(RTLD_NEXT, "sqlite3_exec");
    _Static_assert(sizeof(step) == sizeof(real_step), "POSIX pointers");
    _Static_assert(sizeof(close) == sizeof(real_close), "POSIX pointers");
    _Static_assert(sizeof(exec) == sizeof(real_exec), "POSIX pointers");
    memcpy(&real_step, &step, sizeof(step)); memcpy(&real_close, &close, sizeof(close)); memcpy(&real_exec, &exec, sizeof(exec));
    void *send_symbol=dlsym(RTLD_NEXT,"send"); _Static_assert(sizeof(send_symbol)==sizeof(real_send),"POSIX send pointer");
    memcpy(&real_send,&send_symbol,sizeof(real_send));
    if (!real_step || !real_close || !real_exec || !real_send) _exit(91);
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
    if (!strcmp(mode, "read") && rc == SQLITE_ROW && strstr(sql, "SELECT c.enabled,k.enabled FROM specus_client_session s")
        && !sqlite3_get_autocommit(db) && sqlite3_txn_state(db, "main") == SQLITE_TXN_READ) pause_once();
    if (!strcmp(mode, "publication") && rc == SQLITE_ROW
        && strstr(sql,"WHERE s.tenant_id COLLATE BINARY=? AND s.client_id=? AND s.service_id COLLATE BINARY=?")
        && !sqlite3_get_autocommit(db) && sqlite3_txn_state(db,"main")==SQLITE_TXN_WRITE) pause_once();
    if (!strcmp(mode, "delivery") && rc == SQLITE_ROW && strstr(sql, "SELECT c.enabled,k.enabled FROM specus_client_session s")
        && !sqlite3_get_autocommit(db)) selected = db;
    if (!strcmp(mode,"accept-commit-fail") && rc==SQLITE_ROW
        && strstr(sql,"WHERE s.tenant_id COLLATE BINARY=? AND s.client_id=? AND s.service_id COLLATE BINARY=?")
        && !sqlite3_get_autocommit(db) && sqlite3_txn_state(db,"main")==SQLITE_TXN_WRITE) selected=db;
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
    if (mode && !strcmp(mode,"accept-commit-fail") && db==selected && armed() && sql && !strcmp(sql,"COMMIT")) {
        int expected=0;
        if (atomic_compare_exchange_strong(&fired,&expected,1)) { selected=NULL;mark("ready");return SQLITE_IOERR; }
    }
    if (mode && !strcmp(mode, "observer") && armed() && sql && strstr(sql, "CREATE TABLE IF NOT EXISTS"))
        mark("native-write-attempt");
    return real_exec(db, sql, callback, context, error);
}

static void mark_send(const char *name,int value)
{
    const char *dir=getenv("SPECUS_TEST_CONTROL_BARRIER_DIR");char path[512];
    snprintf(path,sizeof(path),"%s/%s",dir,name);FILE *file=fopen(path,"w");if(!file) _exit(94);
    fprintf(file,"%d\n",value);fclose(file);
}
ssize_t send(int fd,const void *data,size_t length,int flags)
{
    pthread_once(&once,symbols);
    const char *mode=getenv("SPECUS_TEST_CATALOG_SOURCE_MODE");
    int observe=mode && !strcmp(mode,"slow-output") && length>=65536U && armed();
    int number=observe?atomic_fetch_add(&sends,1)+1:0;
    if(observe) mark_send("slow-entered",number);
    /* Observation ONLY: no injected delay or shortened timeout. The actual socket blocks. */
    ssize_t rc=real_send(fd,data,length,flags);
    if(observe) mark_send("slow-returned",number);
    return rc;
}
