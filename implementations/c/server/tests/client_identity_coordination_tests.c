#define _GNU_SOURCE
#include "storage.h"
#include "crypto.h"
#include "json.h"
#include "server_harness.h"
#include <errno.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_KEY "coordination-client-key"
#define TEST_SECRET "coordination-client-secret"
static const char *barrier_library;
typedef struct { char dir[128], path[180]; sqlite3 *db; st_storage_client_credential credential; } fixture;

static int execute(sqlite3 *db, const char *sql)
{
    char *error = NULL; int rc = sqlite3_exec(db, sql, NULL, NULL, &error);
    if (rc != SQLITE_OK) fprintf(stderr, "fixture SQL: %s\n", error == NULL ? sqlite3_errmsg(db) : error);
    sqlite3_free(error); return rc == SQLITE_OK ? 0 : -1;
}
static long long scalar(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL; long long value = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) value = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt); return value;
}
static int insert_credential(const char *path, st_storage_client_credential *credential)
{
    uint8_t digest[ST_SHA256_LEN]; char hex[65];
    st_sha256((const uint8_t *)TEST_SECRET, strlen(TEST_SECRET), digest); st_hex_encode(digest, sizeof(digest), hex);
    return st_storage_upsert_client_credential(path, 0, "default", "alice", TEST_KEY, hex, 1, 8, credential);
}
static int fresh(fixture *f)
{
    memset(f, 0, sizeof(*f)); snprintf(f->dir, sizeof(f->dir), "/tmp/specus-identity-coordination-XXXXXX");
    CHECK(mkdtemp(f->dir) != NULL, "owned fixture directory"); snprintf(f->path, sizeof(f->path), "%s/test.db", f->dir);
    CHECK(st_storage_init(f->path, 0) == 0 && sqlite3_open(f->path, &f->db) == SQLITE_OK && insert_credential(f->path, &f->credential) == 0, "fresh database");
    sqlite3_busy_timeout(f->db, 5000); return 0;
}
static void finish(fixture *f)
{
    sqlite3_close(f->db); unlink(f->path); rmdir(f->dir);
}
static int stale_owner(fixture *f)
{
    CHECK(execute(f->db, "UPDATE specus_client_credential SET owner_username='bob'") == 0, "ownership fixture");
    st_storage_client_identity identity; st_storage_client client;
    CHECK(st_storage_find_or_create_client_identity(f->path, &f->credential, "new-device", "user", "host", &identity) == 0, "provision with same valid secret");
    CHECK(st_storage_get_client(f->path, identity.client_id, &client) == 0 && strcmp(client.owner_username, "bob") == 0, "stale credential resurrected old client owner");
    CHECK(strcmp(f->credential.owner_username, "alice") == 0, "caller snapshot mutated"); return 0;
}
static int rollback_new(fixture *f)
{
    CHECK(execute(f->db, "CREATE TRIGGER fail_identity BEFORE INSERT ON specus_client_identity BEGIN SELECT RAISE(ABORT,'injected identity failure'); END") == 0, "trigger");
    st_storage_client_identity identity = {0};
    CHECK(st_storage_find_or_create_client_identity(f->path, &f->credential, "rollback-device", "user", "host", &identity) < 0, "last insert must fail");
    CHECK(scalar(f->db, "SELECT COUNT(*) FROM client_account") == 0 && scalar(f->db, "SELECT COUNT(*) FROM specus_client_identity") == 0, "failed identity left orphan client");
    CHECK(identity.id == 0 && identity.client_id == 0, "failed identity output leaked"); return 0;
}
static int rejected_snapshot(fixture *f, const char *change, int expected)
{
    CHECK(execute(f->db, change) == 0, "credential change"); st_storage_client_identity identity = {0};
    int rc = st_storage_find_or_create_client_identity(f->path, &f->credential, "rejected-device", "user", "host", &identity);
    CHECK(rc == expected, "changed credential accepted: rc%d expected%d", rc, expected);
    CHECK(scalar(f->db, "SELECT COUNT(*) FROM client_account") == 0 && scalar(f->db, "SELECT COUNT(*) FROM specus_client_identity") == 0, "rejected credential wrote rows"); return 0;
}
static int disabled(fixture *f) { return rejected_snapshot(f,"UPDATE specus_client_credential SET enabled=0",ST_STORAGE_IDENTITY_AUTH_DISABLED); }
static int changed_key(fixture *f) { return rejected_snapshot(f,"UPDATE specus_client_credential SET api_key='rotated-key'",ST_STORAGE_IDENTITY_AUTH_CHANGED); }
static int changed_secret(fixture *f) { return rejected_snapshot(f,"UPDATE specus_client_credential SET secret_hash=printf('%064d',0)",ST_STORAGE_IDENTITY_AUTH_CHANGED); }
static int changed_tenant(fixture *f) { return rejected_snapshot(f,"UPDATE specus_client_credential SET tenant_id='foreign'",ST_STORAGE_IDENTITY_AUTH_CHANGED); }
static int deleted(fixture *f) { return rejected_snapshot(f,"DELETE FROM specus_client_credential",ST_STORAGE_IDENTITY_AUTH_CHANGED); }
static int corrupt_existing(fixture *f)
{
    st_storage_client_identity before, after;
    CHECK(st_storage_find_or_create_client_identity(f->path, &f->credential, "existing-device", "user", "original", &before) == 0, "existing identity");
    CHECK(execute(f->db,"UPDATE specus_client_identity SET tenant_id='foreign',last_seen_at='2026-01-01' ") == 0, "corrupt fixture");
    CHECK(st_storage_find_or_create_client_identity(f->path, &f->credential, "existing-device", "user", "changed", &after) < 0, "foreign identity accepted");
    CHECK(scalar(f->db,"SELECT COUNT(*) FROM specus_client_identity WHERE hostname='original' AND last_seen_at='2026-01-01'") == 1, "corrupt identity mutated before refusal"); return 0;
}
static int existing_owner_is_not_implicitly_transferred(fixture *f)
{
    st_storage_client_identity before,after;st_storage_client client;
    CHECK(st_storage_find_or_create_client_identity(f->path,&f->credential,"existing-device","user","original",&before)==0,"existing identity");
    CHECK(execute(f->db,"UPDATE specus_client_credential SET owner_username='bob'")==0,"credential-only legacy fixture");
    CHECK(st_storage_find_or_create_client_identity(f->path,&f->credential,"existing-device","user","updated",&after)==0&&before.id==after.id&&before.client_id==after.client_id,"existing identity changed");
    CHECK(st_storage_get_client(f->path,after.client_id,&client)==0&&strcmp(client.owner_username,"alice")==0,"login silently transferred existing client");
    return 0;
}
static int rollback_existing(fixture *f)
{
    st_storage_client_identity before,after;
    CHECK(st_storage_find_or_create_client_identity(f->path,&f->credential,"existing-device","user","original",&before)==0,"existing identity");
    CHECK(execute(f->db,"UPDATE specus_client_identity SET last_seen_at='2026-01-01'; CREATE TRIGGER fail_touch BEFORE UPDATE ON specus_client_identity BEGIN SELECT RAISE(ABORT,'injected identity update failure'); END")==0,"late update failure");
    CHECK(st_storage_find_or_create_client_identity(f->path,&f->credential,"existing-device","user","changed",&after)<0,"update failure accepted");
    CHECK(scalar(f->db,"SELECT COUNT(*) FROM specus_client_identity WHERE hostname='original' AND last_seen_at='2026-01-01'")==1&&scalar(f->db,"SELECT COUNT(*) FROM client_account")==1,"existing failure changed rows");
    CHECK(after.id==0&&after.client_id==0,"failed output exposed identity");return 0;
}
static int missing_existing_client(fixture *f)
{
    st_storage_client_identity before,after;
    CHECK(st_storage_find_or_create_client_identity(f->path,&f->credential,"existing-device","user","original",&before)==0,"existing identity");
    CHECK(execute(f->db,"DELETE FROM client_account; UPDATE specus_client_identity SET last_seen_at='2026-01-01'")==0,"orphan fixture");
    CHECK(st_storage_find_or_create_client_identity(f->path,&f->credential,"existing-device","user","changed",&after)<0,"orphan accepted");
    CHECK(scalar(f->db,"SELECT COUNT(*) FROM specus_client_identity WHERE hostname='original' AND last_seen_at='2026-01-01'")==1,"orphan updated before refusal");return 0;
}

typedef struct { pthread_mutex_t mutex; pthread_cond_t condition; int arrived, released; } start_gate;
typedef struct { fixture *f; start_gate *gate; int rc; st_storage_client_identity identity; } worker;
static void *provision(void *arg)
{
    worker *w = arg; pthread_mutex_lock(&w->gate->mutex); ++w->gate->arrived; pthread_cond_broadcast(&w->gate->condition);
    while (!w->gate->released) pthread_cond_wait(&w->gate->condition, &w->gate->mutex);
    pthread_mutex_unlock(&w->gate->mutex);
    w->rc = st_storage_find_or_create_client_identity(w->f->path, &w->f->credential, "same-device", "user", "host", &w->identity); return NULL;
}
static int concurrent(fixture *f)
{
    start_gate gate = {.mutex=PTHREAD_MUTEX_INITIALIZER,.condition=PTHREAD_COND_INITIALIZER};
    worker workers[2] = {{.f=f,.gate=&gate},{.f=f,.gate=&gate}}; pthread_t threads[2];
    CHECK(pthread_create(&threads[0],NULL,provision,&workers[0])==0 && pthread_create(&threads[1],NULL,provision,&workers[1])==0,"workers");
    pthread_mutex_lock(&gate.mutex); while(gate.arrived!=2)pthread_cond_wait(&gate.condition,&gate.mutex);gate.released=1;pthread_cond_broadcast(&gate.condition);pthread_mutex_unlock(&gate.mutex);
    pthread_join(threads[0],NULL);pthread_join(threads[1],NULL);pthread_cond_destroy(&gate.condition);pthread_mutex_destroy(&gate.mutex);
    CHECK(workers[0].rc==0&&workers[1].rc==0&&workers[0].identity.id==workers[1].identity.id&&workers[0].identity.client_id==workers[1].identity.client_id,"two database connections did not converge: %d/%d",workers[0].rc,workers[1].rc);
    CHECK(scalar(f->db,"SELECT COUNT(*) FROM client_account")==1&&scalar(f->db,"SELECT COUNT(*) FROM specus_client_identity")==1,"concurrent orphan rows"); return 0;
}

typedef struct { test_server *server; int rc, status; char *body; } http_worker;
static void *login(void *arg)
{
    http_worker *w=arg;char body[2048];signed_login_body(TEST_KEY,TEST_SECRET,"http-device","user",body,sizeof(body));
    w->rc=http_request(w->server->admin_port,"POST","/api/client/auth/login",body,NULL,&w->status,&w->body);return NULL;
}
static int native_race(const char *label,const char *change,int expected)
{
    test_server server; if(server_prepare(&server)!=0)return 1;
    char ready[400],resume[400],preload[1024],ready_env[450],resume_env[450],key_env[200];
    snprintf(ready,sizeof(ready),"%s/auth-ready",server.dir);snprintf(resume,sizeof(resume),"%s/auth-resume",server.dir);
    int failed=1,ready_fd=-1,resume_fd=-1,started=0;sqlite3 *db=NULL;pthread_t thread;int thread_started=0;http_worker w={.server=&server};
    if(mkfifo(ready,0600)!=0||mkfifo(resume,0600)!=0)goto done;
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);if(ready_fd<0||resume_fd<0)goto done;
    /* Preserve the real sanitizer runtime's required first-loader position in native children.
     * Do not disable its link-order check just to load the test probe. */
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
    snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);snprintf(key_env,sizeof(key_env),"SPECUS_TEST_AUTH_BARRIER_KEY=%s",TEST_KEY);
    server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=key_env;
    if(server_start(&server)!=0)goto done;
    started=1;
    st_storage_client_credential credential;
    if(insert_credential(server.db_path,&credential)!=0||sqlite3_open(server.db_path,&db)!=SQLITE_OK)goto done;
    sqlite3_busy_timeout(db,5000);long long before=scalar(db,"SELECT COUNT(*) FROM client_account");
    if(pthread_create(&thread,NULL,login,&w)!=0)goto done;
    thread_started=1;
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;do{polled=poll(&event,1,5000);}while(polled<0&&errno==EINTR);
    char signal=0;if(polled!=1||read(ready_fd,&signal,1)!=1||signal!='R'){fprintf(stderr,"native %s did not reach actual closed-read barrier\n",label);goto done;}
    if(execute(db,change)!=0)goto done;
    if(write(resume_fd,"C",1)!=1)goto done;
    pthread_join(thread,NULL);thread_started=0;
    if(w.rc!=0||w.status!=expected){fprintf(stderr,"native %s status%d expected%d\n",label,w.status,expected);goto done;}
    if(expected==200){
        long long id=0;st_storage_client client;
        if(st_json_get_i64(w.body,"clientId",&id)!=0||st_storage_get_client(server.db_path,id,&client)!=0||strcmp(client.owner_username,"bob")!=0){fprintf(stderr,"native %s resurrected stale owner\n",label);goto done;}
        if(strcmp(label,"current-policy")==0){int maximum=0;if(st_json_get_int(w.body,"maxOnlineInstances",&maximum)!=0||maximum!=2){fprintf(stderr,"native policy used stale credential limit\n");goto done;}}
    }else if(scalar(db,"SELECT COUNT(*) FROM client_account")!=before||scalar(db,"SELECT COUNT(*) FROM specus_client_identity")!=0||scalar(db,"SELECT COUNT(*) FROM specus_client_session")!=0){fprintf(stderr,"native %s wrote after credential refusal\n",label);goto done;}
    failed=0;
done:
    if(thread_started){ssize_t sent=write(resume_fd,"C",1);if(sent!=1)fprintf(stderr,"native %s resume failed\n",label);pthread_join(thread,NULL);}
    free(w.body);sqlite3_close(db);if(ready_fd>=0)close(ready_fd);if(resume_fd>=0)close(resume_fd);unlink(ready);unlink(resume);
    if(started&&server_stop(&server,10000)!=0)failed=1;
    if(failed)dump_server_log(&server);
    server_cleanup(&server,failed);
    printf("%s native auth coordination: %s\n",failed?"FAIL":"PASS",label);return failed;
}

int main(int argc,char **argv)
{
    if(argc!=3)return 2;
    server_binary=argv[1];barrier_library=argv[2];signal(SIGPIPE,SIG_IGN);setvbuf(stdout,NULL,_IOLBF,0);
    int failed=0;struct {const char *name;int(*run)(fixture *);} tests[]={
        {"fresh-owner",stale_owner},{"rollback-new",rollback_new},{"disabled",disabled},{"key-rotated",changed_key},{"secret-rotated",changed_secret},{"tenant-moved",changed_tenant},{"deleted",deleted},{"corrupt-existing",corrupt_existing},{"concurrent",concurrent},
        {"no-implicit-transfer",existing_owner_is_not_implicitly_transferred},{"rollback-existing",rollback_existing},{"missing-existing-client",missing_existing_client}};
    for(size_t i=0;i<sizeof(tests)/sizeof(tests[0]);++i){fixture f;int result=fresh(&f);if(!result)result=tests[i].run(&f);finish(&f);failed+=result;printf("%s storage auth coordination: %s\n",result?"FAIL":"PASS",tests[i].name);}
    failed+=native_race("ownership","UPDATE specus_client_credential SET owner_username='bob'",200);
    failed+=native_race("current-policy","UPDATE specus_client_credential SET owner_username='bob',max_online_instances=2",200);
    failed+=native_race("disabled","UPDATE specus_client_credential SET enabled=0",403);
    failed+=native_race("key-rotated","UPDATE specus_client_credential SET api_key='rotated-key'",401);
    failed+=native_race("secret-rotated","UPDATE specus_client_credential SET secret_hash=printf('%064d',0)",401);
    failed+=native_race("deleted","DELETE FROM specus_client_credential",401);
    return failed?1:0;
}
