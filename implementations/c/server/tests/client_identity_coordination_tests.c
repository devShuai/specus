#define _GNU_SOURCE
#include "storage.h"
#include "crypto.h"
#include "json.h"
#include "server_harness.h"
#include "security.h"
#include "peer_mesh.h"
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
#include <sys/wait.h>
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
    CHECK(f != NULL, "fixture output required");
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

static int peer_update(fixture *f, const st_storage_client *client, int operation,
                       st_storage_peer_mesh_device *device)
{
    if (operation == 0) return st_storage_ensure_peer_mesh_device(f->path, client, device);
    if (operation == 1) return st_storage_update_peer_mesh_device_enabled(f->path, client, 1, device);
    return st_storage_update_peer_mesh_device_report(f->path, client, "new-public-key", "NAT",
        NULL, NULL, NULL, NULL, "tun", "peer-test", "ready", NULL, device);
}

/* The real caller retains a client struct between reading it and reporting/enabling Peer.
 * SQL changes below are fixtures, not a substitute for the still-unimplemented transfer API. */
static int peer_coordination_case(int operation, int scenario)
{
    fixture f;
    int failed = fresh(&f);
    st_storage_client cached;
    st_storage_client_identity identity;
    st_storage_peer_mesh_device before = {0}, after = {0};
    if (failed) goto done;
    if (st_storage_find_or_create_client_identity(f.path, &f.credential, "peer-device", "user", "host", &identity) != 0
        || st_storage_get_client(f.path, identity.client_id, &cached) != 0) { failed = 1; goto done; }
    if (scenario == 1 || scenario == 5) {
        if (st_storage_ensure_peer_mesh_device(f.path, &cached, &before) != 0
            || execute(f.db, "UPDATE peer_mesh_device SET enabled=1,public_key='original-key'") != 0) { failed = 1; goto done; }
    }
    if (scenario == 0 || scenario == 1 || scenario == 5) {
        if (execute(f.db, "UPDATE client_account SET owner_username='bob',client_name='renamed-current'") != 0) { failed = 1; goto done; }
        cached.message_send_capable = 1; /* A stale capability must not escape in the result. */
    } else if (scenario == 2) {
        if (execute(f.db, "DELETE FROM client_account") != 0) { failed = 1; goto done; }
    } else if (scenario == 3) {
        if (execute(f.db, "UPDATE client_account SET tenant_id='foreign'") != 0) { failed = 1; goto done; }
    }
    if (scenario >= 4) {
        const char *fault = operation == 1
            ? "CREATE TRIGGER fail_peer BEFORE UPDATE OF enabled ON peer_mesh_device BEGIN SELECT RAISE(ABORT,'injected enable failure'); END"
            : "CREATE TRIGGER fail_peer BEFORE UPDATE OF public_key ON peer_mesh_device BEGIN SELECT RAISE(ABORT,'injected report failure'); END";
        if (execute(f.db, fault) != 0) { failed = 1; goto done; }
    }
    int rc = peer_update(&f, &cached, operation, &after);
    if (scenario <= 1) {
        if (rc != 0 || strcmp(after.owner_username, "bob") != 0
            || strcmp(after.client_name, "renamed-current") != 0 || after.message_send_capable != 0
            || strcmp(cached.owner_username, "alice") != 0) failed = 1;
        if (scenario == 1 && (strcmp(after.virtual_ip, before.virtual_ip) != 0 || !after.enabled)) failed = 1;
        if (operation == 2 && strcmp(after.public_key, "new-public-key") != 0) failed = 1;
    } else if (scenario <= 4) {
        if (rc >= 0 || scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_device") != 0 || after.id != 0) failed = 1;
    } else {
        if (rc >= 0 || after.id != 0
            || scalar(f.db, "SELECT COUNT(*) FROM peer_mesh_device WHERE owner_username='alice' AND client_name<>'renamed-current' AND public_key='original-key' AND enabled=1") != 1) failed = 1;
    }
done:
    finish(&f);
    printf("%s Peer owner coordination: operation=%d scenario=%d\n", failed ? "FAIL" : "PASS", operation, scenario);
    return failed;
}

static int peer_current_capabilities(int operation)
{
    fixture f;
    int failed = fresh(&f);
    st_storage_client cached;
    st_storage_client_identity identity;
    st_storage_peer_mesh_device device;
    if (failed) goto done;
    if (st_storage_find_or_create_client_identity(f.path, &f.credential, "peer-device", "user", "host", &identity) != 0
        || st_storage_get_client(f.path, identity.client_id, &cached) != 0) { failed = 1; goto done; }
    if (execute(f.db, "INSERT INTO specus_client_session(tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,expires_at,message_send_capable,message_receive_capable,message_attachments_capable,message_media_preview_capable,message_max_attachment_bytes) SELECT tenant_id,credential_id,id,client_id,client_name,'fixture-token-hash','NETTY_ONLINE',machine_fingerprint,os_user,'2099-01-01',1,1,1,1,12345 FROM specus_client_identity") != 0) { failed = 1; goto done; }
    if (peer_update(&f, &cached, operation, &device) != 0 || !device.message_send_capable
        || !device.message_receive_capable || !device.message_attachments_capable
        || !device.message_media_preview_capable || device.message_max_attachment_bytes != 12345) failed = 1;
    if (execute(f.db, "UPDATE specus_client_session SET status='DISCONNECTED'") != 0
        || peer_update(&f, &cached, operation, &device) != 0 || device.message_send_capable
        || device.message_receive_capable || device.message_attachments_capable
        || device.message_media_preview_capable || device.message_max_attachment_bytes != 0) failed = 1;
done:
    finish(&f);
    printf("%s Peer current capabilities: operation=%d\n", failed ? "FAIL" : "PASS", operation);
    return failed;
}

typedef struct {
    test_server *server;
    const char *method, *path, *token, *request;
    int rc, status;
    char *body;
} credential_http_worker;

static void *mutate_credential(void *arg)
{
    credential_http_worker *w = arg;
    w->rc = http_request(w->server->admin_port, w->method, w->path, w->request,
                         w->token, &w->status, &w->body);
    return NULL;
}

static int same_credential(const st_storage_client_credential *a,
                           const st_storage_client_credential *b, int include_updated)
{
    return a->id == b->id && a->enabled == b->enabled && a->max_online_instances == b->max_online_instances
        && strcmp(a->tenant_id,b->tenant_id) == 0 && strcmp(a->owner_username,b->owner_username) == 0
        && strcmp(a->api_key,b->api_key) == 0 && strcmp(a->secret_hash,b->secret_hash) == 0
        && strcmp(a->created_at,b->created_at) == 0
        && (!include_updated || strcmp(a->updated_at,b->updated_at) == 0);
}

/* Freeze an actual PUT/DELETE after authentication and its closed credential read. Other
 * connections then change fixture state; no production hook or fabricated SQLite result. */
static int native_credential_race(int deleting, int scenario)
{
    test_server server;
    if (server_prepare(&server) != 0) return 1;
    char ready[400],resume[400],preload[1024],ready_env[450],resume_env[450],key_env[200];
    char token[2048],path[160];
    snprintf(ready,sizeof(ready),"%s/auth-ready",server.dir);
    snprintf(resume,sizeof(resume),"%s/auth-resume",server.dir);
    int failed=1,ready_fd=-1,resume_fd=-1,started=0,thread_started=0;
    sqlite3 *db=NULL;
    pthread_t thread;
    credential_http_worker w={.server=&server,.method=deleting?"DELETE":"PUT",.path=path,.token=token,
        .request=scenario==2?"{}":"{\"maxOnlineInstances\":9}"};
    st_storage_management_user actor,target;
    st_storage_client_credential credential,expected={0},after={0};
    int admin=scenario==1 || scenario==3 || scenario==10;
    if (insert_credential(server.db_path,&credential)!=0
        || st_storage_create_management_user(server.db_path,"alice","default","fixture-only-hash",admin?"ADMIN":"USER",1,&actor)!=0
        || st_storage_create_management_user(server.db_path,"bob","default","fixture-only-hash","USER",1,&target)!=0
        || st_security_issue_local_token_for_account("alice","default",admin?"ADMIN":"USER",actor.account_key,
             ADMIN_JWT_SECRET,600,token,sizeof(token))!=0) goto done;
    snprintf(path,sizeof(path),"/api/admin/client-credentials/%lld",credential.id);
    if (scenario==10) w.request="{\"apiKey\":\"explicit-new-key\",\"secret\":\"  explicit-new-secret  \",\"enabled\":false,\"maxOnlineInstances\":9}";
    if (scenario==11) w.request="{\"apiKey\":\"duplicate-request-key\"}";
    if (scenario==12) w.request="{\"enabled\":false}";
    if (mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) goto done;
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (ready_fd<0 || resume_fd<0) goto done;
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
    snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);
    snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);
    snprintf(key_env,sizeof(key_env),"SPECUS_TEST_AUTH_BARRIER_KEY=%s",TEST_KEY);
    server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=key_env;
    if(server_start(&server)!=0) goto done;
    started=1;
    if(sqlite3_open(server.db_path,&db)!=SQLITE_OK) goto done;
    sqlite3_busy_timeout(db,5000);
    if(pthread_create(&thread,NULL,mutate_credential,&w)!=0) goto done;
    thread_started=1;
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,5000); } while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') {
        fprintf(stderr,"credential mutation did not reach closed-read barrier\n");goto done;
    }
    const char *change=NULL;
    switch(scenario) {
        case 0: case 1: case 10: change="UPDATE specus_client_credential SET owner_username='bob'";break;
        case 2: change="UPDATE specus_client_credential SET api_key='rotated-current-key',secret_hash=printf('%064d',0),enabled=0,max_online_instances=3";break;
        case 3: change="UPDATE specus_client_credential SET owner_username='bob'; UPDATE specus_management_user SET role='USER' WHERE login_name='alice'";break;
        case 4: change="UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'";break;
        case 5: case 6: change="DELETE FROM specus_management_user WHERE login_name='alice'";break;
        case 7: change="UPDATE specus_management_user SET tenant_id='foreign' WHERE login_name='alice'";break;
        case 8: change="UPDATE specus_client_credential SET tenant_id='foreign'";break;
        case 9: change="DELETE FROM specus_client_credential";break;
        case 11: break;
        case 12: change="CREATE TRIGGER malformed_credential AFTER UPDATE ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username=printf('%0300d',0) WHERE id=NEW.id; END";break;
        case 13: change="CREATE TRIGGER fail_credential_delete BEFORE DELETE ON specus_client_credential BEGIN SELECT RAISE(ABORT,'injected delete failure'); END";break;
        case 14: change="UPDATE specus_client_credential SET owner_username='bob'; UPDATE specus_management_user SET role='ADMIN' WHERE login_name='alice'";break;
        default: goto done;
    }
    if(change!=NULL && execute(db,change)!=0) goto done;
    if(scenario==6 && st_storage_create_management_user(server.db_path,"alice","default","replacement-fixture-hash","ADMIN",1,&target)!=0) goto done;
    if(scenario==11 && st_storage_insert_client_credential(server.db_path,"default","bob","duplicate-request-key",credential.secret_hash,1,2,&after)!=0) goto done;
    if(scenario!=9 && st_storage_get_client_credential(server.db_path,credential.id,&expected)!=0) goto done;
    int expected_status=deleting?204:200;
    if(scenario==0 || scenario==3 || scenario==8 || scenario==9 || scenario==11 || scenario==13) expected_status=400;
    if(scenario>=4 && scenario<=7) expected_status=403;
    if(scenario==12) expected_status=409;
    if(write(resume_fd,"C",1)!=1) goto done;
    pthread_join(thread,NULL);thread_started=0;
    if(w.rc!=0 || w.status!=expected_status) {
        fprintf(stderr,"credential mutation op=%d scenario=%d status=%d expected=%d\n",deleting,scenario,w.status,expected_status);goto done;
    }
    int found=st_storage_get_client_credential(server.db_path,credential.id,&after)==0;
    if(expected_status==204 || scenario==9) {
        if(found) goto done;
    } else if(expected_status!=200) {
        if(!found || !same_credential(&after,&expected,1)) goto done;
    } else {
        if(scenario!=2) expected.max_online_instances=9;
        if(scenario==10) {
            uint8_t digest[ST_SHA256_LEN];
            st_sha256((const uint8_t *)"explicit-new-secret",strlen("explicit-new-secret"),digest);
            st_hex_encode(digest,sizeof(digest),expected.secret_hash);
            snprintf(expected.api_key,sizeof(expected.api_key),"%s","explicit-new-key");expected.enabled=0;
        }
        if(!found || !same_credential(&after,&expected,0)) goto done;
        if(scenario==10 ? strstr(w.body,"\"secret\":\"explicit-new-secret\"")==NULL : strstr(w.body,"\"secret\":null")==NULL) goto done;
    }
    failed=0;
done:
    if(thread_started) { ssize_t sent=write(resume_fd,"C",1);if(sent!=1)fprintf(stderr,"credential resume failed\n");pthread_join(thread,NULL); }
    free(w.body);sqlite3_close(db);
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    unlink(ready);unlink(resume);
    if(started&&server_stop(&server,10000)!=0)failed=1;
    if(failed)dump_server_log(&server);
    server_cleanup(&server,failed);
    printf("%s native credential coordination: operation=%d scenario=%d\n",failed?"FAIL":"PASS",deleting,scenario);
    return failed;
}

/* The real account resolver has returned a row and released its read lock, but HTTP has
 * not resumed. Fixture writes below commit before POST is allowed to continue. */
static int native_credential_create_race(int scenario)
{
    test_server server;
    if(server_prepare(&server)!=0) return 1;
    char ready[400],resume[400],preload[1024],ready_env[450],resume_env[450],account_env[200],token[2048];
    snprintf(ready,sizeof(ready),"%s/auth-ready",server.dir);
    snprintf(resume,sizeof(resume),"%s/auth-resume",server.dir);
    int failed=1,ready_fd=-1,resume_fd=-1,started=0,thread_started=0;
    sqlite3 *db=NULL;
    pthread_t thread;
    credential_http_worker w={.server=&server,.method="POST",.path="/api/admin/client-credentials",.token=token,
        .request="{\"apiKey\":\"create-race-key\",\"secret\":\"  create-race-secret  \",\"enabled\":false,\"maxOnlineInstances\":9}"};
    st_storage_management_user actor,replacement;
    st_storage_client_credential credential={0},duplicate={0};
    int admin=scenario==6;
    if(st_storage_init(server.db_path,0)!=0
        || st_storage_create_management_user(server.db_path,"alice","default","fixture-only-hash",admin?"ADMIN":"USER",1,&actor)!=0
        || st_security_issue_local_token_for_account("alice","default",admin?"ADMIN":"USER",actor.account_key,
            ADMIN_JWT_SECRET,600,token,sizeof(token))!=0) goto done;
    if(scenario==11) w.request="{}";
    if(mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) goto done;
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(ready_fd<0 || resume_fd<0) goto done;
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
    snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);
    snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);
    snprintf(account_env,sizeof(account_env),"SPECUS_TEST_AUTH_BARRIER_ACCOUNT=%s",actor.account_key);
    server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=account_env;
    if(server_start(&server)!=0) goto done;
    started=1;
    if(sqlite3_open(server.db_path,&db)!=SQLITE_OK) goto done;
    sqlite3_busy_timeout(db,5000);
    if(pthread_create(&thread,NULL,mutate_credential,&w)!=0) goto done;
    thread_started=1;
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,5000); } while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') {
        fprintf(stderr,"credential create did not reach closed account-read barrier\n");goto done;
    }
    const char *change=NULL;
    switch(scenario) {
        case 0: case 11: break;
        case 1: change="UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'";break;
        case 2: case 3: case 12: change="DELETE FROM specus_management_user WHERE login_name='alice'";break;
        case 4: change="UPDATE specus_management_user SET tenant_id='foreign' WHERE login_name='alice'";break;
        case 5: change="UPDATE specus_management_user SET login_name='renamed',login_name_normalized='renamed' WHERE login_name='alice'";break;
        case 6: change="UPDATE specus_management_user SET role='USER' WHERE login_name='alice'";break;
        case 7: break;
        case 8: change="CREATE TRIGGER malformed_created_owner AFTER INSERT ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username=printf('%0300d',0) WHERE id=NEW.id; END";break;
        case 9: change="CREATE TRIGGER wrong_created_owner AFTER INSERT ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username='bob' WHERE id=NEW.id; END";break;
        case 10: change="CREATE TRIGGER fail_credential_insert BEFORE INSERT ON specus_client_credential BEGIN SELECT RAISE(ABORT,'injected insert failure'); END";break;
        case 13: change="UPDATE specus_management_user SET role='ADMIN' WHERE login_name='alice'";break;
        default: goto done;
    }
    if(change!=NULL && execute(db,change)!=0) goto done;
    if((scenario==3 || scenario==12)
        && st_storage_create_management_user(server.db_path,"alice",scenario==12?"foreign":"default","replacement-fixture-hash","ADMIN",1,&replacement)!=0) goto done;
    if(scenario==7) {
        uint8_t digest[ST_SHA256_LEN];char hash[65];
        st_sha256((const uint8_t *)"concurrent-secret",strlen("concurrent-secret"),digest);st_hex_encode(digest,sizeof(digest),hash);
        if(st_storage_insert_client_credential(server.db_path,"default","bob","create-race-key",hash,1,2,&duplicate)!=0) goto done;
    }
    int expected_status=201;
    if((scenario>=1 && scenario<=5) || scenario==12) expected_status=403;
    if(scenario==7) expected_status=400;
    if(scenario>=8 && scenario<=10) expected_status=500;
    if(write(resume_fd,"C",1)!=1) goto done;
    pthread_join(thread,NULL);thread_started=0;
    if(w.rc!=0 || w.status!=expected_status) {
        fprintf(stderr,"credential create scenario=%d status=%d expected=%d\n",scenario,w.status,expected_status);goto done;
    }
    long long count=scalar(db,"SELECT COUNT(*) FROM specus_client_credential");
    if(expected_status==201) {
        char *key=st_json_get_string(w.body,"apiKey"),*secret=st_json_get_string(w.body,"secret");
        uint8_t digest[ST_SHA256_LEN];char hash[65];
        int valid=key!=NULL && secret!=NULL && *key!='\0' && *secret!='\0';
        if(valid) {
            st_sha256((const uint8_t *)secret,strlen(secret),digest);st_hex_encode(digest,sizeof(digest),hash);
            valid=st_storage_get_client_credential_by_api_key(server.db_path,key,&credential)==0
                && count==1 && strcmp(credential.tenant_id,"default")==0 && strcmp(credential.owner_username,"alice")==0
                && strcmp(credential.secret_hash,hash)==0 && credential.enabled==(scenario==11)
                && (scenario==11?credential.max_online_instances>0:credential.max_online_instances==9)
                && (scenario==11 || (strcmp(key,"create-race-key")==0 && strcmp(secret,"create-race-secret")==0));
        }
        free(key);free(secret);
        if(!valid) { fprintf(stderr,"credential create returned inconsistent result scenario=%d count=%lld\n",scenario,count);goto done; }
    } else if(scenario==7) {
        if(count!=1 || st_storage_get_client_credential(server.db_path,duplicate.id,&credential)!=0
            || !same_credential(&duplicate,&credential,1)) goto done;
    } else if(count!=0) { fprintf(stderr,"credential create left rows after refusal scenario=%d count=%lld\n",scenario,count);goto done; }
    failed=0;
done:
    if(thread_started) { ssize_t sent=write(resume_fd,"C",1);if(sent!=1)fprintf(stderr,"credential create resume failed\n");pthread_join(thread,NULL); }
    free(w.body);sqlite3_close(db);
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    unlink(ready);unlink(resume);
    if(started&&server_stop(&server,10000)!=0)failed=1;
    if(failed)dump_server_log(&server);
    server_cleanup(&server,failed);
    printf("%s native credential create coordination: scenario=%d\n",failed?"FAIL":"PASS",scenario);
    return failed;
}

static int direct_credential_coordination(int scenario)
{
    fixture f;
    int failed=fresh(&f);
    st_storage_management_user user,other;
    st_storage_client_credential before={0},after={0},output;
    st_storage_share_builtin_admin builtin={"builtin","default",1};
    st_storage_credential_patch patch={.max_online_provided=1,.max_online_instances=9};
    if(failed) goto done;
    if(st_storage_create_management_user(f.path,"alice","default","fixture-only-hash","USER",1,&user)!=0
        || st_storage_create_management_user(f.path,"bob","default","fixture-only-hash","USER",1,&other)!=0) { failed=1;goto done; }
    st_storage_management_actor actor={"alice","default",user.account_key};
    int expected=0;
    st_storage_client_credential *published=&output;
    switch(scenario) {
        case 0: actor.account_key="";expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 1: actor.account_key=other.account_key;expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 2: actor=(st_storage_management_actor){"builtin","DEFAULT",""};expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 3: actor=(st_storage_management_actor){"builtin","default",""};builtin.accepted=0;expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 4: actor=(st_storage_management_actor){"builtin","default",""};published=NULL;break;
        case 5:
            if(st_storage_insert_client_credential(f.path,"default","bob","duplicate-store-key",f.credential.secret_hash,1,2,&after)!=0) { failed=1;goto done; }
            patch.api_key="duplicate-store-key";expected=ST_STORAGE_CREDENTIAL_KEY_EXISTS;break;
        case 6:
            if(execute(f.db,"CREATE TRIGGER wrong_owner AFTER UPDATE ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username='bob' WHERE id=NEW.id; END")!=0) { failed=1;goto done; }
            expected=-1;published=NULL;break;
        case 7:
            if(execute(f.db,"CREATE TRIGGER malformed_owner AFTER UPDATE ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username=printf('%0300d',0) WHERE id=NEW.id; END")!=0) { failed=1;goto done; }
            expected=-1;break;
        case 8: patch.max_online_instances=0;expected=-1;break;
        case 9:
            if(execute(f.db,"UPDATE specus_client_credential SET owner_username='bob'; UPDATE specus_management_user SET role='\t AdMiN \r\n' WHERE login_name='alice'")!=0) { failed=1;goto done; }
            published=NULL;break;
        default: failed=1;goto done;
    }
    if(st_storage_get_client_credential(f.path,f.credential.id,&before)!=0) { failed=1;goto done; }
    memset(&output,0x7f,sizeof(output));
    int rc=st_storage_patch_client_credential_visible(f.path,f.credential.id,&actor,&builtin,&patch,published);
    if(rc!=expected || st_storage_get_client_credential(f.path,f.credential.id,&after)!=0) { failed=1;goto done; }
    if(rc==0) before.max_online_instances=9;
    if(!same_credential(&before,&after,rc!=0)
        || (published!=NULL && rc!=0 && (output.id!=0 || output.api_key[0]!='\0'))) failed=1;
    if(published==NULL) {
        const unsigned char *untouched=(const unsigned char *)&output;
        for(size_t i=0;i<sizeof(output);++i) if(untouched[i]!=0x7f) failed=1;
    }
done:
    finish(&f);
    printf("%s direct credential coordination: scenario=%d\n",failed?"FAIL":"PASS",scenario);
    return failed;
}

static int direct_credential_create_coordination(int scenario)
{
    fixture f;
    int failed=fresh(&f);
    st_storage_management_user user,other;
    st_storage_client_credential original={0},output,created={0};
    st_storage_share_builtin_admin builtin={"builtin","default",1};
    if(failed) goto done;
    if(st_storage_create_management_user(f.path,"alice","default","fixture-only-hash","USER",1,&user)!=0
        || st_storage_create_management_user(f.path,"bob","default","fixture-only-hash","ADMIN",1,&other)!=0
        || st_storage_get_client_credential(f.path,f.credential.id,&original)!=0) { failed=1;goto done; }
    st_storage_management_actor actor={"alice","default",user.account_key};
    st_storage_client_credential *published=&output;
    const char *key="direct-create-key",*hash=f.credential.secret_hash,*expected_owner="alice";
    int expected=0,maximum=9;
    char oversized[362];memset(oversized,'k',sizeof(oversized)-1);oversized[sizeof(oversized)-1]='\0';
    switch(scenario) {
        case 0: break;
        case 1: actor=(st_storage_management_actor){"BuIlTiN","default",""};expected_owner="builtin";break;
        case 2: actor.account_key="";expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 3: actor.account_key=other.account_key;expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 4: actor=(st_storage_management_actor){"builtin","DEFAULT",""};expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 5: actor=(st_storage_management_actor){"builtin","default",""};builtin.accepted=0;expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 6:
            if(execute(f.db,"UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'")!=0) { failed=1;goto done; }
            expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 7: published=NULL;break;
        case 8: case 9:
            if(execute(f.db,scenario==8
                ? "CREATE TRIGGER wrong_create_owner AFTER INSERT ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username='bob' WHERE id=NEW.id; END"
                : "CREATE TRIGGER malformed_create_owner AFTER INSERT ON specus_client_credential BEGIN UPDATE specus_client_credential SET owner_username=printf('%0300d',0) WHERE id=NEW.id; END")!=0) { failed=1;goto done; }
            expected=-1;if(scenario==8) published=NULL;break;
        case 10: key=TEST_KEY;expected=ST_STORAGE_CREDENTIAL_KEY_EXISTS;break;
        case 11: maximum=0;expected=-1;break;
        case 12: hash="short";expected=-1;break;
        case 13: key="";expected=-1;break;
        case 14: key=oversized;expected=-1;break;
        case 15: actor.username="ALICE";expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        default: failed=1;goto done;
    }
    memset(&output,0x7f,sizeof(output));
    int rc=st_storage_create_client_credential_current_actor(f.path,&actor,&builtin,key,hash,0,maximum,published);
    if(rc!=expected || scalar(f.db,"SELECT COUNT(*) FROM specus_client_credential")!=(rc==0?2:1)
        || st_storage_get_client_credential(f.path,f.credential.id,&created)!=0 || !same_credential(&original,&created,1)) {
        fprintf(stderr,"direct credential create scenario=%d rc=%d expected=%d\n",scenario,rc,expected);failed=1;goto done;
    }
    if(rc==0) {
        if(st_storage_get_client_credential_by_api_key(f.path,key,&created)!=0
            || strcmp(created.owner_username,expected_owner)!=0 || strcmp(created.tenant_id,"default")!=0
            || strcmp(created.secret_hash,hash)!=0 || created.enabled!=0 || created.max_online_instances!=9
            || (published!=NULL && !same_credential(&created,published,1))) failed=1;
    } else if(published!=NULL) {
        const unsigned char *zeroed=(const unsigned char *)&output;
        for(size_t i=0;i<sizeof(output);++i) if(zeroed[i]!=0) failed=1;
    }
    if(published==NULL) {
        const unsigned char *untouched=(const unsigned char *)&output;
        for(size_t i=0;i<sizeof(output);++i) if(untouched[i]!=0x7f) failed=1;
    }
done:
    finish(&f);
    printf("%s direct credential create coordination: scenario=%d\n",failed?"FAIL":"PASS",scenario);
    return failed;
}

static int same_client_state(const st_storage_client *a, const st_storage_client *b, int timestamps)
{
    return a->id==b->id && strcmp(a->tenant_id,b->tenant_id)==0 && strcmp(a->client_name,b->client_name)==0
        && strcmp(a->owner_username,b->owner_username)==0 && a->enabled==b->enabled
        && a->connection_rate_limit_per_minute==b->connection_rate_limit_per_minute
        && strcmp(a->created_at,b->created_at)==0 && (!timestamps || strcmp(a->updated_at,b->updated_at)==0);
}

static int native_client_mutation_race(int deleting, int scenario)
{
    test_server server;
    if(server_prepare(&server)!=0) return 1;
    char ready[400],resume[400],preload[1024],ready_env[450],resume_env[450],client_env[200],token[2048],path[160],change[800];
    snprintf(ready,sizeof(ready),"%s/auth-ready",server.dir);snprintf(resume,sizeof(resume),"%s/auth-resume",server.dir);
    int failed=1,ready_fd=-1,resume_fd=-1,started=0,thread_started=0;
    sqlite3 *db=NULL;pthread_t thread;
    credential_http_worker w={.server=&server,.method=deleting?"DELETE":"PUT",.path=path,.token=token,
        .request=scenario==2?"{}":"{\"connectionRateLimitPerMinute\":99}"};
    st_storage_management_user actor,replacement;
    st_storage_client_credential credential;
    st_storage_client_identity identity;
    st_storage_client initial={0},expected={0},after={0};
    st_storage_peer_mesh_device peer={0};
    int admin=scenario==1 || scenario==3 || scenario==12;
    if(insert_credential(server.db_path,&credential)!=0
        || st_storage_find_or_create_client_identity(server.db_path,&credential,"client-mutation-device","user","host",&identity)!=0
        || st_storage_get_client(server.db_path,identity.client_id,&initial)!=0
        || st_storage_ensure_peer_mesh_device(server.db_path,&initial,&peer)!=0
        || st_storage_create_management_user(server.db_path,"alice","default","fixture-only-hash",admin?"ADMIN":"USER",1,&actor)!=0
        || st_security_issue_local_token_for_account("alice","default",admin?"ADMIN":"USER",actor.account_key,
             ADMIN_JWT_SECRET,600,token,sizeof(token))!=0) goto done;
    snprintf(path,sizeof(path),"/api/admin/clients/%lld",initial.id);
    if(scenario==12) w.request="{\"clientName\":\"explicit-client-name\",\"enabled\":false,\"connectionRateLimitPerMinute\":100}";
    if(mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) goto done;
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(ready_fd<0 || resume_fd<0) goto done;
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
    snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);
    snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);
    snprintf(client_env,sizeof(client_env),"SPECUS_TEST_AUTH_BARRIER_CLIENT_ID=%lld",initial.id);
    server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=client_env;
    if(server_start(&server)!=0) goto done;
    started=1;
    if(sqlite3_open(server.db_path,&db)!=SQLITE_OK) goto done;
    sqlite3_busy_timeout(db,5000);
    if(pthread_create(&thread,NULL,mutate_credential,&w)!=0) goto done;
    thread_started=1;
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,5000); } while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') { fprintf(stderr,"client mutation missed closed-read barrier\n");goto done; }
    change[0]='\0';
    switch(scenario) {
        case 0: case 1: case 12:
            snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld",initial.id);break;
        case 2:
            if(st_storage_update_client_audited(server.db_path,initial.id,"concurrently-renamed",0,7,"fixture",1,&expected,NULL)!=0) goto done;
            break;
        case 3:
            snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld; UPDATE specus_management_user SET role='USER' WHERE login_name='alice'",initial.id);break;
        case 4: strcpy(change,"UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'");break;
        case 5: case 6: strcpy(change,"DELETE FROM specus_management_user WHERE login_name='alice'");break;
        case 7: strcpy(change,"UPDATE specus_management_user SET tenant_id='foreign' WHERE login_name='alice'");break;
        case 8: snprintf(change,sizeof(change),"UPDATE client_account SET tenant_id='foreign' WHERE rowid=%lld",initial.id);break;
        case 9: snprintf(change,sizeof(change),"DELETE FROM client_account WHERE rowid=%lld",initial.id);break;
        case 10: case 11:
            snprintf(change,sizeof(change),deleting
                ? (scenario==10?"CREATE TRIGGER fail_client_delete BEFORE DELETE ON client_account WHEN OLD.rowid=%lld BEGIN SELECT RAISE(ABORT,'injected delete failure'); END"
                    : "CREATE TRIGGER fail_peer_delete BEFORE DELETE ON peer_mesh_device WHEN OLD.client_id=%lld BEGIN SELECT RAISE(ABORT,'injected peer delete failure'); END")
                : (scenario==10?"CREATE TRIGGER malformed_client AFTER UPDATE ON client_account WHEN NEW.rowid=%lld BEGIN UPDATE client_account SET owner_username=printf('%%0300d',0) WHERE rowid=NEW.rowid; END"
                    : "CREATE TRIGGER changed_client_owner AFTER UPDATE ON client_account WHEN NEW.rowid=%lld BEGIN UPDATE client_account SET owner_username='bob' WHERE rowid=NEW.rowid; END"),initial.id);break;
        case 13:
            snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld; UPDATE specus_management_user SET role='ADMIN' WHERE login_name='alice'",initial.id);break;
        case 14: strcpy(change,"UPDATE specus_management_user SET login_name='renamed',login_name_normalized='renamed' WHERE login_name='alice'");break;
        default: goto done;
    }
    if(change[0]!='\0' && execute(db,change)!=0) goto done;
    if(scenario==6 && st_storage_create_management_user(server.db_path,"alice","default","replacement-fixture-hash","ADMIN",1,&replacement)!=0) goto done;
    if(scenario!=9 && st_storage_get_client(server.db_path,initial.id,&expected)!=0) goto done;
    int expected_status=deleting?204:200;
    if(scenario==0 || scenario==3 || scenario==8 || scenario==9) expected_status=404;
    if((scenario>=4 && scenario<=7) || scenario==14) expected_status=403;
    if(scenario==10 || scenario==11) expected_status=deleting?404:409;
    if(write(resume_fd,"C",1)!=1) goto done;
    pthread_join(thread,NULL);thread_started=0;
    if(w.rc!=0 || w.status!=expected_status) { fprintf(stderr,"client mutation op=%d scenario=%d status=%d expected=%d\n",deleting,scenario,w.status,expected_status);goto done; }
    int found=st_storage_get_client(server.db_path,initial.id,&after)==0;
    if(expected_status==204 || scenario==9) {
        if(found) goto done;
    } else if(expected_status!=200) {
        if(!found || !same_client_state(&after,&expected,1)) { fprintf(stderr,"refused client mutation changed row\n");goto done; }
    } else {
        if(scenario!=2) expected.connection_rate_limit_per_minute=scenario==12?100:99;
        if(scenario==12) { strcpy(expected.client_name,"explicit-client-name");expected.enabled=0; }
        if(!found || !same_client_state(&after,&expected,0)) { fprintf(stderr,"client mutation overwrote concurrent state\n");goto done; }
        char *name=st_json_get_string(w.body,"clientName");
        int matches=name!=NULL && strcmp(name,expected.client_name)==0;
        free(name);if(!matches) goto done;
    }
    long long refs=expected_status==204?0:1;
    /* The original identity intentionally remains bound to the deleted, never-reused account ID
     * (client-auth contract); it must not silently provision a replacement on a later login. */
    if(scalar(db,"SELECT COUNT(*) FROM specus_client_identity")!=1 || scalar(db,"SELECT COUNT(*) FROM peer_mesh_device")!=refs
        || scalar(db,"SELECT COUNT(*) FROM specus_client_credential")!=1) { fprintf(stderr,"client mutation reference cleanup/rollback mismatch\n");goto done; }
    failed=0;
done:
    if(thread_started) { ssize_t sent=write(resume_fd,"C",1);if(sent!=1)fprintf(stderr,"client resume failed\n");pthread_join(thread,NULL); }
    free(w.body);sqlite3_close(db);
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    unlink(ready);unlink(resume);
    if(started&&server_stop(&server,10000)!=0)failed=1;
    if(failed)dump_server_log(&server);
    server_cleanup(&server,failed);
    printf("%s native client mutation coordination: operation=%d scenario=%d\n",failed?"FAIL":"PASS",deleting,scenario);
    return failed;
}

/* Pause after the real authenticated account lookup closes its SQLite connection.
 * No read lock is held while the fixture commits the intervening account change. */
static int native_client_create_race(int scenario)
{
    test_server server;
    if(server_prepare(&server)!=0) return 1;
    char ready[400],resume[400],preload[1024],ready_env[450],resume_env[450],account_env[200],token[2048];
    snprintf(ready,sizeof(ready),"%s/auth-ready",server.dir);snprintf(resume,sizeof(resume),"%s/auth-resume",server.dir);
    int failed=1,ready_fd=-1,resume_fd=-1,started=0,thread_started=0;
    sqlite3 *db=NULL;pthread_t thread;
    credential_http_worker w={.server=&server,.method="POST",.path="/api/admin/clients",.token=token,
        .request="{\"clientName\":\"  create-race-client  \",\"enabled\":false,\"connectionRateLimitPerMinute\":9}"};
    st_storage_management_user actor,replacement;
    st_storage_client client={0},duplicate={0},demo={0};
    int admin=scenario==6;
    if(st_storage_get_client_by_name(server.db_path,"Demo client",&demo)!=0
        || st_storage_init(server.db_path,0)!=0
        || st_storage_create_management_user(server.db_path,"alice","default","fixture-only-hash",admin?"ADMIN":"USER",1,&actor)!=0
        || st_security_issue_local_token_for_account("alice","default",admin?"ADMIN":"USER",actor.account_key,
            ADMIN_JWT_SECRET,600,token,sizeof(token))!=0) goto done;
    if(scenario==11) w.request="{\"clientName\":\"create-race-client\"}";
    if(scenario==15) w.request="{\"clientName\":\"create-race-client\",\"connectionRateLimitPerMinute\":0}";
    if(scenario==16) w.request="{}";
    if(mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) goto done;
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(ready_fd<0 || resume_fd<0) goto done;
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
    snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);
    snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);
    snprintf(account_env,sizeof(account_env),"SPECUS_TEST_AUTH_BARRIER_ACCOUNT=%s",actor.account_key);
    server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=account_env;
    if(server_start(&server)!=0) goto done;
    started=1;
    if(sqlite3_open(server.db_path,&db)!=SQLITE_OK) goto done;
    sqlite3_busy_timeout(db,5000);
    if(pthread_create(&thread,NULL,mutate_credential,&w)!=0) goto done;
    thread_started=1;
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,5000); } while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') { fprintf(stderr,"client create missed closed account-read barrier\n");goto done; }
    const char *change=NULL;
    switch(scenario) {
        case 0: case 7: case 11: case 15: case 16: break;
        case 1: change="UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'";break;
        case 2: case 3: case 12: change="DELETE FROM specus_management_user WHERE login_name='alice'";break;
        case 4: change="UPDATE specus_management_user SET tenant_id='foreign' WHERE login_name='alice'";break;
        case 5: change="UPDATE specus_management_user SET login_name='renamed',login_name_normalized='renamed' WHERE login_name='alice'";break;
        case 6: change="UPDATE specus_management_user SET role='USER' WHERE login_name='alice'";break;
        case 8: change="CREATE TRIGGER malformed_created_client AFTER INSERT ON client_account BEGIN UPDATE client_account SET owner_username=printf('%0300d',0) WHERE rowid=NEW.rowid; END";break;
        case 9: change="CREATE TRIGGER wrong_created_client_owner AFTER INSERT ON client_account BEGIN UPDATE client_account SET owner_username='bob' WHERE rowid=NEW.rowid; END";break;
        case 10: change="CREATE TRIGGER fail_client_insert BEFORE INSERT ON client_account BEGIN SELECT RAISE(ABORT,'injected insert failure'); END";break;
        case 13: change="UPDATE specus_management_user SET role='ADMIN' WHERE login_name='alice'";break;
        case 14: change="CREATE TRIGGER wrong_created_client_tenant AFTER INSERT ON client_account BEGIN UPDATE client_account SET tenant_id='foreign' WHERE rowid=NEW.rowid; END";break;
        default: goto done;
    }
    if(change!=NULL && execute(db,change)!=0) goto done;
    if((scenario==3 || scenario==12)
        && st_storage_create_management_user(server.db_path,"alice",scenario==12?"foreign":"default","replacement-fixture-hash","ADMIN",1,&replacement)!=0) goto done;
    if(scenario==7 && st_storage_upsert_client(server.db_path,0,"default","create-race-client","bob",1,7,&duplicate)!=0) goto done;
    int expected_status=201;
    if((scenario>=1 && scenario<=5) || scenario==12) expected_status=403;
    if(scenario==7 || scenario==16) expected_status=400;
    if((scenario>=8 && scenario<=10) || scenario==14) expected_status=409;
    if(write(resume_fd,"C",1)!=1) goto done;
    pthread_join(thread,NULL);thread_started=0;
    if(w.rc!=0 || w.status!=expected_status) { fprintf(stderr,"client create scenario=%d status=%d expected=%d\n",scenario,w.status,expected_status);goto done; }
    long long count=scalar(db,"SELECT COUNT(*) FROM client_account");
    if(expected_status==201) {
        char *name=st_json_get_string(w.body,"clientName");
        long long response_id=0;
        int valid=st_json_get_i64(w.body,"id",&response_id)==0;
        valid=valid && name!=NULL && strcmp(name,"create-race-client")==0
            && st_storage_get_client_by_name(server.db_path,name,&client)==0 && count==2 && response_id==client.id
            && strcmp(client.tenant_id,"default")==0 && strcmp(client.owner_username,"alice")==0
            && client.enabled==(scenario==11 || scenario==15)
            && client.connection_rate_limit_per_minute==((scenario==11 || scenario==15)?30:9);
        free(name);
        if(!valid) { fprintf(stderr,"client create inconsistent result scenario=%d count=%lld\n",scenario,count);goto done; }
    } else if(scenario==7) {
        if(count!=2 || st_storage_get_client(server.db_path,duplicate.id,&client)!=0 || !same_client_state(&duplicate,&client,1)) goto done;
    } else if(count!=1) { fprintf(stderr,"client create left rows after refusal scenario=%d count=%lld\n",scenario,count);goto done; }
    /* The common native harness intentionally seeds the unrelated Demo client. */
    if(st_storage_get_client(server.db_path,demo.id,&client)!=0 || !same_client_state(&demo,&client,1)) goto done;
    if(scalar(db,"SELECT COUNT(*) FROM specus_client_identity")!=0 || scalar(db,"SELECT COUNT(*) FROM peer_mesh_device")!=0) goto done;
    failed=0;
done:
    if(thread_started) { ssize_t sent=write(resume_fd,"C",1);if(sent!=1)fprintf(stderr,"client create resume failed\n");pthread_join(thread,NULL); }
    free(w.body);sqlite3_close(db);
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    unlink(ready);unlink(resume);
    if(started&&server_stop(&server,10000)!=0)failed=1;
    if(failed)dump_server_log(&server);
    server_cleanup(&server,failed);
    printf("%s native client create coordination: scenario=%d\n",failed?"FAIL":"PASS",scenario);
    return failed;
}

static int direct_client_mutation(int scenario)
{
    fixture f;
    int failed=fresh(&f);
    st_storage_management_user user,other;
    st_storage_client_identity identity;
    st_storage_client initial={0},expected={0},actual={0},before,updated;
    st_storage_peer_mesh_device device={0};
    st_storage_share_builtin_admin builtin={"builtin","default",1};
    st_storage_share_ids revoked={0};
    st_storage_peer_close *closed=NULL;
    size_t closed_count=77;
    if(failed) goto done;
    if(st_storage_find_or_create_client_identity(f.path,&f.credential,"direct-client-device","user","host",&identity)!=0
        || st_storage_get_client(f.path,identity.client_id,&initial)!=0
        || st_storage_ensure_peer_mesh_device(f.path,&initial,&device)!=0
        || st_storage_create_management_user(f.path,"alice","default","fixture-only-hash","USER",1,&user)!=0
        || st_storage_create_management_user(f.path,"bob","default","fixture-only-hash","ADMIN",1,&other)!=0) { failed=1;goto done; }
    st_storage_management_actor actor={"alice","default",user.account_key};
    const st_storage_management_actor *resolved=&actor;
    st_storage_client_patch patch={.rate_limit_provided=1,.connection_rate_limit_per_minute=9};
    int deleting=scenario>=10 && scenario!=15,expected_rc=0;
    st_storage_client *published_before=&before,*published_after=deleting?NULL:&updated;
    char change[1000];change[0]='\0';
    switch(scenario) {
        case 0: patch.enabled_provided=1;patch.enabled=0;break;
        case 1: actor=(st_storage_management_actor){"BuIlTiN","default",""};patch.connection_rate_limit_per_minute=-5;break;
        case 2: actor.account_key=other.account_key;expected_rc=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 3: actor.account_key="";expected_rc=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 4: case 5:
            snprintf(change,sizeof(change),scenario==4
                ? "CREATE TRIGGER malformed_patch AFTER UPDATE ON client_account WHEN NEW.rowid=%lld BEGIN UPDATE client_account SET owner_username=printf('%%0300d',0) WHERE rowid=NEW.rowid; END"
                : "CREATE TRIGGER wrong_patch_owner AFTER UPDATE ON client_account WHEN NEW.rowid=%lld BEGIN UPDATE client_account SET owner_username='bob' WHERE rowid=NEW.rowid; END",initial.id);
            expected_rc=-1;if(scenario==5) { published_before=NULL;published_after=NULL; }break;
        case 6:
            if(st_storage_upsert_client(f.path,0,"default","duplicate-client-name","bob",1,30,&actual)!=0) { failed=1;goto done; }
            patch.client_name="duplicate-client-name";expected_rc=ST_STORAGE_CLIENT_NAME_EXISTS;break;
        case 7: actor=(st_storage_management_actor){"builtin","DEFAULT",""};expected_rc=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 8:
            snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld",initial.id);
            expected_rc=ST_STORAGE_CLIENT_NOT_VISIBLE;break;
        case 9: patch.client_name="";expected_rc=-1;break;
        case 10:
            actor=(st_storage_management_actor){"bob","default",other.account_key};
            if(st_storage_update_client_audited(f.path,initial.id,"latest-name-before-delete",1,7,"fixture",1,&actual,NULL)!=0) { failed=1;goto done; }
            break;
        case 11:
            snprintf(change,sizeof(change),"CREATE TRIGGER late_delete_failure BEFORE DELETE ON peer_mesh_device WHEN OLD.client_id=%lld BEGIN SELECT RAISE(ABORT,'injected late failure'); END",initial.id);
            expected_rc=-1;break;
        case 12:
            snprintf(change,sizeof(change),"CREATE TRIGGER resurrect_deleted_client AFTER DELETE ON client_account WHEN OLD.rowid=%lld BEGIN INSERT INTO client_account(rowid,tenant_id,client_name,owner_username,enabled,connection_limit_per_minute,created_at,updated_at) VALUES(OLD.rowid,OLD.tenant_id,OLD.client_name,OLD.owner_username,OLD.enabled,OLD.connection_limit_per_minute,OLD.created_at,OLD.updated_at); END",initial.id);
            expected_rc=-1;break;
        case 13: actor=(st_storage_management_actor){"builtin","default",""};published_before=NULL;break;
        case 14: strcpy(change,"UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'");expected_rc=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 15: case 16: resolved=NULL;expected_rc=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        default: failed=1;goto done;
    }
    if(change[0]!='\0' && execute(f.db,change)!=0) { failed=1;goto done; }
    if(st_storage_get_client(f.path,initial.id,&expected)!=0) { failed=1;goto done; }
    memset(&before,0x7f,sizeof(before));memset(&updated,0x7f,sizeof(updated));
    int rc=deleting
        ? st_storage_delete_client_visible_audited(f.path,initial.id,resolved,&builtin,1,published_before,&revoked,&closed,&closed_count)
        : st_storage_patch_client_visible_audited(f.path,initial.id,resolved,&builtin,&patch,1,published_before,published_after,&revoked);
    int found=st_storage_get_client(f.path,initial.id,&actual)==0;
    if(rc!=expected_rc || (deleting && (closed!=NULL || closed_count!=0)) || revoked.ids!=NULL || revoked.len!=0 || revoked.cap!=0) {
        fprintf(stderr,"direct client mutation scenario=%d rc=%d expected=%d closed=%zu revoked=%zu\n",scenario,rc,expected_rc,closed_count,revoked.len);failed=1;goto done;
    }
    if(rc==0 && deleting) {
        if(found || scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_device")!=0) failed=1;
    } else {
        st_storage_client wanted=expected;
        if(rc==0) { wanted.connection_rate_limit_per_minute=scenario==1?30:9;if(scenario==0)wanted.enabled=0; }
        if(!found || !same_client_state(&wanted,&actual,rc!=0) || scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_device")!=1) failed=1;
        if(rc==0 && published_after!=NULL && !same_client_state(published_after,&actual,1)) failed=1;
    }
    if(scalar(f.db,"SELECT COUNT(*) FROM specus_client_identity")!=1) failed=1;
    if(rc==0 && published_before!=NULL && !same_client_state(published_before,&expected,1)) failed=1;
    const st_storage_client *outputs[]={&before,&updated};
    int provided[]={published_before!=NULL,published_after!=NULL};
    for(size_t n=0;n<2;++n) {
        if(provided[n] && rc==0) continue;
        const unsigned char *bytes=(const unsigned char *)outputs[n];
        unsigned char value=provided[n]?0:0x7f;
        for(size_t i=0;i<sizeof(*outputs[n]);++i) if(bytes[i]!=value) failed=1;
    }
done:
    free(closed);st_storage_share_ids_free(&revoked);finish(&f);
    printf("%s direct client mutation coordination: scenario=%d\n",failed?"FAIL":"PASS",scenario);
    return failed;
}

static int direct_client_create(int scenario)
{
    fixture f;
    int failed=fresh(&f);
    st_storage_management_user user,other;
    st_storage_client output,created={0},duplicate={0};
    st_storage_share_builtin_admin builtin={"builtin","default",1};
    st_storage_client_credential credential;
    if(failed) goto done;
    if(st_storage_create_management_user(f.path,"alice","default","fixture-only-hash","USER",1,&user)!=0
        || st_storage_create_management_user(f.path,"bob","default","fixture-only-hash","ADMIN",1,&other)!=0) { failed=1;goto done; }
    st_storage_management_actor actor={"alice","default",user.account_key};
    const st_storage_management_actor *resolved=&actor;
    st_storage_client *published=&output;
    const char *name="direct-created-client",*owner="alice",*change=NULL;
    int expected=0,rate=9,enabled=scenario==1?7:0;
    char oversized[257];memset(oversized,'n',sizeof(oversized)-1);oversized[sizeof(oversized)-1]='\0';
    switch(scenario) {
        case 0: break;
        case 1: actor=(st_storage_management_actor){"BuIlTiN","default",""};owner="builtin";break;
        case 2: actor.account_key=other.account_key;expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 3: actor.account_key="";expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 4: resolved=NULL;expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 5: actor=(st_storage_management_actor){"builtin","DEFAULT",""};expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 6: name="";expected=-1;break;
        case 7: name=oversized;expected=-1;break;
        case 8:
            if(st_storage_upsert_client(f.path,0,"foreign",name,"bob",1,7,&duplicate)!=0) { failed=1;goto done; }
            expected=ST_STORAGE_CLIENT_NAME_EXISTS;break;
        case 9:
            change="CREATE TRIGGER malformed_client_create AFTER INSERT ON client_account BEGIN UPDATE client_account SET owner_username=printf('%0300d',0) WHERE rowid=NEW.rowid; END";
            expected=-1;break;
        case 10:
            change="CREATE TRIGGER wrong_client_create_owner AFTER INSERT ON client_account BEGIN UPDATE client_account SET owner_username='bob' WHERE rowid=NEW.rowid; END";
            expected=-1;published=NULL;break;
        case 11: published=NULL;break;
        case 12:
            change="CREATE TRIGGER wrong_client_create_tenant AFTER INSERT ON client_account BEGIN UPDATE client_account SET tenant_id='foreign' WHERE rowid=NEW.rowid; END";
            expected=-1;break;
        case 13:
            change="CREATE TRIGGER fail_client_create BEFORE INSERT ON client_account BEGIN SELECT RAISE(ABORT,'injected create failure'); END";
            expected=-1;break;
        case 14: rate=-5;break;
        case 15:
            change="CREATE TRIGGER empty_client_create_time AFTER INSERT ON client_account BEGIN UPDATE client_account SET created_at='' WHERE rowid=NEW.rowid; END";
            expected=-1;break;
        case 16:
            change="UPDATE specus_management_user SET enabled=0 WHERE login_name='alice'";
            expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        case 17:
            actor=(st_storage_management_actor){"builtin","default",""};builtin.accepted=0;
            expected=ST_STORAGE_MANAGEMENT_ACTOR_CHANGED;break;
        default: failed=1;goto done;
    }
    if(change!=NULL && execute(f.db,change)!=0) { failed=1;goto done; }
    memset(&output,0x7f,sizeof(output));
    int rc=st_storage_create_client_current_actor(f.path,resolved,&builtin,name,enabled,rate,published);
    if(rc!=expected || scalar(f.db,"SELECT COUNT(*) FROM client_account")!=((rc==0 || scenario==8)?1:0)
        || scalar(f.db,"SELECT COUNT(*) FROM specus_client_identity")!=0
        || scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_device")!=0
        || st_storage_get_client_credential(f.path,f.credential.id,&credential)!=0 || !same_credential(&f.credential,&credential,1)) {
        fprintf(stderr,"direct client create scenario=%d rc=%d expected=%d\n",scenario,rc,expected);failed=1;goto done;
    }
    if(rc==0) {
        if(st_storage_get_client_by_name(f.path,name,&created)!=0 || created.id<=0
            || strcmp(created.tenant_id,"default")!=0 || strcmp(created.owner_username,owner)!=0
            || created.enabled!=(enabled!=0) || created.connection_rate_limit_per_minute!=(rate<=0?30:rate)
            || created.created_at[0]=='\0' || created.updated_at[0]=='\0'
            || (published!=NULL && !same_client_state(&created,published,1))) failed=1;
    } else if(scenario==8 && (st_storage_get_client(f.path,duplicate.id,&created)!=0 || !same_client_state(&duplicate,&created,1))) failed=1;
    if(rc!=0 || published==NULL) {
        const unsigned char *bytes=(const unsigned char *)&output;
        unsigned char wanted=published==NULL?0x7f:0;
        for(size_t i=0;i<sizeof(output);++i) if(bytes[i]!=wanted) failed=1;
    }
done:
    finish(&f);
    printf("%s direct client create coordination: scenario=%d\n",failed?"FAIL":"PASS",scenario);
    return failed;
}

static int current_peer_permission(int scenario)
{
    fixture f;int failed=fresh(&f);
    st_storage_client source={0},target={0};
    st_storage_peer_mesh_device device;
    if(failed) goto done;
    if(st_storage_upsert_client(f.path,0,"default","current-source","alice",1,30,&source)!=0
        || st_storage_upsert_client(f.path,0,"default","current-target","alice",1,30,&target)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&source,1,&device)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&target,1,&device)!=0) { failed=1;goto done; }
    char change[800];change[0]='\0';int expected=0,rejected=0;
    switch(scenario) {
        case 0: expected=1;break;
        case 1: case 3: case 8: case 11:
            snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld",source.id);break;
        case 2: snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld",target.id);break;
        case 4: snprintf(change,sizeof(change),"UPDATE client_account SET enabled=0 WHERE rowid=%lld",target.id);break;
        case 5: snprintf(change,sizeof(change),"DELETE FROM client_account WHERE rowid=%lld",source.id);rejected=1;break;
        case 6: case 7:
            snprintf(change,sizeof(change),"UPDATE client_account SET tenant_id='foreign' WHERE rowid=%lld",scenario==6?target.id:source.id);rejected=1;break;
        case 9: source.enabled=0;expected=1;break;
        case 10: strcpy(target.owner_username,"bob");expected=1;break;
        default: failed=1;goto done;
    }
    if(change[0]!='\0' && execute(f.db,change)!=0) { failed=1;goto done; }
    if(scenario==3 || scenario==11) {
        if(st_storage_upsert_peer_mesh_acl(f.path,"default","policy-admin",scenario==3?&source:&target,
            scenario==3?&target:&source,1,scenario==3?"OUTBOUND":"INBOUND",NULL)!=0) { failed=1;goto done; }
        expected=1;
    }
    if(scenario==8) { strcpy(source.owner_username,"forged");strcpy(target.owner_username,"forged"); }
    int allowed=77;
    int rc=st_storage_can_peer(f.path,&source,&target,&allowed);
    if((rejected?rc>=0:rc!=0) || allowed!=expected) {
        fprintf(stderr,"current Peer permission scenario=%d rc=%d allowed=%d expected=%d\n",scenario,rc,allowed,expected);failed=1;
    }
done:
    finish(&f);printf("%s current Peer permission: scenario=%d\n",failed?"FAIL":"PASS",scenario);return failed;
}

/* Real library entry point in another process, paused after its first real client read
 * closes. Fixture changes are committed before resume, with no application test hook. */
static int runtime_config_race(int scenario)
{
    fixture f;int failed=fresh(&f),ready_fd=-1,resume_fd=-1;
    pid_t child=-1;
    char ready[256],resume[256],output[256],client_id[40],preload[1024],change[800];
    snprintf(ready,sizeof(ready),"%s/config-ready",f.dir);snprintf(resume,sizeof(resume),"%s/config-resume",f.dir);
    snprintf(output,sizeof(output),"%s/config.json",f.dir);
    st_storage_client source={0},old_peer={0},new_peer={0};
    st_storage_peer_mesh_device source_device,old_device,new_device;
    if(failed) goto done;
    if(st_storage_upsert_client(f.path,0,"default","runtime-source","alice",1,30,&source)!=0
        || st_storage_upsert_client(f.path,0,"default","runtime-old-peer","alice",1,30,&old_peer)!=0
        || st_storage_upsert_client(f.path,0,"default","runtime-new-peer","bob",1,30,&new_peer)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&source,1,&source_device)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&old_peer,1,&old_device)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&new_peer,1,&new_device)!=0) { failed=1;goto done; }
    st_storage_peer_mesh_service service={.tenant_id="default",.client_id=source.id,.client_name="runtime-source",
        .service_id="runtime-service-1",.name="runtime service",.transport="tcp",.application="http",
        .target_host="127.0.0.1",.target_port=8080,.published_port=18080,.path="/",.enabled=1,.visibility="OWNER"};
    if(st_storage_upsert_peer_mesh_service(f.path,&service,NULL)!=0
        || st_storage_upsert_peer_mesh_service_sharing(f.path,"default",1,1,"fixture",NULL)!=0
        || mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) { failed=1;goto done; }
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(ready_fd<0 || resume_fd<0) { failed=1;goto done; }
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"%s",barrier_library);
    snprintf(client_id,sizeof(client_id),"%lld",source.id);
    child=fork();
    if(child==0) {
        setenv("LD_PRELOAD",preload,1);setenv("SPECUS_TEST_AUTH_BARRIER_READY",ready,1);
        setenv("SPECUS_TEST_AUTH_BARRIER_RESUME",resume,1);setenv("SPECUS_TEST_AUTH_BARRIER_CLIENT_ID",client_id,1);
        unsetenv("SPECUS_TEST_AUTH_BARRIER_ACCOUNT");unsetenv("SPECUS_TEST_AUTH_BARRIER_KEY");
        if(scenario==8) { unsetenv("SPECUS_TEST_AUTH_BARRIER_CLIENT_ID");setenv("SPECUS_TEST_AUTH_BARRIER_CONFIG_SNAPSHOT","1",1); }
        else unsetenv("SPECUS_TEST_AUTH_BARRIER_CONFIG_SNAPSHOT");
        setenv("SPECUS_PEER_MESH_ENABLED",scenario==6?"false":"true",1);
        execl("/proc/self/exe","peer-config-test","--peer-config",f.path,source.client_name,output,scenario==7?"1":"2",(char *)NULL);
        _exit(95);
    }
    if(child<0) { failed=1;goto done; }
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,5000); } while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') { fprintf(stderr,"runtime config missed closed-read barrier\n");failed=1;goto done; }
    switch(scenario) {
        case 0: snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld",source.id);break;
        case 1: snprintf(change,sizeof(change),"UPDATE client_account SET client_name='current-runtime-name',owner_username='bob' WHERE rowid=%lld",source.id);break;
        case 2: case 6: snprintf(change,sizeof(change),"DELETE FROM client_account WHERE rowid=%lld",source.id);break;
        case 3: snprintf(change,sizeof(change),"UPDATE client_account SET tenant_id='foreign' WHERE rowid=%lld",source.id);break;
        case 4: snprintf(change,sizeof(change),"UPDATE client_account SET enabled=0 WHERE rowid=%lld",source.id);break;
        case 5: strcpy(change,"CREATE TRIGGER fail_config_ensure BEFORE UPDATE ON peer_mesh_device BEGIN SELECT RAISE(ABORT,'injected config failure'); END");break;
        case 7: change[0]='\0';break;
        case 8: {
            /* No timer race: an actual independent writer must be refused while the
             * snapshot is paused inside its real sharing-row read. */
            sqlite3_busy_timeout(f.db,0);
            int attempt=sqlite3_exec(f.db,"BEGIN IMMEDIATE",NULL,NULL,NULL);
            if(attempt==SQLITE_OK) (void)sqlite3_exec(f.db,"ROLLBACK",NULL,NULL,NULL);
            sqlite3_busy_timeout(f.db,5000);
            if(attempt!=SQLITE_BUSY) { fprintf(stderr,"runtime snapshot did not hold the writer fence: rc=%d\n",attempt);failed=1;goto done; }
            change[0]='\0';break;
        }
        default: failed=1;goto done;
    }
    if(change[0]!='\0' && execute(f.db,change)!=0) { failed=1;goto done; }
    if(write(resume_fd,"C",1)!=1) { failed=1;goto done; }
    int status=0;
    if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status)!=0) { child=-1;failed=1;goto done; }
    child=-1;
    FILE *input=fopen(output,"rb");char config[16384];
    if(input==NULL) { failed=1;goto done; }
    size_t length=fread(config,1,sizeof(config)-1,input);config[length]='\0';
    int io_failed=ferror(input) || length==sizeof(config)-1;fclose(input);
    if(io_failed) { failed=1;goto done; }
    if(scenario>=2 && scenario<=6) failed=strcmp(config,"null")!=0;
    else if(scenario==7) failed=strstr(config,"\"localServices\":[]")==NULL;
    else {
        char allowed[160];snprintf(allowed,sizeof(allowed),"\"allowedPeerVirtualIps\":[\"%s\"]",scenario==8?old_device.virtual_ip:new_device.virtual_ip);
        failed=strstr(config,allowed)==NULL || strstr(config,scenario==8?new_device.virtual_ip:old_device.virtual_ip)!=NULL;
        if(scenario==1 && strstr(config,"\"clientName\":\"current-runtime-name\"")==NULL) failed=1;
    }
    if(failed) fprintf(stderr,"runtime config scenario=%d inconsistent metadata/grants (credential fields omitted)\n",scenario);
    if(scenario==8 && (execute(f.db,"BEGIN IMMEDIATE")!=0 || execute(f.db,"ROLLBACK")!=0)) failed=1;
done:
    if(child>0) { if(write(resume_fd,"C",1)!=1)fprintf(stderr,"config resume failed\n");int status=0;waitpid(child,&status,0); }
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    unlink(ready);unlink(resume);unlink(output);finish(&f);
    printf("%s current runtime config: scenario=%d\n",failed?"FAIL":"PASS",scenario);return failed;
}

static int direct_runtime_snapshot(int scenario)
{
    fixture f;int failed=fresh(&f);
    st_storage_client source={0},old_peer={0},new_peer={0},current={0};
    st_storage_peer_mesh_device source_device,old_device,new_device;
    st_storage_peer_mesh_config snapshot={0};
    if(failed) goto done;
    if(st_storage_upsert_client(f.path,0,"default","snapshot-source","alice",1,30,&source)!=0
        || st_storage_upsert_client(f.path,0,"default","snapshot-old-peer","alice",1,30,&old_peer)!=0
        || st_storage_upsert_client(f.path,0,"default","snapshot-new-peer","bob",1,30,&new_peer)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&source,1,&source_device)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&old_peer,1,&old_device)!=0
        || st_storage_update_peer_mesh_device_enabled(f.path,&new_peer,1,&new_device)!=0) { failed=1;goto done; }
    st_storage_peer_mesh_service service={.tenant_id="default",.client_id=source.id,.client_name="snapshot-source",
        .service_id="snapshot-service-1",.name="snapshot service",.transport="tcp",.application="http",
        .target_host="127.0.0.1",.target_port=8080,.published_port=18080,.path="/",.enabled=1,.visibility="OWNER"};
    st_storage_peer_mesh_service created_service;
    if(st_storage_upsert_peer_mesh_service(f.path,&service,&created_service)!=0
        || st_storage_upsert_peer_mesh_service_sharing(f.path,"default",1,1,"fixture",NULL)!=0) { failed=1;goto done; }
    service.id=created_service.id;
    const st_storage_client *cached=&source;
    int expected=0,ensure=1,services=1;
    char change[1400];change[0]='\0';
    switch(scenario) {
        case 0: snprintf(change,sizeof(change),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld",source.id);break;
        case 1: snprintf(change,sizeof(change),"DELETE FROM peer_mesh_device WHERE client_id=%lld",source.id);ensure=0;break;
        case 2: snprintf(change,sizeof(change),"DELETE FROM client_account WHERE rowid=%lld",source.id);expected=-1;break;
        case 3: snprintf(change,sizeof(change),"UPDATE client_account SET tenant_id='foreign' WHERE rowid=%lld",source.id);expected=-1;break;
        case 4: snprintf(change,sizeof(change),"UPDATE client_account SET enabled=0 WHERE rowid=%lld",source.id);expected=-1;break;
        case 5:
            snprintf(change,sizeof(change),"DELETE FROM peer_mesh_device WHERE client_id=%lld; UPDATE peer_mesh_service_sharing SET updated_by=printf('%%0300d',0)",source.id);expected=-1;break;
        case 6:
            strcpy(change,"CREATE TRIGGER bad_snapshot_device AFTER UPDATE ON peer_mesh_device BEGIN UPDATE peer_mesh_device SET owner_username='wrong' WHERE id=NEW.id; END");expected=-1;break;
        case 7:
            snprintf(change,sizeof(change),"DELETE FROM peer_mesh_device WHERE client_id=%lld; UPDATE peer_mesh_shared_service SET description=printf('%%0400d',0)",source.id);expected=-1;break;
        case 8: cached=NULL;expected=-1;break;
        case 9: strcpy(change,"UPDATE peer_mesh_shared_service SET description=printf('%0400d',0)");services=0;break;
        case 10:
            strcpy(service.visibility,"TENANT");snprintf(service.allowed_client_ids,sizeof(service.allowed_client_ids),"%lld",new_peer.id);
            if(st_storage_upsert_peer_mesh_service(f.path,&service,NULL)!=0
                || st_storage_upsert_peer_mesh_acl(f.path,"default","policy-admin",&source,&new_peer,1,"OUTBOUND",NULL)!=0) { failed=1;goto done; }
            break;
        case 11: strcpy(change,"UPDATE peer_mesh_shared_service SET enabled=0");break;
        case 12:
            strcpy(change,"WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<300) INSERT INTO client_account(tenant_id,client_name,owner_username) SELECT 'default',printf('bulk-%03d',x),'alice' FROM n; INSERT INTO peer_mesh_device(tenant_id,owner_username,client_id,client_name,enabled,virtual_ip,cidr) SELECT tenant_id,owner_username,rowid,client_name,1,printf('100.120.%d.%d',rowid/250,rowid%250+1),'100.96.0.0/11' FROM client_account WHERE client_name LIKE 'bulk-%'");break;
        default: failed=1;goto done;
    }
    if(change[0]!='\0' && execute(f.db,change)!=0) { failed=1;goto done; }
    long long peer_count=scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_device");
    snapshot.client.id=-77;
    int rc=st_storage_load_peer_mesh_config(f.path,cached,ensure,services,&snapshot);
    if(rc!=expected || scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_device")!=peer_count) { fprintf(stderr,"snapshot scenario=%d rc=%d expected=%d\n",scenario,rc,expected);failed=1;goto done; }
    if(rc!=0) {
        const unsigned char *bytes=(const unsigned char *)&snapshot;
        for(size_t i=0;i<sizeof(snapshot);++i) if(bytes[i]!=0) failed=1;
        if(scenario==6 && (st_storage_get_peer_mesh_device_by_client(f.path,"default",source.id,&source_device)!=0
            || strcmp(source_device.owner_username,"alice")!=0)) failed=1;
    } else {
        if(st_storage_get_client(f.path,source.id,&current)!=0 || !same_client_state(&snapshot.client,&current,1)
            || snapshot.has_device!=ensure || !snapshot.sharing.enabled || !snapshot.sharing.mdns_import_enabled
            || snapshot.service_count!=(size_t)services) { failed=1;goto done; }
        if(ensure && (snapshot.device.client_id!=current.id || strcmp(snapshot.device.owner_username,current.owner_username)!=0)) failed=1;
        if(services) {
            size_t wanted=(scenario==1 || scenario==11)?0:scenario==12?301:1;
            if(snapshot.services[0].allowed_peer_count!=wanted) failed=1;
            if(wanted==1 && strcmp(snapshot.services[0].allowed_peer_ips[0],(scenario==0 || scenario==10)?new_device.virtual_ip:old_device.virtual_ip)!=0) failed=1;
        }
    }
done:
    st_storage_peer_mesh_config_free(&snapshot);
    const unsigned char *bytes=(const unsigned char *)&snapshot;
    for(size_t i=0;i<sizeof(snapshot);++i) if(bytes[i]!=0) failed=1;
    finish(&f);printf("%s direct runtime snapshot: scenario=%d\n",failed?"FAIL":"PASS",scenario);return failed;
}

#include "management_ws_coordination_tests.h"
#include "peer_session_coordination_tests.h"

int main(int argc,char **argv)
{
    if(argc>=2 && strcmp(argv[1],"--peer-session-create")==0) return peer_session_create_child(argc,argv);
    if(argc==6 && strcmp(argv[1],"--peer-config")==0) {
        char *config=st_peer_mesh_build_login_config(argv[2],argv[3],atoi(argv[5]));
        FILE *output=fopen(argv[4],"wb");
        if(output==NULL) { free(config);return 96; }
        int failed=fputs(config==NULL?"null":config,output)==EOF;
        if(fclose(output)!=0) failed=1;
        free(config);return failed?97:0;
    }
    if(argc!=3)return 2;
    server_binary=argv[1];barrier_library=argv[2];signal(SIGPIPE,SIG_IGN);setvbuf(stdout,NULL,_IOLBF,0);
    int failed=peer_session_port_pair_fixture();struct {const char *name;int(*run)(fixture *);} tests[]={
        {"fresh-owner",stale_owner},{"rollback-new",rollback_new},{"disabled",disabled},{"key-rotated",changed_key},{"secret-rotated",changed_secret},{"tenant-moved",changed_tenant},{"deleted",deleted},{"corrupt-existing",corrupt_existing},{"concurrent",concurrent},
        {"no-implicit-transfer",existing_owner_is_not_implicitly_transferred},{"rollback-existing",rollback_existing},{"missing-existing-client",missing_existing_client}};
    for(size_t i=0;i<sizeof(tests)/sizeof(tests[0]);++i){fixture f;int result=fresh(&f);if(!result)result=tests[i].run(&f);finish(&f);failed+=result;printf("%s storage auth coordination: %s\n",result?"FAIL":"PASS",tests[i].name);}
    failed+=native_race("ownership","UPDATE specus_client_credential SET owner_username='bob'",200);
    failed+=native_race("current-policy","UPDATE specus_client_credential SET owner_username='bob',max_online_instances=2",200);
    failed+=native_race("disabled","UPDATE specus_client_credential SET enabled=0",403);
    failed+=native_race("key-rotated","UPDATE specus_client_credential SET api_key='rotated-key'",401);
    failed+=native_race("secret-rotated","UPDATE specus_client_credential SET secret_hash=printf('%064d',0)",401);
    failed+=native_race("deleted","DELETE FROM specus_client_credential",401);
    for (int operation = 0; operation < 3; ++operation)
        for (int scenario = 0; scenario < 4; ++scenario)
            failed += peer_coordination_case(operation, scenario);
    failed += peer_coordination_case(1, 4);
    failed += peer_coordination_case(2, 4);
    failed += peer_coordination_case(2, 5);
    for (int operation = 0; operation < 3; ++operation) failed += peer_current_capabilities(operation);
    for (int scenario=0;scenario<10;++scenario)
        for(int deleting=0;deleting<2;++deleting) failed+=native_credential_race(deleting,scenario);
    for (int scenario=10;scenario<=12;++scenario) failed+=native_credential_race(0,scenario);
    failed+=native_credential_race(1,13);
    failed+=native_credential_race(0,14);
    failed+=native_credential_race(1,14);
    for(int scenario=0;scenario<10;++scenario) failed+=direct_credential_coordination(scenario);
    for(int scenario=0;scenario<14;++scenario) failed+=native_credential_create_race(scenario);
    for(int scenario=0;scenario<16;++scenario) failed+=direct_credential_create_coordination(scenario);
    for(int scenario=0;scenario<15;++scenario)
        for(int deleting=0;deleting<2;++deleting) if(!(scenario==12 && deleting)) failed+=native_client_mutation_race(deleting,scenario);
    for(int scenario=0;scenario<17;++scenario) failed+=direct_client_mutation(scenario);
    for(int scenario=0;scenario<17;++scenario) failed+=native_client_create_race(scenario);
    for(int scenario=0;scenario<18;++scenario) failed+=direct_client_create(scenario);
    for(int scenario=0;scenario<12;++scenario) failed+=current_peer_permission(scenario);
    for(int scenario=0;scenario<9;++scenario) failed+=runtime_config_race(scenario);
    for(int scenario=0;scenario<13;++scenario) failed+=direct_runtime_snapshot(scenario);
    for(int messages=0;messages<2;++messages)
        for(int scenario=0;scenario<6;++scenario) failed+=management_post_registration(messages,scenario);
    for(int mode=0;mode<5;++mode)
        for(int admin=0;admin<2;++admin) failed+=management_owner_visibility(admin,mode);
    for(int scenario=0;scenario<17;++scenario)
        for(int null_output=0;null_output<2;++null_output) failed+=direct_peer_session_creation(scenario,null_output);
    for(int scenario=0;scenario<3;++scenario)
        for(int null_output=0;null_output<2;++null_output) failed+=peer_session_transfer_interleaving(scenario,null_output);
    return failed?1:0;
}
