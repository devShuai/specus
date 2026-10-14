#define _GNU_SOURCE
#include "storage.h"
#include "crypto.h"
#include "json.h"
#include "server_harness.h"
#include "security.h"
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
    return failed?1:0;
}
