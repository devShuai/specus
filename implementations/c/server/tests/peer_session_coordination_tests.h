#ifndef SPECUS_PEER_SESSION_COORDINATION_TESTS_H
#define SPECUS_PEER_SESSION_COORDINATION_TESTS_H
#include "owner_transfer.h"
#include <arpa/inet.h>
#include <sys/socket.h>

static int peer_session_port_pair_fixture(void)
{
    int ports[2]={0};
    CHECK(pick_free_port_pair(NULL,&ports[1])<0 && pick_free_port_pair(&ports[0],&ports[0])<0, "invalid pair arguments");
    CHECK(pick_free_port_pair(&ports[0],&ports[1])==0 && ports[0]>0 && ports[1]>0 && ports[0]!=ports[1], "distinct endpoint candidates");
    int sockets[2]={-1,-1},failed=0;
    for (size_t i=0;i<2;++i) {
        sockets[i]=socket(AF_INET,SOCK_STREAM,0);
        struct sockaddr_in address={.sin_family=AF_INET,.sin_addr={.s_addr=htonl(INADDR_LOOPBACK)},.sin_port=htons((uint16_t)ports[i])};
        if (sockets[i]<0 || bind(sockets[i],(struct sockaddr *)&address,sizeof(address))!=0) failed=1;
    }
    for (size_t i=0;i<2;++i) if (sockets[i]>=0) close(sockets[i]);
    printf("%s simultaneous distinct test endpoint allocation\n",failed?"FAIL":"PASS");
    return failed;
}

static int peer_session_fixture(fixture *f, st_storage_client *source, st_storage_client *target)
{
    CHECK(fresh(f) == 0, "fresh Peer-session database");
    st_storage_management_user bob = {0};
    st_storage_peer_mesh_device device = {0};
    CHECK(st_storage_create_management_user(f->path, "bob", "default", "fixture-only-hash", "USER", 1, &bob) == 0
        && st_storage_upsert_client(f->path, 0, "default", "session-source", "alice", 1, 30, source) == 0
        && st_storage_upsert_client(f->path, 0, "default", "session-target", "alice", 1, 30, target) == 0
        && st_storage_update_peer_mesh_device_enabled(f->path, source, 1, &device) == 0
        && st_storage_update_peer_mesh_device_enabled(f->path, target, 1, &device) == 0, "Peer endpoints/current target");
    return 0;
}

/* Exercise the actual unpublished transfer transaction, never an ownership SQL fixture. */
static int peer_session_transfer(fixture *f, long long client_id, st_storage_owner_transfer_result *result)
{
    st_owner_snapshot snapshot = {0};
    char *preview = NULL, revision[65], request[256]; const char *code = NULL;
    if (st_owner_snapshot_load(f->path, "default", 0, client_id, &snapshot) != 0) return 500;
    int status = st_owner_transfer_preview("default", 1, 0, client_id, &snapshot, &preview, revision, &code);
    free(preview); st_owner_snapshot_free(&snapshot);
    if (status != 200) return status;
    snprintf(request, sizeof(request), "{\"scope\":\"single\",\"targetUsername\":\"bob\",\"expectedRevision\":\"%s\"}", revision);
    st_storage_management_actor actor = {"transfer-admin", "default", ""};
    st_storage_share_builtin_admin builtin = {"transfer-admin", "default", 1};
    return st_storage_transfer_owner(f->path, &actor, &builtin, 0, client_id, request, wall_clock_ms(), result, &code);
}

static int direct_peer_session_creation(int scenario, int null_output)
{
    fixture f; st_storage_client source = {0}, target = {0};
    int failed = peer_session_fixture(&f, &source, &target), expected = 0;
    st_storage_peer_mesh_session result = {.id=-77};
    st_storage_owner_transfer_result transfer = {0};
    char change[1024] = {0}; const char *path_type = "RELAY";
    if (failed) goto done;
    switch (scenario) {
        case 0: snprintf(change,sizeof(change),"UPDATE client_account SET client_name='current-source' WHERE rowid=%lld; UPDATE client_account SET client_name='current-target' WHERE rowid=%lld",source.id,target.id);break;
        case 1: strcpy(source.client_name,"forged-source");strcpy(target.client_name,"forged-target");break;
        case 2: case 3:
            if (scenario == 3 && st_storage_upsert_peer_mesh_acl(f.path,"default","independent-policy",&source,&target,1,"OUTBOUND",NULL) != 0) { failed=1;goto done; }
            if (peer_session_transfer(&f,source.id,&transfer) != 200) { failed=1;goto done; }
            expected = scenario == 2 ? -1 : 0;break;
        case 4: snprintf(change,sizeof(change),"DELETE FROM client_account WHERE rowid=%lld",source.id);expected=-1;break;
        case 5: snprintf(change,sizeof(change),"UPDATE client_account SET tenant_id='foreign' WHERE rowid=%lld",source.id);expected=-1;break;
        case 6: snprintf(change,sizeof(change),"UPDATE client_account SET enabled=0 WHERE rowid=%lld",target.id);expected=-1;break;
        case 7: snprintf(change,sizeof(change),"UPDATE peer_mesh_device SET enabled=0 WHERE client_id=%lld",target.id);expected=-1;break;
        case 8: strcpy(change,"CREATE TRIGGER corrupt_session AFTER INSERT ON peer_mesh_session BEGIN UPDATE peer_mesh_session SET source_client_name=printf('%0300d',0) WHERE id=NEW.id; END");expected=-1;break;
        case 9: strcpy(change,"CREATE TRIGGER corrupt_session AFTER INSERT ON peer_mesh_session BEGIN UPDATE peer_mesh_session SET token_hash='changed-token' WHERE id=NEW.id; END");expected=-1;break;
        case 10: strcpy(change,"CREATE TRIGGER corrupt_session AFTER INSERT ON peer_mesh_session BEGIN UPDATE client_account SET owner_username='intruder' WHERE rowid=NEW.source_client_id; END");expected=-1;break;
        case 11: strcpy(change,"CREATE TRIGGER corrupt_session AFTER INSERT ON peer_mesh_session BEGIN DELETE FROM peer_mesh_session WHERE id=NEW.id; END");expected=-1;break;
        case 12: strcpy(change,"CREATE TRIGGER corrupt_session BEFORE INSERT ON peer_mesh_session BEGIN SELECT RAISE(ABORT,'injected session failure'); END");expected=-1;break;
        case 13: strcpy(change,"CREATE TRIGGER corrupt_session AFTER INSERT ON peer_mesh_session BEGIN UPDATE peer_mesh_session SET status=printf('%060d',0) WHERE id=NEW.id; END");expected=-1;break;
        case 14: path_type=NULL;break;
        case 15: strcpy(source.tenant_id,"foreign");expected=-1;break;
        case 16: target=source;expected=-1;break;
        default: failed=1;goto done;
    }
    if (change[0] != '\0' && execute(f.db,change) != 0) { failed=1;goto done; }
    int rc = st_storage_create_peer_mesh_session(f.path,&source,&target,path_type,"session-token-hash",60,null_output?NULL:&result);
    if (rc != expected) { fprintf(stderr,"session scenario%d null%d rc%d expected%d\n",scenario,null_output,rc,expected);failed=1;goto done; }
    if (rc != 0) {
        if (scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_session") != 0) { failed=1;goto done; }
        if (!null_output) {
            const unsigned char *bytes=(const unsigned char *)&result;
            for (size_t i=0;i<sizeof(result);++i) if (bytes[i]!=0) failed=1;
        }
        if (scenario==10 && scalar(f.db,"SELECT COUNT(*) FROM client_account WHERE owner_username='intruder'")!=0) failed=1;
    } else {
        st_storage_client current_source={0},current_target={0};
        st_storage_peer_mesh_session stored={0};
        long long id=scalar(f.db,"SELECT id FROM peer_mesh_session");
        if (scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_session")!=1
            || st_storage_get_client(f.path,source.id,&current_source)!=0
            || st_storage_get_client(f.path,target.id,&current_target)!=0
            || st_storage_get_peer_mesh_session(f.path,"default",id,&stored)!=0
            || strcmp(stored.source_client_name,current_source.client_name)!=0
            || strcmp(stored.target_client_name,current_target.client_name)!=0
            || stored.source_client_id!=source.id || stored.target_client_id!=target.id
            || strcmp(stored.path_type,path_type==NULL?"DIRECT":path_type)!=0
            || strcmp(stored.status,"NEGOTIATING")!=0 || stored.expires_at[0]=='\0') { failed=1;goto done; }
        if (!null_output && (result.id!=id || strcmp(result.source_client_name,stored.source_client_name)!=0
            || strcmp(result.target_client_name,stored.target_client_name)!=0)) failed=1;
    }
done:
    st_storage_owner_transfer_result_free(&transfer);finish(&f);
    printf("%s current Peer-session creation: scenario=%d null-output=%d\n",failed?"FAIL":"PASS",scenario,null_output);
    return failed;
}

static int peer_session_create_child(int argc,char **argv)
{
    if (argc!=7) return 98;
    st_storage_client source={0},target={0};st_storage_peer_mesh_session session={0};
    if (st_storage_get_client(argv[2],strtoll(argv[3],NULL,10),&source)!=0
        || st_storage_get_client(argv[2],strtoll(argv[4],NULL,10),&target)!=0) return 99;
    int rc=st_storage_create_peer_mesh_session(argv[2],&source,&target,"DIRECT","interleaving-token",60,atoi(argv[5])?NULL:&session);
    if (rc!=atoi(argv[6]) || (rc==0 && !atoi(argv[5]) && session.id<=0)) return 100;
    return 0;
}

/* Pause AFTER the real authorization connection closes, holding no SQLite lock.
 * Old code inserts later; coordinated code has already committed. Assert the valid
 * final grant/session ordering, not that an earlier legitimate result sees the future. */
static int peer_session_transfer_interleaving(int scenario,int null_output)
{
    fixture f;st_storage_client source={0},target={0};
    int failed=peer_session_fixture(&f,&source,&target),ready_fd=-1,resume_fd=-1;
    pid_t child=-1;char ready[220],resume[220],preload[1024],source_id[32],target_id[32];
    st_storage_owner_transfer_result transfer={0};
    snprintf(ready,sizeof(ready),"%s/peer-ready",f.dir);snprintf(resume,sizeof(resume),"%s/peer-resume",f.dir);
    if (failed) goto done;
    if (scenario==1 && st_storage_upsert_peer_mesh_acl(f.path,"default","independent-policy",&source,&target,1,"OUTBOUND",NULL)!=0) { failed=1;goto done; }
    if (scenario==2 && execute(f.db,"CREATE TRIGGER fail_transfer BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'injected transfer failure'); END")!=0) { failed=1;goto done; }
    if (mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) { failed=1;goto done; }
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if (ready_fd<0 || resume_fd<0) { failed=1;goto done; }
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if (asan!=NULL && dladdr(asan,&sanitizer)!=0 && sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"%s",barrier_library);
    snprintf(source_id,sizeof(source_id),"%lld",source.id);snprintf(target_id,sizeof(target_id),"%lld",target.id);
    child=fork();
    if (child==0) {
        setenv("LD_PRELOAD",preload,1);setenv("SPECUS_TEST_AUTH_BARRIER_READY",ready,1);
        setenv("SPECUS_TEST_AUTH_BARRIER_RESUME",resume,1);setenv("SPECUS_TEST_AUTH_BARRIER_PEER_SESSION","1",1);
        unsetenv("SPECUS_TEST_AUTH_BARRIER_KEY");unsetenv("SPECUS_TEST_AUTH_BARRIER_ACCOUNT");
        unsetenv("SPECUS_TEST_AUTH_BARRIER_WS_ACCOUNT");unsetenv("SPECUS_TEST_AUTH_BARRIER_CLIENT_ID");
        unsetenv("SPECUS_TEST_AUTH_BARRIER_CONFIG_SNAPSHOT");
        execl("/proc/self/exe","peer-session-test","--peer-session-create",f.path,source_id,target_id,null_output?"1":"0","0",(char *)NULL);
        _exit(95);
    }
    if (child<0) { failed=1;goto done; }
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,5000); } while(polled<0 && errno==EINTR);
    char signal=0;
    if (polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') { fprintf(stderr,"Peer-session creation missed actual closed-auth barrier\n");failed=1;goto done; }
    int status=peer_session_transfer(&f,source.id,&transfer);
    if (status!=(scenario==2?500:200)) { fprintf(stderr,"interleaved real transfer status%d\n",status);failed=1;goto done; }
    if (write(resume_fd,"C",1)!=1) { failed=1;goto done; }
    int child_status=0;
    if (waitpid(child,&child_status,0)!=child || !WIFEXITED(child_status) || WEXITSTATUS(child_status)!=0) { child=-1;failed=1;goto done; }
    child=-1;
    if (scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_session")!=1
        || scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_session WHERE status<>'CLOSED'")!=(scenario==0?0:1)
        || scalar(f.db,"SELECT COUNT(*) FROM client_owner_transfer_audit")!=(scenario==2?0:1)
        || scalar(f.db,"SELECT COUNT(*) FROM client_account WHERE owner_username='bob'")!=(scenario==2?0:1)) { failed=1;goto done; }
    if (scenario==0 && (transfer.closed_count!=1 || transfer.closed[0].source_client_id!=source.id
        || transfer.closed[0].target_client_id!=target.id)) { failed=1;goto done; }
    if (scenario!=0 && transfer.closed_count!=0) { failed=1;goto done; }
    st_storage_client current_source={0};int allowed=-1;
    if (st_storage_get_client(f.path,source.id,&current_source)!=0
        || st_storage_can_peer(f.path,&current_source,&target,&allowed)!=0 || allowed!=(scenario==0?0:1)) failed=1;
done:
    if (child>0) { if (write(resume_fd,"C",1)!=1) fprintf(stderr,"Peer-session child resume failed\n");int status=0;waitpid(child,&status,0); }
    st_storage_owner_transfer_result_free(&transfer);
    if (ready_fd>=0) close(ready_fd);
    if (resume_fd>=0) close(resume_fd);
    unlink(ready);unlink(resume);finish(&f);
    printf("%s actual transfer versus Peer-session creation: scenario=%d null-output=%d\n",failed?"FAIL":"PASS",scenario,null_output);
    return failed;
}
#endif
