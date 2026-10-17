#define _POSIX_C_SOURCE 200809L
#include "owner_transfer.h"
#include "peer_mesh.h"
#include "server_harness.h"
#include "json.h"
#include <sqlite3.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct { char target[256]; char *json; } signal_record;
typedef struct {
    signal_record *records; size_t count;
    long long only_id;
    const char *fail_type;
    int failures;
} capture;
typedef struct { char dir[128],path[180]; sqlite3 *db; st_storage_client source,target,explicit_peer,foreign; } fixture;
static int sql(sqlite3 *db,const char *statement)
{
    char *error=NULL;int rc=sqlite3_exec(db,statement,NULL,NULL,&error);
    if(rc!=SQLITE_OK) fprintf(stderr,"runtime fixture SQL: %s\n",error==NULL?sqlite3_errmsg(db):error);
    sqlite3_free(error);return rc==SQLITE_OK?0:-1;
}
static long long scalar(sqlite3 *db,const char *statement)
{
    sqlite3_stmt *stmt=NULL;long long value=-1;
    if(sqlite3_prepare_v2(db,statement,-1,&stmt,NULL)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_ROW) value=sqlite3_column_int64(stmt,0);
    sqlite3_finalize(stmt);return value;
}
static int online(void *raw,long long id,const char *name)
{
    (void)name;capture *ctx=raw;return ctx->only_id==0 || ctx->only_id==id;
}
static int send_signal(void *raw,const char *target,const char *source,const char *message)
{
    capture *ctx=raw;
    if(strcmp(source,"server")!=0) return -1;
    char *type=st_json_get_top_level_string(message,"type");
    int fail=ctx->failures>0 && type!=NULL && ctx->fail_type!=NULL && strcmp(type,ctx->fail_type)==0;
    free(type);if(fail) { --ctx->failures;return -1; }
    if(ctx->count==SIZE_MAX/sizeof(*ctx->records) || strlen(target)>=sizeof(ctx->records[0].target)) return -1;
    signal_record *grown=realloc(ctx->records,(ctx->count+1)*sizeof(*grown));
    if(grown==NULL) return -1;
    ctx->records=grown;signal_record *record=&ctx->records[ctx->count];
    record->json=strdup(message);if(record->json==NULL) return -1;
    strcpy(record->target,target);++ctx->count;return 0;
}
static void clear_capture(capture *ctx)
{
    for(size_t i=0;i<ctx->count;++i) free(ctx->records[i].json);
    free(ctx->records);ctx->records=NULL;ctx->count=0;
}
static size_t signals(const capture *ctx,const char *target,const char *type,long long session)
{
    size_t count=0;
    for(size_t i=0;i<ctx->count;++i) {
        const signal_record *r=&ctx->records[i];char *actual=st_json_get_top_level_string(r->json,"type");long long id=0;
        int matches=actual!=NULL && strcmp(actual,type)==0 && (target==NULL || strcmp(target,r->target)==0)
            && (session==0 || (st_json_get_i64(r->json,"sessionId",&id)==0 && id==session));
        free(actual);if(matches) ++count;
    }
    return count;
}
static int target_user(const char *path)
{
    st_storage_management_user user={0};
    return st_storage_create_management_user(path,"bob","default","fixture-only-hash","USER",1,&user);
}
static int transfer(const char *path,long long id,const char *actor_name,st_storage_owner_transfer_result *result)
{
    st_owner_snapshot snapshot={0};char *preview=NULL,revision[65],request[256];const char *code=NULL;
    if(st_owner_snapshot_load(path,"default",0,id,&snapshot)!=0) return 500;
    int status=st_owner_transfer_preview("default",1,0,id,&snapshot,&preview,revision,&code);
    free(preview);st_owner_snapshot_free(&snapshot);if(status!=200) return status;
    snprintf(request,sizeof(request),"{\"scope\":\"single\",\"targetUsername\":\"bob\",\"expectedRevision\":\"%s\"}",revision);
    st_storage_management_actor actor={actor_name,"default",""};st_storage_share_builtin_admin builtin={actor_name,"default",1};
    return st_storage_transfer_owner(path,&actor,&builtin,0,id,request,wall_clock_ms(),result,&code);
}
static int fresh(fixture *f)
{
    CHECK(f!=NULL,"fixture output");memset(f,0,sizeof(*f));snprintf(f->dir,sizeof(f->dir),"/tmp/specus-owner-runtime-XXXXXX");
    CHECK(mkdtemp(f->dir)!=NULL,"owned directory");snprintf(f->path,sizeof(f->path),"%s/test.db",f->dir);
    CHECK(st_storage_init(f->path,0)==0 && target_user(f->path)==0 && sqlite3_open(f->path,&f->db)==SQLITE_OK,"real store");
    sqlite3_busy_timeout(f->db,5000);
    CHECK(st_storage_upsert_client(f->path,0,"default","runtime-source","alice",1,60,&f->source)==0
        && st_storage_upsert_client(f->path,0,"default","runtime-target","alice",1,60,&f->target)==0
        && st_storage_upsert_client(f->path,0,"default","runtime-explicit","alice",1,60,&f->explicit_peer)==0
        && st_storage_upsert_client(f->path,0,"foreign","runtime-foreign","alice",1,60,&f->foreign)==0,"clients");
    st_storage_peer_mesh_device device={0};
    CHECK(st_storage_update_peer_mesh_device_enabled(f->path,&f->source,1,&device)==0
        && st_storage_update_peer_mesh_device_enabled(f->path,&f->target,1,&device)==0
        && st_storage_update_peer_mesh_device_enabled(f->path,&f->explicit_peer,1,&device)==0
        && st_storage_upsert_peer_mesh_acl(f->path,"default","independent-policy",&f->source,&f->explicit_peer,1,"BOTH",NULL)==0,"Peer devices/independent grant");
    return 0;
}
static void finish(fixture *f) { sqlite3_close(f->db);unlink(f->path);rmdir(f->dir); }
static int committed_delivery(int failed_type)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");capture ctx={0};
    st_peer_mesh_runtime runtime={f.path,send_signal,online,&ctx,701,2};st_peer_mesh_owner_cursor cursor={0};
    CHECK(st_peer_mesh_owner_changes_init(f.path,&cursor)==0 && cursor.after_id==0,"bookmark before transfer");
    st_storage_peer_mesh_session lost={0},kept={0};
    CHECK(st_storage_create_peer_mesh_session(f.path,&f.source,&f.target,"DIRECT","lost-token",60,&lost)==0
        && st_storage_create_peer_mesh_session(f.path,&f.source,&f.explicit_peer,"DIRECT","kept-token",60,&kept)==0,"real sessions");
    st_storage_owner_transfer_result result={0};CHECK(transfer(f.path,f.source.id,"builtin",&result)==200 && result.closed_count==1,"actual transfer");
    ctx.fail_type=failed_type==1?"close":failed_type==2?"peer-config":NULL;ctx.failures=failed_type==1 || failed_type==2;
    if(failed_type==3) {
        setenv("SPECUS_PEER_MESH_ENABLED","false",1);
        CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)==0 && cursor.after_id==0 && ctx.count==0,"disabled feature acknowledged pending work");
        setenv("SPECUS_PEER_MESH_ENABLED","true",1);
    }
    if(failed_type==1 || failed_type==2) {
        CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)<0 && cursor.after_id==0,"failed delivery advanced cursor");
        clear_capture(&ctx);
    }
    CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)==0 && cursor.after_id==result.audit_id,"committed delivery/retry");
    CHECK(signals(&ctx,f.source.client_name,"close",lost.id)==1 && signals(&ctx,f.target.client_name,"close",lost.id)==1
        && signals(&ctx,NULL,"close",kept.id)==0 && signals(&ctx,f.foreign.client_name,"peer-config",0)==0,"selective close/both endpoints/tenant");
    CHECK(signals(&ctx,f.source.client_name,"peer-config",0)==1 && signals(&ctx,f.explicit_peer.client_name,"roster",0)==1,"current config/roster");
    for(size_t i=0;i<ctx.count;++i) {
        CHECK(strstr(ctx.records[i].json,"lost-token")==NULL && strstr(ctx.records[i].json,"kept-token")==NULL,"secret leaked");
        if(strstr(ctx.records[i].json,"\"type\":\"close\"")!=NULL) CHECK(strstr(ctx.records[i].json,"owner-transferred")!=NULL,"wrong close reason");
    }
    clear_capture(&ctx);CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)==0 && ctx.count==0,"already acknowledged event replayed");
    st_peer_mesh_owner_cursor restarted={0};CHECK(st_peer_mesh_owner_changes_init(f.path,&restarted)==0
        && restarted.after_id==result.audit_id && st_peer_mesh_owner_changes_drain(&runtime,&restarted)==0 && ctx.count==0,"restart bookmark");
    st_storage_owner_transfer_result_free(&result);clear_capture(&ctx);finish(&f);
    printf("PASS committed transfer delivery/retry mode=%d\n",failed_type);return 0;
}
static int rollback_and_independent_cursors(void)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");capture first={.only_id=f.source.id},second={.only_id=f.target.id};
    st_peer_mesh_runtime runtimes[]={{f.path,send_signal,online,&first,0,2},{f.path,send_signal,online,&second,0,2}};
    st_peer_mesh_owner_cursor cursors[2];memset(cursors,0,sizeof(cursors));
    CHECK(st_peer_mesh_owner_changes_init(f.path,&cursors[0])==0 && st_peer_mesh_owner_changes_init(f.path,&cursors[1])==0,"two bookmarks");
    st_storage_peer_mesh_session session={0};CHECK(st_storage_create_peer_mesh_session(f.path,&f.source,&f.target,"DIRECT","session-token",60,&session)==0,"session");
    CHECK(sql(f.db,"CREATE TRIGGER fail_transfer BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'injected audit failure'); END")==0,"fault");
    st_storage_owner_transfer_result result={0};CHECK(transfer(f.path,f.source.id,"builtin",&result)==500,"rollback");
    CHECK(st_peer_mesh_owner_changes_drain(&runtimes[0],&cursors[0])==0 && first.count==0 && cursors[0].after_id==0
        && scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_session WHERE status<>'CLOSED'")==1,"rollback side effects");
    CHECK(sql(f.db,"DROP TRIGGER fail_transfer")==0 && transfer(f.path,f.source.id,"builtin",&result)==200,"commit");
    CHECK(st_peer_mesh_owner_changes_drain(&runtimes[0],&cursors[0])==0 && cursors[1].after_id==0
        && signals(&first,f.source.client_name,"close",session.id)==1,"first local instance");
    CHECK(st_peer_mesh_owner_changes_drain(&runtimes[1],&cursors[1])==0
        && signals(&second,f.target.client_name,"close",session.id)==1 && cursors[0].after_id==cursors[1].after_id,"second independent instance");
    st_storage_owner_transfer_result_free(&result);clear_capture(&first);clear_capture(&second);finish(&f);
    puts("PASS rollback/no effects and independent per-instance acknowledgement");return 0;
}
static int malformed_event(void)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");capture ctx={0};st_peer_mesh_runtime runtime={f.path,send_signal,online,&ctx,0,2};
    st_peer_mesh_owner_cursor cursor={0};CHECK(st_peer_mesh_owner_changes_init(f.path,&cursor)==0,"bookmark");
    CHECK(sql(f.db,"INSERT INTO client_owner_transfer_audit(tenant_id,actor_username,scope,resource_id,target_username,payload_json,occurred_at_ms) VALUES('default','fixture','single',1,'bob','{}',1)")==0,"malformed committed fixture");
    CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)<0 && cursor.after_id==0 && ctx.count==0,"malformed event skipped or delivered");
    CHECK(sql(f.db,"UPDATE client_owner_transfer_audit SET payload_json='{\"tenantId\":\"foreign\",\"closedPeerSessions\":[]}'")==0,"tenant corruption");
    CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)<0 && cursor.after_id==0 && ctx.count==0,"foreign tenant accepted");
    CHECK(st_peer_mesh_owner_changes_init("/nonexistent/owner-journal.db",&cursor)<0 && !cursor.initialized,"bad journal initialized");
    clear_capture(&ctx);finish(&f);puts("PASS malformed event/tenant/store failures retain cursor without effects");return 0;
}
static const char *last_signal(const capture *ctx,const char *target,const char *type)
{
    const char *found=NULL;
    for(size_t i=0;i<ctx->count;++i) {
        char *actual=st_json_get_top_level_string(ctx->records[i].json,"type");
        if(actual!=NULL && strcmp(actual,type)==0 && strcmp(ctx->records[i].target,target)==0) found=ctx->records[i].json;
        free(actual);
    }
    return found;
}
static int announce(const char *path,const st_storage_client *client)
{
    st_storage_client_session session={0};
    strcpy(session.tenant_id,"default");session.credential_id=1;session.identity_id=client->id;session.client_id=client->id;
    strcpy(session.client_name,client->client_name);snprintf(session.token_hash,sizeof(session.token_hash),"fixture-token-%lld",client->id);
    strcpy(session.status,"HTTP_AUTHENTICATED");strcpy(session.machine_fingerprint,"fixture");strcpy(session.os_user,"user");
    strcpy(session.http_login_at,"2026-10-14T00:00:00Z");strcpy(session.expires_at,"2099-01-01T00:00:00Z");session.client_egress_version=1;
    return st_storage_create_client_session(path,&session,&session)==0
        && st_storage_mark_client_session_online(path,session.id,"fixture-channel","127.0.0.1","2026-10-14T00:00:01Z")==0?0:-1;
}
static int egress_and_live_catalogue(void)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");capture ctx={0};st_peer_mesh_runtime runtime={f.path,send_signal,online,&ctx,701,2};
    st_peer_mesh_owner_cursor cursor={0};CHECK(st_peer_mesh_owner_changes_init(f.path,&cursor)==0,"bookmark");
    CHECK(announce(f.path,&f.source)==0 && announce(f.path,&f.target)==0 && announce(f.path,&f.explicit_peer)==0,"current egress capabilities");
    st_storage_peer_mesh_egress_switch enabled={.tenant_id="default",.enabled=1};
    st_storage_peer_mesh_egress_policy policy={.tenant_id="default",.owner_username="alice",.egress_client_id=f.source.id,
        .enabled=1,.scope="PUBLIC",.destination_rules="[{\"cidr\":\"203.0.113.0/24\",\"protocols\":[\"tcp\"],\"portRanges\":[[443,443]]}]",
        .max_concurrent_flows=16,.max_flows_per_consumer=8,.idle_timeout_seconds=60};
    strcpy(policy.egress_client_name,f.source.client_name);
    snprintf(policy.allowed_consumer_client_ids,sizeof(policy.allowed_consumer_client_ids),"%lld,%lld",f.target.id,f.explicit_peer.id);
    st_storage_peer_mesh_service service={.tenant_id="default",.client_id=f.source.id,.service_id="owner-live-service",.name="live service",
        /* Service visibility is OWNER or ACL; an undeclared TENANT value must not grant access. */
        .transport="tcp",.application="http",.target_host="127.0.0.1",.target_port=8080,.published_port=18080,.path="/",.enabled=1,.visibility="ACL"};
    strcpy(service.client_name,f.source.client_name);
    CHECK(st_storage_upsert_peer_mesh_egress_switch(f.path,&enabled)==0 && st_storage_upsert_peer_mesh_egress_policy(f.path,&policy,NULL)==0
        && st_storage_upsert_peer_mesh_service_sharing(f.path,"default",1,1,"fixture",NULL)==0
        && st_storage_upsert_peer_mesh_service(f.path,&service,NULL)==0,"policy/service fixtures");
    const char *report="{\"type\":\"service-report\",\"enabled\":true,\"revision\":1,\"instanceId\":\"runtime-instance\",\"services\":[{\"serviceId\":\"owner-live-service\",\"name\":\"live service\",\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":18080,\"path\":\"/\"}]}";
    CHECK(st_peer_mesh_handle_control(&runtime,f.source.client_name,NULL,report)==0,"actual service publication");
    clear_capture(&ctx);st_storage_owner_transfer_result result={0};CHECK(transfer(f.path,f.source.id,"builtin",&result)==200,"actual transfer");
    CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)==0,"reconcile");
    const char *egress=last_signal(&ctx,f.source.client_name,"egress-config");
    char consumers[100];snprintf(consumers,sizeof(consumers),"\"allowedConsumerClientIds\":[%lld]",f.explicit_peer.id);
    CHECK(egress!=NULL && strstr(egress,consumers)!=NULL,"egress authorization not selectively recomputed");
    const char *withdrawn=last_signal(&ctx,f.target.client_name,"service-catalog"),*preserved=last_signal(&ctx,f.explicit_peer.client_name,"service-catalog");
    CHECK(withdrawn!=NULL && strstr(withdrawn,"\"services\":[]")!=NULL
        && preserved!=NULL && strstr(preserved,"owner-live-service")!=NULL,"lost versus explicit live catalogue visibility");
    const char *catalogue=last_signal(&ctx,f.target.client_name,"egress-catalog");
    CHECK(catalogue!=NULL && strstr(catalogue,"\"egresses\":[]")!=NULL,"consumer egress catalogue retained lost grant");
    st_peer_mesh_service_instance instances[2];size_t count=0;
    CHECK(st_peer_mesh_list_service_instances(f.path,"default",f.source.id,"owner-live-service",instances,2,&count)==0
        && count==1 && instances[0].advertised && instances[0].online,"transfer deleted publisher state");
    CHECK(scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_egress_policy WHERE owner_username='alice'")==1
        && scalar(f.db,"SELECT COUNT(*) FROM peer_mesh_shared_service WHERE enabled=1")==1,"policy ownership/service changed");
    CHECK(st_peer_mesh_handle_disconnect(&runtime,f.source.client_name)==0,"fixture publication cleanup");
    st_storage_owner_transfer_result_free(&result);clear_capture(&ctx);finish(&f);
    puts("PASS selective egress/config/catalogue reauthorization retains live explicit publication");return 0;
}
static int journal_visibility_and_large_event(void)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");capture ctx={0};st_peer_mesh_runtime runtime={f.path,send_signal,online,&ctx,0,2};
    st_peer_mesh_owner_cursor cursor={0};CHECK(st_peer_mesh_owner_changes_init(f.path,&cursor)==0,"bookmark");
    CHECK(sql(f.db,"BEGIN IMMEDIATE; INSERT INTO client_owner_transfer_audit(tenant_id,actor_username,scope,resource_id,target_username,payload_json,occurred_at_ms) VALUES('default','fixture','single',1,'bob','{\"tenantId\":\"default\",\"closedPeerSessions\":[]}',1)")==0,"uncommitted event fixture");
    (void)st_peer_mesh_owner_changes_drain(&runtime,&cursor);
    CHECK(cursor.after_id==0 && ctx.count==0,"uncommitted event observed");CHECK(sql(f.db,"ROLLBACK")==0,"rollback fixture");
    CHECK(sql(f.db,"WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1050) INSERT INTO peer_mesh_session(tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,token_hash) SELECT 'default',s.rowid,s.client_name,t.rowid,t.client_name,'private-token-'||n.x FROM n,client_account s,client_account t WHERE s.client_name='runtime-source' AND t.client_name='runtime-target'")==0,"1050 real incident sessions");
    st_storage_owner_transfer_result result={0};CHECK(transfer(f.path,f.source.id,"builtin",&result)==200 && result.closed_count==1050,"large actual transfer");
    st_storage_owner_transfer_event event={0};CHECK(st_storage_owner_transfer_next(f.path,0,&event)==1 && event.closed_count==1050
        && event.closed[1049].id==1050 && event.id==result.audit_id,"large committed event truncated");
    st_storage_owner_transfer_event_free(&event);st_storage_owner_transfer_result_free(&result);clear_capture(&ctx);finish(&f);
    puts("PASS committed-only journal visibility and 1050-session event without truncation");return 0;
}
static int journal_batch(void)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");capture ctx={0};st_peer_mesh_runtime runtime={f.path,send_signal,online,&ctx,0,2};
    st_peer_mesh_owner_cursor cursor={0};CHECK(st_peer_mesh_owner_changes_init(f.path,&cursor)==0,"bookmark");
    CHECK(sql(f.db,"WITH RECURSIVE n(x) AS(VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<65) INSERT INTO client_owner_transfer_audit(tenant_id,actor_username,scope,resource_id,target_username,payload_json,occurred_at_ms) SELECT 'default','fixture','single',1,'bob','{\"tenantId\":\"default\",\"closedPeerSessions\":[]}',n.x FROM n")==0,"ordered event fixture");
    CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)==0 && cursor.after_id==64,"bounded batch skipped/stalled");
    clear_capture(&ctx);CHECK(st_peer_mesh_owner_changes_drain(&runtime,&cursor)==0 && cursor.after_id==65,"batch continuation");
    clear_capture(&ctx);finish(&f);puts("PASS bounded event batches preserve exact continuation cursor");return 0;
}
typedef struct {
    capture signals;
    pthread_mutex_t lock;
    pthread_cond_t condition;
    int paused,released;
} ordering_capture;
static int ordered_send(void *raw,const char *target,const char *source,const char *message)
{
    ordering_capture *ctx=raw;
    pthread_mutex_lock(&ctx->lock);
    if(!ctx->paused && strcmp(target,"runtime-source")==0 && strstr(message,"\"type\":\"peer-config\"")!=NULL) {
        ctx->paused=1;pthread_cond_broadcast(&ctx->condition);
        while(!ctx->released) pthread_cond_wait(&ctx->condition,&ctx->lock);
    }
    pthread_mutex_unlock(&ctx->lock);
    return send_signal(&ctx->signals,target,source,message);
}
static int ordered_online(void *raw,long long id,const char *name) { (void)raw;(void)id;(void)name;return 1; }
typedef struct { st_peer_mesh_runtime *runtime;int rc; } ordering_worker;
static void *old_snapshot(void *raw)
{
    ordering_worker *worker=raw;worker->rc=st_peer_mesh_refresh_tenant(worker->runtime,"default");return NULL;
}
static int snapshot_ordering(void)
{
    fixture f;CHECK(fresh(&f)==0,"fixture");int failed=0,started=0;pthread_t thread;
    ordering_capture ctx={.lock=PTHREAD_MUTEX_INITIALIZER,.condition=PTHREAD_COND_INITIALIZER};
    st_peer_mesh_runtime runtime={f.path,ordered_send,ordered_online,&ctx,0,2};st_peer_mesh_owner_cursor cursor={0};
    st_storage_owner_transfer_result result={0};ordering_worker worker={.runtime=&runtime,.rc=-1};
    st_storage_peer_mesh_service service={.tenant_id="default",.client_id=f.source.id,.service_id="ordering-service",.name="ordering",
        .transport="tcp",.application="http",.target_host="127.0.0.1",.target_port=8080,.published_port=18080,.path="/",.enabled=1,.visibility="ACL"};
    strcpy(service.client_name,f.source.client_name);
    if(st_storage_upsert_peer_mesh_service_sharing(f.path,"default",1,0,"fixture",NULL)!=0
        || st_storage_upsert_peer_mesh_service(f.path,&service,NULL)!=0 || st_peer_mesh_owner_changes_init(f.path,&cursor)!=0
        || pthread_create(&thread,NULL,old_snapshot,&worker)!=0) { failed=1;goto done; }
    started=1;pthread_mutex_lock(&ctx.lock);
    struct timespec deadline;clock_gettime(CLOCK_REALTIME,&deadline);deadline.tv_sec+=5;
    while(!ctx.paused) { if(pthread_cond_timedwait(&ctx.condition,&ctx.lock,&deadline)!=0) { failed=1;break; } }
    pthread_mutex_unlock(&ctx.lock);if(failed) goto done;
    /* The callback is paused after the OLD real snapshot has been built. This
     * independent transaction must still commit: no DB lock spans network IO. */
    if(transfer(f.path,f.source.id,"builtin",&result)!=200) { failed=1;goto done; }
    size_t signals_before=ctx.signals.count;
    int drain_rc=st_peer_mesh_owner_changes_drain(&runtime,&cursor);
    if(drain_rc>=0 || cursor.after_id!=0 || ctx.signals.count!=signals_before) {
        fprintf(stderr,"ownership event overtook old snapshot: rc=%d cursor=%lld signals=%zu->%zu\n",
            drain_rc,cursor.after_id,signals_before,ctx.signals.count);failed=1;
    }
done:
    pthread_mutex_lock(&ctx.lock);ctx.released=1;pthread_cond_broadcast(&ctx.condition);pthread_mutex_unlock(&ctx.lock);
    if(started) pthread_join(thread,NULL);
    if(started && worker.rc!=0) failed=1;
    if(!failed && (st_peer_mesh_owner_changes_drain(&runtime,&cursor)!=0 || cursor.after_id!=result.audit_id)) failed=1;
    if(!failed) {
        st_storage_peer_mesh_device target={0};
        const char *latest=last_signal(&ctx.signals,f.source.client_name,"peer-config");char forbidden[100];
        if(st_storage_get_peer_mesh_device_by_client(f.path,"default",f.target.id,&target)!=0) failed=1;
        snprintf(forbidden,sizeof(forbidden),"\"%s\"",target.virtual_ip);
        if(latest==NULL || strstr(latest,forbidden)!=NULL) { fprintf(stderr,"old service allowlist survived completed ownership event\n");failed=1; }
    }
    clear_capture(&ctx.signals);st_storage_owner_transfer_result_free(&result);
    pthread_mutex_destroy(&ctx.lock);pthread_cond_destroy(&ctx.condition);finish(&f);
    printf("%s deterministic old-snapshot delivery fence and pending-event retry\n",failed?"FAIL":"PASS");return failed;
}
static int expect_owner_close(int fd,long long session_id)
{
    long long deadline=monotonic_ms()+IO_TIMEOUT_MS;
    while(monotonic_ms()<deadline) {
        st_frame_header header;uint8_t *body=NULL;
        if(read_frame(fd,(int)(deadline-monotonic_ms()),&header,&body)!=1) return -1;
        if(header.command==ST_CMD_MESSAGE_RESPONSE) {
            st_message_response message={0};
            if(st_protocol_decode_message_response(body,header.length,&message)==0 && message.message_type==ST_MESSAGE_TYPE_PEER_CONTROL) {
                long long id=0;char *type=st_json_get_top_level_string(message.message,"type"),*reason=st_json_get_top_level_string(message.message,"reason");
                int found=type!=NULL && reason!=NULL && strcmp(type,"close")==0 && strcmp(reason,"owner-transferred")==0
                    && st_json_get_i64(message.message,"sessionId",&id)==0 && id==session_id;
                free(type);free(reason);st_message_response_free(&message);free(body);if(found) return 0;continue;
            }
            st_message_response_free(&message);
        }
        free(body);
    }
    return -1;
}
static int native_http_transfer(test_server *preview_server,test_server *write_server,long long id)
{
    int status=0;char *body=NULL,*token=NULL,*revision=NULL;char path[160],request[400];int failed=1;
    snprintf(request,sizeof(request),"{\"username\":\"%s\",\"password\":\"%s\"}",ADMIN_USERNAME,ADMIN_PASSWORD);
    if(http_request(preview_server->admin_port,"POST","/auth/login",request,NULL,&status,&body)!=0 || status!=200)goto done;
    token=st_json_get_top_level_string(body,"accessToken");free(body);body=NULL;if(token==NULL)goto done;
    snprintf(path,sizeof(path),"/api/admin/clients/%lld/owner-transfer",id);
    if(http_request(preview_server->admin_port,"GET",path,NULL,token,&status,&body)!=0 || status!=200)goto done;
    revision=st_json_get_top_level_string(body,"revision");free(body);body=NULL;if(revision==NULL)goto done;
    snprintf(request,sizeof(request),"{\"scope\":\"single\",\"targetUsername\":\"bob\",\"expectedRevision\":\"%s\"}",revision);
    if(http_request(write_server->admin_port,"POST",path,request,token,&status,&body)!=0 || status!=200) {
        fprintf(stderr,"cross-instance real ownership POST status%d\n",status);goto done;
    }
    int changed=0,retained=0;
    if(st_json_get_bool(body,"changed",&changed)!=0 || !changed || st_json_get_bool(body,"accessRetained",&retained)!=0 || !retained)goto done;
    failed=0;
done:
    free(body);free(token);free(revision);return failed;
}
static int native_two_instances(int via_http)
{
    test_server first={.pid=-1},second={.pid=-1};runtime_session source={0},target={0};int source_fd=-1,target_fd=-1,data_fd=-1,failed=1;
    st_storage_owner_transfer_result result={0};int first_prepared=0,second_prepared=0;
    if(server_prepare(&first)!=0) goto done;
    first_prepared=1;
    if(server_prepare(&second)!=0) goto done;
    second_prepared=1;
    snprintf(second.db_path,sizeof(second.db_path),"%s",first.db_path);
    for(size_t i=0;i<2;++i) {
        test_server *server=i==0?&first:&second;
        server->extra_env[0]="SPECUS_PEER_MESH_ENABLED=true";server->extra_env[1]="SPECUS_PEER_MESH_STUN_TURN_PORT=0";
        server->extra_env[2]="SPECUS_PEER_MESH_BIND_ADDRESS=127.0.0.1";
        if(server_start(server)!=0) goto done;
    }
    if(create_credential(first.db_path,"runtime-source-key","runtime-source-secret",3)!=0
        || create_credential(first.db_path,"runtime-target-key","runtime-target-secret",3)!=0 || target_user(first.db_path)!=0
        || http_client_login(&first,"runtime-source-key","runtime-source-secret","runtime-source-device","user",&source)!=0
        || http_client_login(&second,"runtime-target-key","runtime-target-secret","runtime-target-device","user",&target)!=0) goto done;
    st_storage_client source_client={0},target_client={0};st_storage_peer_mesh_device device={0};
    if(st_storage_get_client(first.db_path,source.client_id,&source_client)!=0 || st_storage_get_client(first.db_path,target.client_id,&target_client)!=0
        || st_storage_update_peer_mesh_device_enabled(first.db_path,&source_client,1,&device)!=0
        || st_storage_update_peer_mesh_device_enabled(first.db_path,&target_client,1,&device)!=0) goto done;
    char reason[128];
    if(channel_login(first.control_port,&source,"control",&source_fd,reason,sizeof(reason))!=1
        || channel_login(second.control_port,&target,"control",&target_fd,reason,sizeof(reason))!=1) goto done;
    st_storage_peer_mesh_session session={0};
    if(st_storage_create_peer_mesh_session(first.db_path,&source_client,&target_client,"DIRECT","native-session-token",60,&session)!=0)goto done;
    if(via_http ? native_http_transfer(&first,&second,source.client_id)!=0
                : transfer(first.db_path,source.client_id,ADMIN_USERNAME,&result)!=200)goto done;
    if(expect_owner_close(source_fd,session.id)!=0 || expect_owner_close(target_fd,session.id)!=0
        || expect_channel_alive(source_fd)!=0 || expect_channel_alive(target_fd)!=0) goto done;
    if(channel_login(first.control_port,&source,"data",&data_fd,reason,sizeof(reason))!=1 || expect_channel_alive(data_fd)!=0) goto done;
    runtime_session new_device={0};st_storage_client provisioned={0};
    if(http_client_login(&first,"runtime-source-key","runtime-source-secret","post-transfer-device","user",&new_device)!=0
        || st_storage_get_client(first.db_path,new_device.client_id,&provisioned)!=0 || strcmp(provisioned.owner_username,"bob")!=0) goto done;
    failed=0;
done:
    close_fd(&source_fd);close_fd(&target_fd);close_fd(&data_fd);st_storage_owner_transfer_result_free(&result);
    if(first.pid>0 && server_stop(&first,10000)!=0) failed=1;
    if(second.pid>0 && server_stop(&second,10000)!=0) failed=1;
    if(second_prepared) server_cleanup(&second,failed);
    if(first_prepared) server_cleanup(&first,failed);
    printf("%s actual two-process %s transfer notifications retain control connections\n",failed?"FAIL":"PASS",via_http?"HTTP GET A/POST B":"internal writer");return failed;
}
int main(int argc,char **argv)
{
    if(argc!=2) return 2;
    server_binary=argv[1];signal(SIGPIPE,SIG_IGN);setvbuf(stdout,NULL,_IOLBF,0);
    setenv("SPECUS_PEER_MESH_ENABLED","true",1);
    int failed=0;for(int mode=0;mode<4;++mode) failed+=committed_delivery(mode);
    failed+=rollback_and_independent_cursors();failed+=malformed_event();failed+=egress_and_live_catalogue();
    failed+=journal_visibility_and_large_event();failed+=journal_batch();failed+=snapshot_ordering();
    failed+=native_two_instances(0);failed+=native_two_instances(1);
    return failed?1:0;
}
