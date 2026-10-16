/* Native storage + the real outbox core, not a network/client acceptance claim. The linker
 * wrapper observes/fails actual COMMIT calls; no production hooks or SQL in the stage callback. */
#define main catalog_source_reference_main
#include "catalog_source_tests.c"
#undef main
#include "control_outbox.h"
#include <stdatomic.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL acceptance %s:%d: %s\n",__func__,__LINE__,#c); abort(); } } while(0)
typedef struct { int nonempty; size_t services; char name[129]; } staged_payload;
typedef struct {
    fixture base;
    st_storage_peer_catalog_source publisher, recipient;
    st_control_outbox *box;
    st_control_outbox_channel *channel;
    st_control_outbox_ticket *ticket;
    pthread_mutex_t lock;
    pthread_cond_t changed;
    int stages, delivered, released, commit_fault, hold_commit, commit_ready, resume_commit;
    int hold_delivery, delivery_ready, resume_delivery, native_result, queue_result, stage_result, withdrawal;
    staged_payload staged, received;
} acceptance_fixture;
static _Thread_local acceptance_fixture *observed_commit;
int __real_sqlite3_exec(sqlite3 *, const char *, int (*)(void *,int,char **,char **), void *, char **);
int __wrap_sqlite3_exec(sqlite3 *db, const char *sql, int (*callback)(void *,int,char **,char **), void *arg, char **error)
{
    acceptance_fixture *f = observed_commit;
    if (f && !strcmp(sql,"COMMIT")) {
        if (f->commit_fault) return SQLITE_IOERR;
        if (f->hold_commit) {
            pthread_mutex_lock(&f->lock); f->commit_ready=1; pthread_cond_broadcast(&f->changed);
            while (!f->resume_commit) pthread_cond_wait(&f->changed,&f->lock);
            pthread_mutex_unlock(&f->lock);
        }
    }
    return __real_sqlite3_exec(db,sql,callback,arg,error);
}
static void accepted_delivery(void *channel_context,void *item_context,const unsigned char *data,size_t length)
{
    acceptance_fixture *f=channel_context; CHECK(item_context==f && length==sizeof(f->received));
    pthread_mutex_lock(&f->lock); memcpy(&f->received,data,length); ++f->delivered;
    f->delivery_ready=1; pthread_cond_broadcast(&f->changed);
    while(f->hold_delivery && !f->resume_delivery) pthread_cond_wait(&f->changed,&f->lock);
    pthread_mutex_unlock(&f->lock);
}
static void accepted_release(void *context)
{
    acceptance_fixture *f=context;
    pthread_mutex_lock(&f->lock); ++f->released; pthread_cond_broadcast(&f->changed); pthread_mutex_unlock(&f->lock);
}
static int stage_delivery(void *context,const st_storage_peer_catalog_view *view,int visible)
{
    acceptance_fixture *f=context; ++f->stages;
    f->staged.nonempty=visible && view->allowed && view->service_count>0;
    f->staged.services=view->service_count;
    if(view->service_count) snprintf(f->staged.name,sizeof(f->staged.name),"%s",view->services[0].name);
    int rc=st_control_outbox_stage(f->ticket,&f->staged,sizeof(f->staged));
    return rc==0 ? f->stage_result : rc;
}
static void *accept_delivery(void *context)
{
    acceptance_fixture *f=context;
    const char ids[][65]={"svc-cache-source"};
    observed_commit=f;
    f->native_result=st_storage_commit_peer_catalog_delivery(f->base.path,"catalog-source",f->base.publisher.id,
        f->withdrawal?NULL:&f->publisher,f->base.peer.id,&f->recipient,f->withdrawal?NULL:ids,f->withdrawal?0U:1U,stage_delivery,f);
    observed_commit=NULL;
    if(f->native_result==0) f->queue_result=st_control_outbox_commit(f->ticket);
    else { st_control_outbox_abort(f->ticket); f->queue_result=-9; }
    f->ticket=NULL; return NULL;
}
static void wait_boundary(acceptance_fixture *f,int delivery)
{
    struct timespec deadline; CHECK(clock_gettime(CLOCK_REALTIME,&deadline)==0); deadline.tv_sec+=5;
    pthread_mutex_lock(&f->lock);
    while(delivery?!f->delivery_ready:!f->commit_ready) CHECK(pthread_cond_timedwait(&f->changed,&f->lock,&deadline)==0);
    pthread_mutex_unlock(&f->lock);
}
static int independent_writer(const char *path)
{
    sqlite3 *db=NULL; CHECK(sqlite3_open(path,&db)==SQLITE_OK); CHECK(sqlite3_busy_timeout(db,0)==SQLITE_OK);
    int rc=sqlite3_exec(db,"BEGIN IMMEDIATE",NULL,NULL,NULL);
    if(rc==SQLITE_OK) CHECK(sqlite3_exec(db,"ROLLBACK",NULL,NULL,NULL)==SQLITE_OK);
    CHECK(sqlite3_close(db)==SQLITE_OK); return rc;
}
static void prepare_acceptance(acceptance_fixture *f)
{
    memset(f,0,sizeof(*f)); CHECK(prepare(&f->base)==0);
    CHECK(pthread_mutex_init(&f->lock,NULL)==0 && pthread_cond_init(&f->changed,NULL)==0);
    st_storage_client_credential credential; st_storage_client_session session={0};
    CHECK(st_storage_insert_client_credential(f->base.path,"catalog-source","alice","recipient-key","test-key",1,10,&credential)==0);
    session.client_id=session.identity_id=f->base.peer.id; session.credential_id=credential.id; session.peer_service_discovery_version=2;
    strcpy(session.tenant_id,"catalog-source"); strcpy(session.client_name,f->base.peer.client_name);
    strcpy(session.machine_fingerprint,"recipient"); strcpy(session.os_user,"user"); strcpy(session.status,"HTTP_AUTHENTICATED");
    strcpy(session.expires_at,"2999-01-01T00:00:00Z"); memset(session.token_hash,'c',64); session.token_hash[64]='\0';
    CHECK(st_storage_create_client_session(f->base.path,&session,&session)==0
        && st_storage_mark_client_session_online(f->base.path,session.id,"recipient-original","127.0.0.1","2026-10-16T00:00:00Z")==0);
    f->publisher=(st_storage_peer_catalog_source){.guarded=1,.control=f->base.guard};
    f->recipient.guarded=1; st_storage_control_source *guard=&f->recipient.control;
    guard->client_id=f->base.peer.id; guard->session_id=session.id;
    strcpy(guard->tenant_id,"catalog-source"); strcpy(guard->client_name,f->base.peer.client_name);
    strcpy(guard->channel_id,"recipient-original"); strcpy(guard->token_hash,session.token_hash);
    st_control_outbox_limits limits={4,4096,4,4096,2};
    f->box=st_control_outbox_create(&limits,accepted_delivery,accepted_release); CHECK(f->box);
    f->channel=st_control_outbox_channel_create(f->box,f); CHECK(f->channel);
    CHECK(st_control_outbox_reserve(f->channel,sizeof(staged_payload),f,&f->ticket)==0);
}
static void acceptance_case(const char *mode)
{
    acceptance_fixture f; prepare_acceptance(&f); int expected=0,nonempty=1,stages=1; char sql[512]={0};
    if(!strcmp(mode,"normal")) { }
    else if(!strcmp(mode,"publisher-capability")) { snprintf(sql,sizeof(sql),"UPDATE specus_client_session SET peer_service_discovery_version=0 WHERE id=%lld",f.publisher.control.session_id); nonempty=0; }
    else if(!strcmp(mode,"recipient-capability")) { snprintf(sql,sizeof(sql),"UPDATE specus_client_session SET peer_service_discovery_version=0 WHERE id=%lld",f.recipient.control.session_id); expected=1; nonempty=stages=0; }
    else if(!strcmp(mode,"publisher-replaced")) { snprintf(sql,sizeof(sql),"UPDATE specus_client_session SET channel_id='replacement' WHERE id=%lld",f.publisher.control.session_id); nonempty=0; }
    else if(!strcmp(mode,"recipient-replaced")) { snprintf(sql,sizeof(sql),"UPDATE specus_client_session SET channel_id='replacement' WHERE id=%lld",f.recipient.control.session_id); expected=1; nonempty=stages=0; }
    else if(!strcmp(mode,"sharing-disabled")) { strcpy(sql,"UPDATE peer_mesh_service_sharing SET enabled=0"); nonempty=0; }
    else if(!strcmp(mode,"recipient-device-disabled")) { snprintf(sql,sizeof(sql),"UPDATE peer_mesh_device SET enabled=0 WHERE client_id=%lld",f.base.peer.id); nonempty=0; }
    else if(!strcmp(mode,"current-owner")) { strcpy(sql,"UPDATE client_account SET owner_username='bob' WHERE client_name='source-publisher'; UPDATE peer_mesh_device SET owner_username='bob' WHERE client_name='source-publisher'"); nonempty=0; }
    else if(!strcmp(mode,"definition-hidden")) { strcpy(sql,"UPDATE peer_mesh_shared_service SET visibility='FUTURE'"); nonempty=0; }
    else if(!strcmp(mode,"definition-current")) strcpy(sql,"UPDATE peer_mesh_shared_service SET name='fresh definition'");
    else if(!strcmp(mode,"native-error")) { strcpy(sql,"ALTER TABLE peer_mesh_shared_service RENAME TO unavailable_services"); expected=-1; nonempty=stages=0; }
    else if(!strcmp(mode,"stage-cancel")) { f.stage_result=1; expected=1; nonempty=0; }
    else if(!strcmp(mode,"stage-error")) { f.stage_result=-1; expected=-1; nonempty=0; }
    else if(!strcmp(mode,"commit-error")) { f.commit_fault=1; expected=-1; nonempty=0; }
    else if(!strcmp(mode,"withdrawal")) { f.withdrawal=1; nonempty=0; }
    else if(!strcmp(mode,"writer-boundary")) { f.hold_commit=f.hold_delivery=1; }
    else CHECK(0);
    if(*sql) CHECK(execute(f.base.path,sql)==0);
    if(f.hold_commit) {
        pthread_t thread; CHECK(pthread_create(&thread,NULL,accept_delivery,&f)==0); wait_boundary(&f,0);
        CHECK(f.stages==1 && independent_writer(f.base.path)==SQLITE_BUSY);
        pthread_mutex_lock(&f.lock); CHECK(f.delivered==0); f.resume_commit=1; pthread_cond_broadcast(&f.changed); pthread_mutex_unlock(&f.lock);
        wait_boundary(&f,1); CHECK(pthread_join(thread,NULL)==0);
        CHECK(independent_writer(f.base.path)==SQLITE_OK); /* blocked delivery never owns SQL */
        CHECK(execute(f.base.path,"UPDATE peer_mesh_service_sharing SET enabled=0")==0);
        pthread_mutex_lock(&f.lock); f.resume_delivery=1; pthread_cond_broadcast(&f.changed); pthread_mutex_unlock(&f.lock);
    } else (void)accept_delivery(&f);
    st_control_outbox_channel_wait(f.channel);
    fprintf(stderr,"OBSERVATION acceptance %s native=%d queue=%d stages=%d delivered=%d nonempty=%d released=%d\n",
        mode,f.native_result,f.queue_result,f.stages,f.delivered,f.received.nonempty,f.released);
    CHECK(f.native_result==expected && f.stages==stages && f.released==1);
    CHECK(f.delivered==(expected==0?1:0) && f.received.nonempty==nonempty);
    if(!strcmp(mode,"definition-current")) CHECK(!strcmp(f.received.name,"fresh definition"));
    if(expected==0) CHECK(f.queue_result==0); else CHECK(f.queue_result==-9);
    size_t entries=1,bytes=1; st_control_outbox_usage(f.channel,NULL,NULL,&entries,&bytes); CHECK(!entries && !bytes);
    st_control_outbox_channel_destroy(f.channel); CHECK(st_control_outbox_destroy(f.box)==0);
    pthread_cond_destroy(&f.changed); pthread_mutex_destroy(&f.lock); cleanup(&f.base);
    printf("PASS native catalog acceptance %s / private staging, commit gate, bounded reclamation\n",mode);
}
int main(void)
{
    setenv("SPECUS_PEER_MESH_ENABLED","true",1);
    const char *modes[]={"normal","publisher-capability","recipient-capability","publisher-replaced","recipient-replaced",
        "sharing-disabled","recipient-device-disabled","current-owner","definition-hidden","definition-current","native-error",
        "stage-cancel","stage-error","commit-error","withdrawal","writer-boundary"};
    for(size_t i=0;i<sizeof(modes)/sizeof(modes[0]);++i) acceptance_case(modes[i]);
    return 0;
}
