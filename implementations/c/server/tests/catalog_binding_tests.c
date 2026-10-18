#define main catalog_source_reference_main
#include "catalog_source_tests.c"
#undef main

static _Thread_local int no_catalog_alloc;
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__real_realloc(void *,size_t);
void *__wrap_malloc(size_t size) { if(no_catalog_alloc)abort();return __real_malloc(size); }
void *__wrap_calloc(size_t count,size_t size) { if(no_catalog_alloc)abort();return __real_calloc(count,size); }
void *__wrap_realloc(void *data,size_t size) { if(no_catalog_alloc)abort();return __real_realloc(data,size); }

typedef struct { int references, active; st_storage_peer_catalog_source authority; } binding_node;
typedef struct {
    fixture base; /* Existing source/online callbacks can borrow this initial member. */
    binding_node publisher, recipient;
    int capture_error, missing, send_error, attempts, sent, nonempty, hook;
} binding_fixture;

static int capture_binding(void *ctx,const char *path,const st_storage_client *hint,long long session,
    const st_storage_peer_catalog_source *expected,st_peer_mesh_catalog_binding *out)
{
    binding_fixture *f=ctx;memset(out,0,sizeof(*out));
    int publisher=hint->id==f->base.publisher.id;
    binding_node *node=publisher?&f->publisher:&f->recipient;
    if(strcmp(path,f->base.path) || (publisher && (session!=f->base.guard.session_id || !expected
        || !expected->guarded || strcmp(expected->control.channel_id,f->base.guard.channel_id)))) return -1;
    if(f->capture_error && !publisher) return -1;
    if(f->missing==(publisher?2:1)) return 1;
    ++node->references;out->handle=node;out->authority=node->authority;
    if(!publisher && f->hook) {
        char sql[256]; int hook=f->hook;f->hook=0;
        if(hook==1) snprintf(sql,sizeof(sql),"UPDATE specus_client_session SET peer_service_discovery_version=0 WHERE id=%lld",node->authority.control.session_id);
        else if(hook==2) snprintf(sql,sizeof(sql),"UPDATE specus_client_session SET channel_id='successor' WHERE id=%lld",node->authority.control.session_id);
        else snprintf(sql,sizeof(sql),"ALTER TABLE specus_client_session RENAME TO unavailable_session");
        if(execute(path,sql)!=0) { --node->references;memset(out,0,sizeof(*out));return -1; }
    }
    return 0;
}
static int send_binding(void *ctx,const st_peer_mesh_catalog_binding *publisher,
    const st_peer_mesh_catalog_binding *recipient,const char *message)
{
    binding_fixture *f=ctx;++f->attempts;
    if(recipient->handle!=&f->recipient || (publisher && publisher->handle!=&f->publisher)) return -1;
    if(!f->recipient.active || (publisher && !f->publisher.active)) return 1;
    if(f->send_error) return -1;
    int nonempty=strstr(message,"\"serviceId\":\"svc-cache-source\"")!=NULL;
    if(nonempty && !publisher) return -1;
    ++f->sent;f->nonempty+=nonempty;return 0;
}
static void release_binding(void *ctx,st_peer_mesh_catalog_binding *binding)
{
    (void)ctx;binding_node *node=binding->handle;if(node) --node->references;memset(binding,0,sizeof(*binding));
}
typedef struct {
    st_peer_mesh_catalog_binding publisher, recipient;
    char *message; size_t capacity; int nonempty;
} binding_pending;
static int prepare_binding(void *ctx,const st_peer_mesh_catalog_binding *publisher,
    const st_peer_mesh_catalog_binding *recipient,size_t capacity,void **out)
{
    (void)ctx; *out=NULL;
    binding_pending *pending=calloc(1,sizeof(*pending)); if(!pending) return -1;
    pending->message=malloc(capacity); if(!pending->message) {free(pending);return -1;}
    pending->capacity=capacity; pending->recipient=*recipient;
    if(publisher) pending->publisher=*publisher;
    *out=pending;return 0;
}
static int stage_binding(void *ctx,void *reservation,const char *message,int nonempty)
{
    (void)ctx; binding_pending *pending=reservation;size_t length=strlen(message);
    if(length>=pending->capacity) return -1;
    memcpy(pending->message,message,length+1U);pending->nonempty=nonempty;return 0;
}
static int finish_binding(void *ctx,void *reservation,int commit)
{
    binding_pending *pending=reservation;
    int rc=commit?send_binding(ctx,pending->nonempty?&pending->publisher:NULL,&pending->recipient,pending->message):0;
    free(pending->message);free(pending);return rc;
}
static const st_peer_mesh_catalog_transport transport={.capture=capture_binding,.send=send_binding,.release=release_binding,
    .prepare=prepare_binding,.stage=stage_binding,.finish=finish_binding};

static int binding_case(const char *mode)
{
    binding_fixture f={0};int failed=1;st_storage_client_credential credential;st_storage_client_session receiver={0};
#define REQUIRE(c,text) do { if(!(c)){fprintf(stderr,"FAIL catalog binding %s: %s\n",mode,text);goto done;} }while(0)
    REQUIRE(prepare(&f.base)==0,"actual accepted guarded source/cache");
    REQUIRE(st_storage_insert_client_credential(f.base.path,"catalog-source","alice","receiver-key","fixture-secret",1,10,&credential)==0,"receiver credential");
    receiver.client_id=receiver.identity_id=f.base.peer.id;receiver.credential_id=credential.id;receiver.peer_service_discovery_version=2;
    strcpy(receiver.tenant_id,"catalog-source");strcpy(receiver.client_name,f.base.peer.client_name);
    memset(receiver.token_hash,'d',64);receiver.token_hash[64]='\0';
    strcpy(receiver.status,"HTTP_AUTHENTICATED");strcpy(receiver.machine_fingerprint,"receiver");strcpy(receiver.os_user,"user");
    strcpy(receiver.expires_at,"2099-01-01T00:00:00Z");
    REQUIRE(st_storage_create_client_session(f.base.path,&receiver,&receiver)==0
        && st_storage_mark_client_session_online(f.base.path,receiver.id,"receiver-original","127.0.0.1","2026-10-16T00:00:00Z")==0,"real original recipient row");
    f.publisher.active=f.recipient.active=1;f.publisher.authority=(st_storage_peer_catalog_source){.guarded=1,.control=f.base.guard};
    f.recipient.authority.guarded=1;st_storage_control_source *guard=&f.recipient.authority.control;
    guard->client_id=f.base.peer.id;guard->session_id=receiver.id;strcpy(guard->tenant_id,"catalog-source");
    strcpy(guard->client_name,f.base.peer.client_name);strcpy(guard->channel_id,"receiver-original");strcpy(guard->token_hash,receiver.token_hash);
    st_peer_mesh_runtime runtime=f.base.runtime;runtime.ctx=&f;runtime.catalog_transport=&transport;runtime.catalog_transport_required=1;
    int expected=0,expected_sent=1,expected_nonempty=1;
    if(!strcmp(mode,"replay-caller")) {runtime.control_source=guard;runtime.publisher_session_id=receiver.id;runtime.authenticated_client_id=f.base.peer.id;}
    else if(!strcmp(mode,"missing-transport")) {runtime.catalog_transport=NULL;expected=-1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"partial-transport")) {static const st_peer_mesh_catalog_transport partial={0};runtime.catalog_transport=&partial;expected=-1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"legacy-only-required")) {static const st_peer_mesh_catalog_transport legacy={.capture=capture_binding,.send=send_binding,.release=release_binding};runtime.catalog_transport=&legacy;expected=-1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"partial-acceptance")) {static const st_peer_mesh_catalog_transport partial={.capture=capture_binding,.send=send_binding,.release=release_binding,.prepare=prepare_binding};runtime.catalog_transport=&partial;expected=-1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"capture-error")) {f.capture_error=1;expected=-1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"recipient-gone")) {f.missing=1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"publisher-gone")) {f.missing=2;expected_nonempty=0;}
    else if(!strcmp(mode,"recipient-cancelled")) {f.recipient.active=0;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"publisher-cancelled")) {f.publisher.active=0;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"recipient-capability")) {f.hook=1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"recipient-native-replaced")) {f.hook=2;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"native-error")) {f.hook=3;expected=-1;expected_sent=expected_nonempty=0;}
    else if(!strcmp(mode,"send-error")) {f.send_error=1;expected=-1;expected_sent=expected_nonempty=0;}
    else REQUIRE(0,"known scenario");
    int legacy=f.base.sent;
    int rc=pm_replay_catalogs(&runtime,&f.base.peer);
    fprintf(stderr,"OBSERVATION binding %s rc=%d sent=%d nonempty=%d attempts=%d refs=%d/%d\n",mode,rc,f.sent,f.nonempty,f.attempts,f.publisher.references,f.recipient.references);
    REQUIRE(rc==expected && f.sent==expected_sent && f.nonempty==expected_nonempty && f.base.sent==legacy
        && f.publisher.references==0 && f.recipient.references==0,"only captured handles, exact authority, no legacy fallback, references reclaimed on every exit");
    if(!strcmp(mode,"native-error")) REQUIRE(execute(f.base.path,"ALTER TABLE unavailable_session RENAME TO specus_client_session")==0 && current(&f.base),"read error leaves original source recoverable");
    failed=0;
done:
    cleanup(&f.base);printf("%s catalog binding %s lifetime/current native/transport boundary\n",failed?"FAIL":"PASS",mode);return failed;
#undef REQUIRE
}
static int bounded_catalog(void)
{
    pm_catalog *catalog=calloc(1,sizeof(*catalog));st_storage_peer_mesh_service *services=calloc(32,sizeof(*services));
    char *buffer=malloc(PM_CATALOG_CAPACITY);if(!catalog || !services || !buffer)abort();
    catalog->publisher_client_id=1;catalog->publisher_session_id=2;catalog->catalog_revision=3;catalog->created_at_millis=4;catalog->service_count=32;
    memset(catalog->publisher_client_name,1,sizeof(catalog->publisher_client_name)-1U);
    st_storage_peer_catalog_view view={.services=services,.service_count=32,.allowed=1};view.publisher.id=1;
    memcpy(view.publisher.client_name,catalog->publisher_client_name,sizeof(view.publisher.client_name));
    for(size_t i=0;i<32;++i) {
        st_storage_peer_mesh_service *service=&services[i];
        memset(service->service_id,1,64);service->service_id[62]=(char)('A'+i/26U);service->service_id[63]=(char)('A'+i%26U);
        memset(service->name,1,sizeof(service->name)-1U);memset(service->description,1,sizeof(service->description)-1U);
        memset(service->transport,1,sizeof(service->transport)-1U);memset(service->application,1,sizeof(service->application)-1U);
        memset(service->path,1,sizeof(catalog->endpoints[i].path)-1U);service->published_port=65535;
        memcpy(catalog->service_ids[i],service->service_id,sizeof(service->service_id));
        memcpy(catalog->endpoints[i].transport,service->transport,sizeof(service->transport));
        memcpy(catalog->endpoints[i].application,service->application,sizeof(service->application));
        memcpy(catalog->endpoints[i].path,service->path,sizeof(catalog->endpoints[i].path));catalog->endpoints[i].published_port=65535;
    }
    pm_builder builder={.data=buffer,.cap=PM_CATALOG_CAPACITY,.fixed=1};int nonempty=0;
    no_catalog_alloc=1;int rc=pm_format_catalog(catalog,&view,1,"2099-01-01T00:00:00Z",&builder,&nonempty);no_catalog_alloc=0;
    if(rc || !nonempty || builder.len>=PM_CATALOG_CAPACITY)abort();
    char **rows=NULL;size_t count=0;if(st_json_get_raw_array(buffer,"services",&rows,&count) || count!=32)abort();
    st_json_free_string_array(rows,count);size_t required=builder.len;
    builder.len=0;builder.cap=required+1U;no_catalog_alloc=1;
    if(pm_format_catalog(catalog,&view,1,"2099-01-01T00:00:00Z",&builder,&nonempty))abort();
    builder.len=0;builder.cap=required;
    if(pm_format_catalog(catalog,&view,1,"2099-01-01T00:00:00Z",&builder,&nonempty)!=-1)abort();
    no_catalog_alloc=0;free(buffer);free(services);free(catalog);
    printf("PASS catalog bounded formatter 32 maximally escaped field sets / zero allocations / exact capacity and exhaustion\n");return 0;
}
int main(void)
{
    setenv("SPECUS_PEER_MESH_ENABLED","true",1);
    const char *cases[]={"replay-caller","missing-transport","partial-transport","legacy-only-required","partial-acceptance","capture-error","recipient-gone","publisher-gone",
        "recipient-cancelled","publisher-cancelled","recipient-capability","recipient-native-replaced","native-error","send-error"};
    int failures=bounded_catalog();for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) failures+=binding_case(cases[i]);return failures?1:0;
}
