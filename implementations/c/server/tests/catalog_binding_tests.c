#define main catalog_source_reference_main
#include "catalog_source_tests.c"
#undef main

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
static const st_peer_mesh_catalog_transport transport={capture_binding,send_binding,release_binding};

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
int main(void)
{
    setenv("SPECUS_PEER_MESH_ENABLED","true",1);
    const char *cases[]={"replay-caller","missing-transport","partial-transport","capture-error","recipient-gone","publisher-gone",
        "recipient-cancelled","publisher-cancelled","recipient-capability","recipient-native-replaced","native-error","send-error"};
    int failures=0;for(size_t i=0;i<sizeof(cases)/sizeof(cases[0]);++i) failures+=binding_case(cases[i]);return failures?1:0;
}
