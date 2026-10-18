/* Actual private physical transport and socketpairs, not a replacement for server-process or
 * real-language-client acceptance. No production hooks. */
#define main specus_peer_output_server_main
#include "../src/main.c"
#undef main

#define CHECK(c) do { if (!(c)) { fprintf(stderr,"FAIL peer output %s:%d: %s\n",__func__,__LINE__,#c); abort(); } } while(0)
static _Thread_local int no_output_alloc;
void *__real_malloc(size_t);
void *__real_calloc(size_t,size_t);
void *__real_realloc(void *,size_t);
void *__wrap_malloc(size_t size) { CHECK(!no_output_alloc);return __real_malloc(size); }
void *__wrap_calloc(size_t count,size_t size) { CHECK(!no_output_alloc);return __real_calloc(count,size); }
void *__wrap_realloc(void *data,size_t size) { CHECK(!no_output_alloc);return __real_realloc(data,size); }

static specus_session *output_session(const char *name,int *peer)
{
    int fds[2]; CHECK(socketpair(AF_UNIX,SOCK_STREAM,0,fds)==0);
    struct timeval timeout={2,0}; CHECK(setsockopt(fds[1],SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
    specus_session *session=calloc(1,sizeof(*session)); CHECK(session);
    session->control_fd=fds[0]; *peer=fds[1]; session->references=1;
    session->active=session->bound=1; session->config.peer_service_discovery_version=2;
    snprintf(session->config.client_name,sizeof(session->config.client_name),"%s",name);
    atomic_init(&session->control_cancelled,0); atomic_init(&session->nat_retired,0);
    CHECK(pthread_mutex_init(&session->send_lock,NULL)==0 && pthread_cond_init(&session->reference_cond,NULL)==0);
    session->delivery_guard=peer_guard_create(); session->peer_outbox=st_control_outbox_channel_create(peer_outbox,session);
    CHECK(session->delivery_guard && session->peer_outbox); return session;
}
static void output_destroy(specus_session *session,int peer)
{
    CHECK(session->references==1);
    control_cancel(session); shutdown(session->control_fd,SHUT_RDWR);
    session_outbox_dispose(session); close(session->control_fd); close(peer);
    pthread_cond_destroy(&session->reference_cond); pthread_mutex_destroy(&session->send_lock); free(session);
}
static void exact_read(int fd,void *data,size_t length)
{
    unsigned char *out=data;
    while(length) { ssize_t n=recv(fd,out,length,0); CHECK(n>0); out+=(size_t)n;length-=(size_t)n; }
}
static void receive_output(int fd,int command,const char *message)
{
    uint8_t raw[ST_HEADER_SIZE]; st_frame_header header; exact_read(fd,raw,sizeof(raw));
    CHECK(st_protocol_read_header(raw,&header)==0 && header.command==command);
    uint8_t *body=malloc(header.length?header.length:1U); CHECK(body); exact_read(fd,body,header.length);
    if(message) {
        st_message_response decoded={0}; CHECK(st_protocol_decode_message_response(body,header.length,&decoded)==0);
        CHECK(decoded.message && !strcmp(decoded.message,message)); st_message_response_free(&decoded);
    } else CHECK(header.length==0);
    free(body);
}
static void capture_for_test(specus_session *source,specus_session *target,
    st_peer_mesh_catalog_binding *from,st_peer_mesh_catalog_binding *to)
{
    pthread_mutex_lock(&active_session_lock); ++source->references; ++target->references; pthread_mutex_unlock(&active_session_lock);
    *from=(st_peer_mesh_catalog_binding){.handle=source}; *to=(st_peer_mesh_catalog_binding){.handle=target};
}
static void release_for_test(st_peer_mesh_catalog_binding *from,st_peer_mesh_catalog_binding *to)
{
    peer_catalog_release(NULL,from);peer_catalog_release(NULL,to);
}
static void invisible_fifo_and_heartbeat(void)
{
    int source_peer,target_peer,other_peer;
    specus_session *source=output_session("publisher",&source_peer), *target=output_session("recipient",&target_peer),
        *other=output_session("other",&other_peer);
    st_peer_mesh_catalog_binding from,to; capture_for_test(source,target,&from,&to);
    void *pending=NULL; CHECK(peer_catalog_prepare(NULL,&from,&to,4096,&pending)==0);
    no_output_alloc=1;CHECK(peer_catalog_stage(NULL,pending,"old accepted catalog",1)==0);no_output_alloc=0;
    pthread_mutex_lock(&active_session_lock); active_sessions=target; pthread_mutex_unlock(&active_session_lock);
    CHECK(peer_mesh_runtime_send(NULL,"recipient","server","new config")==0);
    st_buffer heartbeat=st_protocol_encode_empty_packet(ST_CMD_HEARTBEAT_RESPONSE);
    CHECK(session_send_packet(target,&heartbeat)==0); receive_output(target_peer,ST_CMD_HEARTBEAT_RESPONSE,NULL);
    st_buffer marker=st_protocol_encode_message_response("server","other",ST_MESSAGE_TYPE_PEER_CONTROL,"other ready");
    CHECK(peer_outbox_enqueue(other,&marker)==0); st_buffer_free(&marker); receive_output(other_peer,ST_CMD_MESSAGE_RESPONSE,"other ready");
    CHECK(peer_catalog_finish(NULL,pending,1)==0); release_for_test(&from,&to);
    receive_output(target_peer,ST_CMD_MESSAGE_RESPONSE,"old accepted catalog"); receive_output(target_peer,ST_CMD_MESSAGE_RESPONSE,"new config");
    pthread_mutex_lock(&active_session_lock);active_sessions=NULL;pthread_mutex_unlock(&active_session_lock);
    output_destroy(source,source_peer);output_destroy(target,target_peer);output_destroy(other,other_peer);
    puts("PASS physical output invisible reservation / catalog-before-config FIFO / heartbeat and other channel progress");
}
static void publisher_lifetime(int empty)
{
    int source_peer,target_peer;specus_session *source=output_session("publisher",&source_peer),*target=output_session("recipient",&target_peer);
    st_peer_mesh_catalog_binding from,to;capture_for_test(source,target,&from,&to);
    void *pending=NULL;CHECK(peer_catalog_prepare(NULL,&from,&to,4096,&pending)==0);
    if(empty) control_cancel(source);
    CHECK(peer_catalog_stage(NULL,pending,empty?"empty withdrawal":"cancelled nonempty",!empty)==0);
    pthread_mutex_lock(&target->send_lock);
    CHECK(peer_catalog_finish(NULL,pending,1)==0);release_for_test(&from,&to);
    CHECK(source->references==1 && atomic_load(&source->delivery_guard->references)==2U);
    /* Destroy the actual source object while the target writer is blocked. Only its independent
     * guard survives; no source session ref or source CID can be retained by queued output. */
    output_destroy(source,source_peer);
    st_buffer marker=st_protocol_encode_message_response("server","recipient",ST_MESSAGE_TYPE_PEER_CONTROL,"after source gone");
    CHECK(peer_outbox_enqueue(target,&marker)==0);st_buffer_free(&marker);
    pthread_mutex_unlock(&target->send_lock);
    if(empty) receive_output(target_peer,ST_CMD_MESSAGE_RESPONSE,"empty withdrawal");
    receive_output(target_peer,ST_CMD_MESSAGE_RESPONSE,"after source gone");
    output_destroy(target,target_peer);
    printf("PASS physical output source object freed before write / %s / independent cancellation guard\n",empty?"empty withdrawal survives":"nonempty cancelled");
}
static void abort_and_retirement(void)
{
    int source_peer,target_peer;specus_session *source=output_session("publisher",&source_peer),*target=output_session("recipient",&target_peer);
    st_peer_mesh_catalog_binding from,to;capture_for_test(source,target,&from,&to);
    void *pending=NULL; CHECK(peer_catalog_prepare(NULL,&from,&to,4096,&pending)==0);
    CHECK(peer_catalog_stage(NULL,pending,"rolled back",1)==0 && peer_catalog_finish(NULL,pending,0)==0);
    size_t entries=1,bytes=1;st_control_outbox_usage(target->peer_outbox,&entries,&bytes,NULL,NULL);CHECK(!entries && !bytes);
    CHECK(peer_catalog_prepare(NULL,&from,&to,4096,&pending)==0 && peer_catalog_stage(NULL,pending,"retired receiver",1)==0);
    control_cancel(target);st_control_outbox_channel_close(target->peer_outbox);
    CHECK(peer_catalog_finish(NULL,pending,1)==1);release_for_test(&from,&to);
    st_control_outbox_usage(target->peer_outbox,&entries,&bytes,NULL,NULL);CHECK(!entries && !bytes);
    output_destroy(source,source_peer);output_destroy(target,target_peer);
    puts("PASS physical output rollback and original receiver retirement reclaim every prepared resource");
}
static void bounded_encoding(void)
{
    const char *values[]={NULL,"","ascii","\"\\\001\n中文"};
    for(size_t a=0;a<4;++a) for(size_t b=0;b<4;++b) for(size_t c=0;c<4;++c) {
        st_buffer expected=st_protocol_encode_message_response(values[a],values[b],ST_MESSAGE_TYPE_PEER_CONTROL,values[c]);CHECK(expected.data);
        uint8_t *actual=malloc(expected.len);size_t length=999;CHECK(actual);
        no_output_alloc=1;
        CHECK(st_protocol_encode_message_response_into(values[a],values[b],ST_MESSAGE_TYPE_PEER_CONTROL,values[c],actual,expected.len,&length)==0);
        CHECK(length==expected.len && !memcmp(actual,expected.data,length));
        CHECK(st_protocol_encode_message_response_into(values[a],values[b],ST_MESSAGE_TYPE_PEER_CONTROL,values[c],actual,expected.len-1U,&length)==-1 && length==0);
        no_output_alloc=0;
        free(actual);st_buffer_free(&expected);
    }
    char *oversize=malloc(ST_MAX_MESSAGE_BODY_SIZE+1U);uint8_t *buffer=malloc(ST_MAX_MESSAGE_BODY_SIZE+1024U);CHECK(oversize && buffer);
    memset(oversize,'x',ST_MAX_MESSAGE_BODY_SIZE);oversize[ST_MAX_MESSAGE_BODY_SIZE]='\0';size_t length=1;
    st_buffer rejected=st_protocol_encode_message_response("server","recipient",ST_MESSAGE_TYPE_PEER_CONTROL,oversize);CHECK(!rejected.data);
    CHECK(st_protocol_encode_message_response_into("server","recipient",ST_MESSAGE_TYPE_PEER_CONTROL,oversize,buffer,ST_MAX_MESSAGE_BODY_SIZE+1024U,&length)==-1 && length==0);
    free(buffer);free(oversize);
    puts("PASS bounded response encoder 64 exact wire comparisons / too-small buffers / unchanged 1MiB message body limit");
}
int main(void)
{
    signal(SIGPIPE,SIG_IGN);CHECK(peer_outbox_start()==0);
    bounded_encoding();invisible_fifo_and_heartbeat();publisher_lifetime(0);publisher_lifetime(1);abort_and_retirement();
    CHECK(st_control_outbox_destroy(peer_outbox)==0);peer_outbox=NULL;return 0;
}
