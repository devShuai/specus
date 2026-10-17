/* Included only by client_identity_coordination_tests.c. Real native HTTP/WS/control.
 * Retain SQL authorization controls and separately exercise actual transfer POSTs. */
typedef struct {
    test_server *server;
    const char *ticket, *endpoint;
    int fd, status;
} management_ws_upgrade;

static void *management_upgrade(void *raw)
{
    management_ws_upgrade *upgrade=raw;
    upgrade->fd=connect_local(upgrade->server->admin_port);
    char request[1024],response[2048]={0};
    snprintf(request,sizeof(request),"GET /ws/%s?ticket=%s HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",upgrade->endpoint,upgrade->ticket);
    if(upgrade->fd<0 || send_all(upgrade->fd,(const uint8_t *)request,strlen(request))!=0) return NULL;
    size_t length=0;long long deadline=monotonic_ms()+IO_TIMEOUT_MS;
    while(length+1<sizeof(response)) {
        if(recv_exact(upgrade->fd,(uint8_t *)response+length,1,deadline)!=1) return NULL;
        if(++length>=4 && memcmp(response+length-4,"\r\n\r\n",4)==0) break;
    }
    (void)sscanf(response,"HTTP/1.1 %d",&upgrade->status);
    if(upgrade->status==101 && strstr(response,"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")==NULL) upgrade->status=-1;
    return NULL;
}

static char *management_ticket(test_server *server,const char *token,const char *endpoint)
{
    char request[80],*response=NULL;int status=0;
    snprintf(request,sizeof(request),"{\"endpoint\":\"%s\"}",endpoint);
    int rc=http_request(server->admin_port,"POST","/api/admin/ws-tickets",request,token,&status,&response);
    char *ticket=rc==0 && status==200?st_json_get_string(response,"ticket"):NULL;
    free(response);return ticket;
}

static int management_frame(int fd,int *opcode,char *body,size_t capacity,int timeout_ms)
{
    uint8_t header[2];long long deadline=monotonic_ms()+timeout_ms;
    int rc=recv_exact(fd,header,2,deadline);
    if(rc==-2) return 0;
    if(rc!=1 || (header[1]&0x80)) return -1;
    size_t length=header[1]&0x7f;
    if(length==127) return -1;
    if(length==126) {
        uint8_t extended[2];
        if(recv_exact(fd,extended,2,deadline)!=1) return -1;
        length=((size_t)extended[0]<<8)|extended[1];
    }
    if(length>=capacity || recv_exact(fd,(uint8_t *)body,length,deadline)!=1) return -1;
    body[length]='\0';*opcode=header[0]&15;return (int)length+1;
}

static int management_send(int fd,int opcode,const char *body)
{
    size_t length=strlen(body);uint8_t frame[4096];
    if(length>sizeof(frame)-8) return -1;
    size_t used=0;frame[used++]=(uint8_t)(0x80|opcode);
    if(length<126) frame[used++]=(uint8_t)(0x80|length);
    else { frame[used++]=0xfe;frame[used++]=(uint8_t)(length>>8);frame[used++]=(uint8_t)length; }
    const uint8_t mask[]={1,2,3,4};memcpy(frame+used,mask,4);used+=4;
    for(size_t i=0;i<length;++i) frame[used++]=(uint8_t)body[i]^mask[i%4];
    return send_all(fd,frame,used);
}

static int management_open(test_server *server,const char *token,const char *endpoint)
{
    char *ticket=management_ticket(server,token,endpoint);
    if(ticket==NULL) return -1;
    management_ws_upgrade upgrade={server,ticket,endpoint,-1,0};
    management_upgrade(&upgrade);free(ticket);
    if(upgrade.status!=101) { close_fd(&upgrade.fd);return -1; }
    char text[2048];int opcode=0;
    if(strcmp(endpoint,"client-messages")==0
        && (management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=1 || strstr(text,"\"type\":\"hello\"")==NULL)) {
        close_fd(&upgrade.fd);return -1;
    }
    if(management_send(upgrade.fd,9,"ready")!=0
        || management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=10) {
        close_fd(&upgrade.fd);return -1;
    }
    return upgrade.fd;
}

static int management_post_registration(int messages,int scenario)
{
    test_server server;if(server_prepare(&server)!=0) return 1;
    char ready[400],resume[400],preload[1024],ready_env[450],resume_env[450],account_env[200],token[2048],admin[2048];
    snprintf(ready,sizeof(ready),"%s/ws-ready",server.dir);snprintf(resume,sizeof(resume),"%s/ws-resume",server.dir);
    int failed=1,ready_fd=-1,resume_fd=-1,started=0,thread_started=0;
    char *ticket=NULL,*response=NULL;pthread_t thread;
    st_storage_management_user user,replacement;
    management_ws_upgrade upgrade={&server,NULL,messages?"client-messages":"connections",-1,0};
    const char *role=scenario==5?"ADMIN":"USER";
    if(st_storage_create_management_user(server.db_path,"ws-actor","default","fixture-only-hash",role,1,&user)!=0
        || st_security_issue_local_token_for_account("ws-actor","default",role,user.account_key,ADMIN_JWT_SECRET,600,token,sizeof(token))!=0
        || st_security_issue_local_token(ADMIN_USERNAME,"default","ADMIN",ADMIN_JWT_SECRET,600,admin,sizeof(admin))!=0
        || mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0) goto done;
    ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
    if(ready_fd<0 || resume_fd<0) goto done;
    Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
    if(asan!=NULL&&dladdr(asan,&sanitizer)!=0&&sanitizer.dli_fname!=NULL)
        snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
    else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
    snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);
    snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);
    snprintf(account_env,sizeof(account_env),"SPECUS_TEST_AUTH_BARRIER_WS_ACCOUNT=%s",user.account_key);
    server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=account_env;
    if(server_start(&server)!=0) goto done;
    started=1;ticket=management_ticket(&server,token,upgrade.endpoint);
    if(ticket==NULL) goto done;
    upgrade.ticket=ticket;
    if(pthread_create(&thread,NULL,management_upgrade,&upgrade)!=0) goto done;
    thread_started=1;
    struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,IO_TIMEOUT_MS); } while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R') { fprintf(stderr,"WS upgrade missed real closed-identity-read barrier\n");goto done; }
    int status=0;
    if(scenario!=0) {
        const char *method=(scenario==2 || scenario==3)?"DELETE":"PUT";
        const char *request=scenario==1?"{\"enabled\":false}":scenario==4?"{\"role\":\"ADMIN\"}":scenario==5?"{\"role\":\"USER\"}":NULL;
        if(http_request(server.admin_port,method,"/api/admin/users/ws-actor",request,admin,&status,&response)!=0
            || status!=((scenario==2 || scenario==3)?204:200)) { fprintf(stderr,"WS interleaved mutation status=%d\n",status);goto done; }
        free(response);response=NULL;
        if(scenario==3 && (st_storage_create_management_user(server.db_path,"ws-actor","default","replacement-hash","USER",1,&replacement)!=0
            || strcmp(user.account_key,replacement.account_key)==0)) goto done;
    }
    if(write(resume_fd,"C",1)!=1) goto done;
    pthread_join(thread,NULL);thread_started=0;
    if(upgrade.status!=101 || upgrade.fd<0) { fprintf(stderr,"WS overlap expected upgrade101 before post-registration check, got%d\n",upgrade.status);goto done; }
    char text[2048];int opcode=0;
    if(scenario!=0) {
        if(management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=2 || opcode!=8
            || (unsigned char)text[0]!=3 || (unsigned char)text[1]!=0xf0) { fprintf(stderr,"WS registered after revocation did not close1008\n");goto done; }
    } else {
        if(messages && (management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=1 || strstr(text,"\"type\":\"hello\"")==NULL)) goto done;
        if(management_send(upgrade.fd,9,"unchanged")!=0 || management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=10) goto done;
    }
    management_ws_upgrade reused={&server,ticket,upgrade.endpoint,-1,0};
    management_upgrade(&reused);close_fd(&reused.fd);
    if(reused.status!=403) goto done;
    failed=0;
done:
    if(thread_started) { if(write(resume_fd,"C",1)!=1)fprintf(stderr,"WS resume failed\n");pthread_join(thread,NULL); }
    free(ticket);free(response);close_fd(&upgrade.fd);
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    unlink(ready);unlink(resume);
    if(started&&server_stop(&server,10000)!=0) failed=1;
    if(failed) dump_server_log(&server);
    server_cleanup(&server,failed);
    printf("%s native WS post-registration: messages=%d scenario=%d\n",failed?"FAIL":"PASS",messages,scenario);return failed;
}

static int management_expect_control_message(int fd,const char *sender)
{
    long long deadline=monotonic_ms()+IO_TIMEOUT_MS;
    while(monotonic_ms()<deadline) {
        st_frame_header header;uint8_t *body=NULL;
        if(read_frame(fd,(int)(deadline-monotonic_ms()),&header,&body)!=1) return -1;
        if(header.command==ST_CMD_MESSAGE_RESPONSE) {
            st_message_response message={0};
            int ok=st_protocol_decode_message_response(body,header.length,&message)==0
                && message.message_type==ST_MESSAGE_TYPE_CLIENT_TO_CLIENT && strcmp(message.client_name,sender)==0
                && strcmp(message.message,"ownership-message")==0;
            st_message_response_free(&message);free(body);return ok?0:-1;
        }
        free(body);
    }
    return -1;
}

static int management_http_owner_transfer(test_server *preview_server,test_server *write_server,
                                           long long client_id,long long credential_id,int group)
{
    char admin[2048],path[180],request[400],*response=NULL,*revision=NULL;int status=0,failed=1;
    if(st_security_issue_local_token(ADMIN_USERNAME,"default","ADMIN",ADMIN_JWT_SECRET,600,admin,sizeof(admin))!=0)return 1;
    snprintf(path,sizeof(path),"/api/admin/%s/%lld/owner-transfer",group?"client-credentials":"clients",group?credential_id:client_id);
    if(http_request(preview_server->admin_port,"GET",path,NULL,admin,&status,&response)!=0 || status!=200)goto done;
    revision=st_json_get_top_level_string(response,"revision");free(response);response=NULL;if(revision==NULL)goto done;
    snprintf(request,sizeof(request),"{\"scope\":\"%s\",\"targetUsername\":\"bob\",\"expectedRevision\":\"%s\"}",group?"credential-group":"single",revision);
    if(http_request(write_server->admin_port,"POST",path,request,admin,&status,&response)!=0 || status!=200) {
        fprintf(stderr,"management WS transfer POST status%d\n",status);goto done;
    }
    int changed=0,retained=0;
    if(st_json_get_bool(response,"changed",&changed)!=0 || !changed
        || st_json_get_bool(response,"accessRetained",&retained)!=0 || !retained)goto done;
    failed=0;
done:
    free(response);free(revision);return failed;
}

static int management_transfer_during_upgrade(test_server *server,test_server *writer,const char *token,
                                               const char *endpoint,int ready_fd,int resume_fd,
                                               long long client_id,long long credential_id)
{
    char *ticket=management_ticket(server,token,endpoint);if(ticket==NULL)return -1;
    management_ws_upgrade upgrade={server,ticket,endpoint,-1,0};pthread_t thread;int started=0,ok=0;
    if(pthread_create(&thread,NULL,management_upgrade,&upgrade)!=0)goto done;
    started=1;struct pollfd event={.fd=ready_fd,.events=POLLIN};int polled;
    do { polled=poll(&event,1,IO_TIMEOUT_MS); }while(polled<0&&errno==EINTR);
    char signal=0;
    if(polled!=1 || read(ready_fd,&signal,1)!=1 || signal!='R')goto done;
    /* The real account lookup is CLOSED and its ticket consumed, but this socket is
     * not yet registered. No database lock is held over the independent HTTP POST. */
    if(management_http_owner_transfer(server,writer,client_id,credential_id,1)!=0)goto done;
    if(write(resume_fd,"C",1)!=1)goto done;
    pthread_join(thread,NULL);started=0;
    if(upgrade.status!=101 || upgrade.fd<0)goto done;
    char text[2048];int opcode=0;
    if(strcmp(endpoint,"client-messages")==0
        && (management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=1 || strstr(text,"\"type\":\"hello\"")==NULL))goto done;
    if(management_send(upgrade.fd,9,"post-transfer-ready")!=0
        || management_frame(upgrade.fd,&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=10)goto done;
    management_ws_upgrade reused={server,ticket,endpoint,-1,0};management_upgrade(&reused);close_fd(&reused.fd);
    if(reused.status!=403)goto done;
    ok=1;
done:
    if(started) { if(write(resume_fd,"C",1)!=1)fprintf(stderr,"ownership WS resume failed\n");pthread_join(thread,NULL); }
    free(ticket);
    if(!ok) { close_fd(&upgrade.fd);return -1; }
    return upgrade.fd;
}

/* mode0: original SQL control; mode1: real single POST; mode2: GET A/group POST B;
 * modes3/4: ticket consumed -> real remote group POST -> register messages/connections.
 * Existing management sockets stay on A, where the actual connection event is produced.
 * This checks fresh authorization across instances, not cross-instance event fan-out. */
static int management_owner_visibility(int independent_admin,int mode)
{
    test_server server;if(server_prepare(&server)!=0) return 1;
    test_server second={.pid=-1};int second_prepared=0,second_started=0;
    const char *stage="prepare";
    int failed=1,started=0,control=-1,data=-1,messages[3]={-1,-1,-1},events[3]={-1,-1,-1};
    int ready_fd=-1,resume_fd=-1;char ready[400]={0},resume[400]={0};
    char preload[1024],ready_env[450],resume_env[450],account_env[200];
    char tokens[3][2048],*response=NULL;sqlite3 *db=NULL;
    const char *names[]={"alice","bob","alice"},*tenants[]={"default","default","foreign"};
    st_storage_management_user users[3];st_storage_client_credential credential;runtime_session runtime;
    for(int i=0;i<3;++i) {
        const char *role=i==0 && independent_admin?"ADMIN":"USER";
        if(st_storage_create_management_user(server.db_path,names[i],tenants[i],"fixture-only-hash",role,1,&users[i])!=0
            || st_security_issue_local_token_for_account(names[i],tenants[i],role,users[i].account_key,ADMIN_JWT_SECRET,600,tokens[i],sizeof(tokens[i]))!=0) goto done;
    }
    if(mode>=3) {
        snprintf(ready,sizeof(ready),"%s/owner-ws-ready",server.dir);snprintf(resume,sizeof(resume),"%s/owner-ws-resume",server.dir);
        if(mkfifo(ready,0600)!=0 || mkfifo(resume,0600)!=0)goto done;
        ready_fd=open(ready,O_RDWR|O_NONBLOCK|O_CLOEXEC);resume_fd=open(resume,O_RDWR|O_NONBLOCK|O_CLOEXEC);
        if(ready_fd<0 || resume_fd<0)goto done;
        Dl_info sanitizer={0};void *asan=dlsym(RTLD_DEFAULT,"__asan_init");
        if(asan!=NULL && dladdr(asan,&sanitizer)!=0 && sanitizer.dli_fname!=NULL)
            snprintf(preload,sizeof(preload),"LD_PRELOAD=%s:%s",sanitizer.dli_fname,barrier_library);
        else snprintf(preload,sizeof(preload),"LD_PRELOAD=%s",barrier_library);
        snprintf(ready_env,sizeof(ready_env),"SPECUS_TEST_AUTH_BARRIER_READY=%s",ready);
        snprintf(resume_env,sizeof(resume_env),"SPECUS_TEST_AUTH_BARRIER_RESUME=%s",resume);
        snprintf(account_env,sizeof(account_env),"SPECUS_TEST_AUTH_BARRIER_WS_ACCOUNT=%s",users[0].account_key);
        server.extra_env[0]=preload;server.extra_env[1]=ready_env;server.extra_env[2]=resume_env;server.extra_env[3]=account_env;
    }
    stage="credential/start";
    if(insert_credential(server.db_path,&credential)!=0 || server_start(&server)!=0) goto done;
    started=1;
    if(mode>=2) {
        if(server_prepare(&second)!=0)goto done;
        second_prepared=1;snprintf(second.db_path,sizeof(second.db_path),"%s",server.db_path);
        if(server_start(&second)!=0)goto done;
        second_started=1;
    }
    stage="native login";harness_login_environment_extra=",\"receiveMessages\":true,\"sendMessages\":true";
    int login=http_client_login(&server,TEST_KEY,TEST_SECRET,"ws-ownership-device","user",&runtime);
    harness_login_environment_extra="";
    char reason[256];
    if(login!=0 || channel_login(server.control_port,&runtime,"control",&control,reason,sizeof(reason))!=1 || expect_channel_alive(control)!=0) goto done;
    /* Bob is registered first, hence receives the fan-out last. His event is a
     * completion witness before checking that earlier, unauthorized sockets are quiet. */
    const int order[]={1,0,2};char text[4096];int opcode=0;
    stage="register sockets";
    for(int n=0;n<3;++n) {
        int i=order[n];
        if(i==0 && mode>=3) {
            const char *endpoint=mode==3?"client-messages":"connections";
            int paused=management_transfer_during_upgrade(&server,&second,tokens[i],endpoint,ready_fd,resume_fd,runtime.client_id,credential.id);
            if(paused<0)goto done;
            if(mode==3) { messages[i]=paused;events[i]=management_open(&server,tokens[i],"connections"); }
            else { events[i]=paused;messages[i]=management_open(&server,tokens[i],"client-messages"); }
        } else { messages[i]=management_open(&server,tokens[i],"client-messages");events[i]=management_open(&server,tokens[i],"connections"); }
        if(messages[i]<0 || events[i]<0) goto done;
    }
    stage=mode==0?"ownership SQL control":"actual ownership POST";
    if(sqlite3_open(server.db_path,&db)!=SQLITE_OK) goto done;
    sqlite3_busy_timeout(db,IO_TIMEOUT_MS);
    if(mode==0) {
        char sql[800];
        snprintf(sql,sizeof(sql),"BEGIN IMMEDIATE; UPDATE client_account SET owner_username='bob' WHERE rowid=%lld; UPDATE specus_client_credential SET owner_username='bob' WHERE id=%lld; UPDATE peer_mesh_device SET owner_username='bob' WHERE client_id=%lld; COMMIT",runtime.client_id,credential.id,runtime.client_id);
        if(execute(db,sql)!=0) goto done;
    } else if(mode<=2) {
        if(management_http_owner_transfer(&server,mode==2?&second:&server,runtime.client_id,credential.id,mode==2)!=0
            || scalar(db,"SELECT COUNT(*) FROM client_owner_transfer_audit")!=1)goto done;
    } else if(scalar(db,"SELECT COUNT(*) FROM client_owner_transfer_audit")!=1)goto done;
    char path[160];snprintf(path,sizeof(path),"/api/admin/clients/%lld",runtime.client_id);
    stage="current REST and outbound WS";
    for(int i=0;i<3;++i) {
        int status=0,allowed=i==1 || (i==0 && independent_admin);
        if(http_request(server.admin_port,"GET",path,NULL,tokens[i],&status,&response)!=0 || status!=(allowed?200:404)) { fprintf(stderr,"current REST owner=%d admin=%d status=%d\n",i,independent_admin,status);goto done; }
        free(response);response=NULL;
        if(mode>=2) {
            if(http_request(second.admin_port,"GET",path,NULL,tokens[i],&status,&response)!=0 || status!=(allowed?200:404))goto done;
            free(response);response=NULL;
        }
        char command[800];snprintf(command,sizeof(command),"{\"type\":\"message\",\"messageId\":\"owner-check\",\"toClientName\":\"%s\",\"message\":\"ownership-message\"}",runtime.client_name);
        if(management_send(messages[i],1,command)!=0) goto done;
        if(allowed) {
            char sender[64];snprintf(sender,sizeof(sender),"admin:%s",names[i]);
            if(management_expect_control_message(control,sender)!=0) goto done;
        }
        if(management_frame(messages[i],&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=1
            || strstr(text,allowed?"\"type\":\"written\"":"\"error\":\"target-not-found\"")==NULL) { fprintf(stderr,"current WS resource authorization mismatch admin=%d subject=%d\n",independent_admin,i);goto done; }
    }
    stage="retained control/data";
    if(expect_channel_alive(control)!=0 || channel_login(server.control_port,&runtime,"data",&data,reason,sizeof(reason))!=1
        || expect_channel_alive(data)!=0 || expect_channel_alive(control)!=0) goto done;
    /* Only control logins/disconnects create connection records; data login does not.
     * First prove both existing channels survive the fixture, then intentionally close
     * them to produce a real event. This is not a transfer-forced reconnection. */
    stage="intentional disconnect event";close_fd(&data);close_fd(&control);
    if(management_frame(events[1],&opcode,text,sizeof(text),IO_TIMEOUT_MS)<=0 || opcode!=1) goto done;
    long long event_id=0;
    if(st_json_get_i64(text,"clientId",&event_id)!=0 || event_id!=runtime.client_id) goto done;
    stage="old owner event filter";
    int old_event=management_frame(events[0],&opcode,text,sizeof(text),independent_admin?IO_TIMEOUT_MS:200);
    if(independent_admin) {
        if(old_event<=0 || opcode!=1 || st_json_get_i64(text,"clientId",&event_id)!=0 || event_id!=runtime.client_id) goto done;
    } else if(old_event!=0) goto done;
    stage="foreign tenant event filter";
    if(management_frame(events[2],&opcode,text,sizeof(text),200)!=0) goto done;
    stage="retained token reconnect";
    if(channel_login(server.control_port,&runtime,"control",&control,reason,sizeof(reason))!=1
        || channel_login(server.control_port,&runtime,"data",&data,reason,sizeof(reason))!=1
        || expect_channel_alive(control)!=0 || expect_channel_alive(data)!=0) goto done;
    stage="retained secret provisions current owner";
    runtime_session derived;st_storage_client derived_client;
    if(http_client_login(&server,TEST_KEY,TEST_SECRET,"new-device-after-owner-fixture","user",&derived)!=0
        || derived.client_id==runtime.client_id || st_storage_get_client(server.db_path,derived.client_id,&derived_client)!=0
        || strcmp(derived_client.owner_username,"bob")!=0 || strcmp(derived_client.tenant_id,"default")!=0
        || expect_channel_alive(control)!=0 || expect_channel_alive(data)!=0) goto done;
    failed=0;
done:
    harness_login_environment_extra="";free(response);sqlite3_close(db);close_fd(&control);close_fd(&data);
    for(int i=0;i<3;++i) { close_fd(&messages[i]);close_fd(&events[i]); }
    if(started&&server_stop(&server,10000)!=0) failed=1;
    if(second_started&&server_stop(&second,10000)!=0)failed=1;
    if(ready_fd>=0)close(ready_fd);
    if(resume_fd>=0)close(resume_fd);
    if(ready[0])unlink(ready);
    if(resume[0])unlink(resume);
    if(failed) { fprintf(stderr,"owner visibility stopped at stage=%s admin=%d\n",stage,independent_admin);dump_server_log(&server); }
    if(second_prepared)server_cleanup(&second,failed);
    server_cleanup(&server,failed);
    printf("%s native current REST/WS owner visibility: independent-admin=%d mode=%d\n",failed?"FAIL":"PASS",independent_admin,mode);return failed;
}
