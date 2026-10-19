#define _POSIX_C_SOURCE 200809L
#include "instant.h"
#include "instant_reference_cases.h"
#include "object_storage.h"
#include "public_room.h"
#include "storage.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <sqlite3.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr,"transfer expiry failed line %d: %s\n",__LINE__,#ok); exit(1); } } while (0)
static char database[]="/tmp/specus-transfer-expiry-XXXXXX";
static const time_t seconds=1789473600;
static long nanos;
static int clock_calls, advance_at_call;
static int listener, deleted_ids[64];
static atomic_int heads, deletes;
static pthread_t server_thread;
static const st_object_storage_identity identity={"t1","alice",0,1};
time_t __wrap_time(time_t *out) { if(out) *out=seconds; return seconds; }
int __real_clock_gettime(clockid_t,struct timespec *);
int __wrap_clock_gettime(clockid_t id,struct timespec *out)
{
    if(id!=CLOCK_REALTIME) return __real_clock_gettime(id,out);
    if(++clock_calls==advance_at_call) nanos=500000200L;
    out->tv_sec=seconds; out->tv_nsec=nanos; return 0;
}
static int sqlite_now64(sqlite3_vfs *vfs,sqlite3_int64 *out)
{ (void)vfs; *out=210866760000000LL+(sqlite3_int64)seconds*1000+nanos/1000000; return SQLITE_OK; }
static int sqlite_now(sqlite3_vfs *vfs,double *out)
{ sqlite3_int64 n; sqlite_now64(vfs,&n); *out=(double)n/86400000.0; return SQLITE_OK; }
static void *serve(void *ignored)
{
    (void)ignored;
    for(;;) {
        int fd=accept(listener,NULL,NULL); if(fd<0) break;
        char request[8192]={0}; size_t used=0;
        while(used<sizeof(request)-1 && !strstr(request,"\r\n\r\n")) {
            ssize_t n=recv(fd,request+used,sizeof(request)-1-used,0); if(n<=0) break; used+=(size_t)n;
        }
        if(strncmp(request,"HEAD ",5)==0) ++heads;
        else { int id=0, index=atomic_load(&deletes); CHECK(sscanf(request,"DELETE /prefix/%d",&id)==1 && index<64);
            deleted_ids[index]=id; atomic_store(&deletes,index+1); }
        const char *response="HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: close\r\n\r\n";
        /* DELETE has an actual body; HEAD advertises its size without sending it. */
        CHECK(send(fd,response,strlen(response),MSG_NOSIGNAL)==(ssize_t)strlen(response));
        if(strncmp(request,"HEAD ",5)!=0) CHECK(send(fd,"x",1,MSG_NOSIGNAL)==1);
        close(fd);
    }
    return NULL;
}
static void start_server(void)
{
    listener=socket(AF_INET,SOCK_STREAM,0); CHECK(listener>=0);
    struct sockaddr_in addr={.sin_family=AF_INET,.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};
    CHECK(bind(listener,(struct sockaddr *)&addr,sizeof(addr))==0 && listen(listener,16)==0);
    socklen_t length=sizeof(addr); CHECK(getsockname(listener,(struct sockaddr *)&addr,&length)==0);
    char endpoint[128]; snprintf(endpoint,sizeof(endpoint),"http://oss.invalid:%u",(unsigned)ntohs(addr.sin_port));
    CHECK(setenv("SPECUS_OBJECT_STORAGE_ENDPOINT",endpoint,1)==0 && pthread_create(&server_thread,NULL,serve,NULL)==0);
}
static sqlite3 *open_db(void) { sqlite3 *db=NULL; CHECK(sqlite3_open(database,&db)==SQLITE_OK); return db; }
static void sql(const char *query)
{
    sqlite3 *db=open_db(); char *error=NULL; int rc=sqlite3_exec(db,query,NULL,NULL,&error);
    if(rc!=SQLITE_OK) fprintf(stderr,"SQL: %s\n%s\n",query,error);
    CHECK(rc==SQLITE_OK);
    sqlite3_free(error); sqlite3_close(db);
}
static long long scalar(const char *query)
{
    sqlite3 *db=open_db(); sqlite3_stmt *stmt=NULL;
    CHECK(sqlite3_prepare_v2(db,query,-1,&stmt,NULL)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_ROW);
    long long result=sqlite3_column_int64(stmt,0); CHECK(sqlite3_step(stmt)==SQLITE_DONE);
    sqlite3_finalize(stmt); sqlite3_close(db); return result;
}
static int request(const char *method,const char *path,const char *body,char out[16384])
{
    CHECK(st_object_storage_build_response(method,path,body,"127.0.0.1",NULL,NULL,&identity,out,16384)>0);
    return atoi(out+9);
}
static void reset(int fractional)
{
    st_public_room_reset_for_tests(); st_object_storage_reset_for_tests(); unlink(database);
    nanos=fractional ? 500000000L : 0;
    clock_calls=0; advance_at_call=0;
    char now[ST_INSTANT_CAPACITY]; CHECK(st_instant_now(now)==0 && st_instant_public(now,now,sizeof(now))==0 && strcmp(now,cutoffs[fractional])==0);
    CHECK(st_storage_init(database,0)==0);
    char out[16384]; long long id=999; st_object_storage_set_ids_for_tests(&id,1);
    CHECK(request("POST","/api/public/transfer/attachments/presign-upload",
        "{\"roomId\":\"expiry-room\",\"roomToken\":\"expiry-owner-token\",\"fileName\":\"test.bin\",\"sizeBytes\":1}",out)==200);
    sql("UPDATE transfer_attachment SET status='EXPIRED',size_bytes=0 WHERE id=999");
}
static void attachment(int id,const char *status,long long bytes,const char *upload,const char *expires,int legacy)
{
    char first[ST_INSTANT_CAPACITY],second[ST_INSTANT_CAPACITY];
    CHECK(st_instant_normalize(upload,first)==0 && st_instant_normalize(expires,second)==0);
    sqlite3 *db=open_db(); sqlite3_stmt *stmt=NULL;
    const char *query="INSERT INTO transfer_attachment(id,tenant_id,scope,room_id,room_token_hash,public_transfer_room_id,owner_username,object_key,file_name,mime_type,size_bytes,status,created_at,updated_at,upload_expires_at,expires_at) "
        "SELECT ?1,tenant_id,scope,room_id,room_token_hash,public_transfer_room_id,owner_username,'prefix/'||?1,file_name,mime_type,?2,?3,created_at,updated_at,?4,?5 FROM transfer_attachment WHERE id=999";
    CHECK(sqlite3_prepare_v2(db,query,-1,&stmt,NULL)==SQLITE_OK
        && sqlite3_bind_int(stmt,1,id)==SQLITE_OK && sqlite3_bind_int64(stmt,2,bytes)==SQLITE_OK
        && sqlite3_bind_text(stmt,3,status,-1,SQLITE_STATIC)==SQLITE_OK
        && sqlite3_bind_text(stmt,4,legacy?upload:first,-1,SQLITE_TRANSIENT)==SQLITE_OK
        && sqlite3_bind_text(stmt,5,legacy?expires:second,-1,SQLITE_TRANSIENT)==SQLITE_OK
        && sqlite3_step(stmt)==SQLITE_DONE && sqlite3_changes(db)==1);
    sqlite3_finalize(stmt); sqlite3_close(db);
}
static void grant(int id,const char *expiry,int legacy)
{
    char token[32],hash[65],stored[ST_INSTANT_CAPACITY]; unsigned char digest[32]; unsigned int size=0;
    snprintf(token,sizeof(token),"grant-%d",id); CHECK(EVP_Digest(token,strlen(token),digest,&size,EVP_sha256(),NULL)==1 && size==32);
    for(int i=0;i<32;++i) snprintf(hash+i*2,3,"%02x",digest[i]);
    CHECK(st_instant_normalize(expiry,stored)==0);
    sqlite3 *db=open_db(); sqlite3_stmt *stmt=NULL;
    CHECK(sqlite3_prepare_v2(db,"INSERT INTO transfer_attachment_download_grant(id,token_hash,tenant_id,username,attachment_id,created_at,expires_at) VALUES(?1,?2,'t1','alice',100,'2026-09-15T11:00:00Z',?3)",-1,&stmt,NULL)==SQLITE_OK
        && sqlite3_bind_int(stmt,1,id)==SQLITE_OK && sqlite3_bind_text(stmt,2,hash,-1,SQLITE_TRANSIENT)==SQLITE_OK
        && sqlite3_bind_text(stmt,3,legacy?expiry:stored,-1,SQLITE_TRANSIENT)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_DONE);
    sqlite3_finalize(stmt); sqlite3_close(db);
}
static const char *far="2026-09-18T12:00:00Z";
static const char *past="2026-09-15T11:00:00Z";
static void settle(void) { CHECK(st_storage_init(database,0)==0 && st_storage_init(database,0)==0); }
static void boundaries(int mode,int fractional,int legacy)
{
    reset(fractional); char out[16384];
    for(int i=0;i<7;++i) {
        if(mode==0) {
            attachment(i+1,"UPLOADED",1LL<<i,past,values[fractional][i],legacy);
            attachment(i+11,"PENDING",1LL<<i,values[fractional][i],far,legacy);
        } else if(mode==1 || mode==4) attachment(i+1,"UPLOADED",1,past,values[fractional][i],legacy);
        else if(mode==3) attachment(i+1,"PENDING",1,values[fractional][i],far,legacy);
        if(mode==1 || mode==2) grant(i+11,values[fractional][i],legacy);
    }
    if(mode==2) attachment(100,"UPLOADED",1,past,far,legacy);
    if(mode==0) {
        attachment(101,"UPLOADED",4096,past,far,legacy); attachment(102,"PENDING",8192,far,far,legacy);
        sql("UPDATE transfer_attachment SET tenant_id='foreign' WHERE id=101;UPDATE transfer_attachment SET owner_username='bob' WHERE id=102");
    }
    settle();
    if(mode==0) {
        CHECK(request("GET","/api/public/transfer/attachments/capabilities",NULL,out)==200);
        if(!strstr(out,"\"storageUsedBytes\":224,")) fprintf(stderr,"usage f=%d legacy=%d: %s\n",fractional,legacy,out);
        CHECK(strstr(out,"\"storageUsedBytes\":224,")!=NULL);
        CHECK(strstr(out,cutoffs[fractional])!=NULL && strstr(out,"private, no-store")!=NULL);
    } else if(mode==1) {
        int before=deletes;
        CHECK(st_object_storage_cleanup_expired()==0);
        CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE id BETWEEN 1 AND 3 AND status='EXPIRED'")==3);
        CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE id BETWEEN 4 AND 7 AND status='UPLOADED'")==4);
        CHECK(scalar("SELECT count(*) FROM transfer_attachment_download_grant")==4);
        CHECK(scalar("SELECT count(*) FROM transfer_attachment_download_grant WHERE id BETWEEN 14 AND 17")==4);
        CHECK(deletes-before==3 && deleted_ids[before]==1 && deleted_ids[before+1]==2 && deleted_ids[before+2]==3);
    } else {
        int before=heads;
        for(int i=0;i<7;++i) {
            char route[192]; int expected;
            if(mode==2) { snprintf(route,sizeof(route),"/api/public/transfer/downloads/grant-%d",i+11); expected=i>=4?302:410; }
            else { snprintf(route,sizeof(route),"/api/public/transfer/attachments/%d/%s",i+1,mode==3?"complete":"presign-download"); expected=(i>=(mode==3?3:4))?200:409; }
            int status=request(mode==2?"GET":"POST",route,"{\"roomToken\":\"expiry-owner-token\"}",out);
            if(status!=expected) fprintf(stderr,"mode=%d f=%d legacy=%d index=%d expected=%d actual=%d\n%s\n",mode,fractional,legacy,i,expected,status,out);
            CHECK(status==expected);
            if(mode==2 && status==302) CHECK(request("GET",route,NULL,out)==410);
        }
        if(mode==2) CHECK(scalar("SELECT count(*) FROM transfer_attachment_download_usage")==3
            && scalar("SELECT count(*) FROM transfer_attachment_download_grant WHERE consumed_at IS NOT NULL")==3);
        if(mode==3) CHECK(heads-before==4 && scalar("SELECT count(*) FROM transfer_attachment WHERE status='UPLOADED'")==4);
        if(mode==4) CHECK(scalar("SELECT count(*) FROM transfer_attachment_download_grant")==3);
    }
    printf("transfer expiry: mode=%d fractional=%d legacy=%d seven boundaries passed\n",mode,fractional,legacy);
}
static void writers_and_migration(void)
{
    reset(1); char out[16384];
    CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE id=999 AND created_at='2026-09-15T12:00:00.500Z' AND upload_expires_at='2026-09-15T12:15:00.5000000Z' AND expires_at='2026-09-18T12:00:00.5000000Z'")==1);
    sql("UPDATE transfer_attachment SET status='UPLOADED',size_bytes=1 WHERE id=999");
    CHECK(request("POST","/api/public/transfer/attachments/999/presign-download","{\"roomToken\":\"expiry-owner-token\"}",out)==200);
    CHECK(strstr(out,"\"expiresAt\":\"2026-09-15T12:10:00.500Z\"")!=NULL
        && strstr(out,"\"expiresAt\":\"2026-09-18T12:00:00.500Z\"")!=NULL);
    CHECK(scalar("SELECT count(*) FROM transfer_attachment_download_grant WHERE created_at='2026-09-15T12:00:00.500Z' AND expires_at='2026-09-15T12:10:00.5000000Z'")==1);
    sql("UPDATE transfer_attachment SET upload_expires_at='2026-09-15T12:15:00.500Z',expires_at='2026-09-18 12:00:00' WHERE id=999;"
        "UPDATE transfer_attachment_download_grant SET expires_at='2026-09-15T14:10:00.500+02:00'");
    settle();
    CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE id=999 AND upload_expires_at='2026-09-15T12:15:00.5000000Z' AND expires_at='2026-09-18T12:00:00.0000000Z'")==1
        && scalar("SELECT count(*) FROM transfer_attachment_download_grant WHERE expires_at='2026-09-15T12:10:00.5000000Z'")==1);
    CHECK(setenv("SPECUS_OBJECT_STORAGE_RETENTION_HOURS","9223372036854775807",1)==0);
    CHECK(request("POST","/api/public/transfer/attachments/presign-upload",
        "{\"roomId\":\"expiry-room\",\"roomToken\":\"expiry-owner-token\",\"fileName\":\"overflow.bin\",\"sizeBytes\":1}",out)==500);
    CHECK(scalar("SELECT count(*) FROM transfer_attachment")==1 && unsetenv("SPECUS_OBJECT_STORAGE_RETENTION_HOURS")==0);
    puts("transfer expiry: actual upload/grant writers preserve fractional TTL; public views,three-column startup migration and retention overflow passed");
}
static void consume_race(int attachment_expires)
{
    reset(1); const char *near="2026-09-15T12:00:00.5000001Z";
    attachment(100,"UPLOADED",1,past,attachment_expires?near:far,0);
    grant(11,attachment_expires?far:near,0); settle();
    clock_calls=0; advance_at_call=2;
    char out[16384]; int status=request("GET","/api/public/transfer/downloads/grant-11",NULL,out);
    advance_at_call=0;
    long long consumed=scalar("SELECT count(*) FROM transfer_attachment_download_grant WHERE consumed_at IS NOT NULL");
    long long charged=scalar("SELECT count(*) FROM transfer_attachment_download_usage");
    if(status!=410 || consumed || charged) fprintf(stderr,"download race attachment=%d status=%d consumed=%lld charged=%lld clocks=%d\n",attachment_expires,status,consumed,charged,clock_calls);
    CHECK(status==410 && consumed==0 && charged==0 && clock_calls>=2);
    printf("transfer expiry: conditional consume crosses100ns attachment=%d,grant unused and quota uncharged\n",attachment_expires);
}
static void account_deletion(void)
{
    reset(1);
    attachment(1,"UPLOADED",1,past,"2026-09-15T12:00:00.5000001Z",0);
    attachment(2,"PENDING",1,far,far,0); attachment(3,"UPLOADED",1,past,past,0);
    attachment(4,"UPLOADED",1,past,far,0); sql("UPDATE transfer_attachment SET owner_username='bob' WHERE id=4");
    st_storage_management_user user;
    CHECK(st_storage_create_management_user(database,"alice","t1","unused-hash","USER",1,&user)==0
        && st_storage_delete_management_user(database,"t1","alice","admin")==0);
    CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE id IN(1,2) AND expires_at='2026-09-15T12:00:00.5000000Z' AND upload_expires_at=expires_at AND updated_at='2026-09-15T12:00:00.500Z'")==2);
    CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE id=3 AND expires_at='2026-09-15T11:00:00.0000000Z'")==1
        && scalar("SELECT count(*) FROM transfer_attachment WHERE id=4 AND expires_at='2026-09-18T12:00:00.0000000Z'")==1);
    puts("transfer expiry: deleting actual account expires its future attachments precisely,preserves past/foreign-owner rows");
}
static void invalid_expiry(void)
{
    reset(1); char out[16384];
    attachment(1,"PENDING",1,far,far,0); attachment(100,"UPLOADED",1,past,far,0); grant(11,far,0);
    sql("UPDATE transfer_attachment SET upload_expires_at='2026-09-18T12:00:00Z'||char(0)||'invalid' WHERE id=1;"
        "UPDATE transfer_attachment SET expires_at='2026-09-18T12:00:00Z'||char(0)||'invalid' WHERE id=100");
    settle(); int before=heads;
    CHECK(request("POST","/api/public/transfer/attachments/1/complete","{\"roomToken\":\"expiry-owner-token\"}",out)==409 && heads==before);
    CHECK(request("POST","/api/public/transfer/attachments/100/presign-download","{\"roomToken\":\"expiry-owner-token\"}",out)==409);
    CHECK(request("GET","/api/public/transfer/downloads/grant-11",NULL,out)==410);
    CHECK(scalar("SELECT count(*) FROM transfer_attachment WHERE (id=1 AND instr(upload_expires_at,char(0))>0) OR (id=100 AND instr(expires_at,char(0))>0)")==2);
    sql("UPDATE transfer_attachment SET expires_at='2026-09-18T12:00:00.0000000Z' WHERE id=100;"
        "UPDATE transfer_attachment_download_grant SET expires_at='2026-09-18T12:00:00Z'||char(0)||'invalid'");
    settle(); CHECK(request("GET","/api/public/transfer/downloads/grant-11",NULL,out)==410);
    CHECK(scalar("SELECT count(*) FROM transfer_attachment_download_grant WHERE consumed_at IS NULL AND instr(expires_at,char(0))>0")==1
        && scalar("SELECT count(*) FROM transfer_attachment_download_usage")==0);
    puts("transfer expiry: embedded NUL stays intact through startup and cannot authorize complete,grant issuance or consumption");
}
static void cleanup(void) { st_public_room_reset_for_tests(); st_object_storage_reset_for_tests(); unlink(database); }
int main(int argc,char **argv)
{
    CHECK(setenv("SPECUS_DB_SEED_DEMO_CLIENT","0",1)==0 && setenv("SPECUS_AUTH_JWT_SECRET","transfer-expiry-test-secret",1)==0
        && setenv("SPECUS_OBJECT_STORAGE_PROVIDER","aliyun-oss",1)==0 && setenv("SPECUS_OBJECT_STORAGE_REGION","cn-hangzhou",1)==0
        && setenv("SPECUS_OBJECT_STORAGE_BUCKET","bucket",1)==0 && setenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_ID","test-id",1)==0
        && setenv("SPECUS_OBJECT_STORAGE_ACCESS_KEY_SECRET","test-secret",1)==0 && setenv("SPECUS_OBJECT_STORAGE_PREFIX","prefix",1)==0
        && setenv("SPECUS_OBJECT_STORAGE_TEST_RESOLVE_ADDRESS","127.0.0.1",1)==0 && setenv("NO_PROXY","*",1)==0 && setenv("no_proxy","*",1)==0);
    int fd=mkstemp(database); CHECK(fd>=0); close(fd); CHECK(setenv("SPECUS_DATABASE_PATH",database,1)==0 && atexit(cleanup)==0);
    sqlite3_vfs fixed=*sqlite3_vfs_find(NULL); fixed.zName="transfer-expiry-clock"; fixed.xCurrentTime=sqlite_now; fixed.xCurrentTimeInt64=sqlite_now64;
    CHECK(sqlite3_vfs_register(&fixed,1)==SQLITE_OK); start_server();
    int selected=argc>1?atoi(argv[1]):-1;
    for(int mode=0;mode<5;++mode) if(selected<0 || mode==selected)
        for(int f=0;f<2;++f) for(int old=0;old<2;++old) boundaries(mode,f,old);
    if(selected<0 || selected==5) writers_and_migration();
    if(selected<0 || selected==6) { consume_race(0); consume_race(1); }
    if(selected<0 || selected==7) account_deletion();
    if(selected<0 || selected==8) invalid_expiry();
    CHECK(shutdown(listener,SHUT_RDWR)==0 && pthread_join(server_thread,NULL)==0); close(listener);
    CHECK(sqlite3_vfs_unregister(&fixed)==SQLITE_OK); return 0;
}
