#define _POSIX_C_SOURCE 200809L
#include "instant.h"
#include "instant_reference_cases.h"
#include "media_capture.h"
#include "storage.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { fprintf(stderr,"media expiry failed line %d: %s\n",__LINE__,#ok); exit(1); } } while (0)
static char database[128];
static const time_t seconds=1789473600;
static long nanos;
static st_storage_client client;
static char sources[7][160];
static const char *content="0123456789";
time_t __wrap_time(time_t *out) { if(out) *out=seconds; return seconds; }
int __real_clock_gettime(clockid_t,struct timespec *);
int __wrap_clock_gettime(clockid_t id,struct timespec *out)
{
    if(id!=CLOCK_REALTIME) return __real_clock_gettime(id,out);
    out->tv_sec=seconds; out->tv_nsec=nanos; return 0;
}
static int sqlite_now64(sqlite3_vfs *vfs,sqlite3_int64 *out)
{ (void)vfs; *out=210866760000000LL+(sqlite3_int64)seconds*1000+nanos/1000000; return SQLITE_OK; }
static int sqlite_now(sqlite3_vfs *vfs,double *out)
{ sqlite3_int64 n; sqlite_now64(vfs,&n); *out=(double)n/86400000.0; return SQLITE_OK; }
static void cleanup(void) { unlink(database); }
static sqlite3 *open_db(void) { sqlite3 *db=NULL; CHECK(sqlite3_open(database,&db)==SQLITE_OK); return db; }
static void sql(const char *query)
{
    sqlite3 *db=open_db(); char *error=NULL; int rc=sqlite3_exec(db,query,NULL,NULL,&error);
    if(rc!=SQLITE_OK) fprintf(stderr,"SQL: %s\n%s\n",query,error);
    CHECK(rc==SQLITE_OK); sqlite3_free(error); sqlite3_close(db);
}
static long long scalar(const char *query)
{
    sqlite3 *db=open_db(); sqlite3_stmt *stmt=NULL;
    CHECK(sqlite3_prepare_v2(db,query,-1,&stmt,NULL)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_ROW);
    long long result=sqlite3_column_int64(stmt,0); CHECK(sqlite3_step(stmt)==SQLITE_DONE);
    sqlite3_finalize(stmt); sqlite3_close(db); return result;
}
static int response(const char *method,const char *path,char out[32768])
{
    st_media_capture_identity identity={client.tenant_id,"admin",1,1};
    CHECK(st_media_capture_build_response(method,path,&identity,database,out,32768)>0);
    return atoi(out+9);
}
static st_media_capture_session *begin(const char *url,const char *mime,size_t length)
{
    char content_type[160],content_length[64];
    snprintf(content_type,sizeof(content_type),"Content-Type: %s",mime);
    snprintf(content_length,sizeof(content_length),"Content-Length: %zu",length);
    char *headers[]={content_type,content_length};
    return st_media_capture_open(database,client.client_name,"media","GET",url,200,headers,2);
}
static void capture(const char *url,const char *mime,const char *body)
{
    st_media_capture_session *session=begin(url,mime,strlen(body));
    CHECK(session && st_media_capture_active(session) && st_media_capture_externalized(session));
    CHECK(st_media_capture_append(session,(const unsigned char *)body,strlen(body))==0);
    st_media_capture_complete(session); st_media_capture_free(session);
}
static void reset(int fractional)
{
    unlink(database); nanos=fractional?500000000L:0;
    char now[ST_INSTANT_CAPACITY]; CHECK(st_instant_now(now)==0 && st_instant_public(now,now,sizeof(now))==0 && strcmp(now,cutoffs[fractional])==0);
    CHECK(st_storage_init(database,1)==0 && st_storage_get_client_by_name(database,"Demo client",&client)==0);
    st_storage_http_route route;
    CHECK(st_storage_create_http_route_for_client(database,client.id,"media","https://origin.example/media",1,0,1,0,0,0,"","",&route)==0 && route.media_capture_enabled);
}
static void set_times(int id,const char *captured,const char *expiry,int legacy)
{
    char stored[ST_INSTANT_CAPACITY]; CHECK(st_instant_normalize(expiry,stored)==0);
    sqlite3 *db=open_db(); sqlite3_stmt *stmt=NULL;
    CHECK(sqlite3_prepare_v2(db,"UPDATE specus_http_media_capture SET captured_at=?1,expires_at=?2 WHERE id=?3",-1,&stmt,NULL)==SQLITE_OK
        && sqlite3_bind_text(stmt,1,captured,-1,SQLITE_TRANSIENT)==SQLITE_OK
        && sqlite3_bind_text(stmt,2,legacy?expiry:stored,-1,SQLITE_TRANSIENT)==SQLITE_OK
        && sqlite3_bind_int(stmt,3,id)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_DONE && sqlite3_changes(db)==1);
    sqlite3_finalize(stmt); sqlite3_close(db);
}
static long long log_lines(const char *name)
{
    char path[1024]; snprintf(path,sizeof(path),"%s/%s",getenv("SPECUS_MEDIA_CAPTURE_TEST_STATE_DIR"),name);
    FILE *file=fopen(path,"r"); if(!file) return 0;
    long long n=0; int c; while((c=fgetc(file))!=EOF) if(c=='\n') ++n;
    CHECK(fclose(file)==0); return n;
}
static void boundaries(int mode,int fractional,int legacy)
{
    reset(fractional);
    for(int i=0;i<7;++i) {
        snprintf(sources[i],sizeof(sources[i]),"https://origin.example/media/expiry-%d.mp4",i+1);
        capture(sources[i],"video/mp4",content);
        set_times(i+1,"2026-01-01T00:00:00Z",values[fractional][i],legacy);
    }
    CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE state='COMPLETE'")==7);
    CHECK(st_storage_init(database,1)==0 && st_storage_init(database,1)==0);
    CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE length(expires_at)<>28")==0);
    if(mode==0) {
        char out[32768]; CHECK(response("GET","/api/admin/traffic/media-captures?page=0&size=10",out)==200);
        const char *cursor=out;
        for(int i=6;i>=0;--i) {
            char expected[160]; snprintf(expected,sizeof(expected),"\"expiresAt\":\"%s\"",values[fractional][i]);
            cursor=strstr(cursor,expected);
            if(!cursor) fprintf(stderr,"list f=%d legacy=%d id=%d expected=%s\n%s\n",fractional,legacy,i+1,expected,out);
            CHECK(cursor); ++cursor;
        }
    } else if(mode==1 || mode==2) {
        if(mode==2) sql("UPDATE specus_http_media_capture SET deduplication_key=NULL");
        long long before=log_lines("initiated.log");
        for(int i=0;i<7;++i) {
            st_media_capture_session *session=begin(sources[i],"video/mp4",strlen(content));
            CHECK(session && st_media_capture_externalized(session));
            int active=st_media_capture_active(session);
            if(active!=(i<4)) fprintf(stderr,"reuse mode=%d f=%d legacy=%d id=%d active=%d\n",mode,fractional,legacy,i+1,active);
            CHECK(active==(i<4));
            st_media_capture_fail(session,"expiry fixture stop"); st_media_capture_free(session);
        }
        CHECK(log_lines("initiated.log")-before==4);
    } else if(mode==3) {
        long long before=log_lines("deleted.log");
        CHECK(st_media_capture_cleanup_expired(database)==0);
        CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE id BETWEEN 1 AND 3")==0
            && scalar("SELECT count(*) FROM specus_http_media_capture WHERE id BETWEEN 4 AND 7")==4
            && log_lines("deleted.log")-before==3);
    } else if(mode==4) {
        for(int i=0;i<7;++i) {
            char path[160],out[32768]; snprintf(path,sizeof(path),"/api/admin/traffic/media-captures/%d/playback-ticket",i+1);
            CHECK(response("POST",path,out)==200);
            const char *expected=i>=4?"\"cachedRanges\":[{\"start\":0,\"end\":9}]":"\"cachedRanges\":[]";
            if(!strstr(out,expected)) fprintf(stderr,"playback f=%d legacy=%d id=%d expected=%s\n%s\n",fractional,legacy,i+1,expected,out);
            CHECK(strstr(out,expected));
        }
    }
    printf("media expiry: mode=%d fractional=%d legacy=%d seven production boundaries passed\n",mode,fractional,legacy);
}
static void retention(int fractional,int legacy)
{
    reset(fractional);
    for(int i=0;i<7;++i) {
        char url[128],captured[ST_INSTANT_CAPACITY]; snprintf(url,sizeof(url),"https://origin.example/media/retention-%d.mp4",i+1);
        capture(url,"video/mp4",content);
        CHECK(st_instant_add_seconds(values[fractional][i],-60,captured)==0 && st_instant_public(captured,captured,sizeof(captured))==0);
        set_times(i+1,captured,"2026-09-15T11:00:00Z",legacy);
    }
    CHECK(st_storage_init(database,1)==0);
    sql("UPDATE specus_http_media_capture SET state='INCOMPLETE' WHERE id=6");
    long long before=log_lines("deleted.log");
    CHECK(st_media_capture_cleanup_expired(database)==0);
    CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE id<=4")==0
        && scalar("SELECT count(*) FROM specus_http_media_capture WHERE id>=5")==3 && log_lines("deleted.log")-before==4);
    for(int i=4;i<7;++i) {
        char expected[ST_INSTANT_CAPACITY],query[256]; CHECK(st_instant_normalize(values[fractional][i],expected)==0);
        snprintf(query,sizeof(query),"SELECT count(*) FROM specus_http_media_capture WHERE id=%d AND expires_at='%s'",i+1,expected);
        CHECK(scalar(query)==1);
    }
    printf("media expiry: retention fractional=%d legacy=%d keeps captured fractions and only extends strictly future targets\n",fractional,legacy);
}
static void writer(void)
{
    reset(1); capture("https://origin.example/media/writer.mp4","video/mp4",content);
    CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE captured_at='2026-09-15T12:00:00.500Z' AND expires_at='2026-09-15T12:01:00.5000000Z'")==1);
    CHECK(setenv("SPECUS_MEDIA_CAPTURE_RETENTION_SECONDS","9223372036854775807",1)==0);
    long long before=log_lines("initiated.log");
    CHECK(begin("https://origin.example/media/overflow.mp4","video/mp4",10)==NULL && log_lines("initiated.log")==before
        && scalar("SELECT count(*) FROM specus_http_media_capture")==1);
    CHECK(setenv("SPECUS_MEDIA_CAPTURE_RETENTION_SECONDS","60",1)==0);
    puts("media expiry: actual writer retains fractional60s,overflow writes no row and initiates no upload");
}
static void live_window(void)
{
    reset(1);
    capture("https://origin.example/media/seg.ts","video/mp2t",content);
    capture("https://origin.example/media/recent.ts","video/mp2t",content);
    capture("https://origin.example/media/old.ts","video/mp2t",content);
    sql("UPDATE specus_http_media_capture SET captured_at='2026-09-15T11:55:00.500Z' WHERE id=3");
    capture("https://origin.example/media/live.m3u8","application/vnd.apple.mpegurl",
        "#EXTM3U\n#EXT-X-TARGETDURATION:6\n#EXTINF:6,\nseg.ts\n");
    CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE id IN(1,2,4) AND live_stream=1 AND expires_at='2026-09-15T12:05:00.5000000Z'")==3);
    CHECK(scalar("SELECT count(*) FROM specus_http_media_capture WHERE id=3 AND live_stream=0 AND expires_at='2026-09-15T12:01:00.5000000Z'")==1);
    puts("media expiry: live manifest,referenced and recent segments retain300s fraction;exact-cutoff old segment unchanged");
}
int main(void)
{
    const char *endpoint=getenv("SPECUS_MEDIA_CAPTURE_TEST_ENDPOINT"); CHECK(endpoint && getenv("SPECUS_MEDIA_CAPTURE_TEST_STATE_DIR"));
    CHECK(setenv("SPECUS_ENV","test",1)==0 && setenv("SPECUS_AUTH_JWT_SECRET","media-expiry-test-secret",1)==0
        && setenv("SPECUS_DB_SEED_DEMO_CLIENT","1",1)==0 && setenv("SPECUS_MEDIA_CAPTURE_ENABLED","true",1)==0
        && setenv("SPECUS_MEDIA_CAPTURE_ENDPOINT",endpoint,1)==0 && setenv("SPECUS_MEDIA_CAPTURE_REGION","us-east-1",1)==0
        && setenv("SPECUS_MEDIA_CAPTURE_BUCKET","media-bucket",1)==0 && setenv("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_ID","media-access",1)==0
        && setenv("SPECUS_MEDIA_CAPTURE_ACCESS_KEY_SECRET","media-secret",1)==0 && setenv("SPECUS_MEDIA_CAPTURE_PATH_STYLE","true",1)==0
        && setenv("SPECUS_MEDIA_CAPTURE_RETENTION_SECONDS","60",1)==0 && setenv("SPECUS_MEDIA_CAPTURE_LIVE_WINDOW_SECONDS","300",1)==0
        && setenv("NO_PROXY","*",1)==0 && setenv("no_proxy","*",1)==0);
    snprintf(database,sizeof(database),"%s/specus-media-expiry-XXXXXX",access("/dev/shm",W_OK)==0?"/dev/shm":"/tmp");
    int fd=mkstemp(database); CHECK(fd>=0); close(fd); CHECK(atexit(cleanup)==0 && setenv("SPECUS_DATABASE_PATH",database,1)==0);
    sqlite3_vfs fixed=*sqlite3_vfs_find(NULL); fixed.zName="media-expiry-clock"; fixed.xCurrentTime=sqlite_now; fixed.xCurrentTimeInt64=sqlite_now64;
    CHECK(sqlite3_vfs_register(&fixed,1)==SQLITE_OK && st_media_capture_validate_current()==0 && st_media_capture_ready_current());
    const char *mode=getenv("SPECUS_MEDIA_EXPIRY_MODE"); int selected=mode?atoi(mode):-1;
    for(int m=0;m<5;++m) if(selected<0 || selected==m)
        for(int f=0;f<2;++f) for(int old=0;old<2;++old) boundaries(m,f,old);
    if(selected<0 || selected==5) for(int f=0;f<2;++f) for(int old=0;old<2;++old) retention(f,old);
    if(selected<0 || selected==6) writer();
    if(selected<0 || selected==7) live_window();
    CHECK(sqlite3_vfs_unregister(&fixed)==SQLITE_OK); return 0;
}
