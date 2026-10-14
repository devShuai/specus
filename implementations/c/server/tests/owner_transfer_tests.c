#define _POSIX_C_SOURCE 200809L
#include "owner_transfer.h"
#include "json.h"
#include "storage.h"
#include "server_harness.h"
#include <sqlite3.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ST_OWNER_TRANSFER_VECTOR_FILE
#define ST_OWNER_TRANSFER_VECTOR_FILE "../../../protocol/test-vectors/client-owner-transfer-plan-v1.json"
#endif
static char *vector, *base, *snapshots;
static char **cases;
static size_t case_count;
static const char *const table_names[] = {"clients", "credentials", "identities", "peers"};
static void free_row(st_owner_row *r) { free(r->tenant_id); free(r->client_name); free(r->owner_username); }

static int read_snapshot(const char *name, st_owner_snapshot *snapshot)
{
    memset(snapshot,0,sizeof(*snapshot));
    char *override=st_json_get_top_level_raw(snapshots,name); CHECK(override!=NULL,"missing snapshot %s",name);
    st_owner_rows *lists[]={&snapshot->clients,&snapshot->credentials,&snapshot->identities,&snapshot->peers};
    for(size_t n=0;n<4U;++n){
        char *array=st_json_get_top_level_raw(override,table_names[n]);
        if(array==NULL)array=st_json_get_top_level_raw(base,table_names[n]);
        CHECK(array!=NULL,"missing snapshot array");
        char *wrapped=malloc(strlen(array)+20U);CHECK(wrapped!=NULL,"allocation");sprintf(wrapped,"{\"rows\":%s}",array);
        char **rows=NULL;size_t count=0;CHECK(st_json_get_raw_array(wrapped,"rows",&rows,&count)==0,"array decode");free(array);free(wrapped);
        for(size_t i=0;i<count;++i){
            st_owner_row row={0};CHECK(st_json_get_i64(rows[i],"id",&row.id)==0,"row id");
            row.tenant_id=st_json_get_top_level_string(rows[i],"tenantId");row.client_name=st_json_get_top_level_string(rows[i],"clientName");row.owner_username=st_json_get_top_level_string(rows[i],"ownerUsername");
            (void)st_json_get_bool(rows[i],"enabled",&row.enabled);(void)st_json_get_i64(rows[i],"credentialId",&row.credential_id);(void)st_json_get_i64(rows[i],"clientId",&row.client_id);
            CHECK(row.tenant_id!=NULL&&st_owner_rows_add(lists[n],row)==0,"append row");
        }
        st_json_free_string_array(rows,count);
    }
    free(override);return 0;
}
static int same_field(const char *actual,const char *expected,const char *field)
{
    char *a=st_json_get_top_level_raw(actual,field),*b=st_json_get_top_level_raw(expected,field);
    int same=a!=NULL&&b!=NULL&&strcmp(a,b)==0;free(a);free(b);return same;
}
static int nullable_equal(const char *a,const char *b)
{
    return (a==NULL&&b==NULL)||(a!=NULL&&b!=NULL&&strcmp(a,b)==0);
}
static int check_states(const char *json,const st_owner_snapshot *s)
{
    char **rows=NULL;size_t count=0;
    CHECK(st_json_get_raw_array(json,"affectedClients",&rows,&count)==0,"affected rows");
    for(size_t i=0;i<count;++i){
        long long id=0;int enabled=-1;
        CHECK(st_json_get_i64(rows[i],"id",&id)==0&&st_json_get_bool(rows[i],"enabled",&enabled)==0,"client fields");
        const st_owner_row *found=NULL;
        for(size_t n=0;n<s->clients.len;++n)if(s->clients.items[n].id==id)found=&s->clients.items[n];
        char *name=st_json_get_top_level_string(rows[i],"clientName"),*owner=st_json_get_top_level_string(rows[i],"ownerUsername");
        CHECK(found!=NULL&&nullable_equal(name,found->client_name)&&nullable_equal(owner,found->owner_username)&&enabled==!!found->enabled,"client state changed");
        free(name);free(owner);
    }
    st_json_free_string_array(rows,count);
    char *credential=st_json_get_top_level_raw(json,"credentialId"),*enabled=st_json_get_top_level_raw(json,"credentialEnabled");
    char *raw_owner=st_json_get_top_level_raw(json,"credentialOwnerUsername"),*owner=st_json_get_top_level_string(json,"credentialOwnerUsername");
    CHECK(credential!=NULL&&enabled!=NULL&&raw_owner!=NULL,"credential fields missing");
    if(strcmp(credential,"null")==0)CHECK(strcmp(enabled,"null")==0&&strcmp(raw_owner,"null")==0,"legacy credential fields");
    else {const st_owner_row *found=NULL;long long id=strtoll(credential,NULL,10);for(size_t n=0;n<s->credentials.len;++n)if(s->credentials.items[n].id==id)found=&s->credentials.items[n];CHECK(found!=NULL&&nullable_equal(owner,found->owner_username)&&strcmp(enabled,found->enabled?"true":"false")==0,"credential state changed");}
    free(credential);free(enabled);free(raw_owner);free(owner);return 0;
}
static int check_preview(const char *actual,const char *expected)
{
    CHECK(st_json_is_valid_object(actual),"invalid preview JSON");
    const char *fields[]={"clientId","credentialId","canTransfer","conflictCode"};
    for(size_t i=0;i<4U;++i)CHECK(same_field(actual,expected,fields[i]),"field %s",fields[i]);
    int retained=0,has_revision=0;
    CHECK(st_json_get_bool(actual,"accessRetained",&retained)==0&&retained,"access warning");
    CHECK(st_json_get_bool(expected,"hasRevision",&has_revision)==0,"revision flag");
    char *revision=st_json_get_top_level_string(actual,"revision");CHECK((revision!=NULL)==has_revision,"revision nullness");free(revision);
    char **affected=NULL,**ids=NULL;size_t affected_count=0,id_count=0;long long total=-1;
    CHECK(st_json_get_raw_array(actual,"affectedClients",&affected,&affected_count)==0&&st_json_get_raw_array(expected,"affectedClientIds",&ids,&id_count)==0&&st_json_get_i64(actual,"affectedClientCount",&total)==0&&affected_count==id_count&&total==(long long)id_count,"complete count");
    for(size_t i=0;i<id_count;++i){long long id=0;CHECK(st_json_get_i64(affected[i],"id",&id)==0&&id==strtoll(ids[i],NULL,10),"sorted id");}
    st_json_free_string_array(affected,affected_count);st_json_free_string_array(ids,id_count);
    CHECK(strstr(actual,"secret")==NULL&&strstr(actual,"token")==NULL&&strstr(actual,"fingerprint")==NULL,"secret leaked");return 0;
}

static int shared_vectors(void)
{
    CHECK(case_count==29U,"shared vector count");
    for(size_t i=0;i<case_count;++i){
        char *name=st_json_get_top_level_string(cases[i],"name"),*snapshot_name=st_json_get_top_level_string(cases[i],"snapshot"),*scope=st_json_get_top_level_string(cases[i],"scope");
        char *request=st_json_get_top_level_raw(cases[i],"request"),*expected=st_json_get_top_level_raw(cases[i],"preview"),*error=st_json_get_top_level_raw(cases[i],"error"),*prepared_target=st_json_get_top_level_string(cases[i],"preparedTarget");
        st_owner_snapshot s;CHECK(read_snapshot(snapshot_name,&s)==0,"snapshot %s",name);
        long long id=0;int admin=1;CHECK(st_json_get_i64(cases[i],"id",&id)==0,"case id");(void)st_json_get_bool(cases[i],"admin",&admin);
        int group=strcmp(scope,"credential-group")==0;char *json=NULL,*target=NULL;char revision[65];const char *code=NULL;
        if(request!=NULL&&strstr(request,"$current")!=NULL){
            CHECK(st_owner_transfer_preview("tenant-a",admin,group,id,&s,&json,revision,&code)==200,"current preview");free(json);json=NULL;
            char *requested_target=st_json_get_top_level_string(request,"targetUsername"),*escaped=st_json_escape(requested_target);free(requested_target);free(request);
            CHECK(escaped!=NULL,"escape target");request=malloc(strlen(escaped)+180U);CHECK(request!=NULL,"request allocation");
            sprintf(request,"{\"scope\":\"%s\",\"targetUsername\":\"%s\",\"expectedRevision\":\"%s\"}",scope,escaped,revision);free(escaped);
        }
        int status=request==NULL?st_owner_transfer_preview("tenant-a",admin,group,id,&s,&json,revision,&code):st_owner_transfer_prepare("tenant-a",admin,group,id,&s,request,&json,&target,&code);
        if(error!=NULL){int want=0;char *expected_code=st_json_get_top_level_string(error,"code");CHECK(st_json_get_int(error,"status",&want)==0&&status==want&&code!=NULL&&strcmp(code,expected_code)==0&&json==NULL&&target==NULL,"case %s: %d/%s",name,status,code==NULL?"null":code);free(expected_code);}
        else {CHECK(status==200,"case %s: status%d/%s",name,status,code==NULL?"null":code);CHECK(check_states(json,&s)==0,"source states");if(prepared_target!=NULL)CHECK(target!=NULL&&strcmp(target,prepared_target)==0,"target %s",name);else CHECK(check_preview(json,expected)==0,"preview %s",name);}
        free(name);free(snapshot_name);free(scope);free(request);free(expected);free(error);free(prepared_target);free(json);free(target);st_owner_snapshot_free(&s);
    }
    printf("All 29 shared ownership plan/error-order cases passed\n");return 0;
}
static int revisions(void)
{
    for(int mutation=0;mutation<15;++mutation){
        st_owner_snapshot s;CHECK(read_snapshot("shared",&s)==0,"base snapshot");char *json=NULL;char old[65],now[65];const char *code=NULL;
        CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,old,&code)==200,"old revision");free(json);char **replace=NULL;
        switch(mutation){
        case 0:replace=&s.clients.items[0].owner_username;break;
        case 1:s.clients.items[0].enabled=!s.clients.items[0].enabled;break;
        case 2:replace=&s.clients.items[0].client_name;break;
        case 3:replace=&s.credentials.items[0].owner_username;break;
        case 4:s.credentials.items[0].enabled=!s.credentials.items[0].enabled;break;
        case 5:replace=&s.peers.items[0].owner_username;break;
        case 6:s.peers.items[0].enabled=!s.peers.items[0].enabled;break;
        case 7:replace=&s.peers.items[0].client_name;break;
        case 8:free_row(&s.clients.items[1]);s.clients.len=1U;free_row(&s.identities.items[1]);s.identities.len=1U;break;
        case 9:{st_owner_row c={.id=1003,.tenant_id=strdup("tenant-a"),.client_name=strdup("new"),.owner_username=strdup("alice"),.enabled=1};st_owner_row e={.id=703,.tenant_id=strdup("tenant-a"),.credential_id=501,.client_id=1003};CHECK(st_owner_rows_add(&s.clients,c)==0&&st_owner_rows_add(&s.identities,e)==0,"new member");break;}
        case 10:s.identities.items[0].id=799;break;
        case 11:free_row(&s.peers.items[0]);s.peers.len=0U;break;
        case 12:s.peers.items[0].id=899;break;
        case 13:free(s.clients.items[0].owner_username);s.clients.items[0].owner_username=NULL;break;
        case 14:s.identities.items[0].id=9007199254740992LL;break;
        }
        if(replace!=NULL){free(*replace);*replace=strdup("changed");CHECK(*replace!=NULL,"replace");}
        CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,now,&code)==200&&strcmp(old,now)!=0,"mutation%d unchanged",mutation);CHECK(check_states(json,&s)==0,"mutated source states");free(json);json=NULL;
        char request[256];snprintf(request,sizeof(request),"{\"scope\":\"credential-group\",\"targetUsername\":\"bob\",\"expectedRevision\":\"%s\"}",old);char *target=NULL;
        CHECK(st_owner_transfer_prepare("tenant-a",1,1,501,&s,request,&json,&target,&code)==409&&strcmp(code,"TRANSFER_PREVIEW_CHANGED")==0,"mutation%d not stale",mutation);free(json);free(target);st_owner_snapshot_free(&s);
    }
    st_owner_snapshot s;CHECK(read_snapshot("shared",&s)==0,"base snapshot");char *json=NULL;char first[65],second[65];const char *code=NULL;
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,first,&code)==200,"original");free(json);
    st_owner_row tmp=s.clients.items[0];s.clients.items[0]=s.clients.items[1];s.clients.items[1]=tmp;tmp=s.identities.items[0];s.identities.items[0]=s.identities.items[1];s.identities.items[1]=tmp;
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,second,&code)==200&&strcmp(first,second)==0,"order affects revision");free(json);
    s.identities.items[0].id=9007199254740992LL;
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,first,&code)==200,"int64 revision");free(json);
    ++s.identities.items[0].id;
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,second,&code)==200&&strcmp(first,second)!=0,"adjacent int64 identities collapsed through double");free(json);
    free(s.clients.items[0].owner_username);s.clients.items[0].owner_username=NULL;
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,first,&code)==200,"null owner");free(json);
    s.clients.items[0].owner_username=strdup("");CHECK(s.clients.items[0].owner_username!=NULL,"empty owner");
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,second,&code)==200&&strcmp(first,second)!=0,"null/empty revision collision");free(json);st_owner_snapshot_free(&s);
    CHECK(read_snapshot("unique",&s)==0,"unique snapshot");
    CHECK(st_owner_transfer_preview("tenant-a",1,0,1001,&s,&json,first,&code)==200,"single revision");free(json);
    CHECK(st_owner_transfer_preview("tenant-a",1,1,501,&s,&json,second,&code)==200&&strcmp(first,second)!=0,"scope not bound");free(json);
    st_owner_rows *lists[]={&s.clients,&s.credentials,&s.identities,&s.peers};
    for(size_t n=0;n<4U;++n)for(size_t i=0;i<lists[n]->len;++i){free(lists[n]->items[i].tenant_id);lists[n]->items[i].tenant_id=strdup("tenant-b");CHECK(lists[n]->items[i].tenant_id!=NULL,"tenant allocation");}
    CHECK(st_owner_transfer_preview("tenant-b",1,1,501,&s,&json,first,&code)==200&&strcmp(first,second)!=0,"tenant not bound");free(json);st_owner_snapshot_free(&s);
    CHECK(read_snapshot("legacy",&s)==0,"legacy snapshot");
    CHECK(st_owner_transfer_preview("tenant-a",1,0,1001,&s,&json,first,&code)==200,"path revision");free(json);
    CHECK(st_owner_transfer_preview("tenant-a",1,0,1002,&s,&json,second,&code)==200&&strcmp(first,second)!=0,"path not bound");free(json);st_owner_snapshot_free(&s);
    printf("All 15 relevant revision mutations rejected; sorted snapshot stable\n");return 0;
}

static int seed_snapshot(sqlite3 *db,st_owner_snapshot *s)
{
    CHECK(sqlite3_exec(db,"BEGIN; DELETE FROM specus_client_identity; DELETE FROM peer_mesh_device; DELETE FROM specus_client_credential; DELETE FROM client_account;",NULL,NULL,NULL)==SQLITE_OK,"clear fixture");
    const char *sql[]={
        "INSERT INTO client_account(id,tenant_id,client_name,owner_username,enabled,connection_limit_per_minute)VALUES(?1,?2,?3,?4,?5,60)",
        "INSERT INTO specus_client_credential(id,tenant_id,owner_username,enabled,api_key,secret_hash)VALUES(?1,?2,?4,?5,'secret-key-'||?1,'secret-hash')",
        "INSERT INTO specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user)VALUES(?1,?2,?6,?7,'identity-'||?1,'secret-fingerprint-'||?1,'user')",
        "INSERT INTO peer_mesh_device(id,tenant_id,client_id,client_name,owner_username,enabled,public_key)VALUES(?1,?2,?7,?3,?4,?5,'secret-key')"};
    st_owner_rows *lists[]={&s->clients,&s->credentials,&s->identities,&s->peers};
    for(size_t n=0;n<4U;++n){sqlite3_stmt *stmt=NULL;CHECK(sqlite3_prepare_v2(db,sql[n],-1,&stmt,NULL)==SQLITE_OK,"fixture prepare: %s",sqlite3_errmsg(db));
        for(size_t i=0;i<lists[n]->len;++i){const st_owner_row *r=&lists[n]->items[i];sqlite3_reset(stmt);sqlite3_clear_bindings(stmt);sqlite3_bind_int64(stmt,1,r->id);sqlite3_bind_text(stmt,2,strcmp(r->tenant_id,"tenant-a")==0?"default":r->tenant_id,-1,SQLITE_STATIC);sqlite3_bind_text(stmt,3,r->client_name,-1,SQLITE_STATIC);sqlite3_bind_text(stmt,4,r->owner_username,-1,SQLITE_STATIC);sqlite3_bind_int(stmt,5,r->enabled);sqlite3_bind_int64(stmt,6,r->credential_id);sqlite3_bind_int64(stmt,7,r->client_id);CHECK(sqlite3_step(stmt)==SQLITE_DONE,"fixture table%zu: %s",n,sqlite3_errmsg(db));}
        sqlite3_finalize(stmt);
    }
    CHECK(sqlite3_exec(db,"COMMIT",NULL,NULL,NULL)==SQLITE_OK,"commit fixture");return 0;
}
static int http_scenario(test_server *server)
{
    int status=0;char *body=NULL;
    CHECK(http_request(server->admin_port,"POST","/auth/login","{\"username\":\"" ADMIN_USERNAME "\",\"password\":\"" ADMIN_PASSWORD "\"}",NULL,&status,&body)==0&&status==200,"admin login");
    char *token=st_json_get_top_level_string(body,"accessToken");free(body);CHECK(token!=NULL,"real admin token");
    CHECK(http_request(server->admin_port,"POST","/api/admin/users","{\"username\":\"preview-user\",\"password\":\"preview-user-password\",\"role\":\"USER\",\"enabled\":true}",token,&status,&body)==0&&status==201,"create user status%d body%s",status,body==NULL?"":body);free(body);
    CHECK(http_request(server->admin_port,"POST","/auth/login","{\"username\":\"preview-user\",\"password\":\"preview-user-password\",\"tenantId\":\"default\"}",NULL,&status,&body)==0&&status==200,"user login");
    char *user=st_json_get_top_level_string(body,"accessToken");free(body);CHECK(user!=NULL,"real user token");
    const char *prefixes[]={"/api/admin/clients/","/api/admin/client-credentials/"};
    for(size_t n=0;n<2U;++n){char path[160];snprintf(path,sizeof(path),"%sinvalid/owner-transfer",prefixes[n]);CHECK(http_request(server->admin_port,"GET",path,NULL,NULL,&status,&body)==0&&status==401,"anonymous priority");free(body);CHECK(http_request(server->admin_port,"GET",path,NULL,user,&status,&body)==0&&status==403,"role priority");free(body);CHECK(http_request(server->admin_port,"GET",path,NULL,token,&status,&body)==0&&status==400,"id priority");free(body);}free(user);
    sqlite3 *db=NULL;CHECK(sqlite3_open(server->db_path,&db)==SQLITE_OK,"fixture db");size_t verified=0U;
    for(size_t i=0;i<case_count;++i){
        char *request=st_json_get_top_level_raw(cases[i],"request");int has_request=request!=NULL;free(request);if(has_request)continue;
        char *name=st_json_get_top_level_string(cases[i],"snapshot");if(strcmp(name,"duplicate-peer")==0){free(name);continue;}
        st_owner_snapshot s;CHECK(read_snapshot(name,&s)==0,"snapshot");free(name);CHECK(seed_snapshot(db,&s)==0,"seed");
        char *scope=st_json_get_top_level_string(cases[i],"scope");long long id=0;CHECK(st_json_get_i64(cases[i],"id",&id)==0,"id");char path[160];snprintf(path,sizeof(path),"%s%lld/owner-transfer",strcmp(scope,"single")==0?prefixes[0]:prefixes[1],id);free(scope);
        char *error=st_json_get_top_level_raw(cases[i],"error"),*expected=st_json_get_top_level_raw(cases[i],"preview");int want=200;if(error!=NULL)CHECK(st_json_get_int(error,"status",&want)==0,"expected status");
        CHECK(http_request(server->admin_port,"GET",path,NULL,token,&status,&body)==0&&status==want,"HTTPvector%zu status%d body%s",i,status,body==NULL?"":body);
        if(error==NULL){CHECK(check_preview(body,expected)==0,"HTTP preview");CHECK(check_states(body,&s)==0,"HTTP source states");}else CHECK(same_field(body,error,"code"),"HTTP code");st_owner_snapshot_free(&s);free(error);free(expected);free(body);++verified;
    }
    CHECK(verified==16U,"HTTP vector count%zu",verified);
    st_owner_snapshot s={0};st_owner_row credential={.id=501,.tenant_id=strdup("tenant-a"),.owner_username=strdup("alice")};CHECK(st_owner_rows_add(&s.credentials,credential)==0,"credential");
    for(int i=0;i<1050;++i){char name[128];snprintf(name,sizeof(name),"quoted\"device\n中文-%d",i);st_owner_row c={.id=1001+i,.tenant_id=strdup("tenant-a"),.client_name=strdup(name),.owner_username=strdup("alice"),.enabled=i%2};st_owner_row e={.id=10001+i,.tenant_id=strdup("tenant-a"),.credential_id=501,.client_id=1001+i};CHECK(st_owner_rows_add(&s.clients,c)==0&&st_owner_rows_add(&s.identities,e)==0,"large group");}
    CHECK(seed_snapshot(db,&s)==0,"seed1050");st_owner_snapshot_free(&s);const char *path="/api/admin/client-credentials/501/owner-transfer";
    CHECK(http_request(server->admin_port,"GET",path,NULL,token,&status,&body)==0&&status==200&&strlen(body)>65536U,"unbounded real HTTP");
    char **affected=NULL;size_t count=0U;CHECK(st_json_get_raw_array(body,"affectedClients",&affected,&count)==0&&count==1050U,"full1050");long long last=0;CHECK(st_json_get_i64(affected[count-1],"id",&last)==0&&last==2050,"sorted tail");st_json_free_string_array(affected,count);
    char *revision=st_json_get_top_level_string(body,"revision");free(body);CHECK(revision!=NULL,"revision");
    CHECK(sqlite3_exec(db,"UPDATE specus_client_identity SET last_seen_at='2026-10-14T20:00:00Z'",NULL,NULL,NULL)==SQLITE_OK,"liveness fixture");
    CHECK(http_request(server->admin_port,"GET",path,NULL,token,&status,&body)==0&&status==200,"liveness GET");char *current=st_json_get_top_level_string(body,"revision");CHECK(current!=NULL&&strcmp(revision,current)==0,"liveness invalidates revision");free(current);free(body);
    CHECK(server_stop(server,10000)==0&&server_start(server)==0,"restart native same DB");CHECK(http_request(server->admin_port,"GET",path,NULL,token,&status,&body)==0&&status==200,"restart GET");current=st_json_get_top_level_string(body,"revision");CHECK(current!=NULL&&strcmp(revision,current)==0,"stateless restart revision");free(current);free(body);free(revision);sqlite3_close(db);free(token);
    printf("16 real HTTP vectors, auth priority, 1050 unbounded UTF8 rows and restart revision passed\n");return 0;
}
#include "owner_transfer_write_tests.h"

int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    server_binary=argv[1];signal(SIGPIPE,SIG_IGN);setvbuf(stdout,NULL,_IOLBF,0);
    FILE *file=fopen(ST_OWNER_TRANSFER_VECTOR_FILE,"rb");CHECK(file!=NULL,"shared vector file");CHECK(fseek(file,0,SEEK_END)==0,"vector seek");long size=ftell(file);CHECK(size>0&&fseek(file,0,SEEK_SET)==0,"vector size");vector=malloc((size_t)size+1U);CHECK(vector!=NULL&&fread(vector,1,(size_t)size,file)==(size_t)size,"vector read");fclose(file);vector[size]='\0';
    base=st_json_get_top_level_raw(vector,"base");snapshots=st_json_get_top_level_raw(vector,"snapshots");CHECK(base!=NULL&&snapshots!=NULL&&st_json_get_raw_array(vector,"cases",&cases,&case_count)==0,"vector decode");
    int failed=shared_vectors()|revisions();if(!failed)failed=ownership_writer_tests();
    if(!failed)failed=run_on_fresh_server("owner-transfer-preview",http_scenario,NULL);
    st_json_free_string_array(cases,case_count);free(snapshots);free(base);free(vector);return failed?1:0;
}
