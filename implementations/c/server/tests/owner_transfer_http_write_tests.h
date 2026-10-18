/* Real HTTP writes. SQL only builds fixtures and inspects committed state. */
#ifndef SPECUS_OWNER_TRANSFER_HTTP_WRITE_TESTS_H
#define SPECUS_OWNER_TRANSFER_HTTP_WRITE_TESTS_H

static int oh_login(test_server *server, const char *username, const char *role,
                    const char *admin, char **token)
{
    char request[512]; int status=0; char *body=NULL;
    if(role!=NULL) {
        snprintf(request,sizeof(request),"{\"username\":\"%s\",\"password\":\"ownership-http-password\",\"role\":\"%s\",\"enabled\":true}",username,role);
        CHECK(http_request(server->admin_port,"POST","/api/admin/users",request,admin,&status,&body)==0 && status==201,"create HTTP account %s status%d",username,status);free(body);
    }
    snprintf(request,sizeof(request),"{\"username\":\"%s\",\"password\":\"%s\",\"tenantId\":\"default\"}",username,role==NULL?ADMIN_PASSWORD:"ownership-http-password");
    CHECK(http_request(server->admin_port,"POST","/auth/login",request,NULL,&status,&body)==0 && status==200,"HTTP login %s status%d",username,status);
    *token=st_json_get_top_level_string(body,"accessToken");free(body);CHECK(*token!=NULL,"real token");return 0;
}

static int oh_seed(sqlite3 *db,const char *name)
{
    st_owner_snapshot snapshot={0};
    if(strcmp(name,"large")==0) {
        st_owner_row credential={.id=501,.tenant_id=strdup("tenant-a"),.owner_username=strdup("alice")};
        CHECK(st_owner_rows_add(&snapshot.credentials,credential)==0,"large credential");
        for(int i=0;i<1050;++i) {
            char label[96];snprintf(label,sizeof(label),"quoted\"device\n中文-%d",i);
            st_owner_row client={.id=1001+i,.tenant_id=strdup("tenant-a"),.client_name=strdup(label),.owner_username=strdup("alice"),.enabled=i%2};
            st_owner_row identity={.id=10001+i,.tenant_id=strdup("tenant-a"),.credential_id=501,.client_id=1001+i};
            CHECK(st_owner_rows_add(&snapshot.clients,client)==0 && st_owner_rows_add(&snapshot.identities,identity)==0,"1050-member fixture");
        }
    } else CHECK(read_snapshot(name,&snapshot)==0,"snapshot %s",name);
    int rc=seed_snapshot(db,&snapshot);st_owner_snapshot_free(&snapshot);CHECK(rc==0,"HTTP fixture seed");
    CHECK(ow_sql(db,"DELETE FROM client_owner_transfer_audit; UPDATE specus_management_user SET enabled=1 WHERE login_name='Bob' AND tenant_id='default';") == 0
        && sqlite3_changes(db)==1,"reset actual Bob HTTP fixture");return 0;
}

static char *oh_state(sqlite3 *db)
{
    const char *sql="SELECT json_array("
        "(SELECT json_group_array(json_array(id,tenant_id,client_name,owner_username,enabled,updated_at)) FROM (SELECT * FROM client_account ORDER BY id)),"
        "(SELECT json_group_array(json_array(id,tenant_id,owner_username,enabled,api_key,secret_hash,max_online_instances,updated_at)) FROM (SELECT * FROM specus_client_credential ORDER BY id)),"
        "(SELECT json_group_array(json_array(id,tenant_id,credential_id,client_id)) FROM (SELECT * FROM specus_client_identity ORDER BY id)),"
        "(SELECT json_group_array(json_array(id,tenant_id,client_id,owner_username,enabled,public_key,updated_at)) FROM (SELECT * FROM peer_mesh_device ORDER BY id)),"
        "(SELECT COUNT(*) FROM client_owner_transfer_audit))";
    sqlite3_stmt *stmt=NULL;char *result=NULL;
    if(sqlite3_prepare_v2(db,sql,-1,&stmt,NULL)==SQLITE_OK && sqlite3_step(stmt)==SQLITE_ROW)
        result=strdup((const char *)sqlite3_column_text(stmt,0));
    sqlite3_finalize(stmt);return result;
}

static int oh_request(test_server *server,const char *token,const char *path,const char *scope,
                       const char *target,char **request)
{
    int status=0;char *body=NULL;
    CHECK(http_request(server->admin_port,"GET",path,NULL,token,&status,&body)==0 && status==200,"actual GET before POST status%d",status);
    char *revision=st_json_get_top_level_string(body,"revision");free(body);CHECK(revision!=NULL,"transferable HTTP revision");
    char *escaped=st_json_escape(target);CHECK(escaped!=NULL,"target escape");
    *request=malloc(strlen(escaped)+strlen(revision)+128U);CHECK(*request!=NULL,"HTTP body allocation");
    sprintf(*request,"{\"scope\":\"%s\",\"targetUsername\":\"%s\",\"expectedRevision\":\"%s\"}",scope,escaped,revision);
    free(escaped);free(revision);return 0;
}

static int oh_expect(test_server *server,sqlite3 *db,const char *token,const char *path,
                     const char *request,int expected,const char *code)
{
    int status=0;char *body=NULL,*before=oh_state(db);CHECK(before!=NULL,"capture resource state");
    CHECK(http_request(server->admin_port,"POST",path,request,token,&status,&body)==0,"real POST transport");
    char *after=oh_state(db);int unchanged=after!=NULL && strcmp(before,after)==0;free(before);free(after);
    char *actual_code=body==NULL?NULL:st_json_get_top_level_string(body,"code");
    int valid=status==expected && (code==NULL || (actual_code!=NULL && strcmp(actual_code,code)==0)) && unchanged;
    if(!valid)fprintf(stderr,"HTTP ownership expected%d/%s actual%d/%s unchanged%d\n",expected,code==NULL?"":code,status,actual_code==NULL?"":actual_code,unchanged);
    free(actual_code);free(body);return valid?0:1;
}

static int oh_structural(test_server *server,sqlite3 *db,const char *admin,const char *user)
{
    size_t count=0;int failed=0;
    for(size_t i=0;i<case_count;++i) {
        char *request=st_json_get_top_level_raw(cases[i],"request");
        long long vector_id=0;CHECK(st_json_get_i64(cases[i],"id",&vector_id)==0,"HTTP vector id");
        if(request==NULL && (vector_id<=0 || vector_id>9007199254740991LL))request=strdup("{}");
        if(request==NULL)continue;
        char *error=st_json_get_top_level_raw(cases[i],"error");
        if(error==NULL){free(request);continue;}
        char *snapshot=st_json_get_top_level_string(cases[i],"snapshot"),*scope=st_json_get_top_level_string(cases[i],"scope");
        char *code=st_json_get_top_level_string(error,"code");long long id=0;int expected=0,authorized=1;
        CHECK(snapshot!=NULL && scope!=NULL && code!=NULL && st_json_get_i64(cases[i],"id",&id)==0 && st_json_get_int(error,"status",&expected)==0,"HTTP shared case");
        (void)st_json_get_bool(cases[i],"admin",&authorized);
        CHECK(oh_seed(db,snapshot)==0,"shared HTTP seed");
        char path[180];snprintf(path,sizeof(path),"/api/admin/%s/%lld/owner-transfer",strcmp(scope,"single")==0?"clients":"client-credentials",id);
        int rc=oh_expect(server,db,authorized?admin:user,path,request,expected,code);
        printf("%s HTTP POST structural vector %zu\n",rc?"FAIL":"PASS",i);failed|=rc;++count;
        free(request);free(error);free(snapshot);free(scope);free(code);
    }
    CHECK(count==12U,"expected12 error-order POST vectors, got%zu",count);return failed;
}

static int oh_access(test_server *server,const char *token,int expected)
{
    int status=0;char *body=NULL;
    int rc=http_request(server->admin_port,"GET","/api/admin/clients/1001",NULL,token,&status,&body);
    free(body);CHECK(rc==0 && status==expected,"current REST ownership expected%d actual%d",expected,status);return 0;
}
static int oh_success(test_server *server,sqlite3 *db,const char *admin,const char *snapshot,
                       int group,long long id,size_t count,const char *target,const char *canonical,
                       const char *alice,const char *bob)
{
    CHECK(oh_seed(db,snapshot)==0,"positive HTTP seed");
    if(count>0)CHECK(oh_access(server,alice,200)==0 && oh_access(server,bob,404)==0,"pre-transfer current REST owner");
    char path[160];snprintf(path,sizeof(path),"/api/admin/%s/%lld/owner-transfer",group?"client-credentials":"clients",id);
    char *request=NULL,*body=NULL;int status=0;
    CHECK(oh_request(server,admin,path,group?"credential-group":"single",target,&request)==0,"real GET confirmation");
    CHECK(http_request(server->admin_port,"POST",path,request,admin,&status,&body)==0 && status==200,"%s HTTP transfer status%d",snapshot,status);
    int changed=0,retained=0;char *owner=st_json_get_top_level_string(body,"targetUsername"),**ids=NULL;size_t ids_count=0;
    CHECK(st_json_get_bool(body,"changed",&changed)==0 && changed && st_json_get_bool(body,"accessRetained",&retained)==0 && retained
        && owner!=NULL && strcmp(owner,canonical)==0 && st_json_get_raw_array(body,"affectedClientIds",&ids,&ids_count)==0 && ids_count==count,"complete HTTP result");
    for(size_t i=0;i<ids_count;++i) {
        sqlite3_stmt *stmt=NULL;CHECK(sqlite3_prepare_v2(db,"SELECT owner_username FROM client_account WHERE id=? AND tenant_id='default'",-1,&stmt,NULL)==SQLITE_OK,"owner query");
        sqlite3_bind_int64(stmt,1,strtoll(ids[i],NULL,10));
        CHECK(sqlite3_step(stmt)==SQLITE_ROW && strcmp((const char *)sqlite3_column_text(stmt,0),canonical)==0,"actual committed HTTP owner");sqlite3_finalize(stmt);
    }
    st_json_free_string_array(ids,ids_count);free(owner);free(body);
    if(count>0)CHECK(oh_access(server,alice,404)==0 && oh_access(server,bob,strcmp(canonical,"Bob")==0?200:404)==0
        && oh_access(server,admin,200)==0,"old owner loses REST, target gains it, independent admin retained");
    CHECK(ow_scalar(db,"SELECT COUNT(*) FROM client_owner_transfer_audit")==1,"exactly one committed audit");
    CHECK(oh_expect(server,db,admin,path,request,409,"TRANSFER_PREVIEW_CHANGED")==0,"old confirmation cannot replay");free(request);request=NULL;
    CHECK(oh_request(server,admin,path,group?"credential-group":"single",target,&request)==0,"fresh no-op preview");
    CHECK(http_request(server->admin_port,"POST",path,request,admin,&status,&body)==0 && status==200
        && st_json_get_bool(body,"changed",&changed)==0 && !changed && ow_scalar(db,"SELECT COUNT(*) FROM client_owner_transfer_audit")==1,"no-op HTTP does not audit");
    free(request);free(body);printf("PASS HTTP POST %s canonical target, retained access flag, audit, stale replay and no-op\n",snapshot);return 0;
}

static int oh_mutation(test_server *server,sqlite3 *db,const char *admin,const char *mutation,
                        int expected,const char *code)
{
    CHECK(oh_seed(db,"shared")==0,"mutation seed");const char *path="/api/admin/client-credentials/501/owner-transfer";
    char *request=NULL;CHECK(oh_request(server,admin,path,"credential-group","Bob",&request)==0,"mutation preview");
    CHECK(ow_sql(db,mutation)==0,"deterministic mutation after HTTP preview");
    if(strncmp(mutation,"CREATE ",7)!=0)CHECK(sqlite3_changes(db)>0,"fixture mutation must affect a row");
    int rc=oh_expect(server,db,admin,path,request,expected,code);free(request);return rc;
}

static int http_write_scenario(test_server *server)
{
    char *admin=NULL,*bob=NULL,*user=NULL,*alice=NULL;sqlite3 *db=NULL;
    CHECK(oh_login(server,ADMIN_USERNAME,NULL,NULL,&admin)==0 && oh_login(server,"Bob","USER",admin,&bob)==0
        && oh_login(server,"http-ordinary","USER",admin,&user)==0 && oh_login(server,"alice","USER",admin,&alice)==0,"HTTP management identities");
    CHECK(sqlite3_open(server->db_path,&db)==SQLITE_OK,"HTTP assertions DB");sqlite3_busy_timeout(db,5000);
    int failed=oh_structural(server,db,admin,user);
    const char *paths[]={"/api/admin/clients/invalid/owner-transfer","/api/admin/client-credentials/invalid/owner-transfer"};
    for(size_t i=0;i<2;++i) {
        failed|=oh_expect(server,db,NULL,paths[i],"null",401,NULL);
        failed|=oh_expect(server,db,user,paths[i],"null",403,"FORBIDDEN");
        failed|=oh_expect(server,db,admin,paths[i],"{}",400,"INVALID_TRANSFER_REQUEST");
    }
    if(!failed) {
        failed|=oh_success(server,db,admin,"legacy",0,1001,1,"  bOB  ","Bob",alice,bob);
        failed|=oh_success(server,db,admin,"unique",0,1001,1,"Bob","Bob",alice,bob);
        failed|=oh_success(server,db,admin,"shared",1,501,2,"Bob","Bob",alice,bob);
        failed|=oh_success(server,db,admin,"empty",1,501,0,"Bob","Bob",alice,bob);
        failed|=oh_success(server,db,admin,"duplicate-identities",0,1001,1,"Bob","Bob",alice,bob);
        failed|=oh_success(server,db,admin,"shared",1,501,2,ADMIN_USERNAME,ADMIN_USERNAME,alice,bob);
        failed|=oh_success(server,db,admin,"large",1,501,1050,"Bob","Bob",alice,bob);
        failed|=oh_mutation(server,db,admin,"UPDATE client_account SET client_name='renamed' WHERE id=1001",409,"TRANSFER_PREVIEW_CHANGED");
        failed|=oh_mutation(server,db,admin,"UPDATE client_account SET enabled=0 WHERE id=1001",409,"TRANSFER_PREVIEW_CHANGED");
        failed|=oh_mutation(server,db,admin,"DELETE FROM client_account WHERE id=1001",409,"INCONSISTENT_CREDENTIAL_GROUP");
        failed|=oh_mutation(server,db,admin,"DELETE FROM specus_client_credential WHERE id=501",404,"RESOURCE_NOT_FOUND");
        failed|=oh_mutation(server,db,admin,"UPDATE specus_management_user SET enabled=0 WHERE login_name='Bob' AND tenant_id='default'",400,"INVALID_TARGET_OWNER");
        failed|=oh_mutation(server,db,admin,"CREATE TRIGGER http_fail_audit BEFORE INSERT ON client_owner_transfer_audit BEGIN SELECT RAISE(ABORT,'http audit fault'); END",500,"INTERNAL_SERVER_ERROR");
    }
    sqlite3_close(db);free(admin);free(user);free(alice);free(bob);printf("%s real HTTP ownership write acceptance\n",failed?"FAIL":"PASS");return failed;
}
#endif
