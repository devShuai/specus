/* Reuse the real SQLite/native source fixture, not a parallel cache model. */
#define main catalog_source_reference_main
#include "catalog_source_tests.c"
#undef main

static int read_counts(fixture *f, const char *path, size_t *instances, size_t *mdns)
{
    st_peer_mesh_service_instance rows[8]; st_peer_mesh_mdns_candidate candidates[8];
#ifdef CATALOG_READ_BASELINE
    (void)path;
    int first=st_peer_mesh_list_service_instances(f->publisher.tenant_id, f->publisher.id,
        "svc-cache-source", rows, 8, instances);
    int second=st_peer_mesh_list_mdns_candidates(f->publisher.tenant_id, f->publisher.id, candidates, 8, mdns);
#else
    int first=st_peer_mesh_list_service_instances(path, f->publisher.tenant_id, f->publisher.id,
        "svc-cache-source", rows, 8, instances);
    int second=st_peer_mesh_list_mdns_candidates(path, f->publisher.tenant_id, f->publisher.id, candidates, 8, mdns);
#endif
    return first ? first : second;
}
static int read_scenario(const char *mode)
{
    fixture f; int failed = 1; size_t instances = 999, mdns = 999;
    pm_catalog cached = {0}; char name[81], other[512] = ""; char *message = NULL;
#define REQUIRE(c, text) do { if (!(c)) { fprintf(stderr,"FAIL catalog read %s: %s\n",mode,text); goto done; } } while(0)
    REQUIRE(prepare(&f) == 0 && snapshot(&f,&cached,name) == 0, "real accepted native/cache fixture");
    const char *path = f.path;
    if (!strcmp(mode,"sql-error")) {
        REQUIRE(execute(path,"ALTER TABLE specus_client_session RENAME TO unavailable_session") == 0,"actual native read failure");
        REQUIRE(read_counts(&f,path,&instances,&mdns) != 0 && instances == 0 && mdns == 0,"SQL failure is an error, not a successful cached projection");
        message=pm_build_catalog_message(&f.runtime,&cached,&f.publisher,&f.peer,1);
        REQUIRE(message == NULL,"no payload is constructed on native read failure");
        REQUIRE(execute(path,"ALTER TABLE unavailable_session RENAME TO specus_client_session") == 0
            && read_counts(&f,path,&instances,&mdns) == 0 && instances == 1 && mdns == 1 && current(&f),"native read recovery retains original CONTROL and cached cohort");
        failed=0; goto done;
    }
    if (!strcmp(mode,"stale")) REQUIRE(execute(path,"UPDATE specus_client_session SET channel_id='successor'") == 0,"actual native takeover");
    else if (!strcmp(mode,"sharing")) REQUIRE(execute(path,"UPDATE peer_mesh_service_sharing SET enabled=0") == 0,"actual sharing toggle");
    else if (!strcmp(mode,"mdns")) REQUIRE(execute(path,"UPDATE peer_mesh_service_sharing SET mdns_import_enabled=0") == 0,"actual mDNS toggle");
    else if (!strcmp(mode,"caps")) REQUIRE(execute(path,"UPDATE specus_client_session SET peer_service_discovery_version=0") == 0,"original source capability revoked");
    else if (!strcmp(mode,"listener")) REQUIRE(execute(path,"UPDATE peer_mesh_shared_service SET published_port=19090,path='/changed'") == 0,"new listener not yet reported");
    else if (!strcmp(mode,"database")) {
        snprintf(other,sizeof(other),"%s/other.db",f.directory);
        REQUIRE(st_storage_init(other,0) == 0,"separate physical database"); path = other;
    } else if (!strcmp(mode,"owner")) REQUIRE(execute(path,"UPDATE client_account SET owner_username='bob' WHERE client_name='source-publisher'; UPDATE peer_mesh_device SET owner_username='bob' WHERE client_name='source-publisher'") == 0,"coherent current publisher transfer");
    else if (!strcmp(mode,"unknown")) REQUIRE(execute(path,"UPDATE peer_mesh_shared_service SET visibility='FUTURE'") == 0,"unknown stored visibility");
    else if (!strcmp(mode,"malformed")) {
        char sql[512]; snprintf(sql,sizeof(sql),"UPDATE peer_mesh_shared_service SET visibility='ACL',allowed_client_ids='%lld,bad'",f.peer.id);
        REQUIRE(execute(path,sql) == 0,"mixed valid and malformed allowlist");
    } else if (!strcmp(mode,"direction")) {
        char sql[1024]; snprintf(sql,sizeof(sql),"UPDATE client_account SET owner_username='bob' WHERE rowid=%lld; UPDATE peer_mesh_device SET owner_username='bob' WHERE client_id=%lld; UPDATE peer_mesh_shared_service SET visibility='ACL'; INSERT INTO peer_mesh_acl(tenant_id,owner_username,source_client_id,target_client_id,source_client_name,target_client_name,direction,allowed) VALUES('catalog-source','bob',%lld,%lld,'source-peer','source-publisher','OUTBOUND',1)",f.peer.id,f.peer.id,f.peer.id,f.publisher.id);
        REQUIRE(execute(path,sql) == 0,"actual directional ACL fixture");
        REQUIRE(report(&f,2,7,"Directional Local") == 0 && snapshot(&f,&cached,name) == 0,"actual consumer-to-publisher report completed");
    } else REQUIRE(0,"known scenario");
    REQUIRE(read_counts(&f,path,&instances,&mdns) == 0,"management projection completed");
    fprintf(stderr,"OBSERVATION catalog read %s instances=%zu mdns=%zu active=%d\n",mode,instances,mdns,cached.active);
    if (!strcmp(mode,"stale") || !strcmp(mode,"sharing") || !strcmp(mode,"caps") || !strcmp(mode,"database"))
        REQUIRE(instances == 0 && mdns == 0,"management never exposes retired/unavailable/other-database cache");
    else if (!strcmp(mode,"mdns")) REQUIRE(instances == 1 && mdns == 0,"current mDNS switch gates candidates without deleting valid instance");
    else if (!strcmp(mode,"direction")) REQUIRE(cached.active && instances == 1,"authorized consumer may initiate toward publisher");
    if (strcmp(mode,"database")) {
        message=pm_build_catalog_message(&f.runtime,&cached,&f.publisher,&f.peer,1);
        REQUIRE(message != NULL,"native current catalog payload constructed");
        int visible=strstr(message,"\"serviceId\":\"svc-cache-source\"") != NULL;
        int expected=!strcmp(mode,"mdns") || !strcmp(mode,"direction");
        fprintf(stderr,"OBSERVATION catalog payload %s visible=%d expected=%d\n",mode,visible,expected);
        REQUIRE(visible == expected,"payload uses original source and current owner/directional policy/strict definition visibility");
    }
    if (!strcmp(mode,"unknown") || !strcmp(mode,"malformed")) {
        st_storage_peer_mesh_config config={0};
        int loaded=st_storage_load_peer_mesh_config(path,&f.publisher,0,1,&config);
        int blocked=loaded==0 && config.service_count==1 && config.services[0].allowed_peer_count==0;
        st_storage_peer_mesh_config_free(&config);
        REQUIRE(blocked,"login/runtime forwarding allowlist also rejects unknown visibility and malformed lists");
    }
    if (!strcmp(mode,"stale") || !strcmp(mode,"sharing") || !strcmp(mode,"mdns") || !strcmp(mode,"caps") || !strcmp(mode,"database")) {
        REQUIRE(execute(f.path,"UPDATE specus_client_session SET channel_id='catalog-original',peer_service_discovery_version=2; UPDATE peer_mesh_service_sharing SET enabled=1,mdns_import_enabled=1") == 0
            && read_counts(&f,f.path,&instances,&mdns) == 0 && instances == 1 && mdns == 1,
            "hidden original cohort is retained and can recover without another report");
    }
    if (!strcmp(mode,"listener")) {
        const char *updated="{\"type\":\"service-report\",\"enabled\":true,\"revision\":2,\"instanceId\":\"updated-listener\",\"services\":[{\"serviceId\":\"svc-cache-source\",\"name\":\"reported\",\"transport\":\"tcp\",\"application\":\"http\",\"publishedPort\":19090,\"path\":\"/changed\"}]}";
        REQUIRE(st_peer_mesh_handle_control(&f.runtime,f.publisher.client_name,NULL,updated) == 0 && snapshot(&f,&cached,name) == 0,"publisher explicitly reports updated listener");
        free(message); message=pm_build_catalog_message(&f.runtime,&cached,&f.publisher,&f.peer,1);
        REQUIRE(message && strstr(message,"\"publishedPort\":19090") && strstr(message,"\"path\":\"/changed\""),"current matching listener becomes visible after report");
    }
    if (!strcmp(mode,"direction")) {
        st_storage_peer_mesh_config config={0};
        int loaded=st_storage_load_peer_mesh_config(path,&f.publisher,0,1,&config);
        int permitted=loaded==0 && config.service_count==1 && config.services[0].allowed_peer_count==1;
        st_storage_peer_mesh_config_free(&config);
        REQUIRE(permitted,"consumer-to-publisher grant also reaches actual local forwarding config");
        char sql[512]; snprintf(sql,sizeof(sql),"UPDATE peer_mesh_acl SET source_client_id=%lld,target_client_id=%lld,source_client_name='source-publisher',target_client_name='source-peer'",f.publisher.id,f.peer.id);
        REQUIRE(execute(path,sql)==0 && report(&f,3,9,"Reverse Only")==0
            && read_counts(&f,path,&instances,&mdns)==0 && instances==0 && mdns==0,"opposite one-way grant cannot publish a consumer directory");
        loaded=st_storage_load_peer_mesh_config(path,&f.publisher,0,1,&config);
        permitted=loaded==0 && config.service_count==1 && config.services[0].allowed_peer_count==0;
        st_storage_peer_mesh_config_free(&config);
        REQUIRE(permitted,"opposite one-way grant cannot broaden forwarding config");
    }
    failed=0;
done:
    free(message); if(*other) unlink(other); cleanup(&f);
    printf("%s catalog read %s source/current policy/database projection\n",failed?"FAIL":"PASS",mode); return failed;
#undef REQUIRE
}
int main(int argc,char **argv)
{
    setenv("SPECUS_PEER_MESH_ENABLED","true",1);
    if(argc==2) return read_scenario(argv[1]);
    if(argc!=1) return 2;
    return read_scenario("stale") + read_scenario("sharing") + read_scenario("mdns") + read_scenario("caps")
        + read_scenario("database") + read_scenario("owner") + read_scenario("unknown") + read_scenario("malformed")
        + read_scenario("direction") + read_scenario("listener") + read_scenario("sql-error") ? 1:0;
}
