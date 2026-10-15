package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.*;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.handler.MessageRequestHandler;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.*;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.websocket.ClientMessagesWebSocketHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real high-ID client/session rows, actual report handler and commit callbacks, no mocked
 * authorization/results. Does not claim current database routing policy/catalog-send acceptance. */
public final class PeerCatalogCommitAssertions {
    enum Case { COMMIT,ROLLBACK,UPDATE_ROLLBACK,WITHDRAW_ROLLBACK,AUTH_REFRESH_ROLLBACK,
        DISCONNECT_ROLLBACK,DISCONNECT_COMMIT,DELETE_ROLLBACK,SHARING_ROLLBACK,RETRY_ROLLED_REV,
        INPUT_COPY,SERVICE_COPY,STATS_COPY,MDNS_COPY,SQL_FAILURE,NESTED_DISCONNECT_COMMIT,NESTED_DISCONNECT_ROLLBACK }
    public static void verify(ConfigurableApplicationContext context,DataSource independent)throws Exception{
        var jdbc=context.getBean(JdbcTemplate.class);var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var properties=context.getBean(PeerMeshProperties.class);boolean enabled=properties.isEnabled();properties.setEnabled(true);
        var previous=jdbc.queryForList("select enabled,mdns_import_enabled from peer_mesh_service_sharing where tenant_id='default'");
        String now=Instant.now().toString();
        if(previous.isEmpty())jdbc.update("insert into peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_at,updated_by) values ('default',true,true,?,'catalog-proof')",now);
        else jdbc.update("update peer_mesh_service_sharing set enabled=true,mdns_import_enabled=true where tenant_id='default'");
        var observer=Executors.newSingleThreadExecutor();List<Executable> checks=new ArrayList<>();
        try{
            for(Case selected:Case.values())checks.add(()->{
                long base=11_100_000+selected.ordinal()*100;fixture(jdbc,base,selected.ordinal());
                var accounts=context.getBean(ClientAccountRepository.class);
                var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
                var services=service(context);var publisher=new PeerCatalogPublicationService(services,context.getBean(PeerCatalogAuthority.class),1024,System::nanoTime);
                var signal=new PeerSignalService(context.getBean(ClientAccountService.class),context.getBean(PeerMeshService.class),services,context.getBean(ClientSessionRepository.class),context.getBean(PeerEgressService.class),publisher);
                var handler=new MessageRequestHandler(signal,context.getBean(ClientAccountService.class),context.getBean(ClientMessageRelayService.class),context.getBean(ClientMessagesWebSocketHandler.class));
                List<EmbeddedChannel> channels=new ArrayList<>();var from=bind(source,base+41,handler,channels,jdbc);var to=bind(target,base+42,null,channels,jdbc);
                var key=new PeerServiceDiscoveryService.CatalogKey("default",base+1,base+41);
                var cache=(PeerCatalogCache)ReflectionTestUtils.getField(services,"catalogCache");
                boolean seeded=List.of(Case.UPDATE_ROLLBACK,Case.WITHDRAW_ROLLBACK,Case.AUTH_REFRESH_ROLLBACK,Case.DISCONNECT_ROLLBACK,Case.DISCONNECT_COMMIT,
                        Case.DELETE_ROLLBACK,Case.SHARING_ROLLBACK,Case.NESTED_DISCONNECT_COMMIT,Case.NESTED_DISCONNECT_ROLLBACK).contains(selected);
                try{
                    if(seeded)tx.executeWithoutResult(status->services.handleReport(source,report(1)));
                    long before=seeded?services.currentCatalog("default",base+1,base+41).revision():0;
                    Runnable producer=()->tx.executeWithoutResult(status->{
                        if(selected==Case.NESTED_DISCONNECT_COMMIT||selected==Case.NESTED_DISCONNECT_ROLLBACK){
                            jdbc.update("update specus_client_session set status='DISCONNECTED' where id=?",base+41);
                            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
                                @Override public void afterCommit(){PeerCatalogCache.committedEffect(()->signal.onClientDisconnected(base+41));}
                            });
                        }else if(selected==Case.AUTH_REFRESH_ROLLBACK)signal.pushCatalogs(services.onAuthorizationChanged("default"));
                        else if(selected==Case.SHARING_ROLLBACK){jdbc.update("update peer_mesh_service_sharing set enabled=false where tenant_id='default'");signal.pushCatalogs(services.onAuthorizationChanged("default"));}
                        else if(selected==Case.DELETE_ROLLBACK){jdbc.update("delete from specus_client_account where id=?",base+1);signal.pushCatalogs(services.withdrawDeletedClient(source));}
                        else if(selected==Case.DISCONNECT_ROLLBACK||selected==Case.DISCONNECT_COMMIT){jdbc.update("update specus_client_session set status='DISCONNECTED' where id=?",base+41);signal.pushCatalogs(services.onClientDisconnected(source,base+41));}
                        else{
                            var report=report(seeded?2:1);if(selected==Case.WITHDRAW_ROLLBACK)report.setEnabled(false);
                            if(selected==Case.INPUT_COPY){
                                signal.pushCatalogs(services.handleReport(source,report));report.getStats().getFirst().setBytesIn(999);report.getMdnsCandidates().getFirst().setName("poison-input");
                            }else from.writeInbound(request(report));
                        }
                        assertNull(from.readOutbound());assertNull(to.readOutbound(),"no catalog wire data before commit");
                        await(observer.submit(()->{
                            var visible=services.currentCatalog("default",base+1,base+41);
                            if(seeded){assertNotNull(visible);assertEquals(before,visible.revision());assertEquals(7,visible.stats().getFirst().getBytesIn());assertEquals("candidate",mdns(services,key).getFirst().getName());}
                            else{assertNull(visible);assertTrue(mdns(services,key).isEmpty());}
                        }));
                        if(selected==Case.SQL_FAILURE)jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','duplicate','duplicate','fixture-only',true,30,?,?)",base+1,Instant.now().toString(),Instant.now().toString());
                        if(selected.name().endsWith("ROLLBACK")||selected==Case.ROLLBACK||selected==Case.RETRY_ROLLED_REV)status.setRollbackOnly();
                    });
                    if(selected==Case.SQL_FAILURE)assertThrows(RuntimeException.class,producer::run);else producer.run();
                    if(selected==Case.RETRY_ROLLED_REV){assertNull(services.currentCatalog("default",base+1,base+41));tx.executeWithoutResult(status->from.writeInbound(request(report(1))));}
                    boolean empty=selected==Case.DISCONNECT_COMMIT||selected==Case.NESTED_DISCONNECT_COMMIT;
                    boolean absent=empty||selected==Case.ROLLBACK||selected==Case.SQL_FAILURE;
                    var snapshot=services.currentCatalog("default",base+1,base+41);
                    if(absent){assertNull(snapshot);assertTrue(mdns(services,key).isEmpty());assertEquals(0,services.trackedCatalogRevisionCount());assertEquals(0,cache.retainedKeyCount());}
                    else{
                        assertNotNull(snapshot,selected.toString());assertEquals("actual-service",snapshot.services().getFirst().getName());assertEquals(7,snapshot.stats().getFirst().getBytesIn());assertEquals("candidate",mdns(services,key).getFirst().getName());
                        if(seeded)assertEquals(before,snapshot.revision(),"rollback must not burn revision");
                        if(selected==Case.SERVICE_COPY)snapshot.services().getFirst().setName("poison-output");
                        if(selected==Case.STATS_COPY)snapshot.stats().getFirst().setBytesIn(999);
                        if(selected==Case.MDNS_COPY)mdns(services,key).getFirst().setName("poison-output");
                        assertEquals("actual-service",services.currentCatalog("default",base+1,base+41).services().getFirst().getName());
                        assertEquals(7,services.currentCatalog("default",base+1,base+41).stats().getFirst().getBytesIn());assertEquals("candidate",mdns(services,key).getFirst().getName());
                    }
                    publisher.publishPending();
                    boolean wire=empty||!seeded&&selected!=Case.ROLLBACK&&selected!=Case.SQL_FAILURE;
                    MessageResponsePacket packet=to.readOutbound();
                    if(wire){assertNotNull(packet,selected.toString());var catalog=JsonUtil.stringToObject(packet.getMessage(),PeerControlMessage.class);assertEquals(PeerControlMessage.TYPE_SERVICE_CATALOG,catalog.getType());assertEquals(empty?0:1,catalog.getServices().size());if(empty)assertTrue(catalog.getRevision()>before);}
                    else assertNull(packet,selected.toString());
                    assertNull(to.readOutbound(),"no duplicate catalog packet");assertFalse(PeerCatalogCache.inCommittedEffect());
                }finally{for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
            });
            assertAll("real service catalog commit/rollback, copies and nested committed withdrawal",checks);
            System.out.println("[catalog-commit-proof] scenarios="+Case.values().length+" actualHighIdReportHandler=PASS fourIndexRollback=PASS copies=PASS nestedWithdrawal=PASS");
        }finally{
            observer.shutdownNow();assertTrue(observer.awaitTermination(5,TimeUnit.SECONDS));properties.setEnabled(enabled);
            if(previous.isEmpty())jdbc.update("delete from peer_mesh_service_sharing where tenant_id='default'");
            else jdbc.update("update peer_mesh_service_sharing set enabled=?,mdns_import_enabled=? where tenant_id='default'",previous.getFirst().get("enabled"),previous.getFirst().get("mdns_import_enabled"));
        }
    }
    @SuppressWarnings("unchecked") private static List<PeerMdnsCandidate> mdns(PeerServiceDiscoveryService service,PeerServiceDiscoveryService.CatalogKey key){return ((Map<PeerServiceDiscoveryService.CatalogKey,List<PeerMdnsCandidate>>)ReflectionTestUtils.getField(service,"mdnsCandidates")).getOrDefault(key,List.of());}
    static PeerServiceDiscoveryService service(ConfigurableApplicationContext context){return new PeerServiceDiscoveryService(context.getBean(PeerMeshService.class),context.getBean(PeerMeshServiceSharingRepository.class),context.getBean(PeerMeshSharedServiceRepository.class),context.getBean(PeerMeshDeviceRepository.class),context.getBean(ClientAccountRepository.class),context.getBean(ClientSessionRepository.class),context.getBean(SpecusMappingRepository.class),context.getBean(HttpRouteMappingRepository.class),context.getBean(WorkbenchReferences.class));}
    static EmbeddedChannel bind(ClientAccount account,long session,MessageRequestHandler handler,List<EmbeddedChannel> channels,JdbcTemplate jdbc){var channel=handler==null?new EmbeddedChannel():new EmbeddedChannel(handler);channel.attr(ServerAttributes.TENANT_ID).set("default");channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(session);SessionUtil.bindSession(new Session(account.getClientName()),channel);jdbc.update("update specus_client_session set channel_id=? where id=?",channel.id().asLongText(),session);channels.add(channel);return channel;}
    private static MessageRequestPacket request(PeerControlMessage report){var request=new MessageRequestPacket();request.setMessageType(MessageType.PEER_CONTROL);request.setMessage(JsonUtil.objectToString(report));return request;}
    static PeerControlMessage report(long revision){var service=new PeerAdvertisedService();service.setServiceId("svc-catalog");service.setName("client-name");service.setTransport("tcp");service.setApplication("http");service.setPublishedPort(18080);var stats=new PeerServiceStats();stats.setServiceId("svc-catalog");stats.setBytesIn(7);stats.setBytesOut(11);var mdns=new PeerMdnsCandidate();mdns.setName("candidate");mdns.setTransport("tcp");mdns.setApplication("http");mdns.setTargetHost("127.0.0.1");mdns.setTargetPort(8080);var report=new PeerControlMessage();report.setType(PeerControlMessage.TYPE_SERVICE_REPORT);report.setEnabled(true);report.setRevision(revision);report.setServices(List.of(service));report.setStats(List.of(stats));report.setMdnsCandidates(List.of(mdns));return report;}
    static void fixture(JdbcTemplate jdbc,long base,int index){String now=Instant.now().toString();for(long id:List.of(base+1,base+2)){
        String name="catalog-commit-"+id;
        jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','catalog-commit',?,'fixture-only',true,30,?,?)",id,name,now,now);
        jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,public_key,enabled,created_at,updated_at) values (?,'default','catalog-commit',?,?,?,'100.119.0.0/16','catalog-key',true,?,?)",id,id,name,"100.119."+(100+index)+"."+(id-base),now,now);
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','catalog-commit',?,'fixture-only',true,3,?,?)",id+20,"catalog-api-"+id,now,now);
        jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',?,?,?,?,'catalog',?,?)",id+30,id+20,id,name,"catalog-machine-"+id,now,now);
        jdbc.update("insert into specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,message_send_capable,message_receive_capable,message_attachments_capable,message_media_preview_capable,message_max_attachment_bytes,peer_service_discovery_version,client_egress_version,client_egress_domain_targets,http_login_at,expires_at) values (?,'default',?,?,?,?,'fixture-only','NETTY_ONLINE',?,'catalog',true,true,true,true,1048576,2,0,false,?,?)",id+40,id+20,id+30,id,name,"catalog-session-"+id,now,Instant.now().plusSeconds(3600).toString());
        }
        jdbc.update("insert into peer_mesh_shared_service(id,tenant_id,client_id,client_name,service_id,name,description,transport,application,target_host,target_port,published_port,path,enabled,visibility,allowed_client_ids,created_at,updated_at) values (?,'default',?,?,'svc-catalog','actual-service','','tcp','http','127.0.0.1',8080,18080,'/',true,'OWNER','',?,?)",base+5,base+1,"catalog-commit-"+(base+1),now,now);
    }
    private static <T>T await(Future<T> future){try{return future.get(5,TimeUnit.SECONDS);}catch(ExecutionException failure){if(failure.getCause() instanceof AssertionError assertion)throw assertion;throw new IllegalStateException("catalog observer failed",failure.getCause());}catch(Exception failure){throw new IllegalStateException("catalog observer failed",failure);}}
}
