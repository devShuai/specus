package com.theshuai.specusserver.database;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerReadSnapshotRepository;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

/** Informational snapshots after an older caller's transaction has ended; routing/grants use
 * current locking guards instead. SQL fixture mutations are not transfer-POST acceptance. */
public final class PeerReadSnapshotAssertions {
    enum Case { SAME_OWNER, FOREIGN_OWNER, OLD_SOURCE_OWNER, OLD_TARGET_OWNER, SOURCE_DISABLED,TARGET_DISABLED,
        SOURCE_DEVICE_DISABLED,TARGET_DEVICE_DISABLED,SOURCE_DELETED,TARGET_DELETED,
        FWD_OUT,FWD_IN,FWD_BOTH,REVERSE_OUT,REVERSE_IN,REVERSE_BOTH,ACL_REVOKED,ACL_FOREIGN_TENANT,
        PARENT_FOREIGN_TENANT,DEVICE_FOREIGN_TENANT,RENAME_TARGET,DEVICE_KEY,
        CAP_BOUND,CAP_REPLACED,CAP_DISCONNECTED,CAP_FOREIGN_CHANNEL,CAP_LEGACY,CAP_INACTIVE,SERVICE_INCOMING,SERVICE_WRONG_DIRECTION,
        SERVICE_DEFINITION,SERVICE_OWNER,SERVICE_EXPLICIT }
    private record Fixture(ClientAccount source,ClientAccount target,long base) {}
    public static void verify(ConfigurableApplicationContext context,DataSource independent) throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class); var writer=new JdbcTemplate(independent);
        var accounts=context.getBean(ClientAccountRepository.class);var mesh=context.getBean(PeerMeshService.class);
        var properties=context.getBean(PeerMeshProperties.class);boolean enabled=properties.isEnabled();properties.setEnabled(true);
        List<Executable> cases=new ArrayList<>();
        try {
            for(Case selected:Case.values())cases.add(()->{
                long base=7_500_000+selected.ordinal()*100;String now=Instant.now().toString();
                boolean cross=selected==Case.FOREIGN_OWNER||selected.name().startsWith("FWD")||selected.name().startsWith("REVERSE")
                        ||selected.name().startsWith("ACL")||selected==Case.SERVICE_INCOMING||selected==Case.SERVICE_WRONG_DIRECTION;
                for(long id:List.of(base+1,base+2)){
                    String owner=id==base+2&&cross?"read-bob":"read-alice";
                    jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,?,'fixture-only',true,30,?,?)",id,owner,"peer-read-"+id,now,now);
                    jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,public_key,enabled,created_at,updated_at) values (?,'default',?,?,?,?,'100.116.0.0/16','read-old-key',true,?,?)",id,owner,id,"peer-read-"+id,"100.116."+(150+selected.ordinal())+"."+(id-base),now,now);
                    jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default',?,?,'fixture-only',true,3,?,?)",id+20,owner,"read-key-"+id,now,now);
                    jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',?,?,?,?,'fixture',?,?)",id+30,id+20,id,"peer-read-"+id,"read-machine-"+id,now,now);
                    insertSession(jdbc,id+40,id,id+20,id+30,true,2,now);
                }
                if(selected.name().startsWith("FWD")||selected.name().startsWith("REVERSE")||selected.name().startsWith("ACL")
                        ||selected==Case.SERVICE_INCOMING||selected==Case.SERVICE_WRONG_DIRECTION){
                    boolean reverse=selected.name().startsWith("REVERSE");String direction=selected.name().endsWith("_IN")?"INBOUND":selected.name().endsWith("BOTH")?"BOTH":"OUTBOUND";
                    if(selected==Case.SERVICE_INCOMING)direction="INBOUND";
                    jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default','read-alice',?,?,?,?,true,?,?,?)",base+5,reverse?base+2:base+1,"read-source",reverse?base+1:base+2,"read-target",direction,now,now);
                }
                boolean service=selected.name().startsWith("SERVICE");
                if(service)jdbc.update("insert into peer_mesh_shared_service(id,tenant_id,client_id,client_name,service_id,name,description,transport,application,target_host,target_port,published_port,path,enabled,visibility,allowed_client_ids,created_at,updated_at) values (?,'default',?,?,'svc-read001','Read service','','tcp','http','127.0.0.1',8080,18080,'',true,?,'',?,?)",base+6,base+1,"peer-read-"+(base+1),selected==Case.SERVICE_OWNER?"OWNER":"EXPLICIT",now,now);
                // Genuine older JPA objects survive in the caller; informational read starts a new transaction.
                var old=new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).execute(status->new Fixture(accounts.findById(base+1).orElseThrow(),accounts.findById(base+2).orElseThrow(),base));
                assertNotNull(old);
                switch(selected){
                    case OLD_SOURCE_OWNER->writer.update("update specus_client_account set owner_username='read-bob' where id=?",base+1);
                    case OLD_TARGET_OWNER,SERVICE_OWNER,SERVICE_EXPLICIT->writer.update("update specus_client_account set owner_username='read-bob' where id=?",base+2);
                    case SOURCE_DISABLED->writer.update("update specus_client_account set enabled=false where id=?",base+1);
                    case TARGET_DISABLED->writer.update("update specus_client_account set enabled=false where id=?",base+2);
                    case SOURCE_DEVICE_DISABLED->writer.update("update peer_mesh_device set enabled=false where client_id=?",base+1);
                    case TARGET_DEVICE_DISABLED->writer.update("update peer_mesh_device set enabled=false where client_id=?",base+2);
                    case SOURCE_DELETED->writer.update("delete from specus_client_account where id=?",base+1);
                    case TARGET_DELETED->writer.update("delete from specus_client_account where id=?",base+2);
                    case ACL_REVOKED->writer.update("update peer_mesh_acl set allowed=false where id=?",base+5);
                    case ACL_FOREIGN_TENANT->writer.update("update peer_mesh_acl set tenant_id='DEFAULT' where id=?",base+5);
                    case PARENT_FOREIGN_TENANT->writer.update("update specus_client_account set tenant_id='DEFAULT' where id=?",base+2);
                    case DEVICE_FOREIGN_TENANT->writer.update("update peer_mesh_device set tenant_id='DEFAULT' where client_id=?",base+2);
                    case RENAME_TARGET->writer.update("update specus_client_account set client_name='read-current-name' where id=?",base+2);
                    case DEVICE_KEY->writer.update("update peer_mesh_device set public_key='read-current-key' where client_id=?",base+2);
                    case CAP_REPLACED->{writer.update("update specus_client_session set message_send_capable=false,message_receive_capable=false,message_attachments_capable=false,message_media_preview_capable=false,peer_service_discovery_version=1 where id=?",base+42);insertSession(writer,base+43,base+2,base+22,base+32,true,2,now);}
                    case CAP_DISCONNECTED->writer.update("update specus_client_session set status='DISCONNECTED' where id=?",base+42);
                    case SERVICE_DEFINITION->writer.update("update peer_mesh_shared_service set target_port=9090,name='Current service' where id=?",base+6);
                    default->{}
                }
                if(selected==Case.SERVICE_EXPLICIT||selected==Case.SERVICE_OWNER)
                    writer.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default','read-alice',?,'source',?,'target',true,'BOTH',?,?)",base+5,base+1,base+2,now,now);
                List<EmbeddedChannel> channels=new ArrayList<>();
                try {
                    if(selected.name().startsWith("CAP_")||service){
                        bind(old.source(),base+41,channels);bind(old.target(),base+42,channels);
                        var targetChannel=channels.getLast();
                        if(selected==Case.CAP_FOREIGN_CHANNEL)targetChannel.attr(ServerAttributes.TENANT_ID).set("DEFAULT");
                        if(selected==Case.CAP_LEGACY)targetChannel.attr(ServerAttributes.CLIENT_SESSION_ID).set(null);
                        if(selected==Case.CAP_INACTIVE)targetChannel.close().syncUninterruptibly();
                    }
                    boolean allowed=!List.of(Case.FOREIGN_OWNER,Case.OLD_SOURCE_OWNER,Case.OLD_TARGET_OWNER,Case.SOURCE_DISABLED,Case.TARGET_DISABLED,
                            Case.SOURCE_DEVICE_DISABLED,Case.TARGET_DEVICE_DISABLED,Case.SOURCE_DELETED,Case.TARGET_DELETED,Case.FWD_IN,Case.REVERSE_OUT,
                            Case.ACL_REVOKED,Case.ACL_FOREIGN_TENANT,Case.PARENT_FOREIGN_TENANT,Case.DEVICE_FOREIGN_TENANT,Case.SERVICE_INCOMING).contains(selected);
                    assertEquals(allowed,mesh.canPeer(old.source(),old.target()),selected.toString());
                    var roster=mesh.allowedRoster(old.source());
                    assertEquals(allowed,roster.stream().anyMatch(peer->peer.clientId()==base+2),"roster "+selected);
                    if(allowed){
                        var peer=roster.stream().filter(row->row.clientId()==base+2).findFirst().orElseThrow();
                        if(selected==Case.RENAME_TARGET)assertEquals("read-current-name",peer.clientName());
                        if(selected==Case.DEVICE_KEY)assertEquals("read-current-key",peer.publicKey());
                        if(selected==Case.CAP_BOUND){assertTrue(peer.online());assertTrue(peer.messageReceiveCapable());assertEquals(2,peer.peerServiceDiscoveryVersion());}
                        if(selected==Case.CAP_REPLACED){assertTrue(peer.online());assertFalse(peer.messageReceiveCapable());assertEquals(1,peer.peerServiceDiscoveryVersion());}
                        if(selected==Case.CAP_DISCONNECTED){assertFalse(peer.online());assertFalse(peer.messageReceiveCapable());assertEquals(0,peer.peerServiceDiscoveryVersion());}
                        if(selected==Case.CAP_FOREIGN_CHANNEL||selected==Case.CAP_INACTIVE){assertFalse(peer.online());assertFalse(peer.messageReceiveCapable());assertEquals(0,peer.peerServiceDiscoveryVersion());}
                        if(selected==Case.CAP_LEGACY){assertTrue(peer.online());assertFalse(peer.messageReceiveCapable());assertEquals(0,peer.peerServiceDiscoveryVersion());}
                    }
                    if(service){
                        ClientAuthLoginResponse.PeerMeshConfig config=mesh.buildRuntimeConfig(old.source());
                        var definition=config.getLocalServices().stream().filter(row->row.getServiceId().equals("svc-read001")).findFirst().orElseThrow();
                        String targetIp="100.116."+(150+selected.ordinal())+".2";
                        assertEquals(selected!=Case.SERVICE_WRONG_DIRECTION&&selected!=Case.SERVICE_OWNER,definition.getAllowedPeerVirtualIps().contains(targetIp),"incoming service policy "+selected);
                        if(selected==Case.SERVICE_DEFINITION){assertEquals(9090,definition.getTargetPort());assertEquals("Current service",definition.getName());}
                    }
                } finally{for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
            });
            assertAll("coherent peer read snapshots and directional roster",cases);
            singleStatement(context);
            isolation(context,independent);
            System.out.println("[peer-read-proof] cases="+Case.values().length+" singleStatement=PASS pairBounded=PASS");
        } finally{properties.setEnabled(enabled);}
    }
    private static void singleStatement(ConfigurableApplicationContext context) throws Exception {
        var repository=context.getBean(PeerReadSnapshotRepository.class);
        Object target=org.springframework.test.util.AopTestUtils.getTargetObject(repository);
        var original=(jakarta.persistence.EntityManager)org.springframework.test.util.ReflectionTestUtils.getField(target,"entities");
        var count=new java.util.concurrent.atomic.AtomicInteger();
        var observer=(jakarta.persistence.EntityManager)java.lang.reflect.Proxy.newProxyInstance(
                jakarta.persistence.EntityManager.class.getClassLoader(),new Class<?>[]{jakarta.persistence.EntityManager.class},(proxy,method,args)->{
                    if(method.getName().equals("createNativeQuery")){
                        count.incrementAndGet();String sql=(String)args[0];
                        assertTrue(sql.contains("union all"));assertFalse(sql.toLowerCase(java.util.Locale.ROOT).contains("for update"));
                    }
                    assertFalse(method.getName().equals("createQuery"),"no secondary JPQL read");
                    try{return method.invoke(original,args);}catch(java.lang.reflect.InvocationTargetException error){throw error.getCause();}
                });
        org.springframework.test.util.ReflectionTestUtils.setField(target,"entities",observer);
        try{
            var snapshot=repository.read("default",7_500_001);
            assertEquals(7_500_001,snapshot.source().id());assertTrue(snapshot.edge(7_500_002).orElseThrow().outgoing("default"));
            assertEquals(1,count.get(),"one real statement, existing transaction connection");
            var pair=repository.readPair("default",7_500_001,7_500_002);
            assertEquals(1,pair.edges().size());assertTrue(pair.definitions().isEmpty());
            assertEquals(2,count.get(),"pair check also exactly one real statement");
        }finally{org.springframework.test.util.ReflectionTestUtils.setField(target,"entities",original);}
    }
    private static void isolation(ConfigurableApplicationContext context,DataSource independent) throws Exception {
        String provider;try(var connection=independent.getConnection()){provider=connection.getMetaData().getDatabaseProductName();}
        if(provider.toLowerCase(java.util.Locale.ROOT).contains("sqlite"))return; // SQLite cannot upgrade this concurrent reader fixture.
        var jdbc=new JdbcTemplate(independent);var accounts=context.getBean(ClientAccountRepository.class);var mesh=context.getBean(PeerMeshService.class);
        var template=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        template.setReadOnly(true);template.setIsolationLevel(org.springframework.transaction.TransactionDefinition.ISOLATION_READ_COMMITTED);
        try{
            template.executeWithoutResult(status->{
                var source=accounts.findById(7_500_001L).orElseThrow();var target=accounts.findById(7_500_002L).orElseThrow();
                assertEquals("read-alice",target.getOwnerUsername());
                assertTrue(mesh.canPeer(source,target));
                // This independently committed write also proves the informational read did not
                // retain a pair/tenant row lock; it is never a stubbed native-query result.
                jdbc.setQueryTimeout(2);assertEquals(1,jdbc.update("update specus_client_account set owner_username='read-bob' where id=7500002"));
                assertEquals("read-alice",target.getOwnerUsername(),"genuine stale L1 remains");
                assertFalse(mesh.canPeer(source,target),"READ COMMITTED native read bypasses stale L1");
                assertTrue(mesh.allowedRoster(source).stream().noneMatch(peer->peer.clientId()==7_500_002));
            });
        }finally{jdbc.update("update specus_client_account set owner_username='read-alice' where id=7500002");}
        if(!provider.toLowerCase(java.util.Locale.ROOT).matches(".*(mysql|mariadb).*"))return;
        template.setIsolationLevel(org.springframework.transaction.TransactionDefinition.ISOLATION_REPEATABLE_READ);
        try{
            template.executeWithoutResult(status->{
                var source=accounts.findById(7_500_001L).orElseThrow();var target=accounts.findById(7_500_002L).orElseThrow();
                jdbc.update("update specus_client_account set owner_username='read-bob' where id=7500002");
                assertTrue(mesh.canPeer(source,target),"informational view intentionally respects enclosing old RR snapshot");
            });
            var source=accounts.findById(7_500_001L).orElseThrow();var target=accounts.findById(7_500_002L).orElseThrow();
            assertFalse(mesh.canPeer(source,target),"new transaction sees committed owner");
        }finally{jdbc.update("update specus_client_account set owner_username='read-alice' where id=7500002");}
    }
    private static void bind(ClientAccount account,long session,List<EmbeddedChannel> channels){var channel=new EmbeddedChannel();channel.attr(ServerAttributes.TENANT_ID).set("default");channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(session);SessionUtil.bindSession(new Session(account.getClientName()),channel);channels.add(channel);}
    private static void insertSession(JdbcTemplate jdbc,long id,long client,long credential,long identity,boolean capable,int version,String now){
        jdbc.update("insert into specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,message_send_capable,message_receive_capable,message_attachments_capable,message_media_preview_capable,message_max_attachment_bytes,peer_service_discovery_version,client_egress_version,client_egress_domain_targets,http_login_at,expires_at) values (?,'default',?,?,?,?,'fixture-only','NETTY_ONLINE',?,'fixture',?,?,?,?,1048576,?,0,false,?,?)",id,credential,identity,client,"peer-read-"+client,"read-session-machine-"+id,capable,capable,capable,capable,version,now,Instant.now().plusSeconds(3600).toString());
    }
}
