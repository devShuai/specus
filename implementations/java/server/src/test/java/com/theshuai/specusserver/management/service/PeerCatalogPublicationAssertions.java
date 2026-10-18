package com.theshuai.specusserver.management.service;

import com.theshuai.common.peermesh.*;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.*;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.*;
import io.netty.channel.embedded.EmbeddedChannel;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.function.Executable;
import org.springframework.aop.framework.Advised;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.*;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;

/** Native current authority, real database rows/transactions and actual channel writes. No
 * mocked policy/capability outcomes. Shared by the real provider boot tests. */
public final class PeerCatalogPublicationAssertions {
    enum Case { COMMIT,ROLLBACK,CONSUMER_OUTBOUND,CONSUMER_INBOUND,PUBLISHER_INBOUND,PUBLISHER_OUTBOUND,
        ACL_BOTH,ACL_DENIED,OWNER_WITH_CROSS_ACL,ALLOWLIST_REVOKED,MALFORMED_ALLOWLIST,UNKNOWN_VISIBILITY,
        PUBLISHER_OWNER,RECIPIENT_OWNER,PUBLISHER_DISABLED,RECIPIENT_DISABLED,PUBLISHER_DEVICE,
        RECIPIENT_DEVICE,PUBLISHER_CREDENTIAL,RECIPIENT_CREDENTIAL,PUBLISHER_SESSION,RECIPIENT_SESSION,
        PUBLISHER_CAPABILITY,RECIPIENT_CAPABILITY,FOREIGN_PUBLISHER_SESSION,FOREIGN_RECIPIENT_SESSION,
        DEFINITION_DISABLED,DEFINITION_DELETED,DEFINITION_MOVED,DEFINITION_RENAMED,RUNTIME_CHANGED,
        SHARING_DISABLED,SHARING_DELETED,SUCCESSOR_PUBLISHER,SUCCESSOR_RECIPIENT,SUPERSEDED_REPORT,
        WITHDRAW_DELETED,WITHDRAW_SUPERSEDED,EXPIRED_QUEUE,CAPACITY_ROLLBACK,RETRY,GIVEUP,
        WRITE_FAILURE,COMMIT_FAILURE,EARLIER_CALLBACK_FAILURE,RETAINED_ACCESS,
        BORROWED_PUBLISHER_CAPABILITY,BORROWED_RECIPIENT_CAPABILITY,PUBLISHER_CHANNEL_DB,RECIPIENT_CHANNEL_DB }
    public static void verify(ConfigurableApplicationContext context,DataSource independent)throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class);var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var properties=context.getBean(PeerMeshProperties.class);boolean original=properties.isEnabled();properties.setEnabled(true);
        var previous=jdbc.queryForList("select enabled,mdns_import_enabled from peer_mesh_service_sharing where tenant_id='default'");
        if(previous.isEmpty())jdbc.update("insert into peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_at,updated_by) values ('default',true,true,?,'catalog-current-proof')",Instant.now().toString());
        var cases=new ArrayList<Executable>();
        try {
            for(Case selected:Case.values())cases.add(()->{
                if(jdbc.queryForObject("select count(*) from peer_mesh_service_sharing where tenant_id='default'",Integer.class)==0)
                    jdbc.update("insert into peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_at,updated_by) values ('default',true,true,?,'catalog-current-proof')",Instant.now().toString());
                jdbc.update("update peer_mesh_service_sharing set enabled=true,mdns_import_enabled=true where tenant_id='default'");
                long base=11_200_000+selected.ordinal()*100;PeerCatalogCommitAssertions.fixture(jdbc,base,selected.ordinal()+30);
                var accounts=context.getBean(ClientAccountRepository.class);var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
                var services=PeerCatalogCommitAssertions.service(context);var clock=new AtomicLong();
                var authority=context.getBean(PeerCatalogAuthority.class);
                var publisher=new PeerCatalogPublicationService(services,authority,selected==Case.CAPACITY_ROLLBACK?1:8,clock::get);
                var channels=new ArrayList<EmbeddedChannel>();var from=PeerCatalogCommitAssertions.bind(source,base+41,null,channels,jdbc);
                var to=PeerCatalogCommitAssertions.bind(target,base+42,null,channels,jdbc);EmbeddedChannel[] successor={null};
                try {
                    boolean directional=List.of(Case.CONSUMER_OUTBOUND,Case.CONSUMER_INBOUND,Case.PUBLISHER_INBOUND,Case.PUBLISHER_OUTBOUND,
                            Case.ACL_BOTH,Case.ACL_DENIED,Case.OWNER_WITH_CROSS_ACL).contains(selected);
                    if(directional){owner(jdbc,base+2,"catalog-consumer");acl(jdbc,base,selected);}
                    boolean withdraw=selected==Case.WITHDRAW_DELETED||selected==Case.WITHDRAW_SUPERSEDED;
                    AtomicInteger offered=new AtomicInteger();
                    Runnable producer=()->tx.executeWithoutResult(status->{
                        accounts.findById(base+1).orElseThrow();accounts.findById(base+2).orElseThrow();
                        context.getBean(PeerMeshSharedServiceRepository.class).findById(base+5).orElseThrow();
                        if(selected==Case.EARLIER_CALLBACK_FAILURE)TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
                            @Override public void afterCommit(){throw new IllegalStateException("intentional earlier commit callback failure");}
                        });
                        var deliveries=services.handleReport(source,PeerCatalogCommitAssertions.report(1));offered.set(deliveries.size());
                        if(deliveries.isEmpty())deliveries=services.catalogsForRecipient(target);
                        if(withdraw){
                            if(selected==Case.WITHDRAW_DELETED)jdbc.update("delete from specus_client_account where id=?",base+1);
                            deliveries=services.withdrawDeletedClient(source);
                        }
                        assertEquals(1,deliveries.size(),"one eligible online consumer receives a candidate or withdrawal");
                        publisher.submit(deliveries.getFirst());
                        if(selected==Case.CAPACITY_ROLLBACK){var staged=deliveries.getFirst();assertThrows(IllegalStateException.class,()->publisher.submit(staged));}
                        assertNull(to.readOutbound(),"no publication before commit");
                        assertThrows(IllegalStateException.class,publisher::publishPending,"worker cannot borrow a producer transaction");
                        if(selected==Case.ROLLBACK||selected==Case.CAPACITY_ROLLBACK)status.setRollbackOnly();
                    });
                    if(selected==Case.EARLIER_CALLBACK_FAILURE)assertThrows(IllegalStateException.class,producer::run);else producer.run();
                    if(selected==Case.CONSUMER_OUTBOUND||selected==Case.PUBLISHER_INBOUND||selected==Case.ACL_BOTH)
                        assertEquals(1,offered.get(),"incoming-only consumer must not be discarded by a publisher's outgoing roster");
                    mutate(context,jdbc,selected,base,source,target,from,to,services,publisher,channels,successor,clock);
                    var proxy=(Advised)authority;AtomicInteger calls=new AtomicInteger();Thread worker=Thread.currentThread();
                    MethodInterceptor fault=invocation->{
                        if(Thread.currentThread()==worker&&invocation.getMethod().getName().equals("publish")){
                            int call=calls.incrementAndGet();
                            if(selected==Case.GIVEUP||selected==Case.RETRY&&call==1)throw new org.springframework.dao.TransientDataAccessResourceException("intentional pre-write failure");
                            if(selected==Case.COMMIT_FAILURE){
                                @SuppressWarnings("unchecked") var originalWriter=(java.util.function.Consumer<PeerControlMessage>)invocation.getArguments()[6];
                                invocation.getArguments()[6]=(java.util.function.Consumer<PeerControlMessage>)message->{
                                    originalWriter.accept(message);
                                    TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
                                        @Override public void beforeCommit(boolean readOnly){throw new org.springframework.dao.TransientDataAccessResourceException("intentional post-write commit failure");}
                                    });
                                };
                            }
                        }
                        return invocation.proceed();
                    };
                    boolean injected=List.of(Case.RETRY,Case.GIVEUP,Case.COMMIT_FAILURE).contains(selected);
                    if(injected)proxy.addAdvice(0,fault);
                    try {
                        publisher.publishPending();
                        if(selected==Case.RETRY||selected==Case.GIVEUP){assertNull(to.readOutbound());publisher.publishPending();if(selected==Case.GIVEUP)publisher.publishPending();}
                        publisher.publishPending(); // No retry after an uncertain accepted write/commit failure.
                    }finally{if(injected)proxy.removeAdvice(fault);}
                    if(injected)assertEquals(selected==Case.RETRY?2:selected==Case.GIVEUP?3:1,calls.get());
                    boolean silent=List.of(Case.ROLLBACK,Case.RECIPIENT_DISABLED,Case.RECIPIENT_CREDENTIAL,Case.RECIPIENT_SESSION,
                            Case.RECIPIENT_CAPABILITY,Case.BORROWED_RECIPIENT_CAPABILITY,Case.RECIPIENT_CHANNEL_DB,Case.FOREIGN_RECIPIENT_SESSION,Case.SUCCESSOR_PUBLISHER,Case.SUCCESSOR_RECIPIENT,
                            Case.SUPERSEDED_REPORT,Case.WITHDRAW_SUPERSEDED,Case.EXPIRED_QUEUE,Case.CAPACITY_ROLLBACK,Case.GIVEUP,Case.WRITE_FAILURE).contains(selected);
                    MessageResponsePacket packet=to.readOutbound();
                    if(silent)assertNull(packet,selected.toString());
                    else {
                        assertNotNull(packet,selected.toString());var catalog=JsonUtil.stringToObject(packet.getMessage(),PeerControlMessage.class);
                        boolean data=List.of(Case.COMMIT,Case.CONSUMER_OUTBOUND,Case.PUBLISHER_INBOUND,Case.ACL_BOTH,Case.DEFINITION_RENAMED,
                                Case.RETRY,Case.COMMIT_FAILURE,Case.EARLIER_CALLBACK_FAILURE,Case.RETAINED_ACCESS).contains(selected);
                        assertEquals(data?1:0,catalog.getServices().size(),selected.toString());
                        assertEquals(base+1,catalog.getPublisherClientId());assertEquals(base+41,catalog.getPublisherSessionId());
                        if(selected==Case.DEFINITION_RENAMED){assertEquals("fresh database name",catalog.getServices().getFirst().getName());assertEquals("fresh database description",catalog.getServices().getFirst().getDescription());}
                        assertFalse(packet.getMessage().contains("targetHost"));assertFalse(packet.getMessage().contains("credential"));
                    }
                    assertNull(to.readOutbound(),"never duplicate a catalog write");if(successor[0]!=null)assertNull(successor[0].readOutbound());
                    assertEquals(selected==Case.CAPACITY_ROLLBACK?1:8,((Semaphore)ReflectionTestUtils.getField(publisher,"slots")).availablePermits());
                    assertEquals(16*1024*1024,((Semaphore)ReflectionTestUtils.getField(publisher,"bytes")).availablePermits());
                }finally{for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
            });
            assertAll("current catalog publication authority",cases);
            boolean rowLocks;
            try(var connection=independent.getConnection()){rowLocks=connection.getMetaData().supportsSelectForUpdate();}
            if(rowLocks){verifyOldSnapshots(context,independent);verifyRowLocks(context,independent);}
            else verifySqliteWireBudget(context);
            System.out.println("[catalog-publication-proof] scenarios="+Case.values().length+" nativeAuthority=PASS exactControls=PASS direction=PASS budgetAndRetry=PASS");
        }finally{
            properties.setEnabled(original);
            if(previous.isEmpty())jdbc.update("delete from peer_mesh_service_sharing where tenant_id='default'");
            else {
                if(jdbc.queryForObject("select count(*) from peer_mesh_service_sharing where tenant_id='default'",Integer.class)==0)jdbc.update("insert into peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_at,updated_by) values ('default',true,true,?,'catalog-current-proof')",Instant.now().toString());
                jdbc.update("update peer_mesh_service_sharing set enabled=?,mdns_import_enabled=? where tenant_id='default'",previous.getFirst().get("enabled"),previous.getFirst().get("mdns_import_enabled"));
            }
        }
    }
    private static void mutate(ConfigurableApplicationContext context,JdbcTemplate jdbc,Case selected,long base,ClientAccount source,ClientAccount target,
                               EmbeddedChannel from,EmbeddedChannel to,PeerServiceDiscoveryService services,PeerCatalogPublicationService publisher,
                               List<EmbeddedChannel> channels,EmbeddedChannel[] successor,AtomicLong clock){
        switch(selected){
            case PUBLISHER_OWNER -> owner(jdbc,base+1,"changed-owner");
            case RECIPIENT_OWNER -> owner(jdbc,base+2,"changed-owner");
            case PUBLISHER_DISABLED,RECIPIENT_DISABLED -> jdbc.update("update specus_client_account set enabled=false where id=?",base+(selected==Case.PUBLISHER_DISABLED?1:2));
            case PUBLISHER_DEVICE,RECIPIENT_DEVICE -> jdbc.update("update peer_mesh_device set enabled=false where client_id=?",base+(selected==Case.PUBLISHER_DEVICE?1:2));
            case PUBLISHER_CREDENTIAL,RECIPIENT_CREDENTIAL -> jdbc.update("update specus_client_credential set enabled=false where id=?",base+(selected==Case.PUBLISHER_CREDENTIAL?21:22));
            case PUBLISHER_SESSION,RECIPIENT_SESSION -> jdbc.update("update specus_client_session set status='DISCONNECTED' where id=?",base+(selected==Case.PUBLISHER_SESSION?41:42));
            case PUBLISHER_CAPABILITY,RECIPIENT_CAPABILITY -> jdbc.update("update specus_client_session set peer_service_discovery_version=1 where id=?",base+(selected==Case.PUBLISHER_CAPABILITY?41:42));
            case BORROWED_PUBLISHER_CAPABILITY,BORROWED_RECIPIENT_CAPABILITY -> {
                long session=base+(selected==Case.BORROWED_PUBLISHER_CAPABILITY?41:42);
                jdbc.update("insert into specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,message_send_capable,message_receive_capable,message_attachments_capable,message_media_preview_capable,message_max_attachment_bytes,peer_service_discovery_version,client_egress_version,client_egress_domain_targets,http_login_at,expires_at) select id+20,tenant_id,credential_id,identity_id,client_id,client_name,'other-proof',status,machine_fingerprint,os_user,true,true,true,true,1048576,2,0,false,http_login_at,expires_at from specus_client_session where id=?",session);
                jdbc.update("update specus_client_session set peer_service_discovery_version=1 where id=?",session);
            }
            case PUBLISHER_CHANNEL_DB,RECIPIENT_CHANNEL_DB -> jdbc.update("update specus_client_session set channel_id='not-this-channel' where id=?",base+(selected==Case.PUBLISHER_CHANNEL_DB?41:42));
            case FOREIGN_PUBLISHER_SESSION -> jdbc.update("update specus_client_session set client_id=? where id=?",base+2,base+41);
            case FOREIGN_RECIPIENT_SESSION -> jdbc.update("update specus_client_session set client_id=? where id=?",base+1,base+42);
            case ALLOWLIST_REVOKED -> jdbc.update("update peer_mesh_shared_service set visibility='ACL',allowed_client_ids='999' where id=?",base+5);
            case MALFORMED_ALLOWLIST -> jdbc.update("update peer_mesh_shared_service set visibility='ACL',allowed_client_ids='[999]' where id=?",base+5);
            case UNKNOWN_VISIBILITY -> jdbc.update("update peer_mesh_shared_service set visibility='UNKNOWN' where id=?",base+5);
            case DEFINITION_DISABLED -> jdbc.update("update peer_mesh_shared_service set enabled=false where id=?",base+5);
            case DEFINITION_DELETED -> jdbc.update("delete from peer_mesh_shared_service where id=?",base+5);
            case DEFINITION_MOVED -> jdbc.update("update peer_mesh_shared_service set client_id=? where id=?",base+2,base+5);
            case DEFINITION_RENAMED -> jdbc.update("update peer_mesh_shared_service set name='fresh database name',description='fresh database description' where id=?",base+5);
            case RUNTIME_CHANGED -> jdbc.update("update peer_mesh_shared_service set published_port=18081 where id=?",base+5);
            case SHARING_DISABLED -> jdbc.update("update peer_mesh_service_sharing set enabled=false where tenant_id='default'");
            case SHARING_DELETED -> jdbc.update("delete from peer_mesh_service_sharing where tenant_id='default'");
            case RETAINED_ACCESS -> {owner(jdbc,base+1,"changed-owner");acl(jdbc,base,Case.CONSUMER_OUTBOUND);}
            case SUCCESSOR_PUBLISHER -> successor[0]=PeerCatalogCommitAssertions.bind(source,base+41,null,channels,jdbc);
            case SUCCESSOR_RECIPIENT -> successor[0]=PeerCatalogCommitAssertions.bind(target,base+42,null,channels,jdbc);
            case SUPERSEDED_REPORT,WITHDRAW_SUPERSEDED -> new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(status->services.handleReport(source,PeerCatalogCommitAssertions.report(2)));
            case EXPIRED_QUEUE -> clock.addAndGet(TimeUnit.SECONDS.toNanos(11));
            case WRITE_FAILURE -> to.pipeline().addLast(new ChannelOutboundHandlerAdapter(){@Override public void write(ChannelHandlerContext ctx,Object message,ChannelPromise promise){promise.setFailure(new IllegalStateException("intentional channel write failure"));}});
            default -> { }
        }
    }
    private static void owner(JdbcTemplate jdbc,long id,String owner){jdbc.update("update specus_client_account set owner_username=? where id=?",owner,id);jdbc.update("update specus_client_credential set owner_username=? where id=?",owner,id+20);}
    private static void acl(JdbcTemplate jdbc,long base,Case selected){
        boolean forward=selected!=Case.PUBLISHER_INBOUND&&selected!=Case.PUBLISHER_OUTBOUND;
        String direction=selected==Case.CONSUMER_INBOUND||selected==Case.PUBLISHER_INBOUND?"INBOUND":selected==Case.ACL_BOTH?"BOTH":"OUTBOUND";
        long a=base+(forward?2:1),b=base+(forward?1:2);String now=Instant.now().toString();
        jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default','catalog-commit',?,?,?, ?,?,?,?,?)",base+6,a,"catalog-commit-"+a,b,"catalog-commit-"+b,selected!=Case.ACL_DENIED,direction,now,now);
        if(selected!=Case.OWNER_WITH_CROSS_ACL)jdbc.update("update peer_mesh_shared_service set visibility='ACL' where id=?",base+5);
    }

    private static void verifyOldSnapshots(ConfigurableApplicationContext context,DataSource independent)throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class);var writer=new JdbcTemplate(independent);
        var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));var authority=context.getBean(PeerCatalogAuthority.class);
        var accounts=context.getBean(ClientAccountRepository.class);var proxy=(Advised)authority;
        for(int selected=0;selected<5;selected++){
            int boundary=selected;long base=11_210_000+selected*100;PeerCatalogCommitAssertions.fixture(jdbc,base,100+selected);
            jdbc.update("update peer_mesh_service_sharing set enabled=true where tenant_id='default'");
            var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
            if(boundary==3){owner(jdbc,base+2,"catalog-consumer");acl(jdbc,base,Case.CONSUMER_OUTBOUND);}
            var services=PeerCatalogCommitAssertions.service(context);var publisher=new PeerCatalogPublicationService(services,authority,8,System::nanoTime);
            var channels=new ArrayList<EmbeddedChannel>();PeerCatalogCommitAssertions.bind(source,base+41,null,channels,jdbc);
            var to=PeerCatalogCommitAssertions.bind(target,base+42,null,channels,jdbc);Thread worker=Thread.currentThread();AtomicBoolean ran=new AtomicBoolean();
            MethodInterceptor stale=invocation->{
                if(Thread.currentThread()==worker&&invocation.getMethod().getName().equals("publish")){
                    assertTrue(TransactionSynchronizationManager.isActualTransactionActive());
                    var old=accounts.findById(base+1).orElseThrow();
                    var oldDefinition=context.getBean(PeerMeshSharedServiceRepository.class).findById(base+5).orElseThrow();
                    var oldSharing=context.getBean(PeerMeshServiceSharingRepository.class).findById("default").orElseThrow();
                    switch(boundary){
                        case 0 -> owner(writer,base+1,"changed-owner");
                        case 1 -> writer.update("update peer_mesh_shared_service set enabled=false where id=?",base+5);
                        case 2 -> writer.update("update peer_mesh_service_sharing set enabled=false where tenant_id='default'");
                        case 3 -> writer.update("update peer_mesh_acl set allowed=false where id=?",base+6);
                        case 4 -> writer.update("update specus_client_session set peer_service_discovery_version=1 where id=?",base+41);
                        default -> throw new AssertionError();
                    }
                    assertEquals("catalog-commit",old.getOwnerUsername());assertTrue(oldDefinition.isEnabled());assertTrue(oldSharing.isEnabled());ran.set(true);
                }
                return invocation.proceed();
            };
            try{
                tx.executeWithoutResult(status->{var deliveries=services.handleReport(source,PeerCatalogCommitAssertions.report(1));assertEquals(1,deliveries.size());publisher.submit(deliveries.getFirst());});
                proxy.addAdvice(proxy.getAdvisors().length,stale);try{publisher.publishPending();}finally{proxy.removeAdvice(stale);}
                assertTrue(ran.get());MessageResponsePacket packet=to.readOutbound();assertNotNull(packet,"current guard must withdraw despite old L1/RR boundary "+boundary);
                assertTrue(JsonUtil.stringToObject(packet.getMessage(),PeerControlMessage.class).getServices().isEmpty());assertNull(to.readOutbound());
                assertEquals(8,((Semaphore)ReflectionTestUtils.getField(publisher,"slots")).availablePermits());
            }finally{for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
        }
        jdbc.update("update peer_mesh_service_sharing set enabled=true where tenant_id='default'");
        System.out.println("[catalog-publication-proof] actualOldL1AndProviderSnapshotBoundaries=5PASS");
    }

    private static void verifyRowLocks(ConfigurableApplicationContext context,DataSource independent)throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class);var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var authority=context.getBean(PeerCatalogAuthority.class);var accounts=context.getBean(ClientAccountRepository.class);
        var channels=new ArrayList<EmbeddedChannel>();var workers=Executors.newFixedThreadPool(2);
        var entered=new CountDownLatch(1);var resume=new CountDownLatch(1);
        try{
            PeerCatalogPublicationService[] publishers=new PeerCatalogPublicationService[2];EmbeddedChannel[] recipients=new EmbeddedChannel[2];
            for(int pair=0;pair<2;pair++){
                long base=11_211_000+pair*100;PeerCatalogCommitAssertions.fixture(jdbc,base,110+pair);
                if(pair==0){owner(jdbc,base+2,"catalog-consumer");acl(jdbc,base,Case.CONSUMER_OUTBOUND);}
                var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
                var services=PeerCatalogCommitAssertions.service(context);var publisher=new PeerCatalogPublicationService(services,authority,8,System::nanoTime);
                PeerCatalogCommitAssertions.bind(source,base+41,null,channels,jdbc);var to=PeerCatalogCommitAssertions.bind(target,base+42,null,channels,jdbc);
                if(pair==0)to.pipeline().addLast(new ChannelOutboundHandlerAdapter(){@Override public void write(ChannelHandlerContext ctx,Object message,ChannelPromise promise)throws Exception{
                    entered.countDown();assertTrue(resume.await(20,TimeUnit.SECONDS));ctx.write(message,promise);
                }});
                tx.executeWithoutResult(status->{var deliveries=services.handleReport(source,PeerCatalogCommitAssertions.report(1)).stream().filter(delivery->Objects.equals(target.getId(),delivery.recipient().getId())).toList();assertEquals(1,deliveries.size());publisher.submit(deliveries.getFirst());});
                publishers[pair]=publisher;recipients[pair]=to;
            }
            Future<?> held=workers.submit(publishers[0]::publishPending);
            try{
                assertTrue(entered.await(10,TimeUnit.SECONDS));
                workers.submit(publishers[1]::publishPending).get(5,TimeUnit.SECONDS);
                MessageResponsePacket unrelated=recipients[1].readOutbound();assertNotNull(unrelated,"shared tenant toggle lock must not serialize unrelated publishers");
                assertEquals(1,JsonUtil.stringToObject(unrelated.getMessage(),PeerControlMessage.class).getServices().size());
                try(var connection=independent.getConnection();var sql=connection.createStatement()){
                    boolean mysql=connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT).matches(".*(mysql|mariadb).*");
                    sql.execute(mysql?"set innodb_lock_wait_timeout=1":"set lock_timeout='200ms'");
                    String[] writes={
                        "update specus_client_account set enabled=false where id=11211001",
                        "update specus_client_credential set enabled=false where id=11211021",
                        "update peer_mesh_device set enabled=false where client_id=11211001",
                        "update peer_mesh_acl set allowed=false where id=11211006",
                        "update specus_client_session set status='DISCONNECTED' where id=11211041",
                        "update specus_client_identity set last_seen_at='locked-proof' where id=11211031",
                        "update peer_mesh_service_sharing set enabled=false where tenant_id='default'",
                        "update peer_mesh_shared_service set enabled=false where id=11211005"};
                    for(String update:writes){var blocked=assertThrows(java.sql.SQLException.class,()->sql.executeUpdate(update));if(mysql)assertEquals(1205,blocked.getErrorCode());else assertEquals("55P03",blocked.getSQLState());}
                }
            }finally{resume.countDown();}
            held.get(25,TimeUnit.SECONDS);MessageResponsePacket packet=recipients[0].readOutbound();assertNotNull(packet);assertEquals(1,JsonUtil.stringToObject(packet.getMessage(),PeerControlMessage.class).getServices().size());
            assertEquals(1,jdbc.update("update peer_mesh_shared_service set enabled=false where id=11211005"));
            System.out.println("[catalog-publication-proof] eightNativeRowsHeldThroughNetworkAcceptance=PASS unrelatedPublisherSameTenant=PASS");
        }finally{resume.countDown();workers.shutdownNow();assertTrue(workers.awaitTermination(5,TimeUnit.SECONDS));for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
    }

    private static void verifySqliteWireBudget(ConfigurableApplicationContext context) {
        // SQLite does not enforce declared VARCHAR lengths. A current native definition may
        // grow after enqueue; charge/admission of the old payload is not a final wire-size check.
        var jdbc=context.getBean(JdbcTemplate.class);long base=11_215_000;PeerCatalogCommitAssertions.fixture(jdbc,base,120);
        jdbc.update("update peer_mesh_service_sharing set enabled=true where tenant_id='default'");
        var accounts=context.getBean(ClientAccountRepository.class);var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
        var services=PeerCatalogCommitAssertions.service(context);var publisher=new PeerCatalogPublicationService(services,context.getBean(PeerCatalogAuthority.class),8,System::nanoTime);
        var channels=new ArrayList<EmbeddedChannel>();PeerCatalogCommitAssertions.bind(source,base+41,null,channels,jdbc);var to=PeerCatalogCommitAssertions.bind(target,base+42,null,channels,jdbc);
        try{
            new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(status->{var deliveries=services.handleReport(source,PeerCatalogCommitAssertions.report(1));assertEquals(1,deliveries.size());publisher.submit(deliveries.getFirst());});
            jdbc.update("update peer_mesh_shared_service set name=? where id=?","x".repeat(70_000),base+5);
            publisher.publishPending();publisher.publishPending();assertNull(to.readOutbound());
            assertEquals(8,((Semaphore)ReflectionTestUtils.getField(publisher,"slots")).availablePermits());assertEquals(16*1024*1024,((Semaphore)ReflectionTestUtils.getField(publisher,"bytes")).availablePermits());
            System.out.println("[catalog-publication-proof] sqliteCurrentMetadataGrowthFinalWireBudget=PASS");
        }finally{for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
    }
}
