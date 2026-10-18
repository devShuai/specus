package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peermesh.*;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusclient.peer.PeerServiceRuntime;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.handler.MessageRequestHandler;
import com.theshuai.specusserver.management.repository.*;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.websocket.ClientMessagesWebSocketHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import static org.junit.jupiter.api.Assertions.*;

/** Actual report handler -> commit queue -> current native authority -> serialized packet ->
 * production Java consumer. The consumer is never reset while the publisher reconnects. */
public final class PeerCatalogRevisionAssertions {
    public static void verify(ConfigurableApplicationContext context,DataSource independent)throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class);var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var properties=context.getBean(PeerMeshProperties.class);boolean enabled=properties.isEnabled();properties.setEnabled(true);
        var previous=jdbc.queryForList("select enabled,mdns_import_enabled from peer_mesh_service_sharing where tenant_id='default'");
        if(previous.isEmpty())jdbc.update("insert into peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_at,updated_by) values ('default',true,true,?,'revision-proof')",Instant.now().toString());
        else jdbc.update("update peer_mesh_service_sharing set enabled=true where tenant_id='default'");
        long base=11_220_000;PeerCatalogCommitAssertions.fixture(jdbc,base,130);
        var accounts=context.getBean(ClientAccountRepository.class);var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
        var services=PeerCatalogCommitAssertions.service(context);var publisher=new PeerCatalogPublicationService(services,context.getBean(PeerCatalogAuthority.class),16,System::nanoTime);
        var signal=new PeerSignalService(context.getBean(ClientAccountService.class),context.getBean(PeerMeshService.class),services,context.getBean(ClientSessionRepository.class),context.getBean(PeerEgressService.class),publisher);
        var handler=new MessageRequestHandler(signal,context.getBean(ClientAccountService.class),context.getBean(ClientMessageRelayService.class),context.getBean(ClientMessagesWebSocketHandler.class));
        var channels=new ArrayList<EmbeddedChannel>();var from=PeerCatalogCommitAssertions.bind(source,base+41,handler,channels,jdbc);var to=PeerCatalogCommitAssertions.bind(target,base+42,null,channels,jdbc);
        List<String> wire=new ArrayList<>();
        try(var consumer=new PeerServiceRuntime((name,message)->{})){
            var config=new ClientAuthLoginResponse.PeerMeshConfig();config.setServiceSharing(PeerServiceSharingStatus.of(true,true,true,false));consumer.applyConfig(config);
            consumer.setRosterLookup(id->new PeerServiceRuntime.RosterHint("100.119.230.1",true));
            for(long reportRevision:new long[]{Long.MAX_VALUE-1,Long.MAX_VALUE}){
                tx.executeWithoutResult(status->from.writeInbound(request(reportRevision)));
                publisher.publishPending();receive(to,consumer,wire,wire.size()+1,1);
            }
            for(long replay:new long[]{Long.MAX_VALUE,Long.MAX_VALUE-1}){
                tx.executeWithoutResult(status->from.writeInbound(request(replay)));publisher.publishPending();assertNull(to.readOutbound());
            }
            tx.executeWithoutResult(status->{jdbc.update("update peer_mesh_service_sharing set enabled=false where tenant_id='default'");signal.pushCatalogs(services.onAuthorizationChanged("default"));});
            publisher.publishPending();receive(to,consumer,wire,3,0);
            tx.executeWithoutResult(status->{jdbc.update("update specus_client_session set status='DISCONNECTED' where id=?",base+41);signal.pushCatalogs(services.onClientDisconnected(source,base+41));});
            publisher.publishPending();receive(to,consumer,wire,4,0);
            assertEquals(0,services.trackedCatalogRevisionCount(),"cleanup must release bounded per-session state");
            SessionUtil.unBindSession(from);from.finishAndReleaseAll();
            var successor=PeerCatalogCommitAssertions.bind(source,base+41,handler,channels,jdbc);
            jdbc.update("update specus_client_session set status='NETTY_ONLINE' where id=?",base+41);jdbc.update("update peer_mesh_service_sharing set enabled=true where tenant_id='default'");
            tx.executeWithoutResult(status->successor.writeInbound(request(1)));
            publisher.publishPending();receive(to,consumer,wire,5,1);
            consumer.applyCatalog(JsonUtil.stringToObject(wire.get(1),PeerControlMessage.class));
            consumer.applyCatalog(JsonUtil.stringToObject(wire.get(3),PeerControlMessage.class));
            assertEquals(1,consumer.remoteServices().size(),"old data or withdrawal cannot roll back the reconnected publisher");
            var clock=(AtomicLong)ReflectionTestUtils.getField(services,"catalogSequence");clock.set(Long.MAX_VALUE);
            assertThrows(RuntimeException.class,()->tx.executeWithoutResult(status->signal.pushCatalogs(services.onAuthorizationChanged("default"))));
            assertEquals(5,services.currentCatalog("default",base+1,base+41).revision());assertNull(to.readOutbound());
            String directory=System.getenv("SPECUS_TEST_CATALOG_REVISION_WIRE_DIR");
            boolean sqlite;try(var connection=independent.getConnection()){sqlite=connection.getMetaData().getDatabaseProductName().toLowerCase(Locale.ROOT).contains("sqlite");}
            if(sqlite&&directory!=null&&!directory.isBlank()){Path folder=Path.of(directory);Files.createDirectories(folder);Files.write(folder.resolve("java.jsonl"),wire);}
            System.out.println("[catalog-revision-proof] rawMAXAndMAXMinusOne=PASS wire1to5=PASS sameAuthSessionReconnectActualConsumer=PASS replay=PASS hardExhaustionNoWrap=PASS");
        }finally{
            properties.setEnabled(enabled);for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}
            if(previous.isEmpty())jdbc.update("delete from peer_mesh_service_sharing where tenant_id='default'");
            else jdbc.update("update peer_mesh_service_sharing set enabled=?,mdns_import_enabled=? where tenant_id='default'",previous.getFirst().get("enabled"),previous.getFirst().get("mdns_import_enabled"));
        }
    }
    private static MessageRequestPacket request(long revision){var request=new MessageRequestPacket();request.setMessageType(MessageType.PEER_CONTROL);request.setMessage(JsonUtil.objectToString(PeerCatalogCommitAssertions.report(revision)));return request;}
    private static void receive(EmbeddedChannel to,PeerServiceRuntime consumer,List<String> wire,long expectedRevision,int count){
        MessageResponsePacket packet=to.readOutbound();assertNotNull(packet);assertNull(to.readOutbound());var message=JsonUtil.stringToObject(packet.getMessage(),PeerControlMessage.class);
        assertEquals(expectedRevision,message.getRevision());assertEquals(count,message.getServices().size());wire.add(packet.getMessage());consumer.applyCatalog(message);assertEquals(count,consumer.remoteServices().size(),"real consumer must apply catalog/withdrawal");
    }
}
