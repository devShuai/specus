package com.theshuai.specusserver.database;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.MessageRequestHandler;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.*;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.websocket.*;
import io.netty.channel.embedded.EmbeddedChannel;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.function.Executable;
import org.springframework.aop.framework.Advised;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.socket.*;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Only the WebSocket transport endpoint is adapted. Native identity/resource/session guards,
 * both public handlers, producer transactions and current publication transactions are real. */
public final class ManagementMessageAssertions {
    enum Case { COMMIT,ROLLBACK,OWNER_TRANSFER,NEW_OWNER_TRANSFER,ADMIN_CROSS_OWNER,USER_OTHER_OWNER,
        ACTOR_DISABLED,ACTOR_DELETED,ACTOR_DEMOTED,ACTOR_PROMOTED,LOGIN_REUSED,CLIENT_DISABLED,
        CREDENTIAL_DISABLED,SESSION_DISCONNECTED,SESSION_REPLACED,BOUND_CAP_DOWNGRADE,
        FOREIGN_ACTOR_TENANT,FOREIGN_CONTROL,DERIVED_DOWNGRADE,WS_CLOSED,WS_IDENTITY_CHANGED,
        CHANNEL_AUTH_CHANGED,CLIENT_RENAMED,EXPIRED,OVERSIZE,RETRY,GIVEUP,AFTER_WRITE_FAILURE,
        CAPACITY_ROLLBACK,OUTER_TX_DRAIN,LEGACY,MULTI_TAB,LEGACY_TICKET,LEGACY_TICKET_REUSED }
    private record Browser(WebSocketSession socket,Map<String,Object> attributes,List<Map<?,?>> packets,AtomicBoolean open,AtomicReference<Runnable> observer) {}
    public static void verify(ConfigurableApplicationContext context,DataSource independent)throws Exception{
        var jdbc=context.getBean(JdbcTemplate.class);var other=new JdbcTemplate(independent);
        var clients=context.getBean(ClientAccountRepository.class);var actors=context.getBean(ManagementUserRepository.class);
        var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        boolean sqlite;try(var connection=independent.getConnection()){sqlite=connection.getMetaData().getDatabaseProductName().contains("SQLite");}
        List<Executable> checks=new ArrayList<>();
        for(boolean outgoing:List.of(true,false))for(Case selected:Case.values())checks.add(()->{
            long base=9_500_000+(outgoing?0:100_000)+selected.ordinal()*100;String now=Instant.now().toString();
            String key="ws-msg-key-"+base,login="ws-msg-"+base,name="ws-client-"+base;
            boolean admin=selected==Case.ADMIN_CROSS_OWNER||selected==Case.ACTOR_DEMOTED;
            String owner=selected==Case.ADMIN_CROSS_OWNER||selected==Case.USER_OTHER_OWNER||selected==Case.NEW_OWNER_TRANSFER?"ws-other-owner":login;
            actor(jdbc,key,login,admin||selected==Case.MULTI_TAB,now);
            jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,?,'fixture-only',true,30,?,?)",base+1,owner,name,now,now);
            boolean legacy=selected==Case.LEGACY;
            if(!legacy){
                jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default',?,?,'fixture-only',true,3,?,?)",base+21,owner,"ws-msg-api-"+base,now,now);
                jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',?,?,?,?,'ws',?,?)",base+31,base+21,base+1,name,"ws-msg-machine-"+base,now,now);
            }
            var clock=new AtomicLong();int capacity=selected==Case.CAPACITY_ROLLBACK?1:8;
            var relay=new ManagementMessageRelayService(context.getBean(ManagementMessageAuthority.class),context.getBean(ClientControlSessionAuthority.class),capacity,clock::get);
            var handler=new ClientMessagesWebSocketHandler(context.getBean(ClientAccountService.class),relay,context.getBean(ManagementWebSocketIdentity.class));
            Browser stale;
            if(selected==Case.MULTI_TAB){stale=browser(key,login,true);handler.afterConnectionEstablished(stale.socket());stale.packets().clear();jdbc.update("update specus_management_user set role='USER' where username=?",key);}else stale=null;
            var browser=browser(selected==Case.LEGACY_TICKET||selected==Case.LEGACY_TICKET_REUSED?null:key,login,admin);handler.afterConnectionEstablished(browser.socket());
            assertTrue(browser.open().get(),"actual handshake identity resolves");browser.packets().clear();
            var reference=clients.findById(base+1).orElseThrow();List<EmbeddedChannel> channels=new ArrayList<>();
            var netty=new MessageRequestHandler(context.getBean(PeerSignalService.class),context.getBean(ClientAccountService.class),context.getBean(ClientMessageRelayService.class),handler);
            var channel=bind(reference,legacy?null:base+41,netty,channels);
            if(!legacy)session(jdbc,base+41,reference,base+21,base+31,channel,true,now);
            var observed=new AtomicInteger();var observationFailure=new AtomicReference<Throwable>();
            if(selected==Case.COMMIT&&!sqlite){
                actor(jdbc,key+"-free",login+"-free",false,now);
                Runnable observe=()->{try{locks(independent,base,key);observed.incrementAndGet();}catch(Throwable error){observationFailure.set(error);}};
                if(outgoing)channel.pipeline().addLast(new io.netty.channel.ChannelOutboundHandlerAdapter(){
                    @Override public void write(io.netty.channel.ChannelHandlerContext ctx,Object value,io.netty.channel.ChannelPromise promise){observe.run();ctx.write(value,promise);}
                });else browser.observer().set(observe);
            }
            try{
                tx.executeWithoutResult(status->{
                    actors.findById(key).orElseThrow();clients.findById(base+1).orElseThrow();
                    String body=selected==Case.OVERSIZE?"中".repeat(32769):"hello-"+selected;
                    try{
                        if(outgoing){
                            if(stale!=null)handler.handleMessage(stale.socket(),new TextMessage(JsonUtil.objectToString(Map.of("type","message","messageId","stale-id","toClientName",name,"message","stale-payload"))));
                            handler.handleMessage(browser.socket(),new TextMessage(JsonUtil.objectToString(Map.of("type","message","messageId","id-"+base,"toClientName",name,"message",body))));
                        }
                        else{
                            var request=new MessageRequestPacket();request.setMessageType(MessageType.CLIENT_TO_CLIENT);request.setToClientName("admin:"+login);request.setMessage(body);channel.writeInbound(request);
                        }
                    }catch(Exception failure){throw new IllegalStateException(failure);}
                    relay.publishPending();assertNull(channel.readOutbound(),"no client data before producer commit");
                    assertTrue(browser.packets().stream().noneMatch(ManagementMessageAssertions::business),"no business/status success before commit");
                    if(selected==Case.CAPACITY_ROLLBACK){
                        assertThrows(IllegalStateException.class,()->{if(outgoing)relay.toClient(browser.socket(),reference,"second","id-second");else relay.fromClient(browser.socket(),reference,channel,"second");});status.setRollbackOnly();
                    }
                    if(selected==Case.ROLLBACK)status.setRollbackOnly();
                });
                switch(selected){
                    case OWNER_TRANSFER->owner(other,base,"ws-new-owner");
                    case NEW_OWNER_TRANSFER->owner(other,base,login);
                    case ACTOR_DISABLED->other.update("update specus_management_user set enabled=false where username=?",key);
                    case ACTOR_DELETED->other.update("delete from specus_management_user where username=?",key);
                    case ACTOR_DEMOTED->other.update("update specus_management_user set role='USER' where username=?",key);
                    case ACTOR_PROMOTED->other.update("update specus_management_user set role='ADMIN' where username=?",key);
                    case LOGIN_REUSED,LEGACY_TICKET_REUSED->{other.update("update specus_management_user set login_name=?,login_name_normalized=? where username=?",login+"-old",login+"-old",key);actor(other,key+"-new",login,admin,now);}
                    case CLIENT_DISABLED->other.update("update specus_client_account set enabled=false where id=?",base+1);
                    case CREDENTIAL_DISABLED->other.update("update specus_client_credential set enabled=false where id=?",base+21);
                    case SESSION_DISCONNECTED->other.update("update specus_client_session set status='DISCONNECTED' where id=?",base+41);
                    case SESSION_REPLACED->bind(reference,base+41,null,channels);
                    case BOUND_CAP_DOWNGRADE->{other.update("update specus_client_session set message_receive_capable=false where id=?",base+41);session(other,base+42,reference,base+21,base+31,channel,true,now);}
                    case FOREIGN_ACTOR_TENANT->other.update("update specus_management_user set tenant_id='DEFAULT' where username=?",key);
                    case FOREIGN_CONTROL->channel.attr(ServerAttributes.TENANT_ID).set("DEFAULT");
                    case DERIVED_DOWNGRADE->channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(null);
                    case WS_CLOSED->browser.open().set(false);
                    case WS_IDENTITY_CHANGED->browser.attributes().put(WebSocketTicketHandshakeInterceptor.ATTR_ACCOUNT_KEY,key+"-other");
                    case CHANNEL_AUTH_CHANGED->channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(base+42);
                    case CLIENT_RENAMED->other.update("update specus_client_account set client_name=? where id=?",name+"-new",base+1);
                    case EXPIRED->clock.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(11));
                    case OUTER_TX_DRAIN->tx.executeWithoutResult(status->{relay.publishPending();assertNull(channel.readOutbound());assertTrue(browser.packets().stream().noneMatch(ManagementMessageAssertions::business));status.setRollbackOnly();});
                    default->{}
                }
                var authority=(Advised)context.getBean(ManagementMessageAuthority.class);var attempts=new AtomicInteger();Thread worker=Thread.currentThread();
                MethodInterceptor fault=invocation->{
                    if(Thread.currentThread()==worker&&invocation.getMethod().getName().equals("publish")){
                        int attempt=attempts.incrementAndGet();
                        if(selected==Case.GIVEUP||selected==Case.RETRY&&attempt==1)throw new org.springframework.dao.TransientDataAccessResourceException("intentional management message fault");
                        Object value=invocation.proceed();
                        if(selected==Case.AFTER_WRITE_FAILURE)throw new org.springframework.dao.TransientDataAccessResourceException("intentional management post-write fault");
                        return value;
                    }
                    return invocation.proceed();
                };
                boolean inject=selected==Case.RETRY||selected==Case.GIVEUP||selected==Case.AFTER_WRITE_FAILURE;
                if(inject)authority.addAdvice(0,fault);
                try{relay.publishPending();relay.publishPending();relay.publishPending();}finally{if(inject)authority.removeAdvice(fault);}
                boolean delivered=List.of(Case.COMMIT,Case.NEW_OWNER_TRANSFER,Case.ADMIN_CROSS_OWNER,Case.RETRY,Case.AFTER_WRITE_FAILURE,Case.OUTER_TX_DRAIN,Case.MULTI_TAB,Case.LEGACY_TICKET).contains(selected)
                        ||!outgoing&&(selected==Case.BOUND_CAP_DOWNGRADE||selected==Case.LEGACY);
                var business=browser.packets().stream().filter(ManagementMessageAssertions::business).toList();
                MessageResponsePacket packet=channel.readOutbound();
                String label=(outgoing?"browser->client ":"client->browser ")+selected;
                if(outgoing&&delivered){assertNotNull(packet,label);assertEquals("admin:"+login,packet.getClientName());assertEquals(name,packet.getToClientName());assertEquals("hello-"+selected,packet.getMessage());assertEquals(1,business.size(),label);assertEquals("written",business.getFirst().get("type"));}
                else{assertNull(packet,label);assertEquals(delivered?1:0,business.size(),label);if(delivered){assertEquals(name,business.getFirst().get("fromClientName"));assertEquals("hello-"+selected,business.getFirst().get("message"));}}
                assertNull(channel.readOutbound(),"no duplicate business packet");
                if(outgoing&&selected==Case.AFTER_WRITE_FAILURE)assertEquals(1,browser.packets().size(),"no failed status after written");
                for(var successor:channels)if(successor!=channel)assertNull(successor.readOutbound(),"no successor retargeting");
                if(List.of(Case.ACTOR_DISABLED,Case.ACTOR_DELETED,Case.ACTOR_DEMOTED,Case.ACTOR_PROMOTED,Case.LOGIN_REUSED,Case.LEGACY_TICKET_REUSED,Case.FOREIGN_ACTOR_TENANT).contains(selected))assertFalse(browser.open().get(),label);
                if(outgoing&&selected==Case.BOUND_CAP_DOWNGRADE)assertTrue(browser.packets().stream().anyMatch(value->"target-cannot-receive-message".equals(value.get("error"))));
                if(inject)assertEquals(selected==Case.RETRY?2:selected==Case.GIVEUP?3:1,attempts.get());
                assertEquals(capacity,((Semaphore)ReflectionTestUtils.getField(relay,"slots")).availablePermits());
                assertEquals(16*1024*1024,((Semaphore)ReflectionTestUtils.getField(relay,"bytes")).availablePermits());
                if(stale!=null){assertFalse(stale.open().get());assertTrue(stale.packets().stream().noneMatch(ManagementMessageAssertions::business));}
                if(selected==Case.COMMIT&&!sqlite){assertNull(observationFailure.get(),String.valueOf(observationFailure.get()));assertEquals(1,observed.get());}
            }finally{for(var item:channels){SessionUtil.unBindSession(item);item.finishAndReleaseAll();}browser.open().set(false);handler.afterConnectionClosed(browser.socket(),CloseStatus.NORMAL);if(stale!=null){stale.open().set(false);handler.afterConnectionClosed(stale.socket(),CloseStatus.NORMAL);}}
        });
        assertAll("current management message identity/ownership/bound session in both directions",checks);
        System.out.println("[management-message-proof] scenarios="+(Case.values().length*2)+" bothHandlers=PASS actorResourceAndBoundSession=PASS commitAndResources=PASS");
    }
    private static boolean business(Map<?,?> value){return "message".equals(value.get("type"))||"written".equals(value.get("type"));}
    private static Browser browser(String key,String login,boolean admin)throws Exception{
        var socket=mock(WebSocketSession.class);Map<String,Object> attributes=new HashMap<>();attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_USER,login);attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_TENANT_ID,"default");attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_ADMIN,admin);attributes.put(WebSocketTicketHandshakeInterceptor.ATTR_ACCOUNT_KEY,key);
        var packets=new ArrayList<Map<?,?>>();var open=new AtomicBoolean(true);when(socket.getAttributes()).thenReturn(attributes);when(socket.isOpen()).thenAnswer(call->open.get());
        var observer=new AtomicReference<Runnable>(() -> {});
        doAnswer(call->{Map<?,?> value=JsonUtil.stringToObject(call.<TextMessage>getArgument(0).getPayload(),Map.class);if("message".equals(value.get("type")))observer.get().run();packets.add(value);return null;}).when(socket).sendMessage(any());
        doAnswer(call->{open.set(false);return null;}).when(socket).close(any(CloseStatus.class));return new Browser(socket,attributes,packets,open,observer);
    }
    private static void locks(DataSource independent,long base,String key)throws Exception{
        assertTrue(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive());
        try(var connection=independent.getConnection();var statement=connection.createStatement()){
            boolean postgres=connection.getMetaData().getDatabaseProductName().contains("PostgreSQL");
            statement.execute(postgres?"set lock_timeout='150ms'":"set innodb_lock_wait_timeout=1");
            assertEquals(1,statement.executeUpdate("update specus_management_user set enabled=false where username='"+key+"-free'"),"unrelated management account is not locked");
            for(String sql:List.of("update specus_management_user set enabled=enabled where username='"+key+"'",
                    "update specus_client_account set enabled=enabled where id="+(base+1),"update specus_client_credential set enabled=enabled where id="+(base+21))){
                var blocked=assertThrows(java.sql.SQLException.class,()->statement.executeUpdate(sql));
                if(postgres)assertEquals("55P03",blocked.getSQLState());else assertEquals(1205,blocked.getErrorCode());
            }
        }
    }
    private static EmbeddedChannel bind(ClientAccount account,Long auth,MessageRequestHandler handler,List<EmbeddedChannel> channels){var channel=handler==null?new EmbeddedChannel():new EmbeddedChannel(handler);channel.attr(ServerAttributes.TENANT_ID).set("default");channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(auth);SessionUtil.bindSession(new Session(account.getClientName()),channel);channels.add(channel);return channel;}
    private static void actor(JdbcTemplate jdbc,String key,String login,boolean admin,String now){jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,'fixture-only',?,true,?,?)",key,login,login,admin?"ADMIN":"USER",now,now);}
    private static void owner(JdbcTemplate jdbc,long base,String owner){jdbc.update("update specus_client_credential set owner_username=? where id=?",owner,base+21);jdbc.update("update specus_client_account set owner_username=? where id=?",owner,base+1);}
    private static void session(JdbcTemplate jdbc,long id,ClientAccount account,long credential,long identity,EmbeddedChannel channel,boolean receive,String now){jdbc.update("insert into specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,message_send_capable,message_receive_capable,message_attachments_capable,message_media_preview_capable,message_max_attachment_bytes,peer_service_discovery_version,client_egress_version,client_egress_domain_targets,http_login_at,expires_at,channel_id) values (?,'default',?,?,?,?,'fixture-only','NETTY_ONLINE',?,'ws',true,?,true,true,1048576,2,0,false,?,?,?)",id,credential,identity,account.getId(),account.getClientName(),"ws-msg-session-"+id,receive,now,Instant.now().plusSeconds(3600).toString(),channel.id().asLongText());}
}
