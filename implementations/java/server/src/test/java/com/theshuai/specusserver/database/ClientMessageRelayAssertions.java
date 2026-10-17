package com.theshuai.specusserver.database;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.handler.MessageRequestHandler;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientControlSessionAuthority;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.websocket.ClientMessagesWebSocketHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.function.Executable;
import org.springframework.aop.framework.Advised;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.jupiter.api.Assertions.*;

/** Real handler pipeline, actual producer transactions/current guards and own worker clock.
 * These SQL mutations test routing fences, not transfer POST acceptance or durable delivery. */
public final class ClientMessageRelayAssertions {
    enum Case { COMMIT, ROLLBACK, OLD_SOURCE_OWNER, OLD_TARGET_OWNER, REVOKED_AFTER_COMMIT,
        SOURCE_DISABLED,TARGET_DISABLED,DEVICE_DISABLED,SOURCE_CREDENTIAL_DISABLED,TARGET_CREDENTIAL_DISABLED,
        SOURCE_SESSION_DISCONNECTED,TARGET_SESSION_DISCONNECTED,FOREIGN_SESSION,WRONG_SOURCE_SESSION,
        WRONG_TARGET_SESSION,DB_CHANNEL_REBOUND,SOURCE_REPLACED,TARGET_REPLACED,AUTH_CHANGED,
        SOURCE_RENAMED,TARGET_RENAMED,SOURCE_TENANT,TARGET_TENANT,DATA_CONTEXT,EMPTY,OVERSIZED,UNICODE_BUDGET,
        CAPACITY_ROLLBACK,EXPLICIT_ACL_TRANSFER,DIRECTION_OUT,DIRECTION_IN,REVERSE_IN,LEGACY,DERIVED_DOWNGRADE,
        BODY_IMMUTABLE,RETRY,GIVEUP,AFTER_WRITE_FAILURE,FOREIGN_IDENTITY,FOREIGN_CREDENTIAL,EXPIRED,BYTE_BUDGET }
    public static void verify(ConfigurableApplicationContext context,DataSource independent) throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class);var other=new JdbcTemplate(independent);
        boolean sqlite;try(var connection=independent.getConnection()){sqlite=connection.getMetaData().getDatabaseProductName().contains("SQLite");}
        var mutation=sqlite?jdbc:other;
        var mesh=context.getBean(PeerMeshService.class);var accounts=context.getBean(ClientAccountRepository.class);
        var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        List<Executable> checks=new ArrayList<>();
        for(Case selected:Case.values())checks.add(()->{
            long base=8_100_000+selected.ordinal()*100;String now=Instant.now().toString();
            boolean legacy=selected==Case.LEGACY;
            for(long id:List.of(base+1,base+2)){
                jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','relay-alice',?,'fixture-only',true,30,?,?)",id,"client-relay-"+id,now,now);
                jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,public_key,enabled,created_at,updated_at) values (?,'default','relay-alice',?,?,?,'100.117.0.0/16','relay-key',true,?,?)",id,id,"client-relay-"+id,"100.117."+(100+selected.ordinal())+"."+(id-base),now,now);
                if(!legacy){
                    jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','relay-alice',?,'fixture-only',true,3,?,?)",id+20,"relay-api-"+id,now,now);
                    jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',?,?,?,?,'relay',?,?)",id+30,id+20,id,"client-relay-"+id,"relay-machine-"+id,now,now);
                }
            }
            var source=accounts.findById(base+1).orElseThrow();var target=accounts.findById(base+2).orElseThrow();
            int capacity=selected==Case.CAPACITY_ROLLBACK?1:8;
            var clock=new java.util.concurrent.atomic.AtomicLong();
            var relay=new ClientMessageRelayService(context.getBean(ClientAccountService.class),mesh,context.getBean(ClientControlSessionAuthority.class),capacity,clock::get);
            var handler=new MessageRequestHandler(context.getBean(PeerSignalService.class),context.getBean(ClientAccountService.class),relay,context.getBean(ClientMessagesWebSocketHandler.class));
            List<EmbeddedChannel> channels=new ArrayList<>();
            var from=bind(source,legacy?null:base+41,handler,channels);var to=bind(target,legacy?null:base+42,null,channels);
            var lockObserved=new AtomicInteger();var lockFailure=new java.util.concurrent.atomic.AtomicReference<Throwable>();
            if(selected==Case.COMMIT&&!sqlite){
                jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','unrelated',?,'fixture-only',true,30,?,?)",base+90,"relay-unrelated-"+base,now,now);
                to.pipeline().addLast(new io.netty.channel.ChannelOutboundHandlerAdapter(){
                    @Override public void write(io.netty.channel.ChannelHandlerContext ctx,Object packet,io.netty.channel.ChannelPromise promise){
                        try{
                            assertTrue(org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive());
                            try(var connection=independent.getConnection();var statement=connection.createStatement()){
                                boolean postgres=connection.getMetaData().getDatabaseProductName().contains("PostgreSQL");
                                statement.execute(postgres?"set lock_timeout='150ms'":"set innodb_lock_wait_timeout=1");
                                assertEquals(1,statement.executeUpdate("update specus_client_account set enabled=false where id="+(base+90)),"unrelated row stays writable");
                                for(String table:List.of("specus_client_account","specus_client_credential")){
                                    long id=table.endsWith("credential")?base+22:base+2;
                                    var blocked=assertThrows(java.sql.SQLException.class,()->statement.executeUpdate("update "+table+" set enabled=enabled where id="+id));
                                    if(postgres)assertEquals("55P03",blocked.getSQLState());else assertEquals(1205,blocked.getErrorCode());
                                }
                            }
                            lockObserved.incrementAndGet();
                        }catch(Throwable error){lockFailure.set(error);}
                        ctx.write(packet,promise);
                    }
                });
            }
            if(!legacy){session(jdbc,base+41,source,base+21,base+31,from,now);session(jdbc,base+42,target,base+22,base+32,to,now);}
            boolean directed=selected==Case.DIRECTION_OUT||selected==Case.DIRECTION_IN||selected==Case.REVERSE_IN;
            if(directed){owner(jdbc,base+2,"relay-bob");acl(jdbc,base,selected==Case.REVERSE_IN,selected==Case.DIRECTION_OUT?"OUTBOUND":"INBOUND",now);}
            var request=new MessageRequestPacket();request.setMessageType(MessageType.CLIENT_TO_CLIENT);request.setClientName("forged-source");request.setToClientName(" "+target.getClientName()+" ");request.setMessage("hello-"+selected);
            boolean preDenied=List.of(Case.OLD_SOURCE_OWNER,Case.OLD_TARGET_OWNER,Case.SOURCE_TENANT,Case.TARGET_TENANT,Case.DATA_CONTEXT,
                    Case.EMPTY,Case.OVERSIZED,Case.UNICODE_BUDGET,Case.DIRECTION_IN,Case.DERIVED_DOWNGRADE,Case.WRONG_SOURCE_SESSION,Case.WRONG_TARGET_SESSION,Case.BYTE_BUDGET).contains(selected);
            try{
                tx.executeWithoutResult(status->{
                    // Genuine old L1 entities coexist with a committed external change on row DBs.
                    accounts.findById(source.getId()).orElseThrow();accounts.findById(target.getId()).orElseThrow();
                    switch(selected){
                        case OLD_SOURCE_OWNER->owner(mutation,base+1,"relay-bob");
                        case OLD_TARGET_OWNER->owner(mutation,base+2,"relay-bob");
                        case SOURCE_TENANT->from.attr(ServerAttributes.TENANT_ID).set("DEFAULT");
                        case TARGET_TENANT->to.attr(ServerAttributes.TENANT_ID).set("DEFAULT");
                        case EMPTY->request.setMessage("  ");
                        case OVERSIZED->request.setMessage("x".repeat(65537));
                        case UNICODE_BUDGET->request.setMessage("中".repeat(32769));
                        case DERIVED_DOWNGRADE->from.attr(ServerAttributes.CLIENT_SESSION_ID).set(null);
                        case WRONG_SOURCE_SESSION->from.attr(ServerAttributes.CLIENT_SESSION_ID).set(base+42);
                        case WRONG_TARGET_SESSION->to.attr(ServerAttributes.CLIENT_SESSION_ID).set(base+41);
                        case BYTE_BUDGET->((Semaphore)ReflectionTestUtils.getField(relay,"bytes")).drainPermits();
                        default->{}
                    }
                    if(selected==Case.DATA_CONTEXT){
                        var data=new EmbeddedChannel(handler);SessionUtil.bindDataSession(new Session(source.getClientName()),data);data.attr(ServerAttributes.TENANT_ID).set("default");channels.add(data);data.writeInbound(request);
                    }else from.writeInbound(request);
                    relay.publishPending();assertNull(from.readOutbound(),"no source packet before commit");assertNull(to.readOutbound(),"no business message before commit");
                    if(selected==Case.CAPACITY_ROLLBACK){assertThrows(IllegalStateException.class,()->relay.submit(request,SessionUtil.getSession(from),from));status.setRollbackOnly();}
                    if(preDenied||selected==Case.ROLLBACK)status.setRollbackOnly();
                });
                if(selected==Case.BYTE_BUDGET)((Semaphore)ReflectionTestUtils.getField(relay,"bytes")).release(16*1024*1024);
                switch(selected){
                    case REVOKED_AFTER_COMMIT->owner(other,base+2,"relay-bob");
                    case SOURCE_DISABLED->other.update("update specus_client_account set enabled=false where id=?",base+1);
                    case TARGET_DISABLED->other.update("update specus_client_account set enabled=false where id=?",base+2);
                    case DEVICE_DISABLED->other.update("update peer_mesh_device set enabled=false where client_id=?",base+2);
                    case SOURCE_CREDENTIAL_DISABLED->other.update("update specus_client_credential set enabled=false where id=?",base+21);
                    case TARGET_CREDENTIAL_DISABLED->other.update("update specus_client_credential set enabled=false where id=?",base+22);
                    case SOURCE_SESSION_DISCONNECTED->other.update("update specus_client_session set status='DISCONNECTED' where id=?",base+41);
                    case TARGET_SESSION_DISCONNECTED->other.update("update specus_client_session set status='DISCONNECTED' where id=?",base+42);
                    case FOREIGN_SESSION->other.update("update specus_client_session set tenant_id='DEFAULT' where id=?",base+42);
                    case DB_CHANNEL_REBOUND->other.update("update specus_client_session set channel_id='another-control' where id=?",base+42);
                    case SOURCE_REPLACED->bind(source,base+41,null,channels);
                    case TARGET_REPLACED->bind(target,base+42,null,channels);
                    case AUTH_CHANGED->from.attr(ServerAttributes.CLIENT_SESSION_ID).set(base+42);
                    case SOURCE_RENAMED->other.update("update specus_client_account set client_name='relay-new-source' where id=?",base+1);
                    case TARGET_RENAMED->other.update("update specus_client_account set client_name='relay-new-target' where id=?",base+2);
                    case EXPLICIT_ACL_TRANSFER->{owner(other,base+2,"relay-bob");acl(other,base,false,"OUTBOUND",now);}
                    case BODY_IMMUTABLE->{request.setMessage("mutated-after-submit");request.setToClientName(source.getClientName());}
                    case FOREIGN_IDENTITY->other.update("update specus_client_identity set tenant_id='DEFAULT' where id=?",base+32);
                    case FOREIGN_CREDENTIAL->other.update("update specus_client_session set credential_id=? where id=?",base+21,base+42);
                    case EXPIRED->clock.addAndGet(java.util.concurrent.TimeUnit.SECONDS.toNanos(11));
                    default->{}
                }
                var proxy=(Advised)mesh;var attempts=new AtomicInteger();Thread worker=Thread.currentThread();
                MethodInterceptor fault=invocation->{
                    if(Thread.currentThread()==worker&&invocation.getMethod().getName().equals("publishAuthorizedSignal")){
                        int attempt=attempts.incrementAndGet();
                        if(selected==Case.GIVEUP||selected==Case.RETRY&&attempt==1)throw new org.springframework.dao.TransientDataAccessResourceException("intentional relay publication fault");
                        Object result=invocation.proceed();
                        if(selected==Case.AFTER_WRITE_FAILURE)throw new org.springframework.dao.TransientDataAccessResourceException("intentional post-write fault");
                        return result;
                    }
                    return invocation.proceed();
                };
                boolean inject=selected==Case.RETRY||selected==Case.GIVEUP||selected==Case.AFTER_WRITE_FAILURE;
                if(inject)proxy.addAdvice(0,fault);
                try{relay.publishPending();relay.publishPending();relay.publishPending();}finally{if(inject)proxy.removeAdvice(fault);}
                boolean delivered=List.of(Case.COMMIT,Case.EXPLICIT_ACL_TRANSFER,Case.DIRECTION_OUT,Case.REVERSE_IN,Case.LEGACY,Case.BODY_IMMUTABLE,Case.RETRY,Case.AFTER_WRITE_FAILURE).contains(selected);
                MessageResponsePacket packet=to.readOutbound();
                if(delivered){assertNotNull(packet,selected.toString());assertEquals(MessageType.CLIENT_TO_CLIENT,packet.getMessageType());assertEquals(source.getClientName(),packet.getClientName());assertEquals(target.getClientName(),packet.getToClientName());assertEquals("hello-"+selected,packet.getMessage());}
                else assertNull(packet,selected.toString());
                assertNull(to.readOutbound(),"no duplicate packet");assertNull(from.readOutbound());
                for(var channel:channels)if(channel!=from&&channel!=to)assertNull(channel.readOutbound(),"must not retarget to successor/data channel");
                if(inject)assertEquals(selected==Case.RETRY?2:selected==Case.GIVEUP?3:1,attempts.get());
                assertEquals(capacity,((Semaphore)ReflectionTestUtils.getField(relay,"slots")).availablePermits());
                assertEquals(16*1024*1024,((Semaphore)ReflectionTestUtils.getField(relay,"bytes")).availablePermits());
                assertEquals(0,jdbc.queryForObject("select count(*) from peer_mesh_session where source_client_id=? or target_client_id=?",Integer.class,base+1,base+2));
                if(selected==Case.COMMIT&&!sqlite){assertNull(lockFailure.get(),String.valueOf(lockFailure.get()));assertEquals(1,lockObserved.get());}
            }finally{for(var channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
        });
        assertAll("current committed client message fallback",checks);
        System.out.println("[client-relay-proof] cases="+Case.values().length+" actualHandler=PASS currentGuards=PASS rollbackAndResourceBalance=PASS");
    }
    private static EmbeddedChannel bind(ClientAccount account,Long session,MessageRequestHandler handler,List<EmbeddedChannel> channels){
        var channel=handler==null?new EmbeddedChannel():new EmbeddedChannel(handler);channel.attr(ServerAttributes.TENANT_ID).set("default");channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(session);SessionUtil.bindSession(new Session(account.getClientName()),channel);channels.add(channel);return channel;
    }
    private static void owner(JdbcTemplate jdbc,long client,String owner){jdbc.update("update specus_client_credential set owner_username=? where id=?",owner,client+20);jdbc.update("update specus_client_account set owner_username=? where id=?",owner,client);}
    private static void acl(JdbcTemplate jdbc,long base,boolean reverse,String direction,String now){jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default','relay-alice',?,'source',?,'target',true,?,?,?)",base+5,reverse?base+2:base+1,reverse?base+1:base+2,direction,now,now);}
    private static void session(JdbcTemplate jdbc,long id,ClientAccount client,long credential,long identity,EmbeddedChannel channel,String now){
        jdbc.update("insert into specus_client_session(id,tenant_id,credential_id,identity_id,client_id,client_name,token_hash,status,machine_fingerprint,os_user,message_send_capable,message_receive_capable,message_attachments_capable,message_media_preview_capable,message_max_attachment_bytes,peer_service_discovery_version,client_egress_version,client_egress_domain_targets,http_login_at,expires_at,channel_id) values (?,'default',?,?,?,?,'fixture-only','NETTY_ONLINE',?,'relay',true,true,true,true,1048576,2,0,false,?,?,?)",id,credential,identity,client.getId(),client.getClientName(),"relay-session-"+id,now,Instant.now().plusSeconds(3600).toString(),channel.id().asLongText());
    }
}
