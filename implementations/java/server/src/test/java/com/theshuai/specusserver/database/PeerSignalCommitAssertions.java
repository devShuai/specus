package com.theshuai.specusserver.database;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.request.MessageRequestPacket;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.session.Session;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.service.*;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.function.Executable;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.aop.framework.Advised;
import org.aopalliance.intercept.MethodInterceptor;
import static org.junit.jupiter.api.Assertions.*;

/** Real DB/services/control packets. Own publisher clock avoids a scheduler racing assertions;
 * the public handler executes inside the same actual outer transaction its Spring proxy uses. */
public final class PeerSignalCommitAssertions {
    enum Case { COMMIT, ROLLBACK, OWNER_REVOKED, CONFIG_FORGERY, ROSTER_FORGERY, GRANT_FORGERY,
        WRONG_SESSION, CLOSED_SESSION, METADATA, TARGET_REPLACED, SOURCE_REPLACED, STALE_SOURCE,
        REVOKED_BEFORE_PUBLISH, TOKEN_REBOUND, CAPACITY_ROLLBACK, CLOSE_BOUND, ROSTER_ROLLBACK,
        REFRESH_ROLLBACK, REFRESH_COMMIT, REVERSE_DIRECTION, CLOSE_WRONG_SESSION, OVERSIZED,
        PUBLISH_RETRY, PUBLISH_GIVEUP, TARGET_TENANT, STALE_CONTEXT }
    private record Fixture(ClientAccount source,ClientAccount target) {}

    public static void verify(ConfigurableApplicationContext context,DataSource independent) throws Exception {
        var jdbc=context.getBean(JdbcTemplate.class); var other=new JdbcTemplate(independent);
        boolean sqlite;
        try(var connection=independent.getConnection()){sqlite=connection.getMetaData().getDatabaseProductName().contains("SQLite");}
        var mutation=sqlite?jdbc:other;
        var mesh=context.getBean(PeerMeshService.class); var accounts=context.getBean(ClientAccountRepository.class);
        var tx=new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
        var properties=context.getBean(PeerMeshProperties.class); boolean enabled=properties.isEnabled(); properties.setEnabled(true);
        List<Executable> cases=new ArrayList<>();
        try {
            for(Case selected:Case.values()) cases.add(()->{
                long base=7_100_000+selected.ordinal()*10;
                var fixture=fixture(context,base); List<EmbeddedChannel> channels=new ArrayList<>();
                var signal=service(context,selected==Case.CAPACITY_ROLLBACK?1:32);
                EmbeddedChannel source=bind(fixture.source(),channels),target=bind(fixture.target(),channels);
                Session sourceSession=SessionUtil.getSession(source);
                try {
                    PeerMeshService.PeerSessionGrant existing=List.of(Case.COMMIT,Case.ROLLBACK,Case.CAPACITY_ROLLBACK).contains(selected)
                            ?null:mesh.createSession(fixture.source(),fixture.target(),PeerMeshService.PATH_DIRECT);
                    if(selected==Case.REVERSE_DIRECTION){
                        jdbc.update("update specus_client_account set owner_username='signal-other' where id=?",fixture.target().getId());
                        jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (?,'default','signal-owner',?,?,?,?,true,'INBOUND',?,?)",base+5,fixture.source().getId(),fixture.source().getClientName(),fixture.target().getId(),fixture.target().getClientName(),Instant.now().toString(),Instant.now().toString());
                    }
                    var message=new PeerControlMessage(); message.setType(PeerControlMessage.TYPE_CANDIDATES);
                    if(List.of(Case.WRONG_SESSION,Case.CLOSED_SESSION,Case.OWNER_REVOKED,Case.TOKEN_REBOUND,Case.CLOSE_BOUND,
                            Case.CONFIG_FORGERY,Case.ROSTER_FORGERY,Case.GRANT_FORGERY,Case.CLOSE_WRONG_SESSION).contains(selected)) message.setSessionId(existing.session().id());
                    if(selected==Case.WRONG_SESSION||selected==Case.CLOSE_WRONG_SESSION){
                        var unrelated=fixture(context,7_200_000+selected.ordinal()*10);
                        message.setSessionId(mesh.createSession(unrelated.source(),unrelated.target(),PeerMeshService.PATH_DIRECT).session().id());
                    }
                    if(selected==Case.CLOSED_SESSION) jdbc.update("update peer_mesh_session set status='CLOSED' where id=?",existing.session().id());
                    if(selected==Case.TOKEN_REBOUND){message.setToken("forged-client-token");message.setExpiresAt("2099-01-01T00:00:00Z");}
                    if(selected==Case.CONFIG_FORGERY)message.setType(PeerControlMessage.TYPE_CONFIG);
                    if(selected==Case.ROSTER_FORGERY)message.setType(PeerControlMessage.TYPE_ROSTER);
                    if(selected==Case.GRANT_FORGERY)message.setType(PeerControlMessage.TYPE_SESSION_GRANT);
                    if(selected==Case.CLOSE_BOUND)message.setType(PeerControlMessage.TYPE_CLOSE);
                    if(selected==Case.CLOSE_WRONG_SESSION)message.setType(PeerControlMessage.TYPE_CLOSE);
                    if(selected==Case.OVERSIZED)message.setReason("x".repeat(64*1024));
                    if(selected==Case.TARGET_TENANT)target.attr(ServerAttributes.TENANT_ID).set("foreign");
                    var request=request(selected==Case.CLOSE_BOUND?"nonparticipant":fixture.target().getClientName(),message);
                    EmbeddedChannel[] successor=new EmbeddedChannel[1];
                    tx.executeWithoutResult(status->{
                        accounts.findById(fixture.source().getId()).orElseThrow();accounts.findById(fixture.target().getId()).orElseThrow();
                        context.getBean(com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository.class)
                                .findByTenantIdAndClientId("default",fixture.source().getId()).orElseThrow();
                        if(selected==Case.OWNER_REVOKED)mutation.update("update specus_client_account set owner_username='signal-other' where id=?",fixture.target().getId());
                        if(selected==Case.METADATA)mutation.update("update peer_mesh_device set public_key='current-signal-public-key' where client_id in (?,?)",fixture.source().getId(),fixture.target().getId());
                        if(selected==Case.STALE_SOURCE||selected==Case.STALE_CONTEXT) successor[0]=bind(fixture.source(),channels);
                        boolean denied=List.of(Case.OWNER_REVOKED,Case.WRONG_SESSION,Case.CLOSED_SESSION,Case.CONFIG_FORGERY,Case.ROSTER_FORGERY,Case.GRANT_FORGERY,Case.STALE_SOURCE,Case.CLOSE_WRONG_SESSION,Case.OVERSIZED,Case.TARGET_TENANT,Case.STALE_CONTEXT).contains(selected);
                        if(denied){assertThrows(RuntimeException.class,()->{if(selected==Case.STALE_CONTEXT)signal.handle(request,sourceSession);else signal.handle(request,sourceSession,source);});status.setRollbackOnly();}
                        else if(selected==Case.ROSTER_ROLLBACK)signal.pushRoster(fixture.source());
                        else if(selected==Case.REFRESH_ROLLBACK||selected==Case.REFRESH_COMMIT){
                            jdbc.update("update specus_client_account set owner_username='signal-other' where id=?",fixture.target().getId());
                            signal.refreshAuthorization(new ManagementContext(TenantContext.defaultTenant(),"system-refresh",false,""));
                        } else if(selected==Case.REVERSE_DIRECTION){
                            signal.handle(request(fixture.source().getClientName(),message),SessionUtil.getSession(target),target);
                        } else signal.handle(request,sourceSession,source);
                        assertNull(source.readOutbound(),"no control packet may escape before the DB commit");
                        assertNull(target.readOutbound(),"no target packet may escape before the DB commit");
                        if(selected==Case.CAPACITY_ROLLBACK){assertThrows(IllegalStateException.class,()->signal.handle(request,sourceSession,source));status.setRollbackOnly();}
                        if(selected==Case.TARGET_REPLACED)successor[0]=bind(fixture.target(),channels);
                        if(selected==Case.SOURCE_REPLACED)successor[0]=bind(fixture.source(),channels);
                        if(selected==Case.REVOKED_BEFORE_PUBLISH)jdbc.update("update specus_client_account set owner_username='signal-other' where id=?",fixture.target().getId());
                        if(selected==Case.ROLLBACK||selected==Case.ROSTER_ROLLBACK||selected==Case.REFRESH_ROLLBACK)status.setRollbackOnly();
                    });
                    Advised proxy=assertInstanceOf(Advised.class,mesh);AtomicInteger publications=new AtomicInteger();Thread publishingThread=Thread.currentThread();
                    MethodInterceptor failure=invocation->{
                        if(Thread.currentThread()==publishingThread&&invocation.getMethod().getName().equals("publishAuthorizedSignal")){
                            int attempt=publications.incrementAndGet();
                            if(selected==Case.PUBLISH_GIVEUP||attempt==1)
                                throw new org.springframework.dao.TransientDataAccessResourceException("intentional peer publication failure");
                        }
                        return invocation.proceed();
                    };
                    boolean inject=selected==Case.PUBLISH_RETRY||selected==Case.PUBLISH_GIVEUP;
                    if(inject)proxy.addAdvice(0,failure);
                    try{
                        signal.publishPendingSignals();
                        if(inject){
                            assertNull(source.readOutbound());assertNull(target.readOutbound());
                            assertEquals(31,((Semaphore)ReflectionTestUtils.getField(signal,"signalSlots")).availablePermits());
                            signal.publishPendingSignals();
                            if(selected==Case.PUBLISH_GIVEUP)signal.publishPendingSignals();
                            assertEquals(selected==Case.PUBLISH_GIVEUP?3:2,publications.get());
                        }
                    }finally{if(inject)proxy.removeAdvice(failure);}
                    signal.refreshCommittedAuthorizations();
                    boolean silent=List.of(Case.ROLLBACK,Case.OWNER_REVOKED,Case.CONFIG_FORGERY,Case.ROSTER_FORGERY,Case.GRANT_FORGERY,
                            Case.WRONG_SESSION,Case.CLOSED_SESSION,Case.TARGET_REPLACED,Case.SOURCE_REPLACED,Case.STALE_SOURCE,
                            Case.REVOKED_BEFORE_PUBLISH,Case.CAPACITY_ROLLBACK,Case.ROSTER_ROLLBACK,Case.REFRESH_ROLLBACK,Case.CLOSE_WRONG_SESSION,Case.OVERSIZED,Case.PUBLISH_GIVEUP,Case.TARGET_TENANT,Case.STALE_CONTEXT).contains(selected);
                    if(silent){assertNull(source.readOutbound());assertNull(target.readOutbound());if(successor[0]!=null)assertNull(successor[0].readOutbound());}
                    else if(selected==Case.REFRESH_COMMIT){
                        assertEquals("CLOSED",jdbc.queryForObject("select status from peer_mesh_session where id=?",String.class,existing.session().id()));
                        assertEquals(PeerControlMessage.TYPE_CLOSE,decode(source.readOutbound()).getType(),"revoke before publishing config/roster");
                        assertEquals(PeerControlMessage.TYPE_CLOSE,decode(target.readOutbound()).getType());
                    } else if(selected==Case.CLOSE_BOUND){
                        assertEquals(PeerControlMessage.TYPE_CLOSE,decode(source.readOutbound()).getType());
                        assertEquals(PeerControlMessage.TYPE_CLOSE,decode(target.readOutbound()).getType());
                    } else {
                        EmbeddedChannel recipient=selected==Case.REVERSE_DIRECTION?source:target;
                        PeerControlMessage forwarded=decode(recipient.readOutbound());assertEquals(PeerControlMessage.TYPE_CANDIDATES,forwarded.getType());
                        assertNotNull(forwarded.getSessionId());
                        assertEquals(1,jdbc.queryForObject("select count(*) from peer_mesh_session where id=?",Integer.class,forwarded.getSessionId()));
                        assertEquals(java.util.HexFormat.of().formatHex(com.theshuai.common.security.HmacSigner.sha256(forwarded.getToken())),
                                jdbc.queryForObject("select token_hash from peer_mesh_session where id=?",String.class,forwarded.getSessionId()));
                        if(selected==Case.TOKEN_REBOUND){assertEquals(existing.token(),forwarded.getToken());assertEquals(existing.session().expiresAt(),forwarded.getExpiresAt());}
                        if(selected==Case.METADATA){assertEquals("current-signal-public-key",forwarded.getSourcePublicKey());assertEquals("current-signal-public-key",forwarded.getTargetPublicKey());}
                        if(selected==Case.REVERSE_DIRECTION){assertNotEquals(existing.session().id(),forwarded.getSessionId());assertEquals("CLOSED",jdbc.queryForObject("select status from peer_mesh_session where id=?",String.class,existing.session().id()));}
                        if(selected!=Case.TOKEN_REBOUND)assertEquals(PeerControlMessage.TYPE_SESSION_GRANT,decode((selected==Case.REVERSE_DIRECTION?target:source).readOutbound()).getType());
                    }
                    assertEquals(selected==Case.CAPACITY_ROLLBACK?1:32,((Semaphore)ReflectionTestUtils.getField(signal,"signalSlots")).availablePermits());
                    assertEquals(16*1024*1024,((Semaphore)ReflectionTestUtils.getField(signal,"signalBytes")).availablePermits());
                    if(selected==Case.ROLLBACK||selected==Case.CAPACITY_ROLLBACK)
                        assertEquals(0,jdbc.queryForObject("select count(*) from peer_mesh_session where source_client_id=? and target_client_id=?",Integer.class,fixture.source().getId(),fixture.target().getId()));
                } finally {for(EmbeddedChannel channel:channels){SessionUtil.unBindSession(channel);channel.finishAndReleaseAll();}}
            });
            assertAll("committed current peer control publication",cases);
        } finally {properties.setEnabled(enabled);}
    }
    private static PeerSignalService service(ConfigurableApplicationContext context,int capacity){
        return new PeerSignalService(context.getBean(ClientAccountService.class),context.getBean(PeerMeshService.class),
                context.getBean(PeerServiceDiscoveryService.class),context.getBean(ClientSessionRepository.class),context.getBean(PeerEgressService.class),context.getBean(com.theshuai.specusserver.management.service.PeerCatalogPublicationService.class),capacity);
    }
    private static Fixture fixture(ConfigurableApplicationContext context,long base){
        var jdbc=context.getBean(JdbcTemplate.class);String now=Instant.now().toString();
        for(long id:List.of(base+1,base+2)){
            jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','signal-owner',?,'fixture-only',true,30,?,?)",id,"peer-signal-"+id,now,now);
            jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,public_key,enabled,created_at,updated_at) values (?,'default','signal-owner',?,?,?,'100.115.0.0/16','old-signal-public-key',true,?,?)",id,id,"peer-signal-"+id,"100.115."+(base/100_000)+"."+(base%1000+id-base),now,now);
        }
        var accounts=context.getBean(ClientAccountRepository.class);return new Fixture(accounts.findById(base+1).orElseThrow(),accounts.findById(base+2).orElseThrow());
    }
    private static EmbeddedChannel bind(ClientAccount account,List<EmbeddedChannel> channels){
        var channel=new EmbeddedChannel();channel.attr(ServerAttributes.TENANT_ID).set(account.getTenantId());
        SessionUtil.bindSession(new Session(account.getClientName()),channel);channels.add(channel);return channel;
    }
    private static MessageRequestPacket request(String target,PeerControlMessage message){
        var request=new MessageRequestPacket();request.setMessageType(MessageType.PEER_CONTROL);request.setToClientName(target);request.setMessage(JsonUtil.objectToString(message));return request;
    }
    private static PeerControlMessage decode(MessageResponsePacket packet){assertNotNull(packet);return JsonUtil.stringToObject(packet.getMessage(),PeerControlMessage.class);}
}
