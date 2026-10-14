package com.theshuai.specusserver.database;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.repository.ClientSessionRepository;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.management.model.SortableInstant;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.function.Executable;
import org.springframework.aop.framework.Advised;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.sql.DataSource;
import java.time.Instant;
import java.util.ArrayList;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import static org.junit.jupiter.api.Assertions.*;

/** Real HMAC HTTP login followed by real Netty service authentication. The independent connection
 * commits after the actual token query; related rows are also primed in JPA to cover an older L1
 * entity as well as MySQL's earlier transaction snapshot. No transfer endpoint is implied. */
final class ClientRuntimeCoordinationAssertions {
    enum Change { OWNER, NAME, CLIENT_DISABLED, CLIENT_DELETED, CREDENTIAL_DISABLED, CREDENTIAL_DELETED,
        TOKEN, EXPIRY, SESSION_CREDENTIAL, SESSION_CLIENT, SESSION_TENANT, SESSION_DELETED, DATA_STATUS,
        SESSION_IDENTITY, CREDENTIAL_TENANT_CASE, CLIENT_TENANT_CASE, SESSION_TENANT_CASE, RATE_RECORD, QUOTA_ONLINE }

    static void verify(ConfigurableApplicationContext context, DataSource independent) {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        var service = context.getBean(ClientAuthService.class);
        var sessions = context.getBean(ClientSessionRepository.class);
        var accounts = context.getBean(ClientAccountRepository.class);
        var credentials = context.getBean(ClientCredentialRepository.class);
        Advised proxy = assertInstanceOf(Advised.class, sessions);
        ArrayList<Executable> cases = new ArrayList<>();
        for (Change change : Change.values()) cases.add(() -> {
            long credentialId = 960001L + change.ordinal();
            String apiKey = "netty-key-" + credentialId, secret = "Netty-fixture-secret", now = Instant.now().toString();
            jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','alice',?,?,true,5,?,?)",
                    credentialId, apiKey, PasswordService.hashToken(secret), now, now);
            if (change == Change.QUOTA_ONLINE) jdbc.update("update specus_client_credential set max_online_instances=1 where id=?", credentialId);
            ClientEnvironmentInfo environment = new ClientEnvironmentInfo();
            environment.setMachineFingerprint("netty-case-" + change); environment.setHostname("netty-case-" + change); environment.setOsUser("runtime-user");
            ClientAuthLoginRequest request = new ClientAuthLoginRequest();
            request.setApiKey(apiKey); request.setTimestamp(Long.toString(System.currentTimeMillis()));
            request.setNonce(UUID.randomUUID().toString()); request.setEnvironment(environment);
            request.setSignature(ClientAuthSigner.signApiKey(apiKey, request.getTimestamp(), request.getNonce(), environment, secret));
            var login = service.login(request, "localhost");
            long clientId = login.getClientId();
            String tokenHash = PasswordService.hashToken(login.getAccessToken());
            long sessionId = jdbc.queryForObject("select id from specus_client_session where token_hash=?", Long.class, tokenHash);
            long identityId = jdbc.queryForObject("select identity_id from specus_client_session where id=?", Long.class, sessionId);
            final EmbeddedChannel quotaChannel;
            final Long otherSessionId;
            if (change == Change.QUOTA_ONLINE) {
                ClientEnvironmentInfo otherEnvironment = new ClientEnvironmentInfo();
                otherEnvironment.setMachineFingerprint("quota-other-host"); otherEnvironment.setHostname("quota-other-host"); otherEnvironment.setOsUser("quota-other-user");
                ClientAuthLoginRequest otherRequest = new ClientAuthLoginRequest(); otherRequest.setApiKey(apiKey);
                otherRequest.setTimestamp(Long.toString(System.currentTimeMillis())); otherRequest.setNonce(UUID.randomUUID().toString()); otherRequest.setEnvironment(otherEnvironment);
                otherRequest.setSignature(ClientAuthSigner.signApiKey(apiKey, otherRequest.getTimestamp(), otherRequest.getNonce(), otherEnvironment, secret));
                var otherLogin = service.login(otherRequest, "localhost");
                otherSessionId = jdbc.queryForObject("select id from specus_client_session where token_hash=?", Long.class, PasswordService.hashToken(otherLogin.getAccessToken()));
                quotaChannel = new EmbeddedChannel(); quotaChannel.attr(ServerAttributes.CLIENT_SESSION_ID).set(otherSessionId);
                SessionUtil.bindControlSession(new Session(otherLogin.getClientName()), quotaChannel);
            } else { quotaChannel = null; otherSessionId = null; }
            if (change == Change.DATA_STATUS) jdbc.update("update specus_client_session set status='NETTY_ONLINE' where id=?", sessionId);
            if (change == Change.RATE_RECORD) jdbc.update("update specus_client_account set connection_rate_limit_per_minute=1 where id=?", clientId);
            String currentName = "current-netty-" + change.ordinal(), changedToken = PasswordService.hashToken("rotated-netty-token");
            String expired = Instant.now().minusSeconds(60).toString();
            AtomicBoolean observed = new AtomicBoolean();
            MethodInterceptor afterTokenRead = invocation -> {
                Object result = invocation.proceed();
                if (invocation.getMethod().getName().equals("findByTokenHash") && tokenHash.equals(invocation.getArguments()[0])
                        && observed.compareAndSet(false, true)) {
                    // Actual JPA reads, not returned mocks. These entries must not be trusted later.
                    assertTrue(credentials.findById(credentialId).isPresent());
                    assertTrue(accounts.findById(clientId).isPresent());
                    switch (change) {
                        case OWNER -> {
                            assertEquals(1, writer.update("update specus_client_credential set owner_username='bob' where id=?", credentialId));
                            assertEquals(1, writer.update("update specus_client_account set owner_username='bob' where id=?", clientId));
                        }
                        case NAME -> {
                            assertEquals(1, writer.update("update specus_client_account set client_name=? where id=?", currentName, clientId));
                            assertEquals(1, writer.update("update specus_client_session set client_name=? where id=?", currentName, sessionId));
                        }
                        case CLIENT_DISABLED -> assertEquals(1, writer.update("update specus_client_account set enabled=false where id=?", clientId));
                        case CLIENT_DELETED -> assertEquals(1, writer.update("delete from specus_client_account where id=?", clientId));
                        case CREDENTIAL_DISABLED -> assertEquals(1, writer.update("update specus_client_credential set enabled=false where id=?", credentialId));
                        case CREDENTIAL_DELETED -> assertEquals(1, writer.update("delete from specus_client_credential where id=?", credentialId));
                        case TOKEN -> assertEquals(1, writer.update("update specus_client_session set token_hash=? where id=?", changedToken, sessionId));
                        case EXPIRY -> assertEquals(1, writer.update("update specus_client_session set expires_at=? where id=?", expired, sessionId));
                        case SESSION_CREDENTIAL -> assertEquals(1, writer.update("update specus_client_session set credential_id=? where id=?", credentialId + 100000, sessionId));
                        case SESSION_CLIENT -> assertEquals(1, writer.update("update specus_client_session set client_id=? where id=?", clientId + 100000, sessionId));
                        case SESSION_TENANT -> assertEquals(1, writer.update("update specus_client_session set tenant_id='foreign' where id=?", sessionId));
                        case SESSION_DELETED -> assertEquals(1, writer.update("delete from specus_client_session where id=?", sessionId));
                        case DATA_STATUS -> assertEquals(1, writer.update("update specus_client_session set status='DISCONNECTED' where id=?", sessionId));
                        case SESSION_IDENTITY -> assertEquals(1, writer.update("update specus_client_session set identity_id=? where id=?", identityId + 100000, sessionId));
                        case CREDENTIAL_TENANT_CASE -> assertEquals(1, writer.update("update specus_client_credential set tenant_id='DEFAULT' where id=?", credentialId));
                        case CLIENT_TENANT_CASE -> assertEquals(1, writer.update("update specus_client_account set tenant_id='DEFAULT' where id=?", clientId));
                        case SESSION_TENANT_CASE -> assertEquals(1, writer.update("update specus_client_session set tenant_id='DEFAULT' where id=?", sessionId));
                        case RATE_RECORD -> { /* Insert only AFTER the current client lock below. */ }
                        case QUOTA_ONLINE -> { /* Change only AFTER the current client lock below. */ }
                    }
                }
                return result;
            };
            proxy.addAdvice(0, afterTokenRead);
            AtomicBoolean rateObserved = new AtomicBoolean();
            Advised clientProxy = assertInstanceOf(Advised.class, accounts);
            MethodInterceptor afterClientLock = invocation -> {
                Object result = invocation.proceed();
                if ((change == Change.RATE_RECORD || change == Change.QUOTA_ONLINE) && invocation.getMethod().getName().equals("lockCurrent")
                        && Long.valueOf(clientId).equals(invocation.getArguments()[0]) && rateObserved.compareAndSet(false, true)) {
                    if (change == Change.RATE_RECORD) assertEquals(1, writer.update("insert into specus_connection_record(tenant_id,client_id,client_name,connected_at,success) values ('default',?,?,?,true)",
                            clientId, login.getClientName(), SortableInstant.format(Instant.now())));
                    else assertEquals(1, writer.update("update specus_client_session set status='NETTY_ONLINE',channel_id=? where id=?",
                            quotaChannel.id().asLongText(), otherSessionId));
                }
                return result;
            };
            clientProxy.addAdvice(0, afterClientLock);
            try {
                LoginRequestPacket packet = new LoginRequestPacket(); packet.setAccessToken(login.getAccessToken());
                var authenticated = assertDoesNotThrow(() -> service.authenticateNetty(packet, "netty-current-channel", "loopback", change == Change.DATA_STATUS));
                assertTrue(observed.get(), "must observe the real token query, not an unused stub");
                if (change == Change.RATE_RECORD || change == Change.QUOTA_ONLINE) assertTrue(rateObserved.get(), "must change actual counter rows after the client snapshot/lock");
                if (change == Change.TOKEN) assertEquals(changedToken, writer.queryForObject("select token_hash from specus_client_session where id=?", String.class, sessionId));
                if (change == Change.EXPIRY) assertEquals(expired, writer.queryForObject("select expires_at from specus_client_session where id=?", String.class, sessionId));
                if (change == Change.SESSION_CREDENTIAL) assertEquals(credentialId + 100000, writer.queryForObject("select credential_id from specus_client_session where id=?", Long.class, sessionId));
                if (change == Change.SESSION_CLIENT) assertEquals(clientId + 100000, writer.queryForObject("select client_id from specus_client_session where id=?", Long.class, sessionId));
                if (change == Change.SESSION_TENANT) assertEquals("foreign", writer.queryForObject("select tenant_id from specus_client_session where id=?", String.class, sessionId));
                if (change == Change.SESSION_IDENTITY) assertEquals(identityId + 100000, writer.queryForObject("select identity_id from specus_client_session where id=?", Long.class, sessionId));
                if (change == Change.SESSION_TENANT_CASE) assertEquals("DEFAULT", writer.queryForObject("select tenant_id from specus_client_session where id=?", String.class, sessionId));
                if (change == Change.OWNER || change == Change.NAME) {
                    assertTrue(authenticated.success(), "ownership alone must retain the old valid access token");
                    assertEquals(change == Change.OWNER ? "bob" : "alice", authenticated.account().getOwnerUsername());
                    if (change == Change.NAME) {
                        assertEquals(currentName, packet.getClientName());
                        assertEquals(currentName, writer.queryForObject("select client_name from specus_client_session where id=?", String.class, sessionId));
                    }
                } else assertFalse(authenticated.success(), "changed/revoked current client/credential/session must be denied: " + change);
            } finally {
                proxy.removeAdvice(afterTokenRead); clientProxy.removeAdvice(afterClientLock);
                if (quotaChannel != null) { SessionUtil.unBindSession(quotaChannel); quotaChannel.finishAndReleaseAll(); }
            }
        });
        assertAll("current Netty credential-client-session proof", cases);
        verifyDeviceCurrentRows(context, independent);
    }

    private static void verifyDeviceCurrentRows(ConfigurableApplicationContext context, DataSource independent) {
        JdbcTemplate jdbc = context.getBean(JdbcTemplate.class), writer = new JdbcTemplate(independent);
        var peers = context.getBean(PeerMeshService.class);
        var accounts = context.getBean(ClientAccountRepository.class);
        var devices = context.getBean(PeerMeshDeviceRepository.class);
        var properties = context.getBean(PeerMeshProperties.class);
        boolean enabled = properties.isEnabled(); properties.setEnabled(true);
        ArrayList<Executable> cases = new ArrayList<>();
        try {
            for (int operation = 0; operation < 4; operation++) {
                int selected = operation;
                cases.add(() -> {
                    long client = 970001L + selected, device = 980001L + selected;
                    String now = Instant.now().toString(), currentName = "current-peer-device-" + selected;
                    String oldIp = "100.96.0." + (21 + selected), currentIp = "100.96.0." + (31 + selected);
                    jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default','alice',?,?,true,30,?,?)",
                            client, "old-peer-device-" + selected, PasswordService.hashToken("peer-token"), now, now);
                    jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,public_key,created_at,updated_at) values (?,'default','alice',?,?,?,'100.96.0.0/24',true,'old-public-key',?,?)",
                            device, client, "old-peer-device-" + selected, oldIp, now, now);
                    new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(status -> {
                        var stale = accounts.findById(client).orElseThrow();
                        assertTrue(devices.findById(device).orElseThrow().isEnabled());
                        assertEquals(1, writer.update("update specus_client_account set owner_username='bob',client_name=? where id=?", currentName, client));
                        assertEquals(1, writer.update("update peer_mesh_device set owner_username='bob',client_name=?,enabled=false,public_key='current-public-key',virtual_ip=?,nat_type='CURRENT-NAT' where id=?", currentName, currentIp, device));
                        switch (selected) {
                            case 0 -> assertFalse(peers.ensureDevice(stale, new ClientEnvironmentInfo()).isEnabled());
                            case 1 -> assertFalse(peers.reportDevice(stale, new PeerControlMessage()).enabled());
                            case 2 -> { var config = peers.buildLoginConfig(stale, new ClientEnvironmentInfo(), "localhost"); assertFalse(config.isEnabled()); assertEquals(currentName, config.getClientName()); }
                            default -> { var config = peers.buildRuntimeConfig(stale); assertFalse(config.isEnabled()); assertEquals(currentName, config.getClientName()); }
                        }
                    });
                    assertEquals("bob", writer.queryForObject("select owner_username from peer_mesh_device where id=?", String.class, device));
                    assertEquals("current-public-key", writer.queryForObject("select public_key from peer_mesh_device where id=?", String.class, device));
                    assertEquals(currentIp, writer.queryForObject("select virtual_ip from peer_mesh_device where id=?", String.class, device));
                    assertEquals("CURRENT-NAT", writer.queryForObject("select nat_type from peer_mesh_device where id=?", String.class, device));
                    assertFalse(writer.queryForObject("select enabled from peer_mesh_device where id=?", Boolean.class, device));
                });
            }
            assertAll("current device metadata despite older caller/L1/RR state", cases);
        } finally { properties.setEnabled(enabled); }
    }
}
