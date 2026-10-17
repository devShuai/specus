package com.theshuai.specusserver.management.service;

import com.theshuai.common.clientauth.ClientAuthLoginRequest;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.clientauth.ClientAuthSigner;
import com.theshuai.common.clientauth.ClientEnvironmentInfo;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.PeerMeshDeviceRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-client-peer-runtime?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=1", "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.database.seed-demo-client=false",
        "specus.peer-mesh.enabled=true", "specus.peer-mesh.cidr=100.122.0.0/24"
})
class ClientPeerRuntimeCoordinationTests {
    @Autowired JdbcTemplate jdbc;
    @Autowired ClientAuthService auth;
    @Autowired PeerMeshService peers;
    @Autowired ClientAccountRepository clients;
    @Autowired PeerMeshDeviceRepository devices;
    @Autowired PlatformTransactionManager transactions;
    ClientAccount stale;
    static final ManagementContext ALICE = new ManagementContext(TenantContext.defaultTenant(), "alice", false, "runtime-alice-key");
    enum Operation { ENSURE, REPORT, LOGIN_CONFIG, RUNTIME_CONFIG }
    enum Unavailable { DELETED, DISABLED, TENANT_CASE }
    enum ActorChange { DISABLED, DELETED, REPLACED, TENANT, LOGIN }

    @BeforeEach void seed() {
        for (String table : new String[]{"peer_mesh_device", "specus_client_session", "specus_client_identity", "specus_client_account", "specus_client_credential", "specus_management_user"})
            jdbc.update("delete from " + table);
        String now = Instant.now().toString();
        jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values ('runtime-alice-key','default','alice','alice',?,'USER',true,?,?)",
                PasswordService.hashToken("unused-fixture-password"), now, now);
        jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (101,'default','alice','stale-client',?,true,30,?,?)",
                PasswordService.hashToken("client-token"), now, now);
        jdbc.update("insert into peer_mesh_device(id,tenant_id,owner_username,client_id,client_name,virtual_ip,cidr,enabled,public_key,created_at,updated_at) values (1001,'default','alice',101,'stale-client','100.122.0.7','100.122.0.0/24',true,'initial-key',?,?)", now, now);
        stale = clients.findById(101L).orElseThrow();
    }

    @ParameterizedTest @EnumSource(Operation.class)
    void staleRuntimeReferenceUsesTheTransferredCurrentOwnerAndNameWithoutChangingItsAddress(Operation operation) {
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            jdbc.update("update specus_client_account set owner_username='bob',client_name='current-client' where id=101");
            jdbc.update("update peer_mesh_device set owner_username='bob',client_name='current-client' where id=1001");
        });
        exercise(operation, "current-client");
        assertEquals("bob", jdbc.queryForObject("select owner_username from peer_mesh_device where id=1001", String.class));
        assertEquals("current-client", jdbc.queryForObject("select client_name from peer_mesh_device where id=1001", String.class));
        assertEquals("100.122.0.7", jdbc.queryForObject("select virtual_ip from peer_mesh_device where id=1001", String.class));
    }

    static Stream<Arguments> unavailableOperations() {
        return Arrays.stream(Unavailable.values()).flatMap(change -> Arrays.stream(Operation.values()).map(operation -> Arguments.of(change, operation)));
    }

    @ParameterizedTest @MethodSource("unavailableOperations")
    void staleRuntimeReferencesCannotRecreateOrWriteForUnavailableClients(Unavailable change, Operation operation) {
        switch (change) {
            case DELETED -> { jdbc.update("delete from peer_mesh_device where client_id=101"); jdbc.update("delete from specus_client_account where id=101"); }
            case DISABLED -> jdbc.update("update specus_client_account set enabled=false where id=101");
            case TENANT_CASE -> jdbc.update("update specus_client_account set tenant_id='DEFAULT' where id=101");
        }
        assertThrows(IllegalArgumentException.class, () -> exercise(operation, "stale-client"));
        assertEquals(change == Unavailable.DELETED ? 0 : 1, jdbc.queryForObject("select count(*) from peer_mesh_device where client_id=101", Integer.class));
    }

    @Test void cachedDeviceCannotRestoreOldEnabledKeyAddressOrOtherMetadata() {
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            assertTrue(devices.findById(1001L).orElseThrow().isEnabled());
            jdbc.update("update peer_mesh_device set enabled=false,public_key='current-key',virtual_ip='100.122.0.8',nat_type='CURRENT-NAT' where id=1001");
            PeerControlMessage report = new PeerControlMessage(); report.setVirtualDeviceStatus("ready");
            var result = peers.reportDevice(stale, report);
            assertFalse(result.enabled());
            assertEquals("100.122.0.8", result.virtualIp());
        });
        assertFalse(jdbc.queryForObject("select enabled from peer_mesh_device where id=1001", Boolean.class));
        assertEquals("current-key", jdbc.queryForObject("select public_key from peer_mesh_device where id=1001", String.class));
        assertEquals("CURRENT-NAT", jdbc.queryForObject("select nat_type from peer_mesh_device where id=1001", String.class));
        assertEquals("ready", jdbc.queryForObject("select virtual_device_status from peer_mesh_device where id=1001", String.class));
    }

    @ParameterizedTest @EnumSource(ActorChange.class)
    void deviceManagementRechecksTheImmutableCurrentActor(ActorChange change) {
        switch (change) {
            case DISABLED -> jdbc.update("update specus_management_user set enabled=false where username='runtime-alice-key'");
            case DELETED -> jdbc.update("delete from specus_management_user where username='runtime-alice-key'");
            case REPLACED -> jdbc.update("update specus_management_user set username='replacement-runtime-key' where username='runtime-alice-key'");
            case TENANT -> jdbc.update("update specus_management_user set tenant_id='foreign' where username='runtime-alice-key'");
            case LOGIN -> jdbc.update("update specus_management_user set login_name='renamed',login_name_normalized='renamed' where username='runtime-alice-key'");
        }
        assertEquals(403, assertThrows(ResponseStatusException.class, () -> peers.updateDevice(ALICE, 101,
                new PeerMeshService.DeviceMutation(false))).getStatusCode().value());
        assertTrue(jdbc.queryForObject("select enabled from peer_mesh_device where id=1001", Boolean.class));
    }

    @Test void oldAdminClaimCannotEditAnotherOwnersDeviceAfterDemotion() {
        jdbc.update("update specus_client_account set owner_username='bob' where id=101");
        jdbc.update("update peer_mesh_device set owner_username='bob' where id=1001");
        var oldAdmin = new ManagementContext(ALICE.tenant(), "alice", true, ALICE.accountKey());
        assertThrows(IllegalArgumentException.class, () -> peers.updateDevice(oldAdmin, 101, new PeerMeshService.DeviceMutation(false)));
        assertTrue(jdbc.queryForObject("select enabled from peer_mesh_device where id=1001", Boolean.class));
    }

    @Test void ownershipOnlyChangeRetainsTheOldTokenForControlAndDataWithCurrentOwner() {
        var login = httpLogin();
        long sessionId = jdbc.queryForObject("select id from specus_client_session where token_hash=?", Long.class, PasswordService.hashToken(login.getAccessToken()));
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            jdbc.update("update specus_client_credential set owner_username='bob' where id=930001");
            jdbc.update("update specus_client_account set owner_username='bob' where id=?", login.getClientId());
            jdbc.update("update peer_mesh_device set owner_username='bob' where client_id=?", login.getClientId());
        });
        LoginRequestPacket control = new LoginRequestPacket(); control.setAccessToken(login.getAccessToken());
        var accepted = auth.authenticateNetty(control, "control-channel", "loopback", false);
        assertTrue(accepted.success()); assertEquals("bob", accepted.account().getOwnerUsername());
        EmbeddedChannel channel = new EmbeddedChannel();
        channel.attr(ServerAttributes.CLIENT_SESSION_ID).set(sessionId);
        SessionUtil.bindControlSession(new Session(control.getClientName()), channel);
        try {
            LoginRequestPacket data = new LoginRequestPacket(); data.setAccessToken(login.getAccessToken());
            var acceptedData = auth.authenticateNetty(data, "data-channel", "loopback", true);
            assertTrue(acceptedData.success()); assertEquals("bob", acceptedData.account().getOwnerUsername());
            assertTrue(SessionUtil.hasMatchingControl(data.getClientName(), acceptedData.clientSessionId()));
        } finally { SessionUtil.unBindSession(channel); channel.finishAndReleaseAll(); }
    }

    @Test void delayedOldChannelCloseDoesNotDisconnectANewerBindingOfTheSameToken() {
        var login = httpLogin();
        LoginRequestPacket packet = new LoginRequestPacket(); packet.setAccessToken(login.getAccessToken());
        var accepted = auth.authenticateNetty(packet, "old-channel", "loopback", false);
        assertTrue(accepted.success());
        jdbc.update("update specus_client_session set channel_id='new-channel',client_egress_version=7 where id=?", accepted.clientSessionId());
        assertFalse(auth.markNettyDisconnected(accepted.clientSessionId(), "old-channel"));
        assertEquals("NETTY_ONLINE", jdbc.queryForObject("select status from specus_client_session where id=?", String.class, accepted.clientSessionId()));
        assertTrue(auth.markNettyDisconnected(accepted.clientSessionId(), "new-channel"));
        String closedAt = jdbc.queryForObject("select disconnected_at from specus_client_session where id=?", String.class, accepted.clientSessionId());
        assertFalse(auth.markNettyDisconnected(accepted.clientSessionId(), "new-channel"));
        assertEquals(closedAt, jdbc.queryForObject("select disconnected_at from specus_client_session where id=?", String.class, accepted.clientSessionId()));
        assertEquals(7, jdbc.queryForObject("select client_egress_version from specus_client_session where id=?", Integer.class, accepted.clientSessionId()));
    }

    private void exercise(Operation operation, String expectedName) {
        switch (operation) {
            case ENSURE -> assertEquals(expectedName, peers.ensureDevice(stale, new ClientEnvironmentInfo()).getClientName());
            case REPORT -> assertEquals(expectedName, peers.reportDevice(stale, new PeerControlMessage()).clientName());
            case LOGIN_CONFIG -> assertEquals(expectedName, peers.buildLoginConfig(stale, new ClientEnvironmentInfo(), "localhost").getClientName());
            case RUNTIME_CONFIG -> assertEquals(expectedName, peers.buildRuntimeConfig(stale).getClientName());
        }
    }

    private ClientAuthLoginResponse httpLogin() {
        String now = Instant.now().toString(), key = "runtime-access-key", secret = "Runtime-access-secret";
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (930001,'default','alice',?,?,true,5,?,?)", key, PasswordService.hashToken(secret), now, now);
        ClientEnvironmentInfo environment = new ClientEnvironmentInfo(); environment.setMachineFingerprint("runtime-access-host");
        environment.setHostname("runtime-access-host"); environment.setOsUser("runtime-user");
        ClientAuthLoginRequest request = new ClientAuthLoginRequest(); request.setApiKey(key);
        request.setTimestamp(Long.toString(System.currentTimeMillis())); request.setNonce(UUID.randomUUID().toString()); request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(key, request.getTimestamp(), request.getNonce(), environment, secret));
        return auth.login(request, "localhost");
    }
}
