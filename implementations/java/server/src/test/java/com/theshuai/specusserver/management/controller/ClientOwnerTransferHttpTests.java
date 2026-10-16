package com.theshuai.specusserver.management.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.clientauth.*;
import com.theshuai.common.protocol.*;
import com.theshuai.common.protocol.request.*;
import com.theshuai.common.protocol.response.*;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.server.NettyServer;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.common.peermesh.PeerControlMessage;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Bean;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.aop.framework.Advised;
import org.aopalliance.intercept.MethodInterceptor;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicBoolean;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URI;
import java.net.Socket;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

import static org.assertj.core.api.Assertions.assertThat;

/** Real HTTP/JWT/security filter/controller/native SQLite. SQL creates fixtures, never transfers. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-owner-http?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=1", "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.netty.bind-address=127.0.0.1", "specus.database.seed-demo-client=false",
        "specus.auth.username=owner-http-admin", "specus.auth.password=owner-http-admin-fixture-password",
        "specus.auth.tenant-id=default", "specus.owner-transfer.notifications.poll=false",
        "specus.peer-mesh.enabled=true", "specus.peer-mesh.stun-turn-port=0",
        "specus.client-auth.per-machine-user-max-instances=4"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(ClientOwnerTransferHttpTests.RemoteCloseObservation.class)
class ClientOwnerTransferHttpTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final String STAMP = "2026-10-16T00:00:00Z";
    @LocalServerPort int port;
    @Autowired JdbcTemplate jdbc;
    @Autowired NettyServer netty;
    @Autowired PeerMeshService mesh;
    private static final AtomicReference<Runnable> BEFORE_OWNERSHIP_REFRESH = new AtomicReference<>();
    @TestConfiguration(proxyBeanMethods=false)
    static class RemoteCloseObservation {
        @Bean static BeanPostProcessor observeOwnershipRefresh() {
            return new BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean,String name) {
                    if (name.equals("peerSignalService") && bean instanceof Advised advised)
                        advised.addAdvice((MethodInterceptor) invocation -> {
                            if(invocation.getMethod().getName().equals("reconcileOwnership")) {
                                Runnable before=BEFORE_OWNERSHIP_REFRESH.getAndSet(null);
                                if(before!=null)before.run();
                            }
                            return invocation.proceed();
                        });
                    return bean;
                }
            };
        }
    }
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private String admin;

    @BeforeEach void fixture() throws Exception {
        for (String table : List.of("client_owner_transfer_receipt", "client_owner_transfer_audit", "peer_mesh_session", "peer_mesh_acl", "peer_mesh_device", "specus_client_identity",
                "specus_client_credential", "specus_client_account", "specus_management_user")) jdbc.update("delete from " + table);
        admin = login("owner-http-admin", "owner-http-admin-fixture-password");
        for (String name : List.of("alice", "Bob")) {
            var created = send("POST", "/api/admin/users", admin, JSON.writeValueAsString(Map.of(
                    "username", name, "password", "owner-http-member-password", "role", "USER", "enabled", true)));
            assertThat(created.statusCode()).as(created.body()).isIn(200, 201);
        }
        jdbc.update("insert into specus_client_account(id,tenant_id,client_name,owner_username,enabled,password_hash,connection_rate_limit_per_minute,created_at,updated_at) values (1001,'default','http-offline','alice',false,'retained-hash',17,?,?),(1002,'default','http-shared','alice',true,'retained-hash',17,?,?)", STAMP, STAMP, STAMP, STAMP);
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (501,'default','alice','http-shared-key','retained-secret-hash',false,4,?,?),(502,'default','alice','http-empty-key','retained-secret-hash',false,4,?,?)", STAMP, STAMP, STAMP, STAMP);
        jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (701,'default',501,1001,'http-offline','fixture-A','user',?,?),(702,'default',501,1002,'http-shared','fixture-B','user',?,?)", STAMP, STAMP, STAMP, STAMP);
        jdbc.update("insert into peer_mesh_device(id,tenant_id,client_id,client_name,owner_username,enabled,virtual_ip,cidr,created_at,updated_at) values (801,'default',1001,'http-offline','alice',false,'100.96.0.1','100.96.0.0/16',?,?)", STAMP, STAMP);
    }

    @Test void publicGroupPostUsesRealPreviewAndAtomicCanonicalOwner() throws Exception {
        String alice = login("alice", "owner-http-member-password"), bob = login("Bob", "owner-http-member-password");
        assertThat(send("GET", "/api/admin/clients/1001", alice, null).statusCode()).isEqualTo(200);
        assertThat(send("GET", "/api/admin/clients/1001", bob, null).statusCode()).isIn(400, 404);
        String path = "/api/admin/client-credentials/501/owner-transfer";
        var preview = send("GET", path, admin, null);
        assertThat(preview.statusCode()).as(preview.body()).isEqualTo(200);
        var request = JSON.writeValueAsString(Map.of("scope", "credential-group", "targetUsername", " bOB ",
                "expectedRevision", JSON.readTree(preview.body()).path("revision").asText()));
        var result = send("POST", path, admin, request);
        assertThat(result.statusCode()).as(result.body()).isEqualTo(200);
        JsonNode body = JSON.readTree(result.body());
        assertThat(body.path("targetUsername").asText()).isEqualTo("Bob");
        assertThat(body.path("affectedClientIds").toString()).isEqualTo("[1001,1002]");
        assertThat(body.path("accessRetained").asBoolean()).isTrue();
        assertThat(result.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(jdbc.queryForList("select owner_username from specus_client_account order by id", String.class)).containsExactly("Bob", "Bob");
        assertThat(jdbc.queryForObject("select enabled from specus_client_account where id=1001", Boolean.class)).isFalse();
        assertThat(jdbc.queryForObject("select enabled from specus_client_credential where id=501", Boolean.class)).isFalse();
        assertThat(jdbc.queryForObject("select owner_username from peer_mesh_device where id=801", String.class)).isEqualTo("Bob");
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_receipt", Integer.class)).isEqualTo(1);
        assertThat(send("GET", "/api/admin/clients/1001", alice, null).statusCode()).isIn(400, 404);
        assertThat(send("GET", "/api/admin/clients/1001", bob, null).statusCode()).isEqualTo(200);
        var stale = send("POST", path, admin, request);
        assertThat(stale.statusCode()).isEqualTo(409);
        assertThat(JSON.readTree(stale.body()).path("code").asText()).isEqualTo("TRANSFER_PREVIEW_CHANGED");
        String fresh = JSON.readTree(send("GET", path, admin, null).body()).path("revision").asText();
        var noop = send("POST", path, admin, JSON.writeValueAsString(Map.of("scope", "credential-group", "targetUsername", "Bob", "expectedRevision", fresh)));
        assertThat(noop.statusCode()).as(noop.body()).isEqualTo(200);
        assertThat(JSON.readTree(noop.body()).path("changed").asBoolean()).isFalse();
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isEqualTo(1);
    }

    @Test void sharedSingleNeedsExplicitGroupAndNonadminWinsOverMalformedJson() throws Exception {
        for (String path : List.of("/api/admin/clients/1001/owner-transfer", "/api/admin/client-credentials/501/owner-transfer")) {
            var forbidden = send("POST", path, login("alice", "owner-http-member-password"), "{malformed");
            assertThat(forbidden.statusCode()).as(forbidden.body()).isEqualTo(403);
            assertThat(send("POST", path, null, "{malformed").statusCode()).isIn(401, 403);
        }
        var conflict = send("POST", "/api/admin/clients/1001/owner-transfer", admin, "{\"scope\":\"single\"}");
        assertThat(conflict.statusCode()).as(conflict.body()).isEqualTo(409);
        assertThat(JSON.readTree(conflict.body()).path("code").asText()).isEqualTo("CREDENTIAL_SHARED");
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select owner_username from specus_client_account where id=1001", String.class)).isEqualTo("alice");
    }

    @Test void zeroDeviceCredentialAndAccountDeletionAreSeparateExplicitOperations() throws Exception {
        String path = "/api/admin/client-credentials/502/owner-transfer";
        var before = send("DELETE", "/api/admin/users/alice", admin, null);
        assertThat(before.statusCode()).as(before.body()).isEqualTo(409);
        assertThat(JSON.readTree(before.body()).path("credentials").asInt()).isEqualTo(2);
        var preview = JSON.readTree(send("GET", path, admin, null).body());
        assertThat(preview.path("affectedClientCount").asInt()).isZero();
        var moved = send("POST", path, admin, JSON.writeValueAsString(Map.of("scope", "credential-group", "targetUsername", "Bob", "expectedRevision", preview.path("revision").asText())));
        assertThat(moved.statusCode()).as(moved.body()).isEqualTo(200);
        assertThat(JSON.readTree(moved.body()).path("affectedClientIds").toString()).isEqualTo("[]");
        assertThat(jdbc.queryForObject("select enabled from specus_client_credential where id=502", Boolean.class)).isFalse();
        assertThat(send("DELETE", "/api/admin/users/alice", admin, null).statusCode()).isEqualTo(409);
        String group = "/api/admin/client-credentials/501/owner-transfer";
        String revision = JSON.readTree(send("GET", group, admin, null).body()).path("revision").asText();
        assertThat(send("POST", group, admin, JSON.writeValueAsString(Map.of("scope", "credential-group", "targetUsername", "Bob", "expectedRevision", revision))).statusCode()).isEqualTo(200);
        assertThat(send("DELETE", "/api/admin/users/alice", admin, null).statusCode()).isIn(200, 204);
    }

    @Test void currentPolicyClosesOnlyLostDefaultPeerSessionsAndPreservesExplicitAcl() throws Exception {
        // No credential for 1001: only that device moves, unlike the shared fixture above.
        jdbc.update("delete from specus_client_identity");
        jdbc.update("update specus_client_account set enabled=true");
        jdbc.update("update peer_mesh_device set enabled=true");
        jdbc.update("insert into specus_client_account(id,tenant_id,client_name,owner_username,enabled,password_hash,connection_rate_limit_per_minute,created_at,updated_at) values (1003,'default','explicit-peer','alice',true,'hash',30,?,?)", STAMP, STAMP);
        for (long id : List.of(1002L, 1003L)) jdbc.update("insert into peer_mesh_device(id,tenant_id,client_id,client_name,owner_username,enabled,virtual_ip,cidr,created_at,updated_at) values (?,'default',?,?,'alice',true,?,'100.96.0.0/16',?,?)", id, id, "peer-"+id, "100.96.0."+(id-1000), STAMP, STAMP);
        jdbc.update("insert into peer_mesh_acl(id,tenant_id,owner_username,source_client_id,source_client_name,target_client_id,target_client_name,allowed,direction,created_at,updated_at) values (900,'default','alice',1001,'http-offline',1003,'explicit-peer',true,'BOTH',?,?)", STAMP, STAMP);
        for (long id : List.of(1002L, 1003L)) jdbc.update("insert into peer_mesh_session(id,tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,path_type,status,started_at,updated_at,expires_at,direct_bytes,relay_bytes) values (?,'default',1001,'http-offline',?,?,'DIRECT','ACTIVE',?,?,'2099-01-01T00:00:00.000000000Z',7,9)", id+1000, id, "peer-"+id, STAMP, STAMP);
        transfer("clients/1001", "single", "Bob");
        assertThat(jdbc.queryForObject("select status from peer_mesh_session where id=2002", String.class)).isEqualTo("CLOSED");
        assertThat(jdbc.queryForObject("select status from peer_mesh_session where id=2003", String.class)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("select owner_username from peer_mesh_acl where id=900", String.class)).isEqualTo("alice");
        assertThat(jdbc.queryForObject("select direct_bytes+relay_bytes from peer_mesh_session where id=2002", Long.class)).isEqualTo(16L);
    }

    @Test void actualHttpTransferPreservesOriginalControlDataTokenAndSignedSecretLogin() throws Exception {
        String key="http-native-key", secret="http-native-fixture-secret";
        jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (503,'default','alice',?,?,true,4,?,?)", key, PasswordService.hashToken(secret), STAMP, STAMP);
        var environment=new ClientEnvironmentInfo();environment.setMachineFingerprint("http-native-machine");environment.setHostname("http-native-machine");environment.setOsUser("fixture-user");environment.setPeerPublicKey("retained-fixture-public-key");
        ClientAuthLoginResponse authenticated=clientLogin(key, secret, environment);
        long id=authenticated.getClientId();String name=authenticated.getClientName();
        await(() -> netty.getBoundPort()>0);
        try (Peer control=new Peer(netty.getBoundPort())) {
            assertThat(control.login(authenticated, ConnectionRole.CONTROL).isSuccess()).isTrue();
            transfer("clients/"+id, "single", "Bob");
            control.heartbeat();
            assertThat(SessionUtil.getChannel(name)).isNotNull();
            try (Peer data=new Peer(netty.getBoundPort())) {
                assertThat(data.login(authenticated, ConnectionRole.DATA).isSuccess()).isTrue();
                data.heartbeat();
            }
            control.heartbeat();
            ClientAuthLoginResponse again=clientLogin(key, secret, environment);
            assertThat(again.getClientId()).isEqualTo(id);assertThat(again.getClientName()).isEqualTo(name);
            assertThat(jdbc.queryForObject("select owner_username from specus_client_account where id=?", String.class, id)).isEqualTo("Bob");
            assertThat(jdbc.queryForObject("select owner_username from peer_mesh_device where client_id=?", String.class, id)).isEqualTo("Bob");
            assertThat(jdbc.queryForObject("select public_key from peer_mesh_device where client_id=?", String.class, id)).isEqualTo(environment.getPeerPublicKey());
        }
        await(() -> SessionUtil.getChannel(name)==null);
    }

    @Test void largeGroupIsNotTruncatedByHttpPreviewOrWrite() throws Exception {
        for (int i=0;i<1050;i++) {
            long id=3000+i;
            jdbc.update("insert into specus_client_account(id,tenant_id,client_name,owner_username,enabled,password_hash,connection_rate_limit_per_minute,created_at,updated_at) values (?,'default',?,'alice',false,'hash',30,?,?)", id, "http-large-"+i, STAMP, STAMP);
            jdbc.update("insert into specus_client_identity(id,tenant_id,credential_id,client_id,client_name,machine_fingerprint,os_user,first_seen_at,last_seen_at) values (?,'default',502,?,?,?,'user',?,?)", id, id, "http-large-"+i, "large-machine-"+i, STAMP, STAMP);
        }
        JsonNode result=transfer("client-credentials/502", "credential-group", "Bob");
        assertThat(result.path("affectedClientIds").size()).isEqualTo(1050);
        assertThat(result.path("affectedClientIds").get(1049).asLong()).isEqualTo(4049);
        assertThat(jdbc.queryForObject("select count(*) from specus_client_account where id>=3000 and owner_username='Bob' and enabled=false", Integer.class)).isEqualTo(1050);
    }

    @Test void invalidBodiesAndForeignPathHaveStableErrorsAndNoWrites() throws Exception {
        String path="/api/admin/client-credentials/501/owner-transfer";
        for (String body : List.of("[]", "{}{}", "{broken", " ".repeat(65_537))) {
            var response=send("POST", path, admin, body);
            assertThat(response.statusCode()).as(response.body()).isEqualTo(400);
            assertThat(JSON.readTree(response.body()).path("code").asText()).isEqualTo("INVALID_TRANSFER_REQUEST");
        }
        jdbc.update("update specus_client_credential set tenant_id='foreign' where id=502");
        var foreign=send("POST", "/api/admin/client-credentials/502/owner-transfer", admin, "{\"scope\":\"single\"}");
        assertThat(foreign.statusCode()).as(foreign.body()).isEqualTo(404);
        assertThat(JSON.readTree(foreign.body()).path("code").asText()).isEqualTo("RESOURCE_NOT_FOUND");
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select owner_username from specus_client_credential where id=502", String.class)).isEqualTo("alice");
    }

    @Test void changedPreviewPrecedesUnavailableTargetAndNeverPartiallyWrites() throws Exception {
        String path="/api/admin/client-credentials/501/owner-transfer";
        String revision=JSON.readTree(send("GET", path, admin, null).body()).path("revision").asText();
        var target=send("PUT", "/api/admin/users/Bob", admin, "{\"enabled\":false}");
        assertThat(target.statusCode()).as(target.body()).isEqualTo(200);
        String request=JSON.writeValueAsString(Map.of("scope", "credential-group", "targetUsername", "Bob", "expectedRevision", revision));
        var unavailable=send("POST", path, admin, request);
        assertThat(unavailable.statusCode()).as(unavailable.body()).isEqualTo(400);
        assertThat(JSON.readTree(unavailable.body()).path("code").asText()).isEqualTo("INVALID_TARGET_OWNER");
        jdbc.update("update specus_client_account set client_name='changed-after-preview' where id=1001");
        var stale=send("POST", path, admin, request);
        assertThat(stale.statusCode()).as(stale.body()).isEqualTo(409);
        assertThat(JSON.readTree(stale.body()).path("code").asText()).isEqualTo("TRANSFER_PREVIEW_CHANGED");
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("select owner_username from specus_client_account where id=1001", String.class)).isEqualTo("alice");
    }

    @Test void finalAuditFailureRollsBackOwnersAndCreatesNoNotificationReceipt() throws Exception {
        String path="/api/admin/client-credentials/501/owner-transfer";
        String revision=JSON.readTree(send("GET", path, admin, null).body()).path("revision").asText();
        String request=JSON.writeValueAsString(Map.of("scope", "credential-group", "targetUsername", "Bob", "expectedRevision", revision));
        jdbc.execute("create trigger fail_http_owner_audit before insert on client_owner_transfer_audit begin select raise(abort,'http-audit-fault'); end");
        try {
            var failed=send("POST", path, admin, request);
            assertThat(failed.statusCode()).as("internal persistence failure must not be reported as invalid user input: "+failed.body()).isEqualTo(500);
            assertThat(jdbc.queryForList("select owner_username from specus_client_account", String.class)).containsOnly("alice");
            assertThat(jdbc.queryForObject("select owner_username from specus_client_credential where id=501", String.class)).isEqualTo("alice");
            assertThat(jdbc.queryForObject("select owner_username from peer_mesh_device where id=801", String.class)).isEqualTo("alice");
            assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_receipt", Integer.class)).isZero();
            assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isZero();
        } finally { jdbc.execute("drop trigger fail_http_owner_audit"); }
        assertThat(send("POST", path, admin, request).statusCode()).isEqualTo(200);
    }

    @Test void closeCommittedBeforeLocalRefreshStillReachesTheOriginalControl() throws Exception {
        String secret="remote-close-fixture-secret";
        List<ClientAuthLoginResponse> clients=new ArrayList<>();
        for(int i=0;i<2;i++) {
            String key="remote-close-key-"+i;
            jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','alice',?,?,true,4,?,?)",503+i,key,PasswordService.hashToken(secret),STAMP,STAMP);
            var environment=new ClientEnvironmentInfo();environment.setMachineFingerprint("remote-close-machine-"+i);environment.setHostname("remote-close-machine-"+i);environment.setOsUser("fixture-user");
            clients.add(clientLogin(key,secret,environment));
        }
        var a=clients.get(0);var b=clients.get(1);await(()->netty.getBoundPort()>0);
        try(Peer source=new Peer(netty.getBoundPort());Peer target=new Peer(netty.getBoundPort())) {
            assertThat(source.login(a,ConnectionRole.CONTROL).isSuccess()).isTrue();
            assertThat(target.login(b,ConnectionRole.CONTROL).isSuccess()).isTrue();
            jdbc.update("update peer_mesh_device set enabled=true where client_id in (?,?)",a.getClientId(),b.getClientId());
            jdbc.update("insert into peer_mesh_session(id,tenant_id,source_client_id,source_client_name,target_client_id,target_client_name,path_type,status,started_at,updated_at,expires_at,direct_bytes,relay_bytes) values (900001,'default',?,?,?,?,'DIRECT','ACTIVE',?,?,'2099-01-01T00:00:00.000000000Z',0,0)",a.getClientId(),a.getClientName(),b.getClientId(),b.getClientName(),STAMP,STAMP);
            var observed=new AtomicBoolean();
            BEFORE_OWNERSHIP_REFRESH.set(()->{
                // Deterministic cross-instance ordering: the native database closure has already
                // committed, but that worker did not own this process's physical CONTROL sockets.
                var closed=mesh.closeUnauthorizedSessions(new ManagementContext(TenantContext.defaultTenant(),"system:remote-closure",true));
                assertThat(closed).extracting(row->row.id()).contains(900001L);observed.set(true);
            });
            transfer("clients/"+a.getClientId(),"single","Bob");
            assertThat(observed).isTrue();
            assertThat(jdbc.queryForObject("select status from peer_mesh_session where id=900001",String.class)).isEqualTo("CLOSED");
            source.heartbeat();target.heartbeat();
            assertThat(source.controls).as("local owner of original CONTROL must replay an already committed close")
                    .anyMatch(message->PeerControlMessage.TYPE_CLOSE.equals(message.getType())&&Long.valueOf(900001).equals(message.getSessionId()));
            assertThat(target.controls).anyMatch(message->PeerControlMessage.TYPE_CLOSE.equals(message.getType())&&Long.valueOf(900001).equals(message.getSessionId()));
        } finally {BEFORE_OWNERSHIP_REFRESH.set(null);}
        await(()->SessionUtil.getChannel(a.getClientName())==null&&SessionUtil.getChannel(b.getClientName())==null);
    }

    private JsonNode transfer(String resource, String scope, String target) throws Exception {
        String path="/api/admin/"+resource+"/owner-transfer";
        var preview=send("GET", path, admin, null);assertThat(preview.statusCode()).as(preview.body()).isEqualTo(200);
        var response=send("POST", path, admin, JSON.writeValueAsString(Map.of("scope", scope, "targetUsername", target, "expectedRevision", JSON.readTree(preview.body()).path("revision").asText())));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    private ClientAuthLoginResponse clientLogin(String key, String secret, ClientEnvironmentInfo environment) throws Exception {
        var request=new ClientAuthLoginRequest();request.setApiKey(key);request.setTimestamp(Long.toString(System.currentTimeMillis()));request.setNonce(UUID.randomUUID().toString());request.setEnvironment(environment);
        request.setSignature(ClientAuthSigner.signApiKey(key,request.getTimestamp(),request.getNonce(),environment,secret));
        var response=send("POST", "/api/client/auth/login", null, JsonUtil.objectToString(request));
        assertThat(response.statusCode()).as(response.body()).isEqualTo(200);
        return JsonUtil.stringToObject(response.body(), ClientAuthLoginResponse.class);
    }

    private static final class Peer implements AutoCloseable {
        private final Socket socket=new Socket();
        private final List<PeerControlMessage> controls=new ArrayList<>();
        Peer(int port) throws Exception {socket.setSoTimeout(5000);socket.connect(new InetSocketAddress("127.0.0.1",port),5000);}
        LoginResponsePacket login(ClientAuthLoginResponse auth, String role) throws Exception {
            var request=new LoginRequestPacket();request.setClientName(auth.getClientName());request.setClientSessionId(auth.getClientSessionId());request.setAccessToken(auth.getAccessToken());request.setConnectionRole(role);send(request);return receive(LoginResponsePacket.class);
        }
        void heartbeat() throws Exception {send(new HeartBeatRequestPacket());receive(HeartBeatResponsePacket.class);}
        void send(Packet packet) throws Exception {var frame=Unpooled.buffer();try{PacketCodec.INSTANCE.encode(frame,packet);byte[] bytes=new byte[frame.readableBytes()];frame.readBytes(bytes);socket.getOutputStream().write(bytes);}finally{frame.release();}}
        <T extends Packet> T receive(Class<T> type) throws Exception {
            for(int i=0;i<64;i++) {
                byte[] header=socket.getInputStream().readNBytes(PacketCodec.HEADER_SIZE);assertThat(header.length).isEqualTo(PacketCodec.HEADER_SIZE);
                int length=ByteBuffer.wrap(header).getInt(7);assertThat(length).isBetween(0,1024*1024);
                byte[] body=socket.getInputStream().readNBytes(length);assertThat(body.length).isEqualTo(length);
                var frame=Unpooled.wrappedBuffer(header,body);Packet packet;try{packet=PacketCodec.INSTANCE.decode(frame);}finally{frame.release();}
                if(packet instanceof MessageResponsePacket message&&MessageType.PEER_CONTROL.equals(message.getMessageType()))
                    controls.add(JsonUtil.stringToObject(message.getMessage(),PeerControlMessage.class));
                if(type.isInstance(packet))return type.cast(packet);
            }
            throw new AssertionError("expected packet missing within bounded frame budget");
        }
        public void close() throws Exception {socket.close();}
    }
    private static void await(BooleanSupplier condition) throws Exception {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!condition.getAsBoolean()){assertThat(System.nanoTime()).as("owned native transport must converge").isLessThan(deadline);Thread.sleep(10);}
    }

    private String login(String username, String password) throws Exception {
        var result = send("POST", "/auth/login", null, JSON.writeValueAsString(Map.of("username", username, "password", password)));
        assertThat(result.statusCode()).as(result.body()).isEqualTo(200);
        String token = JSON.readTree(result.body()).path("accessToken").asText();
        assertThat(token).isNotBlank();
        return token;
    }
    private HttpResponse<String> send(String method, String path, String token, String body) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).timeout(Duration.ofSeconds(20));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        if (body != null) builder.header("Content-Type", "application/json");
        return http.send(builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }
}
