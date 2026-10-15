package com.theshuai.specusserver.handler;

import com.theshuai.common.clientauth.*;
import com.theshuai.common.peermesh.PeerControlMessage;
import com.theshuai.common.protocol.*;
import com.theshuai.common.protocol.request.*;
import com.theshuai.common.protocol.response.*;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.config.PeerMeshProperties;
import com.theshuai.specusserver.management.service.ClientAuthService;
import com.theshuai.specusserver.management.service.AuthenticationResult;
import com.theshuai.specusserver.management.service.ConnectionRecordService;
import com.theshuai.specusserver.management.model.DisconnectReason;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import com.theshuai.specusserver.management.service.PeerServiceDiscoveryService;
import com.theshuai.specusserver.management.service.PeerSignalService;
import com.theshuai.specusserver.security.PasswordService;
import com.theshuai.specusserver.server.NettyServer;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.session.ControlLifecycle;
import io.netty.buffer.Unpooled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.aop.framework.ProxyFactory;
import org.aopalliance.intercept.MethodInterceptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.DirtiesContext;
import org.junit.jupiter.api.AfterEach;

import java.net.*;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;

import static org.junit.jupiter.api.Assertions.*;

/** Actual HTTP/HMAC -> native SQLite/JPA authentication -> production Netty TCP pipeline.
 * One JDBC connection makes lifecycle/transaction lock inversion observable. Observation interceptors
 * pause exact boundaries; authentication, authorization, SQL, catalog and socket work stay real. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-native-control-generation?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=1", "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.netty.bind-address=127.0.0.1", "specus.netty.worker-threads=3",
        "specus.database.seed-demo-client=false", "specus.tls.mode=disabled"
})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_CLASS)
@Import(NativeControlGenerationTests.CleanupObservation.class)
class NativeControlGenerationTests {
    static final AtomicLong IDS = new AtomicLong(13_800_000);
    static final AtomicReference<DeferredCleanup> CLEANUP = new AtomicReference<>();
    static final AtomicReference<LookupProbe> LOOKUP = new AtomicReference<>();
    static final AtomicReference<SignalProbe> SIGNAL = new AtomicReference<>();
    static final AtomicReference<OnlineProbe> ONLINE = new AtomicReference<>();
    static final AtomicReference<SourceProbe> SOURCE = new AtomicReference<>();
    static final ThreadLocal<SourceProbe> REPORT_SCOPE = new ThreadLocal<>();
    @LocalServerPort int httpPort;
    @Autowired JdbcTemplate jdbc;
    @Autowired NettyServer server;
    @Autowired ClientAuthProperties authProperties;
    @Autowired PeerMeshProperties peerProperties;
    @Autowired PeerServiceDiscoveryService discovery;
    @Autowired ConnectionRecordService records;
    @AfterEach void removeCleanupObservation() {CLEANUP.set(null);LOOKUP.set(null);SIGNAL.set(null);ONLINE.set(null);SOURCE.set(null);}

    record DeferredCleanup(long sessionId, CompletableFuture<Runnable> delivery, AtomicBoolean captured) {}
    record LookupProbe(String token, CompletableFuture<Void> seen) {}
    record SignalProbe(String clientName, CompletableFuture<Boolean> onSocketLoop) {}
    record OnlineProbe(String token, CompletableFuture<Void> online, CountDownLatch resume, AtomicBoolean captured,
                       CompletableFuture<Channel> channel, AtomicReference<Thread> worker) {
        OnlineProbe(String token,CompletableFuture<Void> online,CountDownLatch resume,AtomicBoolean captured) {
            this(token,online,resume,captured,new CompletableFuture<>(),new AtomicReference<>());
        }
    }
    record SourceProbe(String name,String instance,CompletableFuture<Void> entered,CompletableFuture<Void> finished,
                       CountDownLatch resume,AtomicBoolean captured) {}

    @TestConfiguration(proxyBeanMethods = false)
    static class CleanupObservation {
        @Bean static BeanPostProcessor observeCleanupDelivery() {
            return new BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean, String name) {
                    if ("managedLoginRequestHandler".equals(name) && bean instanceof ManagedLoginRequestHandler) {
                        var proxy=new ProxyFactory(bean);proxy.setProxyTargetClass(true);
                        proxy.addAdvice((MethodInterceptor) invocation -> {
                            var online=ONLINE.get();
                            if (online != null && "channelRead".equals(invocation.getMethod().getName())
                                    && invocation.getArguments()[1] instanceof LoginRequestPacket packet
                                    && online.token().equals(packet.getAccessToken())) {
                                online.channel().complete(((ChannelHandlerContext)invocation.getArguments()[0]).channel());
                            }
                            return invocation.proceed();
                        });
                        return proxy.getProxy();
                    }
                    if ("clientAccountService".equals(name) && bean instanceof com.theshuai.specusserver.management.service.ClientAccountService) {
                        var proxy=new ProxyFactory(bean);proxy.setProxyTargetClass(true);
                        proxy.addAdvice((MethodInterceptor) invocation -> {
                            var source=REPORT_SCOPE.get();
                            if (source != null && "findClientByName".equals(invocation.getMethod().getName())
                                    && source.name().equals(invocation.getArguments()[0]) && source.captured().compareAndSet(false,true)) {
                                source.entered().complete(null);
                                if (!source.resume().await(10,TimeUnit.SECONDS)) throw new AssertionError("in-flight original source was not released");
                            }
                            return invocation.proceed();
                        });
                        return proxy.getProxy();
                    }
                    if ("clientAuthService".equals(name) && bean instanceof ClientAuthService) {
                        var proxy = new ProxyFactory(bean);proxy.setProxyTargetClass(true);
                        proxy.addAdvice((MethodInterceptor) invocation -> {
                            var result = invocation.proceed();var probe = LOOKUP.get();
                            if (probe != null && "controlClientId".equals(invocation.getMethod().getName())
                                    && probe.token().equals(invocation.getArguments()[0])) probe.seen().complete(null);
                            var online = ONLINE.get();
                            if (online != null && "authenticateNetty".equals(invocation.getMethod().getName())
                                    && invocation.getArguments()[0] instanceof LoginRequestPacket packet
                                    && online.token().equals(packet.getAccessToken()) && result instanceof AuthenticationResult admitted
                                    && admitted.success() && online.captured().compareAndSet(false,true)) {
                                online.worker().set(Thread.currentThread());
                                online.online().complete(null);
                                if (!online.resume().await(10,TimeUnit.SECONDS)) throw new AssertionError("native ONLINE gate was not released");
                            }
                            return result;
                        });
                        return proxy.getProxy();
                    }
                    if (!"peerSignalService".equals(name) || !(bean instanceof PeerSignalService target)) return bean;
                    var proxy = new ProxyFactory(bean);proxy.setProxyTargetClass(true);
                    proxy.addAdvice((MethodInterceptor) invocation -> {
                        var source=SOURCE.get();
                        boolean report=source != null && "handle".equals(invocation.getMethod().getName())
                                && invocation.getArguments()[0] instanceof MessageRequestPacket packet
                                && packet.getMessage().contains(source.instance());
                        var previous=REPORT_SCOPE.get();
                        if (report) REPORT_SCOPE.set(source);
                        try {
                        var signal = SIGNAL.get();
                        if (signal != null && "admitOriginalControl".equals(invocation.getMethod().getName())
                                && invocation.getArguments()[0] instanceof com.theshuai.common.session.Session original
                                && signal.clientName().equals(original.getClientName())) {
                            var channel = (io.netty.channel.Channel) invocation.getArguments()[1];
                            signal.onSocketLoop().complete(channel.eventLoop().inEventLoop());
                        }
                        var probe = CLEANUP.get();
                        if ("onClientDisconnected".equals(invocation.getMethod().getName()) && probe != null
                                && invocation.getArguments()[0] instanceof Long sessionId
                                && sessionId == probe.sessionId() && probe.captured().compareAndSet(false, true)) {
                            probe.delivery().complete(() -> target.onClientDisconnected(sessionId));
                            return null;
                        }
                        return invocation.proceed();
                        } finally {
                            if (report) {
                                if (previous == null) REPORT_SCOPE.remove();else REPORT_SCOPE.set(previous);
                                source.finished().complete(null);
                            }
                        }
                    });
                    return proxy.getProxy();
                }
            };
        }
    }

    @ParameterizedTest @CsvSource({"1,4", "4,1"})
    void sameAuthenticatedSessionCanReplaceItsPhysicalControlAtTheLimit(int credentialLimit, int machineLimit) throws Exception {
        try (var fixture = new Fixture(credentialLimit, machineLimit)) {
            var auth = fixture.authenticate();
            var first = fixture.control(auth);assertTrue(first.reply.isSuccess(), first.reply.getReason());
            var original = SessionUtil.getChannel(auth.getClientName());
            var replacement = fixture.control(auth);

            assertTrue(replacement.reply.isSuccess(), "replacement is not an extra instance: " + replacement.reply.getReason());
            assertNotSame(original, SessionUtil.getChannel(auth.getClientName()));
            assertEquals(1, fixture.onlineCount());
            assertEquals(SessionUtil.getChannel(auth.getClientName()).id().asLongText(), fixture.nativeChannel(auth));
        }
    }

    @ParameterizedTest @CsvSource({"1,4", "4,1"})
    void anotherAuthenticatedSessionDoesNotBorrowTheReplacementExemption(int credentialLimit, int machineLimit) throws Exception {
        try (var fixture = new Fixture(credentialLimit, machineLimit)) {
            var auth = fixture.authenticate();assertTrue(fixture.control(auth).reply.isSuccess());
            var original = SessionUtil.getChannel(auth.getClientName());
            var other = fixture.authenticate();assertNotEquals(auth.getClientSessionId(), other.getClientSessionId());
            assertFalse(fixture.control(other).reply.isSuccess());
            assertSame(original, SessionUtil.getChannel(auth.getClientName()));
            assertTrue(original.isActive());assertEquals(1, fixture.onlineCount());
        }
    }

    @ParameterizedTest @CsvSource({"0,4", "4,0"})
    void zeroQuotaCannotBeBypassedAsAReplacement(int credentialLimit, int machineLimit) throws Exception {
        try (var fixture = new Fixture(credentialLimit, machineLimit)) {
            var auth = fixture.authenticate();assertFalse(fixture.control(auth).reply.isSuccess());
            assertEquals(0, fixture.onlineCount());assertNull(SessionUtil.getChannel(auth.getClientName()));
        }
    }

    @Test
    void sameSessionPhysicalReplacementStartsANewRawReportSequence() throws Exception {
        try (var fixture = new Fixture(4, 4)) {
            var auth = fixture.authenticate();var first = fixture.control(auth);assertTrue(first.reply.isSuccess());
            first.report(40, "original-publisher");fixture.catalog(auth, "original-publisher");
            var before = discovery.currentCatalog("default", auth.getClientId(), auth.getClientSessionId()).revision();
            var replacement = fixture.control(auth);assertTrue(replacement.reply.isSuccess());

            replacement.report(1, "successor-publisher");fixture.catalog(auth, "successor-publisher");

            assertTrue(discovery.currentCatalog("default", auth.getClientId(), auth.getClientSessionId()).revision() > before,
                    "the server-owned consumer sequence must not reset with the raw publisher cursor");
        }
    }

    @Test
    void replayedOldDisconnectCleanupCannotWithdrawTheSameSessionSuccessor() throws Exception {
        try (var fixture = new Fixture(4, 4)) {
            var auth = fixture.authenticate();var first = fixture.control(auth);assertTrue(first.reply.isSuccess());
            first.report(2, "before-disconnect");fixture.catalog(auth, "before-disconnect");
            var deferred = new CompletableFuture<Runnable>();var captured = new AtomicBoolean();
            // Delay only cleanup delivery after native OFFLINE, not its transaction or socket close.
            CLEANUP.set(new DeferredCleanup(auth.getClientSessionId(), deferred, captured));
            SessionUtil.getChannel(auth.getClientName()).close().sync();
            Runnable oldCleanup = deferred.get(5, TimeUnit.SECONDS);
            assertEquals(ClientAuthService.STATUS_DISCONNECTED, fixture.status(auth));

            var replacement = fixture.control(auth);assertTrue(replacement.reply.isSuccess());
            // Higher raw revision keeps this regression independent of the separate raw-reset bug.
            replacement.report(3, "fresh-before-replay");fixture.catalog(auth, "fresh-before-replay");
            oldCleanup.run();

            assertEquals(ClientAuthService.STATUS_NETTY_ONLINE, fixture.status(auth));
            assertTrue(SessionUtil.getChannel(auth.getClientName()).isActive());
            var current = discovery.currentCatalog("default", auth.getClientId(), auth.getClientSessionId());
            assertNotNull(current, "an old cleanup delivery must not remove the online successor catalog");
            assertEquals("fresh-before-replay", current.instanceId());
        }
    }

    @Test
    void aControlWaitingForItsLifecycleDoesNotOccupyTheOnlyDatabaseConnection() throws Exception {
        try (var fixture = new Fixture(4, 4)) {
            var auth=fixture.authenticate();assertTrue(fixture.control(auth).reply.isSuccess());
            var resolved=new CompletableFuture<Void>();LOOKUP.set(new LookupProbe(auth.getAccessToken(),resolved));
            try (var workers=Executors.newFixedThreadPool(2);var held=ControlLifecycle.acquire(auth.getClientId(),null)) {
                var pending=workers.submit(() -> fixture.control(auth));
                resolved.get(5,TimeUnit.SECONDS); // The real native token read completed, before gate acquisition.
                assertEquals(1,workers.submit(() -> jdbc.queryForObject("select 1",Integer.class)).get(1,TimeUnit.SECONDS));
                assertFalse(pending.isDone(),"CONTROL must wait behind its prior generation");
                held.close();
                assertTrue(pending.get(5,TimeUnit.SECONDS).reply.isSuccess());
            }
        }
    }

    @Test
    void aReportWaitingForItsLifecycleLeavesHeartbeatAndTheOnlyDatabaseConnectionLive() throws Exception {
        try (var fixture = new Fixture(4, 4)) {
            var auth=fixture.authenticate();var peer=fixture.control(auth);assertTrue(peer.reply.isSuccess());
            var entered=new CompletableFuture<Boolean>();SIGNAL.set(new SignalProbe(auth.getClientName(),entered));
            try (var workers=Executors.newSingleThreadExecutor();var held=ControlLifecycle.acquire(auth.getClientId(),null)) {
                peer.report(1,"report-after-held-lifecycle"); // Its actual TCP heartbeat reply must still arrive.
                assertFalse(entered.get(5,TimeUnit.SECONDS),"lifecycle/DB admission must not run on the socket event loop");
                assertEquals(1,workers.submit(() -> jdbc.queryForObject("select 1",Integer.class)).get(1,TimeUnit.SECONDS));
                assertNull(discovery.currentCatalog("default",auth.getClientId(),auth.getClientSessionId()));
                held.close();
                fixture.catalog(auth,"report-after-held-lifecycle");
            }
        }
    }

    @Test
    void anotherDeviceCannotDiscardAControlBetweenNativeOnlineAndBindingPublication() throws Exception {
        try (var fixture = new Fixture(1,4);var workers=Executors.newSingleThreadExecutor()) {
            var first=fixture.authenticate();var other=fixture.authenticate("-other-device");
            assertNotEquals(first.getClientId(),other.getClientId());
            var gate=new OnlineProbe(first.getAccessToken(),new CompletableFuture<>(),new CountDownLatch(1),new AtomicBoolean());ONLINE.set(gate);
            var pending=workers.submit(() -> fixture.control(first));
            try {
                gate.online().get(5,TimeUnit.SECONDS);
                assertEquals(ClientAuthService.STATUS_NETTY_ONLINE,fixture.status(first));
                assertNull(SessionUtil.getChannel(first.getClientName()),"the first physical binding is deliberately not published yet");

                var rejected=fixture.control(other);

                assertFalse(rejected.reply.isSuccess(),"pending native ONLINE consumes the shared credential quota");
                assertEquals(ClientAuthService.STATUS_NETTY_ONLINE,fixture.status(first),"another device must not retire a pending authenticated CONTROL as stale");
            } finally {gate.resume().countDown();}
            assertTrue(pending.get(5,TimeUnit.SECONDS).reply.isSuccess());
            assertEquals(1,fixture.onlineCount());
        }
    }

    @Test
    void nativeDisconnectAuditPreservesItsFirstReasonAndTimestamp() throws Exception {
        try (var fixture=new Fixture(4,4)) {
            var auth=fixture.authenticate();assertTrue(fixture.control(auth).reply.isSuccess());
            long record=jdbc.queryForObject("select id from specus_connection_record where channel_id=?",Long.class,fixture.nativeChannel(auth));
            records.recordDisconnect(record,DisconnectReason.REPLACED_BY_NEW_LOGIN);
            String closed=jdbc.queryForObject("select disconnected_at from specus_connection_record where id=?",String.class,record);
            assertNotNull(closed);
            records.recordDisconnect(record,DisconnectReason.CLIENT_CLOSED);
            assertEquals(closed,jdbc.queryForObject("select disconnected_at from specus_connection_record where id=?",String.class,record));
            assertEquals("REPLACED_BY_NEW_LOGIN",jdbc.queryForObject("select disconnect_reason from specus_connection_record where id=?",String.class,record));
        }
    }

    @Test
    void closedAfterNativeOnlineBeforePublicationDoesNotLeaveAGhostControlOrAudit() throws Exception {
        try (var fixture=new Fixture(4,4)) {
            var auth=fixture.authenticate();
            var gate=new OnlineProbe(auth.getAccessToken(),new CompletableFuture<>(),new CountDownLatch(1),new AtomicBoolean());ONLINE.set(gate);
            try {
                fixture.requestControl(auth);
                gate.online().get(5,TimeUnit.SECONDS);
                assertEquals(ClientAuthService.STATUS_NETTY_ONLINE,fixture.status(auth));
                assertNull(SessionUtil.getChannel(auth.getClientName()));
                Channel original=gate.channel().get(5,TimeUnit.SECONDS);
                original.close().sync();assertFalse(original.isActive()); // Actual owned TCP, not a synthetic callback.
            } finally {gate.resume().countDown();}
            await(() -> ClientAuthService.STATUS_DISCONNECTED.equals(fixture.status(auth)),"cancelled native ONLINE did not retire");
            assertNull(SessionUtil.getChannel(auth.getClientName()));
            await(() -> jdbc.queryForObject("select count(*) from specus_connection_record where client_id=? and disconnected_at is not null and disconnect_reason='LOGIN_FAILURE'",Integer.class,auth.getClientId()) == 1,
                    "unpublished successful native authentication must retain its closed independent audit");
            assertTrue(fixture.control(auth).reply.isSuccess(),"the same token must remain usable after cancellation cleanup");
        }
    }

    @Test
    void interruptedAdmissionCannotPublishItsQueuedSuccessAfterNativeCleanup() throws Exception {
        try (var fixture=new Fixture(4,4)) {
            var auth=fixture.authenticate();
            var gate=new OnlineProbe(auth.getAccessToken(),new CompletableFuture<>(),new CountDownLatch(1),new AtomicBoolean());ONLINE.set(gate);
            var onLoop=new CountDownLatch(1);var resumeLoop=new CountDownLatch(1);
            var peer=fixture.requestControl(auth);
            try {
                gate.online().get(5,TimeUnit.SECONDS);Channel original=gate.channel().get(5,TimeUnit.SECONDS);
                original.eventLoop().execute(() -> {
                    onLoop.countDown();
                    try {if(!resumeLoop.await(10,TimeUnit.SECONDS)) throw new AssertionError("owned publication loop was not released");}
                    catch(InterruptedException interrupted) {Thread.currentThread().interrupt();throw new AssertionError(interrupted);}
                });
                assertTrue(onLoop.await(5,TimeUnit.SECONDS));gate.resume().countDown();
                Thread worker=gate.worker().get();
                await(() -> Arrays.stream(worker.getStackTrace()).anyMatch(frame -> frame.getClassName().equals(CompletableFuture.class.getName())
                                && frame.getMethodName().equals("get")),"owned authentication worker did not reach its queued-publication future");
                worker.interrupt();
                await(() -> ClientAuthService.STATUS_DISCONNECTED.equals(fixture.status(auth)),"interrupted native ONLINE did not retire");
                resumeLoop.countDown();
                assertEquals(-1,peer.socket.getInputStream().read(),"a retired admission must not emit its delayed LOGIN success");
                assertNull(SessionUtil.getChannel(auth.getClientName()));
            } finally {gate.resume().countDown();resumeLoop.countDown();}
            assertTrue(fixture.control(auth).reply.isSuccess(),"cancellation must release both lifecycle and pending capacity");
        }
    }

    final class Fixture implements AutoCloseable {
        final long credential = IDS.incrementAndGet();
        final String key = "native-control-" + credential, secret = "native-control-test-secret";
        final String machine = "native-machine-" + credential;
        final int originalLimit = authProperties.getPerMachineUserMaxInstances();
        final boolean originalPeerEnabled = peerProperties.isEnabled();
        final List<Map<String,Object>> originalSharing = jdbc.queryForList("select enabled,mdns_import_enabled from peer_mesh_service_sharing where tenant_id='default'");
        final List<Peer> peers = new ArrayList<>();
        final List<ClientAuthLoginResponse> tokens = new ArrayList<>();
        final HttpClient http = HttpClient.newHttpClient();

        Fixture(int credentialLimit, int machineLimit) {
            peerProperties.setEnabled(true);authProperties.setPerMachineUserMaxInstances(machineLimit);
            String now = Instant.now().toString();
            jdbc.update("insert into specus_client_credential(id,tenant_id,owner_username,api_key,secret_hash,enabled,max_online_instances,created_at,updated_at) values (?,'default','native-control-owner',?,?,true,?,?,?)",
                    credential, key, PasswordService.hashToken(secret), credentialLimit, now, now);
            if (originalSharing.isEmpty()) jdbc.update("insert into peer_mesh_service_sharing(tenant_id,enabled,mdns_import_enabled,updated_at,updated_by) values ('default',true,true,?,'native-control-proof')",now);
            else jdbc.update("update peer_mesh_service_sharing set enabled=true where tenant_id='default'");
        }

        ClientAuthLoginResponse authenticate() throws Exception {return authenticate("");}
        ClientAuthLoginResponse authenticate(String suffix) throws Exception {
            var environment = new ClientEnvironmentInfo();environment.setMachineFingerprint(machine+suffix);
            environment.setHostname(machine+suffix);environment.setOsUser("native-user");environment.setPeerPublicKey("native-test-public-key");
            environment.getClientPeerServiceCapabilities().setVersion(2);
            environment.getClientPeerServiceCapabilities().setApplications(List.of("http"));
            var request = new ClientAuthLoginRequest();request.setApiKey(key);
            request.setTimestamp(Long.toString(System.currentTimeMillis()));request.setNonce(UUID.randomUUID().toString());
            request.setEnvironment(environment);
            request.setSignature(ClientAuthSigner.signApiKey(key, request.getTimestamp(), request.getNonce(), environment, secret));
            var response = http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + httpPort + "/api/client/auth/login"))
                    .timeout(Duration.ofSeconds(5)).header("Content-Type","application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(JsonUtil.objectToString(request))).build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, response.statusCode(), "real signed HTTP login must succeed");
            var result = JsonUtil.stringToObject(response.body(), ClientAuthLoginResponse.class);
            assertNotNull(result.getClientSessionId());assertNotNull(result.getAccessToken());tokens.add(result);
            // Explicit administrator-provisioned device fixture. New devices are disabled by
            // default; the real report authorization must not be weakened to accept them.
            assertEquals(1, jdbc.update("update peer_mesh_device set enabled=true where tenant_id='default' and client_id=?",result.getClientId()));
            return result;
        }

        Peer control(ClientAuthLoginResponse auth) throws Exception {
            var peer=requestControl(auth);
            peer.reply = peer.receive(LoginResponsePacket.class);
            if (peer.reply.isSuccess()) assertEquals(auth.getClientName(), peer.reply.getClientName(), "native auth must canonicalize wire identity");
            return peer;
        }

        Peer requestControl(ClientAuthLoginResponse auth) throws Exception {
            await(() -> server.getBoundPort() > 0, "native TCP listener did not start");
            var peer = new Peer(server.getBoundPort());peers.add(peer);
            var login = new LoginRequestPacket();login.setClientName("untrusted-wire-name");
            login.setClientSessionId(-1L);login.setAccessToken(auth.getAccessToken());login.setConnectionRole(ConnectionRole.CONTROL);
            peer.send(login);
            return peer;
        }

        int onlineCount() {return jdbc.queryForObject("select count(*) from specus_client_session where credential_id=? and status='NETTY_ONLINE'",Integer.class,credential);}
        String nativeChannel(ClientAuthLoginResponse auth) {return jdbc.queryForObject("select channel_id from specus_client_session where id=?",String.class,auth.getClientSessionId());}
        String status(ClientAuthLoginResponse auth) {return jdbc.queryForObject("select status from specus_client_session where id=?",String.class,auth.getClientSessionId());}
        void catalog(ClientAuthLoginResponse auth, String instance) {
            await(() -> {var current=discovery.currentCatalog("default",auth.getClientId(),auth.getClientSessionId());return current != null && instance.equals(current.instanceId());},
                    "production report must become current: " + instance);
        }

        @Override public void close() throws Exception {
            try {
                for (var auth : tokens) {var channel=SessionUtil.getChannel(auth.getClientName());if(channel != null) channel.close().awaitUninterruptibly(5,TimeUnit.SECONDS);}
                for (var peer : peers) peer.close();
                await(() -> onlineCount() == 0, "owned native CONTROL rows did not retire");
                await(() -> jdbc.queryForObject("select count(*) from specus_connection_record where disconnected_at is null and client_id in (select client_id from specus_client_identity where credential_id=?)",Integer.class,credential) == 0,
                        "owned connection audits must retire before context shutdown, not be masked by SERVER_SHUTDOWN cleanup");
                for (var auth : tokens) assertNull(SessionUtil.getChannel(auth.getClientName()));
                await(() -> tokens.stream().allMatch(auth -> discovery.currentCatalog("default",auth.getClientId(),auth.getClientSessionId()) == null),
                        "owned publisher catalogs did not retire before context shutdown");
            } finally {
                http.close();authProperties.setPerMachineUserMaxInstances(originalLimit);peerProperties.setEnabled(originalPeerEnabled);
                if (originalSharing.isEmpty()) jdbc.update("delete from peer_mesh_service_sharing where tenant_id='default'");
                else jdbc.update("update peer_mesh_service_sharing set enabled=?,mdns_import_enabled=? where tenant_id='default'",originalSharing.getFirst().get("enabled"),originalSharing.getFirst().get("mdns_import_enabled"));
            }
        }
    }

    static final class Peer implements AutoCloseable {
        final Socket socket = new Socket();LoginResponsePacket reply;
        Peer(int port) throws Exception {socket.setSoTimeout(5000);socket.connect(new InetSocketAddress("127.0.0.1",port),5000);}
        void send(Packet packet) throws Exception {
            var frame=Unpooled.buffer();try {PacketCodec.INSTANCE.encode(frame,packet);var bytes=new byte[frame.readableBytes()];frame.readBytes(bytes);socket.getOutputStream().write(bytes);}finally{frame.release();}
        }
        <T extends Packet> T receive(Class<T> type) throws Exception {
            for (int i=0;i<64;i++) {
                var header=socket.getInputStream().readNBytes(PacketCodec.HEADER_SIZE);assertEquals(PacketCodec.HEADER_SIZE,header.length,"framed packet expected before EOF");
                int length=ByteBuffer.wrap(header).getInt(7);assertTrue(length >= 0 && length <= 1024*1024);
                var body=socket.getInputStream().readNBytes(length);assertEquals(length,body.length);
                var frame=Unpooled.wrappedBuffer(header,body);Packet packet;try{packet=PacketCodec.INSTANCE.decode(frame);}finally{frame.release();}
                if(type.isInstance(packet)) return type.cast(packet);
            }
            throw new AssertionError("expected packet not received within bounded push budget");
        }
        void report(long revision,String instance) throws Exception {
            var report=new PeerControlMessage();report.setType(PeerControlMessage.TYPE_SERVICE_REPORT);report.setEnabled(true);
            report.setRevision(revision);report.setInstanceId(instance);report.setServices(List.of());
            var packet=new MessageRequestPacket();packet.setMessageType(MessageType.PEER_CONTROL);packet.setMessage(JsonUtil.objectToString(report));send(packet);
            send(new HeartBeatRequestPacket());receive(HeartBeatResponsePacket.class);
        }
        @Override public void close() throws Exception {socket.close();}
    }

    static void await(BooleanSupplier condition,String message) {
        long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(5);
        while(!condition.getAsBoolean()) {if(System.nanoTime() >= deadline) fail(message);try{Thread.sleep(10);}catch(InterruptedException interrupted){Thread.currentThread().interrupt();throw new AssertionError(interrupted);}}
    }
}
