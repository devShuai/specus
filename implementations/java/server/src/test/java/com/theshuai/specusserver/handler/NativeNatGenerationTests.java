package com.theshuai.specusserver.handler;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.protocol.*;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.common.protocol.response.LoginResponsePacket;
import com.theshuai.specusserver.config.NettyServerProperties;
import com.theshuai.specusserver.http.HttpStreamExchange;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.server.RemotePortServerManager;
import com.theshuai.specusserver.server.TcpServer;
import com.theshuai.specusserver.session.ControlLifecycle;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.*;
import org.aopalliance.intercept.MethodInterceptor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;

import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import static org.junit.jupiter.api.Assertions.*;

/** Reuses real signed HTTP/native SQL/Netty admission, not authentication or socket mocks.
 * Inherited CONTROL cases deliberately run again beside the new NAT lifecycle cases. */
@Import({NativeControlGenerationTests.CleanupObservation.class,NativeNatGenerationTests.BindingObservation.class})
class NativeNatGenerationTests extends NativeControlGenerationTests {
    @Autowired RemotePortServerManager remotePorts;
    @Autowired NettyServerProperties netty;
    @Autowired HttpRouteMappingRepository routes;
    static final AtomicReference<BindProbe> BIND=new AtomicReference<>();
    record BindProbe(int port,CompletableFuture<Void> bound,CountDownLatch resume,AtomicBoolean captured) {}
    @AfterEach void clearBindProbe() {var gate=BIND.getAndSet(null);if(gate != null) gate.resume.countDown();}

    @TestConfiguration(proxyBeanMethods=false)
    static class BindingObservation {
        @Bean static BeanPostProcessor pauseOnlyAfterRealListenerBind() {
            return new BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean,String name) {
                    if(!"remotePortServerManager".equals(name) || !(bean instanceof RemotePortServerManager)) return bean;
                    var proxy=new ProxyFactory(bean);proxy.setProxyTargetClass(true);
                    proxy.addAdvice((MethodInterceptor) invocation -> {
                        Object result=invocation.proceed();var gate=BIND.get();
                        if(gate != null && "bind".equals(invocation.getMethod().getName())
                                && Integer.valueOf(gate.port).equals(invocation.getArguments()[0]) && gate.captured.compareAndSet(false,true)) {
                            gate.bound.complete(null);
                            if(!gate.resume.await(10,TimeUnit.SECONDS)) {
                                ((TcpServer)result).close();throw new AssertionError("owned bind gate was not released");
                            }
                        }
                        return result;
                    });return proxy.getProxy();
                }
            };
        }
    }

    @Test void realHttpWorksWhileControlLifecycleIsHeldButRetiredDataCannotReopenIt() throws Exception {
        try(var fixture=new Fixture(4,4);var http=HttpClient.newHttpClient()) {
            var auth=fixture.authenticate();assertTrue(fixture.control(auth).reply.isSuccess());
            var peer=data(fixture,auth);assertTrue(peer.reply.isSuccess());
            HttpRouteMapping route=new HttpRouteMapping();route.setId(IDS.incrementAndGet());
            route.setTenantId("default");route.setClientId(auth.getClientId());route.setClientName(auth.getClientName());
            route.setRoute("web");route.setTargetBaseUrl("http://127.0.0.1:1");
            route.setCreatedAt(Instant.now().toString());route.setUpdatedAt(Instant.now().toString());routes.saveAndFlush(route);
            var request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+httpPort+"/http/"+auth.getClientName()+"/web/"))
                    .timeout(Duration.ofSeconds(5)).GET().build();
            try(var held=ControlLifecycle.acquire(auth.getClientId(),null)) {
                var response=http.sendAsync(request,HttpResponse.BodyHandlers.ofString());
                var open=nat(peer,NatMessageType.OPEN);
                assertEquals("http",open.getMetaData().get("source"));
                var head=new NatMessagePacket();head.setStreamId(open.getStreamId());head.setNatMessageType(NatMessageType.OPEN);
                head.setMetaData(Map.of("source","http","phase","response","statusCode",200,"headers",List.of("Content-Type:text/plain")));
                peer.send(head);
                var payload=new NatMessagePacket();payload.setStreamId(open.getStreamId());payload.setNatMessageType(NatMessageType.DATA);
                payload.setData("original-data".getBytes(StandardCharsets.UTF_8));payload.setFlags(NatMessagePacket.FLAG_END_STREAM);peer.send(payload);
                var received=response.get(2,TimeUnit.SECONDS);assertEquals(200,received.statusCode());assertEquals("original-data",received.body());
            }
            Channel original=SessionUtil.getDataChannel(auth.getClientName());NatServerHandler handler=original.pipeline().get(NatServerHandler.class);
            handler.retire().get(2,TimeUnit.SECONDS);
            assertTrue(original.isActive(),"retirement is independent of eventual physical close");
            assertFalse(handler.openHttpStream(new HttpStreamExchange(SpecusStreamIds.next()),Map.of()));
            assertEquals(502,http.send(request,HttpResponse.BodyHandlers.ofString()).statusCode());
        }
    }

    @Test void replacementReusesRealPublicPortAndDoesNotLetOldCloseReleaseSuccessorQuota() throws Exception {
        int oldGlobal=netty.getMaxExternalConnections(),oldClient=netty.getMaxExternalConnectionsPerClient(),oldPort=netty.getMaxExternalConnectionsPerPort();
        var resume=new CompletableFuture<Runnable>();
        var delayed=new AtomicReference<Channel>();
        try(var fixture=new Fixture(4,4)) {
            netty.setMaxExternalConnections(1);netty.setMaxExternalConnectionsPerClient(1);netty.setMaxExternalConnectionsPerPort(1);
            var auth=fixture.authenticate();assertTrue(fixture.control(auth).reply.isSuccess());
            var first=data(fixture,auth);assertTrue(first.reply.isSuccess());int port=freePort();register(first,auth,port);
            try(var publicOld=new Socket("127.0.0.1",port)) {
                var oldOpen=nat(first,NatMessageType.OPEN);
                Channel oldData=SessionUtil.getDataChannel(auth.getClientName());
                Channel oldExternal=external(oldData.pipeline().get(NatServerHandler.class),oldOpen.getStreamId());
                delayed.set(oldExternal);
                oldExternal.eventLoop().submit(() -> oldExternal.pipeline().addFirst(new ChannelOutboundHandlerAdapter() {
                    boolean released;
                    final List<ChannelPromise> promises=new ArrayList<>();
                    @Override public void close(ChannelHandlerContext ctx,ChannelPromise promise) {
                        if(released) {ctx.close(promise);return;}
                        promises.add(promise);
                        resume.complete(() -> {
                            if(released) return;
                            released=true;
                            promises.forEach(ctx::close);promises.clear();
                        });
                    }
                })).get(2,TimeUnit.SECONDS);
                assertEquals(1,remotePorts.activeExternalConnections());
                var replacement=data(fixture,auth);assertTrue(replacement.reply.isSuccess());
                assertEquals(0,remotePorts.activeExternalConnections(),"old admission must retire before LOGIN success");
                assertTrue(oldExternal.isActive(),"the actual old close callback remains deliberately delayed");
                register(replacement,auth,port); // Actual same-port bind, not an in-memory listener count.
                try(var publicNew=new Socket("127.0.0.1",port)) {
                    var freshOpen=nat(replacement,NatMessageType.OPEN);assertEquals(1,remotePorts.activeExternalConnections());
                    oldExternal.eventLoop().submit(resume.get(2,TimeUnit.SECONDS)).get(2,TimeUnit.SECONDS);
                    assertTrue(oldExternal.closeFuture().await(2,TimeUnit.SECONDS));
                    assertEquals(1,remotePorts.activeExternalConnections(),"old finally must not decrement fresh global/tenant budgets");
                    assertEquals(1,remotePorts.activeExternalConnections("default"));
                    // TCP half-close deliberately keeps its admission until the other direction
                    // ends. Send the real protocol RST, not a synthetic quota decrement.
                    var reset=new NatMessagePacket();reset.setNatMessageType(NatMessageType.RST);reset.setStreamId(freshOpen.getStreamId());replacement.send(reset);
                }
                await(() -> remotePorts.activeExternalConnections() == 0,"fresh public connection quota did not return");
            }
        } finally {
            if(delayed.get() != null) delayed.get().eventLoop().submit(() -> {
                if(resume.isDone()) resume.join().run();
                else delayed.get().pipeline().removeFirst();
                delayed.get().close();
            }).get(2,TimeUnit.SECONDS);
            netty.setMaxExternalConnections(oldGlobal);netty.setMaxExternalConnectionsPerClient(oldClient);netty.setMaxExternalConnectionsPerPort(oldPort);
        }
        assertEquals(0,remotePorts.activeExternalConnections());
    }

    @Test void twoSuccessorsCannotPublishPastAnOldRegisterStillReturningItsRealListener() throws Exception {
        var gate=new BindProbe(freePort(),new CompletableFuture<>(),new CountDownLatch(1),new AtomicBoolean());BIND.set(gate);
        try(var fixture=new Fixture(4,4);var workers=Executors.newFixedThreadPool(2)) {
            var auth=fixture.authenticate();assertTrue(fixture.control(auth).reply.isSuccess());var original=data(fixture,auth);assertTrue(original.reply.isSuccess());
            original.send(registerPacket(auth,gate.port));gate.bound.get(5,TimeUnit.SECONDS);
            try {
                var first=workers.submit(() -> data(fixture,auth));
                await(() -> SessionUtil.getDataChannel(auth.getClientName()) == null,"first successor did not detach the old namespace");
                var second=workers.submit(() -> data(fixture,auth));
                assertThrows(TimeoutException.class,() -> first.get(200,TimeUnit.MILLISECONDS));
                assertThrows(TimeoutException.class,() -> second.get(200,TimeUnit.MILLISECONDS));
                gate.resume.countDown();
                Peer a=first.get(5,TimeUnit.SECONDS),b=second.get(5,TimeUnit.SECONDS);
                assertNotEquals(a.reply.isSuccess(),b.reply.isSuccess(),"only the current physical reservation may publish");
                register(a.reply.isSuccess() ? a : b,auth,gate.port);
            } finally {gate.resume.countDown();}
        }
    }

    private Peer data(Fixture fixture,ClientAuthLoginResponse auth) throws Exception {
        Peer peer=new Peer(server.getBoundPort());synchronized(fixture.peers) {fixture.peers.add(peer);}
        var login=new LoginRequestPacket();login.setClientName("untrusted-data-name");login.setAccessToken(auth.getAccessToken());
        login.setClientSessionId(-1L);login.setConnectionRole(ConnectionRole.DATA);peer.send(login);peer.reply=peer.receive(LoginResponsePacket.class);return peer;
    }
    private static NatMessagePacket registerPacket(ClientAuthLoginResponse auth,int port) {
        var packet=new NatMessagePacket();packet.setNatMessageType(NatMessageType.REGISTER);
        packet.setMetaData(Map.of("port",port,"specusPort",8080,"specusAddress","127.0.0.1","clientName",auth.getClientName()));return packet;
    }
    private static void register(Peer peer,ClientAuthLoginResponse auth,int port) throws Exception {
        peer.send(registerPacket(auth,port));var result=nat(peer,NatMessageType.REGISTER_RESULT);
        assertEquals(Boolean.TRUE,result.getMetaData().get("success"),String.valueOf(result.getMetaData()));
    }
    private static NatMessagePacket nat(Peer peer,NatMessageType type) throws Exception {
        for(int i=0;i<64;i++) {var packet=peer.receive(NatMessagePacket.class);if(packet.getNatMessageType() == type) return packet;}
        throw new AssertionError("expected NAT type not received");
    }
    private static int freePort() throws Exception {try(var reservation=new ServerSocket(0,1,InetAddress.getLoopbackAddress())) {return reservation.getLocalPort();}}
    @SuppressWarnings("unchecked") private static Channel external(NatServerHandler handler,int streamId) throws Exception {
        var field=NatServerHandler.class.getDeclaredField("externalChannels");field.setAccessible(true);
        Channel channel=((Map<Integer,Channel>)field.get(handler)).get(streamId);assertNotNull(channel);return channel;
    }
}
