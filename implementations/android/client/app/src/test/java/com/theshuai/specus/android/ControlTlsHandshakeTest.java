package com.theshuai.specus.android;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.json.JSONObject;
import org.junit.Test;

import java.io.File;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertTrue;

public class ControlTlsHandshakeTest {
    @Test
    public void customCaAndServerNameCompleteARealTlsHandshake() throws Exception {
        File certificate = resourceFile("/tls/localhost-cert.pem");
        File privateKey = resourceFile("/tls/localhost-key.pem");
        SslContext serverTls = SslContextBuilder.forServer(certificate, privateKey).build();
        NioEventLoopGroup acceptors = new NioEventLoopGroup(1);
        NioEventLoopGroup workers = new NioEventLoopGroup(1);
        CountDownLatch byteReceived = new CountDownLatch(1);
        Channel server = null;
        try {
            server = new ServerBootstrap()
                    .group(acceptors, workers)
                    .channel(NioServerSocketChannel.class)
                    .childHandler(new ChannelInitializer<SocketChannel>() {
                        @Override
                        protected void initChannel(SocketChannel channel) {
                            channel.pipeline().addLast(serverTls.newHandler(channel.alloc()));
                            channel.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                                @Override
                                protected void channelRead0(ChannelHandlerContext context, ByteBuf input) {
                                    if (input.isReadable() && input.readUnsignedByte() == 0x2a) {
                                        byteReceived.countDown();
                                    }
                                }
                            });
                        }
                    })
                    .bind("127.0.0.1", 0).sync().channel();
            int port = ((InetSocketAddress) server.localAddress()).getPort();

            Socket raw = new Socket();
            raw.connect(new InetSocketAddress("127.0.0.1", port), 2_000);
            SpecusCore.ControlTlsConfig config = SpecusCore.ControlTlsConfig.parse(new JSONObject()
                    .put("enabled", true)
                    .put("caCertificatePath", certificate.getAbsolutePath())
                    .put("serverName", "localhost"));
            try (Socket tls = SpecusCore.ControlTlsSockets.wrapConnected(
                    raw, "127.0.0.1", port, true, config, 5_000)) {
                tls.getOutputStream().write(0x2a);
                tls.getOutputStream().flush();
                assertTrue(byteReceived.await(5, TimeUnit.SECONDS));
                String protocol = ((javax.net.ssl.SSLSocket) tls).getSession().getProtocol();
                assertTrue(protocol.equals("TLSv1.2") || protocol.equals("TLSv1.3"));
            }
        } finally {
            if (server != null) server.close().syncUninterruptibly();
            acceptors.shutdownGracefully().syncUninterruptibly();
            workers.shutdownGracefully().syncUninterruptibly();
        }
    }

    private static File resourceFile(String name) throws Exception {
        return new File(ControlTlsHandshakeTest.class.getResource(name).toURI());
    }
}
