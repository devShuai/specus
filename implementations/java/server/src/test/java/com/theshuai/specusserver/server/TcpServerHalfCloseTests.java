package com.theshuai.specusserver.server;

import com.theshuai.specusserver.config.NettyServerProperties;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.ChannelInputShutdownEvent;
import io.netty.channel.socket.DuplexChannel;
import io.netty.channel.socket.SocketChannel;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TcpServerHalfCloseTests {
    @Test
    void acceptedSocketCanReplyAfterPeerShutdownOutput() throws Exception {
        byte[] request = "public-request".getBytes(StandardCharsets.UTF_8);
        byte[] response = "reply-after-eof".getBytes(StandardCharsets.UTF_8);
        EventLoopGroup boss = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        EventLoopGroup worker = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
        TcpServer server = new TcpServer(boss, worker, new NettyServerProperties());
        CountDownLatch inputShutdown = new CountDownLatch(1);
        CountDownLatch channelClosed = new CountDownLatch(1);
        AtomicReference<byte[]> received = new AtomicReference<>();
        try {
            server.bind(0, new ChannelInitializer<>() {
                @Override
                protected void initChannel(SocketChannel channel) {
                    channel.pipeline().addLast(new ChannelInboundHandlerAdapter() {
                        private final ByteArrayOutputStream input = new ByteArrayOutputStream();

                        @Override
                        public void channelRead(ChannelHandlerContext ctx, Object msg) {
                            ByteBuf buffer = (ByteBuf) msg;
                            try {
                                byte[] bytes = new byte[buffer.readableBytes()];
                                buffer.readBytes(bytes);
                                input.writeBytes(bytes);
                            } finally {
                                buffer.release();
                            }
                        }

                        @Override
                        public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
                            if (evt instanceof ChannelInputShutdownEvent) {
                                received.set(input.toByteArray());
                                inputShutdown.countDown();
                                ctx.writeAndFlush(Unpooled.wrappedBuffer(response)).addListener(write -> {
                                    if (write.isSuccess()) {
                                        ((DuplexChannel) ctx.channel()).shutdownOutput().addListener(ignored -> ctx.close());
                                    } else {
                                        ctx.close();
                                    }
                                });
                                return;
                            }
                            super.userEventTriggered(ctx, evt);
                        }

                        @Override
                        public void channelInactive(ChannelHandlerContext ctx) {
                            channelClosed.countDown();
                        }
                    });
                }
            });

            try (Socket socket = new Socket("127.0.0.1", server.localPort())) {
                socket.setSoTimeout(5_000);
                socket.getOutputStream().write(request);
                socket.getOutputStream().flush();
                socket.shutdownOutput();

                assertTrue(inputShutdown.await(5, TimeUnit.SECONDS));
                assertArrayEquals(response, socket.getInputStream().readAllBytes());
            }

            assertArrayEquals(request, received.get());
            assertTrue(channelClosed.await(5, TimeUnit.SECONDS));
        } finally {
            server.close();
            worker.shutdownGracefully(0, 2, TimeUnit.SECONDS).syncUninterruptibly();
            boss.shutdownGracefully(0, 2, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }
}
