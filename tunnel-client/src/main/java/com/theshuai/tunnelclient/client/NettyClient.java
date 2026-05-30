package com.theshuai.tunnelclient.client;

import com.theshuai.common.codec.PacketDecoder;
import com.theshuai.common.codec.PacketEncoder;
import com.theshuai.common.codec.Spliter;
import com.theshuai.common.handler.CustomHttpRequestHandler;
import com.theshuai.common.handler.LoginRequestHandler;
import com.theshuai.common.protocol.request.LoginRequestPacket;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.handler.*;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.*;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.springframework.util.DigestUtils;

import java.util.Date;
import java.util.concurrent.TimeUnit;

public class NettyClient {
    public static String CLIENT_NAME = null;
    public static String PASSWORD = null;
    public static String HOST = null;
    public static int PORT = -1;
    private TunnelBean TunnelBean;
    private static final Bootstrap bootstrap = new Bootstrap();

    public NettyClient(TunnelBean TunnelBean) {
        this.TunnelBean = TunnelBean;
        NettyClient.CLIENT_NAME = TunnelBean.getClientName();
        NettyClient.PASSWORD = TunnelBean.getPassword();
        NettyClient.HOST = TunnelBean.getRemoteAddress();
        NettyClient.PORT = TunnelBean.getRemotePort();
    }

    public void start() throws InterruptedException {
        EventLoopGroup workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
        bootstrap.group(workerGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    public void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new ClientSocketIdleStateHandler(NettyClient.this));
                        ch.pipeline().addLast(new Spliter());
                        ch.pipeline().addLast(new PacketDecoder());
                        ch.pipeline().addLast(new LoginResponseHandler());
                        ch.pipeline().addLast(new MessageResponseHandler());
                        ch.pipeline().addLast(new CustomHttpRequestHandler());
                        ch.pipeline().addLast(new LogoutResponseHandler());
                        ch.pipeline().addLast(new PacketEncoder());
                        ch.pipeline().addLast(new HeartBeatTimerHandler(NettyClient.this));
                    }
                });
        connect();
    }

    public void connect() throws InterruptedException {
        ChannelFuture connect = bootstrap.connect(HOST, PORT);

        connect.addListener((ChannelFutureListener) listener -> {
            if (listener.isSuccess()) {
                Channel channel = listener.channel();
                LoginRequestPacket loginRequestPacket = new LoginRequestPacket();
                loginRequestPacket.setClientName(CLIENT_NAME);
                loginRequestPacket.setPassword(PASSWORD);
                loginRequestPacket.setTimestamp(String.valueOf(System.currentTimeMillis()));
                String signString = LoginRequestHandler.md5Salt + loginRequestPacket.getClientName() +
                        loginRequestPacket.getPassword() + loginRequestPacket.getTimestamp();
                loginRequestPacket.setCheckSign(DigestUtils.md5DigestAsHex(signString.getBytes()));
                channel.writeAndFlush(loginRequestPacket);
                System.out.println(new Date() + "连接成功...");
            } else {
                (listener).channel().eventLoop().schedule(() -> {
                    System.out.println("Failed to connect to server, try connect ...");
                    try {
                        connect();
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }, 10, TimeUnit.SECONDS);
            }
        });
    }
}
