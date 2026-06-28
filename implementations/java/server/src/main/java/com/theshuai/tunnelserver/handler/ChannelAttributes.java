package com.theshuai.tunnelserver.handler;

import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.util.AttributeKey;

import java.net.InetSocketAddress;
import java.net.SocketAddress;

/**
 * 数据面 hot path 复用的 Channel 级元数据缓存。
 *
 * <p>Netty 的 {@code channel.id().asLongText()} 每次都会构建一个新的 40 字符 String；
 * 同样，{@code channel.remoteAddress()} 转字符串要走 {@code InetAddress.getHostAddress()}
 * （IPv4 还好，IPv6 + ScopeID 会有更多分配）。这些在每帧调用一次的话，10 Gbps 流量
 * 大概率会拉高 G1 young 区的回收频率，让 JIT 优化效果打折。
 *
 * <p>这里把这些"channel 生命周期内不变"的字符串预算到 {@link AttributeKey} 上：
 * {@code channelActive} 时算一遍，之后整个 channel 的所有 read/write 都直接读 attr。
 *
 * <p>同时提供一个静态 {@link ChannelFutureListener} 单例 {@link #CLOSE_ON_FAILURE}，
 * 替代每帧 lambda（lambda 是闭包，捕获 ctx 时会 boxing 成新对象）。
 */
public final class ChannelAttributes {

    private ChannelAttributes() {}

    /** 缓存 {@code channel.id().asLongText()} 的字符串结果。 */
    public static final AttributeKey<String> CHANNEL_ID =
            AttributeKey.valueOf(ChannelAttributes.class, "channelId");

    /** 缓存远端 / 本端的 IP 字符串和端口。 */
    public static final AttributeKey<EndpointSnapshot> REMOTE_ENDPOINT =
            AttributeKey.valueOf(ChannelAttributes.class, "remoteEndpoint");

    public static final AttributeKey<EndpointSnapshot> LOCAL_ENDPOINT =
            AttributeKey.valueOf(ChannelAttributes.class, "localEndpoint");

    /**
     * channelActive 时一次性初始化所有 hot path 缓存。
     */
    public static void initHotPath(Channel channel) {
        channel.attr(CHANNEL_ID).set(channel.id().asLongText());
        channel.attr(REMOTE_ENDPOINT).set(EndpointSnapshot.of(channel.remoteAddress()));
        channel.attr(LOCAL_ENDPOINT).set(EndpointSnapshot.of(channel.localAddress()));
    }

    /** 读缓存的 channelId；如果 channelActive 还没跑过，fallback 现算（不缓存）。 */
    public static String channelId(Channel channel) {
        String cached = channel.attr(CHANNEL_ID).get();
        return cached != null ? cached : channel.id().asLongText();
    }

    public static EndpointSnapshot remoteEndpoint(Channel channel) {
        EndpointSnapshot cached = channel.attr(REMOTE_ENDPOINT).get();
        return cached != null ? cached : EndpointSnapshot.of(channel.remoteAddress());
    }

    public static EndpointSnapshot localEndpoint(Channel channel) {
        EndpointSnapshot cached = channel.attr(LOCAL_ENDPOINT).get();
        return cached != null ? cached : EndpointSnapshot.of(channel.localAddress());
    }

    /**
     * 静态 listener，写入失败时关闭 channel。
     * 替代代码各处的 {@code future -> { if (!future.isSuccess()) ctx.close(); }} lambda，
     * 避免每次 writeAndFlush 都分配一个新的闭包对象。
     *
     * <p>关闭的是 {@code future.channel()}（即 listener 所附着的写入 channel）。
     * 如果调用方想关闭其它 channel，请单独写 listener，但 hot path 上的常见场景是
     * "写失败 → 关写入这一侧"，本 listener 已覆盖。
     */
    public static final ChannelFutureListener CLOSE_ON_FAILURE = future -> {
        if (!future.isSuccess()) {
            future.channel().close();
        }
    };

    /**
     * Hot path 写入完成后失败就关闭"另一侧" channel 的 listener 工厂。
     *
     * <p>{@link #CLOSE_ON_FAILURE} 是关 {@code future.channel()}（写入端）；
     * 转发场景里更常见的是写失败要关读取端（避免数据继续涌入）。这种情况下没法用纯静态
     * 单例，必须 capture 对端 channel，但仍可以避免在 hot path 内 new
     * lambda——把 listener 实例缓存到 attr 上即可。
     */
    public static ChannelFutureListener closeOnFailureOf(Channel sideToClose) {
        AttributeKey<ChannelFutureListener> key = AttributeKey.valueOf(
                ChannelAttributes.class, "closeListener-" + System.identityHashCode(sideToClose));
        ChannelFutureListener existing = sideToClose.attr(key).get();
        if (existing != null) {
            return existing;
        }
        ChannelFutureListener listener = future -> {
            if (!future.isSuccess()) {
                sideToClose.close();
            }
        };
        sideToClose.attr(key).set(listener);
        return listener;
    }

    /**
     * Endpoint 的紧凑表示：IP 字符串 + 端口。
     */
    public record EndpointSnapshot(String address, int port) {

        public static final EndpointSnapshot EMPTY = new EndpointSnapshot("", 0);

        public static EndpointSnapshot of(SocketAddress socketAddress) {
            if (!(socketAddress instanceof InetSocketAddress inet)) {
                return EMPTY;
            }
            String address = inet.getAddress() != null
                    ? inet.getAddress().getHostAddress()
                    : inet.getHostString();
            return new EndpointSnapshot(address, inet.getPort());
        }
    }
}
