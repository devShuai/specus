package com.theshuai.common.handler;

import com.theshuai.common.protocol.Packet;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.handler.timeout.IdleStateHandler;
import lombok.extern.slf4j.Slf4j;

import java.util.concurrent.TimeUnit;

/**
 * 心跳/读空闲处理的通用骨架：READER_IDLE 关连接，WRITER_IDLE 发一帧保活。
 *
 * <p>子类只需要回答两个问题：
 * <ul>
 *   <li>{@link #buildHeartbeat()}——空闲时该写什么 packet？（客户端写 Request，服务端回 Response）</li>
 *   <li>{@link #onChannelInactive(ChannelHandlerContext)}——连接断开时除了清理还要做什么？
 *       （客户端要安排重连；服务端只清理）</li>
 * </ul>
 *
 * <p>设计上：
 * <ul>
 *   <li>{@link IdleStateHandler#write} 拦截真实流量更新 lastWriteTime，因此有数据时心跳不会触发。</li>
 *   <li>心跳从 {@code channel} 尾部写出，保证能经过后续的协议编码器；写出后会重置 WRITER_IDLE，
 *       下一次仍按写空闲间隔触发。</li>
 *   <li>心跳事件是协议层的正常活动，日志只用 DEBUG 级，避免刷 INFO。</li>
 * </ul>
 */
@Slf4j
public abstract class AbstractIdleHeartbeatHandler extends IdleStateHandler {
    private final int readerIdleSeconds;
    private final int writerIdleSeconds;

    protected AbstractIdleHeartbeatHandler(int readerIdleSeconds, int writerIdleSeconds) {
        super(readerIdleSeconds, writerIdleSeconds, 0, TimeUnit.SECONDS);
        this.readerIdleSeconds = readerIdleSeconds;
        this.writerIdleSeconds = writerIdleSeconds;
    }

    /** 子类返回需要写出的心跳 packet。每次空闲触发都会调用一次。 */
    protected abstract Packet buildHeartbeat();

    /**
     * 子类在 channel 断开时执行额外动作（如安排重连）。基类的 super.channelInactive 已经
     * 执行过 {@link IdleStateHandler} 的清理，子类只需关心"我自己还想做什么"。
     */
    protected void onChannelInactive(ChannelHandlerContext ctx) throws Exception {
        // default no-op
    }

    @Override
    protected final void channelIdle(ChannelHandlerContext ctx, IdleStateEvent evt) throws Exception {
        if (evt.state() == IdleState.READER_IDLE) {
            log.info("{}秒内未读到数据, 关闭连接", readerIdleSeconds);
            ctx.close();
        } else if (evt.state() == IdleState.WRITER_IDLE) {
            log.debug("{}秒未写入数据, 发送心跳", writerIdleSeconds);
            ctx.channel().writeAndFlush(buildHeartbeat()).addListener((ChannelFutureListener) future -> {
                if (!future.isSuccess()) {
                    log.debug("心跳发送失败, 关闭连接: {}",
                            future.cause() == null ? "unknown" : future.cause().toString());
                    future.channel().close();
                }
            });
        }
    }

    @Override
    public final void channelInactive(ChannelHandlerContext ctx) throws Exception {
        // 先调 super 让 IdleStateHandler 取消内部 reader/writer 定时任务，避免在已死 channel 上残留。
        super.channelInactive(ctx);
        onChannelInactive(ctx);
    }
}
