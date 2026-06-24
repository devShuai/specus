package com.theshuai.common.handler;

import com.theshuai.common.protocol.Packet;
import com.theshuai.common.protocol.response.HeartBeatResponsePacket;

/**
 * 服务端控制连接的空闲检测：30 秒写空闲发一帧保活，60 秒读空闲关连接。
 *
 * <p>客户端默认每 5 秒主动心跳一次，server 端的 30 秒 WRITER_IDLE 实际上很少触发——它是兜底，
 * 防止某天客户端实现退化成不再主动心跳。
 */
public class SocketIdleStateHandler extends AbstractIdleHeartbeatHandler {
    private static final int READER_IDLE_TIME = 60;
    private static final int WRITE_IDLE_TIME = 30;

    public SocketIdleStateHandler() {
        super(READER_IDLE_TIME, WRITE_IDLE_TIME);
    }

    @Override
    protected Packet buildHeartbeat() {
        return new HeartBeatResponsePacket();
    }
}
