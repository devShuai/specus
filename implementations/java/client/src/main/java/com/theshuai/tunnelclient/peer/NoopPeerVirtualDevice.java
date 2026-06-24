package com.theshuai.tunnelclient.peer;

import lombok.extern.slf4j.Slf4j;

@Slf4j
final class NoopPeerVirtualDevice implements PeerVirtualDevice {
    private volatile boolean started;

    @Override
    public String name() {
        return "noop";
    }

    @Override
    public void start(PacketHandler outboundHandler) {
        if (!started) {
            started = true;
            log.info("Peer mesh 虚拟网卡适配未启用，当前只运行控制面、直连探测和加密 frame 数据面");
        }
    }

    @Override
    public void writePacket(byte[] packet) {
        log.trace("Peer mesh no-op virtual device drop inbound packet: {} bytes",
                packet == null ? 0 : packet.length);
    }

    @Override
    public void close() {
        started = false;
    }
}
