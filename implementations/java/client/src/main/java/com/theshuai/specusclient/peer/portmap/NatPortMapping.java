package com.theshuai.specusclient.peer.portmap;

import java.time.Instant;

/**
 * 一次成功的 NAT 端口映射结果。
 *
 * @param protocol         哪个协议拿到的（UPNP / NAT_PMP / PCP）
 * @param externalAddress  外部可达的公网 IPv4 地址（路由器报告的）。null 表示协议未告知，
 *                         调用方需要通过其它手段（STUN）补全
 * @param externalPort     外部公网端口
 * @param internalPort     内网本地端口（我们的 UDP socket 绑的那个）
 * @param leaseSeconds     租约时长，单位秒。路由器到这个时刻会自动撤销映射；
 *                         {@code 0} 表示永久（实际上没有协议返回 0，只是占位）
 * @param createdAt        本端记录的创建时刻
 */
public record NatPortMapping(
        PortMappingProtocol protocol,
        String externalAddress,
        int externalPort,
        int internalPort,
        int leaseSeconds,
        Instant createdAt) {

    /**
     * 续期之前应当提前的秒数。
     */
    public static final int RENEWAL_LEAD_SECONDS = 60;

    public Instant expiresAt() {
        return createdAt.plusSeconds(leaseSeconds);
    }

    /**
     * 当前时间是否进入续期窗口（剩余租约 ≤ 60 秒）。
     */
    public boolean shouldRenew(Instant now) {
        return now.isAfter(expiresAt().minusSeconds(RENEWAL_LEAD_SECONDS));
    }
}
