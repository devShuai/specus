package com.theshuai.tunnelclient.peer.portmap;

/**
 * NAT 显式端口映射协议。
 *
 * <p>三种协议都解决同一个问题——客户端跟自家路由器协商「把公网某端口转发到我内网某端口」，
 * 协商成功就能跳过 STUN 探测和打洞，直接拿到一个可被外部 UDP 包到达的公网端点。
 *
 * <p>三者的差别：
 *
 * <ul>
 *   <li>{@link #UPNP}     —— UPnP IGD 1.x/2.x。基于 SSDP 多播发现 + SOAP/XML over HTTP。
 *                            消费级家用路由器（TP-Link、小米、华为、ASUS、Mercury 等）几乎都支持，
 *                            默认绝大多数开启 IGD。中国市场覆盖率最高。
 *   <li>{@link #NAT_PMP}  —— RFC 6886。Apple 原创，简单 UDP 协议。AirPort 路由器、
 *                            OpenWrt、OPNsense 等少数路由器实现，国内覆盖率偏低。
 *   <li>{@link #PCP}      —— RFC 6887。NAT-PMP 的官方后继者，二进制 UDP，多家运营商
 *                            级 NAT（CGNAT）做了实现，更适合现代/IPv6/CGNAT 场景。
 * </ul>
 *
 * <p>三者协议都不冲突，{@link NatPortMappingService} 会并发尝试，选第一个成功的。
 */
public enum PortMappingProtocol {
    UPNP,
    NAT_PMP,
    PCP,
}
