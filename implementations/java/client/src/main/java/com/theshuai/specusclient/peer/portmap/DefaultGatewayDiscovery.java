package com.theshuai.specusclient.peer.portmap;

import lombok.extern.slf4j.Slf4j;

import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 默认网关 IPv4 推断工具。NAT-PMP 和 PCP 需要把请求发到「本网络的路由器」，
 * 但 JDK 没有暴露路由表 API。
 *
 * <p>这里用一个**广泛靠谱**的取巧路径：
 *
 * <ol>
 *   <li>开一个临时的 UDP socket，{@code connect()} 到外网某个公网 IP（不真的发包，
 *       只是让内核选出口接口）；</li>
 *   <li>读 socket 的 local address，就是出口网卡那张 IP；</li>
 *   <li>在该 /24 子网里取 {@code .1} 作为候选网关地址。</li>
 * </ol>
 *
 * <p>家用 / 办公网 99% 的网关都在 {@code x.x.x.1}（部分在 {@code x.x.x.254}，作为兜底候选）。
 * 这套方法不依赖 native call，跨平台一致；唯一会失手的场景是 carrier-grade NAT 多跳网络，
 * 那种场景下 NAT-PMP/PCP 通常也无能为力，要靠 STUN/中继。
 *
 * <p>UPnP 用 SSDP 多播发现，不需要预先知道网关 IP，所以这个工具只服务于 NAT-PMP/PCP。
 */
@Slf4j
final class DefaultGatewayDiscovery {

    private DefaultGatewayDiscovery() {}

    /**
     * 返回若干个候选默认网关 IPv4 地址，按可能性从高到低排列。调用方按顺序试，
     * 第一个能正常响应的就是真的。
     */
    static Set<InetAddress> candidates() {
        Set<InetAddress> result = new LinkedHashSet<>();

        // 第一组候选：通过 "连接到公网" 路由出口 IP 推断
        addCandidatesFromRoutingProbe(result, "1.1.1.1", 53);
        addCandidatesFromRoutingProbe(result, "223.5.5.5", 53);

        // 第二组：遍历本机所有非回环 IPv4 接口，取 .1 / .254
        try {
            Enumeration<NetworkInterface> nics = NetworkInterface.getNetworkInterfaces();
            while (nics != null && nics.hasMoreElements()) {
                NetworkInterface nic = nics.nextElement();
                if (!nic.isUp() || nic.isLoopback() || nic.isVirtual()) {
                    continue;
                }
                Enumeration<InetAddress> addresses = nic.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    if (address instanceof Inet4Address && !address.isLoopbackAddress()
                            && !address.isLinkLocalAddress()) {
                        addCandidatesFromLocalAddress(result, address);
                    }
                }
            }
        } catch (Exception e) {
            log.debug("default gateway 网卡枚举失败: {}", e.getMessage());
        }
        return result;
    }

    private static void addCandidatesFromRoutingProbe(Set<InetAddress> sink, String probeHost, int probePort) {
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.connect(new InetSocketAddress(probeHost, probePort));
            InetAddress local = socket.getLocalAddress();
            if (local instanceof Inet4Address && !local.isAnyLocalAddress()) {
                addCandidatesFromLocalAddress(sink, local);
            }
        } catch (Exception e) {
            log.trace("default gateway 探测 {} 失败: {}", probeHost, e.getMessage());
        }
    }

    private static void addCandidatesFromLocalAddress(Set<InetAddress> sink, InetAddress local) {
        byte[] octets = local.getAddress();
        if (octets.length != 4) {
            return;
        }
        // 同一 /24 的 .1 几乎是中国家用 + 大部分企业网的网关；.254 是另一个常见值（部分 OPNsense / 老款思科）
        addOctet(sink, octets, (byte) 1);
        addOctet(sink, octets, (byte) 254);
    }

    private static void addOctet(Set<InetAddress> sink, byte[] template, byte lastOctet) {
        try {
            byte[] copy = template.clone();
            copy[3] = lastOctet;
            sink.add(InetAddress.getByAddress(copy));
        } catch (Exception ignored) {
        }
    }
}
