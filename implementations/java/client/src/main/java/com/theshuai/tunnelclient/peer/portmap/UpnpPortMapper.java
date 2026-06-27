package com.theshuai.tunnelclient.peer.portmap;

import lombok.extern.slf4j.Slf4j;
import org.bitlet.weupnp.GatewayDevice;
import org.bitlet.weupnp.GatewayDiscover;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * UPnP IGD 客户端，基于 weupnp 库实现。
 *
 * <p>UPnP 比 NAT-PMP/PCP 复杂得多——基于 SSDP 多播发现（UDP 1900），找到一台或多台 IGD 设备后再
 * 通过 SOAP/XML over HTTP 调用 AddPortMapping。weupnp 把这一整套包成几行代码，我们只用关心
 * 业务语义：「请把 (externalPort, UDP) 映射到本机 internalClient:internalPort」。
 *
 * <p>注意 weupnp 0.1.4 的 {@code addPortMapping} 签名**没有 leaseDuration** 参数——映射在路由器侧
 * 走 "permanent / 跟随路由器 reboot" 语义。但很多消费级 IGD 实现会自带 7200 秒默认 lease，
 * 不主动 renew 就过期。这里把 lease 当作 7200 秒（最常见默认值）记账，调用方按这个值续期。
 *
 * <p>UPnP 发现耗时取决于网关响应速度，weupnp 默认 3 秒超时；这里整体调用我们仍然要套外层超时，
 * 防止特别慢的网关把 startup 拖住。
 */
@Slf4j
final class UpnpPortMapper implements NatPortMapper {

    /** 多数消费级 IGD 默认 lease，weupnp 没有显式 API，用这个作为续期周期的依据。 */
    private static final int DEFAULT_ASSUMED_LEASE_SECONDS = 7_200;

    private final AtomicReference<GatewayDevice> cachedGateway = new AtomicReference<>();

    @Override
    public PortMappingProtocol protocol() {
        return PortMappingProtocol.UPNP;
    }

    @Override
    public NatPortMapping addMapping(int internalPort,
                                     int preferredExternal,
                                     int leaseSeconds,
                                     String description) throws PortMappingException {
        GatewayDevice gateway = ensureGateway();
        String externalIp;
        try {
            externalIp = gateway.getExternalIPAddress();
        } catch (Exception e) {
            throw new PortMappingException("UPnP getExternalIPAddress failed", e);
        }
        InetAddress localAddress = gateway.getLocalAddress();
        if (localAddress == null) {
            throw new PortMappingException("UPnP gateway has no local address");
        }

        // 先尝试期望的 external port，被占了就在小范围里 fallback——多数消费级 IGD 没实现
        // AddAnyPortMapping，只能 trial-and-error。
        int externalPort = preferredExternal > 0 ? preferredExternal : internalPort;
        String descriptionSafe = description == null ? "shuai-tunnel" : description;
        for (int attempt = 0; attempt < 4; attempt++) {
            try {
                boolean ok = gateway.addPortMapping(
                        externalPort,
                        internalPort,
                        localAddress.getHostAddress(),
                        "UDP",
                        descriptionSafe);
                if (ok) {
                    log.info("UPnP mapping established: {}:{} -> {}:{} (description='{}')",
                            externalIp, externalPort, localAddress.getHostAddress(), internalPort, descriptionSafe);
                    return new NatPortMapping(
                            protocol(),
                            externalIp,
                            externalPort,
                            internalPort,
                            DEFAULT_ASSUMED_LEASE_SECONDS,
                            Instant.now());
                }
                log.debug("UPnP addPortMapping returned false for external port {}, trying next", externalPort);
            } catch (Exception e) {
                log.debug("UPnP addPortMapping attempt {} failed for external port {}: {}",
                        attempt + 1, externalPort, e.getMessage());
            }
            externalPort = 49_152 + (int) (Math.random() * 16_000); // ephemeral 区间随机
        }
        throw new PortMappingException("UPnP addPortMapping rejected for internal port " + internalPort);
    }

    @Override
    public void deleteMapping(NatPortMapping mapping) {
        GatewayDevice gateway = cachedGateway.get();
        if (gateway == null) {
            return;
        }
        try {
            gateway.deletePortMapping(mapping.externalPort(), "UDP");
            log.debug("UPnP delete sent for external port {}", mapping.externalPort());
        } catch (Exception e) {
            log.debug("UPnP delete failed (best-effort): {}", e.getMessage());
        }
    }

    private GatewayDevice ensureGateway() throws PortMappingException {
        GatewayDevice cached = cachedGateway.get();
        if (cached != null) {
            return cached;
        }
        try {
            GatewayDiscover discover = new GatewayDiscover();
            Map<InetAddress, GatewayDevice> devices = discover.discover();
            if (devices == null || devices.isEmpty()) {
                throw new PortMappingException("UPnP SSDP discovery found no IGD devices");
            }
            GatewayDevice validated = discover.getValidGateway();
            if (validated == null) {
                // 没有 ValidGateway（公网 IP 拿不到）也可能是路由器本身就是 NAT 后面的；
                // 取第一个 device 凑合用，addPortMapping 仍然有可能成功。
                validated = devices.values().iterator().next();
                log.debug("UPnP discover returned no valid gateway with public IP; using first available: {}",
                        validated.getFriendlyName());
            }
            cachedGateway.set(validated);
            log.info("UPnP gateway located: name='{}', model='{}', service={}, local={}",
                    safe(validated.getFriendlyName()),
                    safe(validated.getModelName()),
                    safe(validated.getServiceType()),
                    validated.getLocalAddress() == null ? "?" : validated.getLocalAddress().getHostAddress());
            return validated;
        } catch (PortMappingException e) {
            throw e;
        } catch (Exception e) {
            throw new PortMappingException("UPnP discovery failed", e);
        }
    }

    private static String safe(String s) {
        return s == null ? "?" : s;
    }
}
