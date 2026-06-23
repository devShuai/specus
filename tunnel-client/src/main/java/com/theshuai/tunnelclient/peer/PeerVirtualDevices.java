package com.theshuai.tunnelclient.peer;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.Locale;

@Slf4j
final class PeerVirtualDevices {
    private PeerVirtualDevices() {
    }

    static PeerVirtualDevice create(PeerVirtualDeviceOptions options,
                                    ClientAuthLoginResponse.PeerMeshConfig config) {
        String mode = options == null ? "noop" : options.mode().toLowerCase(Locale.ROOT);
        return switch (mode) {
            case "linux-tun" -> createLinuxTun(options, config);
            case "auto" -> isLinux() ? createLinuxTun(options, config) : new NoopPeerVirtualDevice();
            default -> new NoopPeerVirtualDevice();
        };
    }

    static String key(PeerVirtualDeviceOptions options, ClientAuthLoginResponse.PeerMeshConfig config) {
        String mode = options == null ? "noop" : options.mode().toLowerCase(Locale.ROOT);
        String name = options == null ? "shuai0" : options.tunName();
        int mtu = options == null ? 1400 : options.mtu();
        String virtualIp = config == null ? "" : config.getVirtualIp();
        String cidr = config == null ? "" : config.getCidr();
        return mode + "|" + name + "|" + mtu + "|" + virtualIp + "|" + cidr;
    }

    private static PeerVirtualDevice createLinuxTun(PeerVirtualDeviceOptions options,
                                                   ClientAuthLoginResponse.PeerMeshConfig config) {
        if (!isLinux()) {
            log.warn("Peer mesh linux-tun 只能在 Linux 上启用，当前系统为 {}", System.getProperty("os.name", ""));
            return new NoopPeerVirtualDevice();
        }
        return new LinuxTunPeerVirtualDevice(options, config);
    }

    private static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }
}
