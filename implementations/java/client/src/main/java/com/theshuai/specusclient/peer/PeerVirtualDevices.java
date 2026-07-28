package com.theshuai.specusclient.peer;

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
            case "windows-wintun", "wintun" -> createWindowsWintun(options, config);
            case "mac-utun", "utun", "macos-utun", "darwin-utun" -> createMacUtun(options, config);
            case "auto" -> {
                if (isLinux()) {
                    yield createLinuxTun(options, config);
                }
                if (isWindows()) {
                    yield createWindowsWintun(options, config);
                }
                if (isMac()) {
                    yield createMacUtun(options, config);
                }
                yield new NoopPeerVirtualDevice();
            }
            default -> new NoopPeerVirtualDevice();
        };
    }

    static String key(PeerVirtualDeviceOptions options, ClientAuthLoginResponse.PeerMeshConfig config) {
        String mode = options == null ? "noop" : options.mode().toLowerCase(Locale.ROOT);
        String name = options == null ? "specus0" : options.tunName();
        int mtu = options == null ? PeerVirtualDeviceOptions.DEFAULT_MTU : options.mtu();
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

    private static PeerVirtualDevice createWindowsWintun(PeerVirtualDeviceOptions options,
                                                         ClientAuthLoginResponse.PeerMeshConfig config) {
        if (!isWindows()) {
            log.warn("Peer mesh Wintun 只能在 Windows 上启用，当前系统为 {}", System.getProperty("os.name", ""));
            return new NoopPeerVirtualDevice();
        }
        return new WindowsWintunPeerVirtualDevice(options, config);
    }

    private static PeerVirtualDevice createMacUtun(PeerVirtualDeviceOptions options,
                                                   ClientAuthLoginResponse.PeerMeshConfig config) {
        if (!isMac()) {
            log.warn("Peer mesh macOS utun 只能在 macOS 上启用，当前系统为 {}", System.getProperty("os.name", ""));
            return new NoopPeerVirtualDevice();
        }
        return new MacUtunPeerVirtualDevice(options, config);
    }

    private static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("linux");
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("windows");
    }

    private static boolean isMac() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return os.contains("mac") || os.contains("darwin");
    }
}
