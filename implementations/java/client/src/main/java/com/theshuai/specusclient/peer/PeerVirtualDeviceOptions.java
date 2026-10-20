package com.theshuai.specusclient.peer;

import org.springframework.util.StringUtils;

/**
 * @param egressIpv6 whether the egress consumer is switched on, so the TUN is given the device's
 *                   derived IPv6 address where the platform and the MTU allow the IPv6 data plane
 *                   ({@code protocol/spec/peer-egress.md}, IPv6 数据面)
 */
public record PeerVirtualDeviceOptions(String mode, String tunName, int mtu, boolean egressIpv6) {
    public static final int DEFAULT_MTU = 1280;
    public static final int MIN_MTU = 576;
    public static final int MAX_MTU = 1280;

    public PeerVirtualDeviceOptions {
        mode = StringUtils.hasText(mode) ? mode.trim() : "noop";
        tunName = StringUtils.hasText(tunName) ? tunName.trim() : "specus0";
        mtu = mtu > 0 ? Math.max(MIN_MTU, Math.min(mtu, MAX_MTU)) : DEFAULT_MTU;
    }

    /** A device that serves no egress consumer, and so is given no IPv6 address. */
    public PeerVirtualDeviceOptions(String mode, String tunName, int mtu) {
        this(mode, tunName, mtu, false);
    }
}
