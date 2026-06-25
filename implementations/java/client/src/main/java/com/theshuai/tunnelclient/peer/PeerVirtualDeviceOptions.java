package com.theshuai.tunnelclient.peer;

import org.springframework.util.StringUtils;

public record PeerVirtualDeviceOptions(String mode, String tunName, int mtu) {
    public static final int DEFAULT_MTU = 1280;
    public static final int MIN_MTU = 576;
    public static final int MAX_MTU = 1280;

    public PeerVirtualDeviceOptions {
        mode = StringUtils.hasText(mode) ? mode.trim() : "noop";
        tunName = StringUtils.hasText(tunName) ? tunName.trim() : "shuai0";
        mtu = mtu > 0 ? Math.max(MIN_MTU, Math.min(mtu, MAX_MTU)) : DEFAULT_MTU;
    }
}
