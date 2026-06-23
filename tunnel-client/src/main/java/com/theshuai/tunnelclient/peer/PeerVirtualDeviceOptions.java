package com.theshuai.tunnelclient.peer;

import org.springframework.util.StringUtils;

public record PeerVirtualDeviceOptions(String mode, String tunName, int mtu) {
    public PeerVirtualDeviceOptions {
        mode = StringUtils.hasText(mode) ? mode.trim() : "noop";
        tunName = StringUtils.hasText(tunName) ? tunName.trim() : "shuai0";
        mtu = mtu > 0 ? mtu : 1400;
    }
}
