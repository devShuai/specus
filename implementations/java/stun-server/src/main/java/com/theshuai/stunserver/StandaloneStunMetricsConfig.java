package com.theshuai.stunserver;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Objects;

public record StandaloneStunMetricsConfig(InetAddress bindAddress, int port) {
    public StandaloneStunMetricsConfig {
        Objects.requireNonNull(bindAddress, "bindAddress");
        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException("metrics port must be between 0 and 65535");
        }
    }

    public static StandaloneStunMetricsConfig disabled() {
        return new StandaloneStunMetricsConfig(InetAddress.getLoopbackAddress(), 0);
    }

    public boolean enabled() {
        return port > 0;
    }

    public InetSocketAddress socketAddress() {
        return new InetSocketAddress(bindAddress, port);
    }

    public String describe() {
        return enabled() ? "http://" + bindAddress.getHostAddress() + ":" + port + "/metrics" : "disabled";
    }
}
