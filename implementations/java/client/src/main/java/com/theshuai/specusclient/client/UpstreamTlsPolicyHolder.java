package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.UpstreamTlsConfig;

/**
 * Makes the configured upstream trust policy reachable from the forwarding handlers.
 *
 * <p>Those handlers build their {@link io.netty.handler.ssl.SslContext} from a static initialiser
 * and have no reference to the startup configuration. Rather than thread the config through every
 * constructor, the policy is published once at startup and read from here.
 *
 * <p>The default is a policy that verifies. That matters: if startup ever failed to publish, the
 * handlers would fall back to checking certificates rather than to trusting everything, which is
 * the direction a failure should lean.
 */
public final class UpstreamTlsPolicyHolder {
    private static volatile UpstreamTlsPolicy policy = new UpstreamTlsPolicy(new UpstreamTlsConfig());

    private UpstreamTlsPolicyHolder() {
    }

    public static void configure(UpstreamTlsConfig config) {
        policy = new UpstreamTlsPolicy(config);
    }

    public static UpstreamTlsPolicy current() {
        return policy;
    }
}
