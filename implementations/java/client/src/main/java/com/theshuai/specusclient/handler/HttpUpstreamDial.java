package com.theshuai.specusclient.handler;

import io.netty.resolver.AddressResolverGroup;
import io.netty.resolver.DefaultAddressResolverGroup;

/**
 * How the HTTP route forwarder reaches its target.
 *
 * <p>{@code connectTimeoutMillis} bounds the name lookup, the TCP connect and, for https, the TLS
 * handshake together, as the Go client's dialer and .NET's ConnectTimeout do. Production uses the
 * system resolver and 5 seconds; tests swap in a resolver that fails or never answers, or a shorter
 * timeout, so the failures they classify are real ones produced without the network.
 */
record HttpUpstreamDial(long connectTimeoutMillis, AddressResolverGroup<?> resolver) {
    static final HttpUpstreamDial DEFAULT = new HttpUpstreamDial(5_000, DefaultAddressResolverGroup.INSTANCE);
}
