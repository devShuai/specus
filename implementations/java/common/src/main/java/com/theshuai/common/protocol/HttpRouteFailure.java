package com.theshuai.common.protocol;

/**
 * Why an HTTP route stream failed before its response OPEN, as a client that announced
 * {@code clientHttpRouteCapabilities.version >= 1} reports it in the RST metadata, next to the
 * unchanged value and reason (protocol/spec/service-connectivity-check.md section 6.2).
 *
 * <p>The set is closed. A failure that is none of these, or that the client cannot tell apart,
 * travels without the key, which a server reports as {@code TARGET_UNVERIFIED}: an unclassified
 * reset is better than a wrong diagnosis.
 */
public enum HttpRouteFailure {
    /** The route is not in the client's snapshot, or has no targetBaseUrl. */
    ROUTE_NOT_LOADED("route-not-loaded"),
    /** The route is there, but the target address built from it cannot be used. */
    TARGET_INVALID("target-invalid"),
    /** The target port refused the TCP connect. */
    CONNECT_REFUSED("connect-refused"),
    /** The client's own connect timeout expired, while resolving, connecting or in the TLS handshake. */
    CONNECT_TIMEOUT("connect-timeout"),
    /** The target host name could not be resolved. */
    DNS_FAILED("dns-failed"),
    /** The TLS handshake failed, or the certificate or host name did not verify. */
    TLS_FAILED("tls-failed"),
    /** No route to the host or network, or the connect was reset. */
    UNREACHABLE("unreachable"),
    /** Connected, but the target closed, reset or answered with no usable response head. */
    PROTOCOL_ERROR("protocol-error");

    /** The RST metadata key. */
    public static final String METADATA_KEY = "failure";
    /** {@code environment.clientHttpRouteCapabilities.version} of a client that sends the key. */
    public static final int CAPABILITY_VERSION = 1;

    private final String wireName;

    HttpRouteFailure(String wireName) {
        this.wireName = wireName;
    }

    public String wireName() {
        return wireName;
    }

    /** The failure with this wire name, or null for a name outside the set. */
    public static HttpRouteFailure fromWireName(String wireName) {
        for (HttpRouteFailure failure : values()) {
            if (failure.wireName.equals(wireName)) {
                return failure;
            }
        }
        return null;
    }
}
