package com.theshuai.specus.android;

import io.netty.channel.ConnectTimeoutException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandshakeTimeoutException;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/**
 * Why an HTTP route stream failed before its response OPEN, in the closed set of
 * protocol/spec/service-connectivity-check.md section 6.2. The RST carries it as {@code failure}
 * next to the reason, so the connectivity check can tell a refused target from a route the device
 * has not loaded.
 *
 * <p>It goes by the phase the failure happened in (resolving the route, reaching the target, its
 * TLS handshake, or the exchange once connected) and by the types the JDK and Netty raise there,
 * never by the message text. Whatever cannot be placed is null: the RST then carries its reason
 * alone and a server reports {@code TARGET_UNVERIFIED}.</p>
 *
 * <p>As in the Java client, an unreachable network and a connect reset by the peer have no type of
 * their own on the JVM (a plain {@link java.net.SocketException}) and stay unclassified; only
 * {@link NoRouteToHostException} is reported as unreachable. The client's own 5 second connect
 * timer is Netty's {@link ConnectTimeoutException}; the TLS handshake that follows has Netty's own
 * deadline, and running past it is the connect timeout too.</p>
 */
final class HttpRouteFailure {
    /** {@code environment.clientHttpRouteCapabilities.version} this client declares at login. */
    static final int CAPABILITY_VERSION = 1;
    /** The RST metadata key that carries the classification. */
    static final String METADATA_KEY = "failure";

    static final String ROUTE_NOT_LOADED = "route-not-loaded";
    static final String TARGET_INVALID = "target-invalid";
    static final String CONNECT_REFUSED = "connect-refused";
    static final String CONNECT_TIMEOUT = "connect-timeout";
    static final String DNS_FAILED = "dns-failed";
    static final String TLS_FAILED = "tls-failed";
    static final String UNREACHABLE = "unreachable";
    static final String PROTOCOL_ERROR = "protocol-error";

    /** The whole closed set; nothing else is ever sent. */
    static final List<String> ALL = List.of(ROUTE_NOT_LOADED, TARGET_INVALID, CONNECT_REFUSED,
            CONNECT_TIMEOUT, DNS_FAILED, TLS_FAILED, UNREACHABLE, PROTOCOL_ERROR);

    private HttpRouteFailure() {
    }

    /**
     * The target of a request on {@code targetBaseUrl}, the route's base in the current
     * configuration snapshot (null when the snapshot has no such route). A route that is not there
     * and a target that cannot be built from it are told apart here, before any connection.
     */
    static URI target(String targetBaseUrl, String relativePath, String rawQuery) throws Classified {
        if (targetBaseUrl == null || targetBaseUrl.trim().isEmpty()) {
            throw new Classified(ROUTE_NOT_LOADED, "HTTP route is not configured", null);
        }
        try {
            return SpecusCore.DirectHttpForwarder.buildTarget(targetBaseUrl, relativePath, rawQuery);
        } catch (IllegalArgumentException invalid) {
            throw new Classified(TARGET_INVALID,
                    invalid.getMessage() == null ? "HTTP route address is invalid" : invalid.getMessage(),
                    invalid);
        }
    }

    /** A failure resolving the target's name or connecting to it. */
    static String connectFailure(Throwable cause) {
        Throwable failure = unwrap(cause);
        // Netty's own connect timer; it is a ConnectException, so it is told apart first.
        if (failure instanceof ConnectTimeoutException) {
            return CONNECT_TIMEOUT;
        }
        if (failure instanceof UnknownHostException) {
            return DNS_FAILED;
        }
        if (failure instanceof NoRouteToHostException) {
            return UNREACHABLE;
        }
        if (failure instanceof ConnectException) {
            return CONNECT_REFUSED;
        }
        return null;
    }

    /**
     * A failure of the TLS handshake, after the TCP connect succeeded: the certificate was refused,
     * the target spoke no TLS, or it closed the connection mid-handshake.
     */
    static String handshakeFailure(Throwable cause) {
        return unwrap(cause) instanceof SslHandshakeTimeoutException ? CONNECT_TIMEOUT : TLS_FAILED;
    }

    /**
     * A failure once connected and before any response head: the target closed or reset the
     * connection, or sent bytes that are no HTTP response.
     */
    static String exchangeFailure(Throwable cause) {
        Throwable failure = unwrap(cause);
        return failure instanceof IOException || failure instanceof DecoderException
                ? PROTOCOL_ERROR : null;
    }

    /** The classification a forwarding step attached to what it threw, if any. */
    static String carried(Throwable cause) {
        return unwrap(cause) instanceof Classified classified ? classified.failure : null;
    }

    private static Throwable unwrap(Throwable cause) {
        Throwable current = cause;
        while (current != null && current.getCause() != null
                && (current instanceof ExecutionException || current instanceof CompletionException)) {
            current = current.getCause();
        }
        return current;
    }

    /**
     * A forwarding step failed before the response head, for the reason in the message (what the
     * RST has always carried) and with the classification, or null when it could not tell why.
     */
    static final class Classified extends IOException {
        final String failure;

        Classified(String failure, String message, Throwable cause) {
            super(message, cause);
            this.failure = failure;
        }
    }
}
