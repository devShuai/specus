package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.HttpRouteFailure;
import io.netty.channel.ConnectTimeoutException;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.ssl.SslHandshakeTimeoutException;

import java.io.IOException;
import java.net.ConnectException;
import java.net.NoRouteToHostException;
import java.net.UnknownHostException;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/**
 * Places a failure to get a response head from an HTTP route's target in the closed failure set of
 * protocol/spec/service-connectivity-check.md section 6.2.
 *
 * <p>It goes by the phase the failure happened in (reaching the target, its TLS handshake, or the
 * exchange once connected) and by the exception types the JDK and Netty raise there, never by the
 * message text, which changes with the platform, its language and the libraries. Whatever it
 * cannot place is null: the RST then carries its reason alone and a server reports
 * {@code TARGET_UNVERIFIED}.
 *
 * <p>Some failures the spec names have no type of their own in Java and are left out: the JDK's
 * socket layer reports an unreachable network (ENETUNREACH) and a connect reset by the peer as a
 * plain {@link java.net.SocketException}, the same type as unrelated socket failures. It also
 * raises {@link ConnectException} for an operating system connect timeout as well as a refusal;
 * the client's own 5 second connect timeout always expires long before the system's, so that one is
 * read as a refusal.
 */
final class HttpRouteFailureClassifier {
    private HttpRouteFailureClassifier() {
    }

    /**
     * A failure resolving the target's name or connecting to it. The client's own deadline spans
     * both, so expiring while the name is still being looked up is the connect timeout too, as in
     * the Go and .NET clients; a resolver that gives up on its own is a lookup failure.
     */
    static HttpRouteFailure connectFailure(Throwable cause) {
        Throwable failure = unwrap(cause);
        // Netty's own connect timer; it is a ConnectException, so it is told apart first.
        if (failure instanceof ConnectTimeoutException) {
            return HttpRouteFailure.CONNECT_TIMEOUT;
        }
        if (failure instanceof UnknownHostException) {
            return HttpRouteFailure.DNS_FAILED;
        }
        if (failure instanceof NoRouteToHostException) {
            return HttpRouteFailure.UNREACHABLE;
        }
        if (failure instanceof ConnectException) {
            return HttpRouteFailure.CONNECT_REFUSED;
        }
        return null;
    }

    /**
     * A failure of the TLS handshake, after the TCP connect succeeded. The connect timeout spans the
     * handshake, so a handshake that stalls past it is the connect timeout; anything else that ends
     * the handshake is a TLS failure, whether the certificate was refused, the target spoke no TLS,
     * or it closed the connection mid-handshake, as in the Go client.
     */
    static HttpRouteFailure handshakeFailure(Throwable cause) {
        return unwrap(cause) instanceof SslHandshakeTimeoutException
                ? HttpRouteFailure.CONNECT_TIMEOUT
                : HttpRouteFailure.TLS_FAILED;
    }

    /**
     * A failure once connected and before any response head: the target reset the connection, or
     * sent bytes the HTTP decoder could not use. A closed connection and a malformed head are
     * reported where they are seen, as protocol errors too.
     */
    static HttpRouteFailure exchangeFailure(Throwable cause) {
        Throwable failure = unwrap(cause);
        return failure instanceof IOException || failure instanceof DecoderException
                ? HttpRouteFailure.PROTOCOL_ERROR
                : null;
    }

    /** The failure a forwarding step attached to what it threw, if any. */
    static HttpRouteFailure carried(Throwable cause) {
        return unwrap(cause) instanceof HttpRouteFailureException classified ? classified.failure() : null;
    }

    private static Throwable unwrap(Throwable cause) {
        Throwable current = cause;
        while (current != null && current.getCause() != null
                && (current instanceof ExecutionException || current instanceof CompletionException)) {
            current = current.getCause();
        }
        return current;
    }
}
