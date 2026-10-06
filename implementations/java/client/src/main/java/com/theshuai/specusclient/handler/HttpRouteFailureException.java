package com.theshuai.specusclient.handler;

import com.theshuai.common.protocol.HttpRouteFailure;

import java.io.IOException;

/**
 * A step of forwarding an HTTP route stream failed before the response head, with the
 * classification it carries to the RST, or null when the step could not tell why. The message is
 * the reason the RST has always carried.
 */
final class HttpRouteFailureException extends IOException {
    private final transient HttpRouteFailure failure;

    HttpRouteFailureException(HttpRouteFailure failure, String message, Throwable cause) {
        super(message, cause);
        this.failure = failure;
    }

    HttpRouteFailure failure() {
        return failure;
    }
}
