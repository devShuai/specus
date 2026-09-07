package com.theshuai.specusclient.auth;

import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/** Safe to display: never retain HTTP bodies, credentials or request URLs. */
public final class HttpLoginFailure extends IllegalStateException {
    private final boolean retryable;
    private long retryAfterMillis;

    public HttpLoginFailure(String message, boolean retryable) {
        super(message);
        this.retryable = retryable;
    }

    public boolean isRetryable() { return retryable; }
    public int exitCode() {
        if (getMessage().startsWith("Initial HTTP login timeout")) return 4;
        if (getMessage().matches("HTTP login failed \\(HTTP (400|401|403|409)\\).*")) return 3;
        return 1;
    }
    public long retryAfterMillis() { return retryAfterMillis; }

    public static HttpLoginFailure forStatus(int status, String retryAfter) {
        HttpLoginFailure failure = forStatus(status);
        if (retryAfter != null && failure.isRetryable()) {
            try {
                long seconds;
                if (retryAfter.trim().matches("[0-9]+")) seconds = Long.parseLong(retryAfter.trim());
                else seconds = Duration.between(ZonedDateTime.now(),
                        ZonedDateTime.parse(retryAfter.trim(), DateTimeFormatter.RFC_1123_DATE_TIME)).getSeconds();
                // The CLI's maximum budget is one hour; avoid overflow for untrusted headers.
                failure.retryAfterMillis = Math.max(0, Math.min(3600, seconds)) * 1000;
            } catch (RuntimeException ignored) { /* Invalid header: use normal backoff. */ }
        }
        return failure;
    }

    public static HttpLoginFailure forStatus(int status) {
        boolean retry = status == 408 || status == 425 || status == 429 || status >= 500 && status <= 599;
        String action = status == 400 || status == 401 || status == 403 || status == 409
                ? "Check apiKey/secret, system clock, account permissions and gateway access rules."
                : retry ? "Check network/server availability."
                : "Check serverBaseUrl and server/client compatibility.";
        return new HttpLoginFailure("HTTP login failed (HTTP " + status + "). " + action, retry);
    }
}
