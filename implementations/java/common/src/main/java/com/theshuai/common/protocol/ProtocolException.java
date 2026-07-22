package com.theshuai.common.protocol;

public class ProtocolException extends Exception {
    private final Reason reason;

    public ProtocolException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public ProtocolException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason getReason() {
        return reason;
    }

    public enum Reason {
        INVALID_MAGIC,
        UNSUPPORTED_VERSION,
        UNSUPPORTED_SERIALIZER,
        UNKNOWN_COMMAND,
        INVALID_LENGTH,
        MALFORMED_BODY
    }
}
