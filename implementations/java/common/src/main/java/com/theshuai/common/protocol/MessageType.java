package com.theshuai.common.protocol;

public enum MessageType {
    SERVER_TO_CLIENT(1),
    CLIENT_TO_SERVER(2),
    CLIENT_TO_CLIENT(3),
    NAT_CONTROL(4),
    PEER_CONTROL(5);

    private final int wireId;

    MessageType(int wireId) {
        this.wireId = wireId;
    }

    public int getWireId() {
        return wireId;
    }

    public static MessageType fromWireId(int wireId) {
        for (MessageType value : values()) {
            if (value.wireId == wireId) {
                return value;
            }
        }
        return null;
    }
}
