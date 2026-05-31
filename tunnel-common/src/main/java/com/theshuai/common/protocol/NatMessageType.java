package com.theshuai.common.protocol;

public enum NatMessageType {
    REGISTER(1),
    REGISTER_RESULT(2),
    CONNECTED(3),
    DISCONNECTED(4),
    DATA(5),
    KEEPALIVE(6),
    UNREGISTER(7);

    private int code;

    NatMessageType(int code) {
        this.code = code;
    }

    public static NatMessageType valueOf(int code) {
        for (NatMessageType item : NatMessageType.values()) {
            if (item.code == code) {
                return item;
            }
        }
        return null;
    }

    public int getCode() {
        return code;
    }
}
