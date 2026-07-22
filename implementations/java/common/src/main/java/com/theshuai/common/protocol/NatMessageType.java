package com.theshuai.common.protocol;

public enum NatMessageType {
    REGISTER(1),
    REGISTER_RESULT(2),
    OPEN(3),
    FIN(4),
    DATA(5),
    KEEPALIVE(6),
    UNREGISTER(7),
    RST(8),
    WINDOW_UPDATE(9);

    private final int code;

    NatMessageType(int code) {
        this.code = code;
    }

    public static NatMessageType fromWireId(int code) {
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
