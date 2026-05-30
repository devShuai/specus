package com.theshuai.common.protocol;

public enum MessageType {
    SERVER_TO_CLIENT(0),
    CLIENT_TO_SERVER(1),
    CLIENT_TO_CLIENT(2),
    NAT_CONTROL(3);

    private int value;

    private MessageType(int value) {
        this.value = value;
    }
}
