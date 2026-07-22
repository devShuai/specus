package com.theshuai.common.protocol;

/** Mandatory v2 connection roles used by the login packet. */
public final class ConnectionRole {
    public static final String CONTROL = "control";
    public static final String DATA = "data";

    private ConnectionRole() {
    }

    public static boolean isValid(String value) {
        return CONTROL.equals(value) || DATA.equals(value);
    }
}
