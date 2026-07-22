package com.theshuai.common.command;

public interface Command {
    Byte LOGIN_REQUEST = 1;
    Byte LOGIN_RESPONSE = -1;
    Byte MESSAGE_REQUEST = 2;
    Byte MESSAGE_RESPONSE = -2;
    Byte LOGOUT_REQUEST = 3;
    Byte LOGOUT_RESPONSE = -3;
    Byte HEARTBEAT_REQUEST = 4;
    Byte HEARTBEAT_RESPONSE = -4;
    Byte NAT_MESSAGE = 6;
}
