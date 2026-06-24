package com.theshuai.common.protocol.response;


import com.theshuai.common.protocol.Packet;

import static com.theshuai.common.command.Command.HEARTBEAT_RESPONSE;

public class HeartBeatResponsePacket extends Packet {
    @Override
    public Byte getCommand() {
        return HEARTBEAT_RESPONSE;
    }
}
