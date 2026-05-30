package com.theshuai.common.protocol.request;


import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;

public class HeartBeatRequestPacket extends Packet {
    @Override
    public Byte getCommand() {
        return Command.HEARTBEAT_REQUEST;
    }
}
