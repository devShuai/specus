package com.theshuai.common.protocol;

import com.theshuai.common.command.Command;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@Data
public class NatMessagePacket extends Packet {

    private NatMessageType natMessageType;

    private Map<String, Object> metaData;

    private byte[] data;

    @Override
    public Byte getCommand() {
        return Command.NAT_MESSAGE;
    }
}
