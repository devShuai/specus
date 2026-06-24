package com.theshuai.common.protocol.response;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

import static com.theshuai.common.command.Command.MESSAGE_RESPONSE;

@EqualsAndHashCode(callSuper = true)
@Data
public class MessageResponsePacket extends Packet {
    private String clientName;
    private String toClientName;
    private MessageType messageType;
    private String message;

    @Override
    public Byte getCommand() {
        return MESSAGE_RESPONSE;
    }
}
