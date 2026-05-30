package com.theshuai.common.protocol.request;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class MessageRequestPacket extends Packet {
    private String clientName;
    private String toClientName;
    private MessageType messageType;
    private String message;

    @Override
    public Byte getCommand() {
        return Command.MESSAGE_REQUEST;
    }
}
