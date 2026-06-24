package com.theshuai.common.protocol.response;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class HttpResponsePacket extends Packet {
    private String clientName;
    private String toClientName;
    private String requestId;
    private String response;

    @Override
    public Byte getCommand() {
        return Command.HTTP_RESPONSE;
    }
}
