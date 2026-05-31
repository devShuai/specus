package com.theshuai.common.protocol.response;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data
public class DirectHttpResponsePacket extends Packet {
    private String requestId;
    private int statusCode;
    private List<String> headers;
    private byte[] body;
    private String error;

    @Override
    public Byte getCommand() {
        return Command.DIRECT_HTTP_RESPONSE;
    }
}
