package com.theshuai.common.protocol.request;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Data
public class DirectHttpRequestPacket extends Packet {
    private String requestId;
    private String requestMethod;
    private String route;
    private String relativePath;
    private String rawQuery;
    private List<String> headers;
    private byte[] body;

    @Override
    public Byte getCommand() {
        return Command.DIRECT_HTTP_REQUEST;
    }
}
