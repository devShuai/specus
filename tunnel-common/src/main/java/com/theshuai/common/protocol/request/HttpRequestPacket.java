package com.theshuai.common.protocol.request;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@Data
public class HttpRequestPacket extends Packet {
    private String clientName;
    private String toClientName;
    private String requestId;
    private String requestMethod;
    private String requestUrl;
    private Map<String, String> headerMap;
    private Map<String, String> paramMap;
    private String body;

    @Override
    public Byte getCommand() {
        return Command.HTTP_REQUEST;
    }
}
