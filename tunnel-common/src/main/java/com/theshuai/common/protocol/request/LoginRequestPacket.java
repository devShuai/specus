package com.theshuai.common.protocol.request;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

@EqualsAndHashCode(callSuper = true)
@Data
public class LoginRequestPacket extends Packet {
    private String clientName;
    private String password;
    private String timestamp;
    private String checkSign;

    @Override
    public Byte getCommand() {
        return Command.LOGIN_REQUEST;
    }
}
