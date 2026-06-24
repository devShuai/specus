package com.theshuai.common.protocol.response;

import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

import static com.theshuai.common.command.Command.LOGIN_RESPONSE;

@EqualsAndHashCode(callSuper = true)
@Data
public class LoginResponsePacket extends Packet {
    private String clientName;
    private boolean success;
    private String reason;

    @Override
    public Byte getCommand() {
        return LOGIN_RESPONSE;
    }
}
