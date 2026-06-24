package com.theshuai.common.protocol.response;

import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

import static com.theshuai.common.command.Command.LOGOUT_RESPONSE;


@EqualsAndHashCode(callSuper = true)
@Data
public class LogoutResponsePacket extends Packet {

    private boolean success;

    private String reason;

    @Override
    public Byte getCommand() {
        return LOGOUT_RESPONSE;
    }
}
