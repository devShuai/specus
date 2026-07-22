package com.theshuai.common.protocol.request;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Netty control-channel login after the client has completed HTTP authentication.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class LoginRequestPacket extends Packet {
    private String clientName;
    private Long clientSessionId;
    private String accessToken;
    private String connectionRole;

    @Override
    public Byte getCommand() {
        return Command.LOGIN_REQUEST;
    }
}
