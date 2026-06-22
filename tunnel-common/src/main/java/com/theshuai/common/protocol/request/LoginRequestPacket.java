package com.theshuai.common.protocol.request;

import com.theshuai.common.command.Command;
import com.theshuai.common.protocol.Packet;
import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * Login request: clientName + timestamp + nonce + HMAC-SHA256 signature.
 * The plaintext password is never sent. The signature key is
 * {@code SHA-256(password)} on both sides — see {@link com.theshuai.common.security.HmacSigner}.
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class LoginRequestPacket extends Packet {
    private String clientName;
    private Long clientSessionId;
    private String accessToken;
    private String timestamp;
    private String nonce;
    private byte[] checkSign;

    @Override
    public Byte getCommand() {
        return Command.LOGIN_REQUEST;
    }
}
