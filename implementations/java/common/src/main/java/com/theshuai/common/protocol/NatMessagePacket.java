package com.theshuai.common.protocol;

import com.theshuai.common.command.Command;
import lombok.Data;
import lombok.EqualsAndHashCode;

import java.util.Map;

@EqualsAndHashCode(callSuper = true)
@Data
public class NatMessagePacket extends Packet {
    public static final int FLAG_END_STREAM = 0x01;

    private NatMessageType natMessageType;

    /** Bit flags defined by the NAT stream v2 frame. */
    private int flags;

    /** Connection-local unsigned 32-bit stream id. Zero is reserved for connection control. */
    private int streamId;

    /** Type-specific unsigned 32-bit value (window credit or reset error code). */
    private long value;

    private Map<String, Object> metaData;

    private byte[] data;

    @Override
    public Byte getCommand() {
        return Command.NAT_MESSAGE;
    }
}
