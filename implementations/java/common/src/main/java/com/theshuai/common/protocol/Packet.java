package com.theshuai.common.protocol;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;

@Data
public abstract class Packet {

    @JsonIgnore
    private Byte version = PacketCodec.PROTOCOL_VERSION;

    @JsonIgnore
    public abstract Byte getCommand();
}
