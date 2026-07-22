package com.theshuai.common.protocol;

import com.alibaba.fastjson2.annotation.JSONField;
import lombok.Data;

@Data
public abstract class Packet {

    @JSONField(deserialize = false, serialize = false)
    private Byte version = PacketCodec.PROTOCOL_VERSION;

    @JSONField(serialize = false)
    public abstract Byte getCommand();
}
