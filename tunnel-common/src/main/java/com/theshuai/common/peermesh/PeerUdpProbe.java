package com.theshuai.common.peermesh;

import lombok.Data;

@Data
public class PeerUdpProbe {
    public static final String MAGIC = "shuai-peer-mesh";
    public static final String TYPE_CHECK = "check";
    public static final String TYPE_CHECK_RESPONSE = "check-response";

    private String magic = MAGIC;
    private String type;
    private Long sessionId;
    private Long fromClientId;
    private Long toClientId;
    private String nonce;
    private String token;
    private long sentAtMillis;
}
