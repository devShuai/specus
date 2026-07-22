package com.theshuai.common.peermesh;

import lombok.Data;

@Data
public class PeerCandidate {
    private String type;
    private String transport;
    private String address;
    private int port;
    private long priority;
    private String foundation;
    private String relayId;
    private String addressFamily;
}
