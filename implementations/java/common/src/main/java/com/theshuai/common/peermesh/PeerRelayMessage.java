package com.theshuai.common.peermesh;

import lombok.Data;

@Data
public class PeerRelayMessage {
    public static final String MAGIC = "specus-peer-relay";
    public static final String TYPE_BINDING = "binding";
    public static final String TYPE_BINDING_RESPONSE = "binding-response";
    public static final String TYPE_ALLOCATE = "allocate";
    public static final String TYPE_ALLOCATED = "allocated";
    public static final String TYPE_REFRESH = "refresh";
    public static final String TYPE_SEND = "send";
    public static final String TYPE_DATA = "data";
    public static final String TYPE_ERROR = "error";
    public static final String PROBE_PRIMARY = "primary";
    public static final String PROBE_ALTERNATE = "alternate";
    public static final String PROBE_CHANGED_PORT = "changed-port";

    private String magic = MAGIC;
    private String type;
    private String transactionId;
    private String probeRole;
    private String allocationId;
    private String fromAllocationId;
    private String toAllocationId;
    private String mappedAddress;
    private int mappedPort;
    private String alternateAddress;
    private int alternatePort;
    private String observedByAddress;
    private int observedByPort;
    private long ttlSeconds;
    private String payloadBase64;
    private String error;
}
