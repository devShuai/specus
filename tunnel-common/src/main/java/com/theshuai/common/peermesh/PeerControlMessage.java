package com.theshuai.common.peermesh;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class PeerControlMessage {
    public static final String TYPE_ROSTER = "roster";
    public static final String TYPE_SESSION_GRANT = "session-grant";
    public static final String TYPE_CANDIDATES = "candidates";
    public static final String TYPE_PATH_REPORT = "path-report";
    public static final String TYPE_TRAFFIC_REPORT = "traffic-report";
    public static final String TYPE_DEVICE_REPORT = "device-report";
    public static final String TYPE_CLOSE = "close";

    private String type;
    private Long sessionId;
    private Long sourceClientId;
    private String sourceClientName;
    private Long targetClientId;
    private String targetClientName;
    private String token;
    private String expiresAt;
    private String pathType;
    private String status;
    private Long rttMillis;
    private long directBytes;
    private long relayBytes;
    private String localEndpoint;
    private String remoteEndpoint;
    private String reason;
    private String virtualDeviceMode;
    private String virtualDeviceName;
    private String virtualDeviceStatus;
    private String virtualDeviceError;
    private String natType;
    private String lastEndpoint;
    private long createdAtMillis;
    private List<PeerCandidate> candidates = new ArrayList<>();
    private List<?> peers = new ArrayList<>();
}
