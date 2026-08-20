package com.theshuai.common.peermesh;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import lombok.Data;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class PeerControlMessage {
    public static final String TYPE_CONFIG = "peer-config";
    public static final String TYPE_ROSTER = "roster";
    public static final String TYPE_SESSION_GRANT = "session-grant";
    public static final String TYPE_CANDIDATES = "candidates";
    public static final String TYPE_PATH_REPORT = "path-report";
    public static final String TYPE_TRAFFIC_REPORT = "traffic-report";
    public static final String TYPE_DEVICE_REPORT = "device-report";
    public static final String TYPE_CLOSE = "close";
    public static final String TYPE_SERVICE_REPORT = "service-report";
    public static final String TYPE_SERVICE_CATALOG = "service-catalog";

    private String type;
    private Long sessionId;
    private Long sourceClientId;
    private String sourceClientName;
    private String sourceVirtualIp;
    private String sourcePublicKey;
    /**
     * 发送方本次运行实例的随机 key epoch，用于 SPM2 单向 traffic key 派生。
     * 客户端重启后必须变化，否则复用的 session/token 会导致 AES-GCM nonce 重用。
     */
    private String sourceKeyEpoch;
    private Long targetClientId;
    private String targetClientName;
    private String targetVirtualIp;
    private String targetPublicKey;
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
    private String natMappingBehavior;
    private String natFilteringBehavior;
    private String natBehaviorDiscovery;
    private String lastEndpoint;
    private long createdAtMillis;
    private ClientAuthLoginResponse.PeerMeshConfig peerMesh;
    private int dataFrameVersion = 2;
    private List<PeerCandidate> candidates = List.of();
    private List<?> peers = List.of();
    private Boolean enabled;
    private Long revision;
    private Long publisherClientId;
    private String publisherClientName;
    private Long publisherSessionId;
    private String instanceId;
    private String generatedAt;
    private List<PeerAdvertisedService> services = List.of();
    private List<PeerServiceStats> stats = List.of();
    private List<PeerMdnsCandidate> mdnsCandidates = List.of();
}
