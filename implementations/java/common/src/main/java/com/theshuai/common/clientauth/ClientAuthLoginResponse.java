package com.theshuai.common.clientauth;

import com.theshuai.common.peermesh.LocalPeerService;
import com.theshuai.common.peermesh.PeerServiceDiscovery;
import com.theshuai.common.peermesh.PeerServiceSharingStatus;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class ClientAuthLoginResponse {
    private String tenantId;
    private long clientId;
    private String clientName;
    private long clientSessionId;
    private String accessToken;
    private long tokenTtlSeconds;
    private String nettyHost;
    private int nettyPort;
    private boolean nettyTls;
    private int maxOnlineInstances = 2;
    private ClientPolicy policy = new ClientPolicy();
    private PeerMeshConfig peerMesh = new PeerMeshConfig();
    private List<SpecusEndpoint> specusConfigList = new ArrayList<>();
    private List<HttpRouteEndpoint> httpSpecusConfigList = new ArrayList<>();

    @Data
    public static class ClientPolicy {
        private boolean enabled = true;
        private String billingStatus = "ACTIVE";
        private long retryAfterSeconds = 0;
    }

    @Data
    public static class SpecusEndpoint {
        private int port;
        private String specusAddress;
        private int specusPort;
    }

    @Data
    public static class HttpRouteEndpoint {
        private String route;
        private String targetBaseUrl;
        private boolean insecureSkipVerify;
    }

    @Data
    public static class PeerMeshConfig {
        private boolean enabled = false;
        private long clientId;
        private String clientName;
        private String virtualIp;
        private String cidr;
        private String stunHost;
        private int stunPort;
        private String turnHost;
        private int turnPort;
        private List<String> publicStunServers = new ArrayList<>();
        private String iceUsername;
        private String iceCredential;
        private String iceRealm;
        private String iceNonce;
        private String serverPublicKey;
        private String clientPublicKey;
        private long sessionTtlSeconds;
        private int peerServiceDiscoveryVersion = PeerServiceDiscovery.PROTOCOL_VERSION;
        private PeerServiceSharingStatus serviceSharing = new PeerServiceSharingStatus();
        private List<LocalPeerService> localServices = new ArrayList<>();
    }
}
