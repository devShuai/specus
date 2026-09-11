package com.theshuai.specusclient.bean;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.peeregress.PeerEgressRule;
import com.theshuai.specusclient.client.ClientAuthRefresher;
import com.theshuai.specusclient.peer.PeerVirtualDeviceOptions;
import lombok.Data;

import java.util.List;

@Data
public class SpecusBean {
    private String clientName;
    private Long clientSessionId;
    private String accessToken;
    private long tokenTtlSeconds;
    private long tokenExpiresAtMillis;
    private int maxOnlineInstances = 2;
    private List<SpecusConfig> specusConfigList;
    private List<HttpSpecusConfig> httpSpecusConfigList;
    private ClientAuthLoginResponse.PeerMeshConfig peerMesh;

    /**
     * Route chosen destinations through an egress peer. Local configuration, unlike the egress
     * policy, which the server owns and pushes: a consumer decides for itself what leaves through
     * somebody else's connection.
     */
    private List<PeerEgressRule> peerEgressRules = List.of();
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "specus0";
    private int peerMeshMtu = PeerVirtualDeviceOptions.DEFAULT_MTU;
    private String remoteAddress;
    private int remotePort;
    private boolean nettyTls;
    private transient ClientAuthRefresher authRefresher;
}
