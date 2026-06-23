package com.theshuai.tunnelclient.bean;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.tunnelclient.client.ClientAuthRefresher;
import lombok.Data;

import java.util.List;

@Data
public class TunnelBean {
    private String clientName;
    private Long clientSessionId;
    private String accessToken;
    private long tokenTtlSeconds;
    private long tokenExpiresAtMillis;
    private int maxOnlineInstances = 2;
    private List<TunnelConfig> tunnelConfigList;
    private List<HttpTunnelConfig> httpTunnelConfigList;
    private ClientAuthLoginResponse.PeerMeshConfig peerMesh;
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "shuai0";
    private int peerMeshMtu = 1400;
    private String remoteAddress;
    private int remotePort;
    private transient ClientAuthRefresher authRefresher;
}
