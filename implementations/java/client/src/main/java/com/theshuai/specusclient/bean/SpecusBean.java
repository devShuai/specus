package com.theshuai.specusclient.bean;

import com.theshuai.common.clientauth.ClientAuthLoginResponse;
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
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "specus0";
    private int peerMeshMtu = PeerVirtualDeviceOptions.DEFAULT_MTU;
    private String remoteAddress;
    private int remotePort;
    private transient ClientAuthRefresher authRefresher;
}
