package com.theshuai.specusclient.bean;

import com.theshuai.specusclient.peer.PeerVirtualDeviceOptions;
import lombok.Data;

@Data
public class ClientStartupConfig {
    private String serverBaseUrl;
    private String apiKey;
    private String secret;
    private ControlTlsConfig controlTls = new ControlTlsConfig();
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "specus0";
    private int peerMeshMtu = PeerVirtualDeviceOptions.DEFAULT_MTU;
}
