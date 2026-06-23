package com.theshuai.tunnelclient.bean;

import lombok.Data;

@Data
public class ClientStartupConfig {
    private String serverBaseUrl;
    private String apiKey;
    private String secret;
    private String peerMeshDevice = "noop";
    private String peerMeshTunName = "shuai0";
    private int peerMeshMtu = 1400;
}
