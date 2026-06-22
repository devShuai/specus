package com.theshuai.tunnelclient.bean;

import lombok.Data;

import java.util.List;

@Data
public class TunnelBean {
    private String clientName;
    private String password;
    private Long clientSessionId;
    private String accessToken;
    private int maxOnlineInstances = 2;
    private List<TunnelConfig> tunnelConfigList;
    private List<HttpTunnelConfig> httpTunnelConfigList;
    private String remoteAddress;
    private int remotePort;
}
