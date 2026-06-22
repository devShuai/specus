package com.theshuai.common.clientauth;

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
    private int maxOnlineInstances = 2;
    private ClientPolicy policy = new ClientPolicy();
    private List<TunnelEndpoint> tunnelConfigList = new ArrayList<>();
    private List<HttpRouteEndpoint> httpTunnelConfigList = new ArrayList<>();

    @Data
    public static class ClientPolicy {
        private boolean enabled = true;
        private String billingStatus = "ACTIVE";
        private long retryAfterSeconds = 0;
    }

    @Data
    public static class TunnelEndpoint {
        private int port;
        private String tunnelAddress;
        private int tunnelPort;
    }

    @Data
    public static class HttpRouteEndpoint {
        private String route;
        private String targetBaseUrl;
    }
}
