package com.theshuai.tunnelclient.bean;

import lombok.Data;

@Data
public class HttpTunnelConfig {
    private String route;
    private String targetBaseUrl;
}
