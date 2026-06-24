package com.theshuai.tunnelserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "tunnel.peer-mesh")
@Data
public class PeerMeshProperties {
    private boolean enabled = false;
    private String cidr = "100.96.0.0/11";
    private String publicAddress = "";
    private int stunTurnPort = 3478;
    private int natProbeAlternatePort = 0;
    private long sessionTtlSeconds = 3600;
    private long allocationTtlSeconds = 300;
}
