package com.theshuai.tunnelserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "tunnel.peer-mesh")
@Data
public class PeerMeshProperties {
    private boolean enabled = false;
    private String cidr = "100.96.0.0/11";
    private String publicAddress = "";
    private int stunTurnPort = 3478;
    private String standaloneStunAddress = "";
    private int standaloneStunPort = 3478;
    private String standaloneStunAlternateAddress = "";
    private int standaloneStunAlternatePort = 0;
    private int natProbeAlternatePort = 3479;
    private String stunPrimaryBindAddress = "";
    private String stunAlternateBindAddress = "";
    private String stunAlternatePublicAddress = "";
    private boolean stunBehaviorStrict = false;
    private List<String> publicStunServers = new ArrayList<>();
    private long sessionTtlSeconds = 3600;
    private long allocationTtlSeconds = 300;
    private int relayMinPort = 49152;
    private int relayMaxPort = 65535;
    private int relayWorkerThreads = 0;
    private int relayWorkerQueueCapacity = 10000;
    private boolean turnAuthRequired = true;
    private String turnRealm = "shuai-tunnel";
    private String turnSharedSecret = "";
    private long turnCredentialTtlSeconds = 3600;
}
