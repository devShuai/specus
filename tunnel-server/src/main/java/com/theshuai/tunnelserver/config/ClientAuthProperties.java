package com.theshuai.tunnelserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "tunnel.client-auth")
@Data
public class ClientAuthProperties {
    private int defaultMaxOnlineInstances = 2;
    private int perMachineUserMaxInstances = 1;
    private long tokenTtlSeconds = 28800;
}
