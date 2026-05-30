package com.theshuai.tunnelclient.bean;

import lombok.Data;

@Data
public class TunnelConfig {
    private int port;
    private String tunnelAddress;
    private int tunnelPort;
}
