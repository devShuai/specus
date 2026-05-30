package com.theshuai.tunnelclient.bean;

import lombok.Data;

import java.util.List;

@Data
public class TunnelBean {
    private String clientName;
    private List<TunnelConfig> tunnelConfigList;
    private String remoteAddress;
    private int remotePort;
}
