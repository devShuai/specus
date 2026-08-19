package com.theshuai.common.peermesh;

import lombok.Data;

/**
 * Wire-level advertised peer service. Must not carry targetHost, credentials, URLs or commands.
 */
@Data
public class PeerAdvertisedService {
    private String serviceId;
    private String name;
    private String description;
    private String transport;
    private String application;
    private int publishedPort;
    private String path;
}
