package com.theshuai.common.peermesh;

import lombok.Data;

import java.util.ArrayList;
import java.util.List;

/**
 * Server-authored service definition sent only to the owning client via peer-config.
 * Includes targetHost so the publisher can probe and bind a Peer-only bridge.
 */
@Data
public class LocalPeerService {
    private String serviceId;
    private String name;
    private String description;
    private String transport;
    private String application;
    private String targetHost;
    private int targetPort;
    private int publishedPort;
    private String path;
    private boolean enabled;
    private String visibility;
    /**
     * Server-authored source virtual IP allowlist for the data-plane bridge.
     * An empty list is fail-closed; clients must never infer access from catalog visibility.
     */
    private List<String> allowedPeerVirtualIps = new ArrayList<>();
}
