package com.theshuai.common.peermesh;

import lombok.Data;

/**
 * Owner-only mDNS candidate reported on service-report. Never copied into service-catalog.
 */
@Data
public class PeerMdnsCandidate {
    private String name;
    private String transport;
    private String application;
    private String targetHost;
    private int targetPort;
}
