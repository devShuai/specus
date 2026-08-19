package com.theshuai.common.peermesh;

import lombok.Data;

/**
 * Publisher-only traffic counters carried on {@code service-report}. Never copied into
 * {@code service-catalog}.
 */
@Data
public class PeerServiceStats {
    private String serviceId;
    private long bytesIn;
    private long bytesOut;
    private int activeConnections;
    private long totalConnections;
}
