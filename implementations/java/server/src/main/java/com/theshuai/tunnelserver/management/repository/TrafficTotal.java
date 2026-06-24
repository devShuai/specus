package com.theshuai.tunnelserver.management.repository;

/**
 * 按客户端聚合的上下行流量总量。投影接口，配合 {@link TrafficUsageRepository#sumBytesByTenantId(String)}。
 */
public interface TrafficTotal {
    Long getClientId();

    long getUploadBytes();

    long getDownloadBytes();
}
