package com.theshuai.tunnelserver.management.model;

public record ConnectionRecordView(
        long id,
        Long clientId,
        String clientName,
        String channelId,
        String remoteAddress,
        String connectedAt,
        String disconnectedAt,
        boolean success,
        String failureReason
) {
}
