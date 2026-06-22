package com.theshuai.tunnelserver.management.model;

public record TcpTrafficFrameView(
        long id,
        long clientId,
        String clientName,
        int listenPort,
        Long resourceId,
        String resourceName,
        String channelId,
        String direction,
        String remoteAddress,
        long payloadBytes,
        String payloadPreviewHex,
        String payloadPreviewText,
        boolean truncated,
        String frameTime
) {
}
