package com.theshuai.specusserver.management.model;

public record TcpTrafficFrameView(
        String id,
        long clientId,
        String clientName,
        int listenPort,
        Long resourceId,
        String resourceName,
        String channelId,
        String direction,
        String remoteAddress,
        String sourceAddress,
        Integer sourcePort,
        String destinationAddress,
        Integer destinationPort,
        long streamOffset,
        long streamEndOffset,
        long frameIndex,
        long payloadBytes,
        String payloadBase64,
        String payloadPreviewHex,
        String payloadPreviewText,
        boolean truncated,
        String frameTime
) {
}
