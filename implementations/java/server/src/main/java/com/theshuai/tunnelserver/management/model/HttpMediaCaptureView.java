package com.theshuai.tunnelserver.management.model;

public record HttpMediaCaptureView(
        long id,
        long clientId,
        String clientName,
        String route,
        Long resourceId,
        String sourceUrl,
        String method,
        int statusCode,
        String contentType,
        String mediaKind,
        String entityTag,
        Long contentRangeStart,
        Long contentRangeEnd,
        Long totalBytes,
        long capturedBytes,
        Long segmentSequence,
        boolean initializationSegment,
        boolean liveStream,
        String state,
        String failureReason,
        boolean playable,
        boolean offlineReady,
        String playbackMessage,
        String capturedAt,
        String completedAt,
        String expiresAt
) {
}
