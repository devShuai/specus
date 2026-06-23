package com.theshuai.tunnelserver.management.model;

public record HttpTrafficExchangeView(
        long id,
        long clientId,
        String clientName,
        String route,
        Long resourceId,
        String resourceName,
        String method,
        String relativePath,
        String rawQuery,
        int statusCode,
        boolean success,
        String error,
        String remoteAddress,
        long requestBytes,
        long responseBytes,
        long elapsedMs,
        String requestContentType,
        String responseContentType,
        String responseBodyType,
        String requestHeaders,
        String responseHeaders,
        String requestPreviewHex,
        String requestPreviewText,
        String responsePreviewHex,
        String responsePreviewText,
        boolean requestTruncated,
        boolean responseTruncated,
        String capturedAt
) {
}
