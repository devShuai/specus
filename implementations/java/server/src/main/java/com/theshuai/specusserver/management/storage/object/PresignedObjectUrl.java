package com.theshuai.specusserver.management.storage.object;

import java.util.Map;

public record PresignedObjectUrl(
        String url,
        Map<String, String> headers,
        String expiresAt
) {
}
