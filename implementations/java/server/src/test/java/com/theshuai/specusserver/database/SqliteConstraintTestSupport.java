package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.HttpMediaCapture;

/** Shared by the tests that violate a unique index on a real SQLite database. */
final class SqliteConstraintTestSupport {
    private SqliteConstraintTestSupport() {
    }

    static HttpMediaCapture capture(String deduplicationKey) {
        HttpMediaCapture capture = new HttpMediaCapture();
        capture.setTenantId("default");
        capture.setClientId(1L);
        capture.setClientName("client");
        capture.setRoute("media");
        capture.setSourceUrl("https://example.test/video.mp4");
        capture.setResourceKey("resource");
        capture.setDeduplicationKey(deduplicationKey);
        capture.setMethod("GET");
        capture.setStatusCode(206);
        capture.setMediaKind("video");
        capture.setCapturedBytes(0);
        capture.setObjectKey("object");
        capture.setState("STARTING");
        capture.setCapturedAt("2026-10-07T00:00:00Z");
        capture.setExpiresAt("2026-10-08T00:00:00Z");
        return capture;
    }
}
