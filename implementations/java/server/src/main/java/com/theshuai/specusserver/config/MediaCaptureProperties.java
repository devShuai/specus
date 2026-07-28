package com.theshuai.specusserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "specus.media-capture")
@Data
public class MediaCaptureProperties {
    private boolean enabled;
    private String endpoint = "";
    private String region = "us-east-1";
    private String bucket = "";
    private String accessKeyId = "";
    private String accessKeySecret = "";
    private String objectPrefix = "specus/http-media";
    private boolean pathStyle = true;
    private boolean createBucketIfMissing;
    private long partSizeBytes = 8L * 1024L * 1024L;
    private int maxInflightParts = 4;
    private int uploadThreads = 4;
    private long retentionSeconds = 7L * 24L * 60L * 60L;
    private long liveWindowSeconds = 5L * 60L;
    private long manifestMaxBytes = 16L * 1024L * 1024L;
    private long playbackTicketTtlSeconds = 900;
    private long cleanupIntervalMs = 60_000L;

    public boolean isReady() {
        return enabled
                && hasText(endpoint)
                && hasText(bucket)
                && hasText(accessKeyId)
                && hasText(accessKeySecret);
    }

    public long normalizedPartSizeBytes() {
        return Math.max(5L * 1024L * 1024L, partSizeBytes);
    }

    public int normalizedMaxInflightParts() {
        return Math.max(1, maxInflightParts);
    }

    public int normalizedUploadThreads() {
        return Math.max(1, uploadThreads);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
