package com.theshuai.tunnelserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "tunnel.object-storage")
@Data
public class ObjectStorageProperties {
    private String provider = "disabled";
    private String endpoint = "";
    private String bucket = "";
    private String accessKeyId = "";
    private String accessKeySecret = "";
    private String objectPrefix = "shuai-tunnel/attachments";
    private long uploadUrlTtlSeconds = 900;
    private long downloadUrlTtlSeconds = 600;
    private long retentionHours = 72;
    private long maxAttachmentBytes = 512L * 1024L * 1024L;
}
