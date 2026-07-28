package com.theshuai.specusserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "specus.object-storage")
@Data
public class ObjectStorageProperties {
    private String provider = "disabled";
    private String endpoint = "";
    private String region = "";
    private String bucket = "";
    private String accessKeyId = "";
    private String accessKeySecret = "";
    private String objectPrefix = "specus/attachments";
    private String uploadCallbackUrl = "";
    private long uploadUrlTtlSeconds = 900;
    private long downloadUrlTtlSeconds = 600;
    private long downloadObjectUrlTtlSeconds = 30;
    private long retentionHours = 72;
    private long maxAttachmentBytes = 512L * 1024L * 1024L;
    private long perUserStorageQuotaBytes = 1024L * 1024L * 1024L;
    private long perUserMonthlyDownloadQuotaBytes = 1024L * 1024L * 1024L;
}
