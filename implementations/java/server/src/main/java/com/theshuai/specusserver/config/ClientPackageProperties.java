package com.theshuai.specusserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** Configuration for the public client package catalogue and local package store. */
@Component
@ConfigurationProperties(prefix = "specus.client-packages")
@Data
public class ClientPackageProperties {
    /** Parent data directory. Package bytes are always stored in its {@code packages} child. */
    private String dataDirectory = "./data";

    /** Hard server-side streaming limit; independent from servlet multipart limits. */
    private long maxPackageBytes = 536_870_912L;

    /** Per-source request budget shared by public catalogue, version check and package download. */
    private int publicRateLimitPerIp = 120;

    private long publicRateLimitWindowSeconds = 60;

    /** Use the official GitHub latest Release when no local catalogue entry owns a target. */
    private boolean githubReleaseFallbackEnabled = true;

    /** Successful Release metadata is cached to stay well below GitHub's anonymous API limit. */
    private long githubReleaseCacheSeconds = 1_800;

    /** End-to-end timeout for one GitHub Release metadata request. */
    private int githubReleaseRequestTimeoutSeconds = 8;
}
