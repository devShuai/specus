package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.ClientPackageProperties;
import com.theshuai.specusserver.management.model.ClientDownloadLinkView;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Read-only fallback catalogue backed by the repository's official latest GitHub Release.
 *
 * <p>The API endpoint, repository and accepted asset names are intentionally fixed. Release data is
 * untrusted input: an asset is exposed only when its exact name, GitHub download URL, SHA-256 digest
 * and positive size all agree with the release tag.
 */
@Component
@Slf4j
public class GitHubReleaseCatalog {
    static final URI LATEST_RELEASE_URI = URI.create(
            "https://api.github.com/repos/devShuai/specus/releases/latest");
    private static final int MAX_RESPONSE_CHARACTERS = 1_048_576;
    private static final long MIN_CACHE_SECONDS = 60;
    private static final long MAX_CACHE_SECONDS = 86_400;
    private static final long FAILURE_RETRY_SECONDS = 300;
    private static final int MIN_TIMEOUT_SECONDS = 1;
    private static final int MAX_TIMEOUT_SECONDS = 30;

    private final ClientPackageProperties properties;
    private final HttpClient httpClient;
    private final Clock clock;
    private final ObjectMapper objectMapper;
    private final Object refreshLock = new Object();
    private volatile CachedRelease cache;

    @Autowired
    public GitHubReleaseCatalog(ClientPackageProperties properties) {
        this(properties,
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(clampTimeout(
                                properties.getGithubReleaseRequestTimeoutSeconds())))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build(),
                Clock.systemUTC(),
                new ObjectMapper());
    }

    GitHubReleaseCatalog(ClientPackageProperties properties, HttpClient httpClient, Clock clock,
                         ObjectMapper objectMapper) {
        this.properties = properties;
        this.httpClient = httpClient;
        this.clock = clock;
        this.objectMapper = objectMapper;
    }

    static GitHubReleaseCatalog disabled() {
        ClientPackageProperties properties = new ClientPackageProperties();
        properties.setGithubReleaseFallbackEnabled(false);
        return new GitHubReleaseCatalog(
                properties, HttpClient.newHttpClient(), Clock.systemUTC(), new ObjectMapper());
    }

    boolean maySupplyMissingTarget(Set<String> configuredTargets) {
        return properties.isGithubReleaseFallbackEnabled()
                && descriptors("v0.0.0").stream()
                .map(AssetDescriptor::targetKey)
                .anyMatch(target -> !configuredTargets.contains(target));
    }

    Optional<ReleasePackage> findLatest(String implementation, String platform, String arch) {
        return latestPackages().stream()
                .filter(item -> item.implementation().equals(implementation))
                .filter(item -> item.platform().equals(platform) || item.platform().equals("any"))
                .filter(item -> item.arch().equals(arch) || item.arch().equals("any"))
                .max(Comparator.comparingInt(item -> specificity(item, platform, arch)));
    }

    List<ReleasePackage> latestPackages() {
        if (!properties.isGithubReleaseFallbackEnabled()) {
            return List.of();
        }
        Instant now = clock.instant();
        CachedRelease snapshot = cache;
        if (snapshot != null && now.isBefore(snapshot.refreshAfter())) {
            return snapshot.packages();
        }
        synchronized (refreshLock) {
            now = clock.instant();
            snapshot = cache;
            if (snapshot != null && now.isBefore(snapshot.refreshAfter())) {
                return snapshot.packages();
            }
            try {
                List<ReleasePackage> packages = fetchLatest();
                cache = new CachedRelease(packages, now.plusSeconds(cacheSeconds()));
                return packages;
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                return retainStaleAfterFailure(snapshot, now, "request interrupted", exception);
            } catch (IOException | RuntimeException exception) {
                return retainStaleAfterFailure(snapshot, now, exception.getMessage(), exception);
            }
        }
    }

    private List<ReleasePackage> fetchLatest() throws IOException, InterruptedException {
        int timeoutSeconds = clampTimeout(properties.getGithubReleaseRequestTimeoutSeconds());
        HttpRequest request = HttpRequest.newBuilder(LATEST_RELEASE_URI)
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Accept", "application/vnd.github+json")
                .header("User-Agent", "specus-server")
                .header("X-GitHub-Api-Version", "2022-11-28")
                .GET()
                .build();
        HttpResponse<String> response = httpClient.send(
                request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IOException("GitHub Releases returned HTTP " + response.statusCode());
        }
        String body = response.body();
        if (body == null || body.isBlank() || body.length() > MAX_RESPONSE_CHARACTERS) {
            throw new IOException("GitHub Release response is empty or too large");
        }
        List<ReleasePackage> packages = mapRelease(objectMapper.readTree(body));
        if (packages.isEmpty()) {
            throw new IOException("latest GitHub Release has no trusted client assets");
        }
        return packages;
    }

    private List<ReleasePackage> retainStaleAfterFailure(CachedRelease previous, Instant now,
                                                          String reason, Exception exception) {
        List<ReleasePackage> stale = previous == null ? List.of() : previous.packages();
        cache = new CachedRelease(stale, now.plusSeconds(FAILURE_RETRY_SECONDS));
        log.warn("[client-update] GitHub Release fallback refresh failed; serving {} cached assets: {}",
                stale.size(), reason, exception);
        return stale;
    }

    private long cacheSeconds() {
        return Math.max(MIN_CACHE_SECONDS,
                Math.min(MAX_CACHE_SECONDS, properties.getGithubReleaseCacheSeconds()));
    }

    private static int clampTimeout(int value) {
        return Math.max(MIN_TIMEOUT_SECONDS, Math.min(MAX_TIMEOUT_SECONDS, value));
    }

    static List<ReleasePackage> mapRelease(JsonNode release) {
        if (release == null || !release.isObject()) {
            return List.of();
        }
        String tagName = text(release, "tag_name");
        String version;
        try {
            SemanticVersion.parse(tagName, "release tag");
            version = SemanticVersion.normalize(tagName);
        } catch (IllegalArgumentException exception) {
            return List.of();
        }
        JsonNode assets = release.path("assets");
        if (!assets.isArray()) {
            return List.of();
        }
        Map<String, JsonNode> assetsByName = new HashMap<>();
        for (JsonNode asset : assets) {
            String name = text(asset, "name");
            if (!name.isEmpty()) {
                assetsByName.put(name, asset);
            }
        }

        String releaseTimestamp = firstNonBlank(
                text(release, "published_at"), text(release, "created_at"));
        String changelogUrl = "https://github.com/devShuai/specus/releases/tag/" + tagName;
        List<ReleasePackage> packages = new ArrayList<>();
        for (AssetDescriptor descriptor : descriptors(tagName)) {
            JsonNode asset = assetsByName.get(descriptor.assetName());
            if (asset == null || !asset.path("id").canConvertToLong()
                    || !asset.path("size").canConvertToLong()) {
                continue;
            }
            long id = asset.path("id").longValue();
            long size = asset.path("size").longValue();
            String downloadUrl = text(asset, "browser_download_url");
            String digest = normalizeDigest(text(asset, "digest"));
            if (id <= 0 || size <= 0 || digest == null
                    || !isExpectedAssetUrl(downloadUrl, tagName, descriptor.assetName())) {
                continue;
            }
            String createdAt = firstNonBlank(text(asset, "created_at"), releaseTimestamp);
            String updatedAt = firstNonBlank(text(asset, "updated_at"), releaseTimestamp);
            packages.add(new ReleasePackage(
                    id,
                    descriptor.implementation(),
                    descriptor.platform(),
                    descriptor.arch(),
                    descriptor.displayName(),
                    downloadUrl,
                    descriptor.description(),
                    descriptor.displayOrder(),
                    version,
                    digest,
                    size,
                    changelogUrl,
                    createdAt,
                    updatedAt));
        }
        return List.copyOf(packages);
    }

    private static boolean isExpectedAssetUrl(String value, String tagName, String assetName) {
        try {
            URI uri = URI.create(value);
            String expectedPath = "/devshuai/specus/releases/download/" + tagName + "/" + assetName;
            return "https".equalsIgnoreCase(uri.getScheme())
                    && "github.com".equalsIgnoreCase(uri.getHost())
                    && uri.getPort() == -1
                    && uri.getUserInfo() == null
                    && uri.getQuery() == null
                    && uri.getFragment() == null
                    && expectedPath.equalsIgnoreCase(uri.getPath());
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    private static String normalizeDigest(String value) {
        String digest = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        if (digest.startsWith("sha256:")) {
            digest = digest.substring("sha256:".length());
        }
        return digest.matches("[0-9a-f]{64}") ? digest : null;
    }

    private static String text(JsonNode node, String name) {
        JsonNode value = node == null ? null : node.get(name);
        return value != null && value.isTextual() ? value.textValue().trim() : "";
    }

    private static String firstNonBlank(String first, String second) {
        return first != null && !first.isBlank() ? first : second;
    }

    private static int specificity(ReleasePackage item, String platform, String arch) {
        return (item.platform().equals(platform) ? 2 : 0)
                + (item.arch().equals(arch) ? 1 : 0);
    }

    private static List<AssetDescriptor> descriptors(String tagName) {
        List<AssetDescriptor> descriptors = new ArrayList<>();
        descriptors.add(new AssetDescriptor(
                "specus-client-java-" + tagName + ".jar",
                "java", "any", "any", "Java 21 可执行 JAR",
                "适用于已安装 JDK 21 或更高版本的系统。", 200));
        String[][] goTargets = {
                {"macos", "arm64", "macOS Apple Silicon"},
                {"macos", "x64", "macOS Intel"},
                {"windows", "x64", "Windows x86_64"},
                {"windows", "arm64", "Windows ARM64"},
                {"linux", "x64", "Linux x86_64"},
                {"linux", "arm64", "Linux ARM64"}
        };
        for (int index = 0; index < goTargets.length; index++) {
            String platform = goTargets[index][0];
            String arch = goTargets[index][1];
            String extension = platform.equals("windows") ? "zip" : "tar.gz";
            descriptors.add(new AssetDescriptor(
                    "specus-client-go-" + tagName + "-" + platform + "-" + arch + "." + extension,
                    "go", platform, arch, goTargets[index][2],
                    "静态单文件客户端，无需安装运行时。", 100 + index));
        }
        descriptors.add(new AssetDescriptor(
                "specus-desktop-" + tagName + "-win-x64.zip",
                "csharp", "windows", "x64", "Windows 桌面版",
                "自包含图形客户端，无需单独安装 .NET Runtime。", 300));
        descriptors.add(new AssetDescriptor(
                "specus-client-csharp-" + tagName + ".tar.gz",
                "csharp", "any", "any", ".NET 命令行客户端",
                "跨平台程序集，需要 .NET 10 Runtime。", 310));
        descriptors.add(new AssetDescriptor(
                "specus-client-android-" + tagName + ".apk",
                "android", "android", "any", "Android 应用",
                "适用于 Android 8.0 或更高版本。", 400));
        return descriptors;
    }

    record ReleasePackage(
            long id,
            String implementation,
            String platform,
            String arch,
            String displayName,
            String downloadUrl,
            String description,
            int displayOrder,
            String version,
            String sha256,
            long fileSize,
            String changelogUrl,
            String createdAt,
            String updatedAt
    ) {
        String targetKey() {
            return implementation + "|" + platform + "|" + arch;
        }

        ClientDownloadLinkView toView() {
            return new ClientDownloadLinkView(
                    id, implementation, platform, arch, displayName, downloadUrl, description,
                    displayOrder, true, version, sha256, fileSize, true, changelogUrl, null,
                    false, null, createdAt, updatedAt);
        }
    }

    private record AssetDescriptor(
            String assetName,
            String implementation,
            String platform,
            String arch,
            String displayName,
            String description,
            int displayOrder
    ) {
        String targetKey() {
            return implementation + "|" + platform + "|" + arch;
        }
    }

    private record CachedRelease(List<ReleasePackage> packages, Instant refreshAfter) {
    }
}
