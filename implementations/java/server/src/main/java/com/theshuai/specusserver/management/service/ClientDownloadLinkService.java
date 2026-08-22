package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientDownloadLink;
import com.theshuai.specusserver.management.model.ClientDownloadLinkView;
import com.theshuai.specusserver.management.repository.ClientDownloadLinkRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 客户端下载编目的 CRUD 与版本查询服务。
 *
 * <p>一条记录既是下载页展示项，也是升级编目条目：{@code downloadUrl} 可以直接指向 GitHub Release
 * 资产，也可以指向本服务端托管的包（{@code hosted=true}）。
 *
 * <p>两个唯一约束通过派生列实现，避免依赖各数据库方言的部分索引：
 * <ul>
 *   <li>{@code catalogKey = implementation|platform|arch|version}：同一目标的同一版本只登记一次</li>
 *   <li>{@code latestSlot = implementation|platform|arch}：仅在标记为最新时写入，因此每个目标
 *       至多有一条“最新”</li>
 * </ul>
 */
@Service
@Slf4j
public class ClientDownloadLinkService {
    public static final Set<String> ALLOWED_IMPLEMENTATIONS = Set.of("java", "go", "csharp", "android");
    public static final Set<String> ALLOWED_PLATFORMS = Set.of("windows", "linux", "macos", "android", "any");
    public static final Set<String> ALLOWED_ARCHES = Set.of("x64", "arm64", "any");

    private final ClientDownloadLinkRepository repository;
    private final ClientPackageStorage storage;
    private final TransactionTemplate transactions;
    private final GitHubReleaseCatalog githubReleaseCatalog;

    public ClientDownloadLinkService(ClientDownloadLinkRepository repository,
                                     ClientPackageStorage storage,
                                     PlatformTransactionManager transactionManager) {
        this(repository, storage, transactionManager, GitHubReleaseCatalog.disabled());
    }

    @Autowired
    public ClientDownloadLinkService(ClientDownloadLinkRepository repository,
                                     ClientPackageStorage storage,
                                     PlatformTransactionManager transactionManager,
                                     GitHubReleaseCatalog githubReleaseCatalog) {
        this.repository = repository;
        this.storage = storage;
        this.transactions = new TransactionTemplate(transactionManager);
        this.githubReleaseCatalog = githubReleaseCatalog;
    }

    @Transactional(readOnly = true)
    public List<ClientDownloadLinkView> listAll() {
        return repository.findAllByOrderByDisplayOrderAscIdAsc().stream().map(this::toView).toList();
    }

    public List<ClientDownloadLinkView> listEnabled() {
        List<ClientDownloadLink> catalogue = repository
                .findAllByOrderByImplementationAscDisplayOrderAscIdAsc();
        Set<String> configuredTargets = catalogue.stream()
                .map(this::targetKey)
                .collect(java.util.stream.Collectors.toSet());
        Set<String> versionedTargets = catalogue.stream()
                .filter(row -> StringUtils.hasText(row.getVersion()))
                .map(this::targetKey)
                .collect(java.util.stream.Collectors.toSet());
        List<ClientDownloadLinkView> configured = catalogue.stream()
                .filter(ClientDownloadLink::isEnabled)
                .filter(row -> versionedTargets.contains(targetKey(row))
                        ? Boolean.TRUE.equals(row.getLatest())
                        : !StringUtils.hasText(row.getVersion()))
                .map(this::toView)
                .toList();
        if (!githubReleaseCatalog.maySupplyMissingTarget(configuredTargets)) {
            return configured;
        }
        List<ClientDownloadLinkView> merged = new ArrayList<>(configured);
        githubReleaseCatalog.latestPackages().stream()
                .filter(item -> !configuredTargets.contains(item.targetKey()))
                .map(GitHubReleaseCatalog.ReleasePackage::toView)
                .forEach(merged::add);
        merged.sort(Comparator
                .comparingInt(ClientDownloadLinkView::displayOrder)
                .thenComparing(ClientDownloadLinkView::id));
        return List.copyOf(merged);
    }

    @Transactional
    public ClientDownloadLinkView create(LinkMutation request) {
        if (request == null) {
            throw new IllegalArgumentException("request cannot be null");
        }
        String now = Instant.now().toString();
        ClientDownloadLink row = new ClientDownloadLink();
        row.setId(ClientIdGenerator.newId());
        row.setCreatedAt(now);
        apply(row, request, true);
        row.setUpdatedAt(now);
        return toView(repository.saveAndFlush(row));
    }

    @Transactional
    public ClientDownloadLinkView update(long id, LinkMutation request) {
        if (request == null) {
            throw new IllegalArgumentException("request cannot be null");
        }
        ClientDownloadLink row = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client download link not found: " + id));
        apply(row, request, false);
        row.setUpdatedAt(Instant.now().toString());
        return toView(repository.saveAndFlush(row));
    }

    @Transactional
    public void delete(long id) {
        ClientDownloadLink row = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client download link not found: " + id));
        Path quarantine = Boolean.TRUE.equals(row.getHosted())
                ? storage.quarantine(id).orElse(null)
                : null;
        if (quarantine != null) {
            try {
                afterCompletion(status -> {
                    if (status == TransactionSynchronization.STATUS_COMMITTED) {
                        storage.deleteQuietly(quarantine);
                    } else {
                        storage.restore(quarantine, id);
                    }
                });
            } catch (RuntimeException exception) {
                storage.restore(quarantine, id);
                throw exception;
            }
        }
        repository.delete(row);
        repository.flush();
    }

    /** 把一条记录标记为其目标的最新版本；同目标其它记录的标记会被清除，因此该操作幂等。 */
    @Transactional
    public ClientDownloadLinkView markLatest(long id) {
        ClientDownloadLink row = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client download link not found: " + id));
        if (!StringUtils.hasText(row.getVersion())) {
            throw new IllegalArgumentException("client download link has no version: " + id);
        }
        String version = requireVersion(row.getVersion());
        String minSupportedVersion = normalizeOptionalVersion(row.getMinSupportedVersion());
        validateMinSupportedVersion(minSupportedVersion, version);
        if (!row.isEnabled()) {
            throw new IllegalArgumentException("a disabled client download cannot be latest");
        }
        if (!Boolean.TRUE.equals(row.getHosted()) && !hasAuthoritativeDistributionMetadata(row)) {
            throw new IllegalArgumentException(
                    "an external latest download requires HTTPS, sha256 and a positive fileSize");
        }
        repository.clearLatest(row.getImplementation(), row.getPlatform(), row.getArch());
        repository.flush();
        row.setVersion(version);
        row.setMinSupportedVersion(minSupportedVersion);
        row.setCatalogKey(catalogKey(
                row.getImplementation(), row.getPlatform(), row.getArch(), version, row.getId()));
        row.setLatest(true);
        row.setLatestSlot(latestSlot(row.getImplementation(), row.getPlatform(), row.getArch()));
        row.setUpdatedAt(Instant.now().toString());
        return toView(repository.saveAndFlush(row));
    }

    /**
     * 版本比较收敛在服务端。没有可用编目、或编目版本无法解析时一律返回“无更新”，
     * 而不是把一个不可比较的版本号丢给客户端自己判断。
     */
    public VersionCheckView checkVersion(String implementation, String platform, String arch,
                                               String currentVersion) {
        String normalizedImplementation = requireImplementation(implementation);
        String normalizedPlatform = requirePlatform(platform);
        String normalizedArch = requireArch(arch);
        validateTargetCoordinates(normalizedImplementation, normalizedPlatform, normalizedArch);
        SemanticVersion current = SemanticVersion.parse(currentVersion, "current");

        List<ClientDownloadLink> candidates = repository
                .findByImplementationAndPlatformInAndArchInAndEnabledTrue(
                        normalizedImplementation,
                        fallbackValues(normalizedPlatform),
                        fallbackValues(normalizedArch)).stream()
                // A version is publishable only after an administrator explicitly marks it latest.
                // Falling back to the highest unmarked upload would silently release staged builds
                // after the published package is deleted or has its latest flag cleared.
                .filter(row -> Boolean.TRUE.equals(row.getLatest()))
                .filter(this::hasAuthoritativeDistributionMetadata)
                .filter(row -> safeVersion(row).isPresent())
                .toList();
        ClientDownloadLink latest = candidates.stream()
                .max(Comparator
                        .comparingInt((ClientDownloadLink row) -> specificity(
                                row, normalizedPlatform, normalizedArch))
                        .thenComparing(row -> safeVersion(row).orElseThrow()))
                .orElse(null);
        if (latest == null) {
            boolean configuredTarget = repository.existsByImplementationAndPlatformInAndArchIn(
                    normalizedImplementation,
                    fallbackValues(normalizedPlatform),
                    fallbackValues(normalizedArch));
            if (configuredTarget) {
                return VersionCheckView.none();
            }
            return githubReleaseCatalog
                    .findLatest(normalizedImplementation, normalizedPlatform, normalizedArch)
                    .map(item -> releaseVersionCheck(current, item))
                    .orElseGet(VersionCheckView::none);
        }
        SemanticVersion latestVersion;
        try {
            latestVersion = SemanticVersion.parse(latest.getVersion(), "version");
        } catch (IllegalArgumentException e) {
            log.warn("[client-update] catalogue version is unparseable, reporting no update: id={}, version={}",
                    latest.getId(), latest.getVersion());
            return VersionCheckView.none();
        }
        boolean updateAvailable = latestVersion.compareTo(current) > 0;
        boolean mandatory = false;
        if (updateAvailable && StringUtils.hasText(latest.getMinSupportedVersion())) {
            try {
                mandatory = current.compareTo(
                        SemanticVersion.parse(latest.getMinSupportedVersion(), "minSupportedVersion")) < 0;
            } catch (IllegalArgumentException e) {
                log.warn("[client-update] minSupportedVersion is unparseable, not enforcing: id={}, value={}",
                        latest.getId(), latest.getMinSupportedVersion());
            }
        }
        return new VersionCheckView(
                updateAvailable,
                mandatory,
                SemanticVersion.normalize(latest.getVersion()),
                latest.getDownloadUrl(),
                latest.getSha256(),
                latest.getFileSize() == null ? 0L : latest.getFileSize(),
                latest.getChangelogUrl(),
                Boolean.TRUE.equals(latest.getHosted()) ? latest.getId() : null);
    }

    private VersionCheckView releaseVersionCheck(SemanticVersion current,
                                                  GitHubReleaseCatalog.ReleasePackage latest) {
        SemanticVersion release = SemanticVersion.parse(latest.version(), "release version");
        return new VersionCheckView(
                release.compareTo(current) > 0,
                false,
                latest.version(),
                latest.downloadUrl(),
                latest.sha256(),
                latest.fileSize(),
                latest.changelogUrl(),
                null);
    }

    private List<String> fallbackValues(String requested) {
        LinkedHashSet<String> values = new LinkedHashSet<>();
        values.add(requested);
        values.add("any");
        return List.copyOf(values);
    }

    private int specificity(ClientDownloadLink row, String requestedPlatform, String requestedArch) {
        return (row.getPlatform().equals(requestedPlatform) ? 2 : 0)
                + (row.getArch().equals(requestedArch) ? 1 : 0);
    }

    private Optional<SemanticVersion> safeVersion(ClientDownloadLink row) {
        try {
            return Optional.of(SemanticVersion.parse(row.getVersion(), "catalog version"));
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }
    }

    private boolean hasAuthoritativeDistributionMetadata(ClientDownloadLink row) {
        if (row.getFileSize() == null || row.getFileSize() <= 0
                || row.getSha256() == null || !row.getSha256().matches("[0-9a-f]{64}")) {
            return false;
        }
        if (Boolean.TRUE.equals(row.getHosted())) {
            return row.getId() != null && hostedDownloadUrl(row.getId()).equals(row.getDownloadUrl());
        }
        return isSafeExternalPackageUrl(row.getDownloadUrl());
    }

    private boolean isSafeExternalPackageUrl(String value) {
        if (!StringUtils.hasText(value)) {
            return false;
        }
        try {
            URI uri = new URI(value.trim());
            return uri.isAbsolute()
                    && "https".equalsIgnoreCase(uri.getScheme())
                    && StringUtils.hasText(uri.getHost())
                    && uri.getUserInfo() == null
                    && uri.getRawQuery() == null
                    && uri.getRawFragment() == null;
        } catch (URISyntaxException exception) {
            return false;
        }
    }

    private void apply(ClientDownloadLink row, LinkMutation request, boolean creating) {
        String implementation = requireImplementation(request.implementation());
        String platform = requirePlatform(request.platform());
        String arch = requireArch(request.arch());
        validateTargetCoordinates(implementation, platform, arch);
        row.setImplementation(implementation);
        row.setPlatform(platform);
        row.setArch(arch);
        row.setDisplayName(requireDisplayName(request.displayName()));
        if (creating || !Boolean.TRUE.equals(row.getHosted())) {
            row.setDownloadUrl(requireDownloadUrl(request.downloadUrl()));
        }
        row.setDescription(normalizeDescription(request.description()));
        if (creating || request.version() != null) {
            row.setVersion(normalizeOptionalVersion(request.version()));
        }
        if (creating || (!Boolean.TRUE.equals(row.getHosted()) && request.sha256() != null)) {
            row.setSha256(normalizeSha256(request.sha256()));
        }
        if (creating || (!Boolean.TRUE.equals(row.getHosted()) && request.fileSize() != null)) {
            row.setFileSize(normalizeFileSize(request.fileSize()));
        }
        if (creating || request.changelogUrl() != null) {
            row.setChangelogUrl(normalizeOptionalUrl(request.changelogUrl(), "changelogUrl"));
        }
        if (creating || request.minSupportedVersion() != null) {
            row.setMinSupportedVersion(normalizeOptionalVersion(request.minSupportedVersion()));
        }
        validateMinSupportedVersion(row.getMinSupportedVersion(), row.getVersion());
        row.setCatalogKey(catalogKey(implementation, platform, arch, row.getVersion(), row.getId()));
        if (creating || request.displayOrder() != null) {
            row.setDisplayOrder(request.displayOrder() == null ? 0 : request.displayOrder());
        }
        if (creating || request.enabled() != null) {
            row.setEnabled(request.enabled() == null || request.enabled());
        }
        if (row.getHosted() == null) {
            row.setHosted(false);
        }
        boolean latest = request.isLatest() != null
                ? request.isLatest()
                : Boolean.TRUE.equals(row.getLatest());
        if (latest && !StringUtils.hasText(row.getVersion())) {
            throw new IllegalArgumentException("isLatest requires a versioned catalogue entry");
        }
        if (latest && !row.isEnabled()) {
            throw new IllegalArgumentException("a disabled client download cannot be latest");
        }
        if (latest && !Boolean.TRUE.equals(row.getHosted())
                && !hasAuthoritativeDistributionMetadata(row)) {
            throw new IllegalArgumentException(
                    "an external latest download requires HTTPS, sha256 and a positive fileSize");
        }
        if (latest) {
            // Clear first so "at most one latest per target" still holds when the caller flips the
            // flag onto a different row of the same target.
            repository.clearLatest(implementation, platform, arch);
            repository.flush();
        }
        row.setLatest(latest);
        row.setLatestSlot(latest ? latestSlot(implementation, platform, arch) : null);
    }

    private static String catalogKey(String implementation, String platform, String arch,
                                     String version, long id) {
        return implementation + "|" + platform + "|" + arch + "|"
                + (StringUtils.hasText(version) ? version : "legacy:" + Long.toUnsignedString(id));
    }

    private static String latestSlot(String implementation, String platform, String arch) {
        return implementation + "|" + platform + "|" + arch;
    }

    private String requireImplementation(String value) {
        String normalized = lower(value);
        if (!ALLOWED_IMPLEMENTATIONS.contains(normalized)) {
            throw new IllegalArgumentException("implementation must be one of " + ALLOWED_IMPLEMENTATIONS);
        }
        return normalized;
    }

    private String requirePlatform(String value) {
        String normalized = lower(value);
        if (!ALLOWED_PLATFORMS.contains(normalized)) {
            throw new IllegalArgumentException("platform must be one of " + ALLOWED_PLATFORMS);
        }
        return normalized;
    }

    private String requireArch(String value) {
        String normalized = lower(value);
        if (!ALLOWED_ARCHES.contains(normalized)) {
            throw new IllegalArgumentException("arch must be one of " + ALLOWED_ARCHES);
        }
        return normalized;
    }

    private String requireDisplayName(String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("displayName cannot be blank");
        }
        String trimmed = value.trim();
        if (trimmed.length() > 120) {
            throw new IllegalArgumentException("displayName is too long (max 120)");
        }
        if (trimmed.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("displayName cannot contain control characters");
        }
        return trimmed;
    }

    private String requireVersion(String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("version cannot be blank");
        }
        String normalized = SemanticVersion.normalize(value);
        if (normalized.length() > 32) {
            throw new IllegalArgumentException("version is too long (max 32)");
        }
        SemanticVersion.parse(normalized, "version");
        return normalized;
    }

    private void validateTargetCoordinates(String implementation, String platform, String arch) {
        if ("android".equals(implementation)
                && (!"android".equals(platform) || !"any".equals(arch))) {
            throw new IllegalArgumentException("android packages must use platform=android and arch=any");
        }
        if ("android".equals(platform)
                && (!"android".equals(implementation) || !"any".equals(arch))) {
            throw new IllegalArgumentException("platform=android is reserved for android/any packages");
        }
    }

    private String normalizeOptionalVersion(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String normalized = SemanticVersion.normalize(value);
        if (normalized.length() > 32) {
            throw new IllegalArgumentException("minSupportedVersion is too long (max 32)");
        }
        SemanticVersion.parse(normalized, "minSupportedVersion");
        return normalized;
    }

    private void validateMinSupportedVersion(String minimum, String releaseVersion) {
        if (!StringUtils.hasText(minimum)) {
            return;
        }
        if (!StringUtils.hasText(releaseVersion)) {
            throw new IllegalArgumentException("minSupportedVersion requires version");
        }
        SemanticVersion min = SemanticVersion.parse(minimum, "minSupportedVersion");
        SemanticVersion release = SemanticVersion.parse(releaseVersion, "version");
        if (min.compareTo(release) > 0) {
            throw new IllegalArgumentException("minSupportedVersion cannot be newer than version");
        }
    }

    private String normalizeSha256(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String trimmed = value.trim().toLowerCase(Locale.ROOT);
        if (!trimmed.matches("[0-9a-f]{64}")) {
            throw new IllegalArgumentException("sha256 must be 64 lowercase hex characters");
        }
        return trimmed;
    }

    private Long normalizeFileSize(Long value) {
        if (value == null) {
            return null;
        }
        if (value < 0) {
            throw new IllegalArgumentException("fileSize cannot be negative");
        }
        return value;
    }

    private String requireDownloadUrl(String value) {
        return requireHttpUrl(value, "downloadUrl", true);
    }

    private String normalizeOptionalUrl(String value, String fieldName) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        return requireHttpUrl(value, fieldName, false);
    }

    private String requireHttpUrl(String value, String fieldName, boolean allowRelative) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException(fieldName + " cannot be blank");
        }
        String trimmed = value.trim();
        if (trimmed.length() > 1024 || trimmed.indexOf('\\') >= 0
                || trimmed.chars().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException(fieldName + " is too long (max 1024)");
        }
        try {
            URI uri = new URI(trimmed);
            // A hosted package points at this server's own same-origin download endpoint.
            if (allowRelative && !uri.isAbsolute()) {
                String rawPath = uri.getRawPath();
                String lowerPath = rawPath == null ? "" : rawPath.toLowerCase(Locale.ROOT);
                if (!trimmed.startsWith("/") || trimmed.startsWith("//")
                        || uri.getRawAuthority() != null || rawPath == null
                        || List.of(rawPath.split("/")).contains("..")
                        || lowerPath.contains("%2e")) {
                    throw new IllegalArgumentException(fieldName + " must be a safe root-relative path");
                }
                return trimmed;
            }
            String scheme = uri.getScheme();
            if (!uri.isAbsolute() || scheme == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                throw new IllegalArgumentException(fieldName + " must be an absolute http(s) URL");
            }
            if (!StringUtils.hasText(uri.getHost())) {
                throw new IllegalArgumentException(fieldName + " must contain a host");
            }
            if (uri.getUserInfo() != null) {
                throw new IllegalArgumentException(fieldName + " cannot contain user information");
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(fieldName + " is not a valid URI: " + e.getMessage());
        }
        return trimmed;
    }

    private String normalizeDescription(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() > 512 ? trimmed.substring(0, 512) : trimmed;
    }

    private String lower(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    ClientDownloadLinkView toView(ClientDownloadLink row) {
        boolean hosted = Boolean.TRUE.equals(row.getHosted());
        return new ClientDownloadLinkView(
                row.getId(),
                row.getImplementation(),
                row.getPlatform(),
                row.getArch(),
                row.getDisplayName(),
                row.getDownloadUrl(),
                row.getDescription(),
                row.getDisplayOrder(),
                row.isEnabled(),
                row.getVersion(),
                row.getSha256(),
                row.getFileSize() == null ? 0L : row.getFileSize(),
                Boolean.TRUE.equals(row.getLatest()),
                row.getChangelogUrl(),
                row.getMinSupportedVersion(),
                hosted,
                hosted ? row.getId() : null,
                row.getCreatedAt(),
                row.getUpdatedAt()
        );
    }


    /**
     * 接收上传的发布产物：先落盘到暂存区并计算 SHA-256 与实际字节数，登记成功后再发布到最终路径。
     *
     * <p>失败时暂存文件会被删除；数据库写入失败时已发布的文件会被回滚删除，避免留下无编目的孤儿包。
     */
    public ClientDownloadLinkView upload(InputStream source, long declaredSize, PackageUpload metadata) {
        // Validate all small metadata before accepting and hashing a potentially large stream.
        validatePackageMetadata(metadata);
        ClientPackageStorage.StagedPackage staged = storage.stage(source, declaredSize);
        AtomicReference<ClientDownloadLinkView> result = new AtomicReference<>();
        try {
            transactions.executeWithoutResult(status -> {
                long packageId = ClientIdGenerator.newId();
                String now = Instant.now().toString();
                ClientDownloadLink row = new ClientDownloadLink();
                row.setId(packageId);
                row.setCreatedAt(now);
                row.setHosted(true);
                apply(row, new LinkMutation(
                        metadata.implementation(),
                        metadata.platform(),
                        metadata.arch(),
                        metadata.displayName(),
                        hostedDownloadUrl(packageId),
                        metadata.description(),
                        metadata.displayOrder(),
                        metadata.enabled(),
                        metadata.version(),
                        staged.sha256(),
                        staged.fileSize(),
                        metadata.isLatest(),
                        metadata.changelogUrl(),
                        metadata.minSupportedVersion()), true);
                row.setUpdatedAt(now);
                repository.saveAndFlush(row);
                Path published = storage.publish(staged, packageId);
                try {
                    afterCompletion(completion -> {
                        if (completion != TransactionSynchronization.STATUS_COMMITTED) {
                            storage.deleteQuietly(published);
                        }
                    });
                } catch (RuntimeException exception) {
                    storage.deleteQuietly(published);
                    throw exception;
                }
                result.set(toView(row));
            });
            return result.get();
        } finally {
            storage.deleteQuietly(staged.path());
        }
    }

    private String targetKey(ClientDownloadLink row) {
        return latestSlot(row.getImplementation(), row.getPlatform(), row.getArch());
    }

    private void validatePackageMetadata(PackageUpload metadata) {
        if (metadata == null) {
            throw new IllegalArgumentException("package metadata cannot be null");
        }
        if (Boolean.FALSE.equals(metadata.enabled()) && Boolean.TRUE.equals(metadata.isLatest())) {
            throw new IllegalArgumentException("a disabled client download cannot be latest");
        }
        String releaseVersion = requireVersion(metadata.version());
        requireImplementation(metadata.implementation());
        requirePlatform(metadata.platform());
        requireArch(metadata.arch());
        requireDisplayName(metadata.displayName());
        normalizeOptionalUrl(metadata.changelogUrl(), "changelogUrl");
        validateMinSupportedVersion(metadata.minSupportedVersion(), releaseVersion);
    }

    private void afterCompletion(java.util.function.IntConsumer consumer) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            throw new IllegalStateException("package mutation requires an active transaction");
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                consumer.accept(status);
            }
        });
    }

    /** 解析一个可公开下载的托管包；未启用、非托管或文件缺失都视为不存在。 */
    @Transactional(readOnly = true)
    public DownloadablePackage downloadable(long id) {
        ClientDownloadLink row = repository.findByIdAndEnabledTrueAndHostedTrue(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "client package not found"));
        Path path;
        try {
            path = storage.requireReadable(id);
        } catch (IllegalArgumentException exception) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "client package not found");
        }
        return new DownloadablePackage(
                path,
                downloadFileName(row),
                row.getFileSize() == null ? 0L : row.getFileSize(),
                row.getSha256());
    }

    private String downloadFileName(ClientDownloadLink row) {
        String fallback = "specus-client-" + row.getId();
        String source = StringUtils.hasText(row.getDisplayName()) ? row.getDisplayName().trim() : fallback;
        StringBuilder safe = new StringBuilder(Math.min(160, source.length() + 4));
        for (int index = 0; index < source.length() && safe.length() < 160; index++) {
            char character = source.charAt(index);
            if (Character.isISOControl(character)) {
                continue;
            }
            safe.append("\\/:*?\"<>|".indexOf(character) >= 0 ? '_' : character);
        }
        String fileName = safe.toString().trim();
        while (fileName.endsWith(".")) {
            fileName = fileName.substring(0, fileName.length() - 1).trim();
        }
        if (!StringUtils.hasText(fileName)) {
            fileName = fallback;
        }
        boolean universalAndroidApk = "android".equals(row.getImplementation())
                && "android".equals(row.getPlatform())
                && "any".equals(row.getArch());
        if (universalAndroidApk && !fileName.toLowerCase(Locale.ROOT).endsWith(".apk")) {
            fileName += ".apk";
        }
        return fileName;
    }

    private static String hostedDownloadUrl(long packageId) {
        return "/api/public/client-packages/" + packageId + "/download";
    }

    /** 托管包的上传元数据；文件本身的大小与摘要由服务端计算，不接受调用方声明。 */
    public record PackageUpload(
            String implementation,
            String platform,
            String arch,
            String version,
            String displayName,
            String description,
            String changelogUrl,
            String minSupportedVersion,
            Integer displayOrder,
            Boolean enabled,
            Boolean isLatest
    ) {
    }

    /** 下载所需的最小信息；路径已校验位于包目录内。 */
    public record DownloadablePackage(Path path, String fileName, long fileSize, String sha256) {
    }

    /**
     * 版本检查结果。版本比较收敛在服务端，客户端只上报自己的目标三元组与当前版本；
     * 没有可用编目时返回 {@link #none()}，客户端据此静默跳过本次检查。
     */
    public record VersionCheckView(
            boolean updateAvailable,
            boolean mandatory,
            String latestVersion,
            String downloadUrl,
            String sha256,
            long fileSize,
            String changelogUrl,
            Long packageId
    ) {
        public static VersionCheckView none() {
            return new VersionCheckView(false, false, null, null, null, 0L, null, null);
        }
    }

    public record LinkMutation(
            String implementation,
            String platform,
            String arch,
            String displayName,
            String downloadUrl,
            String description,
            Integer displayOrder,
            Boolean enabled,
            String version,
            String sha256,
            Long fileSize,
            Boolean isLatest,
            String changelogUrl,
            String minSupportedVersion
    ) {
    }
}
