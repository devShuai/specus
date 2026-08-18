package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientDownloadLink;
import com.theshuai.specusserver.management.model.ClientDownloadLinkView;
import com.theshuai.specusserver.management.repository.ClientDownloadLinkRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.Instant;
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

    public ClientDownloadLinkService(ClientDownloadLinkRepository repository,
                                     ClientPackageStorage storage,
                                     PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.storage = storage;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    @Transactional(readOnly = true)
    public List<ClientDownloadLinkView> listAll() {
        return repository.findAllByOrderByDisplayOrderAscIdAsc().stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public List<ClientDownloadLinkView> listEnabled() {
        return repository.findByEnabledTrueOrderByImplementationAscDisplayOrderAscIdAsc()
                .stream().map(this::toView).toList();
    }

    @Transactional
    public ClientDownloadLinkView create(LinkMutation request) {
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
        repository.delete(row);
        repository.flush();
        if (quarantine != null) {
            afterCompletion(status -> {
                if (status == TransactionSynchronization.STATUS_COMMITTED) {
                    storage.deleteQuietly(quarantine);
                } else {
                    storage.restore(quarantine, id);
                }
            });
        }
    }

    /** 把一条记录标记为其目标的最新版本；同目标其它记录的标记会被清除，因此该操作幂等。 */
    @Transactional
    public ClientDownloadLinkView markLatest(long id) {
        ClientDownloadLink row = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client download link not found: " + id));
        if (!StringUtils.hasText(row.getVersion())) {
            throw new IllegalArgumentException("client download link has no version: " + id);
        }
        repository.clearLatest(row.getImplementation(), row.getPlatform(), row.getArch());
        row.setLatest(true);
        row.setLatestSlot(latestSlot(row.getImplementation(), row.getPlatform(), row.getArch()));
        row.setUpdatedAt(Instant.now().toString());
        return toView(repository.saveAndFlush(row));
    }

    /**
     * 版本比较收敛在服务端。没有可用编目、或编目版本无法解析时一律返回“无更新”，
     * 而不是把一个不可比较的版本号丢给客户端自己判断。
     */
    @Transactional(readOnly = true)
    public VersionCheckView checkVersion(String implementation, String platform, String arch,
                                               String currentVersion) {
        String normalizedImplementation = requireImplementation(implementation);
        String normalizedPlatform = requirePlatform(platform);
        String normalizedArch = requireArch(arch);
        SemanticVersion current = SemanticVersion.parse(currentVersion, "current");

        List<ClientDownloadLink> candidates = repository
                .findByImplementationAndPlatformInAndArchInAndEnabledTrueAndHostedTrue(
                        normalizedImplementation,
                        fallbackValues(normalizedPlatform),
                        fallbackValues(normalizedArch)).stream()
                .filter(this::hasAuthoritativePackageMetadata)
                .filter(row -> safeVersion(row).isPresent())
                .toList();
        boolean hasMarkedLatest = candidates.stream().anyMatch(row -> Boolean.TRUE.equals(row.getLatest()));
        ClientDownloadLink latest = candidates.stream()
                .filter(row -> !hasMarkedLatest || Boolean.TRUE.equals(row.getLatest()))
                .max(Comparator
                        .comparingInt((ClientDownloadLink row) -> specificity(
                                row, normalizedPlatform, normalizedArch))
                        .thenComparing(row -> safeVersion(row).orElseThrow()))
                .orElse(null);
        if (latest == null) {
            return VersionCheckView.none();
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
                latest.getVersion(),
                latest.getDownloadUrl(),
                latest.getSha256(),
                latest.getFileSize() == null ? 0L : latest.getFileSize(),
                latest.getChangelogUrl(),
                Boolean.TRUE.equals(latest.getHosted()) ? latest.getId() : null);
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

    private boolean hasAuthoritativePackageMetadata(ClientDownloadLink row) {
        return row.getFileSize() != null && row.getFileSize() > 0
                && row.getSha256() != null && row.getSha256().matches("[0-9a-f]{64}");
    }

    private void apply(ClientDownloadLink row, LinkMutation request, boolean creating) {
        String implementation = requireImplementation(request.implementation());
        String platform = requirePlatform(request.platform());
        String arch = requireArch(request.arch());
        row.setImplementation(implementation);
        row.setPlatform(platform);
        row.setArch(arch);
        row.setDisplayName(requireDisplayName(request.displayName()));
        row.setDownloadUrl(requireDownloadUrl(request.downloadUrl()));
        row.setDescription(normalizeDescription(request.description()));
        row.setVersion(requireVersion(request.version()));
        row.setSha256(normalizeSha256(request.sha256()));
        row.setFileSize(normalizeFileSize(request.fileSize()));
        row.setChangelogUrl(normalizeOptionalUrl(request.changelogUrl(), "changelogUrl"));
        row.setMinSupportedVersion(normalizeOptionalVersion(request.minSupportedVersion()));
        row.setCatalogKey(catalogKey(implementation, platform, arch, row.getVersion()));
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
        if (latest) {
            // Clear first so "at most one latest per target" still holds when the caller flips the
            // flag onto a different row of the same target.
            repository.clearLatest(implementation, platform, arch);
        }
        row.setLatest(latest);
        row.setLatestSlot(latest ? latestSlot(implementation, platform, arch) : null);
    }

    private static String catalogKey(String implementation, String platform, String arch, String version) {
        return implementation + "|" + platform + "|" + arch + "|" + version;
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
        return trimmed;
    }

    private String requireVersion(String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("version cannot be blank");
        }
        String trimmed = value.trim();
        if (trimmed.length() > 32) {
            throw new IllegalArgumentException("version is too long (max 32)");
        }
        SemanticVersion.parse(trimmed, "version");
        return trimmed;
    }

    private String normalizeOptionalVersion(String value) {
        if (!StringUtils.hasText(value)) {
            return null;
        }
        String trimmed = value.trim();
        if (trimmed.length() > 32) {
            throw new IllegalArgumentException("minSupportedVersion is too long (max 32)");
        }
        SemanticVersion.parse(trimmed, "minSupportedVersion");
        return trimmed;
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
        if (trimmed.length() > 1024) {
            throw new IllegalArgumentException(fieldName + " is too long (max 1024)");
        }
        // A hosted package points at this server's own download endpoint, i.e. a relative path.
        if (allowRelative && trimmed.startsWith("/")) {
            return trimmed;
        }
        try {
            URI uri = new URI(trimmed);
            String scheme = uri.getScheme();
            if (!uri.isAbsolute() || scheme == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                throw new IllegalArgumentException(fieldName + " must be an absolute http(s) URL");
            }
            if (!StringUtils.hasText(uri.getHost())) {
                throw new IllegalArgumentException(fieldName + " must contain a host");
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
                row.setHosted(true);
                row.setUpdatedAt(now);
                repository.saveAndFlush(row);
                Path published = storage.publish(staged, packageId);
                afterCompletion(completion -> {
                    if (completion != TransactionSynchronization.STATUS_COMMITTED) {
                        storage.deleteQuietly(published);
                    }
                });
                result.set(toView(row));
            });
            return result.get();
        } finally {
            storage.deleteQuietly(staged.path());
        }
    }

    private void validatePackageMetadata(PackageUpload metadata) {
        if (metadata == null) {
            throw new IllegalArgumentException("package metadata cannot be null");
        }
        String releaseVersion = requireVersion(metadata.version());
        requireImplementation(metadata.implementation());
        requirePlatform(metadata.platform());
        requireArch(metadata.arch());
        requireDisplayName(metadata.displayName());
        normalizeOptionalUrl(metadata.changelogUrl(), "changelogUrl");
        validateMinSupportedVersion(metadata.minSupportedVersion(), releaseVersion);
    }

    /** 解析一个可公开下载的托管包；未启用、非托管或文件缺失都视为不存在。 */
    @Transactional(readOnly = true)
    public DownloadablePackage downloadable(long id) {
        ClientDownloadLink row = repository.findByIdAndEnabledTrueAndHostedTrue(id)
                .orElseThrow(() -> new IllegalArgumentException("client package not found: " + id));
        Path path = storage.requireReadable(id);
        return new DownloadablePackage(
                path,
                row.getDisplayName(),
                row.getFileSize() == null ? 0L : row.getFileSize(),
                row.getSha256());
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
    public record DownloadablePackage(Path path, String displayName, long fileSize, String sha256) {
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
