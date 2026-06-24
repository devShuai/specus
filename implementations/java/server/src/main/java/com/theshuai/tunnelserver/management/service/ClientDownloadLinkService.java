package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientDownloadLink;
import com.theshuai.tunnelserver.management.model.ClientDownloadLinkView;
import com.theshuai.tunnelserver.management.repository.ClientDownloadLinkRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * 客户端下载链接的 CRUD 服务。
 *
 * <p>校验规则：
 * <ul>
 *   <li>{@code implementation} 必须是 {@link #ALLOWED_IMPLEMENTATIONS} 之一</li>
 *   <li>{@code platform} 必须是 {@link #ALLOWED_PLATFORMS} 之一</li>
 *   <li>{@code arch} 必须是 {@link #ALLOWED_ARCHES} 之一</li>
 *   <li>{@code downloadUrl} 必须是合法的 http/https 绝对 URL</li>
 *   <li>{@code displayName} 长度 1~120 字符</li>
 * </ul>
 */
@Service
@Slf4j
public class ClientDownloadLinkService {
    public static final Set<String> ALLOWED_IMPLEMENTATIONS = Set.of("java", "go", "csharp");
    public static final Set<String> ALLOWED_PLATFORMS = Set.of("windows", "linux", "macos", "any");
    public static final Set<String> ALLOWED_ARCHES = Set.of("x64", "arm64", "any");

    private final ClientDownloadLinkRepository repository;

    public ClientDownloadLinkService(ClientDownloadLinkRepository repository) {
        this.repository = repository;
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
        String implementation = requireImplementation(request.implementation());
        String platform = requirePlatform(request.platform());
        String arch = requireArch(request.arch());
        String displayName = requireDisplayName(request.displayName());
        String downloadUrl = requireDownloadUrl(request.downloadUrl());

        String now = Instant.now().toString();
        ClientDownloadLink row = new ClientDownloadLink();
        row.setId(ClientIdGenerator.newId());
        row.setImplementation(implementation);
        row.setPlatform(platform);
        row.setArch(arch);
        row.setDisplayName(displayName);
        row.setDownloadUrl(downloadUrl);
        row.setDescription(normalizeDescription(request.description()));
        row.setDisplayOrder(request.displayOrder() == null ? 0 : request.displayOrder());
        row.setEnabled(request.enabled() == null || request.enabled());
        row.setCreatedAt(now);
        row.setUpdatedAt(now);
        return toView(repository.saveAndFlush(row));
    }

    @Transactional
    public ClientDownloadLinkView update(long id, LinkMutation request) {
        ClientDownloadLink row = repository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("client download link not found: " + id));
        row.setImplementation(requireImplementation(request.implementation()));
        row.setPlatform(requirePlatform(request.platform()));
        row.setArch(requireArch(request.arch()));
        row.setDisplayName(requireDisplayName(request.displayName()));
        row.setDownloadUrl(requireDownloadUrl(request.downloadUrl()));
        row.setDescription(normalizeDescription(request.description()));
        if (request.displayOrder() != null) {
            row.setDisplayOrder(request.displayOrder());
        }
        if (request.enabled() != null) {
            row.setEnabled(request.enabled());
        }
        row.setUpdatedAt(Instant.now().toString());
        return toView(repository.saveAndFlush(row));
    }

    @Transactional
    public void delete(long id) {
        if (!repository.existsById(id)) {
            throw new IllegalArgumentException("client download link not found: " + id);
        }
        repository.deleteById(id);
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

    private String requireDownloadUrl(String value) {
        if (!StringUtils.hasText(value)) {
            throw new IllegalArgumentException("downloadUrl cannot be blank");
        }
        String trimmed = value.trim();
        if (trimmed.length() > 1024) {
            throw new IllegalArgumentException("downloadUrl is too long (max 1024)");
        }
        try {
            URI uri = new URI(trimmed);
            String scheme = uri.getScheme();
            if (!uri.isAbsolute() || scheme == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                throw new IllegalArgumentException("downloadUrl must be an absolute http(s) URL");
            }
            if (!StringUtils.hasText(uri.getHost())) {
                throw new IllegalArgumentException("downloadUrl must contain a host");
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("downloadUrl is not a valid URI: " + e.getMessage());
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
        return value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT);
    }

    private ClientDownloadLinkView toView(ClientDownloadLink row) {
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
                row.getCreatedAt(),
                row.getUpdatedAt()
        );
    }

    public record LinkMutation(
            String implementation,
            String platform,
            String arch,
            String displayName,
            String downloadUrl,
            String description,
            Integer displayOrder,
            Boolean enabled
    ) {
    }
}
