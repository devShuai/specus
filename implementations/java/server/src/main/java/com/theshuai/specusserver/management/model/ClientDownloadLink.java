package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

/**
 * 客户端下载链接：管理员配置好后展示在登录页和 Dashboard，让用户可以一键获取对应实现的客户端。
 *
 * <p>既支持外部 URL，也支持由 specus 在 {@code data/packages} 下托管的不可变发布包。
 * {@code catalogKey} 和 {@code latestSlot} 是跨 SQLite/MySQL/PostgreSQL 的可移植唯一键：前者保证
 * (implementation, platform, arch, version) 唯一，后者保证每个目标最多一个 latest。
 *
 * <p>{@code implementation} 是客户端实现枚举值：{@code java} / {@code go} / {@code csharp}。
 * {@code platform} / {@code arch} 用于区分多平台变体（Windows/Linux/macOS × x64/arm64）。
 */
@Entity
@Table(name = "client_download_link",
        indexes = {
                @Index(name = "idx_client_download_impl", columnList = "implementation"),
                @Index(name = "idx_client_download_order", columnList = "display_order")
        })
@Getter
@Setter
public class ClientDownloadLink {
    @Id
    private Long id;

    /** 客户端实现：{@code java} / {@code go} / {@code csharp}。 */
    @Column(nullable = false, length = 32)
    private String implementation;

    /** 操作系统：{@code windows} / {@code linux} / {@code macos} / {@code any}（Java jar 之类跨平台）。 */
    @Column(nullable = false, length = 32)
    private String platform;

    /** CPU 架构：{@code x64} / {@code arm64} / {@code any}（跨架构 jar 之类）。 */
    @Column(nullable = false, length = 32)
    private String arch;

    /** 用户可见的名字，例如 {@code Windows x64 安装包 1.2.0}。 */
    @Column(name = "display_name", nullable = false, length = 120)
    private String displayName;

    /** 实际下载 URL，必须为 http/https 绝对地址。 */
    @Column(name = "download_url", nullable = false, length = 1024)
    private String downloadUrl;

    /** SemVer 2.0 版本；旧数据由启动迁移填入唯一的 legacy 版本。 */
    @Column(length = 32)
    private String version;

    /** 托管文件的 SHA-256 小写十六进制值；旧外链可为 null。 */
    @Column(length = 64)
    private String sha256;

    @Column(name = "file_size")
    private Long fileSize;

    @Column(name = "is_latest")
    private Boolean latest;

    @Column(name = "changelog_url", length = 1024)
    private String changelogUrl;

    @Column(name = "min_supported_version", length = 32)
    private String minSupportedVersion;

    @Column
    private Boolean hosted;

    @Column(name = "catalog_key", length = 160, unique = true)
    private String catalogKey;

    @Column(name = "latest_slot", length = 100, unique = true)
    private String latestSlot;

    /** 可选说明，譬如哈希值、签名说明等。 */
    @Column(length = 512)
    private String description;

    @Column(name = "display_order", nullable = false)
    private int displayOrder = 0;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
