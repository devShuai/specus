package com.theshuai.tunnelserver.management.model;

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
 * <p>仅存 URL 字符串，不托管二进制——避免 JAR 包大小、磁盘容量、带宽与版本管理问题。URL 一般指向
 * 公司内部 OSS、GitHub Release 或 nexus 等外部托管。
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
