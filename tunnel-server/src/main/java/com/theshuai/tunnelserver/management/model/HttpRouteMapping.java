package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

/**
 * 后台维护的"客户端 HTTP 路由"记录。一行对应客户端
 * {@code tunnelClientConfig.json:httpTunnelConfigList} 中的一项，但服务端为权威来源：
 * 客户端登录或后台 CRUD 时通过 {@code NAT_CONTROL} 全量下发，由
 * {@code DirectHttpRequestHandler} 热替换内存路由表。
 *
 * <p>唯一性：同一客户端的同名 route 唯一；跨客户端可重名（{@code uk_http_route_client_route}）。
 *
 * <p>客户端 ID 使用 {@code Long}（无外键约束，与 {@link TunnelMapping} 的处理一致）—— 删除
 * {@code ClientAccount} 时需要手动级联清理 {@code http_route_mapping}，但本系统的 UX 假设
 * 是"先删完路由再删账户"。
 */
@Entity
@Table(name = "http_route_mapping",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_http_route_client_route",
                columnNames = {"client_id", "route"}
        ),
        indexes = {
                @Index(name = "idx_http_route_tenant", columnList = "tenant_id"),
                @Index(name = "idx_http_route_client", columnList = "client_id")
        })
@Getter
@Setter
public class HttpRouteMapping {
    @Id
    private Long id;

    @Column(name = "tenant_id", length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    /** 冗余字段，与 {@link TunnelMapping#getClientName()} 同样的考虑：列表展示无需 join。 */
    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    /**
     * 客户端 {@code DirectHttpRequestHandler} 用 {@code routes.get(route)} 精确匹配；
     * 长度约束 60 字符，避免恶意长字符串撑爆 URL。
     */
    @Column(nullable = false, length = 60)
    private String route;

    /**
     * 客户端转发目标 URL，例如 {@code http://127.0.0.1:8080}。允许带 path 前缀，
     * {@code DirectHttpForwarder} 会做 scheme/host/port + basePath 越界校验。
     */
    @Column(name = "target_base_url", nullable = false, length = 512)
    private String targetBaseUrl;

    @Column(nullable = false)
    private boolean enabled = true;

    @Column(name = "detail_capture_enabled")
    private Boolean detailCaptureEnabled = false;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
