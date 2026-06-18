package com.theshuai.tunnelserver.management.model;

/**
 * 管理 UI 用的 HTTP 路由展示视图。一个客户端可以有多条路由，每条对应 client 端
 * {@code tunnelClientConfig.json:httpTunnelConfigList} 中的一项。
 *
 * <p>本视图仅做展示，不会持久化；客户端断线后由 {@code HttpRouteRegistry} 自动清理。
 */
public record HttpRouteView(
        Long clientId,
        String clientName,
        String route,
        String targetBaseUrl,
        String reportedAt
) {
}
