package com.theshuai.tunnelserver.management.model;

/**
 * 管理 UI 用的 HTTP 路由展示视图。一行对应一条 {@link HttpRouteMapping}，由
 * {@code HttpRouteService.toView} 构造。
 *
 * <p>历史背景：早期版本字段叫 {@code reportedAt}（来源是客户端上报的内存缓存），
 * 改为持久化模型后语义换成"最后修改时间"，前端 column 文案也跟着调整。
 */
public record HttpRouteView(
        Long id,
        Long clientId,
        String clientName,
        String route,
        String targetBaseUrl,
        boolean enabled,
        boolean detailCaptureEnabled,
        boolean mediaCaptureEnabled,
        boolean pathRewriteEnabled,
        String createdAt,
        String updatedAt
) {
}
