package com.theshuai.specusserver.http;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * 注册 HTTP 直转通道的 WebSocket 隧道端点 {@code /http/**}。
 *
 * <p>与 {@link com.theshuai.specusserver.websocket.WebSocketConfig}（管理后台 {@code /ws/connections}
 * 推送）独立。本端点用于把浏览器对 {@code /http/{clientName}/{route}/**} 的 WebSocket 升级请求
 * 路由到 {@link WebSocketSpecusHandler}，复用 NAT 隧道的 CONNECTED/DATA/DISCONNECTED 帧机制
 * 把字节流转发到 Java 客户端，再由客户端连本地 {@code ws://} 目标服务。
 *
 * <p>路径共存：{@link HttpSpecusController} 显式排除带 {@code Upgrade} 头的请求，升级请求
 * 因而继续匹配本 handler；普通 HTTP 请求仍由优先级更高的
 * {@code RequestMappingHandlerMapping} 路由到 controller。
 *
 * <p>{@code setAllowedOriginPatterns("*")}：HTTP 直转通道本身就是公开流量入口（见
 * {@link HttpSpecusController} 的 {@code /http/**} 默认不要求管理令牌），WS 端点与之保持一致。
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class WebSocketSpecusConfig implements WebSocketConfigurer {
    private final WebSocketSpecusHandler webSocketSpecusHandler;
    private final WebSocketSpecusHandshakeInterceptor handshakeInterceptor;

    public WebSocketSpecusConfig(WebSocketSpecusHandler webSocketSpecusHandler,
                                 WebSocketSpecusHandshakeInterceptor handshakeInterceptor) {
        this.webSocketSpecusHandler = webSocketSpecusHandler;
        this.handshakeInterceptor = handshakeInterceptor;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(webSocketSpecusHandler, "/http/**")
                .addInterceptors(handshakeInterceptor)
                .setAllowedOriginPatterns("*");
    }
}
