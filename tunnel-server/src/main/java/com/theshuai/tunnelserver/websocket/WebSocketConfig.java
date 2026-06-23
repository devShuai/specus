package com.theshuai.tunnelserver.websocket;

import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;

/**
 * 管理后台的实时推送端点。
 *
 * <p>挂在 {@code /ws/connections}：
 * <ul>
 *   <li>handler：{@link ConnectionEventsWebSocketHandler}（推送 {@link ConnectionEvent}）</li>
 *   <li>握手鉴权：{@link JwtHandshakeInterceptor}（query 串 token）</li>
 *   <li>允许同源访问；前端在 SecurityConfig 的 CSP {@code connect-src 'self'} 内</li>
 * </ul>
 *
 * <p>关于 STOMP：本场景只是单向"服务端 → UI"推一个 JSON event，纯 WebSocket 已足够；
 * 引入 STOMP 没有收益，反而要前端引依赖、后端配 broker。
 *
 * <p>{@code @ConditionalOnWebApplication(SERVLET)} 与 {@code SecurityConfig} 的条件保持一致：
 * 非 web 测试上下文（{@code spring.main.web-application-type=none}）下不会拉起 WS，
 * 也就不会触发对 {@code JwtDecoder} 的依赖。
 */
@Configuration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final ConnectionEventsWebSocketHandler connectionEventsHandler;
    private final JwtDecoder jwtDecoder;
    private final ManagementContextResolver contextResolver;

    public WebSocketConfig(ConnectionEventsWebSocketHandler connectionEventsHandler,
                           JwtDecoder jwtDecoder,
                           ManagementContextResolver contextResolver) {
        this.connectionEventsHandler = connectionEventsHandler;
        this.jwtDecoder = jwtDecoder;
        this.contextResolver = contextResolver;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        registry.addHandler(connectionEventsHandler, "/ws/connections")
                .addInterceptors(new JwtHandshakeInterceptor(jwtDecoder, contextResolver))
                // 默认 '*' 同源；显式写出来以示意，不引入 CORS 漏洞
                .setAllowedOriginPatterns("*");
    }
}
