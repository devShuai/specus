package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.connectivity.HttpRouteConnectivityCheckService;
import com.theshuai.specusserver.management.model.HttpRouteView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.HttpRouteService.RouteMutation;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.List;
import java.util.Map;

/**
 * HTTP 路由（{@code httpSpecusConfigList}）管理资源。服务端持久化为权威来源，每次
 * mutation 都会触发 {@code NAT_CONTROL} 全量下发，由客户端 {@code NatClientHandler}
 * 热替换内存路由表（无需重启）。
 *
 * <ul>
 *   <li>{@code GET    /api/admin/http-routes}                    全量列表（可按 clientId 过滤）</li>
 *   <li>{@code POST   /api/admin/clients/{id}/http-routes}       新增路由</li>
 *   <li>{@code PUT    /api/admin/http-routes/{routeId}}          编辑/启停</li>
 *   <li>{@code DELETE /api/admin/http-routes/{routeId}}          删除</li>
 *   <li>{@code POST   /api/admin/http-routes/{routeId}/connectivity-check} 连通性检查</li>
 * </ul>
 *
 * <p>手动下发复用现有的 {@code POST /api/admin/clients/{id}/nat-control}（同时下发
 * TCP + HTTP），不在这里另设端点。
 */
@RestController
@RequestMapping("/api/admin")
public class HttpRouteResource {

    static final String CHECK_CACHE_CONTROL = "private, no-store";

    private final HttpRouteService httpRouteService;
    private final ManagementContextResolver contextResolver;
    private final HttpRouteConnectivityCheckService connectivityCheckService;
    private final ProductMetricsService productMetrics;

    public HttpRouteResource(HttpRouteService httpRouteService,
                             ManagementContextResolver contextResolver,
                             HttpRouteConnectivityCheckService connectivityCheckService,
                             ProductMetricsService productMetrics) {
        this.httpRouteService = httpRouteService;
        this.contextResolver = contextResolver;
        this.connectivityCheckService = connectivityCheckService;
        this.productMetrics = productMetrics;
    }

    @GetMapping("/http-routes")
    public List<HttpRouteView> listHttpRoutes(@AuthenticationPrincipal Jwt jwt,
                                              @RequestParam(required = false) Long clientId) {
        return httpRouteService.listRoutes(contextResolver.resolve(jwt), clientId);
    }

    @PostMapping("/clients/{id}/http-routes")
    public ResponseEntity<HttpRouteView> createHttpRoute(@AuthenticationPrincipal Jwt jwt,
                                                         @PathVariable long id,
                                                         @RequestBody RouteMutation request) {
        HttpRouteView created = httpRouteService.createRoute(contextResolver.resolve(jwt), id, request);
        productMetrics.servicePublished(id);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/http-routes/{routeId}")
    public HttpRouteView updateHttpRoute(@AuthenticationPrincipal Jwt jwt,
                                         @PathVariable long routeId,
                                         @RequestBody RouteMutation request) {
        return httpRouteService.updateRoute(contextResolver.resolve(jwt), routeId, request);
    }

    @DeleteMapping("/http-routes/{routeId}")
    public ResponseEntity<Void> deleteHttpRoute(@AuthenticationPrincipal Jwt jwt, @PathVariable long routeId) {
        httpRouteService.deleteRoute(contextResolver.resolve(jwt), routeId);
        return ResponseEntity.noContent().build();
    }

    /**
     * One end-to-end connectivity check of one route (protocol/spec/service-connectivity-check.md).
     * The route id stays text here: a malformed id is an unknown route (404), not a binding error.
     * Any Content-Type is accepted; the body is read by the check itself, at most 4 KiB.
     */
    @PostMapping("/http-routes/{routeId}/connectivity-check")
    public ResponseEntity<?> checkHttpRouteConnectivity(@AuthenticationPrincipal Jwt jwt,
                                                        @PathVariable String routeId,
                                                        HttpServletRequest request) throws IOException {
        HttpRouteConnectivityCheckService.Response result;
        try {
            result = connectivityCheckService.check(() -> contextResolver.resolve(jwt), routeId,
                    request.getInputStream());
        } catch (ResponseStatusException unauthenticated) {
            // The usual answer of the management API for a missing or revoked session.
            String message = StringUtils.hasText(unauthenticated.getReason())
                    ? unauthenticated.getReason() : "请求失败";
            return ResponseEntity.status(unauthenticated.getStatusCode())
                    .header(HttpHeaders.CACHE_CONTROL, CHECK_CACHE_CONTROL)
                    .body(Map.of("error", message));
        }
        ResponseEntity.BodyBuilder response = ResponseEntity.status(result.status())
                .header(HttpHeaders.CACHE_CONTROL, CHECK_CACHE_CONTROL)
                .contentType(MediaType.APPLICATION_JSON);
        if (result.retryAfterSeconds() != null) {
            response.header(HttpHeaders.RETRY_AFTER, Long.toString(result.retryAfterSeconds()));
        }
        return response.body(result.body());
    }
}
