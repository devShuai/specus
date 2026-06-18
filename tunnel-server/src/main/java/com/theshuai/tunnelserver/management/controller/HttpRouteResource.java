package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.HttpRouteView;
import com.theshuai.tunnelserver.management.service.HttpRouteService;
import com.theshuai.tunnelserver.management.service.HttpRouteService.RouteMutation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * HTTP 路由（{@code httpTunnelConfigList}）管理资源。服务端持久化为权威来源，每次
 * mutation 都会触发 {@code NAT_CONTROL} 全量下发，由客户端 {@code DirectHttpRequestHandler}
 * 热替换内存路由表（无需重启）。
 *
 * <ul>
 *   <li>{@code GET    /api/admin/http-routes}                    全量列表（可按 clientId 过滤）</li>
 *   <li>{@code POST   /api/admin/clients/{id}/http-routes}       新增路由</li>
 *   <li>{@code PUT    /api/admin/http-routes/{routeId}}          编辑/启停</li>
 *   <li>{@code DELETE /api/admin/http-routes/{routeId}}          删除</li>
 * </ul>
 *
 * <p>手动下发复用现有的 {@code POST /api/admin/clients/{id}/nat-control}（同时下发
 * TCP + HTTP），不在这里另设端点。
 */
@RestController
@RequestMapping("/api/admin")
public class HttpRouteResource {

    private final HttpRouteService httpRouteService;

    public HttpRouteResource(HttpRouteService httpRouteService) {
        this.httpRouteService = httpRouteService;
    }

    @GetMapping("/http-routes")
    public List<HttpRouteView> listHttpRoutes(@RequestParam(required = false) Long clientId) {
        return httpRouteService.listRoutes(clientId);
    }

    @PostMapping("/clients/{id}/http-routes")
    public ResponseEntity<HttpRouteView> createHttpRoute(@PathVariable long id,
                                                         @RequestBody RouteMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(httpRouteService.createRoute(id, request));
    }

    @PutMapping("/http-routes/{routeId}")
    public HttpRouteView updateHttpRoute(@PathVariable long routeId,
                                         @RequestBody RouteMutation request) {
        return httpRouteService.updateRoute(routeId, request);
    }

    @DeleteMapping("/http-routes/{routeId}")
    public ResponseEntity<Void> deleteHttpRoute(@PathVariable long routeId) {
        httpRouteService.deleteRoute(routeId);
        return ResponseEntity.noContent().build();
    }
}
