package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.httpshare.HttpShareRules;
import com.theshuai.specusserver.management.model.HttpRouteView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.HttpShareService;
import com.theshuai.specusserver.management.service.HttpRouteService.RouteMutation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

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
 *   <li>{@code POST   /api/admin/http-routes/{routeId}/shares}   签发临时 HTTP 分享（及列表、查看、撤销、审计）</li>
 * </ul>
 *
 * <p>手动下发复用现有的 {@code POST /api/admin/clients/{id}/nat-control}（同时下发
 * TCP + HTTP），不在这里另设端点。
 */
@RestController
@RequestMapping("/api/admin")
public class HttpRouteResource {

    private final HttpRouteService httpRouteService;
    private final HttpShareService httpShareService;
    private final ManagementContextResolver contextResolver;

    public HttpRouteResource(HttpRouteService httpRouteService,
                             HttpShareService httpShareService,
                             ManagementContextResolver contextResolver) {
        this.httpRouteService = httpRouteService;
        this.httpShareService = httpShareService;
        this.contextResolver = contextResolver;
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
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(httpRouteService.createRoute(contextResolver.resolve(jwt), id, request));
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

    // Temporary HTTP shares (protocol/spec/temporary-http-share.md section 4). The route id stays a
    // string so that a non-numeric id is answered like any route the caller cannot see.

    @PostMapping("/http-routes/{routeId}/shares")
    public ResponseEntity<byte[]> createShare(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable String routeId,
                                              @RequestBody(required = false) byte[] body) {
        return HttpShareResponses.management(contextResolver, jwt, 404, HttpShareRules.CODE_ROUTE_NOT_FOUND,
                context -> httpShareService.create(context, routeId, body));
    }

    @GetMapping("/http-routes/{routeId}/shares")
    public ResponseEntity<byte[]> listShares(@AuthenticationPrincipal Jwt jwt, @PathVariable String routeId) {
        return HttpShareResponses.management(contextResolver, jwt, 404, HttpShareRules.CODE_ROUTE_NOT_FOUND,
                context -> httpShareService.list(context, routeId));
    }

    @GetMapping("/http-routes/{routeId}/shares/{shareId}")
    public ResponseEntity<byte[]> getShare(@AuthenticationPrincipal Jwt jwt,
                                           @PathVariable String routeId,
                                           @PathVariable String shareId) {
        return HttpShareResponses.management(contextResolver, jwt, 404, HttpShareRules.CODE_ROUTE_NOT_FOUND,
                context -> httpShareService.get(context, routeId, shareId));
    }

    @PostMapping("/http-routes/{routeId}/shares/{shareId}/revoke")
    public ResponseEntity<byte[]> revokeShare(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable String routeId,
                                              @PathVariable String shareId,
                                              @RequestBody(required = false) byte[] body) {
        return HttpShareResponses.management(contextResolver, jwt, 404, HttpShareRules.CODE_ROUTE_NOT_FOUND,
                context -> httpShareService.revoke(context, routeId, shareId, body));
    }

    @GetMapping("/http-routes/{routeId}/access-audit")
    public ResponseEntity<byte[]> routeAccessAudit(@AuthenticationPrincipal Jwt jwt,
                                                   @PathVariable String routeId,
                                                   @RequestParam(required = false) String limit,
                                                   @RequestParam(required = false) String before) {
        return HttpShareResponses.management(contextResolver, jwt, 404, HttpShareRules.CODE_ROUTE_NOT_FOUND,
                context -> httpShareService.routeAudit(context, routeId, limit, before));
    }

    @GetMapping("/http-access-audit")
    public ResponseEntity<byte[]> tenantAccessAudit(@AuthenticationPrincipal Jwt jwt,
                                                    @RequestParam(required = false) String routeId,
                                                    @RequestParam(required = false) String limit,
                                                    @RequestParam(required = false) String before) {
        return HttpShareResponses.management(contextResolver, jwt, 403, HttpShareRules.CODE_FORBIDDEN,
                context -> httpShareService.tenantAudit(context, routeId, limit, before));
    }
}
