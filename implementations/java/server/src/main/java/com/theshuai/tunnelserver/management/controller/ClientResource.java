package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientNameAvailability;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientResult;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.service.NatControlService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 客户端账号 CRUD。流量统计 flush 触发放在列表读取路径上，确保管理面板看到的上下行总量是当前秒级新鲜的。
 * S3.2 新增单客户端详情、强制刷新端口映射、重试打洞端点。
 */
@RestController
@RequestMapping("/api/admin/clients")
public class ClientResource {
    private final ClientAccountService clientAccountService;
    private final TrafficUsageService trafficUsageService;
    private final ManagementContextResolver contextResolver;
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final NatControlService natControlService;

    public ClientResource(ClientAccountService clientAccountService,
                          TrafficUsageService trafficUsageService,
                          ManagementContextResolver contextResolver,
                          TunnelMappingRepository tunnelMappingRepository,
                          HttpRouteMappingRepository httpRouteMappingRepository,
                          NatControlService natControlService) {
        this.clientAccountService = clientAccountService;
        this.trafficUsageService = trafficUsageService;
        this.contextResolver = contextResolver;
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.natControlService = natControlService;
    }

    @GetMapping
    public List<ClientAccountView> listClients(@AuthenticationPrincipal Jwt jwt) {
        trafficUsageService.flush();
        return clientAccountService.listClients(contextResolver.resolve(jwt));
    }

    @GetMapping("/name-availability")
    public ClientNameAvailability checkClientNameAvailability(@AuthenticationPrincipal Jwt jwt,
                                                              @RequestParam String clientName,
                                                              @RequestParam(required = false) Long excludeClientId) {
        return clientAccountService.checkClientNameAvailability(
                contextResolver.resolve(jwt), clientName, excludeClientId);
    }

    /** S3.2 单客户端聚合详情 */
    @GetMapping("/{id}")
    public Map<String, Object> getClient(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        ManagementContext context = contextResolver.resolve(jwt);
        trafficUsageService.flush();
        ClientAccountView client = clientAccountService.listClients(context).stream()
                .filter(c -> c.id() == id)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + id));
        String tenantId = context.tenant().tenantId();
        List<TunnelMapping> tunnels = tunnelMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(tenantId, id);
        List<HttpRouteMapping> routes = httpRouteMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(tenantId, id);
        return Map.of(
                "client", client,
                "tunnels", tunnels,
                "httpRoutes", routes
        );
    }

    /** S3.2 强制刷新端口映射（触发 NAT renew） */
    @PostMapping("/{id}/force-refresh-port-mapping")
    public Map<String, Object> forceRefreshPortMapping(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        ManagementContext context = contextResolver.resolve(jwt);
        var result = natControlService.pushToClient(context, id);
        return Map.of(
                "tunnels", result.tunnels(),
                "httpRoutes", result.httpRoutes()
        );
    }

    @PostMapping
    public ResponseEntity<ClientResult> createClient(@AuthenticationPrincipal Jwt jwt,
                                                     @RequestBody ClientMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(clientAccountService.createClient(contextResolver.resolve(jwt), request));
    }

    @PutMapping("/{id}")
    public ClientResult updateClient(@AuthenticationPrincipal Jwt jwt,
                                     @PathVariable long id,
                                     @RequestBody ClientMutation request) {
        return clientAccountService.updateClient(contextResolver.resolve(jwt), id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteClient(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        clientAccountService.deleteClient(contextResolver.resolve(jwt), id);
        return ResponseEntity.noContent().build();
    }
}
