package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ClientAccountView;
import com.theshuai.specusserver.management.model.HttpRouteView;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.specusserver.management.service.ClientAccountService.ClientNameAvailability;
import com.theshuai.specusserver.management.service.ClientAccountService.ClientResult;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.NatControlService;
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
    private final SpecusMappingRepository specusMappingRepository;
    private final HttpRouteService httpRouteService;
    private final NatControlService natControlService;

    public ClientResource(ClientAccountService clientAccountService,
                          TrafficUsageService trafficUsageService,
                          ManagementContextResolver contextResolver,
                          SpecusMappingRepository specusMappingRepository,
                          HttpRouteService httpRouteService,
                          NatControlService natControlService) {
        this.clientAccountService = clientAccountService;
        this.trafficUsageService = trafficUsageService;
        this.contextResolver = contextResolver;
        this.specusMappingRepository = specusMappingRepository;
        this.httpRouteService = httpRouteService;
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
        List<SpecusMapping> specusMappings = specusMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(tenantId, id);
        List<HttpRouteView> routes = httpRouteService.listRoutes(context, id);
        return Map.of(
                "client", client,
                "specusMappings", specusMappings,
                "httpRoutes", routes
        );
    }

    /** S3.2 强制刷新端口映射（触发 NAT renew） */
    @PostMapping("/{id}/force-refresh-port-mapping")
    public Map<String, Object> forceRefreshPortMapping(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        ManagementContext context = contextResolver.resolve(jwt);
        var result = natControlService.pushToClient(context, id);
        return Map.of(
                "specusMappings", result.specusMappings(),
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
