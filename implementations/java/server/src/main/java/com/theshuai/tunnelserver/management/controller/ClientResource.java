package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ClientAccountView;
import com.theshuai.tunnelserver.management.service.ClientAccountService;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.tunnelserver.management.service.ClientAccountService.ClientResult;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * 客户端账号 CRUD。流量统计 flush 触发放在列表读取路径上，确保管理面板看到的上下行总量是当前秒级新鲜的。
 */
@RestController
@RequestMapping("/api/admin/clients")
public class ClientResource {
    private final ClientAccountService clientAccountService;
    private final TrafficUsageService trafficUsageService;
    private final ManagementContextResolver contextResolver;

    public ClientResource(ClientAccountService clientAccountService,
                          TrafficUsageService trafficUsageService,
                          ManagementContextResolver contextResolver) {
        this.clientAccountService = clientAccountService;
        this.trafficUsageService = trafficUsageService;
        this.contextResolver = contextResolver;
    }

    @GetMapping
    public List<ClientAccountView> listClients(@AuthenticationPrincipal Jwt jwt) {
        trafficUsageService.flush();
        return clientAccountService.listClients(contextResolver.resolve(jwt));
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
