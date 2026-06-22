package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.ConnectionRecordView;
import com.theshuai.tunnelserver.management.model.ConnectionStatView;
import com.theshuai.tunnelserver.management.service.ConnectionArchiveService;
import com.theshuai.tunnelserver.management.service.ConnectionRecordService;
import com.theshuai.tunnelserver.management.service.ConnectionRecordService.ConnectionFilter;
import com.theshuai.tunnelserver.management.tenant.TenantResolver;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 连接记录 + 连接月度归档 视图。两个端点共享一个 controller 因为它们同属"连接审计"领域。
 */
@RestController
@RequestMapping("/api/admin")
public class ConnectionResource {
    private final ConnectionRecordService connectionRecordService;
    private final ConnectionArchiveService connectionArchiveService;
    private final TenantResolver tenantResolver;

    public ConnectionResource(ConnectionRecordService connectionRecordService,
                              ConnectionArchiveService connectionArchiveService,
                              TenantResolver tenantResolver) {
        this.connectionRecordService = connectionRecordService;
        this.connectionArchiveService = connectionArchiveService;
        this.tenantResolver = tenantResolver;
    }

    @GetMapping("/connections")
    public Map<String, Object> listConnections(@AuthenticationPrincipal Jwt jwt,
                                               @RequestParam(required = false) Long clientId,
                                               @RequestParam(required = false) Boolean success,
                                               @RequestParam(required = false) String from,
                                               @RequestParam(required = false) String to,
                                               @RequestParam(defaultValue = "0") int page,
                                               @RequestParam(defaultValue = "100") int size) {
        int normalizedSize = Math.clamp(size, 1, 500);
        int normalizedPage = Math.max(0, page);
        Page<ConnectionRecordView> result = connectionRecordService.listConnections(
                tenantResolver.resolve(jwt),
                new ConnectionFilter(clientId, success, from, to),
                PageRequest.of(normalizedPage, normalizedSize, Sort.by(Sort.Direction.DESC, "id")));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("items", result.getContent());
        response.put("total", result.getTotalElements());
        response.put("page", result.getNumber());
        response.put("size", result.getSize());
        response.put("totalPages", result.getTotalPages());
        return response;
    }

    @GetMapping("/connection-stats")
    public List<ConnectionStatView> listConnectionStats(@AuthenticationPrincipal Jwt jwt,
                                                        @RequestParam(required = false) String clientName,
                                                        @RequestParam(defaultValue = "100") int limit) {
        return connectionArchiveService.listStats(tenantResolver.resolve(jwt), clientName, limit);
    }
}
