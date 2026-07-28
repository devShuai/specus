package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ConnectionRecordView;
import com.theshuai.specusserver.management.model.ConnectionStatView;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ConnectionArchiveService;
import com.theshuai.specusserver.management.service.ConnectionRecordService;
import com.theshuai.specusserver.management.service.ConnectionRecordService.ConnectionFilter;
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
    private final ManagementContextResolver contextResolver;

    public ConnectionResource(ConnectionRecordService connectionRecordService,
                              ConnectionArchiveService connectionArchiveService,
                              ManagementContextResolver contextResolver) {
        this.connectionRecordService = connectionRecordService;
        this.connectionArchiveService = connectionArchiveService;
        this.contextResolver = contextResolver;
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
        ManagementContext context = contextResolver.resolve(jwt);
        Page<ConnectionRecordView> result = connectionRecordService.listConnections(
                context,
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
        return connectionArchiveService.listStats(contextResolver.resolve(jwt), clientName, limit);
    }
}
