package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsageView;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrameView;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.management.service.TrafficViewService;
import com.theshuai.tunnelserver.management.storage.HttpTrafficSearchField;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 流量使用查询。GET 时主动 flush 一次，使返回值反映最新计数器累计；写入累计本身在
 * {@link TrafficUsageService} 的热路径里完成。
 */
@RestController
@RequestMapping("/api/admin/traffic")
public class TrafficResource {
    private final TrafficViewService trafficViewService;
    private final TrafficUsageService trafficUsageService;
    private final TrafficInspectionService trafficInspectionService;
    private final ManagementContextResolver contextResolver;

    public TrafficResource(TrafficViewService trafficViewService,
                           TrafficUsageService trafficUsageService,
                           TrafficInspectionService trafficInspectionService,
                           ManagementContextResolver contextResolver) {
        this.trafficViewService = trafficViewService;
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.contextResolver = contextResolver;
    }

    @GetMapping
    public List<TrafficUsageView> listTraffic(@AuthenticationPrincipal Jwt jwt,
                                              @RequestParam(required = false) Long clientId,
                                              @RequestParam(defaultValue = "100") int limit) {
        trafficUsageService.flush();
        return trafficViewService.listTraffic(contextResolver.resolve(jwt), clientId, limit);
    }

    @GetMapping("/resources")
    public List<ResourceTrafficUsageView> listResourceTraffic(@AuthenticationPrincipal Jwt jwt,
                                                             @RequestParam(required = false) String type,
                                                             @RequestParam(required = false) Long clientId,
                                                             @RequestParam(defaultValue = "200") int limit) {
        trafficUsageService.flush();
        return trafficViewService.listResourceTraffic(contextResolver.resolve(jwt), type, clientId, limit);
    }

    @GetMapping("/http-exchanges")
    public Map<String, Object> listHttpExchanges(@AuthenticationPrincipal Jwt jwt,
                                                 @RequestParam(required = false) Long clientId,
                                                 @RequestParam(required = false) String route,
                                                 @RequestParam(required = false) String responseBodyType,
                                                 @RequestParam(required = false) String responseDataType,
                                                 @RequestParam(required = false) String field,
                                                 @RequestParam(required = false) String q,
                                                 @RequestParam(defaultValue = "0") int page,
                                                 @RequestParam(defaultValue = "50") int size) {
        trafficInspectionService.flush();
        int normalizedSize = Math.clamp(size, 1, 500);
        int normalizedPage = Math.max(0, page);
        ManagementContext context = contextResolver.resolve(jwt);
        Page<HttpTrafficExchangeView> result = trafficViewService.listHttpExchanges(
                context,
                clientId,
                route,
                firstText(responseBodyType, responseDataType),
                HttpTrafficSearchField.fromCode(field),
                q,
                PageRequest.of(normalizedPage, normalizedSize, Sort.by(Sort.Direction.DESC, "id")));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("items", result.getContent());
        response.put("total", result.getTotalElements());
        response.put("page", result.getNumber());
        response.put("size", result.getSize());
        response.put("totalPages", result.getTotalPages());
        return response;
    }

    @GetMapping("/tcp-frames")
    public Map<String, Object> listTcpFrames(@AuthenticationPrincipal Jwt jwt,
                                             @RequestParam(required = false) Long clientId,
                                             @RequestParam(required = false) Integer listenPort,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(required = false) Integer size,
                                             @RequestParam(required = false) Integer limit) {
        trafficInspectionService.flush();
        int requestedSize = size == null ? (limit == null ? 50 : limit) : size;
        int normalizedSize = Math.clamp(requestedSize, 1, 500);
        int normalizedPage = Math.max(0, page);
        Page<TcpTrafficFrameView> result = trafficViewService.listTcpFrames(
                contextResolver.resolve(jwt),
                clientId,
                listenPort,
                PageRequest.of(normalizedPage, normalizedSize, Sort.by(Sort.Direction.DESC, "id")));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("items", result.getContent());
        response.put("total", result.getTotalElements());
        response.put("page", result.getNumber());
        response.put("size", result.getSize());
        response.put("totalPages", result.getTotalPages());
        return response;
    }

    @GetMapping("/tcp-frames/{id}")
    public TcpTrafficFrameView getTcpFrame(@AuthenticationPrincipal Jwt jwt,
                                           @PathVariable long id) {
        trafficInspectionService.flush();
        return trafficViewService.getTcpFrame(contextResolver.resolve(jwt), id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "TCP frame not found"));
    }

    @GetMapping("/tcp-streams")
    public Map<String, Object> getTcpStream(@AuthenticationPrincipal Jwt jwt,
                                            @RequestParam String channelId,
                                            @RequestParam(defaultValue = "500") int limit) {
        trafficInspectionService.flush();
        int normalizedLimit = Math.clamp(limit, 1, 1000);
        List<TcpTrafficFrameView> items = trafficViewService.listTcpStream(
                contextResolver.resolve(jwt), channelId, normalizedLimit);
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("channelId", channelId);
        response.put("items", items);
        response.put("total", items.size());
        response.put("limit", normalizedLimit);
        response.put("truncated", items.size() >= normalizedLimit);
        return response;
    }

    private String firstText(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        return second;
    }
}
