package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import com.theshuai.specusserver.management.model.ResourceTrafficUsageView;
import com.theshuai.specusserver.management.model.TcpTrafficFrameView;
import com.theshuai.specusserver.management.model.TrafficUsageView;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import com.theshuai.specusserver.management.service.TrafficViewService;
import com.theshuai.specusserver.management.storage.HttpTrafficSearchField;
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
 * 流量使用查询。热路径只做内存累计和入队，后台定时 flush；查询默认不触发同步写入，
 * 需要准实时刷新时可显式传 flush=true。
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
                                              @RequestParam(defaultValue = "100") int limit,
                                              @RequestParam(defaultValue = "false") boolean flush) {
        if (flush) {
            trafficUsageService.flush();
        }
        return trafficViewService.listTraffic(contextResolver.resolve(jwt), clientId, limit);
    }

    @GetMapping("/resources")
    public List<ResourceTrafficUsageView> listResourceTraffic(@AuthenticationPrincipal Jwt jwt,
                                                             @RequestParam(required = false) String type,
                                                             @RequestParam(required = false) Long clientId,
                                                             @RequestParam(defaultValue = "200") int limit,
                                                             @RequestParam(defaultValue = "false") boolean flush) {
        if (flush) {
            trafficUsageService.flush();
        }
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
                                                 @RequestParam(defaultValue = "50") int size,
                                                 @RequestParam(defaultValue = "false") boolean flush) {
        if (flush) {
            trafficInspectionService.flush();
        }
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

    @GetMapping("/http-exchanges/{id}")
    public HttpTrafficExchangeView getHttpExchange(@AuthenticationPrincipal Jwt jwt,
                                                   @PathVariable long id) {
        return trafficViewService.getHttpExchange(contextResolver.resolve(jwt), id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "HTTP exchange not found"));
    }

    @GetMapping("/tcp-frames")
    public Map<String, Object> listTcpFrames(@AuthenticationPrincipal Jwt jwt,
                                             @RequestParam(required = false) Long clientId,
                                             @RequestParam(required = false) Integer listenPort,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(required = false) Integer size,
                                             @RequestParam(required = false) Integer limit,
                                             @RequestParam(defaultValue = "false") boolean flush) {
        if (flush) {
            trafficInspectionService.flush();
        }
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
        return trafficViewService.getTcpFrame(contextResolver.resolve(jwt), id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "TCP frame not found"));
    }

    @GetMapping("/tcp-streams")
    public Map<String, Object> getTcpStream(@AuthenticationPrincipal Jwt jwt,
                                            @RequestParam String channelId,
                                            @RequestParam(defaultValue = "500") int limit,
                                            @RequestParam(required = false) Integer page,
                                            @RequestParam(required = false) Integer size,
                                            @RequestParam(defaultValue = "false") boolean flush) {
        if (flush) {
            trafficInspectionService.flush();
        }
        int normalizedPage = Math.max(0, page == null ? 0 : page);
        int normalizedSize = Math.clamp(size == null ? limit : size, 1, 1000);
        Page<TcpTrafficFrameView> stream = trafficViewService.listTcpStream(
                contextResolver.resolve(jwt),
                channelId,
                PageRequest.of(normalizedPage, normalizedSize, Sort.by(Sort.Direction.ASC, "id")));
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("channelId", channelId);
        response.put("items", stream.getContent());
        response.put("total", stream.getTotalElements());
        response.put("page", normalizedPage);
        response.put("size", normalizedSize);
        response.put("limit", normalizedSize);
        response.put("totalPages", Math.max(1, stream.getTotalPages()));
        response.put("truncated", normalizedPage + 1 < stream.getTotalPages());
        return response;
    }

    @GetMapping("/inspection-status")
    public TrafficInspectionService.Snapshot inspectionStatus() {
        return trafficInspectionService.snapshot();
    }

    private String firstText(String first, String second) {
        if (first != null && !first.isBlank()) {
            return first;
        }
        return second;
    }
}
