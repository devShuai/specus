package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsageView;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrameView;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.service.TrafficInspectionService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.management.service.TrafficViewService;
import com.theshuai.tunnelserver.management.tenant.TenantResolver;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

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
    private final TenantResolver tenantResolver;

    public TrafficResource(TrafficViewService trafficViewService,
                           TrafficUsageService trafficUsageService,
                           TrafficInspectionService trafficInspectionService,
                           TenantResolver tenantResolver) {
        this.trafficViewService = trafficViewService;
        this.trafficUsageService = trafficUsageService;
        this.trafficInspectionService = trafficInspectionService;
        this.tenantResolver = tenantResolver;
    }

    @GetMapping
    public List<TrafficUsageView> listTraffic(@AuthenticationPrincipal Jwt jwt,
                                              @RequestParam(required = false) Long clientId,
                                              @RequestParam(defaultValue = "100") int limit) {
        trafficUsageService.flush();
        return trafficViewService.listTraffic(tenantResolver.resolve(jwt), clientId, limit);
    }

    @GetMapping("/resources")
    public List<ResourceTrafficUsageView> listResourceTraffic(@AuthenticationPrincipal Jwt jwt,
                                                             @RequestParam(required = false) String type,
                                                             @RequestParam(required = false) Long clientId,
                                                             @RequestParam(defaultValue = "200") int limit) {
        trafficUsageService.flush();
        return trafficViewService.listResourceTraffic(tenantResolver.resolve(jwt), type, clientId, limit);
    }

    @GetMapping("/http-exchanges")
    public List<HttpTrafficExchangeView> listHttpExchanges(@AuthenticationPrincipal Jwt jwt,
                                                           @RequestParam(required = false) Long clientId,
                                                           @RequestParam(required = false) String route,
                                                           @RequestParam(defaultValue = "100") int limit) {
        trafficInspectionService.flush();
        return trafficViewService.listHttpExchanges(tenantResolver.resolve(jwt), clientId, route, limit);
    }

    @GetMapping("/tcp-frames")
    public List<TcpTrafficFrameView> listTcpFrames(@AuthenticationPrincipal Jwt jwt,
                                                   @RequestParam(required = false) Long clientId,
                                                   @RequestParam(required = false) Integer listenPort,
                                                   @RequestParam(defaultValue = "200") int limit) {
        trafficInspectionService.flush();
        return trafficViewService.listTcpFrames(tenantResolver.resolve(jwt), clientId, listenPort, limit);
    }
}
