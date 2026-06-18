package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import com.theshuai.tunnelserver.management.service.TrafficViewService;
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

    public TrafficResource(TrafficViewService trafficViewService,
                           TrafficUsageService trafficUsageService) {
        this.trafficViewService = trafficViewService;
        this.trafficUsageService = trafficUsageService;
    }

    @GetMapping
    public List<TrafficUsageView> listTraffic(@RequestParam(required = false) Long clientId,
                                              @RequestParam(defaultValue = "100") int limit) {
        trafficUsageService.flush();
        return trafficViewService.listTraffic(clientId, limit);
    }
}
