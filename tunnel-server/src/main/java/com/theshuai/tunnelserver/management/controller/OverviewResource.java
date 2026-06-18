package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.database.DatabaseInitializer;
import com.theshuai.tunnelserver.management.service.OverviewService;
import com.theshuai.tunnelserver.management.service.TrafficUsageService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * 顶部 Overview 卡片 + 数据库初始化幂等端点。
 */
@RestController
@RequestMapping("/api/admin")
public class OverviewResource {
    private final OverviewService overviewService;
    private final TrafficUsageService trafficUsageService;
    private final DatabaseInitializer databaseInitializer;

    public OverviewResource(OverviewService overviewService,
                            TrafficUsageService trafficUsageService,
                            DatabaseInitializer databaseInitializer) {
        this.overviewService = overviewService;
        this.trafficUsageService = trafficUsageService;
        this.databaseInitializer = databaseInitializer;
    }

    @GetMapping("/overview")
    public Map<String, Object> overview() {
        trafficUsageService.flush();
        return overviewService.overview();
    }

    @PostMapping("/database/initialize")
    public Map<String, Object> initializeDatabase() {
        return databaseInitializer.initialize();
    }
}
