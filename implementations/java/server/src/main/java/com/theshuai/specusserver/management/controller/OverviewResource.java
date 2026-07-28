package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.database.DatabaseInitializer;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.management.service.OverviewService;
import com.theshuai.specusserver.management.service.TrafficUsageService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
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
    private final ManagementContextResolver contextResolver;
    private final ManagementUserService managementUserService;

    public OverviewResource(OverviewService overviewService,
                            TrafficUsageService trafficUsageService,
                            DatabaseInitializer databaseInitializer,
                            ManagementContextResolver contextResolver,
                            ManagementUserService managementUserService) {
        this.overviewService = overviewService;
        this.trafficUsageService = trafficUsageService;
        this.databaseInitializer = databaseInitializer;
        this.contextResolver = contextResolver;
        this.managementUserService = managementUserService;
    }

    @GetMapping("/overview")
    public Map<String, Object> overview(@AuthenticationPrincipal Jwt jwt) {
        trafficUsageService.flush();
        return overviewService.overview(contextResolver.resolve(jwt));
    }

    @PostMapping("/database/initialize")
    public Map<String, Object> initializeDatabase(@AuthenticationPrincipal Jwt jwt) {
        ManagementContext context = contextResolver.resolve(jwt);
        managementUserService.requireAdmin(context);
        return databaseInitializer.initialize(context.tenant());
    }
}
