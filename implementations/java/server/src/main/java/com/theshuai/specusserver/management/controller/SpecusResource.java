package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.SpecusMappingView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.NatControlService;
import com.theshuai.specusserver.management.service.NatControlService.MappingMutation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 端口映射（NAT）资源 + 推送控制端点。
 *
 * <ul>
 *   <li>{@code GET    /api/admin/specus-mappings}                   全量列表（可按 clientId 过滤）</li>
 *   <li>{@code POST   /api/admin/clients/{id}/specus-mappings}      新增映射</li>
 *   <li>{@code PUT    /api/admin/specus-mappings/{specusId}}        编辑/启停</li>
 *   <li>{@code DELETE /api/admin/specus-mappings/{specusId}}        删除</li>
 *   <li>{@code POST   /api/admin/clients/{id}/nat-control}  立刻向在线客户端推送映射快照</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/admin")
public class SpecusResource {
    private final NatControlService natControlService;
    private final ManagementContextResolver contextResolver;

    public SpecusResource(NatControlService natControlService, ManagementContextResolver contextResolver) {
        this.natControlService = natControlService;
        this.contextResolver = contextResolver;
    }

    @GetMapping("/specus-mappings")
    public List<SpecusMappingView> listSpecusMappings(@AuthenticationPrincipal Jwt jwt,
                                               @RequestParam(required = false) Long clientId) {
        return natControlService.listMappings(contextResolver.resolve(jwt), clientId);
    }

    @PostMapping("/clients/{id}/specus-mappings")
    public ResponseEntity<SpecusMappingView> createSpecus(@AuthenticationPrincipal Jwt jwt,
                                                          @PathVariable long id,
                                                          @RequestBody MappingMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(natControlService.createMapping(contextResolver.resolve(jwt), id, request));
    }

    @PutMapping("/specus-mappings/{specusId}")
    public SpecusMappingView updateSpecus(@AuthenticationPrincipal Jwt jwt,
                                          @PathVariable long specusId,
                                          @RequestBody MappingMutation request) {
        return natControlService.updateMapping(contextResolver.resolve(jwt), specusId, request);
    }

    @DeleteMapping("/specus-mappings/{specusId}")
    public ResponseEntity<Void> deleteSpecus(@AuthenticationPrincipal Jwt jwt, @PathVariable long specusId) {
        natControlService.deleteMapping(contextResolver.resolve(jwt), specusId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/clients/{id}/nat-control")
    public Map<String, Object> pushNatControl(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        NatControlService.PushResult result = natControlService.pushToClient(contextResolver.resolve(jwt), id);
        // 兼容老前端：保留 "pushed" 字段（仅 TCP 项数），新前端读 specusMappings/httpRoutes。
        // httpRoutes == -1 时代表"未在后台接管 HTTP 路由"，前端按"-"渲染。
        return Map.of(
                "pushed", result.specusMappings(),
                "specusMappings", result.specusMappings(),
                "httpRoutes", result.httpRoutes()
        );
    }
}
