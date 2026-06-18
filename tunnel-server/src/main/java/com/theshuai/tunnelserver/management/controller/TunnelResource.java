package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.TunnelMappingView;
import com.theshuai.tunnelserver.management.service.NatControlService;
import com.theshuai.tunnelserver.management.service.NatControlService.MappingMutation;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * 端口映射（NAT）资源 + 推送控制端点。
 *
 * <ul>
 *   <li>{@code GET    /api/admin/tunnels}                   全量列表（可按 clientId 过滤）</li>
 *   <li>{@code POST   /api/admin/clients/{id}/tunnels}      新增映射</li>
 *   <li>{@code PUT    /api/admin/tunnels/{tunnelId}}        编辑/启停</li>
 *   <li>{@code DELETE /api/admin/tunnels/{tunnelId}}        删除</li>
 *   <li>{@code POST   /api/admin/clients/{id}/nat-control}  立刻向在线客户端推送映射快照</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/admin")
public class TunnelResource {
    private final NatControlService natControlService;

    public TunnelResource(NatControlService natControlService) {
        this.natControlService = natControlService;
    }

    @GetMapping("/tunnels")
    public List<TunnelMappingView> listTunnels(@RequestParam(required = false) Long clientId) {
        return natControlService.listMappings(clientId);
    }

    @PostMapping("/clients/{id}/tunnels")
    public ResponseEntity<TunnelMappingView> createTunnel(@PathVariable long id, @RequestBody MappingMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(natControlService.createMapping(id, request));
    }

    @PutMapping("/tunnels/{tunnelId}")
    public TunnelMappingView updateTunnel(@PathVariable long tunnelId, @RequestBody MappingMutation request) {
        return natControlService.updateMapping(tunnelId, request);
    }

    @DeleteMapping("/tunnels/{tunnelId}")
    public ResponseEntity<Void> deleteTunnel(@PathVariable long tunnelId) {
        natControlService.deleteMapping(tunnelId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/clients/{id}/nat-control")
    public Map<String, Object> pushNatControl(@PathVariable long id) {
        NatControlService.PushResult result = natControlService.pushToClient(id);
        // 兼容老前端：保留 "pushed" 字段（仅 TCP 项数），新前端读 tunnels/httpRoutes。
        // httpRoutes == -1 时代表"未在后台接管 HTTP 路由"，前端按"-"渲染。
        return Map.of(
                "pushed", result.tunnels(),
                "tunnels", result.tunnels(),
                "httpRoutes", result.httpRoutes()
        );
    }
}
