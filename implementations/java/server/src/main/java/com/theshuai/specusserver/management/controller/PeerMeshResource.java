package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.PeerMeshAclView;
import com.theshuai.specusserver.management.model.PeerMeshDeviceView;
import com.theshuai.specusserver.management.model.PeerMeshPathStatsView;
import com.theshuai.specusserver.management.model.PeerMeshServiceSharingView;
import com.theshuai.specusserver.management.model.PeerMeshSessionView;
import com.theshuai.specusserver.management.model.PeerMeshSharedServiceView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.PeerMeshService;
import com.theshuai.specusserver.management.service.PeerServiceDiscoveryService;
import com.theshuai.specusserver.management.service.PeerSignalService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/admin/peer-mesh")
public class PeerMeshResource {
    private final PeerMeshService peerMeshService;
    private final PeerSignalService peerSignalService;
    private final PeerServiceDiscoveryService peerServiceDiscoveryService;
    private final ManagementContextResolver contextResolver;

    public PeerMeshResource(PeerMeshService peerMeshService,
                            PeerSignalService peerSignalService,
                            PeerServiceDiscoveryService peerServiceDiscoveryService,
                            ManagementContextResolver contextResolver) {
        this.peerMeshService = peerMeshService;
        this.peerSignalService = peerSignalService;
        this.peerServiceDiscoveryService = peerServiceDiscoveryService;
        this.contextResolver = contextResolver;
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("enabled", peerMeshService.isEnabled());
        return status;
    }

    @GetMapping("/devices")
    public List<PeerMeshDeviceView> devices(@AuthenticationPrincipal Jwt jwt) {
        return peerMeshService.listDevices(contextResolver.resolve(jwt));
    }

    @PutMapping("/devices/{clientId}")
    public PeerMeshDeviceView updateDevice(@AuthenticationPrincipal Jwt jwt,
                                           @PathVariable long clientId,
                                           @RequestBody PeerMeshService.DeviceMutation request) {
        var context = contextResolver.resolve(jwt);
        PeerMeshDeviceView updated = peerMeshService.updateDevice(context, clientId, request);
        if (request.enabled() != null) {
            peerSignalService.refreshDevice(context, updated.clientId(), request.enabled());
        }
        return updated;
    }

    @GetMapping("/acls")
    public List<PeerMeshAclView> acls(@AuthenticationPrincipal Jwt jwt) {
        return peerMeshService.listAcls(contextResolver.resolve(jwt));
    }

    @PostMapping("/acls")
    public PeerMeshAclView createAcl(@AuthenticationPrincipal Jwt jwt,
                                     @RequestBody PeerMeshService.AclMutation request) {
        var context = contextResolver.resolve(jwt);
        PeerMeshAclView created = peerMeshService.createAcl(context, request);
        peerSignalService.refreshAuthorization(context);
        return created;
    }

    @DeleteMapping("/acls/{id}")
    public void deleteAcl(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        var context = contextResolver.resolve(jwt);
        peerMeshService.deleteAcl(context, id);
        peerSignalService.refreshAuthorization(context);
    }

    /** 打洞/路径聚合统计：activeDirectRatio 即当前活跃会话的直连占比 */
    @GetMapping("/stats")
    public PeerMeshPathStatsView stats(@AuthenticationPrincipal Jwt jwt) {
        return peerMeshService.pathStats(contextResolver.resolve(jwt));
    }

    @GetMapping("/sessions")
    public Object sessions(@AuthenticationPrincipal Jwt jwt,
                           @RequestParam(defaultValue = "100") int limit,
                           @RequestParam(required = false) Integer page,
                           @RequestParam(required = false) Integer size,
                           @RequestParam(defaultValue = "false") boolean openOnly) {
        if (page != null || size != null) {
            return peerMeshService.listSessionsPage(
                    contextResolver.resolve(jwt),
                    page == null ? 0 : page,
                    size == null ? limit : size,
                    openOnly
            );
        }
        return peerMeshService.listSessions(contextResolver.resolve(jwt), limit);
    }

    @DeleteMapping("/sessions/{id}")
    public PeerMeshSessionView closeSession(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        return peerSignalService.forceClose(contextResolver.resolve(jwt), id);
    }

    @DeleteMapping("/sessions")
    public List<PeerMeshSessionView> closeOpenSessions(@AuthenticationPrincipal Jwt jwt) {
        return peerSignalService.forceCloseOpenSessions(contextResolver.resolve(jwt));
    }

    @GetMapping("/service-sharing")
    public PeerMeshServiceSharingView serviceSharing(@AuthenticationPrincipal Jwt jwt) {
        return peerServiceDiscoveryService.sharingStatus(contextResolver.resolve(jwt));
    }

    @PutMapping("/service-sharing")
    public PeerMeshServiceSharingView updateServiceSharing(@AuthenticationPrincipal Jwt jwt,
                                                           @RequestBody Map<String, Object> body) {
        var context = contextResolver.resolve(jwt);
        Object raw = body == null ? null : body.get("enabled");
        Boolean enabled = raw instanceof Boolean flag ? flag : null;
        Object mdnsRaw = body == null ? null : body.get("mdnsImportEnabled");
        Boolean mdnsImportEnabled = mdnsRaw instanceof Boolean flag ? flag : null;
        var result = peerServiceDiscoveryService.setSharing(context, enabled, mdnsImportEnabled);
        if (result.pushConfig()) {
            peerSignalService.pushSharingConfig(context);
        }
        peerSignalService.pushCatalogs(result.catalogs());
        return result.status();
    }

    @GetMapping("/services")
    public List<PeerMeshSharedServiceView> services(@AuthenticationPrincipal Jwt jwt) {
        return peerServiceDiscoveryService.listServices(contextResolver.resolve(jwt));
    }

    @PostMapping("/services")
    public PeerMeshSharedServiceView createService(@AuthenticationPrincipal Jwt jwt,
                                                   @RequestBody PeerServiceDiscoveryService.ServiceMutation request) {
        var context = contextResolver.resolve(jwt);
        var created = peerServiceDiscoveryService.createService(context, request);
        peerSignalService.pushServiceConfig(context, created.clientId());
        return created;
    }

    @PutMapping("/services/{id}")
    public PeerMeshSharedServiceView updateService(@AuthenticationPrincipal Jwt jwt,
                                                   @PathVariable long id,
                                                   @RequestBody PeerServiceDiscoveryService.ServiceMutation request) {
        var context = contextResolver.resolve(jwt);
        var result = peerServiceDiscoveryService.updateService(context, id, request);
        peerSignalService.pushServiceConfig(context, result.service().clientId());
        peerSignalService.pushCatalogs(result.catalogs());
        return result.service();
    }

    @DeleteMapping("/services/{id}")
    public void deleteService(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        var context = contextResolver.resolve(jwt);
        var result = peerServiceDiscoveryService.deleteService(context, id);
        peerSignalService.pushServiceConfig(context, result.service().clientId());
        peerSignalService.pushCatalogs(result.catalogs());
    }

    @PostMapping("/services/import")
    public PeerServiceDiscoveryService.ImportResult importServices(@AuthenticationPrincipal Jwt jwt,
                                                                   @RequestBody Map<String, Object> body) {
        Object raw = body == null ? null : body.get("clientId");
        Long clientId = raw instanceof Number number ? number.longValue() : null;
        Object sourceRaw = body == null ? null : body.get("source");
        String source = sourceRaw instanceof String value ? value : "tcp-http";
        return peerServiceDiscoveryService.importCandidates(contextResolver.resolve(jwt), clientId, source);
    }

    @GetMapping("/service-audit")
    public List<PeerServiceDiscoveryService.AuditEvent> serviceAudit(@AuthenticationPrincipal Jwt jwt) {
        return peerServiceDiscoveryService.recentAudits(contextResolver.resolve(jwt));
    }
}
