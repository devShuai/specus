package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.model.PeerMeshAclView;
import com.theshuai.tunnelserver.management.model.PeerMeshDeviceView;
import com.theshuai.tunnelserver.management.model.PeerMeshSessionView;
import com.theshuai.tunnelserver.management.security.ManagementContextResolver;
import com.theshuai.tunnelserver.management.service.PeerMeshService;
import com.theshuai.tunnelserver.management.service.PeerSignalService;
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
    private final ManagementContextResolver contextResolver;

    public PeerMeshResource(PeerMeshService peerMeshService,
                            PeerSignalService peerSignalService,
                            ManagementContextResolver contextResolver) {
        this.peerMeshService = peerMeshService;
        this.peerSignalService = peerSignalService;
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
        return peerMeshService.updateDevice(contextResolver.resolve(jwt), clientId, request);
    }

    @GetMapping("/acls")
    public List<PeerMeshAclView> acls(@AuthenticationPrincipal Jwt jwt) {
        return peerMeshService.listAcls(contextResolver.resolve(jwt));
    }

    @PostMapping("/acls")
    public PeerMeshAclView createAcl(@AuthenticationPrincipal Jwt jwt,
                                     @RequestBody PeerMeshService.AclMutation request) {
        return peerMeshService.createAcl(contextResolver.resolve(jwt), request);
    }

    @DeleteMapping("/acls/{id}")
    public void deleteAcl(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        peerMeshService.deleteAcl(contextResolver.resolve(jwt), id);
    }

    @GetMapping("/sessions")
    public List<PeerMeshSessionView> sessions(@AuthenticationPrincipal Jwt jwt,
                                              @RequestParam(defaultValue = "100") int limit) {
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
}
