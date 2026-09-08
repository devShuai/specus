package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.PeerMeshEgressPolicyView;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.PeerEgressService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/admin/peer-mesh/egress")
public class PeerEgressResource {
    private final PeerEgressService peerEgressService;
    private final ManagementContextResolver contextResolver;

    public PeerEgressResource(PeerEgressService peerEgressService,
                              ManagementContextResolver contextResolver) {
        this.peerEgressService = peerEgressService;
        this.contextResolver = contextResolver;
    }

    @GetMapping("/policies")
    public List<PeerMeshEgressPolicyView> policies(@AuthenticationPrincipal Jwt jwt) {
        return peerEgressService.listPolicyViews(contextResolver.resolve(jwt));
    }

    /** Upsert by {@code egressClientId}; omitted fields keep their stored value. */
    @PostMapping("/policies")
    public PeerMeshEgressPolicyView upsert(@AuthenticationPrincipal Jwt jwt,
                                           @RequestBody PeerEgressService.PolicyMutation request) {
        return peerEgressService.upsertPolicyView(contextResolver.resolve(jwt), request);
    }

    @DeleteMapping("/policies/{id}")
    public void delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        peerEgressService.deletePolicy(contextResolver.resolve(jwt), id);
    }
}
