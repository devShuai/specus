package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.PeerMeshEgressPolicyView;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.PeerEgressService;
import com.theshuai.specusserver.management.service.PeerSignalService;
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
    private final PeerSignalService peerSignalService;
    private final ManagementContextResolver contextResolver;

    public PeerEgressResource(PeerEgressService peerEgressService,
                              PeerSignalService peerSignalService,
                              ManagementContextResolver contextResolver) {
        this.peerEgressService = peerEgressService;
        this.peerSignalService = peerSignalService;
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
        ManagementContext context = contextResolver.resolve(jwt);
        PeerMeshEgressPolicyView view = peerEgressService.upsertPolicyView(context, request);
        // Revoking or narrowing a grant has to take effect now, not at the peer next login.
        peerSignalService.pushTenantEgress(context.tenant().tenantId());
        return view;
    }

    @DeleteMapping("/policies/{id}")
    public void delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        ManagementContext context = contextResolver.resolve(jwt);
        peerEgressService.deletePolicy(context, id);
        peerSignalService.pushTenantEgress(context.tenant().tenantId());
    }
}
