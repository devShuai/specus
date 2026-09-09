package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.PeerMeshEgressActivityView;
import com.theshuai.specusserver.management.model.PeerMeshEgressPolicyView;
import com.theshuai.specusserver.management.model.PeerMeshEgressSwitchView;
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
import org.springframework.web.bind.annotation.PutMapping;
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

    /**
     * Tenant-wide egress switch.
     *
     * <p>Separate from the per-device flag on each policy: both must be on for a device to act as an
     * egress. Switching this off stops the whole tenant without losing which devices were configured.
     */
    @GetMapping("/switch")
    public PeerMeshEgressSwitchView switchStatus(@AuthenticationPrincipal Jwt jwt) {
        return peerEgressService.switchStatus(contextResolver.resolve(jwt));
    }

    @PutMapping("/switch")
    public PeerMeshEgressSwitchView setSwitch(@AuthenticationPrincipal Jwt jwt,
                                              @RequestBody SwitchMutation request) {
        ManagementContext context = contextResolver.resolve(jwt);
        PeerMeshEgressSwitchView view = peerEgressService.setSwitch(context,
                request.enabled() != null && request.enabled());
        // Turning the tenant off has to reach the peers now, like any other authorization change.
        peerSignalService.pushTenantEgress(context.tenant().tenantId());
        return view;
    }

    /** Body of {@code PUT /switch}. */
    public record SwitchMutation(Boolean enabled) {
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

    /**
     * Latest counters each egress device reported about itself.
     *
     * <p>Counters only: the report carries no destination, domain or request content, and refusals
     * arrive aggregated by result code rather than per target.
     */
    @GetMapping("/activity")
    public List<PeerMeshEgressActivityView> activity(@AuthenticationPrincipal Jwt jwt) {
        return peerEgressService.listActivity(contextResolver.resolve(jwt), peerSignalService::isOnline);
    }

    @DeleteMapping("/policies/{id}")
    public void delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        ManagementContext context = contextResolver.resolve(jwt);
        peerEgressService.deletePolicy(context, id);
        peerSignalService.pushTenantEgress(context.tenant().tenantId());
    }
}
