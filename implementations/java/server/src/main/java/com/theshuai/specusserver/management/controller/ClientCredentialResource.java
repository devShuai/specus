package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.ClientCredentialService;
import com.theshuai.specusserver.management.service.ClientCredentialService.ClientCredentialView;
import com.theshuai.specusserver.management.service.ClientCredentialService.CredentialMutation;
import com.theshuai.specusserver.management.service.ClientCredentialService.CredentialResult;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.productmetrics.ProductMetricsModel;
import com.theshuai.specusserver.productmetrics.ProductMetricsService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
@RequestMapping("/api/admin/client-credentials")
public class ClientCredentialResource {
    private final ClientCredentialService credentialService;
    private final ManagementContextResolver contextResolver;
    private final ProductMetricsService productMetrics;

    public ClientCredentialResource(ClientCredentialService credentialService,
                                    ManagementContextResolver contextResolver,
                                    ProductMetricsService productMetrics) {
        this.credentialService = credentialService;
        this.contextResolver = contextResolver;
        this.productMetrics = productMetrics;
    }

    @GetMapping
    public List<ClientCredentialView> list(@AuthenticationPrincipal Jwt jwt) {
        return credentialService.list(contextResolver.resolve(jwt));
    }

    @PostMapping
    public ResponseEntity<CredentialResult> create(@AuthenticationPrincipal Jwt jwt,
                                                   @RequestBody CredentialMutation request) {
        ManagementContext context = contextResolver.resolve(jwt);
        CredentialResult created = credentialService.create(context, request);
        // The credential belongs to the caller (ClientCredentialService.create sets the owner).
        productMetrics.milestone(context.tenant().tenantId(), context.username(),
                ProductMetricsModel.STEP_CREDENTIAL_CREATED);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PutMapping("/{id}")
    public CredentialResult update(@AuthenticationPrincipal Jwt jwt,
                                   @PathVariable long id,
                                   @RequestBody CredentialMutation request) {
        return credentialService.update(contextResolver.resolve(jwt), id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        credentialService.delete(contextResolver.resolve(jwt), id);
        return ResponseEntity.noContent().build();
    }
}
