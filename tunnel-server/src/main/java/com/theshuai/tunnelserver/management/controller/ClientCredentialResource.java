package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.service.ClientCredentialService;
import com.theshuai.tunnelserver.management.service.ClientCredentialService.ClientCredentialView;
import com.theshuai.tunnelserver.management.service.ClientCredentialService.CredentialMutation;
import com.theshuai.tunnelserver.management.service.ClientCredentialService.CredentialResult;
import com.theshuai.tunnelserver.management.tenant.TenantResolver;
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
    private final TenantResolver tenantResolver;

    public ClientCredentialResource(ClientCredentialService credentialService,
                                    TenantResolver tenantResolver) {
        this.credentialService = credentialService;
        this.tenantResolver = tenantResolver;
    }

    @GetMapping
    public List<ClientCredentialView> list(@AuthenticationPrincipal Jwt jwt) {
        return credentialService.list(tenantResolver.resolve(jwt));
    }

    @PostMapping
    public ResponseEntity<CredentialResult> create(@AuthenticationPrincipal Jwt jwt,
                                                   @RequestBody CredentialMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(credentialService.create(tenantResolver.resolve(jwt), request));
    }

    @PutMapping("/{id}")
    public CredentialResult update(@AuthenticationPrincipal Jwt jwt,
                                   @PathVariable long id,
                                   @RequestBody CredentialMutation request) {
        return credentialService.update(tenantResolver.resolve(jwt), id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        credentialService.delete(tenantResolver.resolve(jwt), id);
        return ResponseEntity.noContent().build();
    }
}
