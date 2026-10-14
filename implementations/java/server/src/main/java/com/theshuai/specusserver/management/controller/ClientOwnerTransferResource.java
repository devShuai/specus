package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ClientOwnerTransferPreview;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ClientOwnerTransferService;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Only preview GETs are currently delivered; POST must not perform an uncoordinated handover. */
@RestController
@RequestMapping("/api/admin")
public class ClientOwnerTransferResource {
    private final ClientOwnerTransferService transfers;
    private final ManagementContextResolver contextResolver;

    public ClientOwnerTransferResource(ClientOwnerTransferService transfers, ManagementContextResolver contextResolver) {
        this.transfers = transfers;
        this.contextResolver = contextResolver;
    }

    @GetMapping("/clients/{id}/owner-transfer")
    public ResponseEntity<ClientOwnerTransferPreview> previewClient(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(transfers.previewClient(contextResolver.resolve(jwt), id));
    }

    @GetMapping("/client-credentials/{id}/owner-transfer")
    public ResponseEntity<ClientOwnerTransferPreview> previewCredential(@AuthenticationPrincipal Jwt jwt, @PathVariable String id) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(transfers.previewCredential(contextResolver.resolve(jwt), id));
    }
}
