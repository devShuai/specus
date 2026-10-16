package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.model.ClientOwnerTransferPreview;
import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ClientOwnerTransferService;
import com.theshuai.specusserver.management.service.ClientOwnerTransferWriter;
import com.theshuai.specusserver.management.service.ClientOwnerTransferNotifications;
import com.theshuai.specusserver.management.service.ClientOwnerTransferException;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Explicit scope/revision writes use the coordinated transaction core; the committed audit is
 * the cross-instance notification journal. A 200 never claims remote delivery or key revocation. */
@RestController
@RequestMapping("/api/admin")
public class ClientOwnerTransferResource {
    private final ClientOwnerTransferService transfers;
    private final ManagementContextResolver contextResolver;
    private final ClientOwnerTransferWriter writer;
    private final ClientOwnerTransferNotifications notifications;
    private static final ObjectMapper JSON = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    public ClientOwnerTransferResource(ClientOwnerTransferService transfers, ManagementContextResolver contextResolver,
            ClientOwnerTransferWriter writer, ClientOwnerTransferNotifications notifications) {
        this.transfers = transfers;
        this.contextResolver = contextResolver;
        this.writer = writer; this.notifications = notifications;
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

    @PostMapping("/clients/{id}/owner-transfer")
    public ResponseEntity<ClientOwnerTransferWriter.Result> transferClient(@AuthenticationPrincipal Jwt jwt,
            @PathVariable String id, HttpServletRequest request) {
        ManagementContext actor = administrator(jwt);
        return committed(writer.transferClient(actor, id, body(request)));
    }

    @PostMapping("/client-credentials/{id}/owner-transfer")
    public ResponseEntity<ClientOwnerTransferWriter.Result> transferCredential(@AuthenticationPrincipal Jwt jwt,
            @PathVariable String id, HttpServletRequest request) {
        ManagementContext actor = administrator(jwt);
        return committed(writer.transferCredential(actor, id, body(request)));
    }

    private ManagementContext administrator(Jwt jwt) {
        ManagementContext actor = contextResolver.resolve(jwt);
        if (!actor.isAdmin()) throw new ClientOwnerTransferException(403, "FORBIDDEN");
        return actor; // The writer revalidates this identity under its current ordered row locks.
    }

    private static JsonNode body(HttpServletRequest request) {
        try {
            byte[] bytes = request.getInputStream().readNBytes(65_537);
            if (bytes.length > 65_536) throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST");
            return JSON.readTree(bytes);
        } catch (IOException invalid) { throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST"); }
    }

    private ResponseEntity<ClientOwnerTransferWriter.Result> committed(ClientOwnerTransferWriter.Outcome outcome) {
        // Writer proxy has returned: its commit/rollback and connection release have completed.
        // Notification failures retain the durable pending event, never turn a committed write into failure.
        notifications.committed(outcome.auditId());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(outcome.response());
    }
}
