package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.UserDiagramDocumentService;
import com.theshuai.specusserver.management.service.UserDiagramDocumentService.DiagramDocumentDetail;
import com.theshuai.specusserver.management.service.UserDiagramDocumentService.DiagramDocumentMutation;
import com.theshuai.specusserver.management.service.UserDiagramDocumentService.DiagramDocumentView;
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
@RequestMapping("/api/admin/diagrams")
public class UserDiagramDocumentResource {
    private final ManagementContextResolver contextResolver;
    private final UserDiagramDocumentService service;

    public UserDiagramDocumentResource(ManagementContextResolver contextResolver,
                                       UserDiagramDocumentService service) {
        this.contextResolver = contextResolver;
        this.service = service;
    }

    @GetMapping
    public List<DiagramDocumentView> list(@AuthenticationPrincipal Jwt jwt) {
        return service.list(contextResolver.resolve(jwt));
    }

    @GetMapping("/{id}")
    public DiagramDocumentDetail get(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        return service.get(contextResolver.resolve(jwt), id);
    }

    @PostMapping
    public ResponseEntity<DiagramDocumentView> create(@AuthenticationPrincipal Jwt jwt,
                                                      @RequestBody DiagramDocumentMutation request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(service.create(contextResolver.resolve(jwt), request));
    }

    @PutMapping("/{id}")
    public DiagramDocumentView update(@AuthenticationPrincipal Jwt jwt,
                                      @PathVariable long id,
                                      @RequestBody DiagramDocumentMutation request) {
        return service.update(contextResolver.resolve(jwt), id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@AuthenticationPrincipal Jwt jwt, @PathVariable long id) {
        service.delete(contextResolver.resolve(jwt), id);
        return ResponseEntity.noContent().build();
    }
}
