package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.UserDiagramDocument;
import com.theshuai.tunnelserver.management.repository.UserDiagramDocumentRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.service.UserDiagramDocumentService.DiagramDocumentMutation;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UserDiagramDocumentServiceTests {
    private UserDiagramDocumentRepository repository;
    private UserDiagramDocumentService service;

    @BeforeEach
    void setUp() {
        repository = mock(UserDiagramDocumentRepository.class);
        service = new UserDiagramDocumentService(repository);
    }

    @Test
    void createStoresDecodedSnapshotUnderCurrentAccount() {
        ManagementContext context = context("tenant-a", "alice");
        byte[] snapshot = "yjs-cloud-state".getBytes(StandardCharsets.UTF_8);
        when(repository.countByTenantIdAndOwnerUsername("tenant-a", "alice")).thenReturn(0L);
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        service.create(context, new DiagramDocumentMutation(
                "架构图",
                Base64.getEncoder().encodeToString(snapshot),
                null
        ));

        ArgumentCaptor<UserDiagramDocument> captor = ArgumentCaptor.forClass(UserDiagramDocument.class);
        verify(repository).saveAndFlush(captor.capture());
        assertEquals("tenant-a", captor.getValue().getTenantId());
        assertEquals("alice", captor.getValue().getOwnerUsername());
        assertEquals("架构图", captor.getValue().getName());
        assertArrayEquals(snapshot, captor.getValue().getSnapshotData());
    }

    @Test
    void listIsAlwaysScopedByTenantAndUsername() {
        when(repository.findSummariesByOwner("tenant-a", "alice"))
                .thenReturn(List.of());

        service.list(context("tenant-a", "alice"));

        verify(repository).findSummariesByOwner("tenant-a", "alice");
    }

    @Test
    void anotherAccountCannotReadDocument() {
        when(repository.findByIdAndTenantIdAndOwnerUsername(42L, "tenant-b", "bob"))
                .thenReturn(Optional.empty());

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.get(context("tenant-b", "bob"), 42L));

        assertEquals(HttpStatus.NOT_FOUND, error.getStatusCode());
    }

    @Test
    void staleRevisionCannotOverwriteCloudDocument() {
        UserDiagramDocument document = document(42L, "tenant-a", "alice", 3L);
        when(repository.findByIdAndTenantIdAndOwnerUsername(42L, "tenant-a", "alice"))
                .thenReturn(Optional.of(document));

        ResponseStatusException error = assertThrows(ResponseStatusException.class, () -> service.update(
                context("tenant-a", "alice"),
                42L,
                new DiagramDocumentMutation("架构图", Base64.getEncoder().encodeToString(new byte[]{1}), 2L)
        ));

        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
    }

    private static ManagementContext context(String tenantId, String username) {
        return new ManagementContext(new TenantContext(tenantId), username, false);
    }

    private static UserDiagramDocument document(long id, String tenantId, String username, long revision) {
        UserDiagramDocument document = new UserDiagramDocument();
        document.setId(id);
        document.setTenantId(tenantId);
        document.setOwnerUsername(username);
        document.setName("架构图");
        document.setSnapshotData(new byte[]{1});
        document.setSizeBytes(1);
        document.setRevision(revision);
        document.setCreatedAt("2026-07-15T00:00:00Z");
        document.setUpdatedAt("2026-07-15T00:00:00Z");
        return document;
    }
}
