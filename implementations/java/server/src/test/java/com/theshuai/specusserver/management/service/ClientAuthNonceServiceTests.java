package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.repository.ClientAuthNonceRepository;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientAuthNonceServiceTests {
    @Test
    void duplicateNonceForSameApiKeyIsRejectedAtomically() {
        ClientAuthNonceRepository repository = mock(ClientAuthNonceRepository.class);
        when(repository.insertIfAbsent(anyString(), anyString(), anyString())).thenReturn(1, 0);
        ClientAuthNonceService service = new ClientAuthNonceService(repository);

        assertTrue(service.consume("api-key", "nonce"));
        assertFalse(service.consume("api-key", "nonce"));
    }

    @Test
    void expiryAndPurgeCutoffHaveTheSortableWidth() {
        ClientAuthNonceRepository repository = mock(ClientAuthNonceRepository.class);
        when(repository.insertIfAbsent(anyString(), anyString(), anyString())).thenReturn(1);

        new ClientAuthNonceService(repository).consume("api-key", "nonce");

        verify(repository).deleteExpired(argThat(now -> now.length() == SortableInstant.LENGTH));
        verify(repository).insertIfAbsent(anyString(), anyString(),
                argThat(expiresAt -> expiresAt.length() == SortableInstant.LENGTH));
    }
}
