package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.repository.ClientAuthNonceRepository;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
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
}
