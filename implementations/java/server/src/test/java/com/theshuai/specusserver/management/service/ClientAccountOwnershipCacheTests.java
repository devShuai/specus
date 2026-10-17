package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import org.junit.jupiter.api.Test;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class ClientAccountOwnershipCacheTests {
    @Test void lookupStartedBeforeInvalidationCannotReinsertAUsableOldOwner() throws Exception {
        var repository=mock(ClientAccountRepository.class);
        var service=new ClientAccountService(repository,null,null,null,null,null,null,null,null);
        var old=new ClientAccount();old.setId(1L);old.setClientName("cache-fixture");old.setOwnerUsername("alice");
        var current=new ClientAccount();current.setId(1L);current.setClientName("cache-fixture");current.setOwnerUsername("Bob");
        var entered=new CountDownLatch(1);var resume=new CountDownLatch(1);
        when(repository.findByClientName("cache-fixture")).thenAnswer(call -> {
            entered.countDown();assertThat(resume.await(5,TimeUnit.SECONDS)).isTrue();return Optional.of(old);
        }).thenReturn(Optional.of(current));
        try(var executor=Executors.newSingleThreadExecutor()) {
            var before=executor.submit(() -> service.findClientByName("cache-fixture"));
            try {
                assertThat(entered.await(5,TimeUnit.SECONDS)).isTrue();
                service.invalidateOwnershipCache();
            } finally {resume.countDown();}
            assertThat(before.get(5,TimeUnit.SECONDS).orElseThrow().getOwnerUsername()).isEqualTo("alice");
        }
        assertThat(service.findClientByName("cache-fixture").orElseThrow().getOwnerUsername()).isEqualTo("Bob");
        assertThat(service.findClientByName("cache-fixture").orElseThrow().getOwnerUsername()).isEqualTo("Bob");
        verify(repository,times(2)).findByClientName("cache-fixture");
    }
}
