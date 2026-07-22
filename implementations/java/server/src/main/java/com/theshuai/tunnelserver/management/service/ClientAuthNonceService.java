package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.security.HmacSigner;
import com.theshuai.tunnelserver.management.repository.ClientAuthNonceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HexFormat;

@Service
public class ClientAuthNonceService {
    private static final long NONCE_TTL_SECONDS = 120;

    private final ClientAuthNonceRepository repository;

    public ClientAuthNonceService(ClientAuthNonceRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean consume(String apiKey, String nonce) {
        Instant now = Instant.now();
        repository.deleteExpired(now.toString());
        String apiKeyHash = sha256(apiKey);
        String nonceId = sha256(apiKeyHash + "\n" + nonce);
        return repository.insertIfAbsent(nonceId, apiKeyHash, now.plusSeconds(NONCE_TTL_SECONDS).toString()) == 1;
    }

    private static String sha256(String value) {
        return HexFormat.of().formatHex(HmacSigner.sha256(value));
    }
}
