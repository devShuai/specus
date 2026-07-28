package com.theshuai.specusserver.management.repository;

public interface ClientAuthNonceRepositoryCustom {
    int insertIfAbsent(String id, String apiKeyHash, String expiresAt);
}
