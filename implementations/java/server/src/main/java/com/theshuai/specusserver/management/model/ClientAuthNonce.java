package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "specus_client_auth_nonce", indexes = {
        @Index(name = "idx_client_auth_nonce_expires", columnList = "expires_at")
})
@Getter
@Setter
public class ClientAuthNonce {
    @Id
    @Column(length = 64)
    private String id;

    @Column(name = "api_key_hash", nullable = false, length = 64)
    private String apiKeyHash;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;
}
