package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

/**
 * Short-lived, low-entropy code that can be exchanged for a strong room access token.
 * The plaintext eight-digit code is never persisted.
 */
@Entity
@Table(name = "public_transfer_room_pairing_code",
        uniqueConstraints = @UniqueConstraint(name = "uk_public_transfer_pairing_code_hash", columnNames = "code_hash"),
        indexes = @Index(name = "idx_public_transfer_pairing_room", columnList = "room_id"))
@Getter
@Setter
public class PublicTransferRoomPairingCode {
    @Id
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "room_id", nullable = false)
    private PublicTransferRoom room;

    @Column(name = "code_hash", nullable = false, length = 64)
    private String codeHash;

    @Column(nullable = false, length = 16)
    private String role;

    @Column(nullable = false, length = 80)
    private String label;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;

    @Column(name = "max_uses", nullable = false)
    private int maxUses;

    @Column(name = "used_count", nullable = false)
    private int usedCount;

    @Column(name = "revoked_at", length = 40)
    private String revokedAt;
}
