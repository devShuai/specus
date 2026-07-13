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

@Entity
@Table(name = "public_transfer_room_access",
        uniqueConstraints = @UniqueConstraint(name = "uk_public_transfer_access_token", columnNames = "token_hash"),
        indexes = @Index(name = "idx_public_transfer_access_room", columnList = "room_id"))
@Getter
@Setter
public class PublicTransferRoomAccess {
    @Id
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "room_id", nullable = false)
    private PublicTransferRoom room;

    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(nullable = false, length = 16)
    private String role;

    @Column(nullable = false, length = 80)
    private String label;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "revoked_at", length = 40)
    private String revokedAt;
}
