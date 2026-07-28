package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "public_transfer_room",
        uniqueConstraints = @UniqueConstraint(name = "uk_public_transfer_room_key", columnNames = {"room_name", "owner_token_hash"}),
        indexes = @Index(name = "idx_public_transfer_room_name", columnList = "room_name"))
@Getter
@Setter
public class PublicTransferRoom {
    @Id
    private Long id;

    @Column(name = "room_name", nullable = false, length = 120)
    private String roomName;

    @Column(name = "owner_token_hash", nullable = false, length = 64)
    private String ownerTokenHash;

    @Column(name = "created_by_peer_id", nullable = false, length = 120)
    private String createdByPeerId;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
