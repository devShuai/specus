package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "public_transfer_diagram_version",
        indexes = {
                @Index(name = "idx_public_transfer_version_room", columnList = "room_id"),
                @Index(name = "idx_public_transfer_version_created", columnList = "created_at")
        })
@Getter
@Setter
public class PublicTransferDiagramVersion {
    @Id
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "room_id", nullable = false)
    private PublicTransferRoom room;

    @Column(nullable = false, length = 80)
    private String name;

    @Column(name = "author_peer_id", nullable = false, length = 120)
    private String authorPeerId;

    @Lob
    @Column(name = "snapshot_data", nullable = false)
    private byte[] snapshotData;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;
}
