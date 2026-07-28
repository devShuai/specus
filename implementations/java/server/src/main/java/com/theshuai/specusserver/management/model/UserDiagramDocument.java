package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(name = "user_diagram_document",
        indexes = {
                @Index(name = "idx_user_diagram_owner", columnList = "tenant_id,owner_username"),
                @Index(name = "idx_user_diagram_updated", columnList = "updated_at")
        })
@Getter
@Setter
public class UserDiagramDocument {
    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "owner_username", nullable = false, length = 160)
    private String ownerUsername;

    @Column(nullable = false, length = 120)
    private String name;

    @JdbcTypeCode(SqlTypes.LONGVARBINARY)
    @Column(name = "snapshot_data", nullable = false)
    private byte[] snapshotData;

    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    @Version
    @Column(nullable = false)
    private long revision;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
