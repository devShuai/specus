package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One service reference on a management identity's workbench (protocol/spec/service-workbench.md
 * section 4.2): a favourite or a recent open of an HTTP route, TCP mapping or Peer service.
 *
 * <p>The row holds the identity, the list, the reference and one time in epoch milliseconds --
 * nothing else (no names, addresses, ports, caller IP or counts). No foreign keys, like every other
 * table; deleting an object or an account removes its rows explicitly (see
 * {@code WorkbenchReferences}). The table is created by Hibernate's schema update, like
 * {@code user_diagram_document}.
 */
@Entity
@Table(name = "management_workbench_item",
        indexes = {
                // Hibernate orders primary key columns by type size, not as declared, so the reads
                // of one identity (every request) get an index of their own.
                @Index(name = "idx_mwi_identity", columnList = "tenant_id, username"),
                @Index(name = "idx_mwi_object", columnList = "tenant_id, kind, object_id"),
                @Index(name = "idx_mwi_list_at", columnList = "list, at_ms")
        })
@Getter
@Setter
@NoArgsConstructor
public class ManagementWorkbenchItem {
    public static final String FAVORITE = "favorite";
    public static final String RECENT = "recent";

    @EmbeddedId
    private Key key;

    /** addedAt of a favourite, visitedAt of a recent open; server clock, epoch milliseconds. */
    @Column(name = "at_ms", nullable = false)
    private long atMs;

    public ManagementWorkbenchItem(Key key, long atMs) {
        this.key = key;
        this.atMs = atMs;
    }

    /** Primary key {@code (tenant_id, username, list, kind, object_id)}: one row per reference and list. */
    @Embeddable
    public record Key(
            @Column(name = "tenant_id", nullable = false, length = 80) String tenantId,
            @Column(name = "username", nullable = false, length = 80) String username,
            @Column(name = "list", nullable = false, length = 16) String listName,
            @Column(name = "kind", nullable = false, length = 32) String kind,
            @Column(name = "object_id", nullable = false) Long objectId) {
    }
}
