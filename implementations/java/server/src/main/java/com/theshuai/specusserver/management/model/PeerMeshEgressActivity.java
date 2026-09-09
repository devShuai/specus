package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.Getter;
import lombok.Setter;

/**
 * Latest counters an egress device reported about itself.
 *
 * <p>One row per egress device rather than an append-only log: the management view needs what the
 * node is doing now, and keeping history here would grow without bound from a client-driven
 * message. Counters carry no destination, domain or request content, and refusals are aggregated by
 * result code rather than recorded per target.
 */
@Entity
@Table(name = "peer_mesh_egress_activity",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_peer_egress_activity_client",
                columnNames = {"tenant_id", "egress_client_id"}
        ),
        indexes = @Index(name = "idx_peer_egress_activity_tenant", columnList = "tenant_id"))
@Getter
@Setter
public class PeerMeshEgressActivity {
    /**
     * Cap on the serialised refusal map. Twenty-six result codes cannot fill this; the cap exists so
     * a client that invents keys cannot grow the column.
     */
    public static final int MAX_REJECTED_FLOWS_BYTES = 1024;

    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "egress_client_id", nullable = false)
    private Long egressClientId;

    @Column(name = "egress_client_name", nullable = false, length = 120)
    private String egressClientName;

    /**
     * The control-channel session the report arrived on, bound by the server from the authenticated
     * connection rather than read out of the message body.
     */
    @Column(name = "session_id")
    private Long sessionId;

    /** Client-supplied snapshot counter; a report older than the stored one is discarded. */
    @Column(name = "revision", nullable = false)
    private long revision;

    @Column(name = "active_flows", nullable = false)
    private long activeFlows;

    @Column(name = "total_flows", nullable = false)
    private long totalFlows;

    /** Refusals aggregated by result code, as canonical JSON. */
    @Column(name = "rejected_flows", length = MAX_REJECTED_FLOWS_BYTES)
    private String rejectedFlows;

    @Column(name = "bytes_in", nullable = false)
    private long bytesIn;

    @Column(name = "bytes_out", nullable = false)
    private long bytesOut;

    @Column(name = "reported_at", nullable = false, length = 40)
    private String reportedAt;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
