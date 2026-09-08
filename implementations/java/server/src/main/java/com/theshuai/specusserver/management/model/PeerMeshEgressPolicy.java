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
 * Per-device egress authorization, stored separately from {@link PeerMeshAcl}.
 *
 * <p>The two are orthogonal on purpose: {@code PeerMeshAcl} answers whether two devices may reach
 * each other inside the mesh, which says nothing about whether one of them may be used as a way out
 * to the wider network. Effective permission is the intersection of the two.
 */
@Entity
@Table(name = "peer_mesh_egress_policy",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_peer_egress_policy_client",
                columnNames = {"tenant_id", "egress_client_id"}
        ),
        indexes = {
                @Index(name = "idx_peer_egress_policy_tenant", columnList = "tenant_id"),
                @Index(name = "idx_peer_egress_policy_enabled", columnList = "tenant_id, enabled")
        })
@Getter
@Setter
public class PeerMeshEgressPolicy {
    /** Cap on the serialised destination rule list; enforced before persisting. */
    public static final int MAX_DESTINATION_RULES_BYTES = 4096;
    public static final int MAX_DESTINATION_RULES = 64;

    @Id
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "owner_username", nullable = false, length = 80)
    private String ownerUsername;

    @Column(name = "egress_client_id", nullable = false)
    private Long egressClientId;

    @Column(name = "egress_client_name", nullable = false, length = 120)
    private String egressClientName;

    /** Off by default. Both new installations and upgrades must stay off. */
    @Column(nullable = false)
    private boolean enabled = false;

    /** {@code PUBLIC} or {@code LAN}; neither implies the other. */
    @Column(nullable = false, length = 16)
    private String scope = "PUBLIC";

    /** Comma-separated client ids, encoded the same way as shared service allowlists. */
    @Column(name = "allowed_consumer_client_ids", length = 512)
    private String allowedConsumerClientIds = "";

    /**
     * Canonical JSON array of {@code {cidr, protocols, portRanges}} objects.
     *
     * <p>Empty denies everything. There is no unconfigured-therefore-open state.
     */
    @Column(name = "destination_rules", length = MAX_DESTINATION_RULES_BYTES)
    private String destinationRules = "[]";

    @Column(name = "max_concurrent_flows", nullable = false)
    private int maxConcurrentFlows = 256;

    @Column(name = "max_flows_per_consumer", nullable = false)
    private int maxFlowsPerConsumer = 64;

    @Column(name = "idle_timeout_seconds", nullable = false)
    private int idleTimeoutSeconds = 60;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
