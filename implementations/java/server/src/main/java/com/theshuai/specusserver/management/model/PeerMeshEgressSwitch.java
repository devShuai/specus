package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

/**
 * Tenant-wide egress switch.
 *
 * <p>Separate from the per-device {@code enabled} on {@link PeerMeshEgressPolicy}, and both must be
 * on for a device to act as an egress. The per-device flag says whether that device was chosen; this
 * one lets an operator stop the whole tenant at once without editing every policy and, more
 * importantly, without losing which devices were configured when they switch it back on.
 */
@Entity
@Table(name = "peer_mesh_egress_switch")
@Getter
@Setter
public class PeerMeshEgressSwitch {
    @Id
    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    /** Off by default: egress is opt-in for the tenant as well as per device. */
    @Column(nullable = false)
    private boolean enabled = false;

    @Column(name = "updated_by", length = 80)
    private String updatedBy;

    @Column(name = "updated_at", nullable = false, length = 40)
    private String updatedAt;
}
