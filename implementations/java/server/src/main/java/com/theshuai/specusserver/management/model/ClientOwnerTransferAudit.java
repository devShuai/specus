package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import org.hibernate.Length;

/** One atomic ownership change, not a runtime-delivery acknowledgement. No credentials/tokens. */
@Entity
@Table(name = "client_owner_transfer_audit", indexes =
        @Index(name = "idx_owner_transfer_tenant_at", columnList = "tenant_id,occurred_at,id"))
public class ClientOwnerTransferAudit {
    @Id private Long id;
    @Column(name = "tenant_id", nullable = false, length = 80) private String tenant;
    @Column(name = "occurred_at", nullable = false, length = 40) private String occurredAt;
    @Column(name = "actor", nullable = false, length = 120) private String actor;
    @Column(name = "scope", nullable = false, length = 32) private String scope;
    @Column(name = "path_id", nullable = false) private Long pathId;
    @Column(name = "target_username", nullable = false, length = 120) private String target;
    @Column(name = "credential_id") private Long credentialId;
    @Column(name = "detail_json", nullable = false, length = Length.LONG32) private String detail;
    protected ClientOwnerTransferAudit() {}
}
