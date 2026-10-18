package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

/** Per-process consumption of the committed audit journal, NOT a device delivery acknowledgement.
 * Each running instance consumes independently; one instance must never claim another's refresh. */
@Entity
@Table(name = "client_owner_transfer_receipt", indexes =
        @Index(name = "idx_owner_receipt_node_event", columnList = "node_id,event_id"))
public class ClientOwnerTransferReceipt {
    @Id @Column(length = 80) private String id;
    @Column(name = "node_id", nullable = false, length = 36) private String node;
    @Column(name = "event_id", nullable = false) private Long event;
    @Column(name = "processed_at", nullable = false, length = 40) private String processedAt;
    protected ClientOwnerTransferReceipt() {}
}
