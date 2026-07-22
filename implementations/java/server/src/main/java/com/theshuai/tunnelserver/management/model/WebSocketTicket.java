package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_websocket_ticket", indexes = {
        @Index(name = "idx_ws_ticket_expires", columnList = "expires_at")
})
@Getter
@Setter
public class WebSocketTicket {
    @Id
    @Column(name = "token_hash", length = 64)
    private String tokenHash;

    @Column(nullable = false, length = 40)
    private String scope;

    @Lob
    @Column(name = "attributes_json", nullable = false)
    private String attributesJson;

    @Column(name = "remote_address_hash", length = 64)
    private String remoteAddressHash;

    @Column(name = "created_at", nullable = false, length = 40)
    private String createdAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;
}
