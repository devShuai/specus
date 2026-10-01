package com.theshuai.specusserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.ColumnDefault;

@Entity
@Table(name = "specus_client_session", indexes = {
        @Index(name = "idx_client_session_token", columnList = "token_hash"),
        @Index(name = "idx_client_session_credential_status", columnList = "credential_id, status"),
        @Index(name = "idx_client_session_machine_status", columnList = "credential_id, machine_fingerprint, os_user, status")
})
@Getter
@Setter
public class ClientSession {
    @Id
    private Long id;

    @Column(name = "tenant_id", length = 80, nullable = false)
    private String tenantId;

    @Column(name = "credential_id", nullable = false)
    private Long credentialId;

    @Column(name = "identity_id", nullable = false)
    private Long identityId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(nullable = false, length = 40)
    private String status;

    @Column(name = "machine_fingerprint", nullable = false, length = 160)
    private String machineFingerprint;

    @Column(name = "os_user", nullable = false, length = 120)
    private String osUser;

    @Column(name = "hostname", length = 160)
    private String hostname;

    @Column(name = "os_name", length = 120)
    private String osName;

    @Column(name = "os_version", length = 80)
    private String osVersion;

    @Column(name = "os_arch", length = 60)
    private String osArch;

    @Column(name = "client_version", length = 80)
    private String clientVersion;

    @Column(name = "java_version", length = 80)
    private String javaVersion;

    @Column(name = "local_addresses", length = 2000)
    private String localAddresses;

    @Column(name = "message_send_capable", nullable = false)
    private boolean messageSendCapable;

    @Column(name = "message_receive_capable", nullable = false)
    private boolean messageReceiveCapable;

    @Column(name = "message_attachments_capable", nullable = false)
    private boolean messageAttachmentsCapable;

    @Column(name = "message_media_preview_capable", nullable = false)
    private boolean messageMediaPreviewCapable;

    @Column(name = "message_max_attachment_bytes", nullable = false)
    private long messageMaxAttachmentBytes;

    @Column(name = "peer_service_discovery_version", nullable = false)
    private int peerServiceDiscoveryVersion;

    @Column(name = "peer_service_applications", length = 160)
    private String peerServiceApplications;

    /**
     * Peer egress split routing version the client announced at login. 0 or absent means it cannot
     * take part, and the server must not push egress-config or egress-catalog to it.
     */
    @Column(name = "client_egress_version", nullable = false)
    private int clientEgressVersion;

    /**
     * Whether the client, as an egress, announced at login that it resolves domain targets
     * ({@code domainTargetCapable} in {@code clientEgressCapabilities}). Only meaningful with
     * {@link #clientEgressVersion} of 1 or more; it is stored false otherwise.
     *
     * <p>The column default matters: an existing session table gets this column from Hibernate's
     * schema update, and a NOT NULL column added without a default is refused by SQLite and by a
     * non-empty PostgreSQL table. The startup migrator adds it the same way when Hibernate did not.
     */
    @ColumnDefault("false")
    @Column(name = "client_egress_domain_targets", nullable = false)
    private boolean clientEgressDomainTargets;

    @Column(name = "http_login_at", nullable = false, length = 40)
    private String httpLoginAt;

    @Column(name = "netty_connected_at", length = 40)
    private String nettyConnectedAt;

    @Column(name = "disconnected_at", length = 40)
    private String disconnectedAt;

    @Column(name = "expires_at", nullable = false, length = 40)
    private String expiresAt;

    @Column(name = "channel_id", length = 160)
    private String channelId;

    @Column(name = "remote_address", length = 255)
    private String remoteAddress;
}
