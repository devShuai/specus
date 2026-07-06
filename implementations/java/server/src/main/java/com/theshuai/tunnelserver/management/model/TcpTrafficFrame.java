package com.theshuai.tunnelserver.management.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "tunnel_tcp_traffic_frame",
        indexes = {
                @Index(name = "idx_tcp_frame_tenant", columnList = "tenant_id"),
                @Index(name = "idx_tcp_frame_client", columnList = "client_id"),
                @Index(name = "idx_tcp_frame_port", columnList = "listen_port"),
                @Index(name = "idx_tcp_frame_channel", columnList = "channel_id"),
                @Index(name = "idx_tcp_frame_tenant_id", columnList = "tenant_id, id"),
                @Index(name = "idx_tcp_frame_tenant_client_id", columnList = "tenant_id, client_id, id"),
                @Index(name = "idx_tcp_frame_tenant_port_id", columnList = "tenant_id, listen_port, id"),
                @Index(name = "idx_tcp_frame_tenant_client_port_id", columnList = "tenant_id, client_id, listen_port, id"),
                @Index(name = "idx_tcp_frame_tenant_channel_id", columnList = "tenant_id, channel_id, id"),
                @Index(name = "idx_tcp_frame_stream", columnList = "tenant_id, channel_id, frame_direction, stream_offset"),
                @Index(name = "idx_tcp_frame_time", columnList = "frame_time")
        })
@Getter
@Setter
public class TcpTrafficFrame {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false, length = 80)
    private String tenantId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    @Column(name = "client_name", nullable = false, length = 120)
    private String clientName;

    @Column(name = "listen_port", nullable = false)
    private int listenPort;

    @Column(name = "resource_id")
    private Long resourceId;

    @Column(name = "resource_name", nullable = false, length = 255)
    private String resourceName;

    @Column(name = "channel_id", nullable = false, length = 120)
    private String channelId;

    @Column(name = "frame_direction", nullable = false, length = 32)
    private String direction;

    @Column(name = "remote_address", length = 255)
    private String remoteAddress;

    @Column(name = "source_address", length = 255)
    private String sourceAddress;

    @Column(name = "source_port")
    private Integer sourcePort;

    @Column(name = "destination_address", length = 255)
    private String destinationAddress;

    @Column(name = "destination_port")
    private Integer destinationPort;

    @Column(name = "stream_offset")
    private Long streamOffset;

    @Column(name = "stream_end_offset")
    private Long streamEndOffset;

    @Column(name = "frame_index")
    private Long frameIndex;

    @Column(name = "payload_bytes", nullable = false)
    private long payloadBytes;

    @Lob
    @Column(name = "payload_data")
    private byte[] payloadData;

    @Column(name = "payload_preview_hex", length = 4096)
    private String payloadPreviewHex;

    @Column(name = "payload_preview_text", length = 4096)
    private String payloadPreviewText;

    @Column(name = "truncated", nullable = false)
    private boolean truncated;

    @Column(name = "frame_time", nullable = false, length = 40)
    private String frameTime;
}
