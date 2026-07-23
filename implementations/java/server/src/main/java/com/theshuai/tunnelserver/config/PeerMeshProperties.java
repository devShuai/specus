package com.theshuai.tunnelserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "tunnel.peer-mesh")
@Data
public class PeerMeshProperties {
    private boolean enabled = false;
    private String cidr = "100.96.0.0/11";
    private String publicAddress = "";
    private int stunTurnPort = 3478;
    private String standaloneStunAddress = "";
    private int standaloneStunPort = 3478;
    private String standaloneStunAlternateAddress = "";
    private int standaloneStunAlternatePort = 0;
    private int natProbeAlternatePort = 3479;
    private String stunPrimaryBindAddress = "";
    private String stunAlternateBindAddress = "";
    private String stunAlternatePublicAddress = "";
    private boolean stunBehaviorStrict = false;
    private List<String> publicStunServers = new ArrayList<>();
    private long sessionTtlSeconds = 3600;
    private long allocationTtlSeconds = 300;
    private int relayMinPort = 49152;
    private int relayMaxPort = 65535;
    private int relayWorkerThreads = 0;
    private int relayWorkerQueueCapacity = 10000;
    private int udpReceiveBufferBytes = 4 * 1024 * 1024;
    private int udpSendBufferBytes = 4 * 1024 * 1024;
    private int udpTrafficClass = 0x10;
    private boolean turnAuthRequired = true;
    private String turnRealm = "shuai-tunnel";
    private String turnSharedSecret = "";
    private long turnCredentialTtlSeconds = 3600;

    // ── 通用中继（公开互传的浏览器 WebRTC）配额 ────────────────────────────────
    // 这类 allocation 按标准 TURN 语义转发任意载荷，目的地址由浏览器指定，
    // 因此必须有独立于 Peer Mesh 的配额上限，避免被当作开放中继刷带宽。

    /** 通用中继并发 allocation 总数上限；<=0 表示禁用通用中继 */
    private int generalRelayMaxAllocations = 256;
    /** 同一来源 IP 的通用中继并发 allocation 上限 */
    private int generalRelayMaxAllocationsPerAddress = 4;
    /** 单个通用中继 allocation 生命周期内可转发的总字节数；<=0 表示不限。超出即关闭 allocation。 */
    private long generalRelayMaxBytes = 512L * 1024 * 1024;
}
