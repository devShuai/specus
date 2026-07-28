package com.theshuai.specusserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 免登录文件互传的滥用防护参数。公开的 presign-upload 无鉴权,需要按来源 IP 限流,
 * 并对单房间待上传(PENDING)附件数设上限,避免刷预签名 URL 灌 OSS 产生存储/流量账单。
 *
 * <p>默认单实例使用进程内状态。启用 clusterEnabled 后，presence、转发、房间修订和公开入口限流
 * 统一使用 Redis；集群模式不允许在 Redis 不可用时退回本地状态。
 */
@Component
@ConfigurationProperties(prefix = "specus.public-transfer")
@Data
public class PublicTransferProperties {
    /** 单个来源 IP 在一个时间窗内允许的 presign-upload 次数。 */
    private int presignRateLimitPerIp = 30;

    /** 限流时间窗长度(秒)。 */
    private long presignRateLimitWindowSeconds = 300;

    /** 单房间(按 roomToken 哈希)同时存在的 PENDING 附件上限。 */
    private int maxPendingUploadsPerRoom = 50;

    /** 单个公开传输房间允许同时在线的浏览器数量。 */
    private int maxDiscoveryPeersPerRoom = 32;

    /** 单个发现 WebSocket 连接在一个时间窗内允许发送的消息数。 */
    private int discoveryMessageRateLimitPerConnection = 360;

    /** 发现 WebSocket 消息限流时间窗长度(秒)。 */
    private long discoveryMessageRateLimitWindowSeconds = 60;

    /** 是否启用公共互传多实例协调；启用后 redisUri 必填。 */
    private boolean clusterEnabled = false;

    /** Redis URI，例如 redis://user:password@redis.internal:6379/0。 */
    private String redisUri = "";

    /** Redis key/channel 前缀；多个环境共用 Redis 时必须不同。 */
    private String redisKeyPrefix = "specus:v2:public-transfer";

    /** presence 租约 TTL；需显著大于刷新间隔。 */
    private long presenceLeaseSeconds = 30;

    /** 本实例刷新本地 WebSocket presence 的间隔。 */
    private long presenceRefreshIntervalMs = 10_000;

    /** 单次 Redis 操作超时。 */
    private long redisCommandTimeoutMs = 2_000;

    /** 八位数字配对码的有效期(秒);服务端会限制在 60-900 秒。 */
    private long pairingCodeTtlSeconds = 300;

    /** 单个来源 IP 在配对码兑换时间窗内允许尝试的次数。 */
    private int pairingCodeRedeemRateLimitPerIp = 10;

    /** 配对码兑换限流时间窗长度(秒)。 */
    private long pairingCodeRedeemRateLimitWindowSeconds = 300;
}
