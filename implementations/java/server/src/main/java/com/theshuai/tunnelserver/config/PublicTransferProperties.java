package com.theshuai.tunnelserver.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * 免登录文件互传的滥用防护参数。公开的 presign-upload 无鉴权,需要按来源 IP 限流,
 * 并对单房间待上传(PENDING)附件数设上限,避免刷预签名 URL 灌 OSS 产生存储/流量账单。
 *
 * <p>限流为进程内计数,多实例部署时上限按实例数放大;作为一线滥用缓解足够,精确全局配额需外置存储。
 */
@Component
@ConfigurationProperties(prefix = "tunnel.public-transfer")
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
    private int discoveryMessageRateLimitPerConnection = 120;

    /** 发现 WebSocket 消息限流时间窗长度(秒)。 */
    private long discoveryMessageRateLimitWindowSeconds = 60;
}
