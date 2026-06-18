package com.theshuai.tunnelserver.management.model;

public record ConnectionRecordView(
        long id,
        Long clientId,
        String clientName,
        String channelId,
        String remoteAddress,
        String connectedAt,
        String disconnectedAt,
        boolean success,
        String failureReason,
        // 断开原因机器码（DisconnectReason.name()），未知或未打标为 null
        String disconnectReason,
        // 与机器码对应的中文人类可读 label；前端无需再做映射
        String disconnectReasonText
) {
}
