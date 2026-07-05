package com.theshuai.tunnelserver.management.model;

import java.util.List;

/**
 * Peer mesh 打洞/路径聚合统计。
 *
 * <p>{@code activeDirectRatio} = 当前活跃会话中 DIRECT 路径占比，是「打洞成功率」的
 * 直接代理指标；{@code reportedSessions} 只统计收到过 PATH_REPORT 的会话，排除从未
 * 确立路径就超时关闭的协商会话。natTypes 来自设备侧 NAT 探测上报，用于定位失败
 * 集中在哪类 NAT 组合。
 */
public record PeerMeshPathStatsView(
        long totalSessions,
        long reportedSessions,
        long activeSessions,
        long activeDirectSessions,
        long activeRelaySessions,
        Double activeDirectRatio,
        List<PathTypeStat> pathTypes,
        List<NatTypeStat> natTypes) {

    public record PathTypeStat(
            String pathType,
            String status,
            long sessions,
            long reportedSessions,
            Double avgRttMillis,
            long directBytes,
            long relayBytes) {
    }

    public record NatTypeStat(String natType, long devices) {
    }
}
