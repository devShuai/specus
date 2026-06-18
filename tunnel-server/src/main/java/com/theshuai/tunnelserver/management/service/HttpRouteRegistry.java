package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.HttpRouteView;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 服务端内存中保存"每个在线客户端当前生效的 HTTP 路由"快照，仅供管理 UI 展示。
 *
 * <p>数据生命周期：
 * <ul>
 *   <li>客户端登录后通过 {@code HTTP_ROUTES_REPORT} 上报，{@link #report(String, Long, List)}
 *       覆盖式写入（不做 diff，整份替换）</li>
 *   <li>对应 channel inactive 时由 {@code NatServerHandler} 调 {@link #clear(String)} 移除</li>
 *   <li>服务端重启自然清空，下次客户端重连后会再次上报</li>
 * </ul>
 *
 * <p>线程安全：{@link ConcurrentHashMap}；report/clear 与 list 之间允许短暂的不一致，
 * 但展示场景对一致性要求弱，可接受。
 */
@Component
public class HttpRouteRegistry {

    /** 单条路由 + 上报时间。clientId 在 list 时由 controller 根据 clientName 反查，避免登录时还要查库。 */
    private record Entry(String route, String targetBaseUrl, String reportedAt) {
    }

    /** 一个客户端的全部路由。 */
    private record Snapshot(List<Entry> entries, String reportedAt) {
    }

    private final Map<String, Snapshot> byClientName = new ConcurrentHashMap<>();

    /**
     * 覆盖式上报一个客户端当前生效的所有 HTTP 路由。空列表也接受（表示"客户端没有配置 HTTP 路由"）。
     *
     * @param clientName 已通过 session 校验过的客户端名（非空）
     * @param routes     {@code [{"route":"web","targetBaseUrl":"https://..."}, ...]}
     */
    public void report(String clientName, List<Map<String, Object>> routes) {
        if (clientName == null || clientName.isBlank()) {
            return;
        }
        String now = Instant.now().toString();
        List<Entry> entries = new ArrayList<>(routes == null ? 0 : routes.size());
        if (routes != null) {
            for (Map<String, Object> r : routes) {
                if (r == null) {
                    continue;
                }
                String route = Objects.toString(r.get("route"), null);
                String target = Objects.toString(r.get("targetBaseUrl"), "");
                if (route == null || route.isBlank()) {
                    continue;
                }
                entries.add(new Entry(route.trim(), target == null ? "" : target.trim(), now));
            }
        }
        byClientName.put(clientName, new Snapshot(List.copyOf(entries), now));
    }

    /** 客户端断开时调用，幂等。 */
    public void clear(String clientName) {
        if (clientName != null) {
            byClientName.remove(clientName);
        }
    }

    /** 不带过滤的全量列表。{@code clientIdResolver} 用于反查 clientId（可能未登录账号，返回 null）。 */
    public List<HttpRouteView> listAll(java.util.function.Function<String, Long> clientIdResolver) {
        List<HttpRouteView> result = new ArrayList<>();
        byClientName.forEach((clientName, snapshot) -> {
            Long clientId = clientIdResolver == null ? null : clientIdResolver.apply(clientName);
            for (Entry e : snapshot.entries()) {
                result.add(new HttpRouteView(clientId, clientName, e.route(), e.targetBaseUrl(), e.reportedAt()));
            }
        });
        // 同客户端内部按 route 名稳定排序，跨客户端按 clientName
        result.sort((a, b) -> {
            int byName = a.clientName().compareTo(b.clientName());
            return byName != 0 ? byName : a.route().compareTo(b.route());
        });
        return result;
    }

    /** 按 clientName 精确过滤；不存在返回空列表（不为 null）。 */
    public List<HttpRouteView> listByClientName(String clientName, Long clientId) {
        if (clientName == null) {
            return Collections.emptyList();
        }
        Snapshot snapshot = byClientName.get(clientName);
        if (snapshot == null) {
            return Collections.emptyList();
        }
        List<HttpRouteView> out = new ArrayList<>(snapshot.entries().size());
        for (Entry e : snapshot.entries()) {
            out.add(new HttpRouteView(clientId, clientName, e.route(), e.targetBaseUrl(), e.reportedAt()));
        }
        out.sort((a, b) -> a.route().compareTo(b.route()));
        return out;
    }

    /** 仅做监控/调试用：当前缓存的客户端数量。 */
    public int size() {
        return byClientName.size();
    }
}
