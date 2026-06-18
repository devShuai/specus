package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface HttpRouteMappingRepository extends JpaRepository<HttpRouteMapping, Long> {
    List<HttpRouteMapping> findAllByOrderByIdDesc();

    List<HttpRouteMapping> findByClientIdOrderByIdDesc(Long clientId);

    /**
     * 用于下发：仅取启用项，按 id 升序保证客户端面板呈现稳定。
     */
    List<HttpRouteMapping> findByClientIdAndEnabledTrueOrderByIdAsc(Long clientId);

    Optional<HttpRouteMapping> findByClientIdAndRoute(Long clientId, String route);

    /**
     * 区分"该客户端从未在后台管理过 HTTP 路由"和"管理过但当前都禁用/删除"。前一种情况下
     * {@code NatControlService} 会跳过 {@code httpTunnelConfigList} 字段，让客户端继续用本地
     * {@code tunnelClientConfig.json} —— 避免升级时误清除遗留配置。
     */
    boolean existsByClientId(Long clientId);
}
