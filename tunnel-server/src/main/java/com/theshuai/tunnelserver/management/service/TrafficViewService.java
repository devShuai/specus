package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ResourceTrafficUsage;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsageView;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrameView;
import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.tunnelserver.management.repository.ResourceTrafficUsageRepository;
import com.theshuai.tunnelserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * 流量记录的只读视图查询。和 {@link TrafficUsageService}（写入累计 + 周期 flush）解耦——
 * 那个类是热路径写入器，这里是冷路径管理面板查询。
 */
@Service
public class TrafficViewService {
    private final TrafficUsageRepository trafficUsageRepository;
    private final ResourceTrafficUsageRepository resourceTrafficUsageRepository;
    private final HttpTrafficExchangeRepository httpTrafficExchangeRepository;
    private final TcpTrafficFrameRepository tcpTrafficFrameRepository;

    public TrafficViewService(TrafficUsageRepository trafficUsageRepository,
                              ResourceTrafficUsageRepository resourceTrafficUsageRepository,
                              HttpTrafficExchangeRepository httpTrafficExchangeRepository,
                              TcpTrafficFrameRepository tcpTrafficFrameRepository) {
        this.trafficUsageRepository = trafficUsageRepository;
        this.resourceTrafficUsageRepository = resourceTrafficUsageRepository;
        this.httpTrafficExchangeRepository = httpTrafficExchangeRepository;
        this.tcpTrafficFrameRepository = tcpTrafficFrameRepository;
    }

    @Transactional(readOnly = true)
    public List<TrafficUsageView> listTraffic(Long clientId, int limit) {
        return listTraffic(TenantContext.defaultTenant(), clientId, limit);
    }

    @Transactional(readOnly = true)
    public List<TrafficUsageView> listTraffic(TenantContext tenant, Long clientId, int limit) {
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        List<TrafficUsage> usages = clientId == null
                ? trafficUsageRepository.findByTenantIdOrderByUsageDateDescIdDesc(tenant.tenantId(), pageRequest)
                : trafficUsageRepository.findByTenantIdAndClientIdOrderByUsageDateDescIdDesc(
                        tenant.tenantId(), clientId, pageRequest);
        return usages.stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public List<ResourceTrafficUsageView> listResourceTraffic(TenantContext tenant,
                                                              String resourceType,
                                                              Long clientId,
                                                              int limit) {
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        String normalizedType = normalizeResourceType(resourceType);
        List<ResourceTrafficUsage> usages;
        if (clientId == null && normalizedType == null) {
            usages = resourceTrafficUsageRepository.findByTenantIdOrderByUsageDateDescIdDesc(
                    tenant.tenantId(), pageRequest);
        } else if (clientId == null) {
            usages = resourceTrafficUsageRepository.findByTenantIdAndResourceTypeOrderByUsageDateDescIdDesc(
                    tenant.tenantId(), normalizedType, pageRequest);
        } else if (normalizedType == null) {
            usages = resourceTrafficUsageRepository.findByTenantIdAndClientIdOrderByUsageDateDescIdDesc(
                    tenant.tenantId(), clientId, pageRequest);
        } else {
            usages = resourceTrafficUsageRepository.findByTenantIdAndClientIdAndResourceTypeOrderByUsageDateDescIdDesc(
                    tenant.tenantId(), clientId, normalizedType, pageRequest);
        }
        return usages.stream().map(this::toResourceView).toList();
    }

    @Transactional(readOnly = true)
    public List<HttpTrafficExchangeView> listHttpExchanges(TenantContext tenant,
                                                           Long clientId,
                                                           String route,
                                                           int limit) {
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        String normalizedRoute = normalizeRoute(route);
        List<HttpTrafficExchange> exchanges;
        if (clientId == null && normalizedRoute == null) {
            exchanges = httpTrafficExchangeRepository.findByTenantIdOrderByIdDesc(tenant.tenantId(), pageRequest);
        } else if (clientId == null) {
            exchanges = httpTrafficExchangeRepository.findByTenantIdAndRouteOrderByIdDesc(
                    tenant.tenantId(), normalizedRoute, pageRequest);
        } else if (normalizedRoute == null) {
            exchanges = httpTrafficExchangeRepository.findByTenantIdAndClientIdOrderByIdDesc(
                    tenant.tenantId(), clientId, pageRequest);
        } else {
            exchanges = httpTrafficExchangeRepository.findByTenantIdAndClientIdAndRouteOrderByIdDesc(
                    tenant.tenantId(), clientId, normalizedRoute, pageRequest);
        }
        return exchanges.stream().map(this::toHttpExchangeView).toList();
    }

    @Transactional(readOnly = true)
    public List<TcpTrafficFrameView> listTcpFrames(TenantContext tenant,
                                                   Long clientId,
                                                   Integer listenPort,
                                                   int limit) {
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        List<TcpTrafficFrame> frames;
        if (clientId == null && listenPort == null) {
            frames = tcpTrafficFrameRepository.findByTenantIdOrderByIdDesc(tenant.tenantId(), pageRequest);
        } else if (clientId == null) {
            frames = tcpTrafficFrameRepository.findByTenantIdAndListenPortOrderByIdDesc(
                    tenant.tenantId(), listenPort, pageRequest);
        } else if (listenPort == null) {
            frames = tcpTrafficFrameRepository.findByTenantIdAndClientIdOrderByIdDesc(
                    tenant.tenantId(), clientId, pageRequest);
        } else {
            frames = tcpTrafficFrameRepository.findByTenantIdAndClientIdAndListenPortOrderByIdDesc(
                    tenant.tenantId(), clientId, listenPort, pageRequest);
        }
        return frames.stream().map(this::toTcpFrameView).toList();
    }

    private TrafficUsageView toView(TrafficUsage usage) {
        return new TrafficUsageView(
                usage.getId(),
                usage.getClientId(),
                usage.getClientName(),
                usage.getUsageDate(),
                usage.getUploadBytes(),
                usage.getDownloadBytes(),
                usage.getUpdatedAt()
        );
    }

    private ResourceTrafficUsageView toResourceView(ResourceTrafficUsage usage) {
        return new ResourceTrafficUsageView(
                usage.getId(),
                usage.getClientId(),
                usage.getClientName(),
                usage.getResourceType(),
                usage.getResourceKey(),
                usage.getResourceId(),
                usage.getResourceName(),
                usage.getUsageDate(),
                usage.getUploadBytes(),
                usage.getDownloadBytes(),
                usage.getUpdatedAt()
        );
    }

    private HttpTrafficExchangeView toHttpExchangeView(HttpTrafficExchange exchange) {
        return new HttpTrafficExchangeView(
                exchange.getId(),
                exchange.getClientId(),
                exchange.getClientName(),
                exchange.getRoute(),
                exchange.getResourceId(),
                exchange.getResourceName(),
                exchange.getMethod(),
                exchange.getRelativePath(),
                exchange.getRawQuery(),
                exchange.getStatusCode(),
                exchange.isSuccess(),
                exchange.getError(),
                exchange.getRemoteAddress(),
                exchange.getRequestBytes(),
                exchange.getResponseBytes(),
                exchange.getElapsedMs(),
                exchange.getRequestContentType(),
                exchange.getResponseContentType(),
                exchange.getRequestHeaders(),
                exchange.getResponseHeaders(),
                exchange.getRequestPreviewHex(),
                exchange.getRequestPreviewText(),
                exchange.getResponsePreviewHex(),
                exchange.getResponsePreviewText(),
                exchange.isRequestTruncated(),
                exchange.isResponseTruncated(),
                exchange.getCapturedAt()
        );
    }

    private TcpTrafficFrameView toTcpFrameView(TcpTrafficFrame frame) {
        return new TcpTrafficFrameView(
                frame.getId(),
                frame.getClientId(),
                frame.getClientName(),
                frame.getListenPort(),
                frame.getResourceId(),
                frame.getResourceName(),
                frame.getChannelId(),
                frame.getDirection(),
                frame.getRemoteAddress(),
                frame.getPayloadBytes(),
                frame.getPayloadPreviewHex(),
                frame.getPayloadPreviewText(),
                frame.isTruncated(),
                frame.getFrameTime()
        );
    }

    private String normalizeResourceType(String resourceType) {
        if (resourceType == null || resourceType.isBlank()) {
            return null;
        }
        return resourceType.trim().toUpperCase();
    }

    private String normalizeRoute(String route) {
        if (route == null || route.isBlank()) {
            return null;
        }
        return route.trim();
    }
}
