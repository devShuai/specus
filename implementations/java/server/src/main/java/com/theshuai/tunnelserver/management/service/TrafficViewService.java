package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsage;
import com.theshuai.tunnelserver.management.model.ResourceTrafficUsageView;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrameView;
import com.theshuai.tunnelserver.management.model.TrafficUsage;
import com.theshuai.tunnelserver.management.model.TrafficUsageView;
import com.theshuai.tunnelserver.management.repository.ResourceTrafficUsageRepository;
import com.theshuai.tunnelserver.management.repository.TrafficUsageRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.tunnelserver.management.storage.HttpTrafficSearchField;
import com.theshuai.tunnelserver.management.storage.TcpTrafficFrameStore;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * 流量记录的只读视图查询。和 {@link TrafficUsageService}（写入累计 + 周期 flush）解耦——
 * 那个类是热路径写入器，这里是冷路径管理面板查询。
 */
@Service
public class TrafficViewService {
    private final TrafficUsageRepository trafficUsageRepository;
    private final ResourceTrafficUsageRepository resourceTrafficUsageRepository;
    private final HttpTrafficExchangeStore httpTrafficExchangeStore;
    private final TcpTrafficFrameStore tcpTrafficFrameStore;
    private final ClientAccountService clientAccountService;

    public TrafficViewService(TrafficUsageRepository trafficUsageRepository,
                              ResourceTrafficUsageRepository resourceTrafficUsageRepository,
                              HttpTrafficExchangeStore httpTrafficExchangeStore,
                              TcpTrafficFrameStore tcpTrafficFrameStore,
                              ClientAccountService clientAccountService) {
        this.trafficUsageRepository = trafficUsageRepository;
        this.resourceTrafficUsageRepository = resourceTrafficUsageRepository;
        this.httpTrafficExchangeStore = httpTrafficExchangeStore;
        this.tcpTrafficFrameStore = tcpTrafficFrameStore;
        this.clientAccountService = clientAccountService;
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
    public List<TrafficUsageView> listTraffic(ManagementContext context, Long clientId, int limit) {
        if (!canAccessClient(context, clientId)) {
            return List.of();
        }
        if (context.isAdmin()) {
            return listTraffic(context.tenant(), clientId, limit);
        }
        List<Long> visibleClientIds = visibleClientIdList(context);
        if (visibleClientIds.isEmpty()) {
            return List.of();
        }
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        List<TrafficUsage> usages = clientId == null
                ? trafficUsageRepository.findByTenantIdAndClientIdInOrderByUsageDateDescIdDesc(
                        context.tenant().tenantId(), visibleClientIds, pageRequest)
                : trafficUsageRepository.findByTenantIdAndClientIdOrderByUsageDateDescIdDesc(
                        context.tenant().tenantId(), clientId, pageRequest);
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
    public List<ResourceTrafficUsageView> listResourceTraffic(ManagementContext context,
                                                              String resourceType,
                                                              Long clientId,
                                                              int limit) {
        if (!canAccessClient(context, clientId)) {
            return List.of();
        }
        if (context.isAdmin()) {
            return listResourceTraffic(context.tenant(), resourceType, clientId, limit);
        }
        List<Long> visibleClientIds = visibleClientIdList(context);
        if (visibleClientIds.isEmpty()) {
            return List.of();
        }
        PageRequest pageRequest = PageRequest.of(0, Math.clamp(limit, 1, 500));
        String normalizedType = normalizeResourceType(resourceType);
        List<ResourceTrafficUsage> usages;
        if (clientId == null && normalizedType == null) {
            usages = resourceTrafficUsageRepository.findByTenantIdAndClientIdInOrderByUsageDateDescIdDesc(
                    context.tenant().tenantId(), visibleClientIds, pageRequest);
        } else if (clientId == null) {
            usages = resourceTrafficUsageRepository.findByTenantIdAndClientIdInAndResourceTypeOrderByUsageDateDescIdDesc(
                    context.tenant().tenantId(), visibleClientIds, normalizedType, pageRequest);
        } else if (normalizedType == null) {
            usages = resourceTrafficUsageRepository.findByTenantIdAndClientIdOrderByUsageDateDescIdDesc(
                    context.tenant().tenantId(), clientId, pageRequest);
        } else {
            usages = resourceTrafficUsageRepository.findByTenantIdAndClientIdAndResourceTypeOrderByUsageDateDescIdDesc(
                    context.tenant().tenantId(), clientId, normalizedType, pageRequest);
        }
        return usages.stream().map(this::toResourceView).toList();
    }

    @Transactional(readOnly = true)
    public Page<HttpTrafficExchangeView> listHttpExchanges(TenantContext tenant,
                                                           Long clientId,
                                                           String route,
                                                           String responseBodyType,
                                                           HttpTrafficSearchField field,
                                                           String keyword,
                                                           Pageable pageable) {
        return httpTrafficExchangeStore.search(tenant, clientId, null, route, responseBodyType, field, keyword, pageable);
    }

    @Transactional(readOnly = true)
    public Page<HttpTrafficExchangeView> listHttpExchanges(ManagementContext context,
                                                           Long clientId,
                                                           String route,
                                                           String responseBodyType,
                                                           HttpTrafficSearchField field,
                                                           String keyword,
                                                           Pageable pageable) {
        Set<Long> visibleClientIds = visibleClientIds(context);
        if (isDenied(visibleClientIds, clientId)) {
            return Page.empty(pageable);
        }
        return httpTrafficExchangeStore.search(
                context.tenant(), clientId, visibleClientIds, route, responseBodyType, field, keyword, pageable);
    }

    @Transactional(readOnly = true)
    public Page<TcpTrafficFrameView> listTcpFrames(TenantContext tenant,
                                                   Long clientId,
                                                   Integer listenPort,
                                                   Pageable pageable) {
        return tcpTrafficFrameStore.search(tenant, clientId, null, listenPort, pageable);
    }

    @Transactional(readOnly = true)
    public Page<TcpTrafficFrameView> listTcpFrames(ManagementContext context,
                                                   Long clientId,
                                                   Integer listenPort,
                                                   Pageable pageable) {
        Set<Long> visibleClientIds = visibleClientIds(context);
        if (isDenied(visibleClientIds, clientId)) {
            return Page.empty(pageable);
        }
        return tcpTrafficFrameStore.search(context.tenant(), clientId, visibleClientIds, listenPort, pageable);
    }

    @Transactional(readOnly = true)
    public Optional<TcpTrafficFrameView> getTcpFrame(TenantContext tenant, long id) {
        return tcpTrafficFrameStore.findById(tenant, id, null);
    }

    @Transactional(readOnly = true)
    public Optional<TcpTrafficFrameView> getTcpFrame(ManagementContext context, long id) {
        return tcpTrafficFrameStore.findById(context.tenant(), id, visibleClientIds(context));
    }

    @Transactional(readOnly = true)
    public List<TcpTrafficFrameView> listTcpStream(TenantContext tenant, String channelId, int limit) {
        return tcpTrafficFrameStore.findStream(tenant, channelId, null, PageRequest.of(0, Math.clamp(limit, 1, 1000)));
    }

    @Transactional(readOnly = true)
    public List<TcpTrafficFrameView> listTcpStream(ManagementContext context, String channelId, int limit) {
        return tcpTrafficFrameStore.findStream(
                context.tenant(), channelId, visibleClientIds(context), PageRequest.of(0, Math.clamp(limit, 1, 1000)));
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

    private String normalizeResourceType(String resourceType) {
        if (resourceType == null || resourceType.isBlank()) {
            return null;
        }
        return resourceType.trim().toUpperCase();
    }

    private boolean canAccessClient(ManagementContext context, Long clientId) {
        return clientId == null || clientAccountService.canAccessClient(context, clientId);
    }

    private Set<Long> visibleClientIds(ManagementContext context) {
        if (context == null || context.isAdmin()) {
            return null;
        }
        return new HashSet<>(clientAccountService.visibleClientIds(context));
    }

    private List<Long> visibleClientIdList(ManagementContext context) {
        if (context == null || context.isAdmin()) {
            return List.of();
        }
        return clientAccountService.visibleClientIds(context);
    }

    private boolean isDenied(Set<Long> visibleClientIds, Long clientId) {
        if (visibleClientIds == null) {
            return false;
        }
        return visibleClientIds.isEmpty() || (clientId != null && !visibleClientIds.contains(clientId));
    }

}
