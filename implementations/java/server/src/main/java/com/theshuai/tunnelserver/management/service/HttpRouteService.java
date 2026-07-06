package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.HttpRouteView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.security.ManagementContext;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.List;

/**
 * HTTP 路由（{@link HttpRouteMapping}）的 CRUD 服务。每次 mutation 之后都调用
 * {@link NatControlService#pushSnapshotIfOnline(ClientAccount)} 把"当前权威全集"推到在线客户端，
 * 由 {@code DirectHttpRequestHandler.applyRoutes} 热替换其内存路由表。
 *
 * <p>校验规则：
 * <ul>
 *   <li>{@code route}：非空，trim 后长度 1~60，禁止包含 {@code /}（前端做精确匹配，路径段以 {@code /} 分隔）</li>
 *   <li>{@code targetBaseUrl}：非空，trim 后长度 ≤ 512，必须为合法绝对 URL（http/https），
 *       由 {@code DirectHttpForwarder} 进一步校验 scheme/host/port</li>
 *   <li>同一 clientId 下 route 唯一（{@code uk_http_route_client_route}），DB 层会兜底）</li>
 * </ul>
 */
@Service
@Slf4j
public class HttpRouteService {
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final NatControlService natControlService;

    public HttpRouteService(HttpRouteMappingRepository httpRouteMappingRepository,
                            ClientAccountRepository clientAccountRepository,
                            NatControlService natControlService) {
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.natControlService = natControlService;
    }

    @Transactional(readOnly = true)
    public List<HttpRouteView> listRoutes(Long clientId) {
        return listRoutes(TenantContext.defaultTenant(), clientId);
    }

    @Transactional(readOnly = true)
    public List<HttpRouteView> listRoutes(TenantContext tenant, Long clientId) {
        List<HttpRouteMapping> rows = clientId == null
                ? httpRouteMappingRepository.findByTenantIdOrderByIdDesc(tenant.tenantId())
                : httpRouteMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(tenant.tenantId(), clientId);
        return rows.stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public List<HttpRouteView> listRoutes(ManagementContext context, Long clientId) {
        if (context.isAdmin()) {
            return listRoutes(context.tenant(), clientId);
        }
        List<Long> visibleClientIds = visibleClientIds(context);
        if (visibleClientIds.isEmpty() || (clientId != null && !visibleClientIds.contains(clientId))) {
            return List.of();
        }
        List<HttpRouteMapping> rows = clientId == null
                ? httpRouteMappingRepository.findByTenantIdAndClientIdInOrderByIdDesc(
                        context.tenant().tenantId(), visibleClientIds)
                : httpRouteMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(
                        context.tenant().tenantId(), clientId);
        return rows.stream().map(this::toView).toList();
    }

    @Transactional
    public HttpRouteView createRoute(long clientId, RouteMutation request) {
        return createRoute(TenantContext.defaultTenant(), clientId, request);
    }

    @Transactional
    public HttpRouteView createRoute(TenantContext tenant, long clientId, RouteMutation request) {
        ClientAccount account = findClient(tenant, clientId);
        return createRoute(tenant, account, request);
    }

    @Transactional
    public HttpRouteView createRoute(ManagementContext context, long clientId, RouteMutation request) {
        ClientAccount account = findClient(context, clientId);
        return createRoute(context.tenant(), account, request);
    }

    private HttpRouteView createRoute(TenantContext tenant, ClientAccount account, RouteMutation request) {
        String route = requireRoute(request.route());
        String targetBaseUrl = requireTargetBaseUrl(request.targetBaseUrl());
        httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(tenant.tenantId(), account.getId(), route).ifPresent(existing -> {
            throw new IllegalArgumentException("route " + route + " 已存在于该客户端下");
        });

        String now = Instant.now().toString();
        HttpRouteMapping row = new HttpRouteMapping();
        row.setId(ClientIdGenerator.newId());
        row.setTenantId(tenant.tenantId());
        row.setClientId(account.getId());
        row.setClientName(account.getClientName());
        row.setRoute(route);
        row.setTargetBaseUrl(targetBaseUrl);
        row.setEnabled(request.enabled() == null || request.enabled());
        row.setDetailCaptureEnabled(Boolean.TRUE.equals(request.detailCaptureEnabled()));
        row.setPathRewriteEnabled(Boolean.TRUE.equals(request.pathRewriteEnabled()));
        row.setCreatedAt(now);
        row.setUpdatedAt(now);
        HttpRouteMapping saved = httpRouteMappingRepository.saveAndFlush(row);
        natControlService.pushSnapshotIfOnline(account);
        return toView(saved);
    }

    @Transactional
    public HttpRouteView updateRoute(long id, RouteMutation request) {
        return updateRoute(TenantContext.defaultTenant(), id, request);
    }

    @Transactional
    public HttpRouteView updateRoute(TenantContext tenant, long id, RouteMutation request) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        return updateRoute(tenant, row, request);
    }

    @Transactional
    public HttpRouteView updateRoute(ManagementContext context, long id, RouteMutation request) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(route -> canAccessClient(context, route.getClientId()))
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        return updateRoute(context.tenant(), row, request);
    }

    private HttpRouteView updateRoute(TenantContext tenant, HttpRouteMapping row, RouteMutation request) {
        String route = requireRoute(request.route());
        String targetBaseUrl = requireTargetBaseUrl(request.targetBaseUrl());

        if (!route.equals(row.getRoute())) {
            httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(tenant.tenantId(), row.getClientId(), route).ifPresent(existing -> {
                if (!existing.getId().equals(row.getId())) {
                    throw new IllegalArgumentException("route " + route + " 已存在于该客户端下");
                }
            });
        }

        row.setRoute(route);
        row.setTargetBaseUrl(targetBaseUrl);
        row.setEnabled(request.enabled() == null || request.enabled());
        if (request.detailCaptureEnabled() != null) {
            row.setDetailCaptureEnabled(request.detailCaptureEnabled());
        }
        if (request.pathRewriteEnabled() != null) {
            row.setPathRewriteEnabled(request.pathRewriteEnabled());
        }
        row.setUpdatedAt(Instant.now().toString());
        HttpRouteMapping saved = httpRouteMappingRepository.saveAndFlush(row);

        ClientAccount account = clientAccountRepository.findByIdAndTenantId(saved.getClientId(), tenant.tenantId()).orElse(null);
        if (account != null) {
            natControlService.pushSnapshotIfOnline(account);
        }
        return toView(saved);
    }

    @Transactional
    public void deleteRoute(long id) {
        deleteRoute(TenantContext.defaultTenant(), id);
    }

    @Transactional
    public void deleteRoute(TenantContext tenant, long id) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        deleteRoute(tenant, row);
    }

    @Transactional
    public void deleteRoute(ManagementContext context, long id) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(route -> canAccessClient(context, route.getClientId()))
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        deleteRoute(context.tenant(), row);
    }

    private void deleteRoute(TenantContext tenant, HttpRouteMapping row) {
        httpRouteMappingRepository.delete(row);
        httpRouteMappingRepository.flush();
        ClientAccount account = clientAccountRepository.findByIdAndTenantId(row.getClientId(), tenant.tenantId()).orElse(null);
        if (account != null) {
            natControlService.pushSnapshotIfOnline(account);
        }
    }

    private ClientAccount findClient(long clientId) {
        return clientAccountRepository.findById(clientId)
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
    }

    private ClientAccount findClient(TenantContext tenant, long clientId) {
        return clientAccountRepository.findByIdAndTenantId(clientId, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
    }

    private ClientAccount findClient(ManagementContext context, long clientId) {
        return (context.isAdmin()
                ? clientAccountRepository.findByIdAndTenantId(clientId, context.tenant().tenantId())
                : clientAccountRepository.findByIdAndTenantIdAndOwnerUsername(
                        clientId, context.tenant().tenantId(), context.username()))
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
    }

    private boolean canAccessClient(ManagementContext context, Long clientId) {
        if (clientId == null) {
            return false;
        }
        if (context.isAdmin()) {
            return true;
        }
        return clientAccountRepository.findByIdAndTenantIdAndOwnerUsername(
                clientId, context.tenant().tenantId(), context.username()).isPresent();
    }

    private List<Long> visibleClientIds(ManagementContext context) {
        return clientAccountRepository
                .findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username())
                .stream()
                .map(ClientAccount::getId)
                .toList();
    }

    private String requireRoute(String route) {
        if (!StringUtils.hasText(route)) {
            throw new IllegalArgumentException("route cannot be blank");
        }
        String normalized = route.trim();
        if (normalized.length() > 60) {
            throw new IllegalArgumentException("route is too long (max 60)");
        }
        if (normalized.indexOf('/') >= 0) {
            throw new IllegalArgumentException("route must not contain '/'");
        }
        return normalized;
    }

    private String requireTargetBaseUrl(String targetBaseUrl) {
        if (!StringUtils.hasText(targetBaseUrl)) {
            throw new IllegalArgumentException("targetBaseUrl cannot be blank");
        }
        String normalized = targetBaseUrl.trim();
        if (normalized.length() > 512) {
            throw new IllegalArgumentException("targetBaseUrl is too long (max 512)");
        }
        try {
            URI uri = new URI(normalized);
            String scheme = uri.getScheme();
            if (!uri.isAbsolute() || scheme == null
                    || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
                throw new IllegalArgumentException("targetBaseUrl must be an absolute http(s) URL");
            }
            if (!StringUtils.hasText(uri.getHost())) {
                throw new IllegalArgumentException("targetBaseUrl must contain a host");
            }
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("targetBaseUrl is not a valid URI: " + e.getMessage());
        }
        return normalized;
    }

    private HttpRouteView toView(HttpRouteMapping row) {
        return new HttpRouteView(
                row.getId(),
                row.getClientId(),
                row.getClientName(),
                row.getRoute(),
                row.getTargetBaseUrl(),
                row.isEnabled(),
                Boolean.TRUE.equals(row.getDetailCaptureEnabled()),
                Boolean.TRUE.equals(row.getPathRewriteEnabled()),
                row.getCreatedAt(),
                row.getUpdatedAt()
        );
    }

    public record RouteMutation(
            String route,
            String targetBaseUrl,
            Boolean enabled,
            Boolean detailCaptureEnabled,
            Boolean pathRewriteEnabled
    ) {
        public RouteMutation(String route, String targetBaseUrl, Boolean enabled) {
            this(route, targetBaseUrl, enabled, false, false);
        }
    }
}
