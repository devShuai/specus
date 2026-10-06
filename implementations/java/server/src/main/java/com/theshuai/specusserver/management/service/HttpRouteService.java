package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.HttpRouteView;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * HTTP 路由（{@link HttpRouteMapping}）的 CRUD 服务。每次 mutation 之后都调用
 * {@link NatControlService#pushSnapshotIfOnline(ClientAccount)} 把"当前权威全集"推到在线客户端，
 * 由 {@code NatClientHandler.applyHttpRoutes} 热替换其内存路由表。
 *
 * <p>校验规则：
 * <ul>
 *   <li>{@code route}：非空，trim 后长度 1~60，禁止包含 {@code /}（前端做精确匹配，路径段以 {@code /} 分隔）</li>
 *   <li>{@code targetBaseUrl}：非空，trim 后长度 ≤ 512，必须为合法绝对 URL（http/https），
 *       由 {@code HttpRouteTargetResolver} 进一步校验 scheme/host/port</li>
 *   <li>同一 clientId 下 route 唯一（{@code uk_http_route_client_route}），DB 层会兜底）</li>
 * </ul>
 */
@Service
@Slf4j
public class HttpRouteService {
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final NatControlService natControlService;
    private final HttpShareService httpShareService;
    private final WorkbenchReferences workbenchReferences;

    public HttpRouteService(HttpRouteMappingRepository httpRouteMappingRepository,
                            ClientAccountRepository clientAccountRepository,
                            NatControlService natControlService,
                            HttpShareService httpShareService,
                            WorkbenchReferences workbenchReferences) {
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.natControlService = natControlService;
        this.httpShareService = httpShareService;
        this.workbenchReferences = workbenchReferences;
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
        return createRoute(tenant, account, request, null);
    }

    @Transactional
    public HttpRouteView createRoute(ManagementContext context, long clientId, RouteMutation request) {
        ClientAccount account = findClient(context, clientId);
        return createRoute(context.tenant(), account, request, context.username());
    }

    private HttpRouteView createRoute(TenantContext tenant, ClientAccount account, RouteMutation request, String actor) {
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
        row.setMediaCaptureEnabled(Boolean.TRUE.equals(request.mediaCaptureEnabled()));
        row.setPathRewriteEnabled(Boolean.TRUE.equals(request.pathRewriteEnabled()));
        row.setInsecureSkipVerify(Boolean.TRUE.equals(request.insecureSkipVerify()));
        applyAuthentication(row, request, true);
        row.setCreatedAt(now);
        row.setUpdatedAt(now);
        HttpRouteMapping saved = httpRouteMappingRepository.saveAndFlush(row);
        // Same transaction: the route.created audit entry fails the creation if it cannot be written.
        httpShareService.onRouteCreated(actor, saved);
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
        return updateRoute(tenant, row, request, null);
    }

    @Transactional
    public HttpRouteView updateRoute(ManagementContext context, long id, RouteMutation request) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(route -> canAccessClient(context, route.getClientId()))
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        return updateRoute(context.tenant(), row, request, context.username());
    }

    private HttpRouteView updateRoute(TenantContext tenant, HttpRouteMapping row, RouteMutation request,
                                      String actor) {
        String route = requireRoute(request.route());
        String exposureBefore = HttpShareService.exposure(row);
        String authUsernameBefore = row.getAuthUsername();
        String targetBaseUrl = requireTargetBaseUrl(request.targetBaseUrl());
        boolean dataPlaneChanged = !Objects.equals(route, row.getRoute())
                || !Objects.equals(targetBaseUrl, row.getTargetBaseUrl())
                || (request.enabled() != null && request.enabled() != row.isEnabled())
                || (request.insecureSkipVerify() != null
                && request.insecureSkipVerify() != Boolean.TRUE.equals(row.getInsecureSkipVerify()));

        if (!route.equals(row.getRoute())) {
            httpRouteMappingRepository.findByTenantIdAndClientIdAndRoute(tenant.tenantId(), row.getClientId(), route).ifPresent(existing -> {
                if (!existing.getId().equals(row.getId())) {
                    throw new IllegalArgumentException("route " + route + " 已存在于该客户端下");
                }
            });
        }

        row.setRoute(route);
        row.setTargetBaseUrl(targetBaseUrl);
        if (request.enabled() != null) {
            row.setEnabled(request.enabled());
        }
        if (request.detailCaptureEnabled() != null) {
            row.setDetailCaptureEnabled(request.detailCaptureEnabled());
        }
        if (request.mediaCaptureEnabled() != null) {
            row.setMediaCaptureEnabled(request.mediaCaptureEnabled());
        }
        if (request.pathRewriteEnabled() != null) {
            row.setPathRewriteEnabled(request.pathRewriteEnabled());
        }
        if (request.insecureSkipVerify() != null) {
            row.setInsecureSkipVerify(request.insecureSkipVerify());
        }
        applyAuthentication(row, request, false);
        // A new Basic username or password on a protected route is audited; it never ends shares.
        boolean credentialsChanged = Boolean.TRUE.equals(row.getAuthEnabled())
                && (!Objects.equals(authUsernameBefore, row.getAuthUsername())
                || StringUtils.hasText(request.authPassword()));
        row.setUpdatedAt(Instant.now().toString());
        HttpRouteMapping saved = httpRouteMappingRepository.saveAndFlush(row);
        // Same transaction: exposure audit and, when the route is no longer protected, its shares end.
        httpShareService.onRouteUpdated(actor, saved, exposureBefore, credentialsChanged);

        if (dataPlaneChanged) {
            ClientAccount account = clientAccountRepository
                    .findByIdAndTenantId(saved.getClientId(), tenant.tenantId())
                    .orElse(null);
            if (account != null) {
                natControlService.pushSnapshotIfOnline(account);
            }
        }
        return toView(saved);
    }

    /**
     * The route as {@link #updateRoute(ManagementContext, long, RouteMutation)} sees it: same tenant,
     * and the caller is an admin or owns the route's client. Empty for anything else, so a caller
     * cannot tell a route of someone else from one that does not exist.
     */
    @Transactional(readOnly = true)
    public Optional<HttpRouteMapping> findVisibleRoute(ManagementContext context, long id) {
        return httpRouteMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(route -> canAccessClient(context, route.getClientId()));
    }

    /** Whether a stored targetBaseUrl passes the validation applied when it is saved. */
    public static boolean isValidTargetBaseUrl(String targetBaseUrl) {
        try {
            requireTargetBaseUrl(targetBaseUrl);
            return true;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    @Transactional
    public void deleteRoute(long id) {
        deleteRoute(TenantContext.defaultTenant(), id);
    }

    @Transactional
    public void deleteRoute(TenantContext tenant, long id) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        deleteRoute(tenant, row, null);
    }

    @Transactional
    public void deleteRoute(ManagementContext context, long id) {
        HttpRouteMapping row = httpRouteMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(route -> canAccessClient(context, route.getClientId()))
                .orElseThrow(() -> new IllegalArgumentException("http route not found: " + id));
        deleteRoute(context.tenant(), row, context.username());
    }

    private void deleteRoute(TenantContext tenant, HttpRouteMapping row, String actor) {
        // Same transaction: no workbench favourite or recent open outlives the route.
        workbenchReferences.forgetObject(WorkbenchReferences.HTTP_ROUTE, row.getId());
        httpRouteMappingRepository.delete(row);
        httpRouteMappingRepository.flush();
        // Same transaction: route.deleted is audited and every active share of the route ends.
        httpShareService.onRouteDeleted(actor, row);
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

    private static String requireTargetBaseUrl(String targetBaseUrl) {
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

    private void applyAuthentication(HttpRouteMapping row, RouteMutation request, boolean creating) {
        boolean enabled = request.authEnabled() == null
                ? !creating && Boolean.TRUE.equals(row.getAuthEnabled())
                : request.authEnabled();

        String username = normalizeAuthUsername(request.authUsername());
        if (username == null && !creating) {
            username = normalizeAuthUsername(row.getAuthUsername());
        }

        String passwordHash = row.getAuthPasswordHash();
        if (StringUtils.hasText(request.authPassword())) {
            String password = requireAuthPassword(request.authPassword());
            // A per-route gate secret, checked on every proxied request; the login KDF
            // would turn each request into a deliberate 210k-iteration derivation.
            passwordHash = PasswordService.hashToken(password);
        }

        if (enabled) {
            if (!StringUtils.hasText(username)) {
                throw new IllegalArgumentException("authUsername cannot be blank when route authentication is enabled");
            }
            if (!StringUtils.hasText(passwordHash)) {
                throw new IllegalArgumentException("authPassword is required when route authentication is first enabled");
            }
        }

        row.setAuthEnabled(enabled);
        row.setAuthUsername(username);
        row.setAuthPasswordHash(passwordHash);
    }

    private String normalizeAuthUsername(String username) {
        if (!StringUtils.hasText(username)) {
            return null;
        }
        String normalized = username.trim();
        if (normalized.length() > 120) {
            throw new IllegalArgumentException("authUsername is too long (max 120)");
        }
        if (normalized.indexOf(':') >= 0 || normalized.indexOf('\r') >= 0 || normalized.indexOf('\n') >= 0) {
            throw new IllegalArgumentException("authUsername must not contain ':', CR, or LF");
        }
        return normalized;
    }

    private String requireAuthPassword(String password) {
        if (!StringUtils.hasText(password)) {
            throw new IllegalArgumentException("authPassword cannot be blank");
        }
        if (password.length() > 256) {
            throw new IllegalArgumentException("authPassword is too long (max 256)");
        }
        return password;
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
                Boolean.TRUE.equals(row.getMediaCaptureEnabled()),
                Boolean.TRUE.equals(row.getPathRewriteEnabled()),
                Boolean.TRUE.equals(row.getInsecureSkipVerify()),
                Boolean.TRUE.equals(row.getAuthEnabled()),
                StringUtils.hasText(row.getAuthUsername()) ? row.getAuthUsername() : "",
                StringUtils.hasText(row.getAuthPasswordHash()),
                row.getCreatedAt(),
                row.getUpdatedAt()
        );
    }

    public record RouteMutation(
            String route,
            String targetBaseUrl,
            Boolean enabled,
            Boolean detailCaptureEnabled,
            Boolean mediaCaptureEnabled,
            Boolean pathRewriteEnabled,
            Boolean insecureSkipVerify,
            Boolean authEnabled,
            String authUsername,
            String authPassword
    ) {
        public RouteMutation(String route, String targetBaseUrl, Boolean enabled) {
            this(route, targetBaseUrl, enabled, null, null, null, null, null, null, null);
        }

        public RouteMutation(String route,
                             String targetBaseUrl,
                             Boolean enabled,
                             Boolean detailCaptureEnabled,
                             Boolean mediaCaptureEnabled,
                             Boolean pathRewriteEnabled) {
            this(route, targetBaseUrl, enabled, detailCaptureEnabled, mediaCaptureEnabled,
                    pathRewriteEnabled, null, null, null, null);
        }

        public RouteMutation(String route,
                             String targetBaseUrl,
                             Boolean enabled,
                             Boolean detailCaptureEnabled,
                             Boolean mediaCaptureEnabled,
                             Boolean pathRewriteEnabled,
                             Boolean authEnabled,
                             String authUsername,
                             String authPassword) {
            this(route, targetBaseUrl, enabled, detailCaptureEnabled, mediaCaptureEnabled,
                    pathRewriteEnabled, null, authEnabled, authUsername, authPassword);
        }
    }
}
