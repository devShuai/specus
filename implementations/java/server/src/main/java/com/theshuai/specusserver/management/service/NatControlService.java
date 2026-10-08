package com.theshuai.specusserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.PacketCodec;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.specusserver.session.SessionUtil;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.model.SpecusMappingView;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import io.netty.channel.Channel;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 端口映射 (TCP) CRUD + 向在线客户端下发 NAT_CONTROL 的统一服务。
 *
 * <p>下发协议（{@code NAT_CONTROL}）的 JSON 体一直承载 TCP 端口映射 {@code specusConfigList}；
 * 自从 HTTP 路由也由后台管理后，本服务在每次下发时**额外查询** {@link HttpRouteMappingRepository}
 * 把启用项装到同一条消息的 {@code httpSpecusConfigList} 字段。
 *
 * <p>The HTTP route list is always the client's full set of enabled routes, even when it is empty,
 * on every push including the one sent on login. Older clients keep the list they have when the field
 * is missing, so omitting it once the last route was deleted left that route forwarding on the client
 * until it reconnected.
 *
 * <p>HTTP 路由本身的 CRUD 在 {@link HttpRouteService}；它每次写入后回调本类的
 * {@link #pushSnapshotIfOnline(ClientAccount)}，因此一次 mutation 始终下发"当前权威全集"。
 */
@Service
@Slf4j
public class NatControlService {
    /** The 1 MiB MESSAGE body of protocol/spec/control-protocol.md that a NAT_CONTROL travels in. */
    static final int MESSAGE_BODY_LIMIT = PacketCodec.MAX_MESSAGE_BODY_BYTES;
    /** The longest client name a rename allows. */
    static final int CLIENT_NAME_RESERVE_CHARACTERS = 120;
    static final String NAT_CONTROL_TOO_LARGE =
            "客户端的 TCP 映射和 HTTP route 将超过单条 NAT_CONTROL 消息 1 MiB 的上限，无法下发给客户端";
    /*
     * The client's name when a NAT_CONTROL is sized: 120 characters of 4 UTF-8 bytes each in the
     * clientName field, and of a 6-byte backslash-u escape each in the JSON. No name a rename allows
     * takes more in either place, so no later rename pushes an accepted configuration over.
     */
    private static final String LONGEST_FIELD_NAME =
            Character.toString(0x10000).repeat(CLIENT_NAME_RESERVE_CHARACTERS);
    private static final String LONGEST_JSON_NAME =
            Character.toString(0x01).repeat(CLIENT_NAME_RESERVE_CHARACTERS);

    private final SpecusMappingRepository specusMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final int nettyPort;
    private final String publicAddress;
    private final WorkbenchReferences workbenchReferences;

    public NatControlService(SpecusMappingRepository specusMappingRepository,
                             HttpRouteMappingRepository httpRouteMappingRepository,
                             ClientAccountRepository clientAccountRepository,
                             WorkbenchReferences workbenchReferences,
                             @Value("${specus.netty.port:7010}") int nettyPort,
                             @Value("${specus.public-address:}") String publicAddress) {
        this.specusMappingRepository = specusMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.workbenchReferences = workbenchReferences;
        this.nettyPort = nettyPort;
        this.publicAddress = StringUtils.hasText(publicAddress) ? publicAddress.trim() : null;
    }

    @Transactional(readOnly = true)
    public List<SpecusMappingView> listMappings(Long clientId) {
        return listMappings(TenantContext.defaultTenant(), clientId);
    }

    @Transactional(readOnly = true)
    public List<SpecusMappingView> listMappings(TenantContext tenant, Long clientId) {
        List<SpecusMapping> mappings = clientId == null
                ? specusMappingRepository.findByTenantIdOrderByIdDesc(tenant.tenantId())
                : specusMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(tenant.tenantId(), clientId);
        return mappings.stream().map(this::toView).toList();
    }

    @Transactional(readOnly = true)
    public List<SpecusMappingView> listMappings(ManagementContext context, Long clientId) {
        if (context.isAdmin()) {
            return listMappings(context.tenant(), clientId);
        }
        List<Long> visibleClientIds = visibleClientIds(context);
        if (visibleClientIds.isEmpty() || (clientId != null && !visibleClientIds.contains(clientId))) {
            return List.of();
        }
        List<SpecusMapping> mappings = clientId == null
                ? specusMappingRepository.findByTenantIdAndClientIdInOrderByIdDesc(
                        context.tenant().tenantId(), visibleClientIds)
                : specusMappingRepository.findByTenantIdAndClientIdOrderByIdDesc(
                        context.tenant().tenantId(), clientId);
        return mappings.stream().map(this::toView).toList();
    }

    @Transactional
    public SpecusMappingView createMapping(long clientId, MappingMutation request) {
        return createMapping(TenantContext.defaultTenant(), clientId, request);
    }

    @Transactional
    public SpecusMappingView createMapping(TenantContext tenant, long clientId, MappingMutation request) {
        ClientAccount account = findClient(tenant, clientId);
        return createMapping(tenant, account, request);
    }

    @Transactional
    public SpecusMappingView createMapping(ManagementContext context, long clientId, MappingMutation request) {
        ClientAccount account = findClient(context, clientId);
        return createMapping(context.tenant(), account, request);
    }

    private SpecusMappingView createMapping(TenantContext tenant, ClientAccount account, MappingMutation request) {
        int listenPort = requirePort(request.listenPort(), "listenPort");
        int targetPort = requirePort(request.targetPort(), "targetPort");
        String targetAddress = requireTargetAddress(request.targetAddress());
        specusMappingRepository.findByListenPort(listenPort).ifPresent(existing -> {
            throw new IllegalArgumentException("公网端口 " + listenPort + " 已被占用");
        });

        String now = Instant.now().toString();
        SpecusMapping mapping = new SpecusMapping();
        mapping.setId(ClientIdGenerator.newId());
        mapping.setTenantId(tenant.tenantId());
        mapping.setClientId(account.getId());
        mapping.setClientName(account.getClientName());
        mapping.setListenPort(listenPort);
        mapping.setTargetAddress(targetAddress);
        mapping.setTargetPort(targetPort);
        mapping.setEnabled(request.enabled() == null || request.enabled());
        mapping.setDetailCaptureEnabled(Boolean.TRUE.equals(request.detailCaptureEnabled()));
        mapping.setCreatedAt(now);
        mapping.setUpdatedAt(now);
        SpecusMapping saved = specusMappingRepository.saveAndFlush(mapping);
        if (saved.isEnabled()) {
            requireNatControlFits(account);
        }
        pushSnapshotIfOnline(account);
        return toView(saved);
    }

    @Transactional
    public SpecusMappingView updateMapping(long id, MappingMutation request) {
        return updateMapping(TenantContext.defaultTenant(), id, request);
    }

    @Transactional
    public SpecusMappingView updateMapping(TenantContext tenant, long id, MappingMutation request) {
        SpecusMapping mapping = specusMappingRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("mapping not found: " + id));
        return updateMapping(tenant, mapping, request);
    }

    @Transactional
    public SpecusMappingView updateMapping(ManagementContext context, long id, MappingMutation request) {
        SpecusMapping mapping = specusMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(row -> canAccessClient(context, row.getClientId()))
                .orElseThrow(() -> new IllegalArgumentException("mapping not found: " + id));
        return updateMapping(context.tenant(), mapping, request);
    }

    private SpecusMappingView updateMapping(TenantContext tenant, SpecusMapping mapping, MappingMutation request) {
        int listenPort = requirePort(request.listenPort(), "listenPort");
        int targetPort = requirePort(request.targetPort(), "targetPort");
        String targetAddress = requireTargetAddress(request.targetAddress());

        if (listenPort != mapping.getListenPort()) {
            specusMappingRepository.findByListenPort(listenPort).ifPresent(existing -> {
                if (!existing.getId().equals(mapping.getId())) {
                    throw new IllegalArgumentException("公网端口 " + listenPort + " 已被占用");
                }
            });
        }

        mapping.setListenPort(listenPort);
        mapping.setTargetAddress(targetAddress);
        mapping.setTargetPort(targetPort);
        mapping.setEnabled(request.enabled() == null || request.enabled());
        if (request.detailCaptureEnabled() != null) {
            mapping.setDetailCaptureEnabled(request.detailCaptureEnabled());
        }
        mapping.setUpdatedAt(Instant.now().toString());
        SpecusMapping saved = specusMappingRepository.saveAndFlush(mapping);

        ClientAccount account = clientAccountRepository.findByIdAndTenantId(saved.getClientId(), tenant.tenantId()).orElse(null);
        if (account != null) {
            if (saved.isEnabled()) {
                requireNatControlFits(account);
            }
            pushSnapshotIfOnline(account);
        }
        return toView(saved);
    }

    @Transactional
    public void deleteMapping(long id) {
        deleteMapping(TenantContext.defaultTenant(), id);
    }

    @Transactional
    public void deleteMapping(TenantContext tenant, long id) {
        SpecusMapping mapping = specusMappingRepository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("mapping not found: " + id));
        deleteMapping(tenant, mapping);
    }

    @Transactional
    public void deleteMapping(ManagementContext context, long id) {
        SpecusMapping mapping = specusMappingRepository.findByIdAndTenantId(id, context.tenant().tenantId())
                .filter(row -> canAccessClient(context, row.getClientId()))
                .orElseThrow(() -> new IllegalArgumentException("mapping not found: " + id));
        deleteMapping(context.tenant(), mapping);
    }

    private void deleteMapping(TenantContext tenant, SpecusMapping mapping) {
        // Same transaction: no workbench favourite or recent open outlives the mapping.
        workbenchReferences.forgetObject(WorkbenchReferences.TCP_MAPPING, mapping.getId());
        specusMappingRepository.delete(mapping);
        specusMappingRepository.flush();
        ClientAccount account = clientAccountRepository.findByIdAndTenantId(mapping.getClientId(), tenant.tenantId()).orElse(null);
        if (account != null) {
            pushSnapshotIfOnline(account);
        }
    }

    /**
     * 向在线客户端下发当前启用的端口映射 + HTTP 路由快照。客户端离线时抛出异常。
     * 返回 {@link PushResult} 报告本次实际包含的 TCP / HTTP 项数（HTTP 部分若为"未管理"
     * 状态则为 -1，前端可据此区分"管理且为 0"和"未接管"）。
     */
    @Transactional(readOnly = true)
    public PushResult pushToClient(long clientId) {
        return pushToClient(TenantContext.defaultTenant(), clientId);
    }

    @Transactional(readOnly = true)
    public PushResult pushToClient(TenantContext tenant, long clientId) {
        ClientAccount account = findClient(tenant, clientId);
        return pushToClient(tenant, account);
    }

    @Transactional(readOnly = true)
    public PushResult pushToClient(ManagementContext context, long clientId) {
        ClientAccount account = findClient(context, clientId);
        return pushToClient(context.tenant(), account);
    }

    private PushResult pushToClient(TenantContext tenant, ClientAccount account) {
        List<SpecusMapping> mappings = specusMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(tenant.tenantId(), account.getId());
        List<HttpRouteMapping> httpRoutes = loadEnabledHttpRoutes(account);
        if (!sendNatControl(account.getClientName(), mappings, httpRoutes)) {
            throw new IllegalStateException("客户端不在线，无法下发映射");
        }
        return new PushResult(mappings.size(), httpRoutes.size());
    }

    /**
     * 客户端登录成功后自动下发已启用的映射。不抛出异常，仅在失败时记录日志。
     *
     * <p>Always pushes the full snapshot, empty lists included. A client that reconnects after a
     * network drop reuses its access token without a new HTTP login, so this push is the only way it
     * learns that its last mapping or route was deleted while it was offline.
     */
    @Transactional(readOnly = true)
    public void pushOnLogin(String clientName) {
        ClientAccount account = clientAccountRepository.findByClientName(clientName).orElse(null);
        if (account == null) {
            return;
        }
        List<SpecusMapping> mappings = specusMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId());
        List<HttpRouteMapping> httpRoutes = loadEnabledHttpRoutes(account);
        if (sendNatControl(clientName, mappings, httpRoutes)) {
            log.info("[nat-control] auto pushed {} tcp + {} http route(s) to {} on login",
                    mappings.size(), httpRoutes.size(), clientName);
        }
    }

    /**
     * 在 TCP 或 HTTP 任意一类配置发生变化后调用，把当前权威全集推给在线客户端。
     * 客户端不在线时静默返回。
     */
    public void pushSnapshotIfOnline(ClientAccount account) {
        List<SpecusMapping> mappings = specusMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId());
        List<HttpRouteMapping> httpRoutes = loadEnabledHttpRoutes(account);
        if (sendNatControl(account.getClientName(), mappings, httpRoutes)) {
            log.info("[nat-control] auto-synchronized {} tcp + {} http route(s) to {}",
                    mappings.size(), httpRoutes.size(), account.getClientName());
        }
    }

    /** The client's enabled HTTP routes, possibly empty; never {@code null}. See the class javadoc. */
    private List<HttpRouteMapping> loadEnabledHttpRoutes(ClientAccount account) {
        return httpRouteMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId());
    }

    /**
     * Refuses, with the {@link IllegalArgumentException} the management API answers 400 to, a change
     * after which the client's NAT_CONTROL no longer fits one MESSAGE. Call it in the change's
     * transaction once the change is flushed and only when the change leaves the entry enabled: a
     * change that leaves it disabled only shrinks the message. It counts the client's enabled
     * entries, whether or not the client is enabled. See "NAT_CONTROL 的大小" in
     * protocol/spec/control-protocol.md.
     */
    void requireNatControlFits(ClientAccount account) {
        List<SpecusMapping> mappings = specusMappingRepository
                .findByTenantIdAndClientIdAndEnabledTrueOrderByIdAsc(account.getTenantId(), account.getId());
        if (reservedBodyBytes(mappings, loadEnabledHttpRoutes(account)) > MESSAGE_BODY_LIMIT) {
            throw new IllegalArgumentException(NAT_CONTROL_TOO_LARGE);
        }
    }

    /**
     * The MESSAGE body of a NAT_CONTROL carrying these entries, encoded as it is sent, with the
     * client's name counted at the longest a rename allows.
     */
    int reservedBodyBytes(List<SpecusMapping> mappings, List<HttpRouteMapping> httpRoutes) {
        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName(LONGEST_FIELD_NAME);
        packet.setMessageType(MessageType.NAT_CONTROL);
        packet.setMessage(messageJson(LONGEST_JSON_NAME, mappings, httpRoutes));
        return Serializer.COMPACT_BINARY.serialize(packet).length;
    }

    private boolean sendNatControl(String clientName,
                                   List<SpecusMapping> mappings,
                                   List<HttpRouteMapping> httpRoutes) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            return false;
        }

        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName(clientName);
        packet.setMessageType(MessageType.NAT_CONTROL);
        packet.setMessage(messageJson(clientName, mappings, httpRoutes));
        channel.writeAndFlush(packet);
        log.info("[nat-control] pushed {} tcp + {} http route(s) to {}",
                mappings.size(), httpRoutes.size(), clientName);
        return true;
    }

    /** The JSON text of clientName's NAT_CONTROL. */
    String messageJson(String clientName, List<SpecusMapping> mappings, List<HttpRouteMapping> httpRoutes) {
        List<Map<String, Object>> specusConfigList = new ArrayList<>();
        for (SpecusMapping mapping : mappings) {
            Map<String, Object> specusConfig = new LinkedHashMap<>();
            specusConfig.put("port", mapping.getListenPort());
            specusConfig.put("specusAddress", mapping.getTargetAddress());
            specusConfig.put("specusPort", mapping.getTargetPort());
            specusConfigList.add(specusConfig);
        }

        Map<String, Object> specusBean = new LinkedHashMap<>();
        specusBean.put("clientName", clientName);
        specusBean.put("remoteAddress", publicAddress);
        specusBean.put("remotePort", nettyPort);
        specusBean.put("specusConfigList", specusConfigList);
        // Always the full list, an empty array included, so the client replaces what it holds.
        List<Map<String, Object>> httpSpecusConfigList = new ArrayList<>(httpRoutes.size());
        for (HttpRouteMapping route : httpRoutes) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("route", route.getRoute());
            entry.put("targetBaseUrl", route.getTargetBaseUrl());
            entry.put("insecureSkipVerify", Boolean.TRUE.equals(route.getInsecureSkipVerify()));
            httpSpecusConfigList.add(entry);
        }
        specusBean.put("httpSpecusConfigList", httpSpecusConfigList);
        return JsonUtil.objectToString(specusBean);
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

    private int requirePort(Integer port, String field) {
        if (port == null || port < 1 || port > 65535) {
            throw new IllegalArgumentException(field + " must be between 1 and 65535");
        }
        return port;
    }

    private String requireTargetAddress(String targetAddress) {
        if (!StringUtils.hasText(targetAddress)) {
            throw new IllegalArgumentException("targetAddress cannot be blank");
        }
        String normalized = targetAddress.trim();
        if (normalized.length() > 255) {
            throw new IllegalArgumentException("targetAddress is too long");
        }
        return normalized;
    }

    private SpecusMappingView toView(SpecusMapping mapping) {
        return new SpecusMappingView(
                mapping.getId(),
                mapping.getClientId(),
                mapping.getClientName(),
                mapping.getListenPort(),
                mapping.getTargetAddress(),
                mapping.getTargetPort(),
                mapping.isEnabled(),
                Boolean.TRUE.equals(mapping.getDetailCaptureEnabled()),
                mapping.getCreatedAt(),
                mapping.getUpdatedAt()
        );
    }

    public record MappingMutation(
            Integer listenPort,
            String targetAddress,
            Integer targetPort,
            Boolean enabled,
            Boolean detailCaptureEnabled
    ) {
        public MappingMutation(Integer listenPort, String targetAddress, Integer targetPort, Boolean enabled) {
            this(listenPort, targetAddress, targetPort, enabled, false);
        }
    }

    /** 手动下发 endpoint 的返回值：下发的 TCP 映射与 HTTP 路由条数。 */
    public record PushResult(int specusMappings, int httpRoutes) {
    }
}
