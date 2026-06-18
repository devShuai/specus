package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelserver.session.SessionUtil;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.model.TunnelMappingView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.repository.TunnelMappingRepository;
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
 * <p>下发协议（{@code NAT_CONTROL}）的 JSON 体一直承载 TCP 端口映射 {@code tunnelConfigList}；
 * 自从 HTTP 路由也由后台管理后，本服务在每次下发时**额外查询** {@link HttpRouteMappingRepository}
 * 把启用项装到同一条消息的 {@code httpTunnelConfigList} 字段。语义约定见
 * {@link #appendHttpRoutesIfManaged}：
 * <ul>
 *   <li>该客户端从未在后台创建过任何 HTTP 路由 → 字段缺省 → 客户端继续用本地
 *       {@code tunnelClientConfig.json} 兜底（避免升级老部署时误清空）</li>
 *   <li>创建过至少一条（即便全部禁用/删除）→ 字段为数组（可能为空）→ 客户端整体替换</li>
 * </ul>
 *
 * <p>HTTP 路由本身的 CRUD 在 {@link HttpRouteService}；它每次写入后回调本类的
 * {@link #pushSnapshotIfOnline(ClientAccount)}，因此一次 mutation 始终下发"当前权威全集"。
 */
@Service
@Slf4j
public class NatControlService {
    private final TunnelMappingRepository tunnelMappingRepository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final int nettyPort;
    private final String publicAddress;

    public NatControlService(TunnelMappingRepository tunnelMappingRepository,
                             HttpRouteMappingRepository httpRouteMappingRepository,
                             ClientAccountRepository clientAccountRepository,
                             @Value("${tunnel.netty.port:7010}") int nettyPort,
                             @Value("${tunnel.public-address:}") String publicAddress) {
        this.tunnelMappingRepository = tunnelMappingRepository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.nettyPort = nettyPort;
        this.publicAddress = StringUtils.hasText(publicAddress) ? publicAddress.trim() : null;
    }

    @Transactional(readOnly = true)
    public List<TunnelMappingView> listMappings(Long clientId) {
        List<TunnelMapping> mappings = clientId == null
                ? tunnelMappingRepository.findAllByOrderByIdDesc()
                : tunnelMappingRepository.findByClientIdOrderByIdDesc(clientId);
        return mappings.stream().map(this::toView).toList();
    }

    @Transactional
    public TunnelMappingView createMapping(long clientId, MappingMutation request) {
        ClientAccount account = findClient(clientId);
        int listenPort = requirePort(request.listenPort(), "listenPort");
        int targetPort = requirePort(request.targetPort(), "targetPort");
        String targetAddress = requireTargetAddress(request.targetAddress());
        tunnelMappingRepository.findByListenPort(listenPort).ifPresent(existing -> {
            throw new IllegalArgumentException("公网端口 " + listenPort + " 已被占用");
        });

        String now = Instant.now().toString();
        TunnelMapping mapping = new TunnelMapping();
        mapping.setId(ClientIdGenerator.newId());
        mapping.setClientId(account.getId());
        mapping.setClientName(account.getClientName());
        mapping.setListenPort(listenPort);
        mapping.setTargetAddress(targetAddress);
        mapping.setTargetPort(targetPort);
        mapping.setEnabled(request.enabled() == null || request.enabled());
        mapping.setCreatedAt(now);
        mapping.setUpdatedAt(now);
        TunnelMapping saved = tunnelMappingRepository.saveAndFlush(mapping);
        pushSnapshotIfOnline(account);
        return toView(saved);
    }

    @Transactional
    public TunnelMappingView updateMapping(long id, MappingMutation request) {
        TunnelMapping mapping = tunnelMappingRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("mapping not found: " + id));
        int listenPort = requirePort(request.listenPort(), "listenPort");
        int targetPort = requirePort(request.targetPort(), "targetPort");
        String targetAddress = requireTargetAddress(request.targetAddress());

        if (listenPort != mapping.getListenPort()) {
            tunnelMappingRepository.findByListenPort(listenPort).ifPresent(existing -> {
                if (!existing.getId().equals(mapping.getId())) {
                    throw new IllegalArgumentException("公网端口 " + listenPort + " 已被占用");
                }
            });
        }

        mapping.setListenPort(listenPort);
        mapping.setTargetAddress(targetAddress);
        mapping.setTargetPort(targetPort);
        mapping.setEnabled(request.enabled() == null || request.enabled());
        mapping.setUpdatedAt(Instant.now().toString());
        TunnelMapping saved = tunnelMappingRepository.saveAndFlush(mapping);

        ClientAccount account = clientAccountRepository.findById(saved.getClientId()).orElse(null);
        if (account != null) {
            pushSnapshotIfOnline(account);
        }
        return toView(saved);
    }

    @Transactional
    public void deleteMapping(long id) {
        TunnelMapping mapping = tunnelMappingRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("mapping not found: " + id));
        tunnelMappingRepository.delete(mapping);
        tunnelMappingRepository.flush();
        ClientAccount account = clientAccountRepository.findById(mapping.getClientId()).orElse(null);
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
        ClientAccount account = findClient(clientId);
        List<TunnelMapping> mappings = tunnelMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(account.getId());
        List<HttpRouteMapping> httpRoutes = assembleHttpRoutesIfManaged(account.getId());
        if (!sendNatControl(account.getClientName(), mappings, httpRoutes)) {
            throw new IllegalStateException("客户端不在线，无法下发映射");
        }
        return new PushResult(mappings.size(), httpRoutes == null ? -1 : httpRoutes.size());
    }

    /**
     * 客户端登录成功后自动下发已启用的映射。不抛出异常，仅在失败时记录日志。
     * 若两类配置都为空（且 HTTP 未接管），跳过 push 以减少握手抖动。
     */
    @Transactional(readOnly = true)
    public void pushOnLogin(String clientName) {
        ClientAccount account = clientAccountRepository.findByClientName(clientName).orElse(null);
        if (account == null) {
            return;
        }
        List<TunnelMapping> mappings = tunnelMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(account.getId());
        List<HttpRouteMapping> httpRoutes = assembleHttpRoutesIfManaged(account.getId());
        if (mappings.isEmpty() && httpRoutes == null) {
            return;
        }
        if (sendNatControl(clientName, mappings, httpRoutes)) {
            log.info("[nat-control] auto pushed {} tcp + {} http route(s) to {} on login",
                    mappings.size(), httpRoutes == null ? "-" : String.valueOf(httpRoutes.size()), clientName);
        }
    }

    /**
     * 在 TCP 或 HTTP 任意一类配置发生变化后调用，把当前权威全集推给在线客户端。
     * 客户端不在线时静默返回。
     */
    public void pushSnapshotIfOnline(ClientAccount account) {
        List<TunnelMapping> mappings = tunnelMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(account.getId());
        List<HttpRouteMapping> httpRoutes = assembleHttpRoutesIfManaged(account.getId());
        if (sendNatControl(account.getClientName(), mappings, httpRoutes)) {
            log.info("[nat-control] auto-synchronized {} tcp + {} http route(s) to {}",
                    mappings.size(), httpRoutes == null ? "-" : String.valueOf(httpRoutes.size()),
                    account.getClientName());
        }
    }

    /**
     * 仅当客户端在后台**至少**创建过一条 HTTP 路由（含 disabled）时才视为"接管态"，返回当前
     * 启用项列表（可能为空）；否则返回 {@code null}，调用方据此决定是否在 JSON 里写出
     * {@code httpTunnelConfigList} 字段。详见类级 javadoc。
     */
    private List<HttpRouteMapping> assembleHttpRoutesIfManaged(long clientId) {
        if (!httpRouteMappingRepository.existsByClientId(clientId)) {
            return null;
        }
        return httpRouteMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(clientId);
    }

    private boolean sendNatControl(String clientName,
                                   List<TunnelMapping> mappings,
                                   List<HttpRouteMapping> httpRoutes) {
        Channel channel = SessionUtil.getChannel(clientName);
        if (channel == null || !SessionUtil.hasLogin(channel)) {
            return false;
        }

        List<Map<String, Object>> tunnelConfigList = new ArrayList<>();
        for (TunnelMapping mapping : mappings) {
            Map<String, Object> tunnelConfig = new LinkedHashMap<>();
            tunnelConfig.put("port", mapping.getListenPort());
            tunnelConfig.put("tunnelAddress", mapping.getTargetAddress());
            tunnelConfig.put("tunnelPort", mapping.getTargetPort());
            tunnelConfigList.add(tunnelConfig);
        }

        Map<String, Object> tunnelBean = new LinkedHashMap<>();
        tunnelBean.put("clientName", clientName);
        tunnelBean.put("remoteAddress", publicAddress);
        tunnelBean.put("remotePort", nettyPort);
        tunnelBean.put("tunnelConfigList", tunnelConfigList);
        if (httpRoutes != null) {
            // null = 未接管，缺省字段；非 null = 接管态，即便 0 项也要发空数组让客户端整体替换
            List<Map<String, Object>> httpTunnelConfigList = new ArrayList<>(httpRoutes.size());
            for (HttpRouteMapping route : httpRoutes) {
                Map<String, Object> entry = new LinkedHashMap<>();
                entry.put("route", route.getRoute());
                entry.put("targetBaseUrl", route.getTargetBaseUrl());
                httpTunnelConfigList.add(entry);
            }
            tunnelBean.put("httpTunnelConfigList", httpTunnelConfigList);
        }

        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName(clientName);
        packet.setMessageType(MessageType.NAT_CONTROL);
        packet.setMessage(JsonUtil.objectToString(tunnelBean));
        channel.writeAndFlush(packet);
        log.info("[nat-control] pushed {} tcp + {} http route(s) to {}",
                mappings.size(), httpRoutes == null ? "-" : String.valueOf(httpRoutes.size()), clientName);
        return true;
    }

    private ClientAccount findClient(long clientId) {
        return clientAccountRepository.findById(clientId)
                .orElseThrow(() -> new IllegalArgumentException("client not found: " + clientId));
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

    private TunnelMappingView toView(TunnelMapping mapping) {
        return new TunnelMappingView(
                mapping.getId(),
                mapping.getClientId(),
                mapping.getClientName(),
                mapping.getListenPort(),
                mapping.getTargetAddress(),
                mapping.getTargetPort(),
                mapping.isEnabled(),
                mapping.getCreatedAt(),
                mapping.getUpdatedAt()
        );
    }

    public record MappingMutation(
            Integer listenPort,
            String targetAddress,
            Integer targetPort,
            Boolean enabled
    ) {
    }

    /** 手动下发 endpoint 的返回值。{@code httpRoutes == -1} 表示客户端未接管态。 */
    public record PushResult(int tunnels, int httpRoutes) {
    }
}
