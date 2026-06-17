package com.theshuai.tunnelserver.management.service;

import com.theshuai.common.protocol.MessageType;
import com.theshuai.common.protocol.response.MessageResponsePacket;
import com.theshuai.common.util.JsonUtil;
import com.theshuai.common.util.SessionUtil;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.TunnelMapping;
import com.theshuai.tunnelserver.management.model.TunnelMappingView;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
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

@Service
@Slf4j
public class NatControlService {
    private final TunnelMappingRepository tunnelMappingRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final int nettyPort;
    private final String publicAddress;

    public NatControlService(TunnelMappingRepository tunnelMappingRepository,
                             ClientAccountRepository clientAccountRepository,
                             @Value("${tunnel.netty.port:7010}") int nettyPort,
                             @Value("${tunnel.public-address:}") String publicAddress) {
        this.tunnelMappingRepository = tunnelMappingRepository;
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
     * 向在线客户端下发当前启用的端口映射快照（NAT_CONTROL）。客户端离线时抛出异常。
     */
    @Transactional(readOnly = true)
    public int pushToClient(long clientId) {
        ClientAccount account = findClient(clientId);
        List<TunnelMapping> mappings = tunnelMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(account.getId());
        if (!sendNatControl(account.getClientName(), mappings)) {
            throw new IllegalStateException("客户端不在线，无法下发映射");
        }
        return mappings.size();
    }

    /**
     * 客户端登录成功后自动下发已启用的映射。不抛出异常，仅在失败时记录日志。
     */
    @Transactional(readOnly = true)
    public void pushOnLogin(String clientName) {
        ClientAccount account = clientAccountRepository.findByClientName(clientName).orElse(null);
        if (account == null) {
            return;
        }
        List<TunnelMapping> mappings = tunnelMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(account.getId());
        if (mappings.isEmpty()) {
            return;
        }
        if (sendNatControl(clientName, mappings)) {
            log.info("[nat-control] auto pushed {} mapping(s) to {} on login", mappings.size(), clientName);
        }
    }

    private boolean sendNatControl(String clientName, List<TunnelMapping> mappings) {
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

        MessageResponsePacket packet = new MessageResponsePacket();
        packet.setClientName(clientName);
        packet.setMessageType(MessageType.NAT_CONTROL);
        packet.setMessage(JsonUtil.objectToString(tunnelBean));
        channel.writeAndFlush(packet);
        log.info("[nat-control] pushed {} mapping(s) to {}", mappings.size(), clientName);
        return true;
    }

    private void pushSnapshotIfOnline(ClientAccount account) {
        List<TunnelMapping> mappings = tunnelMappingRepository.findByClientIdAndEnabledTrueOrderByIdAsc(account.getId());
        if (sendNatControl(account.getClientName(), mappings)) {
            log.info("[nat-control] automatically synchronized {} mapping(s) to {}", mappings.size(), account.getClientName());
        }
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
}
