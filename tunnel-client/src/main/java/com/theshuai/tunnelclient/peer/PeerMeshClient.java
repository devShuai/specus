package com.theshuai.tunnelclient.peer;

import com.fasterxml.jackson.databind.JsonNode;
import com.theshuai.common.clientauth.ClientAuthLoginResponse;
import com.theshuai.common.util.JsonUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class PeerMeshClient implements AutoCloseable {
    private final Map<Long, PeerInfo> peers = new ConcurrentHashMap<>();
    private volatile ClientAuthLoginResponse.PeerMeshConfig config;
    private volatile boolean running;

    public PeerMeshClient(ClientAuthLoginResponse.PeerMeshConfig config) {
        startOrUpdate(config);
    }

    public synchronized void startOrUpdate(ClientAuthLoginResponse.PeerMeshConfig nextConfig) {
        this.config = nextConfig;
        if (nextConfig == null || !nextConfig.isEnabled()) {
            if (running) {
                log.info("Peer mesh 已关闭");
            }
            running = false;
            peers.clear();
            return;
        }
        running = true;
        log.info("Peer mesh 已启用: client={}, virtualIp={}, cidr={}, stun={}:{}, turn={}:{}",
                nextConfig.getClientName(),
                nextConfig.getVirtualIp(),
                nextConfig.getCidr(),
                nextConfig.getStunHost(),
                nextConfig.getStunPort(),
                nextConfig.getTurnHost(),
                nextConfig.getTurnPort());
        log.info("Peer mesh 数据面已就绪等待平台 TUN/Wintun 适配；当前版本先接入控制信令与设备拓扑");
    }

    public void handleControlMessage(String message) {
        if (!running || !StringUtils.hasText(message)) {
            return;
        }
        JsonNode root = JsonUtil.readString(message);
        if (root == null) {
            log.warn("Peer mesh 信令不是有效 JSON");
            return;
        }
        String type = root.path("type").asText("");
        if ("roster".equals(type)) {
            updateRoster(root.path("peers"));
            return;
        }
        log.debug("收到 peer mesh 信令: type={}, source={}, target={}",
                type,
                root.path("sourceClientName").asText("-"),
                root.path("targetClientName").asText("-"));
    }

    private void updateRoster(JsonNode peerNodes) {
        peers.clear();
        if (peerNodes != null && peerNodes.isArray()) {
            for (JsonNode node : peerNodes) {
                long clientId = node.path("clientId").asLong(0);
                if (clientId <= 0) {
                    continue;
                }
                peers.put(clientId, new PeerInfo(
                        clientId,
                        node.path("clientName").asText(""),
                        node.path("virtualIp").asText(""),
                        node.path("publicKey").asText(""),
                        node.path("natType").asText(""),
                        node.path("lastEndpoint").asText(""),
                        node.path("online").asBoolean(false)
                ));
            }
        }
        log.info("Peer mesh 可互联客户端刷新: {} 个", peers.size());
    }

    @Override
    public void close() {
        running = false;
        peers.clear();
    }

    private record PeerInfo(long clientId,
                            String clientName,
                            String virtualIp,
                            String publicKey,
                            String natType,
                            String lastEndpoint,
                            boolean online) {
    }
}
