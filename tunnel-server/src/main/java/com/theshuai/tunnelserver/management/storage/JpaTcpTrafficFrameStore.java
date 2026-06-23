package com.theshuai.tunnelserver.management.storage;

import com.theshuai.tunnelserver.management.model.TcpTrafficFrame;
import com.theshuai.tunnelserver.management.model.TcpTrafficFrameView;
import com.theshuai.tunnelserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class JpaTcpTrafficFrameStore implements TcpTrafficFrameStore {
    private final TcpTrafficFrameRepository repository;

    public JpaTcpTrafficFrameStore(TcpTrafficFrameRepository repository) {
        this.repository = repository;
    }

    @Override
    public void saveAll(List<TcpTrafficFrame> frames) {
        repository.saveAll(frames);
    }

    @Override
    public Page<TcpTrafficFrameView> search(TenantContext tenant, Long clientId, Integer listenPort, Pageable pageable) {
        Page<TcpTrafficFrame> frames;
        if (clientId == null && listenPort == null) {
            frames = repository.findByTenantIdOrderByIdDesc(tenant.tenantId(), pageable);
        } else if (clientId == null) {
            frames = repository.findByTenantIdAndListenPortOrderByIdDesc(tenant.tenantId(), listenPort, pageable);
        } else if (listenPort == null) {
            frames = repository.findByTenantIdAndClientIdOrderByIdDesc(tenant.tenantId(), clientId, pageable);
        } else {
            frames = repository.findByTenantIdAndClientIdAndListenPortOrderByIdDesc(
                    tenant.tenantId(), clientId, listenPort, pageable);
        }
        return frames.map(frame -> toView(frame, false));
    }

    @Override
    public Optional<TcpTrafficFrameView> findById(TenantContext tenant, long id) {
        return repository.findByTenantIdAndId(tenant.tenantId(), id)
                .map(frame -> toView(frame, true));
    }

    @Override
    public List<TcpTrafficFrameView> findStream(TenantContext tenant, String channelId, Pageable pageable) {
        if (channelId == null || channelId.isBlank()) {
            return List.of();
        }
        return repository.findByTenantIdAndChannelIdOrderByIdAsc(tenant.tenantId(), channelId.trim(), pageable)
                .stream()
                .map(frame -> toView(frame, true))
                .toList();
    }

    @Override
    public String backend() {
        return "db";
    }

    static TcpTrafficFrameView toView(TcpTrafficFrame frame) {
        return toView(frame, true);
    }

    private static TcpTrafficFrameView toView(TcpTrafficFrame frame, boolean includePayload) {
        return new TcpTrafficFrameView(
                frame.getId() == null ? "" : Long.toString(frame.getId()),
                frame.getClientId(),
                frame.getClientName(),
                frame.getListenPort(),
                frame.getResourceId(),
                frame.getResourceName(),
                frame.getChannelId(),
                frame.getDirection(),
                frame.getRemoteAddress(),
                frame.getSourceAddress(),
                frame.getSourcePort(),
                frame.getDestinationAddress(),
                frame.getDestinationPort(),
                longValue(frame.getStreamOffset()),
                longValue(frame.getStreamEndOffset()),
                longValue(frame.getFrameIndex()),
                frame.getPayloadBytes(),
                includePayload ? payloadBase64(frame.getPayloadData()) : "",
                frame.getPayloadPreviewHex(),
                frame.getPayloadPreviewText(),
                frame.isTruncated(),
                frame.getFrameTime()
        );
    }

    private static String payloadBase64(byte[] payloadData) {
        if (payloadData == null || payloadData.length == 0) {
            return "";
        }
        return Base64.getEncoder().encodeToString(payloadData);
    }

    private static long longValue(Long value) {
        return value == null ? 0 : value;
    }
}
