package com.theshuai.specusserver.management.storage;

import com.theshuai.specusserver.management.model.TcpTrafficFrame;
import com.theshuai.specusserver.management.model.TcpTrafficFrameView;
import com.theshuai.specusserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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
    public Page<TcpTrafficFrameView> search(TenantContext tenant, Long clientId, Set<Long> visibleClientIds,
                                            Integer listenPort, Pageable pageable) {
        if (isDenied(clientId, visibleClientIds)) {
            return Page.empty(pageable);
        }
        Page<TcpTrafficFrame> frames;
        if (visibleClientIds != null && clientId == null && listenPort == null) {
            frames = repository.findByTenantIdAndClientIdInOrderByIdDesc(tenant.tenantId(), List.copyOf(visibleClientIds), pageable);
        } else if (visibleClientIds != null && clientId == null) {
            frames = repository.findByTenantIdAndClientIdInAndListenPortOrderByIdDesc(
                    tenant.tenantId(), List.copyOf(visibleClientIds), listenPort, pageable);
        } else if (clientId == null && listenPort == null) {
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
    public Optional<TcpTrafficFrameView> findById(TenantContext tenant, long id, Set<Long> visibleClientIds) {
        if (visibleClientIds != null && visibleClientIds.isEmpty()) {
            return Optional.empty();
        }
        Optional<TcpTrafficFrame> found = visibleClientIds == null
                ? repository.findByTenantIdAndId(tenant.tenantId(), id)
                : repository.findByTenantIdAndIdAndClientIdIn(tenant.tenantId(), id, List.copyOf(visibleClientIds));
        return found
                .map(frame -> toView(frame, true));
    }

    @Override
    public Page<TcpTrafficFrameView> findStream(TenantContext tenant, String channelId, Set<Long> visibleClientIds,
                                                Pageable pageable) {
        if (channelId == null || channelId.isBlank()) {
            return Page.empty(pageable);
        }
        if (visibleClientIds != null && visibleClientIds.isEmpty()) {
            return Page.empty(pageable);
        }
        Page<TcpTrafficFrame> frames = visibleClientIds == null
                ? repository.findByTenantIdAndChannelIdOrderByIdAsc(tenant.tenantId(), channelId.trim(), pageable)
                : repository.findByTenantIdAndChannelIdAndClientIdInOrderByIdAsc(
                        tenant.tenantId(), channelId.trim(), List.copyOf(visibleClientIds), pageable);
        return frames.map(frame -> toView(frame, true));
    }

    private static boolean isDenied(Long clientId, Set<Long> visibleClientIds) {
        if (visibleClientIds == null) {
            return false;
        }
        if (visibleClientIds.isEmpty()) {
            return true;
        }
        return clientId != null && !visibleClientIds.contains(clientId);
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
