package com.theshuai.specusserver.management.storage;

import com.theshuai.specusserver.management.model.TcpTrafficFrame;
import com.theshuai.specusserver.management.model.TcpTrafficFrameView;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface TcpTrafficFrameStore {
    void saveAll(List<TcpTrafficFrame> frames);

    Page<TcpTrafficFrameView> search(TenantContext tenant, Long clientId, Set<Long> visibleClientIds,
                                     Integer listenPort, Pageable pageable);

    Optional<TcpTrafficFrameView> findById(TenantContext tenant, long id, Set<Long> visibleClientIds);

    Page<TcpTrafficFrameView> findStream(TenantContext tenant, String channelId, Set<Long> visibleClientIds,
                                         Pageable pageable);

    String backend();
}
