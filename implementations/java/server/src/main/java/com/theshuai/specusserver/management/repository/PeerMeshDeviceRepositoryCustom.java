package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshDevice;
import java.util.Optional;

public interface PeerMeshDeviceRepositoryCustom {
    /** Caller holds the current client (and its credential) first. Detached current scalar row. */
    Optional<PeerMeshDevice> lockCurrent(String tenantId, Long clientId);
}
