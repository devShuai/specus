package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshAcl;
import java.util.Optional;

public interface PeerMeshAclRepositoryCustom {
    /** Caller holds current actor (management) and ordered current client parents first. */
    Optional<PeerMeshAcl> lockCurrent(Long id, String tenant);
    Optional<PeerMeshAcl> lockPair(String tenant, Long source, Long target);
    PeerMeshAcl upsertCurrent(PeerMeshAcl requested, boolean updateDirection);
    void deleteCurrent(Long id, String tenant);
}
