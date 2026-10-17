package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PeerMeshSession;
import java.util.Optional;

public interface PeerMeshSessionRepositoryCustom {
    /** Immutable endpoint discovery only; not authority/current state. Missing older-snapshot hints fail closed. */
    record Reference(long id, String tenant, long source, long target) {}
    Optional<Reference> findReference(long id);
    /** Caller takes any required current actor/ordered parent locks first. Detached scalar row, not JPA/L1. */
    Optional<PeerMeshSession> lockCurrent(long id);
    /** Caller holds current row lock. Does not write identity/token/expiry fields. Verifies postcondition. */
    PeerMeshSession saveCurrent(PeerMeshSession current);
}
