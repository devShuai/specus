package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ConnectionRecord;
import java.util.Optional;

public interface ConnectionRecordRepositoryCustom {
    /** Caller holds the client's admission locks; current rows, not an older RR COUNT. */
    long countCurrentConnections(String tenantId, Long clientId, String since);
    /** Atomic first-write close, with a refreshed entity only when a field actually changed. */
    Optional<ConnectionRecord> disconnectCurrent(long id, String now, String reason);
}
