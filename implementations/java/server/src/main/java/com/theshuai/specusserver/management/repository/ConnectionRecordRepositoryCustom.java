package com.theshuai.specusserver.management.repository;

public interface ConnectionRecordRepositoryCustom {
    /** Caller holds the client's admission locks; current rows, not an older RR COUNT. */
    long countCurrentConnections(String tenantId, Long clientId, String since);
}
