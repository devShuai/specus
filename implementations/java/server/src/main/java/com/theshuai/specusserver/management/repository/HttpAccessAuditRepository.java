package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.HttpAccessAudit;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface HttpAccessAuditRepository extends JpaRepository<HttpAccessAudit, Long> {

    /** One page of a tenant's audit, newest first; {@code routeId} and {@code before} are optional. */
    @Query("""
            select entry from HttpAccessAudit entry
             where entry.tenantId = :tenantId
               and (:routeId is null or entry.routeId = :routeId)
               and (:before is null or entry.id < :before)
             order by entry.id desc
            """)
    List<HttpAccessAudit> findPage(@Param("tenantId") String tenantId,
                                   @Param("routeId") Long routeId,
                                   @Param("before") Long before,
                                   Pageable page);

    List<HttpAccessAudit> findAllByOrderByIdAsc();

    @Modifying(flushAutomatically = true)
    @Query("delete from HttpAccessAudit entry where entry.occurredAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") Long cutoffSeconds);
}
