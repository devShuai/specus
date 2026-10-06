package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.HttpShare;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Collection;
import java.util.List;

public interface HttpShareRepository extends JpaRepository<HttpShare, String> {

    /** Active shares of a route: not revoked and {@code now < expiresAt}. */
    long countByRouteIdAndRevokedAtIsNullAndExpiresAtGreaterThan(Long routeId, Long nowSeconds);

    List<HttpShare> findByRouteIdOrderByCreatedAtDescShareIdDesc(Long routeId);

    List<HttpShare> findByRouteIdInAndRevokedAtIsNullAndExpiresAtGreaterThanOrderByCreatedAtAscShareIdAsc(
            Collection<Long> routeIds, Long nowSeconds);

    List<HttpShare> findByTenantIdAndCreatedByAndRevokedAtIsNullAndExpiresAtGreaterThanOrderByCreatedAtAscShareIdAsc(
            String tenantId, String createdBy, Long nowSeconds);

    List<HttpShare> findByRevokedAtIsNullAndExpiresAtGreaterThanOrderByCreatedAtAscShareIdAsc(Long nowSeconds);

    List<HttpShare> findByRevokedAtIsNullAndExpiryRecordedAndExpiresAtLessThanEqualOrderByExpiresAtAscShareIdAsc(
            int expiryRecorded, Long nowSeconds);

    /**
     * The only way a share is revoked: a conditional update, so that concurrent instances (and the
     * sweep racing a request) end each share once and write one audit entry.
     */
    @Modifying(flushAutomatically = true)
    @Query("""
            update HttpShare share
               set share.revokedAt = :now,
                   share.revokedBy = :actor,
                   share.revokeReason = :reason
             where share.shareId = :shareId
               and share.revokedAt is null
               and share.expiresAt > :now
            """)
    int revokeIfActive(@Param("shareId") String shareId,
                       @Param("now") Long nowSeconds,
                       @Param("actor") String actor,
                       @Param("reason") String reason);

    @Modifying(flushAutomatically = true)
    @Query("""
            update HttpShare share
               set share.expiryRecorded = 1
             where share.shareId = :shareId
               and share.revokedAt is null
               and share.expiryRecorded = 0
            """)
    int markExpiryRecorded(@Param("shareId") String shareId);

    /** Removes shares that ended (revoked or expired) before {@code cutoff}. */
    @Modifying(flushAutomatically = true)
    @Query("""
            delete from HttpShare share
             where (share.revokedAt is not null and share.revokedAt < :cutoff)
                or (share.revokedAt is null and share.expiresAt < :cutoff)
            """)
    int deleteEndedBefore(@Param("cutoff") Long cutoffSeconds);
}
