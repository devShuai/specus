package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.model.TransferAttachment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TransferAttachmentRepository extends JpaRepository<TransferAttachment, Long> {
    Optional<TransferAttachment> findByIdAndScope(Long id, String scope);

    Optional<TransferAttachment> findByIdAndTenantIdAndScope(Long id, String tenantId, String scope);

    Optional<TransferAttachment> findByObjectKey(String objectKey);

    long countByScopeAndPublicTransferRoomIdAndStatus(String scope, Long publicTransferRoomId, String status);

    /** {@code now} and both expiry columns are {@link SortableInstant} text, so the string order is the time order. */
    @Query("""
            select coalesce(sum(attachment.sizeBytes), 0)
              from TransferAttachment attachment
             where attachment.tenantId = :tenantId
               and attachment.ownerUsername = :ownerUsername
               and attachment.id <> :excludedAttachmentId
               and ((attachment.status = :pendingStatus and attachment.uploadExpiresAt > :now)
                 or (attachment.status = :uploadedStatus and attachment.expiresAt > :now))
            """)
    long sumActiveStorageBytes(@Param("tenantId") String tenantId,
                               @Param("ownerUsername") String ownerUsername,
                               @Param("excludedAttachmentId") long excludedAttachmentId,
                               @Param("pendingStatus") String pendingStatus,
                               @Param("uploadedStatus") String uploadedStatus,
                               @Param("now") String now);

    List<TransferAttachment> findTop100ByExpiresAtBeforeAndStatusNotOrderByExpiresAtAsc(String now, String status);
}
