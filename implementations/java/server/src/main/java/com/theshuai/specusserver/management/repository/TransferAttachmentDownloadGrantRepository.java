package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.TransferAttachmentDownloadGrant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface TransferAttachmentDownloadGrantRepository
        extends JpaRepository<TransferAttachmentDownloadGrant, Long> {

    Optional<TransferAttachmentDownloadGrant> findByTokenHash(String tokenHash);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update TransferAttachmentDownloadGrant grant
               set grant.consumedAt = :consumedAt
             where grant.id = :id
               and grant.tokenHash = :tokenHash
               and grant.consumedAt is null
               and grant.expiresAt > :now
            """)
    int consume(@Param("id") long id,
                @Param("tokenHash") String tokenHash,
                @Param("now") String now,
                @Param("consumedAt") String consumedAt);

    long deleteByExpiresAtBefore(String expiresAt);
}
