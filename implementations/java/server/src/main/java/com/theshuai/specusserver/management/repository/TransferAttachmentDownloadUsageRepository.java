package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.TransferAttachmentDownloadUsage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface TransferAttachmentDownloadUsageRepository
        extends JpaRepository<TransferAttachmentDownloadUsage, Long> {

    @Query("""
            select coalesce(sum(usage.sizeBytes), 0)
              from TransferAttachmentDownloadUsage usage
             where usage.tenantId = :tenantId
               and usage.username = :username
               and usage.usageMonth = :usageMonth
            """)
    long sumBytesByAccountAndMonth(@Param("tenantId") String tenantId,
                                   @Param("username") String username,
                                   @Param("usageMonth") String usageMonth);
}
