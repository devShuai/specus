package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.TransferAttachment;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TransferAttachmentRepository extends JpaRepository<TransferAttachment, Long> {
    Optional<TransferAttachment> findByIdAndScope(Long id, String scope);

    Optional<TransferAttachment> findByIdAndTenantIdAndScope(Long id, String tenantId, String scope);

    List<TransferAttachment> findTop100ByExpiresAtBeforeAndStatusNotOrderByExpiresAtAsc(String now, String status);
}
