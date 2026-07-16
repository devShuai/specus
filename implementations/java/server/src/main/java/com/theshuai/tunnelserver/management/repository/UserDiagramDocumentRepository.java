package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.UserDiagramDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserDiagramDocumentRepository extends JpaRepository<UserDiagramDocument, Long> {
    @Query("""
            select d.id as id, d.name as name, d.sizeBytes as sizeBytes, d.revision as revision,
                   d.createdAt as createdAt, d.updatedAt as updatedAt
              from UserDiagramDocument d
             where d.tenantId = :tenantId and d.ownerUsername = :ownerUsername
             order by d.updatedAt desc
            """)
    List<UserDiagramDocumentSummary> findSummariesByOwner(@Param("tenantId") String tenantId,
                                                          @Param("ownerUsername") String ownerUsername);

    Optional<UserDiagramDocument> findByIdAndTenantIdAndOwnerUsername(Long id, String tenantId, String ownerUsername);

    long countByTenantIdAndOwnerUsername(String tenantId, String ownerUsername);

    interface UserDiagramDocumentSummary {
        Long getId();

        String getName();

        long getSizeBytes();

        long getRevision();

        String getCreatedAt();

        String getUpdatedAt();
    }
}
