package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.HttpMediaReference;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface HttpMediaReferenceRepository extends JpaRepository<HttpMediaReference, Long> {
    List<HttpMediaReference> findByTenantIdAndManifestCaptureIdOrderBySequenceIndexAscIdAsc(
            String tenantId, Long manifestCaptureId);

    void deleteByTenantIdAndManifestCaptureId(String tenantId, Long manifestCaptureId);
}
