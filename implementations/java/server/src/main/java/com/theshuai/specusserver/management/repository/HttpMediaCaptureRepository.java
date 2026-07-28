package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.HttpMediaCapture;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface HttpMediaCaptureRepository extends JpaRepository<HttpMediaCapture, Long> {
    Optional<HttpMediaCapture> findByIdAndTenantId(Long id, String tenantId);

    Optional<HttpMediaCapture> findByTenantIdAndDeduplicationKey(
            String tenantId, String deduplicationKey);

    Optional<HttpMediaCapture>
    findFirstByTenantIdAndResourceKeyAndMediaKindAndContentRangeStartAndContentRangeEndAndTotalBytesAndCapturedBytesAndContentEncodingAndStateAndExpiresAtAfterOrderByIdDesc(
            String tenantId,
            String resourceKey,
            String mediaKind,
            Long contentRangeStart,
            Long contentRangeEnd,
            Long totalBytes,
            long capturedBytes,
            String contentEncoding,
            String state,
            String expiresAt);

    Page<HttpMediaCapture> findByTenantIdOrderByIdDesc(String tenantId, Pageable pageable);

    Page<HttpMediaCapture> findByTenantIdAndClientIdOrderByIdDesc(
            String tenantId, Long clientId, Pageable pageable);

    Page<HttpMediaCapture> findByTenantIdAndClientIdInOrderByIdDesc(
            String tenantId, List<Long> clientIds, Pageable pageable);

    Page<HttpMediaCapture> findByTenantIdAndClientIdAndRouteOrderByIdDesc(
            String tenantId, Long clientId, String route, Pageable pageable);

    Page<HttpMediaCapture> findByTenantIdAndRouteOrderByIdDesc(
            String tenantId, String route, Pageable pageable);

    Page<HttpMediaCapture> findByTenantIdAndClientIdInAndRouteOrderByIdDesc(
            String tenantId, List<Long> clientIds, String route, Pageable pageable);

    List<HttpMediaCapture> findByTenantIdAndResourceKeyAndStateOrderByIdDesc(
            String tenantId, String resourceKey, String state);

    List<HttpMediaCapture> findByTenantIdAndClientIdAndRouteAndSourceUrlAndStateOrderByIdDesc(
            String tenantId, Long clientId, String route, String sourceUrl, String state);

    List<HttpMediaCapture> findTop1000ByTenantIdAndClientIdAndRouteAndMediaKindAndStateOrderByIdDesc(
            String tenantId, Long clientId, String route, String mediaKind, String state);

    List<HttpMediaCapture> findTop200ByStateInAndExpiresAtBeforeOrderByIdAsc(
            List<String> states, String expiresAt);
}
