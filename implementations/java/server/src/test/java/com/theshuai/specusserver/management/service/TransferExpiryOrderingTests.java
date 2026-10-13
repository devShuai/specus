package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ObjectStorageProperties;
import com.theshuai.specusserver.config.PublicTransferProperties;
import com.theshuai.specusserver.database.SortableTimestampMigrator;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.model.TransferAttachment;
import com.theshuai.specusserver.management.model.TransferAttachmentDownloadGrant;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadGrantRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadUsageRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.storage.object.AliyunOssObjectStorageService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Expiry instants a fraction of a second on either side of "now". The storage-usage, expiry-scan
 * and download-grant queries compare the stored text with "now" in SQLite, which is only right when
 * the text order is the time order. Rows are stored as the write paths store them, or in the
 * legacy {@code Instant.toString()} form that the startup migrator rewrites.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false"
})
@Transactional
class TransferExpiryOrderingTests {
    private static final String LONG_AGO = "2026-09-15T11:00:00Z";
    private static final String FAR_AHEAD = "2026-09-18T12:00:00Z";

    @Autowired private TransferAttachmentRepository repository;
    @Autowired private TransferAttachmentDownloadGrantRepository downloadGrantRepository;
    @Autowired private TransferAttachmentDownloadUsageRepository downloadUsageRepository;
    @Autowired private ClientAccountService clientAccountService;
    @Autowired private PublicTransferRoomService publicTransferRoomService;
    @Autowired private SortableTimestampMigrator migrator;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private EntityManager entityManager;

    enum Rows {
        /** As the upload and download paths store them. */
        WRITTEN,
        /** As servers before the fixed width stored them, then rewritten by the startup migrator. */
        LEGACY_MIGRATED
    }

    @ParameterizedTest
    @EnumSource(Rows.class)
    void storageUsageAroundAWholeSecondNow(Rows rows) {
        attachment(rows, 1L, "UPLOADED", 1, LONG_AGO, "2026-09-15T12:00:00.500Z");     // +0.5 s
        attachment(rows, 2L, "UPLOADED", 2, LONG_AGO, "2026-09-15T11:59:59.500Z");     // -0.5 s
        attachment(rows, 3L, "UPLOADED", 4, LONG_AGO, "2026-09-15T12:00:00Z");         // = now
        attachment(rows, 4L, "UPLOADED", 8, LONG_AGO, "2026-09-15T12:00:00.000001Z");  // +1 us
        attachment(rows, 5L, "PENDING", 16, "2026-09-15T12:00:00.250Z", FAR_AHEAD);    // +0.25 s
        attachment(rows, 6L, "PENDING", 32, "2026-09-15T11:59:59.999999Z", FAR_AHEAD); // -1 us
        settle(rows);

        assertThat(storageUsedAt("2026-09-15T12:00:00Z")).isEqualTo(1 + 8 + 16);
    }

    @ParameterizedTest
    @EnumSource(Rows.class)
    void storageUsageAroundAFractionalNow(Rows rows) {
        attachment(rows, 1L, "UPLOADED", 1, LONG_AGO, "2026-09-15T12:00:00Z");         // -0.5 s
        attachment(rows, 2L, "UPLOADED", 2, LONG_AGO, "2026-09-15T12:00:00.500Z");     // = now
        attachment(rows, 3L, "UPLOADED", 4, LONG_AGO, "2026-09-15T12:00:00.500001Z");  // +1 us
        attachment(rows, 4L, "UPLOADED", 8, LONG_AGO, "2026-09-15T12:00:00.499Z");     // -1 ms
        attachment(rows, 5L, "UPLOADED", 16, LONG_AGO, "2026-09-15T12:00:01Z");        // +0.5 s
        attachment(rows, 6L, "PENDING", 32, "2026-09-15T12:00:00.750Z", FAR_AHEAD);    // +0.25 s
        attachment(rows, 7L, "PENDING", 64, "2026-09-15T12:00:00Z", FAR_AHEAD);        // -0.5 s
        settle(rows);

        assertThat(storageUsedAt("2026-09-15T12:00:00.500Z")).isEqualTo(4 + 16 + 32);
    }

    @ParameterizedTest
    @EnumSource(Rows.class)
    void expiryScanAndDownloadGrantsAroundAFractionalNow(Rows rows) {
        attachment(rows, 1L, "UPLOADED", 1, LONG_AGO, "2026-09-15T12:00:00Z");         // -0.5 s
        attachment(rows, 2L, "UPLOADED", 1, LONG_AGO, "2026-09-15T12:00:00.750Z");     // +0.25 s
        attachment(rows, 3L, "UPLOADED", 1, LONG_AGO, "2026-09-15T12:00:00.499Z");     // -1 ms
        attachment(rows, 4L, "UPLOADED", 1, LONG_AGO, "2026-09-15T12:00:00.500001Z");  // +1 us
        grant(rows, 11L, "2026-09-15T12:00:00Z");                                       // -0.5 s
        grant(rows, 12L, "2026-09-15T12:00:00.750Z");                                   // +0.25 s
        grant(rows, 13L, "2026-09-15T12:00:00.500001Z");                                // +1 us
        grant(rows, 14L, "2026-09-15T12:00:00.4Z");                                     // -0.1 s
        settle(rows);
        Instant now = Instant.parse("2026-09-15T12:00:00.500Z");
        String cutoff = SortableInstant.format(now);

        assertThat(repository.findTop100ByExpiresAtBeforeAndStatusNotOrderByExpiresAtAsc(
                cutoff, TransferAttachmentService.STATUS_EXPIRED))
                .extracting(TransferAttachment::getId).containsExactly(1L, 3L);
        assertThat(downloadGrantRepository.consume(11L, token(11L), cutoff, now.toString())).isZero();
        assertThat(downloadGrantRepository.consume(12L, token(12L), cutoff, now.toString())).isOne();
        assertThat(downloadGrantRepository.consume(13L, token(13L), cutoff, now.toString())).isOne();
        assertThat(downloadGrantRepository.deleteByExpiresAtBefore(cutoff)).isEqualTo(2L);
        assertThat(downloadGrantRepository.findAll()).extracting(TransferAttachmentDownloadGrant::getId)
                .containsExactlyInAnyOrder(12L, 13L);
    }

    private long storageUsedAt(String now) {
        ObjectStorageProperties properties = new ObjectStorageProperties();
        properties.setPerUserStorageQuotaBytes(1000);
        TransferAttachmentService service = new TransferAttachmentService(repository, downloadGrantRepository,
                downloadUsageRepository, new AliyunOssObjectStorageService(properties), properties,
                new PublicTransferProperties(), clientAccountService, publicTransferRoomService,
                Clock.fixed(Instant.parse(now), ZoneOffset.UTC));
        return service.capabilities(new ManagementContext(new TenantContext("t1"), "alice", false))
                .storageUsedBytes();
    }

    private void attachment(Rows rows, long id, String status, long sizeBytes,
                            String uploadExpiresAt, String expiresAt) {
        TransferAttachment attachment = new TransferAttachment();
        attachment.setId(id);
        attachment.setTenantId("t1");
        attachment.setOwnerUsername("alice");
        attachment.setScope(TransferAttachmentService.SCOPE_PUBLIC_TRANSFER);
        attachment.setObjectKey("ordering/" + id);
        attachment.setFileName("ordering.bin");
        attachment.setMimeType("application/octet-stream");
        attachment.setSizeBytes(sizeBytes);
        attachment.setStatus(status);
        attachment.setCreatedAt(LONG_AGO);
        attachment.setUpdatedAt(LONG_AGO);
        attachment.setUploadExpiresAt(stored(rows, uploadExpiresAt));
        attachment.setExpiresAt(stored(rows, expiresAt));
        repository.saveAndFlush(attachment);
    }

    private void grant(Rows rows, long id, String expiresAt) {
        TransferAttachmentDownloadGrant grant = new TransferAttachmentDownloadGrant();
        grant.setId(id);
        grant.setTokenHash(token(id));
        grant.setTenantId("t1");
        grant.setUsername("alice");
        grant.setAttachmentId(1L);
        grant.setCreatedAt(LONG_AGO);
        grant.setExpiresAt(stored(rows, expiresAt));
        downloadGrantRepository.saveAndFlush(grant);
    }

    private static String stored(Rows rows, String instant) {
        return rows == Rows.WRITTEN ? SortableInstant.normalize(instant) : Instant.parse(instant).toString();
    }

    private static String token(long id) {
        return "%064d".formatted(id);
    }

    /** Legacy rows go through the startup migrator; afterwards every expiry has the fixed width. */
    private void settle(Rows rows) {
        if (rows == Rows.LEGACY_MIGRATED) {
            migrator.migrate();
            entityManager.clear();
        }
        assertThat(jdbcTemplate.queryForObject("""
                select count(*) from transfer_attachment
                 where length(upload_expires_at) <> ? or length(expires_at) <> ?
                """, Long.class, SortableInstant.LENGTH, SortableInstant.LENGTH)).isZero();
        assertThat(jdbcTemplate.queryForObject(
                "select count(*) from transfer_attachment_download_grant where length(expires_at) <> ?",
                Long.class, SortableInstant.LENGTH)).isZero();
    }
}
