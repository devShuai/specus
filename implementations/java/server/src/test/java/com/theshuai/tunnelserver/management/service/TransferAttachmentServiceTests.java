package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.ObjectStorageProperties;
import com.theshuai.tunnelserver.config.PublicTransferProperties;
import com.theshuai.tunnelserver.management.model.TransferAttachment;
import com.theshuai.tunnelserver.management.repository.TransferAttachmentRepository;
import com.theshuai.tunnelserver.management.storage.object.ObjectStorageService;
import com.theshuai.tunnelserver.management.storage.object.PresignedObjectUrl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TransferAttachmentServiceTests {

    private static final String ROOM_TOKEN = "room-token";
    private static final String SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Mock private TransferAttachmentRepository repository;
    @Mock private ObjectStorageService objectStorageService;
    @Mock private ClientAccountService clientAccountService;

    private final ObjectStorageProperties storageProperties = new ObjectStorageProperties();
    private final PublicTransferProperties publicTransferProperties = new PublicTransferProperties();
    private TransferAttachmentService service;

    @BeforeEach
    void setUp() {
        storageProperties.setUploadUrlTtlSeconds(900);
        storageProperties.setDownloadUrlTtlSeconds(600);
        storageProperties.setRetentionHours(72);
        storageProperties.setMaxAttachmentBytes(1024);
        publicTransferProperties.setMaxPendingUploadsPerRoom(2);
        service = new TransferAttachmentService(
                repository,
                objectStorageService,
                storageProperties,
                publicTransferProperties,
                clientAccountService
        );
    }

    @Test
    void createPublicUploadRejectsWhenRoomPendingQuotaIsFull() {
        when(repository.countByScopeAndRoomTokenHashAndStatus(
                eq(TransferAttachmentService.SCOPE_PUBLIC_TRANSFER),
                any(),
                eq(TransferAttachmentService.STATUS_PENDING)
        )).thenReturn(2L);

        assertThatThrownBy(() -> service.createPublicUpload(publicRequest(10)))
                .isInstanceOf(RateLimitedException.class)
                .hasMessageContaining("待上传文件过多");

        verifyNoInteractions(objectStorageService);
    }

    @Test
    void createPublicUploadNormalizesMetadataAndPresignsClientPut() {
        mockEnabledStorage();
        when(repository.countByScopeAndRoomTokenHashAndStatus(any(), any(), any())).thenReturn(0L);
        when(repository.existsById(anyLong())).thenReturn(false);
        when(repository.saveAndFlush(any(TransferAttachment.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(objectStorageService.presignUpload(any(), eq("text/plain"), any()))
                .thenReturn(new PresignedObjectUrl("https://oss/upload", Map.of("Content-Type", "text/plain"), Instant.now().plusSeconds(900).toString()));

        TransferAttachmentService.PresignUploadResponse response = service.createPublicUpload(new TransferAttachmentService.PresignUploadRequest(
                "../hello.txt",
                "text/plain",
                10L,
                SHA256.toUpperCase(),
                " room-a ",
                ROOM_TOKEN,
                null
        ));

        ArgumentCaptor<TransferAttachment> captor = ArgumentCaptor.forClass(TransferAttachment.class);
        verify(repository).saveAndFlush(captor.capture());
        TransferAttachment saved = captor.getValue();
        assertThat(saved.getFileName()).isEqualTo("hello.txt");
        assertThat(saved.getRoomId()).isEqualTo("room-a");
        assertThat(saved.getSha256()).isEqualTo(SHA256);
        assertThat(saved.getStatus()).isEqualTo(TransferAttachmentService.STATUS_PENDING);
        assertThat(saved.getObjectKey()).contains("/public-transfer/").endsWith("/hello.txt");
        assertThat(response.uploadUrl()).isEqualTo("https://oss/upload");
        assertThat(response.attachment().sha256()).isEqualTo(SHA256);
    }

    @Test
    void fileNameNormalizationUsesUnicodeCodePointsAndSafeLengthBoundaries() {
        mockEnabledStorage();
        when(repository.countByScopeAndRoomTokenHashAndStatus(any(), any(), any())).thenReturn(0L);
        when(repository.existsById(anyLong())).thenReturn(false);
        when(repository.saveAndFlush(any(TransferAttachment.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(objectStorageService.presignUpload(any(), any(), any()))
                .thenReturn(new PresignedObjectUrl("https://oss/upload", Map.of(), Instant.now().plusSeconds(900).toString()));

        Map<String, String> cases = Map.ofEntries(
                Map.entry("mixed/path\\photo😀  中文.png", "photo_.png"),
                Map.entry("😀😀.txt", "_.txt"),
                Map.entry("folder/", "attachment"),
                Map.entry("folder\\", "attachment"),
                Map.entry("folder/...", "attachment"),
                Map.entry("archive..tar...gz", "archive.tar.gz"),
                Map.entry(".env", ".env"),
                Map.entry("file.", "file."),
                Map.entry("   ", "_"),
                Map.entry("  photo .png  ", "_photo_.png_")
        );
        cases.forEach((input, expected) -> {
            var response = service.createPublicUpload(new TransferAttachmentService.PresignUploadRequest(
                    input, "application/octet-stream", 10L, null, "room-a", ROOM_TOKEN, null));
            assertThat(response.attachment().fileName()).as("input %s", input).isEqualTo(expected);
            assertThat(response.objectKey()).doesNotContain("..").endsWith("/" + expected);
        });

        String shortExtension = "." + "b".repeat(178);
        Map<String, String> longCases = Map.of(
                "a".repeat(200) + ".txt", "a".repeat(176) + ".txt",
                "abcdefghij" + shortExtension, "a" + shortExtension,
                "a." + "b".repeat(180), "a." + "b".repeat(178),
                "x".repeat(181), "x".repeat(180)
        );
        longCases.forEach((input, expected) -> {
            var response = service.createPublicUpload(new TransferAttachmentService.PresignUploadRequest(
                    input, "application/octet-stream", 10L, null, "room-a", ROOM_TOKEN, null));
            assertThat(response.attachment().fileName()).as("long input").isEqualTo(expected).hasSize(180);
        });
    }

    @Test
    void createPublicUploadRetriesWhenSaveHitsIdCollision() {
        mockEnabledStorage();
        when(repository.countByScopeAndRoomTokenHashAndStatus(any(), any(), any())).thenReturn(0L);
        when(repository.existsById(anyLong())).thenReturn(false);
        when(objectStorageService.presignUpload(any(), any(), any()))
                .thenReturn(new PresignedObjectUrl("https://oss/first", Map.of(), Instant.now().plusSeconds(900).toString()))
                .thenReturn(new PresignedObjectUrl("https://oss/second", Map.of(), Instant.now().plusSeconds(900).toString()));
        when(repository.saveAndFlush(any(TransferAttachment.class)))
                .thenThrow(new DataIntegrityViolationException("duplicate id"))
                .thenAnswer(invocation -> invocation.getArgument(0));

        TransferAttachmentService.PresignUploadResponse response = service.createPublicUpload(publicRequest(10));

        verify(repository, times(2)).saveAndFlush(any(TransferAttachment.class));
        verify(objectStorageService, atLeastOnce()).presignUpload(any(), any(), any());
        assertThat(response.uploadUrl()).isEqualTo("https://oss/second");
    }

    @Test
    void createDownloadRejectsPendingAttachment() {
        TransferAttachment attachment = uploadedFixture(123L);
        attachment.setStatus(TransferAttachmentService.STATUS_PENDING);
        when(repository.findByIdAndScope(123L, TransferAttachmentService.SCOPE_PUBLIC_TRANSFER))
                .thenReturn(Optional.of(attachment));

        assertThatThrownBy(() -> service.createPublicDownload(123L, new TransferAttachmentService.PresignDownloadRequest(ROOM_TOKEN)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("not uploaded");

        verifyNoInteractions(objectStorageService);
    }

    @Test
    void completeRejectsMissingUploadedObject() {
        mockEnabledStorage();
        TransferAttachment attachment = pendingFixture(123L, 10);
        when(repository.findByIdAndScope(123L, TransferAttachmentService.SCOPE_PUBLIC_TRANSFER))
                .thenReturn(Optional.of(attachment));
        when(objectStorageService.statObject("object/key.txt"))
                .thenReturn(new ObjectStorageService.ObjectStat(false, -1));

        assertThatThrownBy(() -> service.completePublic(123L, new TransferAttachmentService.CompleteAttachmentRequest(ROOM_TOKEN)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("was not uploaded");

        assertThat(attachment.getStatus()).isEqualTo(TransferAttachmentService.STATUS_PENDING);
    }

    @Test
    void completeDeletesOversizedObjectAndRejects() {
        mockEnabledStorage();
        storageProperties.setMaxAttachmentBytes(10);
        TransferAttachment attachment = pendingFixture(123L, 8);
        when(repository.findByIdAndScope(123L, TransferAttachmentService.SCOPE_PUBLIC_TRANSFER))
                .thenReturn(Optional.of(attachment));
        when(objectStorageService.statObject("object/key.txt"))
                .thenReturn(new ObjectStorageService.ObjectStat(true, 11));

        assertThatThrownBy(() -> service.completePublic(123L, new TransferAttachmentService.CompleteAttachmentRequest(ROOM_TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("too large");

        verify(objectStorageService).deleteObject("object/key.txt");
        assertThat(attachment.getStatus()).isEqualTo(TransferAttachmentService.STATUS_PENDING);
    }

    @Test
    void completeStoresActualObjectSizeAndMarksUploaded() {
        mockEnabledStorage();
        TransferAttachment attachment = pendingFixture(123L, 8);
        when(repository.findByIdAndScope(123L, TransferAttachmentService.SCOPE_PUBLIC_TRANSFER))
                .thenReturn(Optional.of(attachment));
        when(objectStorageService.statObject("object/key.txt"))
                .thenReturn(new ObjectStorageService.ObjectStat(true, 9));
        when(repository.save(any(TransferAttachment.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var view = service.completePublic(123L, new TransferAttachmentService.CompleteAttachmentRequest(ROOM_TOKEN));

        assertThat(view.sizeBytes()).isEqualTo(9);
        assertThat(view.status()).isEqualTo(TransferAttachmentService.STATUS_UPLOADED);
        assertThat(attachment.getUploadedAt()).isNotBlank();
    }

    @Test
    void expireOldAttachmentsLoopsUntilNoMoreExpiredRows() {
        mockEnabledStorage();
        TransferAttachment first = expiredFixture(1L, "object/1");
        TransferAttachment second = expiredFixture(2L, "object/2");
        TransferAttachment third = expiredFixture(3L, "object/3");
        when(repository.findTop100ByExpiresAtBeforeAndStatusNotOrderByExpiresAtAsc(any(), eq(TransferAttachmentService.STATUS_EXPIRED)))
                .thenReturn(List.of(first, second))
                .thenReturn(List.of(third))
                .thenReturn(List.of());
        when(repository.save(any(TransferAttachment.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.expireOldAttachments();

        assertThat(first.getStatus()).isEqualTo(TransferAttachmentService.STATUS_EXPIRED);
        assertThat(second.getStatus()).isEqualTo(TransferAttachmentService.STATUS_EXPIRED);
        assertThat(third.getStatus()).isEqualTo(TransferAttachmentService.STATUS_EXPIRED);
        verify(objectStorageService).deleteObject("object/1");
        verify(objectStorageService).deleteObject("object/2");
        verify(objectStorageService).deleteObject("object/3");
        verify(repository, times(2)).flush();
    }

    private TransferAttachmentService.PresignUploadRequest publicRequest(long sizeBytes) {
        return new TransferAttachmentService.PresignUploadRequest(
                "hello.txt",
                "text/plain",
                sizeBytes,
                null,
                "room-a",
                ROOM_TOKEN,
                null
        );
    }

    private TransferAttachment pendingFixture(long id, long sizeBytes) {
        TransferAttachment attachment = baseFixture(id);
        attachment.setStatus(TransferAttachmentService.STATUS_PENDING);
        attachment.setSizeBytes(sizeBytes);
        attachment.setUploadExpiresAt(Instant.now().plusSeconds(60).toString());
        attachment.setExpiresAt(Instant.now().plusSeconds(3600).toString());
        return attachment;
    }

    private TransferAttachment uploadedFixture(long id) {
        TransferAttachment attachment = baseFixture(id);
        attachment.setStatus(TransferAttachmentService.STATUS_UPLOADED);
        attachment.setSizeBytes(10);
        attachment.setUploadExpiresAt(Instant.now().minusSeconds(60).toString());
        attachment.setExpiresAt(Instant.now().plusSeconds(3600).toString());
        attachment.setUploadedAt(Instant.now().toString());
        return attachment;
    }

    private TransferAttachment expiredFixture(long id, String objectKey) {
        TransferAttachment attachment = baseFixture(id);
        attachment.setStatus(TransferAttachmentService.STATUS_UPLOADED);
        attachment.setObjectKey(objectKey);
        attachment.setSizeBytes(10);
        attachment.setUploadExpiresAt(Instant.now().minusSeconds(3600).toString());
        attachment.setExpiresAt(Instant.now().minusSeconds(60).toString());
        return attachment;
    }

    private TransferAttachment baseFixture(long id) {
        TransferAttachment attachment = new TransferAttachment();
        attachment.setId(id);
        attachment.setScope(TransferAttachmentService.SCOPE_PUBLIC_TRANSFER);
        attachment.setRoomId("room-a");
        attachment.setRoomTokenHash(sha256(ROOM_TOKEN));
        attachment.setObjectKey("object/key.txt");
        attachment.setFileName("hello.txt");
        attachment.setMimeType("text/plain");
        attachment.setCreatedAt(Instant.now().toString());
        attachment.setUpdatedAt(Instant.now().toString());
        return attachment;
    }

    private void mockEnabledStorage() {
        when(objectStorageService.isEnabled()).thenReturn(true);
    }

    private String sha256(String value) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(digest.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
