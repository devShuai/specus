package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.MediaCaptureProperties;
import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.model.HttpMediaCapture;
import com.theshuai.tunnelserver.management.model.HttpRouteMapping;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.tunnelserver.management.repository.HttpMediaReferenceRepository;
import com.theshuai.tunnelserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.tunnelserver.management.storage.media.RustFsMediaStorage;
import com.theshuai.tunnelserver.management.storage.media.RustFsMediaStorage.MultipartUpload;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.s3.model.CompletedPart;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class HttpMediaCaptureServiceTests {
    private static final int PART_SIZE = 5 * 1024 * 1024;

    @Test
    void acceptsStreamingMediaWithoutContentLength() {
        ServiceFixture fixture = new ServiceFixture();
        try {
            HttpMediaCaptureService.CaptureSession session = fixture.service.open(
                    "client-a",
                    "video",
                    "GET",
                    "/live.webm",
                    200,
                    List.of("Content-Type:video/webm"));

            assertThat(session.active()).isTrue();
            session.append(new byte[37]);
            session.complete();

            verify(fixture.storage, timeout(5_000))
                    .completeMultipart(any(MultipartUpload.class), any());
            verify(fixture.captureRepository, timeout(5_000).atLeastOnce())
                    .save(any(HttpMediaCapture.class));
            assertThat(fixture.persisted[0].getState())
                    .isEqualTo(HttpMediaCaptureService.STATE_COMPLETE);
            assertThat(fixture.persisted[0].getCapturedBytes()).isEqualTo(37);
            assertThat(fixture.persisted[0].getTotalBytes()).isEqualTo(37);
        } finally {
            fixture.service.shutdown();
        }
    }

    @Test
    void streamsLargeMediaResponseAsRustFsMultipartUpload() {
        ServiceFixture fixture = new ServiceFixture();
        try {
            int totalBytes = PART_SIZE + 37;
            HttpMediaCaptureService.CaptureSession session = fixture.service.open(
                    "client-a",
                    "video",
                    "GET",
                    "/movie.mp4",
                    200,
                    List.of(
                            "Content-Type:video/mp4",
                            "Content-Length:" + totalBytes));

            assertThat(session.active()).isTrue();
            session.append(new byte[totalBytes]);
            session.complete();

            ArgumentCaptor<byte[]> partBytes = ArgumentCaptor.forClass(byte[].class);
            verify(fixture.storage, timeout(5_000).times(2))
                    .uploadPart(any(MultipartUpload.class), anyInt(), partBytes.capture());
            assertThat(partBytes.getAllValues())
                    .extracting(bytes -> bytes.length)
                    .containsExactlyInAnyOrder(PART_SIZE, 37);
            verify(fixture.storage, timeout(5_000))
                    .completeMultipart(any(MultipartUpload.class), any());
            verify(fixture.captureRepository, timeout(5_000).atLeastOnce())
                    .save(any(HttpMediaCapture.class));

            assertThat(fixture.persisted[0].getState()).isEqualTo(HttpMediaCaptureService.STATE_COMPLETE);
            assertThat(fixture.persisted[0].getCapturedBytes()).isEqualTo(totalBytes);
            assertThat(fixture.persisted[0].getObjectEtag()).isEqualTo("complete-etag");
        } finally {
            fixture.service.shutdown();
        }

        verify(fixture.captureRepository, atLeastOnce()).saveAndFlush(any(HttpMediaCapture.class));
    }

    @Test
    void retainsReceivedRangeWhenPlayerCancelsRequest() {
        ServiceFixture fixture = new ServiceFixture();
        try {
            HttpMediaCaptureService.CaptureSession session = fixture.service.open(
                    "client-a",
                    "video",
                    "GET",
                    "/movie.mp4",
                    206,
                    List.of(
                            "Content-Type:video/mp4",
                            "Content-Range:bytes 1024-2047/4096"));

            session.append(new byte[37]);
            session.fail("Broken pipe");

            verify(fixture.storage, timeout(5_000))
                    .completeMultipart(any(MultipartUpload.class), any());
            verify(fixture.captureRepository, timeout(5_000).atLeastOnce())
                    .save(any(HttpMediaCapture.class));

            assertThat(fixture.persisted[0].getState())
                    .isEqualTo(HttpMediaCaptureService.STATE_COMPLETE);
            assertThat(fixture.persisted[0].getCapturedBytes()).isEqualTo(37);
            assertThat(fixture.persisted[0].getContentRangeStart()).isEqualTo(1024);
            assertThat(fixture.persisted[0].getContentRangeEnd()).isEqualTo(1060);
            assertThat(fixture.persisted[0].getTotalBytes()).isEqualTo(4096);
        } finally {
            fixture.service.shutdown();
        }
    }

    @Test
    void redactsAuthenticationTokensFromSourceUrlView() {
        String redacted = HttpMediaCaptureService.redactSourceUrl(
                "/Videos/movie/stream.mp4?deviceId=device-a&ApiKey=secret-value&Tag=etag");

        assertThat(redacted)
                .isEqualTo("/Videos/movie/stream.mp4?deviceId=device-a&ApiKey=***&Tag=etag");
    }

    private static final class ServiceFixture {
        MediaCaptureProperties properties = new MediaCaptureProperties();
        RustFsMediaStorage storage = mock(RustFsMediaStorage.class);
        ClientAccountService accountService = mock(ClientAccountService.class);
        ClientAccountRepository accountRepository = mock(ClientAccountRepository.class);
        HttpRouteMappingRepository routeRepository = mock(HttpRouteMappingRepository.class);
        HttpMediaCaptureRepository captureRepository = mock(HttpMediaCaptureRepository.class);
        HttpMediaReferenceRepository referenceRepository = mock(HttpMediaReferenceRepository.class);
        HttpMediaCapture[] persisted = new HttpMediaCapture[1];
        HttpMediaCaptureService service;

        private ServiceFixture() {
            properties.setPartSizeBytes(PART_SIZE);
            properties.setMaxInflightParts(1);
            properties.setUploadThreads(1);

            ClientAccount account = new ClientAccount();
            account.setId(7L);
            account.setTenantId("tenant-a");
            account.setClientName("client-a");
            HttpRouteMapping route = new HttpRouteMapping();
            route.setId(11L);
            route.setMediaCaptureEnabled(true);

            when(storage.isReady()).thenReturn(true);
            when(accountService.findClientByName("client-a")).thenReturn(Optional.of(account));
            when(routeRepository.findByTenantIdAndClientIdAndRoute("tenant-a", 7L, "video"))
                    .thenReturn(Optional.of(route));
            when(captureRepository.saveAndFlush(any(HttpMediaCapture.class))).thenAnswer(invocation -> {
                HttpMediaCapture capture = invocation.getArgument(0);
                if (capture.getId() == null) {
                    capture.setId(101L);
                }
                persisted[0] = capture;
                return capture;
            });
            when(captureRepository.findById(101L))
                    .thenAnswer(ignored -> Optional.ofNullable(persisted[0]));
            when(storage.beginMultipart(any(), any(), eq(null))).thenAnswer(invocation ->
                    new MultipartUpload(invocation.getArgument(0), "upload-1"));
            when(storage.uploadPart(any(MultipartUpload.class), anyInt(), any(byte[].class)))
                    .thenAnswer(invocation -> CompletedPart.builder()
                            .partNumber(invocation.getArgument(1))
                            .eTag("etag-" + invocation.getArgument(1))
                            .build());
            when(storage.completeMultipart(any(MultipartUpload.class), any()))
                    .thenReturn("complete-etag");

            service = new HttpMediaCaptureService(
                    properties,
                    storage,
                    accountService,
                    accountRepository,
                    routeRepository,
                    captureRepository,
                    referenceRepository);
        }
    }
}
