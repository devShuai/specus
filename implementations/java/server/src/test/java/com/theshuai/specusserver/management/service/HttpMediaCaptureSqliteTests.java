package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.MediaCaptureProperties;
import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpMediaCapture;
import com.theshuai.specusserver.management.model.HttpMediaCaptureView;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.specusserver.management.repository.HttpMediaReferenceRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.HttpMediaCaptureService.CaptureSession;
import com.theshuai.specusserver.management.storage.media.RustFsMediaStorage;
import com.theshuai.specusserver.management.storage.media.RustFsMediaStorage.MultipartUpload;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import software.amazon.awssdk.services.s3.model.CompletedPart;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A media capture's whole life on the SQLite schema Hibernate creates: the capture is stored and
 * completed under the id Hibernate reports, then listed, opened for playback, reused for the same
 * range and removed once expired. Only the object storage is a mock.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false"
})
class HttpMediaCaptureSqliteTests {
    private static final String TENANT = "tenant-a";
    private static final String LONG_AGO = "2026-01-01T00:00:00Z";

    @Autowired
    private HttpMediaCaptureRepository captureRepository;

    @Autowired
    private HttpMediaReferenceRepository referenceRepository;

    @Autowired
    private ClientAccountRepository clientAccountRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private final RustFsMediaStorage storage = mock(RustFsMediaStorage.class);
    private HttpMediaCaptureService service;

    @BeforeEach
    void setUp() {
        MediaCaptureProperties properties = new MediaCaptureProperties();
        properties.setEnabled(true);
        properties.setUploadThreads(1);
        properties.setMaxInflightParts(1);

        ClientAccount account = new ClientAccount();
        account.setId(7L);
        account.setTenantId(TENANT);
        account.setClientName("client-a");
        ClientAccountService accountService = mock(ClientAccountService.class);
        when(accountService.findClientByName("client-a")).thenReturn(Optional.of(account));
        HttpRouteMapping route = new HttpRouteMapping();
        route.setId(11L);
        route.setMediaCaptureEnabled(true);
        HttpRouteMappingRepository routeRepository = mock(HttpRouteMappingRepository.class);
        when(routeRepository.findByTenantIdAndClientIdAndRoute(TENANT, 7L, "video")).thenReturn(Optional.of(route));

        when(storage.isReady()).thenReturn(true);
        when(storage.beginMultipart(any(), any(), any())).thenAnswer(invocation ->
                new MultipartUpload(invocation.getArgument(0), "upload-1"));
        when(storage.uploadPart(any(MultipartUpload.class), anyInt(), any(byte[].class)))
                .thenAnswer(invocation -> CompletedPart.builder()
                        .partNumber(invocation.getArgument(1))
                        .eTag("etag-" + invocation.getArgument(1))
                        .build());
        when(storage.completeMultipart(any(MultipartUpload.class), any())).thenReturn("object-etag");

        service = new HttpMediaCaptureService(properties, storage, accountService, clientAccountRepository,
                routeRepository, captureRepository, referenceRepository);
    }

    @AfterEach
    void tearDown() {
        service.shutdown();
        captureRepository.deleteAll();
    }

    @Test
    void capturesListsPlaysBackReusesAndExpiresAMediaFile() {
        CaptureSession session = open();
        assertThat(session.active()).isTrue();
        session.append(new byte[10]);
        session.complete();

        HttpMediaCapture capture = await().atMost(Duration.ofSeconds(5)).until(
                () -> captureRepository.findAll().stream().findFirst()
                        .filter(row -> HttpMediaCaptureService.STATE_COMPLETE.equals(row.getState()))
                        .orElse(null),
                row -> row != null);
        assertThat(jdbcTemplate.queryForList("select id from specus_http_media_capture", Long.class))
                .containsExactly(capture.getId());

        ManagementContext admin = new ManagementContext(new TenantContext(TENANT), "admin", true);
        assertThat(service.list(admin, null, null, PageRequest.of(0, 10)).getContent())
                .extracting(HttpMediaCaptureView::id, HttpMediaCaptureView::state, HttpMediaCaptureView::playable)
                .containsExactly(tuple(capture.getId(), HttpMediaCaptureService.STATE_COMPLETE, true));
        assertThat(service.requireAccessible(admin, capture.getId()).getObjectKey())
                .isEqualTo(capture.getObjectKey());

        // The same range again is served without a second capture.
        CaptureSession repeat = open();
        assertThat(repeat.active()).isFalse();
        assertThat(repeat.externalized()).isTrue();
        assertThat(captureRepository.count()).isOne();

        jdbcTemplate.update("update specus_http_media_capture set captured_at = ?, expires_at = ?", LONG_AGO, LONG_AGO);
        service.cleanupExpired();

        verify(storage).delete(capture.getObjectKey());
        assertThat(captureRepository.count()).isZero();
    }

    private CaptureSession open() {
        return service.open("client-a", "video", "GET", "/movie.mp4", 200,
                List.of("Content-Type:video/mp4", "Content-Length:10"));
    }
}
