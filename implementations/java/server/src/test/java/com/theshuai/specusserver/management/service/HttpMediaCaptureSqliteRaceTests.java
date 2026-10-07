package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.MediaCaptureProperties;
import com.theshuai.specusserver.management.model.HttpMediaCapture;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.specusserver.management.repository.HttpMediaReferenceRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.specusserver.management.service.HttpRouteService.RouteMutation;
import com.theshuai.specusserver.management.storage.media.RustFsMediaStorage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static com.theshuai.specusserver.database.SqliteConstraintTestSupport.createMediaDeduplicationIndex;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Two captures of the same range racing on a real SQLite database: the one whose insert hits the
 * deduplication index must give way to the one already stored. Shares the context of
 * {@code SqliteConstraintTranslationTests}.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-sqlite-constraint-translation?mode=memory&cache=shared",
                "spring.jpa.hibernate.ddl-auto=update",
                "specus.netty.port=0"
        }
)
class HttpMediaCaptureSqliteRaceTests {
    private static final String CLIENT = "MediaRaceClient";

    @Autowired private ClientAccountService clientAccountService;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private HttpRouteService httpRouteService;
    @Autowired private HttpRouteMappingRepository routeRepository;
    @Autowired private HttpMediaCaptureRepository captureRepository;
    @Autowired private HttpMediaReferenceRepository referenceRepository;
    @Autowired private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        createMediaDeduplicationIndex(jdbcTemplate);
        clearRows();
        clientAccountService.createClient(new ClientMutation(CLIENT, true, 0));
        long clientId = clientAccountRepository.findByClientName(CLIENT).orElseThrow().getId();
        httpRouteService.createRoute(clientId,
                new RouteMutation("video", "http://127.0.0.1:8096", true, false, true, false));
    }

    @AfterEach
    void clearRows() {
        captureRepository.deleteAll();
        routeRepository.deleteAll();
        clientAccountRepository.deleteAll();
    }

    @Test
    void aCaptureThatLosesTheInsertRaceBecomesANoOp() {
        AtomicReference<HttpMediaCapture> winner = new AtomicReference<>();
        HttpMediaCaptureService service = new HttpMediaCaptureService(
                new MediaCaptureProperties(),
                readyStorage(),
                clientAccountService,
                clientAccountRepository,
                routeRepository,
                racedBy(winner),
                referenceRepository);
        try {
            HttpMediaCaptureService.CaptureSession session = service.open(
                    CLIENT,
                    "video",
                    "GET",
                    "/movie.mp4",
                    206,
                    List.of(
                            "Content-Type:video/mp4",
                            "Content-Range:bytes 0-36/100"));

            assertThat(winner.get()).as("the concurrent capture was stored first").isNotNull();
            assertThat(session.active()).isFalse();
            assertThat(session.externalized()).isTrue();
            assertThat(captureRepository.findAll())
                    .singleElement()
                    .extracting(HttpMediaCapture::getId)
                    .isEqualTo(winner.get().getId());
        } finally {
            service.shutdown();
        }
    }

    /**
     * The real repository, except that the first insert is preceded by the same capture stored and
     * committed by a concurrent request, after the duplicate check has found nothing.
     */
    private HttpMediaCaptureRepository racedBy(AtomicReference<HttpMediaCapture> winner) {
        return (HttpMediaCaptureRepository) Proxy.newProxyInstance(
                getClass().getClassLoader(),
                new Class<?>[]{HttpMediaCaptureRepository.class},
                (proxy, method, arguments) -> {
                    if (method.getName().equals("saveAndFlush")
                            && arguments[0] instanceof HttpMediaCapture capture
                            && capture.getId() == null
                            && winner.get() == null) {
                        HttpMediaCapture concurrent = new HttpMediaCapture();
                        BeanUtils.copyProperties(capture, concurrent);
                        winner.set(captureRepository.saveAndFlush(concurrent));
                    }
                    try {
                        return method.invoke(captureRepository, arguments);
                    } catch (InvocationTargetException failure) {
                        throw failure.getCause();
                    }
                });
    }

    private static RustFsMediaStorage readyStorage() {
        return new RustFsMediaStorage(new MediaCaptureProperties()) {
            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public MultipartUpload beginMultipart(String objectKey, String contentType, String contentEncoding) {
                throw new AssertionError("only the capture that wins the race uploads");
            }
        };
    }
}
