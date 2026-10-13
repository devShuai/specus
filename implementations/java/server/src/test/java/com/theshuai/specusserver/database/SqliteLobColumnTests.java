package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import com.theshuai.specusserver.management.model.TcpTrafficFrame;
import com.theshuai.specusserver.management.model.TcpTrafficFrameView;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.specusserver.management.repository.TcpTrafficFrameRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.management.service.ClientAccountService.ClientMutation;
import com.theshuai.specusserver.management.service.HttpRouteService;
import com.theshuai.specusserver.management.service.HttpRouteService.RouteMutation;
import com.theshuai.specusserver.management.service.PublicTransferRoomService;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreateDiagramVersionRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.DiagramVersionView;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RoomCredential;
import com.theshuai.specusserver.management.service.TrafficInspectionService;
import com.theshuai.specusserver.management.service.TrafficViewService;
import com.theshuai.specusserver.management.storage.HttpTrafficExchangeStore;
import com.theshuai.specusserver.management.storage.HttpTrafficSearchField;
import com.theshuai.specusserver.management.storage.TcpTrafficFrameStore;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Reads back every {@code @Lob byte[]} column on a fresh SQLite database through the paths that serve
 * it. sqlite-jdbc does not implement {@code ResultSet.getBlob}, not even for a null value, so loading
 * any such entity failed with "not implemented by SQLite JDBC driver". The dialect is the one
 * {@code application.yml} names.
 */
@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-sqlite-lob-columns?mode=memory&cache=shared",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false",
                "specus.traffic.capture-detail-enabled=true"
        }
)
class SqliteLobColumnTests {
    private static final String CLIENT = "LobClient";
    // A PNG signature and IHDR start: NUL bytes and bytes that are not UTF-8.
    private static final byte[] PNG = {
            (byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n', 0, 0, 0, 0x0d, 'I', 'H', 'D', 'R', (byte) 0xff, 0};

    @Autowired private ClientAccountService clientAccountService;
    @Autowired private ClientAccountRepository clientAccountRepository;
    @Autowired private HttpRouteService httpRouteService;
    @Autowired private HttpRouteMappingRepository routeRepository;
    @Autowired private TrafficInspectionService trafficInspectionService;
    @Autowired private TrafficViewService trafficViewService;
    @Autowired private HttpTrafficExchangeStore httpTrafficExchangeStore;
    @Autowired private HttpTrafficExchangeRepository httpTrafficExchangeRepository;
    @Autowired private TcpTrafficFrameStore tcpTrafficFrameStore;
    @Autowired private TcpTrafficFrameRepository tcpTrafficFrameRepository;
    @Autowired private PublicTransferRoomService publicTransferRoomService;
    @Autowired private JdbcTemplate jdbcTemplate;

    private long clientId;

    @BeforeEach
    void setUp() {
        clearRows();
        clientAccountService.createClient(new ClientMutation(CLIENT, true, 0));
        clientId = clientAccountRepository.findByClientName(CLIENT).orElseThrow().getId();
        httpRouteService.createRoute(clientId,
                new RouteMutation("api", "http://127.0.0.1:8080", true, true, false, false));
    }

    @AfterEach
    void clearRows() {
        httpTrafficExchangeRepository.deleteAllInBatch();
        tcpTrafficFrameRepository.deleteAllInBatch();
        routeRepository.deleteAll();
        clientAccountRepository.deleteAll();
    }

    @Test
    void theLobColumnsKeepTheirSqliteTypes() {
        assertThat(columnType("specus_http_traffic_exchange", "request_body_data")).isEqualTo("blob");
        assertThat(columnType("specus_http_traffic_exchange", "response_body_data")).isEqualTo("blob");
        // No longer a @Lob: a string column like the headers, of the same TEXT affinity as clob.
        assertThat(columnType("specus_http_traffic_exchange", "request_preview_text")).isEqualTo("varchar(2147483647)");
        assertThat(columnType("specus_tcp_traffic_frame", "payload_data")).isEqualTo("blob");
        assertThat(columnType("public_transfer_diagram_version", "snapshot_data")).isEqualTo("blob");
        assertThat(columnType("specus_websocket_ticket", "attributes_json")).isEqualTo("clob");
    }

    @Test
    void httpExchangeDetailShowsTheCapturedBodies() {
        byte[] requestBody = "{\"order\":42}".getBytes(StandardCharsets.UTF_8);
        trafficInspectionService.recordHttpExchange(
                CLIENT,
                "api",
                "POST",
                "/thumbnails",
                null,
                List.of("Content-Type: application/json"),
                requestBody,
                200,
                List.of("Content-Type: image/png"),
                PNG,
                System.currentTimeMillis(),
                "127.0.0.1:60000",
                null);
        trafficInspectionService.flushHttp();

        HttpTrafficExchangeView detail = trafficViewService.getHttpExchange(
                TenantContext.defaultTenant(), onlyExchangeId()).orElseThrow();

        assertThat(detail.requestPreviewText()).isEqualTo("{\"order\":42}");
        assertThat(detail.responsePreviewText())
                .isEqualTo("data:image/png;base64," + Base64.getEncoder().encodeToString(PNG));
    }

    @Test
    void httpExchangeDetailLoadsARowWithoutBodies() {
        // Rows stored before the body columns existed have null there.
        HttpTrafficExchange exchange = exchange();
        exchange.setRequestPreviewText("request preview");
        exchange.setResponsePreviewText("response preview");
        httpTrafficExchangeStore.saveAll(List.of(exchange));

        HttpTrafficExchangeView detail = trafficViewService.getHttpExchange(
                TenantContext.defaultTenant(), onlyExchangeId()).orElseThrow();

        assertThat(detail.requestPreviewText()).isEqualTo("request preview");
        assertThat(detail.responsePreviewText()).isEqualTo("response preview");
    }

    @Test
    void tcpFrameListAndDetailLoadThePayload() {
        TcpTrafficFrame frame = new TcpTrafficFrame();
        frame.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        frame.setClientId(clientId);
        frame.setClientName(CLIENT);
        frame.setListenPort(15432);
        frame.setResourceName("postgres");
        frame.setChannelId("channel-1");
        frame.setDirection("client_to_server");
        frame.setPayloadBytes(PNG.length);
        frame.setPayloadData(PNG);
        frame.setFrameTime(Instant.now().toString());
        tcpTrafficFrameStore.saveAll(List.of(frame));

        List<TcpTrafficFrameView> frames = trafficViewService.listTcpFrames(
                TenantContext.defaultTenant(), null, null, PageRequest.of(0, 20)).getContent();
        assertThat(frames).hasSize(1);
        TcpTrafficFrameView detail = trafficViewService.getTcpFrame(
                TenantContext.defaultTenant(), Long.parseLong(frames.getFirst().id())).orElseThrow();

        assertThat(detail.payloadBase64()).isEqualTo(Base64.getEncoder().encodeToString(PNG));
    }

    @Test
    void diagramVersionsListAndDetailLoadTheSnapshot() {
        String room = "lob-room";
        RoomCredential owner = new RoomCredential(room, "lob-owner-token", "web-owner");
        String first = Base64.getEncoder().encodeToString(PNG);
        String second = Base64.getEncoder().encodeToString("second".getBytes(StandardCharsets.UTF_8));

        publicTransferRoomService.createVersion(room, versionRequest(owner, "first", first));
        // Creating a version reads the room's versions back to prune them.
        DiagramVersionView created = publicTransferRoomService.createVersion(room, versionRequest(owner, "second", second));

        assertThat(publicTransferRoomService.listVersions(room, owner))
                .extracting(DiagramVersionView::name)
                .containsExactlyInAnyOrder("first", "second");
        assertThat(publicTransferRoomService.getVersion(room, created.id(), owner).update()).isEqualTo(second);
    }

    private long onlyExchangeId() {
        List<HttpTrafficExchangeView> exchanges = trafficViewService.listHttpExchanges(
                TenantContext.defaultTenant(), null, null, null, HttpTrafficSearchField.SUMMARY, null,
                PageRequest.of(0, 20)).getContent();
        assertThat(exchanges).hasSize(1);
        return Long.parseLong(exchanges.getFirst().id());
    }

    private HttpTrafficExchange exchange() {
        HttpTrafficExchange exchange = new HttpTrafficExchange();
        exchange.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        exchange.setClientId(clientId);
        exchange.setClientName(CLIENT);
        exchange.setRoute("api");
        exchange.setResourceName("api -> http://127.0.0.1:8080");
        exchange.setMethod("GET");
        exchange.setRelativePath("/legacy");
        exchange.setStatusCode(200);
        exchange.setSuccess(true);
        exchange.setCapturedAt(Instant.now().toString());
        return exchange;
    }

    private static CreateDiagramVersionRequest versionRequest(RoomCredential credential, String name, String update) {
        return new CreateDiagramVersionRequest(
                credential.roomId(), credential.roomToken(), credential.peerId(), name, update);
    }

    private String columnType(String table, String column) {
        return jdbcTemplate.queryForObject(
                "select lower(type) from pragma_table_info(?) where name = ?", String.class, table, column);
    }
}
