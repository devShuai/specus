package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.database.SortableTimestampMigrator;
import com.theshuai.specusserver.management.model.ClientAuthNonce;
import com.theshuai.specusserver.management.model.ConnectionRecord;
import com.theshuai.specusserver.management.model.ConnectionRecordView;
import com.theshuai.specusserver.management.model.HttpMediaCapture;
import com.theshuai.specusserver.management.model.HttpMediaCaptureView;
import com.theshuai.specusserver.management.model.ManagementRegistrationChallenge;
import com.theshuai.specusserver.management.model.PeerMeshSession;
import com.theshuai.specusserver.management.model.PublicTransferRoom;
import com.theshuai.specusserver.management.model.PublicTransferRoomPairingCode;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.model.WebSocketTicket;
import com.theshuai.specusserver.management.repository.ClientAuthNonceRepository;
import com.theshuai.specusserver.management.repository.ConnectionRecordRepository;
import com.theshuai.specusserver.management.repository.HttpMediaCaptureRepository;
import com.theshuai.specusserver.management.repository.ManagementRegistrationChallengeRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSessionRepository;
import com.theshuai.specusserver.management.repository.PublicTransferRoomPairingCodeRepository;
import com.theshuai.specusserver.management.repository.PublicTransferRoomRepository;
import com.theshuai.specusserver.management.repository.WebSocketTicketRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.ConnectionRecordService.ConnectionFilter;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Timestamps a fraction of a second on either side of "now" for every query outside the transfer
 * tables that compares a stored instant with another as text in SQLite. Each case stores seven
 * values under ids 1 to 7: three before now (-0.5 s, -1 ms, -1 us), one equal to it, and three
 * after it (+1 us, +0.25 s, +0.5 s), around a whole-second and a fractional now. Rows are stored
 * as the write paths store them, or in the legacy {@code Instant.toString()} form that the startup
 * migrator rewrites. Views built from those rows still carry the {@code Instant.toString()} form.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false"
})
@Transactional
class SortableTimestampOrderingTests {
    private static final String TENANT = "t1";
    private static final String LONG_AGO = "2026-09-15T11:00:00Z";
    private static final long[] OFFSET_NANOS = {
            -500_000_000L, -1_000_000L, -1_000L, 0L, 1_000L, 250_000_000L, 500_000_000L};
    private static final List<Integer> BEFORE = List.of(1, 2, 3);
    private static final List<Integer> AT_OR_AFTER = List.of(4, 5, 6, 7);
    private static final List<Integer> AFTER = List.of(5, 6, 7);

    @Autowired private ClientAuthNonceRepository nonceRepository;
    @Autowired private WebSocketTicketRepository ticketRepository;
    @Autowired private PeerMeshSessionRepository peerSessionRepository;
    @Autowired private PublicTransferRoomRepository roomRepository;
    @Autowired private PublicTransferRoomPairingCodeRepository pairingCodeRepository;
    @Autowired private ManagementRegistrationChallengeRepository challengeRepository;
    @Autowired private ConnectionRecordRepository connectionRecordRepository;
    @Autowired private ConnectionRecordService connectionRecordService;
    @Autowired private HttpMediaCaptureRepository captureRepository;
    @Autowired private HttpMediaCaptureService captureService;
    @Autowired private SortableTimestampMigrator migrator;
    @Autowired private JdbcTemplate jdbcTemplate;
    @Autowired private EntityManager entityManager;

    enum Rows {
        /** As the write paths store them. */
        WRITTEN,
        /** As servers before the fixed width stored them, then rewritten by the startup migrator. */
        LEGACY_MIGRATED
    }

    static Stream<Arguments> cases() {
        return Stream.of(Rows.values()).flatMap(rows -> Stream.of(
                Arguments.of(rows, Instant.parse("2026-09-15T12:00:00Z")),
                Arguments.of(rows, Instant.parse("2026-09-15T12:00:00.500Z"))));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void clientAuthNoncePurge(Rows rows, Instant now) {
        for (int id = 1; id <= 7; id++) {
            nonceRepository.insertIfAbsent("n" + id, "k".repeat(64), stored(rows, at(now, id)));
        }
        settle(rows, "specus_client_auth_nonce", "expires_at");

        assertThat(nonceRepository.deleteExpired(SortableInstant.format(now))).isEqualTo(BEFORE.size());
        assertThat(nonceRepository.findAll()).extracting(ClientAuthNonce::getId)
                .containsExactlyInAnyOrderElementsOf(ids("n", AT_OR_AFTER));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void webSocketTicketConsumeAndPurge(Rows rows, Instant now) {
        for (int id = 1; id <= 7; id++) {
            for (String use : List.of("consume-", "purge-")) {
                WebSocketTicket ticket = new WebSocketTicket();
                ticket.setTokenHash(use + id);
                ticket.setScope("connections");
                ticket.setAttributesJson("{}");
                ticket.setCreatedAt(LONG_AGO);
                ticket.setExpiresAt(stored(rows, at(now, id)));
                ticketRepository.saveAndFlush(ticket);
            }
        }
        settle(rows, "specus_websocket_ticket", "expires_at");
        String cutoff = SortableInstant.format(now);

        // A ticket is still good at its expiry instant.
        assertThat(IntStream.rangeClosed(1, 7)
                .filter(id -> ticketRepository.consume("consume-" + id, "connections", cutoff) == 1).boxed().toList())
                .containsExactlyElementsOf(AT_OR_AFTER);
        // The purge takes the unconsumed tickets from before now, the "consume-" ones among them.
        assertThat(ticketRepository.deleteExpired(cutoff)).isEqualTo(2 * BEFORE.size());
        assertThat(ticketRepository.findAll()).extracting(WebSocketTicket::getTokenHash)
                .containsExactlyInAnyOrderElementsOf(ids("purge-", AT_OR_AFTER));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void peerSessionExpirySweep(Rows rows, Instant now) {
        for (int id = 1; id <= 7; id++) {
            peerSessionRepository.saveAndFlush(peerSession(id, PeerMeshService.STATUS_ACTIVE, stored(rows, at(now, id))));
        }
        peerSessionRepository.saveAndFlush(peerSession(8, PeerMeshService.STATUS_CLOSED, stored(rows, at(now, 1))));
        settle(rows, "peer_mesh_session", "expires_at");

        assertThat(peerSessionRepository.findByStatusNotAndExpiresAtLessThanEqualOrderByExpiresAtAsc(
                PeerMeshService.STATUS_CLOSED, SortableInstant.format(now), PageRequest.of(0, 100)))
                .extracting(PeerMeshSession::getId).containsExactly(1L, 2L, 3L, 4L);
    }

    @ParameterizedTest
    @MethodSource("cases")
    void pairingCodeRedeem(Rows rows, Instant now) {
        PublicTransferRoom room = new PublicTransferRoom();
        room.setId(91001L);
        room.setRoomName("ordering-room");
        room.setOwnerTokenHash("a".repeat(64));
        room.setCreatedByPeerId("owner");
        room.setCreatedAt(LONG_AGO);
        room.setUpdatedAt(LONG_AGO);
        roomRepository.saveAndFlush(room);
        for (int id = 1; id <= 7; id++) {
            PublicTransferRoomPairingCode pairing = new PublicTransferRoomPairingCode();
            pairing.setId((long) id);
            pairing.setRoom(room);
            pairing.setCodeHash(codeHash(id));
            pairing.setRole("VIEWER");
            pairing.setLabel("ordering");
            pairing.setCreatedAt(LONG_AGO);
            pairing.setExpiresAt(stored(rows, at(now, id)));
            pairing.setMaxUses(1);
            pairing.setUsedCount(0);
            pairingCodeRepository.saveAndFlush(pairing);
        }
        settle(rows, "public_transfer_room_pairing_code", "expires_at");
        String cutoff = SortableInstant.format(now);

        // A code is no longer good at its expiry instant.
        assertThat(IntStream.rangeClosed(1, 7)
                .filter(id -> pairingCodeRepository.consumeUsable(codeHash(id), cutoff) == 1).boxed().toList())
                .containsExactlyElementsOf(AFTER);
    }

    @ParameterizedTest
    @MethodSource("cases")
    void registrationChallengePurge(Rows rows, Instant now) {
        for (int id = 1; id <= 7; id++) {
            ManagementRegistrationChallenge challenge = new ManagementRegistrationChallenge();
            challenge.setRegistrationId("r" + id);
            challenge.setUsername("user" + id);
            challenge.setEmail("user" + id + "@example.test");
            challenge.setPasswordHash("p".repeat(64));
            challenge.setCodeHash("c".repeat(64));
            challenge.setAttemptsRemaining(5);
            challenge.setExpiresAt(stored(rows, at(now, id)));
            challenge.setResendAvailableAt(LONG_AGO);
            challenge.setCreatedAt(LONG_AGO);
            challenge.setUpdatedAt(LONG_AGO);
            challengeRepository.saveAndFlush(challenge);
        }
        settle(rows, "specus_management_registration_challenge", "expires_at");

        assertThat(challengeRepository.deleteByExpiresAtBefore(SortableInstant.format(now))).isEqualTo(BEFORE.size());
        assertThat(challengeRepository.findAll()).extracting(ManagementRegistrationChallenge::getRegistrationId)
                .containsExactlyInAnyOrderElementsOf(ids("r", AT_OR_AFTER));
    }

    @ParameterizedTest
    @MethodSource("cases")
    void connectionRateLimitFilterAndStartupClose(Rows rows, Instant now) {
        for (int id = 1; id <= 7; id++) {
            ConnectionRecord record = new ConnectionRecord();
            record.setTenantId(TENANT);
            record.setClientId(42L);
            record.setClientName("client-a");
            record.setChannelId("c" + id);
            record.setConnectedAt(stored(rows, at(now, id)));
            record.setSuccess(true);
            connectionRecordRepository.saveAndFlush(record);
        }
        settle(rows, "specus_connection_record", "connected_at");

        assertThat(connectionRecordRepository.countByTenantIdAndClientIdAndConnectedAtGreaterThanEqual(
                TENANT, 42L, SortableInstant.format(now))).isEqualTo(AT_OR_AFTER.size());

        // Bounds arrive as the console sends them, an instant without the fixed width, or a bare date.
        assertThat(connections(new ConnectionFilter(null, null, now.toString(), null)))
                .extracting(ConnectionRecordView::channelId).containsExactlyElementsOf(ids("c", AT_OR_AFTER));
        assertThat(connections(new ConnectionFilter(null, null, null, now.toString())))
                .extracting(ConnectionRecordView::channelId).containsExactlyElementsOf(ids("c", List.of(1, 2, 3, 4)));
        List<ConnectionRecordView> all = connections(new ConnectionFilter(null, null, "2026-09-15", null));
        assertThat(all).extracting(ConnectionRecordView::connectedAt)
                .containsExactlyElementsOf(IntStream.rangeClosed(1, 7).mapToObj(id -> at(now, id).toString()).toList());

        assertThat(connectionRecordRepository.closeOpenRecordsBefore(
                SortableInstant.format(now), now.toString(), "SERVER_RESTARTED")).isEqualTo(BEFORE.size());
        entityManager.clear();
        assertThat(connectionRecordRepository.findAll(Sort.by("channelId")))
                .extracting(ConnectionRecord::getDisconnectedAt)
                .containsExactly(now.toString(), now.toString(), now.toString(), null, null, null, null);
    }

    @ParameterizedTest
    @MethodSource("cases")
    void mediaCaptureRetentionSweepAndReuse(Rows rows, Instant now) {
        for (int id = 1; id <= 7; id++) {
            insertCapture(id, stored(rows, at(now, id)));
        }
        settle(rows, "specus_http_media_capture", "expires_at");
        String cutoff = SortableInstant.format(now);

        assertThat(captureRepository.findTop200ByStateInAndExpiresAtBeforeOrderByIdAsc(
                List.of(HttpMediaCaptureService.STATE_COMPLETE), cutoff))
                .extracting(HttpMediaCapture::getResourceKey).containsExactlyElementsOf(ids("res-", BEFORE));
        // A capture is no longer reusable at its expiry instant.
        assertThat(IntStream.rangeClosed(1, 7).filter(id -> captureRepository
                .findFirstByTenantIdAndResourceKeyAndMediaKindAndContentRangeStartAndContentRangeEndAndTotalBytesAndCapturedBytesAndContentEncodingAndStateAndExpiresAtAfterOrderByIdDesc(
                        TENANT, "res-" + id, "MEDIA_SEGMENT", 0L, 9L, 10L, 10L, "identity",
                        HttpMediaCaptureService.STATE_COMPLETE, cutoff)
                .isPresent()).boxed().toList()).containsExactlyElementsOf(AFTER);

        List<HttpMediaCaptureView> views = captureService.list(
                new ManagementContext(new TenantContext(TENANT), "admin", true), null, null,
                PageRequest.of(0, 10)).getContent();
        assertThat(views).extracting(HttpMediaCaptureView::expiresAt)
                .containsExactlyElementsOf(IntStream.iterate(7, id -> id >= 1, id -> id - 1)
                        .mapToObj(id -> at(now, id).toString()).toList());
    }

    private List<ConnectionRecordView> connections(ConnectionFilter filter) {
        return connectionRecordService.listConnections(new TenantContext(TENANT), filter,
                PageRequest.of(0, 20, Sort.by("channelId"))).getContent();
    }

    private static PeerMeshSession peerSession(long id, String status, String expiresAt) {
        PeerMeshSession session = new PeerMeshSession();
        session.setId(id);
        session.setTenantId(TENANT);
        session.setSourceClientId(1L);
        session.setSourceClientName("a");
        session.setTargetClientId(2L);
        session.setTargetClientName("b");
        session.setPathType(PeerMeshService.PATH_DIRECT);
        session.setStatus(status);
        session.setStartedAt(LONG_AGO);
        session.setUpdatedAt(LONG_AGO);
        session.setExpiresAt(expiresAt);
        return session;
    }

    /**
     * Written with an explicit id: Hibernate's SQLite DDL gives this table's IDENTITY id no type, so
     * it is no rowid alias and a row saved through JPA keeps a NULL id.
     */
    private void insertCapture(int id, String expiresAt) {
        jdbcTemplate.update("""
                insert into specus_http_media_capture(
                    id, tenant_id, client_id, client_name, route, source_url, resource_key, method,
                    status_code, content_encoding, media_kind, content_range_start, content_range_end,
                    total_bytes, captured_bytes, initialization_segment, live_stream, object_key, state,
                    captured_at, expires_at)
                values (?, ?, 42, 'client-a', 'media', ?, ?, 'GET', 200, 'identity', 'MEDIA_SEGMENT',
                        0, 9, 10, 10, false, false, ?, ?, ?, ?)
                """, id, TENANT, "https://media.example.test/" + id + ".ts", "res-" + id, "ordering/" + id,
                HttpMediaCaptureService.STATE_COMPLETE, LONG_AGO, expiresAt);
    }

    /** The instant stored under {@code id}: ids 1 to 3 are before now, 4 is now, 5 to 7 are after it. */
    private static Instant at(Instant now, int id) {
        return now.plusNanos(OFFSET_NANOS[id - 1]);
    }

    private static String stored(Rows rows, Instant instant) {
        return rows == Rows.WRITTEN ? SortableInstant.format(instant) : instant.toString();
    }

    private static List<String> ids(String prefix, List<Integer> ids) {
        return ids.stream().map(id -> prefix + id).toList();
    }

    private static String codeHash(int id) {
        return "%064d".formatted(id);
    }

    /** Legacy rows go through the startup migrator; afterwards every compared value has the fixed width. */
    private void settle(Rows rows, String table, String column) {
        if (rows == Rows.LEGACY_MIGRATED) {
            assertThat(widths(table, column)).doesNotContain((long) SortableInstant.LENGTH);
            migrator.migrate();
            entityManager.clear();
        }
        assertThat(widths(table, column)).containsOnly((long) SortableInstant.LENGTH);
    }

    private List<Long> widths(String table, String column) {
        return jdbcTemplate.queryForList("select length(" + column + ") from " + table, Long.class);
    }
}
