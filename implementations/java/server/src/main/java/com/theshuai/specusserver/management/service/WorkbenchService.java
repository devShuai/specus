package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.model.ManagementWorkbenchItem;
import com.theshuai.specusserver.management.model.PeerMeshSharedService;
import com.theshuai.specusserver.management.model.SpecusMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.ManagementWorkbenchItemRepository;
import com.theshuai.specusserver.management.repository.PeerMeshSharedServiceRepository;
import com.theshuai.specusserver.management.repository.SpecusMappingRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static com.theshuai.specusserver.management.model.ManagementWorkbenchItem.FAVORITE;
import static com.theshuai.specusserver.management.model.ManagementWorkbenchItem.RECENT;

/**
 * The service workbench's two short lists per management identity -- favourite services and
 * recently opened services -- per protocol/spec/service-workbench.md (shared vector
 * protocol/test-vectors/service-workbench-v1.json).
 *
 * <p>The identity is {@code (tenantId, username)} of the re-read account ({@link ManagementContext});
 * nothing in a request can name another identity. Every method reads the identity's rows first, so a
 * store that cannot be read fails the request (503 in the resource) before anything else is looked
 * at, and never turns into empty lists. Growth (adding a favourite, recording an open) needs the
 * object to be visible to the caller now, by the rule of the kind's list endpoint; reading and
 * removal never check visibility, so a reference that lost its permission can still be seen and
 * removed. After every successful write the identity's recents are trimmed to retention and bound.
 * Reading never writes. Rows are never cached: every request reads the database.
 */
@Service
@Slf4j
public class WorkbenchService {
    public static final int SCHEMA_VERSION = 1;
    public static final int MAX_FAVORITES = 50;
    public static final int MAX_RECENTS = 20;
    public static final int RECENT_RETENTION_DAYS = 30;
    public static final long RECENT_RETENTION_MS = RECENT_RETENTION_DAYS * 24L * 60 * 60 * 1000;
    /** The largest id a browser holds exactly as a JSON number. */
    public static final long MAX_OBJECT_ID = (1L << 53) - 1;
    /** The closed set of kinds; the order is also the tie-break order. */
    public static final List<String> KINDS = List.of(
            WorkbenchReferences.HTTP_ROUTE, WorkbenchReferences.TCP_MAPPING, WorkbenchReferences.PEER_SERVICE);

    private static final DateTimeFormatter STAMP =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);
    private static final Limits LIMITS = new Limits(MAX_FAVORITES, MAX_RECENTS, RECENT_RETENTION_DAYS);
    /** Ties are broken by the fixed kind order, then by id. */
    private static final Comparator<ManagementWorkbenchItem> REFERENCE_ORDER =
            Comparator.comparingInt((ManagementWorkbenchItem row) -> kindOrder(row.getKey().kind()))
                    .thenComparingLong(row -> row.getKey().objectId());
    /** Favourites: addedAt ascending, so a new one goes last and the others keep their place. */
    private static final Comparator<ManagementWorkbenchItem> FAVORITE_ORDER =
            Comparator.comparingLong(ManagementWorkbenchItem::getAtMs).thenComparing(REFERENCE_ORDER);
    /** Recents: visitedAt descending, newest first. */
    private static final Comparator<ManagementWorkbenchItem> RECENT_ORDER =
            Comparator.comparingLong(ManagementWorkbenchItem::getAtMs).reversed().thenComparing(REFERENCE_ORDER);

    private final ManagementWorkbenchItemRepository repository;
    private final HttpRouteMappingRepository httpRouteMappingRepository;
    private final SpecusMappingRepository specusMappingRepository;
    private final PeerMeshSharedServiceRepository peerMeshSharedServiceRepository;
    private final ClientAccountRepository clientAccountRepository;
    private final WorkbenchClock clock;

    public WorkbenchService(ManagementWorkbenchItemRepository repository,
                            HttpRouteMappingRepository httpRouteMappingRepository,
                            SpecusMappingRepository specusMappingRepository,
                            PeerMeshSharedServiceRepository peerMeshSharedServiceRepository,
                            ClientAccountRepository clientAccountRepository,
                            WorkbenchClock clock) {
        this.repository = repository;
        this.httpRouteMappingRepository = httpRouteMappingRepository;
        this.specusMappingRepository = specusMappingRepository;
        this.peerMeshSharedServiceRepository = peerMeshSharedServiceRepository;
        this.clientAccountRepository = clientAccountRepository;
        this.clock = clock;
    }

    /**
     * Validates the raw path segments: {@code kind} exactly one of {@link #KINDS}; {@code id} decimal
     * ASCII digits without sign, blank or leading zero, 1..2^53-1. Taken as strings on purpose: a
     * framework binding {@code 042} to 42 would accept what the contract refuses.
     *
     * @return the reference, or {@code null} when either part is invalid
     */
    public static Reference parseReference(String kind, String id) {
        if (kind == null || !KINDS.contains(kind) || id == null || id.isEmpty() || id.length() > 16
                || id.charAt(0) == '0') {
            return null;
        }
        for (int i = 0; i < id.length(); i++) {
            char c = id.charAt(i);
            if (c < '0' || c > '9') {
                return null;
            }
        }
        long value = Long.parseLong(id);
        return value <= MAX_OBJECT_ID ? new Reference(kind, value) : null;
    }

    @Transactional(readOnly = true)
    public Document read(ManagementContext context, long now) {
        return document(rows(context), now);
    }

    @Transactional
    public Document addFavorite(ManagementContext context, Reference reference, long now) {
        List<ManagementWorkbenchItem> rows = rows(context);
        requireVisible(context, reference);
        if (find(rows, FAVORITE, reference).isEmpty()) {
            // Adding one that is already there changes nothing, its addedAt included, even when
            // the list is full. Otherwise a full list refuses; nothing is evicted.
            long favorites = rows.stream().filter(row -> FAVORITE.equals(row.getKey().listName())).count();
            if (favorites >= MAX_FAVORITES) {
                throw new Refusal(HttpStatus.CONFLICT, "WORKBENCH_FAVORITES_FULL",
                        "favourites are full (max " + MAX_FAVORITES + ")");
            }
            repository.save(new ManagementWorkbenchItem(key(context, FAVORITE, reference), now));
        }
        return afterWrite(context, now);
    }

    @Transactional
    public Document recordVisit(ManagementContext context, Reference reference, long now) {
        List<ManagementWorkbenchItem> rows = rows(context);
        requireVisible(context, reference);
        Optional<ManagementWorkbenchItem> existing = find(rows, RECENT, reference);
        if (existing.isPresent()) {
            // A clock behind the stored time (another instance) never moves an entry back.
            existing.get().setAtMs(Math.max(existing.get().getAtMs(), now));
        } else {
            repository.save(new ManagementWorkbenchItem(key(context, RECENT, reference), now));
        }
        return afterWrite(context, now);
    }

    @Transactional
    public Document removeFavorite(ManagementContext context, Reference reference, long now) {
        find(rows(context), FAVORITE, reference).ifPresent(repository::delete);
        return afterWrite(context, now);
    }

    @Transactional
    public Document removeRecent(ManagementContext context, Reference reference, long now) {
        find(rows(context), RECENT, reference).ifPresent(repository::delete);
        return afterWrite(context, now);
    }

    @Transactional
    public Document clearFavorites(ManagementContext context, long now) {
        repository.deleteAll(rows(context).stream().filter(row -> FAVORITE.equals(row.getKey().listName())).toList());
        return afterWrite(context, now);
    }

    @Transactional
    public Document clearRecents(ManagementContext context, long now) {
        repository.deleteAll(rows(context).stream().filter(row -> RECENT.equals(row.getKey().listName())).toList());
        return afterWrite(context, now);
    }

    /**
     * The global retention sweep: deletes every identity's recent opens that are 30 days old or
     * older. Idempotent, so any number of instances may run it. First run a minute after startup,
     * then hourly; the identity's own next write also trims its expired rows.
     */
    @Scheduled(initialDelayString = "${specus.workbench.sweep-initial-delay-ms:60000}",
            fixedDelayString = "${specus.workbench.sweep-interval-ms:3600000}")
    @Transactional
    public void sweepExpiredRecents() {
        int removed = repository.deleteRecentsAtOrBefore(clock.millis() - RECENT_RETENTION_MS);
        if (removed > 0) {
            log.debug("[workbench] sweep removed {} expired recent opens", removed);
        }
    }

    /**
     * Ends every successful write: the identity's recents keep only the entries within retention
     * and, of those, the first {@value #MAX_RECENTS} in list order. The rest is deleted, not hidden.
     */
    private Document afterWrite(ManagementContext context, long now) {
        repository.flush();
        List<ManagementWorkbenchItem> rows = new ArrayList<>(rows(context));
        List<ManagementWorkbenchItem> drop = new ArrayList<>();
        int kept = 0;
        for (ManagementWorkbenchItem recent : rows.stream()
                .filter(row -> RECENT.equals(row.getKey().listName())).sorted(RECENT_ORDER).toList()) {
            if (!withinRetention(recent, now) || kept >= MAX_RECENTS) {
                drop.add(recent);
            } else {
                kept++;
            }
        }
        if (!drop.isEmpty()) {
            repository.deleteAll(drop);
            repository.flush();
            rows.removeAll(drop);
        }
        return document(rows, now);
    }

    private Document document(List<ManagementWorkbenchItem> rows, long now) {
        List<FavoriteView> favorites = rows.stream()
                .filter(row -> FAVORITE.equals(row.getKey().listName()))
                .sorted(FAVORITE_ORDER)
                .map(row -> new FavoriteView(row.getKey().kind(), row.getKey().objectId(), stamp(row.getAtMs())))
                .toList();
        List<RecentView> recents = rows.stream()
                .filter(row -> RECENT.equals(row.getKey().listName()))
                .filter(row -> withinRetention(row, now))
                .sorted(RECENT_ORDER)
                .limit(MAX_RECENTS)
                .map(row -> new RecentView(row.getKey().kind(), row.getKey().objectId(), stamp(row.getAtMs())))
                .toList();
        return new Document(SCHEMA_VERSION, LIMITS, favorites, recents);
    }

    /**
     * The object exists and is visible to the caller now: its client is in the caller's tenant and
     * the caller is an administrator by the current account role or the client's owner. Missing,
     * another tenant's and another owner's objects are refused alike.
     */
    private void requireVisible(ManagementContext context, Reference reference) {
        String tenantId = context.tenant().tenantId();
        Optional<Long> clientId = switch (reference.kind()) {
            case WorkbenchReferences.HTTP_ROUTE -> httpRouteMappingRepository
                    .findByIdAndTenantId(reference.id(), tenantId).map(HttpRouteMapping::getClientId);
            case WorkbenchReferences.TCP_MAPPING -> specusMappingRepository
                    .findByIdAndTenantId(reference.id(), tenantId).map(SpecusMapping::getClientId);
            case WorkbenchReferences.PEER_SERVICE -> peerMeshSharedServiceRepository
                    .findByIdAndTenantId(reference.id(), tenantId).map(PeerMeshSharedService::getClientId);
            default -> Optional.empty();
        };
        boolean visible = clientId
                .flatMap(id -> clientAccountRepository.findByIdAndTenantId(id, tenantId))
                .filter(client -> context.isAdmin() || Objects.equals(client.getOwnerUsername(), context.username()))
                .isPresent();
        if (!visible) {
            throw new Refusal(HttpStatus.NOT_FOUND, "WORKBENCH_TARGET_NOT_FOUND", "service not found");
        }
    }

    private List<ManagementWorkbenchItem> rows(ManagementContext context) {
        return repository.findByIdentity(context.tenant().tenantId(), context.username());
    }

    private static Optional<ManagementWorkbenchItem> find(List<ManagementWorkbenchItem> rows, String list,
                                                          Reference reference) {
        return rows.stream()
                .filter(row -> list.equals(row.getKey().listName())
                        && reference.kind().equals(row.getKey().kind())
                        && reference.id() == row.getKey().objectId())
                .findFirst();
    }

    private static ManagementWorkbenchItem.Key key(ManagementContext context, String list, Reference reference) {
        return new ManagementWorkbenchItem.Key(
                context.tenant().tenantId(), context.username(), list, reference.kind(), reference.id());
    }

    private static boolean withinRetention(ManagementWorkbenchItem row, long now) {
        return now - row.getAtMs() < RECENT_RETENTION_MS;
    }

    private static int kindOrder(String kind) {
        int index = KINDS.indexOf(kind);
        return index < 0 ? KINDS.size() : index;
    }

    static String stamp(long epochMillis) {
        return STAMP.format(Instant.ofEpochMilli(epochMillis));
    }

    /** A service reference from the request path, already validated. */
    public record Reference(String kind, long id) {
    }

    public record Limits(int maxFavorites, int maxRecents, int recentRetentionDays) {
    }

    public record FavoriteView(String kind, long id, String addedAt) {
    }

    public record RecentView(String kind, long id, String visitedAt) {
    }

    /** The response body of every successful workbench request, reads and writes alike. */
    public record Document(int schemaVersion, Limits limits, List<FavoriteView> favorites, List<RecentView> recents) {
    }

    /** A refusal that is part of the contract (404, 409); the resource maps it to its code. */
    public static final class Refusal extends RuntimeException {
        private final HttpStatus status;
        private final String code;

        Refusal(HttpStatus status, String code, String message) {
            super(message);
            this.status = status;
            this.code = code;
        }

        public HttpStatus status() {
            return status;
        }

        public String code() {
            return code;
        }
    }
}
