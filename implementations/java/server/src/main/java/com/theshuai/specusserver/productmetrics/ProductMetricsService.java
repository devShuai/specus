package com.theshuai.specusserver.productmetrics;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.productmetrics.ProductMetricsModel.Event;
import com.theshuai.specusserver.productmetrics.ProductMetricsModel.Ingest;
import com.theshuai.specusserver.productmetrics.ProductMetricsModel.SettingsUpdate;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.OnboardingCount;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.ProgressRow;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.SwitchRow;
import com.theshuai.specusserver.productmetrics.ProductMetricsStore.TransferCount;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.util.StringUtils;

import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.regex.Pattern;

import static com.theshuai.specusserver.productmetrics.ProductMetricsModel.*;

/**
 * Server side of the opt-in product metrics (protocol/spec/product-metrics.md): the tenant switch,
 * the onboarding milestones observed on the server's own write paths, transfer-outcome ingest, the
 * retention sweep, purge and the summary. Every count lives in the shared database; only the rate
 * limiter is per process. Logs carry the tenant and the operation, never a username, request body,
 * credential, file name or address.
 */
@Service
@Slf4j
public class ProductMetricsService {
    private static final Pattern DAY = Pattern.compile("\\d{4}-\\d{2}-\\d{2}");

    private final ProductMetricsStore store;
    private final ProductMetricsRateLimiter limiter;
    private final ProductMetricsClock clock;
    private final ProductMetricsProperties properties;
    private final ClientAccountRepository clientAccountRepository;
    private final TransactionTemplate transactions;

    public ProductMetricsService(ProductMetricsStore store,
                                 ProductMetricsRateLimiter limiter,
                                 ProductMetricsClock clock,
                                 ProductMetricsProperties properties,
                                 ClientAccountRepository clientAccountRepository,
                                 PlatformTransactionManager transactionManager) {
        this.store = store;
        this.limiter = limiter;
        this.clock = clock;
        this.properties = properties;
        this.clientAccountRepository = clientAccountRepository;
        this.transactions = new TransactionTemplate(transactionManager);
    }

    /** Status and JSON body of one endpoint call; a null body on 403 means the usual error shape. */
    public record Response(int status, Object body) {
        static Response ok(Object body) {
            return new Response(200, body);
        }

        static Response code(int status, String code) {
            return new Response(status, Map.of("code", code));
        }
    }

    private boolean collecting(SwitchRow row) {
        return properties.isAllowed() && row != null && row.enabled();
    }

    private Response unavailable(String operation, String tenantId, RuntimeException error) {
        log.warn("[product-metrics] storage failed: operation={} tenant={} error={}", operation, tenantId,
                error.getClass().getSimpleName());
        return Response.code(503, CODE_UNAVAILABLE);
    }

    private static String tenantOf(ManagementContext context) {
        return context.tenant().tenantId();
    }

    // -- settings (7.1, 7.2) ------------------------------------------------------------------------

    private Map<String, Object> settingsView(SwitchRow row, boolean admin) {
        Map<String, Object> view = new LinkedHashMap<>();
        view.put("schemaVersion", SCHEMA_VERSION);
        view.put("enabled", collecting(row));
        view.put("disclosureVersion", DISCLOSURE_VERSION);
        view.put("retentionDays", RETENTION_DAYS);
        view.put("onboardingWindowDays", WINDOW_DAYS);
        view.put("updatedAt", row == null || row.updatedAt() == null ? null : instant(row.updatedAt()));
        if (admin) {
            view.put("updatedBy", row == null ? null : row.updatedBy());
        }
        return view;
    }

    public Response settings(ManagementContext context) {
        String tenant = tenantOf(context);
        try {
            return Response.ok(settingsView(store.findSwitch(tenant).orElse(null), context.isAdmin()));
        } catch (DataAccessException | TransactionException error) {
            return unavailable("settings", tenant, error);
        }
    }

    /**
     * PUT /settings. Switching off drops the tenant's progress rows without folding them; switching
     * on clears the purge mark; an unchanged state keeps updatedAt/updatedBy.
     */
    public Response putSettings(ManagementContext context, byte[] body) {
        if (!context.isAdmin()) {
            return new Response(403, null);
        }
        Optional<SettingsUpdate> parsed = parseSettingsUpdate(body);
        if (parsed.isEmpty()) {
            return Response.code(400, CODE_INVALID);
        }
        SettingsUpdate update = parsed.get();
        if (update.enabled() && !String.valueOf(DISCLOSURE_VERSION).equals(update.disclosure())) {
            return Response.code(400, CODE_DISCLOSURE_REQUIRED);
        }
        if (update.enabled() && !properties.isAllowed()) {
            return Response.code(409, CODE_NOT_ALLOWED);
        }
        String tenant = tenantOf(context);
        long now = clock.millis();
        try {
            SwitchRow saved = transactions.execute(status -> {
                SwitchRow row = store.findSwitch(tenant).orElse(new SwitchRow(tenant, false, null, null, null));
                if (row.enabled() != update.enabled()) {
                    row = new SwitchRow(tenant, update.enabled(), context.username(), now,
                            update.enabled() ? null : row.purgedAt());
                }
                store.saveSwitch(row);
                if (!update.enabled()) {
                    store.deleteTenantProgress(tenant);
                }
                return row;
            });
            return Response.ok(settingsView(saved, true));
        } catch (DataAccessException | TransactionException error) {
            return unavailable("put-settings", tenant, error);
        }
    }

    // -- purge (7.3) --------------------------------------------------------------------------------

    public Response purge(ManagementContext context) {
        if (!context.isAdmin()) {
            return new Response(403, null);
        }
        String tenant = tenantOf(context);
        long now = clock.millis();
        try {
            SwitchRow saved = transactions.execute(status -> {
                store.deleteTenantProgress(tenant);
                store.deleteTenantCounts(tenant);
                SwitchRow row = store.findSwitch(tenant).orElse(new SwitchRow(tenant, false, null, null, null));
                row = new SwitchRow(tenant, row.enabled(), row.updatedBy(), row.updatedAt(), now);
                store.saveSwitch(row);
                return row;
            });
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("purged", true);
            body.put("enabled", collecting(saved));
            return Response.ok(body);
        } catch (DataAccessException | TransactionException error) {
            return unavailable("purge", tenant, error);
        }
    }

    // -- ingest (7.4) -------------------------------------------------------------------------------

    /**
     * POST /transfer-outcomes after authentication; {@code body} holds at most MAX_BODY_BYTES + 1 raw
     * bytes. Size, schema, switch, limiter, count -- a refusal at any step leaves the limiter alone.
     * Counting runs in one transaction of atomic upserts.
     */
    public Response ingest(ManagementContext context, byte[] body) {
        Ingest parsed = parseIngest(body);
        if (CODE_TOO_LARGE.equals(parsed.refusal())) {
            return Response.code(413, CODE_TOO_LARGE);
        }
        if (parsed.refusal() != null) {
            return Response.code(400, CODE_INVALID);
        }
        String tenant = tenantOf(context);
        long now = clock.millis();
        String day = dayOf(now);
        Map<Event, Long> counts = new LinkedHashMap<>();
        for (Event event : parsed.events()) {
            counts.merge(event, 1L, Long::sum);
        }
        int accepted = parsed.events().size();
        try {
            return transactions.execute(status -> {
                if (!collecting(store.findSwitch(tenant).orElse(null))) {
                    Map<String, Object> off = new LinkedHashMap<>();
                    off.put("collecting", false);
                    off.put("accepted", 0);
                    return Response.ok(off);
                }
                if (!limiter.admit(tenant, context.username(), accepted, now)) {
                    return Response.code(429, CODE_RATE_LIMITED);
                }
                counts.forEach((event, count) -> store.addTransferCount(new TransferCount(tenant, day, event.mode(),
                        event.path(), event.sizeBucket(), event.attempt(), event.outcome(), count)));
                Map<String, Object> counted = new LinkedHashMap<>();
                counted.put("collecting", true);
                counted.put("accepted", accepted);
                return Response.ok(counted);
            });
        } catch (DataAccessException | TransactionException error) {
            return unavailable("ingest", tenant, error);
        }
    }

    // -- onboarding milestones (4.1) ----------------------------------------------------------------

    private static String milestoneColumn(String step) {
        return switch (step) {
            case STEP_SIGNED_IN -> "signed_in_at";
            case STEP_CREDENTIAL_CREATED -> "credential_created_at";
            case STEP_CLIENT_ONLINE -> "client_online_at";
            default -> null;
        };
    }

    static String reachedStep(ProgressRow row) {
        if (row.clientOnlineAt() != null) {
            return STEP_CLIENT_ONLINE;
        }
        if (row.credentialCreatedAt() != null) {
            return STEP_CREDENTIAL_CREATED;
        }
        if (row.signedInAt() != null) {
            return STEP_SIGNED_IN;
        }
        return STEP_ACCOUNT_CREATED;
    }

    /**
     * Records one onboarding milestone, called after the write path it belongs to succeeded and
     * outside its transaction. Returns the effect ("ignored", "started", "recorded", "completed",
     * "expired"), which only tests read. Never throws: a metrics failure must not fail the write.
     */
    public String milestone(String tenantId, String username, String step) {
        String tenant = StringUtils.hasText(tenantId) ? tenantId : "default";
        try {
            return recordMilestone(tenant, username, step);
        } catch (RuntimeException error) {
            log.warn("[product-metrics] milestone failed: tenant={} step={} error={}", tenant, step,
                    error.getClass().getSimpleName());
            return "ignored";
        }
    }

    private String recordMilestone(String tenant, String username, String step) {
        if (!properties.isAllowed() || !StringUtils.hasText(username)
                || !collecting(store.findSwitch(tenant).orElse(null))) {
            return "ignored";
        }
        long now = clock.millis();
        if (STEP_ACCOUNT_CREATED.equals(step)) {
            return store.insertProgressIfAbsent(new ProgressRow(tenant, username, now, null, null, null))
                    ? "started" : "ignored";
        }
        String column = milestoneColumn(step);
        if (column == null && !STEP_SERVICE_PUBLISHED.equals(step)) {
            return "ignored";
        }
        Optional<ProgressRow> progress = store.findProgress(tenant, username);
        if (progress.isEmpty()) {
            return "ignored";
        }
        if (now >= progress.get().startedAt() + WINDOW_MS) {
            close(tenant, username, null);
            return "expired";
        }
        if (STEP_SERVICE_PUBLISHED.equals(step)) {
            return close(tenant, username, now) ? "completed" : "ignored";
        }
        return store.setMilestone(tenant, username, column, now) ? "recorded" : "ignored";
    }

    /**
     * Folds one progress row into its cohort counter: completed when {@code completedAt} is set,
     * otherwise at the furthest recorded step. The counter moves only after exactly one row was
     * deleted, so a completion racing the sweep or another instance counts once.
     */
    private boolean close(String tenant, String username, Long completedAt) {
        Boolean closed = transactions.execute(status -> {
            Optional<ProgressRow> found = store.findProgress(tenant, username);
            if (found.isEmpty() || store.deleteProgress(tenant, username) != 1) {
                return false;
            }
            ProgressRow row = found.get();
            String reached = reachedStep(row);
            String bucket = NO_DURATION;
            if (completedAt != null) {
                Optional<String> duration = durationBucket(Math.max(0, completedAt - row.startedAt()) / 1000);
                if (duration.isEmpty()) {
                    return false; // unreachable: such a row expires instead of completing
                }
                reached = STEP_SERVICE_PUBLISHED;
                bucket = duration.get();
            }
            store.addOnboardingCount(new OnboardingCount(tenant, dayOf(row.startedAt()), reached, bucket, 1));
            return true;
        });
        return Boolean.TRUE.equals(closed);
    }

    /** service_published for the owner of the client the route or mapping was created on. */
    public void servicePublished(long clientId) {
        try {
            clientAccountRepository.findById(clientId).ifPresent(this::servicePublished);
        } catch (RuntimeException error) {
            log.warn("[product-metrics] service lookup failed: error={}", error.getClass().getSimpleName());
        }
    }

    private void servicePublished(ClientAccount account) {
        milestone(account.getTenantId(), account.getOwnerUsername(), STEP_SERVICE_PUBLISHED);
    }

    /** client_online for the owner of a client whose control connection just logged in. */
    public void clientOnline(ClientAccount account) {
        if (account != null) {
            milestone(account.getTenantId(), account.getOwnerUsername(), STEP_CLIENT_ONLINE);
        }
    }

    /** Drops a deleted account's progress row without folding it into any count. */
    public String userDeleted(String tenantId, String username) {
        try {
            return store.deleteProgress(tenantId, username) > 0 ? "deleted" : "ignored";
        } catch (RuntimeException error) {
            log.warn("[product-metrics] progress removal failed: tenant={} error={}", tenantId,
                    error.getClass().getSimpleName());
            return "ignored";
        }
    }

    // -- retention (9) ------------------------------------------------------------------------------

    /** Hourly, from any instance; the first run a minute after start. */
    @Scheduled(initialDelayString = "${specus.product-metrics.sweep-initial-delay-ms:60000}",
            fixedDelayString = "${specus.product-metrics.sweep-interval-ms:3600000}")
    public void scheduledSweep() {
        try {
            sweep();
        } catch (RuntimeException error) {
            log.warn("[product-metrics] sweep failed: error={}", error.getClass().getSimpleName());
        }
    }

    /** The four retention steps of section 9; idempotent and independent of when it runs. */
    public void sweep() {
        long now = clock.millis();
        List<SwitchRow> switches = store.switches();
        Map<String, Boolean> enabled = new HashMap<>();
        switches.forEach(row -> enabled.put(row.tenantId(), collecting(row)));
        List<ProgressRow> progress = new ArrayList<>(store.progressRows(null));
        progress.sort(Comparator.comparing(ProgressRow::tenantId).thenComparing(ProgressRow::username));
        for (ProgressRow row : progress) {
            if (!enabled.getOrDefault(row.tenantId(), false)) {
                store.deleteProgress(row.tenantId(), row.username());
            } else if (now >= row.startedAt() + WINDOW_MS) {
                close(row.tenantId(), row.username(), null);
            }
        }
        store.deleteCountsBefore(dayOf(now - (RETENTION_DAYS - 1) * DAY_MS));
        for (SwitchRow row : switches) {
            if (!row.enabled() && row.purgedAt() != null) {
                store.deleteTenantCounts(row.tenantId());
                store.deleteTenantProgress(row.tenantId());
            }
        }
    }

    // -- summary (7.5) ------------------------------------------------------------------------------

    private static Optional<LocalDate> parseDay(String text) {
        if (text == null || !DAY.matcher(text).matches()) {
            return Optional.empty();
        }
        try {
            return Optional.of(LocalDate.parse(text));
        } catch (DateTimeParseException invalid) {
            return Optional.empty();
        }
    }

    /** GET /summary?from&to for the tenant's ADMIN; a present but malformed date is a range error. */
    public Response summary(ManagementContext context, Map<String, String> query) {
        if (!context.isAdmin()) {
            return new Response(403, null);
        }
        long now = clock.millis();
        LocalDate today = LocalDate.parse(dayOf(now));
        LocalDate to = today;
        if (query.containsKey("to")) {
            Optional<LocalDate> parsed = parseDay(query.get("to"));
            if (parsed.isEmpty()) {
                return Response.code(400, CODE_RANGE);
            }
            to = parsed.get();
        }
        LocalDate from = to.minusDays(29);
        if (query.containsKey("from")) {
            Optional<LocalDate> parsed = parseDay(query.get("from"));
            if (parsed.isEmpty()) {
                return Response.code(400, CODE_RANGE);
            }
            from = parsed.get();
        }
        if (from.isAfter(to) || ChronoUnit.DAYS.between(from, to) + 1 > MAX_RANGE_DAYS || to.isAfter(today)
                || from.isBefore(today.minusDays(RETENTION_DAYS - 1))) {
            return Response.code(400, CODE_RANGE);
        }
        String tenant = tenantOf(context);
        String low = from.toString();
        String high = to.toString();
        try {
            SwitchRow row = store.findSwitch(tenant).orElse(null);
            List<OnboardingCount> cohorts = store.onboardingCounts(tenant, low, high);
            List<ProgressRow> progress = store.progressRows(tenant);
            List<TransferCount> transfers = store.transferCounts(tenant, low, high);
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("schemaVersion", SCHEMA_VERSION);
            body.put("enabled", collecting(row));
            body.put("from", low);
            body.put("to", high);
            body.put("generatedAt", instant(now));
            body.put("onboarding", onboarding(cohorts, progress, low, high, now));
            body.put("transfers", transfers(transfers));
            return Response.ok(body);
        } catch (DataAccessException | TransactionException error) {
            return unavailable("summary", tenant, error);
        }
    }

    private static Map<String, Object> onboarding(List<OnboardingCount> cohorts, List<ProgressRow> progress,
                                                  String low, String high, long now) {
        Map<String, Long> reached = new HashMap<>();
        Map<String, Long> durations = new HashMap<>();
        long pending = 0;
        for (OnboardingCount row : cohorts) {
            reached.merge(row.reachedStep(), row.users(), Long::sum);
            if (!NO_DURATION.equals(row.durationBucket())) {
                durations.merge(row.durationBucket(), row.users(), Long::sum);
            }
        }
        for (ProgressRow row : progress) {
            String day = dayOf(row.startedAt());
            if (day.compareTo(low) < 0 || day.compareTo(high) > 0) {
                continue;
            }
            reached.merge(reachedStep(row), 1L, Long::sum);
            if (now < row.startedAt() + WINDOW_MS) {
                pending++;
            }
        }
        List<Map<String, Object>> steps = new ArrayList<>();
        Long previous = null;
        for (int index = 0; index < STEPS.size(); index++) {
            long users = 0;
            for (String later : STEPS.subList(index, STEPS.size())) {
                users += reached.getOrDefault(later, 0L);
            }
            Map<String, Object> step = new LinkedHashMap<>();
            step.put("step", STEPS.get(index));
            step.put("users", users);
            step.put("fromPreviousRateBp", previous == null ? null : rateBp(users, previous));
            steps.add(step);
            previous = users;
        }
        long cohortUsers = (long) steps.getFirst().get("users");
        long completed = (long) steps.getLast().get("users");
        List<Map<String, Object>> buckets = new ArrayList<>();
        long completers = 0;
        for (String name : DURATION_BUCKETS) {
            Map<String, Object> bucket = new LinkedHashMap<>();
            bucket.put("bucket", name);
            bucket.put("users", durations.getOrDefault(name, 0L));
            buckets.add(bucket);
            completers += durations.getOrDefault(name, 0L);
        }
        String median = null;
        long position = (completers + 1) / 2; // the ceil(n/2)-th completer, counted from 1
        for (String name : DURATION_BUCKETS) {
            if (completers == 0) {
                break;
            }
            long users = durations.getOrDefault(name, 0L);
            if (position <= users) {
                median = name;
                break;
            }
            position -= users;
        }
        Map<String, Object> onboarding = new LinkedHashMap<>();
        onboarding.put("windowDays", WINDOW_DAYS);
        onboarding.put("cohortUsers", cohortUsers);
        onboarding.put("pendingUsers", pending);
        onboarding.put("final", pending == 0);
        onboarding.put("steps", steps);
        onboarding.put("completed", completed);
        onboarding.put("completionRateBp", rateBp(completed, cohortUsers));
        onboarding.put("durations", buckets);
        onboarding.put("medianDurationBucket", median);
        return onboarding;
    }

    private static Map<String, Object> tally(List<TransferCount> rows, Predicate<TransferCount> match,
                                             Map<String, Object> into) {
        long success = 0;
        long failure = 0;
        long cancelled = 0;
        for (TransferCount row : rows) {
            if (!match.test(row)) {
                continue;
            }
            switch (row.outcome()) {
                case "success" -> success += row.count();
                case "failure" -> failure += row.count();
                case "cancelled" -> cancelled += row.count();
                default -> {
                }
            }
        }
        into.put("success", success);
        into.put("failure", failure);
        into.put("cancelled", cancelled);
        into.put("successRateBp", rateBp(success, success + failure));
        return into;
    }

    private static Map<String, Object> transfers(List<TransferCount> rows) {
        List<Map<String, Object>> cells = new ArrayList<>();
        for (String path : PATHS) {
            for (String size : SIZE_BUCKETS) {
                Map<String, Object> cell = new LinkedHashMap<>();
                cell.put("path", path);
                cell.put("sizeBucket", size);
                tally(rows, row -> row.path().equals(path) && row.sizeBucket().equals(size), cell);
                if ((long) cell.get("success") + (long) cell.get("failure") + (long) cell.get("cancelled") > 0) {
                    cells.add(cell);
                }
            }
        }
        List<Map<String, Object>> byMode = new ArrayList<>();
        for (String mode : MODES) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("mode", mode);
            byMode.add(tally(rows, row -> row.mode().equals(mode), entry));
        }
        List<Map<String, Object>> byAttempt = new ArrayList<>();
        for (String attempt : ATTEMPTS) {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("attempt", attempt);
            byAttempt.add(tally(rows, row -> row.attempt().equals(attempt), entry));
        }
        Map<String, Object> transfers = new LinkedHashMap<>();
        transfers.put("cells", cells);
        transfers.put("byMode", byMode);
        transfers.put("byAttempt", byAttempt);
        transfers.put("total", tally(rows, row -> true, new LinkedHashMap<>()));
        return transfers;
    }
}
