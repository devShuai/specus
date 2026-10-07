package com.theshuai.specusserver.productmetrics;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The closed vocabulary, buckets, rates and request schemas of the opt-in product metrics
 * (protocol/spec/product-metrics.md sections 4, 5 and 7). Pure functions only.
 */
public final class ProductMetricsModel {
    public static final int SCHEMA_VERSION = 1;
    public static final int DISCLOSURE_VERSION = 1;
    public static final int RETENTION_DAYS = 180;
    public static final int WINDOW_DAYS = 14;
    public static final int MAX_BODY_BYTES = 4096;
    public static final int MAX_EVENTS = 20;
    public static final int MAX_RANGE_DAYS = 180;
    public static final int DEFAULT_PER_USER_EVENTS_PER_MINUTE = 120;
    public static final int DEFAULT_PER_TENANT_EVENTS_PER_MINUTE = 3000;

    public static final String CODE_INVALID = "PRODUCT_METRICS_INVALID";
    public static final String CODE_TOO_LARGE = "PRODUCT_METRICS_TOO_LARGE";
    public static final String CODE_RATE_LIMITED = "PRODUCT_METRICS_RATE_LIMITED";
    public static final String CODE_DISCLOSURE_REQUIRED = "PRODUCT_METRICS_DISCLOSURE_REQUIRED";
    public static final String CODE_RANGE = "PRODUCT_METRICS_RANGE";
    public static final String CODE_NOT_ALLOWED = "PRODUCT_METRICS_NOT_ALLOWED";
    public static final String CODE_UNAVAILABLE = "PRODUCT_METRICS_UNAVAILABLE";

    public static final String STEP_ACCOUNT_CREATED = "account_created";
    public static final String STEP_SIGNED_IN = "signed_in";
    public static final String STEP_CREDENTIAL_CREATED = "credential_created";
    public static final String STEP_CLIENT_ONLINE = "client_online";
    public static final String STEP_SERVICE_PUBLISHED = "service_published";
    public static final String NO_DURATION = "none";

    public static final List<String> STEPS = List.of(STEP_ACCOUNT_CREATED, STEP_SIGNED_IN, STEP_CREDENTIAL_CREATED,
            STEP_CLIENT_ONLINE, STEP_SERVICE_PUBLISHED);
    public static final List<String> MODES = List.of("device", "link");
    public static final List<String> PATHS = List.of("direct", "turn", "cloud", "unestablished");
    public static final List<String> ATTEMPTS = List.of("first", "retry_after_failure", "retry_after_cancel");
    public static final List<String> OUTCOMES = List.of("success", "failure", "cancelled");
    public static final List<String> SIZE_BUCKETS = List.of("lt1m", "1m-16m", "16m-128m", "128m-512m", "gt512m");
    public static final List<String> DURATION_BUCKETS = List.of("lt10m", "10m-30m", "30m-2h", "2h-24h", "1d-3d",
            "3d-14d");

    static final long DAY_MS = 86_400_000L;
    static final long WINDOW_MS = WINDOW_DAYS * DAY_MS;
    private static final long MIB = 1L << 20;
    private static final long[] DURATION_UPPER_BOUNDS = {600, 1800, 7200, 86400, 259200, WINDOW_DAYS * 86400L};
    private static final Set<String> EVENT_KEYS = Set.of("mode", "path", "sizeBucket", "attempt", "outcome");
    private static final DateTimeFormatter INSTANT_SECONDS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .withZone(ZoneOffset.UTC);

    /**
     * Strict JSON reading: duplicate keys and trailing content are errors, and nothing non-standard
     * (comments, NaN, single quotes) is accepted.
     */
    private static final ObjectMapper STRICT_JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(JsonParser.Feature.AUTO_CLOSE_SOURCE)
            .build();

    private ProductMetricsModel() {
    }

    /** One reported transfer attempt: exactly the five closed fields. */
    public record Event(String mode, String path, String sizeBucket, String attempt, String outcome) {
        boolean valid() {
            if (!MODES.contains(mode) || !PATHS.contains(path) || !SIZE_BUCKETS.contains(sizeBucket)
                    || !ATTEMPTS.contains(attempt) || !OUTCOMES.contains(outcome)) {
                return false;
            }
            if ("link".equals(mode) && !"cloud".equals(path) && !"unestablished".equals(path)) {
                return false;
            }
            return !("success".equals(outcome) && "unestablished".equals(path));
        }
    }

    /** A validated ingest body, or the refusal code. */
    public record Ingest(List<Event> events, String refusal) {
    }

    /** A validated PUT /settings body; {@code disclosure} is the integer literal, or null when absent. */
    public record SettingsUpdate(boolean enabled, String disclosure) {
    }

    /** Bucket of a file size; an empty or negative size has none (the browser never reports one). */
    public static Optional<String> sizeBucket(long size) {
        if (size < 1) {
            return Optional.empty();
        }
        if (size < MIB) {
            return Optional.of("lt1m");
        }
        if (size < 16 * MIB) {
            return Optional.of("1m-16m");
        }
        if (size <= 128 * MIB) {
            return Optional.of("16m-128m");
        }
        if (size <= 512 * MIB) {
            return Optional.of("128m-512m");
        }
        return Optional.of("gt512m");
    }

    /** Completion-time bucket (negative counts as zero); none at or past the window. */
    public static Optional<String> durationBucket(long seconds) {
        long clamped = Math.max(0, seconds);
        for (int i = 0; i < DURATION_UPPER_BOUNDS.length; i++) {
            if (clamped < DURATION_UPPER_BOUNDS[i]) {
                return Optional.of(DURATION_BUCKETS.get(i));
            }
        }
        return Optional.empty();
    }

    /** numerator/denominator in basis points rounded half up; null without a denominator. */
    public static Long rateBp(long numerator, long denominator) {
        if (denominator == 0) {
            return null;
        }
        return Math.floorDiv(20_000L * numerator + denominator, 2 * denominator);
    }

    /**
     * Validates a transfer-outcome body against the closed schema of section 7.4. The size is
     * checked on the raw bytes before anything parses them; any extra, missing or duplicated key,
     * any value of the wrong JSON type and any trailing content refuses the whole request.
     */
    public static Ingest parseIngest(byte[] body) {
        if (body.length > MAX_BODY_BYTES) {
            return new Ingest(List.of(), CODE_TOO_LARGE);
        }
        JsonNode root = readStrict(body);
        if (root == null || !root.isObject() || root.size() != 2
                || !root.has("schemaVersion") || !root.has("events")) {
            return invalid();
        }
        JsonNode version = root.get("schemaVersion");
        if (!version.isIntegralNumber() || !version.canConvertToInt() || version.intValue() != SCHEMA_VERSION) {
            return invalid();
        }
        JsonNode events = root.get("events");
        if (!events.isArray() || events.isEmpty() || events.size() > MAX_EVENTS) {
            return invalid();
        }
        List<Event> parsed = new ArrayList<>(events.size());
        for (JsonNode node : events) {
            if (!node.isObject() || node.size() != EVENT_KEYS.size()) {
                return invalid();
            }
            for (Iterator<Map.Entry<String, JsonNode>> fields = node.fields(); fields.hasNext(); ) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (!EVENT_KEYS.contains(field.getKey()) || !field.getValue().isTextual()) {
                    return invalid();
                }
            }
            Event event = new Event(node.get("mode").textValue(), node.get("path").textValue(),
                    node.get("sizeBucket").textValue(), node.get("attempt").textValue(),
                    node.get("outcome").textValue());
            if (!event.valid()) {
                return invalid();
            }
            parsed.add(event);
        }
        return new Ingest(parsed, null);
    }

    /** Validates the closed PUT body: enabled (boolean, required), disclosureVersion (integer, optional). */
    public static Optional<SettingsUpdate> parseSettingsUpdate(byte[] body) {
        JsonNode root = readStrict(body);
        if (root == null || !root.isObject() || !root.has("enabled") || !root.get("enabled").isBoolean()) {
            return Optional.empty();
        }
        String disclosure = null;
        for (Iterator<String> names = root.fieldNames(); names.hasNext(); ) {
            String name = names.next();
            if (!"enabled".equals(name) && !"disclosureVersion".equals(name)) {
                return Optional.empty();
            }
        }
        if (root.has("disclosureVersion")) {
            JsonNode version = root.get("disclosureVersion");
            if (!version.isIntegralNumber()) {
                return Optional.empty();
            }
            disclosure = version.bigIntegerValue().toString();
        }
        return Optional.of(new SettingsUpdate(root.get("enabled").booleanValue(), disclosure));
    }

    private static JsonNode readStrict(byte[] body) {
        if (body.length == 0) {
            return null;
        }
        try {
            return STRICT_JSON.readTree(body);
        } catch (IOException invalid) {
            return null;
        }
    }

    private static Ingest invalid() {
        return new Ingest(List.of(), CODE_INVALID);
    }

    /** UTC calendar date of an epoch-millisecond instant. */
    public static String dayOf(long epochMillis) {
        return LocalDate.ofInstant(Instant.ofEpochMilli(epochMillis), ZoneOffset.UTC).toString();
    }

    /** An epoch-millisecond instant to the second, as the contract's examples spell it. */
    public static String instant(long epochMillis) {
        return INSTANT_SECONDS.format(Instant.ofEpochMilli(epochMillis));
    }
}
