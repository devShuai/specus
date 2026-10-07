package com.theshuai.specusserver.management.model;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

/**
 * Fixed-width text form for instants that queries compare as strings.
 *
 * <p>{@link Instant#toString()} drops a zero fraction and otherwise prints 3, 6 or 9 digits, so
 * {@code 12:00:00.500Z} sorts before {@code 12:00:00Z} ('.' &lt; 'Z') and a text comparison is up to
 * a second wrong inside one second. Always seven fraction digits and a trailing 'Z' make the text
 * order the time order on every database, and the value stays an ISO-8601 instant that
 * {@link Instant#parse} reads back. It is the form the Go ({@code isoLayout}) and .NET
 * ({@code IsoDateTimeOffsetConverter}) servers store; digits below 100 ns are truncated.
 */
public final class SortableInstant {
    /** Length of every formatted value, e.g. {@code 2026-09-15T12:00:00.5000000Z}. */
    public static final int LENGTH = 28;

    private static final DateTimeFormatter FORMAT =
            DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSSSSSS'Z'").withZone(ZoneOffset.UTC);

    private SortableInstant() {
    }

    public static String format(Instant instant) {
        return FORMAT.format(instant);
    }

    /** Rewrites any ISO-8601 instant, including the variable-width {@link Instant#toString()} form. */
    public static String normalize(String instant) {
        return format(Instant.parse(instant));
    }
}
