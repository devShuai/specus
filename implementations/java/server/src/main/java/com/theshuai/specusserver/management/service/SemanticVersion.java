package com.theshuai.specusserver.management.service;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Strict SemVer 2.0 parser/comparator used by the server-side update decision. */
final class SemanticVersion implements Comparable<SemanticVersion> {
    private static final Pattern PATTERN = Pattern.compile(
            "^(0|[1-9]\\d*)\\.(0|[1-9]\\d*)\\.(0|[1-9]\\d*)"
                    + "(?:-([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?"
                    + "(?:\\+([0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*))?$"
    );
    private static final Pattern NUMERIC = Pattern.compile("0|[1-9]\\d*");

    private final BigInteger major;
    private final BigInteger minor;
    private final BigInteger patch;
    private final List<Identifier> preRelease;

    private SemanticVersion(BigInteger major, BigInteger minor, BigInteger patch,
                            List<Identifier> preRelease) {
        this.major = major;
        this.minor = minor;
        this.patch = patch;
        this.preRelease = List.copyOf(preRelease);
    }

    static SemanticVersion parse(String value, String fieldName) {
        String normalized = normalize(value);
        if (normalized.length() > 32) {
            throw new IllegalArgumentException(fieldName + " is too long (max 32)");
        }
        Matcher matcher = PATTERN.matcher(normalized);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(fieldName + " must be a valid SemVer 2.0 version");
        }
        List<Identifier> identifiers = new ArrayList<>();
        if (matcher.group(4) != null) {
            for (String part : matcher.group(4).split("\\.")) {
                if (part.chars().allMatch(Character::isDigit) && !NUMERIC.matcher(part).matches()) {
                    throw new IllegalArgumentException(fieldName
                            + " contains a numeric pre-release identifier with a leading zero");
                }
                identifiers.add(new Identifier(part, part.chars().allMatch(Character::isDigit)));
            }
        }
        return new SemanticVersion(new BigInteger(matcher.group(1)),
                new BigInteger(matcher.group(2)), new BigInteger(matcher.group(3)), identifiers);
    }

    /** Canonical storage form: trim whitespace and remove at most one optional lowercase {@code v}. */
    static String normalize(String value) {
        String normalized = value == null ? "" : value.trim();
        return normalized.startsWith("v") ? normalized.substring(1) : normalized;
    }

    @Override
    public int compareTo(SemanticVersion other) {
        int result = major.compareTo(other.major);
        if (result == 0) {
            result = minor.compareTo(other.minor);
        }
        if (result == 0) {
            result = patch.compareTo(other.patch);
        }
        if (result != 0) {
            return result;
        }
        if (preRelease.isEmpty() && other.preRelease.isEmpty()) {
            return 0;
        }
        if (preRelease.isEmpty() || other.preRelease.isEmpty()) {
            return preRelease.isEmpty() ? 1 : -1;
        }
        int common = Math.min(preRelease.size(), other.preRelease.size());
        for (int index = 0; index < common; index++) {
            result = preRelease.get(index).compareTo(other.preRelease.get(index));
            if (result != 0) {
                return result;
            }
        }
        return Integer.compare(preRelease.size(), other.preRelease.size());
    }

    private record Identifier(String value, boolean numeric) implements Comparable<Identifier> {
        private Identifier {
            Objects.requireNonNull(value);
        }

        @Override
        public int compareTo(Identifier other) {
            if (numeric && other.numeric) {
                return new BigInteger(value).compareTo(new BigInteger(other.value));
            }
            if (numeric != other.numeric) {
                return numeric ? -1 : 1;
            }
            return value.compareTo(other.value);
        }
    }
}
