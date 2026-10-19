package com.theshuai.specusserver.management.service;

import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

/** Persisted metadata across implementations; no locale guessing or loss of nanoseconds. */
final class PersistedClientSessionInstant {
    private PersistedClientSessionInstant() { }

    static Instant parse(String value) {
        if (value == null || value.length() < 19 || value.charAt(4) != '-' || value.charAt(7) != '-'
                || (value.charAt(10) != 'T' && value.charAt(10) != ' ')
                || value.charAt(13) != ':' || value.charAt(16) != ':') return null;
        int year = digits(value, 0, 4);
        if (year < 1) return null;
        int month = digits(value, 5, 2), day = digits(value, 8, 2);
        int hour = digits(value, 11, 2), minute = digits(value, 14, 2), second = digits(value, 17, 2);
        int position = 19, nanos = 0;
        if (position < value.length() && value.charAt(position) == '.') {
            position++;
            int count = 0;
            while (position < value.length() && value.charAt(position) >= '0' && value.charAt(position) <= '9') {
                if (count == 9) return null;
                nanos = nanos * 10 + value.charAt(position++) - '0';
                count++;
            }
            if (count == 0) return null;
            while (count++ < 9) nanos *= 10;
        }
        int offset = 0;
        if (value.charAt(10) == ' ') {
            if (position != value.length()) return null; // Historical SQL form is UTC, without a suffix.
        } else if (position + 1 != value.length() || value.charAt(position) != 'Z') {
            if (value.length() - position != 6 || (value.charAt(position) != '+' && value.charAt(position) != '-')
                    || value.charAt(position + 3) != ':') return null;
            int hours = digits(value, position + 1, 2), minutes = digits(value, position + 4, 2);
            if (hours < 0 || hours > 23 || minutes < 0 || minutes > 59) return null;
            offset = (hours * 60 + minutes) * 60;
            if (value.charAt(position) == '-') offset = -offset;
        }
        try {
            long seconds = LocalDateTime.of(year, month, day, hour, minute, second).toEpochSecond(ZoneOffset.UTC);
            return Instant.ofEpochSecond(seconds - offset, nanos);
        } catch (DateTimeException exception) {
            return null;
        }
    }

    private static int digits(String value, int start, int count) {
        int number = 0;
        for (int i = start; i < start + count; i++) {
            char digit = value.charAt(i);
            if (digit < '0' || digit > '9') return -1;
            number = number * 10 + digit - '0';
        }
        return number;
    }
}
