package com.theshuai.tunnelserver.management.repository;

/**
 * Projection produced by the connection-record monthly aggregation query. {@code month} is the
 * {@code yyyy-MM} the rows were grouped by; {@code total} and {@code success} are counts.
 */
public record ConnectionStatRow(Long clientId, String clientName, String month, Long total, Long success) {
}
