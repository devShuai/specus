package com.theshuai.specusserver.session;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * {@code environment.clientHttpRouteCapabilities.version} as each client session announced it at its
 * HTTP login, keyed by the client session id that the session's NAT control and data connections
 * carry ({@code ServerAttributes.CLIENT_SESSION_ID}).
 *
 * <p>The connectivity check trusts the {@code failure} of an HTTP route RST only from a session that
 * announced version 1 or more (protocol/spec/service-connectivity-check.md section 6). The value only
 * matters while that session is connected, so it lives in memory beside the session routing table
 * instead of in the session table. A session the server does not remember, for example one that
 * reconnects with its token after a server restart, reads as version 0: its resets are reported as
 * unverified, never as a guessed failure.
 */
@Component
@Slf4j
public class ClientHttpRouteCapabilities {
    static final int MAX_SESSIONS = 100_000;

    private final Map<Long, Announcement> announcements = new ConcurrentHashMap<>();
    private final int maxSessions;

    public ClientHttpRouteCapabilities() {
        this(MAX_SESSIONS);
    }

    ClientHttpRouteCapabilities(int maxSessions) {
        this.maxSessions = maxSessions;
    }

    /**
     * Keeps what a session announced at login. Absent or negative reads as 0, which is not stored:
     * an unknown session already reads as 0. Sessions whose token expired make room for new ones;
     * when the table is still full the announcement is not kept and the session reads as 0.
     */
    public void remember(Long clientSessionId, int announcedVersion, Instant expiresAt) {
        if (clientSessionId == null) {
            return;
        }
        int version = Math.max(0, announcedVersion);
        if (version == 0) {
            announcements.remove(clientSessionId);
            return;
        }
        if (announcements.size() >= maxSessions && !announcements.containsKey(clientSessionId)) {
            Instant now = Instant.now();
            announcements.values().removeIf(entry -> entry.expiresAt() != null && !entry.expiresAt().isAfter(now));
            if (announcements.size() >= maxSessions) {
                log.warn("HTTP route capability table is full ({} sessions); session {} reads as version 0",
                        maxSessions, clientSessionId);
                return;
            }
        }
        announcements.put(clientSessionId, new Announcement(version, expiresAt));
    }

    /** The version the session announced, or 0 when it announced none or is not known. */
    public int versionOf(Long clientSessionId) {
        if (clientSessionId == null) {
            return 0;
        }
        Announcement announcement = announcements.get(clientSessionId);
        return announcement == null ? 0 : announcement.version();
    }

    private record Announcement(int version, Instant expiresAt) {
    }
}
