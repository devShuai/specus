package com.theshuai.specusserver.connectivity;

import com.theshuai.specusserver.management.security.ManagementContext;

import java.util.Optional;

/** The server records a connectivity check reads before it touches the device. */
public interface ConnectivityCheckTargets {
    /**
     * The route as the caller may see it: same tenant, and the caller is an admin or owns the
     * route's client. Empty when the route does not exist or is not visible, so both answer alike.
     *
     * @throws RuntimeException when the route or its client cannot be read; the check then answers
     *                          {@code 503 CHECK_UNAVAILABLE}, never "not configured"
     */
    Optional<Target> findVisible(ManagementContext caller, long routeId);

    /**
     * What the {@code configured} stage judges, and where the probe goes.
     *
     * @param route        the route name the client knows the route by
     * @param clientName   the name the client's NAT sessions are bound to
     * @param targetValid  whether the stored targetBaseUrl still passes the save-time validation
     */
    record Target(long routeId,
                  String tenantId,
                  String route,
                  String clientName,
                  boolean routeEnabled,
                  boolean clientEnabled,
                  boolean targetValid) {
    }
}
