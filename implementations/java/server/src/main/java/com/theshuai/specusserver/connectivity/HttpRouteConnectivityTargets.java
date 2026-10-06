package com.theshuai.specusserver.connectivity;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.service.HttpRouteService;
import org.springframework.stereotype.Component;

import java.util.Optional;

/** Route and client records from the database, with the visibility of the route management API. */
@Component
public class HttpRouteConnectivityTargets implements ConnectivityCheckTargets {
    private final HttpRouteService httpRouteService;
    private final ClientAccountRepository clientAccountRepository;

    public HttpRouteConnectivityTargets(HttpRouteService httpRouteService,
                                        ClientAccountRepository clientAccountRepository) {
        this.httpRouteService = httpRouteService;
        this.clientAccountRepository = clientAccountRepository;
    }

    @Override
    public Optional<Target> findVisible(ManagementContext caller, long routeId) {
        Optional<HttpRouteMapping> visible = httpRouteService.findVisibleRoute(caller, routeId);
        if (visible.isEmpty()) {
            return Optional.empty();
        }
        HttpRouteMapping route = visible.get();
        Optional<ClientAccount> account = route.getClientId() == null ? Optional.empty()
                : clientAccountRepository.findByIdAndTenantId(route.getClientId(), caller.tenant().tenantId());
        // A route whose client is gone has nothing to check, the same as no route.
        return account.map(client -> new Target(
                route.getId(),
                caller.tenant().tenantId(),
                route.getRoute(),
                client.getClientName(),
                route.isEnabled(),
                client.isEnabled(),
                HttpRouteService.isValidTargetBaseUrl(route.getTargetBaseUrl())));
    }
}
