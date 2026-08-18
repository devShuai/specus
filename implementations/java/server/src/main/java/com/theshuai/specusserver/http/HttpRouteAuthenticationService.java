package com.theshuai.specusserver.http;

import com.theshuai.specusserver.management.model.ClientAccount;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.service.ClientAccountService;
import com.theshuai.specusserver.security.PasswordService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;

/**
 * Resolves and verifies route-scoped HTTP Basic credentials for both HTTP and WebSocket ingress.
 * Routes that are not managed in the database remain public for compatibility with legacy
 * client-local route configuration. Database failures and malformed managed configuration fail
 * closed instead of silently turning a protected route public.
 */
@Service
@Slf4j
public class HttpRouteAuthenticationService {
    public static final String BASIC_CHALLENGE = "Basic realm=\"Specus HTTP Route\", charset=\"UTF-8\"";

    private final ClientAccountService clientAccountService;
    private final HttpRouteMappingRepository routeRepository;

    public HttpRouteAuthenticationService(ClientAccountService clientAccountService,
                                          HttpRouteMappingRepository routeRepository) {
        this.clientAccountService = clientAccountService;
        this.routeRepository = routeRepository;
    }

    public Decision authorize(String clientName, String route, String authorization) {
        try {
            Optional<ClientAccount> account = clientAccountService.findClientByName(clientName);
            if (account.isEmpty()) {
                return Decision.publicRoute();
            }
            Optional<HttpRouteMapping> mapping = routeRepository.findByTenantIdAndClientIdAndRoute(
                    account.get().getTenantId(), account.get().getId(), route);
            if (mapping.isEmpty()) {
                return Decision.publicRoute();
            }
            HttpRouteMapping managedRoute = mapping.get();
            if (!managedRoute.isEnabled()) {
                return Decision.notFound();
            }
            if (!Boolean.TRUE.equals(managedRoute.getAuthEnabled())) {
                return Decision.publicRoute();
            }
            if (!StringUtils.hasText(managedRoute.getAuthUsername())
                    || !isSha256Hex(managedRoute.getAuthPasswordHash())) {
                log.error("[http-route-auth] protected route is missing credentials clientName={} route={}",
                        clientName, route);
                return Decision.unavailable();
            }
            Credentials credentials = decodeBasic(authorization);
            if (credentials == null) {
                return Decision.unauthorized();
            }
            boolean usernameMatches = constantTimeEquals(managedRoute.getAuthUsername(), credentials.username());
            boolean passwordMatches = PasswordService.tokenMatches(
                    credentials.password(), managedRoute.getAuthPasswordHash());
            return usernameMatches & passwordMatches
                    ? Decision.authenticated()
                    : Decision.unauthorized();
        } catch (RuntimeException error) {
            log.error("[http-route-auth] lookup failed clientName={} route={} error={}",
                    clientName, route, error.toString(), error);
            return Decision.unavailable();
        }
    }

    private Credentials decodeBasic(String authorization) {
        if (!StringUtils.hasText(authorization)
                || authorization.length() <= 6
                || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(authorization.substring(6).trim());
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(decoded))
                    .toString();
            int separator = value.indexOf(':');
            if (separator < 1) {
                return null;
            }
            return new Credentials(value.substring(0, separator), value.substring(separator + 1));
        } catch (IllegalArgumentException | CharacterCodingException ignored) {
            return null;
        }
    }

    private boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                sha256(expected),
                sha256(actual));
    }

    private byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("SHA-256 is unavailable", error);
        }
    }

    private static boolean isSha256Hex(String value) {
        if (value == null || value.length() != 64) {
            return false;
        }
        for (int index = 0; index < value.length(); index++) {
            if (Character.digit(value.charAt(index), 16) < 0) {
                return false;
            }
        }
        return true;
    }

    public enum Outcome {
        PUBLIC,
        AUTHENTICATED,
        UNAUTHORIZED,
        NOT_FOUND,
        UNAVAILABLE
    }

    public record Decision(Outcome outcome) {
        static Decision publicRoute() {
            return new Decision(Outcome.PUBLIC);
        }

        static Decision authenticated() {
            return new Decision(Outcome.AUTHENTICATED);
        }

        static Decision unauthorized() {
            return new Decision(Outcome.UNAUTHORIZED);
        }

        static Decision notFound() {
            return new Decision(Outcome.NOT_FOUND);
        }

        static Decision unavailable() {
            return new Decision(Outcome.UNAVAILABLE);
        }

        public boolean allowed() {
            return outcome == Outcome.PUBLIC || outcome == Outcome.AUTHENTICATED;
        }

        public boolean credentialsConsumed() {
            return outcome == Outcome.AUTHENTICATED;
        }
    }

    private record Credentials(String username, String password) {
    }
}
