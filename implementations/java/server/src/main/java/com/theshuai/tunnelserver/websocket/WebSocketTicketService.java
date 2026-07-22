package com.theshuai.tunnelserver.websocket;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.common.security.HmacSigner;
import com.theshuai.tunnelserver.management.model.WebSocketTicket;
import com.theshuai.tunnelserver.management.repository.WebSocketTicketRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;

@Service
public class WebSocketTicketService {
    public static final long TTL_SECONDS = 45;

    private static final TypeReference<Map<String, Object>> ATTRIBUTES_TYPE = new TypeReference<>() { };
    private final WebSocketTicketRepository repository;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();
    private final SecureRandom secureRandom = new SecureRandom();

    public WebSocketTicketService(WebSocketTicketRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public IssuedTicket issue(Scope scope, Map<String, Object> attributes, String remoteAddress) {
        Instant now = Instant.now();
        repository.deleteExpired(now.toString());
        byte[] random = new byte[32];
        secureRandom.nextBytes(random);
        String rawTicket = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        WebSocketTicket entity = new WebSocketTicket();
        entity.setTokenHash(hash(rawTicket));
        entity.setScope(scope.wireName());
        entity.setAttributesJson(writeAttributes(attributes));
        entity.setRemoteAddressHash(StringUtils.hasText(remoteAddress) ? hash(remoteAddress.trim()) : null);
        entity.setCreatedAt(now.toString());
        entity.setExpiresAt(now.plusSeconds(TTL_SECONDS).toString());
        repository.save(entity);
        return new IssuedTicket(rawTicket, entity.getExpiresAt());
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Optional<Map<String, Object>> consume(Scope scope, String rawTicket, String remoteAddress) {
        if (!StringUtils.hasText(rawTicket) || rawTicket.length() > 256) {
            return Optional.empty();
        }
        String tokenHash = hash(rawTicket.trim());
        WebSocketTicket entity = repository.findById(tokenHash).orElse(null);
        if (entity == null || !scope.wireName().equals(entity.getScope())) {
            return Optional.empty();
        }
        if (StringUtils.hasText(entity.getRemoteAddressHash())) {
            if (!StringUtils.hasText(remoteAddress)
                    || !entity.getRemoteAddressHash().equals(hash(remoteAddress.trim()))) {
                return Optional.empty();
            }
        }
        if (repository.consume(tokenHash, scope.wireName(), Instant.now().toString()) != 1) {
            return Optional.empty();
        }
        return Optional.of(readAttributes(entity.getAttributesJson()));
    }

    private String writeAttributes(Map<String, Object> attributes) {
        try {
            return objectMapper.writeValueAsString(Map.copyOf(attributes));
        } catch (Exception exception) {
            throw new IllegalArgumentException("invalid WebSocket ticket attributes", exception);
        }
    }

    private Map<String, Object> readAttributes(String json) {
        try {
            return objectMapper.readValue(json, ATTRIBUTES_TYPE);
        } catch (Exception exception) {
            throw new IllegalStateException("stored WebSocket ticket is invalid", exception);
        }
    }

    private static String hash(String value) {
        return HexFormat.of().formatHex(HmacSigner.sha256(value));
    }

    public enum Scope {
        CONNECTIONS("connections"),
        CLIENT_MESSAGES("client-messages"),
        PUBLIC_TRANSFER("public-transfer");

        private final String wireName;

        Scope(String wireName) {
            this.wireName = wireName;
        }

        public String wireName() {
            return wireName;
        }

        public static Scope adminEndpoint(String endpoint) {
            return switch (endpoint == null ? "" : endpoint.trim()) {
                case "connections" -> CONNECTIONS;
                case "client-messages" -> CLIENT_MESSAGES;
                default -> throw new IllegalArgumentException("unsupported WebSocket endpoint");
            };
        }
    }

    public record IssuedTicket(String ticket, String expiresAt) { }
}
