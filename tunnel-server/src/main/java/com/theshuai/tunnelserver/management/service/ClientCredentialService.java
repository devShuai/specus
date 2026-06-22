package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.ClientAuthProperties;
import com.theshuai.tunnelserver.management.model.ClientCredential;
import com.theshuai.tunnelserver.management.repository.ClientCredentialRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import com.theshuai.tunnelserver.security.PasswordService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

@Service
public class ClientCredentialService {
    private final ClientCredentialRepository repository;
    private final ClientAuthProperties properties;

    public ClientCredentialService(ClientCredentialRepository repository,
                                   ClientAuthProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    @Transactional(readOnly = true)
    public List<ClientCredentialView> list(TenantContext tenant) {
        return repository.findByTenantIdOrderByIdDesc(tenant.tenantId()).stream()
                .map(ClientCredentialService::toView)
                .toList();
    }

    @Transactional
    public CredentialResult create(TenantContext tenant, CredentialMutation request) {
        String apiKey = StringUtils.hasText(request.apiKey())
                ? normalizeApiKey(request.apiKey())
                : "ck_" + UUID.randomUUID().toString().replace("-", "");
        repository.findByApiKey(apiKey).ifPresent(existing -> {
            throw new IllegalArgumentException("apiKey already exists");
        });
        String secret = StringUtils.hasText(request.secret())
                ? request.secret().trim()
                : PasswordService.generatePassword();
        String now = Instant.now().toString();
        ClientCredential credential = new ClientCredential();
        credential.setId(ClientIdGenerator.newId());
        credential.setTenantId(tenant.tenantId());
        credential.setApiKey(apiKey);
        credential.setSecretHash(PasswordService.hash(secret));
        credential.setEnabled(request.enabled() == null || request.enabled());
        credential.setMaxOnlineInstances(normalizeMaxOnline(request.maxOnlineInstances()));
        credential.setCreatedAt(now);
        credential.setUpdatedAt(now);
        return new CredentialResult(toView(repository.save(credential)), secret);
    }

    @Transactional
    public CredentialResult update(TenantContext tenant, long id, CredentialMutation request) {
        ClientCredential credential = repository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("credential not found: " + id));
        if (StringUtils.hasText(request.apiKey())) {
            String apiKey = normalizeApiKey(request.apiKey());
            if (!apiKey.equals(credential.getApiKey())) {
                repository.findByApiKey(apiKey).ifPresent(existing -> {
                    throw new IllegalArgumentException("apiKey already exists");
                });
                credential.setApiKey(apiKey);
            }
        }
        String revealedSecret = null;
        if (StringUtils.hasText(request.secret())) {
            revealedSecret = request.secret().trim();
            credential.setSecretHash(PasswordService.hash(revealedSecret));
        }
        if (request.enabled() != null) {
            credential.setEnabled(request.enabled());
        }
        if (request.maxOnlineInstances() != null) {
            credential.setMaxOnlineInstances(normalizeMaxOnline(request.maxOnlineInstances()));
        }
        credential.setUpdatedAt(Instant.now().toString());
        return new CredentialResult(toView(repository.save(credential)), revealedSecret);
    }

    @Transactional
    public void delete(TenantContext tenant, long id) {
        ClientCredential credential = repository.findByIdAndTenantId(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("credential not found: " + id));
        repository.delete(credential);
    }

    private int normalizeMaxOnline(Integer value) {
        int normalized = value == null ? properties.getDefaultMaxOnlineInstances() : value;
        if (normalized < 1 || normalized > 10000) {
            throw new IllegalArgumentException("maxOnlineInstances must be between 1 and 10000");
        }
        return normalized;
    }

    private String normalizeApiKey(String value) {
        String normalized = value.trim();
        if (normalized.length() < 3 || normalized.length() > 120) {
            throw new IllegalArgumentException("apiKey length must be between 3 and 120");
        }
        return normalized;
    }

    private static ClientCredentialView toView(ClientCredential credential) {
        return new ClientCredentialView(
                credential.getId(),
                credential.getApiKey(),
                credential.isEnabled(),
                credential.getMaxOnlineInstances(),
                credential.getCreatedAt(),
                credential.getUpdatedAt()
        );
    }

    public record CredentialMutation(
            String apiKey,
            String secret,
            Boolean enabled,
            Integer maxOnlineInstances
    ) {
    }

    public record ClientCredentialView(
            long id,
            String apiKey,
            boolean enabled,
            int maxOnlineInstances,
            String createdAt,
            String updatedAt
    ) {
    }

    public record CredentialResult(ClientCredentialView credential, String secret) {
    }
}
