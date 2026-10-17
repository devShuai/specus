package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ClientAuthProperties;
import com.theshuai.specusserver.management.model.ClientCredential;
import com.theshuai.specusserver.management.repository.ClientCredentialRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.security.ManagementWriteAuthority;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
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
    private final ManagementWriteAuthority authority;

    public ClientCredentialService(ClientCredentialRepository repository,
                                   ClientAuthProperties properties,
                                   ManagementWriteAuthority authority) {
        this.repository = repository;
        this.properties = properties;
        this.authority = authority;
    }

    @Transactional(readOnly = true)
    public List<ClientCredentialView> list(TenantContext tenant) {
        return repository.findByTenantIdOrderByIdDesc(tenant.tenantId()).stream()
                .map(ClientCredentialService::toView)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<ClientCredentialView> list(ManagementContext context) {
        List<ClientCredential> credentials = context.isAdmin()
                ? repository.findByTenantIdOrderByIdDesc(context.tenant().tenantId())
                : repository.findByTenantIdAndOwnerUsernameOrderByIdDesc(context.tenant().tenantId(), context.username());
        return credentials.stream().map(ClientCredentialService::toView).toList();
    }

    @Transactional
    public CredentialResult create(TenantContext tenant, CredentialMutation request) {
        authority.reserveWriter();
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
        credential.setSecretHash(PasswordService.hashToken(secret));
        credential.setEnabled(request.enabled() == null || request.enabled());
        credential.setMaxOnlineInstances(normalizeMaxOnline(request.maxOnlineInstances()));
        credential.setCreatedAt(now);
        credential.setUpdatedAt(now);
        return new CredentialResult(toView(repository.save(credential)), secret);
    }

    @Transactional
    public CredentialResult create(ManagementContext context, CredentialMutation request) {
        context = authority.current(context);
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
        credential.setTenantId(context.tenant().tenantId());
        credential.setOwnerUsername(context.username());
        credential.setApiKey(apiKey);
        credential.setSecretHash(PasswordService.hashToken(secret));
        credential.setEnabled(request.enabled() == null || request.enabled());
        credential.setMaxOnlineInstances(normalizeMaxOnline(request.maxOnlineInstances()));
        credential.setCreatedAt(now);
        credential.setUpdatedAt(now);
        return new CredentialResult(toView(repository.save(credential)), secret);
    }

    @Transactional
    public CredentialResult update(TenantContext tenant, long id, CredentialMutation request) {
        ClientCredential credential = repository.lockCurrent(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("credential not found: " + id));
        return updateCredential(credential, request);
    }

    @Transactional
    public CredentialResult update(ManagementContext context, long id, CredentialMutation request) {
        context = authority.current(context);
        ClientCredential credential = findCredential(context, id);
        return updateCredential(credential, request);
    }

    private CredentialResult updateCredential(ClientCredential credential, CredentialMutation request) {
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
            credential.setSecretHash(PasswordService.hashToken(revealedSecret));
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
        ClientCredential credential = repository.lockCurrent(id, tenant.tenantId())
                .orElseThrow(() -> new IllegalArgumentException("credential not found: " + id));
        repository.delete(credential);
    }

    @Transactional
    public void delete(ManagementContext context, long id) {
        context = authority.current(context);
        repository.delete(findCredential(context, id));
    }

    private ClientCredential findCredential(ManagementContext context, long id) {
        return repository.lockCurrent(id, context.tenant().tenantId())
                .filter(credential -> context.isAdmin() || context.username().equals(credential.getOwnerUsername()))
                .orElseThrow(() -> new IllegalArgumentException("credential not found: " + id));
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
                credential.getOwnerUsername(),
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
            String ownerUsername,
            boolean enabled,
            int maxOnlineInstances,
            String createdAt,
            String updatedAt
    ) {
    }

    public record CredentialResult(ClientCredentialView credential, String secret) {
    }
}
