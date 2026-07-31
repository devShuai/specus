package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ManagementUserServiceTests {
    private static final String ISSUER = "https://certus.devshuai.com";
    private ManagementUserRepository repository;
    private ManagementUserService service;

    @BeforeEach
    void setUp() {
        repository = mock(ManagementUserRepository.class);
        AuthProperties properties = new AuthProperties();
        properties.setUsername("dungouji");
        properties.setTenantId("default");
        service = new ManagementUserService(repository, properties);
        when(repository.save(any(ManagementUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void provisionsNewCertusIdentityAsLeastPrivilegedUser() {
        when(repository.findByOidcIdentityKey(any()))
                .thenReturn(Optional.empty());
        when(repository.findByUsernameIgnoreCase("new-user"))
                .thenReturn(Optional.empty());

        ManagementUserService.LoginUser login = service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-new",
                "new-user").orElseThrow();

        assertThat(login.username()).isEqualTo("new-user");
        assertThat(login.tenantId()).isEqualTo("default");
        assertThat(login.role()).isEqualTo(ManagementRole.USER);
        assertThat(login.builtInAdmin()).isFalse();

        ArgumentCaptor<ManagementUser> captor = ArgumentCaptor.forClass(ManagementUser.class);
        verify(repository).save(captor.capture());
        ManagementUser saved = captor.getValue();
        assertThat(saved.getOidcIssuer()).isEqualTo(ISSUER);
        assertThat(saved.getOidcSubject()).isEqualTo("subject-new");
        assertThat(saved.getOidcIdentityKey()).matches("[0-9a-f]{64}");
        assertThat(saved.getPasswordHash()).matches("[0-9a-f]{64}");
        assertThat(saved.isEnabled()).isTrue();
        assertThat(saved.getCreatedAt()).isNotBlank();
        assertThat(saved.getUpdatedAt()).isEqualTo(saved.getCreatedAt());
    }

    @Test
    void immutableSubjectKeepsExistingSpecusUsernameAfterCertusRename() {
        ManagementUser mapped = user("alice", ManagementRole.USER, true);
        mapped.setOidcIssuer(ISSUER);
        mapped.setOidcSubject("subject-alice");
        mapped.setOidcIdentityKey(identityKey(ISSUER, "subject-alice"));
        when(repository.findByOidcIdentityKey(mapped.getOidcIdentityKey()))
                .thenReturn(Optional.of(mapped));

        ManagementUserService.LoginUser login = service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-alice",
                "alice-renamed").orElseThrow();

        assertThat(login.username()).isEqualTo("alice");
        verify(repository, never()).findByUsernameIgnoreCase(any());
        verify(repository, never()).save(any());
    }

    @Test
    void linksEnabledImportedUserOnFirstCertusLogin() {
        ManagementUser existing = user("alice", ManagementRole.ADMIN, true);
        when(repository.findByOidcIdentityKey(any()))
                .thenReturn(Optional.empty());
        when(repository.findByUsernameIgnoreCase("alice"))
                .thenReturn(Optional.of(existing));

        ManagementUserService.LoginUser login = service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-alice",
                "alice").orElseThrow();

        assertThat(login.role()).isEqualTo(ManagementRole.ADMIN);
        assertThat(existing.getOidcIssuer()).isEqualTo(ISSUER);
        assertThat(existing.getOidcSubject()).isEqualTo("subject-alice");
        assertThat(existing.getOidcIdentityKey()).matches("[0-9a-f]{64}");
        verify(repository).save(existing);
    }

    @Test
    void rejectsDisabledOrConflictingExistingUser() {
        ManagementUser disabled = user("disabled", ManagementRole.USER, false);
        disabled.setOidcIdentityKey(identityKey(ISSUER, "subject-disabled"));
        when(repository.findByOidcIdentityKey(disabled.getOidcIdentityKey()))
                .thenReturn(Optional.of(disabled));
        assertThat(service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-disabled",
                "disabled")).isEmpty();

        ManagementUser conflicting = user("alice", ManagementRole.USER, true);
        conflicting.setOidcIssuer(ISSUER);
        conflicting.setOidcSubject("other-subject");
        conflicting.setOidcIdentityKey(identityKey(ISSUER, "other-subject"));
        when(repository.findByOidcIdentityKey(identityKey(ISSUER, "subject-alice")))
                .thenReturn(Optional.empty());
        when(repository.findByUsernameIgnoreCase("alice"))
                .thenReturn(Optional.of(conflicting));
        assertThat(service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-alice",
                "alice")).isEmpty();

        verify(repository, never()).save(any());
    }

    @Test
    void retainsConfiguredBuiltInAdministratorMapping() {
        ManagementUserService.LoginUser login = service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-dungouji",
                "dungouji").orElseThrow();

        assertThat(login.role()).isEqualTo(ManagementRole.ADMIN);
        assertThat(login.builtInAdmin()).isTrue();
        verify(repository, never()).save(any());
    }

    private ManagementUser user(String username, ManagementRole role, boolean enabled) {
        ManagementUser user = new ManagementUser();
        user.setUsername(username);
        user.setTenantId("default");
        user.setPasswordHash("0".repeat(64));
        user.setRole(role);
        user.setEnabled(enabled);
        user.setCreatedAt("2026-07-31T00:00:00Z");
        user.setUpdatedAt("2026-07-31T00:00:00Z");
        return user;
    }

    private String identityKey(String issuer, String subject) {
        try {
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            digest.update(issuer.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            digest.update((byte) 0);
            digest.update(subject.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest.digest());
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
