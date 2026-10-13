package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.model.ManagementUserView;
import com.theshuai.specusserver.management.repository.ManagementUserEmailRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ManagementUserServiceTests {
    private static final String ISSUER = "https://certus.devshuai.com";
    private ManagementUserRepository repository;
    private ManagementUserEmailRepository emailRepository;
    private ManagementUserService service;

    @BeforeEach
    void setUp() {
        repository = mock(ManagementUserRepository.class);
        emailRepository = mock(ManagementUserEmailRepository.class);
        AuthProperties properties = new AuthProperties();
        properties.setUsername("dungouji");
        properties.setPassword("built-in-password");
        properties.setTenantId("default");
        service = new ManagementUserService(repository, properties, null, mock(WorkbenchReferences.class),
                emailRepository);
        when(repository.save(any(ManagementUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(repository.saveAndFlush(any(ManagementUser.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void provisionsNewCertusIdentityAsLeastPrivilegedUser() {
        when(repository.findByOidcIdentityKey(any()))
                .thenReturn(Optional.empty());
        when(repository.findByTenantIdAndLoginNameNormalized("default", "new-user"))
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
        assertThat(saved.getUsername()).isNotEqualTo("new-user");
        assertThat(saved.getLoginName()).isEqualTo("new-user");
        assertThat(saved.getLoginNameNormalized()).isEqualTo("new-user");
        assertThat(saved.getOidcSubject()).isEqualTo("subject-new");
        assertThat(saved.getOidcIdentityKey()).matches("[0-9a-f]{64}");
        // An OIDC-provisioned account gets a hash of a random password nobody holds, so
        // password login can never succeed for it. It is a real hash, not a placeholder digest.
        assertThat(saved.getPasswordHash()).startsWith("$pbkdf2-sha256$v=1$i=");
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
        verify(repository, never()).findAllByUsernameIgnoreCase(any());
        verify(repository, never()).save(any());
    }

    @Test
    void linksEnabledImportedUserOnFirstCertusLogin() {
        ManagementUser existing = user("alice", ManagementRole.ADMIN, true);
        when(repository.findByOidcIdentityKey(any()))
                .thenReturn(Optional.empty());
        when(repository.findByTenantIdAndLoginNameNormalized("default", "alice"))
                .thenReturn(Optional.of(existing));
        when(repository.bindOidcIdentityIfUnbound(
                eq("alice"), eq(ISSUER), eq("subject-alice"), anyString(), anyString()))
                .thenAnswer(invocation -> {
                    existing.setOidcIssuer(invocation.getArgument(1));
                    existing.setOidcSubject(invocation.getArgument(2));
                    existing.setOidcIdentityKey(invocation.getArgument(3));
                    existing.setUpdatedAt(invocation.getArgument(4));
                    return 1;
                });
        when(repository.findById("alice")).thenReturn(Optional.of(existing));

        ManagementUserService.LoginUser login = service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-alice",
                "alice").orElseThrow();

        assertThat(login.role()).isEqualTo(ManagementRole.ADMIN);
        assertThat(existing.getOidcIssuer()).isEqualTo(ISSUER);
        assertThat(existing.getOidcSubject()).isEqualTo("subject-alice");
        assertThat(existing.getOidcIdentityKey()).matches("[0-9a-f]{64}");
        verify(repository).bindOidcIdentityIfUnbound(
                eq("alice"), eq(ISSUER), eq("subject-alice"), anyString(), anyString());
        verify(repository, never()).save(existing);
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
        when(repository.findByTenantIdAndLoginNameNormalized("default", "alice"))
                .thenReturn(Optional.of(conflicting));
        assertThat(service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-alice",
                "alice")).isEmpty();

        verify(repository, never()).save(any());
    }

    @Test
    void rejectsPreferredUsernameThatMatchesConfiguredBuiltInAdministrator() {
        assertThat(service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-dungouji",
                "dungouji")).isEmpty();
        verify(repository, never()).save(any());
    }

    @Test
    void conditionalBindingRejectsConcurrentDifferentIdentityWinner() {
        ManagementUser initiallyUnbound = user("alice", ManagementRole.ADMIN, true);
        ManagementUser winner = user("alice", ManagementRole.ADMIN, true);
        winner.setOidcIssuer(ISSUER);
        winner.setOidcSubject("other-subject");
        winner.setOidcIdentityKey(identityKey(ISSUER, "other-subject"));
        when(repository.findByOidcIdentityKey(identityKey(ISSUER, "subject-alice")))
                .thenReturn(Optional.empty());
        when(repository.findByTenantIdAndLoginNameNormalized("default", "alice"))
                .thenReturn(Optional.of(initiallyUnbound));
        when(repository.findById("alice")).thenReturn(Optional.of(winner));
        when(repository.bindOidcIdentityIfUnbound(
                eq("alice"), eq(ISSUER), eq("subject-alice"), anyString(), anyString()))
                .thenReturn(0);

        assertThat(service.resolveOrProvisionOidcUser(
                ISSUER,
                "subject-alice",
                "alice")).isEmpty();
    }

    @Test
    void resolvesOnlyEnabledExactBoundIdentityAndCurrentLocalRole() {
        ManagementUser bound = user("alice", ManagementRole.ADMIN, true);
        bound.setOidcIssuer(ISSUER);
        bound.setOidcSubject("subject-alice");
        bound.setOidcIdentityKey(identityKey(ISSUER, "subject-alice"));
        when(repository.findByOidcIdentityKey(bound.getOidcIdentityKey()))
                .thenReturn(Optional.of(bound));
        when(repository.findById("alice"))
                .thenReturn(Optional.of(bound));

        assertThat(service.resolveBoundOidcUser(ISSUER, "subject-alice"))
                .get()
                .extracting(ManagementUserService.LoginUser::role)
                .isEqualTo(ManagementRole.ADMIN);
        assertThat(service.resolveBoundOidcUser(ISSUER, "different-subject")).isEmpty();
        assertThat(service.resolveLocalTokenUser("alice"))
                .get()
                .extracting(ManagementUserService.LoginUser::role)
                .isEqualTo(ManagementRole.ADMIN);

        bound.setEnabled(false);
        assertThat(service.resolveBoundOidcUser(ISSUER, "subject-alice")).isEmpty();
        assertThat(service.resolveLocalTokenUser("alice")).isEmpty();
    }

    @Test
    void bareLegacyLoginFailsClosedWhenCaseInsensitiveAccountKeyIsAmbiguous() {
        ManagementUser tenantA = user("Alice", ManagementRole.USER, true);
        tenantA.setTenantId("tenant-a");
        ManagementUser tenantB = user("alice", ManagementRole.USER, true);
        tenantB.setTenantId("tenant-b");
        tenantA.setPasswordHash(PasswordService.hash("secret-password"));
        tenantB.setPasswordHash(PasswordService.hash("secret-password"));
        when(repository.findByTenantIdAndLoginNameNormalized("default", "alice"))
                .thenReturn(Optional.empty());
        when(repository.findAllByUsernameIgnoreCase("alice"))
                .thenReturn(List.of(tenantA, tenantB));

        assertThat(service.authenticate("alice", "secret-password")).isEmpty();
    }

    @Test
    void mutationLookupsAreTenantScopedAndDoNotRevealForeignUsers() {
        ManagementContext tenantAAdmin = new ManagementContext(new TenantContext("tenant-a"), "admin-a", true);
        when(repository.findByTenantIdAndLoginNameNormalized("tenant-a", "bob"))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.updateUser(tenantAAdmin, "bob",
                new ManagementUserService.UserMutation("bob", "new-password", ManagementRole.ADMIN, false)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("用户不存在: bob");
        assertThatThrownBy(() -> service.deleteUser(tenantAAdmin, "bob"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("用户不存在: bob");

        verify(repository, never()).findAllByUsernameIgnoreCase(any());
        verify(repository, never()).save(any());
        verify(repository, never()).delete(any());
    }

    @Test
    void updatesPasswordRoleEnabledAndDeletesInsideActingTenant() {
        ManagementUser bob = user("bob", ManagementRole.USER, true);
        bob.setTenantId("tenant-a");
        ManagementContext tenantAAdmin = new ManagementContext(new TenantContext("tenant-a"), "admin-a", true);
        when(repository.findByTenantIdAndLoginNameNormalized("tenant-a", "bob"))
                .thenReturn(Optional.of(bob));

        var view = service.updateUser(tenantAAdmin, "bob",
                new ManagementUserService.UserMutation("bob", "new-password", ManagementRole.ADMIN, false));

        assertThat(view.role()).isEqualTo(ManagementRole.ADMIN);
        assertThat(view.enabled()).isFalse();
        assertThat(PasswordService.matches("new-password", bob.getPasswordHash())).isTrue();

        service.deleteUser(tenantAAdmin, "bob");
        verify(repository).delete(bob);
        verify(emailRepository).deleteByAccountKey("bob");
    }

    @Test
    void deletingAnAccountReleasesItsEmailByAccountKey() {
        ManagementUser carol = user("4c1f5e0a-3b2d-4e6f-8a9b-0c1d2e3f4a5b", ManagementRole.USER, true);
        carol.setLoginName("Carol");
        carol.setLoginNameNormalized("carol");
        carol.setTenantId("tenant-a");
        ManagementContext tenantAAdmin = new ManagementContext(new TenantContext("tenant-a"), "admin-a", true);
        when(repository.findByTenantIdAndLoginNameNormalized("tenant-a", "carol"))
                .thenReturn(Optional.of(carol));

        assertThat(service.deleteUser(tenantAAdmin, "CAROL")).isEqualTo("Carol");

        // The email row is keyed by the account key, never by the login name.
        verify(emailRepository).deleteByAccountKey("4c1f5e0a-3b2d-4e6f-8a9b-0c1d2e3f4a5b");
        verify(emailRepository, never()).deleteByAccountKey("Carol");
        verify(repository).delete(carol);
    }

    @Test
    void localTokenWithAccountKeyResolvesOnlyThatAccountRow() {
        ManagementUser recreated = user("6d5c4b3a-2f1e-4d0c-9b8a-7f6e5d4c3b2a", ManagementRole.USER, true);
        recreated.setLoginName("alice");
        recreated.setLoginNameNormalized("alice");
        recreated.setTenantId("tenant-a");
        when(repository.findByTenantIdAndLoginNameNormalized("tenant-a", "alice"))
                .thenReturn(Optional.of(recreated));

        assertThat(service.resolveLocalTokenUser("alice", "tenant-a", "6d5c4b3a-2f1e-4d0c-9b8a-7f6e5d4c3b2a"))
                .get()
                .extracting(ManagementUserService.LoginUser::accountKey)
                .isEqualTo("6d5c4b3a-2f1e-4d0c-9b8a-7f6e5d4c3b2a");
        // The key of the deleted alice, or the right key spelled differently, resolves to no one.
        assertThat(service.resolveLocalTokenUser("alice", "tenant-a", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"))
                .isEmpty();
        assertThat(service.resolveLocalTokenUser("alice", "tenant-a", "6D5C4B3A-2F1E-4D0C-9B8A-7F6E5D4C3B2A"))
                .isEmpty();
        // Tokens issued before the claim existed resolve as before, until they expire.
        assertThat(service.resolveLocalTokenUser("alice", "tenant-a", null)).isPresent();
        assertThat(service.resolveLocalTokenUser("alice", "tenant-a", "")).isPresent();
    }

    @Test
    void localTokenWithAccountKeyIsNeverTheBuiltInAdministrator() {
        when(repository.findByTenantIdAndLoginNameNormalized("default", "dungouji"))
                .thenReturn(Optional.empty());

        assertThat(service.resolveLocalTokenUser("dungouji", "default", null))
                .get()
                .matches(ManagementUserService.LoginUser::builtInAdmin)
                .extracting(ManagementUserService.LoginUser::tokenAccountKey)
                .isNull();
        assertThat(service.resolveLocalTokenUser("dungouji", "default", "dungouji")).isEmpty();
    }

    @Test
    void listsTheBuiltInAdministratorOnlyInTheDefaultTenant() {
        ManagementUser dora = user("dora", ManagementRole.ADMIN, true);
        ManagementUser erin = user("erin", ManagementRole.ADMIN, true);
        erin.setTenantId("tenant-a");
        when(repository.findByTenantIdOrderByLoginNameAsc("default")).thenReturn(List.of(dora));
        when(repository.findByTenantIdOrderByLoginNameAsc("tenant-a")).thenReturn(List.of(erin));

        List<ManagementUserView> defaultTenant = service.listUsers(
                new ManagementContext(new TenantContext("default"), "dora", true));
        List<ManagementUserView> tenantA = service.listUsers(
                new ManagementContext(new TenantContext("tenant-a"), "erin", true));

        assertThat(defaultTenant).extracting(ManagementUserView::username).containsExactly("dungouji", "dora");
        assertThat(defaultTenant.getFirst().builtIn()).isTrue();
        assertThat(defaultTenant.getFirst().tenantId()).isEqualTo("default");
        assertThat(tenantA).extracting(ManagementUserView::username).containsExactly("erin");
        assertThat(tenantA).noneMatch(ManagementUserView::builtIn);
    }

    @Test
    void createsSameLoginNameInDifferentTenantWithoutGlobalLookup() {
        ManagementContext tenantAAdmin = new ManagementContext(new TenantContext("tenant-a"), "admin-a", true);
        when(repository.existsByTenantIdAndLoginNameNormalized("tenant-a", "bob")).thenReturn(false);

        ManagementUserService.UserMutation request = new ManagementUserService.UserMutation(
                "Bob", "secret-password", ManagementRole.USER, true);
        var created = service.createUser(tenantAAdmin, request);

        assertThat(created.username()).isEqualTo("Bob");
        assertThat(created.tenantId()).isEqualTo("tenant-a");
        ArgumentCaptor<ManagementUser> captor = ArgumentCaptor.forClass(ManagementUser.class);
        verify(repository).saveAndFlush(captor.capture());
        assertThat(captor.getValue().getUsername()).matches("[0-9a-f-]{36}");
        assertThat(captor.getValue().getLoginNameNormalized()).isEqualTo("bob");
        verify(repository, never()).findAllByUsernameIgnoreCase(anyString());
    }

    private ManagementUser user(String username, ManagementRole role, boolean enabled) {
        ManagementUser user = new ManagementUser();
        user.setUsername(username);
        user.setLoginName(username);
        user.setLoginNameNormalized(username.toLowerCase(java.util.Locale.ROOT));
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
