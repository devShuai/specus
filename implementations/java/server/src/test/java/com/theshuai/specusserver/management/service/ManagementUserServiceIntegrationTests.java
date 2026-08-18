package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.model.ManagementUser;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-management-users?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.auth.username=built-in-admin",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false"
        }
)
class ManagementUserServiceIntegrationTests {
    private static final String ISSUER = "https://certus.devshuai.com";

    @Autowired private ManagementUserService service;
    @Autowired private ManagementUserRepository repository;

    @AfterEach
    void tearDown() {
        repository.deleteAll();
    }

    @Test
    void persistsOidcBindingAndReusesItAfterUsernameChanges() {
        ManagementUserService.LoginUser first = service.resolveOrProvisionOidcUser(
                ISSUER,
                "immutable-subject",
                "first-name").orElseThrow();
        ManagementUserService.LoginUser renamed = service.resolveOrProvisionOidcUser(
                ISSUER,
                "immutable-subject",
                "renamed-in-certus").orElseThrow();

        assertThat(first.username()).isEqualTo("first-name");
        assertThat(first.role()).isEqualTo(ManagementRole.USER);
        assertThat(renamed.username()).isEqualTo("first-name");
        assertThat(repository.count()).isEqualTo(1);
        assertThat(repository.findById("first-name").orElseThrow().getOidcIdentityKey())
                .matches("[0-9a-f]{64}");
    }

    @Test
    void treatsOidcSubjectsAsCaseSensitive() {
        service.resolveOrProvisionOidcUser(ISSUER, "Case-Sensitive", "upper-user").orElseThrow();
        service.resolveOrProvisionOidcUser(ISSUER, "case-sensitive", "lower-user").orElseThrow();

        assertThat(repository.count()).isEqualTo(2);
    }

    @Test
    void adminCannotReadResetOrDeleteUsersFromAnotherTenant() {
        seedUser("bob", "tenant-b");
        ManagementContext tenantAAdmin =
                new ManagementContext(new TenantContext("tenant-a"), "admin-a", true);
        var mutation = new ManagementUserService.UserMutation(
                "bob", "reset-password", ManagementRole.ADMIN, false);

        assertThatThrownBy(() -> service.updateUser(tenantAAdmin, "bob", mutation))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("用户不存在: bob");
        assertThatThrownBy(() -> service.deleteUser(tenantAAdmin, "bob"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("用户不存在: bob");
        // Cross-tenant target and truly-missing target are indistinguishable.
        assertThatThrownBy(() -> service.deleteUser(tenantAAdmin, "ghost"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("用户不存在: ghost");
        assertThat(service.listUsers(tenantAAdmin))
                .noneMatch(view -> view.username().equalsIgnoreCase("bob"));

        ManagementUser unchanged = repository.findById("bob").orElseThrow();
        assertThat(unchanged.getPasswordHash()).isEqualTo("0".repeat(64));
        assertThat(unchanged.getRole()).isEqualTo(ManagementRole.USER);
        assertThat(unchanged.isEnabled()).isTrue();
    }

    @Test
    void adminManagesUsersInsideOwnTenant() {
        seedUser("bob", "tenant-b");
        ManagementContext tenantBAdmin =
                new ManagementContext(new TenantContext("tenant-b"), "admin-b", true);

        var updated = service.updateUser(tenantBAdmin, "bob",
                new ManagementUserService.UserMutation("bob", "new-password", ManagementRole.ADMIN, false));
        assertThat(updated.role()).isEqualTo(ManagementRole.ADMIN);
        assertThat(updated.enabled()).isFalse();
        assertThat(repository.findById("bob").orElseThrow().getPasswordHash())
                .isNotEqualTo("0".repeat(64));

        service.deleteUser(tenantBAdmin, "bob");
        assertThat(repository.findById("bob")).isEmpty();
    }

    private void seedUser(String username, String tenantId) {
        String now = Instant.now().toString();
        ManagementUser user = new ManagementUser();
        user.setUsername(username);
        user.setTenantId(tenantId);
        user.setPasswordHash("0".repeat(64));
        user.setRole(ManagementRole.USER);
        user.setEnabled(true);
        user.setCreatedAt(now);
        user.setUpdatedAt(now);
        repository.save(user);
    }
}
