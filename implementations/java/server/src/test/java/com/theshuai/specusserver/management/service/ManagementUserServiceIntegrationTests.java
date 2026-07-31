package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ManagementRole;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

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
}
