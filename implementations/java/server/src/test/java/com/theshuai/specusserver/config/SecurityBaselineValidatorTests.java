package com.theshuai.specusserver.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecurityBaselineValidatorTests {

    @Test
    void unsetOrUnknownEnvironmentResolvesToProd() {
        assertThat(DeploymentEnvironment.parse(null)).isEqualTo(DeploymentEnvironment.PROD);
        assertThat(DeploymentEnvironment.parse("")).isEqualTo(DeploymentEnvironment.PROD);
        assertThat(DeploymentEnvironment.parse("staging")).isEqualTo(DeploymentEnvironment.PROD);
        assertThat(DeploymentEnvironment.parse("  DEV ")).isEqualTo(DeploymentEnvironment.DEV);
        assertThat(DeploymentEnvironment.parse("Test")).isEqualTo(DeploymentEnvironment.TEST);
    }

    @Test
    void onlyNonProdEnvironmentsAllowDemoData() {
        assertThat(DeploymentEnvironment.PROD.allowsDemoData()).isFalse();
        assertThat(DeploymentEnvironment.DEV.allowsDemoData()).isTrue();
        assertThat(DeploymentEnvironment.TEST.allowsDemoData()).isTrue();
    }

    @Test
    void prodRefusesToStartWithKnownDefaultPassword() {
        for (String password : new String[]{
                "admin", "password", "123456", "12345678", "test1234", " ChangeMe ", "change-me",
                "CHANGE_ME_ADMIN_PASSWORD", "change-me-before-exposure", "specus", "demo"
        }) {
            assertThatThrownBy(() -> validator("prod", password).validate())
                    .as("historical default %s", password)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("已知默认口令");
        }
    }

    @Test
    void prodStartsWithStrongPasswordOrPasswordLoginDisabled() {
        assertThatCode(() -> validator("prod", "8Qb!x2s7Lm#4pTz").validate()).doesNotThrowAnyException();
        // Blank password keeps password login disabled, which is the shipped default.
        assertThatCode(() -> validator("prod", "").validate()).doesNotThrowAnyException();

        AuthProperties disabled = properties("admin");
        disabled.setPasswordLoginEnabled(false);
        assertThatCode(() -> new SecurityBaselineValidator(disabled, "prod", false).validate())
                .doesNotThrowAnyException();
    }

    @Test
    void nonProdOnlyWarnsAboutWeakDefaults() {
        assertThatCode(() -> validator("dev", "admin").validate()).doesNotThrowAnyException();
        assertThatCode(() -> validator("test", "admin").validate()).doesNotThrowAnyException();
    }

    @Test
    void prodRefusesPublishedJwtPlaceholderEvenWhenPasswordLoginIsDisabled() {
        AuthProperties properties = properties("");
        properties.setJwtSecret(" Replace-With-A-Long-Random-Secret ");
        assertThatThrownBy(() -> new SecurityBaselineValidator(properties, "prod", false).validate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("公开占位值");
        assertThatCode(() -> new SecurityBaselineValidator(properties, "dev", false).validate())
                .doesNotThrowAnyException();
        properties.setJwtSecret("unique-random-deployment-secret");
        assertThatCode(() -> new SecurityBaselineValidator(properties, "prod", false).validate())
                .doesNotThrowAnyException();
    }

    private SecurityBaselineValidator validator(String environmentName, String password) {
        return new SecurityBaselineValidator(properties(password), environmentName, false);
    }

    private AuthProperties properties(String password) {
        AuthProperties properties = new AuthProperties();
        properties.setUsername("admin");
        properties.setPassword(password);
        return properties;
    }
}
