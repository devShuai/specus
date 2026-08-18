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
        assertThatThrownBy(() -> validator("prod", "admin").validate())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("已知默认口令");
        assertThatThrownBy(() -> validator("", "test1234").validate())
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> validator("prod", " ChangeMe ").validate())
                .isInstanceOf(IllegalStateException.class);
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
