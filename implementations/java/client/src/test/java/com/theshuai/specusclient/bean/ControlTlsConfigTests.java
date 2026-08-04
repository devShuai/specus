package com.theshuai.specusclient.bean;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ControlTlsConfigTests {

    @Test
    void followsRuntimeTlsSignalWhenEnabledIsOmitted() {
        ControlTlsConfig config = new ControlTlsConfig();

        assertThat(config.resolveEnabled(true)).isTrue();
        assertThat(config.resolveEnabled(false)).isFalse();
    }

    @Test
    void explicitEnabledOverridesRuntimeSignal() {
        ControlTlsConfig config = new ControlTlsConfig();
        config.setEnabled(true);
        assertThat(config.resolveEnabled(false)).isTrue();

        config.setEnabled(false);
        assertThat(config.resolveEnabled(true)).isFalse();
    }

    @Test
    void tlsSpecificOptionImplicitlyEnablesTls() {
        ControlTlsConfig config = new ControlTlsConfig();
        config.setServerName("control.example");

        assertThat(config.resolveEnabled(false)).isTrue();
    }

    @Test
    void validatesTlsOnlyOptionsAndServerBaseUrl() {
        ControlTlsConfig disabled = new ControlTlsConfig();
        disabled.setEnabled(false);
        disabled.setServerName("control.example");
        assertThatThrownBy(() -> disabled.validate("http://127.0.0.1:8088"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("enabled=false");

        ControlTlsConfig conflicting = new ControlTlsConfig();
        conflicting.setEnabled(true);
        conflicting.setCaCertificatePath("ca.pem");
        conflicting.setInsecureSkipVerify(true);
        assertThatThrownBy(() -> conflicting.validate("http://127.0.0.1:8088"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cannot be used together");

        assertThatThrownBy(() -> new ControlTlsConfig().validate("ftp://specus.example"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("absolute http/https URL");

        ControlTlsConfig invalidServerName = new ControlTlsConfig();
        invalidServerName.setServerName("control.example:7010");
        assertThatThrownBy(() -> invalidServerName.validate("https://specus.example"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("must not include a port");
    }

    @Test
    void trimsExplicitServerName() {
        ControlTlsConfig config = new ControlTlsConfig();
        config.setServerName(" control.example ");
        assertThat(config.resolveServerName("192.0.2.10")).isEqualTo("control.example");
    }
}
