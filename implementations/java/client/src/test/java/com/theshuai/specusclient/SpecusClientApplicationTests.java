package com.theshuai.specusclient;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

//@SpringBootTest
class SpecusClientApplicationTests {

    //    @Test
    void contextLoads() {
    }

    @Test
    void reportsManifestVersionOrDeterministicDevelopmentFallback() {
        assertThat(SpecusClientApplication.currentVersion()).isNotBlank();
        if (SpecusClientApplication.class.getPackage().getImplementationVersion() == null) {
            assertThat(SpecusClientApplication.currentVersion()).isEqualTo("0.0.0-dev");
        }
    }

}
