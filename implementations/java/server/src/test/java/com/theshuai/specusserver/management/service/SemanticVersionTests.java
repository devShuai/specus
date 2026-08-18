package com.theshuai.specusserver.management.service;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SemanticVersionTests {
    @Test
    void implementsSemverPrecedenceIncludingEqualityAndBuildMetadata() {
        assertThat(compare("1.0.0", "1.0.0")).isZero();
        assertThat(compare("v1.2.3", "1.2.3")).isZero();
        assertThat(compare("1.0.0+build.2", "1.0.0+build.1")).isZero();
        assertThat(compare("v1.2.3-alpha.1+build.01", "1.2.3-alpha.1")).isZero();
        assertThat(compare("1.0.0", "1.0.0-rc.1")).isPositive();
        assertThat(compare("1.0.0-alpha.2", "1.0.0-alpha.10")).isNegative();
        assertThat(compare("2.0.0", "1.9999999999.9999999999")).isPositive();
    }

    @Test
    void rejectsLooseOrAmbiguousVersions() {
        assertThatThrownBy(() -> SemanticVersion.parse("V1.0.0", "version"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SemanticVersion.parse("1.0", "version"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SemanticVersion.parse("1.0.0-01", "version"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SemanticVersion.parse("1.0.0+build..1", "version"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> SemanticVersion.parse("1.0.0+", "version"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private int compare(String left, String right) {
        return SemanticVersion.parse(left, "left").compareTo(SemanticVersion.parse(right, "right"));
    }
}
