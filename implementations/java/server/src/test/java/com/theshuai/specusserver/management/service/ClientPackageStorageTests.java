package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ClientPackageProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientPackageStorageTests {
    @TempDir
    Path temporaryDirectory;

    @Test
    void stagesHashesAndAtomicallyPublishesInsidePackagesDirectory() throws Exception {
        ClientPackageStorage storage = storage(1024);
        byte[] bytes = "specus-package".getBytes(StandardCharsets.UTF_8);

        ClientPackageStorage.StagedPackage staged = storage.stage(new ByteArrayInputStream(bytes), bytes.length);
        Path published = storage.publish(staged, 42L);

        assertThat(staged.sha256())
                .isEqualTo("5e471da0443561615e4cb8a9221f54dcf7f3ec80c4477e9612e6aa3a46fa9492");
        assertThat(staged.fileSize()).isEqualTo(bytes.length);
        assertThat(published).isEqualTo(temporaryDirectory.resolve("packages").resolve("42"));
        assertThat(Files.readAllBytes(storage.requireReadable(42L))).isEqualTo(bytes);
        ClientPackageStorage.StagedPackage duplicate = storage.stage(
                new ByteArrayInputStream(bytes), bytes.length);
        try {
            assertThatThrownBy(() -> storage.publish(duplicate, 42L))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("already exists");
        } finally {
            storage.deleteQuietly(duplicate.path());
        }

        Path outside = Files.write(temporaryDirectory.resolve("outside-package"), bytes);
        assertThatThrownBy(() -> storage.publish(new ClientPackageStorage.StagedPackage(
                outside, bytes.length, staged.sha256()), 43L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("inside data/packages");
    }

    @Test
    void enforcesActualStreamSizeAndRejectsEmptyOrInvalidIds() {
        ClientPackageStorage storage = storage(4);
        assertThatThrownBy(() -> storage.stage(new ByteArrayInputStream(new byte[5]), 1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds max");
        assertThatThrownBy(() -> storage.stage(new ByteArrayInputStream(new byte[0]), 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
        assertThatThrownBy(() -> storage.stage(new ByteArrayInputStream(new byte[]{1}), -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("negative");
        assertThatThrownBy(() -> storage.requireReadable(-1))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private ClientPackageStorage storage(long limit) {
        ClientPackageProperties properties = new ClientPackageProperties();
        properties.setDataDirectory(temporaryDirectory.toString());
        properties.setMaxPackageBytes(limit);
        return new ClientPackageStorage(properties);
    }
}
