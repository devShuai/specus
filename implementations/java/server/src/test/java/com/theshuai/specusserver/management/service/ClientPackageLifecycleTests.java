package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.ClientPackageProperties;
import com.theshuai.specusserver.management.model.ClientDownloadLink;
import com.theshuai.specusserver.management.repository.ClientDownloadLinkRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.sqlite.SQLiteDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientPackageLifecycleTests {
    @TempDir
    Path temporaryDirectory;

    @Test
    void uploadPublishesAuthoritativeMetadataAndDeleteRemovesBytesAfterCommit() throws Exception {
        ClientDownloadLinkRepository repository = mock(ClientDownloadLinkRepository.class);
        AtomicReference<ClientDownloadLink> saved = new AtomicReference<>();
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> {
            ClientDownloadLink row = invocation.getArgument(0);
            saved.set(row);
            return row;
        });
        ClientPackageStorage storage = storage();
        DataSourceTransactionManager transactionManager = transactionManager();
        ClientDownloadLinkService service = new ClientDownloadLinkService(repository, storage, transactionManager);
        byte[] packageBytes = "android-apk-content".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        var uploaded = service.upload(new ByteArrayInputStream(packageBytes), packageBytes.length,
                new ClientDownloadLinkService.PackageUpload(
                        "android", "android", "any", "2.0.0", "specus Android 2.0.0.apk",
                        "release", "https://example.test/changelog", "1.5.0",
                        1, true, true));

        assertThat(uploaded.hosted()).isTrue();
        assertThat(uploaded.packageId()).isEqualTo(uploaded.id());
        assertThat(uploaded.downloadUrl()).isEqualTo(
                "/api/public/client-packages/" + uploaded.id() + "/download");
        assertThat(uploaded.sha256()).hasSize(64);
        assertThat(uploaded.fileSize()).isEqualTo(packageBytes.length);
        assertThat(Files.readAllBytes(storage.requireReadable(uploaded.id()))).isEqualTo(packageBytes);

        when(repository.findById(uploaded.id())).thenReturn(Optional.of(saved.get()));
        TransactionTemplate transactions = new TransactionTemplate(transactionManager);
        transactions.executeWithoutResult(status -> {
            service.delete(uploaded.id());
            status.setRollbackOnly();
        });
        assertThat(Files.readAllBytes(storage.requireReadable(uploaded.id()))).isEqualTo(packageBytes);

        transactions.executeWithoutResult(status -> service.delete(uploaded.id()));

        assertThatThrownByPackageMissing(storage, uploaded.id());
    }

    @Test
    void failedCatalogueInsertRemovesStagedUpload() throws Exception {
        ClientDownloadLinkRepository repository = mock(ClientDownloadLinkRepository.class);
        when(repository.saveAndFlush(any())).thenThrow(new IllegalStateException("database unavailable"));
        ClientPackageStorage storage = storage();
        ClientDownloadLinkService service = new ClientDownloadLinkService(
                repository, storage, transactionManager());
        byte[] packageBytes = "uncommitted-package".getBytes(java.nio.charset.StandardCharsets.UTF_8);

        assertThatThrownBy(() -> service.upload(
                new ByteArrayInputStream(packageBytes), packageBytes.length,
                new ClientDownloadLinkService.PackageUpload(
                        "go", "linux", "x64", "2.0.0", "specus go 2.0.0",
                        null, null, null, 1, true, true)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("database unavailable");

        try (var files = Files.list(storage.root())) {
            assertThat(files).isEmpty();
        }
    }

    private void assertThatThrownByPackageMissing(ClientPackageStorage storage, long id) {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> storage.requireReadable(id))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not found");
    }

    private ClientPackageStorage storage() {
        ClientPackageProperties properties = new ClientPackageProperties();
        properties.setDataDirectory(temporaryDirectory.toString());
        properties.setMaxPackageBytes(1024);
        return new ClientPackageStorage(properties);
    }

    private DataSourceTransactionManager transactionManager() {
        SQLiteDataSource dataSource = new SQLiteDataSource();
        dataSource.setUrl("jdbc:sqlite:" + temporaryDirectory.resolve("transactions.db"));
        return new DataSourceTransactionManager(dataSource);
    }
}
