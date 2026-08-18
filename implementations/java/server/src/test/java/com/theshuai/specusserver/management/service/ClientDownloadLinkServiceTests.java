package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.model.ClientDownloadLink;
import com.theshuai.specusserver.management.model.ClientDownloadLinkView;
import com.theshuai.specusserver.management.repository.ClientDownloadLinkRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ClientDownloadLinkServiceTests {
    private ClientDownloadLinkRepository repository;
    private ClientPackageStorage storage;
    private ClientDownloadLinkService service;

    @BeforeEach
    void setUp() {
        repository = mock(ClientDownloadLinkRepository.class);
        storage = mock(ClientPackageStorage.class);
        when(repository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        service = new ClientDownloadLinkService(
                repository, storage, mock(PlatformTransactionManager.class));
    }

    @Test
    void publicListReturnsOnlyLatestForVersionedTargetAndPreservesPureLegacyTarget() {
        ClientDownloadLink old = row(1, "go", "windows", "x64", "1.0.0", false, true, true);
        ClientDownloadLink latest = row(2, "go", "windows", "x64", "1.1.0", true, true, true);
        ClientDownloadLink hiddenLegacy = row(3, "go", "windows", "x64", null, false, true, false);
        ClientDownloadLink visibleLegacy = row(4, "java", "any", "any", null, false, true, false);
        when(repository.findAllByOrderByImplementationAscDisplayOrderAscIdAsc())
                .thenReturn(List.of(old, latest, hiddenLegacy, visibleLegacy));

        List<ClientDownloadLinkView> views = service.listEnabled();

        assertThat(views).extracting(ClientDownloadLinkView::id).containsExactly(2L, 4L);
    }

    @Test
    void publicListDoesNotResurrectLegacyLinkWhenVersionedTargetIsDisabled() {
        ClientDownloadLink legacy = row(5, "go", "linux", "x64", null, false, true, false);
        ClientDownloadLink disabledVersion = row(6, "go", "linux", "x64", "2.0.0", false, false, true);
        when(repository.findAllByOrderByImplementationAscDisplayOrderAscIdAsc())
                .thenReturn(List.of(legacy, disabledVersion));

        assertThat(service.listEnabled()).isEmpty();
    }

    @Test
    void versionCheckSupportsAuthoritativeExternalLatestThenSpecificityAndSemver() {
        ClientDownloadLink exact = row(11, "go", "windows", "x64", "1.5.0", true, true, false);
        exact.setMinSupportedVersion("1.4.0");
        ClientDownloadLink universalNewer = row(12, "go", "any", "any", "9.0.0", true, true, true);
        ClientDownloadLink nonLatest = row(13, "go", "windows", "x64", "10.0.0", false, true, true);
        when(repository.findByImplementationAndPlatformInAndArchInAndEnabledTrue(
                "go", List.of("windows", "any"), List.of("x64", "any")))
                .thenReturn(List.of(exact, universalNewer, nonLatest));

        ClientDownloadLinkService.VersionCheckView result =
                service.checkVersion("GO", "windows", "x64", "1.0.0");

        assertThat(result.updateAvailable()).isTrue();
        assertThat(result.mandatory()).isTrue();
        assertThat(result.latestVersion()).isEqualTo("1.5.0");
        assertThat(result.packageId()).isNull();
        assertThat(result.downloadUrl()).startsWith("https://github.com/devShuai/specus/releases/download/");
        assertThat(result.sha256()).hasSize(64);
    }

    @Test
    void versionCheckNeverPublishesUnmarkedPackageAndReturnsNoneAfterLatestIsDeleted() {
        ClientDownloadLink published = row(21, "go", "linux", "x64", "2.0.0", true, true, true);
        ClientDownloadLink staged = row(22, "go", "linux", "x64", "9.0.0", false, true, true);
        when(repository.findByImplementationAndPlatformInAndArchInAndEnabledTrue(
                "go", List.of("linux", "any"), List.of("x64", "any")))
                .thenReturn(List.of(published, staged))
                .thenReturn(List.of(staged));
        when(repository.findById(21L)).thenReturn(Optional.of(published));
        when(storage.quarantine(21L)).thenReturn(Optional.empty());

        assertThat(service.checkVersion("go", "linux", "x64", "1.0.0").latestVersion())
                .isEqualTo("2.0.0");

        service.delete(21L);

        ClientDownloadLinkService.VersionCheckView afterDelete =
                service.checkVersion("go", "linux", "x64", "1.0.0");
        assertThat(afterDelete.updateAvailable()).isFalse();
        assertThat(afterDelete.latestVersion()).isNull();
        assertThat(afterDelete.packageId()).isNull();
        verify(repository).delete(published);
    }

    @Test
    void versionCheckReturnsNoneWhenMatchingPackagesHaveNoExplicitLatest() {
        ClientDownloadLink staged = row(23, "go", "linux", "x64", "9.0.0", false, true, true);
        when(repository.findByImplementationAndPlatformInAndArchInAndEnabledTrue(
                "go", List.of("linux", "any"), List.of("x64", "any")))
                .thenReturn(List.of(staged));

        ClientDownloadLinkService.VersionCheckView result =
                service.checkVersion("go", "linux", "x64", "1.0.0");

        assertThat(result.updateAvailable()).isFalse();
        assertThat(result.latestVersion()).isNull();
        assertThat(result.packageId()).isNull();
    }

    @Test
    void versionCheckSupportsAndroidAnyAndReturnsNullOptionalsWhenNoPackageExists() {
        when(repository.findByImplementationAndPlatformInAndArchInAndEnabledTrue(
                "android", List.of("android", "any"), List.of("any")))
                .thenReturn(List.of());

        ClientDownloadLinkService.VersionCheckView result =
                service.checkVersion("android", "android", "any", "1.0.0");

        assertThat(result.updateAvailable()).isFalse();
        assertThat(result.mandatory()).isFalse();
        assertThat(result.latestVersion()).isNull();
        assertThat(result.downloadUrl()).isNull();
        assertThat(result.sha256()).isNull();
        assertThat(result.changelogUrl()).isNull();
        assertThat(result.packageId()).isNull();
    }

    @Test
    void jsonCrudAcceptsAndroidAndLegacyPayloadWhileKeepingLatestUnique() {
        ClientDownloadLinkView android = service.create(new ClientDownloadLinkService.LinkMutation(
                "android", "android", "any", "Android APK", "https://example.test/client.apk",
                null, 0, true, "v1.2.3", "a".repeat(64), 1024L, true, null, "v1.0.0"));
        ClientDownloadLinkView legacy = service.create(new ClientDownloadLinkService.LinkMutation(
                "java", "any", "any", "Legacy Java", "https://example.test/client.jar",
                null, 1, true, null, null, null, null, null, null));

        assertThat(android.implementation()).isEqualTo("android");
        assertThat(android.platform()).isEqualTo("android");
        assertThat(android.version()).isEqualTo("1.2.3");
        assertThat(android.minSupportedVersion()).isEqualTo("1.0.0");
        assertThat(android.isLatest()).isTrue();
        assertThat(legacy.version()).isNull();
        assertThat(legacy.isLatest()).isFalse();
        verify(repository).clearLatest("android", "android", "any");
    }

    @Test
    void rejectsDeadAndroidCatalogueCoordinates() {
        ClientDownloadLinkService.LinkMutation wrongPlatform = new ClientDownloadLinkService.LinkMutation(
                "android", "windows", "any", "Android APK", "https://example.test/client.apk",
                null, 0, true, "1.2.3", null, null, false, null, null);
        ClientDownloadLinkService.LinkMutation wrongArch = new ClientDownloadLinkService.LinkMutation(
                "android", "android", "arm64", "Android APK", "https://example.test/client.apk",
                null, 0, true, "1.2.3", null, null, false, null, null);
        ClientDownloadLinkService.LinkMutation reservedPlatform = new ClientDownloadLinkService.LinkMutation(
                "go", "android", "any", "Wrong APK", "https://example.test/client.apk",
                null, 0, true, "1.2.3", null, null, false, null, null);

        assertThatThrownBy(() -> service.create(wrongPlatform)).hasMessageContaining("platform=android");
        assertThatThrownBy(() -> service.create(wrongArch)).hasMessageContaining("arch=any");
        assertThatThrownBy(() -> service.create(reservedPlatform)).hasMessageContaining("reserved");
        assertThatThrownBy(() -> service.checkVersion("android", "windows", "any", "1.0.0"))
                .hasMessageContaining("platform=android");
    }

    @Test
    void createAndUpdateRejectDisabledLatestBeforeChangingLatestSlot() {
        ClientDownloadLinkService.LinkMutation disabledLatest = new ClientDownloadLinkService.LinkMutation(
                "android", "android", "any", "Android APK", "https://example.test/client.apk",
                null, 0, false, "1.2.3", null, null, true, null, null);
        assertThatThrownBy(() -> service.create(disabledLatest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("disabled");

        ClientDownloadLink existing = row(31, "android", "android", "any", "1.2.3", true, true, false);
        when(repository.findById(31L)).thenReturn(Optional.of(existing));
        ClientDownloadLinkService.LinkMutation disableExisting = new ClientDownloadLinkService.LinkMutation(
                "android", "android", "any", "Android APK", "https://example.test/client.apk",
                null, 0, false, "1.2.3", null, null, null, null, null);
        assertThatThrownBy(() -> service.update(31L, disableExisting))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("disabled");
    }

    @Test
    void externalLatestRequiresVerifiedHttpsReleaseMetadata() {
        ClientDownloadLinkService.LinkMutation missingDigest = new ClientDownloadLinkService.LinkMutation(
                "go", "windows", "x64", "Go client",
                "https://github.com/devShuai/specus/releases/download/v1.2.3/client.zip",
                null, 0, true, "1.2.3", null, 1024L, true, null, null);
        ClientDownloadLinkService.LinkMutation ambiguousUrl = new ClientDownloadLinkService.LinkMutation(
                "go", "windows", "x64", "Go client",
                "https://github.com/devShuai/specus/releases/download/v1.2.3/client.zip?raw=1",
                null, 0, true, "1.2.3", "a".repeat(64), 1024L, true, null, null);

        assertThatThrownBy(() -> service.create(missingDigest))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("sha256");
        assertThatThrownBy(() -> service.create(ambiguousUrl))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("HTTPS");
    }

    @Test
    void markLatestRequiresEnabledValidSemanticVersion() {
        ClientDownloadLink disabled = row(41, "go", "linux", "x64", "1.2.3", false, false, true);
        ClientDownloadLink invalid = row(42, "go", "linux", "x64", "not-semver", false, true, true);
        ClientDownloadLink canonicalized = row(43, "go", "linux", "x64", "v1.2.3", false, true, true);
        canonicalized.setMinSupportedVersion("v1.0.0");
        when(repository.findById(41L)).thenReturn(Optional.of(disabled));
        when(repository.findById(42L)).thenReturn(Optional.of(invalid));
        when(repository.findById(43L)).thenReturn(Optional.of(canonicalized));

        assertThatThrownBy(() -> service.markLatest(41L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("disabled");
        assertThatThrownBy(() -> service.markLatest(42L))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("SemVer");

        ClientDownloadLinkView latest = service.markLatest(43L);
        assertThat(latest.version()).isEqualTo("1.2.3");
        assertThat(latest.minSupportedVersion()).isEqualTo("1.0.0");
        assertThat(latest.isLatest()).isTrue();
        assertThat(canonicalized.getCatalogKey()).isEqualTo("go|linux|x64|1.2.3");
    }

    @Test
    void androidHostedDownloadGetsSafeApkFileNameWithoutDuplicatingExtension() {
        ClientDownloadLink missingExtension = row(
                51, "android", "android", "any", "1.2.3", true, true, true);
        missingExtension.setDisplayName("Specus Android / universal");
        ClientDownloadLink existingExtension = row(
                52, "android", "android", "any", "1.2.4", true, true, true);
        existingExtension.setDisplayName("Specus-Android.APK");
        Path firstPath = Path.of("packages", "51").toAbsolutePath();
        Path secondPath = Path.of("packages", "52").toAbsolutePath();
        when(repository.findByIdAndEnabledTrueAndHostedTrue(51L)).thenReturn(Optional.of(missingExtension));
        when(repository.findByIdAndEnabledTrueAndHostedTrue(52L)).thenReturn(Optional.of(existingExtension));
        when(storage.requireReadable(51L)).thenReturn(firstPath);
        when(storage.requireReadable(52L)).thenReturn(secondPath);

        assertThat(service.downloadable(51L).fileName()).isEqualTo("Specus Android _ universal.apk");
        assertThat(service.downloadable(52L).fileName()).isEqualTo("Specus-Android.APK");
    }

    private ClientDownloadLink row(long id, String implementation, String platform, String arch,
                                   String version, boolean latest, boolean enabled, boolean hosted) {
        ClientDownloadLink row = new ClientDownloadLink();
        row.setId(id);
        row.setImplementation(implementation);
        row.setPlatform(platform);
        row.setArch(arch);
        row.setDisplayName("package-" + id);
        row.setDownloadUrl(hosted
                ? "/api/public/client-packages/" + id + "/download"
                : "https://github.com/devShuai/specus/releases/download/v"
                        + (version == null ? "legacy" : version) + "/package-" + id);
        row.setDescription(null);
        row.setDisplayOrder((int) id);
        row.setEnabled(enabled);
        row.setVersion(version);
        row.setSha256(version == null ? null : "a".repeat(64));
        row.setFileSize(version == null ? 0L : 100L);
        row.setLatest(latest);
        row.setHosted(hosted);
        row.setCreatedAt("2026-08-18T00:00:00Z");
        row.setUpdatedAt("2026-08-18T00:00:00Z");
        return row;
    }
}
