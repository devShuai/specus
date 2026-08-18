package com.theshuai.specus.android;

import org.junit.Test;

import java.io.IOException;
import java.net.URI;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ClientUpdateCheckerTest {
    private static final String SHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    @Test
    public void parsesHostedUpdateAndResolvesRelativeDownload() throws Exception {
        ClientUpdateChecker.Result result = ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,"
                        + "\"mandatory\":false,"
                        + "\"latestVersion\":\"1.4.0\","
                        + "\"packageId\":42,"
                        + "\"downloadUrl\":\"/api/public/client-packages/42/download\","
                        + "\"sha256\":\"" + SHA256 + "\","
                        + "\"fileSize\":4096,"
                        + "\"changelogUrl\":\"https://github.com/devShuai/specus/releases/tag/v1.4.0\"}",
                URI.create("https://specus.devshuai.com/"));

        assertTrue(result.updateAvailable());
        assertFalse(result.mandatory());
        assertEquals("1.4.0", result.latestVersion());
        assertEquals("https://specus.devshuai.com/api/public/client-packages/42/download", result.downloadUrl());
        assertEquals("https://github.com/devShuai/specus/releases/tag/v1.4.0", result.changelogUrl());
    }

    @Test
    public void noUpdateDoesNotRequirePackageMetadata() throws Exception {
        ClientUpdateChecker.Result result = ClientUpdateChecker.parse(
                "{\"updateAvailable\":false,\"mandatory\":false,\"latestVersion\":\"1.0.0\"}",
                URI.create("https://specus.devshuai.com/"));

        assertFalse(result.updateAvailable());
        assertNull(result.downloadUrl());
    }

    @Test
    public void parsesAuthoritativeExternalReleaseWithoutPackageId() throws Exception {
        String release = "https://github.com/devShuai/specus/releases/download/v1.4.0/specus-android.apk";
        ClientUpdateChecker.Result result = ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,"
                        + "\"latestVersion\":\"1.4.0\","
                        + "\"packageId\":null,"
                        + "\"downloadUrl\":\"" + release + "\","
                        + "\"sha256\":\"" + SHA256 + "\","
                        + "\"fileSize\":4096}",
                URI.create("https://specus.devshuai.com/"));

        assertTrue(result.updateAvailable());
        assertEquals(release, result.downloadUrl());
    }

    @Test
    public void normalizesAndStrictlyValidatesSemanticVersions() throws Exception {
        ClientUpdateChecker.Result result = ClientUpdateChecker.parse(
                "{\"updateAvailable\":false,\"latestVersion\":\"v1.2.3-beta.1+build.4\"}",
                URI.create("https://specus.devshuai.com/"));
        assertEquals("1.2.3-beta.1+build.4", result.latestVersion());

        for (String invalid : new String[]{"1.2", "1.2.3.4", "1.2.3-01", "V1.2.3", "1.2.3\u001b[31m"}) {
            assertThrows(IOException.class, () -> ClientUpdateChecker.parse(
                    "{\"updateAvailable\":false,\"latestVersion\":\"" + invalid + "\"}",
                    URI.create("https://specus.devshuai.com/")));
        }
    }

    @Test
    public void rejectsUnverifiedOrClearTextDownloads() {
        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"downloadUrl\":\"http://attacker.invalid/client.apk\","
                        + "\"sha256\":\"invalid\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));

        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"packageId\":42,"
                        + "\"downloadUrl\":\"https://attacker.invalid/client.apk\","
                        + "\"sha256\":\"" + SHA256 + "\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));

        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"downloadUrl\":\"/api/public/client-packages/42/download\","
                        + "\"sha256\":\"" + SHA256 + "\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));

        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"packageId\":0,"
                        + "\"downloadUrl\":\"/api/public/client-packages/42/download\","
                        + "\"sha256\":\"" + SHA256 + "\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));

        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"packageId\":42,"
                        + "\"downloadUrl\":\"/api/public/client-packages/41/download\","
                        + "\"sha256\":\"" + SHA256 + "\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));

        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"packageId\":null,"
                        + "\"downloadUrl\":\"https://github.com/devShuai/specus/releases/download/v2.0.0/client.apk?raw=1\","
                        + "\"sha256\":\"" + SHA256 + "\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));

        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"packageId\":42,"
                        + "\"downloadUrl\":\"/api/public/client-packages/42/download?raw=1\","
                        + "\"sha256\":\"" + SHA256 + "\",\"fileSize\":1}",
                URI.create("https://specus.devshuai.com/")));
    }

    @Test
    public void checksAtStartupAndEveryTwentyFourHours() {
        long now = 1_000_000_000L;
        assertTrue(ClientUpdateChecker.shouldCheck(0L, now));
        assertFalse(ClientUpdateChecker.shouldCheck(now, now + ClientUpdateChecker.CHECK_INTERVAL_MILLIS - 1));
        assertTrue(ClientUpdateChecker.shouldCheck(now, now + ClientUpdateChecker.CHECK_INTERVAL_MILLIS));
        assertTrue(ClientUpdateChecker.shouldCheck(now, now - 1));
    }
}
