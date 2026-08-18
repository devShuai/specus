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
                        + "\"changelogUrl\":\"https://specus.devshuai.com/releases/1.4.0\"}",
                URI.create("https://specus.devshuai.com/"));

        assertTrue(result.updateAvailable());
        assertFalse(result.mandatory());
        assertEquals("1.4.0", result.latestVersion());
        assertEquals("https://specus.devshuai.com/api/public/client-packages/42/download", result.downloadUrl());
        assertEquals("https://specus.devshuai.com/releases/1.4.0", result.changelogUrl());
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
    public void rejectsUnverifiedOrClearTextDownloads() {
        assertThrows(IOException.class, () -> ClientUpdateChecker.parse("{"
                        + "\"updateAvailable\":true,\"latestVersion\":\"2.0.0\","
                        + "\"downloadUrl\":\"http://attacker.invalid/client.apk\","
                        + "\"sha256\":\"invalid\",\"fileSize\":1}",
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
