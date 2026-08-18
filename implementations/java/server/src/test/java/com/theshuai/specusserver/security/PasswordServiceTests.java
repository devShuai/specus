package com.theshuai.specusserver.security;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordServiceTests {
    private static final String LEGACY_PASSWORD = "legacy-password";

    @Test
    void hashesAreSaltedAndCarryTheirOwnParameters() {
        String first = PasswordService.hash("correct horse battery staple");
        String second = PasswordService.hash("correct horse battery staple");

        assertNotEquals(first, second,
                "two hashes of the same password must differ; the salt is what stops rainbow tables");
        assertTrue(first.startsWith("$pbkdf2-sha256$v=1$i=210000$"), first);
        assertEquals(6, first.split("\\$", -1).length, first);
        assertTrue(PasswordService.matches("correct horse battery staple", first));
        assertFalse(PasswordService.matches("correct horse battery stapl", first));
    }

    @Test
    void currentCostHashesAreNotRewritten() {
        PasswordService.Verification result =
                PasswordService.verify("s3cret", PasswordService.hash("s3cret"));

        assertTrue(result.matches());
        assertFalse(result.needsUpgrade());
        assertNull(result.upgradedHash());
        assertFalse(result.storedIsLegacy());
    }

    /**
     * Existing databases hold bare SHA-256. Those users must not be locked out, and the login is
     * where the stored hash gets replaced.
     */
    @Test
    void legacyHashesVerifyAndAreScheduledForUpgrade() {
        String legacy = legacyDigest(LEGACY_PASSWORD);

        assertTrue(PasswordService.isLegacyHash(legacy));
        PasswordService.Verification result = PasswordService.verify(LEGACY_PASSWORD, legacy);
        assertTrue(result.matches(), "an existing user must not be locked out by the new format");
        assertTrue(result.needsUpgrade());
        assertTrue(result.storedIsLegacy());
        assertNotNull(result.upgradedHash());
        assertTrue(result.upgradedHash().startsWith("$pbkdf2-sha256$"));

        PasswordService.Verification next =
                PasswordService.verify(LEGACY_PASSWORD, result.upgradedHash());
        assertTrue(next.matches());
        assertFalse(next.needsUpgrade(), "the upgraded hash must be final");

        assertTrue(PasswordService.matches(LEGACY_PASSWORD, legacy.toUpperCase(Locale.ROOT)));
        assertFalse(PasswordService.matches("wrong", legacy));
    }

    @Test
    void underCostHashesAreUpgraded() {
        String weak = PasswordService.hash("s3cret", PasswordService.MIN_ITERATIONS);
        PasswordService.Verification result = PasswordService.verify("s3cret", weak);

        assertTrue(result.matches());
        assertTrue(result.needsUpgrade());
        assertTrue(result.upgradedHash().contains("i=" + PasswordService.DEFAULT_ITERATIONS + "$"));
    }

    @Test
    void malformedStoredHashesNeverVerify() {
        String[] malformed = {
                "", "   ", "$",
                "$pbkdf2-sha256$v=1$i=210000$onlythree",
                "$pbkdf2-sha256$v=2$i=210000$c2FsdA$a2V5",
                "$argon2id$v=1$i=210000$c2FsdA$a2V5",
                "$pbkdf2-sha256$v=1$i=1$c2FsdA$a2V5",
                "$pbkdf2-sha256$v=1$i=notanumber$c2FsdA$a2V5",
                "$pbkdf2-sha256$v=1$i=210000$!!!$a2V5",
                "$pbkdf2-sha256$v=1$i=210000$c2FsdA$!!!",
                "a".repeat(63),
                "z".repeat(64),
        };
        for (String stored : malformed) {
            assertFalse(PasswordService.matches("anything", stored), stored);
        }
        assertFalse(PasswordService.matches("anything", null));
        assertFalse(PasswordService.matches(null, "anything"));
    }

    /**
     * Machine secrets keep the plain digest. That is required, not merely cheaper: the HMAC client
     * login uses the 32 raw bytes of the digest as its key, so the format is part of the protocol.
     */
    @Test
    void tokenHashingStaysADeterministicDigest() {
        String token = PasswordService.hashToken("a-high-entropy-token");

        assertEquals(64, token.length());
        assertEquals(token, PasswordService.hashToken("a-high-entropy-token"));
        assertFalse(token.startsWith("$"));
        assertEquals(token, PasswordService.digestKey("a-high-entropy-token"));
        assertTrue(PasswordService.tokenMatches("a-high-entropy-token", token));
        assertFalse(PasswordService.tokenMatches("other", token));
        assertTrue(PasswordService.tokenMatches("a-high-entropy-token", token.toUpperCase(Locale.ROOT)));
        // A password-format hash must never satisfy a token check.
        assertFalse(PasswordService.tokenMatches("x", PasswordService.hash("x")));
    }

    /**
     * A hash written by one implementation has to verify on the others. The vector comes from an
     * independent PBKDF2-HMAC-SHA256 implementation, and Go and .NET assert the same two strings.
     */
    @Test
    void sharedCrossLanguageVectorVerifies() {
        String password = "specus-shared-password";
        String[] vectors = {
                "$pbkdf2-sha256$v=1$i=1000$AAECAwQFBgcICQoLDA0ODw$vnwYtUA8UXxNgCLy7OdAY+f7T+TtG4qdlahTjY1KU5g",
                "$pbkdf2-sha256$v=1$i=210000$AAECAwQFBgcICQoLDA0ODw$BiTFCvEUdO2zrZt0s1Zd0ipbGH5+WaSosMi6WavHxbI",
        };
        for (String vector : vectors) {
            assertTrue(PasswordService.matches(password, vector), vector);
            assertFalse(PasswordService.matches(password + "x", vector), vector);
        }
    }

    private static String legacyDigest(String password) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(password.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }
}
