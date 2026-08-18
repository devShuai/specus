package com.theshuai.specusserver.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Password and secret hashing.
 *
 * <p>Human passwords are stored with a salted, iterated KDF in a self-describing format shared by
 * every implementation:
 *
 * <pre>$pbkdf2-sha256$v=1$i=&lt;iterations&gt;$&lt;base64 salt&gt;$&lt;base64 derived key&gt;</pre>
 *
 * <p>Unsalted single-round SHA-256, which this replaces, hands an attacker who reads the database
 * the whole password list at rainbow-table speed. The parameters travel with each hash, so the cost
 * can be raised later without invalidating stored credentials: an old hash still verifies and the
 * caller is told to write back a fresh one.
 *
 * <p>PBKDF2-HMAC-SHA256 is used rather than Argon2id because it is in the standard library of all
 * four implementations. A shared format matters more than the extra memory hardness here, since a
 * divergent format means an account that works against one server and not another.
 *
 * <p>High-entropy secrets — access tokens, machine credentials, per-route gate secrets — go through
 * {@link #hashToken} instead. There is nothing to guess in them, and an iterated KDF on a
 * per-request check would only be a self-inflicted denial of service.
 */
public final class PasswordService {
    private static final char[] PASSWORD_ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    static final String ALGORITHM = "pbkdf2-sha256";
    static final int VERSION = 1;
    /** Cost applied to new and upgraded hashes. */
    public static final int DEFAULT_ITERATIONS = 210_000;
    /** Stored hashes claiming a cost below this are treated as corrupt rather than trusted. */
    public static final int MIN_ITERATIONS = 1_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final int LEGACY_HEX_LENGTH = 64;

    private PasswordService() {
    }

    public static String generatePassword() {
        char[] password = new char[18];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_ALPHABET[RANDOM.nextInt(PASSWORD_ALPHABET.length)];
        }
        return new String(password);
    }

    /** Derives a new salted hash for a human password at the current cost. */
    public static String hash(String password) {
        return hash(password, DEFAULT_ITERATIONS);
    }

    static String hash(String password, int iterations) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("password cannot be blank");
        }
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] derived = pbkdf2(password, salt, iterations);
        Base64.Encoder encoder = Base64.getEncoder().withoutPadding();
        return "$" + ALGORITHM + "$v=" + VERSION + "$i=" + iterations
                + "$" + encoder.encodeToString(salt)
                + "$" + encoder.encodeToString(derived);
    }

    /**
     * Hashes a high-entropy secret. Deterministic, because these values double as lookup keys.
     */
    public static String hashToken(String secret) {
        if (secret == null) {
            throw new IllegalArgumentException("secret cannot be null");
        }
        return toHex(sha256(secret));
    }

    /** Derives a deterministic lookup key from non-secret identifiers. An index, not a credential. */
    public static String digestKey(String value) {
        return hashToken(value);
    }

    /** Verifies without reporting whether the stored hash should be replaced. */
    public static boolean matches(String password, String expectedHash) {
        return verify(password, expectedHash).matches();
    }

    /** Verifies a token or index digest. Never accepts a password-format hash. */
    public static boolean tokenMatches(String secret, String expectedHash) {
        if (secret == null || expectedHash == null) {
            return false;
        }
        String expected = expectedHash.trim().toLowerCase(java.util.Locale.ROOT);
        if (expected.length() != LEGACY_HEX_LENGTH) {
            return false;
        }
        return MessageDigest.isEqual(
                hashToken(secret).getBytes(StandardCharsets.US_ASCII),
                expected.getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Outcome of verifying a password.
     *
     * @param matches      whether the password was correct
     * @param needsUpgrade whether the stored hash should be replaced with {@code upgradedHash}
     * @param upgradedHash the replacement, or null when none is needed
     * @param storedIsLegacy whether the stored value predated the salted format
     */
    public record Verification(boolean matches, boolean needsUpgrade, String upgradedHash,
                               boolean storedIsLegacy) {
        static Verification failed(boolean legacy) {
            return new Verification(false, false, null, legacy);
        }
    }

    /**
     * Verifies a password against either the current format or a legacy SHA-256 hash.
     *
     * <p>A successful login is the only moment the plaintext exists, so it is the only chance to
     * retire a legacy or under-cost hash. Callers that can persist should act on
     * {@link Verification#needsUpgrade()}.
     */
    public static Verification verify(String password, String expectedHash) {
        if (password == null || expectedHash == null) {
            return Verification.failed(false);
        }
        String stored = expectedHash.trim();
        if (stored.isEmpty()) {
            return Verification.failed(false);
        }
        if (!stored.startsWith("$")) {
            if (!legacyMatches(password, stored)) {
                return Verification.failed(true);
            }
            return new Verification(true, true, hash(password), true);
        }

        Parsed parsed;
        try {
            parsed = parse(stored);
        } catch (IllegalArgumentException malformed) {
            return Verification.failed(false);
        }
        byte[] derived = pbkdf2(password, parsed.salt, parsed.iterations);
        if (!MessageDigest.isEqual(derived, parsed.key)) {
            return Verification.failed(false);
        }
        if (parsed.iterations < DEFAULT_ITERATIONS) {
            return new Verification(true, true, hash(password), false);
        }
        return new Verification(true, false, null, false);
    }

    /** Whether the stored value predates the salted format and still needs a login to migrate. */
    public static boolean isLegacyHash(String storedHash) {
        return storedHash != null && !storedHash.trim().isEmpty() && !storedHash.trim().startsWith("$");
    }

    private record Parsed(int iterations, byte[] salt, byte[] key) {
    }

    private static Parsed parse(String stored) {
        // A leading "$" makes the first field empty: "", algorithm, version, iterations, salt, key.
        String[] parts = stored.split("\\$", -1);
        if (parts.length != 6 || !parts[0].isEmpty()) {
            throw new IllegalArgumentException("malformed password hash");
        }
        if (!ALGORITHM.equals(parts[1])) {
            throw new IllegalArgumentException("unsupported password hash algorithm");
        }
        if (parseTagged(parts[2], "v=") != VERSION) {
            throw new IllegalArgumentException("unsupported password hash version");
        }
        int iterations = parseTagged(parts[3], "i=");
        if (iterations < MIN_ITERATIONS) {
            throw new IllegalArgumentException("invalid password hash iterations");
        }
        byte[] salt = decodeBase64(parts[4]);
        byte[] key = decodeBase64(parts[5]);
        if (salt.length == 0 || key.length == 0) {
            throw new IllegalArgumentException("invalid password hash material");
        }
        return new Parsed(iterations, salt, key);
    }

    private static int parseTagged(String field, String prefix) {
        if (!field.startsWith(prefix)) {
            throw new IllegalArgumentException("malformed password hash field");
        }
        try {
            return Integer.parseInt(field.substring(prefix.length()));
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("malformed password hash number", error);
        }
    }

    private static byte[] decodeBase64(String value) {
        try {
            return Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("invalid base64 in password hash", error);
        }
    }

    private static boolean legacyMatches(String password, String storedHash) {
        if (storedHash.length() != LEGACY_HEX_LENGTH) {
            return false;
        }
        return MessageDigest.isEqual(
                toHex(sha256(password)).getBytes(StandardCharsets.US_ASCII),
                storedHash.toLowerCase(java.util.Locale.ROOT).getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] pbkdf2(String password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException error) {
            throw new IllegalStateException("PBKDF2WithHmacSHA256 is unavailable", error);
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            builder.append(Character.forDigit(value >>> 4 & 0x0F, 16));
            builder.append(Character.forDigit(value & 0x0F, 16));
        }
        return builder.toString();
    }
}
