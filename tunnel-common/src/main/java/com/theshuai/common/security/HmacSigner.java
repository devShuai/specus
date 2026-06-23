package com.theshuai.common.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Objects;

/**
 * Shared HMAC-SHA256 helpers used by client HTTP authentication.
 */
public final class HmacSigner {
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String SHA_256 = "SHA-256";

    private HmacSigner() {
    }

    public static byte[] sha256(String input) {
        Objects.requireNonNull(input, "input");
        try {
            return MessageDigest.getInstance(SHA_256).digest(input.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(SHA_256 + " is unavailable", e);
        }
    }

    public static byte[] hmacSha256(byte[] key, String message) {
        Objects.requireNonNull(key, "key");
        Objects.requireNonNull(message, "message");
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(HMAC_ALGORITHM + " is unavailable", e);
        }
    }

    public static byte[] decodeHex(String hex) {
        if (hex == null || (hex.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string must be non-null and even length");
        }
        int length = hex.length();
        byte[] out = new byte[length / 2];
        for (int i = 0; i < out.length; i++) {
            int high = Character.digit(hex.charAt(i * 2), 16);
            int low = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("invalid hex character at offset " + (i * 2));
            }
            out[i] = (byte) ((high << 4) | low);
        }
        return out;
    }

}
