package com.theshuai.specusserver.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class PasswordService {
    private static final char[] PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789".toCharArray();
    private static final SecureRandom RANDOM = new SecureRandom();

    private PasswordService() {
    }

    public static String generatePassword() {
        char[] password = new char[18];
        for (int i = 0; i < password.length; i++) {
            password[i] = PASSWORD_ALPHABET[RANDOM.nextInt(PASSWORD_ALPHABET.length)];
        }
        return new String(password);
    }

    public static String hash(String password) {
        if (password == null || password.isBlank()) {
            throw new IllegalArgumentException("password cannot be blank");
        }
        return toHex(digest(password));
    }

    public static boolean matches(String password, String expectedHash) {
        if (password == null || expectedHash == null) {
            return false;
        }
        return MessageDigest.isEqual(
                digest(password),
                decodeHex(expectedHash)
        );
    }

    private static byte[] digest(String password) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(password.getBytes(StandardCharsets.UTF_8));
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

    private static byte[] decodeHex(String value) {
        if (value.length() != 64) {
            return new byte[0];
        }
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high == -1 || low == -1) {
                return new byte[0];
            }
            bytes[i] = (byte) (high << 4 | low);
        }
        return bytes;
    }
}
