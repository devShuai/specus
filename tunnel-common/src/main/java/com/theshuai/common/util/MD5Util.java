package com.theshuai.common.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

public class MD5Util {

    private static final String SALT = "abc@123MD5salT,q";

    public static String getSaltMd5(String str) {
        return md5Hex((str + SALT).getBytes(StandardCharsets.UTF_8));
    }

    private static String md5Hex(byte[] bytes) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            return HexFormat.of().formatHex(digest.digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm is unavailable", e);
        }
    }
}
