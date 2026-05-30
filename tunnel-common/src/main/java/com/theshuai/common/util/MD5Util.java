package com.theshuai.common.util;

import org.springframework.util.DigestUtils;

import java.nio.charset.StandardCharsets;

public class MD5Util {

    private final static String salt = "abc@123MD5salT,q";

    public static String getSaltMd5(String str) {
        str += salt;
        return DigestUtils.md5DigestAsHex(str.getBytes(StandardCharsets.UTF_8));
    }
}
