package com.theshuai.common.util;

import jakarta.servlet.http.HttpServletRequest;

public class IPUtil {
    public static String getIp(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
