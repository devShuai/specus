package com.theshuai.specusclient.handler;

import java.net.URI;

/** Route validation helpers shared by the mandatory NAT-stream HTTP forwarder. */
public final class HttpRouteTargetResolver {
    private static final long MAX_RANGE_BYTES = 8L * 1024 * 1024;

    private HttpRouteTargetResolver() {
    }

    static URI buildTarget(String targetBaseUrl, String relativePath, String rawQuery) {
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            throw new IllegalArgumentException("未配置 HTTP route");
        }
        URI base = URI.create(targetBaseUrl);
        if (!"http".equalsIgnoreCase(base.getScheme()) && !"https".equalsIgnoreCase(base.getScheme())) {
            throw new IllegalArgumentException("HTTP route 仅支持 http 和 https");
        }
        if (base.getHost() == null || base.getRawQuery() != null || base.getRawFragment() != null) {
            throw new IllegalArgumentException("HTTP route 地址无效");
        }

        String path = relativePath == null || relativePath.isBlank() ? "/" : relativePath;
        if (!path.startsWith("/") || path.contains("\r") || path.contains("\n")) {
            throw new IllegalArgumentException("HTTP 转发路径无效");
        }
        String baseUrl = targetBaseUrl.endsWith("/")
                ? targetBaseUrl.substring(0, targetBaseUrl.length() - 1)
                : targetBaseUrl;
        URI target = URI.create(baseUrl + path
                + (rawQuery == null || rawQuery.isBlank() ? "" : "?" + rawQuery));
        if (!base.getScheme().equalsIgnoreCase(target.getScheme())
                || !base.getHost().equalsIgnoreCase(target.getHost())
                || base.getPort() != target.getPort()) {
            throw new IllegalArgumentException("HTTP 转发目标越界");
        }
        String basePath = normalizeBasePath(base.getPath());
        for (String segment : target.getPath().split("/")) {
            if (".".equals(segment) || "..".equals(segment)) {
                throw new IllegalArgumentException("HTTP 转发路径越界");
            }
        }
        String targetPath = target.normalize().getPath();
        if (!"/".equals(basePath)
                && !targetPath.equals(basePath)
                && !targetPath.startsWith(basePath + "/")) {
            throw new IllegalArgumentException("HTTP 转发路径越界");
        }
        return target;
    }

    static String boundedRange(String rangeHeader) {
        if (rangeHeader == null) {
            return null;
        }
        String value = rangeHeader.trim();
        if (!value.regionMatches(true, 0, "bytes=", 0, "bytes=".length())) {
            return null;
        }
        String spec = value.substring("bytes=".length()).trim();
        if (spec.isEmpty() || spec.contains(",")) {
            return null;
        }
        int dash = spec.indexOf('-');
        if (dash < 0) {
            return null;
        }

        String startPart = spec.substring(0, dash).trim();
        String endPart = spec.substring(dash + 1).trim();
        try {
            if (startPart.isEmpty()) {
                if (endPart.isEmpty()) {
                    return null;
                }
                long suffixLength = Long.parseLong(endPart);
                return suffixLength <= 0 ? null : "bytes=-" + Math.min(suffixLength, MAX_RANGE_BYTES);
            }

            long start = Long.parseLong(startPart);
            if (start < 0) {
                return null;
            }
            long maxEnd = boundedEnd(start);
            if (endPart.isEmpty()) {
                return "bytes=" + start + "-" + maxEnd;
            }
            long end = Long.parseLong(endPart);
            return end < start ? null : "bytes=" + start + "-" + Math.min(end, maxEnd);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private static String normalizeBasePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
    }

    private static long boundedEnd(long start) {
        long delta = MAX_RANGE_BYTES - 1;
        return Long.MAX_VALUE - start < delta ? Long.MAX_VALUE : start + delta;
    }
}
