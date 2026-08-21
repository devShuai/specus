package com.theshuai.specusserver.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Maps browser Origin/Referer onto the upstream target origin so local CSRF/Host
 * fences (DSH {@code isTrustedApiRequest}) do not treat the public ingress as cross-site.
 */
final class UpstreamBrowserHeaders {
    private UpstreamBrowserHeaders() {
    }

    static List<String> rewrite(List<String> headers, String targetBaseUrl) {
        String origin = originOf(targetBaseUrl);
        if (origin == null || headers == null || headers.isEmpty()) {
            return headers;
        }
        List<String> rewritten = new ArrayList<>(headers.size());
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator <= 0) {
                rewritten.add(header);
                continue;
            }
            String name = header.substring(0, separator);
            String value = header.substring(separator + 1);
            if (name.equalsIgnoreCase("Origin")) {
                rewritten.add(name + ":" + origin);
            } else if (name.equalsIgnoreCase("Referer")) {
                rewritten.add(name + ":" + rewriteReferer(value, origin));
            } else if (name.equalsIgnoreCase("Sec-Fetch-Site")
                    && value.trim().equalsIgnoreCase("cross-site")) {
                rewritten.add(name + ":same-origin");
            } else {
                rewritten.add(header);
            }
        }
        return rewritten;
    }

    static String originOf(String targetBaseUrl) {
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            return null;
        }
        try {
            URI uri = URI.create(targetBaseUrl.trim());
            String scheme = uri.getScheme();
            if (scheme == null || uri.getHost() == null || uri.getHost().isBlank()) {
                return null;
            }
            scheme = scheme.toLowerCase(Locale.ROOT);
            if ("ws".equals(scheme)) {
                scheme = "http";
            } else if ("wss".equals(scheme)) {
                scheme = "https";
            } else if (!"http".equals(scheme) && !"https".equals(scheme)) {
                return null;
            }
            int port = uri.getPort();
            String host = uri.getHost();
            if (port > 0) {
                return scheme + "://" + host + ":" + port;
            }
            return scheme + "://" + host;
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    static String rewriteReferer(String referer, String origin) {
        String trimmed = referer == null ? "" : referer.trim();
        try {
            URI parsed = URI.create(trimmed);
            URI base = URI.create(origin);
            if (parsed.getScheme() == null || parsed.getHost() == null) {
                return origin + "/";
            }
            return new URI(base.getScheme(), parsed.getUserInfo(), base.getHost(), base.getPort(),
                    parsed.getRawPath(), parsed.getRawQuery(), parsed.getRawFragment()).toString();
        } catch (Exception ignored) {
            return origin + "/";
        }
    }
}
