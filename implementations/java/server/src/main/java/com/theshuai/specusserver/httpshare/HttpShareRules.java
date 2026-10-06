package com.theshuai.specusserver.httpshare;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The fixed rules of temporary HTTP shares (protocol/spec/temporary-http-share.md): token format,
 * path-prefix canonicalisation and scope, the share cookie, and the header rewriting on the way to
 * the device and back. Pure functions only; every value here is pinned by
 * {@code protocol/test-vectors/temporary-http-share-v1.json}.
 */
public final class HttpShareRules {
    public static final String TOKEN_VERSION = "hs1";
    public static final int SHARE_ID_BYTES = 12;
    public static final int SECRET_BYTES = 32;
    public static final Pattern TOKEN_PATTERN = Pattern.compile("hs1\\.([A-Za-z0-9_-]{16})\\.([A-Za-z0-9_-]{43})");
    public static final Pattern SHARE_ID_PATTERN = Pattern.compile("[A-Za-z0-9_-]{16}");
    public static final String COOKIE_NAME = "__Secure-specus_http_share";
    public static final int MAX_COOKIE_CANDIDATES = 4;
    public static final String SHARE_ROOT = "/http-share/";
    public static final String LINK_ROOT = "/#/http-share/";

    public static final int MIN_EXPIRES_SECONDS = 300;
    public static final int MAX_EXPIRES_SECONDS = 604_800;
    public static final int MAX_ACTIVE_PER_ROUTE = 20;
    public static final int LABEL_MAX_CODE_POINTS = 60;
    public static final int PREFIX_MAX_BYTES = 256;
    public static final List<String> READ_METHODS = List.of("GET", "HEAD");

    public static final long EXCHANGE_INTERVAL_MS = 6_000;
    public static final int EXCHANGE_BURST = 10;
    public static final long SHARE_INTERVAL_MS = 50;
    public static final int SHARE_BURST = 200;
    public static final int RATE_LIMIT_MAX_KEYS = 10_000;
    public static final int MAX_CONCURRENT_PER_SHARE = 64;

    public static final int SHARE_RETENTION_DAYS = 30;
    public static final int AUDIT_RETENTION_DAYS = 180;
    /** The sweep runs every 30 s; the contract allows at most 60 s. */
    public static final long SWEEP_INTERVAL_MS = 30_000;
    public static final int SWEEP_INTERVAL_MAX_SECONDS = 60;
    /** In-flight streams are rechecked against the database every 2 s; the contract allows 5 s. */
    public static final long STREAM_RECHECK_INTERVAL_MS = 2_000;
    public static final int STREAM_RECHECK_MAX_SECONDS = 5;
    /** Streams whose share has reached expiresAt are cut by a 1 s ticker. */
    public static final long STREAM_EXPIRY_TICK_MS = 1_000;

    public static final String ACCESS_READ = "read";
    public static final String ACCESS_FULL = "full";

    public static final String REASON_REVOKED_BY_USER = "revoked-by-user";
    public static final String REASON_ROUTE_DISABLED = "route-disabled";
    public static final String REASON_ROUTE_MADE_PUBLIC = "route-made-public";
    public static final String REASON_ROUTE_DELETED = "route-deleted";
    public static final String REASON_CLIENT_DISABLED = "client-disabled";
    public static final String REASON_CLIENT_DELETED = "client-deleted";
    public static final String REASON_CREATOR_LOST_ACCESS = "creator-lost-access";
    public static final List<String> REVOKE_REASONS = List.of(
            REASON_REVOKED_BY_USER, REASON_ROUTE_DISABLED, REASON_ROUTE_MADE_PUBLIC, REASON_ROUTE_DELETED,
            REASON_CLIENT_DISABLED, REASON_CLIENT_DELETED, REASON_CREATOR_LOST_ACCESS);

    public static final String AUDIT_SHARE_CREATED = "share.created";
    public static final String AUDIT_SHARE_REVOKED = "share.revoked";
    public static final String AUDIT_SHARE_EXPIRED = "share.expired";
    public static final String AUDIT_ROUTE_CREATED = "route.created";
    public static final String AUDIT_ROUTE_EXPOSURE_CHANGED = "route.exposure-changed";
    public static final String AUDIT_ROUTE_CREDENTIALS_CHANGED = "route.credentials-changed";
    public static final String AUDIT_ROUTE_DELETED = "route.deleted";
    public static final List<String> AUDIT_ACTIONS = List.of(
            AUDIT_SHARE_CREATED, AUDIT_SHARE_REVOKED, AUDIT_SHARE_EXPIRED, AUDIT_ROUTE_CREATED,
            AUDIT_ROUTE_EXPOSURE_CHANGED, AUDIT_ROUTE_CREDENTIALS_CHANGED, AUDIT_ROUTE_DELETED);

    public static final String EXPOSURE_DISABLED = "disabled";
    public static final String EXPOSURE_PROTECTED = "protected";
    public static final String EXPOSURE_PUBLIC = "public";

    public static final String CODE_REQUEST_INVALID = "SHARE_REQUEST_INVALID";
    public static final String CODE_UNAVAILABLE = "SHARE_UNAVAILABLE";
    public static final String CODE_ROUTE_NOT_FOUND = "SHARE_ROUTE_NOT_FOUND";
    public static final String CODE_ROUTE_DISABLED = "SHARE_ROUTE_DISABLED";
    public static final String CODE_CLIENT_DISABLED = "SHARE_CLIENT_DISABLED";
    public static final String CODE_ROUTE_PUBLIC = "SHARE_ROUTE_PUBLIC";
    public static final String CODE_LIMIT_REACHED = "SHARE_LIMIT_REACHED";
    public static final String CODE_NOT_FOUND = "SHARE_NOT_FOUND";
    public static final String CODE_RATE_LIMITED = "SHARE_RATE_LIMITED";
    public static final String CODE_REVOKED = "SHARE_REVOKED";
    public static final String CODE_EXPIRED = "SHARE_EXPIRED";
    public static final String CODE_METHOD_NOT_ALLOWED = "SHARE_METHOD_NOT_ALLOWED";
    public static final String CODE_SCOPE_DENIED = "SHARE_SCOPE_DENIED";
    public static final String CODE_BUSY = "SHARE_BUSY";
    public static final String CODE_FORBIDDEN = "SHARE_FORBIDDEN";

    private static final String UNRESERVED =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    /**
     * RFC 3986 pchar without ";": a servlet container treats ";" as the start of path parameters,
     * so "/docs/..;/admin" would leave the prefix after the container has normalised it.
     */
    private static final String PATH_CHARS = UNRESERVED + "!$&'()*+,=:@/";
    private static final Pattern ESCAPE = Pattern.compile("%[0-9A-F]{2}");
    private static final Set<String> CACHE_HEADERS = Set.of(
            "cache-control", "cdn-cache-control", "surrogate-control", "expires", "pragma");
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private HttpShareRules() {
    }

    // ---------------------------------------------------------------------------------------------
    // Tokens

    /** A freshly generated share id, token and token hash. */
    public record Credentials(String shareId, String token, String tokenSha256) {
        public String sharePath() {
            return SHARE_ROOT + shareId + "/";
        }

        public String linkPath() {
            return LINK_ROOT + token;
        }
    }

    /** Draws the share id and then the secret from {@code random} (a CSPRNG outside tests). */
    public static Credentials newCredentials(HttpShareRandom random) {
        byte[] shareIdBytes = new byte[SHARE_ID_BYTES];
        byte[] secretBytes = new byte[SECRET_BYTES];
        random.nextBytes(shareIdBytes);
        random.nextBytes(secretBytes);
        String shareId = BASE64URL.encodeToString(shareIdBytes);
        String token = TOKEN_VERSION + "." + shareId + "." + BASE64URL.encodeToString(secretBytes);
        return new Credentials(shareId, token, tokenSha256(token));
    }

    /**
     * The share id embedded in a well-formed token, or null. The whole string must match: no
     * trimming, so a trailing newline is not tolerated.
     */
    public static String parseToken(String text) {
        if (text == null) {
            return null;
        }
        Matcher matcher = TOKEN_PATTERN.matcher(text);
        return matcher.matches() ? matcher.group(1) : null;
    }

    public static boolean isShareId(String text) {
        return text != null && SHARE_ID_PATTERN.matcher(text).matches();
    }

    /** lowercase_hex(SHA-256(UTF-8(token))). */
    public static String tokenSha256(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    /** Constant-time comparison of a presented token against the stored hash. */
    public static boolean tokenMatches(String token, String storedSha256) {
        if (token == null || storedSha256 == null) {
            return false;
        }
        return MessageDigest.isEqual(
                tokenSha256(token).getBytes(StandardCharsets.US_ASCII),
                storedSha256.getBytes(StandardCharsets.US_ASCII));
    }

    // ---------------------------------------------------------------------------------------------
    // Paths

    /**
     * RFC 3986 6.2.2 syntax normalisation of an already percent-encoded path: escapes of unreserved
     * characters are decoded and every other escape gets upper-case hex. Returns null for a path
     * that is not plain ASCII pchar/"/"/escapes, or that has a malformed escape. The result only
     * decides the scope; the request is forwarded with its original raw path.
     */
    public static String normalizePath(String raw) {
        if (raw == null) {
            return null;
        }
        StringBuilder out = new StringBuilder(raw.length());
        int index = 0;
        while (index < raw.length()) {
            char ch = raw.charAt(index);
            if (ch == '%') {
                if (index + 3 > raw.length() || !isHex(raw.charAt(index + 1)) || !isHex(raw.charAt(index + 2))) {
                    return null;
                }
                char decoded = (char) Integer.parseInt(raw.substring(index + 1, index + 3), 16);
                if (UNRESERVED.indexOf(decoded) >= 0) {
                    out.append(decoded);
                } else {
                    out.append('%').append(raw.substring(index + 1, index + 3).toUpperCase(Locale.ROOT));
                }
                index += 3;
                continue;
            }
            if (PATH_CHARS.indexOf(ch) < 0) {
                return null;
            }
            out.append(ch);
            index++;
        }
        return out.toString();
    }

    /**
     * A normalized path that could step outside a prefix once the target decodes it: a dot
     * segment, or an escaped slash, backslash or control character.
     */
    static boolean unsafeForPrefix(String normalized) {
        Matcher escapes = ESCAPE.matcher(normalized);
        while (escapes.find()) {
            int code = Integer.parseInt(escapes.group().substring(1), 16);
            if (code == 0x2F || code == 0x5C || code < 0x20 || code == 0x7F) {
                return true;
            }
        }
        String[] segments = normalized.split("/", -1);
        for (int index = 1; index < segments.length; index++) {
            if (segments[index].equals(".") || segments[index].equals("..")) {
                return true;
            }
        }
        return false;
    }

    /** The stored form of a pathPrefix, or null when it must be rejected with 400. */
    public static String canonicalPrefix(String value) {
        if (value == null || !value.startsWith("/") || value.startsWith("//")) {
            return null;
        }
        String normalized = normalizePath(value);
        if (normalized == null || unsafeForPrefix(normalized)) {
            return null;
        }
        String inner = normalized.endsWith("/")
                ? normalized.substring(1, Math.max(1, normalized.length() - 1))
                : normalized.substring(1);
        if (!inner.isEmpty()) {
            for (String segment : inner.split("/", -1)) {
                if (segment.isEmpty()) {
                    return null;
                }
            }
        }
        String canonical = normalized.endsWith("/") ? normalized : normalized + "/";
        if (canonical.getBytes(StandardCharsets.US_ASCII).length > PREFIX_MAX_BYTES) {
            return null;
        }
        return canonical;
    }

    /** Whether the raw relative path (after {@code /http-share/{id}}) lies inside the prefix. */
    public static boolean pathInScope(String prefix, String relativePath) {
        if ("/".equals(prefix)) {
            return true;   // the whole route: no rule beyond the route's own
        }
        String normalized = normalizePath(relativePath);
        if (normalized == null || unsafeForPrefix(normalized)) {
            return false;
        }
        return normalized.equals(prefix.substring(0, prefix.length() - 1)) || normalized.startsWith(prefix);
    }

    // ---------------------------------------------------------------------------------------------
    // Cookies

    /** Every non-empty {@code name=value} pair of the Cookie headers, in order. */
    public static List<String> cookiePairs(List<String> cookieHeaders) {
        List<String> pairs = new ArrayList<>();
        if (cookieHeaders == null) {
            return pairs;
        }
        for (String header : cookieHeaders) {
            if (header == null) {
                continue;
            }
            for (String part : header.split(";", -1)) {
                String pair = stripSpaceTab(part);
                if (!pair.isEmpty()) {
                    pairs.add(pair);
                }
            }
        }
        return pairs;
    }

    static String pairName(String pair) {
        int separator = pair.indexOf('=');
        return stripSpaceTab(separator < 0 ? pair : pair.substring(0, separator));
    }

    static String pairValue(String pair) {
        int separator = pair.indexOf('=');
        return separator < 0 ? "" : stripSpaceTab(pair.substring(separator + 1));
    }

    /**
     * Values of the share cookie that name this share, in order, at most four. A page on the same
     * origin can plant a second cookie of the same name with a longer Path; the browser sends it
     * first, so the server tries a few values instead of only the first one.
     */
    public static List<String> credentialCandidates(List<String> cookieHeaders, String shareId) {
        List<String> candidates = new ArrayList<>();
        for (String pair : cookiePairs(cookieHeaders)) {
            if (!COOKIE_NAME.equals(pairName(pair))) {
                continue;
            }
            String value = pairValue(pair);
            if (shareId.equals(parseToken(value))) {
                candidates.add(value);
                if (candidates.size() == MAX_COOKIE_CANDIDATES) {
                    break;
                }
            }
        }
        return candidates;
    }

    /** The single Cookie header sent to the device: every pair except the share cookie, in order. */
    public static String forwardedCookie(List<String> cookieHeaders) {
        List<String> kept = new ArrayList<>();
        for (String pair : cookiePairs(cookieHeaders)) {
            if (!COOKIE_NAME.equals(pairName(pair))) {
                kept.add(pair);
            }
        }
        return kept.isEmpty() ? null : String.join("; ", kept);
    }

    public static String cookiePath(String shareId) {
        return SHARE_ROOT + shareId + "/";
    }

    /** The Set-Cookie value written by a successful exchange. */
    public static String setCookie(String shareId, String token, long maxAgeSeconds) {
        return COOKIE_NAME + "=" + token + "; Path=" + cookiePath(shareId) + "; Max-Age=" + maxAgeSeconds
                + "; HttpOnly; Secure; SameSite=Strict";
    }

    /** The Set-Cookie value that makes the browser drop the share cookie of an ended share. */
    public static String clearCookie(String shareId) {
        return COOKIE_NAME + "=; Path=" + cookiePath(shareId) + "; Max-Age=0; HttpOnly; Secure; SameSite=Strict";
    }

    // ---------------------------------------------------------------------------------------------
    // Response headers

    /**
     * An upstream Set-Cookie value confined to the share path, or null when it is dropped. Every
     * route and share lives on one origin; a cookie set with Path=/ or a Domain by the target of
     * share A would otherwise be sent to every other route and share the visitor opens. The share
     * cookie and __Host- cookies (which require Path=/) are dropped; Domain is removed; a Path
     * starting with "/" is moved under the share path; a missing or relative Path already defaults
     * to the request directory, which is under the share path.
     */
    public static String scopeSetCookie(String value, String shareId) {
        String[] parts = value.split(";", -1);
        String name = pairName(parts[0]);
        if (COOKIE_NAME.equals(name) || name.toLowerCase(Locale.ROOT).startsWith("__host-")) {
            return null;
        }
        List<String> out = new ArrayList<>();
        out.add(stripSpaceTab(parts[0]));
        for (int index = 1; index < parts.length; index++) {
            String attribute = stripSpaceTab(parts[index]);
            if (attribute.isEmpty()) {
                continue;
            }
            int separator = attribute.indexOf('=');
            String key = stripSpaceTab(separator < 0 ? attribute : attribute.substring(0, separator))
                    .toLowerCase(Locale.ROOT);
            if (key.equals("domain")) {
                continue;
            }
            if (key.equals("path")) {
                String path = separator < 0 ? "" : stripSpaceTab(attribute.substring(separator + 1));
                if (path.startsWith("/")) {
                    attribute = "Path=" + SHARE_ROOT + shareId + path;
                }
            }
            out.add(attribute);
        }
        return String.join("; ", out);
    }

    /**
     * Headers relayed to a share visitor, after the route's own response rules. Set-Cookie is
     * confined to the share path; Clear-Site-Data is dropped because it would wipe the whole
     * origin; cache headers are replaced so that no shared cache keeps a copy and the browser
     * revalidates every reuse. A 101 only gets the cookie and Clear-Site-Data rules.
     */
    public static List<String> responseHeaders(int status, List<String> headers, String shareId) {
        boolean noStore = false;
        List<String> out = new ArrayList<>();
        if (headers != null) {
            for (String header : headers) {
                if (header == null) {
                    continue;
                }
                int separator = header.indexOf(':');
                String name = separator < 0 ? header : header.substring(0, separator);
                String value = separator < 0 ? "" : header.substring(separator + 1);
                String lowered = name.strip().toLowerCase(Locale.ROOT);
                if (lowered.equals("clear-site-data")) {
                    continue;
                }
                if (lowered.equals("set-cookie")) {
                    String scoped = scopeSetCookie(stripSpaceTab(value), shareId);
                    if (scoped != null) {
                        out.add(name.strip() + ":" + scoped);
                    }
                    continue;
                }
                if (status != 101 && CACHE_HEADERS.contains(lowered)) {
                    if (lowered.equals("cache-control")) {
                        for (String directive : value.split(",", -1)) {
                            String directiveName = directive.strip();
                            int equals = directiveName.indexOf('=');
                            if (equals >= 0) {
                                directiveName = directiveName.substring(0, equals);
                            }
                            noStore = noStore || directiveName.toLowerCase(Locale.ROOT).equals("no-store");
                        }
                    }
                    continue;
                }
                out.add(header);
            }
        }
        if (status != 101) {
            out.add("Cache-Control:" + (noStore ? "private, no-store" : "private, no-cache"));
        }
        return out;
    }

    // ---------------------------------------------------------------------------------------------

    private static boolean isHex(char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F');
    }

    /** Python's {@code str.strip(" \t")}: only spaces and tabs, never other whitespace. */
    static String stripSpaceTab(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) {
            start++;
        }
        while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) {
            end--;
        }
        return value.substring(start, end);
    }
}
