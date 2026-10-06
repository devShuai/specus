package com.theshuai.specusserver.connectivity;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Optional;

/**
 * The body of {@code POST /api/admin/http-routes/{routeId}/connectivity-check} and the probe path in
 * it (protocol/spec/service-connectivity-check.md section 3.1).
 *
 * <p>An empty body, or one of only whitespace, is {@code {}}. Anything else must be a JSON object
 * whose only key is {@code path}, a JSON string. The path is checked on its bytes: 1 to 256 of
 * them, a leading {@code /} but not {@code //}, only RFC 3986 pchar and {@code /} with well-formed
 * {@code %XX}, and no {@code .} or {@code ..} segment, {@code %2e} counted as a dot.
 */
public final class ConnectivityCheckRequest {
    public static final int MAX_BODY_BYTES = 4096;
    public static final int MAX_PATH_BYTES = 256;
    public static final String DEFAULT_PATH = "/";

    private static final String PATH_SYMBOLS = "-._~!$&'()*+,;=:@/";
    private static final ObjectMapper JSON = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private ConnectivityCheckRequest() {
    }

    /** Reads at most one byte past the limit, so an oversized body is refused without buffering it. */
    public static byte[] readBody(InputStream input) throws IOException {
        return input == null ? new byte[0] : input.readNBytes(MAX_BODY_BYTES + 1);
    }

    /** The probe path the body asks for, or empty when the body or the path is invalid. */
    public static Optional<String> probePath(byte[] body) {
        if (body != null && body.length > MAX_BODY_BYTES) {
            return Optional.empty();
        }
        if (body == null || isBlank(body)) {
            return Optional.of(DEFAULT_PATH);
        }
        JsonNode root;
        try {
            root = JSON.readTree(body);
        } catch (IOException malformed) {
            return Optional.empty();
        }
        if (root == null || !root.isObject()) {
            return Optional.empty();
        }
        String path = DEFAULT_PATH;
        Iterator<String> names = root.fieldNames();
        while (names.hasNext()) {
            String name = names.next();
            JsonNode value = root.get(name);
            if (!"path".equals(name) || value == null || !value.isTextual()) {
                return Optional.empty();
            }
            path = value.textValue();
        }
        return isValidPath(path) ? Optional.of(path) : Optional.empty();
    }

    public static boolean isValidPath(String path) {
        if (path == null) {
            return false;
        }
        byte[] bytes = path.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 1 || bytes.length > MAX_PATH_BYTES || bytes[0] != '/'
                || (bytes.length > 1 && bytes[1] == '/')) {
            return false;
        }
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xff;
            if (value == '%') {
                if (index + 2 >= bytes.length || !isHex(bytes[index + 1]) || !isHex(bytes[index + 2])) {
                    return false;
                }
                index += 2;
            } else if (!isAlpha(value) && !isDigit(value) && PATH_SYMBOLS.indexOf(value) < 0) {
                return false;
            }
        }
        // Only ASCII is left, so the string splits like its bytes.
        for (String segment : path.split("/", -1)) {
            String dots = segment.replace("%2e", ".").replace("%2E", ".");
            if (dots.equals(".") || dots.equals("..")) {
                return false;
            }
        }
        return true;
    }

    private static boolean isBlank(byte[] body) {
        for (byte value : body) {
            if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                return false;
            }
        }
        return true;
    }

    private static boolean isAlpha(int value) {
        return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z');
    }

    private static boolean isDigit(int value) {
        return value >= '0' && value <= '9';
    }

    private static boolean isHex(byte value) {
        return isDigit(value) || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F');
    }
}
