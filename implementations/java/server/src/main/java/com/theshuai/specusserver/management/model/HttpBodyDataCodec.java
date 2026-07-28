package com.theshuai.specusserver.management.model;

import org.brotli.dec.BrotliInputStream;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public final class HttpBodyDataCodec {
    private HttpBodyDataCodec() {
    }

    public static String toDisplayText(byte[] bodyData, String contentType, String headers, String fallbackText) {
        if (bodyData == null || bodyData.length == 0) {
            return fallbackText == null ? "" : fallbackText;
        }
        String contentEncoding = headerValue(headers, "content-encoding");
        if (hasEncodedBody(contentEncoding)) {
            byte[] decoded = decodeContentEncoding(bodyData, contentEncoding);
            if (decoded != null) {
                return toDisplayText(decoded, contentType);
            }
            return dataUrl("application/octet-stream", bodyData);
        }
        return toDisplayText(bodyData, contentType);
    }

    private static String toDisplayText(byte[] bodyData, String contentType) {
        if (!isTextBody(contentType) && !looksLikeText(bodyData)) {
            return dataUrl(mediaType(contentType), bodyData);
        }
        return sanitizeText(new String(bodyData, StandardCharsets.UTF_8));
    }

    private static byte[] decodeContentEncoding(byte[] bodyData, String contentEncoding) {
        String[] tokens = contentEncoding.split(",");
        byte[] current = bodyData;
        try {
            for (int i = tokens.length - 1; i >= 0; i--) {
                String token = tokens[i].trim().toLowerCase(Locale.ROOT);
                if (token.isBlank() || token.equals("identity")) {
                    continue;
                }
                if (token.equals("gzip") || token.equals("x-gzip")) {
                    current = gunzip(current);
                    continue;
                }
                if (token.equals("deflate") || token.equals("x-deflate")) {
                    current = inflate(current);
                    continue;
                }
                if (token.equals("br")) {
                    current = brotli(current);
                    continue;
                }
                return null;
            }
            return current;
        } catch (IOException | IllegalArgumentException ignored) {
            return null;
        }
    }

    private static byte[] gunzip(byte[] data) throws IOException {
        try (GZIPInputStream input = new GZIPInputStream(new ByteArrayInputStream(data))) {
            return readAll(input);
        }
    }

    private static byte[] inflate(byte[] data) throws IOException {
        try {
            try (InflaterInputStream input = new InflaterInputStream(new ByteArrayInputStream(data))) {
                return readAll(input);
            }
        } catch (IOException first) {
            try (InflaterInputStream input = new InflaterInputStream(new ByteArrayInputStream(data), new Inflater(true))) {
                return readAll(input);
            }
        }
    }

    private static byte[] brotli(byte[] data) throws IOException {
        try (BrotliInputStream input = new BrotliInputStream(new ByteArrayInputStream(data))) {
            return readAll(input);
        }
    }

    private static byte[] readAll(java.io.InputStream input) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) >= 0) {
            output.write(buffer, 0, read);
        }
        return output.toByteArray();
    }

    private static String dataUrl(String mediaType, byte[] bodyData) {
        return "data:" + mediaType + ";base64," + Base64.getEncoder().encodeToString(bodyData);
    }

    private static String headerValue(String headers, String name) {
        if (headers == null || headers.isBlank()) {
            return null;
        }
        String normalizedName = name.toLowerCase(Locale.ROOT);
        for (String header : headers.split("\\R")) {
            int separator = header.indexOf(':');
            if (separator > 0 && normalizedName.equals(header.substring(0, separator).trim().toLowerCase(Locale.ROOT))) {
                return header.substring(separator + 1).trim();
            }
        }
        return null;
    }

    private static boolean hasEncodedBody(String contentEncoding) {
        if (contentEncoding == null || contentEncoding.isBlank()) {
            return false;
        }
        for (String token : contentEncoding.split(",")) {
            String normalized = token.trim().toLowerCase(Locale.ROOT);
            if (!normalized.isBlank() && !normalized.equals("identity")) {
                return true;
            }
        }
        return false;
    }

    private static boolean isTextBody(String contentType) {
        String mediaType = mediaType(contentType);
        return mediaType.startsWith("text/")
                || mediaType.equals("application/json")
                || mediaType.endsWith("+json")
                || mediaType.equals("application/xml")
                || mediaType.endsWith("+xml")
                || mediaType.equals("application/x-www-form-urlencoded")
                || mediaType.equals("application/graphql")
                || mediaType.equals("application/javascript")
                || mediaType.equals("application/ecmascript")
                || mediaType.equals("application/x-yaml")
                || mediaType.equals("application/yaml");
    }

    private static boolean looksLikeText(byte[] data) {
        int inspected = Math.min(data.length, 512);
        int controls = 0;
        for (int i = 0; i < inspected; i++) {
            int value = data[i] & 0xff;
            if (value == 0) {
                return false;
            }
            if (value < 0x20 && value != '\r' && value != '\n' && value != '\t') {
                controls++;
            }
        }
        return inspected == 0 || controls * 10 <= inspected;
    }

    private static String mediaType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return "application/octet-stream";
        }
        String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return mediaType.matches("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+") ? mediaType : "application/octet-stream";
    }

    private static String sanitizeText(String text) {
        if (text == null || text.isEmpty()) {
            return "";
        }
        StringBuilder result = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if ((Character.isISOControl(ch) || Character.isSurrogate(ch)) && ch != '\r' && ch != '\n' && ch != '\t') {
                result.append('.');
            } else {
                result.append(ch);
            }
        }
        return result.toString();
    }
}
