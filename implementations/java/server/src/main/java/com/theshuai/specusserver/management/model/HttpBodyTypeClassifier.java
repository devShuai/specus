package com.theshuai.specusserver.management.model;

import java.util.Locale;
import java.util.Set;

public final class HttpBodyTypeClassifier {
    public static final String EMPTY = "empty";
    public static final String JSON = "json";
    public static final String HTML = "html";
    public static final String XML = "xml";
    public static final String IMAGE = "image";
    public static final String VIDEO = "video";
    public static final String AUDIO = "audio";
    public static final String FORM = "form";
    public static final String SCRIPT = "script";
    public static final String TEXT = "text";
    public static final String BINARY = "binary";

    private static final Set<String> SUPPORTED_TYPES = Set.of(
            EMPTY, JSON, HTML, XML, IMAGE, VIDEO, AUDIO, FORM, SCRIPT, TEXT, BINARY);

    private HttpBodyTypeClassifier() {
    }

    public static String classify(String contentType, long bodyBytes) {
        if (bodyBytes <= 0) {
            return EMPTY;
        }
        String mediaType = mediaType(contentType);
        if (mediaType.isEmpty()) {
            return BINARY;
        }
        if (mediaType.equals("application/json") || mediaType.endsWith("+json")) {
            return JSON;
        }
        if (mediaType.equals("text/html")) {
            return HTML;
        }
        if (mediaType.equals("application/xml") || mediaType.equals("text/xml") || mediaType.endsWith("+xml")) {
            return XML;
        }
        if (mediaType.startsWith("image/")) {
            return IMAGE;
        }
        if (mediaType.startsWith("video/")) {
            return VIDEO;
        }
        if (mediaType.startsWith("audio/")) {
            return AUDIO;
        }
        if (mediaType.equals("application/x-www-form-urlencoded") || mediaType.equals("multipart/form-data")) {
            return FORM;
        }
        if (mediaType.equals("application/javascript")
                || mediaType.equals("application/ecmascript")
                || mediaType.equals("text/javascript")
                || mediaType.equals("text/ecmascript")) {
            return SCRIPT;
        }
        if (mediaType.startsWith("text/")) {
            return TEXT;
        }
        return BINARY;
    }

    public static String normalize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return SUPPORTED_TYPES.contains(normalized) ? normalized : null;
    }

    public static String normalizeOrClassify(String value, String contentType, long bodyBytes) {
        String normalized = normalize(value);
        return normalized == null ? classify(contentType, bodyBytes) : normalized;
    }

    public static String mediaType(String contentType) {
        if (contentType == null || contentType.isBlank()) {
            return "";
        }
        return contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    }
}
