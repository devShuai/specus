package com.theshuai.specusserver.management.service;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class HttpMediaManifestSupport {
    static final String HLS_MANIFEST = "HLS_MANIFEST";
    static final String DASH_MANIFEST = "DASH_MANIFEST";
    static final String PROGRESSIVE = "PROGRESSIVE";
    static final String MEDIA_SEGMENT = "MEDIA_SEGMENT";

    private static final Pattern HLS_URI_ATTRIBUTE = Pattern.compile("URI=(\"([^\"]+)\"|'([^']+)')");
    private static final Pattern DASH_URI_ATTRIBUTE = Pattern.compile(
            "(?i)(media|initialization|sourceURL|href)\\s*=\\s*(\"([^\"]+)\"|'([^']+)')");
    private static final Pattern DASH_BASE_URL = Pattern.compile(
            "(?is)<BaseURL(\\s[^>]*)?>([^<]+)</BaseURL>");
    private static final Pattern CONTENT_RANGE = Pattern.compile(
            "(?i)^bytes\\s+(\\d+)-(\\d+)/(\\d+|\\*)$");
    private static final Pattern NUMBER_IN_NAME = Pattern.compile("(\\d+)(?=\\.[^.]+$)");

    private HttpMediaManifestSupport() {
    }

    static String classify(String sourceUrl, String contentType, int statusCode, String contentRange) {
        String type = mediaType(contentType);
        String path = pathOnly(sourceUrl).toLowerCase(Locale.ROOT);
        if (type.equals("application/vnd.apple.mpegurl")
                || type.equals("application/x-mpegurl")
                || type.equals("audio/mpegurl")
                || path.endsWith(".m3u8")) {
            return HLS_MANIFEST;
        }
        if (type.equals("application/dash+xml") || path.endsWith(".mpd")) {
            return DASH_MANIFEST;
        }
        if (isSegmentPath(path) || type.equals("video/mp2t")
                || type.equals("application/octet-stream")) {
            return MEDIA_SEGMENT;
        }
        if (type.startsWith("video/") || type.startsWith("audio/")
                || isProgressivePath(path)
                || (statusCode == 206 && contentRange != null)) {
            return PROGRESSIVE;
        }
        return null;
    }

    static ContentRange parseContentRange(String value) {
        if (value == null) {
            return null;
        }
        Matcher matcher = CONTENT_RANGE.matcher(value.trim());
        if (!matcher.matches()) {
            return null;
        }
        long start = Long.parseLong(matcher.group(1));
        long end = Long.parseLong(matcher.group(2));
        Long total = "*".equals(matcher.group(3)) ? null : Long.parseLong(matcher.group(3));
        if (end < start || (total != null && end >= total)) {
            return null;
        }
        return new ContentRange(start, end, total);
    }

    static Long inferSequence(String sourceUrl) {
        Matcher matcher = NUMBER_IN_NAME.matcher(pathOnly(sourceUrl));
        if (!matcher.find()) {
            return null;
        }
        try {
            return Long.parseLong(matcher.group(1));
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    static boolean isInitializationSegment(String sourceUrl) {
        String path = pathOnly(sourceUrl).toLowerCase(Locale.ROOT);
        String file = path.substring(path.lastIndexOf('/') + 1);
        return file.startsWith("init.") || file.startsWith("init-") || file.contains("initialization");
    }

    static ParsedManifest parse(String kind, String sourceUrl, String text) {
        if (HLS_MANIFEST.equals(kind)) {
            return parseHls(sourceUrl, text);
        }
        if (DASH_MANIFEST.equals(kind)) {
            return parseDash(sourceUrl, text);
        }
        return new ParsedManifest(false, List.of());
    }

    static String rewrite(String kind, String sourceUrl, String text, String assetBasePath) {
        if (HLS_MANIFEST.equals(kind)) {
            return rewriteHls(sourceUrl, text, assetBasePath);
        }
        if (DASH_MANIFEST.equals(kind)) {
            return rewriteDash(sourceUrl, text, assetBasePath);
        }
        return text;
    }

    static String resolveSourceUrl(String baseSourceUrl, String reference) {
        if (reference == null || reference.isBlank() || reference.startsWith("data:")) {
            return reference;
        }
        try {
            URI base = URI.create("https://capture.invalid" + normalizeSourceUrl(baseSourceUrl));
            URI resolved = base.resolve(reference.trim());
            String path = resolved.getRawPath();
            if (path == null || path.isBlank()) {
                path = "/";
            }
            return normalizeSourceUrl(path + (resolved.getRawQuery() == null ? "" : "?" + resolved.getRawQuery()));
        } catch (IllegalArgumentException ignored) {
            return normalizeSourceUrl(reference);
        }
    }

    static String normalizeSourceUrl(String value) {
        if (value == null || value.isBlank()) {
            return "/";
        }
        String normalized = value.trim();
        try {
            URI uri = URI.create(normalized);
            if (uri.isAbsolute()) {
                normalized = (uri.getRawPath() == null || uri.getRawPath().isBlank() ? "/" : uri.getRawPath())
                        + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
            }
        } catch (IllegalArgumentException ignored) {
            // Keep the original relative value and normalize it below.
        }
        if (!normalized.startsWith("/")) {
            normalized = "/" + normalized;
        }
        return normalized.length() <= 3072 ? normalized : normalized.substring(0, 3072);
    }

    private static ParsedManifest parseHls(String sourceUrl, String text) {
        List<ManifestReference> references = new ArrayList<>();
        long mediaSequence = 0;
        boolean endList = false;
        boolean hasMediaSegment = false;
        String[] lines = text.split("\\R", -1);
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith("#EXT-X-MEDIA-SEQUENCE:")) {
                try {
                    mediaSequence = Long.parseLong(trimmed.substring(trimmed.indexOf(':') + 1).trim());
                } catch (NumberFormatException ignored) {
                    mediaSequence = 0;
                }
            } else if (trimmed.equals("#EXT-X-ENDLIST")) {
                endList = true;
            }

            Matcher attribute = HLS_URI_ATTRIBUTE.matcher(line);
            while (attribute.find()) {
                String uri = firstText(attribute.group(2), attribute.group(3));
                String relation = trimmed.startsWith("#EXT-X-MAP") ? "INITIALIZATION"
                        : trimmed.startsWith("#EXT-X-KEY") ? "KEY" : "ASSET";
                references.add(new ManifestReference(relation, null, uri, resolveSourceUrl(sourceUrl, uri)));
            }
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                String relation = pathOnly(trimmed).toLowerCase(Locale.ROOT).endsWith(".m3u8")
                        ? "PLAYLIST" : "SEGMENT";
                hasMediaSegment = hasMediaSegment || "SEGMENT".equals(relation);
                Long sequence = "SEGMENT".equals(relation) ? mediaSequence++ : null;
                references.add(new ManifestReference(
                        relation, sequence, trimmed, resolveSourceUrl(sourceUrl, trimmed)));
            }
        }
        return new ParsedManifest(hasMediaSegment && !endList, references);
    }

    private static ParsedManifest parseDash(String sourceUrl, String text) {
        List<ManifestReference> references = new ArrayList<>();
        Matcher attributes = DASH_URI_ATTRIBUTE.matcher(text);
        long sequence = 0;
        while (attributes.find()) {
            String name = attributes.group(1).toLowerCase(Locale.ROOT);
            String uri = firstText(attributes.group(3), attributes.group(4));
            String relation = name.equals("initialization") || name.equals("sourceurl")
                    ? "INITIALIZATION" : "SEGMENT";
            references.add(new ManifestReference(
                    relation,
                    "SEGMENT".equals(relation) ? sequence++ : null,
                    uri,
                    resolveSourceUrl(sourceUrl, uri)));
        }
        Matcher baseUrls = DASH_BASE_URL.matcher(text);
        while (baseUrls.find()) {
            String uri = baseUrls.group(2).trim();
            if (!uri.isBlank()) {
                references.add(new ManifestReference(
                        "BASE", null, uri, resolveSourceUrl(sourceUrl, uri)));
            }
        }
        boolean live = Pattern.compile("(?i)<MPD\\b[^>]*\\btype\\s*=\\s*[\"']dynamic[\"']")
                .matcher(text).find();
        return new ParsedManifest(live, references);
    }

    private static String rewriteHls(String sourceUrl, String text, String assetBasePath) {
        StringBuilder result = new StringBuilder(text.length() + 256);
        String[] lines = text.split("\\R", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            Matcher matcher = HLS_URI_ATTRIBUTE.matcher(line);
            StringBuffer attributes = new StringBuffer();
            while (matcher.find()) {
                String original = firstText(matcher.group(2), matcher.group(3));
                String replacement = "URI=\"" + assetUrl(assetBasePath, resolveSourceUrl(sourceUrl, original)) + "\"";
                matcher.appendReplacement(attributes, Matcher.quoteReplacement(replacement));
            }
            matcher.appendTail(attributes);
            String rewritten = attributes.toString();
            String trimmed = rewritten.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                rewritten = assetUrl(assetBasePath, resolveSourceUrl(sourceUrl, trimmed));
            }
            result.append(rewritten);
            if (i + 1 < lines.length) {
                result.append('\n');
            }
        }
        return result.toString();
    }

    private static String rewriteDash(String sourceUrl, String text, String assetBasePath) {
        Matcher attributes = DASH_URI_ATTRIBUTE.matcher(text);
        StringBuffer rewritten = new StringBuffer();
        while (attributes.find()) {
            String attributeName = attributes.group(1);
            String original = firstText(attributes.group(3), attributes.group(4));
            String value = xmlEscape(assetUrl(assetBasePath, resolveSourceUrl(sourceUrl, original)));
            attributes.appendReplacement(rewritten,
                    Matcher.quoteReplacement(attributeName + "=\"" + value + "\""));
        }
        attributes.appendTail(rewritten);

        Matcher baseUrls = DASH_BASE_URL.matcher(rewritten.toString());
        StringBuffer result = new StringBuffer();
        while (baseUrls.find()) {
            String prefix = baseUrls.group(1) == null ? "" : baseUrls.group(1);
            String value = xmlEscape(assetUrl(assetBasePath,
                    resolveSourceUrl(sourceUrl, baseUrls.group(2).trim())));
            baseUrls.appendReplacement(result,
                    Matcher.quoteReplacement("<BaseURL" + prefix + ">" + value + "</BaseURL>"));
        }
        baseUrls.appendTail(result);
        return result.toString();
    }

    private static String assetUrl(String assetBasePath, String resolvedSourceUrl) {
        String encoded = URLEncoder.encode(resolvedSourceUrl, StandardCharsets.UTF_8)
                .replace("+", "%20")
                .replace("%24", "$");
        return assetBasePath + "?url=" + encoded;
    }

    private static boolean isProgressivePath(String path) {
        return path.endsWith(".mp4") || path.endsWith(".webm") || path.endsWith(".mkv")
                || path.endsWith(".mov") || path.endsWith(".m4v") || path.endsWith(".mp3")
                || path.endsWith(".m4a") || path.endsWith(".ogg") || path.endsWith(".opus")
                || path.endsWith(".wav") || path.endsWith(".flac");
    }

    private static boolean isSegmentPath(String path) {
        return path.endsWith(".ts") || path.endsWith(".m4s") || path.endsWith(".cmfv")
                || path.endsWith(".cmfa") || path.endsWith(".aac") || path.endsWith(".vtt")
                || path.endsWith(".key");
    }

    private static boolean isLikelyMediaPath(String path) {
        return isProgressivePath(path) || isSegmentPath(path);
    }

    private static String pathOnly(String sourceUrl) {
        int query = sourceUrl == null ? -1 : sourceUrl.indexOf('?');
        return sourceUrl == null ? "" : query < 0 ? sourceUrl : sourceUrl.substring(0, query);
    }

    private static String mediaType(String contentType) {
        if (contentType == null) {
            return "";
        }
        return contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    }

    private static String firstText(String first, String second) {
        return first != null ? first : second;
    }

    private static String xmlEscape(String value) {
        return value.replace("&", "&amp;").replace("\"", "&quot;");
    }

    record ContentRange(long start, long end, Long total) {
    }

    record ManifestReference(
            String relationType,
            Long sequence,
            String originalUri,
            String resolvedSourceUrl
    ) {
    }

    record ParsedManifest(boolean live, List<ManifestReference> references) {
    }
}
