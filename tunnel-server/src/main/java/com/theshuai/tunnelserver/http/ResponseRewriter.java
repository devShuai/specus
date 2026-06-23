package com.theshuai.tunnelserver.http;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.InflaterInputStream;

/**
 * HTTP 直转通道的响应体路径改写引擎。
 *
 * <p>内网应用（DSM、路由器等）返回的 HTML/CSS/JS 中常包含绝对路径（{@code /foo}），
 * 浏览器在公网访问时会把这类路径解析到根路径，不经过隧道。本组件对 text/html、text/css、
 * application/javascript 等正文做正则改写，把绝对路径前缀加上 {@code /http/{clientName}/{route}/}，
 * 让子资源也走隧道。
 *
 * <p>安全约束：
 * <ul>
 *   <li>不改写外部 URL（{@code http://}、{@code https://}、{@code ftp://}、{@code mailto:}）</li>
 *   <li>不改写协议相对路径（{@code //cdn.com/...}）</li>
 *   <li>不改写 javascript: / data: 等特殊协议</li>
 *   <li>不重复改写已带隧道前缀的路径</li>
 *   <li>body 超过阈值直接跳过，避免 OOM</li>
 * </ul>
 */
@Component
@Slf4j
public class ResponseRewriter {
    private static final Set<String> REWRITABLE_CONTENT_TYPES = Set.of(
            "text/html", "text/css", "text/javascript", "application/javascript",
            "application/x-javascript", "application/ecmascript", "text/ecmascript"
    );

    /** 隧道前缀模版：/http/{clientName}/{route} */
    private static final String PREFIX_TEMPLATE = "/http/%s/%s";

    /**
     * HTML 属性改写：href/src/action/data-href/data-src/poster/background="..." 中以 / 开头的值。
     * 不匹配 // 开头的协议相对路径，不匹配已带 /http/ 前缀的路径。
     */
    private static final Pattern HTML_PATH_PATTERN = Pattern.compile(
            "(href|src|action|data-href|data-src|poster|background)\\s*=\\s*\"(/[^/\"](?:[^\"]*[^>])?)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_PATH_SINGLE_PATTERN = Pattern.compile(
            "(href|src|action|data-href|data-src|poster|background)\\s*=\\s*'(/[^/'](?:[^']*[^>])?)'",
            Pattern.CASE_INSENSITIVE);

    /** CSS url() 中的绝对路径：url(/path) 或 url("/path") 或 url('/path')。 */
    private static final Pattern CSS_URL_PATTERN = Pattern.compile(
            "url\\(\\s*['\"]?(/[^/'\\)\"\\s](?:[^'\\)\"]*[^>])?)['\"]?\\s*\\)",
            Pattern.CASE_INSENSITIVE);

    /** CSS @import 中的绝对路径。 */
    private static final Pattern CSS_IMPORT_PATTERN = Pattern.compile(
            "@import\\s+['\"]/(?!/)(?:[^'\"]*[^>])['\"]",
            Pattern.CASE_INSENSITIVE);

    /** JS 中 fetch/open/URL 函数调用字符串参数里的绝对路径。 */
    private static final Pattern JS_PATH_PATTERN = Pattern.compile(
            "(['\"])(/(?!/)(?:[^'\"]*[^>])?)\\1(?!\\s*\\)?)",
            Pattern.CASE_INSENSITIVE);

    private final int maxBodyBytes;

    public ResponseRewriter(@Value("${tunnel.http.rewrite.max-body-bytes:10485760}") int maxBodyBytes) {
        this.maxBodyBytes = Math.max(0, maxBodyBytes);
    }

    /**
     * 改写响应正文的绝对路径。条件不满足时返回 {@link Optional#empty()}，调用方应原样透传 body。
     */
    public Optional<byte[]> rewrite(byte[] body, String clientName, String route, List<String> headers) {
        if (body == null || body.length == 0 || body.length > maxBodyBytes) {
            return Optional.empty();
        }
        String contentType = extractContentType(headers);
        if (contentType == null || !REWRITABLE_CONTENT_TYPES.contains(contentType)) {
            return Optional.empty();
        }
        byte[] decompressed = decompressIfNeeded(body, headers);
        if (decompressed == null) {
            return Optional.empty();
        }
        String prefix = PREFIX_TEMPLATE.formatted(clientName, route);
        // 高开销：只有当正文里确实存在匹配 / 的绝对路径时才做 UTF-8 解码和替换
        // 快速扫描
        if (!hasAbsolutePath(decompressed)) {
            return Optional.empty();
        }
        String text = new String(decompressed, StandardCharsets.UTF_8);
        String rewritten = text;

        if (contentType.equals("text/html")) {
            rewritten = HTML_PATH_PATTERN.matcher(rewritten).replaceAll("$1=\"" + prefix + "$2\"");
            rewritten = HTML_PATH_SINGLE_PATTERN.matcher(rewritten).replaceAll("$1='" + prefix + "$2'");
        }
        if (contentType.equals("text/css") || contentType.equals("text/html")) {
            rewritten = CSS_URL_PATTERN.matcher(rewritten).replaceAll("url(" + prefix + "$1)");
            rewritten = CSS_IMPORT_PATTERN.matcher(rewritten).replaceAll(
                    m -> "@import '" + prefix + m.group().substring(m.group().indexOf('/')) + "'");
        }
        if (contentType.contains("javascript") || contentType.contains("ecmascript") || contentType.equals("text/html")) {
            rewritten = JS_PATH_PATTERN.matcher(rewritten).replaceAll("$1" + prefix + "$2$1");
        }

        if (rewritten.equals(text)) {
            return Optional.empty();
        }
        log.info("[rewrite] clientName={} route={} contentType={} originalBytes={} rewrittenBytes={}",
                clientName, route, contentType, body.length, rewritten.length());
        return Optional.of(rewritten.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean hasAbsolutePath(byte[] data) {
        for (int i = 0; i < data.length - 1; i++) {
            if (data[i] == '/' && data[i + 1] != '/' && data[i + 1] != '*') {
                return true;
            }
        }
        return false;
    }

    private static String extractContentType(List<String> headers) {
        if (headers == null) {
            return null;
        }
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator > 0
                    && "content-type".equals(header.substring(0, separator).trim().toLowerCase(Locale.ROOT))) {
                String raw = header.substring(separator + 1).trim();
                int semicolon = raw.indexOf(';');
                return (semicolon > 0 ? raw.substring(0, semicolon) : raw).trim().toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    private static byte[] decompressIfNeeded(byte[] body, List<String> headers) {
        String encoding = extractHeader(headers, "content-encoding");
        if (encoding == null) {
            return body;
        }
        return switch (encoding) {
            case "gzip", "x-gzip" -> decompress(body, true);
            case "deflate" -> decompress(body, false);
            default -> body;
        };
    }

    private static byte[] decompress(byte[] compressed, boolean gzip) {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(compressed);
            java.io.InputStream decompressor = gzip ? new GZIPInputStream(in) : new InflaterInputStream(in);
            ByteArrayOutputStream out = new ByteArrayOutputStream(compressed.length * 2);
            byte[] buf = new byte[8192];
            int n;
            while ((n = decompressor.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            decompressor.close();
            return out.toByteArray();
        } catch (IOException e) {
            log.debug("[rewrite] decompress failed: {}", e.toString());
            return null;
        }
    }

    private static String extractHeader(List<String> headers, String name) {
        if (headers == null) {
            return null;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        for (String header : headers) {
            if (header == null) {
                continue;
            }
            int separator = header.indexOf(':');
            if (separator > 0 && lower.equals(header.substring(0, separator).trim().toLowerCase(Locale.ROOT))) {
                return header.substring(separator + 1).trim().toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }
}