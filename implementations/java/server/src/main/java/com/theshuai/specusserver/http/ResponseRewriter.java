package com.theshuai.specusserver.http;

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
     * HTML 属性改写：href / src / action / data-href / data-src / poster / background 等以单个 / 开头的值
     * （不含 //，即不匹配协议相对路径）。
     */
    private static final Pattern HTML_PATH_PATTERN = Pattern.compile(
            "(href|src|action|data-href|data-src|poster|background|formaction|cite|longdesc|usemap)" +
                    "(\\s*=\\s*)\"(/(?!/)[^\"]*)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_PATH_SINGLE_PATTERN = Pattern.compile(
            "(href|src|action|data-href|data-src|poster|background|formaction|cite|longdesc|usemap)" +
                    "(\\s*=\\s*)'(/(?!/)[^']*)'",
            Pattern.CASE_INSENSITIVE);

    /** {@code srcset="/img-1x.png 1x, /img-2x.png 2x"} 类似列表也需要改写。 */
    private static final Pattern HTML_SRCSET_PATTERN = Pattern.compile(
            "(srcset)(\\s*=\\s*)\"([^\"]*)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern HTML_SRCSET_SINGLE_PATTERN = Pattern.compile(
            "(srcset)(\\s*=\\s*)'([^']*)'",
            Pattern.CASE_INSENSITIVE);

    /** CSS url() 中的绝对路径：url(/path) 或 url("/path") 或 url('/path')。 */
    private static final Pattern CSS_URL_PATTERN = Pattern.compile(
            "url\\(\\s*(['\"]?)(/(?!/)[^'\")\\s]+)\\1\\s*\\)",
            Pattern.CASE_INSENSITIVE);

    /** CSS {@code @import "/path"} / {@code @import '/path'}。 */
    private static final Pattern CSS_IMPORT_PATTERN = Pattern.compile(
            "(@import\\s+)(['\"])(/(?!/)[^'\"]*)\\2",
            Pattern.CASE_INSENSITIVE);

    /**
     * 在 HTML 中定位 {@code <head>} 开标签的结束位置，用于注入运行时 polyfill。
     * 不区分大小写，允许 {@code <head>}、{@code <head lang="en">} 等带属性形式。
     */
    private static final Pattern HEAD_TAG_PATTERN = Pattern.compile(
            "<head\\b[^>]*>", Pattern.CASE_INSENSITIVE);

    private final int maxBodyBytes;

    public ResponseRewriter(@Value("${specus.http.rewrite.max-body-bytes:10485760}") int maxBodyBytes) {
        this.maxBodyBytes = Math.max(0, maxBodyBytes);
    }

    /**
     * 改写响应正文的绝对路径。条件不满足时返回 {@link Optional#empty()}，调用方应原样透传 body。
     */
    public Optional<byte[]> rewrite(byte[] body, String clientName, String route, List<String> headers) {
        if (!mayRewrite(body, headers)) {
            log.debug("[rewrite] skip: not a rewrite candidate, clientName={} route={}", clientName, route);
            return Optional.empty();
        }
        String contentType = extractContentType(headers);
        byte[] decompressed = decompressIfNeeded(body, headers);
        if (decompressed == null) {
            log.warn("[rewrite] skip: decompress failed, clientName={} route={} contentType={} encoding={}",
                    clientName, route, contentType, extractHeader(headers, "content-encoding"));
            return Optional.empty();
        }
        String prefix = PREFIX_TEMPLATE.formatted(clientName, route);
        String text = new String(decompressed, StandardCharsets.UTF_8);
        String rewritten = text;

        // 防止重复改写：把已带前缀的路径先临时占位，改写完成后再还原。
        // 关键：匹配 prefix 紧跟"路径终止符"（/、引号、反引号、空白、问号、#、括号、字符串末尾），
        // 否则 JS 里 "/http/c/r" 这种没有尾斜杠的字符串会漏占位，被 JS 正则当成普通绝对路径重复改写
        // 成 "/http/c/r/http/c/r"。
        String placeholder = "\u0000__SPECUS_PREFIX__\u0000";
        java.util.regex.Pattern alreadyPrefixed = java.util.regex.Pattern.compile(
                java.util.regex.Pattern.quote(prefix) + "(?=[/\"'`\\s)?#&]|$)");
        rewritten = alreadyPrefixed.matcher(rewritten).replaceAll(
                java.util.regex.Matcher.quoteReplacement(placeholder));

        if (contentType.equals("text/html")) {
            rewritten = HTML_PATH_PATTERN.matcher(rewritten).replaceAll("$1$2\"" + prefix + "$3\"");
            rewritten = HTML_PATH_SINGLE_PATTERN.matcher(rewritten).replaceAll("$1$2'" + prefix + "$3'");
            rewritten = rewriteSrcset(rewritten, prefix, HTML_SRCSET_PATTERN, '"');
            rewritten = rewriteSrcset(rewritten, prefix, HTML_SRCSET_SINGLE_PATTERN, '\'');
            // 注入运行时 polyfill：拦截 fetch / XMLHttpRequest / new URL / 节点的 src/href 赋值，
            // 给绝对路径动态加前缀。这是处理 SPA / webpack chunk 拼接 URL 的唯一可靠方式
            // ——JS 文件做正则改写会误伤字符串拼接（如 "/api"+"/v2"+"/x" 三段会变成三份前缀）。
            rewritten = injectRuntimePolyfill(rewritten, prefix);
        }
        if (contentType.equals("text/css")) {
            rewritten = CSS_URL_PATTERN.matcher(rewritten).replaceAll("url($1" + prefix + "$2$1)");
            rewritten = CSS_IMPORT_PATTERN.matcher(rewritten).replaceAll("$1$2" + prefix + "$3$2");
        }
        // JS 文件不做正则改写——参见 injectRuntimePolyfill 注释。

        rewritten = rewritten.replace(placeholder, prefix + "/");

        if (rewritten.equals(text)) {
            log.debug("[rewrite] no-op: no absolute paths matched, clientName={} route={} contentType={} bytes={}",
                    clientName, route, contentType, body.length);
            return Optional.empty();
        }
        log.debug("[rewrite] applied clientName={} route={} contentType={} originalBytes={} rewrittenBytes={} prefix={}",
                clientName, route, contentType, body.length, rewritten.length(), prefix);
        return Optional.of(rewritten.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Cheap preflight used by the controller before consulting route rewrite settings.
     * Most HTTP specus responses are JSON, images, or other non-rewritable payloads; skipping
     * the route lookup there removes an avoidable DB/cache hit from the common request path.
     */
    public boolean mayRewrite(byte[] body, List<String> headers) {
        if (body == null || body.length == 0 || body.length > maxBodyBytes) {
            return false;
        }
        String contentType = extractContentType(headers);
        return contentType != null && REWRITABLE_CONTENT_TYPES.contains(contentType);
    }

    public boolean isRewritableContentType(List<String> headers) {
        String contentType = extractContentType(headers);
        return contentType != null && REWRITABLE_CONTENT_TYPES.contains(contentType);
    }

    public int maxBodyBytes() {
        return maxBodyBytes;
    }

    /**
     * 在 HTML 的 {@code <head>} 后注入一段运行时 polyfill。脚本在浏览器执行时拦截：
     * <ul>
     *   <li>{@code fetch(url, ...)}：url 是绝对路径就加前缀</li>
     *   <li>{@code XMLHttpRequest.prototype.open(method, url, ...)}：同上</li>
     *   <li>{@code new URL(input, base)} / {@code new Request(url, ...)}：同上</li>
     *   <li>{@code window.history.pushState/replaceState}：第三个参数 url 改写</li>
     *   <li>{@code <img>}、{@code <script>}、{@code <link>}、{@code <a>}、{@code <iframe>} 等元素的
     *       {@code src} / {@code href} setter：动态创建/赋值时改写</li>
     * </ul>
     *
     * <p>这是处理 SPA / webpack 拼接 URL 的唯一可靠方式——服务端正则改写无法识别
     * {@code "/api" + "/v2.0" + "/x"} 这种运行时拼接，会把每个字符串字面量都加前缀变成
     * {@code "/http/c/r/api" + "/http/c/r/v2.0" + "/http/c/r/x"}，多次拼接后路径里出现多个
     * 重复前缀。
     *
     * <p>注入策略：若 HTML 中找到 {@code <head>}，则在其后注入；否则在文档开头注入。两次访问
     * 同一页面不会重复注入——因为脚本本身被解析后变成 DOM 节点，不会再被服务端看见。
     */
    private static String injectRuntimePolyfill(String html, String prefix) {
        String script = buildPolyfillScript(prefix);
        java.util.regex.Matcher matcher = HEAD_TAG_PATTERN.matcher(html);
        if (matcher.find()) {
            return html.substring(0, matcher.end()) + script + html.substring(matcher.end());
        }
        // 没有 <head>：找 <html> 后插，再没有就放最前
        java.util.regex.Pattern htmlTag = java.util.regex.Pattern.compile("<html\\b[^>]*>",
                java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Matcher m2 = htmlTag.matcher(html);
        if (m2.find()) {
            return html.substring(0, m2.end()) + script + html.substring(m2.end());
        }
        return script + html;
    }

    /**
     * 构造注入到 HTML 的 JavaScript 字符串。模板字面量用单引号包裹避免和 HTML 双引号属性冲突；
     * 内部使用 IIFE 避免污染全局命名空间，且 try/catch 保证任意 monkey-patch 失败都不影响主页面。
     */
    private static String buildPolyfillScript(String prefix) {
        // 安全转义 prefix（不会含特殊字符，但仍走 JSON 字符串编码防御）
        String jsPrefix = "'" + prefix.replace("\\", "\\\\").replace("'", "\\'") + "'";
        return "<script>(function(){try{"
                + "var P=" + jsPrefix + ";"
                // 判断函数：是否应该加前缀（绝对路径且未带前缀，非协议相对，非完整 URL，非 data:）
                + "function need(u){"
                + "if(typeof u!=='string')return false;"
                + "if(u.length===0||u.charAt(0)!=='/')return false;"
                + "if(u.length>1&&u.charAt(1)==='/')return false;"
                + "if(u.indexOf(P+'/')===0||u===P)return false;"
                + "return true;"
                + "}"
                + "function fix(u){return need(u)?P+u:u;}"
                // fetch
                + "if(typeof fetch==='function'){"
                + "var of=fetch;"
                + "window.fetch=function(input,init){"
                + "try{if(typeof input==='string'){input=fix(input);}"
                + "else if(input&&typeof input.url==='string'&&need(input.url)){input=new Request(fix(input.url),input);}}"
                + "catch(e){}"
                + "return of.call(this,input,init);"
                + "};"
                + "}"
                // XMLHttpRequest.open
                + "if(typeof XMLHttpRequest!=='undefined'){"
                + "var oo=XMLHttpRequest.prototype.open;"
                + "XMLHttpRequest.prototype.open=function(m,u){"
                + "try{u=fix(u);}catch(e){}"
                + "arguments[1]=u;"
                + "return oo.apply(this,arguments);"
                + "};"
                + "}"
                // history.pushState / replaceState
                + "function wrapHistory(name){"
                + "var orig=history[name];"
                + "if(typeof orig==='function'){"
                + "history[name]=function(s,t,u){try{if(typeof u==='string')u=fix(u);}catch(e){}return orig.call(this,s,t,u);};"
                + "}"
                + "}"
                + "if(typeof history!=='undefined'){wrapHistory('pushState');wrapHistory('replaceState');}"
                // 元素 setAttribute 拦截
                + "if(typeof Element!=='undefined'){"
                + "var osa=Element.prototype.setAttribute;"
                + "var URL_ATTRS={src:1,href:1,action:1,formaction:1,poster:1,background:1,'data-src':1,'data-href':1};"
                + "Element.prototype.setAttribute=function(n,v){"
                + "try{if(n&&URL_ATTRS[String(n).toLowerCase()]&&typeof v==='string')v=fix(v);}catch(e){}"
                + "return osa.call(this,n,v);"
                + "};"
                + "}"
                // EventSource
                + "if(typeof EventSource==='function'){"
                + "var OE=EventSource;"
                + "window.EventSource=function(u,c){return new OE(fix(u),c);};"
                + "window.EventSource.prototype=OE.prototype;"
                + "}"
                // WebSocket：补 / 开头的相对 ws URL（ws://host/path 不变）
                + "if(typeof WebSocket==='function'){"
                + "var OW=WebSocket;"
                + "window.WebSocket=function(u,p){"
                + "try{if(typeof u==='string'&&u.indexOf('ws://')!==0&&u.indexOf('wss://')!==0&&need(u))u=fix(u);}catch(e){}"
                + "return p===undefined?new OW(u):new OW(u,p);"
                + "};"
                + "window.WebSocket.prototype=OW.prototype;"
                + "}"
                + "}catch(e){console&&console.warn&&console.warn('specus polyfill failed',e);}})();</script>";
    }

    /**
     * 改写 {@code srcset} 形如 {@code "/img-1x.png 1x, /img-2x.png 2x"} 的列表。
     * 对每个逗号分段，找首个非空白 token，若以单 / 开头则加前缀。
     */
    private static String rewriteSrcset(String html, String prefix, Pattern pattern, char quote) {
        return pattern.matcher(html).replaceAll(m -> {
            String attrName = m.group(1);
            String eq = m.group(2);
            String value = m.group(3);
            StringBuilder sb = new StringBuilder(value.length() + 16);
            String[] candidates = value.split(",", -1);
            for (int i = 0; i < candidates.length; i++) {
                if (i > 0) sb.append(',');
                String segment = candidates[i];
                int start = 0;
                while (start < segment.length() && Character.isWhitespace(segment.charAt(start))) {
                    sb.append(segment.charAt(start));
                    start++;
                }
                if (start < segment.length() - 1
                        && segment.charAt(start) == '/'
                        && segment.charAt(start + 1) != '/') {
                    sb.append(prefix);
                }
                sb.append(segment, start, segment.length());
            }
            return java.util.regex.Matcher.quoteReplacement(attrName + eq + quote + sb + quote);
        });
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
            // Bounded: this is the most exposed decompression path in the server, and reading an
            // upstream decompressor to EOF lets a few kilobytes of crafted gzip cost gigabytes.
            byte[] plain = DecompressionLimits.readAllBounded(decompressor, compressed.length);
            decompressor.close();
            return plain;
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
