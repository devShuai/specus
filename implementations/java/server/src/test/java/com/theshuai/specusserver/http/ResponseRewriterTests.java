package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseRewriterTests {
    @Test
    void runtimePolyfillWrapsScriptSrcSetter() {
        ResponseRewriter rewriter = new ResponseRewriter(1024 * 1024);
        byte[] body = """
                <html><head></head><body>
                <img src="/img/logo.png">
                </body></html>
                """.getBytes(StandardCharsets.UTF_8);

        Optional<byte[]> rewritten = rewriter.rewrite(
                body, "Demo client", "dsh", List.of("Content-Type:text/html;charset=UTF-8"));
        assertTrue(rewritten.isPresent());
        String text = new String(rewritten.get(), StandardCharsets.UTF_8);

        assertTrue(text.contains("src=\"/http/Demo client/dsh/img/logo.png\""));
        assertTrue(text.contains("function wrapAttr("));
        assertTrue(text.contains("HTMLScriptElement"));
        assertTrue(text.contains("location.origin"));
        assertTrue(text.contains("wrapHistory('pushState')"));
        assertTrue(text.contains("window.EventSource=function"));
        assertTrue(text.contains("window.WebSocket=function"));
    }
}
