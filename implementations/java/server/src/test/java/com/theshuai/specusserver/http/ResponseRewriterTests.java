package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ResponseRewriterTests {
    @Test
    void runtimePolyfillWrapsScriptSrcSetter() {
        ResponseRewriter rewriter = new ResponseRewriter(1024 * 1024);
        byte[] body = """
                <html><head></head><body>
                <img src="/img/logo.png">
                <img src="//cdn.example.com/logo.png">
                </body></html>
                """.getBytes(StandardCharsets.UTF_8);

        Optional<byte[]> rewritten = rewriter.rewrite(
                body, "Demo client", "dsh", List.of("Content-Type:text/html;charset=UTF-8"));
        assertTrue(rewritten.isPresent());
        String text = new String(rewritten.get(), StandardCharsets.UTF_8);

        assertTrue(text.contains("src=\"/http/Demo client/dsh/img/logo.png\""));
        assertTrue(text.contains("function wrapAttr("));
        assertTrue(text.contains("HTMLScriptElement"));
        assertTrue(text.contains("function hrefOf("));
        assertTrue(text.contains("function rewriteInput("));
        assertTrue(text.contains("function normalizePath(path,base)"));
        assertTrue(text.contains("if(!base)return null"));
        assertTrue(text.contains("while(path.length>1&&path.charAt(1)==='/')path=path.slice(1)"));
        assertTrue(text.contains("var path=normalizePath(u.slice(base.length),base)"));
        assertTrue(text.contains("loc.ws"));
        assertTrue(text.contains("location.origin"));
        assertTrue(text.contains("wrapHistory('pushState')"));
        assertTrue(text.contains("window.EventSource=function"));
        assertTrue(text.contains("window.WebSocket=function"));
        assertTrue(text.contains("src=\"//cdn.example.com/logo.png\""));
    }

    @Test
    void runtimePolyfillRewritesSameOriginDoubleSlashUrls() throws Exception {
        ResponseRewriter rewriter = new ResponseRewriter(1024 * 1024);
        Optional<byte[]> rewritten = rewriter.rewrite(
                "<html><head></head><body></body></html>".getBytes(StandardCharsets.UTF_8),
                "client-a", "dsm", List.of("Content-Type:text/html;charset=UTF-8"));
        assertTrue(rewritten.isPresent());
        String html = new String(rewritten.get(), StandardCharsets.UTF_8);
        int scriptOpen = html.indexOf("<script>");
        int scriptClose = html.indexOf("</script>", scriptOpen);
        assertTrue(scriptOpen >= 0 && scriptClose > scriptOpen);
        String polyfill = html.substring(scriptOpen + "<script>".length(), scriptClose);

        String probe = """
                global.window=global;
                global.location={origin:'https://specus.devshuai.com',protocol:'https:',host:'specus.devshuai.com'};
                global.XMLHttpRequest=function(){};
                XMLHttpRequest.prototype.open=function(method,url){global.openedXhr=url;};
                global.WebSocket=function(url){global.openedWebSocket=url;};
                WebSocket.prototype={};
                """ + polyfill + """
                new XMLHttpRequest().open('POST','https://specus.devshuai.com//synoscgi.sock/socket.io/?EIO=3');
                if(global.openedXhr!=='https://specus.devshuai.com/http/client-a/dsm/synoscgi.sock/socket.io/?EIO=3'){
                  throw new Error('unexpected XHR URL: '+global.openedXhr);
                }
                new XMLHttpRequest().open('GET','//cdn.example.com/app.js');
                if(global.openedXhr!=='//cdn.example.com/app.js'){
                  throw new Error('protocol-relative URL was rewritten: '+global.openedXhr);
                }
                new WebSocket('wss://specus.devshuai.com//synoscgi.sock/socket.io/?EIO=3');
                if(global.openedWebSocket!=='wss://specus.devshuai.com/http/client-a/dsm/synoscgi.sock/socket.io/?EIO=3'){
                  throw new Error('unexpected WebSocket URL: '+global.openedWebSocket);
                }
                """;
        Process process = new ProcessBuilder("node", "-e", probe)
                .redirectErrorStream(true)
                .start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);

        assertEquals(0, process.waitFor(), output);
    }
}
