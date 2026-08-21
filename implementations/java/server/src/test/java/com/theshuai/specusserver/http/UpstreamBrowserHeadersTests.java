package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UpstreamBrowserHeadersTests {
    @Test
    void publicOriginIsRewrittenToLoopbackTarget() {
        List<String> rewritten = UpstreamBrowserHeaders.rewrite(
                List.of(
                        "Origin:https://specus.devshuai.com",
                        "Referer:https://specus.devshuai.com/http/client/dsh/",
                        "Sec-Fetch-Site:same-origin",
                        "Content-Type:application/json"),
                "http://127.0.0.1:3210/app");

        assertThat(rewritten).contains(
                "Origin:http://127.0.0.1:3210",
                "Referer:http://127.0.0.1:3210/http/client/dsh/",
                "Sec-Fetch-Site:same-origin",
                "Content-Type:application/json");
    }

    @Test
    void crossSiteFetchMetadataBecomesSameOrigin() {
        List<String> rewritten = UpstreamBrowserHeaders.rewrite(
                List.of("Origin:https://evil.example", "Sec-Fetch-Site:cross-site"),
                "http://127.0.0.1:8080");
        assertThat(rewritten).containsExactly(
                "Origin:http://127.0.0.1:8080",
                "Sec-Fetch-Site:same-origin");
    }

    @Test
    void missingTargetLeavesHeadersUnchanged() {
        List<String> headers = List.of("Origin:https://specus.devshuai.com");
        assertThat(UpstreamBrowserHeaders.rewrite(headers, null)).isSameAs(headers);
    }
}
