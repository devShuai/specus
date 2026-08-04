package com.theshuai.specusclient.handler;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NatClientHandlerWebSocketTargetTests {

    @Test
    void mapsHttpSchemesAndPreservesEncodedPathAndRawQuery() {
        assertThat(NatClientHandler.buildWsTarget(
                "http://example.test/base%2Froot",
                "/%E4%BD%A0%2F%252F",
                "next=%2Fraw").toASCIIString())
                .isEqualTo("ws://example.test/base%2Froot/%E4%BD%A0%2F%252F?next=%2Fraw");

        assertThat(NatClientHandler.buildWsTarget(
                "https://example.test/base/", "/events", null).toASCIIString())
                .isEqualTo("wss://example.test/base/events");
    }

    @Test
    void rejectsPlainAndEncodedDotSegments() {
        assertRejected("/../admin");
        assertRejected("/%2e%2e/admin");
    }

    @Test
    void rejectsControlCharactersBeforeBuildingTarget() {
        assertThatThrownBy(() -> NatClientHandler.buildWsTarget(
                "http://example.test/base", "/socket\r\nBad: value", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("relativePath 含有非法控制字符");
    }

    private static void assertRejected(String relativePath) {
        assertThatThrownBy(() -> NatClientHandler.buildWsTarget(
                "http://example.test/base", relativePath, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("HTTP 转发路径越界");
    }
}
