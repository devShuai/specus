package com.theshuai.tunnelclient.handler;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HttpRouteTargetResolverTests {
    @Test
    void shouldBuildTargetInsideConfiguredBasePath() {
        URI target = HttpRouteTargetResolver.buildTarget(
                "https://127.0.0.1:8443/base", "/items/1", "download=true");

        assertEquals("https://127.0.0.1:8443/base/items/1?download=true", target.toString());
    }

    @Test
    void shouldRejectUnknownOrEscapingRoute() {
        assertThrows(IllegalArgumentException.class,
                () -> HttpRouteTargetResolver.buildTarget(null, "/", null));
        assertThrows(IllegalArgumentException.class,
                () -> HttpRouteTargetResolver.buildTarget("http://127.0.0.1/base", "/../admin", null));
        assertThrows(IllegalArgumentException.class,
                () -> HttpRouteTargetResolver.buildTarget("file:///tmp", "/demo", null));
    }

    @Test
    void shouldNormalizeOversizedRangeHeaders() {
        assertEquals("bytes=0-8388607", HttpRouteTargetResolver.boundedRange("bytes=0-999999999"));
        assertEquals("bytes=100-8388707", HttpRouteTargetResolver.boundedRange("bytes=100-"));
        assertEquals("bytes=-8388608", HttpRouteTargetResolver.boundedRange("bytes=-999999999"));
        assertEquals("bytes=0-1023", HttpRouteTargetResolver.boundedRange("bytes=0-1023"));
        assertNull(HttpRouteTargetResolver.boundedRange("bytes=0-1023,2048-4095"));
        assertNull(HttpRouteTargetResolver.boundedRange("items=0-1023"));
    }
}
