package com.theshuai.specusserver.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class HttpQueryStringCodecTests {
    @Test
    void encodesOnlyRawBracesAndKeepsExistingEscapes() {
        assertEquals(
                "path=icon_%7B0%7D.png&encoded=%7B1%7D&separator=a/b?c",
                HttpQueryStringCodec.encodeForForwarding(
                        "path=icon_{0}.png&encoded=%7B1%7D&separator=a/b?c"));
    }

    @Test
    void preservesNullAndEmptyQueries() {
        assertNull(HttpQueryStringCodec.encodeForForwarding(null));
        assertEquals("", HttpQueryStringCodec.encodeForForwarding(""));
    }
}
