package com.theshuai.tunnelserver.websocket;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class PublicTransferDiscoveryWebSocketHandlerTests {

    @Test
    void queryLimitDoesNotSplitUtf16SurrogatePair() {
        String prefix = "a".repeat(119);
        String value = prefix + "😀" + "z";

        assertEquals(prefix,
                PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor
                        .truncateUtf16WithoutSplittingSurrogate(value, 120));
        assertEquals(prefix + "😀",
                PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor
                        .truncateUtf16WithoutSplittingSurrogate(value, 121));
        assertEquals("short",
                PublicTransferDiscoveryWebSocketHandler.PublicTransferDiscoveryHandshakeInterceptor
                        .truncateUtf16WithoutSplittingSurrogate("short", 120));
    }
}
