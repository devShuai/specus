package com.theshuai.specusserver.websocket;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


class PublicTransferCoordinationServiceTests {

    @Test
    void netIdIsSha256OfPublicAddress() {
        // 与 groupId 同一 digest 工具(sha256 hex),公式 sha256(publicAddress),不含 roomId 分量。
        // 向量核算:printf '203.0.113.10' | sha256sum;printf 'room\000key' | sha256sum。
        assertEquals("631f08140b24b7274d12df3c37a1a80ce5876dafd7007d772e0114fddf88b682",
                PublicTransferCoordinationService.netId("203.0.113.10"));
        assertEquals("3a18ade7ffb1a1940f2cf4b2891ad8d0fa575625c8da9706202dc2bd52f5d3c8",
                PublicTransferCoordinationService.groupId("room", "key"));
    }

    @Test
    void netIdVariesByPublicAddressOnly() {
        assertNotEquals(PublicTransferCoordinationService.netId("203.0.113.10"),
                PublicTransferCoordinationService.netId("198.51.100.7"));
    }

    @Test
    void netIdToleratesNullAddress() {
        assertEquals(PublicTransferCoordinationService.netId(""),
                PublicTransferCoordinationService.netId(null));
    }

    @Test
    void unknownOrBlankAddressIsNeverSameNet() {
        // 兜底/空地址不可辨识:即使字面相等也不构成同网,避免无地址客户端被聚为一组。
        assertFalse(PublicTransferCoordinationService.sameNetAddress("unknown", "unknown"));
        assertFalse(PublicTransferCoordinationService.sameNetAddress("", ""));
        assertFalse(PublicTransferCoordinationService.sameNetAddress("  ", "  "));
        assertFalse(PublicTransferCoordinationService.sameNetAddress(null, null));
        assertTrue(PublicTransferCoordinationService.sameNetAddress("203.0.113.10", "203.0.113.10"));
        assertFalse(PublicTransferCoordinationService.sameNetAddress("203.0.113.10", "198.51.100.7"));
    }
}
