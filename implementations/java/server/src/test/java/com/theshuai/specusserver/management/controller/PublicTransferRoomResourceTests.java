package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.PublicTransferRateLimiter;
import com.theshuai.specusserver.management.service.PublicTransferRoomService;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreatePairingCodeRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreatePairingCodeResponse;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RedeemPairingCodeRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RedeemPairingCodeResponse;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.Role;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicTransferRoomResourceTests {

    @Test
    void pairingCodeResponsesAreNoStoreAndRedeemUsesTrustedClientAddress() {
        PublicTransferRoomService service = mock(PublicTransferRoomService.class);
        PublicTransferRateLimiter limiter = mock(PublicTransferRateLimiter.class);
        PublicTransferRoomResource resource = new PublicTransferRoomResource(service, limiter);
        CreatePairingCodeRequest createRequest = new CreatePairingCodeRequest(
                "nearby", "owner-token", "owner", "EDITOR", "队友", 1);
        CreatePairingCodeResponse createResponse = new CreatePairingCodeResponse(
                1L, "01234567", Role.EDITOR, "队友",
                "2026-07-20T00:00:00Z", "2026-07-20T00:05:00Z", 1, 0);
        when(service.createPairingCode("nearby", createRequest)).thenReturn(createResponse);

        var created = resource.createPairingCode(createRequest);

        assertEquals(createResponse, created.getBody());
        assertTrue(created.getHeaders().getCacheControl().contains("no-store"));

        RedeemPairingCodeRequest redeemRequest = new RedeemPairingCodeRequest("01234567", "guest");
        RedeemPairingCodeResponse redeemResponse = new RedeemPairingCodeResponse(
                "nearby", Role.EDITOR, "st-editor-secret", "2026-07-21T00:00:00Z");
        when(service.redeemPairingCode(redeemRequest)).thenReturn(redeemResponse);
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        servletRequest.addHeader("X-Forwarded-For", "192.0.2.7, 198.51.100.9");
        servletRequest.addHeader("X-Real-IP", "203.0.113.5");

        var redeemed = resource.redeemPairingCode(servletRequest, redeemRequest);

        verify(limiter).checkPairingCodeRedeem("203.0.113.5");
        assertEquals(redeemResponse, redeemed.getBody());
        assertTrue(redeemed.getHeaders().getCacheControl().contains("no-store"));
    }
}
