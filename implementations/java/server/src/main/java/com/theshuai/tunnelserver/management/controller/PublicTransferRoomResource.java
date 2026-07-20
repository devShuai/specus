package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.service.PublicTransferRoomService;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.AccessTokenView;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateAccessTokenRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreatePairingCodeRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreatePairingCodeResponse;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateDiagramVersionRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreatedAccessToken;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.DiagramVersionDetail;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.DiagramVersionView;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.RedeemPairingCodeRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.RedeemPairingCodeResponse;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.RoomCredential;
import com.theshuai.tunnelserver.management.service.PublicTransferRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class PublicTransferRoomResource {
    private final PublicTransferRoomService service;
    private final PublicTransferRateLimiter rateLimiter;

    public PublicTransferRoomResource(PublicTransferRoomService service,
                                      PublicTransferRateLimiter rateLimiter) {
        this.service = service;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/api/public/transfer/rooms/access-tokens/list")
    public List<AccessTokenView> listAccessTokens(@RequestBody RoomCredential credential) {
        return service.listAccessTokens(credential.roomId(), credential);
    }

    @PostMapping("/api/public/transfer/rooms/access-tokens")
    public ResponseEntity<CreatedAccessToken> createAccessToken(@RequestBody CreateAccessTokenRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(service.createAccessToken(request.roomId(), request));
    }

    @PostMapping("/api/public/transfer/rooms/access-tokens/{accessId}/revoke")
    public AccessTokenView revokeAccessToken(@PathVariable long accessId,
                                             @RequestBody RoomCredential credential) {
        return service.revokeAccessToken(credential.roomId(), accessId, credential);
    }

    @PostMapping("/api/public/transfer/rooms/pairing-codes")
    public ResponseEntity<CreatePairingCodeResponse> createPairingCode(
            @RequestBody CreatePairingCodeRequest request) {
        CreatePairingCodeResponse response = service.createPairingCode(request.roomId(), request);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(response);
    }

    @PostMapping("/api/public/transfer/rooms/pairing-codes/redeem")
    public ResponseEntity<RedeemPairingCodeResponse> redeemPairingCode(
            HttpServletRequest httpRequest,
            @RequestBody RedeemPairingCodeRequest request) {
        rateLimiter.checkPairingCodeRedeem(clientIp(httpRequest));
        RedeemPairingCodeResponse response = service.redeemPairingCode(request);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(response);
    }

    @PostMapping("/api/public/transfer/rooms/diagram/versions/list")
    public List<DiagramVersionView> listVersions(@RequestBody RoomCredential credential) {
        return service.listVersions(credential.roomId(), credential);
    }

    @PostMapping("/api/public/transfer/rooms/diagram/versions")
    public DiagramVersionView createVersion(@RequestBody CreateDiagramVersionRequest request) {
        return service.createVersion(request.roomId(), request);
    }

    @PostMapping("/api/public/transfer/rooms/diagram/versions/{versionId}")
    public DiagramVersionDetail getVersion(@PathVariable long versionId,
                                           @RequestBody RoomCredential credential) {
        return service.getVersion(credential.roomId(), versionId, credential);
    }

    @PostMapping("/api/public/transfer/rooms/diagram/versions/{versionId}/delete")
    public ResponseEntity<Void> deleteVersion(@PathVariable long versionId,
                                              @RequestBody RoomCredential credential) {
        service.deleteVersion(credential.roomId(), versionId, credential);
        return ResponseEntity.noContent().build();
    }

    /** Same trusted-proxy address policy used by the public attachment endpoint and discovery WS. */
    private static String clientIp(HttpServletRequest request) {
        String realIp = request.getHeader("X-Real-IP");
        if (StringUtils.hasText(realIp)) {
            return realIp.trim();
        }
        String forwarded = request.getHeader("X-Forwarded-For");
        if (StringUtils.hasText(forwarded)) {
            String[] parts = forwarded.split(",");
            String last = parts[parts.length - 1].trim();
            if (StringUtils.hasText(last)) {
                return last;
            }
        }
        return request.getRemoteAddr();
    }
}
