package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.PublicTransferRoomService;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.AccessTokenView;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreateAccessTokenRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreatePairingCodeRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreatePairingCodeResponse;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreateDiagramVersionRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.CreatedAccessToken;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.DiagramVersionDetail;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.DiagramVersionView;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RedeemPairingCodeRequest;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RedeemPairingCodeResponse;
import com.theshuai.specusserver.management.service.PublicTransferRoomService.RoomCredential;
import com.theshuai.specusserver.management.service.PublicTransferRateLimiter;
import com.theshuai.specusserver.security.ClientAddressResolver;
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
    private final ClientAddressResolver addressResolver;

    public PublicTransferRoomResource(PublicTransferRoomService service,
                                      PublicTransferRateLimiter rateLimiter,
                                      ClientAddressResolver addressResolver) {
        this.service = service;
        this.rateLimiter = rateLimiter;
        this.addressResolver = addressResolver;
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
    private String clientIp(HttpServletRequest request) {
        return addressResolver.resolve(request);
    }
}
