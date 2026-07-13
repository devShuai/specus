package com.theshuai.tunnelserver.management.controller;

import com.theshuai.tunnelserver.management.service.PublicTransferRoomService;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.AccessTokenView;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateAccessTokenRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateDiagramVersionRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreatedAccessToken;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.DiagramVersionDetail;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.DiagramVersionView;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.RoomCredential;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
public class PublicTransferRoomResource {
    private final PublicTransferRoomService service;

    public PublicTransferRoomResource(PublicTransferRoomService service) {
        this.service = service;
    }

    @PostMapping("/api/public/transfer/rooms/access-tokens/list")
    public List<AccessTokenView> listAccessTokens(@RequestBody RoomCredential credential) {
        return service.listAccessTokens(credential.roomId(), credential);
    }

    @PostMapping("/api/public/transfer/rooms/access-tokens")
    public CreatedAccessToken createAccessToken(@RequestBody CreateAccessTokenRequest request) {
        return service.createAccessToken(request.roomId(), request);
    }

    @PostMapping("/api/public/transfer/rooms/access-tokens/{accessId}/revoke")
    public AccessTokenView revokeAccessToken(@PathVariable long accessId,
                                             @RequestBody RoomCredential credential) {
        return service.revokeAccessToken(credential.roomId(), accessId, credential);
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
}
