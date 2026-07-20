package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.config.PublicTransferProperties;
import com.theshuai.tunnelserver.management.model.PublicTransferDiagramVersion;
import com.theshuai.tunnelserver.management.model.PublicTransferRoom;
import com.theshuai.tunnelserver.management.model.PublicTransferRoomAccess;
import com.theshuai.tunnelserver.management.model.PublicTransferRoomPairingCode;
import com.theshuai.tunnelserver.management.repository.PublicTransferDiagramVersionRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomAccessRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomPairingCodeRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomRepository;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateAccessTokenRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateDiagramVersionRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreatePairingCodeRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.RedeemPairingCodeRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.Role;
import com.theshuai.tunnelserver.security.LocalTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicTransferRoomServiceTests {
    private PublicTransferRoomRepository roomRepository;
    private PublicTransferRoomAccessRepository accessRepository;
    private PublicTransferRoomPairingCodeRepository pairingCodeRepository;
    private PublicTransferDiagramVersionRepository versionRepository;
    private PublicTransferProperties properties;
    private LocalTokenService localTokenService;
    private PublicTransferRoomService service;

    @BeforeEach
    void setUp() {
        roomRepository = mock(PublicTransferRoomRepository.class);
        accessRepository = mock(PublicTransferRoomAccessRepository.class);
        pairingCodeRepository = mock(PublicTransferRoomPairingCodeRepository.class);
        versionRepository = mock(PublicTransferDiagramVersionRepository.class);
        properties = new PublicTransferProperties();
        localTokenService = mock(LocalTokenService.class);
        when(localTokenService.getSecretKey()).thenReturn(new SecretKeySpec(new byte[32], "HmacSHA256"));
        service = new PublicTransferRoomService(
                roomRepository, accessRepository, pairingCodeRepository, versionRepository,
                properties, localTokenService);
    }

    @Test
    void firstRoomTokenBecomesOwnerAndOnlyHashIsStored() {
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHash(any())).thenReturn(Optional.empty());
        when(roomRepository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var access = service.resolve("design-room", "owner-secret", "web-owner");

        assertEquals(Role.OWNER, access.role());
        ArgumentCaptor<PublicTransferRoom> roomCaptor = ArgumentCaptor.forClass(PublicTransferRoom.class);
        verify(roomRepository).saveAndFlush(roomCaptor.capture());
        assertEquals(64, roomCaptor.getValue().getOwnerTokenHash().length());
        assertNotEquals("owner-secret", roomCaptor.getValue().getOwnerTokenHash());
    }

    @Test
    void unknownInviteShapedTokenCannotCreateShadowOwnerRoom() {
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.resolve("design-room", "st-editor-deleted-token", "web-editor"));

        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
        verify(roomRepository, never()).saveAndFlush(any());
    }

    @Test
    void activeInviteResolvesItsAssignedRole() {
        PublicTransferRoom room = room(18L, "design-room");
        PublicTransferRoomAccess invite = new PublicTransferRoomAccess();
        invite.setRoom(room);
        invite.setRole(Role.VIEWER.name());
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHash(any())).thenReturn(Optional.of(invite));

        var access = service.resolve("design-room", "viewer-token", "web-viewer");

        assertEquals(18L, access.roomId());
        assertEquals(Role.VIEWER, access.role());
    }

    @Test
    void expiredInviteIsForbiddenInsteadOfCreatingShadowOwnerRoom() {
        PublicTransferRoomAccess invite = invite(room(18L, "design-room"), Role.EDITOR);
        invite.setExpiresAt(Instant.now().minusSeconds(1).toString());
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHash(any())).thenReturn(Optional.of(invite));

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.resolve("design-room", "expired-token", "web-editor"));

        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
        verify(roomRepository, never()).saveAndFlush(any());
    }

    @Test
    void revokedInviteIsForbiddenInsteadOfCreatingShadowOwnerRoom() {
        PublicTransferRoomAccess invite = invite(room(18L, "design-room"), Role.EDITOR);
        invite.setRevokedAt(Instant.now().toString());
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHash(any())).thenReturn(Optional.of(invite));

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.resolve("design-room", "revoked-token", "web-editor"));

        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
        verify(roomRepository, never()).saveAndFlush(any());
    }

    @Test
    void accessTokenWithoutExpiryRemainsBackwardCompatible() {
        PublicTransferRoom room = ownerRoom(18L, "design-room");
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.of(room));
        when(roomRepository.findById(18L)).thenReturn(Optional.of(room));
        when(accessRepository.findByRoom_IdOrderByCreatedAtDesc(18L)).thenReturn(List.of());
        when(accessRepository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var created = service.createAccessToken("design-room",
                new CreateAccessTokenRequest("design-room", "owner-token", "owner", "EDITOR", "协作者", null));

        assertNull(created.access().expiresAt());
        ArgumentCaptor<PublicTransferRoomAccess> captor = ArgumentCaptor.forClass(PublicTransferRoomAccess.class);
        verify(accessRepository).saveAndFlush(captor.capture());
        assertNull(captor.getValue().getExpiresAt());
    }

    @Test
    void accessTokenExpiryMustBeBetweenFiveMinutesAndSevenDays() {
        PublicTransferRoom room = ownerRoom(18L, "design-room");
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.of(room));
        when(roomRepository.findById(18L)).thenReturn(Optional.of(room));
        when(accessRepository.findByRoom_IdOrderByCreatedAtDesc(18L)).thenReturn(List.of());

        assertThrows(IllegalArgumentException.class, () -> service.createAccessToken("design-room",
                new CreateAccessTokenRequest("design-room", "owner-token", "owner", "EDITOR", "短期", 299L)));
        assertThrows(IllegalArgumentException.class, () -> service.createAccessToken("design-room",
                new CreateAccessTokenRequest("design-room", "owner-token", "owner", "EDITOR", "过长", 604801L)));
    }

    @Test
    void pairingCodeIsEightDigitsAndOnlyHmacIsPersisted() {
        PublicTransferRoom room = ownerRoom(18L, "design-room");
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.of(room));
        when(roomRepository.findById(18L)).thenReturn(Optional.of(room));
        when(pairingCodeRepository.existsByCodeHash(anyString())).thenReturn(false);
        when(pairingCodeRepository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var created = service.createPairingCode("design-room",
                new CreatePairingCodeRequest("design-room", "owner-token", "owner", "VIEWER", "临时访客", null));

        assertTrue(created.code().matches("[0-9]{8}"));
        assertEquals(1, created.maxUses());
        ArgumentCaptor<PublicTransferRoomPairingCode> captor = ArgumentCaptor.forClass(PublicTransferRoomPairingCode.class);
        verify(pairingCodeRepository).saveAndFlush(captor.capture());
        assertEquals(64, captor.getValue().getCodeHash().length());
        assertNotEquals(created.code(), captor.getValue().getCodeHash());
        assertTrue(Instant.parse(created.expiresAt()).isAfter(Instant.parse(created.createdAt())));
    }

    @Test
    void redeemingPairingCodeAtomicallyMintsTwentyFourHourRoleToken() {
        PublicTransferRoom room = room(18L, "design-room");
        PublicTransferRoomPairingCode pairing = new PublicTransferRoomPairingCode();
        pairing.setRoom(room);
        pairing.setRole(Role.EDITOR.name());
        pairing.setLabel("游戏队友");
        when(pairingCodeRepository.consumeUsable(anyString(), anyString())).thenReturn(1);
        when(pairingCodeRepository.findByCodeHash(anyString())).thenReturn(Optional.of(pairing));
        when(accessRepository.findByRoom_IdOrderByCreatedAtDesc(18L)).thenReturn(List.of());
        when(accessRepository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        Instant before = Instant.now();
        var redeemed = service.redeemPairingCode(new RedeemPairingCodeRequest("12345678", "guest"));

        assertEquals("design-room", redeemed.roomId());
        assertEquals(Role.EDITOR, redeemed.role());
        assertTrue(redeemed.roomToken().startsWith("st-editor-"));
        long ttl = Instant.parse(redeemed.expiresAt()).getEpochSecond() - before.getEpochSecond();
        assertTrue(ttl >= 86399 && ttl <= 86401);
        ArgumentCaptor<PublicTransferRoomAccess> captor = ArgumentCaptor.forClass(PublicTransferRoomAccess.class);
        verify(accessRepository).saveAndFlush(captor.capture());
        assertEquals(redeemed.expiresAt(), captor.getValue().getExpiresAt());
    }

    @Test
    void exhaustedOrUnknownPairingCodeDoesNotMintToken() {
        when(pairingCodeRepository.consumeUsable(anyString(), anyString())).thenReturn(0);

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.redeemPairingCode(new RedeemPairingCodeRequest("12345678", "guest")));

        assertEquals(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verify(accessRepository, never()).saveAndFlush(any());
    }

    @Test
    void viewerCannotCreateDiagramVersion() {
        PublicTransferRoom room = room(18L, "design-room");
        PublicTransferRoomAccess invite = new PublicTransferRoomAccess();
        invite.setRoom(room);
        invite.setRole(Role.VIEWER.name());
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHash(any())).thenReturn(Optional.of(invite));

        assertThrows(ResponseStatusException.class, () -> service.createVersion(
                "design-room",
                new CreateDiagramVersionRequest("design-room", "viewer-token", "web-viewer", "checkpoint", "AQID")
        ));
    }

    @Test
    void ownerSnapshotIsDecodedBeforeOrmPersistence() {
        PublicTransferRoom room = room(18L, "design-room");
        room.setOwnerTokenHash("stored-hash");
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.of(room));
        when(roomRepository.findById(18L)).thenReturn(Optional.of(room));
        when(versionRepository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(versionRepository.findByRoom_IdOrderByCreatedAtDesc(18L)).thenAnswer(invocation -> List.of());
        byte[] snapshot = "yjs-state".getBytes(StandardCharsets.UTF_8);

        service.createVersion(
                "design-room",
                new CreateDiagramVersionRequest(
                        "design-room",
                        "owner-token",
                        "web-owner",
                        "checkpoint",
                        Base64.getEncoder().encodeToString(snapshot)
                )
        );

        ArgumentCaptor<PublicTransferDiagramVersion> versionCaptor = ArgumentCaptor.forClass(PublicTransferDiagramVersion.class);
        verify(versionRepository).saveAndFlush(versionCaptor.capture());
        assertArrayEquals(snapshot, versionCaptor.getValue().getSnapshotData());
        assertEquals(snapshot.length, versionCaptor.getValue().getSizeBytes());
    }

    private static PublicTransferRoom room(long id, String name) {
        PublicTransferRoom room = new PublicTransferRoom();
        room.setId(id);
        room.setRoomName(name);
        return room;
    }

    private static PublicTransferRoom ownerRoom(long id, String name) {
        PublicTransferRoom room = room(id, name);
        room.setOwnerTokenHash("stored-owner-hash");
        return room;
    }

    private static PublicTransferRoomAccess invite(PublicTransferRoom room, Role role) {
        PublicTransferRoomAccess invite = new PublicTransferRoomAccess();
        invite.setRoom(room);
        invite.setRole(role.name());
        return invite;
    }
}
