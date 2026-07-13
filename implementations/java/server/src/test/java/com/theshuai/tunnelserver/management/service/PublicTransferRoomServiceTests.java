package com.theshuai.tunnelserver.management.service;

import com.theshuai.tunnelserver.management.model.PublicTransferDiagramVersion;
import com.theshuai.tunnelserver.management.model.PublicTransferRoom;
import com.theshuai.tunnelserver.management.model.PublicTransferRoomAccess;
import com.theshuai.tunnelserver.management.repository.PublicTransferDiagramVersionRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomAccessRepository;
import com.theshuai.tunnelserver.management.repository.PublicTransferRoomRepository;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.CreateDiagramVersionRequest;
import com.theshuai.tunnelserver.management.service.PublicTransferRoomService.Role;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PublicTransferRoomServiceTests {
    private PublicTransferRoomRepository roomRepository;
    private PublicTransferRoomAccessRepository accessRepository;
    private PublicTransferDiagramVersionRepository versionRepository;
    private PublicTransferRoomService service;

    @BeforeEach
    void setUp() {
        roomRepository = mock(PublicTransferRoomRepository.class);
        accessRepository = mock(PublicTransferRoomAccessRepository.class);
        versionRepository = mock(PublicTransferDiagramVersionRepository.class);
        service = new PublicTransferRoomService(roomRepository, accessRepository, versionRepository);
    }

    @Test
    void firstRoomTokenBecomesOwnerAndOnlyHashIsStored() {
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHashAndRevokedAtIsNull(any())).thenReturn(Optional.empty());
        when(roomRepository.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));

        var access = service.resolve("design-room", "owner-secret", "web-owner");

        assertEquals(Role.OWNER, access.role());
        ArgumentCaptor<PublicTransferRoom> roomCaptor = ArgumentCaptor.forClass(PublicTransferRoom.class);
        verify(roomRepository).saveAndFlush(roomCaptor.capture());
        assertEquals(64, roomCaptor.getValue().getOwnerTokenHash().length());
        assertNotEquals("owner-secret", roomCaptor.getValue().getOwnerTokenHash());
    }

    @Test
    void activeInviteResolvesItsAssignedRole() {
        PublicTransferRoom room = room(18L, "design-room");
        PublicTransferRoomAccess invite = new PublicTransferRoomAccess();
        invite.setRoom(room);
        invite.setRole(Role.VIEWER.name());
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHashAndRevokedAtIsNull(any())).thenReturn(Optional.of(invite));

        var access = service.resolve("design-room", "viewer-token", "web-viewer");

        assertEquals(18L, access.roomId());
        assertEquals(Role.VIEWER, access.role());
    }

    @Test
    void viewerCannotCreateDiagramVersion() {
        PublicTransferRoom room = room(18L, "design-room");
        PublicTransferRoomAccess invite = new PublicTransferRoomAccess();
        invite.setRoom(room);
        invite.setRole(Role.VIEWER.name());
        when(roomRepository.findByRoomNameAndOwnerTokenHash(any(), any())).thenReturn(Optional.empty());
        when(accessRepository.findByTokenHashAndRevokedAtIsNull(any())).thenReturn(Optional.of(invite));

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
}
