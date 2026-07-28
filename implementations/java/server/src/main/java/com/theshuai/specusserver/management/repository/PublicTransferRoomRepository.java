package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PublicTransferRoom;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PublicTransferRoomRepository extends JpaRepository<PublicTransferRoom, Long> {
    Optional<PublicTransferRoom> findByRoomNameAndOwnerTokenHash(String roomName, String ownerTokenHash);
}
