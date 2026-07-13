package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PublicTransferRoomAccess;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PublicTransferRoomAccessRepository extends JpaRepository<PublicTransferRoomAccess, Long> {
    Optional<PublicTransferRoomAccess> findByTokenHashAndRevokedAtIsNull(String tokenHash);

    List<PublicTransferRoomAccess> findByRoom_IdOrderByCreatedAtDesc(Long roomId);

    Optional<PublicTransferRoomAccess> findByIdAndRoom_Id(Long id, Long roomId);
}
