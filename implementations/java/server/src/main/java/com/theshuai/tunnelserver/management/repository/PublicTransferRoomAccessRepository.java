package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PublicTransferRoomAccess;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PublicTransferRoomAccessRepository extends JpaRepository<PublicTransferRoomAccess, Long> {
    /**
     * Deliberately includes revoked and expired rows. The room service must distinguish a known
     * but unusable invite from a truly unknown token; otherwise {@code resolve} could create a new
     * owner room from an expired invite token.
     */
    Optional<PublicTransferRoomAccess> findByTokenHash(String tokenHash);

    List<PublicTransferRoomAccess> findByRoom_IdOrderByCreatedAtDesc(Long roomId);

    Optional<PublicTransferRoomAccess> findByIdAndRoom_Id(Long id, Long roomId);
}
