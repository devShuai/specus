package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.PublicTransferRoomPairingCode;
import com.theshuai.specusserver.management.model.SortableInstant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface PublicTransferRoomPairingCodeRepository extends JpaRepository<PublicTransferRoomPairingCode, Long> {
    Optional<PublicTransferRoomPairingCode> findByCodeHash(String codeHash);

    boolean existsByCodeHash(String codeHash);

    /**
     * Atomically reserves one redemption. This avoids the check-then-update race that could let a
     * one-time code mint more than one access token on MySQL/PostgreSQL or concurrent SQLite use.
     * {@code now} and {@code expiresAt} are {@link SortableInstant} text, so the string order is the
     * time order.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update PublicTransferRoomPairingCode pairing
               set pairing.usedCount = pairing.usedCount + 1
             where pairing.codeHash = :codeHash
               and pairing.revokedAt is null
               and pairing.expiresAt > :now
               and pairing.usedCount < pairing.maxUses
            """)
    int consumeUsable(@Param("codeHash") String codeHash, @Param("now") String now);
}
