package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PublicTransferRoom;
import com.theshuai.tunnelserver.management.model.PublicTransferRoomPairingCode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "tunnel.netty.port=0",
        "tunnel.database.seed-demo-client=false"
})
@Transactional
class PublicTransferRoomPairingCodeRepositoryTests {
    @Autowired
    private PublicTransferRoomRepository roomRepository;

    @Autowired
    private PublicTransferRoomPairingCodeRepository pairingCodeRepository;

    @Test
    void conditionalConsumeAllowsExactlyMaxUses() {
        Instant now = Instant.now();
        PublicTransferRoom room = new PublicTransferRoom();
        room.setId(91001L);
        room.setRoomName("pairing-repository-test");
        room.setOwnerTokenHash("a".repeat(64));
        room.setCreatedByPeerId("owner");
        room.setCreatedAt(now.toString());
        room.setUpdatedAt(now.toString());
        roomRepository.saveAndFlush(room);

        PublicTransferRoomPairingCode pairing = new PublicTransferRoomPairingCode();
        pairing.setId(92001L);
        pairing.setRoom(room);
        pairing.setCodeHash("b".repeat(64));
        pairing.setRole("EDITOR");
        pairing.setLabel("一次性配对");
        pairing.setCreatedAt(now.toString());
        pairing.setExpiresAt(now.plusSeconds(300).toString());
        pairing.setMaxUses(1);
        pairing.setUsedCount(0);
        pairingCodeRepository.saveAndFlush(pairing);

        assertEquals(1, pairingCodeRepository.consumeUsable(pairing.getCodeHash(), now.toString()));
        assertEquals(0, pairingCodeRepository.consumeUsable(pairing.getCodeHash(), now.toString()));
        assertEquals(1, pairingCodeRepository.findByCodeHash(pairing.getCodeHash()).orElseThrow().getUsedCount());
    }
}
