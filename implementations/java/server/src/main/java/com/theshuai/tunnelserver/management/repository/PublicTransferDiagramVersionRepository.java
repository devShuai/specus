package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.PublicTransferDiagramVersion;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface PublicTransferDiagramVersionRepository extends JpaRepository<PublicTransferDiagramVersion, Long> {
    List<PublicTransferDiagramVersion> findByRoom_IdOrderByCreatedAtDesc(Long roomId);

    Optional<PublicTransferDiagramVersion> findByIdAndRoom_Id(Long id, Long roomId);
}
