package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientDownloadLink;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ClientDownloadLinkRepository extends JpaRepository<ClientDownloadLink, Long> {
    /** 管理面用：返回全量（含禁用），按 displayOrder + id 排序。 */
    List<ClientDownloadLink> findAllByOrderByDisplayOrderAscIdAsc();

    /** 公开接口用：仅返回 enabled，按 implementation 分组展示。 */
    List<ClientDownloadLink> findByEnabledTrueOrderByImplementationAscDisplayOrderAscIdAsc();
}
