package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientDownloadLink;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ClientDownloadLinkRepository extends JpaRepository<ClientDownloadLink, Long> {
    /** 管理面用：返回全量（含禁用），按 displayOrder + id 排序。 */
    List<ClientDownloadLink> findAllByOrderByDisplayOrderAscIdAsc();

    /** 公开接口用：仅返回 enabled，按 implementation 分组展示。 */
    List<ClientDownloadLink> findByEnabledTrueOrderByImplementationAscDisplayOrderAscIdAsc();

    Optional<ClientDownloadLink> findByImplementationAndPlatformAndArchAndLatestTrueAndEnabledTrue(
            String implementation, String platform, String arch);

    List<ClientDownloadLink> findByImplementationAndPlatformInAndArchInAndEnabledTrueAndHostedTrue(
            String implementation, List<String> platforms, List<String> arches);

    Optional<ClientDownloadLink> findByIdAndEnabledTrueAndHostedTrue(Long id);

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update ClientDownloadLink link
               set link.latest = false, link.latestSlot = null
             where link.implementation = :implementation
               and link.platform = :platform
               and link.arch = :arch
               and link.latest = true
            """)
    int clearLatest(@Param("implementation") String implementation,
                    @Param("platform") String platform,
                    @Param("arch") String arch);
}
