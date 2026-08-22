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

    /** 公开编目筛选用：必须查看禁用版本，避免停用版本后旧外链被意外重新公开。 */
    List<ClientDownloadLink> findAllByOrderByImplementationAscDisplayOrderAscIdAsc();

    List<ClientDownloadLink> findByImplementationAndPlatformInAndArchInAndEnabledTrue(
            String implementation, List<String> platforms, List<String> arches);

    /** Includes disabled rows: any configured target suppresses automatic GitHub fallback. */
    boolean existsByImplementationAndPlatformInAndArchIn(
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
