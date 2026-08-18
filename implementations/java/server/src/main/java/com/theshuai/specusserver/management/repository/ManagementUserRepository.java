package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ManagementUser;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ManagementUserRepository extends JpaRepository<ManagementUser, String> {
    Optional<ManagementUser> findByUsernameIgnoreCase(String username);

    Optional<ManagementUser> findByUsernameIgnoreCaseAndTenantId(String username, String tenantId);

    Optional<ManagementUser> findByOidcIdentityKey(String oidcIdentityKey);

    /**
     * Atomically links an imported local account on its first OIDC login. The conditional update
     * prevents two different issuer/subject pairs racing on the same preferred username from both
     * receiving a token for that account.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            update ManagementUser user
               set user.oidcIssuer = :issuer,
                   user.oidcSubject = :subject,
                   user.oidcIdentityKey = :identityKey,
                   user.updatedAt = :updatedAt
             where lower(user.username) = lower(:username)
               and user.enabled = true
               and (user.oidcIssuer is null or user.oidcIssuer = '')
               and (user.oidcSubject is null or user.oidcSubject = '')
               and (user.oidcIdentityKey is null or user.oidcIdentityKey = '')
            """)
    int bindOidcIdentityIfUnbound(@Param("username") String username,
                                  @Param("issuer") String issuer,
                                  @Param("subject") String subject,
                                  @Param("identityKey") String identityKey,
                                  @Param("updatedAt") String updatedAt);

    boolean existsByUsernameIgnoreCase(String username);

    List<ManagementUser> findByTenantIdOrderByUsernameAsc(String tenantId);
}
