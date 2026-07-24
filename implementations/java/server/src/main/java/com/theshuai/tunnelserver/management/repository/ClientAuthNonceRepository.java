package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientAuthNonce;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientAuthNonceRepository extends JpaRepository<ClientAuthNonce, String>,
        ClientAuthNonceRepositoryCustom {
    @Modifying
    @Query("delete from ClientAuthNonce n where n.expiresAt < :now")
    int deleteExpired(@Param("now") String now);
}
