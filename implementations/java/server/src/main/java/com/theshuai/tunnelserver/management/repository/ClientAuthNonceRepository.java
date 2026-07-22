package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientAuthNonce;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientAuthNonceRepository extends JpaRepository<ClientAuthNonce, String> {
    @Modifying
    @Query(value = """
            insert into tunnel_client_auth_nonce(id, api_key_hash, expires_at)
            values (:id, :apiKeyHash, :expiresAt)
            on conflict (id) do nothing
            """, nativeQuery = true)
    int insertIfAbsent(@Param("id") String id,
                       @Param("apiKeyHash") String apiKeyHash,
                       @Param("expiresAt") String expiresAt);

    @Modifying
    @Query("delete from ClientAuthNonce n where n.expiresAt < :now")
    int deleteExpired(@Param("now") String now);
}
