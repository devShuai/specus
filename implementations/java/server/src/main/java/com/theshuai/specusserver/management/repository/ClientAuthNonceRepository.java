package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ClientAuthNonce;
import com.theshuai.specusserver.management.model.SortableInstant;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ClientAuthNonceRepository extends JpaRepository<ClientAuthNonce, String>,
        ClientAuthNonceRepositoryCustom {
    /** {@code now} and {@code expiresAt} are {@link SortableInstant} text, so the string order is the time order. */
    @Modifying
    @Query("delete from ClientAuthNonce n where n.expiresAt < :now")
    int deleteExpired(@Param("now") String now);
}
