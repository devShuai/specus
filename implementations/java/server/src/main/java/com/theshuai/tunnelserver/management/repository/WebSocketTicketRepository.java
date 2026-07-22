package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.WebSocketTicket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface WebSocketTicketRepository extends JpaRepository<WebSocketTicket, String> {
    @Modifying
    @Query("""
            delete from WebSocketTicket t
             where t.tokenHash = :tokenHash
               and t.scope = :scope
               and t.expiresAt >= :now
            """)
    int consume(@Param("tokenHash") String tokenHash,
                @Param("scope") String scope,
                @Param("now") String now);

    @Modifying
    @Query("delete from WebSocketTicket t where t.expiresAt < :now")
    int deleteExpired(@Param("now") String now);
}
