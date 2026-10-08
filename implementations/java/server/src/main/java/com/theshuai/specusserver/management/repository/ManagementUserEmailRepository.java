package com.theshuai.specusserver.management.repository;

import com.theshuai.specusserver.management.model.ManagementUserEmail;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ManagementUserEmailRepository extends JpaRepository<ManagementUserEmail, String> {
    boolean existsByEmailIgnoreCase(String email);

    /** The email row's username column holds the account key of the account it belongs to. */
    @Modifying
    @Query("delete from ManagementUserEmail e where e.username = :accountKey")
    int deleteByAccountKey(@Param("accountKey") String accountKey);
}
