package com.theshuai.tunnelserver.management.repository;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientAccountRepository extends JpaRepository<ClientAccount, Long> {
    Optional<ClientAccount> findByClientName(String clientName);
}
