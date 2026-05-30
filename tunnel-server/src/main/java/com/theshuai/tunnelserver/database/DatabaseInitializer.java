package com.theshuai.tunnelserver.database;

import com.theshuai.tunnelserver.management.model.ClientAccount;
import com.theshuai.tunnelserver.management.repository.ClientAccountRepository;
import com.theshuai.tunnelserver.management.service.ClientIdGenerator;
import com.theshuai.tunnelserver.security.PasswordService;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class DatabaseInitializer {
    private final ClientAccountRepository clientAccountRepository;
    private final boolean seedDemoClient;
    private final String databasePlatform;

    public DatabaseInitializer(ClientAccountRepository clientAccountRepository,
                               @Value("${tunnel.database.seed-demo-client:true}") boolean seedDemoClient,
                               @Value("${spring.jpa.database-platform:auto}") String databasePlatform) {
        this.clientAccountRepository = clientAccountRepository;
        this.seedDemoClient = seedDemoClient;
        this.databasePlatform = databasePlatform;
    }

    @PostConstruct
    public void initializeAtStartup() {
        initialize();
    }

    @Transactional
    public synchronized Map<String, Object> initialize() {
        if (seedDemoClient && clientAccountRepository.findByClientName("Demo client").isEmpty()) {
            String now = Instant.now().toString();
            ClientAccount client = new ClientAccount();
            client.setId(ClientIdGenerator.newId());
            client.setClientName("Demo client");
            client.setPasswordHash(PasswordService.hash("test1234"));
            client.setEnabled(true);
            client.setConnectionRateLimitPerMinute(30);
            client.setCreatedAt(now);
            client.setUpdatedAt(now);
            clientAccountRepository.save(client);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("initialized", true);
        result.put("orm", "spring-data-jpa");
        result.put("dialect", databasePlatform);
        result.put("clients", clientAccountRepository.count());
        return result;
    }

}
