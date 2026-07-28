package com.theshuai.specusserver.management.service;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-client-auth-nonce?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "specus.netty.port=0",
                "specus.database.seed-demo-client=false"
        }
)
class ClientAuthNonceServiceIntegrationTests {
    @Autowired
    private ClientAuthNonceService service;

    @Test
    void consumesEachApiKeyAndNoncePairOnlyOnce() {
        assertTrue(service.consume("api-key-a", "nonce"));
        assertFalse(service.consume("api-key-a", "nonce"));
        assertTrue(service.consume("api-key-b", "nonce"));
    }
}
