package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.database.ClientOwnershipLockAssertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-ownership-lock-order?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=1", "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.database.seed-demo-client=false"
})
class ClientOwnershipLockTests {
    @Autowired ConfigurableApplicationContext context;
    @Test void malformedCredentialLinksDenyBothTransports() { ClientOwnershipLockAssertions.verifyAuthentication(context); }
    @Test void groupUsesGloballyOrderedCredentialLocks() { ClientOwnershipLockAssertions.verifyOrder(context); }
}
