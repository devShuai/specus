package com.theshuai.specusserver.management.service;
import com.theshuai.specusserver.database.PeerSignalCommitAssertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import javax.sql.DataSource;
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.NONE,properties={
        "spring.datasource.url=jdbc:sqlite:file:target/test-peer-signal-commit?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=1","spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0","specus.database.seed-demo-client=false","specus.peer-mesh.relay-traffic-flush-interval-ms=3600000"
})
class PeerSignalCommitTests {
    @Autowired ConfigurableApplicationContext context; @Autowired DataSource dataSource;
    @Test void committedSignalsUseCurrentAuthorityAndChannels() throws Exception {PeerSignalCommitAssertions.verify(context,dataSource);}
}
