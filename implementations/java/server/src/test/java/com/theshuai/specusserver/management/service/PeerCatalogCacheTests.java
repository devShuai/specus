package com.theshuai.specusserver.management.service;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import javax.sql.DataSource;
@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.NONE,properties={
        "spring.datasource.url=jdbc:sqlite:file:target/test-peer-catalog-cache?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=4","spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0","specus.database.seed-demo-client=false"
})
class PeerCatalogCacheTests{
    @Autowired ConfigurableApplicationContext context;@Autowired DataSource source;
    @Test void catalogIndexesFollowActualTransactions()throws Exception{PeerCatalogCacheAssertions.verify(context,source);}
}
