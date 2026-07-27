package com.theshuai.tunnelserver.management.storage;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.jdbc.core.JdbcTemplate;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.NONE,
        properties = {
                "spring.datasource.url=jdbc:sqlite:file:target/test-http-traffic-summary?mode=memory&cache=shared",
                "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
                "spring.jpa.hibernate.ddl-auto=create-drop",
                "tunnel.netty.port=0",
                "tunnel.database.seed-demo-client=false"
        }
)
class JpaHttpTrafficExchangeStoreIntegrationTests {
    @Autowired
    private HttpTrafficExchangeRepository repository;

    @Autowired
    private HttpTrafficExchangeStore store;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        repository.deleteAll();
    }

    @Test
    void listUsesSummaryQueryWithoutLoadingTheBody() {
        byte[] imageBody = new byte[256 * 1024];
        imageBody[0] = (byte) 0x89;
        imageBody[1] = 0x50;
        imageBody[2] = 0x4e;
        imageBody[3] = 0x47;

        HttpTrafficExchange exchange = new HttpTrafficExchange();
        exchange.setTenantId(TenantContext.DEFAULT_TENANT_ID);
        exchange.setClientId(7L);
        exchange.setClientName("traffic-test");
        exchange.setRoute("images");
        exchange.setResourceName("images -> http://example.test");
        exchange.setMethod("GET");
        exchange.setRelativePath("/large.png");
        exchange.setStatusCode(200);
        exchange.setSuccess(true);
        exchange.setRequestBytes(0);
        exchange.setResponseBytes(imageBody.length);
        exchange.setElapsedMs(12);
        exchange.setResponseContentType("image/png");
        exchange.setResponseBodyType("image");
        exchange.setRequestHeaders("");
        exchange.setResponseHeaders("Content-Type: image/png");
        exchange.setRequestPreviewHex("");
        exchange.setRequestBodyData(new byte[0]);
        exchange.setRequestPreviewText("");
        exchange.setResponsePreviewHex("89504E47");
        exchange.setResponseBodyData(imageBody);
        exchange.setResponsePreviewText("");
        exchange.setRequestTruncated(false);
        exchange.setResponseTruncated(false);
        exchange.setCapturedAt(Instant.now().toString());
        long id = repository.saveAndFlush(exchange).getId();
        // SQLite's BIGINT identity column is not an alias for rowid. Hibernate obtains
        // last_insert_rowid(), but the test table's physical id remains null.
        jdbcTemplate.update(
                "update tunnel_http_traffic_exchange set id = ? where rowid = ?",
                id,
                id);

        Page<HttpTrafficExchangeView> page = store.search(
                TenantContext.defaultTenant(),
                null,
                null,
                null,
                "image",
                HttpTrafficSearchField.SUMMARY,
                null,
                PageRequest.of(0, 20, Sort.by(Sort.Direction.DESC, "id")));

        assertThat(page.getContent()).hasSize(1);
        HttpTrafficExchangeView summary = page.getContent().getFirst();
        assertThat(summary.id()).isEqualTo(Long.toString(id));
        assertThat(summary.responseHeaders()).isNull();
        assertThat(summary.responsePreviewHex()).isNull();
        assertThat(summary.responsePreviewText()).isNull();
    }
}
