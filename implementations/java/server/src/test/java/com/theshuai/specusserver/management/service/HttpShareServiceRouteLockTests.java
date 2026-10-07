package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.config.AuthProperties;
import com.theshuai.specusserver.httpshare.HttpShareRules;
import com.theshuai.specusserver.httpshare.HttpShareRuntime;
import com.theshuai.specusserver.httpshare.HttpShareStreamRegistry;
import com.theshuai.specusserver.management.model.HttpRouteMapping;
import com.theshuai.specusserver.management.repository.ClientAccountRepository;
import com.theshuai.specusserver.management.repository.HttpAccessAuditRepository;
import com.theshuai.specusserver.management.repository.HttpRouteMappingRepository;
import com.theshuai.specusserver.management.repository.HttpShareRepository;
import com.theshuai.specusserver.management.repository.ManagementUserRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.SimpleTransactionStatus;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * The route lock that serializes share creations exists only on MySQL and PostgreSQL, which the
 * test suite does not run. These tests pin the statement per database platform and drive
 * {@link HttpShareService#create} over mocks to show where in the transaction it runs.
 */
class HttpShareServiceRouteLockTests {
    private static final String LOCK_SQL = "SELECT id FROM http_route_mapping WHERE id = :routeId FOR UPDATE";
    private static final byte[] BODY = "{\"expiresInSeconds\": 3600}".getBytes(StandardCharsets.UTF_8);

    private final HttpShareRepository shares = mock(HttpShareRepository.class);
    private final HttpRouteMappingRepository routes = mock(HttpRouteMappingRepository.class);
    private final EntityManager entityManager = mock(EntityManager.class);
    private final Query lockQuery = mock(Query.class);

    @ParameterizedTest
    @ValueSource(strings = {
            "org.hibernate.dialect.MySQLDialect",
            "org.hibernate.dialect.MariaDBDialect",
            "org.hibernate.dialect.PostgreSQLDialect"
    })
    void mysqlAndPostgresqlLockTheRouteRowForUpdate(String platform) {
        assertThat(HttpShareService.routeLockSql(platform)).isEqualTo(LOCK_SQL);
    }

    @ParameterizedTest
    @ValueSource(strings = {"org.hibernate.community.dialect.SQLiteDialect", "auto", ""})
    void sqliteTakesNoLock(String platform) {
        assertThat(HttpShareService.routeLockSql(platform)).isNull();
    }

    @Test
    void creationLocksTheRouteBeforeReadingAndCountingOnMySql() {
        HttpRouteMapping route = new HttpRouteMapping();
        route.setId(42L);
        route.setTenantId("t1");
        route.setClientId(7L);
        when(routes.findById(42L)).thenReturn(Optional.of(route));
        when(entityManager.createNativeQuery(anyString())).thenReturn(lockQuery);
        when(lockQuery.setParameter(anyString(), any())).thenReturn(lockQuery);
        when(lockQuery.getResultList()).thenReturn(List.of(42L));

        // The caller cannot be re-read, so the creation ends with the usual 404 after its reads.
        assertThatThrownBy(() -> service("org.hibernate.dialect.MySQLDialect").create(alice(), "42", BODY))
                .isInstanceOfSatisfying(HttpShareService.ShareProblem.class, problem -> {
                    assertThat(problem.status()).isEqualTo(404);
                    assertThat(problem.code()).isEqualTo(HttpShareRules.CODE_ROUTE_NOT_FOUND);
                });

        InOrder order = inOrder(entityManager, lockQuery, routes, shares);
        order.verify(entityManager).createNativeQuery(LOCK_SQL);
        order.verify(lockQuery).setParameter("routeId", 42L);
        order.verify(lockQuery).getResultList();
        order.verify(routes).findById(42L);
        order.verify(shares).countByRouteIdAndRevokedAtIsNullAndExpiresAtGreaterThan(eq(42L), anyLong());
    }

    @Test
    void aRouteRowGoneUnderTheLockStillAnswersAsBefore() {
        when(routes.findById(42L)).thenReturn(Optional.empty());
        when(entityManager.createNativeQuery(anyString())).thenReturn(lockQuery);
        when(lockQuery.setParameter(anyString(), any())).thenReturn(lockQuery);
        when(lockQuery.getResultList()).thenReturn(List.of());

        assertThatThrownBy(() -> service("org.hibernate.dialect.PostgreSQLDialect").create(alice(), "42", BODY))
                .isInstanceOfSatisfying(HttpShareService.ShareProblem.class, problem -> {
                    assertThat(problem.status()).isEqualTo(404);
                    assertThat(problem.code()).isEqualTo(HttpShareRules.CODE_ROUTE_NOT_FOUND);
                });
    }

    @Test
    void creationOnSqliteIssuesNoLock() {
        when(routes.findById(42L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service("org.hibernate.community.dialect.SQLiteDialect").create(alice(), "42", BODY))
                .isInstanceOf(HttpShareService.ShareProblem.class);

        verifyNoInteractions(entityManager);
    }

    @Test
    void anInvalidBodyIsRefusedBeforeAnyLock() {
        assertThatThrownBy(() -> service("org.hibernate.dialect.MySQLDialect")
                .create(alice(), "42", "{}".getBytes(StandardCharsets.UTF_8)))
                .isInstanceOfSatisfying(HttpShareService.ShareProblem.class,
                        problem -> assertThat(problem.status()).isEqualTo(400));

        verifyNoInteractions(entityManager, routes, shares);
    }

    private HttpShareService service(String platform) {
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(new SimpleTransactionStatus());
        HttpShareService service = new HttpShareService(shares, mock(HttpAccessAuditRepository.class), routes,
                mock(ClientAccountRepository.class), mock(ManagementUserRepository.class), new AuthProperties(),
                new HttpShareRuntime(), mock(HttpShareStreamRegistry.class), transactions, false, platform);
        ReflectionTestUtils.setField(service, "entityManager", entityManager);
        return service;
    }

    private static ManagementContext alice() {
        return new ManagementContext(new TenantContext("t1"), "alice", false);
    }
}
