package com.theshuai.specusserver.management.service;

import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.tenant.TenantContext;
import com.theshuai.specusserver.security.PasswordService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.theshuai.common.session.Session;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.embedded.EmbeddedChannel;

import java.time.Instant;
import java.util.Arrays;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-management-resource-writes?mode=memory&cache=shared",
        "spring.jpa.hibernate.ddl-auto=create-drop", "specus.netty.port=0",
        "specus.database.seed-demo-client=false", "specus.auth.username=write-root",
        "specus.auth.password=write-root-password"
})
class ManagementResourceWriteCoordinationTests {
    @Autowired ClientAccountService clients;
    @Autowired ClientCredentialService credentials;
    @Autowired ManagementUserService users;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;
    static final ManagementContext ALICE = new ManagementContext(TenantContext.defaultTenant(), "alice", true, "alice-key");
    enum ActorChange { DISABLED, DELETED, REPLACED, TENANT, LOGIN }
    enum Mutation { CLIENT_CREATE, CLIENT_UPDATE, CLIENT_DELETE, USER_CREATE, USER_UPDATE, USER_DELETE }
    enum RuntimeChange { RENAME, DISABLE }

    @BeforeEach
    void seed() {
        jdbc.update("delete from specus_client_identity");
        jdbc.update("delete from specus_client_account");
        jdbc.update("delete from specus_client_credential");
        jdbc.update("delete from specus_management_user");
        String now = Instant.now().toString();
        for (String login : new String[]{"alice", "target"})
            jdbc.update("insert into specus_management_user(username,tenant_id,login_name,login_name_normalized,password_hash,role,enabled,created_at,updated_at) values (?,'default',?,?,?,'ADMIN',true,?,?)",
                    login + "-key", login, login, PasswordService.hashToken("write-password"), now, now);
        jdbc.update("insert into specus_client_account(id,tenant_id,owner_username,client_name,password_hash,enabled,connection_rate_limit_per_minute,created_at,updated_at) values (501,'default','alice','write-client',?,true,30,?,?)",
                PasswordService.hashToken("write-token"), now, now);
    }

    static Stream<Arguments> revokedWrites() {
        return Arrays.stream(ActorChange.values()).flatMap(change -> Arrays.stream(Mutation.values())
                .map(mutation -> Arguments.of(change, mutation)));
    }

    @ParameterizedTest
    @MethodSource("revokedWrites")
    void staleActorCannotMutateAnyClientOrUser(ActorChange change, Mutation mutation) {
        switch (change) {
            case DISABLED -> jdbc.update("update specus_management_user set enabled=false where username='alice-key'");
            case DELETED -> jdbc.update("delete from specus_management_user where username='alice-key'");
            case REPLACED -> jdbc.update("update specus_management_user set username='replacement-key' where username='alice-key'");
            case TENANT -> jdbc.update("update specus_management_user set tenant_id='foreign' where username='alice-key'");
            case LOGIN -> jdbc.update("update specus_management_user set login_name='renamed',login_name_normalized='renamed' where username='alice-key'");
        }
        var rejected = assertThrows(ResponseStatusException.class, () -> mutate(mutation, ALICE));
        assertEquals(403, rejected.getStatusCode().value());
        assertEquals("write-client", jdbc.queryForObject("select client_name from specus_client_account where id=501", String.class));
        assertEquals(1, jdbc.queryForObject("select count(*) from specus_client_account", Integer.class));
        assertEquals(1, jdbc.queryForObject("select count(*) from specus_management_user where username='target-key' and enabled=true", Integer.class));
    }

    @Test
    void demotedAdminLosesForeignClientAndAllUserWriteAccess() {
        jdbc.update("update specus_management_user set role='USER' where username='alice-key'");
        jdbc.update("update specus_client_account set owner_username='bob' where id=501");
        for (Mutation mutation : Mutation.values()) {
            if (mutation == Mutation.CLIENT_CREATE) continue;
            if (mutation == Mutation.CLIENT_UPDATE || mutation == Mutation.CLIENT_DELETE)
                assertThrows(IllegalArgumentException.class, () -> mutate(mutation, ALICE));
            else assertEquals(403, assertThrows(ResponseStatusException.class, () -> mutate(mutation, ALICE)).getStatusCode().value());
        }
        mutate(Mutation.CLIENT_CREATE, ALICE);
        assertEquals("alice", jdbc.queryForObject("select owner_username from specus_client_account where client_name='new-write-client'", String.class));
    }

    @Test
    void currentPromotionWorksEvenWhenResolvedContextWasNotAdmin() {
        ManagementContext oldUser = new ManagementContext(ALICE.tenant(), "alice", false, "alice-key");
        jdbc.update("update specus_client_account set owner_username='bob' where id=501");
        mutate(Mutation.CLIENT_UPDATE, oldUser);
        mutate(Mutation.USER_CREATE, oldUser);
        mutate(Mutation.USER_UPDATE, oldUser);
        mutate(Mutation.USER_DELETE, oldUser);
        mutate(Mutation.CLIENT_DELETE, oldUser);
        assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_account", Integer.class));
        assertEquals(0, jdbc.queryForObject("select count(*) from specus_management_user where username='target-key'", Integer.class));
    }

    @Test
    void deletedAccountCannotCreateOrphanedClientsOrCredentials() {
        jdbc.update("delete from specus_client_account");
        users.deleteUser(new ManagementContext(ALICE.tenant(), "write-root", true), "alice");
        assertThrows(ResponseStatusException.class, () -> mutate(Mutation.CLIENT_CREATE, ALICE));
        assertThrows(ResponseStatusException.class, () -> credentials.create(ALICE,
                new ClientCredentialService.CredentialMutation("orphan-key", "orphan-secret", true, 2)));
        assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_account", Integer.class));
        assertEquals(0, jdbc.queryForObject("select count(*) from specus_client_credential", Integer.class));
    }

    @Test
    void transferredClientIsHiddenFromItsFormerRegularOwner() {
        jdbc.update("update specus_management_user set role='USER' where username='alice-key'");
        jdbc.update("update specus_client_account set owner_username='bob' where id=501");
        assertThrows(IllegalArgumentException.class, () -> mutate(Mutation.CLIENT_UPDATE, ALICE));
        assertThrows(IllegalArgumentException.class, () -> mutate(Mutation.CLIENT_DELETE, ALICE));
        assertEquals("bob", jdbc.queryForObject("select owner_username from specus_client_account where id=501", String.class));
        assertEquals("write-client", jdbc.queryForObject("select client_name from specus_client_account where id=501", String.class));
    }

    @ParameterizedTest
    @EnumSource(RuntimeChange.class)
    void rollbackDoesNotDisconnectTheStillValidClient(RuntimeChange change) {
        EmbeddedChannel channel = new EmbeddedChannel();
        SessionUtil.bindSession(new Session("write-client"), channel);
        try {
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                clients.updateClient(ALICE, 501, new ClientAccountService.ClientMutation(
                        change == RuntimeChange.RENAME ? "renamed-runtime-client" : null,
                        change == RuntimeChange.DISABLE ? false : null, null));
                assertTrue(channel.isOpen(), "runtime must remain intact until commit");
                status.setRollbackOnly();
            });
            assertTrue(channel.isOpen(), "a rolled-back mutation must not close the original connection");
            assertEquals("write-client", jdbc.queryForObject("select client_name from specus_client_account where id=501", String.class));
            assertTrue(jdbc.queryForObject("select enabled from specus_client_account where id=501", Boolean.class));
        } finally { SessionUtil.unBindSession(channel); channel.finishAndReleaseAll(); }
    }

    @ParameterizedTest
    @EnumSource(RuntimeChange.class)
    void commitDisconnectsOnlyAfterTheDatabaseMutationAndEvictsTheNameCache(RuntimeChange change) {
        clients.findClientByName("write-client");
        EmbeddedChannel channel = new EmbeddedChannel();
        SessionUtil.bindSession(new Session("write-client"), channel);
        try {
            new TransactionTemplate(transactions).executeWithoutResult(status -> {
                clients.updateClient(ALICE, 501, new ClientAccountService.ClientMutation(
                        change == RuntimeChange.RENAME ? "renamed-runtime-client" : null,
                        change == RuntimeChange.DISABLE ? false : null, null));
                assertTrue(channel.isOpen());
            });
            assertFalse(channel.isOpen());
            if (change == RuntimeChange.RENAME) {
                assertTrue(clients.findClientByName("write-client").isEmpty());
                assertEquals(501L, clients.findClientByName("renamed-runtime-client").orElseThrow().getId());
            } else assertFalse(clients.findClientByName("write-client").orElseThrow().isEnabled());
        } finally { SessionUtil.unBindSession(channel); channel.finishAndReleaseAll(); }
    }

    private void mutate(Mutation mutation, ManagementContext actor) {
        switch (mutation) {
            case CLIENT_CREATE -> clients.createClient(actor, new ClientAccountService.ClientMutation("new-write-client", true, 30));
            case CLIENT_UPDATE -> clients.updateClient(actor, 501, new ClientAccountService.ClientMutation("changed-write-client", null, 9));
            case CLIENT_DELETE -> clients.deleteClient(actor, 501);
            case USER_CREATE -> users.createUser(actor, new ManagementUserService.UserMutation("new-write-user", "New-write-password-1", null, true));
            case USER_UPDATE -> users.updateUser(actor, "target", new ManagementUserService.UserMutation(null, null, null, false));
            case USER_DELETE -> users.deleteUser(actor, "target");
        }
    }
}
