package com.theshuai.specusserver.management.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/** Actual native journal/receipt transactions; notification effects are explicitly mocked here. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
        "spring.datasource.url=jdbc:sqlite:file:target/test-owner-journal?mode=memory&cache=shared",
        "spring.datasource.hikari.maximum-pool-size=1", "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0", "specus.database.seed-demo-client=false", "specus.owner-transfer.notifications.poll=false"
})
class ClientOwnerTransferJournalTests {
    @Autowired ClientOwnerTransferJournal journal;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager transactions;
    private ClientAccountService accounts;
    private PeerSignalService signals;
    private ClientOwnerTransferNotifications consumer;

    @BeforeEach void setup() {
        jdbc.update("delete from client_owner_transfer_receipt");
        jdbc.update("delete from client_owner_transfer_audit");
        accounts = mock(ClientAccountService.class); signals = mock(PeerSignalService.class);
        consumer = new ClientOwnerTransferNotifications(journal, accounts, signals, false);
    }

    @Test void eachNodeConsumesIndependentlyAndAcknowledgementsAreIdempotent() {
        event(20);
        var a = journal.pending("node-a").getFirst();
        journal.acknowledge("node-a", a); journal.acknowledge("node-a", a);
        assertThat(journal.pending("node-a")).isEmpty();
        assertThat(journal.pending("node-b")).containsExactly(a);
        journal.acknowledge("node-b", a);
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_receipt", Integer.class)).isEqualTo(2);
    }

    @Test void aLowerIdCommittedLaterIsNotSkippedByAHighWaterMark() {
        event(50); journal.acknowledge("node-a", journal.pending("node-a").getFirst());
        event(10);
        assertThat(journal.pending("node-a")).extracting(ClientOwnerTransferJournal.Event::id).containsExactly(10L);
    }

    @Test void failedRefreshIsStillPendingAndRetryDoesNotReplayHistoricalOwners() {
        event(30);
        doThrow(new IllegalStateException("isolated refresh failure")).doNothing().when(signals).reconcileOwnership(eq("default"), anyList());
        consumer.committed(30L);
        assertThat(receipts()).isZero();
        consumer.drain(); assertThat(receipts()).isEqualTo(1);
        consumer.drain(); verify(signals, times(2)).reconcileOwnership("default", java.util.List.of());
    }

    @Test void receiptWriteFailureIsRetriedAfterAnAlreadyAppliedRefresh() {
        event(40);
        jdbc.execute("create trigger fail_owner_receipt before insert on client_owner_transfer_receipt begin select raise(abort,'receipt fault'); end");
        try { consumer.drain(); assertThat(receipts()).isZero(); }
        finally { jdbc.execute("drop trigger fail_owner_receipt"); }
        consumer.drain(); assertThat(receipts()).isEqualTo(1);
        verify(signals, times(2)).reconcileOwnership("default", java.util.List.of());
    }

    @Test void rollbackCannotInvalidateCacheOrPerformRuntimeWork() {
        new TransactionTemplate(transactions).executeWithoutResult(status -> {
            event(60);
            assertThatThrownBy(() -> consumer.committed(60L)).isInstanceOf(IllegalStateException.class);
            status.setRollbackOnly();
        });
        consumer.drain(); assertThat(receipts()).isZero();
        assertThat(jdbc.queryForObject("select count(*) from client_owner_transfer_audit", Integer.class)).isZero();
        verifyNoInteractions(accounts, signals);
    }

    @Test void aNewProcessReplaysTheDurableJournalRatherThanSharingAnOthersReceipt() {
        event(70); consumer.drain();
        var second = new ClientOwnerTransferNotifications(journal, accounts, signals, false);
        second.drain(); second.drain();
        assertThat(receipts()).isEqualTo(2);
        assertThat(jdbc.queryForObject("select count(distinct node_id) from client_owner_transfer_receipt", Integer.class)).isEqualTo(2);
        verify(signals, times(2)).reconcileOwnership("default", java.util.List.of());
    }

    @Test void batchesAreBoundedWithoutDroppingUnprocessedEvents() {
        for (long id=100; id<135; id++) event(id);
        consumer.drain(); assertThat(receipts()).isEqualTo(32);
        consumer.drain(); assertThat(receipts()).isEqualTo(35);
    }

    @Test void aFailedBatchDoesNotStarveALaterTenant() {
        for (long id=200; id<233; id++) event(id);
        jdbc.update("update client_owner_transfer_audit set tenant_id='later-tenant' where id=232");
        doThrow(new IllegalStateException("isolated tenant failure")).when(signals).reconcileOwnership(eq("default"), anyList());
        consumer.drain(); assertThat(receipts()).isZero();
        consumer.drain(); assertThat(receipts()).isEqualTo(1);
        verify(signals).reconcileOwnership("later-tenant", java.util.List.of());
    }

    @Test void malformedJournalCannotBeAcknowledgedOrBlockOtherEvents() {
        event(80);event(81);
        jdbc.update("update client_owner_transfer_audit set detail_json=? where id=80", "{\"affectedClientIds\":[9007199254740992]}");
        consumer.drain();assertThat(receipts()).isEqualTo(1);
        assertThat(jdbc.queryForObject("select event_id from client_owner_transfer_receipt",Long.class)).isEqualTo(81L);
        verify(signals).reconcileOwnership("default",java.util.List.of());
    }

    private int receipts() { return jdbc.queryForObject("select count(*) from client_owner_transfer_receipt", Integer.class); }
    private void event(long id) {
        jdbc.update("insert into client_owner_transfer_audit(id,tenant_id,occurred_at,actor,scope,path_id,target_username,detail_json) values (?,'default','2026-10-16T00:00:00Z','fixture','credential-group',1,'Bob','{\"affectedClientIds\":[]}')", id);
    }
}
