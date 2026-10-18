package com.theshuai.specusserver.database;

import com.theshuai.specusserver.management.service.ClientOwnerTransferJournal;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

/** Native provider journal/receipt semantics, not an HTTP/cluster-delivery substitute. */
final class ClientOwnerTransferJournalAssertions {
    static void verify(ConfigurableApplicationContext context) {
        var journal=context.getBean(ClientOwnerTransferJournal.class);
        var jdbc=context.getBean(JdbcTemplate.class);
        String node=UUID.randomUUID().toString(),other=UUID.randomUUID().toString();
        long lower=9_500_000_001L,higher=lower+1,rolledBack=higher+1;
        try {
            insert(jdbc,higher);
            var first=journal.pending(node,higher).orElseThrow();
            journal.acknowledge(node,first);journal.acknowledge(node,first);
            assertTrue(journal.pending(node,higher).isEmpty());
            assertEquals(first,journal.pending(other,higher).orElseThrow());
            // A lower ID appears only after another higher event was acknowledged. Do not skip it.
            insert(jdbc,lower);
            assertEquals(lower,journal.pending(node,lower).orElseThrow().id());
            journal.acknowledge(node,journal.pending(node,lower).orElseThrow());
            assertEquals(2,jdbc.queryForObject("select count(*) from client_owner_transfer_receipt where node_id=?",Integer.class,node));
            assertEquals(0,jdbc.queryForObject("select count(*) from client_owner_transfer_receipt where node_id=?",Integer.class,other));
            new TransactionTemplate(context.getBean(PlatformTransactionManager.class)).executeWithoutResult(status -> {
                insert(jdbc,rolledBack);status.setRollbackOnly();
            });
            assertTrue(journal.pending(node,rolledBack).isEmpty());
        } finally {
            jdbc.update("delete from client_owner_transfer_receipt where event_id in (?,?,?)",lower,higher,rolledBack);
            jdbc.update("delete from client_owner_transfer_audit where id in (?,?,?)",lower,higher,rolledBack);
        }
    }
    private static void insert(JdbcTemplate jdbc,long id) {
        jdbc.update("insert into client_owner_transfer_audit(id,tenant_id,occurred_at,actor,scope,path_id,target_username,detail_json) values (?,'journal-provider','2026-10-16T00:00:00Z','fixture','credential-group',1,'Bob','{\"affectedClientIds\":[]}')",id);
    }
}
