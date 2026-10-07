package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.service.WorkbenchItemWriter;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.theshuai.specusserver.management.model.ManagementWorkbenchItem.FAVORITE;
import static com.theshuai.specusserver.management.model.ManagementWorkbenchItem.RECENT;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Two instances adding the same reference at once (protocol/spec/service-workbench.md section 8):
 * the write that finds the row already there must not fail on the primary key. A favourite keeps
 * its first addedAt; a recent open keeps the later time, whichever instance wrote last.
 */
class WorkbenchConcurrentWriteTests extends WorkbenchHttpTestSupport {

    @Autowired WorkbenchItemWriter writer;

    @Test
    void aRowWrittenMeanwhileByAnotherInstanceIsKeptNotAConflict() {
        long base = BASE_TIME.toEpochMilli();
        writer.addFavorite("t1", "alice", "http-route", 11L, base + 100L);
        writer.addFavorite("t1", "alice", "http-route", 11L, base + 200L);
        writer.recordRecent("t1", "alice", "http-route", 11L, base + 300L);
        writer.recordRecent("t1", "alice", "http-route", 11L, base + 250L);
        writer.recordRecent("t1", "alice", "http-route", 11L, base + 400L);

        assertThat(rows()).containsExactly(
                new Row("t1", "alice", FAVORITE, "http-route", 11L, 100L),
                new Row("t1", "alice", RECENT, "http-route", 11L, 400L));
    }
}
