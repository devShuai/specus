package com.theshuai.common.handler;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RecentStreamTombstonesTests {

    @Test
    void shouldEvictOldestIdAtCapacity() {
        RecentStreamTombstones tombstones = new RecentStreamTombstones(2);

        tombstones.add(10);
        tombstones.add(11);
        tombstones.add(12);

        assertFalse(tombstones.contains(10));
        assertTrue(tombstones.contains(11));
        assertTrue(tombstones.contains(12));
        assertEquals(2, tombstones.size());
    }

    @Test
    void shouldRefreshAnExistingIdWithoutGrowing() {
        RecentStreamTombstones tombstones = new RecentStreamTombstones(2);

        tombstones.add(10);
        tombstones.add(11);
        tombstones.add(10);
        tombstones.add(12);

        assertTrue(tombstones.contains(10));
        assertFalse(tombstones.contains(11));
        assertTrue(tombstones.contains(12));
        assertEquals(2, tombstones.size());
    }

    @Test
    void shouldRejectNonPositiveCapacity() {
        assertThrows(IllegalArgumentException.class, () -> new RecentStreamTombstones(0));
    }
}
