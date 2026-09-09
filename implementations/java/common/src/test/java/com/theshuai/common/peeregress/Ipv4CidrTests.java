package com.theshuai.common.peeregress;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The address parser sits in front of every access decision, so its rejections matter as much as
 * its accepts. Anything it accepts loosely here is a difference the other runtimes can disagree on.
 */
class Ipv4CidrTests {
    @Test
    void acceptsCanonicalAddresses() {
        assertEquals(0, Ipv4Cidr.parseAddress("0.0.0.0"));
        assertEquals(-1, Ipv4Cidr.parseAddress("255.255.255.255"));
        assertEquals("203.0.113.200", Ipv4Cidr.format(Ipv4Cidr.parseAddress("203.0.113.200")));
    }

    @Test
    void rejectsLeadingZeroOctets() {
        // Runtimes disagree on 010: decimal ten or octal eight. A rule must not be able to mean
        // different things in different implementations.
        assertNull(Ipv4Cidr.parseAddress("010.1.1.1"));
        assertNull(Ipv4Cidr.parseAddress("1.02.3.4"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3.00"));
        assertNotNull(Ipv4Cidr.parseAddress("0.1.2.3"));
    }

    @Test
    void rejectsMalformedAddresses() {
        assertNull(Ipv4Cidr.parseAddress(""));
        assertNull(Ipv4Cidr.parseAddress("1.2.3"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3.4.5"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3."));
        assertNull(Ipv4Cidr.parseAddress(".1.2.3"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3.256"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3.4444"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3.-4"));
        assertNull(Ipv4Cidr.parseAddress("1.2.3.4 "));
        assertNull(Ipv4Cidr.parseAddress("::1"));
    }

    @Test
    void rejectsPrefixesWithHostBitsSet() {
        assertNotNull(Ipv4Cidr.parse("203.0.113.0/24"));
        assertNull(Ipv4Cidr.parse("203.0.113.1/24"));
        assertNull(Ipv4Cidr.parse("203.0.113.0/33"));
        assertNull(Ipv4Cidr.parse("203.0.113.0/08"));
        assertNull(Ipv4Cidr.parse("203.0.113.0/"));
    }

    @Test
    void barAddressBecomesAHostPrefix() {
        Ipv4Cidr cidr = Ipv4Cidr.parse("203.0.113.9");
        assertNotNull(cidr);
        assertEquals(32, cidr.prefixLength());
        assertEquals("203.0.113.9/32", cidr.toString());
    }

    @Test
    void containsAndOverlapsFollowPrefixLength() {
        Ipv4Cidr slash24 = Ipv4Cidr.parse("203.0.113.0/24");
        Ipv4Cidr slash25 = Ipv4Cidr.parse("203.0.113.128/25");
        assertTrue(slash24.contains(Ipv4Cidr.parseAddress("203.0.113.255")));
        assertFalse(slash25.contains(Ipv4Cidr.parseAddress("203.0.113.127")));
        assertTrue(slash24.overlaps(slash25));
        assertTrue(slash25.overlaps(slash24));
        assertFalse(slash24.overlaps(Ipv4Cidr.parse("198.51.100.0/24")));

        Ipv4Cidr everything = Ipv4Cidr.parse("0.0.0.0/0");
        assertNotNull(everything);
        assertTrue(everything.contains(Ipv4Cidr.parseAddress("8.8.8.8")));
    }
}
