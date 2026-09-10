package com.theshuai.specusclient.peer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.theshuai.common.peeregress.Ipv4Cidr;
import com.theshuai.common.peeregress.PeerEgressAuthorization;
import com.theshuai.common.peeregress.PeerEgressCodes;
import com.theshuai.common.peeregress.PeerEgressPolicy;
import com.theshuai.specusclient.peer.PeerEgressFlowTable.Flow;
import com.theshuai.specusclient.peer.PeerEgressFlowTable.Key;
import com.theshuai.specusclient.peer.PeerEgressFlowTable.Revocation;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The flow table is what makes a socket legitimate: it holds the quota a policy grants and the
 * record that lets a returning packet be matched to a flow this node actually opened.
 *
 * <p>No shared vector here, unlike the segment and frame layers. Most of this is local resource
 * bookkeeping, where two runtimes disagreeing produces no interop failure. The parts that are
 * observable to a peer -- which flows a purge closes, and which reason a revocation carries -- run
 * through the judgment layer, which the authorization vector already drives in all three runtimes.
 */
class PeerEgressFlowTableTests {

    private static final int TCP = PeerEgressSegment.IPV4_PROTOCOL_TCP;
    private static final int UDP = PeerEgressDatagram.IPV4_PROTOCOL_UDP;
    private static final long EPOCH = 1_800_000_000_000L;

    private static int address(String dotted) {
        Integer value = Ipv4Cidr.parseAddress(dotted);
        assertNotNull(value, dotted + " did not parse");
        return value;
    }

    private static Key key(int protocol, String consumerIp, int consumerPort, String remoteIp, int remotePort) {
        return new Key(protocol, address(consumerIp), consumerPort, address(remoteIp), remotePort);
    }

    private static PeerEgressPolicy policy(String... destinations) {
        PeerEgressPolicy policy = new PeerEgressPolicy();
        policy.setEnabled(true);
        policy.setScope(PeerEgressPolicy.SCOPE_PUBLIC);
        policy.setAllowedConsumerClientIds(List.of(7L, 9L));
        List<PeerEgressPolicy.PeerEgressDestinationRule> rules = new ArrayList<>();
        for (String cidr : destinations) {
            PeerEgressPolicy.PeerEgressDestinationRule rule =
                    new PeerEgressPolicy.PeerEgressDestinationRule();
            rule.setCidr(cidr);
            rule.setProtocols(List.of("tcp", "udp"));
            // An empty portRanges denies every port, so a rule meant to allow traffic says so.
            rule.setPortRanges(List.of(List.of(1, 65535)));
            rules.add(rule);
        }
        policy.setDestinationRules(rules);
        return policy;
    }

    /** A quota that counted TCP and UDP separately would let a consumer double its allowance. */
    @Test
    void countsFeedTheLimitChecksAcrossBothProtocols() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        table.open(key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
        table.open(key(UDP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
        table.open(key(UDP, "100.96.0.2", 51000, "203.0.113.53", 53), 9, EPOCH);

        assertEquals(2, table.countFor(7));
        assertEquals(3, table.size());
        assertEquals(0, table.countFor(11), "an unknown consumer inherited a count");
    }

    /**
     * Two datagrams leaving one consumer port for different destinations are separate sessions.
     * Keying on the source port alone would put the second destination's replies on the first's
     * socket.
     */
    @Test
    void destinationsSharingASourcePortAreSeparateFlows() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        assertNotNull(table.open(key(UDP, "100.96.0.1", 51000, "203.0.113.53", 53), 7, EPOCH));
        assertNotNull(table.open(key(UDP, "100.96.0.1", 51000, "198.51.100.53", 53), 7, EPOCH));
        assertEquals(2, table.size());
    }

    /** A retransmitted SYN is ordinary traffic. Reporting it as new would charge the quota twice. */
    @Test
    void reopeningReturnsNullAndChargesTheQuotaOnce() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        Key flowKey = key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443);
        assertNotNull(table.open(flowKey, 7, EPOCH));
        assertNull(table.open(flowKey, 7, EPOCH + 1000), "a repeated open was reported as new");
        assertEquals(1, table.countFor(7));
        assertEquals(EPOCH + 1000, table.lookup(flowKey).lastSeenMs, "activity was not refreshed");
    }

    /** Nothing in UDP says a session ended, so the idle timer is the only thing that ends one. */
    @Test
    void idleFlowsExpireAndReleaseTheirQuota() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(30_000);
        Key idle = key(UDP, "100.96.0.1", 51000, "203.0.113.53", 53);
        Key busy = key(UDP, "100.96.0.1", 51001, "203.0.113.53", 53);
        table.open(idle, 7, EPOCH);
        table.open(busy, 7, EPOCH);

        assertTrue(table.expire(EPOCH + 20_000).isEmpty(), "reaped before the timeout elapsed");

        table.touch(busy, EPOCH + 25_000);
        List<Flow> reaped = table.expire(EPOCH + 40_000);
        assertEquals(1, reaped.size());
        assertEquals(idle, reaped.get(0).key);
        assertEquals(1, table.countFor(7), "the expired flow did not release its quota slot");
    }

    /** A revoked consumer must stop being forwarded now, not when it next opens something. */
    @Test
    void revokingOneConsumerLeavesTheOthersAlone() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        table.open(key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
        table.open(key(TCP, "100.96.0.1", 40001, "203.0.113.11", 443), 7, EPOCH);
        Key survivor = key(TCP, "100.96.0.2", 40000, "203.0.113.12", 443);
        table.open(survivor, 9, EPOCH);

        assertEquals(2, table.revokeConsumer(7).size());
        assertEquals(1, table.size());
        assertNotNull(table.lookup(survivor), "another consumer's flow was closed");
    }

    /**
     * A purge speaks for its sender's flows. Acting on it for everyone would let any consumer tear
     * down every other consumer's traffic with one message.
     */
    @Test
    void purgeIsScopedToItsSender() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        table.open(key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
        Key otherConsumer = key(TCP, "100.96.0.2", 40000, "203.0.113.10", 443);
        table.open(otherConsumer, 9, EPOCH);

        assertEquals(1, table.purgeDestinations(7, List.of("203.0.113.0/24")).size());
        assertNotNull(table.lookup(otherConsumer), "one consumer's purge closed another's flow");
    }

    /** Treating an unreadable prefix as matching everything would turn one bad message into an outage. */
    @Test
    void purgeIgnoresUnparseablePrefixes() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        table.open(key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);

        assertTrue(table.purgeDestinations(7, List.of("not-a-cidr", "203.0.113.1/24")).isEmpty());
        assertEquals(1, table.size(), "a malformed purge closed a flow");
    }

    /**
     * One policy push can close flows for different reasons at once. A single code for the batch
     * would tell a consumer its flow died of something that did not happen to it.
     */
    @Test
    void reauthorizeReportsEachFlowsOwnReason() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        Key outsideRule = key(TCP, "100.96.0.1", 40000, "198.51.100.10", 443);
        Key deniedConsumer = key(TCP, "100.96.0.2", 40000, "203.0.113.10", 443);
        Key kept = key(TCP, "100.96.0.1", 40001, "203.0.113.10", 443);
        table.open(outsideRule, 7, EPOCH);
        table.open(deniedConsumer, 9, EPOCH);
        table.open(kept, 7, EPOCH);

        PeerEgressPolicy narrowed = policy("203.0.113.0/24");
        narrowed.setAllowedConsumerClientIds(List.of(7L));

        List<Revocation> revoked = table.reauthorize(
                narrowed, consumer -> true, PeerEgressAuthorization.Context.defaults(), List.of());

        assertEquals(2, revoked.size(), "revoked " + revoked.size());
        for (Revocation entry : revoked) {
            if (entry.flow().key.equals(outsideRule)) {
                assertEquals(PeerEgressCodes.DEST_DENIED, entry.code());
            } else {
                assertEquals(PeerEgressCodes.CONSUMER_DENIED, entry.code());
            }
        }
        assertNotNull(table.lookup(kept), "a flow the policy still allows was closed");
    }

    /**
     * Lowering a quota should stop the next flow, not pick live ones to kill. A limit breach is not
     * a permission a running flow lost.
     */
    @Test
    void reauthorizeDoesNotEnforceLoweredLimits() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        table.open(key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
        table.open(key(TCP, "100.96.0.1", 40001, "203.0.113.10", 443), 7, EPOCH);

        PeerEgressPolicy narrowed = policy("203.0.113.0/24");
        narrowed.getLimits().setMaxConcurrentFlows(1);
        narrowed.getLimits().setMaxFlowsPerConsumer(1);

        assertTrue(
                table.reauthorize(narrowed, consumer -> true,
                        PeerEgressAuthorization.Context.defaults(), List.of()).isEmpty(),
                "a lowered quota killed running flows");
    }

    /**
     * Without this a peer could hand the egress a packet carrying any source address it liked and
     * have it relayed into the mesh as though the egress had fetched it.
     */
    @Test
    void returnPathRequiresAnOpenFlow() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        Key flowKey = key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443);
        table.open(flowKey, 7, EPOCH);

        assertTrue(table.hasReturnPath(flowKey));
        assertFalse(table.hasReturnPath(key(TCP, "100.96.0.1", 40000, "198.51.100.10", 443)),
                "a packet from an address this node never contacted was accepted");
        table.close(flowKey);
        assertFalse(table.hasReturnPath(flowKey), "a closed flow still admitted return traffic");
    }

    @Test
    void drainReleasesEverything() {
        PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
        table.open(key(TCP, "100.96.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
        table.open(key(UDP, "100.96.0.2", 51000, "203.0.113.53", 53), 9, EPOCH);

        assertEquals(2, table.drain().size());
        assertEquals(0, table.size());
        assertEquals(0, table.countFor(7));
        assertEquals(0, table.countFor(9));
    }

    /**
     * Every reap emits one record per closed flow. Map order would make those records differ run to
     * run, and addresses compare unsigned so 10.x does not sort above 200.x.
     */
    @Test
    void reapsInAStableOrder() {
        List<Key> first = null;
        for (int attempt = 0; attempt < 8; attempt++) {
            PeerEgressFlowTable table = new PeerEgressFlowTable(60_000);
            table.open(key(TCP, "200.0.113.1", 40000, "203.0.113.10", 443), 7, EPOCH);
            table.open(key(TCP, "10.0.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);
            table.open(key(UDP, "10.0.0.1", 40000, "203.0.113.10", 443), 7, EPOCH);

            List<Key> order = new ArrayList<>();
            for (Flow flow : table.drain()) {
                order.add(flow.key);
            }
            if (first == null) {
                first = order;
                continue;
            }
            assertEquals(first, order, "attempt " + attempt + " produced a different order");
        }
        assertNotNull(first);
        assertEquals(address("10.0.0.1"), first.get(0).consumerIp(),
                "addresses were compared as signed");
        assertEquals(UDP, first.get(2).protocol(), "TCP did not sort before UDP");
    }
}
