package com.theshuai.common.peeregress;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.util.Collections;
import java.util.Map;
import java.util.TreeMap;

/**
 * The {@code egress-report} an egress sends the server, as a client writes it.
 *
 * <p>Running totals, the numbers of the egress section of the local status, not counts for an
 * interval: the server keeps only the latest report of each egress and shows it as it stands. The
 * body carries nothing else. The server binds the reporter from the authenticated control
 * connection and refuses a report naming any {@code sourceClient*}, {@code targetClient*},
 * {@code sessionId} or {@code token}, even as {@code null}; nor does it name a destination, a
 * domain or any request content. See {@code protocol/spec/peer-egress.md} ({@code egress-report});
 * shared vector: {@code protocol/test-vectors/peer-egress-report-v1.json}.
 *
 * @param revision      the wall clock in milliseconds, kept strictly increasing by the sender
 * @param activeFlows   the flows open now, the status's {@code flows}
 * @param totalFlows    the flows opened since the egress process started
 * @param rejectedFlows refusals per result code since the egress process started, the status's
 *                      {@code refused}; a code with no refusals is not listed
 * @param bytesIn       bytes read from destinations
 * @param bytesOut      bytes written to destinations
 */
public record PeerEgressReportMessage(long revision, long activeFlows, long totalFlows,
        Map<String, Long> rejectedFlows, long bytesIn, long bytesOut) {

    public static final String TYPE = "egress-report";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public PeerEgressReportMessage {
        // Sorted, so the same counts encode the same way, and without zero counts: a row of zeros
        // would bury the code that actually refused something.
        Map<String, Long> listed = new TreeMap<>();
        if (rejectedFlows != null) {
            rejectedFlows.forEach((code, count) -> {
                if (code != null && count != null && count > 0) {
                    listed.put(code, count);
                }
            });
        }
        rejectedFlows = Collections.unmodifiableMap(listed);
    }

    /** The message body, with no whitespace and the keys in the spec's order. */
    public String encode() {
        ObjectNode body = MAPPER.createObjectNode();
        body.put("type", TYPE);
        body.put("revision", revision);
        body.put("activeFlows", activeFlows);
        body.put("totalFlows", totalFlows);
        ObjectNode rejected = body.putObject("rejectedFlows");
        rejectedFlows.forEach(rejected::put);
        body.put("bytesIn", bytesIn);
        body.put("bytesOut", bytesOut);
        try {
            return MAPPER.writeValueAsString(body);
        } catch (Exception unwritable) {
            // A tree of strings and numbers always serialises.
            throw new IllegalStateException("egress-report did not encode", unwritable);
        }
    }
}
