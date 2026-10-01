package com.theshuai.specusclient.peer;

import com.theshuai.common.peeregress.PeerEgressDns;
import com.theshuai.common.peeregress.PeerEgressRule;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The DNS responder's wire format (protocol/spec/peer-egress-dns.md, section three, "messages"):
 * what one query message gets -- dropped, forwarded untouched, or answered with bytes built here.
 *
 * <p>Only one kind of message is interpreted: a query (QR clear, opcode QUERY) with exactly one
 * question of class IN whose labels are printable ASCII without a dot. Anything else a header can
 * be read from is the upstream's to answer, because its answer is at least a real one; a response,
 * or fewer than twelve bytes, is dropped; a header whose question cannot be read is FORMERR.
 *
 * <p>Built answers copy the ID, opcode, RD and CD, set QR and RA, clear AA, TC and AD, and copy the
 * question byte for byte, keeping the application's case (some resolvers randomise it against
 * poisoning). A and PTR records name the question through the pointer {@code C00C}, with a TTL of
 * one second: a mapping lives by use, not by TTL. A query carrying OPT gets an OPT back, payload
 * 1232 and nothing else set, or resolvers such as systemd-resolved stop sending EDNS through us.
 *
 * <p>Shared cases: the {@code wire} section of {@code peer-egress-dns-v1.json}, replayed byte for
 * byte.
 */
final class PeerEgressDnsMessage {

    static final int TYPE_A = 1;
    static final int TYPE_PTR = 12;
    static final int TYPE_AAAA = 28;
    static final int TYPE_OPT = 41;
    static final int TYPE_SVCB = 64;
    static final int TYPE_HTTPS = 65;
    static final int TYPE_ANY = 255;
    static final int CLASS_IN = 1;

    static final int RCODE_NOERROR = 0;
    static final int RCODE_FORMERR = 1;
    static final int RCODE_SERVFAIL = 2;
    static final int RCODE_NXDOMAIN = 3;

    /** The TTL of every record built here. */
    static final int ANSWER_TTL = 1;
    /** The UDP payload size the OPT of a built answer advertises. */
    static final int EDNS_PAYLOAD = 1232;

    static final int HEADER_BYTES = 12;
    private static final String IN_ADDR_ARPA = ".in-addr.arpa";
    /** How many compression pointers a name may follow before it is taken to loop. */
    private static final int MAX_POINTER_HOPS = 16;

    private PeerEgressDnsMessage() {
    }

    /** What happens to one query message. */
    enum Kind {
        /** Not answered at all. */
        DROP,
        /** Sent to the upstreams unchanged, their reply returned unchanged. */
        FORWARD,
        /** Answered with {@link Result#response()}. */
        ANSWER
    }

    /**
     * @param exhausted the answer is SERVFAIL because the pool had no address for a new name
     */
    record Result(Kind kind, byte[] response, boolean exhausted) {
        static final Result DROP = new Result(Kind.DROP, null, false);
        static final Result FORWARD = new Result(Kind.FORWARD, null, false);

        static Result answer(byte[] response) {
            return new Result(Kind.ANSWER, response, false);
        }
    }

    /** The labels of a name as they appeared, and the position after it in the message. */
    private record Name(List<byte[]> labels, int end) {
    }

    /**
     * Decides one query and builds the answer when it is ours.
     *
     * @param rules      the consumer's rules; a name is claimed by the domain rule phase two selects
     * @param meshCidr   the mesh network, for validating the rules
     * @param pool       the fake-IP pool: fake answers are allocated from it, reverse names read
     *                   from it without refreshing the mapping
     */
    static Result respond(List<PeerEgressRule> rules, String meshCidr, PeerEgressFakeIpPool pool,
            byte[] message, long nowMs) {
        if (message == null || message.length < HEADER_BYTES) {
            return Result.DROP;
        }
        int flags = u16(message, 2);
        if ((flags & 0x8000) != 0) {
            return Result.DROP;
        }
        if (((flags >>> 11) & 0x0F) != 0 || u16(message, 4) != 1) {
            return Result.FORWARD;
        }
        Name name = readName(message, HEADER_BYTES, false);
        if (name == null || name.end() + 4 > message.length) {
            return Result.answer(reply(message, RCODE_FORMERR, new byte[0], new byte[0], 0, false));
        }
        int qtype = u16(message, name.end());
        int qclass = u16(message, name.end() + 2);
        byte[] question = java.util.Arrays.copyOfRange(message, HEADER_BYTES, name.end() + 4);
        boolean edns = hasOpt(message, name.end() + 4,
                u16(message, 6) + u16(message, 8) + u16(message, 10));
        String text = usableName(name.labels());
        if (qclass != CLASS_IN || text == null) {
            return Result.FORWARD;
        }

        if (text.endsWith(IN_ADDR_ARPA)) {
            return reverse(message, question, qtype, edns, text, pool);
        }

        Integer index = PeerEgressDns.selectDomainRule(rules, text, meshCidr, pool.cidr());
        if (index == null || PeerEgressRule.ACTION_DIRECT.equals(action(rules.get(index)))) {
            return Result.FORWARD;
        }
        if (qtype == TYPE_AAAA || qtype == TYPE_HTTPS || qtype == TYPE_SVCB || qtype == TYPE_ANY) {
            // NODATA: an address or endpoint that bypasses the fake one is exactly what the rule is
            // there to keep from the application. ANY would carry the real addresses as surely.
            return Result.answer(reply(message, RCODE_NOERROR, question, new byte[0], 0, edns));
        }
        if (qtype != TYPE_A) {
            return Result.FORWARD;
        }
        PeerEgressFakeIpPool.Answer allocated = pool.query(text, nowMs);
        if (allocated.exhausted()) {
            return new Result(Kind.ANSWER, reply(message, RCODE_SERVFAIL, question, new byte[0], 0, edns), true);
        }
        byte[] record = record(TYPE_A, new byte[] {
                (byte) (allocated.address() >>> 24), (byte) (allocated.address() >>> 16),
                (byte) (allocated.address() >>> 8), (byte) (int) allocated.address()});
        return Result.answer(reply(message, RCODE_NOERROR, question, record, 1, edns));
    }

    /**
     * A reverse name in the pool is answered from the mapping, which the lookup does not refresh;
     * one outside the pool, or one that is not four decimal octets without leading zeros, is the
     * upstream's.
     */
    private static Result reverse(byte[] message, byte[] question, int qtype, boolean edns, String text,
            PeerEgressFakeIpPool pool) {
        String[] octets = text.substring(0, text.length() - IN_ADDR_ARPA.length()).split("\\.", -1);
        if (octets.length != 4) {
            return Result.FORWARD;
        }
        int address = 0;
        for (int index = 3; index >= 0; index--) {
            String octet = octets[index];
            // Only the spelling a resolver writes: decimal, no leading zero. Any other is some other
            // name, and the upstream's to answer.
            if (octet.isEmpty() || octet.length() > 3 || !octet.chars().allMatch(c -> c >= '0' && c <= '9')
                    || (octet.length() > 1 && octet.charAt(0) == '0')) {
                return Result.FORWARD;
            }
            int value = Integer.parseInt(octet);
            if (value > 255) {
                return Result.FORWARD;
            }
            address = (address << 8) | value;
        }
        if (!pool.contains(address)) {
            return Result.FORWARD;
        }
        String mapped = pool.nameOf(address);
        if (mapped == null) {
            return Result.answer(reply(message, RCODE_NXDOMAIN, question, new byte[0], 0, edns));
        }
        if (qtype != TYPE_PTR) {
            return Result.answer(reply(message, RCODE_NOERROR, question, new byte[0], 0, edns));
        }
        return Result.answer(reply(message, RCODE_NOERROR, question, record(TYPE_PTR, encodeName(mapped)), 1, edns));
    }

    /**
     * SERVFAIL for a forwarded query that got no reply, built by the same rules as any answer. A
     * query with exactly one readable question gets it copied, and an OPT when it carried one, so
     * a resolver matching replies by question still takes it. A forwarded query need not have one
     * -- no question, several, a pointer in it -- and then the header alone goes back, with a
     * question count of zero.
     */
    static byte[] servfail(byte[] query) {
        if (query == null || query.length < HEADER_BYTES) {
            return null;
        }
        Name name = u16(query, 4) == 1 ? readName(query, HEADER_BYTES, false) : null;
        if (name == null || name.end() + 4 > query.length) {
            return reply(query, RCODE_SERVFAIL, new byte[0], new byte[0], 0, false);
        }
        byte[] question = java.util.Arrays.copyOfRange(query, HEADER_BYTES, name.end() + 4);
        boolean edns = hasOpt(query, name.end() + 4, u16(query, 6) + u16(query, 8) + u16(query, 10));
        return reply(query, RCODE_SERVFAIL, question, new byte[0], 0, edns);
    }

    /** The two bytes a reply's ID is compared on. */
    static int id(byte[] message) {
        return message == null || message.length < 2 ? -1 : u16(message, 0);
    }

    private static byte[] reply(byte[] query, int rcode, byte[] question, byte[] answer, int answers, boolean edns) {
        ByteArrayOutputStream out = header(query, rcode, question.length > 0 ? 1 : 0, answers, edns);
        out.writeBytes(question);
        out.writeBytes(answer);
        if (edns) {
            out.writeBytes(opt());
        }
        return out.toByteArray();
    }

    /** ID, opcode, RD and CD copied; QR and RA set; AA, TC and AD clear. */
    private static ByteArrayOutputStream header(byte[] query, int rcode, int questions, int answers, boolean edns) {
        int flags = u16(query, 2);
        int out = 0x8000 | (flags & 0x7800) | (flags & 0x0100) | 0x0080 | (flags & 0x0010) | rcode;
        ByteArrayOutputStream buffer = new ByteArrayOutputStream(128);
        writeU16(buffer, u16(query, 0));
        writeU16(buffer, out);
        writeU16(buffer, questions);
        writeU16(buffer, answers);
        writeU16(buffer, 0);
        writeU16(buffer, edns ? 1 : 0);
        return buffer;
    }

    /** OPT: the root name, type 41, the payload as its class, and no extended RCODE, version or DO. */
    private static byte[] opt() {
        return new byte[] {0, 0, (byte) TYPE_OPT, (byte) (EDNS_PAYLOAD >>> 8), (byte) EDNS_PAYLOAD, 0, 0, 0, 0, 0, 0};
    }

    /** One IN record naming the question through the pointer C00C, TTL one second. */
    private static byte[] record(int type, byte[] rdata) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(16 + rdata.length);
        writeU16(out, 0xC00C);
        writeU16(out, type);
        writeU16(out, CLASS_IN);
        writeU16(out, 0);
        writeU16(out, ANSWER_TTL);
        writeU16(out, rdata.length);
        out.writeBytes(rdata);
        return out.toByteArray();
    }

    /** A name as labels, without compression. The name is one a rule matched, so ASCII. */
    static byte[] encodeName(String name) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(name.length() + 2);
        String trimmed = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        for (String label : trimmed.split("\\.")) {
            byte[] raw = label.getBytes(StandardCharsets.US_ASCII);
            out.write(raw.length);
            out.writeBytes(raw);
        }
        out.write(0);
        return out.toByteArray();
    }

    /**
     * The labels of a name starting at pos, or null when it cannot be read: running past the end,
     * an extended label type, a pointer where none is allowed, or a pointer chain that loops.
     */
    private static Name readName(byte[] message, int start, boolean allowPointers) {
        List<byte[]> labels = new ArrayList<>();
        int pos = start;
        int end = -1;
        int hops = 0;
        while (true) {
            if (pos >= message.length) {
                return null;
            }
            int length = message[pos] & 0xFF;
            if (length == 0) {
                return new Name(labels, end < 0 ? pos + 1 : end);
            }
            if ((length & 0xC0) == 0xC0) {
                if (!allowPointers || pos + 1 >= message.length || hops > MAX_POINTER_HOPS) {
                    return null;
                }
                if (end < 0) {
                    end = pos + 2;
                }
                pos = ((length & 0x3F) << 8) | (message[pos + 1] & 0xFF);
                hops++;
                continue;
            }
            if ((length & 0xC0) != 0 || pos + 1 + length > message.length) {
                return null;
            }
            labels.add(java.util.Arrays.copyOfRange(message, pos + 1, pos + 1 + length));
            pos += 1 + length;
        }
    }

    /**
     * Whether one of the records from pos on is an OPT. A record that cannot be read ends the
     * search, and the query is answered as one without EDNS.
     */
    private static boolean hasOpt(byte[] message, int start, int count) {
        int pos = start;
        for (int index = 0; index < count; index++) {
            Name name = readName(message, pos, true);
            if (name == null || name.end() + 10 > message.length) {
                return false;
            }
            pos = name.end();
            if (u16(message, pos) == TYPE_OPT) {
                return true;
            }
            pos += 10 + u16(message, pos + 8);
        }
        return false;
    }

    /**
     * The name as rules see it, or null when it is not one they could match: no labels, or a label
     * with a dot or a byte outside printable ASCII. Such a query is forwarded, never answered.
     */
    private static String usableName(List<byte[]> labels) {
        if (labels.isEmpty()) {
            return null;
        }
        StringBuilder text = new StringBuilder();
        for (byte[] label : labels) {
            for (byte value : label) {
                int b = value & 0xFF;
                if (b < 0x21 || b > 0x7E || b == '.') {
                    return null;
                }
            }
            if (text.length() > 0) {
                text.append('.');
            }
            text.append(new String(label, StandardCharsets.US_ASCII).toLowerCase(Locale.ROOT));
        }
        return text.toString();
    }

    private static String action(PeerEgressRule rule) {
        return rule.getAction() == null ? "" : rule.getAction().trim();
    }

    static int u16(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
    }
}
