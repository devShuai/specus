using System.Buffers.Binary;
using System.Text;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>What the responder does with one DNS message.</summary>
internal enum PeerEgressDnsResult
{
    /// <summary>Not a query at all: a response, or shorter than a header. Nothing is sent back.</summary>
    Drop,

    /// <summary>Not for this responder to answer: sent to the upstreams byte for byte.</summary>
    Forward,

    /// <summary>Answered here, with <see cref="PeerEgressDnsDecision.Response"/>.</summary>
    Answer,
}

/// <param name="Response">The answer's bytes, for <see cref="PeerEgressDnsResult.Answer"/>.</param>
/// <param name="Exhausted">The answer is SERVFAIL because the fake-IP pool had no address to give.</param>
internal readonly record struct PeerEgressDnsDecision(PeerEgressDnsResult Result, byte[]? Response = null, bool Exhausted = false);

/// <summary>
/// The responder's wire format (protocol/spec/peer-egress-dns.md, section three; shared vector
/// <c>wire</c> in <c>peer-egress-dns-v1.json</c>): which messages it interprets, and the exact bytes
/// of every answer it builds itself.
/// </summary>
/// <remarks>
/// It interprets exactly one kind of message -- a standard query with one IN question whose labels
/// are printable ASCII -- and hands everything else it does not drop to the upstreams untouched. An
/// upstream's answer to something unusual is at least a real answer; one made up here would not be.
///
/// <para>The answers it builds copy the question section byte for byte, keeping the application's
/// letter case (some resolvers randomise it against spoofing), point the record's name at it with
/// <c>C00C</c>, give every record a one-second TTL, and echo EDNS with a 1232-byte payload when the
/// query carried it: without that, a resolver such as systemd-resolved marks this upstream as not
/// speaking EDNS and strips it from the queries it forwards through here as well.</para>
/// </remarks>
internal static class PeerEgressDnsWire
{
    internal const int AnswerTtlSeconds = 1;
    internal const int EdnsPayload = 1232;
    internal const int HeaderBytes = 12;

    private const ushort TypeA = 1;
    private const ushort TypePtr = 12;
    private const ushort TypeAaaa = 28;
    private const ushort TypeOpt = 41;
    private const ushort TypeSvcb = 64;
    private const ushort TypeHttps = 65;
    private const ushort TypeAny = 255;
    private const ushort ClassIn = 1;

    private const int RcodeFormErr = 1;
    private const int RcodeServFail = 2;
    private const int RcodeNxDomain = 3;

    private const string InAddrArpa = ".in-addr.arpa";

    /// <summary>How far a name may chase compression pointers before it is taken as a loop.</summary>
    private const int MaxPointerHops = 16;

    private static readonly PeerEgressDnsDecision Dropped = new(PeerEgressDnsResult.Drop);
    private static readonly PeerEgressDnsDecision Forwarded = new(PeerEgressDnsResult.Forward);

    /// <summary>
    /// Decides one query message: drop it, forward it, or answer it here. A claimed name's A query
    /// takes an address from the pool; a reverse lookup inside the pool reads it without refreshing.
    /// </summary>
    public static PeerEgressDnsDecision Respond(byte[] message, IReadOnlyList<PeerEgressRule> rules, string? meshCidr,
        PeerEgressFakeIpPool pool, long nowMs)
    {
        if (message.Length < HeaderBytes)
        {
            return Dropped;
        }
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(2));
        if ((flags & 0x8000) != 0)
        {
            // A response, arriving where queries go: whatever it is, it is not ours to answer.
            return Dropped;
        }
        var questions = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(4));
        if (((flags >> 11) & 0x0F) != 0 || questions != 1)
        {
            return Forwarded;
        }
        if (!ReadName(message, HeaderBytes, allowPointers: false, out var labels, out var end) || end + 4 > message.Length)
        {
            // The header claims a question that is not there, or one that points elsewhere: a
            // query nothing downstream could read either.
            return new PeerEgressDnsDecision(PeerEgressDnsResult.Answer, Reply(message, RcodeFormErr, [], [], 0, false));
        }
        var type = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(end));
        var @class = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(end + 2));
        var question = message[HeaderBytes..(end + 4)];
        var edns = FindOpt(message, end + 4, RecordCount(message));
        var name = UsableName(labels);
        if (@class != ClassIn || name is null)
        {
            return Forwarded;
        }

        if (name.EndsWith(InAddrArpa, StringComparison.Ordinal))
        {
            return Reverse(message, name, type, question, edns, pool);
        }

        var index = PeerEgressRules.SelectDomainRule(rules, name, meshCidr, pool.Cidr);
        var action = index < 0 ? PeerEgressRules.ActionDirect : rules[index].Action?.Trim() ?? string.Empty;
        if (action == PeerEgressRules.ActionDirect)
        {
            // Not taken over: the application gets the real answer and address rules apply to it.
            return Forwarded;
        }
        if (type is TypeAaaa or TypeHttps or TypeSvcb or TypeAny)
        {
            // Any of these would hand the application an address or endpoint that bypasses the fake
            // one, so a claimed name has none of them.
            return Answer(Reply(message, 0, question, [], 0, edns));
        }
        if (type != TypeA)
        {
            return Forwarded;
        }
        var allocated = pool.Query(name, nowMs);
        if (allocated.Exhausted)
        {
            return new PeerEgressDnsDecision(PeerEgressDnsResult.Answer,
                Reply(message, RcodeServFail, question, [], 0, edns), Exhausted: true);
        }
        var record = new byte[16];
        WriteRecordHeader(record, TypeA, 4);
        BinaryPrimitives.WriteUInt32BigEndian(record.AsSpan(12), allocated.Address);
        return Answer(Reply(message, 0, question, record, 1, edns));
    }

    /// <summary>
    /// SERVFAIL for a query the upstreams could not answer. Built by the same rules as every other
    /// answer: the question copied when the query had one this responder can read, EDNS echoed when
    /// it could find it. A forwarded query can be one it does not interpret, and then the header is
    /// all that is answered.
    /// </summary>
    public static byte[] ServFail(byte[] message)
    {
        if (message.Length < HeaderBytes)
        {
            return [];
        }
        byte[] question = [];
        var edns = false;
        if (BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(4)) == 1
            && ReadName(message, HeaderBytes, allowPointers: false, out _, out var end)
            && end + 4 <= message.Length)
        {
            question = message[HeaderBytes..(end + 4)];
            edns = FindOpt(message, end + 4, RecordCount(message));
        }
        return Reply(message, RcodeServFail, question, [], 0, edns);
    }

    /// <summary>The message's ID, which a forwarded query's answer has to carry back.</summary>
    public static ushort Id(ReadOnlySpan<byte> message) =>
        message.Length >= 2 ? BinaryPrimitives.ReadUInt16BigEndian(message) : (ushort)0;

    /// <summary>
    /// A reverse lookup. Inside the pool it is answered from the mappings, which it does not
    /// refresh: asking which name an address stands for is not using it. Outside, it is forwarded.
    /// </summary>
    private static PeerEgressDnsDecision Reverse(byte[] message, string name, ushort type, byte[] question, bool edns,
        PeerEgressFakeIpPool pool)
    {
        var octets = name[..^InAddrArpa.Length].Split('.');
        if (octets.Length != 4)
        {
            return Forwarded;
        }
        uint address = 0;
        // Reversed: the first label is the address's last octet.
        for (var index = 3; index >= 0; index--)
        {
            var octet = octets[index];
            if (octet.Length is 0 or > 3 || !octet.All(char.IsAsciiDigit) || int.Parse(octet) > 255)
            {
                return Forwarded;
            }
            address = (address << 8) | (uint)int.Parse(octet);
        }
        if (!pool.Contains(address))
        {
            return Forwarded;
        }
        if (pool.NameFor(address) is not { } mapped)
        {
            return Answer(Reply(message, RcodeNxDomain, question, [], 0, edns));
        }
        if (type != TypePtr)
        {
            return Answer(Reply(message, 0, question, [], 0, edns));
        }
        var target = EncodeName(mapped);
        var record = new byte[12 + target.Length];
        WriteRecordHeader(record, TypePtr, target.Length);
        target.CopyTo(record.AsSpan(12));
        return Answer(Reply(message, 0, question, record, 1, edns));
    }

    private static PeerEgressDnsDecision Answer(byte[] response) => new(PeerEgressDnsResult.Answer, response);

    /// <summary>A record's fixed part: the name as a pointer to the question, IN, the TTL, the data length.</summary>
    private static void WriteRecordHeader(byte[] record, ushort type, int dataLength)
    {
        record[0] = 0xC0;
        record[1] = 0x0C;
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(2), type);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(4), ClassIn);
        BinaryPrimitives.WriteUInt32BigEndian(record.AsSpan(6), AnswerTtlSeconds);
        BinaryPrimitives.WriteUInt16BigEndian(record.AsSpan(10), (ushort)dataLength);
    }

    /// <summary>
    /// A response built from the query: ID, opcode, RD and CD copied; QR and RA set; AA, TC and AD
    /// clear.
    /// </summary>
    private static byte[] Reply(byte[] message, int rcode, byte[] question, byte[] answer, int answers, bool edns)
    {
        var flags = BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(2));
        var outFlags = 0x8000 | (flags & 0x7800) | (flags & 0x0100) | 0x0080 | (flags & 0x0010) | rcode;
        var response = new byte[HeaderBytes + question.Length + answer.Length + (edns ? 11 : 0)];
        response[0] = message[0];
        response[1] = message[1];
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2), (ushort)outFlags);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4), (ushort)(question.Length > 0 ? 1 : 0));
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6), (ushort)answers);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(10), (ushort)(edns ? 1 : 0));
        question.CopyTo(response.AsSpan(HeaderBytes));
        answer.CopyTo(response.AsSpan(HeaderBytes + question.Length));
        if (edns)
        {
            // OPT: the root name, the payload size in the class, and a zero TTL -- extended RCODE,
            // version and flags, DO included, all clear -- with no options.
            var opt = response.AsSpan(HeaderBytes + question.Length + answer.Length);
            BinaryPrimitives.WriteUInt16BigEndian(opt[1..], TypeOpt);
            BinaryPrimitives.WriteUInt16BigEndian(opt[3..], EdnsPayload);
        }
        return response;
    }

    private static int RecordCount(byte[] message) =>
        BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(6))
        + BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(8))
        + BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(10));

    /// <summary>
    /// The labels of a name and the position just after it; false when it cannot be read. A question
    /// name may not use compression pointers; the records after it may.
    /// </summary>
    private static bool ReadName(byte[] message, int position, bool allowPointers, out List<byte[]> labels, out int end)
    {
        labels = [];
        end = -1;
        var hops = 0;
        while (true)
        {
            if (position >= message.Length)
            {
                return false;
            }
            int length = message[position];
            if (length == 0)
            {
                if (end < 0)
                {
                    end = position + 1;
                }
                return true;
            }
            if ((length & 0xC0) == 0xC0)
            {
                if (!allowPointers || position + 1 >= message.Length || hops > MaxPointerHops)
                {
                    return false;
                }
                if (end < 0)
                {
                    end = position + 2;
                }
                position = ((length & 0x3F) << 8) | message[position + 1];
                hops++;
                continue;
            }
            if ((length & 0xC0) != 0 || position + 1 + length > message.Length)
            {
                return false;
            }
            labels.Add(message[(position + 1)..(position + 1 + length)]);
            position += 1 + length;
        }
    }

    /// <summary>
    /// Whether one of the records from a position is an OPT. A record that cannot be read ends the
    /// search, and the query is answered as one without EDNS.
    /// </summary>
    private static bool FindOpt(byte[] message, int position, int count)
    {
        for (var record = 0; record < count; record++)
        {
            if (!ReadName(message, position, allowPointers: true, out _, out var end) || end + 10 > message.Length)
            {
                return false;
            }
            if (BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(end)) == TypeOpt)
            {
                return true;
            }
            position = end + 10 + BinaryPrimitives.ReadUInt16BigEndian(message.AsSpan(end + 8));
        }
        return false;
    }

    /// <summary>
    /// The name as rules see it, lower case; null when it is not one they could match: empty, or a
    /// label holding a dot or a byte outside printable ASCII. Such a query is forwarded.
    /// </summary>
    private static string? UsableName(List<byte[]> labels)
    {
        if (labels.Count == 0)
        {
            return null;
        }
        var text = new StringBuilder();
        foreach (var label in labels)
        {
            if (text.Length > 0)
            {
                text.Append('.');
            }
            foreach (var value in label)
            {
                if (value is < 0x21 or > 0x7E or 0x2E)
                {
                    return null;
                }
                text.Append(value is >= (byte)'A' and <= (byte)'Z' ? (char)(value + 32) : (char)value);
            }
        }
        return text.ToString();
    }

    /// <summary>A name in wire form, uncompressed.</summary>
    private static byte[] EncodeName(string name)
    {
        var output = new List<byte>(name.Length + 2);
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            output.Add((byte)label.Length);
            output.AddRange(Encoding.ASCII.GetBytes(label));
        }
        output.Add(0);
        return [.. output];
    }
}
