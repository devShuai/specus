using System.Text;
using System.Text.Json;

namespace Specus.Protocol.PeerEgress;

/// <summary>
/// The <c>SPEG1</c> frame.
/// </summary>
/// <remarks>
/// SPEG1 is the third plaintext type carried inside an SPM2 frame, alongside a bare IPv4 packet and
/// an STMSG2 application message. Egress traffic gets its own type on purpose: relaxing the
/// existing bare-IPv4 checks to carry it would weaken the mesh path, so the two are separated the
/// moment the payload is decrypted.
///
/// <para>Wire format and rejection cases: <c>protocol/spec/peer-egress.md</c>, driven by
/// <c>protocol/test-vectors/peer-egress-frame-v1.json</c>.</para>
/// </remarks>
public static class PeerEgressFrame
{
    public const int HeaderBytes = 8;
    public const int TypeIpPacket = 1;
    public const int TypeControl = 2;

    /// <summary>
    /// bit0 is set by an egress device when it forwards while acting as a consumer itself. An
    /// egress that receives it refuses: there are no multi-hop egress chains.
    /// </summary>
    public const int FlagHop = 0x01;

    public const string ControlFlowReject = "flow-reject";
    public const string ControlFlowPurge = "flow-purge";

    /// <summary>
    /// Phase two: a consumer binds one of its fake addresses to the name a flow to it should reach
    /// (protocol/spec/peer-egress-dns.md).
    /// </summary>
    public const string ControlNameBind = "name-bind";

    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SPEG1");
    private const int Ipv4MinHeaderBytes = 20;
    private const int Ipv6HeaderBytes = 40;
    private const int ProtocolTcp = 6;
    private const int ProtocolUdp = 17;

    /// <summary>
    /// The parsed tuple of a type=1 body, filled only for that type. For an IPv6 body the addresses
    /// are in RFC 5952 form and <see cref="Protocol"/> is the next header.
    /// </summary>
    public sealed record Inner(
        string SourceIp,
        string DestinationIp,
        int Protocol,
        int SourcePort,
        int DestinationPort,
        bool Ipv6 = false)
    {
        public static Inner Empty { get; } = new("", "", 0, 0, 0);
    }

    /// <summary>One decoded frame, or the code it was refused with.</summary>
    public sealed record Decoded(int Type, bool Hop, byte[] Body, Inner Inner, string? Code)
    {
        public bool Accepted => Code is null;

        public static Decoded Refused(string code) => new(0, false, [], Inner.Empty, code);
    }

    /// <summary>
    /// Reports whether a decrypted payload carries the SPEG1 magic.
    /// </summary>
    /// <remarks>
    /// Only the magic is checked, so a frame that is addressed to the egress path but malformed is
    /// still routed here and rejected with its own code, rather than falling through to the
    /// bare-IPv4 checks and being dropped for the wrong reason.
    /// </remarks>
    public static bool LooksLikeFrame(ReadOnlySpan<byte> payload) =>
        payload.Length >= Magic.Length && payload[..Magic.Length].SequenceEqual(Magic);

    /// <summary>
    /// Decodes one frame as a receiver without the IPv6 data plane does, refusing an IPv6 body with
    /// <c>EGRESS_IPV6_UNSUPPORTED</c>. The consumer reads frames this way: it does not carry IPv6
    /// (<see cref="PeerEgressRules.ConsumerCarriesIpv6"/>).
    /// </summary>
    public static Decoded Parse(ReadOnlySpan<byte> payload) => Parse(payload, ipv6: false);

    /// <summary>
    /// Decodes one frame, returning the failing result code on rejection. <paramref name="ipv6"/> says
    /// whether this receiver accepts an IPv6 body: an egress that announces <c>ipv6PacketCapable</c>.
    /// </summary>
    /// <remarks>
    /// The checks run in a fixed order so every implementation reports the same code for a frame
    /// that violates more than one constraint.
    /// </remarks>
    public static Decoded Parse(ReadOnlySpan<byte> payload, bool ipv6)
    {
        if (payload.Length < HeaderBytes)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
        }
        if (!payload[..Magic.Length].SequenceEqual(Magic))
        {
            return Decoded.Refused(PeerEgressCodes.FrameBadMagic);
        }
        int type = payload[5];
        if (type != TypeIpPacket && type != TypeControl)
        {
            return Decoded.Refused(PeerEgressCodes.FrameUnknownType);
        }
        int flags = payload[6];
        // Reserved bits and the reserved byte are refused rather than ignored: tolerating them now
        // would make them unusable for a later version, since old builds would accept anything.
        if ((flags & ~FlagHop) != 0 || payload[7] != 0)
        {
            return Decoded.Refused(PeerEgressCodes.FrameReservedSet);
        }
        if ((flags & FlagHop) != 0)
        {
            return Decoded.Refused(PeerEgressCodes.HopNotAllowed);
        }
        var body = payload[HeaderBytes..].ToArray();

        if (type == TypeControl)
        {
            var code = ValidateControlBody(body);
            return code is null
                ? new Decoded(type, false, body, Inner.Empty, null)
                : Decoded.Refused(code);
        }

        var innerResult = ParseInnerPacket(body, ipv6);
        return innerResult.Accepted
            ? new Decoded(type, false, body, innerResult.Inner, null)
            : innerResult;
    }

    /// <summary>
    /// Reads a type=1 body. A body shorter than the smallest IPv4 header is truncated whatever its
    /// version, as it was before IPv6 bodies were read: no IPv6 header fits in it either. Then the
    /// version decides: 4 reads as IPv4, 6 as IPv6 when <paramref name="ipv6"/> is set, and anything
    /// else is <c>EGRESS_IPV6_UNSUPPORTED</c>.
    /// </summary>
    private static Decoded ParseInnerPacket(byte[] body, bool ipv6)
    {
        if (body.Length < Ipv4MinHeaderBytes)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
        }
        if (ipv6 && (body[0] >> 4) == 6)
        {
            return ParseInnerPacket6(body);
        }
        if ((body[0] >> 4) != 4)
        {
            return Decoded.Refused(PeerEgressCodes.Ipv6Unsupported);
        }
        var ihl = (body[0] & 0x0F) * 4;
        if (ihl < Ipv4MinHeaderBytes || body.Length < ihl)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
        }
        var total = (body[2] << 8) | body[3];
        if (total < ihl || total > body.Length)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
        }
        // A body longer than the IPv4 total length means trailing bytes rode along; refuse rather
        // than silently keeping the prefix.
        if (total != body.Length)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTrailingBytes);
        }

        int protocol = body[9];
        var sourcePort = 0;
        var destinationPort = 0;
        if ((protocol == ProtocolTcp || protocol == ProtocolUdp) && body.Length >= ihl + 4)
        {
            sourcePort = (body[ihl] << 8) | body[ihl + 1];
            destinationPort = (body[ihl + 2] << 8) | body[ihl + 3];
        }
        var inner = new Inner(
            Dotted(body, 12), Dotted(body, 16), protocol, sourcePort, destinationPort);
        return new Decoded(TypeIpPacket, false, body, inner, null);
    }

    /// <summary>
    /// Reads an IPv6 body (protocol/spec/peer-egress.md, IPv6 数据面, 出口).
    /// </summary>
    /// <remarks>
    /// Only the fixed header is read: the next header is the protocol, and ports are taken when it is
    /// TCP or UDP. An extension header is not walked; a packet that starts with one is refused later
    /// by protocol, the way ICMP over IPv4 is. There are no jumbograms, so a payload length of zero
    /// with bytes behind the header is trailing bytes like any other mismatch.
    /// </remarks>
    private static Decoded ParseInnerPacket6(byte[] body)
    {
        if (body.Length < Ipv6HeaderBytes)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
        }
        var total = Ipv6HeaderBytes + ((body[4] << 8) | body[5]);
        if (total > body.Length)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
        }
        if (total < body.Length)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTrailingBytes);
        }
        int nextHeader = body[6];
        var sourcePort = 0;
        var destinationPort = 0;
        if ((nextHeader == ProtocolTcp || nextHeader == ProtocolUdp) && body.Length >= Ipv6HeaderBytes + 4)
        {
            sourcePort = (body[Ipv6HeaderBytes] << 8) | body[Ipv6HeaderBytes + 1];
            destinationPort = (body[Ipv6HeaderBytes + 2] << 8) | body[Ipv6HeaderBytes + 3];
        }
        var inner = new Inner(Address6(body, 8), Address6(body, 24), nextHeader, sourcePort, destinationPort,
            Ipv6: true);
        return new Decoded(TypeIpPacket, false, body, inner, null);
    }

    private static string Address6(byte[] packet, int offset)
    {
        var value = UInt128.Zero;
        for (var index = 0; index < 16; index++)
        {
            value = (value << 8) | packet[offset + index];
        }
        return Ipv6Cidr.FormatAddress(value);
    }

    private static string Dotted(byte[] packet, int offset) =>
        $"{packet[offset]}.{packet[offset + 1]}.{packet[offset + 2]}.{packet[offset + 3]}";

    private static string? ValidateControlBody(byte[] body)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(body);
        }
        catch (JsonException)
        {
            return PeerEgressCodes.FrameMalformedControl;
        }
        using (document)
        {
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                return PeerEgressCodes.FrameMalformedControl;
            }
            var type = document.RootElement.TryGetProperty("type", out var element)
                       && element.ValueKind == JsonValueKind.String
                ? element.GetString()
                : "";
            if (type is ControlFlowReject or ControlFlowPurge)
            {
                return null;
            }
            if (type == ControlNameBind)
            {
                // Both fields, both well formed: a binding the egress cannot resolve or dial is
                // refused here rather than stored.
                var root = document.RootElement;
                return Ipv4Cidr.TryParseAddress(Text(root, "address"), out _) && PeerEgressNames.Valid(Text(root, "name"))
                    ? null
                    : PeerEgressCodes.FrameMalformedControl;
            }
            return PeerEgressCodes.ControlUnsupported;
        }
    }

    /// <summary>Builds a frame. hop is set only when this node forwards as a consumer of another egress.</summary>
    /// <summary>
    /// One control message body.
    /// </summary>
    /// <remarks>
    /// Fields not carried by a given message type stay empty or zero and are left out of the
    /// encoding, which is what makes the canonical bytes short enough to compare by eye.
    /// </remarks>
    public sealed record Control(
        string Type,
        string Protocol,
        string SourceIp,
        int SourcePort,
        string DestinationIp,
        int DestinationPort,
        IReadOnlyList<string> Destinations,
        string Code,
        string Address = "",
        string Name = "")
    {
        /// <summary>A flow-reject: the reason one flow was refused, for the consumer to display.</summary>
        public static Control FlowReject(
            string protocol, string sourceIp, int sourcePort,
            string destinationIp, int destinationPort, string code) =>
            new(ControlFlowReject, protocol, sourceIp, sourcePort, destinationIp, destinationPort, [], code);

        /// <summary>A flow-purge: the destinations whose established flows the egress should close.</summary>
        public static Control FlowPurge(IReadOnlyList<string>? destinations, string code) =>
            new(ControlFlowPurge, string.Empty, string.Empty, 0, string.Empty, 0,
                destinations ?? [], code);

        /// <summary>A name-bind: the name a fake address stands for, normalised.</summary>
        public static Control NameBind(string address, string name) =>
            new(ControlNameBind, string.Empty, string.Empty, 0, string.Empty, 0, [], string.Empty,
                address, PeerEgressNames.Normalize(name));
    }

    /// <summary>
    /// Serialises a control message in the key order the spec fixes, so two implementations produce
    /// byte-identical frames for the same message.
    /// </summary>
    /// <remarks>
    /// Assembled rather than handed to a serialiser's property ordering, because that ordering is a
    /// property of the library rather than of the protocol, and the shared vector pins these exact
    /// bytes. Values still go through the encoder: a code or a destination arrives from the wire.
    /// </remarks>
    public static byte[] EncodeControl(Control control)
    {
        var text = new StringBuilder(96).Append('{');
        AppendString(text, "type", control.Type, first: true);
        AppendString(text, "protocol", control.Protocol, first: false);
        AppendString(text, "sourceIp", control.SourceIp, first: false);
        AppendNumber(text, "sourcePort", control.SourcePort);
        AppendString(text, "destinationIp", control.DestinationIp, first: false);
        AppendNumber(text, "destinationPort", control.DestinationPort);
        if (control.Destinations.Count > 0)
        {
            text.Append(",\"destinations\":[");
            for (var index = 0; index < control.Destinations.Count; index++)
            {
                if (index > 0)
                {
                    text.Append(',');
                }
                text.Append(JsonSerializer.Serialize(control.Destinations[index]));
            }
            text.Append(']');
        }
        AppendString(text, "code", control.Code, first: false);
        AppendString(text, "address", control.Address, first: false);
        AppendString(text, "name", control.Name, first: false);
        return Encoding.UTF8.GetBytes(text.Append('}').ToString());
    }

    private static void AppendString(StringBuilder text, string name, string? value, bool first)
    {
        if (string.IsNullOrEmpty(value))
        {
            return;
        }
        if (!first)
        {
            text.Append(',');
        }
        text.Append('"').Append(name).Append("\":").Append(JsonSerializer.Serialize(value));
    }

    private static void AppendNumber(StringBuilder text, string name, int value)
    {
        if (value == 0)
        {
            return;
        }
        text.Append(",\"").Append(name).Append("\":").Append(value);
    }

    /// <summary>Reads a control body, returning null when it cannot be parsed.</summary>
    public static Control? DecodeControl(ReadOnlySpan<byte> body)
    {
        if (body.Length == 0)
        {
            return null;
        }
        try
        {
            using var document = JsonDocument.Parse(body.ToArray());
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            var destinations = new List<string>();
            if (root.TryGetProperty("destinations", out var list) && list.ValueKind == JsonValueKind.Array)
            {
                foreach (var entry in list.EnumerateArray())
                {
                    destinations.Add(entry.GetString() ?? string.Empty);
                }
            }
            return new Control(
                Text(root, "type"), Text(root, "protocol"), Text(root, "sourceIp"),
                Number(root, "sourcePort"), Text(root, "destinationIp"),
                Number(root, "destinationPort"), destinations, Text(root, "code"),
                Text(root, "address"), Text(root, "name"));
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;

    private static int Number(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var parsed)
            ? parsed
            : 0;

    public static byte[] Encode(int type, bool hop, ReadOnlySpan<byte> body)
    {
        var frame = new byte[HeaderBytes + body.Length];
        Magic.CopyTo(frame.AsSpan());
        frame[5] = (byte)type;
        frame[6] = (byte)(hop ? FlagHop : 0);
        body.CopyTo(frame.AsSpan(HeaderBytes));
        return frame;
    }
}
