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

    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SPEG1");
    private const int Ipv4MinHeaderBytes = 20;
    private const int ProtocolTcp = 6;
    private const int ProtocolUdp = 17;

    /// <summary>The parsed IPv4 tuple of a type=1 body, filled only for that type.</summary>
    public sealed record Inner(
        string SourceIp,
        string DestinationIp,
        int Protocol,
        int SourcePort,
        int DestinationPort)
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
    /// Decodes one frame, returning the failing result code on rejection.
    /// </summary>
    /// <remarks>
    /// The checks run in a fixed order so every implementation reports the same code for a frame
    /// that violates more than one constraint.
    /// </remarks>
    public static Decoded Parse(ReadOnlySpan<byte> payload)
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

        var innerResult = ParseInnerPacket(body);
        return innerResult.Accepted
            ? new Decoded(type, false, body, innerResult.Inner, null)
            : innerResult;
    }

    private static Decoded ParseInnerPacket(byte[] body)
    {
        if (body.Length < Ipv4MinHeaderBytes)
        {
            return Decoded.Refused(PeerEgressCodes.FrameTruncated);
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
            // Includes name-bind, which phase two defines. Refusing keeps a phase-one egress from
            // looking like it honours domain rules it does not implement.
            return PeerEgressCodes.ControlUnsupported;
        }
    }

    /// <summary>Builds a frame. hop is set only when this node forwards as a consumer of another egress.</summary>
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
