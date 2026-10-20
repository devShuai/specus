using System.Buffers.Binary;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The IPv6 packets the egress user-space stack reads from consumers and writes back
/// (protocol/spec/peer-egress.md, IPv6 数据面, 出口).
/// </summary>
/// <remarks>
/// The stack is the IPv4 one. A segment or datagram carries the family it arrived in, and everything
/// above the codec -- the state machine, the flow table, the judgment layer -- works on it unchanged.
/// The device address the source is checked against is <see cref="Specus.Protocol.PeerEgress.PeerEgressMeshAddress"/>.
/// </remarks>
internal static class PeerEgressIpv6
{
    public const int HeaderBytes = 40;

    /// <summary>
    /// ICMPv6. Like every next header but TCP and UDP it is refused, and named only so the tests can
    /// say what they send.
    /// </summary>
    public const byte NextHeaderIcmp = 58;

    /// <summary>What the egress writes on every packet it returns to a consumer.</summary>
    public const byte HopLimit = 64;

    /// <summary>
    /// Returns what follows the fixed header of an IPv6 packet carrying <paramref name="nextHeader"/>
    /// directly, with exactly the length the header states; or an empty span with false.
    /// </summary>
    public static bool TryPayload(ReadOnlySpan<byte> packet, byte nextHeader, out ReadOnlySpan<byte> payload)
    {
        payload = default;
        if (packet.Length < HeaderBytes || packet[0] >> 4 != 6 || packet[6] != nextHeader)
        {
            return false;
        }
        int length = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        if (HeaderBytes + length != packet.Length)
        {
            return false;
        }
        payload = packet[HeaderBytes..];
        return true;
    }

    /// <summary>An address as the packet carries it, most significant byte first.</summary>
    public static UInt128 ReadAddress(ReadOnlySpan<byte> bytes) => BinaryPrimitives.ReadUInt128BigEndian(bytes[..16]);

    public static UInt128 SourceOf(ReadOnlySpan<byte> packet) => ReadAddress(packet[8..24]);

    public static UInt128 DestinationOf(ReadOnlySpan<byte> packet) => ReadAddress(packet[24..40]);

    /// <summary>
    /// Fills the fixed header of a packet the egress returns: traffic class and flow label zero, hop
    /// limit 64.
    /// </summary>
    public static void WriteHeader(Span<byte> packet, byte nextHeader, int payloadLength, UInt128 source,
        UInt128 destination)
    {
        packet[0] = 0x60;
        packet[1] = 0;
        packet[2] = 0;
        packet[3] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet[4..6], (ushort)payloadLength);
        packet[6] = nextHeader;
        packet[7] = HopLimit;
        BinaryPrimitives.WriteUInt128BigEndian(packet[8..24], source);
        BinaryPrimitives.WriteUInt128BigEndian(packet[24..40], destination);
    }

    /// <summary>
    /// The TCP and UDP checksum over the RFC 8200 8.1 pseudo-header: both addresses, the upper-layer
    /// length as 32 bits, three zero bytes and the next header. Over a segment that already carries its
    /// checksum it comes to zero, the same convention as the IPv4 helpers.
    /// </summary>
    public static int Checksum(UInt128 source, UInt128 destination, byte nextHeader, ReadOnlySpan<byte> upper)
    {
        ulong sum = 0;
        for (var shift = 112; shift >= 0; shift -= 16)
        {
            sum += (ulong)(ushort)(source >> shift);
            sum += (ulong)(ushort)(destination >> shift);
        }
        var length = (uint)upper.Length;
        sum += length >> 16;
        sum += length & 0xFFFF;
        sum += nextHeader;
        var index = 0;
        while (index + 1 < upper.Length)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(upper.Slice(index, 2));
            index += 2;
        }
        if (index < upper.Length)
        {
            sum += (ulong)upper[index] << 8;
        }
        while ((sum >> 16) != 0)
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int)(~sum & 0xFFFF);
    }

    /// <summary>An IPv6 address as a dialled address takes it.</summary>
    public static System.Net.IPAddress ToAddress(UInt128 address)
    {
        var bytes = new byte[16];
        BinaryPrimitives.WriteUInt128BigEndian(bytes, address);
        return new System.Net.IPAddress(bytes);
    }

    /// <summary>The address of an IPv6 <see cref="System.Net.IPAddress"/>, its scope dropped.</summary>
    public static UInt128 FromAddress(System.Net.IPAddress address) => ReadAddress(address.GetAddressBytes());
}
