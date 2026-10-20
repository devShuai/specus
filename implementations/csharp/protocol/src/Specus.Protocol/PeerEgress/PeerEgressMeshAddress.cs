namespace Specus.Protocol.PeerEgress;

/// <summary>
/// The IPv6 address a device has in the egress data plane (protocol/spec/peer-egress.md, IPv6 数据面,
/// 设备地址): the prefix <c>fd53:7065:6375:7300::/96</c> with the device's mesh IPv4 as its low 32 bits.
/// </summary>
/// <remarks>
/// The prefix is fixed and does not follow <c>peerMeshCidr</c>. To IPv6 it is what the Peer Mesh
/// network is to IPv4, so an egress refuses a destination inside it the way it refuses a mesh one.
/// Pinned by the <c>meshAddress</c> section of protocol/test-vectors/peer-egress-ipv6-v1.json.
/// </remarks>
public static class PeerEgressMeshAddress
{
    /// <summary>The prefix every device's IPv6 address lies in.</summary>
    public const string Prefix = "fd53:7065:6375:7300::/96";

    private static readonly UInt128 Network = new(0xfd53_7065_6375_7300UL, 0);

    /// <summary><see cref="Prefix"/> as a prefix.</summary>
    public static Ipv6Cidr PrefixCidr { get; } = new(Network, 96);

    /// <summary>The IPv6 address derived from a mesh IPv4 address.</summary>
    public static UInt128 Derive(uint meshIpv4) => Network | meshIpv4;

    /// <summary>
    /// Derives a device's address from its mesh IPv4 as the mesh writes it, or reports false when that
    /// is not an IPv4 address at all.
    /// </summary>
    public static bool TryDerive(string? meshIpv4, out UInt128 address)
    {
        if (!Ipv4Cidr.TryParseAddress(meshIpv4, out var value))
        {
            address = UInt128.Zero;
            return false;
        }
        address = Derive(value);
        return true;
    }

    /// <summary>Reads the mesh IPv4 back out of a derived address. Only an address inside the prefix is one.</summary>
    public static bool TryUnderive(UInt128 address, out uint meshIpv4)
    {
        if (address >> 32 != Network >> 32)
        {
            meshIpv4 = 0;
            return false;
        }
        meshIpv4 = (uint)(address & uint.MaxValue);
        return true;
    }
}
