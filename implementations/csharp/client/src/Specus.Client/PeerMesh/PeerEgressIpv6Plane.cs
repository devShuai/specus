using Specus.Client.Configuration;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// A virtual device that can say whether it carries IPv6: whether it is up with its derived address
/// assigned, and why not when it is not (protocol/spec/peer-egress.md, IPv6 数据面, 消费端). A device
/// that does not implement it -- the noop device -- carries no IPv6.
/// </summary>
internal interface IPeerVirtualDeviceIpv6
{
    /// <summary>Whether the device carries IPv6 now, and why not when it does not.</summary>
    (bool Ready, string Reason) Ipv6Ready();
}

/// <summary>
/// Whether this consumer has the IPv6 data plane, and giving the TUN the device's derived IPv6 address
/// (protocol/spec/peer-egress.md, IPv6 数据面, 消费端).
/// </summary>
/// <remarks>
/// The address is the mesh IPv4 inside <c>fd53:7065:6375:7300::/96</c>, as a /128: no on-link route
/// comes with it, so nothing reaches the TUN by IPv6 but what a rule's route sends there, and the
/// system picks it as the source for exactly that traffic. Without it an application's packet would
/// leave with some other source, which the data plane refuses as <c>ipv6-source-not-mesh</c>.
///
/// <para>No platform guard: the command builders are the part worth testing everywhere, and only the
/// devices that run them are platform-specific.</para>
/// </remarks>
internal static class PeerEgressIpv6Plane
{
    /// <summary>
    /// The smallest MTU IPv6 allows on any link (RFC 8200 5). A device whose Peer Mesh MTU is below it
    /// has no IPv6 data plane, and a peer path that probes below it carries no IPv6.
    /// </summary>
    public const int MinimumMtu = 1280;

    /// <summary>The reason a device given no derived address carries no IPv6.</summary>
    public const string NotAsked =
        "the consumer is off or peerMeshMtu is below 1280, so the TUN was given no IPv6 address";

    /// <summary>
    /// Whether this platform reads IPv6 from its TUN, gives the TUN the device's derived IPv6 address
    /// and routes IPv6 into it: wherever route takeover exists, Linux, Windows and macOS. Decided by
    /// the same checks as the takeover, so the two cannot disagree about the platform.
    /// </summary>
    public static bool PlatformCarriesIpv6 => PeerEgressRouteCommanders.TakeoverSupported();

    /// <summary>
    /// Whether a consumer with this <c>peerMeshMtu</c> has an IPv6 data plane on this platform: IPv6
    /// packets read from the TUN, IPv6 routes installed into it, and IPv6 carried to the egress.
    /// Unset reads as the default. Without it a well-formed IPv6 rule is refused with
    /// <c>EGRESS_RULE_IPV6_UNSUPPORTED</c>. The TUN must also have taken its address; that is the
    /// device's answer, <see cref="IPeerVirtualDeviceIpv6"/>.
    /// </summary>
    public static bool ConsumerCarriesIpv6(int peerMeshMtu)
    {
        if (peerMeshMtu <= 0)
        {
            peerMeshMtu = SpecusClientConfig.DefaultPeerMeshMtu;
        }
        return PlatformCarriesIpv6 && peerMeshMtu >= MinimumMtu;
    }

    /// <summary>
    /// The derived IPv6 address the TUN is given, or null when it is given none: the consumer is
    /// switched off, or this device has no IPv6 data plane (its platform, or a peerMeshMtu below 1280).
    /// Assigned only for the consumer -- an address on the TUN serves nothing else, and a device that
    /// never asked for IPv6 should not grow one.
    /// </summary>
    public static string? DeviceAddress(SpecusClientConfig config, string? virtualIpv4)
    {
        if (!config.PeerEgressEnabled || !ConsumerCarriesIpv6(config.PeerMeshMtu))
        {
            return null;
        }
        return PeerEgressMeshAddress.TryDerive(virtualIpv4?.Trim(), out var address)
            ? Ipv6Cidr.FormatAddress(address)
            : null;
    }

    /// <summary>
    /// The spec's <c>ip -6 address add &lt;address&gt;/128 dev &lt;tun&gt;</c>. Argv entries, never seen
    /// by a shell. Add rather than replace: the interface was created a moment ago and dies with the
    /// descriptor, so an address already on it is not this run's.
    /// </summary>
    public static string[] LinuxAssignAddressArgs(string device, string address) =>
        ["ip", "-6", "address", "add", address + "/128", "dev", device];

    /// <summary>Whether an address lies in <c>fe80::/10</c>.</summary>
    public static bool IsLinkLocal(UInt128 address) => (address >> 118) == 0x3FA;

    /// <summary>Whether an address lies in <c>ff00::/8</c>.</summary>
    public static bool IsMulticast(UInt128 address) => (address >> 120) == 0xFF;
}
