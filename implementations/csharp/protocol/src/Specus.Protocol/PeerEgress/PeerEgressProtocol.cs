namespace Specus.Protocol.PeerEgress;

/// <summary>
/// Version negotiation for peer egress split routing.
/// </summary>
/// <remarks>
/// The version is tracked separately from the individual target capabilities so that a later
/// release adding domain rules can coexist with clients that only understand address targets,
/// instead of gating everything on the version number alone.
/// </remarks>
public static class PeerEgressProtocol
{
    /// <summary>The split-routing version this build speaks.</summary>
    public const int ProtocolVersion = 1;

    /// <summary>
    /// Clamps a client-announced version to what this build understands. Zero means the client
    /// cannot take part, and the server must not push egress-config or egress-catalog to it.
    /// </summary>
    public static int NormalizeVersion(int version) =>
        version < 1 ? 0 : Math.Min(version, ProtocolVersion);

    /// <summary>IPv6 target sockets on the egress, not consumer IPv6 packet support.</summary>
    public static bool DeclaresIpv6Targets(int version, bool declared) =>
        NormalizeVersion(version) >= 1 && declared;

    /// <summary>IPv6 packets carried in SPEG1 to the egress, independent of IPv6 target sockets.</summary>
    public static bool DeclaresIpv6Packets(int version, bool declared) =>
        NormalizeVersion(version) >= 1 && declared;
}
