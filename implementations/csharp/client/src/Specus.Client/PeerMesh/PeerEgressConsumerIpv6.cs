using System.Buffers.Binary;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// The consumer side of the IPv6 data plane (protocol/spec/peer-egress.md, IPv6 数据面, 消费端).
/// </summary>
/// <remarks>
/// The same rule as for IPv4 shapes it: a destination an egress rule claims never goes out locally.
/// What IPv6 adds is a few checks before the rules are asked, because the TUN sees more of the
/// system's own IPv6 than it ever saw of IPv4: neighbour discovery and multicast reports on every
/// interface, and applications that bound some other address. Pinned by
/// protocol/test-vectors/peer-egress-ipv6-v1.json (consumerOutbound, returnPath, failure).
/// </remarks>
internal sealed partial class PeerEgressConsumer
{
    private const int Icmpv6DestinationUnreachable = 1;

    /// <summary>
    /// The counterpart of IPv4's host unreachable: the stack reports EHOSTUNREACH on the socket.
    /// </summary>
    private const int Icmpv6AddressUnreachable = 3;

    private const int Icmpv6HeaderBytes = 8;

    /// <summary>
    /// Whether the device carries IPv6 now, given with each configuration. Without it every IPv6
    /// packet is left alone in both directions, as before the data plane existed.
    /// </summary>
    internal bool CarriesIpv6 { get; set; }

    /// <summary>
    /// The address derived from this node's mesh address: the only source an IPv6 packet may leave
    /// with and the only destination a reply may come back to. Null without a mesh address.
    /// </summary>
    private UInt128? _virtualIp6;

    /// <summary>
    /// The effective MTU of the session to an egress, the one the IPv4 path clamps to. Null, or an
    /// egress it has no measurement for, is not checked: the data plane exists only at a configured
    /// MTU of at least 1280.
    /// </summary>
    internal Func<long, int?>? PathMtu { get; set; }

    /// <summary>Whether the last catalogue says this egress takes IPv6 packets. Not listed means no.</summary>
    private bool Ipv6Capable(long egress) =>
        _catalog.Listed.TryGetValue(egress, out var listing) && listing.Ipv6PacketCapable;

    /// <summary>
    /// Why an IPv6 packet to an egress is refused and answered, or null when it may go: the egress is
    /// offline or stopped by its catalogue standing, or does not take IPv6 packets.
    /// </summary>
    private string? Unavailable6(long egress)
    {
        if (egress <= 0 || !_online.GetValueOrDefault(egress))
        {
            return "egress-unavailable";
        }
        if (PeerEgressStanding.BlockedReason(StandingOf(egress)) is { } standing)
        {
            return standing;
        }
        // Online and not ruled out by the catalogue, but not said to take IPv6 packets: sent anyway it
        // would be refused there with EGRESS_IPV6_UNSUPPORTED. Answered like an egress that is not
        // there, as egress-no-domain is, so the application fails now.
        return Ipv6Capable(egress) ? null : "egress-no-ipv6";
    }

    /// <summary>
    /// Decides what happens to one IPv6 packet read from the TUN.
    /// </summary>
    /// <remarks>
    /// In order, before the rules: a link-local source or a multicast destination is the system's own
    /// traffic and is dropped without a count; a source that is not this device's derived address
    /// would be refused by the egress, which checks it against the session, so it is not sent
    /// (<c>ipv6-source-not-mesh</c>); a destination inside the derived prefix is another device's, and
    /// device-to-device traffic stays IPv4 (<c>ipv6-mesh-unsupported</c>). Then the rules, as for IPv4,
    /// and for a packet that would be sent to an egress the effective MTU of the session to it: below
    /// 1280 it cannot carry IPv6 at all (<c>ipv6-path-mtu</c>).
    ///
    /// <para>The path check runs once the rules have named the egress rather than strictly before
    /// them, since the session whose MTU it reads is the one to the egress the rule names; a packet a
    /// block rule drops, or one to an egress that is not there, has no session to ask about. None of
    /// these drops is answered: they are not an egress being unavailable but traffic this data plane
    /// cannot carry. <c>egress-no-ipv6</c> is answered, like <c>egress-no-domain</c>.</para>
    /// </remarks>
    private PeerEgressConsumerOutcome HandleOutbound6(byte[] packet, long nowMs)
    {
        if (packet.Length < PeerEgressIpv6.HeaderBytes)
        {
            return PeerEgressConsumerOutcome.NotMine;
        }
        if (!CarriesIpv6)
        {
            // Without the data plane no IPv6 rule is in force, so nothing can claim the packet.
            return PeerEgressConsumerOutcome.NotMine;
        }
        var source = PeerEgressIpv6.SourceOf(packet);
        var destination = PeerEgressIpv6.DestinationOf(packet);
        if (PeerEgressIpv6Plane.IsLinkLocal(source) || PeerEgressIpv6Plane.IsMulticast(destination))
        {
            return PeerEgressConsumerOutcome.Ignored;
        }
        if (_virtualIp6 is not { } own || source != own)
        {
            RecordBlocked("ipv6-source-not-mesh");
            return PeerEgressConsumerOutcome.BlockedIpv6;
        }
        if (PeerEgressMeshAddress.PrefixCidr.Contains(destination))
        {
            RecordBlocked("ipv6-mesh-unsupported");
            return PeerEgressConsumerOutcome.BlockedIpv6;
        }
        var match = Steer6(destination);
        if (!match.Matched || match.Action is not (PeerEgressRules.ActionEgress or PeerEgressRules.ActionBlock))
        {
            return PeerEgressConsumerOutcome.NotMine;
        }
        if (match.Action == PeerEgressRules.ActionBlock)
        {
            // A block rule is a drop, as for IPv4.
            RecordBlocked("rule");
            return PeerEgressConsumerOutcome.BlockedByRule;
        }
        // The next header is the protocol: TCP and UDP are carried, and anything else -- ICMPv6, an
        // extension header, a fragment header -- is dropped as ICMP is for IPv4.
        int nextHeader = packet[6];
        if (nextHeader != PeerEgressSegment.Ipv4ProtocolTcp && nextHeader != PeerEgressDatagram.Ipv4ProtocolUdp)
        {
            RecordBlocked("unsupported-protocol");
            return PeerEgressConsumerOutcome.Unsupported;
        }
        var egress = match.EgressClientId ?? 0;
        if (Unavailable6(egress) is { } unavailable)
        {
            RecordBlocked(unavailable);
            if (FailurePacket6(packet, nextHeader) is { } answer)
            {
                toTun?.Invoke(answer);
            }
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }
        // Asked of the mesh, whose lock is taken here as the send callback already takes it for
        // reachability: the caller's lock on this consumer is held, and the mesh never takes that one
        // while holding its own.
        if (PathMtu?.Invoke(egress) is { } pathMtu && pathMtu < PeerEgressIpv6Plane.MinimumMtu)
        {
            RecordBlocked("ipv6-path-mtu");
            return PeerEgressConsumerOutcome.BlockedIpv6;
        }

        if (FlowKeyFor6(packet, nextHeader) is { } key)
        {
            var flow = Remembered(key, nowMs);
            // A new connection reusing the five-tuple of one that closed, as for IPv4.
            if (flow is { ClosedAtMs: not null } && IsBareSyn(packet))
            {
                Forget(flow);
                flow = null;
            }
            flow ??= Register(key, egress, nowMs);
            Touch(flow, packet, outbound: true, nowMs);
            if (nextHeader == PeerEgressSegment.Ipv4ProtocolTcp)
            {
                flow.NoteApplicationProgress(packet);
            }
        }
        if (send is null)
        {
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }
        // The packet goes as it is: SPEG1 carries an IPv6 packet unchanged, its version telling the two
        // families apart. hop stays clear, as for IPv4.
        if (!send(egress, PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet)))
        {
            RecordBlocked("send-failed");
            return PeerEgressConsumerOutcome.BlockedNoEgress;
        }
        return PeerEgressConsumerOutcome.Forwarded;
    }

    /// <summary>
    /// Decides an IPv6 destination by the IPv6 rules alone. There is no fake-IP pool in IPv6 -- names
    /// are answered with IPv4 fake addresses only -- so only address rules apply, and only while the
    /// data plane is on.
    /// </summary>
    private PeerEgressRuleMatch Steer6(UInt128 destination) =>
        PeerEgressRules.Match(_rules, Ipv6Cidr.FormatAddress(destination), _meshCidr, _pool?.Cidr, CarriesIpv6);

    /// <summary>
    /// Whether an IPv6 flow's destination still goes to the egress carrying it, by the same decision a
    /// new packet would get, and that egress still takes IPv6 packets.
    /// </summary>
    private bool StillOurs6(UInt128 remote, long egress)
    {
        var match = Steer6(remote);
        return match.Action == PeerEgressRules.ActionEgress
            && match.EgressClientId == egress
            && CanTake(egress)
            && Ipv6Capable(egress);
    }

    /// <summary>
    /// Takes an IPv6 packet an egress sent back (vector <c>returnPath</c>). A packet not addressed to
    /// this device's derived address is not the consumer's, and is left for the egress role of a
    /// device that is both. One whose source is inside the derived prefix would let an egress speak as
    /// another device, and one that matches no live flow this device opened through this egress was
    /// never asked for.
    /// </summary>
    private bool HandleInbound6(byte[] packet, PeerEgressFrame.Inner inner, long fromEgress, long nowMs)
    {
        if (packet.Length < PeerEgressIpv6.HeaderBytes)
        {
            return false;
        }
        var source = PeerEgressIpv6.SourceOf(packet);
        var destination = PeerEgressIpv6.DestinationOf(packet);
        if (_virtualIp6 is not { } own || destination != own)
        {
            return false;
        }
        if (PeerEgressMeshAddress.PrefixCidr.Contains(source))
        {
            RecordBlocked("return-mesh-source");
            return true;
        }
        // Mirrored: the reply travels the other way.
        var key = new PeerEgressFlowTable.Key(inner.Protocol, 0, (ushort)inner.DestinationPort, 0,
            (ushort)inner.SourcePort, Ipv6: true, ConsumerIp6: destination, RemoteIp6: source);
        if (Remembered(key, nowMs) is not { } flow || flow.Egress != fromEgress)
        {
            RecordBlocked("return-no-flow");
            return true;
        }
        Touch(flow, packet, outbound: false, nowMs);
        flow.Replied = true;
        toTun?.Invoke(packet);
        return true;
    }

    /// <summary>
    /// The five-tuple of an IPv6 packet as the consumer sees it, the mirror of what the egress records.
    /// Only a TCP or UDP header directly behind the fixed header is read: the data plane carries
    /// nothing else.
    /// </summary>
    private static PeerEgressFlowTable.Key? FlowKeyFor6(byte[] packet, int nextHeader)
    {
        if (packet.Length < PeerEgressIpv6.HeaderBytes + 4)
        {
            return null;
        }
        return new PeerEgressFlowTable.Key(
            nextHeader, 0, ReadUInt16(packet, PeerEgressIpv6.HeaderBytes),
            0, ReadUInt16(packet, PeerEgressIpv6.HeaderBytes + 2),
            Ipv6: true, ConsumerIp6: PeerEgressIpv6.SourceOf(packet), RemoteIp6: PeerEgressIpv6.DestinationOf(packet));
    }

    /// <summary>
    /// Answers an IPv6 packet the consumer refused to forward, the way <see cref="FailurePacket"/>
    /// answers an IPv4 one: a TCP segment with a reset by RFC 793, a UDP datagram with an ICMPv6
    /// address unreachable. Pinned by the failure section of peer-egress-ipv6-v1.json.
    /// </summary>
    public static byte[]? FailurePacket6(byte[] packet, int nextHeader) => nextHeader switch
    {
        PeerEgressSegment.Ipv4ProtocolTcp => PeerEgressSegment.Parse6(packet) is { } segment
            ? PeerEgressSegment.BuildReset(segment)
            : null,
        PeerEgressDatagram.Ipv4ProtocolUdp => Icmpv6AddressUnreachableFor(packet),
        _ => null,
    };

    /// <summary>
    /// An ICMPv6 destination unreachable, code 3, for an IPv6 packet: from the packet's destination
    /// back to its source, hop limit 64, quoting as much of the packet as fits without the whole error
    /// passing the IPv6 minimum MTU (RFC 4443 2.4 c). The checksum covers the RFC 8200 pseudo-header,
    /// as every ICMPv6 checksum does.
    /// </summary>
    internal static byte[]? Icmpv6AddressUnreachableFor(byte[] packet)
    {
        if (packet.Length < PeerEgressIpv6.HeaderBytes || packet[0] >> 4 != 6)
        {
            return null;
        }
        var original = Math.Min(packet.Length,
            PeerEgressIpv6.HeaderBytes + BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(4, 2)));
        var quoted = Math.Min(original,
            PeerEgressIpv6Plane.MinimumMtu - PeerEgressIpv6.HeaderBytes - Icmpv6HeaderBytes);
        var source = PeerEgressIpv6.DestinationOf(packet);
        var destination = PeerEgressIpv6.SourceOf(packet);
        var response = new byte[PeerEgressIpv6.HeaderBytes + Icmpv6HeaderBytes + quoted];
        PeerEgressIpv6.WriteHeader(response, PeerEgressIpv6.NextHeaderIcmp, Icmpv6HeaderBytes + quoted, source, destination);
        var message = response.AsSpan(PeerEgressIpv6.HeaderBytes);
        message[0] = Icmpv6DestinationUnreachable;
        message[1] = Icmpv6AddressUnreachable;
        packet.AsSpan(0, quoted).CopyTo(message[Icmpv6HeaderBytes..]);
        BinaryPrimitives.WriteUInt16BigEndian(message[2..4],
            (ushort)PeerEgressIpv6.Checksum(source, destination, PeerEgressIpv6.NextHeaderIcmp, message));
        return response;
    }
}
