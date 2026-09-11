using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// The joins between the egress plane and Peer Mesh.
/// </summary>
/// <remarks>
/// What is worth testing here is not the plane, which has its own suites, but the decisions the
/// wiring makes on its behalf: which role is offered a frame first, what happens to a frame that
/// arrives before anything configured this node, and whether a frame leaves through the queue rather
/// than inline under the plane's lock.
/// </remarks>
public class PeerEgressMeshTests : IDisposable
{
    private const string VirtualIp = "100.96.0.1";

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-mesh-" + Guid.NewGuid().ToString("N"));

    private readonly List<long> _sentTo = [];
    private readonly List<byte[]> _sentFrames = [];
    private readonly List<byte[]> _toDevice = [];
    private volatile bool _reachable = true;
    private PeerEgressMesh? _mesh;

    public PeerEgressMeshTests() => Directory.CreateDirectory(_directory);

    public void Dispose()
    {
        _mesh?.Dispose();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
        GC.SuppressFinalize(this);
    }

    private sealed class FakeHost(PeerEgressMeshTests owner, string directory) : IPeerEgressMeshHost
    {
        public bool CanReach(long peerId) => owner._reachable;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame)
        {
            lock (owner._sentFrames)
            {
                owner._sentTo.Add(peerId);
                owner._sentFrames.Add((byte[])frame.Clone());
            }
            return Task.FromResult(true);
        }

        public Task WriteToDeviceAsync(byte[] packet)
        {
            lock (owner._toDevice)
            {
                owner._toDevice.Add((byte[])packet.Clone());
            }
            return Task.CompletedTask;
        }

        public string TunName => "specus0";

        public string MeshCidr => "100.96.0.0/11";

        public string VirtualIp => PeerEgressMeshTests.VirtualIp;

        public IReadOnlyList<string> DeploymentDenyCidrs() => ["203.0.113.250/32"];

        public IReadOnlyList<string> PeerEndpointAddresses() => ["198.51.100.240"];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");
    }

    private PeerEgressMesh NewMesh()
    {
        _mesh = new PeerEgressMesh(new FakeHost(this, _directory),
            dialer: new FakeDialer(), commander: new FakeCommander());
        return _mesh;
    }

    /// <summary>A routing table that accepts everything and touches nothing on this machine.</summary>
    private sealed class FakeCommander : IPeerEgressRouteCommander
    {
        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) =>
            PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
        }

        public void Remove(PeerEgressRoute route)
        {
        }
    }

    /// <summary>
    /// A socket that never fails and never reads. With the real dialer these cases would each spend
    /// the whole connect timeout reaching an address nobody routes, which is a test of the network
    /// rather than of the wiring.
    /// </summary>
    private sealed class FakeDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            new IdleSocket();

        private sealed class IdleSocket : IPeerEgressSocket
        {
            private readonly ManualResetEventSlim _closed = new(false);

            public int Read(byte[] buffer)
            {
                _closed.Wait();
                return -1;
            }

            public void Write(byte[] data)
            {
            }

            public void Dispose() => _closed.Set();
        }
    }

    private List<byte[]> Frames()
    {
        lock (_sentFrames)
        {
            return [.. _sentFrames];
        }
    }

    private void ClearFrames()
    {
        lock (_sentFrames)
        {
            _sentFrames.Clear();
        }
    }

    private static void WaitFor(string what, Func<bool> condition)
    {
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < deadline)
        {
            if (condition())
            {
                return;
            }
            Thread.Sleep(1);
        }
        Assert.Fail($"timed out waiting for {what}");
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static byte[] SynTo(string destination) =>
        PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false,
            PeerEgressSegment.Build(new Segment(
                Address(VirtualIp), Address(destination), 40000, 443,
                1000, 0, PeerEgressSegment.FlagSyn, 65535, 1360, [])));

    // Q stands in for the quote and is converted at the end, so the message stays readable rather
    // than disappearing into a wall of escapes.
    private static string ConfigFor(long revision, string cidr) => Json(
        "{QtypeQ:Qegress-configQ,QenabledQ:true,QrevisionQ:" + revision
        + ",QscopeQ:QPUBLICQ,QallowedConsumerClientIdsQ:[7],QdestinationRulesQ:[{QcidrQ:Q"
        + cidr + "Q,QprotocolsQ:[QtcpQ,QudpQ],QportRangesQ:[[1,65535]]}],"
        + "QlimitsQ:{QmaxConcurrentFlowsQ:8,QmaxFlowsPerConsumerQ:4,QidleTimeoutSecondsQ:60}}");

    /// <summary>Turns the Q stand-in into a real quote, so no line here needs escaping.</summary>
    private static string Json(string text) => text.Replace('Q', '"');

    private static PeerEgressRule Rule(string match, string action, long? target = null) => new()
    {
        Match = match,
        Action = action,
        EgressClientId = target,
    };

    private static byte[] PacketTo(string destination) =>
        PeerEgressSegment.Build(new Segment(
            Address(VirtualIp), Address(destination), 40000, 443,
            1000, 0, PeerEgressSegment.FlagSyn, 65535, 0, []));

    /// <summary>
    /// A frame that arrives before anything configured this node is dropped, not answered. Building
    /// the plane on first contact would let any peer turn an unconfigured device into an egress by
    /// sending it one.
    /// </summary>
    [Fact]
    public void AFrameBeforeAnyConfigIsDroppedRatherThanAnswered()
    {
        var wiring = NewMesh();

        Assert.True(wiring.HandleInboundFrame(7, SynTo("203.0.113.10")),
            "the frame was left for the mesh's own dispatch");
        Assert.True(Frames().Count == 0, "an unconfigured node answered a frame");
    }

    /// <summary>A payload that is not SPEG1 is left for the mesh's other cases.</summary>
    [Fact]
    public void ANonEgressPayloadIsNotClaimed()
    {
        var wiring = NewMesh();
        var bare = PeerEgressSegment.Build(new Segment(
            Address("203.0.113.10"), Address(VirtualIp), 443, 40000,
            0, 0, PeerEgressSegment.FlagAck, 65535, 0, []));

        Assert.False(wiring.HandleInboundFrame(7, bare), "a bare IPv4 packet was claimed");
    }

    /// <summary>
    /// A pushed config builds the plane and takes effect, and the frames it produces leave through
    /// the queue rather than inline under the plane's lock.
    /// </summary>
    [Fact]
    public void APushedConfigMakesTheNodeAnEgress()
    {
        var wiring = NewMesh();
        wiring.ApplyEgressConfig(ConfigFor(1, "203.0.113.0/24"));

        Assert.True(wiring.HandleInboundFrame(7, SynTo("203.0.113.10")), "the frame was not claimed");
        WaitFor("the SYN-ACK to be sent", () => Frames().Count > 0);

        var decoded = PeerEgressFrame.Parse(Frames()[0]);
        Assert.True(decoded.Accepted, "the frame we produced does not parse");
        Assert.Equal(PeerEgressFrame.TypeIpPacket, decoded.Type);
    }

    /// <summary>
    /// A destination the policy does not cover is refused, and the refusal reaches the consumer as a
    /// control message rather than as silence.
    /// </summary>
    [Fact]
    public void ARefusedDestinationIsToldWhy()
    {
        var wiring = NewMesh();
        wiring.ApplyEgressConfig(ConfigFor(1, "203.0.113.0/24"));

        wiring.HandleInboundFrame(7, SynTo("198.51.100.10"));
        WaitFor("a refusal to be sent", () => Frames().Exists(raw =>
        {
            var frame = PeerEgressFrame.Parse(raw);
            return frame.Accepted && frame.Type == PeerEgressFrame.TypeControl;
        }));
    }

    /// <summary>
    /// A snapshot at or below the last accepted one is ignored, so a reordered or replayed push
    /// cannot walk the policy backwards.
    /// </summary>
    [Fact]
    public void AReplayedRevisionIsIgnored()
    {
        var wiring = NewMesh();
        wiring.ApplyEgressConfig(ConfigFor(5, "203.0.113.0/24"));
        // An older snapshot that would have narrowed the policy to something else.
        wiring.ApplyEgressConfig(ConfigFor(4, "198.51.100.0/24"));

        wiring.HandleInboundFrame(7, SynTo("203.0.113.10"));
        WaitFor("the newer policy to still be in force", () => Frames().Exists(raw =>
        {
            var frame = PeerEgressFrame.Parse(raw);
            return frame.Accepted && frame.Type == PeerEgressFrame.TypeIpPacket;
        }));
    }

    /// <summary>A message that is not an egress-config must not configure anything.</summary>
    [Fact]
    public void AnUnreadableConfigChangesNothing()
    {
        var wiring = NewMesh();
        wiring.ApplyEgressConfig(Json("{QtypeQ:Qegress-catalogQ,QrevisionQ:1}"));

        Assert.True(wiring.HandleInboundFrame(7, SynTo("203.0.113.10")));
        Assert.True(Frames().Count == 0, "a catalogue was read as a policy");
    }

    /// <summary>
    /// Traffic no consumer rule claims stays with the mesh's own handling. Claiming it would swallow
    /// the mesh's packets, which share the device.
    /// </summary>
    [Fact]
    public void OutboundTrafficNoRuleClaimsIsLeftAlone()
    {
        var wiring = NewMesh();
        wiring.ApplyRules([Rule("203.0.113.0/24", PeerEgressRules.ActionEgress, 2)]);

        Assert.False(wiring.HandleOutbound(PacketTo("8.8.8.8")),
            "an unclaimed destination was swallowed");
    }

    /// <summary>
    /// A destination a rule claims is this layer's, even when the egress cannot take it. Handing it
    /// back would send it out locally, which is the leak the whole feature exists to prevent.
    /// </summary>
    [Fact]
    public void OutboundTrafficARuleClaimsIsNotHandedBack()
    {
        var wiring = NewMesh();
        wiring.ApplyRules([Rule("203.0.113.0/24", PeerEgressRules.ActionEgress, 2)]);

        Assert.True(wiring.HandleOutbound(PacketTo("203.0.113.10")),
            "a claimed destination was handed back");
    }

    /// <summary>
    /// An unreachable egress still claims the packet. Handing it back would send it out locally,
    /// from the address the user arranged for it not to come from, which is worse than the
    /// connection failing because it fails silently.
    /// </summary>
    [Fact]
    public void OutboundTrafficIsStillClaimedWhenTheEgressCannotBeReached()
    {
        var wiring = NewMesh();
        wiring.ApplyRules([Rule("203.0.113.0/24", PeerEgressRules.ActionEgress, 2)]);
        wiring.SyncEgressAvailability(new Dictionary<long, bool> { [2] = true });
        _reachable = false;

        Assert.True(wiring.HandleOutbound(PacketTo("203.0.113.10")),
            "an unreachable egress handed the packet back to the local stack");
        Assert.True(Frames().Count == 0, "a frame was sent to an unreachable peer");
    }

    /// <summary>
    /// An egress going offline closes its flows and tells it to drop its side, so the user does not
    /// see a connection that is dead at one end and open at the other.
    /// </summary>
    [Fact]
    public void AnEgressGoingOfflinePurgesItsFlows()
    {
        var wiring = NewMesh();
        wiring.ApplyRules([Rule("203.0.113.0/24", PeerEgressRules.ActionEgress, 2)]);
        wiring.SyncEgressAvailability(new Dictionary<long, bool> { [2] = true });
        Assert.True(wiring.HandleOutbound(PacketTo("203.0.113.10")));

        ClearFrames();
        wiring.SyncEgressAvailability(new Dictionary<long, bool> { [2] = false });

        // The purge is queued like every other frame, so it arrives on the send loop rather than
        // inline: waiting is the difference between testing the wiring and testing the scheduler.
        WaitFor("the flow-purge to be sent", () => Frames().Exists(raw =>
        {
            var frame = PeerEgressFrame.Parse(raw);
            if (!frame.Accepted || frame.Type != PeerEgressFrame.TypeControl)
            {
                return false;
            }
            var control = PeerEgressFrame.DecodeControl(frame.Body);
            return control is not null
                && control.Type == PeerEgressFrame.ControlFlowPurge
                && control.Destinations.Contains("203.0.113.10/32");
        }));
    }

    /// <summary>Revocation reaches the plane even though the plane never asks the mesh anything.</summary>
    [Fact]
    public void AClosingSessionRevokesThatPeersFlows()
    {
        var wiring = NewMesh();
        wiring.ApplyEgressConfig(ConfigFor(1, "203.0.113.0/24"));
        wiring.HandleInboundFrame(7, SynTo("203.0.113.10"));
        WaitFor("the flow to open", () => Frames().Count > 0);

        ClearFrames();
        wiring.RevokeConsumer(7);

        WaitFor("the revoked consumer to be told", () => Frames().Exists(raw =>
        {
            var frame = PeerEgressFrame.Parse(raw);
            return frame.Accepted && frame.Type == PeerEgressFrame.TypeControl;
        }));
    }

    /// <summary>Closing has to stop forwarding, not merely ask it to stop.</summary>
    [Fact]
    public void ClosingStopsForwarding()
    {
        var wiring = NewMesh();
        wiring.ApplyEgressConfig(ConfigFor(1, "203.0.113.0/24"));
        wiring.HandleInboundFrame(7, SynTo("203.0.113.10"));
        WaitFor("the flow to open", () => Frames().Count > 0);

        wiring.Dispose();
        ClearFrames();

        wiring.HandleInboundFrame(7, SynTo("203.0.113.11"));
        // A shut-down plane refuses rather than opening, so whatever it says must not be a SYN-ACK.
        Assert.False(Frames().Exists(raw =>
        {
            var frame = PeerEgressFrame.Parse(raw);
            if (!frame.Accepted || frame.Type != PeerEgressFrame.TypeIpPacket)
            {
                return false;
            }
            return PeerEgressSegment.Parse(frame.Body) is { } segment
                && segment.Has(PeerEgressSegment.FlagSyn) && segment.Has(PeerEgressSegment.FlagAck);
        }), "a shut-down node completed a handshake");
    }
}
