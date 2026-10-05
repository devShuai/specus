using System.Text.Json;
using System.Text.RegularExpressions;
using Specus.Client.Cli;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// What a consumer makes of an egress its rules name once the catalogue can speak for it, bound to
/// <c>peer-egress-standing-v1.json</c> (protocol/spec/peer-egress.md, 能力不支持): the standing, whether
/// a flow goes out, the counter a blocked one moves and the answer the application gets, the purge
/// when a standing turns, how long the status waits before saying the server sent no catalogue, and
/// the lines a person reads about it.
/// </summary>
/// <remarks>
/// Every vector case is replayed with real packets through the consumer itself -- for an address
/// rule and for a domain rule steered through the fake-IP pool -- and once more through the mesh,
/// where the catalogue arrives as the JSON the server pushes and every frame and answer leaves
/// through the real queues.
/// </remarks>
public sealed class PeerEgressStandingVectorTests : IDisposable
{
    private const long Epoch = 1_800_000_000_000L;
    private const string ConsumerIp = "100.96.0.7";
    private const long Egress = 2;

    /// <summary>Another egress, so a catalogue that leaves <see cref="Egress"/> out still lists something.</summary>
    private const long OtherEgress = 9;

    private const string Destination = "203.0.113.10";

    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "specus-egress-standing-" + Guid.NewGuid().ToString("N"));

    private readonly List<PeerEgressMesh> _meshes = [];

    public void Dispose()
    {
        foreach (var mesh in _meshes)
        {
            mesh.Dispose();
        }
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
            // A leftover temp directory is not worth failing a test over.
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private static string RepositoryFile(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine([directory.FullName, .. parts]);
            if (File.Exists(candidate))
            {
                return candidate;
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate " + string.Join("/", parts));
    }

    private static JsonDocument Vector() =>
        JsonDocument.Parse(File.ReadAllText(RepositoryFile("protocol", "test-vectors", "peer-egress-standing-v1.json")));

    private static List<JsonElement> Cases(JsonDocument vector) =>
        [.. vector.RootElement.GetProperty("cases").EnumerateArray()];

    private static string Name(JsonElement testCase) => testCase.GetProperty("name").GetString()!;

    private static bool Online(JsonElement testCase) => testCase.GetProperty("online").GetBoolean();

    private static bool Received(JsonElement testCase) => testCase.GetProperty("catalogReceived").GetBoolean();

    private static bool Listed(JsonElement testCase) => testCase.GetProperty("listed").GetBoolean();

    private static long? Version(JsonElement testCase) =>
        testCase.TryGetProperty("egressVersion", out var version) ? version.GetInt64() : null;

    private static string Standing(JsonElement testCase) => testCase.GetProperty("standing").GetString()!;

    private static string? Blocked(JsonElement testCase) =>
        testCase.GetProperty("blocked") is { ValueKind: JsonValueKind.String } reason ? reason.GetString() : null;

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    private static PeerEgressRule Rule(string match, long egress) =>
        new() { Match = match, Action = PeerEgressRules.ActionEgress, EgressClientId = egress };

    private static byte[] Tcp(string destination, ushort sourcePort, int flags) =>
        PeerEgressSegment.Build(new PeerEgressSegment.Segment(Address(ConsumerIp), Address(destination), sourcePort, 443,
            1000, (flags & PeerEgressSegment.FlagAck) != 0 ? 2000u : 0u, flags, 65535, 0, []));

    private static byte[] Syn(string destination, ushort sourcePort = 40000) =>
        Tcp(destination, sourcePort, PeerEgressSegment.FlagSyn);

    private static byte[] Udp(string destination, ushort sourcePort = 50000) =>
        PeerEgressDatagram.Build(new PeerEgressDatagram.Datagram(Address(ConsumerIp), Address(destination), sourcePort, 443,
            "datagram"u8.ToArray()));

    /// <summary>
    /// The catalogue a case describes, as the consumer decides by it.
    /// </summary>
    /// <remarks>
    /// Not listed is a catalogue that lists another egress rather than an empty one, so an egress
    /// being left out is what is tested and not an empty list. With no catalogue in this session and
    /// <paramref name="capable"/>, the egress was listed as resolving names by an earlier session's
    /// catalogue: what was learned about names survives the session, the standing does not.
    /// </remarks>
    private static PeerEgressCatalogSnapshot Catalog(JsonElement testCase, bool capable)
    {
        var listed = new Dictionary<long, PeerEgressCatalogListing> { [OtherEgress] = new(true, 1) };
        if (Listed(testCase))
        {
            listed[Egress] = new PeerEgressCatalogListing(capable, Version(testCase));
        }
        else if (!Received(testCase) && capable)
        {
            listed[Egress] = new PeerEgressCatalogListing(true, null);
        }
        return new PeerEgressCatalogSnapshot(Received(testCase), listed);
    }

    /// <summary>The same catalogue as the JSON a server pushes.</summary>
    private static string CatalogJson(long revision, JsonElement testCase)
    {
        var entries = new List<string> { $"{{\"clientId\":{OtherEgress},\"online\":true,\"egressVersion\":1}}" };
        if (Listed(testCase))
        {
            entries.Add(Version(testCase) is { } version
                ? $"{{\"clientId\":{Egress},\"online\":true,\"egressVersion\":{version}}}"
                : $"{{\"clientId\":{Egress},\"online\":true}}");
        }
        return $"{{\"type\":\"egress-catalog\",\"revision\":{revision},\"egresses\":[{string.Join(",", entries)}]}}";
    }

    // ----------------------------------------------------------------------------------------------
    // The decision
    // ----------------------------------------------------------------------------------------------

    [Fact]
    public void TheWaitIsTheSharedVectors()
    {
        using var vector = Vector();
        var wait = PeerEgressCatalog.CatalogWaitMs;
        Assert.Equal(vector.RootElement.GetProperty("catalogWaitSeconds").GetInt64() * 1000, wait);
    }

    [Fact]
    public void StandingMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in Cases(vector))
        {
            var standing = PeerEgressStanding.Of(Received(testCase), Listed(testCase), Version(testCase));
            Assert.True(Standing(testCase) == standing, $"{Name(testCase)}: {standing}");
            // The snapshot the consumer holds reads the same standing.
            Assert.True(Standing(testCase) == Catalog(testCase, capable: true).StandingOf(Egress), $"{Name(testCase)}: snapshot");
        }
    }

    /// <summary>
    /// Each case through the consumer with an address rule: a SYN and a datagram either both go to
    /// the egress, or both are counted under the case's reason and answered -- a reset, an ICMP
    /// unreachable -- with nothing sent. The status reports the case's standing for the egress.
    /// </summary>
    [Fact]
    public void EveryCaseThroughTheConsumerForAnAddressRule()
    {
        using var vector = Vector();
        foreach (var testCase in Cases(vector))
        {
            var label = Name(testCase);
            var sent = new List<(long Egress, byte[] Frame)>();
            var tun = new List<byte[]>();
            var consumer = new PeerEgressConsumer((egress, frame) =>
            {
                sent.Add((egress, frame));
                return true;
            }, tun.Add);
            Assert.Empty(consumer.Configure([Rule("203.0.113.0/24", Egress)], PeerEgressRules.DefaultMeshCidr, ConsumerIp, Epoch));
            consumer.SetEgressOnline(Egress, Online(testCase), Epoch);
            Assert.Empty(consumer.SetCatalog(Catalog(testCase, capable: false), Epoch));
            Assert.Equal(Standing(testCase), consumer.StandingOf(Egress));

            var packets = new[] { Syn(Destination), Udp(Destination) };
            var outcomes = packets.Select(packet => consumer.HandleOutbound(packet, Epoch)).ToList();
            ExpectDecision(label, Blocked(testCase), packets, outcomes, sent, tun, consumer.BlockedCounts(), nameBinds: false);

            var status = JsonSerializer.SerializeToElement(PeerEgressStatus.Section(consumer.StatusSnapshot(Epoch), [],
                PeerEgressApplyOutcome.None, null));
            var peer = Assert.Single(status.GetProperty("consumer").GetProperty("peers").EnumerateArray());
            Assert.Equal(Egress, peer.GetProperty("clientId").GetInt64());
            Assert.True(Online(testCase) == peer.GetProperty("online").GetBoolean(), label);
            Assert.True(Standing(testCase) == peer.GetProperty("standing").GetString(), $"{label}: status {peer.GetProperty("standing")}");
        }
    }

    /// <summary>
    /// Each case through the fake-IP pool with a domain rule, with the egress resolving names and
    /// without. The standing is decided before the domain capability: a blocked case keeps its own
    /// reason either way, and a case that sends goes out only to an egress that resolves names,
    /// otherwise it is <c>egress-no-domain</c>.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void EveryCaseThroughTheConsumerForADomainRule(bool capable)
    {
        using var vector = Vector();
        foreach (var testCase in Cases(vector))
        {
            var label = $"{Name(testCase)} capable={capable}";
            var sent = new List<(long Egress, byte[] Frame)>();
            var tun = new List<byte[]>();
            var pool = new PeerEgressFakeIpPool(Cidr("198.18.0.0/29"), () => Epoch);
            var consumer = new PeerEgressConsumer((egress, frame) =>
            {
                sent.Add((egress, frame));
                return true;
            }, tun.Add);
            Assert.Empty(consumer.Configure([Rule("example.com", Egress)], PeerEgressRules.DefaultMeshCidr, ConsumerIp, Epoch, pool));
            consumer.SetEgressOnline(Egress, Online(testCase), Epoch);
            consumer.SetCatalog(Catalog(testCase, capable), Epoch);
            var address = Ipv4Cidr.FormatAddress(pool.Query("example.com", Epoch).Address);

            var packets = new[] { Syn(address), Udp(address) };
            var outcomes = packets.Select(packet => consumer.HandleOutbound(packet, Epoch)).ToList();
            var expected = Blocked(testCase) ?? (capable ? null : "egress-no-domain");
            ExpectDecision(label, expected, packets, outcomes, sent, tun, consumer.BlockedCounts(), nameBinds: true);
        }
    }

    /// <summary>
    /// Each case through the mesh: the rules through a reconcile, availability from the host, the
    /// catalogue as the server's JSON, and every frame and answer through the real queues. No
    /// catalogue in this session is reached the way it is in the client: a session that had one
    /// which did not list the egress ends, and the next has not had one yet.
    /// </summary>
    [Fact]
    public void EveryCaseThroughTheMesh()
    {
        using var vector = Vector();
        foreach (var testCase in Cases(vector))
        {
            var label = Name(testCase);
            var (mesh, host) = Mesh(new Dictionary<long, bool> { [Egress] = Online(testCase) });
            mesh.ApplyRules([Rule("203.0.113.0/24", Egress)]);
            if (Received(testCase))
            {
                mesh.ApplyEgressCatalog(CatalogJson(1, testCase));
            }
            else
            {
                mesh.ApplyEgressCatalog(
                    $"{{\"type\":\"egress-catalog\",\"revision\":5,\"egresses\":[{{\"clientId\":{OtherEgress},\"egressVersion\":1}}]}}");
                mesh.NewControlSession();
            }

            var packets = new[] { Syn(Destination), Udp(Destination) };
            foreach (var packet in packets)
            {
                Assert.True(mesh.HandleOutbound(packet), $"{label}: the consumer did not claim a destination its rule covers");
            }
            var blocked = Blocked(testCase);
            host.Settle(blocked is null ? 2 : 0, blocked is null ? 0 : 2);
            var consumer = JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer");
            var counts = consumer.GetProperty("blocked").EnumerateObject().ToDictionary(entry => entry.Name, entry => entry.Value.GetInt64());
            var sent = host.SentSnapshot();
            var device = host.DeviceSnapshot();
            if (blocked is null)
            {
                Assert.True(sent.Count == 2 && sent.All(frame => frame.Egress == Egress), $"{label}: sent {sent.Count}");
                for (var index = 0; index < packets.Length; index++)
                {
                    Assert.Equal(packets[index], PeerEgressFrame.Parse(sent[index].Frame).Body);
                }
                Assert.True(device.Count == 0 && counts.Count == 0, $"{label}: blocked {JsonSerializer.Serialize(counts)}");
            }
            else
            {
                Assert.True(sent.Count == 0, $"{label}: a blocked packet was sent");
                Assert.True(counts.Count == 1 && counts.GetValueOrDefault(blocked) == 2, $"{label}: blocked {JsonSerializer.Serialize(counts)}");
                ExpectAnswers(label, packets, device);
            }
            var peer = Assert.Single(consumer.GetProperty("peers").EnumerateArray());
            Assert.True(Standing(testCase) == peer.GetProperty("standing").GetString(), $"{label}: status {peer.GetProperty("standing")}");
            // A catalogue in this session says received; a new session has only just started waiting.
            Assert.True((Received(testCase) ? "received" : "waiting") == consumer.GetProperty("catalog").GetString(), label);
        }
    }

    /// <summary>
    /// What one replay of two packets has to show: forwarded, both to the egress (each after its
    /// name-bind on the domain path), nothing counted and nothing answered; or blocked, nothing sent,
    /// the reason counted twice and nothing else, and each packet answered.
    /// </summary>
    private static void ExpectDecision(string label, string? blocked, byte[][] packets, List<PeerEgressConsumerOutcome> outcomes,
        List<(long Egress, byte[] Frame)> sent, List<byte[]> tun, IReadOnlyDictionary<string, long> counts, bool nameBinds)
    {
        if (blocked is null)
        {
            Assert.True(outcomes.All(outcome => outcome == PeerEgressConsumerOutcome.Forwarded), $"{label}: {string.Join(",", outcomes)}");
            var perPacket = nameBinds ? 2 : 1;
            Assert.True(sent.Count == packets.Length * perPacket && sent.All(frame => frame.Egress == Egress), $"{label}: sent {sent.Count}");
            for (var index = 0; index < packets.Length; index++)
            {
                var carried = PeerEgressFrame.Parse(sent[index * perPacket + perPacket - 1].Frame);
                Assert.True(carried.Accepted && carried.Type == PeerEgressFrame.TypeIpPacket, $"{label}: packet frame");
                Assert.Equal(packets[index], carried.Body);
                if (nameBinds)
                {
                    var binding = PeerEgressFrame.DecodeControl(PeerEgressFrame.Parse(sent[index * perPacket].Frame).Body);
                    Assert.True(binding is { Type: PeerEgressFrame.ControlNameBind, Name: "example.com" }, $"{label}: name-bind");
                }
            }
            Assert.True(tun.Count == 0 && counts.Count == 0, $"{label}: blocked {JsonSerializer.Serialize(counts)}");
            return;
        }
        Assert.True(outcomes.All(outcome => outcome == PeerEgressConsumerOutcome.BlockedNoEgress), $"{label}: {string.Join(",", outcomes)}");
        Assert.True(sent.Count == 0, $"{label}: a blocked packet was sent");
        Assert.True(counts.Count == 1 && counts.GetValueOrDefault(blocked) == packets.Length,
            $"{label}: expected {blocked}, counted {JsonSerializer.Serialize(counts)}");
        ExpectAnswers(label, packets, tun);
    }

    /// <summary>A reset answering the SYN and an ICMP unreachable answering the datagram, in order.</summary>
    private static void ExpectAnswers(string label, byte[][] packets, List<byte[]> answers)
    {
        Assert.True(answers.Count == packets.Length, $"{label}: {answers.Count} answers");
        var reset = PeerEgressSegment.Parse(answers[0]);
        Assert.True(reset is not null && reset.Has(PeerEgressSegment.FlagRst), $"{label}: the SYN was not answered with a reset");
        Assert.Equal(PeerIpPacket.DestinationIPv4(packets[0]), Ipv4Cidr.FormatAddress(reset!.SourceIp));
        Assert.Equal(ConsumerIp, Ipv4Cidr.FormatAddress(reset.DestinationIp));
        Assert.True(answers[1][9] == 1, $"{label}: the datagram was not answered with ICMP");
        Assert.Equal(ConsumerIp, PeerIpPacket.DestinationIPv4(answers[1]));
    }

    // ----------------------------------------------------------------------------------------------
    // Purges
    // ----------------------------------------------------------------------------------------------

    /// <summary>
    /// A standing that turns blocking closes the egress's flows the way its going offline does: the
    /// purge names them, an acknowledged TCP flow is reset, and the next packet on it is blocked
    /// under the standing's reason. Turning back to unknown, as a new session does, purges nothing.
    /// </summary>
    [Theory]
    [InlineData("unsupported", "egress-unsupported")]
    [InlineData("not-offered", "egress-not-offered")]
    public void AStandingTurningBlockingPurgesTheEgressFlows(string turnsTo, string reason)
    {
        var tun = new List<byte[]>();
        var sent = 0;
        var consumer = new PeerEgressConsumer((_, _) =>
        {
            sent++;
            return true;
        }, tun.Add);
        consumer.Configure([Rule("203.0.113.0/24", Egress), Rule("198.51.100.0/24", OtherEgress)],
            PeerEgressRules.DefaultMeshCidr, ConsumerIp, Epoch);
        consumer.SetEgressOnline(Egress, true, Epoch);
        consumer.SetEgressOnline(OtherEgress, true, Epoch);
        var offered = new Dictionary<long, PeerEgressCatalogListing> { [Egress] = new(false, 1), [OtherEgress] = new(false, 1) };
        Assert.Empty(consumer.SetCatalog(new PeerEgressCatalogSnapshot(true, offered), Epoch));
        var acknowledged = Tcp(Destination, 40000, PeerEgressSegment.FlagAck);
        foreach (var packet in new[] { Syn(Destination), acknowledged, Udp(Destination), Syn("198.51.100.20") })
        {
            Assert.Equal(PeerEgressConsumerOutcome.Forwarded, consumer.HandleOutbound(packet, Epoch));
        }
        Assert.Equal(4, sent);

        var turned = new Dictionary<long, PeerEgressCatalogListing>(offered);
        if (turnsTo == "unsupported")
        {
            turned[Egress] = new PeerEgressCatalogListing(false, 0);
        }
        else
        {
            turned.Remove(Egress);
        }
        var purge = consumer.SetCatalog(new PeerEgressCatalogSnapshot(true, turned), Epoch + 1);
        Assert.Equal(turnsTo, consumer.StandingOf(Egress));
        // Only the egress whose standing turned, and its one destination, carried by two flows.
        Assert.Equal([Egress], purge.Keys);
        Assert.Equal(["203.0.113.10/32"], purge[Egress]);
        var reset = PeerEgressSegment.Parse(Assert.Single(tun));
        Assert.True(reset is not null && reset.Has(PeerEgressSegment.FlagRst), "the acknowledged flow was not reset");
        Assert.Equal(1, consumer.StatusSnapshot(Epoch + 1).Flows);

        Assert.Equal(PeerEgressConsumerOutcome.BlockedNoEgress, consumer.HandleOutbound(acknowledged, Epoch + 2));
        Assert.Equal(1, consumer.BlockedCounts()[reason]);
        Assert.Equal(4, sent);

        // A new session: no catalogue yet, every standing unknown. That blocks nothing, so it closes
        // nothing, and the egress takes flows again.
        Assert.Empty(consumer.SetCatalog(new PeerEgressCatalogSnapshot(false, turned), Epoch + 3));
        Assert.Equal(PeerEgressStanding.Unknown, consumer.StandingOf(Egress));
        Assert.Equal(PeerEgressConsumerOutcome.Forwarded, consumer.HandleOutbound(Syn(Destination, 40001), Epoch + 3));
    }

    /// <summary>The same for a flow steered by name: its pool address is purged.</summary>
    [Fact]
    public void AStandingTurningBlockingPurgesFlowsSteeredByName()
    {
        var consumer = new PeerEgressConsumer((_, _) => true, _ => { });
        var pool = new PeerEgressFakeIpPool(Cidr("198.18.0.0/29"), () => Epoch);
        consumer.Configure([Rule("example.com", Egress)], PeerEgressRules.DefaultMeshCidr, ConsumerIp, Epoch, pool);
        consumer.SetEgressOnline(Egress, true, Epoch);
        consumer.SetCatalog(new PeerEgressCatalogSnapshot(true,
            new Dictionary<long, PeerEgressCatalogListing> { [Egress] = new(true, 1) }), Epoch);
        var address = Ipv4Cidr.FormatAddress(pool.Query("example.com", Epoch).Address);
        Assert.Equal(PeerEgressConsumerOutcome.Forwarded, consumer.HandleOutbound(Syn(address), Epoch));

        var purge = consumer.SetCatalog(new PeerEgressCatalogSnapshot(true,
            new Dictionary<long, PeerEgressCatalogListing> { [Egress] = new(true, 0) }), Epoch + 1);
        Assert.Equal([address + "/32"], purge[Egress]);
        Assert.Equal(PeerEgressConsumerOutcome.BlockedNoEgress, consumer.HandleOutbound(Syn(address, 40001), Epoch + 2));
        Assert.Equal(1, consumer.BlockedCounts()["egress-unsupported"]);
        Assert.False(consumer.BlockedCounts().ContainsKey("egress-no-domain"));
    }

    /// <summary>Through the mesh the purge leaves as a flow-purge frame to the egress.</summary>
    [Fact]
    public void TheMeshSendsThePurgeWhenACatalogueTurnsTheStanding()
    {
        var (mesh, host) = Mesh(new Dictionary<long, bool> { [Egress] = true });
        mesh.ApplyRules([Rule("203.0.113.0/24", Egress)]);
        mesh.ApplyEgressCatalog($"{{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":[{{\"clientId\":{Egress},\"egressVersion\":1}}]}}");
        Assert.True(mesh.HandleOutbound(Syn(Destination)));
        host.Settle(1, 0);

        mesh.ApplyEgressCatalog($"{{\"type\":\"egress-catalog\",\"revision\":2,\"egresses\":[{{\"clientId\":{Egress},\"egressVersion\":0}}]}}");
        host.Settle(2, 0);
        var (egress, frame) = host.SentSnapshot()[^1];
        Assert.Equal(Egress, egress);
        var parsed = PeerEgressFrame.Parse(frame);
        Assert.True(parsed.Accepted && parsed.Type == PeerEgressFrame.TypeControl);
        var control = PeerEgressFrame.DecodeControl(parsed.Body)!;
        Assert.Equal(PeerEgressFrame.ControlFlowPurge, control.Type);
        Assert.Equal(["203.0.113.10/32"], control.Destinations);
        var peer = Assert.Single(JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer").GetProperty("peers").EnumerateArray());
        Assert.Equal("unsupported", peer.GetProperty("standing").GetString());
        Assert.Equal(0, peer.GetProperty("flows").GetInt32());
    }

    // ----------------------------------------------------------------------------------------------
    // consumer.catalog
    // ----------------------------------------------------------------------------------------------

    /// <summary>
    /// <c>waiting</c> before the control session authenticates and for 30 seconds after, <c>none</c>
    /// from then on, <c>received</c> once a catalogue is accepted. A new session waits again, from
    /// its own authentication.
    /// </summary>
    [Fact]
    public void TheStatusSaysWhenTheServerSentNoCatalogue()
    {
        var now = Epoch;
        var (mesh, _) = Mesh(new Dictionary<long, bool> { [Egress] = true }, () => now);
        mesh.ApplyRules([Rule("203.0.113.0/24", Egress)]);
        string Catalog() => JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer").GetProperty("catalog").GetString()!;

        Assert.Equal("waiting", Catalog());
        now += 60_000;
        Assert.Equal("waiting", Catalog());

        mesh.ControlAuthenticated();
        now += PeerEgressCatalog.CatalogWaitMs - 1;
        Assert.Equal("waiting", Catalog());
        now += 1;
        Assert.Equal("none", Catalog());
        var lines = EgressView.Lines(JsonSerializer.SerializeToElement(mesh.Status()));
        Assert.Single(lines, line => line.StartsWith("    server: ", StringComparison.Ordinal));

        mesh.ApplyEgressCatalog($"{{\"type\":\"egress-catalog\",\"revision\":3,\"egresses\":[{{\"clientId\":{Egress},\"egressVersion\":1}}]}}");
        Assert.Equal("received", Catalog());
        now += 3_600_000;
        Assert.Equal("received", Catalog());

        mesh.NewControlSession();
        Assert.Equal("waiting", Catalog());
        mesh.ControlAuthenticated();
        now += PeerEgressCatalog.CatalogWaitMs;
        Assert.Equal("none", Catalog());
        // A catalogue at a revision the last session had already passed is this session's first.
        mesh.ApplyEgressCatalog($"{{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":[{{\"clientId\":{Egress},\"egressVersion\":1}}]}}");
        Assert.Equal("received", Catalog());
    }

    /// <summary>
    /// The status carries the two new reasons as counters like every other, and each peer's
    /// standing next to whether it is online.
    /// </summary>
    [Fact]
    public void TheStatusCountsBothNewReasonsAndNamesEachStanding()
    {
        var (mesh, host) = Mesh(new Dictionary<long, bool> { [Egress] = true, [OtherEgress] = true, [5] = false });
        mesh.ApplyRules([Rule("203.0.113.0/24", Egress), Rule("198.51.100.0/24", OtherEgress), Rule("192.0.2.0/24", 5)]);
        mesh.ApplyEgressCatalog($"{{\"type\":\"egress-catalog\",\"revision\":1,\"egresses\":[{{\"clientId\":{OtherEgress},\"egressVersion\":0}}]}}");
        Assert.True(mesh.HandleOutbound(Syn(Destination)));
        Assert.True(mesh.HandleOutbound(Syn("198.51.100.20")));
        Assert.True(mesh.HandleOutbound(Udp("198.51.100.20")));
        Assert.True(mesh.HandleOutbound(Syn("192.0.2.30")));
        host.Settle(0, 4);

        var consumer = JsonSerializer.SerializeToElement(mesh.Status()).GetProperty("consumer");
        var blocked = consumer.GetProperty("blocked");
        Assert.Equal(1, blocked.GetProperty("egress-not-offered").GetInt64());
        Assert.Equal(2, blocked.GetProperty("egress-unsupported").GetInt64());
        Assert.Equal(1, blocked.GetProperty("egress-unavailable").GetInt64());
        var peers = consumer.GetProperty("peers").EnumerateArray()
            .ToDictionary(peer => peer.GetProperty("clientId").GetInt64(), peer => peer);
        Assert.Equal("not-offered", peers[Egress].GetProperty("standing").GetString());
        Assert.Equal("unsupported", peers[OtherEgress].GetProperty("standing").GetString());
        // Offline and not listed: the standing is reported, the problem is that it is offline.
        Assert.False(peers[5].GetProperty("online").GetBoolean());
        Assert.Equal("not-offered", peers[5].GetProperty("standing").GetString());
        Assert.Equal(["clientId", "online", "standing", "path", "flows"],
            peers[Egress].EnumerateObject().Select(field => field.Name));
        Assert.Equal("received", consumer.GetProperty("catalog").GetString());
    }

    // ----------------------------------------------------------------------------------------------
    // What a person reads
    // ----------------------------------------------------------------------------------------------

    /// <summary>The two-line problems as protocol/spec/peer-egress.md pins them, for one egress id.</summary>
    private static List<string> PinnedLines(long id)
    {
        var spec = File.ReadAllText(RepositoryFile("protocol", "spec", "peer-egress.md")).Replace("\r\n", "\n");
        var section = spec[spec.IndexOf("### 能力不支持", StringComparison.Ordinal)..];
        var start = section.IndexOf("```text\n", StringComparison.Ordinal) + "```text\n".Length;
        var block = section[start..section.IndexOf("\n```", start, StringComparison.Ordinal)];
        return [.. block.Split('\n').Select(line => Regex.Replace(line, @"\bN\b", id.ToString(System.Globalization.CultureInfo.InvariantCulture)))];
    }

    /// <summary>
    /// The lines, byte for byte as the spec pins them, in the pinned order: offline, not offered,
    /// unsupported, no path, one per egress and the first that holds; the server line once, only
    /// while <c>catalog</c> is <c>none</c>.
    /// </summary>
    [Fact]
    public void TheViewPrintsThePinnedLinesInThePinnedOrder()
    {
        var pinned = PinnedLines(42);
        Assert.Equal(6, pinned.Count);
        string State(string catalog) => $$$"""
            {"consumer": {"active": true, "flows": 0, "catalog": "{{{catalog}}}",
              "rules": [{"index": 0, "match": "203.0.113.0/24", "action": "egress", "egressClientId": 41, "inForce": true}],
              "routes": [],
              "peers": [{"clientId": 41, "online": false, "standing": "not-offered", "path": "none", "flows": 0},
                        {"clientId": 42, "online": true, "standing": "not-offered", "path": "none", "flows": 0},
                        {"clientId": 43, "online": true, "standing": "unsupported", "path": "none", "flows": 0},
                        {"clientId": 44, "online": true, "standing": "offered", "path": "none", "flows": 0},
                        {"clientId": 45, "online": true, "standing": "unknown", "path": "direct", "flows": 0},
                        {"clientId": 46, "online": true, "standing": "offered", "path": "relay", "flows": 0}],
              "blocked": {"egress-not-offered": 3, "egress-unsupported": 1}},
             "egress": {"active": false}}
            """;
        using var none = JsonDocument.Parse(State("none"));
        var lines = EgressView.Lines(none.RootElement);
        var problems = lines.Skip(1).TakeWhile(line => !line.StartsWith("    blocked: ", StringComparison.Ordinal)).ToList();
        List<string> expected =
        [
            "    egress peer 41: offline, so its rules have nowhere to send",
            "      fix: start egress device 41 or restore its connection; until then its destinations are blocked, not sent locally",
            pinned[0], pinned[1],
            .. PinnedLines(43)[2..4],
            "    egress peer 44: online but no path to it yet",
            "      fix: wait for a direct or relay path; if it lasts, check that both devices reach the server over UDP",
            pinned[4], pinned[5],
        ];
        Assert.Equal(expected, problems);
        Assert.Equal("  consumer: 1 rules (0 not in force) | 0 routes (0 not installed) | 0 flows | 6 egress peers (1 offline, 1 via relay)", lines[0]);
        Assert.Contains("    blocked: egress-not-offered=3, egress-unsupported=1", lines);

        foreach (var catalog in new[] { "waiting", "received", "" })
        {
            using var other = JsonDocument.Parse(State(catalog));
            Assert.DoesNotContain(EgressView.Lines(other.RootElement), line => line.StartsWith("    server: ", StringComparison.Ordinal));
        }
        // A state file from a build that knew no standing reads as before: offline and no path only.
        using var older = JsonDocument.Parse("""
            {"consumer": {"active": true, "rules": [], "routes": [],
              "peers": [{"clientId": 42, "online": true, "path": "direct", "flows": 0}]},
             "egress": {"active": false}}
            """);
        Assert.DoesNotContain(EgressView.Lines(older.RootElement), line => line.StartsWith("    egress peer ", StringComparison.Ordinal));
    }

    // ----------------------------------------------------------------------------------------------
    // Mesh harness
    // ----------------------------------------------------------------------------------------------

    private static Ipv4Cidr Cidr(string text)
    {
        Assert.True(Ipv4Cidr.TryParse(text, out var value), $"{text} did not parse");
        return value;
    }

    private (PeerEgressMesh Mesh, Host Host) Mesh(Dictionary<long, bool> availability, Func<long>? clock = null)
    {
        var directory = Path.Combine(_directory, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var host = new Host(directory) { EgressAvailability = availability };
        var mesh = new PeerEgressMesh(host, dialer: new RefusingDialer(), commander: new AcceptingCommander(),
            catalogClock: clock);
        _meshes.Add(mesh);
        return (mesh, host);
    }

    private sealed class Host(string directory) : IPeerEgressMeshHost
    {
        private readonly List<(long, byte[])> _sent = [];
        private readonly List<byte[]> _device = [];

        public IReadOnlyDictionary<long, bool> EgressAvailability { get; set; } = new Dictionary<long, bool>();

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame)
        {
            lock (_sent)
            {
                _sent.Add((peerId, (byte[])frame.Clone()));
            }
            return Task.FromResult(true);
        }

        public Task WriteToDeviceAsync(byte[] packet)
        {
            lock (_device)
            {
                _device.Add((byte[])packet.Clone());
            }
            return Task.CompletedTask;
        }

        public List<(long Egress, byte[] Frame)> SentSnapshot()
        {
            lock (_sent)
            {
                return [.. _sent];
            }
        }

        public List<byte[]> DeviceSnapshot()
        {
            lock (_device)
            {
                return [.. _device];
            }
        }

        /// <summary>
        /// Waits until at least this much has been delivered, then a moment more so that anything
        /// delivered beyond it is seen too.
        /// </summary>
        public void Settle(int sent, int device)
        {
            var deadline = DateTime.UtcNow.AddSeconds(5);
            while ((SentSnapshot().Count < sent || DeviceSnapshot().Count < device) && DateTime.UtcNow < deadline)
            {
                Thread.Sleep(5);
            }
            Thread.Sleep(50);
        }

        public string TunName => "specus0";

        public string MeshCidr => PeerEgressRules.DefaultMeshCidr;

        public string VirtualIp => ConsumerIp;

        public IReadOnlyList<string> DeploymentDenyCidrs() => [];

        public IReadOnlyList<string> PeerEndpointAddresses() => [];

        public int? PathMtuForPeer(long peerId) => null;

        public string? RouteJournalPath => Path.Combine(directory, "egress-routes.json");
    }

    private sealed class AcceptingCommander : IPeerEgressRouteCommander
    {
        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) => PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
        }

        public void Remove(PeerEgressRoute route)
        {
        }
    }

    private sealed class RefusingDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) =>
            throw new IOException("nothing is dialled in this test");
    }
}
