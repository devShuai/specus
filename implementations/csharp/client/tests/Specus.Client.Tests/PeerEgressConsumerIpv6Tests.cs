using System.Text.Json;
using Specus.Client.Cli;
using Specus.Client.Configuration;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// The consumer side of the IPv6 data plane against protocol/test-vectors/peer-egress-ipv6-v1.json:
/// ruleValidation, consumerOutbound, returnPath and failure. The data plane is switched on in the
/// consumer directly, so these run on every platform the suite runs on whatever this build carries.
/// </summary>
public sealed class PeerEgressConsumerIpv6Tests
{
    private const long Epoch = 1_800_000_000_000L;
    private const long Egress = 2L;

    /// <summary>The rule every packet in the vector's consumer sections falls under.</summary>
    private static readonly PeerEgressRule TestRule = new()
    {
        Match = "2001:db8:1::/48", Action = PeerEgressRules.ActionEgress, EgressClientId = Egress,
    };

    /// <summary>A consumer with the IPv6 data plane, and what it sent and wrote.</summary>
    private sealed class Harness
    {
        public List<(long Egress, byte[] Frame)> Sent { get; } = [];
        public List<byte[]> ToTun { get; } = [];
        public PeerEgressConsumer Consumer { get; }

        public Harness(string meshIpv4, IReadOnlyList<PeerEgressRule> rules, bool online, bool capable)
        {
            Consumer = new PeerEgressConsumer(
                (egress, frame) =>
                {
                    Sent.Add((egress, (byte[])frame.Clone()));
                    return true;
                },
                packet => ToTun.Add((byte[])packet.Clone()));
            Consumer.Configure(rules, PeerEgressRules.DefaultMeshCidr, meshIpv4, Epoch, carriesIpv6: true);
            Consumer.SetCatalog(new PeerEgressCatalogSnapshot(true, new Dictionary<long, PeerEgressCatalogListing>
            {
                [Egress] = new(false, 1, capable),
            }), Epoch);
            Consumer.SetEgressOnline(Egress, online, Epoch);
        }

        public IReadOnlyDictionary<string, long> Blocked => Consumer.BlockedCounts();
    }

    private static JsonDocument Vector(string name = "peer-egress-ipv6-v1.json")
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
        }
        throw new FileNotFoundException(name);
    }

    private static byte[] Hex(JsonElement element, string property) =>
        Convert.FromHexString(element.GetProperty(property).GetString()!);

    private static string Text(byte[]? packet) => packet is null ? "" : Convert.ToHexString(packet).ToLowerInvariant();

    private static UInt128 Address6(string text)
    {
        Assert.True(Ipv6Cidr.TryParseAddress(text, out var address), text);
        return address;
    }

    private static UInt128 Derived(string meshIpv4)
    {
        Assert.True(PeerEgressMeshAddress.TryDerive(meshIpv4, out var address), meshIpv4);
        return address;
    }

    private static byte[] Segment6(UInt128 source, UInt128 destination, uint seq, uint ack, int flags, byte[]? payload = null) =>
        PeerEgressSegment.Build(new Segment(0, 0, 40000, 443, seq, ack, flags, 65535, 0, payload ?? [],
            Ipv6: true, SourceIp6: source, DestinationIp6: destination));

    private static byte[] Frame(byte[] packet) => PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false, packet);

    [Fact]
    public void RuleValidationMatchesTheSharedVector()
    {
        using var vector = Vector();
        var toARule = Hex(vector.RootElement.GetProperty("consumerOutbound").GetProperty("cases")[0], "packetHex");
        var cases = vector.RootElement.GetProperty("ruleValidation").GetProperty("cases").EnumerateArray().ToList();
        Assert.NotEmpty(cases);
        foreach (var testCase in cases)
        {
            var name = testCase.GetProperty("name").GetString();
            var rule = testCase.GetProperty("rule").Deserialize<PeerEgressRule>()!;
            var online = testCase.GetProperty("egressOnline").GetBoolean();
            var capable = testCase.GetProperty("egressIpv6PacketCapable").GetBoolean();
            var code = testCase.GetProperty("code");
            var want = code.ValueKind == JsonValueKind.Null ? null : code.GetString();
            Assert.True(want == PeerEgressRules.RuleStatus(rule, PeerEgressRules.DefaultMeshCidr, null,
                _ => online, _ => false, carriesIpv6: true, _ => capable), name);

            // The same answer from the status a running consumer publishes.
            var harness = new Harness("100.96.0.1", [rule], online, capable);
            var section = JsonSerializer.SerializeToElement(PeerEgressStatus.Section(
                harness.Consumer.StatusSnapshot(Epoch), [], PeerEgressApplyOutcome.None, null)).GetProperty("consumer");
            var published = section.GetProperty("rules")[0];
            Assert.True((want is null) == published.GetProperty("inForce").GetBoolean(), name);
            Assert.True(want == (published.TryGetProperty("code", out var given) ? given.GetString() : null), name);

            // And what the traffic does: a rule out of force for its egress still claims its
            // destination, and blocks it under the egress's reason rather than letting it out.
            if (want == PeerEgressCodes.RuleMeshOverlap
                || !Ipv6Cidr.TryParse(rule.Match, out var prefix) || !prefix.Contains(PeerEgressIpv6.DestinationOf(toARule)))
            {
                continue;
            }
            harness.Consumer.HandleOutbound(toARule, Epoch);
            if (!online)
            {
                Assert.True(harness.Blocked.GetValueOrDefault("egress-unavailable") == 1, name);
            }
            else if (want == PeerEgressCodes.RuleEgressNoIpv6)
            {
                Assert.True(harness.Blocked.GetValueOrDefault("egress-no-ipv6") == 1 && harness.Sent.Count == 0, name);
            }
            else
            {
                Assert.True(harness.Sent.Count == 1 && harness.Blocked.Count == 0, name);
            }
        }
    }

    [Fact]
    public void ConsumerOutboundMatchesTheSharedVector()
    {
        using var vector = Vector();
        var section = vector.RootElement.GetProperty("consumerOutbound");
        var mesh = section.GetProperty("consumerMeshIpv4").GetString()!;
        foreach (var testCase in section.GetProperty("cases").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var harness = new Harness(mesh, [TestRule], online: true, capable: true);
            var mtu = testCase.GetProperty("effectiveMtu").GetInt32();
            harness.Consumer.PathMtu = egress =>
            {
                Assert.Equal(Egress, egress);
                return mtu;
            };
            var packet = Hex(testCase, "packetHex");
            var outcome = harness.Consumer.HandleOutbound(packet, Epoch);
            Assert.True(harness.ToTun.Count == 0, $"{name}: answered into the TUN");
            switch (testCase.GetProperty("expect").GetString())
            {
                case "forward":
                    Assert.True(outcome == PeerEgressConsumerOutcome.Forwarded && harness.Sent.Count == 1
                        && harness.Sent[0].Egress == Egress, $"{name}: {outcome}");
                    var frame = PeerEgressFrame.Parse(harness.Sent[0].Frame, ipv6: true);
                    Assert.True(frame.Accepted && frame.Type == PeerEgressFrame.TypeIpPacket && !frame.Hop
                        && frame.Body.SequenceEqual(packet), $"{name}: the packet did not go as it was");
                    Assert.Empty(harness.Blocked);
                    break;
                case "drop-silently":
                    Assert.True(outcome == PeerEgressConsumerOutcome.Ignored && harness.Sent.Count == 0
                        && harness.Blocked.Count == 0, $"{name}: {outcome}");
                    break;
                case var reason:
                    Assert.True(harness.Sent.Count == 0 && harness.Blocked.Count == 1
                        && harness.Blocked.GetValueOrDefault(reason!) == 1,
                        $"{name}: {outcome} {string.Join(",", harness.Blocked.Keys)}; want {reason}");
                    break;
            }
        }
    }

    [Fact]
    public void ReturnPathMatchesTheSharedVector()
    {
        using var vector = Vector();
        var section = vector.RootElement.GetProperty("returnPath");
        var mesh = section.GetProperty("consumerMeshIpv4").GetString()!;
        // The flow the replies belong to is the vector's own outbound packet: the same five-tuple,
        // mirrored.
        var opening = Hex(vector.RootElement.GetProperty("consumerOutbound").GetProperty("cases")[0], "packetHex");
        foreach (var testCase in section.GetProperty("cases").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var harness = new Harness(mesh, [TestRule], online: true, capable: true);
            if (testCase.GetProperty("liveFlow").GetBoolean())
            {
                Assert.Equal(PeerEgressConsumerOutcome.Forwarded, harness.Consumer.HandleOutbound(opening, Epoch));
            }
            var packet = Hex(testCase, "packetHex");
            var claimed = harness.Consumer.HandleInbound(Frame(packet), Egress, Epoch);
            switch (testCase.GetProperty("expect").GetString())
            {
                case "deliver":
                    Assert.True(claimed && harness.ToTun.Count == 1 && harness.ToTun[0].SequenceEqual(packet)
                        && harness.Blocked.Count == 0, name);
                    break;
                case "not-for-consumer":
                    Assert.True(!claimed && harness.ToTun.Count == 0 && harness.Blocked.Count == 0, name);
                    break;
                case var reason:
                    Assert.True(claimed && harness.ToTun.Count == 0 && harness.Blocked.Count == 1
                        && harness.Blocked.GetValueOrDefault(reason!) == 1, $"{name}: want {reason}");
                    break;
            }
        }

        // From the right five-tuple but another egress, a reply is not one this device asked for.
        var other = new Harness(mesh, [TestRule], online: true, capable: true);
        other.Consumer.HandleOutbound(opening, Epoch);
        var reply = Hex(section.GetProperty("cases")[0], "packetHex");
        Assert.True(other.Consumer.HandleInbound(Frame(reply), 3L, Epoch));
        Assert.Equal(1, other.Blocked.GetValueOrDefault("return-no-flow"));
        Assert.Empty(other.ToTun);
    }

    /// <summary>Without the data plane the consumer leaves IPv6 alone in both directions, as before it existed.</summary>
    [Fact]
    public void Ipv6IsNotClaimedWithoutTheDataPlane()
    {
        using var vector = Vector();
        var harness = new Harness("100.96.0.1", [TestRule], online: true, capable: true);
        harness.Consumer.Configure([TestRule], PeerEgressRules.DefaultMeshCidr, "100.96.0.1", Epoch, carriesIpv6: false);
        foreach (var testCase in vector.RootElement.GetProperty("consumerOutbound").GetProperty("cases").EnumerateArray())
        {
            Assert.Equal(PeerEgressConsumerOutcome.NotMine, harness.Consumer.HandleOutbound(Hex(testCase, "packetHex"), Epoch));
        }
        var reply = Hex(vector.RootElement.GetProperty("returnPath").GetProperty("cases")[0], "packetHex");
        Assert.False(harness.Consumer.HandleInbound(Frame(reply), Egress, Epoch), "an IPv6 reply was claimed without the data plane");
        Assert.Empty(harness.Blocked);
        Assert.Empty(harness.Sent);
    }

    /// <summary>Byte for byte: what goes back into the TUN when the egress a rule names is unavailable.</summary>
    [Fact]
    public void FailureMatchesTheSharedVector()
    {
        using var vector = Vector();
        var failure = vector.RootElement.GetProperty("failure");
        var cases = failure.GetProperty("resetOnPacket").GetProperty("cases").EnumerateArray()
            .Concat(failure.GetProperty("unreachableOnDatagram").GetProperty("cases").EnumerateArray()).ToList();
        Assert.True(cases.Count >= 4, "the vector carried too few failure cases");
        foreach (var testCase in cases)
        {
            var name = testCase.GetProperty("name").GetString();
            var packet = Hex(testCase, "packetHex");
            var want = testCase.GetProperty("expect").GetProperty("packetHex").GetString()!;
            Assert.True(want == Text(PeerEgressConsumer.FailurePacket6(packet, packet[6])), name);
            Assert.True(Convert.FromHexString(want).Length <= PeerEgressIpv6Plane.MinimumMtu, $"{name}: past the IPv6 minimum MTU");

            // Through the data plane: the rule's egress is offline.
            var harness = new Harness("100.96.0.1", [TestRule], online: false, capable: true);
            Assert.Equal(PeerEgressConsumerOutcome.BlockedNoEgress, harness.Consumer.HandleOutbound(packet, Epoch));
            Assert.True(harness.ToTun.Count == 1 && Text(harness.ToTun[0]) == want, $"{name}: not the vector's answer");
        }
    }

    /// <summary>egress-no-ipv6 is answered like egress-no-domain: the application fails now.</summary>
    [Fact]
    public void AnEgressWithoutIpv6IsAnsweredAndNothingIsSent()
    {
        using var vector = Vector();
        var syn = Hex(vector.RootElement.GetProperty("failure").GetProperty("resetOnPacket").GetProperty("cases")[0], "packetHex");
        var harness = new Harness("100.96.0.1", [TestRule], online: true, capable: false);
        Assert.Equal(PeerEgressConsumerOutcome.BlockedNoEgress, harness.Consumer.HandleOutbound(syn, Epoch));
        Assert.Empty(harness.Sent);
        Assert.Equal(1, harness.Blocked.GetValueOrDefault("egress-no-ipv6"));
        Assert.Single(harness.ToTun);
        Assert.Equal(Text(PeerEgressConsumer.FailurePacket6(syn, syn[6])), Text(harness.ToTun[0]));
    }

    /// <summary>
    /// resetOnPurge in IPv6: a flow the consumer closes itself is reset from what it remembered, by
    /// the same rule as IPv4, and the purge names the destination as a /128.
    /// </summary>
    [Fact]
    public void APurgeResetsAnIpv6Flow()
    {
        var local = Derived("100.96.0.1");
        var remote = Address6("2001:db8:1::c8");
        var data = Segment6(local, remote, 5000, 9000, PeerEgressSegment.FlagAck | PeerEgressSegment.FlagPsh, "GET /"u8.ToArray());

        var harness = new Harness("100.96.0.1", [TestRule], online: true, capable: true);
        Assert.Equal(PeerEgressConsumerOutcome.Forwarded, harness.Consumer.HandleOutbound(data, Epoch));
        var purge = harness.Consumer.SetEgressOnline(Egress, false, Epoch);
        Assert.Equal(["2001:db8:1::c8/128"], purge[Egress]);
        var reset = Assert.Single(harness.ToTun);
        var parsed = PeerEgressSegment.Parse6(reset);
        Assert.NotNull(parsed);
        Assert.Equal((remote, local, (ushort)443, (ushort)40000), (parsed.SourceIp6, parsed.DestinationIp6, parsed.SourcePort, parsed.DestinationPort));
        Assert.Equal((PeerEgressSegment.FlagRst | PeerEgressSegment.FlagAck, 9000u, 5005u, 0),
            (parsed.Flags, parsed.Seq, parsed.Ack, parsed.Window));
        Assert.Equal((byte)PeerEgressIpv6.HopLimit, reset[7]);
        Assert.Equal(0, reset[1]);

        // The catalogue no longer saying the egress takes IPv6 packets closes the flow as well.
        harness = new Harness("100.96.0.1", [TestRule], online: true, capable: true);
        harness.Consumer.HandleOutbound(data, Epoch);
        purge = harness.Consumer.SetCatalog(new PeerEgressCatalogSnapshot(true,
            new Dictionary<long, PeerEgressCatalogListing> { [Egress] = new(false, 1) }), Epoch);
        Assert.Single(purge[Egress]);
        Assert.Equal(0, harness.Consumer.FlowCount);

        // And so does the device ceasing to carry IPv6.
        harness = new Harness("100.96.0.1", [TestRule], online: true, capable: true);
        harness.Consumer.HandleOutbound(data, Epoch);
        purge = harness.Consumer.Configure([TestRule], PeerEgressRules.DefaultMeshCidr, "100.96.0.1", Epoch, carriesIpv6: false);
        Assert.Equal(["2001:db8:1::c8/128"], purge[Egress]);
        Assert.Equal(0, harness.Consumer.FlowCount);
    }

    /// <summary>A flow-reject for an IPv6 flow names it in IPv6, and resets and forgets it.</summary>
    [Fact]
    public void AFlowRejectClosesAnIpv6Flow()
    {
        var local = Derived("100.96.0.1");
        var remote = Address6("2001:db8:1::c8");
        var harness = new Harness("100.96.0.1", [TestRule], online: true, capable: true);
        harness.Consumer.HandleOutbound(Segment6(local, remote, 5000, 9000, PeerEgressSegment.FlagAck), Epoch);
        var body = PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.FlowReject(
            "tcp", Ipv6Cidr.FormatAddress(local), 40000, Ipv6Cidr.FormatAddress(remote), 443,
            PeerEgressCodes.DestinationDenied));
        Assert.True(harness.Consumer.HandleInbound(PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body), Egress, Epoch));
        Assert.Equal(0, harness.Consumer.FlowCount);
        Assert.Single(harness.ToTun);
        Assert.Equal(1, harness.Blocked.GetValueOrDefault("rejected-egress_dest_denied"));
    }

    /// <summary>
    /// The rule set of the rules vector's ipv6 section, run through the consumer's own steering with
    /// the data plane: what each IPv6 destination's packet does is what the vector says the rules
    /// decide.
    /// </summary>
    [Fact]
    public void TheConsumerSteersByTheRulesVector()
    {
        using var vector = Vector("peer-egress-rules-v1.json");
        var section = vector.RootElement.GetProperty("ipv6");
        var rules = section.GetProperty("rules").EnumerateArray().Select(rule => rule.Deserialize<PeerEgressRule>()!).ToList();
        var egresses = rules.Where(rule => rule.EgressClientId is > 0).Select(rule => rule.EgressClientId!.Value).Distinct().ToList();
        var local = Derived("100.96.0.1");
        var checkedCases = 0;
        foreach (var testCase in section.GetProperty("cases").EnumerateArray())
        {
            if (!Ipv6Cidr.TryParseAddress(testCase.GetProperty("destination").GetString(), out var destination)
                || PeerEgressIpv6Plane.IsMulticast(destination) || PeerEgressMeshAddress.PrefixCidr.Contains(destination))
            {
                continue;
            }
            var sent = new List<long>();
            var consumer = new PeerEgressConsumer((egress, _) =>
            {
                sent.Add(egress);
                return true;
            }, _ => { });
            consumer.Configure(rules, PeerEgressRules.DefaultMeshCidr, "100.96.0.1", Epoch, carriesIpv6: true);
            consumer.SetCatalog(new PeerEgressCatalogSnapshot(true,
                egresses.ToDictionary(egress => egress, _ => new PeerEgressCatalogListing(false, 1, true))), Epoch);
            foreach (var egress in egresses)
            {
                consumer.SetEgressOnline(egress, true, Epoch);
            }
            var outcome = consumer.HandleOutbound(Segment6(local, destination, 1, 0, PeerEgressSegment.FlagSyn), Epoch);
            var expect = testCase.GetProperty("expect");
            var name = testCase.GetProperty("name").GetString();
            switch (expect.GetProperty("action").GetString())
            {
                case PeerEgressRules.ActionEgress:
                    Assert.True(outcome == PeerEgressConsumerOutcome.Forwarded
                        && sent.SequenceEqual([expect.GetProperty("egressClientId").GetInt64()]), $"{name}: {outcome}");
                    break;
                case PeerEgressRules.ActionBlock:
                    Assert.True(outcome == PeerEgressConsumerOutcome.BlockedByRule, $"{name}: {outcome}");
                    break;
                default:
                    Assert.True(outcome == PeerEgressConsumerOutcome.NotMine, $"{name}: a direct destination was claimed ({outcome})");
                    break;
            }
            checkedCases++;
        }
        Assert.True(checkedCases > 0, "no case of the rules vector was steered");
    }

    /// <summary>
    /// At the default MTU a platform with the data plane gets the data-plane section's answers through
    /// the production entry points -- what config validate, egress rules and egress test judge with --
    /// and below 1280 the section without one.
    /// </summary>
    [Fact]
    public void TheCommandLineFollowsThisPlatformsDataPlane()
    {
        using var vector = Vector("peer-egress-rules-v1.json");
        var section = vector.RootElement.GetProperty("ipv6");
        var rules = section.GetProperty("rules").EnumerateArray().Select(rule => rule.Deserialize<PeerEgressRule>()!).ToList();
        var carries = PeerEgressIpv6Plane.ConsumerCarriesIpv6(SpecusClientConfig.DefaultPeerMeshMtu);
        Assert.Equal(PeerEgressIpv6Plane.PlatformCarriesIpv6, carries);
        var below = new SpecusClientConfig { PeerMeshMtu = 1200, PeerEgressRules = rules };
        foreach (var entry in section.GetProperty("withoutIpv6DataPlane").GetProperty("ruleCodes").EnumerateArray())
        {
            var code = entry.GetProperty("code");
            Assert.Equal(code.ValueKind == JsonValueKind.Null ? null : code.GetString(),
                EgressEdit.RuleCode(below, rules[entry.GetProperty("index").GetInt32()]));
        }
        if (!carries)
        {
            return;
        }
        var refused = section.GetProperty("refusedRules").EnumerateArray()
            .ToDictionary(entry => entry.GetProperty("index").GetInt32(), entry => entry.GetProperty("code").GetString());
        var config = new SpecusClientConfig { PeerEgressEnabled = true, PeerEgressRules = rules };
        for (var index = 0; index < rules.Count; index++)
        {
            Assert.Equal(refused.GetValueOrDefault(index), EgressEdit.RuleCode(config, rules[index]));
        }
        foreach (var testCase in section.GetProperty("cases").EnumerateArray())
        {
            var destination = testCase.GetProperty("destination").GetString()!;
            if (!EgressEdit.IsAddress(destination))
            {
                continue;
            }
            var data = EgressEdit.Preview("c.jsonc", config, destination, []);
            var index = testCase.GetProperty("expect").GetProperty("matchedRuleIndex");
            Assert.True((index.ValueKind == JsonValueKind.Null ? -1 : index.GetInt32()) == (int)data["matchedRuleIndex"]!, destination);
        }
    }

    /// <summary>Whether a device carries IPv6 is its platform's support and an MTU of at least 1280; unset reads as the default.</summary>
    [Fact]
    public void CarryingIpv6NeedsThePlatformAndTheMinimumMtu()
    {
        Assert.False(PeerEgressIpv6Plane.ConsumerCarriesIpv6(SpecusClientConfig.MinPeerMeshMtu));
        Assert.False(PeerEgressIpv6Plane.ConsumerCarriesIpv6(1279));
        Assert.Equal(PeerEgressIpv6Plane.PlatformCarriesIpv6, PeerEgressIpv6Plane.ConsumerCarriesIpv6(1280));
        Assert.Equal(PeerEgressIpv6Plane.PlatformCarriesIpv6, PeerEgressIpv6Plane.ConsumerCarriesIpv6(0));
    }

    /// <summary>The derived address goes to the TUN only for a consumer with the IPv6 data plane.</summary>
    [Fact]
    public void TheTunIsGivenItsDerivedAddressOnlyForTheConsumer()
    {
        var address = PeerEgressIpv6Plane.DeviceAddress(new SpecusClientConfig { PeerEgressEnabled = true, PeerMeshMtu = 1280 }, "100.96.0.1");
        Assert.Equal(PeerEgressIpv6Plane.PlatformCarriesIpv6 ? "fd53:7065:6375:7300::6460:1" : null, address);
        Assert.Null(PeerEgressIpv6Plane.DeviceAddress(new SpecusClientConfig { PeerMeshMtu = 1280 }, "100.96.0.1"));
        Assert.Null(PeerEgressIpv6Plane.DeviceAddress(new SpecusClientConfig { PeerEgressEnabled = true, PeerMeshMtu = 1200 }, "100.96.0.1"));
        Assert.Null(PeerEgressIpv6Plane.DeviceAddress(new SpecusClientConfig { PeerEgressEnabled = true, PeerMeshMtu = 1280 }, ""));
        Assert.Equal(["ip", "-6", "address", "add", "fd53:7065:6375:7300::6460:1/128", "dev", "specus0"],
            PeerEgressIpv6Plane.LinuxAssignAddressArgs("specus0", "fd53:7065:6375:7300::6460:1"));
    }

    [Theory]
    [InlineData("fe80::1", true, false)]
    [InlineData("febf:ffff::1", true, false)]
    [InlineData("fec0::1", false, false)]
    [InlineData("ff02::16", false, true)]
    [InlineData("2001:db8::1", false, false)]
    public void LinkLocalAndMulticastAreReadByPrefix(string text, bool linkLocal, bool multicast)
    {
        var address = Address6(text);
        Assert.Equal(linkLocal, PeerEgressIpv6Plane.IsLinkLocal(address));
        Assert.Equal(multicast, PeerEgressIpv6Plane.IsMulticast(address));
    }
}
