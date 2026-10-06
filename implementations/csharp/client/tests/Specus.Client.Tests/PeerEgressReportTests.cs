using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.PeerMesh;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Protocol.PeerEgress;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// The <c>egress-report</c>: when it goes out, what it says, and how it leaves.
/// </summary>
/// <remarks>
/// The vector pins the decision and the body against the generator's reference reporter. The other
/// cases drive the real plane on a clock and a timer that move only when told, and read what reached
/// the host or the control connection: a reporter that agrees with the vector is no use if the mesh
/// feeds it the wrong numbers, never starts its timer, or wraps the body in an envelope the server
/// refuses.
/// </remarks>
public class PeerEgressReportTests : IDisposable
{
    private const long T0 = 1_791_000_000_000L;
    private const long Minute = 60_000L;
    private const string VirtualIp = "100.96.0.1";

    /// <summary>What the server refuses to find in a report, an explicit null included.</summary>
    private static readonly string[] ServerBound =
    [
        "sourceClientId", "sourceClientName", "sourceVirtualIp", "sourcePublicKey", "sourceKeyEpoch",
        "targetClientId", "targetClientName", "targetVirtualIp", "targetPublicKey", "sessionId", "token",
    ];

    private static readonly string[] ReportFields =
        ["type", "revision", "activeFlows", "totalFlows", "rejectedFlows", "bytesIn", "bytesOut"];

    private readonly List<string> _toServer = [];
    private PeerEgressMesh? _mesh;

    public void Dispose()
    {
        _mesh?.Dispose();
        GC.SuppressFinalize(this);
    }

    // ----------------------------------------------------------------------------------------------
    // The shared vector
    // ----------------------------------------------------------------------------------------------

    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-report-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-report-v1.json");
    }

    /// <summary>
    /// Every event of <c>peer-egress-report-v1.json</c> through the reporter: a tick is one check,
    /// with the vector's wall clock and its egress section as the plane's status. The plane is
    /// enabled exactly when the vector's egress runs, since this build always announces the egress
    /// capability.
    /// </summary>
    [Fact]
    public void ReplaysTheSharedVector()
    {
        using var vector = Vector();
        var root = vector.RootElement;
        Assert.True(TimeSpan.FromSeconds(root.GetProperty("intervalSeconds").GetInt32()) == PeerEgressReporter.Interval,
            "the check interval differs from the vector's");

        var reporter = new PeerEgressReporter();
        var index = 0;
        var sent = 0;
        foreach (var step in root.GetProperty("events").EnumerateArray())
        {
            if (step.TryGetProperty("newSession", out var newSession) && newSession.GetBoolean())
            {
                reporter.NewSession();
                index++;
                continue;
            }
            var egress = step.GetProperty("egress");
            var status = new PeerEgressRuntimeStatus(
                Enabled: step.GetProperty("active").GetBoolean(),
                Revision: 0,
                Flows: egress.GetProperty("flows").GetInt32(),
                TotalFlows: egress.GetProperty("totalFlows").GetInt64(),
                BytesIn: egress.GetProperty("bytesIn").GetInt64(),
                BytesOut: egress.GetProperty("bytesOut").GetInt64(),
                Refused: egress.GetProperty("refused").EnumerateObject()
                    .ToDictionary(entry => entry.Name, entry => entry.Value.GetInt64()));

            var report = reporter.Check(step.GetProperty("wallMs").GetInt64(), status);

            var expected = step.GetProperty("report");
            if (expected.ValueKind == JsonValueKind.Null)
            {
                Assert.True(report is null, $"event {index}: sent {report?.Encode()} where the vector sends nothing");
            }
            else
            {
                Assert.True(report is not null, $"event {index}: sent nothing where the vector sends {expected.GetRawText()}");
                var body = report!.Encode();
                Assert.True(JsonNode.DeepEquals(JsonNode.Parse(body), JsonNode.Parse(expected.GetRawText())),
                    $"event {index}: sent {body}, the vector sends {expected.GetRawText()}");
                sent++;
            }
            index++;
        }
        Assert.True(sent > 0 && index > sent, "the vector exercised neither a report nor a skipped check");
    }

    // ----------------------------------------------------------------------------------------------
    // The mesh: the plane's numbers, on the mesh's timer
    // ----------------------------------------------------------------------------------------------

    /// <summary>
    /// The mesh starts the check with the first policy, reads the plane the status reads, and keeps
    /// one revision sequence across sessions and planes.
    /// </summary>
    [Fact]
    public void TheMeshReportsWhatThePlaneCounts()
    {
        var time = new ManualTime(T0);
        var wiring = NewMesh(time);
        Assert.True(time.Timers.Count == 0, "a timer ran before anything made this node an egress");

        wiring.ApplyEgressConfig(ConfigFor(1, enabled: true));
        var timer = Assert.Single(time.Timers);
        Assert.True(timer.Period == TimeSpan.FromMinutes(1) && timer.DueTime == TimeSpan.FromMinutes(1),
            $"checked every {timer.Period} after {timer.DueTime}, not every minute");

        // The first check reports though nothing happened, so the page shows the egress reporting.
        time.Tick(0);
        AssertReport(wiring, Single(), T0);
        time.Tick(Minute);
        Assert.True(ToServer().Count == 0, "an unchanged check reported again");

        // Switched off: nothing. Switched on again: the first check reports, unchanged or not.
        wiring.ApplyEgressConfig(ConfigFor(2, enabled: false));
        time.Tick(Minute);
        Assert.True(ToServer().Count == 0, "a switched-off egress reported");
        wiring.ApplyEgressConfig(ConfigFor(3, enabled: true));
        time.Tick(Minute);
        AssertReport(wiring, Single(), T0 + 3 * Minute);

        // A flow opened and one refused: the numbers move, and the next check carries them.
        wiring.HandleInboundFrame(7, SynTo("203.0.113.10"));
        wiring.HandleInboundFrame(7, SynTo("198.51.100.10"));
        WaitFor("the plane to count both", () =>
        {
            var egress = Egress(wiring);
            return egress["flows"]!.GetValue<int>() == 1 && egress["totalFlows"]!.GetValue<long>() == 1
                && egress["refused"]!.AsObject().Count == 1;
        });
        time.Tick(Minute);
        var moved = Single();
        AssertReport(wiring, moved, T0 + 4 * Minute);
        var body = JsonNode.Parse(moved)!;
        Assert.True(body["activeFlows"]!.GetValue<long>() == 1 && body["totalFlows"]!.GetValue<long>() == 1,
            $"the open flow is not in {moved}");
        Assert.True(body["rejectedFlows"]!.AsObject().Count == 1, $"the refusal is not in {moved}");

        // A new control session reports at the next check though nothing changed, and a clock that
        // stepped back does not take the revision with it.
        wiring.NewControlSession();
        time.NowMs = T0 + Minute;
        time.Tick(0);
        AssertReport(wiring, Single(), T0 + 4 * Minute + 1);

        // A reconnect replaces the plane. Until the next policy builds one there is nothing to
        // report; then the new plane's numbers go out, still above every revision sent before.
        wiring.ShutdownServing();
        wiring.NewControlSession();
        time.Tick(Minute);
        Assert.True(ToServer().Count == 0, "a node with no plane reported");
        wiring.ApplyEgressConfig(ConfigFor(1, enabled: true));
        Assert.True(time.Timers.Count == 1, "a second plane started a second check");
        time.NowMs = T0 + 10 * Minute;
        time.Tick(0);
        var fresh = Single();
        AssertReport(wiring, fresh, T0 + 10 * Minute);
        Assert.True(JsonNode.Parse(fresh)!["totalFlows"]!.GetValue<long>() == 0,
            $"the report read the old plane: {fresh}");

        wiring.Dispose();
        Assert.True(timer.Disposed, "the check outlived the mesh");
    }

    /// <summary>
    /// A send that fails is not retried at the next check: only a change, a new session or the
    /// egress being switched on again sends again.
    /// </summary>
    [Fact]
    public void AFailedSendIsNotRetried()
    {
        var time = new ManualTime(T0);
        var host = new FakeHost(this) { Accepts = false };
        _mesh = new PeerEgressMesh(host, dialer: new FakeDialer(), commander: new FakeCommander(), time: time);
        _mesh.ApplyEgressConfig(ConfigFor(1, enabled: true));

        time.Tick(0);
        Assert.True(ToServer().Count == 1, "the first check did not try to report");
        host.Accepts = true;
        time.Tick(Minute);
        Assert.True(ToServer().Count == 1, "a report that failed was sent again unchanged");
    }

    // ----------------------------------------------------------------------------------------------
    // The control connection: the envelope the server accepts
    // ----------------------------------------------------------------------------------------------

    /// <summary>
    /// Through the real client: the report leaves on the control connection as a PEER_CONTROL
    /// request to nobody, its body holds the report's fields and nothing that names a sender, and
    /// its numbers are the ones the local status prints.
    /// </summary>
    [Fact]
    public async Task TheReportLeavesOnTheControlConnectionWithoutIdentity()
    {
        var time = new ManualTime(T0);
        await using var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance, time: time);
        await using var wire = new MemoryStream();
        await using var writer = new FrameWriter(wire);
        using var written = new SemaphoreSlim(0);
        writer.PacketWritten += () => written.Release();
        // Everything a careless body could copy from: the session, the token, the mesh identity.
        var runtime = new SpecusRuntimeState
        {
            ClientId = 2,
            ClientName = "office-gateway",
            ClientSessionId = 31,
            AccessToken = "session-token",
            PeerMesh = new PeerMeshConfig
            {
                Enabled = true,
                ClientId = 2,
                ClientName = "office-gateway",
                VirtualIp = "100.96.0.2",
                Cidr = "100.96.0.0/11",
                ClientPublicKey = "public-key",
            },
        };
        SetPrivateField(client, "_runtime", runtime);
        SetPrivateField(client, "_writer", writer);

        await client.HandleControlAsync(ConfigFor(1, enabled: true), runtime, writer, CancellationToken.None);
        var timer = Assert.Single(time.Timers);

        timer.Fire();
        Assert.True(await written.WaitAsync(TimeSpan.FromSeconds(10)), "no report reached the control connection");
        var first = Assert.Single(Requests(wire));
        AssertEnvelope(first);
        AssertMatchesStatus(client.EgressStatus(), first.Message!, T0);

        // An unchanged check sends nothing: had it sent, the next request would carry its revision.
        time.Tick(Minute);

        // A refusal by the real plane, then a check: the count is the status's own.
        var mesh = (PeerEgressMesh)typeof(PeerMeshClient)
            .GetField("_egress", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(client)!;
        mesh.HandleInboundFrame(7, SynTo("198.51.100.10"));
        WaitFor("the refusal to be counted", () =>
            ToNode(client.EgressStatus())["egress"]!["refused"]!.AsObject().Count == 1);
        time.Tick(Minute);
        Assert.True(await written.WaitAsync(TimeSpan.FromSeconds(10)), "the changed numbers were not reported");
        var requests = Requests(wire);
        Assert.True(requests.Count == 2, $"{requests.Count} requests on the control connection");
        AssertEnvelope(requests[1]);
        AssertMatchesStatus(client.EgressStatus(), requests[1].Message!, T0 + 2 * Minute);
        Assert.True(JsonNode.Parse(requests[1].Message!)!["rejectedFlows"]!.AsObject().Count == 1,
            $"the refusal is not in {requests[1].Message}");
    }

    private static void AssertEnvelope(MessageRequestPacket request)
    {
        Assert.Equal(MessageType.PeerControl, request.MessageType);
        Assert.True(string.IsNullOrEmpty(request.ToClientName),
            $"addressed to {request.ToClientName}; the server refuses a report with a recipient");
        var body = JsonNode.Parse(request.Message!)!.AsObject();
        foreach (var field in ServerBound)
        {
            Assert.False(body.ContainsKey(field), $"the body carries {field}, which the server binds itself");
        }
        Assert.True(body.Select(entry => entry.Key).Order(StringComparer.Ordinal)
                .SequenceEqual(ReportFields.Order(StringComparer.Ordinal)),
            $"the body is not exactly a report: {request.Message}");
        Assert.Equal(PeerEgressReportMessage.Type, body["type"]!.GetValue<string>());
    }

    // ----------------------------------------------------------------------------------------------
    // Helpers
    // ----------------------------------------------------------------------------------------------

    /// <summary>The report's numbers are the egress section of the local status, at the same moment.</summary>
    private static void AssertMatchesStatus(Dictionary<string, object?> status, string report, long revision)
    {
        var egress = ToNode(status)["egress"]!;
        var rejected = new JsonObject();
        foreach (var (code, count) in egress["refused"]!.AsObject())
        {
            if (count!.GetValue<long>() > 0)
            {
                rejected[code] = count.GetValue<long>();
            }
        }
        var expected = new JsonObject
        {
            ["type"] = PeerEgressReportMessage.Type,
            ["revision"] = revision,
            ["activeFlows"] = egress["flows"]!.GetValue<int>(),
            ["totalFlows"] = egress["totalFlows"]!.GetValue<long>(),
            ["rejectedFlows"] = rejected,
            ["bytesIn"] = egress["bytesIn"]!.GetValue<long>(),
            ["bytesOut"] = egress["bytesOut"]!.GetValue<long>(),
        };
        // Through text, so both sides hold parsed numbers rather than one holding CLR values.
        Assert.True(JsonNode.DeepEquals(JsonNode.Parse(report), JsonNode.Parse(expected.ToJsonString())),
            $"sent {report}; the status says {expected.ToJsonString()}");
    }

    private static void AssertReport(PeerEgressMesh wiring, string report, long revision) =>
        AssertMatchesStatus(wiring.Status(), report, revision);

    private static JsonNode Egress(PeerEgressMesh wiring) => ToNode(wiring.Status())["egress"]!;

    private static JsonNode ToNode(Dictionary<string, object?> status) =>
        JsonNode.Parse(JsonSerializer.Serialize(status))!;

    /// <summary>Every MESSAGE_REQUEST written to the control connection so far.</summary>
    private static List<MessageRequestPacket> Requests(MemoryStream wire)
    {
        var bytes = wire.ToArray();
        var requests = new List<MessageRequestPacket>();
        var offset = 0;
        while (offset < bytes.Length)
        {
            Assert.True(PacketCodec.TryDecode(bytes.AsSpan(offset), out var packet, out var consumed),
                "the control connection carries a partial frame");
            requests.Add(Assert.IsType<MessageRequestPacket>(packet));
            offset += consumed;
        }
        return requests;
    }

    private List<string> ToServer()
    {
        lock (_toServer)
        {
            return [.. _toServer];
        }
    }

    /// <summary>The one report sent since the last call.</summary>
    private string Single()
    {
        lock (_toServer)
        {
            var report = Assert.Single(_toServer);
            _toServer.Clear();
            return report;
        }
    }

    private PeerEgressMesh NewMesh(ManualTime time)
    {
        _mesh = new PeerEgressMesh(new FakeHost(this), dialer: new FakeDialer(), commander: new FakeCommander(),
            time: time);
        return _mesh;
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

    private static void SetPrivateField(object instance, string name, object value) =>
        instance.GetType()
            .GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!
            .SetValue(instance, value);

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

    // Q stands in for the quote and is converted at the end, so the message stays readable.
    private static string ConfigFor(long revision, bool enabled) => (
        "{QtypeQ:Qegress-configQ,QenabledQ:" + (enabled ? "true" : "false") + ",QrevisionQ:" + revision
        + ",QscopeQ:QPUBLICQ,QallowedConsumerClientIdsQ:[7],QdestinationRulesQ:[{QcidrQ:Q203.0.113.0/24Q,"
        + "QprotocolsQ:[QtcpQ,QudpQ],QportRangesQ:[[1,65535]]}],"
        + "QlimitsQ:{QmaxConcurrentFlowsQ:8,QmaxFlowsPerConsumerQ:4,QidleTimeoutSecondsQ:600}}").Replace('Q', '"');

    private sealed class FakeHost(PeerEgressReportTests owner) : IPeerEgressMeshHost
    {
        public volatile bool Accepts = true;

        public bool CanReach(long peerId) => true;

        public Task<bool> SendToPeerAsync(long peerId, byte[] frame) => Task.FromResult(true);

        public Task<bool> SendToServerAsync(string message)
        {
            lock (owner._toServer)
            {
                owner._toServer.Add(message);
            }
            return Task.FromResult(Accepts);
        }

        public Task WriteToDeviceAsync(byte[] packet) => Task.CompletedTask;

        public string TunName => "specus0";

        public string MeshCidr => "100.96.0.0/11";

        public string VirtualIp => PeerEgressReportTests.VirtualIp;

        public IReadOnlyList<string> DeploymentDenyCidrs() => ["203.0.113.250/32"];

        public IReadOnlyList<string> PeerEndpointAddresses() => [];

        public int? PathMtuForPeer(long peerId) => null;
    }

    /// <summary>A routing table that accepts everything and touches nothing on this machine.</summary>
    private sealed class FakeCommander : IPeerEgressRouteCommander
    {
        public PeerEgressRouteConflictCheck Conflict(PeerEgressRoute route) => PeerEgressRouteConflictCheck.None;

        public void Install(PeerEgressRoute route)
        {
        }

        public void Remove(PeerEgressRoute route)
        {
        }
    }

    /// <summary>A socket that opens at once and never reads, so a flow stays open without a network.</summary>
    private sealed class FakeDialer : IPeerEgressDialer
    {
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs) => new IdleSocket();

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
}

/// <summary>A wall clock and timers that move only when a test moves them.</summary>
internal sealed class ManualTime(long startMs) : TimeProvider
{
    private readonly List<ManualTimer> _timers = [];
    private long _nowMs = startMs;

    public long NowMs
    {
        get => Interlocked.Read(ref _nowMs);
        set => Interlocked.Exchange(ref _nowMs, value);
    }

    public IReadOnlyList<ManualTimer> Timers
    {
        get
        {
            lock (_timers)
            {
                return [.. _timers.Where(timer => !timer.Disposed)];
            }
        }
    }

    public override DateTimeOffset GetUtcNow() => DateTimeOffset.FromUnixTimeMilliseconds(NowMs);

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(callback, state, dueTime, period);
        lock (_timers)
        {
            _timers.Add(timer);
        }
        return timer;
    }

    /// <summary>Moves the clock on, then fires every live timer once, as their next period would.</summary>
    public void Tick(long advanceMs)
    {
        NowMs += advanceMs;
        foreach (var timer in Timers)
        {
            timer.Fire();
        }
    }
}

internal sealed class ManualTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) : ITimer
{
    public TimeSpan DueTime { get; private set; } = dueTime;

    public TimeSpan Period { get; private set; } = period;

    public bool Disposed { get; private set; }

    public void Fire()
    {
        if (!Disposed)
        {
            callback(state);
        }
    }

    public bool Change(TimeSpan dueTime, TimeSpan period)
    {
        DueTime = dueTime;
        Period = period;
        return !Disposed;
    }

    public void Dispose() => Disposed = true;

    public ValueTask DisposeAsync()
    {
        Dispose();
        return ValueTask.CompletedTask;
    }
}
