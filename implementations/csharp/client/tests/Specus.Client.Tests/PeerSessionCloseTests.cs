using System.Collections;
using System.Reflection;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

// Real control parser and socket-owning runtime; injected dialer, no external network/device.
public sealed class PeerSessionCloseTests
{
    public static IEnumerable<object[]> Vectors()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var path = Path.Combine(directory.FullName, "protocol/test-vectors/peer-session-close-v1.json");
            if (File.Exists(path))
            {
                using var document = JsonDocument.Parse(File.ReadAllText(path));
                var cases = document.RootElement.GetProperty("cases");
                Assert.Equal(13, cases.GetArrayLength());
                return cases.EnumerateArray().Select(item => new object[] {
                    item.GetProperty("name").GetString()!, item.GetRawText() }).ToArray();
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("shared close vector not found");
    }

    [Theory]
    [MemberData(nameof(Vectors))]
    public async Task CloseIsBoundToCurrentSession(string name, string json)
    {
        _ = name;
        using var document = JsonDocument.Parse(json);
        var scenario = document.RootElement;
        await using var client = new PeerMeshClient(new SpecusClientConfig(), NullLogger<PeerMeshClient>.Instance);
        await using var writer = new FrameWriter(new MemoryStream());
        var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var dialer = new Dialer();
        var runtime = new PeerEgressRuntime((_, _) => {}, dialer, _ => {}, () => now);
        var plane = Get<PeerEgressMesh>(client, "_egress");
        typeof(PeerEgressMesh).GetField("_runtime", BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(plane, runtime);
        var sessions = Get<IDictionary>(client, "_sessions");
        var byId = Get<IDictionary>(client, "_sessionsById");
        try
        {
            runtime.ApplyPolicy(new PeerEgressPolicy {
                Enabled = true, Scope = PeerEgressAuthorization.ScopePublic, AllowedConsumerClientIds = [7L, 9L],
                DestinationRules = [new PeerEgressDestinationRule {
                    Cidr = "203.0.113.0/24", Protocols = ["tcp"], PortRanges = [[1, 65535]] }]
            }, PeerEgressContext.Default, now);
            Install(sessions, byId, runtime, 7, 200, 40000, now);
            Install(sessions, byId, runtime, 9, 300, 40001, now);
            Assert.Equal(2, runtime.FlowCount);
            Assert.Equal(2, dialer.Sockets.Count);
            foreach (var message in scenario.GetProperty("messages").EnumerateArray())
                await client.HandleControlAsync(message.GetRawText(), new SpecusRuntimeState(), writer, CancellationToken.None);
            Assert.Equal(scenario.GetProperty("closedPeerId").GetInt64() == 0 ? 2 : 1, runtime.FlowCount);
            for (var index = 0; index < 2; index++)
            {
                var peer = index == 0 ? 7L : 9L;
                var id = index == 0 ? 200L : 300L;
                var closed = scenario.GetProperty("closedPeerId").GetInt64() == peer;
                Assert.Equal(closed ? 1 : 0, dialer.Sockets[index].Closes);
                Assert.Equal(!closed, sessions.Contains(peer));
                Assert.Equal(!closed, byId.Contains(id));
            }
            if (scenario.TryGetProperty("replacementSessionId", out var replacement))
            {
                var id = replacement.GetInt64();
                Install(sessions, byId, runtime, 7, id, 40002, now);
                Assert.Equal(3, dialer.Sockets.Count);
                foreach (var message in scenario.GetProperty("messages").EnumerateArray())
                    await client.HandleControlAsync(message.GetRawText(), new SpecusRuntimeState(), writer, CancellationToken.None);
                Assert.NotNull(sessions[7L]);
                Assert.Same(sessions[7L], byId[id]);
                Assert.Equal(id, sessions[7L]!.GetType().GetProperty("Id")!.GetValue(sessions[7L]));
                Assert.Equal(0, dialer.Sockets[2].Closes);
                Assert.Equal(0, dialer.Sockets[1].Closes);
                Assert.True(sessions.Contains(9L));
            }
        }
        finally { runtime.Shutdown(now); }
    }

    private static void Install(IDictionary sessions, IDictionary byId, PeerEgressRuntime runtime,
        long peer, long id, ushort port, long now)
    {
        var type = typeof(PeerMeshClient).GetNestedType("PeerMeshSession", BindingFlags.NonPublic)!;
        var session = Activator.CreateInstance(type, nonPublic: true)!;
        type.GetProperty("Id")!.SetValue(session, id);
        type.GetProperty("PeerId")!.SetValue(session, peer);
        sessions[peer] = session;
        byId[id] = session;
        Assert.True(Ipv4Cidr.TryParseAddress("100.96.0.1", out var source));
        Assert.True(Ipv4Cidr.TryParseAddress("203.0.113.10", out var destination));
        var syn = new PeerEgressSegment.Segment(source, destination, port, 443, 1000, 0,
            PeerEgressSegment.FlagSyn, 65535, 1360, []);
        runtime.HandleFrame(peer, PeerEgressFrame.Encode(PeerEgressFrame.TypeIpPacket, false,
            PeerEgressSegment.Build(syn)), now);
    }

    private static T Get<T>(object target, string name) =>
        (T)target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(target)!;

    private sealed class Socket : IPeerEgressSocket
    {
        public int Closes { get; private set; }
        public int Read(byte[] buffer) => throw new InvalidOperationException("reader must not run in lifecycle fixture");
        public void Write(byte[] data) {}
        public void Dispose() => Closes++;
    }

    private sealed class Dialer : IPeerEgressDialer
    {
        public List<Socket> Sockets { get; } = [];
        public IPeerEgressSocket Dial(string protocol, string host, int port, long timeoutMs)
        {
            var socket = new Socket();
            Sockets.Add(socket);
            return socket;
        }
    }
}
