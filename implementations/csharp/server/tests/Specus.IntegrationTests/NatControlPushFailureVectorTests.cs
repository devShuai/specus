using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Nat;
using Specus.Server.Networking;
using Specus.Server.PeerMesh;
using Specus.Server.Security;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays <c>existingOversize</c> of protocol/test-vectors/nat-control-size-v1.json: a client whose
/// enabled routes, written straight to the database, take its NAT_CONTROL past the 1 MiB MESSAGE
/// body. Its control login stands and the Peer Mesh login push still arrives, the manual pushes
/// answer 409, route changes are stored and answered as usual, and nothing reaches the connection,
/// which stays open, until the configuration is back within the limit. Before, the login push threw
/// and the dispatcher closed the connection, skipping the Peer Mesh push, and the client reconnected
/// into the same failure.
/// </summary>
public sealed class NatControlPushFailureVectorTests
{
    private const string Tenant = "default";
    private const string TargetPrefix = "http://127.0.0.1:8080/";
    private static readonly TimeSpan Wait = TimeSpan.FromSeconds(5);
    /// <summary>How long a NAT_CONTROL that should not come is given to show up anyway.</summary>
    private static readonly TimeSpan Quiet = TimeSpan.FromMilliseconds(300);

    [Fact]
    public async Task ExistingOversizeConfigurationIsNeitherSentNorDisconnecting()
    {
        using var vector = JsonDocument.Parse(await File.ReadAllTextAsync(VectorPath()));
        var root = vector.RootElement;
        var errorContains = root.GetProperty("errorContains").GetString()!;
        var scenario = root.GetProperty("existingOversize");

        // Peer Mesh on for its login push; without the STUN/TURN hosted service the test binds no UDP port.
        await using var server = await TestServerFixture.StartAsync(
            new Dictionary<string, string?> { ["Specus:PeerMesh:Enabled"] = "true" },
            RemoveStunTurnServer);
        using var admin = server.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken("admin", Tenant, ManagementRole.Admin));

        var (clientId, session) = await DemoSessionAsync(server);
        var fill = await FillAsync(server, clientId, scenario.GetProperty("jsonBytesWithEmptyClientName").GetInt32(),
            scenario.GetProperty("fillTargetBaseUrlMaxBytes").GetInt32());

        ControlConnection? control = null;
        try
        {
            var index = 0;
            foreach (var step in scenario.GetProperty("steps").EnumerateArray())
            {
                var op = step.GetProperty("op").GetString()!;
                var label = $"step {index++} {op}";
                HttpResponseMessage? response = null;
                switch (op)
                {
                    case "connect":
                    {
                        var connected = await ControlConnection.LoginAsync(server.ControlPort, new LoginRequestPacket
                        {
                            ClientName = DatabaseInitializer.DemoClientName,
                            ClientSessionId = session.Id,
                            AccessToken = session.AccessToken,
                            ConnectionRole = ConnectionRole.Control,
                        });
                        control = connected;
                        await AwaitAsync($"{label}: the Peer Mesh login push",
                            () => connected.PeerTypes.Contains("peer-config"));
                        break;
                    }
                    case "pushNatControl":
                        response = await admin.PostAsync($"/api/admin/clients/{clientId}/nat-control", null);
                        break;
                    case "forceRefreshPortMapping":
                        response = await admin.PostAsync(
                            $"/api/admin/clients/{clientId}/force-refresh-port-mapping", null);
                        break;
                    case "createRoute":
                        response = await admin.PostAsJsonAsync($"/api/admin/clients/{clientId}/http-routes", new
                        {
                            route = step.GetProperty("route").GetString(),
                            targetBaseUrl = step.GetProperty("targetBaseUrl").GetString(),
                            enabled = step.GetProperty("enabled").GetBoolean(),
                        });
                        break;
                    case "deleteFillRoute":
                        response = await admin.DeleteAsync($"/api/admin/http-routes/{fill[0]}");
                        fill.RemoveAt(0);
                        break;
                    case "shrinkInStore":
                    {
                        await using var scope = server.HostServices.CreateAsyncScope();
                        await scope.ServiceProvider.GetRequiredService<SpecusDbContext>().HttpRouteMappings
                            .Where(r => fill.Contains(r.Id))
                            .ExecuteUpdateAsync(setters => setters.SetProperty(r => r.Enabled, false));
                        break;
                    }
                    default:
                        throw new InvalidOperationException($"{label}: unknown op");
                }

                if (response is not null)
                {
                    using (response)
                    {
                        var body = await response.Content.ReadAsStringAsync();
                        Assert.True(step.GetProperty("expect").GetInt32() == (int)response.StatusCode,
                            $"{label}: {(int)response.StatusCode} {body}");
                        if (response.StatusCode == HttpStatusCode.Conflict)
                        {
                            using var answer = JsonDocument.Parse(body);
                            Assert.Contains(errorContains, answer.RootElement.GetProperty("error").GetString());
                        }
                    }
                }
                var client = control ?? throw new InvalidOperationException($"{label}: not connected");
                if (step.TryGetProperty("natControl", out var natControl) && natControl.GetBoolean())
                {
                    await AwaitAsync($"{label}: the NAT_CONTROL", () => !client.NatControls.IsEmpty);
                    using var first = JsonDocument.Parse(client.NatControls.First());
                    foreach (var route in first.RootElement.GetProperty("httpSpecusConfigList").EnumerateArray())
                    {
                        Assert.False(route.GetProperty("route").GetString()!.StartsWith("fill-", StringComparison.Ordinal),
                            $"{label}: the first NAT_CONTROL still lists {route}");
                    }
                }
                else
                {
                    await Task.Delay(Quiet);
                    Assert.True(client.NatControls.IsEmpty, $"{label}: a NAT_CONTROL reached the client");
                }
                Assert.False(client.Closed.IsCompleted, $"{label}: the control connection was closed");
            }
        }
        finally
        {
            if (control is not null)
            {
                await control.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// Replays <c>writeFailure</c> of protocol/test-vectors/nat-control-size-v1.json: a client that is
    /// online, but whose control connection cannot be written. The manual pushes answer the 409 of an
    /// offline client, and route changes, whose push fails the same way, are stored and answered as
    /// usual. Before, the write's IOException escaped: every one of these answered 500, the changes
    /// after they had been stored.
    /// </summary>
    [Fact]
    public async Task WriteFailureAnswersAsAnOfflineClient()
    {
        using var vector = JsonDocument.Parse(await File.ReadAllTextAsync(VectorPath()));
        var scenario = vector.RootElement.GetProperty("writeFailure");
        var errorContains = scenario.GetProperty("errorContains").GetString()!;

        await using var server = await TestServerFixture.StartAsync();
        using var admin = server.CreateClient();
        admin.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer",
            server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken("admin", Tenant, ManagementRole.Admin));
        var (clientId, _) = await DemoSessionAsync(server);

        var registry = server.HostServices.GetRequiredService<SessionRegistry>();
        using var lifetime = new CancellationTokenSource();
        var writer = new BrokenFrameWriter();
        var broken = new SpecusConnectionContext("nat-control-write-failure-test", "127.0.0.1:12345", writer,
            lifetime.Token, () => { }, new ReadGate(lifetime.Token), new WriteBackpressureGate(64 * 1024, 1024 * 1024));
        broken.OnLoginSuccess(DatabaseInitializer.DemoClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            clientSessionId: 1);
        registry.Replace(DatabaseInitializer.DemoClientName, broken);
        try
        {
            var routes = new Dictionary<string, long>();
            var index = 0;
            foreach (var step in scenario.GetProperty("steps").EnumerateArray())
            {
                var op = step.GetProperty("op").GetString()!;
                var label = $"step {index++} {op}";
                var writesBefore = writer.Writes;
                using var response = op switch
                {
                    "createRoute" => await admin.PostAsJsonAsync($"/api/admin/clients/{clientId}/http-routes", new
                    {
                        route = step.GetProperty("route").GetString(),
                        targetBaseUrl = step.GetProperty("targetBaseUrl").GetString(),
                        enabled = step.GetProperty("enabled").GetBoolean(),
                    }),
                    "deleteRoute" => await admin.DeleteAsync(
                        $"/api/admin/http-routes/{routes[step.GetProperty("route").GetString()!]}"),
                    "pushNatControl" => await admin.PostAsync($"/api/admin/clients/{clientId}/nat-control", null),
                    "forceRefreshPortMapping" => await admin.PostAsync(
                        $"/api/admin/clients/{clientId}/force-refresh-port-mapping", null),
                    _ => throw new InvalidOperationException($"{label}: unknown op"),
                };
                var body = await response.Content.ReadAsStringAsync();
                Assert.True(step.GetProperty("expect").GetInt32() == (int)response.StatusCode,
                    $"{label}: {(int)response.StatusCode} {body}");
                if (response.StatusCode == HttpStatusCode.Conflict)
                {
                    using var answer = JsonDocument.Parse(body);
                    Assert.Contains(errorContains, answer.RootElement.GetProperty("error").GetString());
                }
                if (op == "createRoute")
                {
                    using var created = JsonDocument.Parse(body);
                    routes[step.GetProperty("route").GetString()!] = created.RootElement.GetProperty("id").GetInt64();
                }
                Assert.True(writer.Writes > writesBefore,
                    $"{label}: nothing was written to the control connection, so its failure was not met");
            }
        }
        finally
        {
            registry.Unbind(DatabaseInitializer.DemoClientName, broken);
        }
    }

    /// <summary>
    /// A database error in the NAT_CONTROL login push is only logged, as in Java and Go: the login
    /// stands, the connection stays and the Peer Mesh login push still arrives. Before, the dispatcher
    /// closed the connection and skipped the Peer Mesh push, and the client logged in again.
    /// </summary>
    [Fact]
    public async Task LoginPushDatabaseErrorKeepsTheConnectionAndThePeerMeshPush()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"specus-missing-{Guid.NewGuid():N}", "specus.db");
        await using var server = await TestServerFixture.StartAsync(
            new Dictionary<string, string?> { ["Specus:PeerMesh:Enabled"] = "true" },
            services =>
            {
                RemoveStunTurnServer(services);
                foreach (var registration in services.Where(s => s.ServiceType == typeof(NatControlService)).ToList())
                {
                    services.Remove(registration);
                }
                // Its database cannot be opened, so the login push fails on its first query.
                services.AddScoped(provider => new NatControlService(
                    new SpecusDbContext(new DbContextOptionsBuilder<SpecusDbContext>()
                        .UseSqlite($"Data Source={missing};Mode=ReadOnly").Options),
                    provider.GetRequiredService<SessionRegistry>(),
                    provider.GetRequiredService<IOptions<NettyServerOptions>>(),
                    provider.GetRequiredService<IOptions<SpecusOptions>>(),
                    provider.GetRequiredService<ILogger<NatControlService>>()));
            });
        var (_, session) = await DemoSessionAsync(server);

        await using var control = await ControlConnection.LoginAsync(server.ControlPort, new LoginRequestPacket
        {
            ClientName = DatabaseInitializer.DemoClientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            ConnectionRole = ConnectionRole.Control,
        });
        await AwaitAsync("the Peer Mesh login push", () => control.PeerTypes.Contains("peer-config"));
        await Task.Delay(Quiet);
        Assert.True(control.NatControls.IsEmpty, "a NAT_CONTROL reached the client");
        Assert.False(control.Closed.IsCompleted, "the control connection was closed");
    }

    /// <summary>Takes the STUN/TURN hosted service out, so a test with Peer Mesh on binds no UDP port.</summary>
    private static void RemoveStunTurnServer(IServiceCollection services)
    {
        foreach (var stun in services.Where(s => s.ServiceType == typeof(IHostedService)
                     && s.ImplementationType == typeof(StunTurnServer)).ToList())
        {
            services.Remove(stun);
        }
    }

    private static async Task AwaitAsync(string what, Func<bool> condition)
    {
        var deadline = DateTime.UtcNow + Wait;
        while (!condition())
        {
            Assert.True(DateTime.UtcNow < deadline, $"{what} did not arrive within {Wait}");
            await Task.Delay(20);
        }
    }

    /// <summary>The demo client and the access token an HTTP login would hand it.</summary>
    private static async Task<(long ClientId, ClientAuthSession Session)> DemoSessionAsync(TestServerFixture server)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.AsNoTracking()
            .SingleAsync(c => c.ClientName == DatabaseInitializer.DemoClientName);
        var credential = await db.ClientCredentials.AsNoTracking()
            .SingleAsync(c => c.ApiKey == DatabaseInitializer.DemoCredentialApiKey);
        var now = DateTimeOffset.UtcNow;
        var identity = new ClientIdentity
        {
            Id = ClientIdGenerator.NewId(),
            TenantId = credential.TenantId,
            CredentialId = credential.Id,
            ClientId = account.Id,
            ClientName = account.ClientName,
            MachineFingerprint = "nat-push-failure-machine",
            OsUser = "nat-push-failure",
            Hostname = "nat-push-failure",
            FirstSeenAt = now,
            LastSeenAt = now,
        };
        var session = scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>().Create(credential, identity,
            account, TimeSpan.FromHours(1), new ClientEnvironmentInfo
            {
                MachineFingerprint = identity.MachineFingerprint,
                OsUser = identity.OsUser,
                Hostname = identity.Hostname,
            });
        return (account.Id, session);
    }

    /// <summary>
    /// Enabled routes written straight to the database, each target <paramref name="targetBytes"/> long,
    /// enough of them that the targets alone take the NAT_CONTROL JSON to <paramref name="jsonBytes"/>.
    /// </summary>
    private static async Task<List<long>> FillAsync(TestServerFixture server, long clientId, int jsonBytes,
        int targetBytes)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == clientId);
        var now = DateTimeOffset.UtcNow;
        var target = TargetPrefix + new string('f', targetBytes - TargetPrefix.Length);
        var routes = Enumerable.Range(0, (jsonBytes + targetBytes - 1) / targetBytes)
            .Select(i => new HttpRouteMapping
            {
                Id = 800_000 + i,
                TenantId = account.TenantId,
                ClientId = clientId,
                ClientName = account.ClientName,
                Route = $"fill-{i:0000}",
                TargetBaseUrl = target,
                Enabled = true,
                CreatedAt = now,
                UpdatedAt = now,
            })
            .ToList();
        db.HttpRouteMappings.AddRange(routes);
        await db.SaveChangesAsync();
        return routes.Select(r => r.Id).ToList();
    }

    private static string VectorPath()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null;
             directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "nat-control-size-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("protocol/test-vectors/nat-control-size-v1.json not found");
    }

    /// <summary>A logged-in control connection whose every write fails, as one the client has already dropped.</summary>
    private sealed class BrokenFrameWriter : IFrameWriter
    {
        private int _writes;

        public int Writes => Volatile.Read(ref _writes);

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref _writes);
            return ValueTask.FromException(new IOException("Broken pipe"));
        }
    }

    /// <summary>A control connection that keeps every NAT_CONTROL body and PEER_CONTROL type it receives.</summary>
    private sealed class ControlConnection : IAsyncDisposable
    {
        private readonly TcpClient _tcp;
        private readonly NetworkStream _stream;
        private readonly CancellationTokenSource _stop = new();
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task? _loop;

        private ControlConnection(TcpClient tcp)
        {
            _tcp = tcp;
            _stream = tcp.GetStream();
        }

        public System.Collections.Concurrent.ConcurrentQueue<string> NatControls { get; } = new();

        public System.Collections.Concurrent.ConcurrentQueue<string> PeerTypes { get; } = new();

        /// <summary>Completes when the server closed the connection.</summary>
        public Task Closed => _closed.Task;

        public static async Task<ControlConnection> LoginAsync(int port, LoginRequestPacket login)
        {
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(IPAddress.Loopback, port);
            var connection = new ControlConnection(tcp);
            try
            {
                await connection._stream.WriteAsync(PacketCodec.Encode(login));
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
                var answer = await connection.ReadAsync(timeout.Token) as LoginResponsePacket;
                Assert.True(answer is { Success: true }, $"control login failed: {answer?.Reason}");
                connection._loop = Task.Run(connection.ReadLoopAsync);
                return connection;
            }
            catch
            {
                await connection.DisposeAsync();
                throw;
            }
        }

        private async Task ReadLoopAsync()
        {
            try
            {
                while (await ReadAsync(_stop.Token) is { } packet)
                {
                    if (packet is MessageResponsePacket { MessageType: MessageType.NatControl } nat)
                    {
                        NatControls.Enqueue(nat.Message ?? string.Empty);
                    }
                    else if (packet is MessageResponsePacket { MessageType: MessageType.PeerControl } peer)
                    {
                        using var signal = JsonDocument.Parse(peer.Message ?? "{}");
                        PeerTypes.Enqueue(signal.RootElement.TryGetProperty("type", out var type)
                            ? type.GetString() ?? string.Empty
                            : string.Empty);
                    }
                }
            }
            catch (Exception)
            {
                // The server closed or reset the connection, or the test disposed it.
            }
            finally
            {
                _closed.TrySetResult();
            }
        }

        private async Task<Packet?> ReadAsync(CancellationToken cancellationToken)
        {
            var header = new byte[PacketCodec.HeaderSize];
            try
            {
                await _stream.ReadExactlyAsync(header, cancellationToken);
            }
            catch (EndOfStreamException)
            {
                return null;
            }
            var (_, length) = PacketCodec.DecodeHeader(header);
            var frame = new byte[PacketCodec.HeaderSize + length];
            header.CopyTo(frame, 0);
            await _stream.ReadExactlyAsync(frame.AsMemory(PacketCodec.HeaderSize), cancellationToken);
            return PacketCodec.DecodeExact(frame);
        }

        public async ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _tcp.Dispose();
            if (_loop is not null)
            {
                await _loop;
            }
            _stop.Dispose();
        }
    }
}
