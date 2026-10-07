using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays <c>server.scenarios</c> of protocol/test-vectors/http-route-lifecycle-v1.json, every
/// scenario on a fresh server with a new client account. Account and route changes go through the
/// admin API. A fake client logs in for real on the control and data connections (with an access
/// token issued for the account, the token a reconnecting client holds), records every
/// NAT_CONTROL it is pushed, and answers every HTTP OPEN with the vector's <c>forwarded</c>
/// response, like a client that still forwards whatever routes it once had. Public requests go
/// through the real <c>/http/{clientName}/{route}/**</c> entry.
/// </summary>
public sealed class HttpRouteLifecycleVectorTests
{
    // A space and non-ASCII letters, so the public URL segment has to be percent-encoded.
    private const string InitialClientName = "route lifecycle 客户端";

    public static TheoryData<string> ScenarioIds()
    {
        var ids = new TheoryData<string>();
        foreach (var id in ScenarioIdList())
        {
            ids.Add(id);
        }
        return ids;
    }

    private static List<string> ScenarioIdList()
    {
        using var vector = LoadVector();
        return Scenarios(vector.RootElement).Select(scenario => scenario.GetProperty("id").GetString()!).ToList();
    }

    [Fact]
    public void EveryScenarioOfTheVectorIsReplayed()
    {
        using var vector = LoadVector();
        var scenarios = Scenarios(vector.RootElement).ToList();
        var ids = ScenarioIdList();
        Assert.Equal(ids.Count, ScenarioIds().Count);
        Assert.Equal(ids.Count, ids.Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(7, scenarios.Count);
        Assert.Equal(46, scenarios.Sum(scenario => scenario.GetProperty("steps").GetArrayLength()));
    }

    [Theory]
    [MemberData(nameof(ScenarioIds))]
    public async Task ScenarioMatchesTheSharedVector(string id)
    {
        using var vector = LoadVector();
        var scenario = Scenarios(vector.RootElement).Single(item => item.GetProperty("id").GetString() == id);

        await using var run = await ScenarioRun.StartAsync(vector.RootElement, InitialClientName);
        var steps = scenario.GetProperty("steps").EnumerateArray().ToList();
        var replayed = 0;
        foreach (var (step, index) in steps.Select((step, index) => (step, index)))
        {
            await run.ReplayAsync(step, $"{id} step {index} ({step.GetProperty("op").GetString()})");
            replayed++;
        }
        Assert.Equal(steps.Count, replayed);
    }

    private static IEnumerable<JsonElement> Scenarios(JsonElement root) =>
        root.GetProperty("server").GetProperty("scenarios").EnumerateArray();

    private static JsonDocument LoadVector() => JsonDocument.Parse(File.ReadAllText(FindVector()));

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "http-route-lifecycle-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate http-route-lifecycle-v1.json");
    }

    /// <summary>One scenario: a fresh server, its admin session, the client account and the fake client.</summary>
    private sealed class ScenarioRun : IAsyncDisposable
    {
        private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
        private static readonly TimeSpan StepTimeout = TimeSpan.FromSeconds(15);

        private readonly TestServerFixture _server;
        private readonly HttpClient _admin;
        private readonly HttpClient _public;
        private readonly string _targetBaseUrl;
        private readonly string _basicUsername;
        private readonly string _basicPassword;
        private readonly FakeResponse _response;
        private readonly OpenCounter _opens = new();
        private readonly Dictionary<string, long> _routes = new(StringComparer.Ordinal);
        private long _clientId;
        private string _clientName;
        private string? _formerName;
        private ClientAuthSession? _session;
        private FakeClient? _fake;

        private ScenarioRun(TestServerFixture server, HttpClient admin, JsonElement vector, string clientName)
        {
            _server = server;
            _admin = admin;
            _public = server.Server.CreateClient();
            _clientName = clientName;
            _targetBaseUrl = vector.GetProperty("targetBaseUrl").GetString()!;
            var credentials = vector.GetProperty("basicCredentials");
            _basicUsername = credentials.GetProperty("username").GetString()!;
            _basicPassword = credentials.GetProperty("password").GetString()!;
            var response = vector.GetProperty("fakeClientResponse");
            _response = new FakeResponse(response.GetProperty("status").GetInt32(),
                response.GetProperty("headers").EnumerateArray().Select(header => header.GetString()!).ToList(),
                response.GetProperty("body").GetString()!);
        }

        public static async Task<ScenarioRun> StartAsync(JsonElement vector, string clientName)
        {
            var server = await TestServerFixture.StartAsync();
            var admin = server.Server.CreateClient();
            using (var login = await admin.PostAsJsonAsync("/auth/login", new { username = "admin", password = "admin" }))
            {
                login.EnsureSuccessStatusCode();
                var token = await login.Content.ReadFromJsonAsync<JsonElement>(JsonOptions);
                admin.DefaultRequestHeaders.Authorization =
                    new AuthenticationHeaderValue("Bearer", token.GetProperty("accessToken").GetString());
            }
            var run = new ScenarioRun(server, admin, vector, clientName);
            await run.CreateClientAsync("create the scenario's client");
            return run;
        }

        public async Task ReplayAsync(JsonElement step, string label)
        {
            switch (step.GetProperty("op").GetString())
            {
                case "createRoute":
                {
                    var route = step.GetProperty("route").GetString()!;
                    var auth = step.GetProperty("auth").GetBoolean();
                    var pushesBefore = _fake?.NatControlCount ?? 0;
                    var created = await AdminAsync(HttpMethod.Post, $"/api/admin/clients/{_clientId}/http-routes",
                        new
                        {
                            route,
                            targetBaseUrl = _targetBaseUrl,
                            enabled = true,
                            authEnabled = auth,
                            authUsername = auth ? _basicUsername : null,
                            authPassword = auth ? _basicPassword : null,
                        }, label);
                    _routes[route] = created.GetProperty("id").GetInt64();
                    await ExpectPushAsync(step, pushesBefore, label);
                    break;
                }
                case "setRouteEnabled":
                {
                    var route = step.GetProperty("route").GetString()!;
                    var pushesBefore = _fake?.NatControlCount ?? 0;
                    await AdminAsync(HttpMethod.Put, $"/api/admin/http-routes/{RouteId(route, label)}",
                        new { route, targetBaseUrl = _targetBaseUrl, enabled = step.GetProperty("enabled").GetBoolean() },
                        label);
                    await ExpectPushAsync(step, pushesBefore, label);
                    break;
                }
                case "deleteRoute":
                {
                    var route = step.GetProperty("route").GetString()!;
                    var pushesBefore = _fake?.NatControlCount ?? 0;
                    await AdminAsync(HttpMethod.Delete, $"/api/admin/http-routes/{RouteId(route, label)}", null, label);
                    _routes.Remove(route);
                    await ExpectPushAsync(step, pushesBefore, label);
                    break;
                }
                case "setClientEnabled":
                    await AdminAsync(HttpMethod.Put, $"/api/admin/clients/{_clientId}",
                        new { enabled = step.GetProperty("enabled").GetBoolean() }, label);
                    await ExpectSessionClosedAsync(step, label);
                    break;
                case "renameClient":
                {
                    var renamed = _clientName + step.GetProperty("suffix").GetString();
                    await AdminAsync(HttpMethod.Put, $"/api/admin/clients/{_clientId}", new { clientName = renamed },
                        label);
                    _formerName = _clientName;
                    _clientName = renamed;
                    await ExpectSessionClosedAsync(step, label);
                    break;
                }
                case "deleteClient":
                    await AdminAsync(HttpMethod.Delete, $"/api/admin/clients/{_clientId}", null, label);
                    _routes.Clear();
                    _session = null;
                    await ExpectSessionClosedAsync(step, label);
                    break;
                case "createClient":
                    await CreateClientAsync(label);
                    break;
                case "connect":
                    await ConnectAsync(step, label);
                    break;
                case "disconnect":
                    Assert.True(_fake is not null, $"{label}: no fake client is connected");
                    await _fake.DisposeAsync();
                    _fake = null;
                    await WaitOfflineAsync(label);
                    break;
                case "request":
                    await RequestAsync(step, label);
                    break;
                default:
                    Assert.Fail($"{label}: unknown op");
                    break;
            }
        }

        private async Task CreateClientAsync(string label)
        {
            var created = await AdminAsync(HttpMethod.Post, "/api/admin/clients",
                new { clientName = _clientName, enabled = true }, label);
            var client = created.GetProperty("client");
            Assert.Equal(_clientName, client.GetProperty("clientName").GetString());
            _clientId = client.GetProperty("id").GetInt64();
            _routes.Clear();
            _session = null;
        }

        private async Task ConnectAsync(JsonElement step, string label)
        {
            Assert.True(_fake is null, $"{label}: the fake client is already connected");
            // Kept across a disconnect: the second connect reconnects with the same access token,
            // so it gets no new HTTP login snapshot and only the login push tells it about routes.
            _session ??= await IssueSessionAsync();
            _fake = await FakeClient.ConnectAsync(_server.ControlPort, _clientName, _session, _response, _opens,
                label);
            var push = await _fake.NatControlAsync(0, label + " login push");
            AssertRouteList(push, step.GetProperty("expectLoginPush"), label + " login push");
        }

        private async Task ExpectPushAsync(JsonElement step, int pushesBefore, string label)
        {
            var expected = step.GetProperty("expectPush");
            if (expected.ValueKind == JsonValueKind.Null)
            {
                return;
            }
            Assert.True(_fake is not null, $"{label}: a push is expected but no fake client is connected");
            var push = await _fake.NatControlAsync(pushesBefore, label + " push");
            AssertRouteList(push, expected, label + " push");
        }

        private async Task ExpectSessionClosedAsync(JsonElement step, string label)
        {
            if (!step.TryGetProperty("expectSessionClosed", out var expected) || !expected.GetBoolean())
            {
                return;
            }
            Assert.True(_fake is not null, $"{label}: no fake client is connected");
            Assert.True(await _fake.WaitClosedAsync(TimeSpan.FromSeconds(5)),
                $"{label}: the server did not close the control and data connections within 5 s");
            await _fake.DisposeAsync();
            _fake = null;
        }

        private async Task RequestAsync(JsonElement step, string label)
        {
            var clientName = step.GetProperty("client").GetString() switch
            {
                "current" => _clientName,
                "former" => _formerName ?? throw new InvalidOperationException($"{label}: no former name"),
                var other => throw new InvalidOperationException($"{label}: unknown client {other}"),
            };
            var route = step.GetProperty("route");
            var url = route.ValueKind == JsonValueKind.Null
                ? $"/http/{Uri.EscapeDataString(clientName)}/"
                : $"/http/{Uri.EscapeDataString(clientName)}/{Uri.EscapeDataString(route.GetString()!)}"
                  + step.GetProperty("path").GetString();
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            switch (step.GetProperty("credentials").GetString())
            {
                case "none":
                    break;
                case "valid":
                    request.Headers.Authorization = Basic(_basicUsername, _basicPassword);
                    break;
                case "wrong":
                    request.Headers.Authorization = Basic(_basicUsername, "wrong");
                    break;
                default:
                    Assert.Fail($"{label}: unknown credentials");
                    break;
            }
            var websocket = step.GetProperty("websocket").GetBoolean();
            if (websocket)
            {
                request.Headers.Connection.Add("Upgrade");
                request.Headers.Upgrade.Add(new ProductHeaderValue("websocket"));
                request.Headers.TryAddWithoutValidation("Sec-WebSocket-Key",
                    Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)));
                request.Headers.TryAddWithoutValidation("Sec-WebSocket-Version", "13");
            }

            var opensBefore = _opens.Count;
            using var timeout = new CancellationTokenSource(StepTimeout);
            using var response = await _public.SendAsync(request, timeout.Token);
            var body = await response.Content.ReadAsStringAsync(timeout.Token);
            var status = (int)response.StatusCode;
            var forwarded = _opens.Count > opensBefore;
            var seen = $"{label}: GET {url} -> {status} {body}";

            var expect = step.GetProperty("expect");
            if (expect.TryGetProperty("status", out var expectedStatus))
            {
                Assert.True(expectedStatus.GetInt32() == status, $"{seen}; expected status {expectedStatus}");
            }
            if (expect.TryGetProperty("statusAnyOf", out var anyOf))
            {
                Assert.True(anyOf.EnumerateArray().Any(item => item.GetInt32() == status),
                    $"{seen}; expected status in {anyOf}");
            }
            if (websocket)
            {
                Assert.True(response.StatusCode != HttpStatusCode.SwitchingProtocols, $"{seen}; upgrade accepted");
            }
            if (expect.TryGetProperty("noStore", out var noStore) && noStore.GetBoolean())
            {
                Assert.True(response.Headers.CacheControl?.NoStore == true,
                    $"{seen}; Cache-Control is '{response.Headers.CacheControl}', expected no-store");
            }
            if (expect.TryGetProperty("basicChallenge", out var challenge) && challenge.GetBoolean())
            {
                var schemes = response.Headers.WwwAuthenticate.Select(value => value.Scheme).ToList();
                Assert.True(schemes.Count > 0 && schemes.All(scheme => scheme == "Basic"),
                    $"{seen}; WWW-Authenticate is '{response.Headers.WwwAuthenticate}', expected Basic");
            }
            if (expect.TryGetProperty("body", out var expectedBody))
            {
                Assert.True(expectedBody.GetString() == body, $"{seen}; expected body {expectedBody}");
            }
            Assert.True(expect.GetProperty("forwarded").GetBoolean() == forwarded,
                $"{seen}; forwarded to the fake client: {forwarded}, expected {expect.GetProperty("forwarded")}");
        }

        /// <summary>The access token an HTTP login would hand this account, kept by a reconnecting client.</summary>
        private async Task<ClientAuthSession> IssueSessionAsync()
        {
            await using var scope = _server.HostServices.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var account = await db.ClientAccounts.AsNoTracking().SingleAsync(c => c.Id == _clientId);
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
                MachineFingerprint = "route-lifecycle-machine",
                OsUser = "route-lifecycle",
                Hostname = "route-lifecycle",
                FirstSeenAt = now,
                LastSeenAt = now,
            };
            return scope.ServiceProvider.GetRequiredService<ClientAuthSessionStore>().Create(credential, identity,
                account, TimeSpan.FromHours(1), new ClientEnvironmentInfo
                {
                    MachineFingerprint = identity.MachineFingerprint,
                    OsUser = identity.OsUser,
                    Hostname = identity.Hostname,
                });
        }

        /// <summary>Waits until the admin API lists the client offline and its session is no longer online.</summary>
        private async Task WaitOfflineAsync(string label)
        {
            var sessions = _server.HostServices.GetRequiredService<ClientAuthSessionStore>();
            var deadline = DateTime.UtcNow + StepTimeout;
            while (true)
            {
                var clients = await AdminAsync(HttpMethod.Get, "/api/admin/clients", null, label);
                var online = clients.EnumerateArray()
                    .Single(client => client.GetProperty("id").GetInt64() == _clientId)
                    .GetProperty("online").GetBoolean();
                var sessionOnline = _session is not null
                                    && sessions.FindById(_session.Id)?.Status == ClientAuthSessionStatus.NettyOnline;
                if (!online && !sessionOnline)
                {
                    return;
                }
                Assert.True(DateTime.UtcNow < deadline, $"{label}: the server still shows the client online");
                await Task.Delay(25);
            }
        }

        private long RouteId(string route, string label) =>
            _routes.TryGetValue(route, out var id) ? id : throw new InvalidOperationException($"{label}: no route {route}");

        private async Task<JsonElement> AdminAsync(HttpMethod method, string path, object? body, string label)
        {
            using var request = new HttpRequestMessage(method, path);
            if (body is not null)
            {
                request.Content = JsonContent.Create(body, options: JsonOptions);
            }
            using var timeout = new CancellationTokenSource(StepTimeout);
            using var response = await _admin.SendAsync(request, timeout.Token);
            var text = await response.Content.ReadAsStringAsync(timeout.Token);
            Assert.True(response.IsSuccessStatusCode, $"{label}: {method} {path} -> {(int)response.StatusCode} {text}");
            if (string.IsNullOrWhiteSpace(text))
            {
                return default;
            }
            using var document = JsonDocument.Parse(text);
            return document.RootElement.Clone();
        }

        private static AuthenticationHeaderValue Basic(string username, string password) =>
            new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}")));

        private static void AssertRouteList(string message, JsonElement expected, string label)
        {
            using var bean = JsonDocument.Parse(message);
            Assert.True(bean.RootElement.TryGetProperty("httpSpecusConfigList", out var routes)
                        && routes.ValueKind == JsonValueKind.Array,
                $"{label}: NAT_CONTROL must carry httpSpecusConfigList as an array: {message}");
            var actual = routes.EnumerateArray().Select(route => route.GetProperty("route").GetString()!)
                .Order(StringComparer.Ordinal).ToList();
            var wanted = expected.EnumerateArray().Select(route => route.GetString()!)
                .Order(StringComparer.Ordinal).ToList();
            Assert.True(wanted.SequenceEqual(actual),
                $"{label}: routes [{string.Join(", ", actual)}], expected [{string.Join(", ", wanted)}]");
        }

        public async ValueTask DisposeAsync()
        {
            if (_fake is not null)
            {
                await _fake.DisposeAsync();
            }
            _public.Dispose();
            _admin.Dispose();
            await _server.DisposeAsync();
        }
    }

    private sealed record FakeResponse(int Status, List<string> Headers, string Body);

    /// <summary>Every NAT OPEN any fake client of the scenario received.</summary>
    private sealed class OpenCounter
    {
        private int _count;

        public int Count => Volatile.Read(ref _count);

        public void Increment() => Interlocked.Increment(ref _count);
    }

    /// <summary>
    /// A client that logged in on a control and a data connection. It keeps every NAT_CONTROL body
    /// in arrival order and answers every HTTP OPEN with the vector's response, whatever the route.
    /// </summary>
    private sealed class FakeClient : IAsyncDisposable
    {
        private readonly List<string> _natControls = [];
        private readonly FakeResponse _response;
        private readonly OpenCounter _opens;
        private FakeConnection? _control;
        private FakeConnection? _data;

        private FakeClient(FakeResponse response, OpenCounter opens)
        {
            _response = response;
            _opens = opens;
        }

        public int NatControlCount
        {
            get
            {
                lock (_natControls)
                {
                    return _natControls.Count;
                }
            }
        }

        public static async Task<FakeClient> ConnectAsync(int port, string clientName, ClientAuthSession session,
            FakeResponse response, OpenCounter opens, string label)
        {
            var client = new FakeClient(response, opens);
            try
            {
                client._control = await FakeConnection.ConnectAsync(port);
                var control = await client._control.LoginAsync(Login(clientName, session, ConnectionRole.Control));
                Assert.True(control.Success, $"{label}: control login failed: {control.Reason}");
                client._control.Start(client.OnControlAsync);

                client._data = await FakeConnection.ConnectAsync(port);
                var data = await client._data.LoginAsync(Login(clientName, session, ConnectionRole.Data));
                Assert.True(data.Success, $"{label}: data login failed: {data.Reason}");
                client._data.Start(client.OnDataAsync);
                return client;
            }
            catch
            {
                await client.DisposeAsync();
                throw;
            }
        }

        public async Task<string> NatControlAsync(int index, string label)
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(5);
            while (true)
            {
                lock (_natControls)
                {
                    if (_natControls.Count > index)
                    {
                        return _natControls[index];
                    }
                }
                Assert.True(DateTime.UtcNow < deadline, $"{label}: no NAT_CONTROL #{index} within 5 s");
                await Task.Delay(20);
            }
        }

        public async Task<bool> WaitClosedAsync(TimeSpan timeout)
        {
            try
            {
                await Task.WhenAll(_control!.Closed, _data!.Closed).WaitAsync(timeout);
                return true;
            }
            catch (TimeoutException)
            {
                return false;
            }
        }

        private static LoginRequestPacket Login(string clientName, ClientAuthSession session, string role) => new()
        {
            ClientName = clientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            ConnectionRole = role,
        };

        private async Task OnControlAsync(Packet packet)
        {
            switch (packet)
            {
                case MessageResponsePacket { MessageType: MessageType.NatControl } message:
                    lock (_natControls)
                    {
                        _natControls.Add(message.Message ?? string.Empty);
                    }
                    break;
                case HeartbeatRequestPacket:
                    await _control!.SendAsync(new HeartbeatResponsePacket());
                    break;
            }
        }

        private async Task OnDataAsync(Packet packet)
        {
            switch (packet)
            {
                case NatMessagePacket { NatMessageType: NatMessageType.Open } open:
                    _opens.Increment();
                    if (Equals(open.MetaData?.GetValueOrDefault("source"), "http"))
                    {
                        await RespondAsync(open.StreamId);
                    }
                    break;
                case HeartbeatRequestPacket:
                    await _data!.SendAsync(new HeartbeatResponsePacket());
                    break;
            }
        }

        private async Task RespondAsync(uint streamId)
        {
            await _data!.SendAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Open,
                StreamId = streamId,
                MetaData = new Dictionary<string, object?>
                {
                    ["source"] = "http",
                    ["phase"] = "response",
                    ["statusCode"] = _response.Status,
                    ["headers"] = _response.Headers.ToList(),
                },
            });
            await _data.SendAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Data,
                StreamId = streamId,
                Data = Encoding.UTF8.GetBytes(_response.Body),
            });
            await _data.SendAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Fin,
                StreamId = streamId,
            });
        }

        public async ValueTask DisposeAsync()
        {
            if (_data is not null)
            {
                await _data.DisposeAsync();
            }
            if (_control is not null)
            {
                await _control.DisposeAsync();
            }
        }
    }

    /// <summary>One TCP connection to the control port, framed with the real packet codec.</summary>
    private sealed class FakeConnection : IAsyncDisposable
    {
        private readonly TcpClient _tcp;
        private readonly NetworkStream _stream;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private readonly CancellationTokenSource _stop = new();
        private readonly TaskCompletionSource _closed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Task? _loop;

        private FakeConnection(TcpClient tcp)
        {
            _tcp = tcp;
            _stream = tcp.GetStream();
        }

        /// <summary>Completes when the server closed the connection (or it was disposed).</summary>
        public Task Closed => _closed.Task;

        public static async Task<FakeConnection> ConnectAsync(int port)
        {
            var tcp = new TcpClient { NoDelay = true };
            try
            {
                await tcp.ConnectAsync(IPAddress.Loopback, port);
            }
            catch
            {
                tcp.Dispose();
                throw;
            }
            return new FakeConnection(tcp);
        }

        public async Task<LoginResponsePacket> LoginAsync(LoginRequestPacket login)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await SendAsync(login);
            while (true)
            {
                var packet = await ReadAsync(timeout.Token)
                             ?? throw new IOException("connection closed before LOGIN_RESPONSE");
                if (packet is LoginResponsePacket response)
                {
                    return response;
                }
            }
        }

        public void Start(Func<Packet, Task> handle) => _loop = Task.Run(() => ReadLoopAsync(handle));

        public async Task SendAsync(Packet packet)
        {
            var frame = PacketCodec.Encode(packet);
            await _writeLock.WaitAsync();
            try
            {
                await _stream.WriteAsync(frame);
            }
            finally
            {
                _writeLock.Release();
            }
        }

        private async Task ReadLoopAsync(Func<Packet, Task> handle)
        {
            try
            {
                while (await ReadAsync(_stop.Token) is { } packet)
                {
                    await handle(packet);
                }
            }
            catch (Exception)
            {
                // The server closed or reset the connection, or the test disposed it. Anything else
                // ends the connection too, as it would end a real client's, and shows up as a
                // missing push or a request that did not reach this client.
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
            _closed.TrySetResult();
            _stop.Dispose();
            _writeLock.Dispose();
        }
    }
}
