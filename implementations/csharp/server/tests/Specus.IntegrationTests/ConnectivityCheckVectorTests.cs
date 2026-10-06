using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Specus.Server.Connectivity;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays protocol/test-vectors/service-connectivity-check-v1.json through the real
/// <see cref="ConnectivityCheckService"/> and <see cref="ConnectivityCheckAdmission"/>: an in-memory
/// route store, a scripted device that moves a fake monotonic clock to each answer's atMs, and a
/// field-by-field comparison of the API answer. The two cases decided before the service runs
/// (unauthenticated, bad request) go through the real HTTP endpoint.
/// </summary>
public sealed class ConnectivityCheckVectorTests
{
    private const long RouteId = 42;
    private const long StartMs = 5_000_000;
    private const string Tenant = "default";
    private const string Owner = "alice";
    private static readonly DateTimeOffset WallClock = new(2026, 10, 6, 8, 0, 0, 250, TimeSpan.Zero);

    private static readonly string[] BodyKeyOrder =
    [
        "schemaVersion", "kind", "routeId", "checkedAt", "outcome", "stoppedAt", "code", "totalMs",
        "requests", "stages", "statusClass",
    ];

    public static TheoryData<string> CaseNames()
    {
        var names = new TheoryData<string>();
        foreach (var testCase in LoadVector()["cases"]!.AsArray())
        {
            names.Add(testCase!["name"]!.GetValue<string>());
        }
        return names;
    }

    [Fact]
    public void EveryVectorCaseIsReplayed()
    {
        // Guards the theory below against an empty vector or cases that would collapse into one.
        var names = LoadVector()["cases"]!.AsArray().Select(c => c!["name"]!.GetValue<string>()).ToArray();
        Assert.Equal(38, names.Length);
        Assert.Equal(names.Length, names.Distinct(StringComparer.Ordinal).Count());
    }

    [Theory]
    [MemberData(nameof(CaseNames))]
    public async Task CaseMatchesTheSharedVector(string name)
    {
        var testCase = LoadVector()["cases"]!.AsArray().Single(c => c!["name"]!.GetValue<string>() == name)!;
        var input = testCase["input"]!.AsObject();
        var expect = testCase["expect"]!.AsObject();
        var expectedStatus = expect["httpStatus"]!.GetValue<int>();

        if (!Flag(input, "authenticated") || !Flag(input, "requestValid"))
        {
            await AssertThroughHttpEndpointAsync(Flag(input, "authenticated"), expect);
            return;
        }

        var clock = new ManualTimeProvider(StartMs, WallClock);
        var logs = new CapturingLogger();
        var admission = new ConnectivityCheckAdmission();
        var device = new ScriptedDevice(clock, StartMs);
        var routes = new InMemoryRoutes();
        var service = new ConnectivityCheckService(routes, device, admission, clock, logs);
        var caller = new ManagementContext(Tenant, Owner, ManagementRole.User, false);

        if (!Flag(input, "configReadable"))
        {
            routes.Fail = true;
            await AssertRefusalAsync(service, caller, expect);
            return;
        }
        if (!Flag(input, "routeVisible"))
        {
            // Absent, another tenant's and another owner's route answer identically.
            await AssertRefusalAsync(service, caller, expect);
            routes.Add(Route(RouteId, enabled: true, targetValid: true), Account(Tenant, "bob", enabled: true));
            await AssertRefusalAsync(service, caller, expect);
            routes.Add(Route(RouteId, enabled: true, targetValid: true), Account("tenant-b", Owner, enabled: true));
            await AssertRefusalAsync(service, caller, expect);
            Assert.Empty(device.Opened);
            return;
        }
        if (input["admission"]?.GetValue<string>() is { } admissionCase)
        {
            await AssertAdmissionRefusalAsync(admissionCase, routes, device, service, caller, expect);
            return;
        }

        var route = input["route"]!.AsObject();
        var deviceInput = input["device"]!.AsObject();
        routes.Add(Route(RouteId, Flag(route, "enabled"), Flag(route, "targetValid")),
            Account(Tenant, Owner, Flag(deviceInput, "enabled")));
        device.PresenceValue = !Flag(deviceInput, "controlOnline")
            ? ConnectivityDevicePresence.Offline
            : !Flag(deviceInput, "dataOnline")
                ? ConnectivityDevicePresence.DataChannelDown
                : ConnectivityDevicePresence.Online;
        device.Capability = deviceInput["httpRouteCapability"]?.GetValue<int>() ?? 0;
        foreach (var answer in input["answers"]!.AsArray())
        {
            device.Answers.Enqueue(answer!.AsObject());
        }

        var result = await service.CheckAsync(caller, RouteId, "/", new ConnectivityCheckStart(StartMs, WallClock),
            CancellationToken.None);

        Assert.Equal(expectedStatus, result.HttpStatus);
        Assert.Null(result.RetryAfterSeconds);
        var expectedBody = expect["body"]!.AsObject();
        var body = JsonNode.Parse(result.BodyJson())!.AsObject();
        Assert.Equal(BodyKeyOrder.Where(key => key is "routeId" or "checkedAt" || expectedBody.ContainsKey(key)),
            body.Select(pair => pair.Key));
        Assert.Equal(RouteId, body["routeId"]!.GetValue<long>());
        Assert.Equal("2026-10-06T08:00:00Z", body["checkedAt"]!.GetValue<string>());
        foreach (var (key, expected) in expectedBody)
        {
            Assert.True(JsonNode.DeepEquals(expected, body[key]),
                $"{name}: {key} expected {expected?.ToJsonString() ?? "null"} got {body[key]?.ToJsonString() ?? "null"}");
        }
        Assert.Empty(device.Answers);

        // Every probe is the fixed request of section 5.1, in the order the vector lists them.
        var requests = expectedBody["requests"]!.AsArray().Select(m => m!.GetValue<string>()).ToArray();
        Assert.Equal(requests, device.Opened.Select(m => (string)m["method"]!));
        foreach (var metadata in device.Opened)
        {
            AssertProbeMetadata(metadata, (string)metadata["method"]!, "api", "/");
        }

        var line = Assert.Single(logs.Lines);
        Assert.Equal(
            $"[connectivity-check] tenant={Tenant} user={Owner} route={RouteId} " +
            $"outcome={expectedBody["outcome"]!.GetValue<string>()} " +
            $"stage={expectedBody["stoppedAt"]?.GetValue<string>() ?? "-"} " +
            $"code={expectedBody["code"]!.GetValue<string>()} totalMs={expectedBody["totalMs"]!.GetValue<long>()}",
            line);
        Assert.Equal(0, admission.InFlight);
    }

    /// <summary>The vector's rate.events through the limiter itself, with its clock in ms.</summary>
    [Fact]
    public void RateEventsReplayThroughTheLimiter()
    {
        var admission = new ConnectivityCheckAdmission();
        var events = LoadVector()["rate"]!["events"]!.AsArray();
        Assert.NotEmpty(events);
        foreach (var item in events)
        {
            var e = item!.AsObject();
            var user = e["username"]!.GetValue<string>();
            var routeId = e["routeId"]!.GetValue<long>();
            var decision = admission.TryAdmit(Tenant, user, routeId, e["atMs"]!.GetValue<long>());
            Assert.Equal(e["admitted"]!.GetValue<bool>(), decision.Admitted);
            if (decision.Admitted)
            {
                admission.Release(Tenant, routeId);
                continue;
            }
            Assert.Equal(e["httpStatus"]!.GetValue<int>(), decision.HttpStatus);
            Assert.Equal(e["code"]!.GetValue<string>(), decision.Code);
            Assert.Equal(e["retryAfterSeconds"]!.GetValue<int>(), decision.RetryAfterSeconds);
            Assert.Equal(e["limitedBy"]!.GetValue<string>(), decision.LimitedBy);
        }
    }

    /// <summary>
    /// The same events through the whole service: a refusal is a 429 with Retry-After and changes
    /// nothing, and rate-limited refusals are logged at most once per user and minute.
    /// </summary>
    [Fact]
    public async Task RateEventsReplayThroughTheService()
    {
        var clock = new ManualTimeProvider(0, WallClock);
        var logs = new CapturingLogger();
        var routes = new InMemoryRoutes();
        var device = new ScriptedDevice(clock, 0) { PresenceValue = ConnectivityDevicePresence.Offline };
        var service = new ConnectivityCheckService(routes, device, new ConnectivityCheckAdmission(), clock, logs);
        var events = LoadVector()["rate"]!["events"]!.AsArray();
        foreach (var routeId in events.Select(e => e!["routeId"]!.GetValue<long>()).Distinct())
        {
            routes.Add(Route(routeId, enabled: true, targetValid: true), Account(Tenant, Owner, enabled: true));
        }

        var refusalLines = new List<string>();
        foreach (var item in events)
        {
            var e = item!.AsObject();
            clock.SetMs(e["atMs"]!.GetValue<long>());
            var user = e["username"]!.GetValue<string>();
            var caller = new ManagementContext(Tenant, user,
                user == Owner ? ManagementRole.User : ManagementRole.Admin, false);
            var routeId = e["routeId"]!.GetValue<long>();
            var result = await service.CheckAsync(caller, routeId, "/", ConnectivityCheckStart.Now(clock),
                CancellationToken.None);
            if (e["admitted"]!.GetValue<bool>())
            {
                Assert.Equal(200, result.HttpStatus);
                Assert.Equal("DEVICE_OFFLINE", JsonNode.Parse(result.BodyJson())!["code"]!.GetValue<string>());
                continue;
            }
            Assert.Equal(e["httpStatus"]!.GetValue<int>(), result.HttpStatus);
            Assert.Equal(e["code"]!.GetValue<string>(), result.Code);
            Assert.Equal(e["retryAfterSeconds"]!.GetValue<int>(), result.RetryAfterSeconds);
            Assert.Equal($$"""{"code":"{{e["code"]!.GetValue<string>()}}"}""", result.BodyJson());
        }

        refusalLines.AddRange(logs.Lines.Where(line => line.Contains(" refused ", StringComparison.Ordinal)));
        Assert.Equal(
        [
            "[connectivity-check] tenant=default user=alice route=1 refused code=CHECK_RATE_LIMITED retryAfter=10",
            "[connectivity-check] tenant=default user=admin route=1 refused code=CHECK_RATE_LIMITED retryAfter=10",
        ], refusalLines);
    }

    [Fact]
    public void LimiterRefusesNewKeysOnlyWhenEveryEntryIsStillLive()
    {
        var limiter = new GcraLimiter<int>(10_000, 1, 2);
        limiter.Take(1, 0);
        limiter.Take(2, 5_000);
        Assert.False(limiter.HasRoomFor(3, 9_999));
        Assert.True(limiter.HasRoomFor(1, 9_999));
        // At 10 000 the first entry is no longer live and may go; the second one may not.
        Assert.True(limiter.HasRoomFor(3, 10_000));
        Assert.Equal(1, limiter.Count);
        Assert.Equal(5_000, limiter.WaitMs(2, 10_000));
    }

    [Fact]
    public void FullKeyTableIsBusyAndConsumesNothing()
    {
        var admission = new ConnectivityCheckAdmission();
        for (var i = 0; i < ConnectivityCheckAdmission.MaxKeys; i++)
        {
            Assert.True(admission.TryAdmit(Tenant, "user-" + (i / 10), i + 1, 0).Admitted);
            admission.Release(Tenant, i + 1);
        }
        var refused = admission.TryAdmit(Tenant, "someone-else", 999_999, 1);
        Assert.False(refused.Admitted);
        Assert.Equal(503, refused.HttpStatus);
        Assert.Equal("CHECK_BUSY", refused.Code);
        Assert.Equal(1, refused.RetryAfterSeconds);
        // Once the route entries are no longer live, the same request is admitted.
        Assert.True(admission.TryAdmit(Tenant, "someone-else", 999_999, 10_000).Admitted);
    }

    private static async Task AssertAdmissionRefusalAsync(string admissionCase, InMemoryRoutes routes,
        ScriptedDevice device, ConnectivityCheckService service, ManagementContext caller, JsonObject expect)
    {
        routes.Add(Route(RouteId, enabled: true, targetValid: true), Account(Tenant, Owner, enabled: true));
        device.PresenceValue = ConnectivityDevicePresence.Online;
        var running = new List<Task<ConnectivityCheckResult>>();
        if (admissionCase == "route-in-progress")
        {
            running.Add(service.CheckAsync(caller, RouteId, "/", new ConnectivityCheckStart(StartMs, WallClock),
                CancellationToken.None));
        }
        else
        {
            Assert.Equal("server-busy", admissionCase);
            for (var i = 0; i < ConnectivityCheckAdmission.MaxConcurrentPerServer; i++)
            {
                var other = 1_000 + i;
                routes.Add(Route(other, enabled: true, targetValid: true), Account(Tenant, "owner-" + i, enabled: true));
                running.Add(service.CheckAsync(new ManagementContext(Tenant, "owner-" + i, ManagementRole.User, false),
                    other, "/", new ConnectivityCheckStart(StartMs, WallClock), CancellationToken.None));
            }
        }
        Assert.All(running, task => Assert.False(task.IsCompleted));

        await AssertRefusalAsync(service, caller, expect);

        device.ReleaseBlocked();
        foreach (var task in running)
        {
            Assert.Equal(200, (await task).HttpStatus);
        }
    }

    private static async Task AssertRefusalAsync(ConnectivityCheckService service, ManagementContext caller,
        JsonObject expect)
    {
        var result = await service.CheckAsync(caller, RouteId, "/", new ConnectivityCheckStart(StartMs, WallClock),
            CancellationToken.None);
        var code = expect["code"]!.GetValue<string>();
        Assert.Equal(expect["httpStatus"]!.GetValue<int>(), result.HttpStatus);
        Assert.Equal(code, result.Code);
        Assert.Null(result.Report);
        Assert.Equal($$"""{"code":"{{code}}"}""", result.BodyJson());
        // 429 and 503 carry Retry-After; CHECK_UNAVAILABLE waits one second like the others.
        var retryAfter = expect["retryAfterSeconds"]?.GetValue<int>()
                         ?? (result.HttpStatus == 503 ? 1 : (int?)null);
        Assert.Equal(retryAfter, result.RetryAfterSeconds);
    }

    private static async Task AssertThroughHttpEndpointAsync(bool authenticated, JsonObject expect)
    {
        await using var server = await TestServerFixture.StartAsync();
        using var client = server.CreateClient();
        if (authenticated)
        {
            var login = await client.PostAsJsonAsync("/auth/login", new { username = "admin", password = "admin" });
            login.EnsureSuccessStatusCode();
            var token = (await login.Content.ReadFromJsonAsync<JsonObject>())!["accessToken"]!.GetValue<string>();
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        }
        using var response = await client.PostAsync("/api/admin/http-routes/1/connectivity-check",
            new StringContent("""{"path":"/healthz","extra":true}""", Encoding.UTF8, "application/json"));

        Assert.Equal((HttpStatusCode)expect["httpStatus"]!.GetValue<int>(), response.StatusCode);
        Assert.Equal("private, no-store", RawCacheControl(response));
        if (expect["code"]?.GetValue<string>() is { } code)
        {
            Assert.Equal($$"""{"code":"{{code}}"}""", await response.Content.ReadAsStringAsync());
        }
    }

    internal static void AssertProbeMetadata(IReadOnlyDictionary<string, object?> metadata, string method,
        string route, string path)
    {
        Assert.Equal(
            ["source", "phase", "requestId", "method", "route", "relativePath", "rawQuery", "headers"],
            metadata.Keys.ToArray());
        Assert.Equal("http", metadata["source"]);
        Assert.Equal("request", metadata["phase"]);
        Assert.Matches(new Regex("^[0-9a-f]{32}$"), (string)metadata["requestId"]!);
        Assert.Equal(method, metadata["method"]);
        Assert.Equal(route, metadata["route"]);
        Assert.Equal(path, metadata["relativePath"]);
        Assert.Equal(string.Empty, metadata["rawQuery"]);
        Assert.Equal(["Accept:*/*", "User-Agent:specus-connectivity-check/1"],
            Assert.IsAssignableFrom<IEnumerable<string>>(metadata["headers"]));
    }

    /// <summary>The header as sent; the typed CacheControl value re-orders its directives.</summary>
    internal static string RawCacheControl(HttpResponseMessage response) =>
        response.Headers.NonValidated.TryGetValues("Cache-Control", out var values) ? values.ToString() : "";

    private static bool Flag(JsonObject input, string key) => input[key]?.GetValue<bool>() ?? true;

    private static HttpRouteMapping Route(long id, bool enabled, bool targetValid) => new()
    {
        Id = id,
        TenantId = Tenant,
        ClientId = id * 10,
        ClientName = "probe-device",
        Route = "api",
        TargetBaseUrl = targetValid ? "http://127.0.0.1:8080/base" : "ftp://127.0.0.1/base",
        Enabled = enabled,
    };

    private static ClientAccount Account(string tenant, string owner, bool enabled) => new()
    {
        TenantId = tenant,
        OwnerUsername = owner,
        ClientName = "probe-device",
        Enabled = enabled,
    };

    private static JsonObject LoadVector() => JsonNode.Parse(File.ReadAllText(FindVector()))!.AsObject();

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "service-connectivity-check-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate service-connectivity-check-v1.json");
    }

    /// <summary>A monotonic clock in whole milliseconds that only moves when told to.</summary>
    internal sealed class ManualTimeProvider(long startMs, DateTimeOffset wallClock) : TimeProvider
    {
        private readonly long _origin = startMs;
        private long _ms = startMs;

        public override long TimestampFrequency => 1000;

        public override long GetTimestamp() => Interlocked.Read(ref _ms);

        public override DateTimeOffset GetUtcNow() =>
            wallClock + TimeSpan.FromMilliseconds(Interlocked.Read(ref _ms) - _origin);

        public void SetMs(long ms) => Interlocked.Exchange(ref _ms, ms);

        public void Advance(long ms) => Interlocked.Add(ref _ms, ms);
    }

    private sealed class InMemoryRoutes : IConnectivityRouteSource
    {
        private readonly ConcurrentDictionary<long, ConnectivityRouteTarget> _routes = new();

        public bool Fail { get; set; }

        public void Add(HttpRouteMapping route, ClientAccount account)
        {
            account.Id = route.ClientId;
            _routes[route.Id] = new ConnectivityRouteTarget(route, account);
        }

        public Task<ConnectivityRouteTarget?> FindAsync(long routeId, CancellationToken cancellationToken) =>
            Fail
                ? Task.FromException<ConnectivityRouteTarget?>(new InvalidOperationException("database is down"))
                : Task.FromResult(_routes.TryGetValue(routeId, out var target) ? target : null);
    }

    /// <summary>
    /// Answers each probe with the next scripted answer, after moving the clock to its atMs (or to
    /// the deadline for none). With no script left it blocks until released, which holds a check
    /// in flight.
    /// </summary>
    private sealed class ScriptedDevice(ManualTimeProvider clock, long startMs) : IConnectivityDeviceGateway
    {
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Queue<JsonObject> Answers { get; } = new();

        public ConcurrentQueue<Dictionary<string, object?>> Opened { get; } = new();

        public ConnectivityDevicePresence PresenceValue { get; set; } = ConnectivityDevicePresence.Online;

        public int Capability { get; set; }

        public void ReleaseBlocked() => _release.TrySetResult();

        public ConnectivityDevicePresence Presence(string clientName) => PresenceValue;

        public async Task<ConnectivityProbeAnswer> ProbeAsync(string clientName,
            Dictionary<string, object?> metadata, TimeSpan budget, CancellationToken cancellationToken)
        {
            Opened.Enqueue(metadata);
            if (!Answers.TryDequeue(out var answer))
            {
                await _release.Task.WaitAsync(cancellationToken);
                return ConnectivityProbeAnswer.Response(204);
            }
            var kind = answer["kind"]!.GetValue<string>();
            if (kind == "none")
            {
                clock.Advance((long)Math.Ceiling(budget.TotalMilliseconds));
                return ConnectivityProbeAnswer.NoAnswer();
            }
            clock.SetMs(startMs + answer["atMs"]!.GetValue<long>());
            return kind switch
            {
                "response" => ConnectivityProbeAnswer.Response(answer["status"]!.GetValue<int>()),
                "rst" => ConnectivityProbeAnswer.Reset(answer["failure"]?.GetValue<string>(), Capability),
                "link-lost" => ConnectivityProbeAnswer.LinkLost(),
                "open-failed" => ConnectivityProbeAnswer.NotOpened(answer["cause"]!.GetValue<string>() switch
                {
                    "stream-limit" => ConnectivityOpenFailure.StreamLimit,
                    "write-failed" => ConnectivityOpenFailure.WriteFailed,
                    var cause => throw new InvalidDataException(cause),
                }),
                _ => throw new InvalidDataException(kind),
            };
        }
    }

    private sealed class CapturingLogger : ILogger<ConnectivityCheckService>
    {
        private readonly ConcurrentQueue<string> _lines = new();

        public IReadOnlyList<string> Lines => _lines.ToArray();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Information)
            {
                _lines.Enqueue(formatter(state, exception));
            }
        }
    }
}
