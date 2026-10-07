using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.ProductMetrics;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Replays protocol/test-vectors/product-metrics-v1.json: the bucket and rate cases, the 44 ingest
/// validation bodies and every scenario, each on a fresh server and SQLite store, through the real
/// HTTP pipeline (routing, the shared admin authentication layer, the product metrics endpoints and
/// the store) with the product metrics clock pinned at each op's time. Milestone, user-deletion and
/// sweep ops call the server-internal hooks directly, as the vector prescribes.
/// </summary>
public sealed class ProductMetricsVectorTests
{
    private const string Settings = "/api/admin/product-metrics/settings";
    private const string Data = "/api/admin/product-metrics/data";
    private const string Ingest = "/api/admin/product-metrics/transfer-outcomes";
    private const string Summary = "/api/admin/product-metrics/summary";

    public static TheoryData<string> ScenarioNames()
    {
        using var vector = LoadVector();
        var names = new TheoryData<string>();
        foreach (var scenario in vector.RootElement.GetProperty("scenarios").EnumerateArray())
        {
            names.Add(scenario.GetProperty("name").GetString()!);
        }
        return names;
    }

    [Fact]
    public void EveryScenarioOfTheVectorIsReplayed()
    {
        using var vector = LoadVector();
        var scenarios = vector.RootElement.GetProperty("scenarios").EnumerateArray().ToList();
        Assert.Equal(5, scenarios.Count);
        Assert.Equal(scenarios.Count, ScenarioNames().Count);
        Assert.Equal(128, scenarios.Sum(scenario => scenario.GetProperty("ops").GetArrayLength()));
        Assert.Equal(44, vector.RootElement.GetProperty("ingestValidation").GetProperty("cases").GetArrayLength());
    }

    [Fact]
    public void BucketsAndRatesMatchTheVector()
    {
        using var vector = LoadVector();
        var root = vector.RootElement;
        foreach (var item in root.GetProperty("sizeBuckets").EnumerateArray())
        {
            Assert.Equal(item.GetProperty("bucket").GetString(),
                ProductMetricsModel.SizeBucket(item.GetProperty("sizeBytes").GetInt64()));
        }
        foreach (var item in root.GetProperty("durationBuckets").EnumerateArray())
        {
            Assert.Equal(item.GetProperty("bucket").GetString(),
                ProductMetricsModel.DurationBucket(item.GetProperty("seconds").GetInt64()));
        }
        foreach (var item in root.GetProperty("rates").EnumerateArray())
        {
            var expected = item.GetProperty("rateBp");
            Assert.Equal(expected.ValueKind == JsonValueKind.Null ? null : expected.GetInt64(),
                ProductMetricsModel.RateBp(item.GetProperty("numerator").GetInt64(),
                    item.GetProperty("denominator").GetInt64()));
        }
    }

    [Fact]
    public async Task IngestValidationMatchesTheVector()
    {
        using var vector = LoadVector();
        var validation = vector.RootElement.GetProperty("ingestValidation");
        var context = validation.GetProperty("context");
        await using var run = await Run.StartAsync();
        var actor = context.GetProperty("actor");
        await run.AddActorAsync(actor);
        var at = Instant(context.GetProperty("at").GetString()!);
        run.SetClock(at);
        await run.WithDbAsync(async db =>
        {
            db.ProductMetricsSwitches.Add(new ProductMetricsSwitch
            {
                TenantId = actor.GetProperty("tenantId").GetString()!, Enabled = true, UpdatedBy = "root",
                UpdatedAt = at,
            });
            await db.SaveChangesAsync();
        });
        var replayed = 0;
        foreach (var item in validation.GetProperty("cases").EnumerateArray())
        {
            var name = item.GetProperty("name").GetString()!;
            var body = Encoding.UTF8.GetBytes(item.GetProperty("bodyText").GetString()!);
            Assert.Equal(item.GetProperty("bodyBytes").GetInt32(), body.Length);
            run.ResetLimits(ProductMetricsModel.DefaultPerUserEventsPerMinute,
                ProductMetricsModel.DefaultPerTenantEventsPerMinute);
            var before = await run.TransferTotalAsync();
            var expect = item.GetProperty("expect");
            await run.CallAsync(HttpMethod.Post, Ingest, actor, body, expect, name);
            var accepted = expect.GetProperty("status").GetInt32() == 200
                ? expect.GetProperty("body").GetProperty("accepted").GetInt64()
                : 0;
            Assert.True(before + accepted == await run.TransferTotalAsync(), $"{name}: counted events");
            replayed++;
        }
        Assert.Equal(44, replayed);
    }

    [Theory]
    [MemberData(nameof(ScenarioNames))]
    public async Task ScenarioMatchesTheSharedVector(string name)
    {
        using var vector = LoadVector();
        var scenario = vector.RootElement.GetProperty("scenarios").EnumerateArray()
            .Single(item => item.GetProperty("name").GetString() == name);
        await using var run = await Run.StartAsync();
        var limits = scenario.GetProperty("limits");
        run.ResetLimits(limits.GetProperty("perUserEventsPerMinute").GetInt32(),
            limits.GetProperty("perTenantEventsPerMinute").GetInt32());
        foreach (var op in scenario.GetProperty("ops").EnumerateArray())
        {
            if (op.TryGetProperty("actor", out var actor) && actor.ValueKind == JsonValueKind.Object)
            {
                await run.AddActorAsync(actor);
            }
        }
        await run.LoadAsync(scenario.GetProperty("initialState"));

        var index = 0;
        foreach (var op in scenario.GetProperty("ops").EnumerateArray())
        {
            var kind = op.GetProperty("op").GetString()!;
            var label = $"{name} op {index++} ({kind} at {op.GetProperty("at").GetString()})";
            run.SetClock(Instant(op.GetProperty("at").GetString()!));
            var expect = op.GetProperty("expect");
            var actor = op.TryGetProperty("actor", out var value) ? value : default;
            switch (kind)
            {
                case "milestone":
                    Assert.True(expect.GetProperty("effect").GetString() == await run.Metrics.MilestoneAsync(
                            op.GetProperty("tenantId").GetString(), op.GetProperty("username").GetString(),
                            op.GetProperty("step").GetString()!),
                        $"{label}: effect");
                    break;
                case "userDeleted":
                    Assert.True(expect.GetProperty("effect").GetString() == await run.Metrics.UserDeletedAsync(
                            op.GetProperty("tenantId").GetString(), op.GetProperty("username").GetString()!),
                        $"{label}: effect");
                    break;
                case "sweep":
                    await run.Metrics.SweepAsync(CancellationToken.None);
                    break;
                case "checkpoint":
                    await run.CompareStateAsync(expect.GetProperty("state"), label);
                    break;
                case "getSettings":
                    await run.CallAsync(HttpMethod.Get, Settings, actor, null, expect, label);
                    break;
                case "putSettings":
                    await run.CallAsync(HttpMethod.Put, Settings, actor,
                        Encoding.UTF8.GetBytes(op.GetProperty("body").GetRawText()), expect, label);
                    break;
                case "purge":
                    await run.CallAsync(HttpMethod.Delete, Data, actor, null, expect, label);
                    break;
                case "ingest":
                    await run.CallAsync(HttpMethod.Post, Ingest, actor,
                        Encoding.UTF8.GetBytes(op.GetProperty("bodyText").GetString()!), expect, label);
                    break;
                case "summary":
                    await run.CallAsync(HttpMethod.Get, Summary + Query(op.GetProperty("query")), actor, null, expect,
                        label);
                    break;
                default:
                    Assert.Fail($"{label}: unknown op");
                    break;
            }
        }
        Assert.Equal(scenario.GetProperty("ops").GetArrayLength(), index);
    }

    private static string Query(JsonElement query)
    {
        var parts = query.EnumerateObject()
            .Select(item => $"{item.Name}={Uri.EscapeDataString(item.Value.GetString()!)}")
            .ToList();
        return parts.Count == 0 ? string.Empty : "?" + string.Join('&', parts);
    }

    internal static long Instant(string text) =>
        DateTimeOffset.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal)
            .ToUnixTimeMilliseconds();

    private static long? Instant(JsonElement value) =>
        value.ValueKind == JsonValueKind.Null ? null : Instant(value.GetString()!);

    internal static JsonDocument LoadVector() => JsonDocument.Parse(File.ReadAllText(FindVector()));

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "product-metrics-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate product-metrics-v1.json");
    }

    /// <summary>The product metrics clock, pinned by the test.</summary>
    internal sealed class PinnedClock() : ProductMetricsClock(TimeProvider.System)
    {
        public long Now { get; set; }

        public override long NowMs() => Now;
    }

    /// <summary>One fresh server, clock, limiter and store.</summary>
    internal sealed class Run : IAsyncDisposable
    {
        private readonly TestServerFixture _server;
        private readonly PinnedClock _clock;
        private readonly HttpClient _http;
        private readonly Dictionary<string, (string Tenant, string Role)> _actors = new(StringComparer.Ordinal);

        private Run(TestServerFixture server, PinnedClock clock)
        {
            _server = server;
            _clock = clock;
            _http = server.CreateClient();
        }

        public ProductMetricsService Metrics => _server.HostServices.GetRequiredService<ProductMetricsService>();

        public HttpClient Http => _http;

        public TestServerFixture Server => _server;

        public static async Task<Run> StartAsync(IReadOnlyDictionary<string, string?>? configuration = null)
        {
            var clock = new PinnedClock();
            var server = await TestServerFixture.StartAsync(configuration, services =>
            {
                services.AddSingleton<ProductMetricsClock>(clock);
                // The sweep runs only when the vector says so.
                foreach (var hosted in services
                             .Where(descriptor => descriptor.ServiceType == typeof(IHostedService)
                                 && descriptor.ImplementationType == typeof(ProductMetricsSweepService))
                             .ToList())
                {
                    services.Remove(hosted);
                }
            });
            return new Run(server, clock);
        }

        public void SetClock(long epochMs) => _clock.Now = epochMs;

        public void ResetLimits(int perUser, int perTenant) =>
            _server.HostServices.GetRequiredService<ProductMetricsRateLimiter>().Reset(perUser, perTenant);

        public async Task WithDbAsync(Func<SpecusDbContext, Task> work)
        {
            await using var scope = _server.HostServices.CreateAsyncScope();
            await work(scope.ServiceProvider.GetRequiredService<SpecusDbContext>());
        }

        /// <summary>The vector's actor as a real account of its tenant with its role.</summary>
        public async Task AddActorAsync(JsonElement actor)
        {
            var username = actor.GetProperty("username").GetString()!;
            var identity = (actor.GetProperty("tenantId").GetString()!, actor.GetProperty("role").GetString()!);
            if (_actors.TryGetValue(username, out var known))
            {
                Assert.Equal(known, identity);
                return;
            }
            _actors[username] = identity;
            await WithDbAsync(async db =>
            {
                var now = DateTimeOffset.UtcNow;
                db.ManagementUsers.Add(new ManagementUser
                {
                    Username = username,
                    TenantId = identity.Item1,
                    PasswordHash = new string('0', 64),
                    Role = identity.Item2 == "ADMIN" ? ManagementRole.Admin : ManagementRole.User,
                    Enabled = true,
                    CreatedAt = now,
                    UpdatedAt = now,
                });
                await db.SaveChangesAsync();
            });
        }

        public string Token(string tenant, string username) =>
            _server.HostServices.GetRequiredService<LocalTokenService>()
                .IssueToken(username, tenant, ManagementRole.User);

        public async Task CallAsync(HttpMethod method, string path, JsonElement actor, byte[]? body,
            JsonElement expect, string label)
        {
            using var request = new HttpRequestMessage(method, path);
            if (actor.ValueKind == JsonValueKind.Object)
            {
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer",
                    Token(actor.GetProperty("tenantId").GetString()!, actor.GetProperty("username").GetString()!));
            }
            if (body is not null)
            {
                request.Content = new ByteArrayContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }
            using var response = await _http.SendAsync(request);
            var text = await response.Content.ReadAsStringAsync();
            var status = expect.GetProperty("status").GetInt32();
            Assert.True(status == (int)response.StatusCode, $"{label}: expected {status}, got {(int)response.StatusCode} {text}");
            Assert.True(response.Headers.CacheControl is { NoStore: true, Private: true },
                $"{label}: Cache-Control {response.Headers.CacheControl}");
            if (expect.TryGetProperty("body", out var expectedBody))
            {
                using var actual = JsonDocument.Parse(text);
                Assert.True(JsonElement.DeepEquals(expectedBody, actual.RootElement),
                    $"{label}: body\n got {text}\nwant {expectedBody.GetRawText()}");
            }
        }

        public async Task LoadAsync(JsonElement state)
        {
            await WithDbAsync(async db =>
            {
                foreach (var row in state.EnumerateObjectOrEmpty("switches"))
                {
                    db.ProductMetricsSwitches.Add(new ProductMetricsSwitch
                    {
                        TenantId = row.GetProperty("tenantId").GetString()!,
                        Enabled = row.GetProperty("enabled").GetBoolean(),
                        UpdatedBy = row.GetProperty("updatedBy").GetString(),
                        UpdatedAt = Instant(row.GetProperty("updatedAt")),
                        PurgedAt = Instant(row.GetProperty("purgedAt")),
                    });
                }
                foreach (var row in state.EnumerateObjectOrEmpty("progress"))
                {
                    db.ProductMetricsOnboardingProgress.Add(Progress(row));
                }
                foreach (var row in state.EnumerateObjectOrEmpty("onboardingDaily"))
                {
                    db.ProductMetricsOnboardingDaily.Add(Onboarding(row));
                }
                foreach (var row in state.EnumerateObjectOrEmpty("transferDaily"))
                {
                    db.ProductMetricsTransferDaily.Add(Transfer(row));
                }
                await db.SaveChangesAsync();
            });
        }

        public async Task<long> TransferTotalAsync()
        {
            long total = 0;
            await WithDbAsync(async db => total = await db.ProductMetricsTransferDaily.SumAsync(row => row.Count));
            return total;
        }

        /// <summary>Compares the four tables with a checkpoint; times compare as instants.</summary>
        public async Task CompareStateAsync(JsonElement state, string label)
        {
            await WithDbAsync(async db =>
            {
                var switches = (await db.ProductMetricsSwitches.AsNoTracking().ToListAsync())
                    .Select(row => $"{row.TenantId}|{row.Enabled}|{row.UpdatedBy}|{row.UpdatedAt}|{row.PurgedAt}");
                var expectedSwitches = state.GetProperty("switches").EnumerateArray().Select(row =>
                    $"{row.GetProperty("tenantId").GetString()}|{row.GetProperty("enabled").GetBoolean()}|"
                    + $"{row.GetProperty("updatedBy").GetString()}|{Instant(row.GetProperty("updatedAt"))}|"
                    + $"{Instant(row.GetProperty("purgedAt"))}");
                AssertRows(label, "product_metrics_switch", expectedSwitches, switches);

                var progress = (await db.ProductMetricsOnboardingProgress.AsNoTracking().ToListAsync()).Select(Describe);
                var expectedProgress = state.GetProperty("progress").EnumerateArray().Select(Progress).Select(Describe);
                AssertRows(label, "product_metrics_onboarding_progress", expectedProgress, progress);

                var onboarding = (await db.ProductMetricsOnboardingDaily.AsNoTracking().ToListAsync()).Select(Describe);
                var expectedOnboarding = state.GetProperty("onboardingDaily").EnumerateArray().Select(Onboarding)
                    .Select(Describe);
                AssertRows(label, "product_metrics_onboarding_daily", expectedOnboarding, onboarding);

                var transfers = (await db.ProductMetricsTransferDaily.AsNoTracking().ToListAsync()).Select(Describe);
                var expectedTransfers = state.GetProperty("transferDaily").EnumerateArray().Select(Transfer)
                    .Select(Describe);
                AssertRows(label, "product_metrics_transfer_daily", expectedTransfers, transfers);
            });
        }

        private static void AssertRows(string label, string table, IEnumerable<string> expected,
            IEnumerable<string> actual)
        {
            var want = expected.OrderBy(row => row, StringComparer.Ordinal).ToList();
            var got = actual.OrderBy(row => row, StringComparer.Ordinal).ToList();
            Assert.True(want.SequenceEqual(got),
                $"{label}: {table}\n got {string.Join("; ", got)}\nwant {string.Join("; ", want)}");
        }

        private static string Describe(ProductMetricsOnboardingProgress row) =>
            $"{row.TenantId}|{row.Username}|{row.StartedAt}|{row.SignedInAt}|{row.CredentialCreatedAt}|{row.ClientOnlineAt}";

        private static string Describe(ProductMetricsOnboardingDaily row) =>
            $"{row.TenantId}|{row.CohortDay}|{row.ReachedStep}|{row.DurationBucket}|{row.Users}";

        private static string Describe(ProductMetricsTransferDaily row) =>
            $"{row.TenantId}|{row.Day}|{row.Mode}|{row.Path}|{row.SizeBucket}|{row.Attempt}|{row.Outcome}|{row.Count}";

        private static ProductMetricsOnboardingProgress Progress(JsonElement row) => new()
        {
            TenantId = row.GetProperty("tenantId").GetString()!,
            Username = row.GetProperty("username").GetString()!,
            StartedAt = Instant(row.GetProperty("startedAt").GetString()!),
            SignedInAt = Instant(row.GetProperty("signedInAt")),
            CredentialCreatedAt = Instant(row.GetProperty("credentialCreatedAt")),
            ClientOnlineAt = Instant(row.GetProperty("clientOnlineAt")),
        };

        private static ProductMetricsOnboardingDaily Onboarding(JsonElement row) => new()
        {
            TenantId = row.GetProperty("tenantId").GetString()!,
            CohortDay = row.GetProperty("cohortDay").GetString()!,
            ReachedStep = row.GetProperty("reachedStep").GetString()!,
            DurationBucket = row.GetProperty("durationBucket").GetString()!,
            Users = row.GetProperty("users").GetInt64(),
        };

        private static ProductMetricsTransferDaily Transfer(JsonElement row) => new()
        {
            TenantId = row.GetProperty("tenantId").GetString()!,
            Day = row.GetProperty("day").GetString()!,
            Mode = row.GetProperty("mode").GetString()!,
            Path = row.GetProperty("path").GetString()!,
            SizeBucket = row.GetProperty("sizeBucket").GetString()!,
            Attempt = row.GetProperty("attempt").GetString()!,
            Outcome = row.GetProperty("outcome").GetString()!,
            Count = row.GetProperty("count").GetInt64(),
        };

        public async ValueTask DisposeAsync()
        {
            _http.Dispose();
            await _server.DisposeAsync();
        }
    }
}

internal static class ProductMetricsJsonExtensions
{
    public static IEnumerable<JsonElement> EnumerateObjectOrEmpty(this JsonElement element, string property) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(property, out var value)
            ? value.EnumerateArray()
            : [];
}
