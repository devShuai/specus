using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data.Entities;
using Specus.Server.ProductMetrics;

namespace Specus.IntegrationTests;

/// <summary>
/// The real write paths fire the onboarding milestones: an admin creating the account, its password
/// sign-in, its first credential, its client's control-channel login and the first HTTP route on that
/// client. Deleting another account drops its progress row and switching off drops the rest. A
/// member's transfer outcomes are counted and only the tenant's ADMIN reads the summary.
/// </summary>
public sealed class ProductMetricsWritePathTests
{
    private const string Tenant = "default";
    private const string Password = "product-metrics-password";

    [Fact]
    public async Task WritePathsRecordTheOnboardingMilestones()
    {
        await using var run = await ProductMetricsVectorTests.Run.StartAsync();
        run.SetClock(ProductMetricsVectorTests.Instant("2026-09-01T08:00:00Z"));
        await AddAdminAsync(run, "pm-admin");
        var admin = run.Token(Tenant, "pm-admin");

        Assert.Equal(HttpStatusCode.Created, (await SendAsync(run, HttpMethod.Post, "/api/admin/users", admin,
            new { username = "pm-early", password = Password, role = "USER" })).StatusCode);
        Assert.Null(await ProgressAsync(run, "pm-early"));

        var enable = await SendAsync(run, HttpMethod.Put, "/api/admin/product-metrics/settings", admin,
            new { enabled = true, disclosureVersion = 1 });
        Assert.Equal(HttpStatusCode.OK, enable.StatusCode);
        Assert.Equal("pm-admin", (await enable.Content.ReadFromJsonAsync<JsonObject>())!["updatedBy"]!.GetValue<string>());

        Assert.Equal(HttpStatusCode.Created, (await SendAsync(run, HttpMethod.Post, "/api/admin/users", admin,
            new { username = "pm-alice", password = Password, role = "USER" })).StatusCode);
        var progress = await ProgressAsync(run, "pm-alice");
        Assert.NotNull(progress);
        Assert.Null(progress.SignedInAt);

        run.SetClock(ProductMetricsVectorTests.Instant("2026-09-01T08:01:00Z"));
        var login = await run.Http.PostAsJsonAsync("/auth/login", new { username = "pm-alice", password = Password });
        Assert.Equal(HttpStatusCode.OK, login.StatusCode);
        var alice = (await login.Content.ReadFromJsonAsync<JsonObject>())!["accessToken"]!.GetValue<string>();
        Assert.NotNull((await ProgressAsync(run, "pm-alice"))!.SignedInAt);

        Assert.Equal(HttpStatusCode.Created, (await SendAsync(run, HttpMethod.Post, "/api/admin/client-credentials",
            alice, new { })).StatusCode);
        Assert.NotNull((await ProgressAsync(run, "pm-alice"))!.CredentialCreatedAt);

        run.SetClock(ProductMetricsVectorTests.Instant("2026-09-01T08:05:00Z"));
        var (clientId, connection) = await LogClientInAsync(run, "pm-alice");
        using var controlConnection = connection;
        var deadline = DateTime.UtcNow.AddSeconds(10);
        while ((await ProgressAsync(run, "pm-alice"))!.ClientOnlineAt is null && DateTime.UtcNow < deadline)
        {
            await Task.Delay(20);
        }
        Assert.NotNull((await ProgressAsync(run, "pm-alice"))!.ClientOnlineAt);

        run.SetClock(ProductMetricsVectorTests.Instant("2026-09-01T08:20:00Z"));
        var route = await SendAsync(run, HttpMethod.Post, $"/api/admin/clients/{clientId}/http-routes", alice,
            new { route = "metrics", targetBaseUrl = "http://127.0.0.1:18080", enabled = true });
        Assert.True(route.StatusCode == HttpStatusCode.Created, await route.Content.ReadAsStringAsync());
        Assert.Null(await ProgressAsync(run, "pm-alice"));
        await run.WithDbAsync(async db =>
        {
            var cohort = await db.ProductMetricsOnboardingDaily.AsNoTracking().SingleAsync();
            Assert.Equal(("2026-09-01", "service_published", "10m-30m", 1L),
                (cohort.CohortDay, cohort.ReachedStep, cohort.DurationBucket, cohort.Users));
        });

        Assert.Equal(HttpStatusCode.Created, (await SendAsync(run, HttpMethod.Post, "/api/admin/users", admin,
            new { username = "pm-bob", password = Password, role = "USER" })).StatusCode);
        Assert.NotNull(await ProgressAsync(run, "pm-bob"));
        Assert.Equal(HttpStatusCode.NoContent,
            (await SendAsync(run, HttpMethod.Delete, "/api/admin/users/pm-bob", admin, null)).StatusCode);
        Assert.Null(await ProgressAsync(run, "pm-bob"));

        var events = new
        {
            schemaVersion = 1,
            events = new[]
            {
                new { mode = "device", path = "turn", sizeBucket = "1m-16m", attempt = "retry_after_failure",
                    outcome = "success" },
            },
        };
        var ingest = await SendAsync(run, HttpMethod.Post, "/api/admin/product-metrics/transfer-outcomes", alice,
            events);
        Assert.Equal(HttpStatusCode.OK, ingest.StatusCode);
        Assert.Equal(1, (await ingest.Content.ReadFromJsonAsync<JsonObject>())!["accepted"]!.GetValue<int>());
        var member = await (await SendAsync(run, HttpMethod.Get, "/api/admin/product-metrics/settings", alice, null))
            .Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(member!.ContainsKey("updatedBy"));
        Assert.Equal(HttpStatusCode.Forbidden,
            (await SendAsync(run, HttpMethod.Get, "/api/admin/product-metrics/summary", alice, null)).StatusCode);
        var summary = await (await SendAsync(run, HttpMethod.Get, "/api/admin/product-metrics/summary", admin, null))
            .Content.ReadFromJsonAsync<JsonObject>();
        Assert.Equal(1, summary!["onboarding"]!["completed"]!.GetValue<int>());
        Assert.Equal("10m-30m", summary["onboarding"]!["medianDurationBucket"]!.GetValue<string>());
        Assert.Equal(10000, summary["transfers"]!["byAttempt"]![1]!["successRateBp"]!.GetValue<int>());

        Assert.Equal(HttpStatusCode.Created, (await SendAsync(run, HttpMethod.Post, "/api/admin/users", admin,
            new { username = "pm-carol", password = Password, role = "USER" })).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(run, HttpMethod.Put, "/api/admin/product-metrics/settings",
            admin, new { enabled = false })).StatusCode);
        await run.WithDbAsync(async db => Assert.Equal(0, await db.ProductMetricsOnboardingProgress.CountAsync()));
        var stopped = await SendAsync(run, HttpMethod.Post, "/api/admin/product-metrics/transfer-outcomes", alice,
            events);
        Assert.False((await stopped.Content.ReadFromJsonAsync<JsonObject>())!["collecting"]!.GetValue<bool>());
    }

    [Fact]
    public async Task TheDeploymentSwitchKeepsEveryTenantOff()
    {
        await using var run = await ProductMetricsVectorTests.Run.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:ProductMetrics:Allowed"] = "false",
        });
        run.SetClock(ProductMetricsVectorTests.Instant("2026-09-01T08:00:00Z"));
        await AddAdminAsync(run, "pm-admin");
        var admin = run.Token(Tenant, "pm-admin");
        var enable = await SendAsync(run, HttpMethod.Put, "/api/admin/product-metrics/settings", admin,
            new { enabled = true, disclosureVersion = 1 });
        Assert.Equal(HttpStatusCode.Conflict, enable.StatusCode);
        Assert.Equal("PRODUCT_METRICS_NOT_ALLOWED",
            (await enable.Content.ReadFromJsonAsync<JsonObject>())!["code"]!.GetValue<string>());
        var settings = await (await SendAsync(run, HttpMethod.Get, "/api/admin/product-metrics/settings", admin, null))
            .Content.ReadFromJsonAsync<JsonObject>();
        Assert.False(settings!["enabled"]!.GetValue<bool>());
        using var oversize = new HttpRequestMessage(HttpMethod.Post, "/api/admin/product-metrics/transfer-outcomes")
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(new string(' ', 4097))),
        };
        oversize.Headers.Authorization = new AuthenticationHeaderValue("Bearer", admin);
        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, (await run.Http.SendAsync(oversize)).StatusCode);
    }

    [Fact]
    public void EnvironmentVariablesMapToTheProductMetricsSection()
    {
        var map = SpecusEnvironmentVariables.BuildConfigurationMap(new Dictionary<string, string?>
        {
            ["SPECUS_PRODUCT_METRICS_ALLOWED"] = "false",
            ["SPECUS_PRODUCT_METRICS_PER_USER_EVENTS_PER_MINUTE"] = "60",
        });
        Assert.Equal("false", map["Specus:ProductMetrics:Allowed"]);
        Assert.Equal("60", map["Specus:ProductMetrics:PerUserEventsPerMinute"]);
    }

    /// <summary>Cases beyond the shared vector: duplicated keys, non-integer spellings of 1, trailing content.</summary>
    [Fact]
    public void TheClosedSchemaRefusesDuplicatesFractionsAndTrailingContent()
    {
        const string sample =
            "{\"mode\":\"device\",\"path\":\"direct\",\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"success\"}";
        foreach (var body in new[]
                 {
                     "{\"schemaVersion\":1,\"schemaVersion\":1,\"events\":[" + sample + "]}",
                     "{\"schemaVersion\":1,\"events\":[{\"mode\":\"device\",\"mode\":\"device\",\"path\":\"direct\","
                     + "\"sizeBucket\":\"lt1m\",\"attempt\":\"first\",\"outcome\":\"success\"}]}",
                     "{\"schemaVersion\":1.0,\"events\":[" + sample + "]}",
                     "{\"schemaVersion\":1e0,\"events\":[" + sample + "]}",
                     "{\"schemaVersion\":1,\"events\":[" + sample + "]} {}",
                     "",
                     "{\"schemaVersion\":1,\"events\":[" + sample,
                 })
        {
            Assert.True(ProductMetricsModel.ParseIngest(Encoding.UTF8.GetBytes(body), out _)
                == ProductMetricsModel.IngestRefusal.Invalid, body);
        }
        Assert.Equal(ProductMetricsModel.IngestRefusal.Invalid,
            ProductMetricsModel.ParseIngest(new byte[] { (byte)'{', (byte)'"', 0xff, (byte)'"', (byte)'}' }, out _));
        Assert.Equal(ProductMetricsModel.IngestRefusal.None,
            ProductMetricsModel.ParseIngest(Encoding.UTF8.GetBytes(" \n{\"events\":[" + sample + "],\"schemaVersion\":1}\n"),
                out var events));
        Assert.Single(events);

        foreach (var body in new[]
                 {
                     "{\"disclosureVersion\":1}", "{\"enabled\":\"true\"}", "{\"enabled\":true,\"disclosureVersion\":true}",
                     "{\"enabled\":true,\"disclosureVersion\":1.5}", "{\"enabled\":false,\"tenantId\":\"t2\"}",
                     "{\"enabled\":false,\"enabled\":true}", "[true]", "{\"enabled\":false}x",
                     "{\"enabled\":true,\"disclosureVersion\":null}", "{}", "{\"enabled\":true,\"disclosureVersion\":\"1\"}",
                 })
        {
            Assert.Null(ProductMetricsModel.ParseSettingsUpdate(Encoding.UTF8.GetBytes(body)));
        }
        Assert.Equal(new ProductMetricsModel.SettingsUpdate(true, "2"),
            ProductMetricsModel.ParseSettingsUpdate("{\"disclosureVersion\":2,\"enabled\":true}"u8));
    }

    private static async Task AddAdminAsync(ProductMetricsVectorTests.Run run, string username)
    {
        using var actor = JsonDocument.Parse(JsonSerializer.Serialize(new
        {
            tenantId = Tenant, username, role = "ADMIN",
        }));
        await run.AddActorAsync(actor.RootElement);
    }

    private static async Task<HttpResponseMessage> SendAsync(ProductMetricsVectorTests.Run run, HttpMethod method,
        string path, string token, object? body)
    {
        var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null)
        {
            request.Content = JsonContent.Create(body);
        }
        return await run.Http.SendAsync(request);
    }

    private static async Task<ProductMetricsOnboardingProgress?> ProgressAsync(ProductMetricsVectorTests.Run run,
        string username)
    {
        ProductMetricsOnboardingProgress? row = null;
        await run.WithDbAsync(async db => row = await db.ProductMetricsOnboardingProgress.AsNoTracking()
            .SingleOrDefaultAsync(item => item.TenantId == Tenant && item.Username == username));
        return row;
    }

    /// <summary>
    /// Logs a client of <paramref name="owner"/> in over the real control port: an account and a
    /// session issued the way /api/client/auth/login issues them, then a LoginRequest frame.
    /// </summary>
    private static async Task<(long ClientId, TcpClient Connection)> LogClientInAsync(
        ProductMetricsVectorTests.Run run, string owner)
    {
        var services = run.Server.HostServices;
        ClientAccount account = null!;
        ClientCredential credential = null!;
        await run.WithDbAsync(async db =>
        {
            credential = await db.ClientCredentials.AsNoTracking().SingleAsync(item => item.OwnerUsername == owner);
            var now = DateTimeOffset.UtcNow;
            account = new ClientAccount
            {
                Id = ClientIdGenerator.NewId(), TenantId = Tenant, OwnerUsername = owner,
                ClientName = "pm-client", PasswordHash = new string('0', 64), Enabled = true,
                CreatedAt = now, UpdatedAt = now,
            };
            db.ClientAccounts.Add(account);
            await db.SaveChangesAsync();
        });
        var identity = new ClientIdentity
        {
            Id = ClientIdGenerator.NewId(), TenantId = Tenant, CredentialId = credential.Id, ClientId = account.Id,
            ClientName = account.ClientName, MachineFingerprint = "pm-machine", OsUser = "pm", Hostname = "pm-host",
        };
        var session = services.GetRequiredService<ClientAuthSessionStore>().Create(credential, identity, account,
            TimeSpan.FromHours(1), new ClientEnvironmentInfo
            {
                MachineFingerprint = "pm-machine", OsUser = "pm", Hostname = "pm-host",
            });

        var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, run.Server.ControlPort);
        var stream = tcp.GetStream();
        await stream.WriteAsync(PacketCodec.Encode(new LoginRequestPacket
        {
            ClientName = account.ClientName,
            ClientSessionId = session.Id,
            AccessToken = session.AccessToken,
            ConnectionRole = ConnectionRole.Control,
        }));
        var buffer = new List<byte>();
        var chunk = new byte[4096];
        Packet? packet = null;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (packet is null)
        {
            var read = await stream.ReadAsync(chunk, timeout.Token);
            Assert.True(read > 0, "control connection closed before the login response");
            buffer.AddRange(chunk.AsSpan(0, read).ToArray());
            PacketCodec.TryDecode(buffer.ToArray(), out packet, out _);
        }
        var response = Assert.IsType<LoginResponsePacket>(packet);
        Assert.True(response.Success, response.Reason);
        // The connection stays open: the milestone is recorded after the response, on its lifetime.
        return (account.Id, tcp);
    }
}
