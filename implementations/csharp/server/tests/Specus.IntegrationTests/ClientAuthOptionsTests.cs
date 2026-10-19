using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Hosting;

namespace Specus.IntegrationTests;

public sealed class ClientAuthOptionsTests
{
    [Fact]
    public async Task ClientAuthSignatureHexIsCaseSensitiveLikeJava()
    {
        await using var server = await TestServerFixture.StartAsync();
        using var client = server.CreateClient();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var nonce = Guid.NewGuid().ToString("N");
        const string machine = "machine-uppercase-signature";
        const string osUser = "alice";
        var signature = Sign(DatabaseInitializer.DemoCredentialApiKey, timestamp, nonce, machine, osUser,
            DatabaseInitializer.DemoCredentialSecret).ToUpperInvariant();

        var response = await client.PostAsJsonAsync("/api/client/auth/login", new
        {
            apiKey = DatabaseInitializer.DemoCredentialApiKey,
            timestamp,
            nonce,
            signature,
            environment = new { machineFingerprint = machine, hostname = "host", osUser },
        });

        Assert.Equal(System.Net.HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task ClientAuthLoginUsesClientAuthTokenTtl()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:Auth:TokenTtlSeconds"] = "60",
            ["Specus:ClientAuth:TokenTtlSeconds"] = "1234",
            ["Specus:Tls:RequireEncryption"] = "true",
            ["Specus:Tls:TerminatedUpstream"] = "true",
            ["Specus:Netty:BindAddress"] = "127.0.0.1",
        });
        using var client = server.CreateClient();
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var nonce = "nonce-" + Guid.NewGuid().ToString("N");
        var machine = "machine-ttl";
        var osUser = "alice";
        var before = DateTimeOffset.UtcNow;

        var response = await client.PostAsJsonAsync("/api/client/auth/login", new
        {
            apiKey = DatabaseInitializer.DemoCredentialApiKey,
            timestamp,
            nonce,
            signature = Sign(DatabaseInitializer.DemoCredentialApiKey, timestamp, nonce, machine, osUser,
                DatabaseInitializer.DemoCredentialSecret),
            environment = new
            {
                machineFingerprint = machine,
                hostname = "tenant-host",
                osUser,
                osName = "test-os",
                osArch = "amd64",
                clientMessageCapabilities = new
                {
                    sendMessages = true,
                    receiveMessages = true,
                    attachments = true,
                    mediaPreview = true,
                    maxAttachmentBytes = 123456L,
                },
                localAddresses = new[] { "10.1.2.3" },
            },
        });
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("nettyTls").GetBoolean());
        var body = JsonSerializer.Deserialize<ClientAuthLoginBody>(json,
            new JsonSerializerOptions(JsonSerializerDefaults.Web));

        Assert.NotNull(body);
        Assert.Equal(1234, body.TokenTtlSeconds);

        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var session = await db.ClientSessions.AsNoTracking()
            .FirstAsync(row => row.Id == body.ClientSessionId);
        var minExpiresAt = before.AddSeconds(1234 - 2);
        var maxExpiresAt = DateTimeOffset.UtcNow.AddSeconds(1234 + 2);
        Assert.InRange(session.ExpiresAt, minExpiresAt, maxExpiresAt);
        Assert.True(session.MessageSendCapable);
        Assert.True(session.MessageReceiveCapable);
        Assert.True(session.MessageAttachmentsCapable);
        Assert.True(session.MessageMediaPreviewCapable);
        Assert.Equal(123456L, session.MessageMaxAttachmentBytes);
    }

    /// <summary>
    /// The egress-catalog advertises domain targets from what the egress's session announced, so
    /// the login has to keep it. It only counts alongside a usable egress version: a client that
    /// cannot take part at all must not be recorded as resolving names.
    /// </summary>
    [Fact]
    public async Task ClientAuthLoginStoresTheAnnouncedEgressDomainTargets()
    {
        await using var server = await TestServerFixture.StartAsync();
        using var client = server.CreateClient();

        var declared = await LoginWithEgressCapabilitiesAsync(server, client, "machine-egress-domain",
            new { version = 1, consumerCapable = true, egressCapable = true, domainTargetCapable = true });
        Assert.Equal(1, declared.ClientEgressVersion);
        Assert.True(declared.ClientEgressDomainTargets);

        var undeclared = await LoginWithEgressCapabilitiesAsync(server, client, "machine-egress-plain",
            new { version = 1, consumerCapable = true, egressCapable = true });
        Assert.Equal(1, undeclared.ClientEgressVersion);
        Assert.False(undeclared.ClientEgressDomainTargets);

        var unversioned = await LoginWithEgressCapabilitiesAsync(server, client, "machine-egress-v0",
            new { version = 0, domainTargetCapable = true });
        Assert.Equal(0, unversioned.ClientEgressVersion);
        Assert.False(unversioned.ClientEgressDomainTargets);

        var absent = await LoginWithEgressCapabilitiesAsync(server, client, "machine-egress-absent", null);
        Assert.Equal(0, absent.ClientEgressVersion);
        Assert.False(absent.ClientEgressDomainTargets);
    }

    [Theory]
    [InlineData(1, true, true)]
    [InlineData(1, null, false)]
    [InlineData(1, false, false)]
    [InlineData(0, true, false)]
    [InlineData(-1, true, false)]
    [InlineData(2, true, true)]
    public async Task ClientAuthLoginStoresAnnouncedIpv6TargetSocketSupport(int version, bool? declared, bool expected)
    {
        await using var server = await TestServerFixture.StartAsync();
        using var client = server.CreateClient();
        var capabilities = new Dictionary<string, object?> { ["version"] = version, ["egressCapable"] = true };
        if (declared.HasValue) capabilities["ipv6TargetCapable"] = declared.Value;
        var stored = await LoginWithEgressCapabilitiesAsync(server, client, "machine-egress-ipv6", capabilities);
        // Missing on the legacy model is observed as false, so this regression
        // executes before the persistence field exists as well as after it is added.
        var value = stored.GetType().GetProperty("ClientEgressIpv6Targets")?.GetValue(stored);
        Assert.Equal(expected, value is bool capable && capable);
    }

    public static IEnumerable<object[]> Ipv6PacketLoginVectorCases()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var path = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-ipv6-packet-announcement-v1.json");
            if (!File.Exists(path)) continue;
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var cases = document.RootElement.GetProperty("login");
            Assert.Equal(8, cases.GetArrayLength());
            foreach (var example in cases.EnumerateArray())
                yield return [example.GetProperty("name").GetString()!, example.GetRawText()];
            yield break;
        }
        throw new InvalidOperationException("Shared IPv6 packet announcement vector not found");
    }

    /// <summary>
    /// The login keeps ipv6PacketCapable by the same rule as ipv6TargetCapable, and neither
    /// declaration is read from the other.
    /// </summary>
    [Theory]
    [MemberData(nameof(Ipv6PacketLoginVectorCases))]
    public async Task ClientAuthLoginStoresAnnouncedIpv6PacketSupport(string caseName, string caseJson)
    {
        using var document = JsonDocument.Parse(caseJson);
        var example = document.RootElement;
        var capabilities = example.GetProperty("capabilities");
        await using var server = await TestServerFixture.StartAsync();
        using var client = server.CreateClient();
        var stored = await LoginWithEgressCapabilitiesAsync(server, client, "machine-egress-ipv6-packet",
            capabilities.ValueKind == JsonValueKind.Object ? capabilities : null);
        Assert.True(example.GetProperty("stored").GetBoolean() == stored.ClientEgressIpv6Packets,
            $"{caseName}: wrong IPv6 packet declaration");
        var targets = example.GetProperty("normalizedVersion").GetInt32() >= 1
            && capabilities.ValueKind == JsonValueKind.Object
            && capabilities.TryGetProperty("ipv6TargetCapable", out var flag) && flag.ValueKind == JsonValueKind.True;
        Assert.True(targets == stored.ClientEgressIpv6Targets, $"{caseName}: wrong IPv6 target declaration");
    }

    /// <summary>
    /// The connectivity check trusts RST metadata.failure only from a session that announced
    /// clientHttpRouteCapabilities.version >= 1, so the login keeps that version with the session.
    /// </summary>
    [Fact]
    public async Task ClientAuthLoginKeepsTheAnnouncedHttpRouteCapability()
    {
        await using var server = await TestServerFixture.StartAsync();
        using var client = server.CreateClient();
        var sessions = server.HostServices.GetRequiredService<ClientAuthSessionStore>();

        var capable = await LoginWithHttpRouteCapabilitiesAsync(client, "machine-route-v1", new { version = 1 });
        Assert.Equal(1, sessions.FindById(capable)!.HttpRouteCapabilityVersion);

        var negative = await LoginWithHttpRouteCapabilitiesAsync(client, "machine-route-negative", new { version = -4 });
        Assert.Equal(0, sessions.FindById(negative)!.HttpRouteCapabilityVersion);

        var absent = await LoginWithHttpRouteCapabilitiesAsync(client, "machine-route-absent", null);
        Assert.Equal(0, sessions.FindById(absent)!.HttpRouteCapabilityVersion);
    }

    [Fact]
    public async Task CredentialCreateUsesClientAuthDefaultMaxOnlineInstances()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Specus:ClientAuth:DefaultMaxOnlineInstances"] = "7",
        });
        using var client = server.CreateClient();
        var login = await client.PostAsJsonAsync("/auth/login", new
        {
            username = "admin",
            password = "admin",
        });
        login.EnsureSuccessStatusCode();
        var token = await login.Content.ReadFromJsonAsync<TokenBody>();
        Assert.NotNull(token);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token!.AccessToken);

        var response = await client.PostAsJsonAsync("/api/admin/client-credentials", new
        {
            apiKey = "ck_default_max",
            secret = "tenant-secret",
            enabled = true,
        });
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<CredentialResultBody>();

        Assert.NotNull(body);
        Assert.Equal(7, body!.Credential.MaxOnlineInstances);
    }

    /// <summary>
    /// Logs in from a fresh machine and returns the stored session. A null
    /// <paramref name="egressCapabilities"/> leaves the object out of the request entirely.
    /// </summary>
    private static async Task<Specus.Server.Data.Entities.ClientSession> LoginWithEgressCapabilitiesAsync(
        TestServerFixture server, HttpClient client, string machine, object? egressCapabilities)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var nonce = "nonce-" + Guid.NewGuid().ToString("N");
        const string osUser = "alice";
        var environment = new Dictionary<string, object?>
        {
            ["machineFingerprint"] = machine,
            ["hostname"] = "egress-host",
            ["osUser"] = osUser,
        };
        if (egressCapabilities is not null)
        {
            environment["clientEgressCapabilities"] = egressCapabilities;
        }
        var response = await client.PostAsJsonAsync("/api/client/auth/login", new
        {
            apiKey = DatabaseInitializer.DemoCredentialApiKey,
            timestamp,
            nonce,
            signature = Sign(DatabaseInitializer.DemoCredentialApiKey, timestamp, nonce, machine, osUser,
                DatabaseInitializer.DemoCredentialSecret),
            environment,
        });
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<ClientAuthLoginBody>();
        Assert.NotNull(body);

        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        return await db.ClientSessions.AsNoTracking()
            .FirstAsync(row => row.Id == body!.ClientSessionId);
    }

    /// <summary>Logs in from a fresh machine and returns the client session id.</summary>
    private static async Task<long> LoginWithHttpRouteCapabilitiesAsync(HttpClient client, string machine,
        object? httpRouteCapabilities)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        var nonce = "nonce-" + Guid.NewGuid().ToString("N");
        const string osUser = "alice";
        var environment = new Dictionary<string, object?>
        {
            ["machineFingerprint"] = machine,
            ["hostname"] = "route-host",
            ["osUser"] = osUser,
        };
        if (httpRouteCapabilities is not null)
        {
            environment["clientHttpRouteCapabilities"] = httpRouteCapabilities;
        }
        var response = await client.PostAsJsonAsync("/api/client/auth/login", new
        {
            apiKey = DatabaseInitializer.DemoCredentialApiKey,
            timestamp,
            nonce,
            signature = Sign(DatabaseInitializer.DemoCredentialApiKey, timestamp, nonce, machine, osUser,
                DatabaseInitializer.DemoCredentialSecret),
            environment,
        });
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<ClientAuthLoginBody>();
        Assert.NotNull(body);
        return body!.ClientSessionId;
    }

    private static string Sign(string apiKey, string timestamp, string nonce, string machineFingerprint,
        string osUser, string secret)
    {
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var message = string.Join('\n', apiKey, timestamp, nonce, machineFingerprint, osUser);
        return Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(message)))
            .ToLowerInvariant();
    }

    private sealed record ClientAuthLoginBody(long ClientSessionId, long TokenTtlSeconds);
    private sealed record TokenBody(string AccessToken);
    private sealed record CredentialResultBody(CredentialBody Credential);
    private sealed record CredentialBody(int MaxOnlineInstances);
}
