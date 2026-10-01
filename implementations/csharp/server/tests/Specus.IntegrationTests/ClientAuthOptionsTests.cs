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
