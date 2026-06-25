using System.Net.Http.Json;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Hosting;

namespace ShuaiTunnel.IntegrationTests;

public sealed class ClientAuthOptionsTests
{
    [Fact]
    public async Task ClientAuthLoginUsesClientAuthTokenTtl()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:Auth:TokenTtlSeconds"] = "60",
            ["Tunnel:ClientAuth:TokenTtlSeconds"] = "1234",
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
                localAddresses = new[] { "10.1.2.3" },
            },
        });
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<ClientAuthLoginBody>();

        Assert.NotNull(body);
        Assert.Equal(1234, body.TokenTtlSeconds);

        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var session = await db.ClientSessions.AsNoTracking()
            .FirstAsync(row => row.Id == body.ClientSessionId);
        var minExpiresAt = before.AddSeconds(1234 - 2);
        var maxExpiresAt = DateTimeOffset.UtcNow.AddSeconds(1234 + 2);
        Assert.InRange(session.ExpiresAt, minExpiresAt, maxExpiresAt);
    }

    [Fact]
    public async Task CredentialCreateUsesClientAuthDefaultMaxOnlineInstances()
    {
        await using var server = await TestServerFixture.StartAsync(new Dictionary<string, string?>
        {
            ["Tunnel:ClientAuth:DefaultMaxOnlineInstances"] = "7",
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
