using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Security;

namespace Specus.IntegrationTests;

/// <summary>
/// Account lifecycle (protocol/spec/management-accounts.md sections 5-7, issue #199), the
/// counterpart of Java's <c>ManagementAccountsHttpTests</c>: replays
/// protocol/test-vectors/management-accounts-v1.json through the real routes and walks the
/// delete-then-recreate path with tokens <c>/auth/login</c> really issued.
/// </summary>
public sealed class ManagementAccountLifecycleTests
{
    private const string JwtSecret = "integration-test-secret";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task ReplaysTheTokenResolutionVector()
    {
        using var vector = LoadVector();
        await using var server = await TestServerFixture.StartAsync();
        await SeedVectorAccountsAsync(server, vector.RootElement);
        foreach (var testCase in vector.RootElement.GetProperty("tokenResolution").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            using var client = Bearer(server, Sign(testCase.GetProperty("claims")));
            using var me = await client.GetAsync("/api/admin/me");
            using var refresh = await client.PostAsync("/auth/refresh", content: null);
            var expect = testCase.GetProperty("expect");
            if (expect.ValueKind == JsonValueKind.Null)
            {
                Assert.True(me.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,
                    $"{name}: me {me.StatusCode}");
                Assert.True(refresh.StatusCode == HttpStatusCode.Unauthorized, $"{name}: refresh {refresh.StatusCode}");
                continue;
            }
            Assert.True(me.StatusCode == HttpStatusCode.OK, $"{name}: me {me.StatusCode}");
            var view = await me.Content.ReadFromJsonAsync<UserBody>(JsonOptions);
            Assert.Equal((expect.GetProperty("username").GetString(), expect.GetProperty("tenantId").GetString(),
                expect.GetProperty("builtIn").GetBoolean()), (view!.Username, view.TenantId, view.BuiltIn));
            Assert.True(refresh.StatusCode == HttpStatusCode.OK, $"{name}: refresh {refresh.StatusCode}");
            var token = (await refresh.Content.ReadFromJsonAsync<TokenBody>(JsonOptions))!.AccessToken;
            using var payload = Payload(token);
            Assert.Equal(expect.GetProperty("username").GetString(), payload.RootElement.GetProperty("sub").GetString());
            Assert.Equal(expect.GetProperty("tenantId").GetString(),
                payload.RootElement.GetProperty("tenant_id").GetString());
            var expectedUid = expect.GetProperty("uid");
            if (expectedUid.ValueKind == JsonValueKind.Null)
            {
                Assert.False(payload.RootElement.TryGetProperty("uid", out _), $"{name}: refreshed token has uid");
            }
            else
            {
                Assert.Equal(expectedUid.GetString(), payload.RootElement.GetProperty("uid").GetString());
            }
        }
    }

    [Fact]
    public async Task ReplaysTheUserListVector()
    {
        using var vector = LoadVector();
        await using var server = await TestServerFixture.StartAsync();
        await SeedVectorAccountsAsync(server, vector.RootElement);
        foreach (var testCase in vector.RootElement.GetProperty("userLists").EnumerateArray())
        {
            using var client = Bearer(server, Sign(testCase.GetProperty("caller")));
            var views = await client.GetFromJsonAsync<List<UserBody>>("/api/admin/users", JsonOptions);
            var expected = testCase.GetProperty("expect").EnumerateArray()
                .Select(view => (view.GetProperty("username").GetString()!, view.GetProperty("tenantId").GetString()!,
                    view.GetProperty("builtIn").GetBoolean()))
                .ToList();
            Assert.Equal(expected, views!.Select(view => (view.Username, view.TenantId, view.BuiltIn)).ToList());
        }
    }

    [Fact]
    public async Task DeletedAccountTokensDoNotResolveToARecreatedAccountOfTheSameName()
    {
        await using var server = await TestServerFixture.StartAsync();
        using var anonymous = server.CreateClient();
        using (var admin = Payload(await LoginAsync(anonymous, "admin", "admin", null)))
        {
            Assert.False(admin.RootElement.TryGetProperty("uid", out _));
        }
        await SeedAsync(server, "5a4b3c2d-1e0f-4a9b-8c7d-6e5f4a3b2c1d", "erin", "tenant-a", ManagementRole.Admin);
        using var tenantAdmin = Bearer(server, Sign(new Dictionary<string, string>
        {
            ["sub"] = "erin", ["tenant_id"] = "tenant-a", ["role"] = "ADMIN",
        }));
        var create = new { username = "alice", password = "alice-password", role = "USER", enabled = true };
        Assert.Equal(HttpStatusCode.Created, (await tenantAdmin.PostAsJsonAsync("/api/admin/users", create)).StatusCode);

        var first = await LoginAsync(anonymous, "alice", "alice-password", "tenant-a");
        var firstKey = await AccountKeyAsync(server, "tenant-a", "alice");
        Assert.Equal(firstKey, Uid(first));
        Assert.Equal(HttpStatusCode.NoContent, (await tenantAdmin.DeleteAsync("/api/admin/users/alice")).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await tenantAdmin.PostAsJsonAsync("/api/admin/users", create)).StatusCode);
        var secondKey = await AccountKeyAsync(server, "tenant-a", "alice");
        Assert.NotEqual(firstKey, secondKey);

        // The first alice's token names an account row that is gone; it does not pass to the second.
        using var firstClient = Bearer(server, first);
        var me = (await firstClient.GetAsync("/api/admin/me")).StatusCode;
        Assert.True(me is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden, $"me {me}");
        Assert.Equal(HttpStatusCode.Unauthorized, (await firstClient.PostAsync("/auth/refresh", null)).StatusCode);

        var second = await LoginAsync(anonymous, "alice", "alice-password", "tenant-a");
        Assert.Equal(secondKey, Uid(second));
        using var secondClient = Bearer(server, second);
        Assert.Equal(HttpStatusCode.OK, (await secondClient.GetAsync("/api/admin/me")).StatusCode);
        using var refreshed = await secondClient.PostAsync("/auth/refresh", null);
        Assert.Equal(HttpStatusCode.OK, refreshed.StatusCode);
        Assert.Equal(secondKey, Uid((await refreshed.Content.ReadFromJsonAsync<TokenBody>(JsonOptions))!.AccessToken));
    }

    [Fact]
    public async Task DeletingAnAccountReleasesItsEmail()
    {
        await using var server = await TestServerFixture.StartAsync();
        await SeedAsync(server, "9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5", "dora", "default", ManagementRole.Admin);
        await SeedAsync(server, "0f1e2d3c-4b5a-4968-8776-655443322110", "frank", "default", ManagementRole.User);
        await SeedAsync(server, "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", "grace", "default", ManagementRole.User);
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var now = DateTimeOffset.UtcNow;
            db.ManagementUserEmails.Add(new ManagementUserEmail
            {
                Username = "0f1e2d3c-4b5a-4968-8776-655443322110", Email = "frank@example.com",
                VerifiedAt = now, CreatedAt = now, UpdatedAt = now,
            });
            db.ManagementUserEmails.Add(new ManagementUserEmail
            {
                Username = "1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d", Email = "grace@example.com",
                VerifiedAt = now, CreatedAt = now, UpdatedAt = now,
            });
            await db.SaveChangesAsync();
        }
        using var dora = Bearer(server, Sign(new Dictionary<string, string>
        {
            ["sub"] = "dora", ["tenant_id"] = "default", ["role"] = "ADMIN",
            ["uid"] = "9e8d7c6b-5a4f-4e3d-a2c1-b0a9f8e7d6c5",
        }));

        Assert.Equal(HttpStatusCode.NoContent, (await dora.DeleteAsync("/api/admin/users/FRANK")).StatusCode);

        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var emails = await db.ManagementUserEmails.AsNoTracking().Select(email => email.Email).ToListAsync();
            Assert.Equal(new[] { "grace@example.com" }, emails);
            Assert.False(await db.ManagementUsers.AnyAsync(user => user.Username == "0f1e2d3c-4b5a-4968-8776-655443322110"));
        }
    }

    private static async Task SeedVectorAccountsAsync(TestServerFixture server, JsonElement vector)
    {
        foreach (var account in vector.GetProperty("accounts").EnumerateArray())
        {
            await SeedAsync(server, account.GetProperty("accountKey").GetString()!,
                account.GetProperty("loginName").GetString()!, account.GetProperty("tenantId").GetString()!,
                account.GetProperty("role").GetString() == "ADMIN" ? ManagementRole.Admin : ManagementRole.User,
                account.GetProperty("enabled").GetBoolean());
        }
    }

    private static async Task SeedAsync(TestServerFixture server, string accountKey, string loginName,
        string tenantId, ManagementRole role, bool enabled = true)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        db.ManagementUsers.Add(new ManagementUser
        {
            Username = accountKey,
            LoginName = loginName,
            LoginNameNormalized = ManagementUser.NormalizeLoginName(loginName),
            TenantId = tenantId,
            PasswordHash = PasswordHasher.Hash("vector-password"),
            Role = role,
            Enabled = enabled,
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    private static async Task<string> AccountKeyAsync(TestServerFixture server, string tenantId, string loginName)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var normalized = ManagementUser.NormalizeLoginName(loginName);
        return (await db.ManagementUsers.AsNoTracking()
            .SingleAsync(user => user.TenantId == tenantId && user.LoginNameNormalized == normalized)).Username;
    }

    /// <summary>Signs the claims as the server's own local token, with iss, iat and exp added.</summary>
    private static string Sign(JsonElement claims) => Sign(claims.EnumerateObject()
        .ToDictionary(claim => claim.Name, claim => claim.Value.GetString()!));

    private static string Sign(Dictionary<string, string> claims)
    {
        var now = DateTimeOffset.UtcNow;
        var payload = new Dictionary<string, object>
        {
            ["iss"] = LocalTokenService.Issuer,
            ["iat"] = now.ToUnixTimeSeconds(),
            ["exp"] = now.AddMinutes(10).ToUnixTimeSeconds(),
        };
        foreach (var (name, value) in claims)
        {
            payload[name] = value;
        }
        var signingInput = Base64Url(JsonSerializer.SerializeToUtf8Bytes(new { alg = "HS256", typ = "JWT" }))
            + "." + Base64Url(JsonSerializer.SerializeToUtf8Bytes(payload));
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(JwtSecret));
        return signingInput + "." + Base64Url(HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(signingInput)));
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static JsonDocument Payload(string token)
    {
        var segment = token.Split('.')[1].Replace('-', '+').Replace('_', '/');
        segment = segment.PadRight(segment.Length + ((4 - segment.Length % 4) % 4), '=');
        return JsonDocument.Parse(Convert.FromBase64String(segment));
    }

    private static string? Uid(string token)
    {
        using var payload = Payload(token);
        return payload.RootElement.TryGetProperty("uid", out var uid) ? uid.GetString() : null;
    }

    private static HttpClient Bearer(TestServerFixture server, string token)
    {
        var client = server.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private static async Task<string> LoginAsync(HttpClient client, string username, string password,
        string? tenantId)
    {
        object body = tenantId is null ? new { username, password } : new { username, password, tenantId };
        using var response = await client.PostAsJsonAsync("/auth/login", body);
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<TokenBody>(JsonOptions))!.AccessToken;
    }

    private static JsonDocument LoadVector() => JsonDocument.Parse(File.ReadAllText(FindVector()));

    private static string FindVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors",
                "management-accounts-v1.json");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }
        throw new FileNotFoundException("cannot locate management-accounts-v1.json");
    }

    private sealed record TokenBody(string AccessToken, string TokenType, long ExpiresIn);

    private sealed record UserBody(string Username, string TenantId, string Role, bool Admin, bool BuiltIn,
        bool Enabled);
}
