using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Server.Authentication;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.Security;
using Specus.Server.WebSockets;

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

    /// <summary>Java ManagementAccountsHttpTests.replaysTheAccountDeletionVector (management-accounts.md 7.1).</summary>
    [Fact]
    public async Task ReplaysTheAccountDeletionVector()
    {
        using var vector = LoadVector();
        var deletion = vector.RootElement.GetProperty("accountDeletion");
        await using var server = await TestServerFixture.StartAsync();
        foreach (var account in deletion.GetProperty("accounts").EnumerateArray())
        {
            await SeedAsync(server, account.GetProperty("accountKey").GetString()!,
                account.GetProperty("loginName").GetString()!, account.GetProperty("tenantId").GetString()!,
                account.GetProperty("role").GetString() == "ADMIN" ? ManagementRole.Admin : ManagementRole.User);
        }
        var seed = deletion.GetProperty("seed");
        await SeedDeletionRowsAsync(server, seed);
        using var actor = Bearer(server, Sign(deletion.GetProperty("actor")));
        var index = 0;
        foreach (var step in deletion.GetProperty("steps").EnumerateArray())
        {
            var name = $"step {index++}: {step}";
            if (step.TryGetProperty("deleteUser", out var deleteUser))
            {
                var expect = step.GetProperty("expect");
                using var response = await actor.DeleteAsync("/api/admin/users/" + deleteUser.GetString());
                var body = await response.Content.ReadAsStringAsync();
                Assert.True(expect.GetProperty("status").GetInt32() == (int)response.StatusCode, $"{name} {body}");
                if (response.StatusCode == HttpStatusCode.Conflict)
                {
                    using var refusal = JsonDocument.Parse(body);
                    Assert.False(string.IsNullOrWhiteSpace(refusal.RootElement.GetProperty("error").GetString()), name);
                    Assert.Equal(expect.GetProperty("clients").GetInt64(),
                        refusal.RootElement.GetProperty("clients").GetInt64());
                    Assert.Equal(expect.GetProperty("credentials").GetInt64(),
                        refusal.RootElement.GetProperty("credentials").GetInt64());
                }
            }
            else if (step.TryGetProperty("get", out var get))
            {
                var expect = step.GetProperty("expect");
                using var reader = Bearer(server, Sign(step.GetProperty("as")));
                using var response = await reader.GetAsync(get.GetString());
                var body = await response.Content.ReadAsStringAsync();
                Assert.True(expect.GetProperty("status").GetInt32() == (int)response.StatusCode, $"{name} {body}");
                using var actual = JsonDocument.Parse(body);
                Assert.True(JsonElement.DeepEquals(expect.GetProperty("body"), actual.RootElement), $"{name} {body}");
            }
            else
            {
                await ApplyDeletionFixtureAsync(server, step);
            }
        }

        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var after = deletion.GetProperty("rowsAfter");
        var now = DateTimeOffset.UtcNow;
        var owners = new Dictionary<string, Dictionary<long, string>>
        {
            ["clients"] = await db.ClientAccounts.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.OwnerUsername ?? ""),
            ["credentials"] = await db.ClientCredentials.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.OwnerUsername ?? ""),
            ["diagrams"] = await db.UserDiagramDocuments.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.OwnerUsername),
            ["downloadGrants"] = await db.TransferAttachmentDownloadGrants.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.Username),
            ["downloadUsage"] = await db.TransferAttachmentDownloadUsages.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.Username),
            ["acls"] = await db.PeerMeshAcls.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.OwnerUsername),
            ["egressPolicies"] = await db.PeerMeshEgressPolicies.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.OwnerUsername),
            ["devices"] = await db.PeerMeshDevices.AsNoTracking().ToDictionaryAsync(row => row.Id, row => row.OwnerUsername),
            ["attachments"] = (await db.TransferAttachments.AsNoTracking().ToListAsync()).ToDictionary(row => row.Id,
                row => (row.OwnerUsername ?? "") + (row.ExpiresAt > now
                    && (row.Status != TransferAttachmentService.StatusPending || row.UploadExpiresAt > now)
                        ? " active" : " inactive")),
        };
        foreach (var table in after.EnumerateObject())
        {
            var expected = new SortedDictionary<long, string>();
            foreach (var row in table.Value.EnumerateArray())
            {
                var owner = (row.TryGetProperty("owner", out var value) ? value : row.GetProperty("username")).GetString()!;
                if (row.TryGetProperty("active", out var active))
                {
                    owner += active.GetBoolean() ? " active" : " inactive";
                }
                expected[row.GetProperty("id").GetInt64()] = owner;
            }
            var actual = new SortedDictionary<long, string>();
            foreach (var row in seed.GetProperty(table.Name).EnumerateArray())
            {
                var id = row.GetProperty("id").GetInt64();
                if (owners[table.Name].TryGetValue(id, out var owner))
                {
                    actual[id] = owner;
                }
            }
            Assert.True(expected.SequenceEqual(actual),
                $"{table.Name}: {string.Join(", ", actual)} want {string.Join(", ", expected)}");
        }
        var expectedAccounts = deletion.GetProperty("accountsAfter").EnumerateArray()
            .Select(account => $"{account.GetProperty("tenantId").GetString()}/{account.GetProperty("loginName").GetString()}="
                + account.GetProperty("accountKey").GetString())
            .Order(StringComparer.Ordinal).ToList();
        var tenants = deletion.GetProperty("accountsAfter").EnumerateArray()
            .Select(account => account.GetProperty("tenantId").GetString()!).Distinct().ToList();
        var actualAccounts = (await db.ManagementUsers.AsNoTracking().Where(user => tenants.Contains(user.TenantId))
                .ToListAsync())
            .Select(user => $"{user.TenantId}/{user.LoginName}={user.Username}")
            .Order(StringComparer.Ordinal).ToList();
        Assert.Equal(expectedAccounts, actualAccounts);
    }

    /// <summary>Java ManagementAccountsHttpTests.deletingAnAccountClosesItsManagementWebSockets.</summary>
    [Fact]
    public async Task DeletingAnAccountClosesItsManagementWebSockets()
    {
        await using var server = await TestServerFixture.StartAsync();
        using var anonymous = server.CreateClient();
        using var admin = Bearer(server, await LoginAsync(anonymous, "admin", "admin", null));
        // bob administers the default tenant, so the connection events of its clients reach him.
        await SeedAsync(server, "7c2f3a4b-5d6e-4f70-9b8c-0d1e2f3a4b5c", "bob", "default", ManagementRole.Admin);
        using var bob = Bearer(server, Sign(new Dictionary<string, string>
        {
            ["sub"] = "bob", ["tenant_id"] = "default", ["role"] = "ADMIN",
            ["uid"] = "7c2f3a4b-5d6e-4f70-9b8c-0d1e2f3a4b5c",
        }));
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var bobMessages = await ConnectManagementSocketAsync(server, bob, "client-messages", cts.Token);
        Assert.Contains("\"hello\"", await ReceiveTextAsync(bobMessages, cts.Token), StringComparison.Ordinal);
        using var bobEvents = await ConnectManagementSocketAsync(server, bob, "connections", cts.Token);
        using var adminMessages = await ConnectManagementSocketAsync(server, admin, "client-messages", cts.Token);
        Assert.Contains("\"hello\"", await ReceiveTextAsync(adminMessages, cts.Token), StringComparison.Ordinal);
        // An event reaching bob's connection proves the hub has registered it.
        await using (var scope = server.HostServices.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
            var demo = await db.ClientAccounts.AsNoTracking().FirstAsync(account => account.TenantId == "default",
                cts.Token);
            await scope.ServiceProvider.GetRequiredService<ConnectionRecordService>().RecordConnectionAsync(
                AuthenticationResult.Pass(demo), demo.ClientName, "account-deletion-ws", "127.0.0.1:51001", cts.Token);
        }
        Assert.Contains("\"created\"", await ReceiveTextAsync(bobEvents, cts.Token), StringComparison.Ordinal);

        Assert.Equal(HttpStatusCode.NoContent, (await admin.DeleteAsync("/api/admin/users/bob")).StatusCode);

        var buffer = new byte[4096];
        var closed = await bobMessages.ReceiveAsync(buffer, cts.Token);
        Assert.Equal(WebSocketMessageType.Close, closed.MessageType);
        Assert.Equal(WebSocketCloseStatus.PolicyViolation, closed.CloseStatus);
        Assert.Equal(WebSocketMessageType.Close, (await bobEvents.ReceiveAsync(buffer, cts.Token)).MessageType);
        // Another identity's connection stays open.
        var hub = server.HostServices.GetRequiredService<ClientMessagesHub>();
        var source = new ClientAccount { TenantId = "default", ClientName = "deleted-account-client" };
        Assert.False(await hub.DeliverFromClientAsync(source, "admin:bob", "to the deleted account", cts.Token));
        Assert.True(await hub.DeliverFromClientAsync(source, "admin:admin", "still here", cts.Token));
        Assert.Contains("still here", await ReceiveTextAsync(adminMessages, cts.Token), StringComparison.Ordinal);
    }

    private static async Task<WebSocket> ConnectManagementSocketAsync(TestServerFixture server, HttpClient client,
        string endpoint, CancellationToken cancellationToken)
    {
        using var issued = await client.PostAsJsonAsync("/api/admin/ws-tickets", new { endpoint }, cancellationToken);
        issued.EnsureSuccessStatusCode();
        using var ticket = JsonDocument.Parse(await issued.Content.ReadAsStringAsync(cancellationToken));
        return await server.Server.CreateWebSocketClient().ConnectAsync(
            new Uri($"ws://localhost/ws/{endpoint}?ticket="
                + Uri.EscapeDataString(ticket.RootElement.GetProperty("ticket").GetString()!)),
            cancellationToken);
    }

    private static async Task<string> ReceiveTextAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[16384];
        using var message = new MemoryStream();
        while (true)
        {
            var result = await socket.ReceiveAsync(buffer, cancellationToken);
            Assert.Equal(WebSocketMessageType.Text, result.MessageType);
            message.Write(buffer, 0, result.Count);
            if (result.EndOfMessage)
            {
                return Encoding.UTF8.GetString(message.ToArray());
            }
        }
    }

    private static async Task SeedDeletionRowsAsync(TestServerFixture server, JsonElement seed)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var now = DateTimeOffset.UtcNow;
        var later = now.AddHours(1);
        static long Id(JsonElement row, string name = "id") => row.GetProperty(name).GetInt64();
        static string Text(JsonElement row, string name) => row.GetProperty(name).GetString()!;
        foreach (var row in seed.GetProperty("clients").EnumerateArray())
        {
            db.ClientAccounts.Add(new ClientAccount
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), OwnerUsername = Text(row, "owner"),
                ClientName = Text(row, "clientName"), PasswordHash = new string('0', 64), CreatedAt = now, UpdatedAt = now,
            });
        }
        foreach (var row in seed.GetProperty("credentials").EnumerateArray())
        {
            db.ClientCredentials.Add(new ClientCredential
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), OwnerUsername = Text(row, "owner"),
                ApiKey = $"acct-del-{Id(row)}", SecretHash = new string('0', 64), CreatedAt = now, UpdatedAt = now,
            });
        }
        foreach (var row in seed.GetProperty("diagrams").EnumerateArray())
        {
            db.UserDiagramDocuments.Add(new UserDiagramDocument
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), OwnerUsername = Text(row, "owner"),
                Name = $"acct-del-{Id(row)}", SnapshotData = [1], SizeBytes = 1, Revision = 1,
                CreatedAt = now, UpdatedAt = now,
            });
        }
        foreach (var row in seed.GetProperty("attachments").EnumerateArray())
        {
            db.TransferAttachments.Add(new TransferAttachment
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), Scope = "ADMIN_CLIENT_MESSAGE",
                OwnerUsername = Text(row, "owner"), ObjectKey = $"acct-del/{Id(row)}", FileName = "file.bin",
                SizeBytes = 1, Status = Text(row, "status"), CreatedAt = now, UpdatedAt = now,
                UploadExpiresAt = later, ExpiresAt = later,
            });
        }
        foreach (var row in seed.GetProperty("downloadGrants").EnumerateArray())
        {
            db.TransferAttachmentDownloadGrants.Add(new TransferAttachmentDownloadGrant
            {
                Id = Id(row), TokenHash = Id(row).ToString("D64"), TenantId = Text(row, "tenantId"),
                Username = Text(row, "username"), AttachmentId = Id(row, "attachmentId"), CreatedAt = now,
                ExpiresAt = later,
            });
        }
        foreach (var row in seed.GetProperty("downloadUsage").EnumerateArray())
        {
            db.TransferAttachmentDownloadUsages.Add(new TransferAttachmentDownloadUsage
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), Username = Text(row, "username"),
                AttachmentId = Id(row, "attachmentId"), SizeBytes = 1, UsageMonth = now.ToString("yyyy-MM"),
                CreatedAt = now,
            });
        }
        foreach (var row in seed.GetProperty("acls").EnumerateArray())
        {
            db.PeerMeshAcls.Add(new PeerMeshAcl
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), OwnerUsername = Text(row, "owner"),
                SourceClientId = Id(row, "sourceClientId"), SourceClientName = $"acct-del-{Id(row, "sourceClientId")}",
                TargetClientId = Id(row, "targetClientId"), TargetClientName = $"acct-del-{Id(row, "targetClientId")}",
                CreatedAt = now, UpdatedAt = now,
            });
        }
        foreach (var row in seed.GetProperty("egressPolicies").EnumerateArray())
        {
            db.PeerMeshEgressPolicies.Add(new PeerMeshEgressPolicy
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), OwnerUsername = Text(row, "owner"),
                EgressClientId = Id(row, "egressClientId"), EgressClientName = $"acct-del-{Id(row, "egressClientId")}",
                CreatedAt = now, UpdatedAt = now,
            });
        }
        foreach (var row in seed.GetProperty("devices").EnumerateArray())
        {
            db.PeerMeshDevices.Add(new PeerMeshDevice
            {
                Id = Id(row), TenantId = Text(row, "tenantId"), OwnerUsername = Text(row, "owner"),
                ClientId = Id(row, "clientId"), ClientName = $"acct-del-{Id(row, "clientId")}",
                VirtualIp = $"10.77.0.{Id(row) % 250}", Cidr = "10.77.0.0/16", CreatedAt = now, UpdatedAt = now,
            });
        }
        await db.SaveChangesAsync();
    }

    private static async Task ApplyDeletionFixtureAsync(TestServerFixture server, JsonElement step)
    {
        await using var scope = server.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var id = step.TryGetProperty("id", out var value) ? value.GetInt64() : 0;
        switch (step.GetProperty("fixture").GetString())
        {
            case "transfer-client":
                var owner = step.GetProperty("owner").GetString()!;
                await db.ClientAccounts.Where(client => client.Id == id)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(client => client.OwnerUsername, owner));
                await db.PeerMeshDevices.Where(device => device.ClientId == id)
                    .ExecuteUpdateAsync(setters => setters.SetProperty(device => device.OwnerUsername, owner));
                break;
            case "delete-client":
                await db.ClientAccounts.Where(client => client.Id == id).ExecuteDeleteAsync();
                break;
            case "delete-credential":
                await db.ClientCredentials.Where(credential => credential.Id == id).ExecuteDeleteAsync();
                break;
            case "create-account":
                await SeedAsync(server, step.GetProperty("accountKey").GetString()!,
                    step.GetProperty("loginName").GetString()!, step.GetProperty("tenantId").GetString()!,
                    step.GetProperty("role").GetString() == "ADMIN" ? ManagementRole.Admin : ManagementRole.User);
                break;
            default:
                throw new InvalidOperationException($"unknown fixture {step}");
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
