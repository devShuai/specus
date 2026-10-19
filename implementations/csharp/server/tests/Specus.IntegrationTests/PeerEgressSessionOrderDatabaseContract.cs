using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Protocol.PeerEgress;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using Specus.Server.PeerMesh;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

// Linked into the three mandatory real-database suites. The same raw persisted
// strings and actual catalogue service must work on each provider, not just SQLite.
public static class PeerEgressSessionOrderDatabaseContract
{
    public static Task AssertAsync(SpecusDbContext db) =>
        AssertVectorAsync(db, "peer-egress-session-order-v1.json", 26, false);

    public static Task AssertScopeAsync(SpecusDbContext db) =>
        AssertVectorAsync(db, "peer-egress-session-scope-v1.json", 8, true);

    private static async Task AssertVectorAsync(SpecusDbContext db, string vectorFile, int expectedCases, bool literalScope)
    {
        Assert.Empty(await db.ClientAccounts.AsNoTracking().ToArrayAsync());
        var now = DateTimeOffset.UtcNow;
        ClientAccount AddClient(long id, string name, string ip)
        {
            var account = new ClientAccount
            {
                Id = id, TenantId = "default", OwnerUsername = "order-owner", ClientName = name,
                PasswordHash = "unused", Enabled = true, ConnectionRateLimitPerMinute = 60,
                CreatedAt = now, UpdatedAt = now,
            };
            db.ClientAccounts.Add(account);
            db.PeerMeshDevices.Add(new PeerMeshDevice
            {
                Id = id + 10000, TenantId = "default", OwnerUsername = "order-owner",
                ClientId = id, ClientName = name, VirtualIp = ip, Cidr = "100.96.0.0/11",
                Enabled = true, CreatedAt = now, UpdatedAt = now,
            });
            return account;
        }
        var consumer = AddClient(1001, "order-consumer", "100.96.0.10");
        var egress = AddClient(2002, "order-egress", "100.96.0.11");
        db.PeerMeshAcls.Add(new PeerMeshAcl
        {
            Id = 9001, TenantId = "default", SourceClientId = consumer.Id, SourceClientName = consumer.ClientName,
            TargetClientId = egress.Id, TargetClientName = egress.ClientName, Allowed = true,
            Direction = PeerMeshService.DirectionBoth, CreatedAt = now, UpdatedAt = now,
        });
        await db.SaveChangesAsync();
        var service = new PeerMeshService(db, new SessionRegistry(NullLogger<SessionRegistry>.Instance),
            Options.Create(new PeerMeshOptions { Enabled = true, Cidr = "100.96.0.0/11", PublicAddress = "203.0.113.10", SessionTtlSeconds = 3600 }),
            NullLogger<PeerMeshService>.Instance, null, new PeerMeshServiceState());
        var admin = new ManagementContext("default", "admin", ManagementRole.Admin, true);
        await service.SetEgressSwitchAsync(admin, true, default);
        await service.UpsertEgressPolicyAsync(admin, new PeerEgressPolicyMutation(
            EgressClientId: egress.Id, Enabled: true, Scope: PeerEgressAuthorization.ScopePublic,
            AllowedConsumerClientIds: [consumer.Id], DestinationRules: [],
            MaxConcurrentFlows: null, MaxFlowsPerConsumer: null, IdleTimeoutSeconds: null), default);

        var model = db.Model.FindEntityType(typeof(ClientSession))!;
        var table = StoreObjectIdentifier.Table(model.GetTableName()!, model.GetSchema());
        var sql = db.GetService<ISqlGenerationHelper>();
        string Column(string property) => sql.DelimitIdentifier(model.FindProperty(property)!.GetColumnName(table)!);
        var update = $"UPDATE {sql.DelimitIdentifier(table.Name, table.Schema)} "
            + $"SET {Column(nameof(ClientSession.NettyConnectedAt))} = {{0}}, {Column(nameof(ClientSession.HttpLoginAt))} = {{1}} "
            + $"WHERE {Column(nameof(ClientSession.Id))} = {{2}}";
        // The shared MySQL EF provider emits an aliased DELETE that MariaDB rejects.
        // This dedicated owned test database has no unrelated sessions to preserve.
        var resetSessions = $"DELETE FROM {sql.DelimitIdentifier(table.Name, table.Schema)}";
        using var vector = LoadVector(vectorFile);
        Assert.Equal(expectedCases, vector.RootElement.GetProperty("cases").GetArrayLength());
        Assert.False(vector.RootElement.GetProperty("consumerIpv6DataPlaneEnabled").GetBoolean());
        foreach (var example in vector.RootElement.GetProperty("cases").EnumerateArray())
        {
            await db.Database.ExecuteSqlRawAsync(resetSessions);
            db.ChangeTracker.Clear();
            foreach (var declaration in example.GetProperty("sessions").EnumerateArray())
            {
                var id = declaration.GetProperty("id").GetInt64();
                db.ClientSessions.Add(new ClientSession
                {
                    Id = id, TenantId = literalScope ? declaration.GetProperty("tenantId").GetString()!
                        : declaration.GetProperty("tenantId").GetString() == "tenant-a" ? "default" : "tenant-b",
                    ClientId = literalScope ? declaration.GetProperty("clientId").GetInt64()
                        : declaration.GetProperty("clientId").GetInt64() == 1002 ? egress.Id : 3003,
                    ClientName = "order-egress", TokenHash = $"order-session-{id}",
                    Status = declaration.GetProperty("status").GetString()!,
                    MachineFingerprint = "fixture-machine", OsUser = "fixture-user",
                    HttpLoginAt = now, NettyConnectedAt = now, ExpiresAt = now.AddHours(1),
                    ClientEgressVersion = declaration.GetProperty("version").GetInt32(),
                    ClientEgressDomainTargets = declaration.GetProperty("domainTargetCapable").GetBoolean(),
                    ClientEgressIpv6Targets = declaration.GetProperty("ipv6TargetCapable").GetBoolean(),
                });
                await db.SaveChangesAsync();
                // A CLR DBNull argument makes EF ask the provider for a DBNull
                // type mapping. Use the provider's own explicitly typed parameter
                // so a missing control timestamp is really SQL NULL on all vendors.
                using var parameterFactory = db.Database.GetDbConnection().CreateCommand();
                var connectedParameter = parameterFactory.CreateParameter();
                connectedParameter.ParameterName = "connectionTime";
                connectedParameter.DbType = System.Data.DbType.String;
                connectedParameter.Value = (object?)declaration.GetProperty("connectedAt").GetString() ?? DBNull.Value;
                await db.Database.ExecuteSqlRawAsync(update,
                    connectedParameter,
                    declaration.GetProperty("httpLoginAt").GetString()!, id);
            }
            var catalog = await service.BuildEgressCatalogAsync(consumer, new ClientEgressCapabilities { Version = 1 }, default);
            var entry = Assert.Single(catalog!.Egresses!);
            var expected = example.GetProperty("expected");
            var name = example.GetProperty("name").GetString();
            Assert.True(expected.GetProperty("version").GetInt32() == entry.EgressVersion, $"{name}: wrong version");
            Assert.True(expected.GetProperty("domainTargetCapable").GetBoolean() == entry.DomainTargetCapable, $"{name}: wrong domain declaration");
            Assert.True(expected.GetProperty("ipv6TargetCapable").GetBoolean() == entry.Ipv6TargetCapable, $"{name}: wrong IPv6 declaration");
        }
    }

    private static JsonDocument LoadVector(string vectorFile)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var path = Path.Combine(directory.FullName, "protocol", "test-vectors", vectorFile);
            if (File.Exists(path)) return JsonDocument.Parse(File.ReadAllText(path));
        }
        throw new InvalidOperationException("Shared session ordering vector not found");
    }
}
