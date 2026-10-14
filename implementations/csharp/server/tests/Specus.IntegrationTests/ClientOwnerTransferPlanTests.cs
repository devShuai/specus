using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.EntityFrameworkCore;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.IntegrationTests;

public sealed class ClientOwnerTransferPlanTests
{
    internal static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    internal static readonly ManagementContext Admin = new("tenant-a", "admin", ManagementRole.Admin, false);

    public static IEnumerable<object[]> SharedCases()
    {
        var vector = Vector();
        Assert.Equal(1, vector["version"]!.GetValue<int>());
        Assert.Equal(29, vector["cases"]!.AsArray().Count);
        return vector["cases"]!.AsArray().Select(item => new object[] { item!["name"]!.GetValue<string>(), item.ToJsonString() });
    }

    [Theory]
    [MemberData(nameof(SharedCases))]
    public void ReplaysSharedStructuralVectors(string name, string scenarioJson)
    {
        Assert.NotEmpty(name);
        var scenario = JsonNode.Parse(scenarioJson)!.AsObject();
        var snapshot = ReadSnapshot(Input(scenario));
        var before = JsonSerializer.Serialize(snapshot, JsonOptions);
        var scope = Scope(scenario["scope"]!.GetValue<string>());
        var id = scenario["id"]!.GetValue<long>();
        var context = Admin with { Role = scenario["admin"]?.GetValue<bool>() == false ? ManagementRole.User : ManagementRole.Admin };
        var hasRequest = scenario.ContainsKey("request");
        var request = scenario["request"]?.DeepClone();
        if (request is JsonObject requested && requested["expectedRevision"]?.ToJsonString() == "\"$current\"")
            requested["expectedRevision"] = Preview(context, scope, id, snapshot).Revision;
        using var body = JsonDocument.Parse(request?.ToJsonString() ?? "null");
        if (scenario["error"] is { } error)
        {
            var failure = Assert.Throws<ClientOwnerTransferException>(() =>
            {
                if (hasRequest) Prepare(context, scope, id, body.RootElement, snapshot);
                else Preview(context, scope, id, snapshot);
            });
            Assert.Equal(error["status"]!.GetValue<int>(), failure.Status);
            Assert.Equal(error["code"]!.GetValue<string>(), failure.Code);
            Assert.Equal(failure.Code, failure.Message);
        }
        else if (scenario["preparedTarget"] is { } target)
        {
            var prepared = Prepare(context, scope, id, body.RootElement, snapshot);
            Assert.Equal(target.GetValue<string>(), prepared.RequestedTargetUsername);
            Assert.True(prepared.Preview.AccessRetained);
        }
        else AssertPreview(Preview(context, scope, id, snapshot), scenario, snapshot);
        Assert.Equal(before, JsonSerializer.Serialize(snapshot, JsonOptions));
    }

    internal static void AssertPreview(ClientOwnerTransferPreview actual, JsonObject scenario, Snapshot snapshot)
    {
        var expected = scenario["preview"]!;
        Assert.Equal(expected["clientId"]?.GetValue<long>(), actual.ClientId);
        Assert.Equal(expected["credentialId"]?.GetValue<long>(), actual.CredentialId);
        Assert.Equal(expected["canTransfer"]!.GetValue<bool>(), actual.CanTransfer);
        Assert.Equal(expected["conflictCode"]?.GetValue<string>(), actual.ConflictCode);
        Assert.Equal(scenario["scope"]!.GetValue<string>(), actual.Scope);
        Assert.Equal(expected["affectedClientIds"]!.AsArray().Select(n => n!.GetValue<long>()), actual.AffectedClients.Select(c => c.Id));
        Assert.Equal(actual.AffectedClients.Count, actual.AffectedClientCount);
        Assert.Equal(expected["hasRevision"]!.GetValue<bool>(), actual.Revision is not null);
        Assert.True(actual.AccessRetained);
        foreach (var client in actual.AffectedClients)
        {
            var original = snapshot.Clients.Single(c => c.Id == client.Id);
            Assert.Equal((original.ClientName, original.OwnerUsername, original.Enabled), (client.ClientName, client.OwnerUsername, client.Enabled));
        }
        if (actual.CredentialId is { } credentialId)
        {
            var original = snapshot.Credentials.Single(c => c.Id == credentialId);
            Assert.Equal(original.OwnerUsername, actual.CredentialOwnerUsername);
            Assert.Equal(original.Enabled, actual.CredentialEnabled);
        }
        else
        {
            Assert.Null(actual.CredentialOwnerUsername);
            Assert.Null(actual.CredentialEnabled);
        }
        var json = JsonSerializer.Serialize(actual, JsonOptions);
        foreach (var secretField in new[] { "secret", "token", "fingerprint", "privateKey" }) Assert.DoesNotContain(secretField, json);
    }

    [Theory]
    [InlineData("clients", "ownerUsername")]
    [InlineData("clients", "enabled")]
    [InlineData("credentials", "ownerUsername")]
    [InlineData("credentials", "enabled")]
    [InlineData("peers", "ownerUsername")]
    [InlineData("peers", "enabled")]
    [InlineData("clients", "clientName")]
    [InlineData("peers", "clientName")]
    [InlineData("relations", "delete")]
    [InlineData("relations", "add")]
    [InlineData("identities", "id")]
    [InlineData("peers", "remove")]
    [InlineData("peers", "id")]
    public void EveryRelevantChangeInvalidatesRevision(string table, string field)
    {
        var original = Vector()["base"]!.AsObject();
        var changed = original.DeepClone().AsObject();
        if (table == "relations" && field == "delete")
        {
            changed["clients"]!.AsArray().RemoveAt(1);
            changed["identities"]!.AsArray().RemoveAt(1);
        }
        else if (table == "relations")
        {
            var client = changed["clients"]![1]!.DeepClone();
            client["id"] = 1003;
            changed["clients"]!.AsArray().Add(client);
            var edge = changed["identities"]![1]!.DeepClone();
            edge["id"] = 703;
            edge["clientId"] = 1003;
            changed["identities"]!.AsArray().Add(edge);
        }
        else if (field == "remove") changed[table]!.AsArray().Clear();
        else changed[table]![0]![field] = field switch
        {
            "enabled" => JsonValue.Create(!changed[table]![0]![field]!.GetValue<bool>()),
            "id" => JsonValue.Create(799L),
            "clientName" => JsonValue.Create("renamed"),
            _ => JsonValue.Create("bob"),
        };
        var oldRevision = Preview(Admin, PathScope.CredentialGroup, 501, ReadSnapshot(original)).Revision;
        var current = ReadSnapshot(changed);
        Assert.NotEqual(oldRevision, Preview(Admin, PathScope.CredentialGroup, 501, current).Revision);
        using var request = JsonDocument.Parse(JsonSerializer.Serialize(new { scope = "credential-group", targetUsername = "bob", expectedRevision = oldRevision }));
        var failure = Assert.Throws<ClientOwnerTransferException>(() => Prepare(Admin, PathScope.CredentialGroup, 501, request.RootElement, current));
        Assert.Equal((409, "TRANSFER_PREVIEW_CHANGED"), (failure.Status, failure.Code));
    }

    [Fact]
    public void RevisionIsStatelessOrderIndependentAndBoundToTenantScopePath()
    {
        var data = ReadSnapshot(Vector()["base"]!);
        var original = Preview(Admin, PathScope.CredentialGroup, 501, data);
        var reversed = new Snapshot(data.Clients.Reverse().ToArray(), data.Credentials.Reverse().ToArray(), data.Identities.Reverse().ToArray(), data.Peers.Reverse().ToArray());
        var other = Preview(Admin with { Username = "another-admin" }, PathScope.CredentialGroup, 501, reversed);
        Assert.Equal(original.Revision, other.Revision);
        Assert.Equal(original.AffectedClients, other.AffectedClients);
        var otherTenant = new Snapshot(data.Clients.Select(c => c with { TenantId = "tenant-b" }).ToArray(),
            data.Credentials.Select(c => c with { TenantId = "tenant-b" }).ToArray(),
            data.Identities.Select(c => c with { TenantId = "tenant-b" }).ToArray(), data.Peers.Select(c => c with { TenantId = "tenant-b" }).ToArray());
        Assert.NotEqual(original.Revision, Preview(Admin with { TenantId = "tenant-b" }, PathScope.CredentialGroup, 501, otherTenant).Revision);
        var unique = new Snapshot(data.Clients, data.Credentials, [data.Identities[0]], data.Peers);
        Assert.NotEqual(Preview(Admin, PathScope.Single, 1001, unique).Revision, Preview(Admin, PathScope.CredentialGroup, 501, unique).Revision);
        var legacy = new Snapshot(data.Clients, [], [], []);
        Assert.NotEqual(Preview(Admin, PathScope.Single, 1001, legacy).Revision, Preview(Admin, PathScope.Single, 1002, legacy).Revision);
    }

    [Fact]
    public void LargeGroupIsCompleteAndSnapshotOwnsImmutableInputs()
    {
        var clients = Enumerable.Range(0, 1050).Select(n => new ClientRow(1001 + n, "tenant-a", $"device-{n}", "alice", n % 2 == 0)).ToList();
        var identities = Enumerable.Range(0, 1050).Select(n => new IdentityRow(10001 + n, "tenant-a", 501, 1001 + n)).ToList();
        var snapshot = new Snapshot(clients, [new CredentialRow(501, "tenant-a", "alice", false)], identities, []);
        clients.Clear();
        identities.Clear();
        var result = Preview(Admin, PathScope.CredentialGroup, 501, snapshot);
        Assert.Equal(1050, result.AffectedClientCount);
        Assert.Equal(2050, result.AffectedClients[^1].Id);
        Assert.Throws<NotSupportedException>(() => ((IList<ClientRow>)snapshot.Clients).Clear());
        Assert.Throws<NotSupportedException>(() => ((IList<OwnerTransferAffectedClient>)result.AffectedClients).Clear());
    }

    [Fact]
    public void OpaqueRevisionAndLengthDelimitedTextAreNotNormalized()
    {
        var input = Vector()["base"]!.DeepClone();
        var snapshot = ReadSnapshot(input);
        var revision = Preview(Admin, PathScope.CredentialGroup, 501, snapshot).Revision;
        using var request = JsonDocument.Parse(JsonSerializer.Serialize(new { scope = "credential-group", targetUsername = "bob", expectedRevision = " " + revision }));
        Assert.Equal("TRANSFER_PREVIEW_CHANGED", Assert.Throws<ClientOwnerTransferException>(() => Prepare(Admin, PathScope.CredentialGroup, 501, request.RootElement, snapshot)).Code);
        input["clients"]![0]!["clientName"] = "one\ntwo";
        input["clients"]![0]!["ownerUsername"] = "three";
        var first = Preview(Admin, PathScope.CredentialGroup, 501, ReadSnapshot(input)).Revision;
        input["clients"]![0]!["clientName"] = "one";
        input["clients"]![0]!["ownerUsername"] = "two\nthree";
        Assert.NotEqual(first, Preview(Admin, PathScope.CredentialGroup, 501, ReadSnapshot(input)).Revision);
    }

    [Theory]
    [InlineData("sqlite", "\"Id\"")]
    [InlineData("postgres", "\"Id\"")]
    [InlineData("mysql", "`Id`")]
    public void SnapshotUsesActualProviderModelPrimaryKeyNames(string provider, string quotedKey)
    {
        var options = new DbContextOptionsBuilder<SpecusDbContext>();
        switch (provider)
        {
            case "sqlite": options.UseSqlite("Data Source=:memory:"); break;
            case "postgres": options.UseNpgsql("Host=localhost;Database=offline;Username=offline"); break;
            case "mysql": options.UseMySQL("server=localhost;database=offline;user=offline"); break;
            default: throw new ArgumentOutOfRangeException(nameof(provider));
        }
        using var db = new SpecusDbContext(options.Options);
        var command = new ClientOwnerTransferService(db).SnapshotCommandText();
        foreach (var alias in new[] { "c", "i", "p" }) Assert.Contains($"{alias}.{quotedKey}", command);
        Assert.DoesNotContain("__", command);
        Assert.DoesNotContain("c.id", command);
        Assert.Contains("@tenant", command);
        Assert.Contains("@id", command);
        // This test checks SQL generation only, not live PostgreSQL/MySQL acceptance.
    }

    internal static JsonObject Vector()
    {
        var root = new DirectoryInfo(AppContext.BaseDirectory);
        while (root is not null && !File.Exists(Path.Combine(root.FullName, "protocol/test-vectors/client-owner-transfer-plan-v1.json"))) root = root.Parent;
        Assert.NotNull(root);
        return JsonNode.Parse(File.ReadAllText(Path.Combine(root!.FullName, "protocol/test-vectors/client-owner-transfer-plan-v1.json")))!.AsObject();
    }

    internal static JsonObject Input(JsonObject scenario)
    {
        var vector = Vector();
        var input = vector["base"]!.DeepClone().AsObject();
        foreach (var pair in vector["snapshots"]![scenario["snapshot"]!.GetValue<string>()]!.AsObject()) input[pair.Key] = pair.Value!.DeepClone();
        return input;
    }

    internal static Snapshot ReadSnapshot(JsonNode node) => JsonSerializer.Deserialize<Snapshot>(node.ToJsonString(), JsonOptions)!;
    internal static PathScope Scope(string scope) => scope == "single" ? PathScope.Single : PathScope.CredentialGroup;
}
