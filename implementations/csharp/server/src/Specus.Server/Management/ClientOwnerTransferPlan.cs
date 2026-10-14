using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Specus.Server.Management;

public sealed class ClientOwnerTransferException(int status, string code) : Exception(code)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
}

public sealed record ClientOwnerTransferPreview(
    string Scope, long? ClientId, long? CredentialId, string? CredentialOwnerUsername,
    bool? CredentialEnabled, IReadOnlyList<OwnerTransferAffectedClient> AffectedClients,
    int AffectedClientCount, bool CanTransfer, string? ConflictCode, string? Revision,
    bool AccessRetained);

public sealed record OwnerTransferAffectedClient(long Id, string? ClientName, string? OwnerUsername, bool Enabled);

// Pure range/revision validation only (contract steps 1–8). This is not a transfer writer,
// target-account lookup, authorization token, or replacement for database coordination.
internal static class ClientOwnerTransferPlan
{
    internal const long MaxSafeId = 9_007_199_254_740_991;
    internal enum PathScope { Single, CredentialGroup }
    internal static string WireName(this PathScope scope) => scope == PathScope.Single ? "single" : "credential-group";
    internal sealed record ClientRow(long Id, string TenantId, string? ClientName, string? OwnerUsername, bool Enabled);
    internal sealed record CredentialRow(long Id, string TenantId, string? OwnerUsername, bool Enabled);
    internal sealed record IdentityRow(long Id, string TenantId, long CredentialId, long ClientId);
    internal sealed record PeerRow(long Id, string TenantId, long ClientId, string? ClientName, string? OwnerUsername, bool Enabled);

    // Includes ALL identity edges touching the chosen credential/clients, including foreign edges.
    internal sealed record Snapshot
    {
        public IReadOnlyList<ClientRow> Clients { get; }
        public IReadOnlyList<CredentialRow> Credentials { get; }
        public IReadOnlyList<IdentityRow> Identities { get; }
        public IReadOnlyList<PeerRow> Peers { get; }

        public Snapshot(IReadOnlyList<ClientRow> clients, IReadOnlyList<CredentialRow> credentials,
            IReadOnlyList<IdentityRow> identities, IReadOnlyList<PeerRow> peers)
        {
            Clients = Array.AsReadOnly(clients.ToArray());
            Credentials = Array.AsReadOnly(credentials.ToArray());
            Identities = Array.AsReadOnly(identities.ToArray());
            Peers = Array.AsReadOnly(peers.ToArray());
        }
    }

    internal sealed record Prepared(ClientOwnerTransferPreview Preview, string RequestedTargetUsername);

    internal static ClientOwnerTransferPreview Preview(ManagementContext context, PathScope scope, long pathId, Snapshot data)
    {
        AuthorizeAndValidateId(context, pathId);
        RequireResource(context, scope, pathId, data);
        return Build(context.TenantId, scope, pathId, data);
    }

    internal static Prepared Prepare(ManagementContext context, PathScope scope, long pathId,
        JsonElement request, Snapshot current)
    {
        AuthorizeAndValidateId(context, pathId);
        if (request.ValueKind != JsonValueKind.Object) throw Invalid();
        RequireResource(context, scope, pathId, current);
        if (!request.TryGetProperty("scope", out var requestedScope)
            || requestedScope.ValueKind != JsonValueKind.String || requestedScope.GetString() != scope.WireName()) throw Invalid();
        foreach (var field in new[] { "targetUsername", "expectedRevision" })
            if (request.TryGetProperty(field, out var value) && value.ValueKind != JsonValueKind.String) throw Invalid();
        var preview = Build(context.TenantId, scope, pathId, current);
        if (!preview.CanTransfer) throw new ClientOwnerTransferException(409, "CREDENTIAL_SHARED");
        var target = RequiredText(request, "targetUsername");
        var revision = RequiredText(request, "expectedRevision");
        if (preview.Revision != revision) throw new ClientOwnerTransferException(409, "TRANSFER_PREVIEW_CHANGED");
        return new Prepared(preview, target.Trim());
    }

    internal static void AuthorizeAndValidateId(ManagementContext context, long id)
    {
        ArgumentNullException.ThrowIfNull(context);
        if (!context.IsAdmin) throw new ClientOwnerTransferException(403, "FORBIDDEN");
        if (id <= 0 || id > MaxSafeId) throw Invalid();
    }

    private static void RequireResource(ManagementContext context, PathScope scope, long id, Snapshot data)
    {
        var exists = scope == PathScope.Single
            ? data.Clients.Any(c => c.Id == id && c.TenantId == context.TenantId)
            : data.Credentials.Any(c => c.Id == id && c.TenantId == context.TenantId);
        if (!exists) throw new ClientOwnerTransferException(404, "RESOURCE_NOT_FOUND");
    }

    private static ClientOwnerTransferPreview Build(string tenant, PathScope scope, long pathId, Snapshot data)
    {
        long? credentialId = scope == PathScope.CredentialGroup ? pathId : null;
        if (scope == PathScope.Single)
        {
            foreach (var edge in data.Identities.Where(i => i.ClientId == pathId))
            {
                if (edge.TenantId != tenant || (credentialId is not null && credentialId != edge.CredentialId)) throw Inconsistent();
                credentialId = edge.CredentialId;
            }
        }

        CredentialRow? credential = null;
        IdentityRow[] identities = [];
        SortedSet<long> clientIds = [];
        if (credentialId is { } selectedId)
        {
            var found = data.Credentials.Where(c => c.Id == selectedId).ToArray();
            if (selectedId <= 0 || selectedId > MaxSafeId || found.Length != 1 || found[0].TenantId != tenant) throw Inconsistent();
            credential = found[0];
            identities = data.Identities.Where(i => i.CredentialId == selectedId).OrderBy(i => i.Id).ToArray();
            HashSet<long> identityIds = [];
            foreach (var edge in identities)
            {
                if (edge.TenantId != tenant || !identityIds.Add(edge.Id)) throw Inconsistent();
                clientIds.Add(edge.ClientId);
            }
        }
        else clientIds.Add(pathId);

        var byId = data.Clients.ToLookup(c => c.Id);
        var clients = clientIds.Select(id =>
        {
            var found = byId[id].ToArray();
            if (id <= 0 || id > MaxSafeId || found.Length != 1 || found[0].TenantId != tenant) throw Inconsistent();
            return found[0];
        }).ToArray();
        foreach (var edge in data.Identities)
            if (clientIds.Contains(edge.ClientId)
                && (edge.TenantId != tenant || credentialId is null || credentialId != edge.CredentialId)) throw Inconsistent();
        var peers = data.Peers.Where(p => p.TenantId == tenant && clientIds.Contains(p.ClientId)).OrderBy(p => p.Id).ToArray();
        HashSet<long> peerClients = [];
        HashSet<long> peerIds = [];
        foreach (var peer in peers)
            if (!peerClients.Add(peer.ClientId) || !peerIds.Add(peer.Id)) throw Inconsistent();

        var shared = scope == PathScope.Single && clientIds.Count > 1;
        var affected = Array.AsReadOnly(clients.Select(c => new OwnerTransferAffectedClient(c.Id, c.ClientName, c.OwnerUsername, c.Enabled)).ToArray());
        return new ClientOwnerTransferPreview(scope.WireName(), scope == PathScope.Single ? pathId : null,
            credentialId, credential?.OwnerUsername, credential?.Enabled, affected, affected.Count,
            !shared, shared ? "CREDENTIAL_SHARED" : null,
            shared ? null : Revision(tenant, scope, pathId, credential, clients, identities, peers), true);
    }

    private static string Revision(string tenant, PathScope scope, long pathId, CredentialRow? credential,
        ClientRow[] clients, IdentityRow[] identities, PeerRow[] peers)
    {
        using var bytes = new MemoryStream();
        using (var output = new BinaryWriter(bytes, Encoding.UTF8, leaveOpen: true))
        {
            Text(output, "specus-owner-transfer-dotnet-v1");
            Text(output, tenant);
            Text(output, scope.WireName());
            output.Write(pathId);
            output.Write(credential is not null);
            if (credential is not null)
            {
                output.Write(credential.Id);
                Text(output, credential.OwnerUsername);
                output.Write(credential.Enabled);
            }
            output.Write(clients.Length);
            foreach (var client in clients)
            {
                output.Write(client.Id);
                Text(output, client.ClientName);
                Text(output, client.OwnerUsername);
                output.Write(client.Enabled);
            }
            output.Write(identities.Length);
            foreach (var edge in identities)
            {
                output.Write(edge.Id);
                output.Write(edge.CredentialId);
                output.Write(edge.ClientId);
            }
            output.Write(peers.Length);
            foreach (var peer in peers)
            {
                output.Write(peer.Id);
                output.Write(peer.ClientId);
                Text(output, peer.ClientName);
                Text(output, peer.OwnerUsername);
                output.Write(peer.Enabled);
            }
        }
        return Convert.ToHexStringLower(SHA256.HashData(bytes.ToArray()));
    }

    private static void Text(BinaryWriter output, string? value)
    {
        if (value is null) { output.Write(-1); return; }
        var encoded = Encoding.UTF8.GetBytes(value);
        output.Write(encoded.Length);
        output.Write(encoded);
    }

    private static string RequiredText(JsonElement request, string field)
    {
        if (!request.TryGetProperty(field, out var value) || string.IsNullOrWhiteSpace(value.GetString())) throw Invalid();
        return value.GetString()!;
    }

    private static ClientOwnerTransferException Invalid() => new(400, "INVALID_TRANSFER_REQUEST");
    private static ClientOwnerTransferException Inconsistent() => new(409, "INCONSISTENT_CREDENTIAL_GROUP");
}
