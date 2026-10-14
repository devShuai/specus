using System.Data;
using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using static Specus.Server.Management.ClientOwnerTransferPlan;

namespace Specus.Server.Management;

// GET only. No ownership writes until login/edit/delete/Peer/target-state races are coordinated.
public sealed class ClientOwnerTransferService(SpecusDbContext db)
{
    public Task<ClientOwnerTransferPreview> PreviewClientAsync(ManagementContext context, string id, CancellationToken cancellationToken) =>
        PreviewAsync(context, PathScope.Single, ParseId(context, id), cancellationToken);

    public Task<ClientOwnerTransferPreview> PreviewCredentialAsync(ManagementContext context, string id, CancellationToken cancellationToken) =>
        PreviewAsync(context, PathScope.CredentialGroup, ParseId(context, id), cancellationToken);

    internal static long ParseId(ManagementContext context, string? text)
    {
        AuthorizeAndValidateId(context, 1); // Role precedes path parsing.
        if (string.IsNullOrEmpty(text) || text.Length > 19 || text.Any(c => c is < '0' or > '9')
            || !long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out var id))
            throw new ClientOwnerTransferException(400, "INVALID_TRANSFER_REQUEST");
        AuthorizeAndValidateId(context, id);
        return id;
    }

    private async Task<ClientOwnerTransferPreview> PreviewAsync(ManagementContext context, PathScope scope, long id,
        CancellationToken cancellationToken) => Preview(context, scope, id, await LoadAsync(context, scope, id, cancellationToken).ConfigureAwait(false));

    internal async Task<Snapshot> LoadAsync(ManagementContext context, PathScope scope, long id, CancellationToken cancellationToken)
    {
        List<ClientRow> clients = [];
        List<CredentialRow> credentials = [];
        List<IdentityRow> identities = [];
        List<PeerRow> peers = [];
        var connection = db.Database.GetDbConnection();
        var openedHere = connection.State == ConnectionState.Closed;
        if (openedHere) await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = SnapshotCommandText();
            command.Transaction = db.Database.CurrentTransaction?.GetDbTransaction();
            foreach (var pair in new (string Name, object Value)[] { ("@tenant", context.TenantId), ("@id", id), ("@scope", scope.WireName()) })
            {
                var parameter = command.CreateParameter();
                parameter.ParameterName = pair.Name;
                parameter.Value = pair.Value;
                command.Parameters.Add(parameter);
            }
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var rowId = reader.GetInt64(1);
                var tenant = reader.GetString(2);
                string? TextAt(int ordinal) => reader.IsDBNull(ordinal) ? null : reader.GetString(ordinal);
                switch (reader.GetString(0))
                {
                    case "client": clients.Add(new ClientRow(rowId, tenant, TextAt(3), TextAt(4), reader.GetBoolean(5))); break;
                    case "credential": credentials.Add(new CredentialRow(rowId, tenant, TextAt(4), reader.GetBoolean(5))); break;
                    case "identity": identities.Add(new IdentityRow(rowId, tenant, reader.GetInt64(6), reader.GetInt64(7))); break;
                    case "peer": peers.Add(new PeerRow(rowId, tenant, reader.GetInt64(7), TextAt(3), TextAt(4), reader.GetBoolean(5))); break;
                    default: throw new InvalidOperationException("Unknown ownership snapshot row type");
                }
            }
        }
        finally
        {
            if (openedHere) await connection.CloseAsync().ConfigureAwait(false);
        }
        return new Snapshot(clients, credentials, identities, peers);
    }

    internal string SnapshotCommandText()
    {
        var sql = db.GetService<ISqlGenerationHelper>();
        string Key<T>()
        {
            var entity = db.Model.FindEntityType(typeof(T))!;
            var table = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
            return sql.DelimitIdentifier(entity.FindProperty("Id")!.GetColumnName(table)!);
        }
        // EF's .NET schema uses a quoted PascalCase primary key on PostgreSQL, unlike Java's
        // lowercase id. Resolve identifiers from the actual provider model; values stay bound.
        return SnapshotSql.Replace("__client_key__", Key<ClientAccount>(), StringComparison.Ordinal)
            .Replace("__credential_key__", Key<ClientCredential>(), StringComparison.Ordinal)
            .Replace("__identity_key__", Key<ClientIdentity>(), StringComparison.Ordinal)
            .Replace("__peer_key__", Key<PeerMeshDevice>(), StringComparison.Ordinal);
    }

    // One statement = one snapshot even on PostgreSQL READ COMMITTED. Do not tenant-filter
    // identity edges before validation or page the group; both can hide corrupt members.
    internal const string SnapshotSql = """
        WITH path_client AS (
            SELECT __client_key__ AS selected_id FROM specus_client_account
            WHERE __client_key__ = @id AND tenant_id = @tenant AND @scope = 'single'
        ), selected_credentials AS (
            SELECT __credential_key__ AS selected_id FROM specus_client_credential
            WHERE __credential_key__ = @id AND tenant_id = @tenant AND @scope = 'credential-group'
            UNION
            SELECT i.credential_id FROM specus_client_identity i
            WHERE i.client_id IN (SELECT selected_id FROM path_client)
        ), affected_clients AS (
            SELECT selected_id FROM path_client
            UNION
            SELECT i.client_id FROM specus_client_identity i
            WHERE i.credential_id IN (SELECT selected_id FROM selected_credentials)
        )
        SELECT 'client' AS kind, c.__client_key__ AS row_id, c.tenant_id, c.client_name,
               c.owner_username, c.enabled,
               CAST(NULL AS DECIMAL(19,0)) AS credential_id, CAST(NULL AS DECIMAL(19,0)) AS client_id
        FROM specus_client_account c WHERE c.__client_key__ IN (SELECT selected_id FROM affected_clients)
        UNION ALL
        SELECT 'credential', c.__credential_key__, c.tenant_id, NULL, c.owner_username, c.enabled, NULL, NULL
        FROM specus_client_credential c WHERE c.__credential_key__ IN (SELECT selected_id FROM selected_credentials)
        UNION ALL
        SELECT 'identity', i.__identity_key__, i.tenant_id, NULL, NULL, NULL, i.credential_id, i.client_id
        FROM specus_client_identity i
        WHERE i.credential_id IN (SELECT selected_id FROM selected_credentials)
           OR i.client_id IN (SELECT selected_id FROM affected_clients)
        UNION ALL
        SELECT 'peer', p.__peer_key__, p.tenant_id, p.client_name, p.owner_username, p.enabled, NULL, p.client_id
        FROM peer_mesh_device p
        WHERE p.tenant_id = @tenant AND p.client_id IN (SELECT selected_id FROM affected_clients)
        """;
}
