using System.Data;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.Server.Hosting;

/// <summary>
/// Tenant-scoped management login names (protocol/spec/management-accounts.md section 3), the
/// counterpart of Java's <c>ManagementUserSchemaMigrator</c>. The AddManagementLoginNames migration
/// adds the columns, backfills them in SQL and creates the unique index; these startup steps make the
/// result independent of the database's own <c>LOWER()</c> (SQLite folds ASCII only), stop a duplicate
/// before anything is written, and check that the index is the one the identity model relies on.
/// </summary>
public sealed partial class DatabaseInitializer
{
    internal const string ManagementUserTable = "specus_management_user";
    internal const string ManagementLoginNameIndex = "uq_management_user_tenant_login_name";
    private const string ManagementLoginNamesMigrationSuffix = "_AddManagementLoginNames";
    private static readonly string[] ManagementLoginNameIndexColumns = ["tenant_id", "login_name_normalized"];
    private const string UpdateManagementLoginNameSql =
        "UPDATE specus_management_user SET login_name = {0}, login_name_normalized = {1} WHERE username = {2}";
    internal const string ManagementUserEmailTable = "specus_management_user_email";
    private const string RemoveOrphanedManagementEmailsSql =
        "DELETE FROM specus_management_user_email WHERE username NOT IN (SELECT username FROM specus_management_user)";

    /// <summary>
    /// Runs before EF applies AddManagementLoginNames to an existing database. When two accounts of one
    /// tenant would get the same canonical login name the start is refused before anything is written:
    /// MySQL does not roll DDL back, so letting the migration fail at its unique index would leave the
    /// new columns behind, and the next start could not add them again.
    /// </summary>
    internal static async Task CheckManagementLoginNamesBeforeMigrationAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        // A database that does not exist yet has nothing to check, and must not be opened here:
        // opening a SQLite file creates it, and EF then skips its own creation step (which also
        // switches the file to WAL journaling).
        if (!await db.GetService<IRelationalDatabaseCreator>().ExistsAsync(cancellationToken).ConfigureAwait(false))
        {
            return;
        }
        var pending = await db.Database.GetPendingMigrationsAsync(cancellationToken).ConfigureAwait(false);
        if (!pending.Any(id => id.EndsWith(ManagementLoginNamesMigrationSuffix, StringComparison.Ordinal))
            || !await TableExistsAsync(db, ManagementUserTable, cancellationToken).ConfigureAwait(false))
        {
            return;
        }
        var hasLoginNames = await ColumnExistsAsync(db, ManagementUserTable, "login_name", cancellationToken)
            .ConfigureAwait(false);
        var rows = await ReadManagementLoginNameRowsAsync(db, hasLoginNames, cancellationToken)
            .ConfigureAwait(false);
        _ = ResolveManagementLoginNames(rows);
    }

    /// <summary>
    /// Idempotent, runs on every start after the migrations: adds the columns if a database lacks them,
    /// gives every row its login name (the stored one, else the account key) and the canonical form of
    /// it, refusing to start on a duplicate within a tenant before writing anything, then ensures and
    /// verifies <c>uq_management_user_tenant_login_name</c>. Last, it deletes the email records whose
    /// account key no account has any more: accounts deleted before the delete took their email along
    /// left them behind, and the address could never register again.
    /// </summary>
    internal static async Task EnsureManagementLoginNamesAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        if (!await TableExistsAsync(db, ManagementUserTable, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException($"table {ManagementUserTable} does not exist");
        }
        await EnsureColumnAsync(db, ManagementUserTable, "login_name", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, ManagementUserTable, "login_name_normalized", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);

        var rows = await ReadManagementLoginNameRowsAsync(db, withLoginNames: true, cancellationToken)
            .ConfigureAwait(false);
        var stale = ResolveManagementLoginNames(rows)
            .Where(row => !string.Equals(row.Stored.LoginName, row.LoginName, StringComparison.Ordinal)
                || !string.Equals(row.Stored.LoginNameNormalized, row.LoginNameNormalized, StringComparison.Ordinal))
            .ToList();
        if (stale.Count > 0)
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken)
                .ConfigureAwait(false);
            foreach (var row in stale)
            {
                await db.Database.ExecuteSqlRawAsync(UpdateManagementLoginNameSql,
                        [row.LoginName, row.LoginNameNormalized, row.Stored.AccountKey], cancellationToken)
                    .ConfigureAwait(false);
            }
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }

        await EnsureUniqueIndexAsync(db, ManagementLoginNameIndex, ManagementUserTable,
            string.Join(", ", ManagementLoginNameIndexColumns), cancellationToken).ConfigureAwait(false);
        if (!await IsManagementLoginNameIndexValidAsync(db, cancellationToken).ConfigureAwait(false))
        {
            throw new InvalidOperationException(
                $"index {ManagementLoginNameIndex} must be unique on (tenant_id, login_name_normalized)");
        }
        if (await TableExistsAsync(db, ManagementUserEmailTable, cancellationToken).ConfigureAwait(false))
        {
            await db.Database.ExecuteSqlRawAsync(RemoveOrphanedManagementEmailsSql, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The login name each row must carry, checked in full before the caller writes anything: a blank
    /// or over-long name, or one canonical name twice within a tenant, refuses the start.
    /// </summary>
    private static List<ResolvedManagementLoginName> ResolveManagementLoginNames(
        IReadOnlyList<StoredManagementLoginName> rows)
    {
        var resolved = new List<ResolvedManagementLoginName>(rows.Count);
        var tenantNames = new HashSet<string>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var loginName = string.IsNullOrWhiteSpace(row.LoginName) ? row.AccountKey : row.LoginName.Trim();
            if (string.IsNullOrWhiteSpace(loginName) || loginName.Length > 80)
            {
                throw new InvalidOperationException("management user has an invalid login name");
            }
            var tenantId = ManagementContext.NormalizeTenant(row.TenantId);
            var normalized = ManagementUser.NormalizeLoginName(loginName);
            if (!tenantNames.Add(tenantId + '\0' + normalized))
            {
                throw new InvalidOperationException(
                    $"duplicate management login name in tenant '{tenantId}'");
            }
            resolved.Add(new ResolvedManagementLoginName(row, loginName, normalized));
        }
        return resolved;
    }

    private static async Task<List<StoredManagementLoginName>> ReadManagementLoginNameRowsAsync(
        SpecusDbContext db, bool withLoginNames, CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var command = connection.CreateCommand();
        command.CommandText = withLoginNames
            ? $"SELECT username, tenant_id, login_name, login_name_normalized FROM {ManagementUserTable}"
            : $"SELECT username, tenant_id FROM {ManagementUserTable}";
        var rows = new List<StoredManagementLoginName>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            rows.Add(new StoredManagementLoginName(
                reader.GetString(0),
                reader.IsDBNull(1) ? null : reader.GetString(1),
                withLoginNames && !reader.IsDBNull(2) ? reader.GetString(2) : null,
                withLoginNames && !reader.IsDBNull(3) ? reader.GetString(3) : null));
        }
        return rows;
    }

    /// <summary>
    /// Reads the index back: it must be unique and cover exactly (tenant_id, login_name_normalized),
    /// in that order. An index of that name with another definition is refused rather than trusted.
    /// </summary>
    private static async Task<bool> IsManagementLoginNameIndexValidAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }

        bool unique;
        var columns = new List<string>();
        await using var command = connection.CreateCommand();
        switch (DatabaseDialect(db.Database.ProviderName))
        {
            case "sqlite":
            {
                command.CommandText = $"PRAGMA index_list({ManagementUserTable})";
                bool? listed = null;
                await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        if (string.Equals(reader.GetString(1), ManagementLoginNameIndex, StringComparison.Ordinal))
                        {
                            listed = Convert.ToInt64(reader.GetValue(2)) == 1;
                        }
                    }
                }
                if (listed is null)
                {
                    return false;
                }
                unique = listed.Value;
                await using var info = connection.CreateCommand();
                info.CommandText = $"PRAGMA index_info({ManagementLoginNameIndex})";
                var ordered = new SortedList<long, string>();
                await using (var reader = await info.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        ordered.Add(Convert.ToInt64(reader.GetValue(0)),
                            reader.IsDBNull(2) ? string.Empty : reader.GetString(2));
                    }
                }
                columns.AddRange(ordered.Values);
                break;
            }
            case "postgresql":
            {
                command.CommandText = """
                    SELECT indexdef FROM pg_indexes
                    WHERE schemaname = current_schema() AND tablename = @table AND indexname = @index
                    """;
                AddParameter(command, "@table", ManagementUserTable);
                AddParameter(command, "@index", ManagementLoginNameIndex);
                var definition = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false) as string;
                // e.g. CREATE UNIQUE INDEX uq_... ON public.specus_management_user USING btree (tenant_id, login_name_normalized)
                var match = definition is null ? null : PostgresUniqueIndexDefinition().Match(definition);
                if (match is not { Success: true })
                {
                    return false;
                }
                unique = true;
                columns.AddRange(match.Groups[1].Value.Split(',')
                    .Select(column => column.Trim().Trim('"')));
                break;
            }
            case "mysql":
            {
                command.CommandText = """
                    SELECT non_unique, column_name FROM information_schema.statistics
                    WHERE table_schema = DATABASE() AND table_name = @table AND index_name = @index
                    ORDER BY seq_in_index
                    """;
                AddParameter(command, "@table", ManagementUserTable);
                AddParameter(command, "@index", ManagementLoginNameIndex);
                unique = true;
                await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        unique &= Convert.ToInt64(reader.GetValue(0)) == 0;
                        // A functional key part has no column name; some servers report the
                        // dictionary's names as binary strings.
                        columns.Add(reader.IsDBNull(1)
                            ? string.Empty
                            : reader.GetValue(1) is byte[] bytes
                                ? System.Text.Encoding.UTF8.GetString(bytes)
                                : Convert.ToString(reader.GetValue(1)) ?? string.Empty);
                    }
                }
                break;
            }
            default:
                // An unknown provider has no metadata query here; the migration created the index.
                return true;
        }
        return unique && columns.SequenceEqual(ManagementLoginNameIndexColumns, StringComparer.OrdinalIgnoreCase);
    }

    private static void AddParameter(System.Data.Common.DbCommand command, string name, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }

    [GeneratedRegex(@"^CREATE UNIQUE INDEX \S+ ON \S+ USING \w+ \(([^()]*)\)$", RegexOptions.CultureInvariant)]
    private static partial Regex PostgresUniqueIndexDefinition();

    private sealed record StoredManagementLoginName(string AccountKey, string? TenantId, string? LoginName,
        string? LoginNameNormalized);

    private sealed record ResolvedManagementLoginName(StoredManagementLoginName Stored, string LoginName,
        string LoginNameNormalized);
}
