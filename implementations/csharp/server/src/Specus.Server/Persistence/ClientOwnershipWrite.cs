using System.Data;
using System.Data.Common;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;

using Specus.Server.Data;

namespace Specus.Server.Persistence;

// Shared database boundary for ownership transfer and signed client startup. This is not a
// process mutex. After management actor locks: credentials -> clients -> identities/devices.
internal static class ClientOwnershipWrite
{
    internal static bool IsNative(SpecusDbContext db) => db.Database.ProviderName switch
    {
        "Microsoft.EntityFrameworkCore.Sqlite" => false,
        "MySql.EntityFrameworkCore" or "Npgsql.EntityFrameworkCore.PostgreSQL" => true,
        _ => throw new NotSupportedException("unsupported ownership transaction provider"),
    };

    internal static Task<IDbContextTransaction> BeginAsync(SpecusDbContext db, CancellationToken ct)
    {
        if (db.Database.CurrentTransaction is not null)
            throw new InvalidOperationException("ownership operation requires its own transaction");
        // SQLite's Serializable transaction reserves the writer before a read snapshot.
        // Native READ COMMITTED sees writes committed while an explicit row lock was waiting.
        return db.Database.BeginTransactionAsync(IsNative(db) ? IsolationLevel.ReadCommitted : IsolationLevel.Serializable, ct);
    }

    internal static async Task LockAsync<T>(SpecusDbContext db, object id, string tenant, CancellationToken ct, string property = "Id")
    {
        var (table, key) = Identifiers<T>(db, property);
        await using var command = Command(db, $"SELECT {key} FROM {table} WHERE {key}=@id AND tenant_id=@tenant" + (IsNative(db) ? " FOR UPDATE" : ""),
            ("@id", id), ("@tenant", tenant));
        _ = await command.ExecuteScalarAsync(ct).ConfigureAwait(false);
    }

    internal static (string Table, string Key) Identifiers<T>(SpecusDbContext db, string property)
    {
        var entity = db.Model.FindEntityType(typeof(T)) ?? throw new InvalidOperationException("unmapped ownership entity");
        var store = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        var sql = db.GetService<ISqlGenerationHelper>();
        return (sql.DelimitIdentifier(store.Name, store.Schema), sql.DelimitIdentifier(entity.FindProperty(property)!.GetColumnName(store)!));
    }

    internal static DbCommand Command(SpecusDbContext db, string text, params (string Name, object? Value)[] parameters)
    {
        var command = db.Database.GetDbConnection().CreateCommand();
        command.Transaction = (db.Database.CurrentTransaction ?? throw new InvalidOperationException("ownership transaction required")).GetDbTransaction();
        command.CommandText = text;
        foreach (var (name, value) in parameters)
        {
            var parameter = command.CreateParameter(); parameter.ParameterName = name;
            parameter.Value = value ?? DBNull.Value; command.Parameters.Add(parameter);
        }
        return command;
    }

    // Only application-assigned startup entities call this. Use the actual provider model,
    // including PostgreSQL's quoted Id and ISO value converters; never flush caller tracking.
    internal static async Task InsertAsync<T>(SpecusDbContext db, T value, CancellationToken ct) where T : class
    {
        var entity = db.Model.FindEntityType(typeof(T)) ?? throw new InvalidOperationException("unmapped startup entity");
        var store = StoreObjectIdentifier.Table(entity.GetTableName()!, entity.GetSchema());
        var sql = db.GetService<ISqlGenerationHelper>();
        var properties = entity.GetProperties().ToArray();
        var columns = properties.Select(p => sql.DelimitIdentifier(p.GetColumnName(store)!));
        var names = properties.Select((_, n) => "@p" + n).ToArray();
        var parameters = properties.Select((p, n) =>
        {
            var raw = (p.PropertyInfo ?? throw new InvalidOperationException("shadow startup property unsupported")).GetValue(value);
            var converter = p.GetTypeMapping().Converter;
            return (names[n], converter is null ? raw : converter.ConvertToProvider(raw));
        }).ToArray();
        await using var command = Command(db, $"INSERT INTO {sql.DelimitIdentifier(store.Name, store.Schema)} ({string.Join(',', columns)}) VALUES ({string.Join(',', names)})", parameters);
        if (await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false) != 1)
            throw new InvalidOperationException("startup entity was not inserted");
    }
}
