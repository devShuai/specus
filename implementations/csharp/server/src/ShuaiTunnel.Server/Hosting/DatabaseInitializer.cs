using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Data;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Management;

namespace ShuaiTunnel.Server.Hosting;

/// <summary>
/// Database bootstrapper for both process startup and the management UI's idempotent
/// "initialize database" action. It mirrors Java's <c>DatabaseInitializer</c> while using
/// EF Core migrations as the schema authority.
/// </summary>
public sealed class DatabaseInitializer
{
    public const string DemoClientName = "Demo client";
    public const string DemoCredentialApiKey = "demo-client";
    public const string DemoCredentialSecret = "test1234";

    private readonly IServiceProvider _services;
    private readonly IOptions<DatabaseOptions> _options;
    private readonly IOptions<ClientAuthOptions> _clientAuth;
    private readonly ILogger<DatabaseInitializer> _logger;

    public DatabaseInitializer(IServiceProvider services, IOptions<DatabaseOptions> options,
        IOptions<ClientAuthOptions> clientAuth,
        ILogger<DatabaseInitializer> logger)
    {
        _services = services;
        _options = options;
        _clientAuth = clientAuth;
        _logger = logger;
    }

    public async Task<DatabaseInitializeResult> InitializeAsync(CancellationToken cancellationToken,
        string? tenantId = null, string? ownerUsername = null)
    {
        var normalizedTenant = ManagementContext.NormalizeTenant(tenantId);
        var normalizedOwner = string.IsNullOrWhiteSpace(ownerUsername) ? "admin" : ownerUsername.Trim();
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
        await EnsureManagementUserTableAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureClientDownloadLinkTableAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureMappingCompatibilityColumnsAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureTrafficDetailTablesAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsurePeerMeshTablesAsync(db, cancellationToken).ConfigureAwait(false);

        if (_options.Value.SeedDemoClient)
        {
            await SeedDemoClientAsync(db, normalizedTenant, normalizedOwner, cancellationToken).ConfigureAwait(false);
        }

        var clients = await db.ClientAccounts
            .LongCountAsync(c => c.TenantId == normalizedTenant, cancellationToken)
            .ConfigureAwait(false);
        return new DatabaseInitializeResult(
            Initialized: true,
            TenantId: normalizedTenant,
            Orm: "entity-framework-core",
            Dialect: DatabaseDialect(db.Database.ProviderName),
            Clients: clients);
    }

    private async Task SeedDemoClientAsync(TunnelDbContext db, string tenantId, string ownerUsername,
        CancellationToken cancellationToken)
    {
        var accountExists = await db.ClientAccounts
            .AsNoTracking()
            .AnyAsync(a => a.ClientName == DemoClientName, cancellationToken)
            .ConfigureAwait(false);
        var now = DateTimeOffset.UtcNow;
        if (!accountExists)
        {
            db.ClientAccounts.Add(new ClientAccount
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = tenantId,
                OwnerUsername = ownerUsername,
                ClientName = DemoClientName,
                PasswordHash = PasswordHasher.Hash(DemoCredentialSecret),
                Enabled = true,
                ConnectionRateLimitPerMinute = 30,
                CreatedAt = now,
                UpdatedAt = now,
            });
        }
        if (!await db.ClientCredentials.AsNoTracking()
                .AnyAsync(c => c.ApiKey == DemoCredentialApiKey, cancellationToken)
                .ConfigureAwait(false))
        {
            db.ClientCredentials.Add(new ClientCredential
            {
                Id = ClientIdGenerator.NewId(),
                TenantId = tenantId,
                OwnerUsername = ownerUsername,
                ApiKey = DemoCredentialApiKey,
                SecretHash = PasswordHasher.Hash(DemoCredentialSecret),
                Enabled = true,
                MaxOnlineInstances = NormalizeDefaultMaxOnlineInstances(
                    _clientAuth.Value.DefaultMaxOnlineInstances),
                CreatedAt = now,
                UpdatedAt = now,
            });
        }
        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        if (!accountExists)
        {
            _logger.LogInformation("seeded {ClientName}", DemoClientName);
        }
    }

    private static int NormalizeDefaultMaxOnlineInstances(int value) => value is < 1 or > 10_000 ? 2 : value;

    private static Task EnsureManagementUserTableAsync(TunnelDbContext db, CancellationToken cancellationToken) =>
        db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS tunnel_management_user (
              username VARCHAR(80) PRIMARY KEY,
              tenant_id VARCHAR(80) NOT NULL,
              password_hash VARCHAR(64) NOT NULL,
              role VARCHAR(20) NOT NULL,
              enabled INTEGER NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken);

    private static async Task EnsureClientDownloadLinkTableAsync(TunnelDbContext db,
        CancellationToken cancellationToken)
    {
        var dialect = DatabaseDialect(db.Database.ProviderName);
        var idType = dialect switch
        {
            "mysql" => "BIGINT NOT NULL PRIMARY KEY",
            "postgresql" => "BIGINT PRIMARY KEY",
            _ => "INTEGER PRIMARY KEY",
        };
        var boolType = BooleanColumnType(db.Database.ProviderName).Replace(" DEFAULT 0", " DEFAULT 1");

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS client_download_link (
              id {idType},
              implementation VARCHAR(32) NOT NULL,
              platform VARCHAR(32) NOT NULL,
              arch VARCHAR(32) NOT NULL,
              display_name VARCHAR(120) NOT NULL,
              download_url VARCHAR(1024) NOT NULL,
              description VARCHAR(512),
              display_order INTEGER NOT NULL DEFAULT 0,
              enabled {boolType},
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_client_download_impl", "client_download_link",
            "implementation", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_client_download_order", "client_download_link",
            "display_order", cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureMappingCompatibilityColumnsAsync(TunnelDbContext db,
        CancellationToken cancellationToken)
    {
        var boolType = BooleanColumnType(db.Database.ProviderName);
        await EnsureColumnAsync(db, "tunnel_mapping", "detail_capture_enabled", boolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "detail_capture_enabled", boolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "path_rewrite_enabled", boolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "tunnel_connection_record", "tenant_id", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tunnel_connection_tenant", "tunnel_connection_record",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "tunnel_connection_stat", "tenant_id", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await BackfillConnectionStatTenantAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tunnel_connection_stat_tenant", "tunnel_connection_stat",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "tunnel_traffic_usage", "tenant_id", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tunnel_traffic_tenant", "tunnel_traffic_usage",
            "tenant_id", cancellationToken).ConfigureAwait(false);
    }

    private static Task BackfillConnectionStatTenantAsync(TunnelDbContext db, CancellationToken cancellationToken) =>
        db.Database.ExecuteSqlRawAsync("""
            UPDATE tunnel_connection_stat
            SET tenant_id = COALESCE(
                (SELECT c.tenant_id FROM tunnel_client_account c WHERE c.id = tunnel_connection_stat.client_id LIMIT 1),
                (SELECT c.tenant_id FROM tunnel_client_account c
                    WHERE tunnel_connection_stat.client_id IS NULL
                      AND c.client_name = tunnel_connection_stat.client_name LIMIT 1),
                tenant_id,
                'default')
            WHERE tenant_id IS NULL OR tenant_id = '' OR tenant_id = 'default'
            """, cancellationToken);

    private static async Task EnsureTrafficDetailTablesAsync(TunnelDbContext db,
        CancellationToken cancellationToken)
    {
        var dialect = DatabaseDialect(db.Database.ProviderName);
        var idType = dialect switch
        {
            "mysql" => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "postgresql" => "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
            _ => "INTEGER PRIMARY KEY AUTOINCREMENT",
        };
        var boolType = BooleanColumnType(db.Database.ProviderName).Replace(" DEFAULT 0", string.Empty);
        var payloadType = dialect switch
        {
            "mysql" => "LONGBLOB NOT NULL",
            "postgresql" => "BYTEA NOT NULL",
            _ => "BLOB NOT NULL",
        };
        var textType = dialect == "mysql" ? "LONGTEXT" : "TEXT";

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS tunnel_resource_traffic_usage (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              client_id BIGINT NOT NULL,
              client_name VARCHAR(120) NOT NULL,
              resource_type VARCHAR(32) NOT NULL,
              resource_key VARCHAR(128) NOT NULL,
              resource_id BIGINT,
              resource_name VARCHAR(255) NOT NULL,
              usage_date VARCHAR(10) NOT NULL,
              upload_bytes BIGINT NOT NULL,
              download_bytes BIGINT NOT NULL,
              updated_at VARCHAR(40) NOT NULL,
              CONSTRAINT uk_resource_traffic_resource_date
                UNIQUE (tenant_id, client_id, resource_type, resource_key, usage_date)
            )
            """, cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_resource_traffic_tenant", "tunnel_resource_traffic_usage",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_resource_traffic_client", "tunnel_resource_traffic_usage",
            "client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_resource_traffic_type", "tunnel_resource_traffic_usage",
            "resource_type", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_resource_traffic_date", "tunnel_resource_traffic_usage",
            "usage_date", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS tunnel_http_traffic_exchange (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              client_id BIGINT NOT NULL,
              client_name VARCHAR(120) NOT NULL,
              route VARCHAR(128) NOT NULL,
              resource_id BIGINT,
              resource_name VARCHAR(255),
              method VARCHAR(16),
              relative_path VARCHAR(1024),
              raw_query VARCHAR(2048),
              status_code INTEGER NOT NULL,
              success {boolType},
              error VARCHAR(2048),
              remote_address VARCHAR(255),
              request_bytes BIGINT NOT NULL,
              response_bytes BIGINT NOT NULL,
              elapsed_ms BIGINT NOT NULL,
              request_content_type VARCHAR(255),
              response_content_type VARCHAR(255),
              response_body_type VARCHAR(32),
              request_headers VARCHAR(8192),
              response_headers VARCHAR(8192),
              request_preview_hex VARCHAR(4096),
              request_preview_text {textType},
              response_preview_hex VARCHAR(4096),
              response_preview_text {textType},
              request_truncated {boolType},
              response_truncated {boolType},
              captured_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS tunnel_tcp_traffic_frame (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              client_id BIGINT NOT NULL,
              client_name VARCHAR(120) NOT NULL,
              listen_port INTEGER NOT NULL,
              resource_id BIGINT,
              resource_name VARCHAR(255),
              channel_id VARCHAR(120) NOT NULL,
              frame_direction VARCHAR(32) NOT NULL,
              remote_address VARCHAR(255),
              source_address VARCHAR(255),
              source_port INTEGER,
              destination_address VARCHAR(255),
              destination_port INTEGER,
              stream_offset BIGINT NOT NULL,
              stream_end_offset BIGINT NOT NULL,
              frame_index BIGINT NOT NULL,
              payload_bytes BIGINT NOT NULL,
              payload_data {payloadType},
              payload_preview_hex VARCHAR(4096),
              payload_preview_text VARCHAR(4096),
              truncated {boolType},
              frame_time VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_http_traffic_tenant", "tunnel_http_traffic_exchange",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_client", "tunnel_http_traffic_exchange",
            "client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_route", "tunnel_http_traffic_exchange",
            "route", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_body_type", "tunnel_http_traffic_exchange",
            "response_body_type", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_captured_at", "tunnel_http_traffic_exchange",
            "captured_at", cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_tcp_traffic_tenant", "tunnel_tcp_traffic_frame",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_client", "tunnel_tcp_traffic_frame",
            "client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_listen_port", "tunnel_tcp_traffic_frame",
            "listen_port", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_channel", "tunnel_tcp_traffic_frame",
            "channel_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_stream", "tunnel_tcp_traffic_frame",
            "tenant_id, channel_id, frame_direction, stream_offset", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_frame_time", "tunnel_tcp_traffic_frame",
            "frame_time", cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsurePeerMeshTablesAsync(TunnelDbContext db,
        CancellationToken cancellationToken)
    {
        var dialect = DatabaseDialect(db.Database.ProviderName);
        var boolType = BooleanColumnType(db.Database.ProviderName).Replace(" DEFAULT 0", string.Empty);
        var idType = dialect switch
        {
            "mysql" => "BIGINT NOT NULL PRIMARY KEY",
            "postgresql" => "BIGINT PRIMARY KEY",
            _ => "INTEGER PRIMARY KEY",
        };

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS peer_mesh_device (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              owner_username VARCHAR(80) NOT NULL,
              client_id BIGINT NOT NULL,
              client_name VARCHAR(120) NOT NULL,
              virtual_ip VARCHAR(64) NOT NULL,
              cidr VARCHAR(64) NOT NULL,
              public_key VARCHAR(256),
              nat_type VARCHAR(80),
              last_endpoint VARCHAR(255),
              virtual_device_mode VARCHAR(80),
              virtual_device_name VARCHAR(80),
              virtual_device_status VARCHAR(80),
              virtual_device_error VARCHAR(512),
              virtual_device_updated_at VARCHAR(40),
              enabled {boolType},
              last_seen_at VARCHAR(40),
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL,
              CONSTRAINT uk_peer_mesh_device_client UNIQUE (tenant_id, client_id),
              CONSTRAINT uk_peer_mesh_device_ip UNIQUE (tenant_id, virtual_ip)
            )
            """, cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS peer_mesh_acl (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              owner_username VARCHAR(80) NOT NULL,
              source_client_id BIGINT NOT NULL,
              source_client_name VARCHAR(120) NOT NULL,
              target_client_id BIGINT NOT NULL,
              target_client_name VARCHAR(120) NOT NULL,
              allowed {boolType},
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL,
              CONSTRAINT uk_peer_mesh_acl_pair UNIQUE (tenant_id, source_client_id, target_client_id)
            )
            """, cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS peer_mesh_session (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              source_client_id BIGINT NOT NULL,
              source_client_name VARCHAR(120) NOT NULL,
              target_client_id BIGINT NOT NULL,
              target_client_name VARCHAR(120) NOT NULL,
              path_type VARCHAR(40) NOT NULL,
              status VARCHAR(40) NOT NULL,
              token_hash VARCHAR(64),
              started_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL,
              expires_at VARCHAR(40) NOT NULL,
              closed_at VARCHAR(40),
              rtt_millis BIGINT,
              local_endpoint VARCHAR(255),
              remote_endpoint VARCHAR(255),
              direct_bytes BIGINT NOT NULL DEFAULT 0,
              relay_bytes BIGINT NOT NULL DEFAULT 0,
              last_traffic_at VARCHAR(40)
            )
            """, cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_peer_mesh_device_owner", "peer_mesh_device",
            "tenant_id, owner_username", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_device_client_name", "peer_mesh_device",
            "client_name", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_acl_source", "peer_mesh_acl",
            "tenant_id, source_client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_acl_target", "peer_mesh_acl",
            "tenant_id, target_client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_session_tenant", "peer_mesh_session",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_session_source", "peer_mesh_session",
            "tenant_id, source_client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_session_target", "peer_mesh_session",
            "tenant_id, target_client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_peer_mesh_session_status", "peer_mesh_session",
            "status", cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureIndexAsync(TunnelDbContext db, string indexName, string table,
        string columns, CancellationToken cancellationToken)
    {
        if (await IndexExistsAsync(db, table, indexName, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        await ExecuteSchemaSqlAsync(db,
                $"CREATE INDEX {indexName} ON {table} ({columns})", cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task EnsureColumnAsync(TunnelDbContext db, string table, string column,
        string definition, CancellationToken cancellationToken)
    {
        if (await ColumnExistsAsync(db, table, column, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        await ExecuteSchemaSqlAsync(db,
                $"ALTER TABLE {table} ADD COLUMN {column} {definition}", cancellationToken)
            .ConfigureAwait(false);
    }

    private static Task ExecuteSchemaSqlAsync(TunnelDbContext db, string sql, CancellationToken cancellationToken)
    {
        return db.Database.ExecuteSqlRawAsync(sql, cancellationToken);
    }

    private static async Task<bool> ColumnExistsAsync(TunnelDbContext db, string table, string column,
        CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var command = connection.CreateCommand();
        if (DatabaseDialect(db.Database.ProviderName) == "sqlite")
        {
            command.CommandText = $"PRAGMA table_info({table})";
            await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                if (string.Equals(reader.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }
            return false;
        }

        command.CommandText = """
            SELECT COUNT(*) FROM information_schema.columns
            WHERE table_name = @table AND column_name = @column
            """;
        var tableParameter = command.CreateParameter();
        tableParameter.ParameterName = "@table";
        tableParameter.Value = table;
        command.Parameters.Add(tableParameter);
        var columnParameter = command.CreateParameter();
        columnParameter.ParameterName = "@column";
        columnParameter.Value = column;
        command.Parameters.Add(columnParameter);
        var count = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt64(count) > 0;
    }

    private static async Task<bool> IndexExistsAsync(TunnelDbContext db, string table, string indexName,
        CancellationToken cancellationToken)
    {
        var connection = db.Database.GetDbConnection();
        if (connection.State != ConnectionState.Open)
        {
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        }

        await using var command = connection.CreateCommand();
        switch (DatabaseDialect(db.Database.ProviderName))
        {
            case "sqlite":
                command.CommandText = $"PRAGMA index_list({table})";
                await using (var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
                {
                    while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
                    {
                        if (string.Equals(reader.GetString(1), indexName, StringComparison.OrdinalIgnoreCase))
                        {
                            return true;
                        }
                    }
                    return false;
                }
            case "postgresql":
                command.CommandText = "SELECT COUNT(*) FROM pg_indexes WHERE tablename = @table AND indexname = @index";
                break;
            case "mysql":
                command.CommandText = """
                    SELECT COUNT(*) FROM information_schema.statistics
                    WHERE table_schema = DATABASE() AND table_name = @table AND index_name = @index
                    """;
                break;
            default:
                return false;
        }

        var tableParameter = command.CreateParameter();
        tableParameter.ParameterName = "@table";
        tableParameter.Value = table;
        command.Parameters.Add(tableParameter);

        var indexParameter = command.CreateParameter();
        indexParameter.ParameterName = "@index";
        indexParameter.Value = indexName;
        command.Parameters.Add(indexParameter);

        var count = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        return Convert.ToInt64(count) > 0;
    }

    private static string BooleanColumnType(string? providerName)
    {
        return DatabaseDialect(providerName) switch
        {
            "mysql" => "TINYINT(1) NOT NULL DEFAULT 0",
            "postgresql" => "SMALLINT NOT NULL DEFAULT 0",
            _ => "INTEGER NOT NULL DEFAULT 0",
        };
    }

    private static string DatabaseDialect(string? providerName)
    {
        if (providerName is null)
        {
            return "unknown";
        }

        if (providerName.Contains("Sqlite", StringComparison.OrdinalIgnoreCase))
        {
            return "sqlite";
        }

        if (providerName.Contains("Npgsql", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("PostgreSQL", StringComparison.OrdinalIgnoreCase))
        {
            return "postgresql";
        }

        if (providerName.Contains("MySql", StringComparison.OrdinalIgnoreCase)
            || providerName.Contains("MySQL", StringComparison.OrdinalIgnoreCase))
        {
            return "mysql";
        }

        return providerName;
    }
}

public sealed record DatabaseInitializeResult(bool Initialized, string TenantId, string Orm, string Dialect, long Clients);
