using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Data;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.Server.Hosting;

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
    private readonly IOptions<SpecusOptions> _specus;
    private readonly ILogger<DatabaseInitializer> _logger;

    public DatabaseInitializer(IServiceProvider services, IOptions<DatabaseOptions> options,
        IOptions<ClientAuthOptions> clientAuth,
        IOptions<SpecusOptions> specus,
        ILogger<DatabaseInitializer> logger)
    {
        _services = services;
        _options = options;
        _clientAuth = clientAuth;
        _specus = specus;
        _logger = logger;
    }

    /// <summary>Demo data is convenience-only; prod never seeds it regardless of the requested flag.</summary>
    private bool SeedDemoDataEnabled =>
        _options.Value.SeedDemoClient
        && DeploymentEnvironments.Parse(_specus.Value.Env).AllowsDemoData();

    public async Task<DatabaseInitializeResult> InitializeAsync(CancellationToken cancellationToken,
        string? tenantId = null, string? ownerUsername = null)
    {
        var normalizedTenant = ManagementContext.NormalizeTenant(tenantId);
        var normalizedOwner = string.IsNullOrWhiteSpace(ownerUsername) ? "admin" : ownerUsername.Trim();
        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        await db.Database.MigrateAsync(cancellationToken).ConfigureAwait(false);
        await EnsureManagementUserTableAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureManagementRegistrationTablesAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureClientDownloadLinkTableAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureClientMessageCapabilityColumnsAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureTransferAttachmentTableAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureDiagramAndTransferRoomTablesAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureTransferRoomCredentialColumnsAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureMappingCompatibilityColumnsAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureHttpMediaTablesAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureTrafficDetailTablesAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsurePeerMeshTablesAsync(db, cancellationToken).ConfigureAwait(false);

        var environment = DeploymentEnvironments.Parse(_specus.Value.Env);
        var cleanup = await DisableLegacyDemoCredentialsAsync(db, environment, cancellationToken)
            .ConfigureAwait(false);
        if (cleanup.ClientAccounts > 0 || cleanup.ClientCredentials > 0)
        {
            _logger.LogWarning(
                "[security-baseline] disabled legacy demo credentials: accounts={Accounts}, credentials={Credentials}",
                cleanup.ClientAccounts, cleanup.ClientCredentials);
        }

        if (SeedDemoDataEnabled)
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

    private async Task SeedDemoClientAsync(SpecusDbContext db, string tenantId, string ownerUsername,
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
                PasswordHash = PasswordHasher.HashToken(DemoCredentialSecret),
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
                SecretHash = PasswordHasher.HashToken(DemoCredentialSecret),
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

    /// <summary>
    /// Disables only the credentials shipped by older releases. Both the public identifier and
    /// the original secret digest must still match, so operator-rotated and unrelated rows remain
    /// untouched. The two updates share one transaction; any database failure aborts startup and
    /// rolls back both changes.
    /// </summary>
    internal static async Task<LegacyDemoCredentialCleanupResult> DisableLegacyDemoCredentialsAsync(
        SpecusDbContext db,
        DeploymentEnvironment environment,
        CancellationToken cancellationToken)
    {
        if (!environment.IsProd())
        {
            return LegacyDemoCredentialCleanupResult.None;
        }

        var legacyHash = PasswordHasher.HashToken(DemoCredentialSecret);
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);

        // Query by all persisted selectors, then retain ordinal checks so a database configured
        // with a case-insensitive collation cannot turn a near-match into a security migration.
        var accountCandidates = await db.ClientAccounts
            .Where(row => row.Enabled
                          && row.ClientName == DemoClientName
                          && row.PasswordHash == legacyHash)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        var credentialCandidates = await db.ClientCredentials
            .Where(row => row.Enabled
                          && row.ApiKey == DemoCredentialApiKey
                          && row.SecretHash == legacyHash)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var now = DateTimeOffset.UtcNow;
        var accounts = 0;
        foreach (var account in accountCandidates)
        {
            if (!string.Equals(account.ClientName, DemoClientName, StringComparison.Ordinal)
                || !string.Equals(account.PasswordHash, legacyHash, StringComparison.Ordinal))
            {
                continue;
            }
            account.Enabled = false;
            account.UpdatedAt = now;
            accounts++;
        }

        var credentials = 0;
        foreach (var credential in credentialCandidates)
        {
            if (!string.Equals(credential.ApiKey, DemoCredentialApiKey, StringComparison.Ordinal)
                || !string.Equals(credential.SecretHash, legacyHash, StringComparison.Ordinal))
            {
                continue;
            }
            credential.Enabled = false;
            credential.UpdatedAt = now;
            credentials++;
        }

        await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        return new LegacyDemoCredentialCleanupResult(accounts, credentials);
    }

    internal readonly record struct LegacyDemoCredentialCleanupResult(
        int ClientAccounts,
        int ClientCredentials)
    {
        internal static LegacyDemoCredentialCleanupResult None => new(0, 0);
    }

    private static Task EnsureManagementUserTableAsync(SpecusDbContext db, CancellationToken cancellationToken) =>
        db.Database.ExecuteSqlRawAsync("""
            CREATE TABLE IF NOT EXISTS specus_management_user (
              username VARCHAR(80) PRIMARY KEY,
              tenant_id VARCHAR(80) NOT NULL,
              password_hash VARCHAR(64) NOT NULL,
              role VARCHAR(20) NOT NULL,
              enabled INTEGER NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken);

    private static async Task EnsureManagementRegistrationTablesAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        await ExecuteSchemaSqlAsync(db, """
            CREATE TABLE IF NOT EXISTS specus_management_user_email (
              username VARCHAR(80) PRIMARY KEY,
              email VARCHAR(254) NOT NULL,
              verified_at VARCHAR(40) NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uq_management_user_email", "specus_management_user_email",
            "email", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_management_user_email_verified", "specus_management_user_email",
            "verified_at", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, """
            CREATE TABLE IF NOT EXISTS specus_management_registration_challenge (
              registration_id VARCHAR(64) PRIMARY KEY,
              username VARCHAR(80) NOT NULL,
              email VARCHAR(254) NOT NULL,
              password_hash VARCHAR(64) NOT NULL,
              code_hash VARCHAR(64) NOT NULL,
              attempts_remaining INTEGER NOT NULL,
              expires_at VARCHAR(40) NOT NULL,
              resend_available_at VARCHAR(40) NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uq_registration_challenge_username",
            "specus_management_registration_challenge", "username", cancellationToken)
            .ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uq_registration_challenge_email",
            "specus_management_registration_challenge", "email", cancellationToken)
            .ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_registration_challenge_expiry",
            "specus_management_registration_challenge", "expires_at", cancellationToken)
            .ConfigureAwait(false);
    }

    internal static async Task EnsureClientDownloadLinkTableAsync(SpecusDbContext db,
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
        var latestType = DatabaseDialect(db.Database.ProviderName) switch
        {
            "postgresql" => "BOOLEAN NOT NULL DEFAULT FALSE",
            "mysql" => "TINYINT(1) NOT NULL DEFAULT 0",
            _ => "INTEGER NOT NULL DEFAULT 0",
        };
        await EnsureColumnAsync(db, "client_download_link", "version", "VARCHAR(32)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "client_download_link", "sha256", "VARCHAR(64)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "client_download_link", "file_size", "BIGINT NOT NULL DEFAULT 0",
            cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "client_download_link", "is_latest", latestType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "client_download_link", "latest_slot", "VARCHAR(104)",
            cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "client_download_link", "changelog_url", "VARCHAR(1024)",
            cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "client_download_link", "min_supported_version", "VARCHAR(32)",
            cancellationToken).ConfigureAwait(false);
        var latestValue = dialect == "postgresql" ? "TRUE" : "1";
        var notLatestValue = dialect == "postgresql" ? "FALSE" : "0";
        await ExecuteSchemaSqlAsync(db, $"""
            UPDATE client_download_link
            SET is_latest = {notLatestValue}, latest_slot = NULL
            WHERE is_latest = {latestValue} AND enabled = {notLatestValue}
            """, cancellationToken).ConfigureAwait(false);
        await ExecuteSchemaSqlAsync(db, $"""
            UPDATE client_download_link
            SET is_latest = {notLatestValue}, latest_slot = NULL
            WHERE is_latest = {latestValue}
              AND id NOT IN (
                SELECT keep_id FROM (
                  SELECT MAX(id) AS keep_id
                  FROM client_download_link
                  WHERE is_latest = {latestValue}
                  GROUP BY implementation, platform, arch
                ) AS latest_rows
              )
            """, cancellationToken).ConfigureAwait(false);
        await ExecuteSchemaSqlAsync(db, $"""
            UPDATE client_download_link
            SET latest_slot = NULL
            WHERE is_latest = {notLatestValue}
            """, cancellationToken).ConfigureAwait(false);
        var latestSlotExpression = dialect == "mysql"
            ? "CONCAT(implementation, '/', platform, '/', arch)"
            : "implementation || '/' || platform || '/' || arch";
        await ExecuteSchemaSqlAsync(db, $"""
            UPDATE client_download_link
            SET latest_slot = {latestSlotExpression}
            WHERE is_latest = {latestValue}
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uq_client_download_version", "client_download_link",
            "implementation, platform, arch, version", cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uq_client_download_latest_slot", "client_download_link",
            "latest_slot", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_client_download_latest", "client_download_link",
            "implementation, platform, arch, is_latest, enabled", cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureMappingCompatibilityColumnsAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var boolType = BooleanColumnType(db.Database.ProviderName);
        var authBoolType = DatabaseDialect(db.Database.ProviderName) == "postgresql"
            ? "BOOLEAN NOT NULL DEFAULT FALSE"
            : boolType;
        await EnsureColumnAsync(db, "specus_mapping", "detail_capture_enabled", boolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "detail_capture_enabled", boolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "media_capture_enabled", authBoolType,
            cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "path_rewrite_enabled", boolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "auth_enabled", authBoolType, cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "auth_username", "VARCHAR(120)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "http_route_mapping", "auth_password_hash", "VARCHAR(64)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_connection_record", "tenant_id", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await BackfillConnectionRecordTenantAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_specus_connection_tenant", "specus_connection_record",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_connection_stat", "tenant_id", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await BackfillConnectionStatTenantAsync(db, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_specus_connection_stat_tenant", "specus_connection_stat",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_traffic_usage", "tenant_id", "VARCHAR(80)", cancellationToken)
            .ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_specus_traffic_tenant", "specus_traffic_usage",
            "tenant_id", cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureClientMessageCapabilityColumnsAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var booleanDefinition = DatabaseDialect(db.Database.ProviderName) switch
        {
            "postgresql" => "BOOLEAN NOT NULL DEFAULT FALSE",
            "mysql" => "TINYINT(1) NOT NULL DEFAULT 0",
            _ => "INTEGER NOT NULL DEFAULT 0",
        };
        await EnsureColumnAsync(db, "specus_client_session", "message_send_capable",
            booleanDefinition, cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_client_session", "message_receive_capable",
            booleanDefinition, cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_client_session", "message_attachments_capable",
            booleanDefinition, cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_client_session", "message_media_preview_capable",
            booleanDefinition, cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_client_session", "message_max_attachment_bytes",
            "BIGINT NOT NULL DEFAULT 0", cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureHttpMediaTablesAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var dialect = DatabaseDialect(db.Database.ProviderName);
        var idType = dialect switch
        {
            "mysql" => "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY",
            "postgresql" => "BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY",
            _ => "INTEGER PRIMARY KEY AUTOINCREMENT",
        };
        var boolType = dialect switch
        {
            "postgresql" => "BOOLEAN NOT NULL DEFAULT FALSE",
            "mysql" => "TINYINT(1) NOT NULL DEFAULT 0",
            _ => "INTEGER NOT NULL DEFAULT 0",
        };
        var textType = dialect == "mysql" ? "LONGTEXT" : "TEXT";

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS specus_http_media_capture (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              client_id BIGINT NOT NULL,
              client_name VARCHAR(120) NOT NULL,
              route VARCHAR(128) NOT NULL,
              resource_id BIGINT,
              source_url VARCHAR(3072) NOT NULL,
              resource_key VARCHAR(64) NOT NULL,
              deduplication_key VARCHAR(64),
              method VARCHAR(16) NOT NULL,
              status_code INTEGER NOT NULL,
              content_type VARCHAR(255),
              content_encoding VARCHAR(128),
              media_kind VARCHAR(32) NOT NULL,
              entity_tag VARCHAR(512),
              last_modified VARCHAR(128),
              content_range_start BIGINT,
              content_range_end BIGINT,
              total_bytes BIGINT,
              captured_bytes BIGINT NOT NULL,
              segment_sequence BIGINT,
              initialization_segment {boolType},
              live_stream {boolType},
              object_key VARCHAR(1024) NOT NULL,
              upload_id VARCHAR(1024),
              object_etag VARCHAR(512),
              state VARCHAR(24) NOT NULL,
              failure_reason VARCHAR(2048),
              response_headers {textType},
              captured_at VARCHAR(40) NOT NULL,
              completed_at VARCHAR(40),
              expires_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS specus_http_media_reference (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              manifest_capture_id BIGINT NOT NULL,
              relation_type VARCHAR(24) NOT NULL,
              sequence_index BIGINT,
              original_uri VARCHAR(2048) NOT NULL,
              resolved_source_url VARCHAR(3072) NOT NULL,
              created_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_http_media_tenant_id", "specus_http_media_capture",
            "tenant_id, id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_media_tenant_client_id", "specus_http_media_capture",
            "tenant_id, client_id, id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_media_tenant_resource_id", "specus_http_media_capture",
            "tenant_id, resource_key, id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_media_tenant_client_route_id", "specus_http_media_capture",
            "tenant_id, client_id, route, id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_media_state_expires", "specus_http_media_capture",
            "state, expires_at", cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uk_http_media_deduplication_key",
            "specus_http_media_capture", "deduplication_key", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_media_reference_manifest_sequence",
            "specus_http_media_reference", "tenant_id, manifest_capture_id, sequence_index",
            cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_media_reference_manifest",
            "specus_http_media_reference", "tenant_id, manifest_capture_id", cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task EnsureTransferAttachmentTableAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var idType = DatabaseDialect(db.Database.ProviderName) switch
        {
            "mysql" => "BIGINT NOT NULL PRIMARY KEY",
            "postgresql" => "BIGINT PRIMARY KEY",
            _ => "INTEGER PRIMARY KEY",
        };
        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS transfer_attachment (
              id {idType},
              tenant_id VARCHAR(80),
              scope VARCHAR(40) NOT NULL,
              room_id VARCHAR(120),
              room_token_hash VARCHAR(64),
              public_transfer_room_id BIGINT,
              owner_username VARCHAR(80),
              target_client_id BIGINT,
              object_key VARCHAR(512) NOT NULL,
              file_name VARCHAR(255) NOT NULL,
              mime_type VARCHAR(120) NOT NULL,
              size_bytes BIGINT NOT NULL,
              sha256 VARCHAR(64),
              status VARCHAR(24) NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL,
              upload_expires_at VARCHAR(40) NOT NULL,
              expires_at VARCHAR(40) NOT NULL,
              uploaded_at VARCHAR(40)
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_transfer_attachment_tenant", "transfer_attachment",
            "tenant_id, scope, id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_transfer_attachment_room", "transfer_attachment",
            "scope, room_id, id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_transfer_attachment_public_room",
            "transfer_attachment", "scope, public_transfer_room_id, id", cancellationToken)
            .ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_transfer_attachment_owner_status", "transfer_attachment",
            "tenant_id, owner_username, status, expires_at", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_transfer_attachment_expires", "transfer_attachment",
            "expires_at, status", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS transfer_attachment_download_usage (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              username VARCHAR(80) NOT NULL,
              attachment_id BIGINT NOT NULL,
              size_bytes BIGINT NOT NULL,
              usage_month VARCHAR(7) NOT NULL,
              created_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_attachment_download_usage_account_month",
            "transfer_attachment_download_usage", "tenant_id, username, usage_month",
            cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_attachment_download_usage_attachment",
            "transfer_attachment_download_usage", "attachment_id, created_at",
            cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS transfer_attachment_download_grant (
              id {idType},
              token_hash VARCHAR(64) NOT NULL,
              tenant_id VARCHAR(80) NOT NULL,
              username VARCHAR(80) NOT NULL,
              attachment_id BIGINT NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              expires_at VARCHAR(40) NOT NULL,
              consumed_at VARCHAR(40)
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "IX_transfer_attachment_download_grant_token_hash",
            "transfer_attachment_download_grant", "token_hash", cancellationToken)
            .ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_attachment_download_grant_attachment",
            "transfer_attachment_download_grant", "attachment_id, created_at",
            cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_attachment_download_grant_expiry",
            "transfer_attachment_download_grant", "expires_at, consumed_at",
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task EnsureTransferRoomCredentialColumnsAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var discoverableType = DatabaseDialect(db.Database.ProviderName) switch
        {
            "postgresql" => "BOOLEAN NOT NULL DEFAULT TRUE",
            "mysql" => "TINYINT(1) NOT NULL DEFAULT 1",
            _ => "INTEGER NOT NULL DEFAULT 1",
        };
        await EnsureColumnAsync(db, "specus_websocket_ticket", "room_role", "VARCHAR(16)",
            cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "specus_websocket_ticket", "discoverable", discoverableType,
            cancellationToken).ConfigureAwait(false);
        await EnsureColumnAsync(db, "transfer_attachment", "public_transfer_room_id", "BIGINT",
            cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_transfer_attachment_public_room",
            "transfer_attachment", "scope, public_transfer_room_id, id", cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task EnsureDiagramAndTransferRoomTablesAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        var dialect = DatabaseDialect(db.Database.ProviderName);
        var idType = dialect switch
        {
            "mysql" => "BIGINT NOT NULL PRIMARY KEY",
            "postgresql" => "BIGINT PRIMARY KEY",
            _ => "INTEGER PRIMARY KEY",
        };
        var blobType = dialect switch
        {
            "mysql" => "LONGBLOB",
            "postgresql" => "BYTEA",
            _ => "BLOB",
        };

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS public_transfer_room (
              id {idType},
              room_name VARCHAR(120) NOT NULL,
              owner_token_hash VARCHAR(64) NOT NULL,
              created_by_peer_id VARCHAR(120) NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uk_public_transfer_room_key", "public_transfer_room",
            "room_name, owner_token_hash", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_public_transfer_room_name", "public_transfer_room",
            "room_name", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS public_transfer_room_access (
              id {idType},
              room_id BIGINT NOT NULL,
              token_hash VARCHAR(64) NOT NULL,
              role VARCHAR(16) NOT NULL,
              label VARCHAR(80) NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              expires_at VARCHAR(40),
              revoked_at VARCHAR(40)
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uk_public_transfer_access_token",
            "public_transfer_room_access", "token_hash", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_public_transfer_access_room", "public_transfer_room_access",
            "room_id", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS public_transfer_room_pairing_code (
              id {idType},
              room_id BIGINT NOT NULL,
              code_hash VARCHAR(64) NOT NULL,
              role VARCHAR(16) NOT NULL,
              label VARCHAR(80) NOT NULL,
              created_at VARCHAR(40) NOT NULL,
              expires_at VARCHAR(40) NOT NULL,
              max_uses INTEGER NOT NULL,
              used_count INTEGER NOT NULL,
              revoked_at VARCHAR(40)
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureUniqueIndexAsync(db, "uk_public_transfer_pairing_code_hash",
            "public_transfer_room_pairing_code", "code_hash", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_public_transfer_pairing_room",
            "public_transfer_room_pairing_code", "room_id", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS public_transfer_diagram_version (
              id {idType},
              room_id BIGINT NOT NULL,
              name VARCHAR(80) NOT NULL,
              author_peer_id VARCHAR(120) NOT NULL,
              snapshot_data {blobType} NOT NULL,
              size_bytes BIGINT NOT NULL,
              created_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_public_transfer_version_room",
            "public_transfer_diagram_version", "room_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_public_transfer_version_created",
            "public_transfer_diagram_version", "created_at", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS user_diagram_document (
              id {idType},
              tenant_id VARCHAR(80) NOT NULL,
              owner_username VARCHAR(160) NOT NULL,
              name VARCHAR(120) NOT NULL,
              snapshot_data {blobType} NOT NULL,
              size_bytes BIGINT NOT NULL,
              revision BIGINT NOT NULL DEFAULT 0,
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL
            )
            """, cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_user_diagram_owner", "user_diagram_document",
            "tenant_id, owner_username", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_user_diagram_updated", "user_diagram_document",
            "updated_at", cancellationToken).ConfigureAwait(false);
    }

    private static Task BackfillConnectionStatTenantAsync(SpecusDbContext db, CancellationToken cancellationToken)
    {
        return db.Database.ExecuteSqlRawAsync(
            BuildConnectionStatTenantBackfillSql(db.Database.ProviderName),
            cancellationToken);
    }

    internal static async Task BackfillConnectionRecordTenantAsync(SpecusDbContext db,
        CancellationToken cancellationToken)
    {
        await using var transaction = await db.Database.BeginTransactionAsync(cancellationToken)
            .ConfigureAwait(false);
        await db.Database.ExecuteSqlRawAsync(
                BuildConnectionRecordTenantBackfillSql(db.Database.ProviderName),
                ["default"], cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static string BuildConnectionRecordTenantBackfillSql(string? providerName)
    {
        var idColumn = DatabaseDialect(providerName) switch
        {
            "postgresql" => "\"Id\"",
            _ => "Id",
        };
        return
            "UPDATE specus_connection_record " +
            "SET tenant_id = COALESCE(" +
                "(SELECT NULLIF(TRIM(c.tenant_id), '') FROM specus_client_account c " +
                    "WHERE c." + idColumn + " = specus_connection_record.client_id LIMIT 1)," +
                "{0}) " +
            "WHERE tenant_id IS NULL OR TRIM(tenant_id) = ''";
    }

    private static string BuildConnectionStatTenantBackfillSql(string? providerName)
    {
        // The PK column on specus_client_account is created as PascalCase "Id" by EF Core's
        // migration. PostgreSQL preserves the casing and requires "Id" to be double-quoted in
        // raw SQL; SQLite and MySQL are case-insensitive on column names so plain Id also works
        // there. The column name is a compile-time constant chosen from a closed set per
        // provider — no user input — so the EF1002 raw-SQL warning at the call site doesn't
        // apply here. We build the SQL string ahead of the call to keep the analyzer quiet.
        var idColumn = DatabaseDialect(providerName) switch
        {
            "postgresql" => "\"Id\"",
            _ => "Id",
        };
        return
            "UPDATE specus_connection_stat " +
            "SET tenant_id = COALESCE(" +
                "(SELECT c.tenant_id FROM specus_client_account c WHERE c." + idColumn + " = specus_connection_stat.client_id LIMIT 1)," +
                "(SELECT c.tenant_id FROM specus_client_account c " +
                    "WHERE specus_connection_stat.client_id IS NULL " +
                      "AND c.client_name = specus_connection_stat.client_name LIMIT 1)," +
                "tenant_id," +
                "'default') " +
            "WHERE tenant_id IS NULL OR tenant_id = '' OR tenant_id = 'default'";
    }

    private static async Task EnsureTrafficDetailTablesAsync(SpecusDbContext db,
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
            CREATE TABLE IF NOT EXISTS specus_resource_traffic_usage (
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

        await EnsureIndexAsync(db, "idx_resource_traffic_tenant", "specus_resource_traffic_usage",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_resource_traffic_client", "specus_resource_traffic_usage",
            "client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_resource_traffic_type", "specus_resource_traffic_usage",
            "resource_type", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_resource_traffic_date", "specus_resource_traffic_usage",
            "usage_date", cancellationToken).ConfigureAwait(false);

        await ExecuteSchemaSqlAsync(db, $"""
            CREATE TABLE IF NOT EXISTS specus_http_traffic_exchange (
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
            CREATE TABLE IF NOT EXISTS specus_tcp_traffic_frame (
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

        await EnsureIndexAsync(db, "idx_http_traffic_tenant", "specus_http_traffic_exchange",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_client", "specus_http_traffic_exchange",
            "client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_route", "specus_http_traffic_exchange",
            "route", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_body_type", "specus_http_traffic_exchange",
            "response_body_type", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_http_traffic_captured_at", "specus_http_traffic_exchange",
            "captured_at", cancellationToken).ConfigureAwait(false);

        await EnsureIndexAsync(db, "idx_tcp_traffic_tenant", "specus_tcp_traffic_frame",
            "tenant_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_client", "specus_tcp_traffic_frame",
            "client_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_listen_port", "specus_tcp_traffic_frame",
            "listen_port", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_channel", "specus_tcp_traffic_frame",
            "channel_id", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_stream", "specus_tcp_traffic_frame",
            "tenant_id, channel_id, frame_direction, stream_offset", cancellationToken).ConfigureAwait(false);
        await EnsureIndexAsync(db, "idx_tcp_traffic_frame_time", "specus_tcp_traffic_frame",
            "frame_time", cancellationToken).ConfigureAwait(false);
    }

    internal static async Task EnsurePeerMeshTablesAsync(SpecusDbContext db,
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
              direction VARCHAR(16) NOT NULL DEFAULT 'OUTBOUND',
              created_at VARCHAR(40) NOT NULL,
              updated_at VARCHAR(40) NOT NULL,
              CONSTRAINT uk_peer_mesh_acl_pair UNIQUE (tenant_id, source_client_id, target_client_id)
            )
            """, cancellationToken).ConfigureAwait(false);

        await EnsureColumnAsync(db, "peer_mesh_acl", "direction",
            "VARCHAR(16) NOT NULL DEFAULT 'OUTBOUND'", cancellationToken).ConfigureAwait(false);
        await db.Database.ExecuteSqlRawAsync(
            "UPDATE peer_mesh_acl SET direction = 'OUTBOUND' WHERE direction IS NULL OR TRIM(direction) = ''",
            cancellationToken).ConfigureAwait(false);

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

    private static async Task EnsureIndexAsync(SpecusDbContext db, string indexName, string table,
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

    private static async Task EnsureUniqueIndexAsync(SpecusDbContext db, string indexName,
        string table, string columns, CancellationToken cancellationToken)
    {
        if (await IndexExistsAsync(db, table, indexName, cancellationToken).ConfigureAwait(false))
        {
            return;
        }

        await ExecuteSchemaSqlAsync(db,
                $"CREATE UNIQUE INDEX {indexName} ON {table} ({columns})", cancellationToken)
            .ConfigureAwait(false);
    }

    private static async Task EnsureColumnAsync(SpecusDbContext db, string table, string column,
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

    private static Task ExecuteSchemaSqlAsync(SpecusDbContext db, string sql, CancellationToken cancellationToken)
    {
        return db.Database.ExecuteSqlRawAsync(sql, cancellationToken);
    }

    private static async Task<bool> ColumnExistsAsync(SpecusDbContext db, string table, string column,
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

    private static async Task<bool> IndexExistsAsync(SpecusDbContext db, string table, string indexName,
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
