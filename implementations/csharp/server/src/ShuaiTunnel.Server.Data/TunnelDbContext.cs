using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Data.Conversion;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Data;

/// <summary>
/// Single DbContext for the management surface. Table names mirror the Java JPA schema so
/// migrations stay diff-able against any prior deployment that wants to compare. Column names
/// follow Java's <c>@Column</c> snake_case so the SPA's existing fetch shape keeps working.
/// </summary>
public sealed class TunnelDbContext : DbContext
{
    public TunnelDbContext(DbContextOptions<TunnelDbContext> options) : base(options)
    {
    }

    public DbSet<ClientAccount> ClientAccounts => Set<ClientAccount>();
    public DbSet<ClientCredential> ClientCredentials => Set<ClientCredential>();
    public DbSet<ClientIdentity> ClientIdentities => Set<ClientIdentity>();
    public DbSet<ClientSession> ClientSessions => Set<ClientSession>();
    public DbSet<ConnectionRecord> ConnectionRecords => Set<ConnectionRecord>();
    public DbSet<TunnelMapping> TunnelMappings => Set<TunnelMapping>();
    public DbSet<HttpRouteMapping> HttpRouteMappings => Set<HttpRouteMapping>();
    public DbSet<TrafficUsage> TrafficUsages => Set<TrafficUsage>();
    public DbSet<ConnectionStat> ConnectionStats => Set<ConnectionStat>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        var iso = new IsoDateTimeOffsetConverter();
        var isoNullable = new IsoNullableDateTimeOffsetConverter();

        modelBuilder.Entity<ClientAccount>(b =>
        {
            b.ToTable("tunnel_client_account");
            b.HasKey(x => x.Id);
            // Application-assigned IDs (ClientIdGenerator) — disable EF auto-generation.
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.OwnerUsername).HasColumnName("owner_username").HasMaxLength(80);
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.HasIndex(x => x.ClientName).IsUnique();
            b.Property(x => x.PasswordHash).HasColumnName("password_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.ConnectionRateLimitPerMinute)
                .HasColumnName("connection_rate_limit_per_minute").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_tunnel_client_tenant");
            b.HasIndex(x => new { x.TenantId, x.OwnerUsername }).HasDatabaseName("idx_tunnel_client_owner");
        });

        modelBuilder.Entity<ClientCredential>(b =>
        {
            b.ToTable("tunnel_client_credential");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.OwnerUsername).HasColumnName("owner_username").HasMaxLength(80);
            b.Property(x => x.ApiKey).HasColumnName("api_key").HasMaxLength(120).IsRequired();
            b.Property(x => x.SecretHash).HasColumnName("secret_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.MaxOnlineInstances).HasColumnName("max_online_instances").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.ApiKey).IsUnique().HasDatabaseName("uk_client_credential_api_key");
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_client_credential_tenant");
            b.HasIndex(x => new { x.TenantId, x.OwnerUsername }).HasDatabaseName("idx_client_credential_owner");
        });

        modelBuilder.Entity<ClientIdentity>(b =>
        {
            b.ToTable("tunnel_client_identity");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.CredentialId).HasColumnName("credential_id").IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.MachineFingerprint).HasColumnName("machine_fingerprint").HasMaxLength(160).IsRequired();
            b.Property(x => x.OsUser).HasColumnName("os_user").HasMaxLength(120).IsRequired();
            b.Property(x => x.Hostname).HasColumnName("hostname").HasMaxLength(160);
            b.Property(x => x.FirstSeenAt).HasColumnName("first_seen_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.LastSeenAt).HasColumnName("last_seen_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.CredentialId, x.MachineFingerprint, x.OsUser })
                .IsUnique()
                .HasDatabaseName("uk_client_identity_machine_user");
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_client_identity_tenant");
            b.HasIndex(x => x.ClientId).HasDatabaseName("idx_client_identity_client");
        });

        modelBuilder.Entity<ClientSession>(b =>
        {
            b.ToTable("tunnel_client_session");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.CredentialId).HasColumnName("credential_id").IsRequired();
            b.Property(x => x.IdentityId).HasColumnName("identity_id").IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.TokenHash).HasColumnName("token_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(40).IsRequired();
            b.Property(x => x.MachineFingerprint).HasColumnName("machine_fingerprint").HasMaxLength(160).IsRequired();
            b.Property(x => x.OsUser).HasColumnName("os_user").HasMaxLength(120).IsRequired();
            b.Property(x => x.Hostname).HasColumnName("hostname").HasMaxLength(160);
            b.Property(x => x.OsName).HasColumnName("os_name").HasMaxLength(120);
            b.Property(x => x.OsVersion).HasColumnName("os_version").HasMaxLength(80);
            b.Property(x => x.OsArch).HasColumnName("os_arch").HasMaxLength(60);
            b.Property(x => x.ClientVersion).HasColumnName("client_version").HasMaxLength(80);
            b.Property(x => x.JavaVersion).HasColumnName("java_version").HasMaxLength(80);
            b.Property(x => x.LocalAddresses).HasColumnName("local_addresses").HasMaxLength(2000);
            b.Property(x => x.HttpLoginAt).HasColumnName("http_login_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.NettyConnectedAt).HasColumnName("netty_connected_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.Property(x => x.DisconnectedAt).HasColumnName("disconnected_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ChannelId).HasColumnName("channel_id").HasMaxLength(160);
            b.Property(x => x.RemoteAddress).HasColumnName("remote_address").HasMaxLength(255);
            b.HasIndex(x => x.TokenHash).HasDatabaseName("idx_client_session_token");
            b.HasIndex(x => new { x.CredentialId, x.Status }).HasDatabaseName("idx_client_session_credential_status");
            b.HasIndex(x => new { x.CredentialId, x.MachineFingerprint, x.OsUser, x.Status })
                .HasDatabaseName("idx_client_session_machine_status");
        });

        modelBuilder.Entity<ConnectionRecord>(b =>
        {
            b.ToTable("tunnel_connection_record");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.ClientId).HasColumnName("client_id");
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.ChannelId).HasColumnName("channel_id").HasMaxLength(160);
            b.Property(x => x.RemoteAddress).HasColumnName("remote_address").HasMaxLength(255);
            b.Property(x => x.ConnectedAt).HasColumnName("connected_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.DisconnectedAt).HasColumnName("disconnected_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.Property(x => x.Success).HasColumnName("success").IsRequired();
            b.Property(x => x.FailureReason).HasColumnName("failure_reason").HasMaxLength(255);
            b.Property(x => x.DisconnectReason).HasColumnName("disconnect_reason").HasMaxLength(40);
            // Composite index on (client_id, connected_at) backs the rate-limit COUNT plus
            // per-client history listings; the connected_at-only index backs the retention purge.
            b.HasIndex(x => new { x.ClientId, x.ConnectedAt })
                .HasDatabaseName("idx_tunnel_connection_client_time");
            b.HasIndex(x => x.ConnectedAt).HasDatabaseName("idx_tunnel_connection_connected_at");
        });

        modelBuilder.Entity<TunnelMapping>(b =>
        {
            b.ToTable("tunnel_mapping");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.ListenPort).HasColumnName("listen_port").IsRequired();
            b.Property(x => x.TargetAddress).HasColumnName("target_address").HasMaxLength(255).IsRequired();
            b.Property(x => x.TargetPort).HasColumnName("target_port").IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.ListenPort).IsUnique();
            b.HasIndex(x => x.ClientId);
        });

        modelBuilder.Entity<HttpRouteMapping>(b =>
        {
            b.ToTable("http_route_mapping");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.Route).HasColumnName("route").HasMaxLength(60).IsRequired();
            b.Property(x => x.TargetBaseUrl).HasColumnName("target_base_url").HasMaxLength(512).IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.ClientId, x.Route }).IsUnique();
            b.HasIndex(x => x.ClientId);
        });

        modelBuilder.Entity<TrafficUsage>(b =>
        {
            b.ToTable("tunnel_traffic_usage");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.UsageDate).HasColumnName("usage_date").HasMaxLength(10).IsRequired();
            b.Property(x => x.UploadBytes).HasColumnName("upload_bytes").IsRequired();
            b.Property(x => x.DownloadBytes).HasColumnName("download_bytes").IsRequired();
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.ClientId, x.UsageDate }).IsUnique();
            b.HasIndex(x => x.ClientId);
        });

        modelBuilder.Entity<ConnectionStat>(b =>
        {
            b.ToTable("tunnel_connection_stat");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.ClientId).HasColumnName("client_id");
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.StatMonth).HasColumnName("stat_month").HasMaxLength(7).IsRequired();
            b.Property(x => x.TotalCount).HasColumnName("total_count").IsRequired();
            b.Property(x => x.SuccessCount).HasColumnName("success_count").IsRequired();
            b.Property(x => x.FailureCount).HasColumnName("failure_count").IsRequired();
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.ClientName, x.StatMonth }).IsUnique();
            b.HasIndex(x => x.ClientName);
        });
    }
}
