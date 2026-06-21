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
