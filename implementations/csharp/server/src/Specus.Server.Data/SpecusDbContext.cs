using Microsoft.EntityFrameworkCore;
using Specus.Server.Data.Conversion;
using Specus.Server.Data.Entities;

namespace Specus.Server.Data;

/// <summary>
/// Single DbContext for the management surface. Table names mirror the Java JPA schema so
/// migrations stay diff-able against any prior deployment that wants to compare. Column names
/// follow Java's <c>@Column</c> snake_case so the SPA's existing fetch shape keeps working.
/// </summary>
public sealed class SpecusDbContext : DbContext
{
    public SpecusDbContext(DbContextOptions<SpecusDbContext> options) : base(options)
    {
    }

    public DbSet<ClientAccount> ClientAccounts => Set<ClientAccount>();
    public DbSet<ClientCredential> ClientCredentials => Set<ClientCredential>();
    public DbSet<ClientAuthNonce> ClientAuthNonces => Set<ClientAuthNonce>();
    public DbSet<WebSocketTicket> WebSocketTickets => Set<WebSocketTicket>();
    public DbSet<ClientIdentity> ClientIdentities => Set<ClientIdentity>();
    public DbSet<ClientSession> ClientSessions => Set<ClientSession>();
    public DbSet<ManagementUser> ManagementUsers => Set<ManagementUser>();
    public DbSet<ManagementUserEmail> ManagementUserEmails => Set<ManagementUserEmail>();
    public DbSet<ManagementRegistrationChallenge> ManagementRegistrationChallenges =>
        Set<ManagementRegistrationChallenge>();
    public DbSet<ClientDownloadLink> ClientDownloadLinks => Set<ClientDownloadLink>();
    public DbSet<ConnectionRecord> ConnectionRecords => Set<ConnectionRecord>();
    public DbSet<SpecusMapping> SpecusMappings => Set<SpecusMapping>();
    public DbSet<HttpRouteMapping> HttpRouteMappings => Set<HttpRouteMapping>();
    public DbSet<TrafficUsage> TrafficUsages => Set<TrafficUsage>();
    public DbSet<ResourceTrafficUsage> ResourceTrafficUsages => Set<ResourceTrafficUsage>();
    public DbSet<HttpTrafficExchange> HttpTrafficExchanges => Set<HttpTrafficExchange>();
    public DbSet<TcpTrafficFrame> TcpTrafficFrames => Set<TcpTrafficFrame>();
    public DbSet<PeerMeshDevice> PeerMeshDevices => Set<PeerMeshDevice>();
    public DbSet<PeerMeshAcl> PeerMeshAcls => Set<PeerMeshAcl>();
    public DbSet<PeerMeshSession> PeerMeshSessions => Set<PeerMeshSession>();
    public DbSet<ConnectionStat> ConnectionStats => Set<ConnectionStat>();
    public DbSet<TransferAttachment> TransferAttachments => Set<TransferAttachment>();
    public DbSet<TransferAttachmentDownloadUsage> TransferAttachmentDownloadUsages =>
        Set<TransferAttachmentDownloadUsage>();
    public DbSet<TransferAttachmentDownloadGrant> TransferAttachmentDownloadGrants =>
        Set<TransferAttachmentDownloadGrant>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        var iso = new IsoDateTimeOffsetConverter();
        var isoNullable = new IsoNullableDateTimeOffsetConverter();

        modelBuilder.Entity<ClientAccount>(b =>
        {
            b.ToTable("specus_client_account");
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
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_specus_client_tenant");
            b.HasIndex(x => new { x.TenantId, x.OwnerUsername }).HasDatabaseName("idx_specus_client_owner");
        });

        modelBuilder.Entity<ClientCredential>(b =>
        {
            b.ToTable("specus_client_credential");
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

        modelBuilder.Entity<ClientAuthNonce>(b =>
        {
            b.ToTable("specus_client_auth_nonce");
            b.HasKey(x => new { x.ApiKeyHash, x.NonceHash });
            b.Property(x => x.ApiKeyHash).HasColumnName("api_key_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.NonceHash).HasColumnName("nonce_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.ExpiresAt).HasDatabaseName("idx_client_auth_nonce_expiry");
        });

        modelBuilder.Entity<WebSocketTicket>(b =>
        {
            b.ToTable("specus_websocket_ticket");
            b.HasKey(x => x.TokenHash);
            b.Property(x => x.TokenHash).HasColumnName("token_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.Scope).HasColumnName("scope").HasMaxLength(40).IsRequired();
            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(80);
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80);
            b.Property(x => x.IsAdmin).HasColumnName("is_admin").IsRequired();
            b.Property(x => x.RoomId).HasColumnName("room_id").HasMaxLength(120);
            b.Property(x => x.RoomKey).HasColumnName("room_key").HasMaxLength(80);
            b.Property(x => x.PeerId).HasColumnName("peer_id").HasMaxLength(120);
            b.Property(x => x.DisplayName).HasColumnName("display_name").HasMaxLength(120);
            b.Property(x => x.SharedRoom).HasColumnName("shared_room").IsRequired();
            b.Property(x => x.RemoteAddressHash).HasColumnName("remote_address_hash").HasMaxLength(64)
                .IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.ExpiresAt).HasDatabaseName("idx_websocket_ticket_expiry");
        });

        modelBuilder.Entity<ClientIdentity>(b =>
        {
            b.ToTable("specus_client_identity");
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
            b.ToTable("specus_client_session");
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
            b.Property(x => x.MessageSendCapable).HasColumnName("message_send_capable").IsRequired();
            b.Property(x => x.MessageReceiveCapable).HasColumnName("message_receive_capable").IsRequired();
            b.Property(x => x.MessageAttachmentsCapable).HasColumnName("message_attachments_capable").IsRequired();
            b.Property(x => x.MessageMediaPreviewCapable).HasColumnName("message_media_preview_capable").IsRequired();
            b.Property(x => x.MessageMaxAttachmentBytes).HasColumnName("message_max_attachment_bytes").IsRequired();
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

        modelBuilder.Entity<ManagementUser>(b =>
        {
            b.ToTable("specus_management_user");
            b.HasKey(x => x.Username);
            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(80).IsRequired();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.PasswordHash).HasColumnName("password_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.Role).HasColumnName("role").HasMaxLength(20).IsRequired()
                .HasConversion<string>();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_management_user_tenant");
            b.HasIndex(x => x.Role).HasDatabaseName("idx_management_user_role");
        });

        modelBuilder.Entity<ManagementUserEmail>(b =>
        {
            b.ToTable("specus_management_user_email");
            b.HasKey(x => x.Username);
            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(80).IsRequired();
            b.Property(x => x.Email).HasColumnName("email").HasMaxLength(254).IsRequired();
            b.Property(x => x.VerifiedAt).HasColumnName("verified_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.Email).IsUnique().HasDatabaseName("uq_management_user_email");
            b.HasIndex(x => x.VerifiedAt).HasDatabaseName("idx_management_user_email_verified");
        });

        modelBuilder.Entity<ManagementRegistrationChallenge>(b =>
        {
            b.ToTable("specus_management_registration_challenge");
            b.HasKey(x => x.RegistrationId);
            b.Property(x => x.RegistrationId).HasColumnName("registration_id").HasMaxLength(64)
                .IsRequired();
            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(80).IsRequired();
            b.Property(x => x.Email).HasColumnName("email").HasMaxLength(254).IsRequired();
            b.Property(x => x.PasswordHash).HasColumnName("password_hash").HasMaxLength(64)
                .IsRequired();
            b.Property(x => x.CodeHash).HasColumnName("code_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.AttemptsRemaining).HasColumnName("attempts_remaining").IsRequired();
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ResendAvailableAt).HasColumnName("resend_available_at").HasMaxLength(40)
                .IsRequired().HasConversion(iso);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.Username).IsUnique().HasDatabaseName("uq_registration_challenge_username");
            b.HasIndex(x => x.Email).IsUnique().HasDatabaseName("uq_registration_challenge_email");
            b.HasIndex(x => x.ExpiresAt).HasDatabaseName("idx_registration_challenge_expiry");
        });

        modelBuilder.Entity<ClientDownloadLink>(b =>
        {
            b.ToTable("client_download_link");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.Implementation).HasColumnName("implementation").HasMaxLength(32).IsRequired();
            b.Property(x => x.Platform).HasColumnName("platform").HasMaxLength(32).IsRequired();
            b.Property(x => x.Arch).HasColumnName("arch").HasMaxLength(32).IsRequired();
            b.Property(x => x.DisplayName).HasColumnName("display_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.DownloadUrl).HasColumnName("download_url").HasMaxLength(1024).IsRequired();
            b.Property(x => x.Description).HasColumnName("description").HasMaxLength(512);
            b.Property(x => x.DisplayOrder).HasColumnName("display_order").IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.Implementation).HasDatabaseName("idx_client_download_impl");
            b.HasIndex(x => x.DisplayOrder).HasDatabaseName("idx_client_download_order");
        });

        modelBuilder.Entity<ConnectionRecord>(b =>
        {
            b.ToTable("specus_connection_record");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80);
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
                .HasDatabaseName("idx_specus_connection_client_time");
            b.HasIndex(x => x.ConnectedAt).HasDatabaseName("idx_specus_connection_connected_at");
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_specus_connection_tenant");
        });

        modelBuilder.Entity<SpecusMapping>(b =>
        {
            b.ToTable("specus_mapping");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.ListenPort).HasColumnName("listen_port").IsRequired();
            b.Property(x => x.TargetAddress).HasColumnName("target_address").HasMaxLength(255).IsRequired();
            b.Property(x => x.TargetPort).HasColumnName("target_port").IsRequired();
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.DetailCaptureEnabled).HasColumnName("detail_capture_enabled").IsRequired();
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
            b.Property(x => x.DetailCaptureEnabled).HasColumnName("detail_capture_enabled").IsRequired();
            b.Property(x => x.PathRewriteEnabled).HasColumnName("path_rewrite_enabled").IsRequired();
            b.Property(x => x.AuthEnabled).HasColumnName("auth_enabled").IsRequired();
            b.Property(x => x.AuthUsername).HasColumnName("auth_username").HasMaxLength(120);
            b.Property(x => x.AuthPasswordHash).HasColumnName("auth_password_hash").HasMaxLength(64);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.ClientId, x.Route }).IsUnique();
            b.HasIndex(x => x.ClientId);
        });

        modelBuilder.Entity<TrafficUsage>(b =>
        {
            b.ToTable("specus_traffic_usage");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80);
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.UsageDate).HasColumnName("usage_date").HasMaxLength(10).IsRequired();
            b.Property(x => x.UploadBytes).HasColumnName("upload_bytes").IsRequired();
            b.Property(x => x.DownloadBytes).HasColumnName("download_bytes").IsRequired();
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.ClientId, x.UsageDate }).IsUnique();
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_specus_traffic_tenant");
            b.HasIndex(x => x.ClientId).HasDatabaseName("idx_specus_traffic_client");
        });

        modelBuilder.Entity<ResourceTrafficUsage>(b =>
        {
            b.ToTable("specus_resource_traffic_usage");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.ResourceType).HasColumnName("resource_type").HasMaxLength(32).IsRequired();
            b.Property(x => x.ResourceKey).HasColumnName("resource_key").HasMaxLength(128).IsRequired();
            b.Property(x => x.ResourceId).HasColumnName("resource_id");
            b.Property(x => x.ResourceName).HasColumnName("resource_name").HasMaxLength(255).IsRequired();
            b.Property(x => x.UsageDate).HasColumnName("usage_date").HasMaxLength(10).IsRequired();
            b.Property(x => x.UploadBytes).HasColumnName("upload_bytes").IsRequired();
            b.Property(x => x.DownloadBytes).HasColumnName("download_bytes").IsRequired();
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.TenantId, x.ClientId, x.ResourceType, x.ResourceKey, x.UsageDate })
                .IsUnique()
                .HasDatabaseName("uk_resource_traffic_resource_date");
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_resource_traffic_tenant");
            b.HasIndex(x => x.ClientId).HasDatabaseName("idx_resource_traffic_client");
            b.HasIndex(x => x.ResourceType).HasDatabaseName("idx_resource_traffic_type");
            b.HasIndex(x => x.UsageDate).HasDatabaseName("idx_resource_traffic_date");
        });

        modelBuilder.Entity<HttpTrafficExchange>(b =>
        {
            b.ToTable("specus_http_traffic_exchange");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.Route).HasColumnName("route").HasMaxLength(128).IsRequired();
            b.Property(x => x.ResourceId).HasColumnName("resource_id");
            b.Property(x => x.ResourceName).HasColumnName("resource_name").HasMaxLength(255);
            b.Property(x => x.Method).HasColumnName("method").HasMaxLength(16);
            b.Property(x => x.RelativePath).HasColumnName("relative_path").HasMaxLength(1024);
            b.Property(x => x.RawQuery).HasColumnName("raw_query").HasMaxLength(2048);
            b.Property(x => x.StatusCode).HasColumnName("status_code").IsRequired();
            b.Property(x => x.Success).HasColumnName("success").IsRequired();
            b.Property(x => x.Error).HasColumnName("error").HasMaxLength(2048);
            b.Property(x => x.RemoteAddress).HasColumnName("remote_address").HasMaxLength(255);
            b.Property(x => x.RequestBytes).HasColumnName("request_bytes").IsRequired();
            b.Property(x => x.ResponseBytes).HasColumnName("response_bytes").IsRequired();
            b.Property(x => x.ElapsedMs).HasColumnName("elapsed_ms").IsRequired();
            b.Property(x => x.RequestContentType).HasColumnName("request_content_type").HasMaxLength(255);
            b.Property(x => x.ResponseContentType).HasColumnName("response_content_type").HasMaxLength(255);
            b.Property(x => x.ResponseBodyType).HasColumnName("response_body_type").HasMaxLength(32);
            b.Property(x => x.RequestHeaders).HasColumnName("request_headers").HasMaxLength(8192);
            b.Property(x => x.ResponseHeaders).HasColumnName("response_headers").HasMaxLength(8192);
            b.Property(x => x.RequestPreviewHex).HasColumnName("request_preview_hex").HasMaxLength(4096);
            b.Property(x => x.RequestPreviewText).HasColumnName("request_preview_text");
            b.Property(x => x.ResponsePreviewHex).HasColumnName("response_preview_hex").HasMaxLength(4096);
            b.Property(x => x.ResponsePreviewText).HasColumnName("response_preview_text");
            b.Property(x => x.RequestTruncated).HasColumnName("request_truncated").IsRequired();
            b.Property(x => x.ResponseTruncated).HasColumnName("response_truncated").IsRequired();
            b.Property(x => x.CapturedAt).HasColumnName("captured_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_http_traffic_tenant");
            b.HasIndex(x => x.ClientId).HasDatabaseName("idx_http_traffic_client");
            b.HasIndex(x => x.Route).HasDatabaseName("idx_http_traffic_route");
            b.HasIndex(x => x.ResponseBodyType).HasDatabaseName("idx_http_traffic_body_type");
            b.HasIndex(x => x.CapturedAt).HasDatabaseName("idx_http_traffic_captured_at");
        });

        modelBuilder.Entity<TcpTrafficFrame>(b =>
        {
            b.ToTable("specus_tcp_traffic_frame");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.ListenPort).HasColumnName("listen_port").IsRequired();
            b.Property(x => x.ResourceId).HasColumnName("resource_id");
            b.Property(x => x.ResourceName).HasColumnName("resource_name").HasMaxLength(255);
            b.Property(x => x.ChannelId).HasColumnName("channel_id").HasMaxLength(120).IsRequired();
            b.Property(x => x.Direction).HasColumnName("frame_direction").HasMaxLength(32).IsRequired();
            b.Property(x => x.RemoteAddress).HasColumnName("remote_address").HasMaxLength(255);
            b.Property(x => x.SourceAddress).HasColumnName("source_address").HasMaxLength(255);
            b.Property(x => x.SourcePort).HasColumnName("source_port");
            b.Property(x => x.DestinationAddress).HasColumnName("destination_address").HasMaxLength(255);
            b.Property(x => x.DestinationPort).HasColumnName("destination_port");
            b.Property(x => x.StreamOffset).HasColumnName("stream_offset").IsRequired();
            b.Property(x => x.StreamEndOffset).HasColumnName("stream_end_offset").IsRequired();
            b.Property(x => x.FrameIndex).HasColumnName("frame_index").IsRequired();
            b.Property(x => x.PayloadBytes).HasColumnName("payload_bytes").IsRequired();
            b.Property(x => x.PayloadData).HasColumnName("payload_data").IsRequired();
            b.Property(x => x.PayloadPreviewHex).HasColumnName("payload_preview_hex").HasMaxLength(4096);
            b.Property(x => x.PayloadPreviewText).HasColumnName("payload_preview_text").HasMaxLength(4096);
            b.Property(x => x.Truncated).HasColumnName("truncated").IsRequired();
            b.Property(x => x.FrameTime).HasColumnName("frame_time").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_tcp_traffic_tenant");
            b.HasIndex(x => x.ClientId).HasDatabaseName("idx_tcp_traffic_client");
            b.HasIndex(x => x.ListenPort).HasDatabaseName("idx_tcp_traffic_listen_port");
            b.HasIndex(x => x.ChannelId).HasDatabaseName("idx_tcp_traffic_channel");
            b.HasIndex(x => new { x.TenantId, x.ChannelId, x.Direction, x.StreamOffset })
                .HasDatabaseName("idx_tcp_traffic_stream");
            b.HasIndex(x => x.FrameTime).HasDatabaseName("idx_tcp_traffic_frame_time");
        });

        modelBuilder.Entity<PeerMeshDevice>(b =>
        {
            b.ToTable("peer_mesh_device");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.OwnerUsername).HasColumnName("owner_username").HasMaxLength(80).IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id").IsRequired();
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.VirtualIp).HasColumnName("virtual_ip").HasMaxLength(64).IsRequired();
            b.Property(x => x.Cidr).HasColumnName("cidr").HasMaxLength(64).IsRequired();
            b.Property(x => x.PublicKey).HasColumnName("public_key").HasMaxLength(256);
            b.Property(x => x.NatType).HasColumnName("nat_type").HasMaxLength(80);
            b.Property(x => x.NatMappingBehavior).HasColumnName("nat_mapping_behavior").HasMaxLength(80);
            b.Property(x => x.NatFilteringBehavior).HasColumnName("nat_filtering_behavior").HasMaxLength(80);
            b.Property(x => x.NatBehaviorDiscovery).HasColumnName("nat_behavior_discovery").HasMaxLength(40);
            b.Property(x => x.LastEndpoint).HasColumnName("last_endpoint").HasMaxLength(255);
            b.Property(x => x.VirtualDeviceMode).HasColumnName("virtual_device_mode").HasMaxLength(80);
            b.Property(x => x.VirtualDeviceName).HasColumnName("virtual_device_name").HasMaxLength(80);
            b.Property(x => x.VirtualDeviceStatus).HasColumnName("virtual_device_status").HasMaxLength(80);
            b.Property(x => x.VirtualDeviceError).HasColumnName("virtual_device_error").HasMaxLength(512);
            b.Property(x => x.VirtualDeviceUpdatedAt).HasColumnName("virtual_device_updated_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.Property(x => x.Enabled).HasColumnName("enabled").IsRequired();
            b.Property(x => x.LastSeenAt).HasColumnName("last_seen_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.TenantId, x.ClientId }).IsUnique()
                .HasDatabaseName("uk_peer_mesh_device_client");
            b.HasIndex(x => new { x.TenantId, x.VirtualIp }).IsUnique()
                .HasDatabaseName("uk_peer_mesh_device_ip");
            b.HasIndex(x => new { x.TenantId, x.OwnerUsername }).HasDatabaseName("idx_peer_mesh_device_owner");
            b.HasIndex(x => x.ClientName).HasDatabaseName("idx_peer_mesh_device_client_name");
        });

        modelBuilder.Entity<PeerMeshAcl>(b =>
        {
            b.ToTable("peer_mesh_acl");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.OwnerUsername).HasColumnName("owner_username").HasMaxLength(80).IsRequired();
            b.Property(x => x.SourceClientId).HasColumnName("source_client_id").IsRequired();
            b.Property(x => x.SourceClientName).HasColumnName("source_client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.TargetClientId).HasColumnName("target_client_id").IsRequired();
            b.Property(x => x.TargetClientName).HasColumnName("target_client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.Allowed).HasColumnName("allowed").IsRequired();
            b.Property(x => x.Direction).HasColumnName("direction").HasMaxLength(16).IsRequired()
                .HasDefaultValue("OUTBOUND");
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.TenantId, x.SourceClientId, x.TargetClientId }).IsUnique()
                .HasDatabaseName("uk_peer_mesh_acl_pair");
            b.HasIndex(x => new { x.TenantId, x.SourceClientId }).HasDatabaseName("idx_peer_mesh_acl_source");
            b.HasIndex(x => new { x.TenantId, x.TargetClientId }).HasDatabaseName("idx_peer_mesh_acl_target");
        });

        modelBuilder.Entity<PeerMeshSession>(b =>
        {
            b.ToTable("peer_mesh_session");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.SourceClientId).HasColumnName("source_client_id").IsRequired();
            b.Property(x => x.SourceClientName).HasColumnName("source_client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.TargetClientId).HasColumnName("target_client_id").IsRequired();
            b.Property(x => x.TargetClientName).HasColumnName("target_client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.PathType).HasColumnName("path_type").HasMaxLength(40).IsRequired();
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(40).IsRequired();
            b.Property(x => x.TokenHash).HasColumnName("token_hash").HasMaxLength(64);
            b.Property(x => x.StartedAt).HasColumnName("started_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ClosedAt).HasColumnName("closed_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.Property(x => x.RttMillis).HasColumnName("rtt_millis");
            b.Property(x => x.LocalEndpoint).HasColumnName("local_endpoint").HasMaxLength(255);
            b.Property(x => x.RemoteEndpoint).HasColumnName("remote_endpoint").HasMaxLength(255);
            b.Property(x => x.DirectBytes).HasColumnName("direct_bytes").IsRequired();
            b.Property(x => x.RelayBytes).HasColumnName("relay_bytes").IsRequired();
            b.Property(x => x.LastTrafficAt).HasColumnName("last_traffic_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_peer_mesh_session_tenant");
            b.HasIndex(x => new { x.TenantId, x.SourceClientId }).HasDatabaseName("idx_peer_mesh_session_source");
            b.HasIndex(x => new { x.TenantId, x.TargetClientId }).HasDatabaseName("idx_peer_mesh_session_target");
            b.HasIndex(x => x.Status).HasDatabaseName("idx_peer_mesh_session_status");
        });

        modelBuilder.Entity<ConnectionStat>(b =>
        {
            b.ToTable("specus_connection_stat");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).ValueGeneratedOnAdd();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.ClientId).HasColumnName("client_id");
            b.Property(x => x.ClientName).HasColumnName("client_name").HasMaxLength(120).IsRequired();
            b.Property(x => x.StatMonth).HasColumnName("stat_month").HasMaxLength(7).IsRequired();
            b.Property(x => x.TotalCount).HasColumnName("total_count").IsRequired();
            b.Property(x => x.SuccessCount).HasColumnName("success_count").IsRequired();
            b.Property(x => x.FailureCount).HasColumnName("failure_count").IsRequired();
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => x.TenantId).HasDatabaseName("idx_specus_connection_stat_tenant");
            b.HasIndex(x => new { x.TenantId, x.ClientName, x.StatMonth }).IsUnique()
                .HasDatabaseName("uk_specus_connection_stat");
            b.HasIndex(x => x.ClientName);
        });

        modelBuilder.Entity<TransferAttachment>(b =>
        {
            b.ToTable("transfer_attachment");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80);
            b.Property(x => x.Scope).HasColumnName("scope").HasMaxLength(40).IsRequired();
            b.Property(x => x.RoomId).HasColumnName("room_id").HasMaxLength(120);
            b.Property(x => x.RoomTokenHash).HasColumnName("room_token_hash").HasMaxLength(64);
            b.Property(x => x.OwnerUsername).HasColumnName("owner_username").HasMaxLength(80);
            b.Property(x => x.TargetClientId).HasColumnName("target_client_id");
            b.Property(x => x.ObjectKey).HasColumnName("object_key").HasMaxLength(512).IsRequired();
            b.Property(x => x.FileName).HasColumnName("file_name").HasMaxLength(255).IsRequired();
            b.Property(x => x.MimeType).HasColumnName("mime_type").HasMaxLength(120).IsRequired();
            b.Property(x => x.SizeBytes).HasColumnName("size_bytes").IsRequired();
            b.Property(x => x.Sha256).HasColumnName("sha256").HasMaxLength(64);
            b.Property(x => x.Status).HasColumnName("status").HasMaxLength(24).IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UpdatedAt).HasColumnName("updated_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UploadExpiresAt).HasColumnName("upload_expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.UploadedAt).HasColumnName("uploaded_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.HasIndex(x => new { x.TenantId, x.Scope, x.Id })
                .HasDatabaseName("idx_transfer_attachment_tenant");
            b.HasIndex(x => new { x.Scope, x.RoomId, x.Id })
                .HasDatabaseName("idx_transfer_attachment_room");
            b.HasIndex(x => new { x.TenantId, x.OwnerUsername, x.Status, x.ExpiresAt })
                .HasDatabaseName("idx_transfer_attachment_owner_status");
            b.HasIndex(x => new { x.ExpiresAt, x.Status })
                .HasDatabaseName("idx_transfer_attachment_expires");
        });

        modelBuilder.Entity<TransferAttachmentDownloadUsage>(b =>
        {
            b.ToTable("transfer_attachment_download_usage");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(80).IsRequired();
            b.Property(x => x.AttachmentId).HasColumnName("attachment_id").IsRequired();
            b.Property(x => x.SizeBytes).HasColumnName("size_bytes").IsRequired();
            b.Property(x => x.UsageMonth).HasColumnName("usage_month").HasMaxLength(7).IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.HasIndex(x => new { x.TenantId, x.Username, x.UsageMonth })
                .HasDatabaseName("idx_attachment_download_usage_account_month");
            b.HasIndex(x => new { x.AttachmentId, x.CreatedAt })
                .HasDatabaseName("idx_attachment_download_usage_attachment");
        });

        modelBuilder.Entity<TransferAttachmentDownloadGrant>(b =>
        {
            b.ToTable("transfer_attachment_download_grant");
            b.HasKey(x => x.Id);
            b.Property(x => x.Id).HasColumnName("id").ValueGeneratedNever();
            b.Property(x => x.TokenHash).HasColumnName("token_hash").HasMaxLength(64).IsRequired();
            b.Property(x => x.TenantId).HasColumnName("tenant_id").HasMaxLength(80).IsRequired();
            b.Property(x => x.Username).HasColumnName("username").HasMaxLength(80).IsRequired();
            b.Property(x => x.AttachmentId).HasColumnName("attachment_id").IsRequired();
            b.Property(x => x.CreatedAt).HasColumnName("created_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ExpiresAt).HasColumnName("expires_at").HasMaxLength(40).IsRequired()
                .HasConversion(iso);
            b.Property(x => x.ConsumedAt).HasColumnName("consumed_at").HasMaxLength(40)
                .HasConversion(isoNullable);
            b.HasIndex(x => x.TokenHash).IsUnique();
            b.HasIndex(x => new { x.AttachmentId, x.CreatedAt })
                .HasDatabaseName("idx_attachment_download_grant_attachment");
            b.HasIndex(x => new { x.ExpiresAt, x.ConsumedAt })
                .HasDatabaseName("idx_attachment_download_grant_expiry");
        });
    }
}
