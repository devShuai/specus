using Microsoft.EntityFrameworkCore;
using Specus.Server.Authentication;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Hosting;
using Specus.Server.Http;
using Specus.Server.Management;
using Specus.Server.Nat;
using Specus.Server.PeerMesh;
using Specus.Server.Security;
using Specus.Server.Services;
using Specus.Server.Sessions;
using Specus.Server.WebSockets;

var builder = WebApplication.CreateBuilder(args);

// Configuration --------------------------------------------------------------------------------

builder.Configuration.AddSpecusEnvironmentVariables();

// Wire option groups under the Specus:* prefix. Mirrors Java's @ConfigurationProperties.
builder.Services.Configure<NettyServerOptions>(
    builder.Configuration.GetSection(NettyServerOptions.SectionName));
builder.Services.Configure<SpecusOptions>(
    builder.Configuration.GetSection(SpecusOptions.SectionName));
builder.Services.Configure<LoginExecutorOptions>(
    builder.Configuration.GetSection(LoginExecutorOptions.SectionName));
builder.Services.Configure<DatabaseOptions>(
    builder.Configuration.GetSection(DatabaseOptions.SectionName));
builder.Services.Configure<AuthOptions>(
    builder.Configuration.GetSection(AuthOptions.SectionName));
builder.Services.Configure<ClientAuthOptions>(
    builder.Configuration.GetSection(ClientAuthOptions.SectionName));
builder.Services.Configure<ConnectionRecordOptions>(
    builder.Configuration.GetSection(ConnectionRecordOptions.SectionName));
builder.Services.Configure<TrafficOptions>(
    builder.Configuration.GetSection(TrafficOptions.SectionName));
builder.Services.Configure<ElasticsearchOptions>(
    builder.Configuration.GetSection(ElasticsearchOptions.SectionName));
builder.Services.Configure<DirectHttpOptions>(
    builder.Configuration.GetSection(DirectHttpOptions.SectionName));
builder.Services.Configure<PublicTransferOptions>(
    builder.Configuration.GetSection(PublicTransferOptions.SectionName));
builder.Services.Configure<ObjectStorageOptions>(
    builder.Configuration.GetSection(ObjectStorageOptions.SectionName));
builder.Services.Configure<PeerMeshOptions>(
    builder.Configuration.GetSection(PeerMeshOptions.SectionName));
builder.Services.Configure<OidcOptions>(
    builder.Configuration.GetSection(OidcOptions.SectionName));
builder.Services.Configure<TlsOptions>(
    builder.Configuration.GetSection(TlsOptions.SectionName));

builder.WebHost.ConfigureKestrel((context, kestrel) =>
{
    var tls = context.Configuration.GetSection(TlsOptions.SectionName).Get<TlsOptions>() ?? new TlsOptions();
    var certificate = TlsCertificateLoader.LoadServerCertificate(tls);
    if (certificate is not null)
    {
        kestrel.ConfigureEndpointDefaults(endpoint => endpoint.UseHttps(certificate));
    }
});

// Persistence ---------------------------------------------------------------------------------

builder.Services.AddDbContext<SpecusDbContext>(options =>
{
    var cs = builder.Configuration.GetConnectionString("Specus")
        ?? "Data Source=./specus.db";
    var provider = builder.Configuration[$"{DatabaseOptions.SectionName}:Provider"] ?? "sqlite";
    switch (provider.Trim().ToLowerInvariant())
    {
        case "postgres":
        case "postgresql":
        case "npgsql":
            options.UseNpgsql(cs, o => o.MigrationsAssembly("Specus.Server.Data.Postgres"));
            break;
        case "mysql":
        case "mariadb":
            options.UseMySQL(cs, o => o.MigrationsAssembly("Specus.Server.Data.MySql"));
            break;
        case "sqlite":
            // Migrations for SQLite live in the Data project itself.
            options.UseSqlite(cs, o => o.MigrationsAssembly("Specus.Server.Data"));
            break;
        default:
            throw new InvalidOperationException(
                $"Unknown {DatabaseOptions.SectionName}:Provider '{provider}'. " +
                "Use 'sqlite', 'postgres', or 'mysql'.");
    }
});

builder.Services.AddScoped<ClientAccountService>();
builder.Services.AddScoped<ConnectionRecordService>();
builder.Services.AddScoped<NatControlService>();
builder.Services.AddScoped<ManagementQueryService>();
builder.Services.AddScoped<ManagementMutationService>();
builder.Services.AddScoped<ManagementUserService>();
builder.Services.AddScoped<RegistrationService>();
builder.Services.AddSingleton<IRegistrationEmailSender, SmtpRegistrationEmailSender>();
builder.Services.AddSingleton<ITurnstileVerifier, TurnstileVerifier>();
builder.Services.AddHostedService<RegistrationChallengeCleanupService>();
builder.Services.AddSingleton<TurnCredentialService>();
builder.Services.AddScoped<PeerMeshService>();
builder.Services.AddHostedService<StunTurnServer>();
builder.Services.AddHostedService<PeerMeshRelayTrafficFlushService>();
builder.Services.AddSingleton<ElasticsearchTrafficDetailClient>();
builder.Services.AddSingleton<IObjectStorageService, AliyunOssObjectStorageService>();
builder.Services.AddSingleton<PublicTransferCoordinationService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<PublicTransferCoordinationService>());
builder.Services.AddSingleton<PublicTransferRateLimiter>();
builder.Services.AddHostedService<PublicTransferRateLimiterCleanupService>();
builder.Services.AddScoped<TransferAttachmentService>();
builder.Services.AddHostedService<TransferAttachmentExpirationService>();
builder.Services.AddSingleton<TrafficInspectionService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<TrafficInspectionService>());
builder.Services.AddHttpClient();
builder.Services.AddHttpClient(nameof(TurnstileVerifier), client =>
    client.Timeout = TimeSpan.FromSeconds(8));
builder.Services.AddHttpClient(nameof(AliyunOssObjectStorageService))
    .ConfigurePrimaryHttpMessageHandler(AliyunOssObjectStorageService.CreateNoRedirectHandler);

builder.Services.AddSingleton<ClientAuthSessionStore>();
builder.Services.AddSingleton<LocalTokenService>();
builder.Services.AddSingleton<AdminBearerTokenValidator>();
builder.Services.AddSingleton<WebSocketTicketService>();
builder.Services.AddSingleton<OidcTokenValidator>();
builder.Services.AddSingleton<IOidcJwkProvider, HttpOidcJwkProvider>();
builder.Services.AddSingleton<OidcTokenExchangeService>();
builder.Services.AddSingleton<IOidcTokenEndpointClient, HttpOidcTokenEndpointClient>();
builder.Services.AddSingleton<DatabaseInitializer>();
builder.Services.AddSingleton<ConnectionArchiveService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ConnectionArchiveService>());

// Control-channel pipeline --------------------------------------------------------------------

builder.Services.AddSingleton<SessionRegistry>();
builder.Services.AddSingleton<LoginExecutor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<LoginExecutor>());
builder.Services.AddSingleton<RemotePortServerManager>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<RemotePortServerManager>());
builder.Services.AddSingleton<TrafficUsageService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<TrafficUsageService>());
builder.Services.AddSingleton<NatServerHandler>();
builder.Services.AddSingleton<DirectHttpDispatcher>();
builder.Services.AddSingleton<ConnectionEventsHub>();
builder.Services.AddSingleton<ClientMessagesHub>();
builder.Services.AddSingleton<PublicTransferDiscoveryHub>();
builder.Services.AddHostedService<PublicTransferPresenceRefreshService>();
builder.Services.AddSingleton<ControlChannelTlsProvider>();
builder.Services.AddSingleton<IControlChannelDispatcher, ControlChannelDispatcher>();
builder.Services.AddSingleton<ControlChannelListener>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ControlChannelListener>());

var app = builder.Build();

// Boot-time DB migration + demo seed.
using (var scope = app.Services.CreateScope())
{
    var initializer = scope.ServiceProvider.GetRequiredService<DatabaseInitializer>();
    await initializer.InitializeAsync(app.Lifetime.ApplicationStopping);
}

app.UseManagementSecurityHeaders();
app.UseAdminApiExceptionHandling();
app.UseAdminApiAuthentication();
app.UseWebSockets();

// Management SPA: same static contract as Java's resources/static. Root redirects to the real
// static asset so ASP.NET Core can still apply generated ETag/compression/fingerprint metadata.
app.MapGet("/", () => Results.LocalRedirect("/index.html"));
app.MapStaticAssets();

app.MapAdminApi();
app.MapClientAuthApi();
app.MapTransferAttachmentApi();
app.MapWebSocketTicketApi();
app.MapDirectHttpSpecus();
app.MapConnectionEventsWebSocket();
app.MapClientMessagesWebSocket();
app.MapPublicTransferDiscoveryWebSocket();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.Run();

// Make the implicit Program class public so the integration tests can spin it up via
// WebApplicationFactory.
public partial class Program;
