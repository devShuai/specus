using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
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
builder.Services.Configure<MediaCaptureOptions>(
    builder.Configuration.GetSection(MediaCaptureOptions.SectionName));
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
    var databaseOptions = builder.Configuration.GetSection(DatabaseOptions.SectionName)
        .Get<DatabaseOptions>() ?? new DatabaseOptions();
    var database = DatabaseConfiguration.Resolve(databaseOptions,
        builder.Configuration.GetConnectionString("Specus"));
    switch (database.Provider)
    {
        case "postgres":
            options.UseNpgsql(database.ConnectionString, o =>
            {
                o.MigrationsAssembly("Specus.Server.Data.Postgres");
                o.MaxBatchSize(database.BatchSize);
            });
            break;
        case "mysql":
            options.UseMySQL(database.ConnectionString, o =>
            {
                o.MigrationsAssembly("Specus.Server.Data.MySql");
                o.MaxBatchSize(database.BatchSize);
            });
            break;
        case "sqlite":
            // Migrations for SQLite live in the Data project itself.
            options.UseSqlite(database.ConnectionString, o =>
            {
                o.MigrationsAssembly("Specus.Server.Data");
                o.MaxBatchSize(database.BatchSize);
            });
            break;
        default:
            throw new InvalidOperationException($"Unknown database provider '{database.Provider}'.");
    }
});

builder.Services.AddScoped<ClientAccountService>();
builder.Services.AddScoped<ConnectionRecordService>();
builder.Services.AddScoped<NatControlService>();
builder.Services.AddScoped<ManagementQueryService>();
builder.Services.AddScoped<ManagementMutationService>();
builder.Services.AddScoped<ManagementUserService>();
builder.Services.AddScoped<UserDiagramDocumentService>();
builder.Services.AddScoped<PublicTransferRoomService>();
builder.Services.AddScoped<RegistrationService>();
builder.Services.AddSingleton<IRegistrationEmailSender, SmtpRegistrationEmailSender>();
builder.Services.AddSingleton<ITurnstileVerifier, TurnstileVerifier>();
builder.Services.AddSingleton<LoginRateLimiter>();
builder.Services.AddSingleton<ClientAddressResolver>();
builder.Services.AddHostedService<RegistrationChallengeCleanupService>();
builder.Services.AddSingleton<TurnCredentialService>();
builder.Services.AddScoped<PeerMeshService>();
builder.Services.AddHostedService<StunTurnServer>();
builder.Services.AddHostedService<PeerMeshRelayTrafficFlushService>();
builder.Services.AddSingleton<ElasticsearchTrafficDetailClient>();
builder.Services.AddSingleton<IObjectStorageService, AliyunOssObjectStorageService>();
builder.Services.AddSingleton<IHttpMediaStorage, RustFsMediaStorage>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddHostedService<HttpMediaStorageInitializer>();
builder.Services.AddSingleton<HttpMediaUploadScheduler>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<HttpMediaUploadScheduler>());
builder.Services.AddScoped<HttpMediaCaptureService>();
builder.Services.AddScoped<HttpMediaPlaybackService>();
builder.Services.AddSingleton<HttpMediaPlaybackTicketService>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<HttpMediaPlaybackTicketService>());
builder.Services.AddHostedService<HttpMediaCaptureCleanupService>();
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
builder.Services.AddHttpClient(nameof(RustFsMediaStorage), client =>
        client.Timeout = Timeout.InfiniteTimeSpan)
    .ConfigurePrimaryHttpMessageHandler(RustFsMediaStorage.CreateNoRedirectHandler);

builder.Services.AddSingleton<ClientAuthSessionStore>();
builder.Services.AddSingleton<LocalTokenService>();
builder.Services.AddScoped<AdminBearerTokenValidator>();
builder.Services.AddSingleton<WebSocketTicketService>();
builder.Services.AddSingleton<OidcTokenValidator>();
builder.Services.AddSingleton<IOidcJwkProvider, HttpOidcJwkProvider>();
builder.Services.AddScoped<OidcTokenExchangeService>();
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

// Refuse to start a production deployment that still carries a shipped default credential.
{
    var specusOptions = app.Services.GetRequiredService<IOptions<SpecusOptions>>().Value;
    var authOptions = app.Services.GetRequiredService<IOptions<AuthOptions>>().Value;
    var environment = DeploymentEnvironments.Parse(specusOptions.Env);
    var violation = DeploymentEnvironments.DescribeSecurityBaselineViolation(
        environment, authOptions.PasswordLoginEnabled, authOptions.Password);
    if (violation is not null)
    {
        throw new InvalidOperationException(violation);
    }
    if (DeploymentEnvironments.IsKnownDefaultPassword(authOptions.Password))
    {
        app.Logger.LogWarning(
            "[security-baseline] Specus:Auth:Password is a known default credential; prod would refuse to start");
    }
}

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
app.MapHttpMediaApi();
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
