using Microsoft.EntityFrameworkCore;
using ShuaiTunnel.Server.Authentication;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Hosting;
using ShuaiTunnel.Server.Http;
using ShuaiTunnel.Server.Management;
using ShuaiTunnel.Server.Nat;
using ShuaiTunnel.Server.Security;
using ShuaiTunnel.Server.Services;
using ShuaiTunnel.Server.Sessions;
using ShuaiTunnel.Server.WebSockets;

var builder = WebApplication.CreateBuilder(args);

// Configuration --------------------------------------------------------------------------------

builder.Configuration.AddTunnelEnvironmentVariables();

// Wire option groups under the Tunnel:* prefix. Mirrors Java's @ConfigurationProperties.
builder.Services.Configure<NettyServerOptions>(
    builder.Configuration.GetSection(NettyServerOptions.SectionName));
builder.Services.Configure<TunnelOptions>(
    builder.Configuration.GetSection(TunnelOptions.SectionName));
builder.Services.Configure<LoginExecutorOptions>(
    builder.Configuration.GetSection(LoginExecutorOptions.SectionName));
builder.Services.Configure<DatabaseOptions>(
    builder.Configuration.GetSection(DatabaseOptions.SectionName));
builder.Services.Configure<AuthOptions>(
    builder.Configuration.GetSection(AuthOptions.SectionName));
builder.Services.Configure<TrafficOptions>(
    builder.Configuration.GetSection(TrafficOptions.SectionName));
builder.Services.Configure<DirectHttpOptions>(
    builder.Configuration.GetSection(DirectHttpOptions.SectionName));

// Persistence ---------------------------------------------------------------------------------

builder.Services.AddDbContext<TunnelDbContext>(options =>
{
    var cs = builder.Configuration.GetConnectionString("Tunnel")
        ?? "Data Source=./shuai-tunnel.db";
    options.UseSqlite(cs);
});

builder.Services.AddScoped<ClientAccountService>();
builder.Services.AddScoped<ConnectionRecordService>();
builder.Services.AddScoped<NatControlService>();
builder.Services.AddScoped<ManagementQueryService>();
builder.Services.AddScoped<ManagementMutationService>();

builder.Services.AddSingleton<LocalTokenService>();
builder.Services.AddSingleton<DatabaseInitializer>();

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

app.UseAdminApiExceptionHandling();
app.UseAdminApiAuthentication();
app.MapAdminApi();
app.MapDirectHttpTunnel();
app.MapConnectionEventsWebSocket();

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.Run();

// Make the implicit Program class public so the integration tests can spin it up via
// WebApplicationFactory.
public partial class Program;
