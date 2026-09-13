using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Updates;
using Specus.Client.Cli;
using System.Text.Json;

ClientCliOptions options;
try
{
    options = ClientCliOptions.Parse(args);
}
catch (ArgumentException error)
{
    return CliOutput.Result(args.Contains("--json"), "arguments", 2, null, $"specus-client: {error.Message}");
}

if (options.Help)
{
    return CliOutput.Result(options.Json, "help", 0, new { help = ClientCliOptions.HelpText }, ClientCliOptions.HelpText);
}
if (options.Version)
{
    return CliOutput.Result(options.Json, "version", 0, new { version = ClientVersion.Current }, ClientVersion.Current);
}
var configPath = Path.GetFullPath(options.ConfigPath ?? "client.jsonc");
if (options.Command is "status" or "peers" or "services" or "egress") return CliState.Query(configPath, options);
if (options.Command == "ui") return await LocalUi.RunAsync(options, configPath);
SpecusClientConfig config;
try
{
    config = SpecusClientConfigLoader.Load(options.ConfigPath, warning => Console.Error.WriteLine($"Warning: {warning}"));
}
catch (Exception error) when (error is IOException or InvalidDataException or UnauthorizedAccessException or JsonException or ArgumentException)
{
    var detail = error is JsonException json
        ? $"Invalid JSONC at line {json.LineNumber + 1}, column {json.BytePositionInLine + 1}."
        : error.Message;
    return CliOutput.Result(options.Json, options.Command, 2, null, $"specus-client: {configPath}: {detail}\nCheck the configuration or run --help for usage.");
}
if (options.Command == "validate")
{
    return CliOutput.Result(options.Json, "config validate", 0, new { configPath, offline = true }, $"Configuration valid: {configPath} (offline; connectivity not tested)");
}
if (options.AutoUpdate) { config.AutoUpdate = true; config.UpdateEnabled = true; }
if (options.NoUpdate) { config.AutoUpdate = false; config.UpdateEnabled = false; }
if (options.Command == "show")
{
    var effective = CliOutput.RedactedConfig(config);
    return CliOutput.Result(options.Json, "config show", 0, new { configPath, config = effective }, configPath + "\n" + effective.ToJsonString(new() { WriteIndented = true }));
}
if (options.Command == "doctor")
{
    var scope = options.Probe ? "server-tcp" : "offline";
    var data = new { configPath, scope, authenticationTested = false, businessTested = false };
    if (options.Probe)
    {
        try
        {
            var uri = new Uri(config.ServerBaseUrl);
            using var connection = new System.Net.Sockets.TcpClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await connection.ConnectAsync(uri.Host, uri.Port, timeout.Token);
        }
        catch (Exception error) when (error is System.Net.Sockets.SocketException or OperationCanceledException)
        { return CliOutput.Result(options.Json, "doctor", 4, data, "Server TCP probe failed or timed out. Check DNS, proxy, firewall and server availability; authentication was not attempted."); }
    }
    return CliOutput.Result(options.Json, "doctor", 0, data, $"Doctor passed ({scope}); authentication, TLS and business readiness not tested.");
}

CliState cliState;
try { cliState = new CliState(configPath); }
catch (Exception error) when (error is IOException or UnauthorizedAccessException)
{ Console.Error.WriteLine("Cannot create private CLI state. Check SPECUS_CLI_STATE_DIR permissions."); return 2; }
using var stateLifetime = cliState;
var builder = Host.CreateApplicationBuilder();
builder.Logging.ClearProviders();
builder.Logging.SetMinimumLevel(options.Debug ? LogLevel.Debug : LogLevel.Information);
builder.Services.Configure<ConsoleLoggerOptions>(options => options.LogToStandardErrorThreshold = LogLevel.Trace);
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "HH:mm:ss ";
});
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(_ => new ClientHttpTransports(
    ClientAuthService.BuildDefaultClient(),
    DirectHttpForwarder.BuildDefaultClient()));
builder.Services.AddSingleton(sp => new ClientAuthService(
    sp.GetRequiredService<SpecusClientConfig>(),
    sp.GetRequiredService<ClientHttpTransports>().Authentication,
    sp.GetRequiredService<ILogger<ClientAuthService>>()) { InitialLoginTimeout = TimeSpan.FromSeconds(options.LoginTimeout) });
builder.Services.AddSingleton(sp => new DirectHttpForwarder(
    sp.GetRequiredService<ClientHttpTransports>().RouteForwarding));
builder.Services.AddSingleton(sp => new SpecusControlClient(
    sp.GetRequiredService<SpecusClientConfig>(),
    sp.GetRequiredService<ClientAuthService>(),
    sp.GetRequiredService<DirectHttpForwarder>(),
    sp.GetRequiredService<ILoggerFactory>(), cliState));
builder.Services.AddSingleton<ClientUpdateService>();
builder.Services.AddSingleton<IClientUpdateService>(sp =>
    sp.GetRequiredService<ClientUpdateService>());
builder.Services.AddSingleton<ClientExitStatus>();
builder.Services.AddHostedService(sp => new ClientRunHostedService(
    sp.GetRequiredService<SpecusControlClient>().RunAsync,
    sp.GetRequiredService<IHostApplicationLifetime>(),
    sp.GetRequiredService<ClientExitStatus>(),
    sp.GetRequiredService<ILogger<ClientRunHostedService>>()));
builder.Services.AddHostedService<ClientUpdateHostedService>();

using var host = builder.Build();
host.Services.GetRequiredService<ILoggerFactory>()
    .CreateLogger("specus-client")
    .LogInformation("loaded config from {path}", SpecusClientConfigLoader.ResolvePath(options.ConfigPath));
var exitStatus = host.Services.GetRequiredService<ClientExitStatus>();
await host.RunAsync();
return exitStatus.Code;

internal sealed class ClientHttpTransports(HttpClient authentication, HttpClient routeForwarding)
    : IDisposable
{
    public HttpClient Authentication { get; } = authentication;

    public HttpClient RouteForwarding { get; } = routeForwarding;

    public void Dispose()
    {
        Authentication.Dispose();
        RouteForwarding.Dispose();
    }
}
