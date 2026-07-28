using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;

string? overridePath = null;
for (var i = 0; i < args.Length; i++)
{
    if ((args[i] == "-c" || args[i] == "--config") && i + 1 < args.Length)
    {
        overridePath = args[++i];
    }
    else if (args[i].StartsWith("--config=", StringComparison.Ordinal))
    {
        overridePath = args[i]["--config=".Length..];
    }
}

var config = SpecusClientConfigLoader.Load(overridePath);

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "HH:mm:ss ";
});
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(_ => DirectHttpForwarder.BuildDefaultClient());
builder.Services.AddSingleton<ClientAuthService>();
builder.Services.AddSingleton(sp => new DirectHttpForwarder(sp.GetRequiredService<HttpClient>()));
builder.Services.AddSingleton(sp => new SpecusControlClient(
    sp.GetRequiredService<SpecusClientConfig>(),
    sp.GetRequiredService<ClientAuthService>(),
    sp.GetRequiredService<DirectHttpForwarder>(),
    sp.GetRequiredService<ILoggerFactory>()));
builder.Services.AddHostedService<SpecusClientHostedService>();

var host = builder.Build();
host.Services.GetRequiredService<ILoggerFactory>()
    .CreateLogger("specus-client")
    .LogInformation("loaded config from {path}", SpecusClientConfigLoader.ResolvePath(overridePath));
await host.RunAsync();

internal sealed class SpecusClientHostedService : BackgroundService
{
    private readonly SpecusControlClient _client;

    public SpecusClientHostedService(SpecusControlClient client)
    {
        _client = client;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _client.RunAsync(stoppingToken);
}
