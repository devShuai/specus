using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;

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

var config = TunnelClientConfigLoader.Load(overridePath);

var builder = Host.CreateApplicationBuilder(args);
builder.Logging.AddSimpleConsole(options =>
{
    options.IncludeScopes = false;
    options.TimestampFormat = "HH:mm:ss ";
});
builder.Services.AddSingleton(config);
builder.Services.AddSingleton(_ => DirectHttpForwarder.BuildDefaultClient());
builder.Services.AddSingleton(sp => new DirectHttpForwarder(sp.GetRequiredService<HttpClient>()));
builder.Services.AddSingleton(sp => new TunnelControlClient(
    sp.GetRequiredService<TunnelClientConfig>(),
    sp.GetRequiredService<DirectHttpForwarder>(),
    sp.GetRequiredService<ILoggerFactory>()));
builder.Services.AddHostedService<TunnelClientHostedService>();

var host = builder.Build();
host.Services.GetRequiredService<ILoggerFactory>()
    .CreateLogger("shuai-tunnel-client")
    .LogInformation("loaded config from {path}", TunnelClientConfigLoader.ResolvePath(overridePath));
await host.RunAsync();

internal sealed class TunnelClientHostedService : BackgroundService
{
    private readonly TunnelControlClient _client;

    public TunnelClientHostedService(TunnelControlClient client)
    {
        _client = client;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) => _client.RunAsync(stoppingToken);
}
