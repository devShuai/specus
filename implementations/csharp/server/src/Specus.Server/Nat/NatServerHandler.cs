using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Management;

namespace Specus.Server.Nat;

public sealed class NatServerHandler
{
    private readonly ConcurrentDictionary<SpecusConnectionContext, NatClientSession> _sessions = new();
    private readonly ConcurrentDictionary<string, NatClientSession> _sessionsByName =
        new(StringComparer.Ordinal);
    private readonly RemotePortServerManager _remotePorts;
    private readonly TrafficUsageService _traffic;
    private readonly TrafficInspectionService _inspection;
    private readonly IOptions<NettyServerOptions> _options;
    private readonly ILoggerFactory _loggerFactory;

    public NatServerHandler(RemotePortServerManager remotePorts,
        TrafficUsageService traffic,
        TrafficInspectionService inspection,
        IOptions<NettyServerOptions> options,
        ILoggerFactory loggerFactory)
    {
        _remotePorts = remotePorts;
        _traffic = traffic;
        _inspection = inspection;
        _options = options;
        _loggerFactory = loggerFactory;
    }

    public Task HandleAsync(SpecusConnectionContext context, NatMessagePacket packet)
    {
        var session = GetOrAttach(context);
        return session.HandleAsync(packet);
    }

    public void Attach(SpecusConnectionContext context) => GetOrAttach(context);

    private NatClientSession GetOrAttach(SpecusConnectionContext context)
    {
        var session = _sessions.GetOrAdd(context, CreateSession);
        if (!string.IsNullOrWhiteSpace(context.ClientName))
        {
            _sessionsByName[context.ClientName] = session;
        }
        return session;
    }

    internal Task<HttpSpecusStream> OpenHttpStreamAsync(string clientName,
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        if (!_sessionsByName.TryGetValue(clientName, out var session))
        {
            throw new InvalidOperationException($"client is offline: {clientName}");
        }
        return session.OpenHttpStreamAsync(metadata, cancellationToken);
    }

    public async Task OnConnectionClosedAsync(SpecusConnectionContext context)
    {
        if (_sessions.TryRemove(context, out var session))
        {
            if (context.ClientName is { } name)
            {
                _sessionsByName.TryRemove(new KeyValuePair<string, NatClientSession>(name, session));
            }
            await session.DisposeAsync().ConfigureAwait(false);
        }
    }

    private NatClientSession CreateSession(SpecusConnectionContext context) =>
        new(context, _remotePorts, _traffic, _inspection, _options, _loggerFactory,
            _loggerFactory.CreateLogger<NatClientSession>());
}
