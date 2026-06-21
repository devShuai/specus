using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.ControlChannel;

namespace ShuaiTunnel.Server.Nat;

public sealed class NatServerHandler
{
    private readonly ConcurrentDictionary<TunnelConnectionContext, NatClientSession> _sessions = new();
    private readonly RemotePortServerManager _remotePorts;
    private readonly TrafficUsageService _traffic;
    private readonly IOptions<NettyServerOptions> _options;
    private readonly ILoggerFactory _loggerFactory;

    public NatServerHandler(RemotePortServerManager remotePorts,
        TrafficUsageService traffic,
        IOptions<NettyServerOptions> options,
        ILoggerFactory loggerFactory)
    {
        _remotePorts = remotePorts;
        _traffic = traffic;
        _options = options;
        _loggerFactory = loggerFactory;
    }

    public Task HandleAsync(TunnelConnectionContext context, NatMessagePacket packet)
    {
        var session = _sessions.GetOrAdd(context, CreateSession);
        return session.HandleAsync(packet);
    }

    public async Task OnConnectionClosedAsync(TunnelConnectionContext context)
    {
        if (_sessions.TryRemove(context, out var session))
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
    }

    private NatClientSession CreateSession(TunnelConnectionContext context) =>
        new(context, _remotePorts, _traffic, _options, _loggerFactory,
            _loggerFactory.CreateLogger<NatClientSession>());
}
