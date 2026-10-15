using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Management;
using Specus.Server.Sessions;

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
    private readonly SessionRegistry _registry;
    private readonly object _namespaceLock = new();

    public NatServerHandler(RemotePortServerManager remotePorts,
        TrafficUsageService traffic,
        TrafficInspectionService inspection,
        IOptions<NettyServerOptions> options,
        ILoggerFactory loggerFactory, SessionRegistry registry)
    {
        _remotePorts = remotePorts;
        _traffic = traffic;
        _inspection = inspection;
        _options = options;
        _loggerFactory = loggerFactory;
        _registry = registry;
    }

    internal Func<SpecusConnectionContext, Task>? HandlingForTests { get; set; }
    internal Action<NatClientSession>? SessionCreatedForTests { get; set; }

    public async Task HandleAsync(SpecusConnectionContext context, NatMessagePacket packet)
    {
        if (HandlingForTests is { } handling) await handling(context).ConfigureAwait(false);
        NatClientSession? session;
        lock (_namespaceLock)
        {
            if (_registry.CurrentDataControl(context) is null
                || !_sessions.TryGetValue(context, out session)
                || context.ClientName is not { } name
                || !_sessionsByName.TryGetValue(name, out var current) || !ReferenceEquals(current, session))
                return;
        }
        await session.HandleAsync(packet).ConfigureAwait(false);
    }

    /// <summary>Runs at the end of <see cref="Attach"/>, so a test can hold a data login there.</summary>
    internal Action<SpecusConnectionContext>? AttachedForTests { get; set; }

    public void Attach(SpecusConnectionContext context)
    {
        context.Lifetime.ThrowIfCancellationRequested();
        if (context.PairedControl is not { } control || control.Lifetime.IsCancellationRequested
            || !ReferenceEquals(_registry.Find(context.ClientName!), control))
            throw new InvalidOperationException("data control connection is not current");
        lock (_namespaceLock)
        {
            if (_sessionsByName.ContainsKey(context.ClientName!))
                throw new InvalidOperationException("previous data namespace has not retired");
            var session = CreateSession(context);
            SessionCreatedForTests?.Invoke(session);
            _sessions[context] = session;
            _sessionsByName[context.ClientName!] = session;
        }
        AttachedForTests?.Invoke(context);
    }

    // Authenticated login only, outside the new socket's write lock. Complete irreversible
    // retirement (including old listener/budget release) before publishing its successor.
    internal async Task RetireCurrentAsync(string clientName)
    {
        NatClientSession? session;
        lock (_namespaceLock)
        {
            if (!_sessionsByName.TryRemove(clientName, out session)) return;
            _sessions.TryRemove(new KeyValuePair<SpecusConnectionContext, NatClientSession>(session.Context, session));
        }
        session.Context.CloseAsync();
        await session.DisposeAsync().ConfigureAwait(false);
    }

    internal Task<HttpSpecusStream> OpenHttpStreamAsync(string clientName,
        Dictionary<string, object?> metadata, CancellationToken cancellationToken,
        bool discardResponseBody = false)
    {
        if (!_sessionsByName.TryGetValue(clientName, out var session))
        {
            throw new InvalidOperationException($"client is offline: {clientName}");
        }
        return session.OpenHttpStreamAsync(metadata, cancellationToken, discardResponseBody);
    }

    internal Task<WebSocketSpecusStream> OpenWebSocketStreamAsync(string clientName,
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        if (!_sessionsByName.TryGetValue(clientName, out var session))
        {
            throw new InvalidOperationException($"client is offline: {clientName}");
        }
        return session.OpenWebSocketStreamAsync(metadata, cancellationToken);
    }

    public async Task OnConnectionClosedAsync(SpecusConnectionContext context)
    {
        NatClientSession? session;
        lock (_namespaceLock)
        {
            // Keep the old namespace discoverable by login retirement until its shared
            // disposal task finishes; otherwise replacement could miss in-flight teardown.
            if (!_sessions.TryGetValue(context, out session)) return;
        }
        await session.DisposeAsync().ConfigureAwait(false);
        lock (_namespaceLock)
        {
            _sessions.TryRemove(new KeyValuePair<SpecusConnectionContext, NatClientSession>(context, session));
            if (context.ClientName is { } name)
            {
                _sessionsByName.TryRemove(new KeyValuePair<string, NatClientSession>(name, session));
            }
        }
    }

    private NatClientSession CreateSession(SpecusConnectionContext context) =>
        new(context, _remotePorts, _traffic, _inspection, _options, _loggerFactory,
            _loggerFactory.CreateLogger<NatClientSession>());
}
