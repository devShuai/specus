using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Sessions;

/// <summary>
/// Lookup table from <c>clientName → connection</c>. Mirrors Java's <c>SessionUtil</c>.
///
/// <para>The interesting invariant: a successful login from a name that already has an open
/// session displaces the prior connection. We stamp <c>REPLACED_BY_NEW_LOGIN</c> on the old
/// context so its close path writes the right reason — then trigger close.</para>
///
/// <para>Process-wide singleton (registered with <see cref="Microsoft.Extensions.DependencyInjection.ServiceLifetime.Singleton"/>).</para>
/// </summary>
public sealed class SessionRegistry
{
    private readonly ConcurrentDictionary<string, TunnelConnectionContext> _byName = new(StringComparer.Ordinal);
    private readonly ILogger<SessionRegistry> _logger;

    public SessionRegistry(ILogger<SessionRegistry> logger)
    {
        _logger = logger;
    }

    public TunnelConnectionContext? Find(string clientName) =>
        _byName.TryGetValue(clientName, out var context) ? context : null;

    /// <summary>
    /// Race-free swap that returns whatever it displaces. The displaced context is stamped
    /// <c>REPLACED_BY_NEW_LOGIN</c>; the caller is responsible for asking that connection to
    /// close (typically via <see cref="ControlChannel.TunnelConnectionContext.CloseAsync"/>).
    /// </summary>
    public TunnelConnectionContext? Replace(string clientName, TunnelConnectionContext newContext)
    {
        TunnelConnectionContext? prior = null;
        _byName.AddOrUpdate(clientName,
            _ => newContext,
            (_, existing) =>
            {
                prior = existing;
                return newContext;
            });
        if (prior is not null && !ReferenceEquals(prior, newContext))
        {
            prior.MarkDisconnectIfAbsent(DisconnectReason.ReplacedByNewLogin);
            _logger.LogInformation("session replaced: client={ClientName} oldChannel={Old} newChannel={New}",
                clientName, prior.ChannelId, newContext.ChannelId);
            return prior;
        }
        return null;
    }

    /// <summary>Drop the binding only if it still points at the given context. Avoids dropping a
    /// fresh login that has already replaced this one.</summary>
    public void Unbind(string clientName, TunnelConnectionContext context)
    {
        // ConcurrentDictionary.TryRemove with a value-equality overload requires .NET 5+; works on net10.
        _byName.TryRemove(new KeyValuePair<string, TunnelConnectionContext>(clientName, context));
    }

    public bool HasLogin(TunnelConnectionContext context) =>
        context.ClientName is { } name && _byName.TryGetValue(name, out var bound) && ReferenceEquals(bound, context);
}
