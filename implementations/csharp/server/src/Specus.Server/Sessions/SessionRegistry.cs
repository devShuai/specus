using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Specus.Server.ControlChannel;
using Specus.Server.Data.Entities;

namespace Specus.Server.Sessions;

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
    private readonly ConcurrentDictionary<string, SpecusConnectionContext> _controls = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, SpecusConnectionContext> _data = new(StringComparer.Ordinal);
    private readonly ILogger<SessionRegistry> _logger;

    public SessionRegistry(ILogger<SessionRegistry> logger)
    {
        _logger = logger;
    }

    public SpecusConnectionContext? Find(string clientName) =>
        _controls.TryGetValue(clientName, out var context) ? context : null;

    public SpecusConnectionContext? FindData(string clientName) =>
        _data.TryGetValue(clientName, out var context) ? context : null;

    /// <summary>
    /// Race-free swap that returns whatever it displaces. The displaced context is stamped
    /// <c>REPLACED_BY_NEW_LOGIN</c>; the caller is responsible for asking that connection to
    /// close (typically via <see cref="ControlChannel.SpecusConnectionContext.CloseAsync"/>).
    /// </summary>
    public SpecusConnectionContext? Replace(string clientName, SpecusConnectionContext newContext)
    {
        SpecusConnectionContext? prior = null;
        _controls.AddOrUpdate(clientName,
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

    public SpecusConnectionContext? ReplaceData(string clientName, SpecusConnectionContext newContext)
    {
        SpecusConnectionContext? prior = null;
        _data.AddOrUpdate(clientName,
            _ => newContext,
            (_, existing) =>
            {
                prior = existing;
                return newContext;
            });
        if (prior is not null && !ReferenceEquals(prior, newContext))
        {
            prior.MarkDisconnectIfAbsent(DisconnectReason.ReplacedByNewLogin);
            return prior;
        }
        return null;
    }

    /// <summary>Drop the binding only if it still points at the given context. Avoids dropping a
    /// fresh login that has already replaced this one.</summary>
    public void Unbind(string clientName, SpecusConnectionContext context)
    {
        // ConcurrentDictionary.TryRemove with a value-equality overload requires .NET 5+; works on net10.
        _controls.TryRemove(new KeyValuePair<string, SpecusConnectionContext>(clientName, context));
        _data.TryRemove(new KeyValuePair<string, SpecusConnectionContext>(clientName, context));
    }

    public bool HasLogin(SpecusConnectionContext context) =>
        context.ClientName is { } name
        && ((_controls.TryGetValue(name, out var control) && ReferenceEquals(control, context))
            || (_data.TryGetValue(name, out var data) && ReferenceEquals(data, context)));
}
