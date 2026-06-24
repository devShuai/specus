using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.Server.Nat;

public sealed class NatControlService
{
    private readonly TunnelDbContext _db;
    private readonly SessionRegistry _sessions;
    private readonly NettyServerOptions _netty;
    private readonly TunnelOptions _tunnel;
    private readonly ILogger<NatControlService> _logger;

    public NatControlService(TunnelDbContext db, SessionRegistry sessions,
        IOptions<NettyServerOptions> netty, IOptions<TunnelOptions> tunnel,
        ILogger<NatControlService> logger)
    {
        _db = db;
        _sessions = sessions;
        _netty = netty.Value;
        _tunnel = tunnel.Value;
        _logger = logger;
    }

    public async Task PushOnLoginAsync(string clientName, CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == clientName, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return;
        }

        var mappings = await _db.TunnelMappings.AsNoTracking()
            .Where(m => m.ClientId == account.Id && m.Enabled)
            .OrderBy(m => m.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var httpRoutesManaged = await _db.HttpRouteMappings.AsNoTracking()
            .AnyAsync(r => r.ClientId == account.Id, cancellationToken)
            .ConfigureAwait(false);
        var httpRoutes = httpRoutesManaged
            ? await _db.HttpRouteMappings.AsNoTracking()
                .Where(r => r.ClientId == account.Id && r.Enabled)
                .OrderBy(r => r.Id)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false)
            : null;

        if (mappings.Count == 0 && httpRoutes is null)
        {
            return;
        }

        if (await SendNatControlAsync(clientName, mappings, httpRoutes, cancellationToken)
                .ConfigureAwait(false))
        {
            _logger.LogInformation("[nat-control] pushed {TcpCount} tcp + {HttpCount} http route(s) to {Client}",
                mappings.Count, httpRoutes is null ? "-" : httpRoutes.Count.ToString(), clientName);
        }
    }

    public async Task<PushResult> PushToClientAsync(long clientId, CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == clientId, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client not found: {clientId}");
        var (mappings, httpRoutes) = await LoadSnapshotAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (!await SendNatControlAsync(account.ClientName, mappings, httpRoutes, cancellationToken)
                .ConfigureAwait(false))
        {
            throw new InvalidOperationException("客户端不在线，无法下发映射");
        }
        return new PushResult(mappings.Count, httpRoutes is null ? -1 : httpRoutes.Count);
    }

    public async Task PushSnapshotIfOnlineAsync(long clientId, CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == clientId, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return;
        }

        var (mappings, httpRoutes) = await LoadSnapshotAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (await SendNatControlAsync(account.ClientName, mappings, httpRoutes, cancellationToken)
                .ConfigureAwait(false))
        {
            _logger.LogInformation("[nat-control] synchronized {TcpCount} tcp + {HttpCount} http route(s) to {Client}",
                mappings.Count, httpRoutes is null ? "-" : httpRoutes.Count.ToString(), account.ClientName);
        }
    }

    private async Task<(IReadOnlyList<TunnelMapping> Mappings, IReadOnlyList<HttpRouteMapping>? HttpRoutes)>
        LoadSnapshotAsync(long clientId, CancellationToken cancellationToken)
    {
        var mappings = await _db.TunnelMappings.AsNoTracking()
            .Where(m => m.ClientId == clientId && m.Enabled)
            .OrderBy(m => m.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var httpRoutesManaged = await _db.HttpRouteMappings.AsNoTracking()
            .AnyAsync(r => r.ClientId == clientId, cancellationToken)
            .ConfigureAwait(false);
        var httpRoutes = httpRoutesManaged
            ? await _db.HttpRouteMappings.AsNoTracking()
                .Where(r => r.ClientId == clientId && r.Enabled)
                .OrderBy(r => r.Id)
                .ToListAsync(cancellationToken)
                .ConfigureAwait(false)
            : null;
        return (mappings, httpRoutes);
    }

    private async Task<bool> SendNatControlAsync(string clientName,
        IReadOnlyList<TunnelMapping> mappings,
        IReadOnlyList<HttpRouteMapping>? httpRoutes,
        CancellationToken cancellationToken)
    {
        var context = _sessions.Find(clientName);
        if (context is null || !_sessions.HasLogin(context))
        {
            return false;
        }

        var tunnelConfigList = new List<Dictionary<string, object?>>(mappings.Count);
        foreach (var mapping in mappings)
        {
            tunnelConfigList.Add(new Dictionary<string, object?>
            {
                ["port"] = mapping.ListenPort,
                ["tunnelAddress"] = mapping.TargetAddress,
                ["tunnelPort"] = mapping.TargetPort,
            });
        }

        var tunnelBean = new Dictionary<string, object?>
        {
            ["clientName"] = clientName,
            ["remoteAddress"] = string.IsNullOrWhiteSpace(_tunnel.PublicAddress)
                ? null
                : _tunnel.PublicAddress.Trim(),
            ["remotePort"] = _netty.Port,
            ["tunnelConfigList"] = tunnelConfigList,
        };

        if (httpRoutes is not null)
        {
            var httpTunnelConfigList = new List<Dictionary<string, object?>>(httpRoutes.Count);
            foreach (var route in httpRoutes)
            {
                httpTunnelConfigList.Add(new Dictionary<string, object?>
                {
                    ["route"] = route.Route,
                    ["targetBaseUrl"] = route.TargetBaseUrl,
                });
            }
            tunnelBean["httpTunnelConfigList"] = httpTunnelConfigList;
        }

        var packet = new MessageResponsePacket
        {
            ClientName = clientName,
            MessageType = MessageType.NatControl,
            Message = JsonSerializer.Serialize(tunnelBean),
        };

        await context.Writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        return true;
    }
}

public sealed record PushResult(int Tunnels, int HttpRoutes);
