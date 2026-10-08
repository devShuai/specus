using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Sessions;

namespace Specus.Server.Nat;

public sealed class NatControlService
{
    /// <summary>The 1 MiB MESSAGE body of protocol/spec/control-protocol.md that a NAT_CONTROL travels in.</summary>
    public const int MessageBodyLimit = PacketCodec.MaxMessageBodySize;

    /// <summary>The longest client name a rename allows.</summary>
    public const int ClientNameReserveCharacters = 120;

    public const string TooLargeMessage =
        "客户端的 TCP 映射和 HTTP route 将超过单条 NAT_CONTROL 消息 1 MiB 的上限，无法下发给客户端";

    /// <summary>The 409 of a manual push whose NAT_CONTROL, as stored, does not fit one MESSAGE.</summary>
    public const string NotSentMessage =
        "客户端的 TCP 映射和 HTTP route 超过单条 NAT_CONTROL 消息 1 MiB 的上限，未下发给客户端";

    // The client's name when a NAT_CONTROL is sized: 120 characters of 4 UTF-8 bytes each in the
    // clientName field, and of a 6-byte \uXXXX escape each in the JSON. No name a rename allows takes
    // more in either place, so no later rename pushes an accepted configuration over.
    private static readonly string LongestFieldName =
        string.Concat(Enumerable.Repeat("\U00010000", ClientNameReserveCharacters));
    private static readonly string LongestJsonName = new('\u0001', ClientNameReserveCharacters);

    private readonly SpecusDbContext _db;
    private readonly SessionRegistry _sessions;
    private readonly NettyServerOptions _netty;
    private readonly SpecusOptions _specus;
    private readonly ILogger<NatControlService> _logger;

    public NatControlService(SpecusDbContext db, SessionRegistry sessions,
        IOptions<NettyServerOptions> netty, IOptions<SpecusOptions> specus,
        ILogger<NatControlService> logger)
    {
        _db = db;
        _sessions = sessions;
        _netty = netty.Value;
        _specus = specus.Value;
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

        // Always the full snapshot, empty lists included: a client that reconnects with its access
        // token gets no new HTTP login snapshot, so if its last route was deleted while it was
        // offline, this push is the only way it learns to stop forwarding that route.
        // A NAT_CONTROL that does not fit one MESSAGE is only logged and does not throw: the login
        // stands and the Peer Mesh push after it still runs. Closing the connection would only have
        // the client log in again into the same failure.
        var (mappings, httpRoutes) = await LoadSnapshotAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (await SendNatControlAsync(clientName, mappings, httpRoutes, cancellationToken)
                .ConfigureAwait(false) == Delivery.Sent)
        {
            _logger.LogInformation("[nat-control] pushed {TcpCount} tcp + {HttpCount} http route(s) to {Client}",
                mappings.Count, httpRoutes.Count, clientName);
        }
    }

    public async Task<PushResult> PushToClientAsync(long clientId, CancellationToken cancellationToken)
    {
        var account = await _db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.Id == clientId, cancellationToken)
            .ConfigureAwait(false) ?? throw new ArgumentException($"client not found: {clientId}");
        var (mappings, httpRoutes) = await LoadSnapshotAsync(account.Id, cancellationToken).ConfigureAwait(false);
        // Both failures are the InvalidOperationException the management API answers 409 to; a
        // NAT_CONTROL that does not fit one MESSAGE was not sent and must not be reported as pushed.
        var delivery = await SendNatControlAsync(account.ClientName, mappings, httpRoutes, cancellationToken)
            .ConfigureAwait(false);
        return delivery switch
        {
            Delivery.Offline => throw new InvalidOperationException("客户端不在线，无法下发映射"),
            Delivery.NotSent => throw new InvalidOperationException(NotSentMessage),
            _ => new PushResult(mappings.Count, httpRoutes.Count),
        };
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

        // A NAT_CONTROL that does not fit one MESSAGE is only logged: the change that called this
        // stands and answers as it would have.
        var (mappings, httpRoutes) = await LoadSnapshotAsync(account.Id, cancellationToken).ConfigureAwait(false);
        if (await SendNatControlAsync(account.ClientName, mappings, httpRoutes, cancellationToken)
                .ConfigureAwait(false) == Delivery.Sent)
        {
            _logger.LogInformation("[nat-control] synchronized {TcpCount} tcp + {HttpCount} http route(s) to {Client}",
                mappings.Count, httpRoutes.Count, account.ClientName);
        }
    }

    private async Task<(IReadOnlyList<SpecusMapping> Mappings, IReadOnlyList<HttpRouteMapping> HttpRoutes)>
        LoadSnapshotAsync(long clientId, CancellationToken cancellationToken)
    {
        var mappings = await _db.SpecusMappings.AsNoTracking()
            .Where(m => m.ClientId == clientId && m.Enabled)
            .OrderBy(m => m.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);

        var httpRoutes = await _db.HttpRouteMappings.AsNoTracking()
            .Where(r => r.ClientId == clientId && r.Enabled)
            .OrderBy(r => r.Id)
            .ToListAsync(cancellationToken)
            .ConfigureAwait(false);
        return (mappings, httpRoutes);
    }

    /// <summary>What became of one NAT_CONTROL push.</summary>
    private enum Delivery
    {
        Sent,
        /// <summary>The client has no logged-in control connection.</summary>
        Offline,
        /// <summary>The NAT_CONTROL does not fit one MESSAGE, or cannot be encoded: nothing was written.</summary>
        NotSent,
    }

    /// <summary>
    /// Writes <paramref name="clientName"/>'s NAT_CONTROL to its control connection. One that does not
    /// fit one MESSAGE is not handed to the connection, whose encoder would throw: it is logged once
    /// and the connection is kept, so the client goes on with the configuration it has. See
    /// "NAT_CONTROL 的大小" in protocol/spec/control-protocol.md.
    /// </summary>
    private async Task<Delivery> SendNatControlAsync(string clientName,
        IReadOnlyList<SpecusMapping> mappings,
        IReadOnlyList<HttpRouteMapping> httpRoutes,
        CancellationToken cancellationToken)
    {
        var context = _sessions.Find(clientName);
        if (context is null || !_sessions.HasLogin(context))
        {
            return Delivery.Offline;
        }

        var packet = new MessageResponsePacket
        {
            ClientName = clientName,
            MessageType = MessageType.NatControl,
        };
        int bodyBytes;
        try
        {
            packet.Message = MessageJson(clientName, mappings, httpRoutes);
            bodyBytes = CompactBinarySerializer.Serialize(packet).Length;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex,
                "[nat-control] not pushed to {Client}: its NAT_CONTROL of {TcpCount} tcp + {HttpCount} http route(s) cannot be encoded; the connection is kept",
                clientName, mappings.Count, httpRoutes.Count);
            return Delivery.NotSent;
        }
        if (bodyBytes > MessageBodyLimit)
        {
            _logger.LogError(
                "[nat-control] not pushed to {Client}: its NAT_CONTROL of {TcpCount} tcp + {HttpCount} http route(s) takes {BodyBytes} bytes, over the {Limit}-byte MESSAGE body limit; the connection is kept, disable or delete entries to bring it back within the limit",
                clientName, mappings.Count, httpRoutes.Count, bodyBytes, MessageBodyLimit);
            return Delivery.NotSent;
        }

        await context.Writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        return Delivery.Sent;
    }

    /// <summary>
    /// Throws the <see cref="ArgumentException"/> the management API answers 400 to when the
    /// client's NAT_CONTROL would no longer fit one MESSAGE once <paramref name="mapping"/> or
    /// <paramref name="route"/>, as the change leaves it, takes the place of the stored entry with its
    /// id or joins the list. It counts the client's enabled entries, whether or not the client is
    /// enabled. A change that leaves the entry disabled only shrinks the message and always passes.
    /// See "NAT_CONTROL 的大小" in protocol/spec/control-protocol.md.
    /// </summary>
    public async Task EnsureFitsAsync(long clientId, SpecusMapping? mapping, HttpRouteMapping? route,
        CancellationToken cancellationToken)
    {
        if (mapping is { Enabled: false } || route is { Enabled: false })
        {
            return;
        }
        var (mappings, httpRoutes) = await LoadSnapshotAsync(clientId, cancellationToken).ConfigureAwait(false);
        if (mapping is not null)
        {
            mappings = mappings.Where(m => m.Id != mapping.Id).Append(mapping).ToList();
        }
        if (route is not null)
        {
            httpRoutes = httpRoutes.Where(r => r.Id != route.Id).Append(route).ToList();
        }
        if (ReservedBodyBytes(mappings, httpRoutes) > MessageBodyLimit)
        {
            throw new ArgumentException(TooLargeMessage);
        }
    }

    /// <summary>
    /// The MESSAGE body of a NAT_CONTROL carrying these entries, encoded as it is sent, with the
    /// client's name counted at the longest a rename allows.
    /// </summary>
    public int ReservedBodyBytes(IReadOnlyList<SpecusMapping> mappings, IReadOnlyList<HttpRouteMapping> httpRoutes)
    {
        var packet = new MessageResponsePacket
        {
            ClientName = LongestFieldName,
            MessageType = MessageType.NatControl,
            Message = MessageJson(LongestJsonName, mappings, httpRoutes),
        };
        return CompactBinarySerializer.Serialize(packet).Length;
    }

    /// <summary>The JSON text of <paramref name="clientName"/>'s NAT_CONTROL.</summary>
    public string MessageJson(string clientName, IReadOnlyList<SpecusMapping> mappings,
        IReadOnlyList<HttpRouteMapping> httpRoutes)
    {
        var specusConfigList = new List<Dictionary<string, object?>>(mappings.Count);
        foreach (var mapping in mappings)
        {
            specusConfigList.Add(new Dictionary<string, object?>
            {
                ["port"] = mapping.ListenPort,
                ["specusAddress"] = mapping.TargetAddress,
                ["specusPort"] = mapping.TargetPort,
            });
        }

        var specusBean = new Dictionary<string, object?>
        {
            ["clientName"] = clientName,
            ["remoteAddress"] = string.IsNullOrWhiteSpace(_specus.PublicAddress)
                ? null
                : _specus.PublicAddress.Trim(),
            ["remotePort"] = _netty.Port,
            ["specusConfigList"] = specusConfigList,
        };

        // The HTTP route list is always the full set, even when empty: older clients keep the list
        // they have when the field is missing, so omitting it after the last route was deleted left
        // that route forwarding on the client until it reconnected.
        var httpSpecusConfigList = new List<Dictionary<string, object?>>(httpRoutes.Count);
        foreach (var route in httpRoutes)
        {
            httpSpecusConfigList.Add(new Dictionary<string, object?>
            {
                ["route"] = route.Route,
                ["targetBaseUrl"] = route.TargetBaseUrl,
            });
        }
        specusBean["httpSpecusConfigList"] = httpSpecusConfigList;
        return JsonSerializer.Serialize(specusBean);
    }
}

public sealed record PushResult(int SpecusMappings, int HttpRoutes);
