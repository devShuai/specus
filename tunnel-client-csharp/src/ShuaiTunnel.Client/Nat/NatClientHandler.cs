using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Nat;

/// <summary>
/// Owns all NAT state for one control-channel session: tunnel registrations, per-channel
/// local sockets, REGISTER/UNREGISTER diff on NAT_CONTROL hot reloads, and one-shot
/// HTTP_ROUTES_REPORT upload. Mirrors the Java <c>NatClientHandler</c>.
/// </summary>
internal sealed class NatClientHandler : IAsyncDisposable
{
    private readonly FrameWriter _writer;
    private readonly DirectHttpHandler _directHttp;
    private readonly ILogger _logger;
    private readonly string _clientName;

    private readonly object _stateLock = new();
    private readonly Dictionary<int, TunnelConfigEntry> _tunnels = new();
    private readonly HashSet<int> _registered = new();
    private readonly ConcurrentDictionary<string, LocalTunnelChannel> _channels = new();
    private bool _httpRoutesReported;
    private bool _controlWritable = true;
    private CancellationToken _cancellationToken;

    public NatClientHandler(
        IEnumerable<TunnelConfigEntry> tunnels,
        string clientName,
        FrameWriter writer,
        DirectHttpHandler directHttp,
        ILogger logger)
    {
        _writer = writer;
        _directHttp = directHttp;
        _logger = logger;
        _clientName = clientName;
        foreach (var entry in tunnels)
        {
            _tunnels[entry.Port] = entry;
        }
    }

    public void Bind(CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;
    }

    /// <summary>Sends REGISTER for every configured tunnel that has not yet been registered.</summary>
    public async Task RegisterAllAsync()
    {
        List<TunnelConfigEntry> pending;
        lock (_stateLock)
        {
            pending = _tunnels
                .Where(kv => _registered.Add(kv.Key))
                .Select(kv => kv.Value)
                .ToList();
        }
        foreach (var entry in pending)
        {
            await SendRegisterAsync(entry).ConfigureAwait(false);
        }
    }

    /// <summary>Single-shot HTTP_ROUTES_REPORT, mirroring the Java client's diagnostic upload.</summary>
    public async Task ReportHttpRoutesAsync()
    {
        bool shouldSend;
        lock (_stateLock)
        {
            shouldSend = !_httpRoutesReported;
            _httpRoutesReported = true;
        }
        if (!shouldSend)
        {
            return;
        }
        var routes = _directHttp.SnapshotRoutes()
            .Where(kv => !string.IsNullOrWhiteSpace(kv.Key))
            .Select(kv => (object?)new Dictionary<string, object?>
            {
                ["route"] = kv.Key,
                ["targetBaseUrl"] = kv.Value,
            })
            .ToList();
        var packet = new NatMessagePacket
        {
            NatMessageType = NatMessageType.HttpRoutesReport,
            MetaData = new Dictionary<string, object?>
            {
                ["clientName"] = _clientName,
                ["routes"] = routes,
            },
        };
        await _writer.WriteAsync(packet, _cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Reconciles server-pushed tunnel configs against the local map: send UNREGISTER for
    /// vanished ports, replace the desired set, then re-register any new ports.
    /// </summary>
    public async Task ApplyConfigAsync(IEnumerable<TunnelConfigEntry> desired)
    {
        List<int> toUnregister;
        List<TunnelConfigEntry> toRegister;
        lock (_stateLock)
        {
            var next = desired.ToDictionary(entry => entry.Port);
            toUnregister = _registered.Where(port => !next.ContainsKey(port)).ToList();
            foreach (var port in toUnregister)
            {
                _registered.Remove(port);
            }
            _tunnels.Clear();
            foreach (var kv in next)
            {
                _tunnels[kv.Key] = kv.Value;
            }
            toRegister = _tunnels
                .Where(kv => _registered.Add(kv.Key))
                .Select(kv => kv.Value)
                .ToList();
        }
        foreach (var port in toUnregister)
        {
            var packet = new NatMessagePacket
            {
                NatMessageType = NatMessageType.Unregister,
                MetaData = new Dictionary<string, object?> { ["port"] = port },
            };
            await _writer.WriteAsync(packet, _cancellationToken).ConfigureAwait(false);
        }
        foreach (var entry in toRegister)
        {
            await SendRegisterAsync(entry).ConfigureAwait(false);
        }
    }

    /// <summary>Routes one inbound <see cref="NatMessagePacket"/> to its sub-handler.</summary>
    public async Task HandleAsync(NatMessagePacket packet)
    {
        switch (packet.NatMessageType)
        {
            case NatMessageType.RegisterResult:
                HandleRegisterResult(packet);
                break;
            case NatMessageType.Connected:
                await HandleConnectedAsync(packet).ConfigureAwait(false);
                break;
            case NatMessageType.Data:
                await HandleDataAsync(packet).ConfigureAwait(false);
                break;
            case NatMessageType.Disconnected:
                HandleDisconnected(packet);
                break;
            case NatMessageType.Keepalive:
                // ignore; reader-idle gets reset by the inbound bytes themselves
                break;
            default:
                _logger.LogDebug("NAT: unhandled message type {type}", packet.NatMessageType);
                break;
        }
    }

    /// <summary>Updates writability so local channels can pause reads when control is full.</summary>
    public void SetControlWritable(bool writable)
    {
        _controlWritable = writable;
        foreach (var channel in _channels.Values)
        {
            channel.SetControlWritable(writable);
        }
    }

    private async Task SendRegisterAsync(TunnelConfigEntry entry)
    {
        _logger.LogInformation(
            "REGISTER public:{port} -> {addr}:{tunnelPort}", entry.Port, entry.TunnelAddress, entry.TunnelPort);
        var packet = new NatMessagePacket
        {
            NatMessageType = NatMessageType.Register,
            MetaData = new Dictionary<string, object?>
            {
                ["port"] = entry.Port,
                ["tunnelAddress"] = entry.TunnelAddress,
                ["tunnelPort"] = entry.TunnelPort,
                ["clientName"] = _clientName,
            },
        };
        await _writer.WriteAsync(packet, _cancellationToken).ConfigureAwait(false);
    }

    private void HandleRegisterResult(NatMessagePacket packet)
    {
        var port = AsInt(packet.MetaData, "port");
        var success = packet.MetaData is not null
            && packet.MetaData.TryGetValue("success", out var raw)
            && raw is bool b && b;
        if (success)
        {
            _logger.LogInformation("REGISTER ok, port={port}", port);
        }
        else
        {
            var reason = packet.MetaData is not null && packet.MetaData.TryGetValue("reason", out var r)
                ? r as string
                : null;
            _logger.LogWarning("REGISTER failed, port={port}, reason={reason}", port, reason);
        }
    }

    private async Task HandleConnectedAsync(NatMessagePacket packet)
    {
        var port = AsInt(packet.MetaData, "port");
        var channelId = packet.MetaData?.TryGetValue("channelId", out var c) == true ? c as string : null;
        if (string.IsNullOrEmpty(channelId))
        {
            _logger.LogWarning("CONNECTED missing channelId");
            return;
        }
        if (!_tunnels.TryGetValue(port ?? -1, out var entry))
        {
            _logger.LogWarning("CONNECTED for unknown port {port}", port);
            await SendDisconnectAsync(channelId!).ConfigureAwait(false);
            return;
        }
        try
        {
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(entry.TunnelAddress, entry.TunnelPort, _cancellationToken).ConfigureAwait(false);
            var channel = new LocalTunnelChannel(
                channelId!, port!.Value, tcp, _writer, _logger, c => _channels.TryRemove(c.ChannelId, out _));
            channel.SetControlWritable(_controlWritable);
            _channels[channelId!] = channel;
            _ = Task.Run(async () =>
            {
                await channel.PumpAsync(_cancellationToken).ConfigureAwait(false);
                await SendDisconnectAsync(channelId!).ConfigureAwait(false);
            }, _cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "local dial {addr}:{port} failed", entry.TunnelAddress, entry.TunnelPort);
            await SendDisconnectAsync(channelId!).ConfigureAwait(false);
        }
    }

    private async Task HandleDataAsync(NatMessagePacket packet)
    {
        var channelId = packet.MetaData?.TryGetValue("channelId", out var c) == true ? c as string : null;
        if (string.IsNullOrEmpty(channelId) || packet.Data is null || packet.Data.Length == 0)
        {
            return;
        }
        if (_channels.TryGetValue(channelId!, out var channel))
        {
            await channel.WriteAsync(packet.Data, _cancellationToken).ConfigureAwait(false);
        }
    }

    private void HandleDisconnected(NatMessagePacket packet)
    {
        var channelId = packet.MetaData?.TryGetValue("channelId", out var c) == true ? c as string : null;
        if (string.IsNullOrEmpty(channelId))
        {
            return;
        }
        if (_channels.TryRemove(channelId!, out var channel))
        {
            channel.Close();
        }
    }

    private async Task SendDisconnectAsync(string channelId)
    {
        try
        {
            var packet = new NatMessagePacket
            {
                NatMessageType = NatMessageType.Disconnected,
                MetaData = new Dictionary<string, object?> { ["channelId"] = channelId },
            };
            await _writer.WriteAsync(packet, _cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "send DISCONNECTED({channelId}) failed", channelId);
        }
    }

    private static int? AsInt(Dictionary<string, object?>? meta, string key)
    {
        if (meta is null || !meta.TryGetValue(key, out var raw) || raw is null)
        {
            return null;
        }
        return raw switch
        {
            int i => i,
            long l => (int)l,
            double d => (int)d,
            string s when int.TryParse(s, out var parsed) => parsed,
            JsonElement e when e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var v) => v,
            _ => null,
        };
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var channel in _channels.Values)
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }
        _channels.Clear();
    }
}
