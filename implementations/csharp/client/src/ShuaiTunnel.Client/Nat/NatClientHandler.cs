using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Configuration;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Nat;

/// <summary>
/// Owns all NAT state for one control-channel session: tunnel registrations, per-channel
/// local sockets, REGISTER/UNREGISTER diffs on NAT_CONTROL hot reloads, and v2 HTTP/WebSocket
/// stream dispatch. Mirrors the Java <c>NatClientHandler</c>.
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
    private readonly ConcurrentDictionary<uint, LocalTunnelChannel> _channels = new();
    private readonly ConcurrentDictionary<uint, WebSocketTunnelChannel> _wsChannels = new();
    private readonly ConcurrentDictionary<uint, HttpStreamChannel> _httpChannels = new();
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
            case NatMessageType.Open:
                await HandleOpenAsync(packet).ConfigureAwait(false);
                break;
            case NatMessageType.Data:
                await HandleDataAsync(packet).ConfigureAwait(false);
                break;
            case NatMessageType.Fin:
                if (_httpChannels.TryGetValue(packet.StreamId, out var httpRequest))
                {
                    await httpRequest.FinishRequestAsync(packet.MetaData, _cancellationToken)
                        .ConfigureAwait(false);
                }
                else
                {
                    HandleClosed(packet);
                }
                break;
            case NatMessageType.Rst:
                if (_httpChannels.TryRemove(packet.StreamId, out var resetHttp))
                {
                    resetHttp.Abort(AsString(packet.MetaData, "reason"));
                }
                else
                {
                    HandleClosed(packet);
                }
                break;
            case NatMessageType.Keepalive:
                // ignore; reader-idle gets reset by the inbound bytes themselves
                break;
            case NatMessageType.WindowUpdate:
                if (_httpChannels.TryGetValue(packet.StreamId, out var httpFlowChannel)
                    && !httpFlowChannel.AddResponseCredit(packet.Value))
                {
                    throw new InvalidDataException("invalid HTTP WINDOW_UPDATE");
                }
                if (_channels.TryGetValue(packet.StreamId, out var flowChannel)
                    && !flowChannel.AddSendCredit(packet.Value))
                {
                    throw new InvalidDataException("invalid stream WINDOW_UPDATE");
                }
                if (_wsChannels.TryGetValue(packet.StreamId, out var wsFlowChannel)
                    && !wsFlowChannel.AddSendCredit(packet.Value))
                {
                    throw new InvalidDataException("invalid websocket WINDOW_UPDATE");
                }
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
        foreach (var channel in _wsChannels.Values)
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
            if (port is not null)
            {
                lock (_stateLock)
                {
                    _registered.Remove(port.Value);
                }
            }
            var reason = packet.MetaData is not null && packet.MetaData.TryGetValue("reason", out var r)
                ? r as string
                : null;
            _logger.LogWarning("REGISTER failed, port={port}, reason={reason}", port, reason);
        }
    }

    private async Task HandleOpenAsync(NatMessagePacket packet)
    {
        var source = AsString(packet.MetaData, "source");
        if (string.Equals(source, "http", StringComparison.Ordinal))
        {
            await HandleHttpOpenAsync(packet).ConfigureAwait(false);
            return;
        }
        if (string.Equals(source, "ws", StringComparison.Ordinal))
        {
            await HandleWebSocketConnectedAsync(packet).ConfigureAwait(false);
            return;
        }

        var port = AsInt(packet.MetaData, "port");
        if (port is null)
        {
            _logger.LogWarning("CONNECTED missing port");
            return;
        }
        var channelId = AsString(packet.MetaData, "channelId");
        if (string.IsNullOrEmpty(channelId))
        {
            _logger.LogWarning("CONNECTED missing channelId");
            return;
        }
        if (!_tunnels.TryGetValue(port.Value, out var entry))
        {
            _logger.LogWarning("CONNECTED for unknown port {port}", port);
            return;
        }
        try
        {
            var tcp = new TcpClient { NoDelay = true };
            await tcp.ConnectAsync(entry.TunnelAddress, entry.TunnelPort, _cancellationToken).ConfigureAwait(false);
            var channel = new LocalTunnelChannel(
                packet.StreamId, channelId, port.Value, tcp, _writer, _logger,
                c => _channels.TryRemove(c.StreamId, out _));
            channel.SetControlWritable(_controlWritable);
            _channels[packet.StreamId] = channel;
            _ = Task.Run(async () =>
            {
                await channel.PumpAsync(_cancellationToken).ConfigureAwait(false);
                await SendFinAsync(packet.StreamId).ConfigureAwait(false);
            }, _cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "local dial {addr}:{port} failed", entry.TunnelAddress, entry.TunnelPort);
            await SendResetAsync(packet.StreamId, 1, "local connect failed").ConfigureAwait(false);
        }
    }

    private Task HandleHttpOpenAsync(NatMessagePacket packet)
    {
        if (!string.Equals(AsString(packet.MetaData, "phase"), "request", StringComparison.Ordinal)
            || packet.MetaData is null)
        {
            return SendResetAsync(packet.StreamId, 20, "invalid HTTP OPEN");
        }
        var route = AsString(packet.MetaData, "route");
        if (string.IsNullOrWhiteSpace(route))
        {
            return SendResetAsync(packet.StreamId, 20, "invalid HTTP OPEN");
        }
        if (!_directHttp.TryResolveRoute(route, out var targetBaseUrl)
            || string.IsNullOrWhiteSpace(targetBaseUrl))
        {
            _logger.LogWarning(
                "HTTP stream {StreamId} requested unknown route {Route}; available routes=[{Routes}]",
                packet.StreamId,
                route,
                _directHttp.DescribeRoutes());
            return SendResetAsync(packet.StreamId, 22, "unknown HTTP route");
        }
        var channel = new HttpStreamChannel(packet.StreamId, packet.MetaData, _directHttp,
            targetBaseUrl, _writer, _logger, _cancellationToken,
            closed => _httpChannels.TryRemove(
                new KeyValuePair<uint, HttpStreamChannel>(closed.StreamId, closed)));
        if (!_httpChannels.TryAdd(packet.StreamId, channel))
        {
            channel.Abort("duplicate HTTP stream");
            return SendResetAsync(packet.StreamId, 21, "duplicate HTTP stream");
        }
        _ = Task.Run(channel.RunAsync, _cancellationToken);
        return Task.CompletedTask;
    }

    private async Task HandleWebSocketConnectedAsync(NatMessagePacket packet)
    {
        var channelId = AsString(packet.MetaData, "channelId");
        var route = AsString(packet.MetaData, "route");
        if (string.IsNullOrWhiteSpace(channelId) || string.IsNullOrWhiteSpace(route))
        {
            _logger.LogWarning("[ws-tunnel][client] CONNECTED missing channelId/route");
            if (!string.IsNullOrWhiteSpace(channelId))
            {
                await SendResetAsync(packet.StreamId, 2, "invalid websocket open").ConfigureAwait(false);
            }
            return;
        }

        var routes = _directHttp.SnapshotRoutes();
        if (!routes.TryGetValue(route, out var targetBaseUrl) || string.IsNullOrWhiteSpace(targetBaseUrl))
        {
            _logger.LogWarning("[ws-tunnel][client] CONNECTED for unknown route {route}", route);
            await SendResetAsync(packet.StreamId, 3, "unknown websocket route").ConfigureAwait(false);
            return;
        }

        var relativePath = AsString(packet.MetaData, "relativePath");
        var rawQuery = AsString(packet.MetaData, "rawQuery");
        if (!TryBuildWebSocketTarget(targetBaseUrl, relativePath, rawQuery, out var target, out var error))
        {
            _logger.LogWarning("[ws-tunnel][client] CONNECTED route={route} build-target-failed error={error}", route, error);
            await SendResetAsync(packet.StreamId, 4, "invalid websocket target").ConfigureAwait(false);
            return;
        }

        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(_cancellationToken);
            connectCts.CancelAfter(TimeSpan.FromSeconds(5));
            var socket = BuildLocalWebSocket();
            foreach (var header in WebSocketHandshakeHeaders(packet.MetaData))
            {
                try
                {
                    socket.Options.SetRequestHeader(header.Key, header.Value);
                }
                catch (ArgumentException ex)
                {
                    _logger.LogDebug(ex, "[ws-tunnel][client] skip unsupported handshake header {header}", header.Key);
                }
            }

            await socket.ConnectAsync(target, connectCts.Token).ConfigureAwait(false);
            if (_wsChannels.TryRemove(packet.StreamId, out var previous))
            {
                await previous.DisposeAsync().ConfigureAwait(false);
            }
            var channel = new WebSocketTunnelChannel(
                packet.StreamId,
                channelId,
                socket,
                _writer,
                _logger,
                c => _wsChannels.TryRemove(c.StreamId, out _));
            channel.SetControlWritable(_controlWritable);
            _wsChannels[packet.StreamId] = channel;
            _logger.LogInformation("[ws-tunnel][client] ws handshake ok channelId={channelId} route={route} target={target}",
                channelId, route, target.GetLeftPart(UriPartial.Path));
            _ = Task.Run(async () =>
            {
                await channel.PumpAsync(_cancellationToken).ConfigureAwait(false);
                await SendFinAsync(packet.StreamId).ConfigureAwait(false);
            }, _cancellationToken);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "[ws-tunnel][client] connect local ws failed channelId={channelId} route={route}", channelId, route);
            await SendResetAsync(packet.StreamId, 5, "websocket connect failed").ConfigureAwait(false);
        }
    }

    private async Task HandleDataAsync(NatMessagePacket packet)
    {
        if (packet.Data is null || packet.Data.Length == 0)
        {
            return;
        }
        if (_httpChannels.TryGetValue(packet.StreamId, out var httpChannel))
        {
            await httpChannel.OfferRequestDataAsync(packet.Data, _cancellationToken)
                .ConfigureAwait(false);
            return;
        }
        if (_wsChannels.TryGetValue(packet.StreamId, out var wsChannel))
        {
            await wsChannel.WriteAsync(packet.Data, _cancellationToken).ConfigureAwait(false);
            await SendWindowUpdateAsync(packet.StreamId, packet.Data.Length).ConfigureAwait(false);
            return;
        }
        if (_channels.TryGetValue(packet.StreamId, out var channel))
        {
            await channel.WriteAsync(packet.Data, _cancellationToken).ConfigureAwait(false);
            await SendWindowUpdateAsync(packet.StreamId, packet.Data.Length).ConfigureAwait(false);
        }
    }

    private void HandleClosed(NatMessagePacket packet)
    {
        if (_wsChannels.TryRemove(packet.StreamId, out var wsChannel))
        {
            wsChannel.Close();
            return;
        }
        if (_channels.TryRemove(packet.StreamId, out var channel))
        {
            channel.Close();
        }
    }

    private async Task SendFinAsync(uint streamId)
    {
        try
        {
            var packet = new NatMessagePacket
            {
                NatMessageType = NatMessageType.Fin,
                StreamId = streamId,
            };
            await _writer.WriteAsync(packet, _cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "send FIN({streamId}) failed", streamId);
        }
    }

    private async Task SendResetAsync(uint streamId, uint errorCode, string reason)
    {
        try
        {
            await _writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Rst,
                StreamId = streamId,
                Value = errorCode,
                MetaData = new Dictionary<string, object?> { ["reason"] = reason },
            }, _cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "send RST({streamId}) failed", streamId);
        }
    }

    private ValueTask SendWindowUpdateAsync(uint streamId, int credit) =>
        _writer.WritePriorityAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.WindowUpdate,
            StreamId = streamId,
            Value = checked((uint)credit),
        }, _cancellationToken);

    private static string? AsString(Dictionary<string, object?>? meta, string key)
    {
        if (meta is null || !meta.TryGetValue(key, out var raw) || raw is null)
        {
            return null;
        }
        return raw switch
        {
            string s => s,
            JsonElement e when e.ValueKind == JsonValueKind.String => e.GetString(),
            JsonValue value when value.TryGetValue<string>(out var text) => text,
            _ => raw.ToString(),
        };
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

    internal static bool TryBuildWebSocketTarget(
        string targetBaseUrl, string? relativePath, string? rawQuery, out Uri target, out string error)
    {
        target = null!;
        error = "";
        if (string.IsNullOrWhiteSpace(targetBaseUrl))
        {
            error = "未配置 HTTP route";
            return false;
        }

        var wsUrl = targetBaseUrl.Trim();
        if (wsUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            wsUrl = "ws://" + wsUrl["http://".Length..];
        }
        else if (wsUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            wsUrl = "wss://" + wsUrl["https://".Length..];
        }
        else if (!wsUrl.StartsWith("ws://", StringComparison.OrdinalIgnoreCase)
                 && !wsUrl.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
        {
            error = "HTTP route 仅支持 http/https/ws/wss";
            return false;
        }

        if (!Uri.TryCreate(wsUrl, UriKind.Absolute, out var baseUri)
            || string.IsNullOrWhiteSpace(baseUri.Host)
            || !string.IsNullOrEmpty(baseUri.Query)
            || !string.IsNullOrEmpty(baseUri.Fragment))
        {
            error = "HTTP route 地址无效";
            return false;
        }

        var tail = string.IsNullOrWhiteSpace(relativePath) ? "/" : relativePath!;
        if (tail.Contains('\r') || tail.Contains('\n'))
        {
            error = "relativePath 含有非法控制字符";
            return false;
        }
        var escapedPath = baseUri.GetComponents(UriComponents.Path, UriFormat.UriEscaped);
        var basePath = escapedPath.Length == 0 ? "" : "/" + escapedPath;
        string path;
        if (basePath.EndsWith("/", StringComparison.Ordinal) && tail.StartsWith("/", StringComparison.Ordinal))
        {
            path = basePath + tail[1..];
        }
        else if (basePath.Length > 0 && !basePath.EndsWith("/", StringComparison.Ordinal)
                 && !tail.StartsWith("/", StringComparison.Ordinal))
        {
            path = basePath + "/" + tail;
        }
        else
        {
            path = basePath + tail;
        }
        if (path.Length == 0)
        {
            path = "/";
        }

        var full = baseUri.GetLeftPart(UriPartial.Authority) + path
            + (string.IsNullOrWhiteSpace(rawQuery) ? "" : "?" + rawQuery);
        if (!Uri.TryCreate(full, UriKind.Absolute, out var created))
        {
            error = "目标地址拼接失败";
            return false;
        }
        target = created;
        return true;
    }

    internal static ClientWebSocket BuildLocalWebSocket()
    {
        var socket = new ClientWebSocket();
        socket.Options.RemoteCertificateValidationCallback = static (_, _, _, _) => true;
        return socket;
    }

    internal static List<KeyValuePair<string, string>> WebSocketHandshakeHeaders(Dictionary<string, object?>? meta)
    {
        var headers = new List<KeyValuePair<string, string>>();
        foreach (var line in AsStringEnumerable(meta, "headers"))
        {
            var separator = line.IndexOf(':');
            if (separator <= 0)
            {
                continue;
            }
            var name = line[..separator];
            if (SkippedWebSocketHandshakeHeaders.Contains(name))
            {
                continue;
            }
            headers.Add(new KeyValuePair<string, string>(name, line[(separator + 1)..]));
        }
        return headers;
    }

    private static readonly HashSet<string> SkippedWebSocketHandshakeHeaders =
        new(StringComparer.OrdinalIgnoreCase)
        {
            "connection", "content-length", "host", "keep-alive",
            "proxy-authenticate", "proxy-authorization", "te", "trailer",
            "transfer-encoding", "upgrade", "sec-websocket-key",
            "sec-websocket-version", "sec-websocket-extensions",
            "sec-websocket-protocol", "sec-websocket-accept",
        };

    private static IEnumerable<string> AsStringEnumerable(Dictionary<string, object?>? meta, string key)
    {
        if (meta is null || !meta.TryGetValue(key, out var raw) || raw is null)
        {
            yield break;
        }
        switch (raw)
        {
            case IEnumerable<string> strings:
                foreach (var item in strings)
                {
                    yield return item;
                }
                yield break;
            case JsonArray array:
                foreach (var node in array)
                {
                    if (node is JsonValue value && value.TryGetValue<string>(out var text))
                    {
                        yield return text;
                    }
                }
                yield break;
            case JsonElement { ValueKind: JsonValueKind.Array } element:
                foreach (var item in element.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String)
                    {
                        yield return item.GetString()!;
                    }
                }
                yield break;
            case IEnumerable<object?> objects:
                foreach (var item in objects)
                {
                    if (item is not null)
                    {
                        yield return item.ToString()!;
                    }
                }
                yield break;
        }
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var channel in _channels.Values)
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }
        _channels.Clear();
        foreach (var channel in _wsChannels.Values)
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }
        _wsChannels.Clear();
        foreach (var channel in _httpChannels.Values)
        {
            await channel.DisposeAsync().ConfigureAwait(false);
        }
        _httpChannels.Clear();
    }
}
