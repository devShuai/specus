using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Logging;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Protocol;
using Specus.Protocol.Packets;

namespace Specus.Client.Nat;

/// <summary>
/// Owns all NAT state for one control-channel session: specus registrations, per-channel
/// local sockets, REGISTER/UNREGISTER diffs on NAT_CONTROL hot reloads, and v2 HTTP/WebSocket
/// stream dispatch. Mirrors the Java <c>NatClientHandler</c>.
/// </summary>
internal sealed class NatClientHandler : IAsyncDisposable
{
    private const int MaximumClosedStreams = 1024;
    private const int MaximumPendingStreams = 1024;
    private const int MaximumPendingStreamBytes = 4 * 1024 * 1024;
    private static readonly TimeSpan LocalConnectTimeout = TimeSpan.FromSeconds(5);

    private readonly FrameWriter _writer;
    private readonly DirectHttpHandler _directHttp;
    private readonly ILogger _logger;
    private readonly string _clientName;
    private readonly Func<string, int, CancellationToken, Task<TcpClient>> _tcpConnector;

    private readonly object _stateLock = new();
    private readonly Dictionary<int, SpecusConfigEntry> _specusMappings = new();
    private readonly HashSet<int> _registered = new();
    private readonly HashSet<uint> _openStreamIds = new();
    private readonly Dictionary<uint, PendingOpen> _pendingStreams = new();
    private readonly ConcurrentDictionary<uint, LocalSpecusChannel> _channels = new();
    private readonly ConcurrentDictionary<uint, WebSocketSpecusChannel> _wsChannels = new();
    private readonly ConcurrentDictionary<uint, HttpStreamChannel> _httpChannels = new();
    private readonly ConcurrentDictionary<uint, byte> _closedStreams = new();
    private readonly ConcurrentQueue<uint> _closedStreamOrder = new();
    private bool _controlWritable = true;
    private CancellationToken _cancellationToken;

    public NatClientHandler(
        IEnumerable<SpecusConfigEntry> specusMappings,
        string clientName,
        FrameWriter writer,
        DirectHttpHandler directHttp,
        ILogger logger,
        Func<string, int, CancellationToken, Task<TcpClient>>? tcpConnector = null)
    {
        _writer = writer;
        _directHttp = directHttp;
        _logger = logger;
        _clientName = clientName;
        _tcpConnector = tcpConnector ?? ConnectLocalTcpAsync;
        foreach (var entry in specusMappings)
        {
            _specusMappings[entry.Port] = entry;
        }
    }

    public void Bind(CancellationToken cancellationToken)
    {
        _cancellationToken = cancellationToken;
    }

    /// <summary>Sends REGISTER for every configured specus that has not yet been registered.</summary>
    public async Task RegisterAllAsync()
    {
        List<SpecusConfigEntry> pending;
        lock (_stateLock)
        {
            pending = _specusMappings
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
    /// Reconciles server-pushed specus configs against the local map: send UNREGISTER for
    /// vanished ports, replace the desired set, then re-register any new ports.
    /// </summary>
    public async Task ApplyConfigAsync(IEnumerable<SpecusConfigEntry> desired)
    {
        List<int> toUnregister;
        List<SpecusConfigEntry> toRegister;
        lock (_stateLock)
        {
            var next = desired.ToDictionary(entry => entry.Port);
            toUnregister = _registered.Where(port => !next.ContainsKey(port)).ToList();
            foreach (var port in toUnregister)
            {
                _registered.Remove(port);
            }
            _specusMappings.Clear();
            foreach (var kv in next)
            {
                _specusMappings[kv.Key] = kv.Value;
            }
            toRegister = _specusMappings
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
                    try
                    {
                        await httpRequest.FinishRequestAsync(packet.MetaData, _cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (InvalidDataException ex)
                    {
                        await RejectHttpStreamAsync(packet.StreamId, httpRequest, ex.Message)
                            .ConfigureAwait(false);
                    }
                }
                else
                {
                    await HandleRemoteFinAsync(packet.StreamId).ConfigureAwait(false);
                }
                break;
            case NatMessageType.Rst:
                if (_httpChannels.TryRemove(packet.StreamId, out var resetHttp))
                {
                    MarkStreamClosed(packet.StreamId);
                    resetHttp.Abort(AsString(packet.MetaData, "reason"));
                }
                else if (IsClosedStream(packet.StreamId))
                {
                    // A reset may race with the response pump completing locally.
                }
                else
                {
                    HandleReset(packet.StreamId);
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
                // WINDOW_UPDATE can race a terminal frame.  Credit for a recently closed
                // stream is consumed without resurrecting that stream.
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

    private async Task SendRegisterAsync(SpecusConfigEntry entry)
    {
        _logger.LogInformation(
            "REGISTER public:{port} -> {addr}:{specusPort}", entry.Port, entry.SpecusAddress, entry.SpecusPort);
        var packet = new NatMessagePacket
        {
            NatMessageType = NatMessageType.Register,
            MetaData = new Dictionary<string, object?>
            {
                ["port"] = entry.Port,
                ["specusAddress"] = entry.SpecusAddress,
                ["specusPort"] = entry.SpecusPort,
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
            var reservation = TryReserveStream(packet.StreamId, pending: false, out _);
            if (reservation != StreamReservationResult.Reserved)
            {
                await RejectDuplicateOpenAsync(packet.StreamId, reservation).ConfigureAwait(false);
                return;
            }
            await HandleHttpOpenAsync(packet).ConfigureAwait(false);
            return;
        }

        var pendingResult = TryReserveStream(packet.StreamId, pending: true, out var pending);
        if (pendingResult != StreamReservationResult.Reserved || pending is null)
        {
            await RejectDuplicateOpenAsync(packet.StreamId, pendingResult).ConfigureAwait(false);
            return;
        }
        if (string.Equals(source, "ws", StringComparison.Ordinal))
        {
            _ = HandleWebSocketConnectedAsync(packet, pending);
            return;
        }

        var port = AsInt(packet.MetaData, "port");
        if (port is null)
        {
            _logger.LogWarning("CONNECTED missing port");
            FailPendingStream(packet.StreamId, pending);
            await WriteResetPacketAsync(packet.StreamId, 2, "TCP OPEN missing port").ConfigureAwait(false);
            return;
        }
        var channelId = AsString(packet.MetaData, "channelId");
        if (string.IsNullOrEmpty(channelId))
        {
            _logger.LogWarning("CONNECTED missing channelId");
            FailPendingStream(packet.StreamId, pending);
            await WriteResetPacketAsync(packet.StreamId, 2, "TCP OPEN missing channelId").ConfigureAwait(false);
            return;
        }
        if (!_specusMappings.TryGetValue(port.Value, out var entry))
        {
            _logger.LogWarning("CONNECTED for unknown port {port}", port);
            FailPendingStream(packet.StreamId, pending);
            await WriteResetPacketAsync(packet.StreamId, 3, "TCP OPEN for unknown port").ConfigureAwait(false);
            return;
        }

        _ = ConnectTcpAsync(packet.StreamId, channelId, port.Value, entry, pending);
    }

    private async Task ConnectTcpAsync(uint streamId, string channelId, int publicPort,
        SpecusConfigEntry entry, PendingOpen pending)
    {
        TcpClient? tcp = null;
        try
        {
            tcp = await _tcpConnector(entry.SpecusAddress, entry.SpecusPort, pending.Token)
                .ConfigureAwait(false);
            var channel = new LocalSpecusChannel(
                streamId, channelId, publicPort, tcp, _writer, _logger,
                c =>
                {
                    if (_channels.TryRemove(
                            new KeyValuePair<uint, LocalSpecusChannel>(c.StreamId, c)))
                    {
                        MarkStreamClosed(c.StreamId);
                    }
                });
            channel.SetControlWritable(_controlWritable);
            if (!TryActivateTcpStream(streamId, pending, channel, out var bufferedPackets))
            {
                await channel.DisposeAsync().ConfigureAwait(false);
                return;
            }
            tcp = null; // ownership transferred to LocalSpecusChannel
            foreach (var buffered in bufferedPackets)
            {
                await HandleBufferedPacketAsync(buffered).ConfigureAwait(false);
            }
            _ = Task.Run(async () =>
            {
                var completion = await channel.PumpAsync(_cancellationToken).ConfigureAwait(false);
                if (completion == LocalSpecusPumpResult.LocalFin)
                {
                    await SendFinAsync(streamId).ConfigureAwait(false);
                }
                else if (completion == LocalSpecusPumpResult.Reset)
                {
                    await SendResetAsync(streamId, 6, "local TCP read failed").ConfigureAwait(false);
                }
            }, CancellationToken.None);
        }
        catch (OperationCanceledException) when (pending.Token.IsCancellationRequested)
        {
            if (FailPendingStream(streamId, pending) && !_cancellationToken.IsCancellationRequested)
            {
                await WriteResetPacketAsync(streamId, 1, "local connect timed out").ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "local dial {addr}:{port} failed", entry.SpecusAddress, entry.SpecusPort);
            if (FailPendingStream(streamId, pending))
            {
                await WriteResetPacketAsync(streamId, 1, "local connect failed").ConfigureAwait(false);
            }
        }
        finally
        {
            tcp?.Dispose();
            pending.Dispose();
        }
    }

    private Task HandleHttpOpenAsync(NatMessagePacket packet)
    {
        if (!string.Equals(AsString(packet.MetaData, "phase"), "request", StringComparison.Ordinal)
            || packet.MetaData is null)
        {
            return RejectNewHttpStreamAsync(packet.StreamId, 20, "invalid HTTP OPEN");
        }
        var route = AsString(packet.MetaData, "route");
        if (string.IsNullOrWhiteSpace(route))
        {
            return RejectNewHttpStreamAsync(packet.StreamId, 20, "invalid HTTP OPEN");
        }
        if (!_directHttp.TryResolveRoute(route, out var targetBaseUrl)
            || string.IsNullOrWhiteSpace(targetBaseUrl))
        {
            _logger.LogWarning(
                "HTTP stream {StreamId} requested unknown route {Route}; available routes=[{Routes}]",
                packet.StreamId,
                route,
                _directHttp.DescribeRoutes());
            return RejectNewHttpStreamAsync(packet.StreamId, 22, "unknown HTTP route");
        }
        var channel = new HttpStreamChannel(packet.StreamId, packet.MetaData, _directHttp,
            targetBaseUrl, _writer, _logger, _cancellationToken,
            closed =>
            {
                if (_httpChannels.TryRemove(
                        new KeyValuePair<uint, HttpStreamChannel>(closed.StreamId, closed)))
                {
                    MarkStreamClosed(closed.StreamId);
                }
            });
        if (!_httpChannels.TryAdd(packet.StreamId, channel))
        {
            channel.Abort("duplicate HTTP stream");
            MarkStreamClosed(packet.StreamId);
            return WriteResetPacketAsync(packet.StreamId, 21, "duplicate HTTP stream");
        }
        _ = Task.Run(channel.RunAsync, _cancellationToken);
        return Task.CompletedTask;
    }

    private async Task HandleWebSocketConnectedAsync(NatMessagePacket packet, PendingOpen pending)
    {
        var channelId = AsString(packet.MetaData, "channelId");
        var route = AsString(packet.MetaData, "route");
        if (string.IsNullOrWhiteSpace(channelId) || string.IsNullOrWhiteSpace(route))
        {
            _logger.LogWarning("[ws-specus][client] CONNECTED missing channelId/route");
            if (FailPendingStream(packet.StreamId, pending))
            {
                await WriteResetPacketAsync(packet.StreamId, 2, "invalid websocket open").ConfigureAwait(false);
            }
            return;
        }

        var routes = _directHttp.SnapshotRoutes();
        if (!routes.TryGetValue(route, out var targetBaseUrl) || string.IsNullOrWhiteSpace(targetBaseUrl))
        {
            _logger.LogWarning("[ws-specus][client] CONNECTED for unknown route {route}", route);
            if (FailPendingStream(packet.StreamId, pending))
            {
                await WriteResetPacketAsync(packet.StreamId, 3, "unknown websocket route").ConfigureAwait(false);
            }
            return;
        }

        var relativePath = AsString(packet.MetaData, "relativePath");
        var rawQuery = AsString(packet.MetaData, "rawQuery");
        if (!TryBuildWebSocketTarget(targetBaseUrl, relativePath, rawQuery, out var target, out var error))
        {
            _logger.LogWarning("[ws-specus][client] CONNECTED route={route} build-target-failed error={error}", route, error);
            if (FailPendingStream(packet.StreamId, pending))
            {
                await WriteResetPacketAsync(packet.StreamId, 4, "invalid websocket target").ConfigureAwait(false);
            }
            return;
        }

        RawWebSocketConnection? socket = null;
        try
        {
            socket = await ConnectLocalWebSocketAsync(target,
                WebSocketHandshakeHeaders(packet.MetaData), pending.Token).ConfigureAwait(false);
            var channel = new WebSocketSpecusChannel(
                packet.StreamId,
                channelId,
                socket,
                _writer,
                _logger,
                c =>
                {
                    if (_wsChannels.TryRemove(
                            new KeyValuePair<uint, WebSocketSpecusChannel>(c.StreamId, c)))
                    {
                        MarkStreamClosed(c.StreamId);
                    }
                });
            channel.SetControlWritable(_controlWritable);
            if (!TryActivateWebSocketStream(
                    packet.StreamId, pending, channel, out var bufferedPackets))
            {
                await channel.DisposeAsync().ConfigureAwait(false);
                return;
            }
            socket = null; // ownership transferred to WebSocketSpecusChannel
            foreach (var buffered in bufferedPackets)
            {
                await HandleBufferedPacketAsync(buffered).ConfigureAwait(false);
            }
            _logger.LogInformation("[ws-specus][client] ws handshake ok channelId={channelId} route={route} target={target}",
                channelId, route, target.GetLeftPart(UriPartial.Path));
            _ = Task.Run(async () =>
            {
                var completion = await channel.PumpAsync(_cancellationToken).ConfigureAwait(false);
                if (completion == WebSocketPumpResult.CloseCreditTimedOut)
                {
                    await SendResetAsync(packet.StreamId, 8, "websocket close credit timeout")
                        .ConfigureAwait(false);
                }
                else
                {
                    await SendFinAsync(packet.StreamId).ConfigureAwait(false);
                }
            }, CancellationToken.None);
        }
        catch (OperationCanceledException) when (pending.Token.IsCancellationRequested)
        {
            if (FailPendingStream(packet.StreamId, pending) && !_cancellationToken.IsCancellationRequested)
            {
                await WriteResetPacketAsync(packet.StreamId, 5, "websocket connect timed out")
                    .ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[ws-specus][client] connect local ws failed channelId={channelId} route={route}", channelId, route);
            if (FailPendingStream(packet.StreamId, pending))
            {
                await WriteResetPacketAsync(packet.StreamId, 5, "websocket connect failed").ConfigureAwait(false);
            }
        }
        finally
        {
            if (socket is not null)
            {
                await socket.DisposeAsync().ConfigureAwait(false);
            }
            pending.Dispose();
        }
    }

    private async Task HandleDataAsync(NatMessagePacket packet)
    {
        if (_httpChannels.TryGetValue(packet.StreamId, out var httpChannel))
        {
            if (packet.Data is null || packet.Data.Length == 0)
            {
                return;
            }
            try
            {
                await httpChannel.OfferRequestDataAsync(packet.Data, _cancellationToken)
                    .ConfigureAwait(false);
                if ((packet.Flags & NatMessagePacket.FlagEndStream) != 0)
                {
                    await httpChannel.FinishRequestAsync(packet.MetaData, _cancellationToken)
                        .ConfigureAwait(false);
                }
            }
            catch (InvalidDataException ex)
            {
                await RejectHttpStreamAsync(packet.StreamId, httpChannel, ex.Message)
                    .ConfigureAwait(false);
            }
            return;
        }
        if (_wsChannels.TryGetValue(packet.StreamId, out var wsChannel))
        {
            if (packet.Data is null || packet.Data.Length == 0)
            {
                return;
            }
            await wsChannel.WriteAsync(packet.Data, _cancellationToken).ConfigureAwait(false);
            await SendWindowUpdateAsync(packet.StreamId, packet.Data.Length).ConfigureAwait(false);
            return;
        }
        if (IsClosedStream(packet.StreamId))
        {
            await WriteResetPacketAsync(packet.StreamId, 7, "DATA for closed stream")
                .ConfigureAwait(false);
            return;
        }
        if (_channels.TryGetValue(packet.StreamId, out var channel))
        {
            var data = packet.Data ?? [];
            if (data.Length > 0)
            {
                var result = await channel.WriteAsync(data, _cancellationToken).ConfigureAwait(false);
                if (result == LocalSpecusWriteResult.DataAfterFin)
                {
                    channel.Reset();
                    await SendResetAsync(packet.StreamId, 7, "TCP DATA after FIN")
                        .ConfigureAwait(false);
                    return;
                }
                if (result == LocalSpecusWriteResult.Reset)
                {
                    await SendResetAsync(packet.StreamId, 7, "local TCP write failed").ConfigureAwait(false);
                    return;
                }
                await SendWindowUpdateAsync(packet.StreamId, data.Length).ConfigureAwait(false);
            }
            if ((packet.Flags & NatMessagePacket.FlagEndStream) != 0)
            {
                await HandleRemoteFinAsync(packet.StreamId).ConfigureAwait(false);
            }
            return;
        }
        var pendingResult = TryBufferPendingPacket(packet);
        if (pendingResult == PendingBufferResult.Buffered)
        {
            return;
        }
        if (pendingResult == PendingBufferResult.Overflow)
        {
            CancelPendingStream(packet.StreamId);
            await WriteResetPacketAsync(packet.StreamId, 7, "DATA before local stream opened")
                .ConfigureAwait(false);
            return;
        }
        RememberClosedStream(packet.StreamId);
        await WriteResetPacketAsync(packet.StreamId, 7, "DATA for unknown TCP stream")
            .ConfigureAwait(false);
    }

    private async Task HandleRemoteFinAsync(uint streamId)
    {
        if (_wsChannels.TryRemove(streamId, out var wsChannel))
        {
            MarkStreamClosed(streamId);
            wsChannel.Close();
            return;
        }
        if (IsClosedStream(streamId))
        {
            await WriteResetPacketAsync(streamId, 7, "FIN for closed stream").ConfigureAwait(false);
            return;
        }
        if (!_channels.TryGetValue(streamId, out var channel))
        {
            var pendingResult = TryBufferPendingPacket(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Fin,
                StreamId = streamId,
            });
            if (pendingResult == PendingBufferResult.Buffered)
            {
                return;
            }
            CancelPendingStream(streamId);
            RememberClosedStream(streamId);
            await WriteResetPacketAsync(streamId, 7, "FIN for unknown TCP stream").ConfigureAwait(false);
            return;
        }

        var result = channel.FinishRemoteDirection();
        if (result == LocalSpecusRemoteFinResult.Invalid)
        {
            channel.Reset();
            await SendResetAsync(streamId, 7, "duplicate TCP FIN").ConfigureAwait(false);
            return;
        }
        if (result == LocalSpecusRemoteFinResult.Reset)
        {
            await SendResetAsync(streamId, 8, "local TCP shutdown failed").ConfigureAwait(false);
        }
    }

    private void HandleReset(uint streamId)
    {
        if (CancelPendingStream(streamId))
        {
            return;
        }
        if (_wsChannels.TryRemove(streamId, out var wsChannel))
        {
            MarkStreamClosed(streamId);
            wsChannel.Close();
            return;
        }
        if (IsClosedStream(streamId))
        {
            return;
        }
        if (_channels.TryGetValue(streamId, out var channel))
        {
            channel.Reset();
            return;
        }
        throw new InvalidDataException($"TCP RST for unknown stream {streamId}");
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
        MarkStreamClosed(streamId);
        await WriteResetPacketAsync(streamId, errorCode, reason).ConfigureAwait(false);
    }

    private async Task WriteResetPacketAsync(uint streamId, uint errorCode, string reason)
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

        var baseUrl = targetBaseUrl.Trim();
        string httpBaseUrl;
        string targetScheme;
        if (baseUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            httpBaseUrl = "http://" + baseUrl["http://".Length..];
            targetScheme = "ws";
        }
        else if (baseUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            httpBaseUrl = "https://" + baseUrl["https://".Length..];
            targetScheme = "wss";
        }
        else if (baseUrl.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            httpBaseUrl = "http://" + baseUrl["ws://".Length..];
            targetScheme = "ws";
        }
        else if (baseUrl.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
        {
            httpBaseUrl = "https://" + baseUrl["wss://".Length..];
            targetScheme = "wss";
        }
        else
        {
            error = "HTTP route 仅支持 http/https/ws/wss";
            return false;
        }

        var tail = string.IsNullOrWhiteSpace(relativePath) ? "/" : relativePath!;
        if (tail.Contains('\r') || tail.Contains('\n'))
        {
            error = "relativePath 含有非法控制字符";
            return false;
        }
        if (!DirectHttpForwarder.TryBuildTarget(httpBaseUrl, tail, rawQuery, out var httpTarget, out error))
        {
            return false;
        }

        var httpText = httpTarget.OriginalString;
        var schemeSeparator = httpText.IndexOf(':');
        if (schemeSeparator < 0
            || !Uri.TryCreate(targetScheme + httpText[schemeSeparator..], UriKind.Absolute, out var created))
        {
            error = "目标地址拼接失败";
            return false;
        }
        target = created;
        return true;
    }

    private async Task RejectHttpStreamAsync(uint streamId, HttpStreamChannel channel, string reason)
    {
        if (_httpChannels.TryRemove(
                new KeyValuePair<uint, HttpStreamChannel>(streamId, channel)))
        {
            MarkStreamClosed(streamId);
            channel.Abort(reason);
            await WriteResetPacketAsync(streamId, 27, reason).ConfigureAwait(false);
        }
    }

    private Task RejectNewHttpStreamAsync(uint streamId, uint errorCode, string reason)
    {
        MarkStreamClosed(streamId);
        return WriteResetPacketAsync(streamId, errorCode, reason);
    }

    private async Task RejectDuplicateOpenAsync(uint streamId, StreamReservationResult result)
    {
        var reason = result == StreamReservationResult.Reused
            ? "reused stream id"
            : result == StreamReservationResult.Excessive
                ? "too many pending streams"
                : "duplicate stream id";

        if (result == StreamReservationResult.Duplicate)
        {
            if (_httpChannels.TryRemove(streamId, out var http))
            {
                http.Abort(reason);
            }
            if (_wsChannels.TryRemove(streamId, out var ws))
            {
                ws.Close();
            }
            if (_channels.TryGetValue(streamId, out var tcp))
            {
                tcp.Reset();
            }
            CancelPendingStream(streamId);
        }
        MarkStreamClosed(streamId);
        await WriteResetPacketAsync(streamId, 7, reason).ConfigureAwait(false);
    }

    private StreamReservationResult TryReserveStream(uint streamId, bool pending,
        out PendingOpen? pendingOpen)
    {
        pendingOpen = null;
        lock (_stateLock)
        {
            if (_closedStreams.ContainsKey(streamId))
            {
                return StreamReservationResult.Reused;
            }
            if (!_openStreamIds.Add(streamId))
            {
                return StreamReservationResult.Duplicate;
            }
            if (!pending)
            {
                return StreamReservationResult.Reserved;
            }
            if (_pendingStreams.Count >= MaximumPendingStreams)
            {
                _openStreamIds.Remove(streamId);
                return StreamReservationResult.Excessive;
            }
            pendingOpen = new PendingOpen(_cancellationToken, LocalConnectTimeout);
            _pendingStreams.Add(streamId, pendingOpen);
            return StreamReservationResult.Reserved;
        }
    }

    private bool TryActivateTcpStream(uint streamId, PendingOpen pending,
        LocalSpecusChannel channel, out IReadOnlyList<NatMessagePacket> bufferedPackets)
    {
        bufferedPackets = [];
        lock (_stateLock)
        {
            if (!_pendingStreams.TryGetValue(streamId, out var current)
                || !ReferenceEquals(current, pending)
                || !_openStreamIds.Contains(streamId))
            {
                return false;
            }
            _pendingStreams.Remove(streamId);
            if (!_channels.TryAdd(streamId, channel))
            {
                _openStreamIds.Remove(streamId);
                RememberClosedStream(streamId);
                return false;
            }
            bufferedPackets = pending.TakeBufferedPackets();
        }
        pending.Dispose();
        return true;
    }

    private bool TryActivateWebSocketStream(uint streamId, PendingOpen pending,
        WebSocketSpecusChannel channel, out IReadOnlyList<NatMessagePacket> bufferedPackets)
    {
        bufferedPackets = [];
        lock (_stateLock)
        {
            if (!_pendingStreams.TryGetValue(streamId, out var current)
                || !ReferenceEquals(current, pending)
                || !_openStreamIds.Contains(streamId))
            {
                return false;
            }
            _pendingStreams.Remove(streamId);
            if (!_wsChannels.TryAdd(streamId, channel))
            {
                _openStreamIds.Remove(streamId);
                RememberClosedStream(streamId);
                return false;
            }
            bufferedPackets = pending.TakeBufferedPackets();
        }
        pending.Dispose();
        return true;
    }

    private bool FailPendingStream(uint streamId, PendingOpen expected)
    {
        var removed = false;
        lock (_stateLock)
        {
            if (_pendingStreams.TryGetValue(streamId, out var current)
                && ReferenceEquals(current, expected))
            {
                _pendingStreams.Remove(streamId);
                _openStreamIds.Remove(streamId);
                removed = true;
            }
        }
        if (removed)
        {
            expected.Cancel();
            expected.Dispose();
            RememberClosedStream(streamId);
        }
        return removed;
    }

    private PendingBufferResult TryBufferPendingPacket(NatMessagePacket packet)
    {
        lock (_stateLock)
        {
            if (!_pendingStreams.TryGetValue(packet.StreamId, out var pending))
            {
                return PendingBufferResult.NotPending;
            }
            return pending.TryBufferPacket(packet, MaximumPendingStreamBytes)
                ? PendingBufferResult.Buffered
                : PendingBufferResult.Overflow;
        }
    }

    private async Task HandleBufferedPacketAsync(NatMessagePacket packet)
    {
        if (packet.NatMessageType == NatMessageType.Data)
        {
            await HandleDataAsync(packet).ConfigureAwait(false);
        }
        else if (packet.NatMessageType == NatMessageType.Fin)
        {
            await HandleRemoteFinAsync(packet.StreamId).ConfigureAwait(false);
        }
    }

    private bool CancelPendingStream(uint streamId)
    {
        PendingOpen? pending = null;
        lock (_stateLock)
        {
            if (_pendingStreams.Remove(streamId, out pending))
            {
                _openStreamIds.Remove(streamId);
            }
        }
        if (pending is null)
        {
            return false;
        }
        pending.Cancel();
        pending.Dispose();
        RememberClosedStream(streamId);
        return true;
    }

    private void MarkStreamClosed(uint streamId)
    {
        PendingOpen? pending = null;
        lock (_stateLock)
        {
            _openStreamIds.Remove(streamId);
            _pendingStreams.Remove(streamId, out pending);
        }
        pending?.Cancel();
        pending?.Dispose();
        RememberClosedStream(streamId);
    }

    private void RememberClosedStream(uint streamId)
    {
        if (!_closedStreams.TryAdd(streamId, 0))
        {
            return;
        }
        _closedStreamOrder.Enqueue(streamId);
        while (_closedStreams.Count > MaximumClosedStreams
               && _closedStreamOrder.TryDequeue(out var expired))
        {
            _closedStreams.TryRemove(expired, out _);
        }
    }

    private bool IsClosedStream(uint streamId) => _closedStreams.ContainsKey(streamId);

    internal bool HasPendingStream(uint streamId)
    {
        lock (_stateLock)
        {
            return _pendingStreams.ContainsKey(streamId);
        }
    }

    internal bool HasTcpStream(uint streamId) => _channels.ContainsKey(streamId);

    private static async Task<TcpClient> ConnectLocalTcpAsync(
        string address, int port, CancellationToken cancellationToken)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
            return tcp;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    internal static Task<RawWebSocketConnection> ConnectLocalWebSocketAsync(Uri target,
        IReadOnlyList<KeyValuePair<string, string>> headers, CancellationToken cancellationToken) =>
        RawWebSocketConnection.ConnectAsync(target, headers, cancellationToken);

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
        PendingOpen[] pending;
        lock (_stateLock)
        {
            pending = _pendingStreams.Values.ToArray();
            _pendingStreams.Clear();
            _openStreamIds.Clear();
        }
        foreach (var open in pending)
        {
            open.Cancel();
            open.Dispose();
        }
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
        _closedStreams.Clear();
        while (_closedStreamOrder.TryDequeue(out _))
        {
        }
    }

    private enum StreamReservationResult
    {
        Reserved,
        Duplicate,
        Reused,
        Excessive,
    }

    private enum PendingBufferResult
    {
        NotPending,
        Buffered,
        Overflow,
    }

    private sealed class PendingOpen : IDisposable
    {
        private readonly CancellationTokenSource _source;
        private readonly List<NatMessagePacket> _bufferedPackets = new();
        private int _bufferedBytes;
        private int _disposed;

        public PendingOpen(CancellationToken session, TimeSpan timeout)
        {
            _source = CancellationTokenSource.CreateLinkedTokenSource(session);
            _source.CancelAfter(timeout);
            Token = _source.Token;
        }

        public CancellationToken Token { get; }

        public bool TryBufferPacket(NatMessagePacket packet, int maximumBytes)
        {
            var bytes = packet.Data?.Length ?? 0;
            if (bytes > maximumBytes - _bufferedBytes)
            {
                return false;
            }
            _bufferedBytes += bytes;
            _bufferedPackets.Add(packet);
            return true;
        }

        public IReadOnlyList<NatMessagePacket> TakeBufferedPackets()
        {
            if (_bufferedPackets.Count == 0)
            {
                return [];
            }
            var packets = _bufferedPackets.ToArray();
            _bufferedPackets.Clear();
            _bufferedBytes = 0;
            return packets;
        }

        public void Cancel()
        {
            try { _source.Cancel(); }
            catch (ObjectDisposedException) { }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                _source.Dispose();
            }
        }
    }
}
