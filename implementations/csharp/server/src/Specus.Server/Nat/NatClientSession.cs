using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data.Entities;
using Specus.Server.Management;

namespace Specus.Server.Nat;

internal sealed class NatClientSession : IAsyncDisposable
{
    private const int MaximumClosedStreamIds = 1024;

    private readonly SpecusConnectionContext _context;
    private readonly RemotePortServerManager _remotePorts;
    private readonly TrafficUsageService _traffic;
    private readonly TrafficInspectionService _inspection;
    private readonly NettyServerOptions _options;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<NatClientSession> _logger;
    private readonly ConcurrentDictionary<int, RemotePortBinding> _bindings = new();
    private readonly ConcurrentDictionary<uint, ExternalConnection> _externalChannels = new();
    private readonly ConcurrentDictionary<uint, HttpSpecusStream> _httpStreams = new();
    private readonly ConcurrentDictionary<uint, WebSocketSpecusStream> _webSocketStreams = new();
    private readonly ConcurrentDictionary<uint, byte> _closedStreamIds = new();
    private readonly ConcurrentQueue<uint> _closedStreamOrder = new();
    private readonly object _admissionLock = new();
    private readonly Dictionary<int, int> _portExternalCounts = new();

    private int _activeClientExternalChannels;
    private int _nextStreamId;
    private volatile bool _registered;

    public NatClientSession(SpecusConnectionContext context,
        RemotePortServerManager remotePorts,
        TrafficUsageService traffic,
        TrafficInspectionService inspection,
        IOptions<NettyServerOptions> options,
        ILoggerFactory loggerFactory,
        ILogger<NatClientSession> logger)
    {
        _context = context;
        _remotePorts = remotePorts;
        _traffic = traffic;
        _inspection = inspection;
        _options = options.Value;
        _loggerFactory = loggerFactory;
        _logger = logger;
        _context.WriteBackpressure.BackpressureChanged += OnControlWriteBackpressureChanged;
    }

    public async Task HandleAsync(NatMessagePacket packet)
    {
        switch (packet.NatMessageType)
        {
            case NatMessageType.Register:
                await ProcessRegisterAsync(packet).ConfigureAwait(false);
                return;
            case NatMessageType.Unregister:
                await ProcessUnregisterAsync(packet).ConfigureAwait(false);
                return;
            case NatMessageType.Keepalive:
                return;
            case NatMessageType.Open:
                if (HandleHttpResponseHead(packet))
                {
                    return;
                }
                break;
            case NatMessageType.Data:
                if (_httpStreams.TryGetValue(packet.StreamId, out var httpData))
                {
                    if (!httpData.OnResponseData(packet.Data))
                    {
                        ProtocolViolation("invalid HTTP DATA");
                        return;
                    }
                    if ((packet.Flags & NatMessagePacket.FlagEndStream) != 0
                        && !httpData.OnResponseEnd(packet.MetaData))
                    {
                        ProtocolViolation("invalid HTTP terminal frame");
                    }
                    return;
                }
                if (_webSocketStreams.TryGetValue(packet.StreamId, out var webSocketData))
                {
                    var result = webSocketData.OnData(packet.Data);
                    if (result == WebSocketStreamIngestResult.FlowControlViolation)
                    {
                        ProtocolViolation("invalid WebSocket DATA");
                    }
                    else if (result == WebSocketStreamIngestResult.QueueFull)
                    {
                        await webSocketData.ResetAsync(31, "WebSocket browser is too slow",
                            _context.Lifetime).ConfigureAwait(false);
                    }
                    return;
                }
                if (IsClosedStream(packet.StreamId))
                {
                    await RejectTcpStreamAsync(packet.StreamId, 7, "DATA for closed stream")
                        .ConfigureAwait(false);
                    return;
                }
                if (_registered)
                {
                    await ProcessDataAsync(packet).ConfigureAwait(false);
                    return;
                }
                break;
            case NatMessageType.Fin:
            case NatMessageType.Rst:
                if (_httpStreams.TryGetValue(packet.StreamId, out var httpEnd))
                {
                    var valid = packet.NatMessageType == NatMessageType.Rst
                        ? httpEnd.OnReset(AsString(packet.MetaData, "reason"))
                        : httpEnd.OnResponseEnd(packet.MetaData);
                    if (!valid)
                    {
                        ProtocolViolation("invalid HTTP terminal frame");
                    }
                    return;
                }
                if (_webSocketStreams.TryGetValue(packet.StreamId, out var webSocketEnd))
                {
                    if (packet.NatMessageType == NatMessageType.Rst)
                    {
                        webSocketEnd.OnReset(AsString(packet.MetaData, "reason"));
                    }
                    else
                    {
                        webSocketEnd.OnEnd();
                    }
                    return;
                }
                if (IsClosedStream(packet.StreamId))
                {
                    if (packet.NatMessageType == NatMessageType.Rst)
                    {
                        return;
                    }
                    await RejectTcpStreamAsync(packet.StreamId, 7, "FIN for closed stream")
                        .ConfigureAwait(false);
                    return;
                }
                if (_registered)
                {
                    await ProcessClosedAsync(packet).ConfigureAwait(false);
                    return;
                }
                break;
            case NatMessageType.WindowUpdate:
                if (_httpStreams.TryGetValue(packet.StreamId, out var httpFlow))
                {
                    if (!httpFlow.AddSendCredit(packet.Value))
                    {
                        ProtocolViolation("invalid HTTP WINDOW_UPDATE");
                    }
                    return;
                }
                if (_webSocketStreams.TryGetValue(packet.StreamId, out var webSocketFlow))
                {
                    if (!webSocketFlow.AddSendCredit(packet.Value))
                    {
                        ProtocolViolation("invalid WebSocket WINDOW_UPDATE");
                    }
                    return;
                }
                if (IsClosedStream(packet.StreamId))
                {
                    return;
                }
                if (!_registered)
                {
                    break;
                }
                if (!_externalChannels.TryGetValue(packet.StreamId, out var flow)
                    || flow.AddSendCredit(packet.Value))
                {
                    return;
                }
                _logger.LogWarning("invalid WINDOW_UPDATE stream={StreamId} credit={Credit}",
                    packet.StreamId, packet.Value);
                _context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
                _context.CloseAsync();
                return;
            default:
                break;
        }
        ProtocolViolation($"invalid NAT frame {packet.NatMessageType}");
    }

    internal async Task<HttpSpecusStream> OpenHttpStreamAsync(
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        var streamId = AllocateStreamId();
        var stream = new HttpSpecusStream(_context, streamId, RemoveHttpStream);
        if (!_httpStreams.TryAdd(streamId, stream))
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw new InvalidOperationException("HTTP stream id collision");
        }
        try
        {
            await _context.Writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Open,
                StreamId = streamId,
                MetaData = metadata,
            }, cancellationToken).ConfigureAwait(false);
            return stream;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    internal async Task<WebSocketSpecusStream> OpenWebSocketStreamAsync(
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        var streamId = AllocateStreamId();
        var stream = new WebSocketSpecusStream(_context, streamId, RemoveWebSocketStream);
        if (!_webSocketStreams.TryAdd(streamId, stream))
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw new InvalidOperationException("WebSocket stream id collision");
        }
        try
        {
            await _context.Writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Open,
                StreamId = streamId,
                MetaData = metadata,
            }, cancellationToken).ConfigureAwait(false);
            return stream;
        }
        catch
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _context.WriteBackpressure.BackpressureChanged -= OnControlWriteBackpressureChanged;

        foreach (var (_, binding) in _bindings.ToArray())
        {
            _bindings.TryRemove(binding.Port, out _);
            await binding.DisposeAsync().ConfigureAwait(false);
        }

        foreach (var (_, external) in _externalChannels.ToArray())
        {
            if (_externalChannels.TryRemove(external.StreamId, out var removed))
            {
                removed.WriteBackpressure.BackpressureChanged -= OnExternalWriteBackpressureChanged;
                await removed.DisposeAsync().ConfigureAwait(false);
            }
        }
        _externalChannels.Clear();
        foreach (var stream in _httpStreams.Values)
        {
            stream.OnReset("control channel closed");
        }
        _httpStreams.Clear();
        foreach (var stream in _webSocketStreams.Values)
        {
            stream.OnReset("control channel closed");
        }
        _webSocketStreams.Clear();
        _closedStreamIds.Clear();
        while (_closedStreamOrder.TryDequeue(out _))
        {
        }
    }

    private async Task ProcessRegisterAsync(NatMessagePacket packet)
    {
        var meta = packet.MetaData;
        var port = AsInt(meta, "port");
        var specusPort = AsInt(meta, "specusPort");
        var specusAddress = AsString(meta, "specusAddress");
        var requestedClientName = AsString(meta, "clientName");

        var result = new Dictionary<string, object?>();
        if (port is not null)
        {
            result["port"] = port.Value;
        }

        if (port is null || specusPort is null || string.IsNullOrEmpty(specusAddress)
            || string.IsNullOrEmpty(requestedClientName))
        {
            result["success"] = false;
            result["reason"] = "missing required metadata";
            await WriteRegisterResultAsync(result).ConfigureAwait(false);
            _context.MarkDisconnectIfAbsent(DisconnectReason.RegisterFailed);
            _context.CloseAsync();
            return;
        }

        if (!string.Equals(_context.ClientName, requestedClientName, StringComparison.Ordinal))
        {
            _logger.LogWarning("REGISTER clientName mismatch: session={SessionClient}, claimed={Claimed}",
                _context.ClientName, requestedClientName);
            _context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
            _context.CloseAsync();
            return;
        }

        if (_bindings.ContainsKey(port.Value))
        {
            result["success"] = false;
            result["reason"] = $"port {port.Value} already in use";
            await WriteRegisterResultAsync(result).ConfigureAwait(false);
            return;
        }

        try
        {
            var binding = await _remotePorts.BindAsync(port.Value,
                    (socket, ct) => AcceptExternalAsync(port.Value, socket, ct),
                    _context.Lifetime)
                .ConfigureAwait(false);
            if (!_bindings.TryAdd(port.Value, binding))
            {
                await binding.DisposeAsync().ConfigureAwait(false);
                throw new InvalidOperationException($"port {port.Value} already in use");
            }

            _registered = true;
            result["success"] = true;
            _logger.LogInformation("register success, start server on port {Port} --> {Address}:{TargetPort} [{Client}]",
                port.Value, specusAddress, specusPort.Value, _context.ClientName);
        }
        catch (Exception ex)
        {
            result["success"] = false;
            result["reason"] = ex.Message;
            _logger.LogError(ex, "REGISTER failed on port {Port} [{Client}]", port.Value, _context.ClientName);
        }

        await WriteRegisterResultAsync(result).ConfigureAwait(false);
    }

    private async Task ProcessUnregisterAsync(NatMessagePacket packet)
    {
        var port = AsInt(packet.MetaData, "port");
        if (port is null)
        {
            return;
        }

        if (_bindings.TryRemove(port.Value, out var binding))
        {
            await binding.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task ProcessDataAsync(NatMessagePacket packet)
    {
        if (!_externalChannels.TryGetValue(packet.StreamId, out var external))
        {
            await RejectTcpStreamAsync(packet.StreamId, 7, "DATA for unknown TCP stream")
                .ConfigureAwait(false);
            return;
        }

        var data = packet.Data ?? [];
        var result = await external.WriteFromClientAsync(data, _context.Lifetime).ConfigureAwait(false);
        if (result == ExternalWriteResult.DataAfterFin)
        {
            await external.SendResetAsync(7, "TCP DATA after FIN", CancellationToken.None)
                .ConfigureAwait(false);
            return;
        }
        if (result == ExternalWriteResult.Reset)
        {
            await external.SendResetAsync(41, "public TCP write failed", CancellationToken.None)
                .ConfigureAwait(false);
            return;
        }
        if (data.Length > 0)
        {
            await _context.Writer.WritePriorityAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.WindowUpdate,
                StreamId = packet.StreamId,
                Value = checked((uint)data.Length),
            }, _context.Lifetime).ConfigureAwait(false);
        }
        if ((packet.Flags & NatMessagePacket.FlagEndStream) != 0)
        {
            await ProcessClosedAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Fin,
                StreamId = packet.StreamId,
            }).ConfigureAwait(false);
        }
    }

    private async Task ProcessClosedAsync(NatMessagePacket packet)
    {
        if (!_externalChannels.TryGetValue(packet.StreamId, out var external))
        {
            if (packet.NatMessageType == NatMessageType.Rst)
            {
                if (IsClosedStream(packet.StreamId))
                {
                    return;
                }
                ProtocolViolation($"TCP RST for never-opened stream {packet.StreamId}");
                return;
            }
            await RejectTcpStreamAsync(packet.StreamId, 7, "FIN for unknown TCP stream")
                .ConfigureAwait(false);
            return;
        }

        if (packet.NatMessageType == NatMessageType.Rst)
        {
            RememberClosedStream(packet.StreamId);
            external.ResetFromClient();
            return;
        }

        var result = external.FinishClientDirection();
        if (result == ExternalFinResult.Invalid)
        {
            await external.SendResetAsync(7, "duplicate TCP FIN", CancellationToken.None)
                .ConfigureAwait(false);
            return;
        }
        if (result == ExternalFinResult.Reset)
        {
            await external.SendResetAsync(42, "public TCP shutdown failed", CancellationToken.None)
                .ConfigureAwait(false);
        }
        UpdateControlReadForWritability();
    }

    private async Task AcceptExternalAsync(int port, Socket socket, CancellationToken cancellationToken)
    {
        if (!TryAcquireExternalChannel(port))
        {
            try { socket.Close(); } catch { /* already closed */ }
            return;
        }

        ExternalConnection? external = null;
        try
        {
            var streamId = AllocateStreamId();
            external = new ExternalConnection(socket, streamId, port, _context.ClientName!,
                _context, _traffic, _inspection, _options, _loggerFactory.CreateLogger<ExternalConnection>());
            external.WriteBackpressure.BackpressureChanged += OnExternalWriteBackpressureChanged;

            // Mirror Java's `syncExternalReadWithControl`: a fresh external inherits the
            // control channel's read state so a paused control immediately throttles a new
            // external too.
            if (_context.WriteBackpressure.IsBackpressured)
            {
                external.ReadGate.Pause();
            }

            _externalChannels[external.StreamId] = external;
            UpdateControlReadForWritability();
            await external.RunAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (external is not null)
            {
                external.WriteBackpressure.BackpressureChanged -= OnExternalWriteBackpressureChanged;
                _externalChannels.TryRemove(external.StreamId, out _);
                RememberClosedStream(external.StreamId);
                _inspection.ReleaseTcpStream(external.ChannelId);
                UpdateControlReadForWritability();
            }
            ReleaseExternalChannel(port);
        }
    }

    private void OnControlWriteBackpressureChanged(bool _)
    {
        UpdateExternalReadsForControlWritability();
        UpdateControlReadForWritability();
    }

    private void OnExternalWriteBackpressureChanged(bool _) =>
        UpdateControlReadForWritability();

    private void UpdateExternalReadsForControlWritability()
    {
        var controlWritable = !_context.WriteBackpressure.IsBackpressured;
        foreach (var external in _externalChannels.Values)
        {
            if (controlWritable)
            {
                external.ReadGate.Resume();
            }
            else
            {
                external.ReadGate.Pause();
            }
        }
    }

    private void UpdateControlReadForWritability()
    {
        var controlWritable = !_context.WriteBackpressure.IsBackpressured;
        var externalsWritable = _externalChannels.Values.All(static external =>
            !external.WriteBackpressure.IsBackpressured);

        if (controlWritable && externalsWritable)
        {
            _context.ReadGate.Resume();
        }
        else
        {
            _context.ReadGate.Pause();
        }
    }

    private bool TryAcquireExternalChannel(int port)
    {
        var tenantId = _context.TenantId;
        if (!_remotePorts.TryAcquireExternalConnection(tenantId))
        {
            return false;
        }

        lock (_admissionLock)
        {
            if (ReachedLimit(_activeClientExternalChannels, _options.MaxExternalConnectionsPerClient))
            {
                _remotePorts.ReleaseExternalConnection(tenantId);
                _remotePorts.RecordRejectedExternalConnection(tenantId);
                return false;
            }

            _portExternalCounts.TryGetValue(port, out var portCount);
            if (ReachedLimit(portCount, _options.MaxExternalConnectionsPerPort))
            {
                _remotePorts.ReleaseExternalConnection(tenantId);
                _remotePorts.RecordRejectedExternalConnection(tenantId);
                return false;
            }

            _activeClientExternalChannels++;
            _portExternalCounts[port] = portCount + 1;
            return true;
        }
    }

    private void ReleaseExternalChannel(int port)
    {
        lock (_admissionLock)
        {
            if (_activeClientExternalChannels > 0)
            {
                _activeClientExternalChannels--;
            }

            if (_portExternalCounts.TryGetValue(port, out var count))
            {
                if (count <= 1)
                {
                    _portExternalCounts.Remove(port);
                }
                else
                {
                    _portExternalCounts[port] = count - 1;
                }
            }
        }

        _remotePorts.ReleaseExternalConnection(_context.TenantId);
    }

    private static bool ReachedLimit(int current, int max) => max > 0 && current >= max;

    private uint AllocateStreamId()
    {
        while (true)
        {
            var streamId = unchecked((uint)Interlocked.Increment(ref _nextStreamId));
            if (streamId != 0 && !_externalChannels.ContainsKey(streamId)
                              && !_httpStreams.ContainsKey(streamId)
                              && !_webSocketStreams.ContainsKey(streamId))
            {
                _closedStreamIds.TryRemove(streamId, out _);
                return streamId;
            }
        }
    }

    private bool HandleHttpResponseHead(NatMessagePacket packet)
    {
        if (!string.Equals(AsString(packet.MetaData, "source"), "http", StringComparison.Ordinal)
            || !string.Equals(AsString(packet.MetaData, "phase"), "response", StringComparison.Ordinal)
            || !_httpStreams.TryGetValue(packet.StreamId, out var stream))
        {
            return false;
        }
        if (!stream.OnResponseHead(packet.MetaData))
        {
            ProtocolViolation("duplicate HTTP response OPEN");
        }
        return true;
    }

    private void RemoveHttpStream(uint streamId, HttpSpecusStream expected)
    {
        if (_httpStreams.TryRemove(new KeyValuePair<uint, HttpSpecusStream>(streamId, expected)))
        {
            RememberClosedStream(streamId);
        }
    }

    private void RemoveWebSocketStream(uint streamId, WebSocketSpecusStream expected)
    {
        if (!_webSocketStreams.TryRemove(
                new KeyValuePair<uint, WebSocketSpecusStream>(streamId, expected)))
        {
            return;
        }
        RememberClosedStream(streamId);
    }

    private void RememberClosedStream(uint streamId)
    {
        if (!_closedStreamIds.TryAdd(streamId, 0))
        {
            return;
        }
        _closedStreamOrder.Enqueue(streamId);
        while (_closedStreamIds.Count > MaximumClosedStreamIds
               && _closedStreamOrder.TryDequeue(out var expired))
        {
            _closedStreamIds.TryRemove(expired, out _);
        }
    }

    internal bool IsClosedStream(uint streamId) => _closedStreamIds.ContainsKey(streamId);

    internal bool HasExternalStream(uint streamId) => _externalChannels.ContainsKey(streamId);

    private async Task RejectTcpStreamAsync(uint streamId, uint errorCode, string reason)
    {
        RememberClosedStream(streamId);
        await _context.Writer.WritePriorityAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Rst,
            StreamId = streamId,
            Value = errorCode,
            MetaData = new Dictionary<string, object?> { ["reason"] = reason },
        }, _context.Lifetime).ConfigureAwait(false);
    }

    private void ProtocolViolation(string reason)
    {
        _logger.LogWarning("{Reason} on channel {ChannelId}", reason, _context.ChannelId);
        _context.MarkDisconnectIfAbsent(DisconnectReason.ProtocolViolation);
        _context.CloseAsync();
    }

    private ValueTask WriteRegisterResultAsync(Dictionary<string, object?> metaData)
    {
        return _context.Writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.RegisterResult,
            MetaData = metaData,
        }, _context.Lifetime);
    }

    private static string? AsString(Dictionary<string, object?>? meta, string key)
    {
        if (meta is null || !meta.TryGetValue(key, out var value))
        {
            return null;
        }
        return value switch
        {
            null => null,
            string s => s,
            bool b => b ? "true" : "false",
            IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
            JsonElement element => element.ValueKind switch
            {
                JsonValueKind.Null or JsonValueKind.Undefined => null,
                JsonValueKind.String => element.GetString(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                JsonValueKind.Number => element.GetRawText(),
                _ => element.ToString(),
            },
            _ => value.ToString(),
        };
    }

    private static int? AsInt(Dictionary<string, object?>? meta, string key)
    {
        if (meta is null || !meta.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }
        return value switch
        {
            int i => i,
            long l => unchecked((int)l),
            short s => s,
            byte b => b,
            float f => (int)f,
            double d => (int)d,
            decimal m => (int)m,
            JsonElement e when e.ValueKind == JsonValueKind.Number && e.TryGetInt32(out var parsedJsonInt) => parsedJsonInt,
            JsonElement e when e.ValueKind == JsonValueKind.Number && e.TryGetDouble(out var parsedJsonDouble) => (int)parsedJsonDouble,
            JsonElement e when e.ValueKind == JsonValueKind.String => ParseInt(e.GetString()),
            string s when int.TryParse(s, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.InvariantCulture, out var parsed) => parsed,
            _ => null,
        };
    }

    private static int? ParseInt(string? value)
    {
        return int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
            ? parsed
            : null;
    }
}
