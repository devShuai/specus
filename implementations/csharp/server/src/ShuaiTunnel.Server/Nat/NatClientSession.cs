using System.Collections.Concurrent;
using System.Globalization;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.ControlChannel;
using ShuaiTunnel.Server.Data.Entities;
using ShuaiTunnel.Server.Management;

namespace ShuaiTunnel.Server.Nat;

internal sealed class NatClientSession : IAsyncDisposable
{
    private readonly TunnelConnectionContext _context;
    private readonly RemotePortServerManager _remotePorts;
    private readonly TrafficUsageService _traffic;
    private readonly TrafficInspectionService _inspection;
    private readonly NettyServerOptions _options;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<NatClientSession> _logger;
    private readonly ConcurrentDictionary<int, RemotePortBinding> _bindings = new();
    private readonly ConcurrentDictionary<uint, ExternalConnection> _externalChannels = new();
    private readonly ConcurrentDictionary<uint, HttpTunnelStream> _httpStreams = new();
    private readonly object _admissionLock = new();
    private readonly Dictionary<int, int> _portExternalCounts = new();

    private int _activeClientExternalChannels;
    private int _nextStreamId;
    private volatile bool _registered;

    public NatClientSession(TunnelConnectionContext context,
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
                    }
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

    internal async Task<HttpTunnelStream> OpenHttpStreamAsync(
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        var streamId = AllocateStreamId();
        var stream = new HttpTunnelStream(_context, streamId, RemoveHttpStream);
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
    }

    private async Task ProcessRegisterAsync(NatMessagePacket packet)
    {
        var meta = packet.MetaData;
        var port = AsInt(meta, "port");
        var tunnelPort = AsInt(meta, "tunnelPort");
        var tunnelAddress = AsString(meta, "tunnelAddress");
        var requestedClientName = AsString(meta, "clientName");

        var result = new Dictionary<string, object?>();
        if (port is not null)
        {
            result["port"] = port.Value;
        }

        if (port is null || tunnelPort is null || string.IsNullOrEmpty(tunnelAddress)
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
                port.Value, tunnelAddress, tunnelPort.Value, _context.ClientName);
        }
        catch (Exception ex)
        {
            result["success"] = false;
            result["reason"] = ex.Message;
            _logger.LogError(ex, "REGISTER failed on port {Port} [{Client}]", port.Value, _context.ClientName);
        }

        await WriteRegisterResultAsync(result).ConfigureAwait(false);
        if (!Equals(result["success"], true))
        {
            _context.MarkDisconnectIfAbsent(DisconnectReason.RegisterFailed);
            _context.CloseAsync();
        }
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
        if (packet.Data is not { Length: > 0 } data)
        {
            return;
        }
        if (!_externalChannels.TryGetValue(packet.StreamId, out var external))
        {
            return;
        }

        await external.WriteFromClientAsync(data, _context.Lifetime).ConfigureAwait(false);
        await _context.Writer.WritePriorityAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.WindowUpdate,
            StreamId = packet.StreamId,
            Value = checked((uint)data.Length),
        }, _context.Lifetime).ConfigureAwait(false);
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
        if (!_externalChannels.TryRemove(packet.StreamId, out var external))
        {
            return;
        }

        external.WriteBackpressure.BackpressureChanged -= OnExternalWriteBackpressureChanged;
        await external.DisposeAsync().ConfigureAwait(false);
        _inspection.ReleaseTcpStream(external.ChannelId);
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
        if (!_remotePorts.TryAcquireExternalConnection())
        {
            return false;
        }

        lock (_admissionLock)
        {
            if (ReachedLimit(_activeClientExternalChannels, _options.MaxExternalConnectionsPerClient))
            {
                _remotePorts.ReleaseExternalConnection();
                _remotePorts.RecordRejectedExternalConnection();
                return false;
            }

            _portExternalCounts.TryGetValue(port, out var portCount);
            if (ReachedLimit(portCount, _options.MaxExternalConnectionsPerPort))
            {
                _remotePorts.ReleaseExternalConnection();
                _remotePorts.RecordRejectedExternalConnection();
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

        _remotePorts.ReleaseExternalConnection();
    }

    private static bool ReachedLimit(int current, int max) => max > 0 && current >= max;

    private uint AllocateStreamId()
    {
        while (true)
        {
            var streamId = unchecked((uint)Interlocked.Increment(ref _nextStreamId));
            if (streamId != 0 && !_externalChannels.ContainsKey(streamId)
                              && !_httpStreams.ContainsKey(streamId))
            {
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

    private void RemoveHttpStream(uint streamId, HttpTunnelStream expected) =>
        _httpStreams.TryRemove(new KeyValuePair<uint, HttpTunnelStream>(streamId, expected));

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
