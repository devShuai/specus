using System.Collections.Concurrent;
using System.Globalization;
using System.IO.Compression;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Data;
using ShuaiTunnel.Server.Data.Entities;

namespace ShuaiTunnel.Server.Management;

public sealed class TrafficInspectionService : BackgroundService
{
    public const string DirectionPublicToClient = "PUBLIC_TO_CLIENT";
    public const string DirectionClientToPublic = "CLIENT_TO_PUBLIC";
    private static readonly TimeSpan CaptureDecisionTtl = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan DefaultCaptureFlushInterval = TimeSpan.FromSeconds(2);

    private readonly IServiceProvider _services;
    private readonly TrafficOptions _options;
    private readonly ElasticsearchTrafficDetailClient _elasticsearch;
    private readonly ILogger<TrafficInspectionService> _logger;
    private readonly ConcurrentQueue<PendingHttpExchange> _pendingHttpExchanges = new();
    private readonly ConcurrentQueue<PendingTcpFrame> _pendingTcpFrames = new();
    private readonly ConcurrentDictionary<string, CaptureDecision> _detailCaptureDecisionCache = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, StreamCursor> _tcpCursors = new(StringComparer.Ordinal);
    private readonly SemaphoreSlim _flushLock = new(1, 1);
    private int _pendingHttpCount;
    private int _pendingTcpCount;

    public TrafficInspectionService(IServiceProvider services, IOptions<TrafficOptions> options,
        ElasticsearchTrafficDetailClient elasticsearch, ILogger<TrafficInspectionService> logger)
    {
        _services = services;
        _options = options.Value;
        _elasticsearch = elasticsearch;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(CaptureFlushInterval);
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                try
                {
                    await FlushAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Traffic detail flush failed");
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown path.
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        await FlushAsync(CancellationToken.None).ConfigureAwait(false);
    }

    public async Task RecordHttpExchangeAsync(HttpExchangeCapture capture, CancellationToken cancellationToken)
    {
        if (!_options.CaptureDetailEnabled || string.IsNullOrWhiteSpace(capture.ClientName))
        {
            return;
        }

        var route = (capture.Route ?? string.Empty).Trim();
        if (!await ShouldCaptureHttpDetailAsync(capture.ClientName, route, cancellationToken).ConfigureAwait(false)
            || !AcquireSlot(ref _pendingHttpCount))
        {
            return;
        }

        var requestContentType = HeaderValue(capture.RequestHeaders, "content-type");
        var responseContentType = HeaderValue(capture.ResponseHeaders, "content-type");
        var now = DateTimeOffset.UtcNow;
        var success = capture.Error is null;
        _pendingHttpExchanges.Enqueue(new PendingHttpExchange(
            capture.ClientName,
            route,
            Cap(capture.Method, 16) ?? string.Empty,
            Cap(string.IsNullOrWhiteSpace(capture.RelativePath) ? "/" : capture.RelativePath, 1024) ?? "/",
            Cap(capture.RawQuery, 2048),
            capture.StatusCode <= 0
                ? success ? StatusCodes.Status200OK : StatusCodes.Status502BadGateway
                : capture.StatusCode,
            success,
            Cap(capture.Error, 2048),
            Cap(capture.RemoteAddress, 255),
            capture.RequestBody?.LongLength ?? 0,
            capture.ResponseBody?.LongLength ?? 0,
            Math.Max(0, (long)(now - capture.StartedAt.ToUniversalTime()).TotalMilliseconds),
            Cap(requestContentType, 255),
            Cap(responseContentType, 255),
            ClassifyHttpBody(responseContentType, capture.ResponseBody?.Length ?? 0),
            Cap(JoinHeaders(capture.RequestHeaders), HeaderChars),
            Cap(JoinHeaders(capture.ResponseHeaders), HeaderChars),
            string.Empty,
            BodyText(capture.RequestBody, requestContentType, HeaderValue(capture.RequestHeaders, "content-encoding")),
            string.Empty,
            BodyText(capture.ResponseBody, responseContentType, HeaderValue(capture.ResponseHeaders, "content-encoding")),
            false,
            false,
            now));
    }

    public async Task RecordTcpFrameAsync(TcpFrameCapture capture, CancellationToken cancellationToken)
    {
        if (!_options.CaptureDetailEnabled
            || string.IsNullOrWhiteSpace(capture.ClientName)
            || capture.ListenPort <= 0)
        {
            return;
        }

        if (!await ShouldCaptureTcpDetailAsync(capture.ClientName, capture.ListenPort, cancellationToken).ConfigureAwait(false)
            || !AcquireSlot(ref _pendingTcpCount))
        {
            return;
        }

        var payload = capture.Payload ?? [];
        var (offset, endOffset, frameIndex) = NextPosition(capture.ClientName, capture.ListenPort,
            capture.ChannelId, capture.Direction, payload.Length);
        var (hex, text, truncated) = TcpPreview(payload, PreviewBytes);
        _pendingTcpFrames.Enqueue(new PendingTcpFrame(
            capture.ClientName,
            capture.ListenPort,
            Cap(capture.ChannelId, 120) ?? string.Empty,
            Cap(capture.Direction, 32) ?? string.Empty,
            PeerAddress(capture.Direction, capture.SourceAddress, capture.SourcePort,
                capture.DestinationAddress, capture.DestinationPort),
            Cap(capture.SourceAddress, 255),
            capture.SourcePort,
            Cap(capture.DestinationAddress, 255),
            capture.DestinationPort,
            offset,
            endOffset,
            frameIndex,
            payload.LongLength,
            payload.ToArray(),
            hex,
            text,
            truncated,
            DateTimeOffset.UtcNow));
    }

    public void ReleaseTcpStream(string? channelId)
    {
        if (string.IsNullOrWhiteSpace(channelId))
        {
            return;
        }
        var token = "|" + channelId + "|";
        foreach (var key in _tcpCursors.Keys)
        {
            if (key.Contains(token, StringComparison.Ordinal))
            {
                _tcpCursors.TryRemove(key, out _);
            }
        }
    }

    public async Task FlushAsync(CancellationToken cancellationToken = default)
    {
        await _flushLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await FlushHttpAsync(cancellationToken).ConfigureAwait(false);
            await FlushTcpAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _flushLock.Release();
        }
    }

    private async Task FlushHttpAsync(CancellationToken cancellationToken)
    {
        var pending = DrainHttp();
        if (pending.Count == 0)
        {
            return;
        }

        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var accounts = new Dictionary<string, ClientAccount?>(StringComparer.Ordinal);
        var rows = new List<HttpTrafficExchange>(pending.Count);
        foreach (var item in pending)
        {
            if (!accounts.TryGetValue(item.ClientName, out var account))
            {
                account = await db.ClientAccounts.AsNoTracking()
                    .FirstOrDefaultAsync(c => c.ClientName == item.ClientName, cancellationToken)
                    .ConfigureAwait(false);
                accounts[item.ClientName] = account;
            }
            if (account is null)
            {
                continue;
            }

            var descriptor = await ResolveHttpResourceAsync(db, account, item.Route, cancellationToken)
                .ConfigureAwait(false);
            rows.Add(new HttpTrafficExchange
            {
                TenantId = account.TenantId,
                ClientId = account.Id,
                ClientName = account.ClientName,
                Route = item.Route,
                ResourceId = descriptor.ResourceId,
                ResourceName = descriptor.ResourceName,
                Method = item.Method,
                RelativePath = item.RelativePath,
                RawQuery = item.RawQuery,
                StatusCode = item.StatusCode,
                Success = item.Success,
                Error = item.Error,
                RemoteAddress = item.RemoteAddress,
                RequestBytes = item.RequestBytes,
                ResponseBytes = item.ResponseBytes,
                ElapsedMs = item.ElapsedMs,
                RequestContentType = item.RequestContentType,
                ResponseContentType = item.ResponseContentType,
                ResponseBodyType = item.ResponseBodyType,
                RequestHeaders = item.RequestHeaders,
                ResponseHeaders = item.ResponseHeaders,
                RequestPreviewHex = item.RequestPreviewHex,
                RequestPreviewText = item.RequestPreviewText,
                ResponsePreviewHex = item.ResponsePreviewHex,
                ResponsePreviewText = item.ResponsePreviewText,
                RequestTruncated = item.RequestTruncated,
                ResponseTruncated = item.ResponseTruncated,
                CapturedAt = item.CapturedAt,
            });
        }

        if (rows.Count == 0)
        {
            return;
        }

        if (_elasticsearch.IsEnabled)
        {
            foreach (var row in rows)
            {
                await _elasticsearch.SaveHttpAsync(row, cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            db.HttpTrafficExchanges.AddRange(rows);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task FlushTcpAsync(CancellationToken cancellationToken)
    {
        var pending = DrainTcp();
        if (pending.Count == 0)
        {
            return;
        }

        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
        var accounts = new Dictionary<string, ClientAccount?>(StringComparer.Ordinal);
        var rows = new List<TcpTrafficFrame>(pending.Count);
        foreach (var item in pending)
        {
            if (!accounts.TryGetValue(item.ClientName, out var account))
            {
                account = await db.ClientAccounts.AsNoTracking()
                    .FirstOrDefaultAsync(c => c.ClientName == item.ClientName, cancellationToken)
                    .ConfigureAwait(false);
                accounts[item.ClientName] = account;
            }
            if (account is null)
            {
                continue;
            }

            var descriptor = await ResolveTcpResourceAsync(db, account, item.ListenPort, cancellationToken)
                .ConfigureAwait(false);
            rows.Add(new TcpTrafficFrame
            {
                TenantId = account.TenantId,
                ClientId = account.Id,
                ClientName = account.ClientName,
                ListenPort = item.ListenPort,
                ResourceId = descriptor.ResourceId,
                ResourceName = descriptor.ResourceName,
                ChannelId = item.ChannelId,
                Direction = item.Direction,
                RemoteAddress = item.RemoteAddress,
                SourceAddress = item.SourceAddress,
                SourcePort = item.SourcePort,
                DestinationAddress = item.DestinationAddress,
                DestinationPort = item.DestinationPort,
                StreamOffset = item.StreamOffset,
                StreamEndOffset = item.StreamEndOffset,
                FrameIndex = item.FrameIndex,
                PayloadBytes = item.PayloadBytes,
                PayloadData = item.PayloadData,
                PayloadPreviewHex = item.PayloadPreviewHex,
                PayloadPreviewText = item.PayloadPreviewText,
                Truncated = item.Truncated,
                FrameTime = item.FrameTime,
            });
        }

        if (rows.Count == 0)
        {
            return;
        }

        if (_elasticsearch.IsEnabled)
        {
            foreach (var row in rows)
            {
                await _elasticsearch.SaveTcpAsync(row, cancellationToken).ConfigureAwait(false);
            }
        }
        else
        {
            db.TcpTrafficFrames.AddRange(rows);
            await db.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private (long Offset, long EndOffset, long FrameIndex) NextPosition(
        string clientName, int listenPort, string channelId, string direction, int payloadBytes)
    {
        var key = $"{clientName}|{listenPort}|{channelId}|{direction}";
        var cursor = _tcpCursors.GetOrAdd(key, _ => new StreamCursor());
        var offset = cursor.AddPayload(payloadBytes);
        var index = cursor.NextIndex();
        return (offset, offset + payloadBytes, index);
    }

    private int PreviewBytes => _options.CapturePreviewBytes <= 0 ? 256 : _options.CapturePreviewBytes;
    private int HeaderChars => _options.CaptureHeaderChars <= 0 ? 8192 : _options.CaptureHeaderChars;
    private int MaxPending => Math.Max(0, _options.CaptureMaxPending);
    private int FlushBatchSize => Math.Max(1, _options.CaptureFlushBatchSize);
    private TimeSpan CaptureFlushInterval => _options.CaptureFlushIntervalMs > 0
        ? TimeSpan.FromMilliseconds(_options.CaptureFlushIntervalMs)
        : DefaultCaptureFlushInterval;

    private async Task<bool> ShouldCaptureHttpDetailAsync(string clientName, string route,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(route))
        {
            return false;
        }

        return await CachedCaptureDecisionAsync(
                $"http:{clientName}:{route}",
                async token =>
                {
                    await using var scope = _services.CreateAsyncScope();
                    var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
                    var account = await db.ClientAccounts.AsNoTracking()
                        .FirstOrDefaultAsync(c => c.ClientName == clientName, token)
                        .ConfigureAwait(false);
                    if (account is null)
                    {
                        return false;
                    }

                    return await db.HttpRouteMappings.AsNoTracking()
                        .AnyAsync(r => r.ClientId == account.Id
                                       && r.ClientName == account.ClientName
                                       && r.Route == route
                                       && r.DetailCaptureEnabled,
                            token)
                        .ConfigureAwait(false);
                },
                cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<bool> ShouldCaptureTcpDetailAsync(string clientName, int listenPort,
        CancellationToken cancellationToken) =>
        await CachedCaptureDecisionAsync(
                $"tcp:{clientName}:{listenPort.ToString(CultureInfo.InvariantCulture)}",
                async token =>
                {
                    await using var scope = _services.CreateAsyncScope();
                    var db = scope.ServiceProvider.GetRequiredService<TunnelDbContext>();
                    return await db.TunnelMappings.AsNoTracking()
                        .AnyAsync(m => m.ClientName == clientName
                                       && m.ListenPort == listenPort
                                       && m.DetailCaptureEnabled,
                            token)
                        .ConfigureAwait(false);
                },
                cancellationToken)
            .ConfigureAwait(false);

    private async Task<bool> CachedCaptureDecisionAsync(string key, Func<CancellationToken, Task<bool>> loader,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        if (_detailCaptureDecisionCache.TryGetValue(key, out var cached) && cached.ExpiresAt > now)
        {
            return cached.Enabled;
        }

        var enabled = await loader(cancellationToken).ConfigureAwait(false);
        _detailCaptureDecisionCache[key] = new CaptureDecision(enabled, now.Add(CaptureDecisionTtl));
        return enabled;
    }

    private bool AcquireSlot(ref int count)
    {
        if (MaxPending <= 0)
        {
            return false;
        }

        var current = Interlocked.Increment(ref count);
        if (current <= MaxPending)
        {
            return true;
        }

        Interlocked.Decrement(ref count);
        return false;
    }

    private List<PendingHttpExchange> DrainHttp()
    {
        var rows = new List<PendingHttpExchange>(Math.Min(FlushBatchSize,
            Math.Max(0, Volatile.Read(ref _pendingHttpCount))));
        for (var i = 0; i < FlushBatchSize; i++)
        {
            if (!_pendingHttpExchanges.TryDequeue(out var item))
            {
                break;
            }
            Interlocked.Decrement(ref _pendingHttpCount);
            rows.Add(item);
        }
        return rows;
    }

    private List<PendingTcpFrame> DrainTcp()
    {
        var rows = new List<PendingTcpFrame>(Math.Min(FlushBatchSize,
            Math.Max(0, Volatile.Read(ref _pendingTcpCount))));
        for (var i = 0; i < FlushBatchSize; i++)
        {
            if (!_pendingTcpFrames.TryDequeue(out var item))
            {
                break;
            }
            Interlocked.Decrement(ref _pendingTcpCount);
            rows.Add(item);
        }
        return rows;
    }

    private static async Task<ResourceDescriptor> ResolveHttpResourceAsync(
        TunnelDbContext db, ClientAccount account, string route, CancellationToken cancellationToken)
    {
        var mapping = await db.HttpRouteMappings.AsNoTracking()
            .FirstOrDefaultAsync(r => r.ClientId == account.Id
                                      && r.ClientName == account.ClientName
                                      && r.Route == route,
                cancellationToken)
            .ConfigureAwait(false);
        return mapping is null
            ? new ResourceDescriptor(null, route)
            : new ResourceDescriptor(mapping.Id, $"{mapping.Route} -> {mapping.TargetBaseUrl}");
    }

    private static async Task<ResourceDescriptor> ResolveTcpResourceAsync(
        TunnelDbContext db, ClientAccount account, int listenPort, CancellationToken cancellationToken)
    {
        var mapping = await db.TunnelMappings.AsNoTracking()
            .FirstOrDefaultAsync(m => m.ClientId == account.Id
                                      && m.ClientName == account.ClientName
                                      && m.ListenPort == listenPort,
                cancellationToken)
            .ConfigureAwait(false);
        return mapping is null
            ? new ResourceDescriptor(null, "端口 " + listenPort.ToString(CultureInfo.InvariantCulture))
            : new ResourceDescriptor(mapping.Id,
                $"{mapping.ListenPort.ToString(CultureInfo.InvariantCulture)} -> {mapping.TargetAddress}:{mapping.TargetPort.ToString(CultureInfo.InvariantCulture)}");
    }

    private static string? HeaderValue(IReadOnlyList<string>? headers, string name)
    {
        if (headers is null)
        {
            return null;
        }
        foreach (var header in headers)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator > 0 && header[..separator].Trim().Equals(name, StringComparison.OrdinalIgnoreCase))
            {
                return header[(separator + 1)..].Trim();
            }
        }
        return null;
    }

    private static string JoinHeaders(IReadOnlyList<string>? headers)
    {
        if (headers is null || headers.Count == 0)
        {
            return string.Empty;
        }
        return string.Join('\n', headers.Where(h => !string.IsNullOrWhiteSpace(h)).Select(MaskHeader));
    }

    private static string MaskHeader(string header)
    {
        var separator = header.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0)
        {
            return header;
        }
        var name = header[..separator].Trim();
        return IsSensitiveHeader(name) ? header[..(separator + 1)] + "***" : header;
    }

    private static bool IsSensitiveHeader(string name) =>
        name.Equals("authorization", StringComparison.OrdinalIgnoreCase)
        || name.Equals("proxy-authorization", StringComparison.OrdinalIgnoreCase)
        || name.Equals("cookie", StringComparison.OrdinalIgnoreCase)
        || name.Equals("set-cookie", StringComparison.OrdinalIgnoreCase)
        || name.Equals("x-api-key", StringComparison.OrdinalIgnoreCase)
        || name.Equals("x-auth-token", StringComparison.OrdinalIgnoreCase)
        || name.Equals("x-csrf-token", StringComparison.OrdinalIgnoreCase);

    private static string BodyText(byte[]? data, string? contentType, string? contentEncoding)
    {
        if (data is null || data.Length == 0)
        {
            return string.Empty;
        }
        var display = DecodeContentEncoding(data, contentEncoding);
        if (!IsTextBody(contentType) && !LooksLikeText(display))
        {
            return $"data:{MediaType(contentType)};base64,{Convert.ToBase64String(display)}";
        }
        return SanitizeText(Encoding.UTF8.GetString(display));
    }

    private static byte[] DecodeContentEncoding(byte[] data, string? contentEncoding)
    {
        if (string.IsNullOrWhiteSpace(contentEncoding))
        {
            return data;
        }
        var current = data;
        var decoded = false;
        foreach (var token in contentEncoding.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Reverse())
        {
            if (token.Equals("identity", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            var next = DecodeOne(current, token);
            if (next is null)
            {
                return decoded ? current : data;
            }
            current = next;
            decoded = true;
        }
        return current;
    }

    private static byte[]? DecodeOne(byte[] data, string token)
    {
        var normalized = token.ToLowerInvariant();
        return normalized switch
        {
            "gzip" or "x-gzip" => TryDecode(data, source => new GZipStream(source, CompressionMode.Decompress)),
            "deflate" or "x-deflate" =>
                TryDecode(data, source => new ZLibStream(source, CompressionMode.Decompress))
                ?? TryDecode(data, source => new DeflateStream(source, CompressionMode.Decompress)),
            "br" => TryDecode(data, source => new BrotliStream(source, CompressionMode.Decompress)),
            _ => null,
        };
    }

    private static byte[]? TryDecode(byte[] data, Func<Stream, Stream> decoderFactory)
    {
        try
        {
            using var source = new MemoryStream(data);
            using var decoder = decoderFactory(source);
            using var output = new MemoryStream();
            decoder.CopyTo(output);
            return output.ToArray();
        }
        catch (InvalidDataException)
        {
            return null;
        }
        catch (IOException)
        {
            return null;
        }
    }

    private static bool IsTextBody(string? contentType)
    {
        var media = MediaType(contentType);
        return media.StartsWith("text/", StringComparison.Ordinal)
               || media == "application/json"
               || media.EndsWith("+json", StringComparison.Ordinal)
               || media == "application/xml"
               || media.EndsWith("+xml", StringComparison.Ordinal)
               || media == "application/x-www-form-urlencoded"
               || media == "application/graphql"
               || media == "application/javascript"
               || media == "application/ecmascript"
               || media == "application/x-yaml"
               || media == "application/yaml";
    }

    private static string MediaType(string? contentType)
    {
        var media = (contentType ?? string.Empty).Split(';', 2)[0].Trim().ToLowerInvariant();
        return media.Contains('/', StringComparison.Ordinal) ? media : "application/octet-stream";
    }

    private static bool LooksLikeText(byte[] data)
    {
        if (!Utf8IsValid(data))
        {
            return false;
        }
        var inspected = Math.Min(data.Length, 512);
        var controls = 0;
        for (var i = 0; i < inspected; i++)
        {
            var value = data[i];
            if (value == 0)
            {
                return false;
            }
            if (value < 0x20 && value is not ((byte)'\r') and not ((byte)'\n') and not ((byte)'\t'))
            {
                controls++;
            }
        }
        return inspected == 0 || controls * 10 <= inspected;
    }

    private static bool Utf8IsValid(byte[] data)
    {
        var text = Encoding.UTF8.GetString(data);
        return !text.Contains('\uFFFD', StringComparison.Ordinal);
    }

    private static (string Hex, string Text, bool Truncated) TcpPreview(byte[] data, int maxBytes)
    {
        if (data.Length == 0 || maxBytes <= 0)
        {
            return (string.Empty, string.Empty, data.Length > 0);
        }
        var length = Math.Min(data.Length, maxBytes);
        var hex = Convert.ToHexString(data.AsSpan(0, length)).Chunk(2)
            .Select(chars => new string(chars));
        return (string.Join(' ', hex), SanitizeText(Encoding.UTF8.GetString(data, 0, length)), data.Length > length);
    }

    private static string SanitizeText(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var ch in text)
        {
            builder.Append(char.IsControl(ch) && ch is not '\r' and not '\n' and not '\t' ? '.' : ch);
        }
        return builder.ToString();
    }

    private static string ClassifyHttpBody(string? contentType, int bytes)
    {
        if (bytes <= 0)
        {
            return "empty";
        }
        var media = MediaType(contentType);
        if (media == "application/json" || media.EndsWith("+json", StringComparison.Ordinal)) return "json";
        if (media == "text/html") return "html";
        if (media == "application/xml" || media == "text/xml" || media.EndsWith("+xml", StringComparison.Ordinal)) return "xml";
        if (media.StartsWith("image/", StringComparison.Ordinal)) return "image";
        if (media.StartsWith("video/", StringComparison.Ordinal)) return "video";
        if (media.StartsWith("audio/", StringComparison.Ordinal)) return "audio";
        if (media is "application/x-www-form-urlencoded" or "multipart/form-data") return "form";
        if (media.Contains("javascript", StringComparison.Ordinal) || media.Contains("ecmascript", StringComparison.Ordinal)) return "script";
        if (media.StartsWith("text/", StringComparison.Ordinal)) return "text";
        return "binary";
    }

    private static string? PeerAddress(string direction, string? sourceAddress, int? sourcePort,
        string? destinationAddress, int? destinationPort)
    {
        if (direction == DirectionPublicToClient)
        {
            return Endpoint(sourceAddress, sourcePort);
        }
        if (direction == DirectionClientToPublic)
        {
            return Endpoint(destinationAddress, destinationPort);
        }
        return Endpoint(sourceAddress, sourcePort) ?? Endpoint(destinationAddress, destinationPort);
    }

    private static string? Endpoint(string? address, int? port)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return port is null ? null : ":" + port.Value.ToString(CultureInfo.InvariantCulture);
        }
        return port is null ? address : $"{address}:{port.Value.ToString(CultureInfo.InvariantCulture)}";
    }

    private static string? Cap(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }
        return value.Length <= max ? value : value[..max];
    }

    private sealed record CaptureDecision(bool Enabled, DateTimeOffset ExpiresAt);

    private sealed record ResourceDescriptor(long? ResourceId, string? ResourceName);

    private sealed record PendingHttpExchange(
        string ClientName,
        string Route,
        string Method,
        string RelativePath,
        string? RawQuery,
        int StatusCode,
        bool Success,
        string? Error,
        string? RemoteAddress,
        long RequestBytes,
        long ResponseBytes,
        long ElapsedMs,
        string? RequestContentType,
        string? ResponseContentType,
        string ResponseBodyType,
        string? RequestHeaders,
        string? ResponseHeaders,
        string RequestPreviewHex,
        string RequestPreviewText,
        string ResponsePreviewHex,
        string ResponsePreviewText,
        bool RequestTruncated,
        bool ResponseTruncated,
        DateTimeOffset CapturedAt);

    private sealed record PendingTcpFrame(
        string ClientName,
        int ListenPort,
        string ChannelId,
        string Direction,
        string? RemoteAddress,
        string? SourceAddress,
        int? SourcePort,
        string? DestinationAddress,
        int? DestinationPort,
        long StreamOffset,
        long StreamEndOffset,
        long FrameIndex,
        long PayloadBytes,
        byte[] PayloadData,
        string PayloadPreviewHex,
        string PayloadPreviewText,
        bool Truncated,
        DateTimeOffset FrameTime);

    private sealed class StreamCursor
    {
        private long _offset;
        private long _index;

        public long AddPayload(long bytes) => Interlocked.Add(ref _offset, bytes) - bytes;
        public long NextIndex() => Interlocked.Increment(ref _index) - 1;
    }
}

public sealed record HttpExchangeCapture(
    string ClientName,
    string Route,
    string Method,
    string RelativePath,
    string? RawQuery,
    IReadOnlyList<string>? RequestHeaders,
    byte[]? RequestBody,
    int StatusCode,
    IReadOnlyList<string>? ResponseHeaders,
    byte[]? ResponseBody,
    DateTimeOffset StartedAt,
    string? RemoteAddress,
    string? Error);

public sealed record TcpFrameCapture(
    string ClientName,
    int ListenPort,
    string ChannelId,
    string Direction,
    string? SourceAddress,
    int? SourcePort,
    string? DestinationAddress,
    int? DestinationPort,
    byte[] Payload);
