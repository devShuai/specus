using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using ShuaiTunnel.Client.Control;
using ShuaiTunnel.Client.DirectHttp;
using ShuaiTunnel.Protocol;
using ShuaiTunnel.Protocol.Flow;
using ShuaiTunnel.Protocol.Packets;

namespace ShuaiTunnel.Client.Nat;

/// <summary>Streams one NAT v2 HTTP request to a local route and its response back.</summary>
internal sealed class HttpStreamChannel : IAsyncDisposable
{
    private readonly uint _streamId;
    private readonly Dictionary<string, object?> _metadata;
    private readonly DirectHttpHandler _routes;
    private readonly FrameWriter _writer;
    private readonly ILogger _logger;
    private readonly Action<HttpStreamChannel> _onClose;
    private readonly CancellationTokenSource _lifetime;
    private readonly StreamingRequestContent _requestContent;
    private readonly StreamSendWindow _responseWindow = new();
    private int _closed;

    public HttpStreamChannel(uint streamId, Dictionary<string, object?> metadata,
        DirectHttpHandler routes, FrameWriter writer, ILogger logger,
        CancellationToken session, Action<HttpStreamChannel> onClose)
    {
        _streamId = streamId;
        _metadata = new Dictionary<string, object?>(metadata);
        _routes = routes;
        _writer = writer;
        _logger = logger;
        _onClose = onClose;
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(session);
        _requestContent = new StreamingRequestContent(
            AsLong(metadata, "contentLength"), ReturnRequestCreditAsync);
    }

    public uint StreamId => _streamId;

    public ValueTask OfferRequestDataAsync(byte[] data, CancellationToken cancellationToken) =>
        _requestContent.OfferAsync(data, cancellationToken);

    public ValueTask FinishRequestAsync(Dictionary<string, object?>? metadata,
        CancellationToken cancellationToken) =>
        _requestContent.FinishAsync(AsStrings(metadata, "trailers"), cancellationToken);

    public bool AddResponseCredit(uint credit) => _responseWindow.Add(credit);

    public void Abort(string? reason)
    {
        _requestContent.Abort(new IOException(string.IsNullOrWhiteSpace(reason)
            ? "HTTP stream reset by server"
            : reason));
        Close();
    }

    public async Task RunAsync()
    {
        try
        {
            await ForwardAsync(_lifetime.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "HTTP stream {StreamId} failed", _streamId);
            await SendResetAsync(26, ex.Message).ConfigureAwait(false);
        }
        finally
        {
            Close();
        }
    }

    private async Task ForwardAsync(CancellationToken cancellationToken)
    {
        var method = RequiredString(_metadata, "method");
        var route = RequiredString(_metadata, "route");
        if (!_routes.SnapshotRoutes().TryGetValue(route, out var baseUrl))
        {
            throw new InvalidOperationException("未配置 HTTP route");
        }
        if (!DirectHttpForwarder.TryBuildTarget(baseUrl, AsString(_metadata, "relativePath"),
                AsString(_metadata, "rawQuery"), out var target, out var error))
        {
            throw new InvalidOperationException(error);
        }

        using var request = new HttpRequestMessage(new HttpMethod(method), target)
        {
            Content = _requestContent,
        };
        if (AsStrings(_metadata, "trailerNames").Count > 0)
        {
            throw new NotSupportedException("当前 .NET HTTP transport 不支持请求 trailers");
        }
        var headers = AsStrings(_metadata, "headers");
        var boundedRange = DirectHttpForwarder.BoundedRange(
            DirectHttpForwarder.FirstHeader(headers, "range"));
        DirectHttpForwarder.CopyRequestHeaders(headers, request, boundedRange is not null);
        if (boundedRange is not null)
        {
            request.Headers.TryAddWithoutValidation("Range", boundedRange);
        }

        using var response = await _routes.Forwarder.SendAsync(request, cancellationToken)
            .ConfigureAwait(false);
        var trailerNames = DeclaredResponseTrailers(response);
        await _writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = _streamId,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "response",
                ["statusCode"] = (int)response.StatusCode,
                ["headers"] = DirectHttpForwarder.CollectResponseHeaders(response),
                ["trailerNames"] = trailerNames,
            },
        }, cancellationToken).ConfigureAwait(false);

        long total = 0;
        await using var body = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        var buffer = new byte[64 * 1024];
        while (true)
        {
            var read = await body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total += read;
            if (total > DirectHttpForwarder.MaxResponseBodySize)
            {
                throw new InvalidOperationException("HTTP 响应体超过限制");
            }
            if (!await _responseWindow.ConsumeAsync(read, cancellationToken).ConfigureAwait(false))
            {
                throw new IOException("HTTP response window closed");
            }
            await _writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Data,
                StreamId = _streamId,
                Data = buffer.AsSpan(0, read).ToArray(),
            }, cancellationToken).ConfigureAwait(false);
        }

        var trailers = FlattenHeaders(response.TrailingHeaders);
        await _writer.WriteAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = _streamId,
            MetaData = trailers.Count == 0
                ? null
                : new Dictionary<string, object?> { ["trailers"] = trailers },
        }, cancellationToken).ConfigureAwait(false);
    }

    private ValueTask ReturnRequestCreditAsync(int bytes, CancellationToken cancellationToken) =>
        _writer.WritePriorityAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.WindowUpdate,
            StreamId = _streamId,
            Value = checked((uint)bytes),
        }, cancellationToken);

    private async ValueTask SendResetAsync(uint code, string reason)
    {
        if (Volatile.Read(ref _closed) != 0)
        {
            return;
        }
        try
        {
            await _writer.WriteAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.Rst,
                StreamId = _streamId,
                Value = code,
                MetaData = new Dictionary<string, object?> { ["reason"] = reason },
            }, CancellationToken.None).ConfigureAwait(false);
        }
        catch
        {
        }
    }

    private void Close()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0)
        {
            return;
        }
        _lifetime.Cancel();
        _requestContent.Abort(new IOException("HTTP stream closed"));
        _responseWindow.Close();
        _onClose(this);
    }

    public ValueTask DisposeAsync()
    {
        Close();
        _lifetime.Dispose();
        _requestContent.Dispose();
        return ValueTask.CompletedTask;
    }

    private static string RequiredString(Dictionary<string, object?> metadata, string key) =>
        AsString(metadata, key) is { Length: > 0 } value
            ? value
            : throw new InvalidDataException($"HTTP OPEN missing {key}");

    private static string? AsString(Dictionary<string, object?>? metadata, string key)
    {
        if (metadata is null || !metadata.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }
        return value switch
        {
            string text => text,
            JsonValue json when json.TryGetValue<string>(out var text) => text,
            JsonElement { ValueKind: JsonValueKind.String } json => json.GetString(),
            _ => value.ToString(),
        };
    }

    private static long? AsLong(Dictionary<string, object?> metadata, string key)
    {
        if (!metadata.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }
        return value switch
        {
            long number => number,
            int number => number,
            double number => (long)number,
            JsonValue json when json.TryGetValue<long>(out var number) => number,
            JsonElement json when json.TryGetInt64(out var number) => number,
            _ when long.TryParse(value.ToString(), out var number) => number,
            _ => null,
        };
    }

    private static List<string> AsStrings(Dictionary<string, object?>? metadata, string key)
    {
        if (metadata is null || !metadata.TryGetValue(key, out var value) || value is null)
        {
            return [];
        }
        return value switch
        {
            IEnumerable<string> values => values.ToList(),
            JsonArray array => array.Select(static item => item?.GetValue<string>())
                .Where(static item => item is not null).Cast<string>().ToList(),
            JsonElement { ValueKind: JsonValueKind.Array } array => array.EnumerateArray()
                .Where(static item => item.ValueKind == JsonValueKind.String)
                .Select(static item => item.GetString()!).ToList(),
            IEnumerable<object?> values => values.Where(static item => item is not null)
                .Select(static item => item!.ToString()!).ToList(),
            _ => [],
        };
    }

    private static List<string> DeclaredResponseTrailers(HttpResponseMessage response)
    {
        var names = new HashSet<string>(response.TrailingHeaders.Select(static header => header.Key),
            StringComparer.OrdinalIgnoreCase);
        if (response.Headers.TryGetValues("Trailer", out var declarations))
        {
            foreach (var name in declarations.SelectMany(static value =>
                         value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)))
            {
                if (IsValidHeaderName(name))
                {
                    names.Add(name);
                }
            }
        }
        return names.ToList();
    }

    private static List<string> FlattenHeaders(HttpHeaders headers)
    {
        var result = new List<string>();
        foreach (var (name, values) in headers)
        {
            result.AddRange(values.Select(value => $"{name}:{value}"));
        }
        return result;
    }

    private static bool IsValidHeaderName(string name) =>
        !string.IsNullOrWhiteSpace(name) && name.All(static ch =>
            char.IsAsciiLetterOrDigit(ch) || "!#$%&'*+-.^_`|~".Contains(ch));

    private sealed class StreamingRequestContent : HttpContent
    {
        private readonly Channel<RequestChunk> _chunks = Channel.CreateBounded<RequestChunk>(
            new BoundedChannelOptions(32) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });
        private readonly long? _contentLength;
        private readonly Func<int, CancellationToken, ValueTask> _consumed;
        private long _received;
        private int _finished;

        public StreamingRequestContent(long? contentLength,
            Func<int, CancellationToken, ValueTask> consumed)
        {
            _contentLength = contentLength is >= 0 ? contentLength : null;
            _consumed = consumed;
        }

        public async ValueTask OfferAsync(byte[] data, CancellationToken cancellationToken)
        {
            if (data.Length == 0 || Volatile.Read(ref _finished) != 0)
            {
                throw new InvalidDataException("invalid HTTP request DATA");
            }
            var total = Interlocked.Add(ref _received, data.Length);
            if (total > DirectHttpForwarder.MaxRequestBodySize)
            {
                throw new InvalidDataException("HTTP 请求体超过限制");
            }
            await _chunks.Writer.WriteAsync(new RequestChunk(data.ToArray(), null), cancellationToken)
                .ConfigureAwait(false);
        }

        public async ValueTask FinishAsync(List<string> trailers, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _finished, 1) != 0)
            {
                throw new InvalidDataException("duplicate HTTP request FIN");
            }
            await _chunks.Writer.WriteAsync(new RequestChunk(null, trailers), cancellationToken)
                .ConfigureAwait(false);
            _chunks.Writer.TryComplete();
        }

        public void Abort(Exception error)
        {
            Interlocked.Exchange(ref _finished, 1);
            _chunks.Writer.TryComplete(error);
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            SerializeToStreamAsync(stream, context, CancellationToken.None);

        protected override async Task SerializeToStreamAsync(Stream stream, TransportContext? context,
            CancellationToken cancellationToken)
        {
            await foreach (var chunk in _chunks.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                if (chunk.Data is { Length: > 0 } data)
                {
                    await stream.WriteAsync(data, cancellationToken).ConfigureAwait(false);
                    await _consumed(data.Length, cancellationToken).ConfigureAwait(false);
                }
                if (chunk.Trailers is not null)
                {
                    if (chunk.Trailers.Count > 0)
                    {
                        throw new NotSupportedException("当前 .NET HTTP transport 不支持请求 trailers");
                    }
                }
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _contentLength ?? 0;
            return _contentLength is not null;
        }

        private readonly record struct RequestChunk(byte[]? Data, List<string>? Trailers);
    }
}
