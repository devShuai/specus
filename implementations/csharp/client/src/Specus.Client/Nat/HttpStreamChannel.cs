using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Protocol;
using Specus.Protocol.Flow;
using Specus.Protocol.Packets;

namespace Specus.Client.Nat;

/// <summary>Streams one NAT v2 HTTP request to a local route and its response back.</summary>
internal sealed class HttpStreamChannel : IAsyncDisposable
{
    private readonly uint _streamId;
    private readonly Dictionary<string, object?> _metadata;
    private readonly DirectHttpHandler _routes;
    private readonly string _targetBaseUrl;
    private readonly bool _insecureSkipVerify;
    private readonly FrameWriter _writer;
    private readonly ILogger _logger;
    private readonly Action<HttpStreamChannel> _onClose;
    private readonly CancellationTokenSource _lifetime;
    private readonly StreamingRequestContent _requestContent;
    private readonly RequestTrailerState? _requestTrailers;
    private readonly StreamSendWindow _responseWindow = new();
    private int _closed;

    public HttpStreamChannel(uint streamId, Dictionary<string, object?> metadata,
        DirectHttpHandler routes, string targetBaseUrl, FrameWriter writer, ILogger logger,
        CancellationToken session, Action<HttpStreamChannel> onClose,
        bool insecureSkipVerify = false)
    {
        _streamId = streamId;
        _metadata = new Dictionary<string, object?>(metadata);
        _routes = routes;
        _targetBaseUrl = targetBaseUrl;
        _insecureSkipVerify = insecureSkipVerify;
        _writer = writer;
        _logger = logger;
        _onClose = onClose;
        _lifetime = CancellationTokenSource.CreateLinkedTokenSource(session);
        var trailerNames = AsStrings(metadata, "trailerNames");
        _requestTrailers = trailerNames.Count == 0 ? null : new RequestTrailerState(trailerNames);
        _requestContent = new StreamingRequestContent(
            AsLong(metadata, "contentLength"), ReturnRequestCreditAsync, _requestTrailers);
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
        if (!DirectHttpForwarder.TryBuildTarget(_targetBaseUrl, AsString(_metadata, "relativePath"),
                AsString(_metadata, "rawQuery"), out var target, out var error))
        {
            throw new InvalidOperationException(error);
        }

        using var request = new HttpRequestMessage(new HttpMethod(method), target)
        {
            Content = _requestContent,
        };
        TrailerHttpTransport? trailerTransport = null;
        if (_requestTrailers is not null)
        {
            request.Version = HttpVersion.Version11;
            request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
            request.Headers.TransferEncodingChunked = true;
            request.Headers.TryAddWithoutValidation("Trailer", _requestTrailers.Names);
            trailerTransport = new TrailerHttpTransport(_requestTrailers, _insecureSkipVerify);
        }
        var headers = AsStrings(_metadata, "headers");
        var boundedRange = DirectHttpForwarder.BoundedRange(
            DirectHttpForwarder.FirstHeader(headers, "range"));
        DirectHttpForwarder.CopyRequestHeaders(headers, request, boundedRange is not null);
        DirectHttpForwarder.BindUpstreamAuthority(request, target);
        if (boundedRange is not null)
        {
            request.Headers.TryAddWithoutValidation("Range", boundedRange);
        }

        using var requestTrailerTransport = trailerTransport;
        using var response = trailerTransport is null
            ? await _routes.Forwarder.SendAsync(
                request, _insecureSkipVerify, cancellationToken).ConfigureAwait(false)
            : await trailerTransport.SendAsync(request, cancellationToken).ConfigureAwait(false);
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

        var trailers = FlattenTrailers(response.TrailingHeaders);
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
                if (IsValidHeaderName(name) && !DirectHttpForwarder.SkippedHeaders.Contains(name))
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

    private static List<string> FlattenTrailers(HttpHeaders headers)
    {
        var result = new List<string>();
        foreach (var (name, values) in headers)
        {
            if (!IsValidHeaderName(name) || DirectHttpForwarder.SkippedHeaders.Contains(name))
            {
                continue;
            }
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
        private readonly RequestTrailerState? _trailers;
        private long _received;
        private int _finished;

        public StreamingRequestContent(long? contentLength,
            Func<int, CancellationToken, ValueTask> consumed,
            RequestTrailerState? trailers)
        {
            _contentLength = contentLength is >= 0 ? contentLength : null;
            _consumed = consumed;
            _trailers = trailers;
        }

        public async ValueTask OfferAsync(byte[] data, CancellationToken cancellationToken)
        {
            if (Volatile.Read(ref _finished) != 0)
            {
                throw new InvalidDataException("HTTP DATA after FIN");
            }
            if (data.Length == 0)
            {
                throw new InvalidDataException("invalid HTTP request DATA");
            }
            var total = Interlocked.Add(ref _received, data.Length);
            if (total > DirectHttpForwarder.MaxRequestBodySize
                || _contentLength is { } expected && total > expected)
            {
                Interlocked.Exchange(ref _finished, 1);
                _chunks.Writer.TryComplete(new InvalidDataException(
                    total > DirectHttpForwarder.MaxRequestBodySize
                        ? "HTTP 请求体超过限制"
                        : "HTTP request DATA exceeds declared contentLength"));
                return;
            }
            try
            {
                await _chunks.Writer.WriteAsync(new RequestChunk(data.ToArray(), null), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ChannelClosedException) when (Volatile.Read(ref _finished) != 0)
            {
            }
        }

        public async ValueTask FinishAsync(List<string> trailers, CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref _finished, 1) != 0)
            {
                throw new InvalidDataException("duplicate HTTP FIN");
            }
            if (_contentLength is { } expected && Interlocked.Read(ref _received) != expected)
            {
                _chunks.Writer.TryComplete(new InvalidDataException(
                    "HTTP request body does not match declared contentLength"));
                return;
            }
            try
            {
                await _chunks.Writer.WriteAsync(new RequestChunk(null, trailers), cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (ChannelClosedException)
            {
                return;
            }
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
                    _trailers?.Complete(chunk.Trailers);
                }
            }
        }

        protected override bool TryComputeLength(out long length)
        {
            length = _contentLength ?? 0;
            return _trailers is null && _contentLength is not null;
        }

        private readonly record struct RequestChunk(byte[]? Data, List<string>? Trailers);
    }

    /// <summary>
    /// SocketsHttpHandler currently has no public request-trailer API.  For declared
    /// HTTP/1.1 trailers, wrap its post-TLS plaintext stream and replace the terminal
    /// chunk emitted after HttpContent serialization with the validated trailer block.
    /// </summary>
    private sealed class TrailerHttpTransport : IDisposable
    {
        private readonly HttpClient _client;

        public TrailerHttpTransport(RequestTrailerState trailers, bool insecureSkipVerify)
        {
            var handler = DirectHttpForwarder.BuildDefaultHandler(insecureSkipVerify);
            handler.PooledConnectionLifetime = TimeSpan.Zero;
            handler.PlaintextStreamFilter = (context, _) =>
                ValueTask.FromResult<Stream>(new TrailerInjectingStream(
                    context.PlaintextStream, trailers));
            _client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        }

        public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            _client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);

        public void Dispose() => _client.Dispose();
    }

    private sealed class RequestTrailerState
    {
        private readonly HashSet<string> _declared;
        private byte[]? _terminator;

        public RequestTrailerState(IEnumerable<string> names)
        {
            _declared = names.Where(IsValidHeaderName)
                .Where(static name => !DirectHttpForwarder.SkippedHeaders.Contains(name))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (_declared.Count == 0)
            {
                throw new InvalidDataException("HTTP request contains no valid trailer names");
            }
            Names = _declared.ToList();
        }

        public IReadOnlyList<string> Names { get; }

        public void Complete(IEnumerable<string> values)
        {
            var builder = new StringBuilder("0\r\n");
            foreach (var value in values)
            {
                var separator = value.IndexOf(':');
                if (separator <= 0)
                {
                    continue;
                }
                var name = value[..separator].Trim();
                var trailerValue = value[(separator + 1)..].Trim();
                if (!_declared.Contains(name) || !IsSafeHeaderValue(trailerValue))
                {
                    continue;
                }
                builder.Append(name).Append(": ").Append(trailerValue).Append("\r\n");
            }
            builder.Append("\r\n");
            Volatile.Write(ref _terminator, Encoding.ASCII.GetBytes(builder.ToString()));
        }

        public byte[]? Terminator => Volatile.Read(ref _terminator);

        private static bool IsSafeHeaderValue(string value) =>
            !value.Contains('\r') && !value.Contains('\n')
                && value.All(static ch => ch == '\t' || ch >= ' ' && ch != '\u007f');
    }

    private sealed class TrailerInjectingStream(Stream inner, RequestTrailerState trailers) : Stream
    {
        private static ReadOnlySpan<byte> EmptyTerminator => "0\r\n\r\n"u8;
        private static ReadOnlySpan<byte> HeaderTerminator => "\r\n\r\n"u8;
        private readonly byte[] _tail = new byte[EmptyTerminator.Length];
        private int _tailLength;
        private int _headerTerminatorMatch;
        private bool _headersComplete;
        private bool _injected;

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => inner.CanSeek;
        public override bool CanWrite => inner.CanWrite;
        public override long Length => inner.Length;
        public override long Position { get => inner.Position; set => inner.Position = value; }
        public override void Flush() => inner.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) =>
            inner.FlushAsync(cancellationToken);
        public override int Read(byte[] buffer, int offset, int count) =>
            inner.Read(buffer, offset, count);
        public override int Read(Span<byte> buffer) => inner.Read(buffer);
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default) => inner.ReadAsync(buffer, cancellationToken);
        public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
        public override void SetLength(long value) => inner.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) =>
            Write(buffer.AsSpan(offset, count));

        public override void Write(ReadOnlySpan<byte> buffer)
        {
            if (!TryInject(buffer, out var replacement))
            {
                inner.Write(buffer);
                return;
            }
            if (!replacement.IsEmpty)
            {
                inner.Write(replacement.Span);
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count,
            CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (!TryInject(buffer.Span, out var replacement))
            {
                return inner.WriteAsync(buffer, cancellationToken);
            }
            return replacement.IsEmpty
                ? ValueTask.CompletedTask
                : inner.WriteAsync(replacement, cancellationToken);
        }

        private bool TryInject(ReadOnlySpan<byte> buffer, out ReadOnlyMemory<byte> replacement)
        {
            replacement = default;
            if (_injected)
            {
                return false;
            }

            var bodyOffset = 0;
            if (!_headersComplete)
            {
                bodyOffset = FindBodyOffset(buffer);
                if (bodyOffset < 0)
                {
                    return false;
                }
            }

            var terminator = trailers.Terminator;
            if (terminator is null || bodyOffset == buffer.Length)
            {
                return false;
            }

            var body = TransformBody(buffer[bodyOffset..], terminator);
            if (bodyOffset == 0)
            {
                replacement = body;
            }
            else
            {
                var combined = new byte[bodyOffset + body.Length];
                buffer[..bodyOffset].CopyTo(combined);
                body.AsSpan().CopyTo(combined.AsSpan(bodyOffset));
                replacement = combined;
            }
            return true;
        }

        private int FindBodyOffset(ReadOnlySpan<byte> buffer)
        {
            var marker = HeaderTerminator;
            for (var index = 0; index < buffer.Length; index++)
            {
                var value = buffer[index];
                if (value == marker[_headerTerminatorMatch])
                {
                    _headerTerminatorMatch++;
                }
                else
                {
                    _headerTerminatorMatch = value == marker[0] ? 1 : 0;
                }
                if (_headerTerminatorMatch != marker.Length)
                {
                    continue;
                }
                _headersComplete = true;
                _headerTerminatorMatch = 0;
                return index + 1;
            }
            return -1;
        }

        private byte[] TransformBody(ReadOnlySpan<byte> buffer, ReadOnlySpan<byte> terminator)
        {
            var totalLength = checked(_tailLength + buffer.Length);
            if (totalLength <= EmptyTerminator.Length)
            {
                buffer.CopyTo(_tail.AsSpan(_tailLength));
                _tailLength = totalLength;
                if (_tailLength == EmptyTerminator.Length
                    && _tail.AsSpan().SequenceEqual(EmptyTerminator))
                {
                    _tailLength = 0;
                    _injected = true;
                    return terminator.ToArray();
                }
                return [];
            }

            var combined = new byte[totalLength];
            _tail.AsSpan(0, _tailLength).CopyTo(combined);
            buffer.CopyTo(combined.AsSpan(_tailLength));
            var prefixLength = totalLength - EmptyTerminator.Length;
            combined.AsSpan(prefixLength).CopyTo(_tail);
            _tailLength = EmptyTerminator.Length;

            if (!_tail.AsSpan().SequenceEqual(EmptyTerminator))
            {
                return combined.AsSpan(0, prefixLength).ToArray();
            }

            _tailLength = 0;
            _injected = true;
            var replacement = new byte[prefixLength + terminator.Length];
            combined.AsSpan(0, prefixLength).CopyTo(replacement);
            terminator.CopyTo(replacement.AsSpan(prefixLength));
            return replacement;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }

        public override async ValueTask DisposeAsync()
        {
            await inner.DisposeAsync().ConfigureAwait(false);
            GC.SuppressFinalize(this);
        }
    }
}
