using System.Collections.Frozen;
using System.Net.WebSockets;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.Data;
using Specus.Server.Management;
using Specus.Server.Nat;

namespace Specus.Server.Http;

/// <summary>
/// Public HTTP ingress for browser/API traffic that should be carried through a connected specus
/// client. This is the ASP.NET endpoint counterpart to Java's <c>HttpSpecusController</c>; it
/// strips hop-by-hop headers, bounds request bodies, and delegates the control-channel round trip
/// to <see cref="DirectHttpDispatcher"/>.
/// </summary>
public static class DirectHttpEndpoints
{
    private static readonly FrozenSet<string> SkippedHeaders = new[]
    {
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    // Empty HttpMethodMetadata means any method. The protocol intentionally exposes ANY /http/**
    // so WebDAV and application-specific verbs are forwarded as-is.
    private static readonly string[] Methods = [];

    public static void MapDirectHttpSpecus(this WebApplication app)
    {
        app.MapMethods("/http/{clientName}/{route}/{**rest}", Methods, ForwardAsync);
        app.MapMethods("/http/{clientName}/{route}", Methods, ForwardAsync);
    }

    private static async Task ForwardAsync(HttpContext context, string clientName, string route,
        string? rest, DirectHttpDispatcher dispatcher, TrafficUsageService traffic,
        IOptions<DirectHttpOptions> options, SpecusDbContext db, TrafficInspectionService inspection,
        HttpMediaCaptureService mediaCaptures)
    {
        var startedAt = DateTimeOffset.UtcNow;
        var relativePath = RelativePath(context, rest);
        HttpRouteAccessPolicy accessPolicy;
        try
        {
            accessPolicy = await LoadRouteAccessPolicyAsync(db, clientName, route, context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (Exception) when (!context.RequestAborted.IsCancellationRequested)
        {
            context.Response.Headers.CacheControl = "no-store";
            await WriteTextErrorAsync(context.Response, StatusCodes.Status503ServiceUnavailable,
                "HTTP 路由认证配置暂时不可用").ConfigureAwait(false);
            return;
        }

        if (accessPolicy.Managed && !accessPolicy.Enabled)
        {
            context.Response.Headers.CacheControl = "no-store";
            await WriteTextErrorAsync(context.Response, StatusCodes.Status404NotFound,
                "HTTP 路由不存在或未启用").ConfigureAwait(false);
            return;
        }

        if (accessPolicy.AuthEnabled
            && !HttpRouteBasicAuthenticator.IsConfigured(accessPolicy.AuthUsername,
                accessPolicy.AuthPasswordHash))
        {
            context.Response.Headers.CacheControl = "no-store";
            await WriteTextErrorAsync(context.Response, StatusCodes.Status503ServiceUnavailable,
                "HTTP 路由认证配置暂时不可用").ConfigureAwait(false);
            return;
        }

        if (accessPolicy.AuthEnabled
            && !HttpRouteBasicAuthenticator.IsAuthorized(context.Request.Headers.Authorization.ToString(),
                accessPolicy.AuthUsername, accessPolicy.AuthPasswordHash))
        {
            context.Response.Headers.WWWAuthenticate =
                "Basic realm=\"Specus HTTP Route\", charset=\"UTF-8\"";
            context.Response.Headers.CacheControl = "no-store";
            await WriteTextErrorAsync(context.Response, StatusCodes.Status401Unauthorized,
                "需要 HTTP Basic 认证").ConfigureAwait(false);
            return;
        }

        if (RawServerWebSocketConnection.LooksLikeWebSocketUpgrade(context.Request))
        {
            try
            {
                await ForwardWebSocketAsync(context, clientName, route, relativePath, dispatcher,
                    accessPolicy.AuthEnabled).ConfigureAwait(false);
            }
            catch (RawWebSocketHandshakeException ex) when (!context.Response.HasStarted)
            {
                await WriteTextErrorAsync(context.Response, ex.StatusCode, ex.Message)
                    .ConfigureAwait(false);
            }
            return;
        }

        var requestHeaders = RequestHeaders(context.Request, accessPolicy.AuthEnabled, false);
        var requestCapture = new LimitedCapture(64 * 1024);
        var responseCapture = new LimitedCapture(64 * 1024);
        IHttpMediaCaptureSession? mediaCapture = null;
        var requestTrailerNames = DeclaredRequestTrailers(context.Request, accessPolicy.AuthEnabled);
        var requestMetadata = new Dictionary<string, object?>
        {
            ["source"] = "http",
            ["phase"] = "request",
            ["method"] = context.Request.Method,
            ["route"] = route,
            ["relativePath"] = relativePath,
            ["rawQuery"] = RawQuery(context.Request.QueryString),
            ["headers"] = requestHeaders,
            ["trailerNames"] = requestTrailerNames,
        };
        if (context.Request.ContentLength is { } contentLength)
        {
            requestMetadata["contentLength"] = contentLength;
        }
        if (context.Request.ContentLength > options.Value.MaxRequestBodySize)
        {
            const string message = "HTTP 请求体超过限制";
            var responseBody = Encoding.UTF8.GetBytes(message);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    context.Request.Method, relativePath, RawQuery(context.Request.QueryString),
                    requestHeaders, Array.Empty<byte>(),
                    StatusCodes.Status413PayloadTooLarge, PlainErrorHeaders(), responseBody, startedAt,
                    context.Connection.RemoteIpAddress?.ToString(), message), context.RequestAborted)
                .ConfigureAwait(false);
            await WriteTextErrorAsync(context.Response, StatusCodes.Status413PayloadTooLarge,
                message).ConfigureAwait(false);
            return;
        }

        try
        {
            await using var stream = await dispatcher.OpenAsync(clientName, requestMetadata,
                    context.RequestAborted).ConfigureAwait(false);
            using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            var pumpTask = PumpRequestAsync(context, stream, traffic, clientName, route,
                requestCapture, options.Value.MaxRequestBodySize, accessPolicy.AuthEnabled,
                requestTrailerNames, pumpCts.Token);

            using var headCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
            headCts.CancelAfter(TimeSpan.FromMilliseconds(Math.Max(1, options.Value.TimeoutMs)));
            Dictionary<string, object?> head;
            try
            {
                head = await stream.WaitResponseHeadAsync(headCts.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (headCts.IsCancellationRequested
                                                     && !context.RequestAborted.IsCancellationRequested)
            {
                await stream.ResetAsync(1, "HTTP response header timeout", CancellationToken.None)
                    .ConfigureAwait(false);
                throw new DirectHttpSpecusException(StatusCodes.Status504GatewayTimeout, "HTTP 转发请求超时");
            }

            var statusCode = AsInt(head, "statusCode");
            if (statusCode is not int validStatusCode || validStatusCode is < 100 or > 599)
            {
                await stream.ResetAsync(2, "invalid HTTP response status", CancellationToken.None)
                    .ConfigureAwait(false);
                throw new DirectHttpSpecusException(StatusCodes.Status502BadGateway, "HTTP 响应状态无效");
            }
            var originalResponseHeaders = AsStrings(head, "headers");
            var responseHeaders = originalResponseHeaders;
            var rawQuery = RawQuery(context.Request.QueryString);
            mediaCapture = await mediaCaptures.OpenAsync(clientName, route, context.Request.Method,
                string.IsNullOrWhiteSpace(rawQuery) ? relativePath : relativePath + "?" + rawQuery,
                validStatusCode, originalResponseHeaders, context.RequestAborted).ConfigureAwait(false);
            if (mediaCapture.Externalized)
            {
                responseCapture = new LimitedCapture(0);
            }
            var responseTrailerNames = ValidTrailerNames(AsStrings(head, "trailerNames"), false);
            foreach (var trailerName in responseTrailerNames)
            {
                context.Response.DeclareTrailer(trailerName);
            }

            var rewrite = accessPolicy.PathRewriteEnabled && IsRewritable(originalResponseHeaders);
            using var rewriteBuffer = new MemoryStream();
            var responseStarted = false;
            List<string>? responseTrailers = null;

            void StartResponse()
            {
                if (responseStarted)
                {
                    return;
                }
                context.Response.StatusCode = validStatusCode;
                CopyHeaders(responseHeaders, context.Response);
                responseStarted = true;
            }

            while (true)
            {
                var item = await stream.ReadResponseAsync(context.RequestAborted).ConfigureAwait(false);
                if (item.End)
                {
                    responseTrailers = AsStrings(item.Metadata, "trailers");
                    break;
                }
                var data = item.Data ?? Array.Empty<byte>();

                await mediaCapture.AppendAsync(data, context.RequestAborted).ConfigureAwait(false);
                responseCapture.Write(data);
                traffic.RecordHttpDownload(clientName, route, data.Length);

                if (rewrite && rewriteBuffer.Length + data.Length <= options.Value.RewriteMaxBodyBytes)
                {
                    await rewriteBuffer.WriteAsync(data, context.RequestAborted).ConfigureAwait(false);
                    await stream.ConsumeResponseAsync(data.Length, context.RequestAborted).ConfigureAwait(false);
                    continue;
                }
                if (rewrite)
                {
                    rewrite = false;
                    StartResponse();
                    var buffered = rewriteBuffer.ToArray();
                    await WriteResponseChunkAsync(context.Response, buffered,
                        context.RequestAborted).ConfigureAwait(false);
                }
                StartResponse();
                await WriteResponseChunkAsync(context.Response, data,
                    context.RequestAborted).ConfigureAwait(false);
                await stream.ConsumeResponseAsync(data.Length, context.RequestAborted).ConfigureAwait(false);
            }

            await mediaCapture.CompleteAsync(CancellationToken.None).ConfigureAwait(false);

            if (rewrite)
            {
                var body = rewriteBuffer.ToArray();
                if (ResponseRewriter.TryRewrite(body, clientName, route, originalResponseHeaders,
                        options.Value.RewriteMaxBodyBytes, out var rewritten))
                {
                    body = rewritten;
                    responseHeaders = StripRewriteHeaders(responseHeaders);
                }
                StartResponse();
                await WriteResponseChunkAsync(context.Response, body,
                    context.RequestAborted).ConfigureAwait(false);
            }
            else if (!responseStarted)
            {
                StartResponse();
            }

            foreach (var trailer in responseTrailers ?? [])
            {
                AppendResponseTrailer(context.Response, trailer, responseTrailerNames);
            }
            if (!pumpTask.IsCompleted)
            {
                pumpCts.Cancel();
            }
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    context.Request.Method, relativePath, RawQuery(context.Request.QueryString),
                    requestHeaders, requestCapture.Bytes(), context.Response.StatusCode,
                    originalResponseHeaders, responseCapture.Bytes(), startedAt,
                    context.Connection.RemoteIpAddress?.ToString(), null), context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (DirectHttpSpecusException ex)
        {
            if (mediaCapture is not null)
            {
                await mediaCapture.FailAsync(ex.Message, CancellationToken.None).ConfigureAwait(false);
            }
            var responseBody = Encoding.UTF8.GetBytes(ex.Message);
            await inspection.RecordHttpExchangeAsync(new HttpExchangeCapture(clientName, route,
                    context.Request.Method, relativePath, RawQuery(context.Request.QueryString),
                    requestHeaders, requestCapture.Bytes(),
                    ex.StatusCode, PlainErrorHeaders(), responseBody, startedAt, context.Connection.RemoteIpAddress?.ToString(),
                    ex.Message), CancellationToken.None)
                .ConfigureAwait(false);
            await WriteTextErrorAsync(context.Response, ex.StatusCode, ex.Message).ConfigureAwait(false);
        }
        finally
        {
            if (mediaCapture is { Active: true })
            {
                await mediaCapture.FailAsync("媒体响应中断", CancellationToken.None)
                    .ConfigureAwait(false);
            }
        }
    }

    private static async Task PumpRequestAsync(HttpContext context, HttpSpecusStream stream,
        TrafficUsageService traffic, string clientName, string route, LimitedCapture capture,
        int maxBytes, bool stripAuthorization, IReadOnlyCollection<string> declaredTrailerNames,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[64 * 1024];
        long total = 0;
        try
        {
            while (true)
            {
                var read = await context.Request.Body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    var trailers = RequestTrailers(context, stripAuthorization, declaredTrailerNames);
                    await stream.FinishRequestAsync(trailers.Count == 0
                            ? null
                            : new Dictionary<string, object?> { ["trailers"] = trailers }, cancellationToken)
                        .ConfigureAwait(false);
                    return;
                }
                total += read;
                capture.Write(buffer.AsSpan(0, read));
                if (total > maxBytes)
                {
                    await stream.ResetAsync(4, "HTTP request body exceeds limit", CancellationToken.None)
                        .ConfigureAwait(false);
                    return;
                }
                await stream.SendDataAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                traffic.RecordHttpUpload(clientName, route, read);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception)
        {
            await stream.ResetAsync(5, "HTTP request stream failed", CancellationToken.None)
                .ConfigureAwait(false);
            throw;
        }
    }

    private static string RelativePath(HttpContext context, string? rest)
    {
        var rawTarget = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        if (!string.IsNullOrEmpty(rawTarget))
        {
            var queryIndex = rawTarget.IndexOf('?', StringComparison.Ordinal);
            var rawPath = queryIndex >= 0 ? rawTarget[..queryIndex] : rawTarget;
            const string prefix = "/http/";
            if (rawPath.StartsWith(prefix, StringComparison.Ordinal))
            {
                var clientSeparator = rawPath.IndexOf('/', prefix.Length);
                if (clientSeparator >= 0)
                {
                    var routeSeparator = rawPath.IndexOf('/', clientSeparator + 1);
                    return routeSeparator >= 0 ? PreserveRawPathEncoding(rawPath[routeSeparator..]) : "/";
                }
                return "/";
            }
        }

        return string.IsNullOrWhiteSpace(rest) ? "/" : PreserveRawPathEncoding("/" + rest);
    }

    private static string PreserveRawPathEncoding(string path)
    {
        var builder = new StringBuilder(path.Length);
        for (var i = 0; i < path.Length;)
        {
            var ch = path[i];
            if (ch == '%' && i + 2 < path.Length && IsHex(path[i + 1]) && IsHex(path[i + 2]))
            {
                builder.Append(path, i, 3);
                i += 3;
                continue;
            }

            if (ch <= 0x7f && IsRawPathSafeAscii(ch))
            {
                builder.Append(ch);
                i++;
                continue;
            }

            var consumed = char.IsHighSurrogate(ch) && i + 1 < path.Length && char.IsLowSurrogate(path[i + 1])
                ? 2
                : 1;
            foreach (var b in Encoding.UTF8.GetBytes(path.AsSpan(i, consumed).ToString()))
            {
                builder.Append('%');
                builder.Append(b.ToString("X2", System.Globalization.CultureInfo.InvariantCulture));
            }
            i += consumed;
        }
        return builder.ToString();
    }

    private static bool IsHex(char ch) =>
        ch is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';

    private static bool IsRawPathSafeAscii(char ch) =>
        ch is >= 'A' and <= 'Z'
            or >= 'a' and <= 'z'
            or >= '0' and <= '9'
            or '/'
            or '-'
            or '.'
            or '_'
            or '~'
            or '!'
            or '$'
            or '&'
            or '\''
            or '('
            or ')'
            or '*'
            or '+'
            or ','
            or ';'
            or '='
            or ':'
            or '@';

    private static List<string> RequestHeaders(HttpRequest request, bool stripAuthorization,
        bool webSocket)
    {
        var headers = new List<string>();
        foreach (var (name, values) in request.Headers)
        {
            if (!ShouldForward(name)
                || (webSocket && WebSocketHandshakeHeaders.Contains(name))
                || (stripAuthorization && name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            foreach (var value in values)
            {
                headers.Add($"{name}:{value}");
            }
        }
        return headers;
    }

    private static async Task ForwardWebSocketAsync(HttpContext context, string clientName,
        string route, string relativePath, DirectHttpDispatcher dispatcher, bool stripAuthorization)
    {
        var metadata = new Dictionary<string, object?>
        {
            ["source"] = "ws",
            ["channelId"] = Guid.NewGuid().ToString(),
            ["clientName"] = clientName,
            ["route"] = route,
            ["relativePath"] = relativePath,
            ["rawQuery"] = RawQuery(context.Request.QueryString),
            ["headers"] = RequestHeaders(context.Request, stripAuthorization, true),
            ["body"] = Array.Empty<byte>(),
        };

        await using var socket = await RawServerWebSocketConnection.AcceptAsync(
            context, context.RequestAborted).ConfigureAwait(false);
        var closeState = new WebSocketTunnelCloseState();
        WebSocketSpecusStream stream;
        try
        {
            stream = await dispatcher.OpenWebSocketAsync(clientName, metadata, context.RequestAborted)
                .ConfigureAwait(false);
        }
        catch (DirectHttpSpecusException ex)
        {
            await SafeSendBrowserCloseAsync(socket,
                    (ushort)WebSocketCloseStatus.InternalServerError, ex.Message)
                .ConfigureAwait(false);
            return;
        }

        await using var streamLifetime = stream;
        using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(context.RequestAborted);
        var browserToClient = PumpBrowserWebSocketAsync(socket, stream, closeState, pumpCts.Token);
        var clientToBrowser = PumpClientWebSocketAsync(socket, stream, closeState, pumpCts.Token);
        var completed = await Task.WhenAny(browserToClient, clientToBrowser).ConfigureAwait(false);
        var peerPump = ReferenceEquals(completed, browserToClient) ? clientToBrowser : browserToClient;
        if (closeState.CloseStarted && !peerPump.IsCompleted)
        {
            var peerTerminal = await Task.WhenAny(peerPump, Task.Delay(TimeSpan.FromSeconds(5),
                context.RequestAborted)).ConfigureAwait(false);
            if (ReferenceEquals(peerTerminal, peerPump))
            {
                completed = peerPump;
            }
        }
        try
        {
            await completed.ConfigureAwait(false);
        }
        finally
        {
            pumpCts.Cancel();
            await IgnoreTunnelCompletionAsync(browserToClient).ConfigureAwait(false);
            await IgnoreTunnelCompletionAsync(clientToBrowser).ConfigureAwait(false);
        }
    }

    internal static async Task PumpBrowserWebSocketAsync(RawServerWebSocketConnection socket,
        WebSocketSpecusStream stream,
        WebSocketTunnelCloseState closeState, CancellationToken cancellationToken)
    {
        var fragmentOpen = false;
        long messageBytes = 0;
        try
        {
            while (!cancellationToken.IsCancellationRequested && socket.IsOpen)
            {
                var frame = await socket.ReadFrameAsync(cancellationToken).ConfigureAwait(false);
                if (frame is null)
                {
                    break;
                }
                ValidateWebSocketFragmentSequence(frame, ref fragmentOpen, ref messageBytes);
                if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
                {
                    closeState.MarkBrowserInitiated();
                    using var closeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    closeCts.CancelAfter(TimeSpan.FromSeconds(5));
                    await SendRawWebSocketFrameToClientAsync(stream, frame, finish: true,
                        closeCts.Token).ConfigureAwait(false);
                    await socket.ReplyToCloseAsync(frame, closeCts.Token).ConfigureAwait(false);
                    return;
                }
                await SendRawWebSocketFrameToClientAsync(stream, frame, finish: false,
                    cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The opposite side ended the tunnel or the HTTP request was aborted.
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
        {
            closeState.MarkBrowserInitiated();
            await SendGeneratedCloseToClientAsync(stream,
                (ushort)WebSocketCloseStatus.ProtocolError, "invalid WebSocket frame",
                CancellationToken.None).ConfigureAwait(false);
            await SafeSendBrowserCloseAsync(socket,
                (ushort)WebSocketCloseStatus.ProtocolError, "invalid WebSocket frame")
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            if (stream.PeerTerminated)
            {
                closeState.MarkClientInitiated();
                return;
            }
            await SendGeneratedCloseToClientAsync(stream,
                (ushort)WebSocketCloseStatus.InternalServerError, string.Empty,
                CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static async Task PumpClientWebSocketAsync(RawServerWebSocketConnection socket,
        WebSocketSpecusStream stream,
        WebSocketTunnelCloseState closeState, CancellationToken cancellationToken)
    {
        var fragmentOpen = false;
        long messageBytes = 0;
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var item = await stream.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (item.End)
                {
                    if (!closeState.CloseStarted)
                    {
                        closeState.MarkClientInitiated();
                        await SafeSendBrowserCloseAsync(socket,
                                (ushort)WebSocketCloseStatus.EndpointUnavailable, string.Empty)
                            .ConfigureAwait(false);
                    }
                    return;
                }

                var encoded = item.Data ?? Array.Empty<byte>();
                var frame = WebSocketSpecusFrame.Decode(encoded);
                var payload = frame.Payload;
                if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
                {
                    payload = frame.CloseCode == 0
                        ? []
                        : [(byte)(frame.CloseCode >> 8), (byte)frame.CloseCode, .. payload];
                }
                var rawFrame = new RawServerWebSocketFrame(
                    frame.Opcode, frame.FinalFragment, frame.Rsv, payload);
                ValidateWebSocketFragmentSequence(rawFrame, ref fragmentOpen, ref messageBytes);
                if (frame.Opcode == WebSocketSpecusFrame.OpcodeClose)
                {
                    closeState.MarkClientInitiated();
                }
                await socket.WriteFrameAsync(rawFrame, cancellationToken).ConfigureAwait(false);
                await stream.ConsumeAsync(encoded.Length, CancellationToken.None).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // The browser side ended first.
        }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentException)
        {
            await stream.ResetAsync(30, "invalid WebSocket SWS2 frame", CancellationToken.None)
                .ConfigureAwait(false);
            await SafeSendBrowserCloseAsync(socket,
                (ushort)WebSocketCloseStatus.ProtocolError, "invalid WebSocket frame")
                .ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            closeState.MarkClientInitiated();
            await SafeSendBrowserCloseAsync(socket,
                (ushort)WebSocketCloseStatus.InternalServerError, "WebSocket tunnel reset")
                .ConfigureAwait(false);
        }
    }

    private static async Task SendRawWebSocketFrameToClientAsync(WebSocketSpecusStream stream,
        RawServerWebSocketFrame rawFrame, bool finish, CancellationToken cancellationToken)
    {
        var (closeCode, payload) = SplitClosePayload(rawFrame);
        var offset = 0;
        var first = true;
        do
        {
            var length = Math.Min(WebSocketSpecusFrame.MaxPayloadBytes, payload.Length - offset);
            var last = offset + length == payload.Length;
            var frame = new WebSocketSpecusFrame(
                first ? rawFrame.Opcode : WebSocketSpecusFrame.OpcodeContinuation,
                rawFrame.FinalFragment && last,
                first ? rawFrame.Rsv : (byte)0,
                first ? closeCode : (ushort)0,
                payload.AsSpan(offset, length).ToArray());
            await stream.SendDataAsync(frame.Encode(), cancellationToken).ConfigureAwait(false);
            offset += length;
            first = false;
        }
        while (offset < payload.Length);
        if (finish)
        {
            await stream.FinishAsync(cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task SendGeneratedCloseToClientAsync(WebSocketSpecusStream stream,
        ushort status, string reason, CancellationToken cancellationToken)
    {
        var reasonBytes = Encoding.UTF8.GetBytes(TruncateCloseReason(reason));
        var payload = new byte[2 + reasonBytes.Length];
        payload[0] = (byte)(status >> 8);
        payload[1] = (byte)status;
        reasonBytes.CopyTo(payload, 2);
        using var closeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        closeCts.CancelAfter(TimeSpan.FromSeconds(5));
        try
        {
            await SendRawWebSocketFrameToClientAsync(stream,
                new RawServerWebSocketFrame(WebSocketSpecusFrame.OpcodeClose, true, 0, payload),
                finish: true, closeCts.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException)
        {
            // DisposeAsync emits a bounded best-effort RST when CLOSE + FIN could not be delivered.
        }
    }

    private static void ValidateWebSocketFragmentSequence(RawServerWebSocketFrame frame,
        ref bool fragmentOpen, ref long messageBytes)
    {
        if (frame.Opcode >= WebSocketSpecusFrame.OpcodeClose)
        {
            return;
        }
        if (frame.Opcode == WebSocketSpecusFrame.OpcodeContinuation)
        {
            if (!fragmentOpen)
            {
                throw new InvalidDataException("orphan WebSocket continuation frame");
            }
        }
        else if (fragmentOpen)
        {
            throw new InvalidDataException(
                "new WebSocket message before fragmented message completed");
        }
        messageBytes = checked(messageBytes + frame.Payload.Length);
        if (messageBytes > WebSocketMaxMessageBytes)
        {
            throw new InvalidDataException("WebSocket message exceeds limit");
        }
        fragmentOpen = !frame.FinalFragment;
        if (frame.FinalFragment)
        {
            messageBytes = 0;
        }
    }

    private static (ushort CloseCode, byte[] Payload) SplitClosePayload(
        RawServerWebSocketFrame frame)
    {
        if (frame.Opcode != WebSocketSpecusFrame.OpcodeClose || frame.Payload.Length == 0)
        {
            return (0, frame.Payload);
        }
        if (frame.Payload.Length == 1)
        {
            throw new InvalidDataException("invalid WebSocket close payload");
        }
        return ((ushort)((frame.Payload[0] << 8) | frame.Payload[1]), frame.Payload[2..]);
    }

    private static async Task<bool> SafeSendBrowserCloseAsync(
        RawServerWebSocketConnection socket, ushort status, string reason)
    {
        using var closeCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        try
        {
            var reasonBytes = Encoding.UTF8.GetBytes(TruncateCloseReason(reason));
            var payload = new byte[2 + reasonBytes.Length];
            payload[0] = (byte)(status >> 8);
            payload[1] = (byte)status;
            reasonBytes.CopyTo(payload, 2);
            await socket.WriteFrameAsync(new RawServerWebSocketFrame(
                WebSocketSpecusFrame.OpcodeClose, true, 0, payload), closeCts.Token)
                .ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is OperationCanceledException or IOException
                                   or InvalidOperationException or ObjectDisposedException)
        {
            return false;
        }
    }

    private static string TruncateCloseReason(string reason)
    {
        if (Encoding.UTF8.GetByteCount(reason) <= 123)
        {
            return reason;
        }
        var builder = new StringBuilder();
        var bytes = 0;
        foreach (var rune in reason.EnumerateRunes())
        {
            if (bytes + rune.Utf8SequenceLength > 123)
            {
                break;
            }
            builder.Append(rune.ToString());
            bytes += rune.Utf8SequenceLength;
        }
        return builder.ToString();
    }

    private static async Task IgnoreTunnelCompletionAsync(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Expected when the peer pump wins.
        }
        catch (Exception ex) when (ex is WebSocketException or IOException)
        {
            // Expected when either transport disappears during shutdown.
        }
    }

    internal sealed class WebSocketTunnelCloseState
    {
        private int _clientInitiated;
        private int _browserInitiated;

        public bool ClientInitiated => Volatile.Read(ref _clientInitiated) != 0;
        public bool CloseStarted => ClientInitiated
            || Volatile.Read(ref _browserInitiated) != 0;

        public void MarkClientInitiated() => Interlocked.Exchange(ref _clientInitiated, 1);
        public void MarkBrowserInitiated() => Interlocked.Exchange(ref _browserInitiated, 1);
    }

    private static List<string> PlainErrorHeaders() => ["Content-Type:text/plain;charset=UTF-8"];

    private static string? RawQuery(QueryString queryString) =>
        queryString.HasValue ? queryString.Value![1..] : null;

    private static void CopyHeaders(List<string>? source, HttpResponse response)
    {
        if (source is null)
        {
            return;
        }

        foreach (var header in source)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                continue;
            }
            var name = header[..separator];
            if (ShouldForward(name))
            {
                response.Headers.Append(name, header[(separator + 1)..]);
            }
        }
    }

    private static async Task<HttpRouteAccessPolicy> LoadRouteAccessPolicyAsync(SpecusDbContext db,
        string clientName, string route,
        CancellationToken cancellationToken)
    {
        var account = await db.ClientAccounts.AsNoTracking()
            .FirstOrDefaultAsync(c => c.ClientName == clientName, cancellationToken)
            .ConfigureAwait(false);
        if (account is null)
        {
            return HttpRouteAccessPolicy.Public;
        }
        return await db.HttpRouteMappings.AsNoTracking()
            .Where(r => r.ClientId == account.Id && r.Route == route)
            .Select(r => new HttpRouteAccessPolicy(true, r.Enabled, r.PathRewriteEnabled, r.AuthEnabled,
                r.AuthUsername, r.AuthPasswordHash))
            .FirstOrDefaultAsync(cancellationToken)
            .ConfigureAwait(false) ?? HttpRouteAccessPolicy.Public;
    }

    private static List<string>? StripRewriteHeaders(List<string>? source)
    {
        if (source is null)
        {
            return null;
        }
        var result = new List<string>(source.Count);
        foreach (var header in source)
        {
            var separator = header.IndexOf(':', StringComparison.Ordinal);
            if (separator <= 0)
            {
                result.Add(header);
                continue;
            }
            var name = header[..separator].Trim();
            if (name.Equals("content-encoding", StringComparison.OrdinalIgnoreCase)
                || name.Equals("content-length", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            result.Add(header);
        }
        return result;
    }

    private static readonly FrozenSet<string> RewritableContentTypes = new[]
    {
        "text/html", "text/css", "text/javascript", "application/javascript",
        "application/x-javascript", "application/ecmascript", "text/ecmascript",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private static readonly FrozenSet<string> WebSocketHandshakeHeaders = new[]
    {
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-extensions",
        "sec-websocket-protocol",
        "sec-websocket-accept",
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    private const int WebSocketMaxMessageBytes = 16 * 1024 * 1024;

    private static bool IsRewritable(IReadOnlyList<string>? headers)
    {
        foreach (var header in headers ?? [])
        {
            var separator = header.IndexOf(':');
            if (separator > 0 && header[..separator].Equals("content-type", StringComparison.OrdinalIgnoreCase))
            {
                var contentType = header[(separator + 1)..].Split(';', 2)[0].Trim();
                return RewritableContentTypes.Contains(contentType);
            }
        }
        return false;
    }

    private static async Task WriteResponseChunkAsync(HttpResponse response, byte[] data,
        CancellationToken cancellationToken)
    {
        if (data.Length == 0)
        {
            return;
        }
        await response.Body.WriteAsync(data, cancellationToken).ConfigureAwait(false);
        await response.Body.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static int? AsInt(Dictionary<string, object?>? metadata, string key)
    {
        if (metadata is null || !metadata.TryGetValue(key, out var value) || value is null)
        {
            return null;
        }
        return value switch
        {
            int number => number,
            long number when number is >= int.MinValue and <= int.MaxValue => (int)number,
            double number when number is >= int.MinValue and <= int.MaxValue => (int)number,
            JsonValue json when json.TryGetValue<int>(out var number) => number,
            JsonElement json when json.TryGetInt32(out var number) => number,
            _ when int.TryParse(value.ToString(), out var number) => number,
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

    private static List<string> DeclaredRequestTrailers(HttpRequest request, bool stripAuthorization) =>
        ValidTrailerNames(request.Headers["Trailer"].SelectMany(static value =>
            (value ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)),
            stripAuthorization);

    private static List<string> RequestTrailers(HttpContext context, bool stripAuthorization,
        IReadOnlyCollection<string> declaredTrailerNames)
    {
        var feature = context.Features.Get<IHttpRequestTrailersFeature>();
        if (feature is null || !feature.Available)
        {
            return [];
        }
        var allowed = ValidTrailerNames(declaredTrailerNames, stripAuthorization)
            .ToFrozenSet(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();
        foreach (var (name, values) in feature.Trailers)
        {
            if (!allowed.Contains(name))
            {
                continue;
            }
            result.AddRange(values.Where(IsValidHeaderValue).Select(value => $"{name}:{value}"));
        }
        return result;
    }

    private static void AppendResponseTrailer(HttpResponse response, string line,
        IReadOnlyCollection<string> declaredTrailerNames)
    {
        var separator = line.IndexOf(':');
        if (separator <= 0)
        {
            return;
        }
        var name = line[..separator].Trim();
        var value = line[(separator + 1)..].Trim();
        if (declaredTrailerNames.Contains(name, StringComparer.OrdinalIgnoreCase)
            && IsSafeTrailerName(name) && IsValidHeaderValue(value))
        {
            response.AppendTrailer(name, value);
        }
    }

    private static List<string> ValidTrailerNames(IEnumerable<string> names, bool stripAuthorization) =>
        names.Select(static name => name.Trim())
            .Where(name => IsSafeTrailerName(name)
                           && (!stripAuthorization
                               || !name.Equals("Authorization", StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static bool IsSafeTrailerName(string name) =>
        IsValidHeaderName(name) && !SkippedHeaders.Contains(name);

    private static bool IsValidHeaderValue(string? value) =>
        value is not null && value.IndexOfAny(['\r', '\n']) < 0;

    private static bool IsValidHeaderName(string name) =>
        !string.IsNullOrWhiteSpace(name) && name.All(static ch =>
            char.IsAsciiLetterOrDigit(ch) || "!#$%&'*+-.^_`|~".Contains(ch));

    private sealed class LimitedCapture
    {
        private readonly object _sync = new();
        private readonly int _limit;
        private readonly MemoryStream _buffer = new();

        public LimitedCapture(int limit) => _limit = Math.Max(0, limit);

        public void Write(ReadOnlySpan<byte> data)
        {
            lock (_sync)
            {
                var remaining = _limit - checked((int)_buffer.Length);
                if (remaining > 0)
                {
                    _buffer.Write(data[..Math.Min(data.Length, remaining)]);
                }
            }
        }

        public byte[] Bytes()
        {
            lock (_sync)
            {
                return _buffer.ToArray();
            }
        }
    }

    private static bool ShouldForward(string name) => !SkippedHeaders.Contains(name);

    private static async Task WriteTextErrorAsync(HttpResponse response, int statusCode, string message)
    {
        response.StatusCode = statusCode;
        response.ContentType = "text/plain;charset=UTF-8";
        await response.WriteAsync(message, Encoding.UTF8).ConfigureAwait(false);
    }

    private sealed record HttpRouteAccessPolicy(bool Managed, bool Enabled, bool PathRewriteEnabled, bool AuthEnabled,
        string? AuthUsername, string? AuthPasswordHash)
    {
        public static readonly HttpRouteAccessPolicy Public = new(false, true, false, false, null, null);
    }
}
