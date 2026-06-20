using System.Collections.Concurrent;
using Microsoft.Extensions.Options;
using ShuaiTunnel.Protocol.Packets;
using ShuaiTunnel.Server.Configuration;
using ShuaiTunnel.Server.Sessions;

namespace ShuaiTunnel.Server.Http;

public sealed class DirectHttpDispatcher
{
    private readonly ConcurrentDictionary<string, TaskCompletionSource<DirectHttpResponsePacket>> _pending = new();
    private readonly SessionRegistry _sessions;
    private readonly DirectHttpOptions _options;
    private readonly ILogger<DirectHttpDispatcher> _logger;

    public DirectHttpDispatcher(SessionRegistry sessions, IOptions<DirectHttpOptions> options,
        ILogger<DirectHttpDispatcher> logger)
    {
        _sessions = sessions;
        _options = options.Value;
        _logger = logger;
    }

    public async Task<DirectHttpResponsePacket> ForwardAsync(string clientName,
        DirectHttpRequestPacket packet, CancellationToken cancellationToken)
    {
        var context = _sessions.Find(clientName);
        if (context is null || !_sessions.HasLogin(context))
        {
            throw new DirectHttpTunnelException(StatusCodes.Status503ServiceUnavailable,
                $"客户端不在线: {clientName}");
        }

        var requestId = Guid.NewGuid().ToString();
        packet.RequestId = requestId;
        var tcs = new TaskCompletionSource<DirectHttpResponsePacket>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[requestId] = tcs;

        try
        {
            await context.Writer.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            return await tcs.Task.WaitAsync(TimeSpan.FromMilliseconds(Math.Max(1, _options.TimeoutMs)),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            throw new DirectHttpTunnelException(StatusCodes.Status504GatewayTimeout, "HTTP 转发请求超时");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (DirectHttpTunnelException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[http-direct] request {RequestId} failed", requestId);
            throw new DirectHttpTunnelException(StatusCodes.Status502BadGateway, "HTTP 转发请求失败", ex);
        }
        finally
        {
            _pending.TryRemove(requestId, out _);
        }
    }

    public void Ack(DirectHttpResponsePacket packet)
    {
        if (packet.RequestId is null || !_pending.TryGetValue(packet.RequestId, out var tcs))
        {
            _logger.LogWarning("[http-direct] dropped response for unknown request {RequestId}", packet.RequestId);
            return;
        }

        tcs.TrySetResult(packet);
    }
}

public sealed class DirectHttpTunnelException : Exception
{
    public DirectHttpTunnelException(int statusCode, string message) : base(message)
    {
        StatusCode = statusCode;
    }

    public DirectHttpTunnelException(int statusCode, string message, Exception innerException)
        : base(message, innerException)
    {
        StatusCode = statusCode;
    }

    public int StatusCode { get; }
}
