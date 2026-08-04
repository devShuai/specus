using Specus.Server.Nat;

namespace Specus.Server.Http;

/// <summary>Opens mandatory NAT stream v2 HTTP exchanges for the public HTTP ingress.</summary>
public sealed class DirectHttpDispatcher
{
    private readonly NatServerHandler _nat;

    public DirectHttpDispatcher(NatServerHandler nat)
    {
        _nat = nat;
    }

    internal async Task<HttpSpecusStream> OpenAsync(string clientName,
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        try
        {
            return await _nat.OpenHttpStreamAsync(clientName, metadata, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            throw new DirectHttpSpecusException(StatusCodes.Status503ServiceUnavailable,
                $"客户端不在线: {clientName}", ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new DirectHttpSpecusException(StatusCodes.Status502BadGateway,
                "HTTP 转发请求发送失败", ex);
        }
    }

    internal async Task<WebSocketSpecusStream> OpenWebSocketAsync(string clientName,
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        try
        {
            return await _nat.OpenWebSocketStreamAsync(clientName, metadata, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            throw new DirectHttpSpecusException(StatusCodes.Status503ServiceUnavailable,
                $"客户端不在线: {clientName}", ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new DirectHttpSpecusException(StatusCodes.Status502BadGateway,
                "WebSocket 隧道请求发送失败", ex);
        }
    }
}

public sealed class DirectHttpSpecusException : Exception
{
    public DirectHttpSpecusException(int statusCode, string message) : base(message)
    {
        StatusCode = statusCode;
    }

    public DirectHttpSpecusException(int statusCode, string message, Exception innerException)
        : base(message, innerException)
    {
        StatusCode = statusCode;
    }

    public int StatusCode { get; }
}
