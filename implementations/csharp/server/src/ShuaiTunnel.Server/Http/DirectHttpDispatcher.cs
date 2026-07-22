using ShuaiTunnel.Server.Nat;

namespace ShuaiTunnel.Server.Http;

/// <summary>Opens mandatory NAT stream v2 HTTP exchanges for the public HTTP ingress.</summary>
public sealed class DirectHttpDispatcher
{
    private readonly NatServerHandler _nat;

    public DirectHttpDispatcher(NatServerHandler nat)
    {
        _nat = nat;
    }

    internal async Task<HttpTunnelStream> OpenAsync(string clientName,
        Dictionary<string, object?> metadata, CancellationToken cancellationToken)
    {
        try
        {
            return await _nat.OpenHttpStreamAsync(clientName, metadata, cancellationToken)
                .ConfigureAwait(false);
        }
        catch (InvalidOperationException ex)
        {
            throw new DirectHttpTunnelException(StatusCodes.Status503ServiceUnavailable,
                $"客户端不在线: {clientName}", ex);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            throw new DirectHttpTunnelException(StatusCodes.Status502BadGateway,
                "HTTP 转发请求发送失败", ex);
        }
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
