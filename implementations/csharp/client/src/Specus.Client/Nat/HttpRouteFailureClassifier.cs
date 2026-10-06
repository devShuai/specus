using System.Net.Sockets;
using Specus.Protocol.HttpRoute;

namespace Specus.Client.Nat;

/// <summary>
/// Places a failure to get a response head from an HTTP route's target in the closed failure set
/// of protocol/spec/service-connectivity-check.md section 6.2.
/// </summary>
/// <remarks>
/// It reads exception types, <see cref="HttpRequestError"/> and <see cref="SocketError"/>, which
/// the runtime normalises across platforms (<c>WSAECONNREFUSED</c> and <c>ECONNREFUSED</c> are
/// both <see cref="SocketError.ConnectionRefused"/>), and never the message text, which changes
/// with the platform, its language and the runtime. Whatever it cannot place returns null: the RST
/// then carries its reason alone and a server reports <c>TARGET_UNVERIFIED</c>.
/// </remarks>
internal static class HttpRouteFailureClassifier
{
    /// <summary>Classifies an exception from sending a request, before any response head.</summary>
    /// <param name="exception">What the HTTP client threw.</param>
    /// <param name="timeoutIsConnectTimeout">
    /// True when the client has no overall request timeout, so a timeout before the response head
    /// can only be SocketsHttpHandler's ConnectTimeout. That timeout spans the TLS handshake, as
    /// the Go client's does, so a handshake that stalls is a connect timeout too.
    /// </param>
    public static string? Classify(Exception exception, bool timeoutIsConnectTimeout) => exception switch
    {
        HttpRequestException request => Classify(request),
        // SocketsHttpHandler reports ConnectTimeout as a cancellation wrapping a TimeoutException.
        OperationCanceledException { InnerException: TimeoutException } when timeoutIsConnectTimeout
            => HttpRouteFailure.ConnectTimeout,
        _ => null,
    };

    /// <summary>RST metadata: the reason as always, and the failure next to it when there is one.</summary>
    public static Dictionary<string, object?> ResetMetadata(string reason, string? failure)
    {
        var metadata = new Dictionary<string, object?> { ["reason"] = reason };
        if (failure is not null)
        {
            metadata[HttpRouteFailure.MetadataKey] = failure;
        }
        return metadata;
    }

    private static string? Classify(HttpRequestException exception) => exception.HttpRequestError switch
    {
        HttpRequestError.NameResolutionError => HttpRouteFailure.DnsFailed,
        // Raised by the connect itself, with the socket error inside.
        HttpRequestError.ConnectionError => ClassifyConnect(Find<SocketException>(exception)),
        HttpRequestError.SecureConnectionError => HttpRouteFailure.TlsFailed,
        // Connected, but the target closed before the head, sent one that does not parse, or sent
        // one larger than the handler accepts.
        HttpRequestError.ResponseEnded or HttpRequestError.InvalidResponse
            or HttpRequestError.ConfigurationLimitExceeded => HttpRouteFailure.ProtocolError,
        // Connected, and the target reset or aborted the connection before the head.
        HttpRequestError.Unknown when Find<SocketException>(exception)?.SocketErrorCode
            is SocketError.ConnectionReset or SocketError.ConnectionAborted => HttpRouteFailure.ProtocolError,
        _ => null,
    };

    private static string? ClassifyConnect(SocketException? socket) => socket?.SocketErrorCode switch
    {
        SocketError.ConnectionRefused => HttpRouteFailure.ConnectRefused,
        // The operating system gives up on a SYN long after ConnectTimeout, but it is the same failure.
        SocketError.TimedOut => HttpRouteFailure.ConnectTimeout,
        // Only HostNotFound and TryAgain become NameResolutionError; no address of the family is
        // still a lookup that found nothing usable.
        SocketError.HostNotFound or SocketError.TryAgain or SocketError.NoData => HttpRouteFailure.DnsFailed,
        SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown
            or SocketError.NetworkDown or SocketError.ConnectionReset => HttpRouteFailure.Unreachable,
        _ => null,
    };

    private static T? Find<T>(Exception exception) where T : Exception
    {
        for (Exception? current = exception; current is not null; current = current.InnerException)
        {
            if (current is T match)
            {
                return match;
            }
        }
        return null;
    }
}
