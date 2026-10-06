using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Protocol;
using Specus.Protocol.HttpRoute;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

/// <summary>
/// An HTTP stream that fails before its response OPEN classifies the failure on its RST for the
/// connectivity check (protocol/spec/service-connectivity-check.md section 6).
/// </summary>
/// <remarks>
/// The failures are produced for real on loopback through the handler the forwarder builds. Name
/// lookups and unreachable networks are the exception: the system resolver would send the query to
/// the network and loopback is never unreachable, so a connect callback raises the socket error
/// those produce and SocketsHttpHandler wraps it as it wraps its own.
/// </remarks>
public sealed class HttpRouteFailureTests
{
    [Fact]
    public void TheLoginEnvironmentAnnouncesTheHttpRouteCapability()
    {
        var environment = ClientEnvironmentInfo.Collect(NullLogger.Instance);
        using var document = JsonDocument.Parse(JsonSerializer.Serialize(environment));

        Assert.True(document.RootElement.TryGetProperty("clientHttpRouteCapabilities", out var capabilities),
            "the login environment carries no clientHttpRouteCapabilities");
        // A server trusts metadata.failure only from a session that announced version 1.
        Assert.Equal(1, capabilities.GetProperty("version").GetInt32());
    }

    public static TheoryData<string, string> RealFailures => new()
    {
        { "closed port", HttpRouteFailure.ConnectRefused },
        { "connect that never completes", HttpRouteFailure.ConnectTimeout },
        { "TLS handshake that never completes", HttpRouteFailure.ConnectTimeout },
        { "https to a plain HTTP server", HttpRouteFailure.TlsFailed },
        { "untrusted certificate", HttpRouteFailure.TlsFailed },
        { "closed before the response head", HttpRouteFailure.ProtocolError },
        { "reset before the response head", HttpRouteFailure.ProtocolError },
        { "malformed status line", HttpRouteFailure.ProtocolError },
        { "name not found", HttpRouteFailure.DnsFailed },
        { "host unreachable", HttpRouteFailure.Unreachable },
        { "network unreachable", HttpRouteFailure.Unreachable },
    };

    [Theory]
    [MemberData(nameof(RealFailures))]
    public async Task ClassifiesWhatTheHandlerThrows(string scenario, string expected)
    {
        await using var upstream = Upstream.For(scenario);
        using var client = new HttpClient(upstream.Handler) { Timeout = Timeout.InfiniteTimeSpan };

        var error = await Assert.ThrowsAnyAsync<Exception>(() => client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, upstream.Target),
            HttpCompletionOption.ResponseHeadersRead));

        Assert.Equal(expected, HttpRouteFailureClassifier.Classify(error, timeoutIsConnectTimeout: true));
    }

    /// <summary>
    /// With an overall request timeout on the client, a timeout cannot be told from the connect
    /// timeout, and a timeout waiting for the head is no connect failure at all.
    /// </summary>
    [Fact]
    public async Task ARequestTimeoutIsNotAConnectTimeout()
    {
        await using var upstream = Upstream.For("silent http");
        using var client = new HttpClient(upstream.Handler) { Timeout = TimeSpan.FromMilliseconds(300) };

        var error = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.SendAsync(
            new HttpRequestMessage(HttpMethod.Head, upstream.Target),
            HttpCompletionOption.ResponseHeadersRead));

        Assert.Null(HttpRouteFailureClassifier.Classify(error, timeoutIsConnectTimeout: false));
    }

    [Fact]
    public void UnknownFailuresAreNotGuessedAt()
    {
        Assert.Null(HttpRouteFailureClassifier.Classify(new InvalidDataException("x"), true));
        Assert.Null(HttpRouteFailureClassifier.Classify(
            new HttpRequestException(HttpRequestError.ConnectionError, "x",
                new SocketException((int)SocketError.AccessDenied)), true));
        Assert.Null(HttpRouteFailureClassifier.Classify(
            new HttpRequestException(HttpRequestError.Unknown, "x", new IOException("x")), true));
    }

    public static TheoryData<string, uint, string?> StreamFailures => new()
    {
        { "missing route", 22, HttpRouteFailure.RouteNotLoaded },
        { "route without target", 22, HttpRouteFailure.RouteNotLoaded },
        { "unusable target", 26, HttpRouteFailure.TargetInvalid },
        { "closed port", 26, HttpRouteFailure.ConnectRefused },
        { "name not found", 26, HttpRouteFailure.DnsFailed },
        { "connect that never completes", 26, HttpRouteFailure.ConnectTimeout },
        { "https to a plain HTTP server", 26, HttpRouteFailure.TlsFailed },
        { "closed before the response head", 26, HttpRouteFailure.ProtocolError },
        { "malformed request", 26, null },
    };

    /// <summary>
    /// The RST written on the data connection carries the failure next to the value and reason it
    /// always had; a failure outside the set carries no failure key.
    /// </summary>
    [Theory]
    [MemberData(nameof(StreamFailures))]
    public async Task TheStreamResetCarriesTheFailure(string scenario, uint value, string? failure)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        await using var upstream = Upstream.For(scenario);
        var routes = scenario switch
        {
            "missing route" => [],
            "route without target" => [new HttpSpecusConfigEntry { Route = "api" }],
            "unusable target" => [new HttpSpecusConfigEntry { Route = "api", TargetBaseUrl = "ftp://127.0.0.1/" }],
            _ => new[] { new HttpSpecusConfigEntry { Route = "api", TargetBaseUrl = upstream.Target } },
        };
        var pipe = new Pipe();
        await using var writer = new FrameWriter(pipe.Writer.AsStream());
        using var http = new HttpClient(upstream.Handler) { Timeout = Timeout.InfiniteTimeSpan };
        using var forwarder = new DirectHttpForwarder(http);
        var directHttp = new DirectHttpHandler(routes, writer, forwarder, NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            Array.Empty<SpecusConfigEntry>(), "failure-test", writer, directHttp,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(timeout.Token);

        var open = new Dictionary<string, object?>
        {
            ["source"] = "http",
            ["phase"] = "request",
            ["route"] = "api",
            ["relativePath"] = "/",
        };
        if (scenario != "malformed request")
        {
            open["method"] = "HEAD";
        }
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open, StreamId = 41, MetaData = open,
        });
        await nat.HandleAsync(new NatMessagePacket { NatMessageType = NatMessageType.Fin, StreamId = 41 });

        var reset = await ReadResetAsync(pipe.Reader, 41, timeout.Token);
        Assert.Equal(value, reset.Value);
        Assert.False(string.IsNullOrWhiteSpace(MetadataString(reset, "reason")), "the RST lost its reason");
        if (failure is null)
        {
            Assert.False(reset.MetaData!.ContainsKey(HttpRouteFailure.MetadataKey),
                "an unclassified failure carries a failure key");
        }
        else
        {
            Assert.Equal(failure, MetadataString(reset, HttpRouteFailure.MetadataKey));
        }
    }

    private static async Task<NatMessagePacket> ReadResetAsync(PipeReader reader, uint streamId,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            var packet = await FrameReader.ReadFrameAsync(reader, 32 * 1024 * 1024, cancellationToken);
            if (packet is not NatMessagePacket nat || nat.StreamId != streamId)
            {
                continue;
            }
            Assert.NotEqual(NatMessageType.Open, nat.NatMessageType);
            if (nat.NatMessageType == NatMessageType.Rst)
            {
                return nat;
            }
        }
    }

    private static string? MetadataString(NatMessagePacket packet, string key) =>
        packet.MetaData is not null && packet.MetaData.TryGetValue(key, out var value)
            ? value switch
            {
                null => null,
                string text => text,
                JsonElement { ValueKind: JsonValueKind.String } json => json.GetString(),
                _ => value.ToString(),
            }
            : null;

    /// <summary>A target that fails one way, and the handler that reaches it.</summary>
    private sealed class Upstream : IAsyncDisposable
    {
        private readonly TcpListener? _listener;
        private readonly CancellationTokenSource _stop = new();
        private readonly X509Certificate2? _certificate;

        private Upstream(string target, SocketsHttpHandler handler, TcpListener? listener = null,
            X509Certificate2? certificate = null)
        {
            Target = target;
            Handler = handler;
            _listener = listener;
            _certificate = certificate;
        }

        public string Target { get; }

        public SocketsHttpHandler Handler { get; }

        public static Upstream For(string scenario)
        {
            var handler = DirectHttpForwarder.BuildDefaultHandler();
            switch (scenario)
            {
                case "closed port":
                    return new Upstream($"http://127.0.0.1:{ClosedPort()}", handler);
                case "connect that never completes":
                    // Holds the connect as an unanswered SYN would, until ConnectTimeout cancels it.
                    handler.ConnectTimeout = TimeSpan.FromMilliseconds(200);
                    handler.ConnectCallback = async (_, token) =>
                    {
                        await Task.Delay(Timeout.Infinite, token);
                        throw new InvalidOperationException("unreachable");
                    };
                    return new Upstream($"http://127.0.0.1:{ClosedPort()}", handler);
                case "TLS handshake that never completes":
                    handler.ConnectTimeout = TimeSpan.FromMilliseconds(300);
                    return Serving("https", handler, (_, _) => Silent());
                case "silent http":
                    return Serving("http", handler, (_, _) => Silent());
                case "https to a plain HTTP server":
                    return Serving("https", handler, async (stream, token) =>
                    {
                        // A ClientHello is no request head; answer whatever arrives first, as an
                        // HTTP server does with bytes it cannot parse.
                        _ = await stream.ReadAsync(new byte[4096], token);
                        await stream.WriteAsync(
                            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray(),
                            token);
                    });
                case "untrusted certificate":
                    return ServingTls(handler);
                case "closed before the response head":
                    return Serving("http", handler, ReadRequestHeadAsync);
                case "reset before the response head":
                    return Serving("http", handler, ReadRequestHeadAsync, resetOnClose: true);
                case "malformed status line":
                    return Serving("http", handler, async (stream, token) =>
                    {
                        await ReadRequestHeadAsync(stream, token);
                        await stream.WriteAsync("SPECUS-NOT-HTTP\r\n\r\n"u8.ToArray(), token);
                    });
                case "name not found":
                    return Raising("http://specus-connectivity-check.invalid", handler, SocketError.HostNotFound);
                case "host unreachable":
                    return Raising("http://192.0.2.1", handler, SocketError.HostUnreachable);
                case "network unreachable":
                    return Raising("http://192.0.2.1", handler, SocketError.NetworkUnreachable);
                default:
                    return new Upstream($"http://127.0.0.1:{ClosedPort()}", handler);
            }
        }

        private static Upstream Raising(string target, SocketsHttpHandler handler, SocketError error)
        {
            handler.ConnectCallback = (_, _) => throw new SocketException((int)error);
            return new Upstream(target, handler);
        }

        private static Upstream Serving(string scheme, SocketsHttpHandler handler,
            Func<NetworkStream, CancellationToken, Task> serve, bool resetOnClose = false)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var upstream = new Upstream($"{scheme}://127.0.0.1:{((IPEndPoint)listener.LocalEndpoint).Port}",
                handler, listener);
            upstream.Accept(async (client, token) =>
            {
                await using var stream = client.GetStream();
                await serve(stream, token);
                if (resetOnClose)
                {
                    client.Client.LingerState = new LingerOption(true, 0);
                }
            });
            return upstream;
        }

        private static Upstream ServingTls(SocketsHttpHandler handler)
        {
            var certificate = SelfSignedForLocalhost();
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var upstream = new Upstream($"https://localhost:{((IPEndPoint)listener.LocalEndpoint).Port}",
                handler, listener, certificate);
            upstream.Accept(async (client, token) =>
            {
                await using var ssl = new SslStream(client.GetStream());
                await ssl.AuthenticateAsServerAsync(certificate);
            });
            return upstream;
        }

        private void Accept(Func<TcpClient, CancellationToken, Task> serve)
        {
            var listener = _listener!;
            var token = _stop.Token;
            _ = Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    TcpClient client;
                    try
                    {
                        client = await listener.AcceptTcpClientAsync(token);
                    }
                    catch
                    {
                        return;
                    }
                    _ = Task.Run(async () =>
                    {
                        using (client)
                        {
                            try
                            {
                                await serve(client, token);
                            }
                            catch
                            {
                                // The client gives up on these targets; that is the point.
                            }
                        }
                    });
                }
            });
        }

        private static async Task Silent() => await Task.Delay(TimeSpan.FromSeconds(30));

        private static async Task ReadRequestHeadAsync(NetworkStream stream, CancellationToken token)
        {
            var received = new StringBuilder();
            var buffer = new byte[4096];
            while (!received.ToString().Contains("\r\n\r\n", StringComparison.Ordinal))
            {
                var read = await stream.ReadAsync(buffer, token);
                if (read == 0)
                {
                    return;
                }
                received.Append(Encoding.ASCII.GetString(buffer, 0, read));
            }
        }

        private static int ClosedPort()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private static X509Certificate2 SelfSignedForLocalhost()
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=localhost", key,
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("localhost");
            request.CertificateExtensions.Add(names.Build());
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1),
                DateTimeOffset.UtcNow.AddHours(1));
            // The server needs the private key attached, which round-tripping through PFX guarantees.
            return X509CertificateLoader.LoadPkcs12(certificate.Export(X509ContentType.Pfx), null);
        }

        public ValueTask DisposeAsync()
        {
            _stop.Cancel();
            _listener?.Stop();
            _certificate?.Dispose();
            _stop.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
