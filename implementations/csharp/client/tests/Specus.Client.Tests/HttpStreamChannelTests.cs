using Microsoft.Extensions.Logging.Abstractions;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Specus.Client.Configuration;
using Specus.Client.Control;
using Specus.Client.DirectHttp;
using Specus.Client.Nat;
using Specus.Protocol;
using Specus.Protocol.Packets;

namespace Specus.Client.Tests;

public sealed class HttpStreamChannelTests
{
    [Fact]
    public async Task DuplicateFinAndLateDataAreRejectedAfterRequestEnds()
    {
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        using var http = new HttpClient();
        var routes = new DirectHttpHandler(
            new[]
            {
                new HttpSpecusConfigEntry
                {
                    Route = "web",
                    TargetBaseUrl = "http://127.0.0.1:8080",
                },
            },
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);
        await using var channel = new HttpStreamChannel(
            7,
            new Dictionary<string, object?>
            {
                ["method"] = "GET",
                ["route"] = "web",
            },
            routes,
            "http://127.0.0.1:8080",
            writer,
            NullLogger.Instance,
            CancellationToken.None,
            _ => { });

        await channel.FinishRequestAsync(null, CancellationToken.None);
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await channel.FinishRequestAsync(null, CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await channel.OfferRequestDataAsync([1, 2, 3], CancellationToken.None));
    }

    [Fact]
    public async Task UnknownRouteIsRejectedAsAStreamErrorWithoutBreakingLaterFrames()
    {
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        using var http = new HttpClient();
        var routes = new DirectHttpHandler(
            Array.Empty<HttpSpecusConfigEntry>(),
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            Array.Empty<SpecusConfigEntry>(),
            "test-client",
            writer,
            routes,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(CancellationToken.None);

        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = 9,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "request",
                ["method"] = "GET",
                ["route"] = "missing",
            },
        });
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 9,
            Data = [1],
        });
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = 9,
        });

        Assert.True(transport.Length > 0);
    }

    [Fact]
    public async Task DataEndStreamDeliversBodyBeforeFinishingRequest()
    {
        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        using var capture = new CapturingBodyHandler();
        using var http = new HttpClient(capture);
        var routes = new DirectHttpHandler(
            new[]
            {
                new HttpSpecusConfigEntry
                {
                    Route = "web",
                    TargetBaseUrl = "http://local.test",
                },
            },
            writer,
            new DirectHttpForwarder(http),
            NullLogger<DirectHttpHandler>.Instance);
        await using var nat = new NatClientHandler(
            Array.Empty<SpecusConfigEntry>(),
            "test-client",
            writer,
            routes,
            NullLogger<NatClientHandler>.Instance);
        nat.Bind(CancellationToken.None);
        var payload = "final-request-chunk"u8.ToArray();

        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = 10,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "request",
                ["method"] = "POST",
                ["route"] = "web",
                ["contentLength"] = (long)payload.Length,
            },
        });
        await nat.HandleAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Data,
            StreamId = 10,
            Data = payload,
            Flags = NatMessagePacket.FlagEndStream,
        });

        Assert.Equal(payload, await capture.Body.WaitAsync(TimeSpan.FromSeconds(5)));
    }

    [Fact]
    public async Task DeclaredRequestTrailersAreSentAfterTheChunkedBody()
    {
        var requestBody = Enumerable.Repeat((byte)'a', 192 * 1024).ToArray();
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var endpoint = (IPEndPoint)listener.LocalEndpoint;
        var capturedRequest = Task.Run(async () =>
        {
            using var socket = await listener.AcceptTcpClientAsync();
            await using var network = socket.GetStream();
            using var received = new MemoryStream();
            var buffer = new byte[1024];
            while (received.Length < requestBody.Length + 128 * 1024)
            {
                var read = await network.ReadAsync(buffer);
                Assert.True(read > 0, "upstream closed before the request trailer arrived");
                received.Write(buffer, 0, read);
                var text = Encoding.ASCII.GetString(received.GetBuffer(), 0, checked((int)received.Length));
                if (text.Contains("0\r\nX-Checksum: ok\r\n\r\n", StringComparison.OrdinalIgnoreCase))
                {
                    await network.WriteAsync(
                        "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"u8.ToArray());
                    return text;
                }
            }
            throw new InvalidDataException("upstream request exceeded capture limit");
        });

        await using var transport = new MemoryStream();
        await using var writer = new FrameWriter(transport);
        using var ordinaryHttp = new HttpClient();
        var routes = new DirectHttpHandler(
            new[]
            {
                new HttpSpecusConfigEntry
                {
                    Route = "web",
                    TargetBaseUrl = $"http://127.0.0.1:{endpoint.Port}",
                },
            },
            writer,
            new DirectHttpForwarder(ordinaryHttp),
            NullLogger<DirectHttpHandler>.Instance);
        await using var channel = new HttpStreamChannel(
            11,
            new Dictionary<string, object?>
            {
                ["method"] = "POST",
                ["route"] = "web",
                ["contentLength"] = (long)requestBody.Length,
                ["trailerNames"] = new[] { "X-Checksum" },
            },
            routes,
            $"http://127.0.0.1:{endpoint.Port}",
            writer,
            NullLogger.Instance,
            CancellationToken.None,
            _ => { });

        var run = channel.RunAsync();
        await channel.OfferRequestDataAsync(requestBody, CancellationToken.None);
        await channel.FinishRequestAsync(new Dictionary<string, object?>
        {
            ["trailers"] = new[] { "X-Checksum:ok", "Undeclared:ignored" },
        }, CancellationToken.None);

        var requestText = await capturedRequest.WaitAsync(TimeSpan.FromSeconds(10));
        await run.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Contains("Transfer-Encoding: chunked", requestText, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Trailer: X-Checksum", requestText, StringComparison.OrdinalIgnoreCase);
        Assert.True(requestText.Length > requestBody.Length);
        Assert.Contains("0\r\nX-Checksum: ok\r\n\r\n", requestText, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Undeclared", requestText, StringComparison.OrdinalIgnoreCase);
    }

    private sealed class CapturingBodyHandler : HttpMessageHandler
    {
        private readonly TaskCompletionSource<byte[]> _body =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public Task<byte[]> Body => _body.Task;

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null
                ? Array.Empty<byte>()
                : await request.Content.ReadAsByteArrayAsync(cancellationToken);
            _body.TrySetResult(body);
            return new HttpResponseMessage(HttpStatusCode.NoContent)
            {
                Content = new ByteArrayContent(Array.Empty<byte>()),
            };
        }
    }
}
