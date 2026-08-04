using System.Collections.Concurrent;
using System.Net;
using System.Net.WebSockets;
using System.Text;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Specus.Protocol;
using Specus.Protocol.Packets;
using Specus.Server.Authentication;
using Specus.Server.ControlChannel;
using Specus.Server.Data;
using Specus.Server.Data.Entities;
using Specus.Server.Hosting;
using Specus.Server.Http;
using Specus.Server.Nat;
using Specus.Server.Networking;
using Specus.Server.Sessions;

namespace Specus.IntegrationTests;

public sealed class DirectHttpWebSocketTests : IAsyncLifetime
{
    private const string Route = "secure-ws";
    private const string Username = "ws-user";
    private const string Password = "ws-password";
    private static readonly string ClientName = DatabaseInitializer.DemoClientName;

    private TestServerFixture? _server;

    public async Task InitializeAsync()
    {
        _server = await TestServerFixture.StartAsync();
        await SeedProtectedRouteAsync();
    }

    public async Task DisposeAsync()
    {
        if (_server is not null)
        {
            await _server.DisposeAsync();
        }
    }

    [Fact]
    public async Task MissingBasicIsRejectedBeforeUpgradeAndNatOpen()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var webSockets = _server!.Server.CreateWebSocketClient();

        var exception = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            webSockets.ConnectAsync(WebSocketUri(), cancellation.Token));

        Assert.Contains("status code: 401", exception.Message, StringComparison.Ordinal);
        Assert.Equal(0, session.Writer.OpenCount);

        using var http = _server.CreateClient();
        using var response = await http.GetAsync(HttpPath(), cancellation.Token);
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var challenge = Assert.Single(response.Headers.WwwAuthenticate);
        Assert.Equal("Basic", challenge.Scheme);
        Assert.Contains("Specus HTTP Route", challenge.Parameter, StringComparison.Ordinal);
        Assert.Equal(0, session.Writer.OpenCount);
    }

    [Fact]
    public async Task HttpResponseOnlyPublishesSafeDeclaredPeerTrailers()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var http = _server!.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, HttpPath("trailers"));
        request.Headers.Authorization = System.Net.Http.Headers.AuthenticationHeaderValue.Parse(
            BasicAuthorization());

        var responseTask = http.SendAsync(request, cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open
                      && Equals(packet.MetaData?["source"], "http"), cancellation.Token);
        await session.Writer.InjectAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Open,
            StreamId = opened.StreamId,
            MetaData = new Dictionary<string, object?>
            {
                ["source"] = "http",
                ["phase"] = "response",
                ["statusCode"] = 200,
                ["trailerNames"] = new[]
                {
                    "Digest", "Content-Length", "X-Injected", "digest",
                },
            },
        });
        await session.Writer.InjectAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = opened.StreamId,
            MetaData = new Dictionary<string, object?>
            {
                ["trailers"] = new[]
                {
                    "Digest:sha-256=valid",
                    "X-Undeclared:must-not-cross",
                    "Content-Length:999",
                    "X-Injected:ok\r\nX-Evil: yes",
                },
            },
        });

        using var response = await responseTask;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("sha-256=valid", Assert.Single(response.TrailingHeaders.GetValues("Digest")));
        foreach (var name in new[] { "X-Undeclared", "Content-Length", "X-Injected", "X-Evil" })
        {
            Assert.False(response.TrailingHeaders.Contains(name));
        }
    }

    [Fact]
    public async Task ProtectedUpgradeOpensWsMetadataAndFiltersHandshakeCredentials()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var webSockets = AuthorizedWebSocketClient();
        webSockets.ConfigureRequest = request =>
        {
            request.Headers["Authorization"] = BasicAuthorization();
            request.Headers["X-Upstream-Test"] = "kept";
        };
        using var socket = await webSockets.ConnectAsync(WebSocketUri("chat/socket??x=%2F"),
            cancellation.Token);

        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);

        Assert.Equal("ws", opened.MetaData!["source"]);
        Assert.Equal(ClientName, opened.MetaData["clientName"]);
        Assert.Equal(Route, opened.MetaData["route"]);
        Assert.Equal("/chat/socket", opened.MetaData["relativePath"]);
        Assert.Equal("?x=%2F", opened.MetaData["rawQuery"]);
        Assert.False(string.IsNullOrWhiteSpace(opened.MetaData["channelId"]?.ToString()));
        Assert.Empty(Assert.IsType<byte[]>(opened.MetaData["body"]));

        var headers = Assert.IsAssignableFrom<IEnumerable<string>>(opened.MetaData["headers"]);
        Assert.Contains(headers,
            value => value.Equals("X-Upstream-Test:kept", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(headers, value => HeaderName(value).Equals(
            "Authorization", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(headers, value => HeaderName(value).Equals(
            "Connection", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(headers, value => HeaderName(value).Equals(
            "Upgrade", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(headers, value => HeaderName(value).StartsWith(
            "Sec-WebSocket-", StringComparison.OrdinalIgnoreCase));

        socket.Abort();
    }

    [Fact]
    public async Task BrowserTextAndBinaryBecomeSws2NatData()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);

        var text = Encoding.UTF8.GetBytes("你好 websocket");
        await socket.SendAsync(new ArraySegment<byte>(text), WebSocketMessageType.Text, true,
            cancellation.Token);
        var textPacket = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Data
                      && packet.StreamId == opened.StreamId, cancellation.Token);
        var textFrame = WebSocketSpecusFrame.Decode(textPacket.Data!);
        Assert.Equal(WebSocketSpecusFrame.OpcodeText, textFrame.Opcode);
        Assert.True(textFrame.FinalFragment);
        Assert.Equal(text, textFrame.Payload);

        byte[] binary = [0, 1, 2, 0xff, 0x7f];
        await socket.SendAsync(new ArraySegment<byte>(binary), WebSocketMessageType.Binary, true,
            cancellation.Token);
        var binaryPacket = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Data
                      && packet.StreamId == opened.StreamId, cancellation.Token);
        var binaryFrame = WebSocketSpecusFrame.Decode(binaryPacket.Data!);
        Assert.Equal(WebSocketSpecusFrame.OpcodeBinary, binaryFrame.Opcode);
        Assert.True(binaryFrame.FinalFragment);
        Assert.Equal(binary, binaryFrame.Payload);

        socket.Abort();
    }

    [Fact]
    public async Task BrowserPingIsAnsweredLocallyAndOnlyBrowserPongBecomesSws2Data()
    {
        await using var session = BoundNatSession.Bind(_server!);
        const uint streamId = 7001;
        var pingPayload = "route-ping"u8.ToArray();
        var pongPayload = "route-pong"u8.ToArray();
        var transport = new ScriptedDuplexStream([
            .. BuildMaskedClientControlFrame(WebSocketSpecusFrame.OpcodePing, pingPayload),
            .. BuildMaskedClientControlFrame(WebSocketSpecusFrame.OpcodePong, pongPayload),
        ]);
        await using var socket = RawServerWebSocketConnection.CreateForTesting(transport);
        await using var stream = new WebSocketSpecusStream(session.Context, streamId, (_, _) => { });

        await DirectHttpEndpoints.PumpBrowserWebSocketAsync(socket, stream,
            new DirectHttpEndpoints.WebSocketTunnelCloseState(), CancellationToken.None);

        var packet = Assert.Single(session.Writer.Snapshot(), item =>
            item.NatMessageType == NatMessageType.Data && item.StreamId == streamId);
        var tunnelFrame = WebSocketSpecusFrame.Decode(packet.Data!);
        Assert.Equal(WebSocketSpecusFrame.OpcodePong, tunnelFrame.Opcode);
        Assert.Equal(pongPayload, tunnelFrame.Payload);
        byte[] expectedPong =
        [
            (byte)0x8A,
            (byte)pingPayload.Length,
            .. pingPayload,
        ];
        Assert.Equal(expectedPong, transport.WrittenBytes);
    }

    [Fact]
    public async Task NatTextAndFragmentedBinaryReachBrowserAndReturnWindowCredit()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);

        var text = new WebSocketSpecusFrame(WebSocketSpecusFrame.OpcodeText, true, 0, 0,
            Encoding.UTF8.GetBytes("来自客户端"));
        var encodedText = text.Encode();
        await session.Writer.InjectAsync(Data(opened.StreamId, encodedText));
        var receivedText = await ReceiveAsync(socket, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Text, receivedText.Result.MessageType);
        Assert.True(receivedText.Result.EndOfMessage);
        Assert.Equal(text.Payload, receivedText.Payload);
        await AssertWindowCreditAsync(session.Writer, opened.StreamId, encodedText.Length,
            cancellation.Token);

        var first = new WebSocketSpecusFrame(WebSocketSpecusFrame.OpcodeBinary, false, 0, 0,
            [1, 2, 3]);
        var encodedFirst = first.Encode();
        await session.Writer.InjectAsync(Data(opened.StreamId, encodedFirst));
        var receivedFirst = await ReceiveAsync(socket, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Binary, receivedFirst.Result.MessageType);
        Assert.False(receivedFirst.Result.EndOfMessage);
        Assert.Equal(first.Payload, receivedFirst.Payload);
        await AssertWindowCreditAsync(session.Writer, opened.StreamId, encodedFirst.Length,
            cancellation.Token);

        var last = new WebSocketSpecusFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0, 0,
            [4, 5, 6]);
        var encodedLast = last.Encode();
        await session.Writer.InjectAsync(Data(opened.StreamId, encodedLast));
        var receivedLast = await ReceiveAsync(socket, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Binary, receivedLast.Result.MessageType);
        Assert.True(receivedLast.Result.EndOfMessage);
        Assert.Equal(last.Payload, receivedLast.Payload);
        await AssertWindowCreditAsync(session.Writer, opened.StreamId, encodedLast.Length,
            cancellation.Token);

        socket.Abort();
    }

    [Fact]
    public async Task BrowserCloseSendsExactlyOneCloseDataAndFin()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);

        await socket.CloseAsync(WebSocketCloseStatus.NormalClosure, "browser done",
            cancellation.Token);
        var closePacket = await session.Writer.ReadAsync(
            packet => IsCloseData(packet, opened.StreamId), cancellation.Token);
        var closeFrame = WebSocketSpecusFrame.Decode(closePacket.Data!);
        Assert.Equal((ushort)WebSocketCloseStatus.NormalClosure, closeFrame.CloseCode);
        Assert.Equal("browser done", Encoding.UTF8.GetString(closeFrame.Payload));
        await session.Writer.ReadAsync(packet => packet.NatMessageType == NatMessageType.Fin
                                                 && packet.StreamId == opened.StreamId,
            cancellation.Token);

        await Task.Delay(100, cancellation.Token);
        Assert.Single(session.Writer.Snapshot(), packet => IsCloseData(packet, opened.StreamId));
        Assert.Single(session.Writer.Snapshot(), packet =>
            packet.NatMessageType == NatMessageType.Fin && packet.StreamId == opened.StreamId);
    }

    [Fact]
    public async Task ClientCloseAndFinReachBrowserAndReturnCloseAndFin()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);

        var close = new WebSocketSpecusFrame(WebSocketSpecusFrame.OpcodeClose, true, 0,
            (ushort)WebSocketCloseStatus.EndpointUnavailable, Encoding.UTF8.GetBytes("upstream gone"));
        var encodedClose = close.Encode();
        await session.Writer.InjectAsync(Data(opened.StreamId, encodedClose));
        await session.Writer.InjectAsync(new NatMessagePacket
        {
            NatMessageType = NatMessageType.Fin,
            StreamId = opened.StreamId,
        });

        var received = await ReceiveAsync(socket, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Close, received.Result.MessageType);
        Assert.Equal(WebSocketCloseStatus.EndpointUnavailable, received.Result.CloseStatus);
        Assert.Equal("upstream gone", received.Result.CloseStatusDescription);
        await socket.CloseOutputAsync(WebSocketCloseStatus.EndpointUnavailable, "upstream gone",
            cancellation.Token);
        await AssertWindowCreditAsync(session.Writer, opened.StreamId, encodedClose.Length,
            cancellation.Token);

        var returnedClose = await session.Writer.ReadAsync(
            packet => IsCloseData(packet, opened.StreamId), cancellation.Token);
        var returnedFrame = WebSocketSpecusFrame.Decode(returnedClose.Data!);
        Assert.Equal((ushort)WebSocketCloseStatus.EndpointUnavailable, returnedFrame.CloseCode);
        Assert.Equal("upstream gone", Encoding.UTF8.GetString(returnedFrame.Payload));
        await session.Writer.ReadAsync(packet => packet.NatMessageType == NatMessageType.Fin
                                                 && packet.StreamId == opened.StreamId,
            cancellation.Token);

        await Task.Delay(100, cancellation.Token);
        Assert.Single(session.Writer.Snapshot(), packet => IsCloseData(packet, opened.StreamId));
        Assert.Single(session.Writer.Snapshot(), packet =>
            packet.NatMessageType == NatMessageType.Fin && packet.StreamId == opened.StreamId);
    }

    [Theory]
    [InlineData(NatMessageType.Fin)]
    [InlineData(NatMessageType.Rst)]
    public async Task ClientTerminalOnlyClosesBrowserWithoutReplyAndLateFramesKeepNatContext(
        NatMessageType terminalType)
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);
        var terminal = new NatMessagePacket
        {
            NatMessageType = terminalType,
            StreamId = opened.StreamId,
            MetaData = terminalType == NatMessageType.Rst
                ? new Dictionary<string, object?> { ["reason"] = "upstream reset" }
                : null,
        };

        await session.Writer.InjectAsync(terminal);

        var received = await ReceiveAsync(socket, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Close, received.Result.MessageType);

        await session.Writer.InjectAsync(terminal);
        var lateFrame = new WebSocketSpecusFrame(WebSocketSpecusFrame.OpcodeText, true, 0, 0,
            Encoding.UTF8.GetBytes("late data"));
        await session.Writer.InjectAsync(Data(opened.StreamId, lateFrame.Encode()));
        await Task.Delay(100, cancellation.Token);

        Assert.False(session.Context.Lifetime.IsCancellationRequested);
        Assert.DoesNotContain(session.Writer.Snapshot(), packet =>
            IsCloseData(packet, opened.StreamId));
        Assert.DoesNotContain(session.Writer.Snapshot(), packet =>
            packet.NatMessageType == NatMessageType.Fin && packet.StreamId == opened.StreamId);
    }

    [Fact]
    public async Task FullWebSocketQueueResetsOnlyThatStreamAndKeepsNatContext()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);
        var frame = new WebSocketSpecusFrame(WebSocketSpecusFrame.OpcodeText, true, 0, 0,
            [(byte)'x']).Encode();

        session.Writer.BlockPriorityWrites();
        try
        {
            await session.Writer.InjectAsync(Data(opened.StreamId, frame));
            await AssertWindowCreditAsync(session.Writer, opened.StreamId, frame.Length,
                cancellation.Token);

            for (var i = 0; i < 33; i++)
            {
                await session.Writer.InjectAsync(Data(opened.StreamId, frame));
            }

            var reset = await session.Writer.ReadAsync(packet =>
                    packet.NatMessageType == NatMessageType.Rst
                    && packet.StreamId == opened.StreamId,
                cancellation.Token);
            Assert.Equal(31U, reset.Value);
            Assert.Equal("WebSocket browser is too slow", reset.MetaData!["reason"]);
            Assert.False(session.Context.Lifetime.IsCancellationRequested);
            Assert.DoesNotContain(session.Writer.Snapshot(), packet =>
                packet.NatMessageType == NatMessageType.Rst
                && packet.StreamId != opened.StreamId);
        }
        finally
        {
            session.Writer.ReleasePriorityWrites();
        }

        using var nextSocket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri("next"),
            cancellation.Token);
        var nextOpened = await session.Writer.ReadAsync(packet =>
                packet.NatMessageType == NatMessageType.Open
                && packet.StreamId != opened.StreamId,
            cancellation.Token);
        Assert.NotEqual(opened.StreamId, nextOpened.StreamId);
        Assert.False(session.Context.Lifetime.IsCancellationRequested);
        nextSocket.Abort();
    }

    [Fact]
    public async Task MalformedSws2ResetsNatStreamAndClosesBrowserWithProtocolError()
    {
        await using var session = BoundNatSession.Bind(_server!);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socket = await AuthorizedWebSocketClient().ConnectAsync(WebSocketUri(),
            cancellation.Token);
        var opened = await session.Writer.ReadAsync(
            packet => packet.NatMessageType == NatMessageType.Open, cancellation.Token);

        await session.Writer.InjectAsync(Data(opened.StreamId, [0x01, 0x02, 0x03]));

        var reset = await session.Writer.ReadAsync(packet =>
            packet.NatMessageType == NatMessageType.Rst && packet.StreamId == opened.StreamId,
            cancellation.Token);
        Assert.Equal(30U, reset.Value);
        Assert.Equal("invalid WebSocket SWS2 frame", reset.MetaData!["reason"]);

        var received = await ReceiveAsync(socket, cancellation.Token);
        Assert.Equal(WebSocketMessageType.Close, received.Result.MessageType);
        Assert.Equal(WebSocketCloseStatus.ProtocolError, received.Result.CloseStatus);
        Assert.Equal("invalid WebSocket frame", received.Result.CloseStatusDescription);
    }

    private async Task SeedProtectedRouteAsync()
    {
        await using var scope = _server!.HostServices.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SpecusDbContext>();
        var account = await db.ClientAccounts.SingleAsync(client => client.ClientName == ClientName);
        var now = DateTimeOffset.UtcNow;
        db.HttpRouteMappings.Add(new HttpRouteMapping
        {
            Id = ClientIdGenerator.NewId(),
            ClientId = account.Id,
            ClientName = account.ClientName,
            Route = Route,
            TargetBaseUrl = "ws://127.0.0.1:65535",
            Enabled = true,
            AuthEnabled = true,
            AuthUsername = Username,
            AuthPasswordHash = PasswordHasher.Hash(Password),
            CreatedAt = now,
            UpdatedAt = now,
        });
        await db.SaveChangesAsync();
    }

    private Microsoft.AspNetCore.TestHost.WebSocketClient AuthorizedWebSocketClient()
    {
        var client = _server!.Server.CreateWebSocketClient();
        client.ConfigureRequest = request => request.Headers["Authorization"] = BasicAuthorization();
        return client;
    }

    private static Uri WebSocketUri(string rest = "socket") => new(
        $"ws://localhost/http/{Uri.EscapeDataString(ClientName)}/{Route}/{rest}");

    private static string HttpPath(string rest = "socket") =>
        $"/http/{Uri.EscapeDataString(ClientName)}/{Route}/{rest}";

    private static string BasicAuthorization() => "Basic " + Convert.ToBase64String(
        Encoding.UTF8.GetBytes($"{Username}:{Password}"));

    private static string HeaderName(string header)
    {
        var separator = header.IndexOf(':', StringComparison.Ordinal);
        return separator < 0 ? header : header[..separator];
    }

    private static NatMessagePacket Data(uint streamId, byte[] data) => new()
    {
        NatMessageType = NatMessageType.Data,
        StreamId = streamId,
        Data = data,
    };

    private static byte[] BuildMaskedClientControlFrame(byte opcode, byte[] payload)
    {
        Assert.InRange(payload.Length, 0, 125);
        ReadOnlySpan<byte> mask = [0x12, 0x34, 0x56, 0x78];
        var wire = new byte[6 + payload.Length];
        wire[0] = (byte)(0x80 | opcode);
        wire[1] = (byte)(0x80 | payload.Length);
        mask.CopyTo(wire.AsSpan(2, 4));
        for (var index = 0; index < payload.Length; index++)
        {
            wire[6 + index] = (byte)(payload[index] ^ mask[index & 3]);
        }
        return wire;
    }

    private static bool IsCloseData(NatMessagePacket packet, uint streamId)
    {
        if (packet.NatMessageType != NatMessageType.Data || packet.StreamId != streamId
            || packet.Data is null)
        {
            return false;
        }
        try
        {
            return WebSocketSpecusFrame.Decode(packet.Data).Opcode == WebSocketSpecusFrame.OpcodeClose;
        }
        catch (InvalidDataException)
        {
            return false;
        }
    }

    private static async Task AssertWindowCreditAsync(CapturingNatFrameWriter writer, uint streamId,
        int expectedCredit, CancellationToken cancellationToken)
    {
        var update = await writer.ReadAsync(packet =>
                packet.NatMessageType == NatMessageType.WindowUpdate && packet.StreamId == streamId,
            cancellationToken);
        Assert.Equal((uint)expectedCredit, update.Value);
    }

    private static async Task<ReceivedFrame> ReceiveAsync(WebSocket socket,
        CancellationToken cancellationToken)
    {
        var buffer = new byte[WebSocketSpecusFrame.MaxPayloadBytes];
        var result = await socket.ReceiveAsync(new ArraySegment<byte>(buffer), cancellationToken);
        return new ReceivedFrame(result, buffer.AsSpan(0, result.Count).ToArray());
    }

    private sealed record ReceivedFrame(WebSocketReceiveResult Result, byte[] Payload);

    private sealed class ScriptedDuplexStream(byte[] input) : Stream
    {
        private readonly MemoryStream _input = new(input, writable: false);
        private readonly MemoryStream _output = new();

        public byte[] WrittenBytes => _output.ToArray();

        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _input.ReadAsync(buffer, cancellationToken);

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default) =>
            _output.WriteAsync(buffer, cancellationToken);

        public override void Flush() => _output.Flush();
        public override Task FlushAsync(CancellationToken cancellationToken) =>
            _output.FlushAsync(cancellationToken);
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count) =>
            _input.Read(buffer, offset, count);
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            _output.Write(buffer, offset, count);

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _input.Dispose();
                _output.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    private sealed class BoundNatSession : IAsyncDisposable
    {
        private readonly NatServerHandler _nat;
        private readonly SessionRegistry _registry;
        private readonly CancellationTokenSource _lifetime;

        private BoundNatSession(NatServerHandler nat, SessionRegistry registry,
            CancellationTokenSource lifetime, CapturingNatFrameWriter writer,
            SpecusConnectionContext context)
        {
            _nat = nat;
            _registry = registry;
            _lifetime = lifetime;
            Writer = writer;
            Context = context;
        }

        public CapturingNatFrameWriter Writer { get; }

        public SpecusConnectionContext Context { get; }

        public static BoundNatSession Bind(TestServerFixture server)
        {
            var nat = server.HostServices.GetRequiredService<NatServerHandler>();
            var registry = server.HostServices.GetRequiredService<SessionRegistry>();
            var lifetime = new CancellationTokenSource();
            var writer = new CapturingNatFrameWriter(nat);
            var context = new SpecusConnectionContext(
                "direct-http-websocket-test",
                "127.0.0.1:12345",
                writer,
                lifetime.Token,
                lifetime.Cancel,
                new ReadGate(lifetime.Token),
                new WriteBackpressureGate(64 * 1024, 1024 * 1024));
            context.OnLoginSuccess(ClientName, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                clientSessionId: 1, connectionRole: ConnectionRole.Data);
            writer.Context = context;
            registry.ReplaceData(ClientName, context);
            nat.Attach(context);
            return new BoundNatSession(nat, registry, lifetime, writer, context);
        }

        public async ValueTask DisposeAsync()
        {
            Writer.ReleasePriorityWrites();
            _registry.Unbind(ClientName, Context);
            _lifetime.Cancel();
            await _nat.OnConnectionClosedAsync(Context);
            _lifetime.Dispose();
        }
    }

    private sealed class CapturingNatFrameWriter : IFrameWriter
    {
        private readonly NatServerHandler _nat;
        private readonly Channel<NatMessagePacket> _packets =
            Channel.CreateUnbounded<NatMessagePacket>(new UnboundedChannelOptions
            {
                SingleReader = false,
                SingleWriter = false,
            });
        private readonly ConcurrentQueue<NatMessagePacket> _snapshot = new();
        private TaskCompletionSource<bool>? _priorityWriteGate;
        private int _openCount;

        public CapturingNatFrameWriter(NatServerHandler nat)
        {
            _nat = nat;
        }

        public SpecusConnectionContext Context { get; set; } = null!;

        public int OpenCount => Volatile.Read(ref _openCount);

        public ValueTask WriteAsync(Packet packet, CancellationToken cancellationToken = default)
        {
            if (packet is not NatMessagePacket natPacket)
            {
                return ValueTask.CompletedTask;
            }
            var captured = Clone(natPacket);
            if (captured.NatMessageType == NatMessageType.Open)
            {
                Interlocked.Increment(ref _openCount);
            }
            _snapshot.Enqueue(captured);
            if (!_packets.Writer.TryWrite(captured))
            {
                return ValueTask.FromException(new IOException("failed to capture NAT packet"));
            }
            return ValueTask.CompletedTask;
        }

        public async ValueTask WritePriorityAsync(Packet packet,
            CancellationToken cancellationToken = default)
        {
            await WriteAsync(packet, cancellationToken).ConfigureAwait(false);
            var gate = Volatile.Read(ref _priorityWriteGate);
            if (gate is not null)
            {
                await gate.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
        }

        public void BlockPriorityWrites()
        {
            var gate = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
            if (Interlocked.CompareExchange(ref _priorityWriteGate, gate, null) is not null)
            {
                throw new InvalidOperationException("priority writes are already blocked");
            }
        }

        public void ReleasePriorityWrites() =>
            Interlocked.Exchange(ref _priorityWriteGate, null)?.TrySetResult(true);

        public Task InjectAsync(NatMessagePacket packet) => _nat.HandleAsync(Context, packet);

        public async Task<NatMessagePacket> ReadAsync(Func<NatMessagePacket, bool> predicate,
            CancellationToken cancellationToken)
        {
            await foreach (var packet in _packets.Reader.ReadAllAsync(cancellationToken))
            {
                if (predicate(packet))
                {
                    return packet;
                }
            }
            throw new EndOfStreamException("NAT packet capture completed");
        }

        public IReadOnlyList<NatMessagePacket> Snapshot() => _snapshot.ToArray();

        private static NatMessagePacket Clone(NatMessagePacket packet) => new()
        {
            NatMessageType = packet.NatMessageType,
            Flags = packet.Flags,
            StreamId = packet.StreamId,
            Value = packet.Value,
            MetaData = packet.MetaData is null
                ? null
                : new Dictionary<string, object?>(packet.MetaData),
            Data = packet.Data?.ToArray(),
        };
    }
}
