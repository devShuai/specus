using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Specus.Protocol;
using Specus.Protocol.Codec;
using Specus.Protocol.Packets;
using Specus.Server.Configuration;
using Specus.Server.ControlChannel;
using Specus.Server.Data.Entities;

namespace Specus.IntegrationTests;

/// <summary>
/// "帧写入失败" in protocol/spec/control-protocol.md: a frame whose write fails or is cut short
/// leaves part of it on the wire, and the client would read anything written after it out of step.
/// Such a connection is closed and written no more, and a caller that gives up on its write cannot
/// cut a frame short: only the connection's lifetime can.
/// </summary>
public sealed class ControlWriteFailureTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);
    /// <summary>How long a frame that must not be written is given to show up anyway.</summary>
    private static readonly TimeSpan Quiet = TimeSpan.FromMilliseconds(300);

    [Fact]
    public async Task AWriteCutShortClosesTheConnectionAndNothingFollowsIt()
    {
        var stream = new CutShortStream(failFirstWrite: true);
        await using var pair = await ConnectionPair.OpenAsync(stream);
        var connection = pair.Connection;

        await Assert.ThrowsAsync<IOException>(() => connection.WriteAsync(Message("first")).AsTask());
        var cut = stream.Wire().Length;
        Assert.True(cut > 0, "the failed write put nothing on the wire; the test cuts no frame short");
        Assert.True(connection.Context.Lifetime.IsCancellationRequested,
            "the connection stayed open after a frame was cut short");
        Assert.Equal(DisconnectReason.IoError, connection.Context.ReadDisconnectReason());

        var direct = await Record.ExceptionAsync(() => connection.WriteAsync(Message("second")).AsTask().WaitAsync(Timeout));
        Assert.NotNull(direct);
        Assert.IsNotType<TimeoutException>(direct);
        var queued = await Record.ExceptionAsync(() => connection.WriteAsync(Data(1, 1024)).AsTask().WaitAsync(Timeout));
        Assert.NotNull(queued);
        Assert.IsNotType<TimeoutException>(queued);
        try
        {
            await connection.WritePriorityAsync(new NatMessagePacket
            {
                NatMessageType = NatMessageType.WindowUpdate,
                StreamId = 1,
                Value = 1024,
            }).AsTask().WaitAsync(Timeout);
        }
        catch (Exception error) when (error is not TimeoutException)
        {
        }
        await Task.Delay(Quiet);
        Assert.Equal(cut, stream.Wire().Length);
    }

    [Fact]
    public async Task ACallerGivingUpDoesNotCutItsFrameShort()
    {
        var stream = new CutShortStream(failFirstWrite: false);
        await using var pair = await ConnectionPair.OpenAsync(stream);
        var connection = pair.Connection;
        var first = Message("first");
        var second = Message("second");
        using var caller = new CancellationTokenSource();

        var firstWrite = connection.WriteAsync(first, caller.Token).AsTask();
        await stream.HalfWritten.WaitAsync(Timeout);
        var secondWrite = connection.WriteAsync(second).AsTask();
        caller.Cancel();
        await Task.Delay(Quiet);
        Assert.Equal(PacketCodec.Encode(first).Length / 2, stream.Wire().Length);

        stream.Release();
        await firstWrite.WaitAsync(Timeout);
        await secondWrite.WaitAsync(Timeout);
        Assert.Equal(PacketCodec.Encode(first).Concat(PacketCodec.Encode(second)).ToArray(), stream.Wire());
        Assert.False(connection.Context.Lifetime.IsCancellationRequested);
    }

    /// <summary>
    /// The same for a NAT DATA frame, which goes through the per-stream queue: a Direct HTTP request
    /// aborted while its body is being forwarded stops waiting at once, and the frame still goes out
    /// whole before the next one.
    /// </summary>
    [Fact]
    public async Task AStreamFrameWhoseCallerGaveUpIsStillWrittenWhole()
    {
        var stream = new CutShortStream(failFirstWrite: false);
        await using var pair = await ConnectionPair.OpenAsync(stream);
        var connection = pair.Connection;
        var first = Data(1, 4096);
        var second = Data(2, 4096);
        using var caller = new CancellationTokenSource();

        var firstWrite = connection.WriteAsync(first, caller.Token).AsTask();
        await stream.HalfWritten.WaitAsync(Timeout);
        var secondWrite = connection.WriteAsync(second).AsTask();
        caller.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstWrite.WaitAsync(Timeout));
        await Task.Delay(Quiet);
        Assert.Equal(PacketCodec.Encode(first).Length / 2, stream.Wire().Length);

        stream.Release();
        await secondWrite.WaitAsync(Timeout);
        Assert.Equal(PacketCodec.Encode(first).Concat(PacketCodec.Encode(second)).ToArray(), stream.Wire());
        Assert.False(connection.Context.Lifetime.IsCancellationRequested);
    }

    private static MessageResponsePacket Message(string text) => new()
    {
        ClientName = "server",
        ToClientName = "client",
        MessageType = MessageType.ServerToClient,
        Message = text + new string('x', 4096),
    };

    private static NatMessagePacket Data(uint streamId, int length) => new()
    {
        NatMessageType = NatMessageType.Data,
        StreamId = streamId,
        Data = new byte[length],
    };

    /// <summary>A <see cref="SpecusConnection"/> over <paramref name="stream"/>, with a real
    /// accepted socket behind it for the connection to close.</summary>
    private sealed class ConnectionPair : IAsyncDisposable
    {
        private readonly Socket _client;

        private ConnectionPair(SpecusConnection connection, Socket client)
        {
            Connection = connection;
            _client = client;
        }

        public SpecusConnection Connection { get; }

        public static async Task<ConnectionPair> OpenAsync(Stream stream)
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                var client = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
                var server = await listener.AcceptSocketAsync();
                var connection = new SpecusConnection(server, stream, new NoDispatcher(),
                    NullLogger.Instance, new NettyServerOptions(), CancellationToken.None);
                return new ConnectionPair(connection, client);
            }
            finally
            {
                listener.Stop();
            }
        }

        public async ValueTask DisposeAsync()
        {
            await Connection.DisposeAsync();
            _client.Dispose();
        }
    }

    private sealed class NoDispatcher : IControlChannelDispatcher
    {
        public Task OnConnectionOpenedAsync(SpecusConnectionContext context) => Task.CompletedTask;
        public Task DispatchAsync(SpecusConnectionContext context, Packet packet) => Task.CompletedTask;
        public Task OnConnectionClosedAsync(SpecusConnectionContext context) => Task.CompletedTask;
    }

    /// <summary>
    /// A transport whose first write puts half of what it is given on the wire and then fails, as a
    /// write cut short by a reset or a write timeout, or holds there until released or cancelled, as
    /// one blocked on a client that stopped reading. Every later write goes through whole.
    /// </summary>
    private sealed class CutShortStream(bool failFirstWrite) : Stream
    {
        private readonly object _gate = new();
        private readonly MemoryStream _wire = new();
        private readonly TaskCompletionSource _halfWritten = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _release = new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _writes;

        public Task HalfWritten => _halfWritten.Task;

        public void Release() => _release.TrySetResult();

        public byte[] Wire()
        {
            lock (_gate)
            {
                return _wire.ToArray();
            }
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            if (Interlocked.Increment(ref _writes) != 1)
            {
                Append(buffer);
                return;
            }
            var half = buffer.Length / 2;
            Append(buffer[..half]);
            _halfWritten.TrySetResult();
            if (failFirstWrite)
            {
                throw new IOException("connection reset after half a frame");
            }
            await _release.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            Append(buffer[half..]);
        }

        private void Append(ReadOnlyMemory<byte> bytes)
        {
            lock (_gate)
            {
                _wire.Write(bytes.Span);
            }
        }

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
            WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override void Write(byte[] buffer, int offset, int count) =>
            WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override void Flush() { }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
