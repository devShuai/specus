using System.Buffers.Binary;
using Specus.Protocol;
using Specus.Server.Http;

namespace Specus.IntegrationTests;

public sealed class RawServerWebSocketConnectionTests
{
    [Fact]
    public async Task ReadsMaskedClientFramesAndWritesUnmaskedServerFrames()
    {
        var input = BuildClientFrame(WebSocketSpecusFrame.OpcodeBinary, finalFragment: true,
            rsv: 0, [1, 2, 3], masked: true);
        await using var reader = RawServerWebSocketConnection.CreateForTesting(
            new MemoryStream(input));

        var frame = await reader.ReadFrameAsync(CancellationToken.None);

        Assert.NotNull(frame);
        Assert.Equal(WebSocketSpecusFrame.OpcodeBinary, frame!.Opcode);
        Assert.True(frame.FinalFragment);
        Assert.Equal(new byte[] { 1, 2, 3 }, frame.Payload);

        var output = new MemoryStream();
        await using var writer = RawServerWebSocketConnection.CreateForTesting(output);
        await writer.WriteFrameAsync(new RawServerWebSocketFrame(
            WebSocketSpecusFrame.OpcodePing, true, 0, [4, 5]), CancellationToken.None);
        var wire = output.ToArray();
        Assert.Equal(0x89, wire[0]);
        Assert.Equal(0, wire[1] & 0x80);
        Assert.Equal(2, wire[1] & 0x7f);
        Assert.Equal(new byte[] { 4, 5 }, wire[2..]);
    }

    [Fact]
    public async Task RejectsUnmaskedClientFrameAndUnexpectedRsvBits()
    {
        await using var unmasked = RawServerWebSocketConnection.CreateForTesting(new MemoryStream(
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, true, 0, "x"u8.ToArray(),
                masked: false)));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await unmasked.ReadFrameAsync(CancellationToken.None));

        await using var reserved = RawServerWebSocketConnection.CreateForTesting(new MemoryStream(
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, true, 1, "x"u8.ToArray(),
                masked: true)));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await reserved.ReadFrameAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ContinuationStateMachineAllowsControlInterleaveAndRejectsInvalidSequences()
    {
        var valid = Concat(
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, false, 0, "a"u8.ToArray(), true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodePong, true, 0, "p"u8.ToArray(), true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0,
                "b"u8.ToArray(), true));
        await using (var connection = RawServerWebSocketConnection.CreateForTesting(
                         new MemoryStream(valid)))
        {
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
        }

        await using (var orphan = RawServerWebSocketConnection.CreateForTesting(new MemoryStream(
                         BuildClientFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0,
                             "x"u8.ToArray(), true))))
        {
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await orphan.ReadFrameAsync(CancellationToken.None));
        }

        var overlapping = Concat(
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, false, 0, "a"u8.ToArray(), true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeBinary, true, 0, [1], true));
        await using var overlap = RawServerWebSocketConnection.CreateForTesting(
            new MemoryStream(overlapping));
        Assert.NotNull(await overlap.ReadFrameAsync(CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await overlap.ReadFrameAsync(CancellationToken.None));
    }

    [Fact]
    public async Task RejectsMalformedControlAndCloseFrames()
    {
        var cases = new[]
        {
            BuildClientFrame(WebSocketSpecusFrame.OpcodePing, false, 0, [1], true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeClose, true, 0, [0x03], true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeClose, true, 0, [0x03, 0xED], true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeClose, true, 0,
                [0x03, 0xE8, 0xC3, 0x28], true),
        };

        foreach (var wire in cases)
        {
            await using var connection = RawServerWebSocketConnection.CreateForTesting(
                new MemoryStream(wire));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await connection.ReadFrameAsync(CancellationToken.None));
        }
    }

    [Fact]
    public async Task BrowserPingGetsSamePayloadPongLocallyWhileBrowserPongRemainsVisible()
    {
        var input = Concat(
            BuildClientFrame(WebSocketSpecusFrame.OpcodePing, true, 0,
                "local-ping"u8.ToArray(), true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodePong, true, 0,
                "browser-pong"u8.ToArray(), true));
        var transport = new ScriptedDuplexStream(input);
        await using var connection = RawServerWebSocketConnection.CreateForTesting(transport);

        var tunnelFrame = await connection.ReadFrameAsync(CancellationToken.None);

        Assert.NotNull(tunnelFrame);
        Assert.Equal(WebSocketSpecusFrame.OpcodePong, tunnelFrame!.Opcode);
        Assert.Equal("browser-pong"u8.ToArray(), tunnelFrame.Payload);
        var response = transport.WrittenBytes;
        Assert.Equal(0x8A, response[0]);
        Assert.Equal(0, response[1] & 0x80);
        Assert.Equal("local-ping"u8.Length, response[1] & 0x7f);
        Assert.Equal("local-ping"u8.ToArray(), response[2..]);
    }

    [Fact]
    public async Task ValidatesTextUtf8AcrossContinuationBoundaries()
    {
        var valid = Concat(
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, false, 0, [0xF0, 0x9F], true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0,
                [0x98, 0x80], true));
        await using (var connection = RawServerWebSocketConnection.CreateForTesting(
                         new MemoryStream(valid)))
        {
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
        }

        var malformed = new[]
        {
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, true, 0, [0xC3, 0x28], true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, true, 0, [0xE2, 0x82], true),
        };
        foreach (var wire in malformed)
        {
            await using var connection = RawServerWebSocketConnection.CreateForTesting(
                new MemoryStream(wire));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await connection.ReadFrameAsync(CancellationToken.None));
        }

        var invalidContinuation = Concat(
            BuildClientFrame(WebSocketSpecusFrame.OpcodeText, false, 0, [0xF0, 0x9F], true),
            BuildClientFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0, [0x28], true));
        await using var fragmented = RawServerWebSocketConnection.CreateForTesting(
            new MemoryStream(invalidContinuation));
        Assert.NotNull(await fragmented.ReadFrameAsync(CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await fragmented.ReadFrameAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ConcurrentServerWritesRemainWholeAndSerialized()
    {
        var output = new YieldingWriteStream();
        await using var connection = RawServerWebSocketConnection.CreateForTesting(output);

        await Task.WhenAll(Enumerable.Range(0, 64).Select(index =>
            connection.WriteFrameAsync(new RawServerWebSocketFrame(
                    WebSocketSpecusFrame.OpcodeBinary, true, 0,
                    [(byte)index, (byte)index, (byte)index]), CancellationToken.None)
                .AsTask()));

        var wire = output.ToArray();
        Assert.Equal(64 * 5, wire.Length);
        for (var offset = 0; offset < wire.Length; offset += 5)
        {
            Assert.Equal(0x82, wire[offset]);
            Assert.Equal(3, wire[offset + 1]);
            Assert.Equal(wire[offset + 2], wire[offset + 3]);
            Assert.Equal(wire[offset + 2], wire[offset + 4]);
        }
    }

    private static byte[] BuildClientFrame(byte opcode, bool finalFragment, byte rsv,
        byte[] payload, bool masked)
    {
        var extendedBytes = payload.Length < 126 ? 0 : payload.Length <= ushort.MaxValue ? 2 : 8;
        var maskBytes = masked ? 4 : 0;
        var wire = new byte[2 + extendedBytes + maskBytes + payload.Length];
        wire[0] = (byte)(opcode | (rsv << 4) | (finalFragment ? 0x80 : 0));
        var offset = 2;
        if (extendedBytes == 0)
        {
            wire[1] = (byte)(payload.Length | (masked ? 0x80 : 0));
        }
        else if (extendedBytes == 2)
        {
            wire[1] = (byte)(126 | (masked ? 0x80 : 0));
            BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(offset, 2), (ushort)payload.Length);
            offset += 2;
        }
        else
        {
            wire[1] = (byte)(127 | (masked ? 0x80 : 0));
            BinaryPrimitives.WriteUInt64BigEndian(wire.AsSpan(offset, 8), (ulong)payload.Length);
            offset += 8;
        }

        ReadOnlySpan<byte> mask = [0x12, 0x34, 0x56, 0x78];
        if (masked)
        {
            mask.CopyTo(wire.AsSpan(offset, 4));
            offset += 4;
        }
        for (var index = 0; index < payload.Length; index++)
        {
            wire[offset + index] = masked
                ? (byte)(payload[index] ^ mask[index & 3])
                : payload[index];
        }
        return wire;
    }

    private static byte[] Concat(params byte[][] values)
    {
        var result = new byte[values.Sum(value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(result, offset);
            offset += value.Length;
        }
        return result;
    }

    private sealed class YieldingWriteStream : Stream
    {
        private readonly List<byte> _bytes = [];
        private readonly object _lock = new();

        public byte[] ToArray()
        {
            lock (_lock)
            {
                return [.. _bytes];
            }
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            foreach (var value in buffer.Span.ToArray())
            {
                cancellationToken.ThrowIfCancellationRequested();
                lock (_lock)
                {
                    _bytes.Add(value);
                }
                await Task.Yield();
            }
        }

        public override void Flush() { }
        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();
    }

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
}
