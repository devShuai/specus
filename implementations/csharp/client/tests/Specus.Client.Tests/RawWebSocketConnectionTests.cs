using System.Buffers.Binary;
using Specus.Client.Nat;
using Specus.Protocol;

namespace Specus.Client.Tests;

public sealed class RawWebSocketConnectionTests
{
    [Fact]
    public async Task ReadsUnmaskedServerFramesAndWritesMaskedClientFrames()
    {
        await using var reader = RawWebSocketConnection.CreateForTesting(new MemoryStream(
            ServerFrame(WebSocketSpecusFrame.OpcodePong, true, 0, [1, 2])));
        var frame = await reader.ReadFrameAsync(CancellationToken.None);
        Assert.NotNull(frame);
        Assert.Equal(WebSocketSpecusFrame.OpcodePong, frame!.Opcode);
        Assert.Equal(new byte[] { 1, 2 }, frame.Payload);

        var output = new MemoryStream();
        await using var writer = RawWebSocketConnection.CreateForTesting(output);
        await writer.WriteFrameAsync(new RawWebSocketFrame(
            WebSocketSpecusFrame.OpcodeBinary, true, 0, [3, 4]), CancellationToken.None);
        var wire = output.ToArray();
        Assert.Equal(0x82, wire[0]);
        Assert.NotEqual(0, wire[1] & 0x80);
        Assert.Equal(2, wire[1] & 0x7f);
        Assert.Equal((byte)3, (byte)(wire[6] ^ wire[2]));
        Assert.Equal((byte)4, (byte)(wire[7] ^ wire[3]));
    }

    [Fact]
    public async Task RejectsMaskedServerFramesRsvAndInvalidFragmentSequences()
    {
        var invalid = new[]
        {
            ServerFrame(WebSocketSpecusFrame.OpcodeText, true, 0, "x"u8.ToArray(), masked: true),
            ServerFrame(WebSocketSpecusFrame.OpcodeText, true, 1, "x"u8.ToArray()),
            ServerFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0, "x"u8.ToArray()),
        };
        foreach (var wire in invalid)
        {
            await using var connection = RawWebSocketConnection.CreateForTesting(
                new MemoryStream(wire));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await connection.ReadFrameAsync(CancellationToken.None));
        }

        var overlapWire = Concat(
            ServerFrame(WebSocketSpecusFrame.OpcodeBinary, false, 0, [1]),
            ServerFrame(WebSocketSpecusFrame.OpcodeText, true, 0, "x"u8.ToArray()));
        await using var overlap = RawWebSocketConnection.CreateForTesting(
            new MemoryStream(overlapWire));
        Assert.NotNull(await overlap.ReadFrameAsync(CancellationToken.None));
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await overlap.ReadFrameAsync(CancellationToken.None));
    }

    [Fact]
    public async Task ValidatesClosePayloadAndFragmentedTextUtf8()
    {
        var valid = Concat(
            ServerFrame(WebSocketSpecusFrame.OpcodeText, false, 0, [0xF0, 0x9F]),
            ServerFrame(WebSocketSpecusFrame.OpcodePing, true, 0, [1]),
            ServerFrame(WebSocketSpecusFrame.OpcodeContinuation, true, 0, [0x98, 0x80]));
        await using (var connection = RawWebSocketConnection.CreateForTesting(
                         new MemoryStream(valid)))
        {
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
            Assert.NotNull(await connection.ReadFrameAsync(CancellationToken.None));
        }

        var malformed = new[]
        {
            ServerFrame(WebSocketSpecusFrame.OpcodeText, true, 0, [0xC3, 0x28]),
            ServerFrame(WebSocketSpecusFrame.OpcodeClose, true, 0, [0x03]),
            ServerFrame(WebSocketSpecusFrame.OpcodeClose, true, 0, [0x03, 0xED]),
            ServerFrame(WebSocketSpecusFrame.OpcodeClose, true, 0,
                [0x03, 0xE8, 0xC3, 0x28]),
        };
        foreach (var wire in malformed)
        {
            await using var connection = RawWebSocketConnection.CreateForTesting(
                new MemoryStream(wire));
            await Assert.ThrowsAsync<InvalidDataException>(async () =>
                await connection.ReadFrameAsync(CancellationToken.None));
        }
    }

    [Fact]
    public async Task ClientWriteStateRejectsRsvOrInvalidContinuation()
    {
        await using var rsv = RawWebSocketConnection.CreateForTesting(new MemoryStream());
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await rsv.WriteFrameAsync(new RawWebSocketFrame(
                WebSocketSpecusFrame.OpcodeBinary, true, 1, [1]), CancellationToken.None));

        await using var orphan = RawWebSocketConnection.CreateForTesting(new MemoryStream());
        await Assert.ThrowsAsync<InvalidDataException>(async () =>
            await orphan.WriteFrameAsync(new RawWebSocketFrame(
                WebSocketSpecusFrame.OpcodeContinuation, true, 0, [1]),
                CancellationToken.None));
    }

    private static byte[] ServerFrame(byte opcode, bool finalFragment, byte rsv, byte[] payload,
        bool masked = false)
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
}
