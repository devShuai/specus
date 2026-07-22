using System.Buffers.Binary;

namespace ShuaiTunnel.Protocol;

/// <summary>Mandatory SWS2 envelope for WebSocket frames carried by NAT DATA.</summary>
public sealed class WebSocketTunnelFrame
{
    public const byte OpcodeContinuation = 0x0;
    public const byte OpcodeText = 0x1;
    public const byte OpcodeBinary = 0x2;
    public const byte OpcodeClose = 0x8;
    public const byte OpcodePing = 0x9;
    public const byte OpcodePong = 0xA;
    public const int HeaderBytes = 12;
    public const int MaxPayloadBytes = 64 * 1024 - HeaderBytes;

    private static ReadOnlySpan<byte> Magic => "SWS2"u8;
    private readonly byte[] _payload;

    public WebSocketTunnelFrame(byte opcode, bool finalFragment, byte rsv, ushort closeCode, byte[]? payload)
    {
        Opcode = opcode;
        FinalFragment = finalFragment;
        Rsv = rsv;
        CloseCode = closeCode;
        _payload = payload?.ToArray() ?? [];
        Validate();
    }

    public byte Opcode { get; }
    public bool FinalFragment { get; }
    public byte Rsv { get; }
    public ushort CloseCode { get; }
    public byte[] Payload => _payload.ToArray();

    public byte[] Encode()
    {
        var encoded = new byte[HeaderBytes + _payload.Length];
        Magic.CopyTo(encoded);
        encoded[4] = Opcode;
        encoded[5] = (byte)((FinalFragment ? 1 : 0) | ((Rsv & 7) << 1));
        BinaryPrimitives.WriteUInt16BigEndian(encoded.AsSpan(6, 2), CloseCode);
        BinaryPrimitives.WriteUInt32BigEndian(encoded.AsSpan(8, 4), (uint)_payload.Length);
        _payload.CopyTo(encoded, HeaderBytes);
        return encoded;
    }

    public static WebSocketTunnelFrame Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < HeaderBytes)
        {
            throw new InvalidDataException("truncated SWS2 frame");
        }
        if (!encoded[..4].SequenceEqual(Magic))
        {
            throw new InvalidDataException("invalid SWS2 magic");
        }
        var flags = encoded[5];
        if ((flags & 0xF0) != 0)
        {
            throw new InvalidDataException("unknown SWS2 flags");
        }
        var payloadLength = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(8, 4));
        if (payloadLength > MaxPayloadBytes || payloadLength != encoded.Length - HeaderBytes)
        {
            throw new InvalidDataException("invalid SWS2 payload length");
        }
        try
        {
            return new WebSocketTunnelFrame(
                encoded[4],
                (flags & 1) != 0,
                (byte)((flags >> 1) & 7),
                BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(6, 2)),
                encoded[HeaderBytes..].ToArray());
        }
        catch (ArgumentException ex)
        {
            throw new InvalidDataException(ex.Message, ex);
        }
    }

    private void Validate()
    {
        if (Opcode is not (OpcodeContinuation or OpcodeText or OpcodeBinary or OpcodeClose or OpcodePing or OpcodePong))
        {
            throw new ArgumentException($"unsupported SWS2 opcode {Opcode}");
        }
        if (Rsv > 7 || _payload.Length > MaxPayloadBytes)
        {
            throw new ArgumentException("invalid SWS2 frame bounds");
        }
        if (Opcode >= OpcodeClose && (!FinalFragment || Rsv != 0 || _payload.Length > 125))
        {
            throw new ArgumentException("invalid fragmented/control SWS2 frame");
        }
        if (Opcode == OpcodeClose)
        {
            if (_payload.Length > 123)
            {
                throw new ArgumentException("WebSocket close reason exceeds 123 bytes");
            }
            if (CloseCode != 0 && (CloseCode < 1000 || CloseCode >= 5000))
            {
                throw new ArgumentException("invalid WebSocket close code");
            }
            if (CloseCode == 0 && _payload.Length != 0)
            {
                throw new ArgumentException("WebSocket close reason requires a close code");
            }
        }
        else if (CloseCode != 0)
        {
            throw new ArgumentException("close code is only valid on CLOSE");
        }
    }
}
