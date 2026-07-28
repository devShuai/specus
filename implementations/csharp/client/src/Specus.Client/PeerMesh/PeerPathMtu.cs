using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Specus.Client.PeerMesh;

internal static class PeerPathMtu
{
    public const int MinInnerMtu = 576;
    public const int MaxInnerMtu = 9000;
    public const int MaxAttempts = 3;
    public static readonly TimeSpan ProbeTimeout = TimeSpan.FromMilliseconds(750);
    public static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(10);

    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("SPMTU2");
    private const byte ProbeType = 1;
    private const byte AckType = 2;
    private const int HeaderBytes = 6 + 1 + 8 + 2;

    internal sealed record Message(bool IsProbe, ulong Nonce, int InnerMtu);
    internal sealed record Probe(ulong Nonce, int InnerMtu);
    internal sealed record Transition(Probe? NextProbe = null, int? CompletedMtu = null);
    internal sealed record CacheEntry(int InnerMtu, DateTimeOffset ValidUntil);

    public static byte[] EncodeProbe(ulong nonce, int innerMtu)
    {
        Validate(nonce, innerMtu);
        var payload = new byte[innerMtu];
        WriteHeader(payload, ProbeType, nonce, innerMtu);
        return payload;
    }

    public static byte[] EncodeAck(ulong nonce, int innerMtu)
    {
        Validate(nonce, innerMtu);
        var payload = new byte[HeaderBytes];
        WriteHeader(payload, AckType, nonce, innerMtu);
        return payload;
    }

    public static bool LooksLike(ReadOnlySpan<byte> payload) =>
        payload.Length >= Magic.Length && payload[..Magic.Length].SequenceEqual(Magic);

    public static Message? Decode(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < HeaderBytes || !LooksLike(payload))
        {
            return null;
        }
        var type = payload[6];
        var nonce = BinaryPrimitives.ReadUInt64BigEndian(payload[7..15]);
        var innerMtu = BinaryPrimitives.ReadUInt16BigEndian(payload[15..17]);
        if (nonce == 0 || innerMtu < MinInnerMtu || innerMtu > MaxInnerMtu)
        {
            return null;
        }
        if (type == ProbeType && payload.Length == innerMtu)
        {
            return new Message(true, nonce, innerMtu);
        }
        return type == AckType && payload.Length == HeaderBytes
            ? new Message(false, nonce, innerMtu)
            : null;
    }

    private static void WriteHeader(Span<byte> output, byte type, ulong nonce, int innerMtu)
    {
        Magic.CopyTo(output);
        output[6] = type;
        BinaryPrimitives.WriteUInt64BigEndian(output[7..15], nonce);
        BinaryPrimitives.WriteUInt16BigEndian(output[15..17], checked((ushort)innerMtu));
    }

    private static void Validate(ulong nonce, int innerMtu)
    {
        if (nonce == 0 || innerMtu < MinInnerMtu || innerMtu > MaxInnerMtu)
        {
            throw new ArgumentOutOfRangeException(nameof(innerMtu), "invalid path MTU message");
        }
    }

    internal sealed class Discovery
    {
        private readonly object _sync = new();
        private string _pathKey = "";
        private int _ceiling = MinInnerMtu;
        private int _lower = MinInnerMtu;
        private int _upper = MinInnerMtu;
        private int _effective = MinInnerMtu;
        private int _pendingSize;
        private ulong _pendingNonce;
        private int _attempts;
        private bool _sawFailure;
        private DateTimeOffset _validUntil;

        public Transition Activate(string pathKey, int configuredMtu, CacheEntry? cached, DateTimeOffset now)
        {
            lock (_sync)
            {
                configuredMtu = Normalize(configuredMtu);
                if (_pathKey == pathKey && (_pendingSize > 0 || now < _validUntil))
                {
                    return new Transition();
                }
                _pathKey = pathKey;
                _ceiling = configuredMtu;
                _lower = MinInnerMtu;
                _upper = configuredMtu;
                _pendingSize = 0;
                _pendingNonce = 0;
                _attempts = 0;
                _sawFailure = false;
                if (cached is not null && now < cached.ValidUntil)
                {
                    _effective = Math.Min(configuredMtu, Normalize(cached.InnerMtu));
                    _lower = _effective;
                    _upper = _effective;
                    _validUntil = cached.ValidUntil;
                    return new Transition();
                }
                _effective = configuredMtu;
                _validUntil = default;
                return Issue(configuredMtu);
            }
        }

        public Transition Acknowledge(ulong nonce, int innerMtu, DateTimeOffset now)
        {
            lock (_sync)
            {
                if (_pendingSize == 0 || _pendingNonce != nonce || _pendingSize != innerMtu)
                {
                    return new Transition();
                }
                _lower = Math.Max(_lower, innerMtu);
                _effective = _sawFailure ? _lower : _ceiling;
                _pendingSize = 0;
                _pendingNonce = 0;
                _attempts = 0;
                if (_lower >= _upper)
                {
                    return Complete(now);
                }
                return Issue(_lower + ((_upper - _lower + 1) / 2));
            }
        }

        public Transition Timeout(ulong nonce, DateTimeOffset now)
        {
            lock (_sync)
            {
                if (_pendingSize == 0 || _pendingNonce != nonce)
                {
                    return new Transition();
                }
                if (_attempts < MaxAttempts)
                {
                    _attempts++;
                    return new Transition(new Probe(_pendingNonce, _pendingSize));
                }
                _sawFailure = true;
                _upper = Math.Max(MinInnerMtu, _pendingSize - 1);
                _effective = Math.Min(_effective, _upper);
                _pendingSize = 0;
                _pendingNonce = 0;
                _attempts = 0;
                if (_upper <= _lower)
                {
                    _effective = _lower;
                    return Complete(now);
                }
                return Issue(_lower + ((_upper - _lower + 1) / 2));
            }
        }

        public int EffectiveMtu(int configuredMtu)
        {
            lock (_sync)
            {
                return Math.Min(Normalize(configuredMtu), Math.Max(MinInnerMtu, _effective));
            }
        }

        public string PathKey
        {
            get
            {
                lock (_sync)
                {
                    return _pathKey;
                }
            }
        }

        private Transition Issue(int size)
        {
            _pendingSize = Math.Max(MinInnerMtu, Math.Min(_ceiling, size));
            _pendingNonce = RandomNonce();
            _attempts = 1;
            return new Transition(new Probe(_pendingNonce, _pendingSize));
        }

        private Transition Complete(DateTimeOffset now)
        {
            _effective = Math.Max(MinInnerMtu, Math.Min(_ceiling, _effective));
            _validUntil = now + CacheTtl;
            return new Transition(CompletedMtu: _effective);
        }
    }

    private static int Normalize(int value) => Math.Clamp(value, MinInnerMtu, MaxInnerMtu);

    private static ulong RandomNonce()
    {
        Span<byte> raw = stackalloc byte[8];
        ulong nonce;
        do
        {
            RandomNumberGenerator.Fill(raw);
            nonce = BinaryPrimitives.ReadUInt64BigEndian(raw) & (ulong)long.MaxValue;
        } while (nonce == 0);
        return nonce;
    }
}
