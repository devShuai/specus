using System.Security.Cryptography;

namespace Specus.Server.Http;

/// <summary>The clock of the share service; tests replace it to replay the vectors at fixed instants.</summary>
public class HttpShareClock
{
    private readonly TimeProvider _time;

    public HttpShareClock(TimeProvider time)
    {
        _time = time;
    }

    public virtual DateTimeOffset UtcNow => _time.GetUtcNow();

    public long NowMs => UtcNow.ToUnixTimeMilliseconds();

    /// <summary>Now truncated to the whole second, the unit every stored instant uses.</summary>
    public long NowSeconds => Math.DivRem(NowMs, 1000, out var remainder) - (remainder < 0 ? 1 : 0);
}

/// <summary>The random source for share ids and secrets; only a CSPRNG outside tests.</summary>
public interface IHttpShareRandom
{
    void Fill(Span<byte> destination);
}

public sealed class CryptoHttpShareRandom : IHttpShareRandom
{
    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);
}

/// <summary>
/// This instance's in-flight streams per share (HTTP requests and WebSockets together). It bounds
/// each share to 64 concurrent streams and lets a revoke, an expiry or a recheck cut them: every
/// lease carries a token that the forwarding code turns into a NAT RST and an aborted response.
/// </summary>
public sealed class HttpShareStreamRegistry
{
    private readonly object _sync = new();
    private readonly Dictionary<string, List<Lease>> _byShare = new(StringComparer.Ordinal);

    /// <summary>A lease for one more stream of the share, or null when it already has 64.</summary>
    public Lease? TryAcquire(string shareId, long expiresAtSeconds)
    {
        lock (_sync)
        {
            if (!_byShare.TryGetValue(shareId, out var leases))
            {
                leases = [];
                _byShare[shareId] = leases;
            }
            if (leases.Count >= HttpShareProtocol.MaxConcurrentPerShare)
            {
                return null;
            }
            var lease = new Lease(this, shareId, expiresAtSeconds);
            leases.Add(lease);
            return lease;
        }
    }

    public int Count(string shareId)
    {
        lock (_sync)
        {
            return _byShare.TryGetValue(shareId, out var leases) ? leases.Count : 0;
        }
    }

    /// <summary>The shares that currently have streams on this instance.</summary>
    public IReadOnlyList<string> ActiveShareIds()
    {
        lock (_sync)
        {
            return _byShare.Keys.ToList();
        }
    }

    /// <summary>Cuts every in-flight stream of the share on this instance.</summary>
    public void Cut(string shareId)
    {
        List<Lease> leases;
        lock (_sync)
        {
            if (!_byShare.TryGetValue(shareId, out var current))
            {
                return;
            }
            leases = current.ToList();
        }
        foreach (var lease in leases)
        {
            lease.Cancel();
        }
    }

    /// <summary>Cuts the streams whose share expired at or before <paramref name="nowMs"/>.</summary>
    public void CutExpired(long nowMs)
    {
        List<Lease> expired;
        lock (_sync)
        {
            expired = _byShare.Values.SelectMany(static leases => leases)
                .Where(lease => lease.ExpiresAtSeconds * 1000 <= nowMs)
                .ToList();
        }
        foreach (var lease in expired)
        {
            lease.Cancel();
        }
    }

    private void Release(Lease lease)
    {
        lock (_sync)
        {
            if (_byShare.TryGetValue(lease.ShareId, out var leases)
                && leases.Remove(lease) && leases.Count == 0)
            {
                _byShare.Remove(lease.ShareId);
            }
        }
    }

    public sealed class Lease : IDisposable
    {
        private readonly HttpShareStreamRegistry _registry;
        private readonly CancellationTokenSource _cut = new();
        private int _released;

        internal Lease(HttpShareStreamRegistry registry, string shareId, long expiresAtSeconds)
        {
            _registry = registry;
            ShareId = shareId;
            ExpiresAtSeconds = expiresAtSeconds;
        }

        public string ShareId { get; }

        public long ExpiresAtSeconds { get; }

        /// <summary>Cancelled when the stream must end because its share has ended.</summary>
        public CancellationToken CutToken => _cut.Token;

        internal void Cancel()
        {
            try
            {
                _cut.Cancel();
            }
            catch (AggregateException)
            {
                // A cut callback failed; the stream is being torn down either way.
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
            {
                _registry.Release(this);
            }
        }
    }
}
