namespace Specus.Server.Connectivity;

/// <summary>
/// Generic cell rate algorithm: one theoretical arrival time (TAT) per key, integer milliseconds.
/// A request at <c>now</c> conforms when <c>now &gt;= TAT - tolerance</c>; conforming moves the TAT
/// to <c>max(TAT, now) + interval</c>, with <c>tolerance = (burst - 1) * interval</c>
/// (service-connectivity-check.md section 7, the generator's <c>Gcra</c>).
/// </summary>
/// <remarks>
/// The key table is bounded. An entry whose TAT is not after <c>now</c> is the same as no entry
/// and may be dropped at any time; a live entry is never dropped, since that would hand its key a
/// fresh allowance. Not thread-safe: <see cref="ConnectivityCheckAdmission"/> serializes access.
/// </remarks>
internal sealed class GcraLimiter<TKey> where TKey : notnull
{
    private readonly Dictionary<TKey, long> _tat = new();
    private readonly long _interval;
    private readonly long _tolerance;
    private readonly int _maxKeys;

    public GcraLimiter(long intervalMs, int burst, int maxKeys)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(intervalMs, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(burst, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxKeys, 1);
        _interval = intervalMs;
        _tolerance = (burst - 1) * intervalMs;
        _maxKeys = maxKeys;
    }

    public int Count => _tat.Count;

    /// <summary>Milliseconds until a request for <paramref name="key"/> conforms; 0 when it does.</summary>
    public long WaitMs(TKey key, long now)
    {
        var tat = _tat.TryGetValue(key, out var stored) ? stored : now;
        return Math.Max(0, tat - _tolerance - now);
    }

    /// <summary>
    /// True when <see cref="Take"/> can record <paramref name="key"/>: it already has an entry, or
    /// there is room once the entries that are no longer live have been dropped.
    /// </summary>
    public bool HasRoomFor(TKey key, long now)
    {
        if (_tat.ContainsKey(key) || _tat.Count < _maxKeys)
        {
            return true;
        }
        foreach (var (stored, tat) in _tat.ToArray())
        {
            if (tat <= now)
            {
                _tat.Remove(stored);
            }
        }
        return _tat.Count < _maxKeys;
    }

    public void Take(TKey key, long now)
    {
        var tat = _tat.TryGetValue(key, out var stored) ? stored : now;
        _tat[key] = Math.Max(tat, now) + _interval;
    }
}

/// <summary>Why a check was not admitted, or that it was.</summary>
internal readonly record struct ConnectivityAdmissionDecision(
    bool Admitted,
    int HttpStatus,
    string? Code,
    int RetryAfterSeconds,
    string? LimitedBy)
{
    public static ConnectivityAdmissionDecision Admit() => new(true, StatusCodes.Status200OK, null, 0, null);

    public static ConnectivityAdmissionDecision Refuse(int httpStatus, string code, int retryAfterSeconds,
        string? limitedBy = null) => new(false, httpStatus, code, retryAfterSeconds, limitedBy);
}

/// <summary>
/// Process-wide admission for connectivity checks, in the contract's order: one check per route
/// (429 <c>CHECK_IN_PROGRESS</c>), at most <see cref="MaxConcurrentPerServer"/> per process
/// (503 <c>CHECK_BUSY</c>), then the two GCRA keys (429 <c>CHECK_RATE_LIMITED</c>, or 503
/// <c>CHECK_BUSY</c> when a key table is full of live entries). A refusal changes nothing; an
/// admitted check holds its in-flight slots until <see cref="Release"/>.
/// </summary>
/// <remarks>
/// The clock is passed in as integer milliseconds so the shared vector's <c>rate.events</c> replay
/// through this very code. All state is in memory and per process, like the existing limiters.
/// </remarks>
internal sealed class ConnectivityCheckAdmission
{
    public const int MaxConcurrentPerServer = 32;
    public const int MaxKeys = 10_000;
    public const long RouteIntervalMs = 10_000;
    public const int RouteBurst = 1;
    public const long UserIntervalMs = 30_000;
    public const int UserBurst = 10;
    public const long RefusalLogIntervalMs = 60_000;

    public const string LimitedByRoute = "route";
    public const string LimitedByUser = "user";

    private readonly object _gate = new();
    private readonly HashSet<(string Tenant, long RouteId)> _inFlightRoutes = new();
    private readonly GcraLimiter<(string Tenant, long RouteId)> _perRoute =
        new(RouteIntervalMs, RouteBurst, MaxKeys);
    private readonly GcraLimiter<(string Tenant, string Username)> _perUser =
        new(UserIntervalMs, UserBurst, MaxKeys);
    private readonly Dictionary<(string Tenant, string Username), long> _refusalLogged = new();

    public int InFlight
    {
        get
        {
            lock (_gate)
            {
                return _inFlightRoutes.Count;
            }
        }
    }

    public ConnectivityAdmissionDecision TryAdmit(string tenantId, string username, long routeId, long nowMs)
    {
        var routeKey = (tenantId, routeId);
        var userKey = (tenantId, username);
        lock (_gate)
        {
            if (_inFlightRoutes.Contains(routeKey))
            {
                return ConnectivityAdmissionDecision.Refuse(StatusCodes.Status429TooManyRequests,
                    ConnectivityCode.InProgress, 1);
            }
            if (_inFlightRoutes.Count >= MaxConcurrentPerServer)
            {
                return ConnectivityAdmissionDecision.Refuse(StatusCodes.Status503ServiceUnavailable,
                    ConnectivityCode.Busy, 1);
            }

            var routeWait = _perRoute.WaitMs(routeKey, nowMs);
            var userWait = _perUser.WaitMs(userKey, nowMs);
            var wait = Math.Max(routeWait, userWait);
            if (wait > 0)
            {
                return ConnectivityAdmissionDecision.Refuse(StatusCodes.Status429TooManyRequests,
                    ConnectivityCode.RateLimited, RetryAfterSeconds(wait),
                    routeWait >= userWait ? LimitedByRoute : LimitedByUser);
            }
            if (!_perRoute.HasRoomFor(routeKey, nowMs) || !_perUser.HasRoomFor(userKey, nowMs))
            {
                return ConnectivityAdmissionDecision.Refuse(StatusCodes.Status503ServiceUnavailable,
                    ConnectivityCode.Busy, 1);
            }

            _perRoute.Take(routeKey, nowMs);
            _perUser.Take(userKey, nowMs);
            _inFlightRoutes.Add(routeKey);
            return ConnectivityAdmissionDecision.Admit();
        }
    }

    /// <summary>Frees the in-flight slots of an admitted check. The rate already taken stays taken.</summary>
    public void Release(string tenantId, long routeId)
    {
        lock (_gate)
        {
            _inFlightRoutes.Remove((tenantId, routeId));
        }
    }

    /// <summary>
    /// True at most once per (tenant, username) per minute: rate-limited refusals are logged that
    /// sparsely. The table is bounded like the key tables; when it is full of recent entries the
    /// line is skipped rather than an entry evicted.
    /// </summary>
    public bool ShouldLogRefusal(string tenantId, string username, long nowMs)
    {
        var key = (tenantId, username);
        lock (_gate)
        {
            if (_refusalLogged.TryGetValue(key, out var last))
            {
                if (nowMs - last < RefusalLogIntervalMs)
                {
                    return false;
                }
            }
            else if (_refusalLogged.Count >= MaxKeys)
            {
                foreach (var (stored, at) in _refusalLogged.ToArray())
                {
                    if (nowMs - at >= RefusalLogIntervalMs)
                    {
                        _refusalLogged.Remove(stored);
                    }
                }
                if (_refusalLogged.Count >= MaxKeys)
                {
                    return false;
                }
            }
            _refusalLogged[key] = nowMs;
            return true;
        }
    }

    /// <summary>Whole seconds, rounded up, at least 1.</summary>
    public static int RetryAfterSeconds(long waitMs) =>
        (int)Math.Max(1, Math.Min(int.MaxValue, (waitMs + 999) / 1000));
}
