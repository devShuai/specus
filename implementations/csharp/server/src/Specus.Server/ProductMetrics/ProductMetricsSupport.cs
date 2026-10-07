using Microsoft.Extensions.Options;

namespace Specus.Server.ProductMetrics;

/// <summary>
/// Deployment settings of the opt-in product metrics (<c>Specus:ProductMetrics</c>, env
/// <c>SPECUS_PRODUCT_METRICS_*</c>). <see cref="Allowed"/> false keeps every tenant off: enabling
/// answers 409 and nothing is collected (protocol/spec/product-metrics.md section 13).
/// </summary>
public sealed class ProductMetricsOptions
{
    public const string SectionName = "Specus:ProductMetrics";

    public bool Allowed { get; set; } = true;
    public int PerUserEventsPerMinute { get; set; } = ProductMetricsModel.DefaultPerUserEventsPerMinute;
    public int PerTenantEventsPerMinute { get; set; } = ProductMetricsModel.DefaultPerTenantEventsPerMinute;
}

/// <summary>
/// The wall clock of the product metrics: day boundaries, the onboarding window and limiter
/// minutes. Its own type so a test can pin metrics time without moving token expiry.
/// </summary>
public class ProductMetricsClock
{
    private readonly TimeProvider _time;

    public ProductMetricsClock(TimeProvider time)
    {
        _time = time;
    }

    public virtual long NowMs() => _time.GetUtcNow().ToUnixTimeMilliseconds();
}

/// <summary>
/// Fixed UTC-minute event budgets per member (tenant + username) and per tenant (section 8). A
/// batch that would exceed either budget is refused whole and charges nothing. Per process, like
/// the other limiters: with several instances the effective budget is a multiple, which only
/// affects the tenant's own statistics.
/// </summary>
public sealed class ProductMetricsRateLimiter
{
    private readonly object _gate = new();
    private readonly Dictionary<string, int> _members = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _tenants = new(StringComparer.Ordinal);
    private long _minute = long.MinValue;
    private int _perUser;
    private int _perTenant;

    public ProductMetricsRateLimiter(IOptions<ProductMetricsOptions> options)
    {
        _perUser = options.Value.PerUserEventsPerMinute;
        _perTenant = options.Value.PerTenantEventsPerMinute;
    }

    public bool TryAdmit(string tenantId, string username, int events, long nowMs)
    {
        lock (_gate)
        {
            var minute = (long)Math.Floor(nowMs / 60_000d);
            if (minute != _minute)
            {
                _minute = minute;
                _members.Clear();
                _tenants.Clear();
            }
            var member = tenantId + "\n" + username;
            var memberUsed = _members.GetValueOrDefault(member);
            var tenantUsed = _tenants.GetValueOrDefault(tenantId);
            if (memberUsed + events > _perUser || tenantUsed + events > _perTenant)
            {
                return false;
            }
            _members[member] = memberUsed + events;
            _tenants[tenantId] = tenantUsed + events;
            return true;
        }
    }

    /// <summary>Replaces the budgets and forgets every window; tests set the vector's limits.</summary>
    public void Reset(int perUserEventsPerMinute, int perTenantEventsPerMinute)
    {
        lock (_gate)
        {
            _perUser = perUserEventsPerMinute;
            _perTenant = perTenantEventsPerMinute;
            _minute = long.MinValue;
            _members.Clear();
            _tenants.Clear();
        }
    }
}

/// <summary>Status and JSON body of one product metrics endpoint call.</summary>
public sealed record ProductMetricsResult(int Status, object? Body)
{
    public static ProductMetricsResult Ok(object body) => new(StatusCodes.Status200OK, body);

    public static ProductMetricsResult Code(int status, string code) =>
        new(status, new Dictionary<string, object?> { ["code"] = code });

    public static readonly ProductMetricsResult Forbidden =
        new(StatusCodes.Status403Forbidden, new Dictionary<string, object?> { ["error"] = "需要 admin 权限" });
}

/// <summary>Runs the retention sweep a minute after start and then hourly, from any instance.</summary>
public sealed class ProductMetricsSweepService : BackgroundService
{
    private static readonly TimeSpan FirstRunDelay = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan Interval = TimeSpan.FromHours(1);

    private readonly ProductMetricsService _service;
    private readonly ILogger<ProductMetricsSweepService> _logger;

    public ProductMetricsSweepService(ProductMetricsService service, ILogger<ProductMetricsSweepService> logger)
    {
        _service = service;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await Task.Delay(FirstRunDelay, stoppingToken).ConfigureAwait(false);
            using var timer = new PeriodicTimer(Interval);
            do
            {
                try
                {
                    await _service.SweepAsync(stoppingToken).ConfigureAwait(false);
                }
                catch (Exception error) when (error is not OperationCanceledException)
                {
                    // The sweep names no account; the next hourly run retries.
                    _logger.LogWarning("[product-metrics] sweep failed: {Error}", error.GetType().Name);
                }
            }
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal host shutdown.
        }
    }
}
