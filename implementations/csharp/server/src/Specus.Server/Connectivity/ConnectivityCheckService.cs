using System.Security.Cryptography;
using Specus.Protocol.HttpRoute;
using Specus.Server.Management;

namespace Specus.Server.Connectivity;

/// <summary>
/// One bounded end-to-end check of one HTTP route the caller may manage: configured, device online,
/// target reachable, access succeeded, each decided once with a stable code and the elapsed
/// milliseconds, stopping at the first stage that did not pass (service-connectivity-check.md,
/// the reference <c>check()</c> in tools/protocol/generate_service_connectivity_vectors.py).
/// </summary>
/// <remarks>
/// The route store, the device side and the clock are seams so the shared vector drives this code
/// with scripted answers and a fake clock. Nothing here reads, returns or logs the target address,
/// the probe path, response headers, the body, the exact status or an RST reason.
/// </remarks>
internal sealed class ConnectivityCheckService
{
    /// <summary>A trusted RST <c>metadata.failure</c> and the stage and code it decides (section 6.2).</summary>
    private static readonly IReadOnlyDictionary<string, (string Stage, string Code)> RstFailures =
        new Dictionary<string, (string Stage, string Code)>(StringComparer.Ordinal)
        {
            [HttpRouteFailure.RouteNotLoaded] = (ConnectivityStage.DeviceOnline, ConnectivityCode.DeviceRouteNotLoaded),
            [HttpRouteFailure.TargetInvalid] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetAddressInvalid),
            [HttpRouteFailure.ConnectRefused] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetConnectRefused),
            [HttpRouteFailure.ConnectTimeout] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetConnectTimeout),
            [HttpRouteFailure.DnsFailed] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetDnsFailed),
            [HttpRouteFailure.TlsFailed] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetTlsFailed),
            [HttpRouteFailure.Unreachable] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetUnreachable),
            [HttpRouteFailure.ProtocolError] = (ConnectivityStage.TargetReachable, ConnectivityCode.TargetProtocolError),
        };

    private readonly IConnectivityRouteSource _routes;
    private readonly IConnectivityDeviceGateway _devices;
    private readonly ConnectivityCheckAdmission _admission;
    private readonly TimeProvider _time;
    private readonly ILogger<ConnectivityCheckService> _logger;

    public ConnectivityCheckService(IConnectivityRouteSource routes, IConnectivityDeviceGateway devices,
        ConnectivityCheckAdmission admission, TimeProvider time, ILogger<ConnectivityCheckService> logger)
    {
        _routes = routes;
        _devices = devices;
        _admission = admission;
        _time = time;
        _logger = logger;
    }

    /// <summary>
    /// Runs steps 3 to 8 of section 3.2 for an authenticated caller whose body was valid: read the
    /// route (503), visibility (404), admission (429/503), then the check itself (200).
    /// </summary>
    public async Task<ConnectivityCheckResult> CheckAsync(ManagementContext caller, long routeId, string path,
        ConnectivityCheckStart start, CancellationToken cancellationToken)
    {
        ConnectivityRouteTarget? target;
        try
        {
            target = await _routes.FindAsync(routeId, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning("[connectivity-check] route store unavailable: {ErrorType}", ex.GetType().Name);
            return ConnectivityCheckResult.Refuse(StatusCodes.Status503ServiceUnavailable,
                ConnectivityCode.Unavailable, 1);
        }
        // Absent, another tenant's, and someone else's route answer alike.
        if (target is null || !caller.CanAccess(target.Account))
        {
            return ConnectivityCheckResult.Refuse(StatusCodes.Status404NotFound, ConnectivityCode.TargetNotFound);
        }

        var tenant = ManagementContext.NormalizeTenant(caller.TenantId);
        var decision = _admission.TryAdmit(tenant, caller.Username, routeId, NowMs());
        if (!decision.Admitted)
        {
            if (decision.Code == ConnectivityCode.RateLimited
                && _admission.ShouldLogRefusal(tenant, caller.Username, NowMs()))
            {
                _logger.LogInformation(
                    "[connectivity-check] tenant={Tenant} user={User} route={RouteId} refused code={Code} retryAfter={RetryAfter}",
                    tenant, caller.Username, routeId, ConnectivityCode.RateLimited, decision.RetryAfterSeconds);
            }
            return ConnectivityCheckResult.Refuse(decision.HttpStatus, decision.Code!, decision.RetryAfterSeconds);
        }

        try
        {
            var report = await RunAsync(target, routeId, path, start, cancellationToken).ConfigureAwait(false);
            _logger.LogInformation(
                "[connectivity-check] tenant={Tenant} user={User} route={RouteId} outcome={Outcome} stage={Stage} code={Code} totalMs={TotalMs}",
                tenant, caller.Username, routeId, report.Outcome, report.StoppedAt ?? "-", report.Code,
                report.TotalMs);
            return ConnectivityCheckResult.Ran(report);
        }
        finally
        {
            _admission.Release(tenant, routeId);
        }
    }

    private async Task<ConnectivityCheckReport> RunAsync(ConnectivityRouteTarget target, long routeId,
        string path, ConnectivityCheckStart start, CancellationToken cancellationToken)
    {
        var run = new StageRun(routeId, start.WallClock);
        var route = target.Route;
        var account = target.Account;

        // Stage 1: configured -- server records only, decided at 0.
        if (!route.Enabled)
        {
            return run.Decide(ConnectivityStage.Configured, ConnectivityResult.Failed, ConnectivityCode.RouteDisabled, 0);
        }
        if (!account.Enabled)
        {
            return run.Decide(ConnectivityStage.Configured, ConnectivityResult.Failed, ConnectivityCode.ClientDisabled, 0);
        }
        if (!TargetValid(route.TargetBaseUrl))
        {
            return run.Decide(ConnectivityStage.Configured, ConnectivityResult.Failed,
                ConnectivityCode.RouteTargetInvalid, 0);
        }
        run.Pass(ConnectivityStage.Configured, ConnectivityCode.Configured, 0);

        // Stage 2 precondition: an authenticated control session and its data connection. No
        // reconnect grace: the check reports the state right now.
        switch (_devices.Presence(account.ClientName))
        {
            case ConnectivityDevicePresence.Offline:
                return run.Decide(ConnectivityStage.DeviceOnline, ConnectivityResult.Failed,
                    ConnectivityCode.DeviceOffline, 0);
            case ConnectivityDevicePresence.DataChannelDown:
                return run.Decide(ConnectivityStage.DeviceOnline, ConnectivityResult.Failed,
                    ConnectivityCode.DeviceDataChannelDown, 0);
        }

        var (head, headAt) = await AskAsync(run, ConnectivityCheck.MethodHead, account.ClientName, route.Route,
            path, start, cancellationToken).ConfigureAwait(false);
        switch (head.Kind)
        {
            case ConnectivityAnswerKind.OpenFailed:
                return run.Decide(ConnectivityStage.DeviceOnline, ConnectivityResult.Failed,
                    head.OpenFailure == ConnectivityOpenFailure.StreamLimit
                        ? ConnectivityCode.DeviceBusy
                        : ConnectivityCode.DeviceLinkLost, headAt);
            case ConnectivityAnswerKind.None:
                // The connection was held and the write succeeded; a device stuck with a live TCP
                // connection cannot be told apart from a target that never answered.
                run.Pass(ConnectivityStage.DeviceOnline, ConnectivityCode.DeviceOnline, ConnectivityCheck.BudgetMs);
                return run.Decide(ConnectivityStage.TargetReachable, ConnectivityResult.Failed,
                    ConnectivityCode.TargetTimeout, ConnectivityCheck.BudgetMs);
            case ConnectivityAnswerKind.LinkLost:
                return run.Decide(ConnectivityStage.DeviceOnline, ConnectivityResult.Failed,
                    ConnectivityCode.DeviceLinkLost, headAt);
            case ConnectivityAnswerKind.Reset:
                if (head.SessionCapability >= HttpRouteFailure.CapabilityVersion
                    && head.Failure is { } failure
                    && RstFailures.TryGetValue(failure, out var classified))
                {
                    if (classified.Stage == ConnectivityStage.DeviceOnline)
                    {
                        return run.Decide(ConnectivityStage.DeviceOnline, ConnectivityResult.Failed,
                            classified.Code, headAt);
                    }
                    run.Pass(ConnectivityStage.DeviceOnline, ConnectivityCode.DeviceOnline, headAt);
                    return run.Decide(ConnectivityStage.TargetReachable, ConnectivityResult.Failed,
                        classified.Code, headAt);
                }
                // An older client, no classification, or one this server does not know: the device
                // answered, but nothing says whether the target was ever reached.
                run.Pass(ConnectivityStage.DeviceOnline, ConnectivityCode.DeviceOnline, headAt);
                return run.Decide(ConnectivityStage.TargetReachable, ConnectivityResult.Unverified,
                    ConnectivityCode.TargetUnverified, headAt);
        }

        run.Pass(ConnectivityStage.DeviceOnline, ConnectivityCode.DeviceOnline, headAt);
        if (head.Status is not int status || !IsAnswerStatus(status))
        {
            // Clients never relay 1xx; a head without a usable status is not an answer.
            return run.Decide(ConnectivityStage.TargetReachable, ConnectivityResult.Failed,
                ConnectivityCode.TargetProtocolError, headAt);
        }
        run.Pass(ConnectivityStage.TargetReachable, ConnectivityCode.TargetAnswered, headAt);

        if (status is not (StatusCodes.Status405MethodNotAllowed or StatusCodes.Status501NotImplemented))
        {
            var (result, code) = AccessCode(status);
            return run.Decide(ConnectivityStage.AccessSucceeded, result, code, headAt, status);
        }

        // HEAD refused by method: exactly one GET, in what is left of the same budget.
        var (get, getAt) = await AskAsync(run, ConnectivityCheck.MethodGet, account.ClientName, route.Route,
            path, start, cancellationToken).ConfigureAwait(false);
        if (get.Kind == ConnectivityAnswerKind.Response && get.Status is int getStatus && IsAnswerStatus(getStatus))
        {
            var (result, code) = AccessCode(getStatus);
            return run.Decide(ConnectivityStage.AccessSucceeded, result, code, getAt, getStatus);
        }
        return run.Decide(ConnectivityStage.AccessSucceeded, ConnectivityResult.Failed,
            ConnectivityCode.AccessNoAnswer, getAt);
    }

    /// <summary>
    /// Sends one probe request and returns the answer with the moment it was decided: elapsed
    /// milliseconds capped at the budget, and exactly the budget for no answer.
    /// </summary>
    private async Task<(ConnectivityProbeAnswer Answer, long AtMs)> AskAsync(StageRun run, string method,
        string clientName, string routeName, string path, ConnectivityCheckStart start,
        CancellationToken cancellationToken)
    {
        run.Requests.Add(method);
        var remainingMs = ConnectivityCheck.BudgetMs - _time.GetElapsedTime(start.Timestamp).TotalMilliseconds;
        if (remainingMs <= 0)
        {
            return (ConnectivityProbeAnswer.NoAnswer(), ConnectivityCheck.BudgetMs);
        }
        var answer = await _devices.ProbeAsync(clientName, ProbeMetadata(method, routeName, path),
            TimeSpan.FromMilliseconds(remainingMs), cancellationToken).ConfigureAwait(false);
        if (answer.Kind == ConnectivityAnswerKind.None)
        {
            return (answer, ConnectivityCheck.BudgetMs);
        }
        var elapsed = (long)_time.GetElapsedTime(start.Timestamp).TotalMilliseconds;
        return (answer, Math.Clamp(elapsed, 0, ConnectivityCheck.BudgetMs));
    }

    /// <summary>
    /// OPEN metadata of a probe (section 5.1): nothing from the admin request, no body, no
    /// credentials, an identifiable User-Agent.
    /// </summary>
    internal static Dictionary<string, object?> ProbeMetadata(string method, string routeName, string path) => new()
    {
        ["source"] = "http",
        ["phase"] = "request",
        ["requestId"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
        ["method"] = method,
        ["route"] = routeName,
        ["relativePath"] = path,
        ["rawQuery"] = string.Empty,
        ["headers"] = new List<string> { "Accept:*/*", "User-Agent:" + ConnectivityCheck.UserAgent },
    };

    private static bool TargetValid(string? targetBaseUrl)
    {
        try
        {
            _ = ManagementMutationService.RequireTargetBaseUrl(targetBaseUrl);
            return true;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsAnswerStatus(int status) => status is >= 200 and <= 599;

    private static (string Result, string Code) AccessCode(int status) => status switch
    {
        >= 200 and <= 399 => (ConnectivityResult.Passed, ConnectivityCode.AccessOk),
        401 or 403 or 407 => (ConnectivityResult.Unverified, ConnectivityCode.AccessAuthRequired),
        404 or 410 => (ConnectivityResult.Failed, ConnectivityCode.AccessNotFound),
        >= 400 and <= 499 => (ConnectivityResult.Failed, ConnectivityCode.AccessClientError),
        _ => (ConnectivityResult.Failed, ConnectivityCode.AccessServerError),
    };

    private long NowMs() => (long)((Int128)_time.GetTimestamp() * 1000 / _time.TimestampFrequency);

    /// <summary>The stages decided so far, in order; finishing fills the rest with skipped.</summary>
    private sealed class StageRun(long routeId, DateTimeOffset checkedAt)
    {
        private readonly List<ConnectivityStageReport> _decided = [];

        public List<string> Requests { get; } = [];

        public void Pass(string stage, string code, long atMs) =>
            _decided.Add(new ConnectivityStageReport(stage, ConnectivityResult.Passed, code, atMs));

        /// <summary>Decides the last stage this check reaches and builds the report.</summary>
        public ConnectivityCheckReport Decide(string stage, string result, string code, long atMs,
            int? answeredStatus = null)
        {
            _decided.Add(new ConnectivityStageReport(stage, result, code, atMs));
            var stages = new List<ConnectivityStageReport>(ConnectivityStage.All.Count);
            foreach (var name in ConnectivityStage.All)
            {
                stages.Add(_decided.FirstOrDefault(entry => entry.Stage == name)
                    ?? new ConnectivityStageReport(name, ConnectivityResult.Skipped, null, null));
            }
            var outcome = result switch
            {
                ConnectivityResult.Passed => ConnectivityOutcome.Succeeded,
                ConnectivityResult.Unverified => ConnectivityOutcome.Unverified,
                _ => ConnectivityOutcome.Failed,
            };
            return new ConnectivityCheckReport(
                routeId,
                checkedAt,
                outcome,
                outcome == ConnectivityOutcome.Succeeded ? null : stage,
                code,
                atMs,
                Requests.ToArray(),
                stages,
                answeredStatus is int status ? $"{status / 100}xx" : null);
        }
    }
}
