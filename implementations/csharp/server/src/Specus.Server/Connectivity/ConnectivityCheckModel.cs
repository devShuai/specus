using System.Globalization;
using System.Text;
using System.Text.Json;
using Specus.Server.Data.Entities;

namespace Specus.Server.Connectivity;

/// <summary>
/// Fixed values of the HTTP route connectivity check (protocol/spec/service-connectivity-check.md).
/// They are part of the contract and the shared vector, not configuration.
/// </summary>
internal static class ConnectivityCheck
{
    public const int SchemaVersion = 1;
    public const string Kind = "http-route";

    /// <summary>One budget for HEAD and the optional GET, from the start of request handling.</summary>
    public const long BudgetMs = 10_000;

    public const string DefaultPath = "/";
    public const int MaxPathBytes = 256;
    public const int MaxBodyBytes = 4096;
    public const string CacheControl = "private, no-store";
    public const string UserAgent = "specus-connectivity-check/1";

    /// <summary>RST value the server ends a probe stream with; clients do not read it.</summary>
    public const uint ProbeResetCode = 1;

    public const string MethodHead = "HEAD";
    public const string MethodGet = "GET";
}

internal static class ConnectivityStage
{
    public const string Configured = "configured";
    public const string DeviceOnline = "device-online";
    public const string TargetReachable = "target-reachable";
    public const string AccessSucceeded = "access-succeeded";

    public static IReadOnlyList<string> All { get; } =
        [Configured, DeviceOnline, TargetReachable, AccessSucceeded];
}

internal static class ConnectivityResult
{
    public const string Passed = "passed";
    public const string Failed = "failed";
    public const string Unverified = "unverified";
    public const string Skipped = "skipped";
}

internal static class ConnectivityOutcome
{
    public const string Succeeded = "succeeded";
    public const string Failed = "failed";
    public const string Unverified = "unverified";
}

/// <summary>Stage codes and API refusal codes.</summary>
internal static class ConnectivityCode
{
    public const string Configured = "CONFIGURED";
    public const string RouteDisabled = "ROUTE_DISABLED";
    public const string ClientDisabled = "CLIENT_DISABLED";
    public const string RouteTargetInvalid = "ROUTE_TARGET_INVALID";

    public const string DeviceOnline = "DEVICE_ONLINE";
    public const string DeviceOffline = "DEVICE_OFFLINE";
    public const string DeviceDataChannelDown = "DEVICE_DATA_CHANNEL_DOWN";
    public const string DeviceBusy = "DEVICE_BUSY";
    public const string DeviceRouteNotLoaded = "DEVICE_ROUTE_NOT_LOADED";
    public const string DeviceLinkLost = "DEVICE_LINK_LOST";

    public const string TargetAnswered = "TARGET_ANSWERED";
    public const string TargetConnectRefused = "TARGET_CONNECT_REFUSED";
    public const string TargetConnectTimeout = "TARGET_CONNECT_TIMEOUT";
    public const string TargetDnsFailed = "TARGET_DNS_FAILED";
    public const string TargetTlsFailed = "TARGET_TLS_FAILED";
    public const string TargetUnreachable = "TARGET_UNREACHABLE";
    public const string TargetAddressInvalid = "TARGET_ADDRESS_INVALID";
    public const string TargetProtocolError = "TARGET_PROTOCOL_ERROR";
    public const string TargetTimeout = "TARGET_TIMEOUT";
    public const string TargetUnverified = "TARGET_UNVERIFIED";

    public const string AccessOk = "ACCESS_OK";
    public const string AccessAuthRequired = "ACCESS_AUTH_REQUIRED";
    public const string AccessNotFound = "ACCESS_NOT_FOUND";
    public const string AccessClientError = "ACCESS_CLIENT_ERROR";
    public const string AccessServerError = "ACCESS_SERVER_ERROR";
    public const string AccessNoAnswer = "ACCESS_NO_ANSWER";

    public const string RequestInvalid = "CHECK_REQUEST_INVALID";
    public const string Unavailable = "CHECK_UNAVAILABLE";
    public const string TargetNotFound = "CHECK_TARGET_NOT_FOUND";
    public const string InProgress = "CHECK_IN_PROGRESS";
    public const string Busy = "CHECK_BUSY";
    public const string RateLimited = "CHECK_RATE_LIMITED";
}

/// <summary>A route row together with the client account that owns it.</summary>
internal sealed record ConnectivityRouteTarget(HttpRouteMapping Route, ClientAccount Account);

/// <summary>Reads the route a check is about. Tests substitute an in-memory store.</summary>
internal interface IConnectivityRouteSource
{
    /// <summary>
    /// The route and its client, or null when either does not exist. Throws when the store cannot
    /// be read; the check then answers <c>CHECK_UNAVAILABLE</c>, never "not configured".
    /// </summary>
    Task<ConnectivityRouteTarget?> FindAsync(long routeId, CancellationToken cancellationToken);
}

internal enum ConnectivityDevicePresence
{
    /// <summary>No authenticated control session for the client name in this process.</summary>
    Offline,

    /// <summary>A control session, but no data connection bound to it.</summary>
    DataChannelDown,

    Online,
}

internal enum ConnectivityAnswerKind
{
    /// <summary>The device relayed a response head.</summary>
    Response,

    /// <summary>The device reset the stream before any response head.</summary>
    Reset,

    /// <summary>The data connection closed or was replaced before any answer.</summary>
    LinkLost,

    /// <summary>The probe stream could not be handed to the device.</summary>
    OpenFailed,

    /// <summary>No answer within the budget; the probe stream has been reset.</summary>
    None,
}

internal enum ConnectivityOpenFailure
{
    /// <summary>Writing OPEN or the request FIN failed, or the data connection vanished.</summary>
    WriteFailed,

    /// <summary>The data connection already carries the server's maximum of streams.</summary>
    StreamLimit,
}

/// <summary>
/// What the device did with one probe request. For a reset, <see cref="Failure"/> is the RST
/// <c>metadata.failure</c> and <see cref="SessionCapability"/> the HTTP route capability version
/// announced by the session owning the connection the probe ran on; never the reason text.
/// </summary>
internal readonly record struct ConnectivityProbeAnswer(
    ConnectivityAnswerKind Kind,
    int? Status = null,
    string? Failure = null,
    int SessionCapability = 0,
    ConnectivityOpenFailure OpenFailure = ConnectivityOpenFailure.WriteFailed)
{
    public static ConnectivityProbeAnswer Response(int? status) => new(ConnectivityAnswerKind.Response, status);

    public static ConnectivityProbeAnswer Reset(string? failure, int sessionCapability) =>
        new(ConnectivityAnswerKind.Reset, Failure: failure, SessionCapability: sessionCapability);

    public static ConnectivityProbeAnswer LinkLost() => new(ConnectivityAnswerKind.LinkLost);

    public static ConnectivityProbeAnswer NotOpened(ConnectivityOpenFailure failure) =>
        new(ConnectivityAnswerKind.OpenFailed, OpenFailure: failure);

    public static ConnectivityProbeAnswer NoAnswer() => new(ConnectivityAnswerKind.None);
}

/// <summary>
/// The device side of a check: who is online in this process, and one probe exchange on the
/// device's data connection. Tests substitute a scripted device.
/// </summary>
internal interface IConnectivityDeviceGateway
{
    ConnectivityDevicePresence Presence(string clientName);

    /// <summary>
    /// Opens one HTTP stream with <paramref name="metadata"/> on the client's data connection,
    /// ends the request at once and waits at most <paramref name="budget"/> for the first answer.
    /// The stream is over when this returns: reset unless it already ended both ways, its body
    /// never read. Cancellation of <paramref name="cancellationToken"/> resets the stream and
    /// propagates.
    /// </summary>
    Task<ConnectivityProbeAnswer> ProbeAsync(string clientName, Dictionary<string, object?> metadata,
        TimeSpan budget, CancellationToken cancellationToken);
}

/// <summary>The instant request handling began: the budget's monotonic origin and checkedAt.</summary>
internal readonly record struct ConnectivityCheckStart(long Timestamp, DateTimeOffset WallClock)
{
    public static ConnectivityCheckStart Now(TimeProvider time) => new(time.GetTimestamp(), time.GetUtcNow());
}

internal sealed record ConnectivityStageReport(string Stage, string Result, string? Code, long? AtMs);

/// <summary>The 200 body of a check that ran, written in the contract's key order.</summary>
internal sealed record ConnectivityCheckReport(
    long RouteId,
    DateTimeOffset CheckedAt,
    string Outcome,
    string? StoppedAt,
    string Code,
    long TotalMs,
    IReadOnlyList<string> Requests,
    IReadOnlyList<ConnectivityStageReport> Stages,
    string? StatusClass)
{
    public string ToJson()
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber("schemaVersion", ConnectivityCheck.SchemaVersion);
            writer.WriteString("kind", ConnectivityCheck.Kind);
            writer.WriteNumber("routeId", RouteId);
            writer.WriteString("checkedAt", FormatCheckedAt(CheckedAt));
            writer.WriteString("outcome", Outcome);
            if (StoppedAt is null)
            {
                writer.WriteNull("stoppedAt");
            }
            else
            {
                writer.WriteString("stoppedAt", StoppedAt);
            }
            writer.WriteString("code", Code);
            writer.WriteNumber("totalMs", TotalMs);
            writer.WriteStartArray("requests");
            foreach (var method in Requests)
            {
                writer.WriteStringValue(method);
            }
            writer.WriteEndArray();
            writer.WriteStartArray("stages");
            foreach (var stage in Stages)
            {
                writer.WriteStartObject();
                writer.WriteString("stage", stage.Stage);
                writer.WriteString("result", stage.Result);
                if (stage.Code is not null)
                {
                    writer.WriteString("code", stage.Code);
                }
                if (stage.AtMs is { } atMs)
                {
                    writer.WriteNumber("atMs", atMs);
                }
                writer.WriteEndObject();
            }
            writer.WriteEndArray();
            if (StatusClass is not null)
            {
                writer.WriteString("statusClass", StatusClass);
            }
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>UTC, RFC 3339, whole seconds: <c>2026-10-06T08:00:00Z</c>.</summary>
    public static string FormatCheckedAt(DateTimeOffset value) =>
        value.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
}

/// <summary>What the endpoint answers: a refusal <c>{"code":...}</c> or a report.</summary>
internal sealed record ConnectivityCheckResult(int HttpStatus, string? Code, int? RetryAfterSeconds,
    ConnectivityCheckReport? Report)
{
    public static ConnectivityCheckResult Refuse(int httpStatus, string code, int? retryAfterSeconds = null) =>
        new(httpStatus, code, retryAfterSeconds, null);

    public static ConnectivityCheckResult Ran(ConnectivityCheckReport report) =>
        new(StatusCodes.Status200OK, null, null, report);

    public string BodyJson() => Report is not null
        ? Report.ToJson()
        : JsonSerializer.Serialize(new Dictionary<string, string> { ["code"] = Code ?? string.Empty });
}
