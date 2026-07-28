using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Text;

namespace Specus.StunServer;

public sealed class StunMetrics
{
    private readonly long _startedTicks = Stopwatch.GetTimestamp();
    private readonly ConcurrentDictionary<string, long> _drops = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _responses = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, long> _features = new(StringComparer.Ordinal);
    private long _packetsReceived;
    private long _requestsAccepted;
    private long _bytesReceived;
    private long _bytesSent;

    public void RecordPacket(int bytes)
    {
        Interlocked.Increment(ref _packetsReceived);
        Interlocked.Add(ref _bytesReceived, Math.Max(0, bytes));
    }

    public void RecordAcceptedRequest() => Interlocked.Increment(ref _requestsAccepted);

    public void RecordDrop(string reason) => _drops.AddOrUpdate(reason, 1, static (_, value) => value + 1);

    public void RecordResponse(int code, int bytes)
    {
        _responses.AddOrUpdate(
            code.ToString(CultureInfo.InvariantCulture),
            1,
            static (_, value) => value + 1);
        Interlocked.Add(ref _bytesSent, Math.Max(0, bytes));
    }

    public void RecordFeature(string feature) =>
        _features.AddOrUpdate(feature, 1, static (_, value) => value + 1);

    public string Render(int trackedSources)
    {
        var result = new StringBuilder(2_048);
        AppendCounter(
            result,
            "stun_packets_received_total",
            "UDP datagrams received by the STUN service.",
            Interlocked.Read(ref _packetsReceived));
        AppendCounter(
            result,
            "stun_requests_accepted_total",
            "Valid Binding requests accepted for processing.",
            Interlocked.Read(ref _requestsAccepted));
        AppendCounter(
            result,
            "stun_bytes_received_total",
            "UDP payload bytes received by the STUN service.",
            Interlocked.Read(ref _bytesReceived));
        AppendCounter(
            result,
            "stun_bytes_sent_total",
            "STUN response payload bytes sent by the service.",
            Interlocked.Read(ref _bytesSent));
        AppendLabelCounters(
            result,
            "stun_packets_dropped_total",
            "UDP datagrams dropped before a response was sent.",
            "reason",
            _drops);
        AppendLabelCounters(
            result,
            "stun_responses_total",
            "STUN Binding responses sent by response code.",
            "code",
            _responses);
        AppendLabelCounters(
            result,
            "stun_feature_requests_total",
            "Accepted Binding requests using RFC 5780 features.",
            "feature",
            _features);
        result.AppendLine("# HELP stun_tracked_sources Current source IP token buckets.")
            .AppendLine("# TYPE stun_tracked_sources gauge")
            .Append("stun_tracked_sources ")
            .AppendLine(Math.Max(0, trackedSources).ToString(CultureInfo.InvariantCulture));
        result.AppendLine("# HELP stun_uptime_seconds STUN process uptime in seconds.")
            .AppendLine("# TYPE stun_uptime_seconds gauge")
            .Append("stun_uptime_seconds ")
            .AppendLine(
                ((Stopwatch.GetTimestamp() - _startedTicks) / Stopwatch.Frequency)
                .ToString(CultureInfo.InvariantCulture));
        return result.ToString();
    }

    private static void AppendCounter(StringBuilder result, string name, string help, long value) =>
        result.Append("# HELP ").Append(name).Append(' ').AppendLine(help)
            .Append("# TYPE ").Append(name).AppendLine(" counter")
            .Append(name).Append(' ').AppendLine(value.ToString(CultureInfo.InvariantCulture));

    private static void AppendLabelCounters(
        StringBuilder result,
        string name,
        string help,
        string labelName,
        IEnumerable<KeyValuePair<string, long>> counters)
    {
        result.Append("# HELP ").Append(name).Append(' ').AppendLine(help)
            .Append("# TYPE ").Append(name).AppendLine(" counter");
        foreach (var item in counters.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            result.Append(name)
                .Append('{')
                .Append(labelName)
                .Append("=\"")
                .Append(Escape(item.Key))
                .Append("\"} ")
                .AppendLine(item.Value.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static string Escape(string value) =>
        value.Replace("\\", "\\\\", StringComparison.Ordinal)
            .Replace("\"", "\\\"", StringComparison.Ordinal);
}
