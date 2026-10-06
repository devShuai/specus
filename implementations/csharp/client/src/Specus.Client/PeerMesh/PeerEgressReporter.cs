using Specus.Protocol.PeerEgress;

namespace Specus.Client.PeerMesh;

/// <summary>
/// When this egress sends <c>egress-report</c>, and the revision it carries.
/// </summary>
/// <remarks>
/// One per process, checked every <see cref="Interval"/> (protocol/spec/peer-egress.md,
/// <c>egress-report</c>; vector <c>peer-egress-report-v1.json</c>). A check sends when the egress
/// is running and either nothing went out yet in this control session while it was, or a value
/// differs from the last one that did. Otherwise nothing is sent: the server keeps the latest report
/// until a newer one replaces it, so repeating it says nothing new.
///
/// <para>The revision is the wall clock in milliseconds, held strictly increasing. A counter from one
/// would restart below the value the server still holds after this process restarts, and the
/// server ignores a report older than the one it has.</para>
///
/// <para>Time arrives as an argument, so the vector can step it. Not safe for concurrent use; the
/// caller serialises checks.</para>
/// </remarks>
internal sealed class PeerEgressReporter
{
    /// <summary>The vector's <c>intervalSeconds</c>.</summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    private long _revision;

    /// <summary>What went out last in this control session while the egress was running.</summary>
    private PeerEgressReportMessage? _lastSent;

    /// <summary>
    /// A new control session: the next check reports whatever it finds. The server may have
    /// restarted, or lost the row.
    /// </summary>
    public void NewSession() => _lastSent = null;

    /// <summary>
    /// One check. Returns the report to send, or null to send nothing.
    /// </summary>
    /// <param name="wallMs">This machine's wall clock, in Unix milliseconds.</param>
    /// <param name="status">
    /// The egress plane as the local status reads it, or null when there is none. The plane is
    /// running while it holds an <c>enabled: true</c> <c>egress-config</c>; the server sends one only
    /// to a login that announced the egress capability, which this build always does.
    /// </param>
    /// <remarks>
    /// The report is taken as sent once it is returned. A send that fails is logged and not
    /// retried: the next check sends again only if something changed, as the spec asks.
    /// </remarks>
    public PeerEgressReportMessage? Check(long wallMs, PeerEgressRuntimeStatus? status)
    {
        if (status is not { Enabled: true })
        {
            // Switched off, or never on. The first check after it runs again reports.
            _lastSent = null;
            return null;
        }
        var values = new PeerEgressReportMessage(0, status.Flows, status.TotalFlows, status.Refused,
            status.BytesIn, status.BytesOut);
        if (values.SameValues(_lastSent))
        {
            return null;
        }
        // A clock stepped back must not walk the revision back with it.
        _revision = Math.Max(_revision + 1, wallMs);
        _lastSent = values with { Revision = _revision };
        return _lastSent;
    }
}
