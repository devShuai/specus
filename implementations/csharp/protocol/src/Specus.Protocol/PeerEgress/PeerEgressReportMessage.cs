using System.Text;
using System.Text.Json;

namespace Specus.Protocol.PeerEgress;

/// <summary>
/// The <c>egress-report</c> an egress sends the server, for the admin activity page.
/// </summary>
/// <remarks>
/// Running totals, the same numbers as the egress section of the local status, not counts for an
/// interval: the server keeps only the latest report of each egress, so an interval would leave the
/// page describing "since the last report" and frozen there whenever the reports stop.
///
/// <para>Nothing here says who sent it. The server binds the reporter from the authenticated control
/// connection and refuses a report that carries any <c>sourceClient*</c>, <c>targetClient*</c>,
/// <c>sessionId</c> or <c>token</c>, an explicit null included, so the body has no such field to
/// leave out by mistake.</para>
///
/// <para>Shared vector: <c>protocol/test-vectors/peer-egress-report-v1.json</c>; rules in
/// protocol/spec/peer-egress.md, <c>egress-report</c>.</para>
/// </remarks>
/// <param name="Revision">Wall-clock milliseconds, kept strictly increasing by the sender.</param>
/// <param name="ActiveFlows">The status's <c>flows</c>.</param>
/// <param name="RejectedFlows">
/// The status's <c>refused</c>. A code counted zero times is not sent: a row of zeros buries the one
/// that happened.
/// </param>
public sealed record PeerEgressReportMessage(
    long Revision,
    long ActiveFlows,
    long TotalFlows,
    IReadOnlyDictionary<string, long> RejectedFlows,
    long BytesIn,
    long BytesOut)
{
    public const string Type = "egress-report";

    /// <summary>The message body, sent as a PEER_CONTROL message to the server.</summary>
    public string Encode()
    {
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer))
        {
            writer.WriteStartObject();
            writer.WriteString("type", Type);
            writer.WriteNumber("revision", Revision);
            writer.WriteNumber("activeFlows", ActiveFlows);
            writer.WriteNumber("totalFlows", TotalFlows);
            writer.WriteStartObject("rejectedFlows");
            foreach (var (code, count) in Rejected())
            {
                writer.WriteNumber(code, count);
            }
            writer.WriteEndObject();
            writer.WriteNumber("bytesIn", BytesIn);
            writer.WriteNumber("bytesOut", BytesOut);
            writer.WriteEndObject();
        }
        return Encoding.UTF8.GetString(buffer.ToArray());
    }

    /// <summary>
    /// Whether the two would show the same numbers, revision aside. Compared as sent, so a code
    /// counted zero times is no difference.
    /// </summary>
    public bool SameValues(PeerEgressReportMessage? other) =>
        other is not null
        && ActiveFlows == other.ActiveFlows
        && TotalFlows == other.TotalFlows
        && BytesIn == other.BytesIn
        && BytesOut == other.BytesOut
        && Rejected().SequenceEqual(other.Rejected());

    private IEnumerable<KeyValuePair<string, long>> Rejected() =>
        RejectedFlows
            .Where(entry => entry.Value > 0)
            .OrderBy(entry => entry.Key, StringComparer.Ordinal);
}
