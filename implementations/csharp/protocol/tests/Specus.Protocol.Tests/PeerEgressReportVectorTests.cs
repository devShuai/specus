using System.Text.Json;
using System.Text.Json.Nodes;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Binds the <c>egress-report</c> body to <c>peer-egress-report-v1.json</c>.
/// </summary>
/// <remarks>
/// Only the body: given the egress section and the revision a report was sent with, the encoder
/// writes what the vector says. When a report goes out is the client's reporter, replayed against
/// the same vector in the client's own tests.
/// </remarks>
public class PeerEgressReportVectorTests
{
    private static JsonDocument ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "protocol", "test-vectors", "peer-egress-report-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-report-v1.json");
    }

    private static PeerEgressReportMessage From(long revision, JsonElement egress) => new(
        revision,
        egress.GetProperty("flows").GetInt64(),
        egress.GetProperty("totalFlows").GetInt64(),
        egress.GetProperty("refused").EnumerateObject().ToDictionary(entry => entry.Name, entry => entry.Value.GetInt64()),
        egress.GetProperty("bytesIn").GetInt64(),
        egress.GetProperty("bytesOut").GetInt64());

    [Fact]
    public void EncodesEveryReportOfTheSharedVector()
    {
        using var vector = ReadVector();
        var encoded = 0;
        foreach (var step in vector.RootElement.GetProperty("events").EnumerateArray())
        {
            if (!step.TryGetProperty("report", out var expected) || expected.ValueKind == JsonValueKind.Null)
            {
                continue;
            }
            var body = From(expected.GetProperty("revision").GetInt64(), step.GetProperty("egress")).Encode();
            Assert.True(JsonNode.DeepEquals(JsonNode.Parse(body), JsonNode.Parse(expected.GetRawText())),
                $"encoded {body}, the vector sends {expected.GetRawText()}");
            encoded++;
        }
        Assert.True(encoded > 0, "the vector carried no report");
    }

    /// <summary>
    /// Two reports that would show the same numbers are the same whatever their revisions, and a
    /// code counted zero times is not a number the page shows.
    /// </summary>
    [Fact]
    public void ComparesTheValuesAsSent()
    {
        var sent = new PeerEgressReportMessage(5, 1, 6, new Dictionary<string, long> { ["EGRESS_DEST_DENIED"] = 1 }, 5000, 1300);

        Assert.True(sent.SameValues(sent with
        {
            Revision = 9,
            RejectedFlows = new Dictionary<string, long> { ["EGRESS_SCOPE_DENIED"] = 0, ["EGRESS_DEST_DENIED"] = 1 },
        }), "a zero count or a new revision read as a change");
        Assert.False(sent.SameValues(sent with { BytesOut = 1301 }), "a byte count change was missed");
        Assert.False(sent.SameValues(sent with
        {
            RejectedFlows = new Dictionary<string, long> { ["EGRESS_DEST_DENIED"] = 2 },
        }), "a refusal count change was missed");
        Assert.False(sent.SameValues(null), "nothing sent yet read as the same");
    }
}
