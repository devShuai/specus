using System.Text.Json;
using Specus.Client.PeerMesh;
using Segment = Specus.Client.PeerMesh.PeerEgressSegment.Segment;

namespace Specus.Client.Tests;

/// <summary>
/// Replays <c>peer-egress-tcp-v1.json</c> against the .NET user-space TCP stack.
/// </summary>
/// <remarks>
/// The fixture is the same one Go and Java assert against, so this is what "three runtimes agree"
/// means in practice. Its expectations were recorded from the Go stack, so passing here proves
/// agreement rather than independent correctness; the argument for the behaviour itself lives
/// beside the Go implementation, case by case against the RFCs.
/// </remarks>
public class PeerEgressTcpVectorTests
{
    private static JsonDocument ReadVector(string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException($"cannot locate {name}");
    }

    private static uint ParseAddress(string dotted)
    {
        uint value = 0;
        foreach (var part in dotted.Split('.'))
        {
            value = (value << 8) | byte.Parse(part);
        }
        return value;
    }

    private static int FlagsOf(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Array)
        {
            return 0;
        }
        var flags = 0;
        foreach (var entry in element.EnumerateArray())
        {
            flags |= entry.GetString()!.ToUpperInvariant() switch
            {
                "FIN" => PeerEgressSegment.FlagFin,
                "SYN" => PeerEgressSegment.FlagSyn,
                "RST" => PeerEgressSegment.FlagRst,
                "PSH" => PeerEgressSegment.FlagPsh,
                "ACK" => PeerEgressSegment.FlagAck,
                _ => 0
            };
        }
        return flags;
    }

    private static List<string> FlagNames(int flags)
    {
        var names = new List<string>(3);
        if ((flags & PeerEgressSegment.FlagFin) != 0) { names.Add("FIN"); }
        if ((flags & PeerEgressSegment.FlagSyn) != 0) { names.Add("SYN"); }
        if ((flags & PeerEgressSegment.FlagRst) != 0) { names.Add("RST"); }
        if ((flags & PeerEgressSegment.FlagPsh) != 0) { names.Add("PSH"); }
        if ((flags & PeerEgressSegment.FlagAck) != 0) { names.Add("ACK"); }
        return names;
    }

    private static byte[] DecodeHex(JsonElement parent, string property)
    {
        if (!parent.TryGetProperty(property, out var element)
            || element.ValueKind != JsonValueKind.String)
        {
            return [];
        }
        var text = element.GetString();
        return string.IsNullOrEmpty(text) ? [] : Convert.FromHexString(text);
    }

    private static string HexOf(byte[] data) =>
        data.Length == 0 ? "" : Convert.ToHexString(data).ToLowerInvariant();

    private static long OptionalLong(JsonElement parent, string property, long fallback = 0) =>
        parent.TryGetProperty(property, out var element) && element.ValueKind == JsonValueKind.Number
            ? element.GetInt64()
            : fallback;

    private static bool OptionalBool(JsonElement parent, string property) =>
        parent.TryGetProperty(property, out var element) && element.ValueKind == JsonValueKind.True;

    [Fact]
    public void TcpStackMatchesSharedVector()
    {
        using var vector = ReadVector("peer-egress-tcp-v1.json");
        var root = vector.RootElement;
        var parameters = root.GetProperty("params");

        var localIp = ParseAddress(parameters.GetProperty("egressIp").GetString()!);
        var remoteIp = ParseAddress(parameters.GetProperty("consumerIp").GetString()!);
        var consumerPort = (ushort)parameters.GetProperty("consumerPort").GetInt32();
        var targetPort = (ushort)parameters.GetProperty("targetPort").GetInt32();
        var pathMtu = parameters.GetProperty("pathMtu").GetInt32();
        var idleTimeoutMs = parameters.GetProperty("idleTimeoutMs").GetInt64();
        var iss = (uint)parameters.GetProperty("iss").GetInt64();
        var epochMs = parameters.GetProperty("epochMs").GetInt64();

        var cases = root.GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "vector carried no cases");

        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            PeerEgressTcpConnection? connection = null;
            var nowMs = epochMs;
            var stepIndex = 0;

            foreach (var step in testCase.GetProperty("steps").EnumerateArray())
            {
                nowMs += OptionalLong(step, "advanceMs");
                var action = step.GetProperty("do").GetString();
                var output = new PeerEgressTcpConnection.Output();

                switch (action)
                {
                    case "segment":
                        var segment = new Segment(
                            remoteIp, localIp, consumerPort, targetPort,
                            (uint)OptionalLong(step, "seq"),
                            (uint)OptionalLong(step, "ack"),
                            step.TryGetProperty("flags", out var flags) ? FlagsOf(flags) : 0,
                            (int)OptionalLong(step, "window"),
                            (int)OptionalLong(step, "mss"),
                            DecodeHex(step, "payloadHex"));
                        if (connection is null)
                        {
                            connection = PeerEgressTcpConnection.Accept(
                                segment, iss, pathMtu, idleTimeoutMs, nowMs, output);
                        }
                        else
                        {
                            output = connection.OnSegment(segment, nowMs);
                        }
                        break;
                    case "appData":
                        output = connection!.OnAppData(DecodeHex(step, "dataHex"), nowMs);
                        break;
                    case "appClose":
                        output = connection!.OnAppClose(nowMs);
                        break;
                    case "abort":
                        output = connection!.Abort();
                        break;
                    case "tick":
                        output = connection!.OnTick(nowMs);
                        break;
                    default:
                        throw new InvalidOperationException($"unknown step {action}");
                }

                AssertStep(name, stepIndex, step.GetProperty("expect"), connection!, output);
                stepIndex++;
            }
        }
    }

    private static void AssertStep(
        string name,
        int index,
        JsonElement expect,
        PeerEgressTcpConnection connection,
        PeerEgressTcpConnection.Output output)
    {
        var where = $"{name} step {index}";

        // The fixture spells states the way Go does; .NET spells them the way .NET does.
        var expectedState = expect.GetProperty("state").GetString()!.Replace("_", "");
        Assert.True(
            string.Equals(expectedState, connection.CurrentState.ToString(), StringComparison.OrdinalIgnoreCase),
            $"{where} state: {connection.CurrentState}, want {expect.GetProperty("state").GetString()}");

        Assert.Equal(
            expect.TryGetProperty("deliverHex", out var deliver) ? deliver.GetString() : "",
            HexOf(output.Deliver));
        Assert.Equal(OptionalBool(expect, "closeApp"), output.CloseApp);
        Assert.Equal(OptionalBool(expect, "done"), output.Done);
        Assert.Equal(OptionalBool(expect, "reset"), output.Reset);

        var expectedSegments = expect.GetProperty("segments");
        Assert.True(
            expectedSegments.GetArrayLength() == output.Segments.Count,
            $"{where} emitted {output.Segments.Count} segments, want {expectedSegments.GetArrayLength()}");

        var position = 0;
        foreach (var wanted in expectedSegments.EnumerateArray())
        {
            var produced = PeerEgressSegment.Parse(output.Segments[position]);
            Assert.True(produced is not null, $"{where} emitted a segment it cannot parse back");
            var at = $"{where} segment {position}";

            // Compared as names, so a mismatch reads as SYN|ACK rather than as a bitmask.
            Assert.Equal(FlagNames(FlagsOf(wanted.GetProperty("flags"))), FlagNames(produced!.Flags));
            Assert.True((uint)wanted.GetProperty("seq").GetInt64() == produced.Seq, $"{at} seq");
            Assert.True((uint)wanted.GetProperty("ack").GetInt64() == produced.Ack, $"{at} ack");
            Assert.True(wanted.GetProperty("window").GetInt32() == produced.Window, $"{at} window");
            Assert.True((int)OptionalLong(wanted, "mss") == produced.Mss, $"{at} mss");
            Assert.Equal(
                wanted.TryGetProperty("payloadHex", out var payload) ? payload.GetString() : "",
                HexOf(produced.Payload));
            position++;
        }
    }
}
