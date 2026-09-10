using System.Text.Json;
using Specus.Protocol.PeerEgress;

namespace Specus.Protocol.Tests;

/// <summary>
/// Replays <c>peer-egress-control-v1.json</c> against the .NET <c>egress-config</c> decoder.
/// </summary>
/// <remarks>
/// The push is produced by three server implementations and read by three clients. Its expectations
/// come from an independent reference decoder in the generator rather than from any implementation,
/// so agreeing with it is independent agreement.
/// </remarks>
public class PeerEgressControlVectorTests
{
    private static JsonDocument ReadVector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(
                directory.FullName, "protocol", "test-vectors", "peer-egress-control-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-control-v1.json");
    }

    [Fact]
    public void EgressConfigDecodeMatchesSharedVector()
    {
        using var vector = ReadVector();
        var section = vector.RootElement.GetProperty("egressConfig");
        var accept = section.GetProperty("accept");
        var reject = section.GetProperty("reject");
        Assert.True(accept.GetArrayLength() > 0, "control vector carried no accept cases");
        Assert.True(reject.GetArrayLength() > 0, "control vector carried no reject cases");

        foreach (var testCase in accept.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            var decoded = PeerEgressConfigMessage.Decode(testCase.GetProperty("message").GetString());
            Assert.True(decoded is not null, $"{name}: the message was refused");

            var expect = testCase.GetProperty("expect");
            Assert.True(expect.GetProperty("revision").GetInt64() == decoded!.Revision, $"{name}: revision");

            var want = expect.GetProperty("policy");
            var policy = decoded.Policy;
            Assert.True(want.GetProperty("enabled").GetBoolean() == policy.Enabled, $"{name}: enabled");
            Assert.True(want.GetProperty("scope").GetString() == policy.Scope, $"{name}: scope");
            Assert.True(
                want.GetProperty("allowedConsumerClientIds").GetArrayLength() == policy.AllowedConsumerClientIds.Count,
                $"{name}: consumers");

            var wantRules = want.GetProperty("destinationRules");
            Assert.True(wantRules.GetArrayLength() == policy.DestinationRules.Count,
                $"{name}: destination rules");
            var index = 0;
            foreach (var expectedRule in wantRules.EnumerateArray())
            {
                var rule = policy.DestinationRules[index];
                Assert.True(expectedRule.GetProperty("cidr").GetString() == rule.Cidr,
                    $"{name}: rule {index} cidr");
                Assert.True(expectedRule.GetProperty("protocols").GetArrayLength() == rule.Protocols.Count,
                    $"{name}: rule {index} protocols");
                Assert.True(expectedRule.GetProperty("portRanges").GetArrayLength() == rule.PortRanges.Count,
                    $"{name}: rule {index} port ranges");
                index++;
            }

            var limits = want.GetProperty("limits");
            Assert.True(limits.GetProperty("maxConcurrentFlows").GetInt32() == policy.Limits.MaxConcurrentFlows,
                $"{name}: maxConcurrentFlows");
            Assert.True(limits.GetProperty("maxFlowsPerConsumer").GetInt32() == policy.Limits.MaxFlowsPerConsumer,
                $"{name}: maxFlowsPerConsumer");
            Assert.True(limits.GetProperty("idleTimeoutSeconds").GetInt32() == policy.Limits.IdleTimeoutSeconds,
                $"{name}: idleTimeoutSeconds");
        }

        foreach (var testCase in reject.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            Assert.True(PeerEgressConfigMessage.Decode(testCase.GetProperty("message").GetString()) is null,
                $"{name}: the message was accepted");
        }
    }
}
