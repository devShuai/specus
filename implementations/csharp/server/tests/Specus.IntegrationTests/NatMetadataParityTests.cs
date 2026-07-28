using System.Reflection;

namespace Specus.IntegrationTests;

public sealed class NatMetadataParityTests
{
    private static readonly Type NatClientSessionType = Type.GetType(
        "Specus.Server.Nat.NatClientSession, Specus.Server",
        throwOnError: true)!;

    private static readonly MethodInfo AsStringMethod = NatClientSessionType.GetMethod(
        "AsString",
        BindingFlags.NonPublic | BindingFlags.Static)!;

    private static readonly MethodInfo AsIntMethod = NatClientSessionType.GetMethod(
        "AsInt",
        BindingFlags.NonPublic | BindingFlags.Static)!;

    [Fact]
    public void MetadataHelpersMatchJavaCoercion()
    {
        var meta = new Dictionary<string, object?>
        {
            ["channelId"] = 12345,
            ["enabled"] = true,
            ["stringPort"] = "10022",
            ["doublePort"] = 10023.9d,
            ["longPort"] = 10024L,
        };

        Assert.Equal("12345", InvokeAsString(meta, "channelId"));
        Assert.Equal("true", InvokeAsString(meta, "enabled"));
        Assert.Equal(10022, InvokeAsInt(meta, "stringPort"));
        Assert.Equal(10023, InvokeAsInt(meta, "doublePort"));
        Assert.Equal(10024, InvokeAsInt(meta, "longPort"));
    }

    private static string? InvokeAsString(Dictionary<string, object?> meta, string key)
    {
        return (string?)AsStringMethod.Invoke(null, new object?[] { meta, key });
    }

    private static int? InvokeAsInt(Dictionary<string, object?> meta, string key)
    {
        return (int?)AsIntMethod.Invoke(null, new object?[] { meta, key });
    }
}
