using System.Text.Json;
using System.Text.Json.Serialization;
using Specus.Protocol.HttpRoute;

namespace Specus.Protocol.Tests;

/// <summary>
/// The failure names are the contract with every server, which keys its connectivity-check stage
/// codes on them; the shared vector lists the closed set.
/// </summary>
public sealed class HttpRouteFailureVectorTests
{
    [Fact]
    public void FailuresAreTheConnectivityVectorSet()
    {
        var vector = ReadVector("service-connectivity-check-v1.json");

        Assert.Equal(vector.RstFailures.Keys.Order(StringComparer.Ordinal),
            HttpRouteFailure.All.Order(StringComparer.Ordinal));
        Assert.Equal(HttpRouteFailure.All.Count, HttpRouteFailure.All.Distinct().Count());
    }

    private static ConnectivityVector ReadVector(string name)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; directory is not null && depth < 12; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", name);
            if (File.Exists(candidate))
            {
                return JsonSerializer.Deserialize<ConnectivityVector>(File.ReadAllText(candidate))
                    ?? throw new InvalidDataException($"{name} decoded to null");
            }
        }
        throw new FileNotFoundException($"cannot locate {name}");
    }

    private sealed record ConnectivityVector
    {
        [JsonPropertyName("rstFailures")]
        public Dictionary<string, JsonElement> RstFailures { get; init; } = [];
    }
}
