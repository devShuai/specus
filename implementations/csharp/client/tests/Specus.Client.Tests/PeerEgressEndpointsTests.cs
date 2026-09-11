using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// This deployment's endpoints, and this host's own networks.
/// </summary>
/// <remarks>
/// The derivation is driven by the shared vector because three clients holding the same
/// configuration must produce the same forced-deny list: one that missed an endpoint would forward
/// to it while the others refused.
/// </remarks>
public class PeerEgressEndpointsTests
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
    public void DeploymentDenyCidrsMatchTheSharedVector()
    {
        using var vector = ReadVector();
        var cases = vector.RootElement.GetProperty("deploymentEndpoints").GetProperty("cases");
        Assert.True(cases.GetArrayLength() > 0, "control vector carried no deployment endpoint cases");

        foreach (var testCase in cases.EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString()!;
            var input = testCase.GetProperty("input");
            var expected = testCase.GetProperty("expect").EnumerateArray()
                .Select(entry => entry.GetString() ?? string.Empty).ToList();

            var got = PeerEgressEndpoints.DeploymentDenyCidrs(
                input.GetProperty("serverBaseUrl").GetString(),
                input.GetProperty("stunHost").GetString(),
                input.GetProperty("turnHost").GetString(),
                input.GetProperty("relayAddress").GetString());

            Assert.True(expected.SequenceEqual(got), $"{name}: derived {string.Join(", ", got)}");
        }
    }

    /// <summary>
    /// An interface address is masked down to its network before it is used. Recording the address
    /// itself would deny one host where the whole network has to be denied, since the loop this
    /// guards against is reaching anything on the network the interface sits on.
    /// </summary>
    [Fact]
    public void InterfaceAddressesAreMaskedToTheirNetwork()
    {
        Assert.Equal("192.168.1.0/24", PeerEgressEndpoints.NetworkOf(Address("192.168.1.44"), 24));
        Assert.Equal("10.0.0.0/8", PeerEgressEndpoints.NetworkOf(Address("10.7.3.1"), 8));
        Assert.Equal("203.0.113.9/32", PeerEgressEndpoints.NetworkOf(Address("203.0.113.9"), 32));
        // A zero-length prefix would be the whole internet. Masking has to produce 0.0.0.0/0 rather
        // than shifting by 32, which is a no-op on a 32-bit value rather than a wipe.
        Assert.Equal("0.0.0.0/0", PeerEgressEndpoints.NetworkOf(Address("203.0.113.9"), 0));
    }

    /// <summary>Whatever this host reports, the result has to be prefixes the judgment layer can parse.</summary>
    [Fact]
    public void LocalInterfacesAreReportedAsUsablePrefixes()
    {
        foreach (var cidr in PeerEgressEndpoints.LocalInterfaceCidrs())
        {
            Assert.True(Ipv4Cidr.TryParse(cidr, out _),
                $"{cidr} is not a prefix the judgment layer can read");
        }
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }
}
