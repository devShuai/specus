using System.Text;
using System.Text.Json;
using Specus.Client.PeerMesh;
using Specus.Protocol.PeerEgress;

namespace Specus.Client.Tests;

/// <summary>
/// Phase two on the egress side, bound to <c>peer-egress-dns-v1.json</c>: the name-bind a consumer
/// sends, and the address an egress picks for a name.
/// </summary>
public class PeerEgressNamesTests
{
    private static JsonDocument Vector()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, "protocol", "test-vectors", "peer-egress-dns-v1.json");
            if (File.Exists(candidate))
            {
                return JsonDocument.Parse(File.ReadAllText(candidate));
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("cannot locate peer-egress-dns-v1.json");
    }

    private static uint Address(string dotted)
    {
        Assert.True(Ipv4Cidr.TryParseAddress(dotted, out var value), $"{dotted} did not parse");
        return value;
    }

    /// <summary>name-bind is encoded byte for byte as the other runtimes encode it, with the name normalised.</summary>
    [Fact]
    public void NameBindMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("nameBind").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var body = PeerEgressFrame.EncodeControl(PeerEgressFrame.Control.NameBind(
                testCase.GetProperty("address").GetString()!, testCase.GetProperty("domain").GetString()!));
            Assert.True(testCase.GetProperty("json").GetString() == Encoding.UTF8.GetString(body), name);
            var frame = PeerEgressFrame.Parse(PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, body));
            Assert.True(frame.Accepted, $"{name}: the encoded binding does not validate: {frame.Code}");
        }
    }

    /// <summary>
    /// The egress dials the first resolved address the policy allows. This build resolves IPv4 only
    /// and does not announce IPv6 targets, so a case that expects an AAAA address is one it answers as
    /// unresolved; every other case must match the vector exactly.
    /// </summary>
    [Fact]
    public void AddressChoiceMatchesTheSharedVector()
    {
        using var vector = Vector();
        foreach (var testCase in vector.RootElement.GetProperty("egressChoice").EnumerateArray())
        {
            var name = testCase.GetProperty("name").GetString();
            var a = testCase.GetProperty("a").EnumerateArray().Select(item => Address(item.GetString()!)).ToList();
            var aaaa = testCase.GetProperty("aaaa").GetArrayLength();
            var decisions = testCase.GetProperty("decisions");
            var choice = PeerEgressRuntime.ChooseAddress(a, address =>
            {
                var code = decisions.GetProperty(Ipv4Cidr.FormatAddress(address)).GetString();
                return code == PeerEgressCodes.Allowed ? null : code;
            });
            if (a.Count == 0 && aaaa > 0 && testCase.GetProperty("ipv6TargetCapable").GetBoolean())
            {
                Assert.True(choice.Code == PeerEgressCodes.NameUnresolved,
                    $"{name}: an IPv4-only egress should find nothing to dial, got {choice.Code}");
                continue;
            }
            Assert.True(testCase.GetProperty("code").GetString() == (choice.Code ?? PeerEgressCodes.Allowed),
                $"{name}: code {choice.Code}");
            var expected = testCase.GetProperty("address");
            if (expected.ValueKind == JsonValueKind.String)
            {
                Assert.True(expected.GetString() == Ipv4Cidr.FormatAddress(choice.Address),
                    $"{name}: chose {Ipv4Cidr.FormatAddress(choice.Address)}");
            }
        }
    }

    [Theory]
    [InlineData("example.com", true)]
    [InlineData("WWW.Example.COM.", true)]
    [InlineData("xn--fiqs8s.example", true)]
    [InlineData("localhost", false)]
    [InlineData("*.example.com", false)]
    [InlineData("a_b.example.com", false)]
    [InlineData("-a.example", false)]
    [InlineData("1.2.3.4", false)]
    [InlineData("", false)]
    [InlineData("中国.example", false)]
    public void ValidatesNames(string name, bool valid) => Assert.Equal(valid, PeerEgressNames.Valid(name));

    [Theory]
    [InlineData("{\"type\":\"name-bind\"}")]
    [InlineData("{\"type\":\"name-bind\",\"address\":\"198.18.0.5\"}")]
    [InlineData("{\"type\":\"name-bind\",\"address\":\"not-an-address\",\"name\":\"example.com\"}")]
    [InlineData("{\"type\":\"name-bind\",\"address\":\"198.18.0.5\",\"name\":\"*.example.com\"}")]
    public void RefusesAMalformedNameBind(string body)
    {
        var frame = PeerEgressFrame.Parse(PeerEgressFrame.Encode(PeerEgressFrame.TypeControl, false, Encoding.UTF8.GetBytes(body)));
        Assert.Equal(PeerEgressCodes.FrameMalformedControl, frame.Code);
    }

    [Fact]
    public void KeepsBindingsByRecentUseWithinTheCaps()
    {
        var table = new PeerEgressNameTable();
        for (uint address = 1; address <= PeerEgressNameTable.CapacityPerConsumer; address++)
        {
            table.Bind(7, address, "example.com");
        }
        table.Lookup(7, 1);
        table.Bind(7, PeerEgressNameTable.CapacityPerConsumer + 1, "late.example");
        Assert.True(table.Lookup(7, 1) is not null, "the binding just used was evicted");
        Assert.True(table.Lookup(7, 2) is null, "the least recently used binding survived a full table");

        table.Bind(9, 1, "other.example");
        table.DropConsumer(7);
        Assert.Equal(1, table.Count);
        Assert.Equal("other.example", table.Lookup(9, 1));
    }
}
