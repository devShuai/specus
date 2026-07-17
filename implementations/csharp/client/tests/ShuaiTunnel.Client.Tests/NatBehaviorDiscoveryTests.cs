using System.Net;
using ShuaiTunnel.Client.PeerMesh;

namespace ShuaiTunnel.Client.Tests;

public sealed class NatBehaviorDiscoveryTests
{
    private static readonly IPEndPoint Primary = new(IPAddress.Parse("203.0.113.10"), 3478);
    private static readonly IPEndPoint Other = new(IPAddress.Parse("203.0.113.11"), 3479);
    private static readonly IPEndPoint Mapped = new(IPAddress.Parse("198.51.100.20"), 52000);

    [Fact]
    public void ClassifiesEndpointIndependentMappingAndFiltering()
    {
        var discovery = new NatBehaviorDiscovery();
        var filter = RequireProbe(
            discovery.Begin(Primary, Mapped, Other),
            NatBehaviorProbe.FilterChangeIpAndPort);
        Assert.Equal(Other, filter.ExpectedResponseEndpoint);

        var mappingIp = RequireProbe(
            discovery.Succeeded(filter.Generation, filter.Probe, Mapped),
            NatBehaviorProbe.MappingAlternateIp);
        Assert.Equal(new IPEndPoint(Other.Address, Primary.Port), mappingIp.TargetEndpoint);
        var mappingIpPort = RequireProbe(
            discovery.Succeeded(mappingIp.Generation, mappingIp.Probe, Mapped),
            NatBehaviorProbe.MappingAlternateIpAndPort);
        var completed = discovery.Succeeded(mappingIpPort.Generation, mappingIpPort.Probe, Mapped).Snapshot;

        Assert.True(completed.Complete);
        Assert.Equal(NatBehavior.EndpointIndependent, completed.MappingBehavior);
        Assert.Equal(NatBehavior.EndpointIndependent, completed.FilteringBehavior);
    }

    [Fact]
    public void ClassifiesAddressDependentMappingAndFiltering()
    {
        var discovery = new NatBehaviorDiscovery();
        var filterBoth = RequireProbe(
            discovery.Begin(Primary, Mapped, Other),
            NatBehaviorProbe.FilterChangeIpAndPort);
        var filterPort = RequireProbe(
            discovery.TimedOut(filterBoth.Generation, filterBoth.Probe),
            NatBehaviorProbe.FilterChangePort);
        Assert.Equal(new IPEndPoint(Primary.Address, Other.Port), filterPort.ExpectedResponseEndpoint);

        var mappingIp = RequireProbe(
            discovery.Succeeded(filterPort.Generation, filterPort.Probe, Mapped),
            NatBehaviorProbe.MappingAlternateIp);
        var mappedII = new IPEndPoint(IPAddress.Parse("198.51.100.20"), 52010);
        var mappingIpPort = RequireProbe(
            discovery.Succeeded(mappingIp.Generation, mappingIp.Probe, mappedII),
            NatBehaviorProbe.MappingAlternateIpAndPort);
        var completed = discovery.Succeeded(mappingIpPort.Generation, mappingIpPort.Probe, mappedII).Snapshot;

        Assert.Equal(NatBehavior.AddressDependent, completed.MappingBehavior);
        Assert.Equal(NatBehavior.AddressDependent, completed.FilteringBehavior);
    }

    [Fact]
    public void ClassifiesAddressAndPortDependentMappingAndFiltering()
    {
        var discovery = new NatBehaviorDiscovery();
        var filterBoth = RequireProbe(
            discovery.Begin(Primary, Mapped, Other),
            NatBehaviorProbe.FilterChangeIpAndPort);
        var filterPort = RequireProbe(
            discovery.TimedOut(filterBoth.Generation, filterBoth.Probe),
            NatBehaviorProbe.FilterChangePort);
        var mappingIp = RequireProbe(
            discovery.TimedOut(filterPort.Generation, filterPort.Probe),
            NatBehaviorProbe.MappingAlternateIp);
        var mappingIpPort = RequireProbe(
            discovery.Succeeded(
                mappingIp.Generation,
                mappingIp.Probe,
                new IPEndPoint(IPAddress.Parse("198.51.100.20"), 52010)),
            NatBehaviorProbe.MappingAlternateIpAndPort);
        var completed = discovery.Succeeded(
            mappingIpPort.Generation,
            mappingIpPort.Probe,
            new IPEndPoint(IPAddress.Parse("198.51.100.20"), 52020)).Snapshot;

        Assert.Equal(NatBehavior.AddressAndPortDependent, completed.MappingBehavior);
        Assert.Equal(NatBehavior.AddressAndPortDependent, completed.FilteringBehavior);
    }

    [Fact]
    public void UnsupportedFilteringStillCompletesMapping()
    {
        var discovery = new NatBehaviorDiscovery();
        var filter = RequireProbe(
            discovery.Begin(Primary, Mapped, Other),
            NatBehaviorProbe.FilterChangeIpAndPort);
        var mappingIp = RequireProbe(
            discovery.Failed(filter.Generation, filter.Probe, true),
            NatBehaviorProbe.MappingAlternateIp);
        var mappingIpPort = RequireProbe(
            discovery.Succeeded(mappingIp.Generation, mappingIp.Probe, Mapped),
            NatBehaviorProbe.MappingAlternateIpAndPort);
        var completed = discovery.Succeeded(mappingIpPort.Generation, mappingIpPort.Probe, Mapped).Snapshot;

        Assert.Equal(NatBehavior.EndpointIndependent, completed.MappingBehavior);
        Assert.Equal(NatBehavior.Unsupported, completed.FilteringBehavior);
    }

    [Fact]
    public void DoesNotTrustNegativeFilteringWhenAlternateEndpointValidationFails()
    {
        var discovery = new NatBehaviorDiscovery();
        var filterBoth = RequireProbe(
            discovery.Begin(Primary, Mapped, Other),
            NatBehaviorProbe.FilterChangeIpAndPort);
        var filterPort = RequireProbe(
            discovery.TimedOut(filterBoth.Generation, filterBoth.Probe),
            NatBehaviorProbe.FilterChangePort);
        var mappingIp = RequireProbe(
            discovery.Succeeded(filterPort.Generation, filterPort.Probe, Mapped),
            NatBehaviorProbe.MappingAlternateIp);
        var completed = discovery.TimedOut(mappingIp.Generation, mappingIp.Probe).Snapshot;

        Assert.Equal(NatBehavior.Unknown, completed.MappingBehavior);
        Assert.Equal(NatBehavior.Unknown, completed.FilteringBehavior);
    }

    private static NatBehaviorProbeRequest RequireProbe(
        NatBehaviorTransition transition,
        NatBehaviorProbe expected)
    {
        Assert.True(transition.Accepted);
        Assert.NotNull(transition.NextProbe);
        Assert.Equal(expected, transition.NextProbe.Probe);
        return transition.NextProbe;
    }
}
